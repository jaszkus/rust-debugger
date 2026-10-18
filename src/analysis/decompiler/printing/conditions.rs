use super::super::*;
use crate::analysis::decompiler::pcode::StackBase;
use super::{
    c_type_for_size, fmt_const, mentions_reg, pval_str, resolve_pval, PVal, TypeHints, ABI_ARG_REGS,
};
use crate::analysis::flow::cfg::CFG;
use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashMap as HashMap;

pub(crate) fn reads_regs(op: &POp) -> Vec<&'static str> {
    let mut out = Vec::new();
    fn visit(v: &PVar, out: &mut Vec<&'static str>) {
        match v {
            PVar::Reg(r) => out.push(r),
            PVar::Mem(b, _) => visit(b, out),
            PVar::Scaled { base, index, .. } => {
                visit(base, out);
                visit(index, out);
            }
            _ => {}
        }
    }
    match op {
        POp::Copy { dst, src, .. } => {
            visit(src, &mut out);
            let _ = dst;
        }
        POp::IntAdd { a, b, .. }
        | POp::IntSub { a, b, .. }
        | POp::IntMul { a, b, .. }
        | POp::IntDiv { a, b, .. }
        | POp::IntSDiv { a, b, .. }
        | POp::IntAnd { a, b, .. }
        | POp::IntOr { a, b, .. }
        | POp::IntXor { a, b, .. }
        | POp::IntLeft { a, b, .. }
        | POp::IntShr { a, b, .. }
        | POp::IntSar { a, b, .. } => {
            visit(a, &mut out);
            visit(b, &mut out);
        }
        POp::Zext { src, .. } | POp::Sext { src, .. } | POp::Cvt { src, .. } => {
            visit(src, &mut out)
        }
        POp::FloatBinop { a, b, .. } => {
            visit(a, &mut out);
            visit(b, &mut out);
        }
        POp::FloatCmp { a, b, .. } => {
            visit(a, &mut out);
            visit(b, &mut out);
        }
        POp::Load { addr, .. } => visit(addr, &mut out),
        POp::Store { addr, src, .. } => {
            visit(addr, &mut out);
            visit(src, &mut out);
        }
        POp::Cmp { a, b, .. } | POp::Test { a, b, .. } => {
            visit(a, &mut out);
            visit(b, &mut out);
        }
        POp::Push { src, .. } => visit(src, &mut out),
        POp::AddrOf { base, index, .. } => {
            if let Some(b) = base {
                visit(b, &mut out);
            }
            if let Some(i) = index {
                visit(i, &mut out);
            }
        }
        POp::BranchInd { target } | POp::CallInd { target } => visit(target, &mut out),
        POp::Call { .. } => {
            for r in [
                "rcx", "rdx", "r8", "r9", "rax", "rsp", "eax", "ecx", "edx", "esp",
            ] {
                out.push(r);
            }
        }
        POp::Return | POp::ReturnPop { .. } => {
            for r in ["rax", "rbp", "rsp", "eax", "ebp", "esp"] {
                out.push(r);
            }
        }
        _ => {}
    }
    out
}

pub(crate) fn written_reg(op: &POp) -> Option<&'static str> {
    match op {
        POp::Copy { dst, .. }
        | POp::IntAdd { dst, .. }
        | POp::IntSub { dst, .. }
        | POp::IntMul { dst, .. }
        | POp::IntDiv { dst, .. }
        | POp::IntSDiv { dst, .. }
        | POp::IntAnd { dst, .. }
        | POp::IntOr { dst, .. }
        | POp::IntXor { dst, .. }
        | POp::IntLeft { dst, .. }
        | POp::IntShr { dst, .. }
        | POp::IntSar { dst, .. }
        | POp::Zext { dst, .. }
        | POp::Sext { dst, .. }
        | POp::Load { dst, .. }
        | POp::SetCC { dst, .. }
        | POp::Pop { dst, .. }
        | POp::LeaAddr { dst, .. }
        | POp::AddrOf { dst, .. } => match dst {
            PVar::Reg(r) => Some(r),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn is_pure(op: &POp) -> bool {
    matches!(
        op,
        POp::Copy { .. }
            | POp::IntAdd { .. }
            | POp::IntSub { .. }
            | POp::IntMul { .. }
            | POp::IntDiv { .. }
            | POp::IntSDiv { .. }
            | POp::IntAnd { .. }
            | POp::IntOr { .. }
            | POp::IntXor { .. }
            | POp::IntLeft { .. }
            | POp::IntShr { .. }
            | POp::IntSar { .. }
            | POp::Zext { .. }
            | POp::Sext { .. }
            | POp::SetCC { .. }
            | POp::LeaAddr { .. }
            | POp::AddrOf { .. }
    )
}

pub(crate) fn collect_pvar_regs(v: &PVar, out: &mut Vec<&'static str>) {
    match v {
        PVar::Reg(r) => out.push(r),
        PVar::Mem(b, _) => collect_pvar_regs(b, out),
        PVar::Scaled { base, index, .. } => {
            collect_pvar_regs(base, out);
            collect_pvar_regs(index, out);
        }
        _ => {}
    }
}

pub(crate) fn cse_key(
    op: &POp,
    reg_values: &HashMap<&'static str, PVal>,
) -> Option<(String, Vec<&'static str>)> {
    let (sym, a, b) = match op {
        POp::IntAdd { a, b, .. } => ("+", a, b),
        POp::IntMul { a, b, .. } => ("*", a, b),
        POp::IntAnd { a, b, .. } => ("&", a, b),
        POp::IntOr { a, b, .. } => ("|", a, b),
        POp::IntXor { a, b, .. } => ("^", a, b),
        POp::IntSub { a, b, .. } => ("-", a, b),
        _ => return None,
    };
    written_reg(op)?;
    let mut parts = [
        pval_str(&resolve_pval(a, reg_values)),
        pval_str(&resolve_pval(b, reg_values)),
    ];
    if matches!(sym, "+" | "*" | "&" | "|" | "^") {
        parts.sort();
    }
    let mut oregs = Vec::new();
    collect_pvar_regs(a, &mut oregs);
    collect_pvar_regs(b, &mut oregs);
    oregs.sort();
    oregs.dedup();
    Some((format!("{}|{}|{}", sym, parts[0], parts[1]), oregs))
}

pub(crate) fn cse_invalidate(
    cse: &mut HashMap<String, (&'static str, Vec<&'static str>)>,
    w: &str,
) {
    cse.retain(|_, (holder, oregs)| *holder != w && !oregs.contains(&w));
}

pub(crate) fn clobber_call(reg_values: &mut HashMap<&'static str, PVal>, is64: bool) {
    let _ = is64;
    let removed: Vec<&'static str> = CALL_CLOBBERED
        .iter()
        .copied()
        .chain(["xmm0", "xmm1", "xmm2", "xmm3"])
        .collect();
    for r in &removed {
        reg_values.remove(*r);
    }
    if !reg_values.is_empty() {
        let stale: Vec<&'static str> = reg_values
            .iter()
            .filter(|kv| removed.iter().any(|r| mentions_reg(kv.1, r)))
            .map(|kv| *kv.0)
            .collect();
        for k in stale {
            reg_values.insert(k, PVal::Opaque(k));
        }
    }
}

pub(crate) fn collect_call_args(
    reg_values: &HashMap<&'static str, PVal>,
    is64: bool,
) -> Vec<String> {
    let mut args = Vec::new();
    if !is64 {
        for r in ["rcx", "rdx"] {
            if let Some(v) = reg_values.get(r) {
                let s = pval_str(v);
                if s != *r || matches!(v, PVal::Opaque(_)) {
                    args.push(s);
                }
            }
        }
        return args;
    }
    for r in ABI_ARG_REGS {
        if let Some(v) = reg_values.get(r) {
            let s = pval_str(v);
            if s != r || matches!(v, PVal::Opaque(_)) {
                args.push(s);
            }
        }
    }
    args.dedup();
    args
}

pub(crate) fn take_call_args(
    reg_values: &HashMap<&'static str, PVal>,
    is64: bool,
    push_args: &mut Vec<PVal>,
) -> Vec<String> {
    if !is64 && !push_args.is_empty() {
        let mut vals: Vec<String> = push_args.drain(..).map(|v| pval_str(&v)).collect();
        vals.reverse();
        return vals;
    }
    push_args.clear();
    collect_call_args(reg_values, is64)
}

pub(crate) fn fmt_load(
    addr: &PVar,
    size: u32,
    reg_values: &HashMap<&'static str, PVal>,
    float_hint: Option<bool>,
    hints: Option<&TypeHints>,
) -> String {
    let ty: String = match float_hint {
        Some(true) => {
            if size == 8 {
                "double".into()
            } else {
                "float".into()
            }
        }
        _ => c_type_for_size(size).to_string(),
    };
    let ty = ty.as_str();
    match addr {
        PVar::StackSlot { base, off } => {
            let b = if *base == StackBase::Rbp { 0u8 } else { 1u8 };
            let name = if let Some(h) = hints {
                if let Some(vn) = &h.var_names {
                    let pc = h.cur_pc.get();
                    if let Some(n) = vn.read_stack.get(&(pc, b, *off)).or_else(|| vn.write_stack.get(&(pc, b, *off))) {
                        n.clone()
                    } else {
                        fallback_slot_name(*off, h)
                    }
                } else {
                    fallback_slot_name(*off, h)
                }
            } else {
                if *off < 0 { format!("local_{:X}", off.unsigned_abs()) } else { format!("arg_{:X}", off) }
            };
            if let Some(h) = hints {
                if let Some(vn) = &h.var_names {
                    if vn.size_of.get(&name).copied() == Some(size) {
                        return name;
                    }
                }
            }
            format!("*({0} *)&{1}", ty, name)
        }
        PVar::Addr(a) => format!("*({0} *)&DAT_{1:X}", ty, a),
        PVar::Reg(r) => {
            let base = reg_values
                .get(r)
                .map(pval_str)
                .unwrap_or_else(|| r.to_string());
            format!("*({} *){}", ty, base)
        }
        PVar::Mem(base, disp) => {
            let b = fmt_var(base);
            let b = reg_values.get(b.as_str()).map(pval_str).unwrap_or(b);
            if *disp == 0 {
                format!("*({} *){}", ty, b)
            } else if *disp > 0 {
                format!("*({} *)({} + {:#x})", ty, b, disp)
            } else {
                format!("*({} *)({} - {:#x})", ty, b, -disp)
            }
        }
        PVar::Scaled {
            base,
            index,
            scale,
            disp,
        } => {
            let b = fmt_var(base);
            let b = reg_values.get(b.as_str()).map(pval_str).unwrap_or(b);
            let i = fmt_var(index);
            let i = reg_values.get(i.as_str()).map(pval_str).unwrap_or(i);
            let inner = if *scale == 1 {
                format!("{} + {}", b, i)
            } else {
                format!("{} + {} * {}", b, i, scale)
            };
            if *disp == 0 {
                format!("*({} *)({})", ty, inner)
            } else if *disp > 0 {
                format!("*({} *)({} + {:#x})", ty, inner, disp)
            } else {
                format!("*({} *)({} - {:#x})", ty, inner, -disp)
            }
        }
        other => format!("*({} *){}", ty, fmt_var(other)),
    }
}

pub(crate) fn fallback_slot_name(off: i64, hints: &TypeHints) -> String {
    if off < 0 {
        format!("local_{:X}", off.unsigned_abs())
    } else if hints.spill_slots.contains(&off) || hints.local_slots.contains(&off) {
        if hints.spill_slots.contains(&off) && !hints.local_slots.contains(&off) {
            format!("stk_{:X}", off)
        } else {
            format!("local_{:X}", off)
        }
    } else if hints.param_slots.contains(&off) {
        format!("param_{:X}", off)
    } else {
        format!("arg_{:X}", off)
    }
}

pub(crate) fn fmt_var(v: &PVar) -> String {
    match v {
        PVar::Reg(r) => r.to_string(),
        PVar::Const(c) => fmt_const(*c),
        PVar::StackSlot { off, .. } => {
            if *off < 0 {
                format!("local_{:X}", off.unsigned_abs())
            } else {
                format!("arg_{:X}", off)
            }
        }
        PVar::Mem(base, disp) => {
            if *disp == 0 {
                format!("*({})", fmt_var(base))
            } else if *disp > 0 {
                format!("*({} + {:#x})", fmt_var(base), disp)
            } else {
                format!("*({} - {:#x})", fmt_var(base), -disp)
            }
        }
        PVar::Scaled {
            base,
            index,
            scale,
            disp,
        } => {
            let inner = if *scale == 1 {
                format!("{} + {}", fmt_var(base), fmt_var(index))
            } else {
                format!("{} + {} * {}", fmt_var(base), fmt_var(index), scale)
            };
            if *disp == 0 {
                format!("*({})", inner)
            } else if *disp > 0 {
                format!("*({} + {:#x})", inner, disp)
            } else {
                format!("*({} - {:#x})", inner, -disp)
            }
        }
        PVar::Addr(a) => format!("DAT_{:X}", a),
        PVar::Tmp(i) => format!("tmp_{}", i),
    }
}

pub(crate) fn fmt_var_with_hints(v: &PVar, hints: &TypeHints) -> String {
    match v {
        PVar::StackSlot { base, off } => {
            let b = if *base == StackBase::Rbp { 0u8 } else { 1u8 };
            if let Some(vn) = &hints.var_names {
                let pc = hints.cur_pc.get();
                if let Some(n) = vn.read_stack.get(&(pc, b, *off)).or_else(|| vn.write_stack.get(&(pc, b, *off))) {
                    return n.clone();
                }
            }
            fallback_slot_name(*off, hints)
        }
        _ => fmt_var(v),
    }
}

pub(crate) fn resolve_pval_with_hints(
    v: &PVar,
    reg_values: &HashMap<&'static str, PVal>,
    hints: &TypeHints,
) -> PVal {
    match v {
        PVar::Reg(r) => reg_values
            .get(r)
            .cloned()
            .unwrap_or_else(|| PVal::E(r.to_string())),
        PVar::Const(c) => PVal::C(*c),
        other => PVal::E(fmt_var_with_hints(other, hints)),
    }
}

pub(crate) fn recover_condition(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    imap: &[DisasmInstruction],
    block_id: usize,
    consts: &HashMap<&'static str, Lattice>,
    hints: Option<&TypeHints>,
) -> String {
    if block_id >= cfg.blocks.len() {
        return "cond".into();
    }

    let cv = |v: &PVar| -> String {
        match v {
            PVar::Reg(r) => match consts.get(r) {
                Some(Lattice::Const(c)) => fmt_const(*c),
                _ => {
                    if let Some(h) = hints { fmt_var_with_hints(v, h) } else { fmt_var(v) }
                }
            },
            _ => {
                if let Some(h) = hints { fmt_var_with_hints(v, h) } else { fmt_var(v) }
            }
        }
    };

    let mut cmp_pair: Option<(PVar, PVar, bool)> = None;
    let mut float_cmp_pair: Option<(PVar, PVar)> = None;
    let mut flag_setter: Option<(String, PVar, PVar, String)> = None;
    let mut jcc_mnemonic = String::new();
    let mut ah_float_cmp: Option<(PVar, PVar)> = None;
    let mut ah_test_mask: Option<i64> = None;

    for (addr, op) in &bops[block_id] {
        if let Some(di) = imap_get(imap, *addr) {
            if di.mnemonic.starts_with('j') && di.mnem() != "jmp" && di.mnem() != "jecxz" {
                jcc_mnemonic = di.mnemonic.to_string();
                break;
            }
            if di.mnem() == "lahf" || di.mnem() == "sahf" {
                continue;
            }
        }
        match op {
            POp::Cmp { a, b, .. } => cmp_pair = Some((a.clone(), b.clone(), false)),
            POp::Test { a, b, .. } => {
                let is_ah = matches!(a, PVar::Reg(_))
                    && imap_get(imap, *addr)
                        .map(|d| d.ops().to_ascii_lowercase().starts_with("ah"))
                        .unwrap_or(false);
                if is_ah {
                    if ah_float_cmp.is_some() {
                        if let PVar::Const(m) = b {
                            ah_test_mask = Some(*m);
                        }
                    }
                } else {
                    cmp_pair = Some((a.clone(), b.clone(), true));
                }
            }
            POp::FloatCmp { a, b, .. } => {
                float_cmp_pair = Some((a.clone(), b.clone()));
                ah_float_cmp = Some((a.clone(), b.clone()));
                ah_test_mask = None;
            }
            POp::IntAdd { dst, a, b, .. } => {
                flag_setter = Some(("add".into(), a.clone(), b.clone(), fmt_var(dst)))
            }
            POp::IntSub { dst, a, b, .. } => {
                flag_setter = Some(("sub".into(), a.clone(), b.clone(), fmt_var(dst)))
            }
            POp::IntAnd { dst, a, b, .. } => {
                flag_setter = Some(("and".into(), a.clone(), b.clone(), fmt_var(dst)))
            }
            POp::IntOr { dst, a, b, .. } => {
                flag_setter = Some(("or".into(), a.clone(), b.clone(), fmt_var(dst)))
            }
            POp::IntXor { dst, a, b, .. } => {
                flag_setter = Some(("xor".into(), a.clone(), b.clone(), fmt_var(dst)))
            }
            _ => {}
        }
    }

    if !jcc_mnemonic.is_empty() {
        if let (Some(mask), Some((fa, fb))) = (ah_test_mask, ah_float_cmp.clone()) {
            let av = cv(&fa);
            let bv = cv(&fb);
            return float_cc_via_mask(&jcc_mnemonic, mask, &av, &bv);
        }
    }

    if let Some((a, b, is_test)) = cmp_pair {
        let av = cv(&a);
        let bv = cv(&b);
        return jcc_to_expr(&jcc_mnemonic, &av, &bv, is_test);
    }

    if let Some((a, b)) = float_cmp_pair {
        let av = cv(&a);
        let bv = cv(&b);
        return match jcc_mnemonic.as_str() {
            "je" | "jz" => format!("{} == {}", av, bv),
            "jne" | "jnz" => format!("{} != {}", av, bv),
            "ja" | "jnbe" => format!("{} > {}", av, bv),
            "jae" | "jnb" | "jnc" => format!("{} >= {}", av, bv),
            "jb" | "jnae" | "jc" => format!("{} < {}", av, bv),
            "jbe" | "jna" => format!("{} <= {}", av, bv),
            _ => "cond".into(),
        };
    }

    if let Some((kind, a, b, dst)) = flag_setter {
        let expr = match kind.as_str() {
            "add" => format!("({} + {})", cv(&a), cv(&b)),
            "sub" => format!("({} - {})", cv(&a), cv(&b)),
            "and" => format!("({} & {})", cv(&a), cv(&b)),
            "or" => format!("({} | {})", cv(&a), cv(&b)),
            "xor" => format!("({} ^ {})", cv(&a), cv(&b)),
            _ => dst,
        };
        let cond = result_cond(&jcc_mnemonic, &expr);
        if cond != "cond" {
            return cond;
        }
    }

    if !jcc_mnemonic.is_empty() {
        return jcc_only_expr(&jcc_mnemonic);
    }

    "cond".into()
}

pub(crate) fn float_cc_via_mask(jcc: &str, mask: i64, a: &str, b: &str) -> String {
    let eq = format!("{} == {}", a, b);
    let ne = format!("{} != {}", a, b);
    let lt = format!("{} < {}", a, b);
    let le = format!("{} <= {}", a, b);
    let gt = format!("{} > {}", a, b);
    let ge = format!("{} >= {}", a, b);
    match mask {
        0x40 => match jcc {
            "je" | "jz" => eq,
            "jne" | "jnz" => ne,
            _ => "cond".into(),
        },
        0x41 | 0x44 | 0x45 => match jcc {
            "je" | "jz" => eq,
            "jne" | "jnz" => ne,
            "ja" | "jnbe" => gt,
            "jbe" | "jna" => le,
            "jb" | "jnae" | "jc" => lt,
            "jae" | "jnb" | "jnc" => ge,
            _ => "cond".into(),
        },
        0x01 => match jcc {
            "jb" | "jnae" | "jc" => lt,
            "jae" | "jnb" | "jnc" => ge,
            _ => "cond".into(),
        },
        _ => "cond".into(),
    }
}

pub(crate) fn result_cond(jcc: &str, expr: &str) -> String {
    match jcc {
        "jz" | "je" => format!("{} == 0", expr),
        "jnz" | "jne" => format!("{} != 0", expr),
        "js" => format!("{} < 0", expr),
        "jns" => format!("{} >= 0", expr),
        "jl" | "jnge" => format!("{} < 0", expr),
        "jle" | "jng" => format!("{} <= 0", expr),
        "jg" | "jnle" => format!("{} > 0", expr),
        "jge" | "jnl" => format!("{} >= 0", expr),
        "jb" | "jnae" | "jc" => "borrow".into(),
        "jbe" | "jna" => "borrow || ZF".into(),
        "ja" | "jnbe" => "!borrow && !ZF".into(),
        "jae" | "jnb" | "jnc" => "!borrow".into(),
        "jo" => format!("overflow({})", expr),
        "jno" => format!("!overflow({})", expr),
        _ => "cond".into(),
    }
}

pub(crate) fn jcc_to_expr(jcc: &str, a: &str, b: &str, is_test: bool) -> String {
    if is_test {
        if a == b {
            return match jcc {
                "jz" | "je" => format!("{} == 0", a),
                "jnz" | "jne" => format!("{} != 0", a),
                "js" => format!("{} < 0", a),
                "jns" => format!("{} >= 0", a),
                _ => format!("{} & {}", a, b),
            };
        }
        return match jcc {
            "jz" | "je" => format!("({} & {}) == 0", a, b),
            "jnz" | "jne" => format!("({} & {}) != 0", a, b),
            _ => format!("({} & {})", a, b),
        };
    }
    match jcc {
        "je" | "jz" => format!("{} == {}", a, b),
        "jne" | "jnz" => format!("{} != {}", a, b),
        "jl" | "jnge" => format!("{} < {}", a, b),
        "jle" | "jng" => format!("{} <= {}", a, b),
        "jg" | "jnle" => format!("{} > {}", a, b),
        "jge" | "jnl" => format!("{} >= {}", a, b),
        "jb" | "jnae" | "jc" => format!("(unsigned){} < (unsigned){}", a, b),
        "jbe" | "jna" => format!("(unsigned){} <= (unsigned){}", a, b),
        "ja" | "jnbe" => format!("(unsigned){} > (unsigned){}", a, b),
        "jae" | "jnb" | "jnc" => format!("(unsigned){} >= (unsigned){}", a, b),
        "js" => format!("({} - {}) < 0", a, b),
        "jns" => format!("({} - {}) >= 0", a, b),
        "jo" => format!("overflow({} - {})", a, b),
        "jno" => format!("!overflow({} - {})", a, b),
        "jp" | "jpe" => format!("parity({} - {})", a, b),
        "jnp" | "jpo" => format!("!parity({} - {})", a, b),
        _ => format!("{} ? {}", a, b),
    }
}

pub(crate) fn jcc_only_expr(jcc: &str) -> String {
    match jcc {
        "jz" | "je" => "ZF".into(),
        "jnz" | "jne" => "!ZF".into(),
        "js" => "SF".into(),
        "jns" => "!SF".into(),
        "jc" | "jb" => "CF".into(),
        "jnc" | "jnb" => "!CF".into(),
        "jo" => "OF".into(),
        "jno" => "!OF".into(),
        _ => "cond".into(),
    }
}
