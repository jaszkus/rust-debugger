use super::super::*;
use crate::analysis::decompiler::pcode::StackBase;
use super::{
    c_type_for_size, fmt_const, mentions_reg, pval_str, resolve_pval, PVal, TypeHints, ABI_ARG_REGS, SSE_ARG_REGS, WIN64_ARG_REGS,
};
use crate::analysis::flow::cfg::CFG;
use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashMap as HashMap;

thread_local! {
    static ADDR_IS_64: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

pub(crate) fn set_addr_is_64(value: bool) {
    ADDR_IS_64.with(|cell| cell.set(value));
}

fn is_small_abs_addr(value: u64) -> bool {
    ADDR_IS_64.with(std::cell::Cell::get) && value <= u32::MAX as u64
}

fn is_shift_constant(value: u64) -> bool {
    value > u32::MAX as u64 && value & 0xffff_ffff == 0
}

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
        POp::Cmp { a, b, .. } | POp::Test { a, b, .. } | POp::BitTest { a, b, .. } => {
            visit(a, &mut out);
            visit(b, &mut out);
        }
        POp::CondCopy { dst, src, .. } => {
            visit(dst, &mut out);
            visit(src, &mut out);
        }
        POp::BitModify { dst, bit, .. } => {
            visit(dst, &mut out);
            visit(bit, &mut out);
        }
        POp::Cmpxchg { addr, src, .. } => {
            visit(addr, &mut out);
            visit(src, &mut out);
            out.push("rax");
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
        POp::BranchInd { target } => visit(target, &mut out),
        POp::CallInd { target } => {
            visit(target, &mut out);
            for r in ABI_ARG_REGS {
                out.push(r);
            }
            for r in WIN64_ARG_REGS {
                out.push(r);
            }
            for r in SSE_ARG_REGS {
                out.push(r);
            }
        }
        POp::Call { .. } => {
            for r in ABI_ARG_REGS {
                out.push(r);
            }
            for r in WIN64_ARG_REGS {
                out.push(r);
            }
            for r in SSE_ARG_REGS {
                out.push(r);
            }
            for r in ["rax", "rsp", "eax", "esp"] {
                out.push(r);
            }
        }
        POp::Return | POp::ReturnPop { .. } => {
            for r in ["rax", "rbp", "rsp", "eax", "ebp", "esp", "xmm0"] {
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
        POp::CondCopy { dst, .. } | POp::BitModify { dst, .. } => match dst {
            PVar::Reg(r) => Some(r),
            _ => None,
        },
        POp::Cmpxchg { .. } => Some("rax"),
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
            | POp::CondCopy { .. }
            | POp::BitTest { .. }
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
        .chain(SSE_ARG_REGS)
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
    is_win64: bool,
) -> Vec<String> {
    let mut args = Vec::new();
    if !is64 {
        return args;
    }
    let regs: &[&str] = if is_win64 {
        &WIN64_ARG_REGS
    } else {
        &ABI_ARG_REGS
    };
    for r in regs {
        if let Some(v) = reg_values.get(r) {
            let s = pval_str(v);
            if s != *r || matches!(v, PVal::Opaque(_)) {
                args.push(s);
            }
        }
    }
    args
}

pub(crate) fn take_call_args_sig(
    reg_values: &HashMap<&'static str, PVal>,
    is64: bool,
    is_win64: bool,
    params: &[bool],
    push_args: &mut Vec<PVal>,
) -> Vec<String> {
    if !is64 {
        return take_call_args(reg_values, is64, is_win64, push_args);
    }
    push_args.clear();
    let mut out = Vec::new();
    let mut gp = 0usize;
    let mut sse = 0usize;
    for (idx, &is_float) in params.iter().enumerate() {
        let reg = if is_win64 {
            if idx >= WIN64_ARG_REGS.len() {
                break;
            }
            if is_float {
                SSE_ARG_REGS[idx]
            } else {
                WIN64_ARG_REGS[idx]
            }
        } else if is_float {
            let Some(&r) = SSE_ARG_REGS.get(sse) else {
                break;
            };
            sse += 1;
            r
        } else {
            let Some(&r) = ABI_ARG_REGS.get(gp) else {
                break;
            };
            gp += 1;
            r
        };
        match reg_values.get(reg) {
            Some(v) => {
                let s = pval_str(v);
                if s != reg || matches!(v, PVal::Opaque(_)) {
                    out.push(s);
                } else {
                    out.push(reg.to_string());
                }
            }
            None => out.push(reg.to_string()),
        }
    }
    out
}

pub(crate) fn take_call_args(
    reg_values: &HashMap<&'static str, PVal>,
    is64: bool,
    is_win64: bool,
    push_args: &mut Vec<PVal>,
) -> Vec<String> {
    if !is64 && !push_args.is_empty() {
        let mut vals: Vec<String> = push_args.drain(..).map(|v| pval_str(&v)).collect();
        vals.reverse();
        return vals;
    }
    push_args.clear();
    collect_call_args(reg_values, is64, is_win64)
}



pub(crate) fn struct_member_expr(
    base: &PVar,
    off: i64,
    base_text: &str,
    hints: Option<&TypeHints>,
) -> Option<String> {
    let hints = hints?;
    let PVar::Reg(r) = base else {
        return None;
    };
    
    
    if base_text.contains('+') || base_text.contains('-') {
        return None;
    }
    let (st, display) = if let Some(st) = hints.value_structs.get(base_text) {
        (st, st.owner.as_deref().unwrap_or(base_text))
    } else {
        (hints.structs.get(*r)?, base_text)
    };
    let field = st.field(off)?;
    if field.starts_with("field_0x") {
        return None;
    }
    Some(format!("{}->{}", display, field))
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
            if let Some(h) = hints {
                let pc = h.cur_pc.get();
                let norm = if b == 1 {
                    *off + h.rsp_at.get(&pc).copied().unwrap_or(0)
                } else {
                    *off + h.rbp_delta
                };
                if let Some(st) = h.stack_structs.iter().find(|s| {
                    s.base_reg == b
                        && norm >= s.base_norm
                        && norm < s.base_norm.saturating_add(s.size as i64)
                }) {
                    let base_name = st
                        .base_display
                        .clone()
                        .or_else(|| {
                            h.var_names
                                .as_ref()
                                .and_then(|vn| vn.stack_by_raw.get(&(b, st.base)))
                                .cloned()
                        })
                        .unwrap_or_else(|| fallback_slot_name(st.base, h));
                    let rel = norm - st.base_norm;
                    if st.is_union
                        && let Some((_, _fsize, fname)) = st
                            .fields
                            .iter()
                            .find(|(o, fs, _)| *o == rel && *fs == size as usize)
                    {
                        return format!("{}.{}", base_name, fname);
                    }
                    if norm == st.base_norm && size as usize >= st.size {
                        return base_name;
                    }
                    if let Some((_, _fsize, fname)) = st
                        .fields
                        .iter()
                        .find(|(o, fs, _)| *o == rel && *fs == size as usize)
                    {
                        return format!("{}.{}", base_name, fname);
                    }
                }
                if let Some((name, local_size)) = h.stack_names.get(&norm)
                    && *local_size == size as usize
                {
                    return name.clone();
                }
            }
            let name = if let Some(h) = hints {
                if let Some(vn) = &h.var_names {
                    let pc = h.cur_pc.get();
                    if let Some(n) = vn.read_stack.get(&(pc, b, *off))
                        .or_else(|| vn.write_stack.get(&(pc, b, *off)))
                        .or_else(|| vn.stack_by_raw.get(&(b, *off))) {
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
            if let Some(h) = hints
                && let Some(vn) = &h.var_names
                    && vn.size_of.get(&name).copied() == Some(size) {
                        return name;
                    }
            format!("*({0} *)&{1}", ty, name)
        }
        PVar::Addr(a) if is_small_abs_addr(*a) => {
            format!("*({} *){}", ty, fmt_const(*a as i64))
        }
        PVar::Addr(a) => format!("*({0} *)&DAT_{1:x}", ty, a),
        PVar::Reg(r) => {
            let base = reg_values
                .get(r)
                .map(pval_str)
                .unwrap_or_else(|| r.to_string());
            if let Some(m) = struct_member_expr(addr, 0, &base, hints) {
                return m;
            }
            format!("*({} *){}", ty, base)
        }
        PVar::Mem(base, disp) => {
            let b = fmt_var(base);
            let b = reg_values.get(b.as_str()).map(pval_str).unwrap_or(b);
            if let Some(m) = struct_member_expr(base, *disp, &b, hints) {
                return m;
            }
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
        PVar::Addr(a) if is_small_abs_addr(*a) || is_shift_constant(*a) => fmt_const(*a as i64),
        PVar::Addr(a) => format!("DAT_{:x}", a),
        PVar::Tmp(i) => format!("tmp_{}", i),
    }
}

pub(crate) fn fmt_var_with_hints(v: &PVar, hints: &TypeHints) -> String {
    match v {
        PVar::StackSlot { base, off } => {
            let b = if *base == StackBase::Rbp { 0u8 } else { 1u8 };
            let pc = hints.cur_pc.get();
            let norm = if b == 1 {
                *off + hints.rsp_at.get(&pc).copied().unwrap_or(0)
            } else {
                *off + hints.rbp_delta
            };
            if let Some((name, _size)) = hints.stack_names.get(&norm) {
                return name.clone();
            }
            if let Some(vn) = &hints.var_names
                && let Some(n) = vn.read_stack.get(&(pc, b, *off))
                    .or_else(|| vn.write_stack.get(&(pc, b, *off)))
                    .or_else(|| vn.stack_by_raw.get(&(b, *off))) {
                    return n.clone();
            }
            fallback_slot_name(*off, hints)
        }
        PVar::Mem(base, off) => {
            if let PVar::Reg(r) = &**base
                && let Some(st) = hints.structs.get(*r)
                && let Some(field) = st.field(*off)
                && !field.starts_with("field_0x")
            {
                return format!("{}->{}", fmt_var(base), field);
            }
            fmt_var(v)
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
        PVar::StackSlot { base, off } => {
            let b = if *base == StackBase::Rbp { 0u8 } else { 1u8 };
            let pc = hints.cur_pc.get();
            let norm = if b == 1 {
                *off + hints.rsp_at.get(&pc).copied().unwrap_or(0)
            } else {
                *off + hints.rbp_delta
            };
            if let Some((name, _)) = hints.stack_names.get(&norm) {
                PVal::E(name.clone())
            } else {
                PVal::E(fmt_var_with_hints(v, hints))
            }
        }
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
    let mut cmp_size: u32 = 8;
    let mut float_cmp_pair: Option<(PVar, PVar)> = None;
    let mut bit_test: Option<(PVar, PVar)> = None;
    let mut flag_setter: Option<(String, PVar, PVar, String)> = None;
    let mut jcc_mnemonic = String::new();
    let mut ah_float_cmp: Option<(PVar, PVar)> = None;
    let mut ah_test_mask: Option<i64> = None;
    let mut ops_since_sub: usize = usize::MAX;
    let mut cmp_follows_sub = false;

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
            POp::Cmp { a, b, size } => {
                cmp_pair = Some((a.clone(), b.clone(), false));
                cmp_size = *size;
                cmp_follows_sub = ops_since_sub <= 1;
            }
            POp::Test { a, b, size } => {
                cmp_size = *size;
                cmp_follows_sub = ops_since_sub <= 1;
                let is_ah = matches!(a, PVar::Reg(_))
                    && imap_get(imap, *addr)
                        .map(|d| d.ops().to_ascii_lowercase().starts_with("ah"))
                        .unwrap_or(false);
                if is_ah {
                    if ah_float_cmp.is_some()
                        && let PVar::Const(m) = b {
                            ah_test_mask = Some(*m);
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
            POp::BitTest { a, b, .. } => {
                bit_test = Some((a.clone(), b.clone()));
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
        if matches!(op, POp::IntSub { .. }) {
            ops_since_sub = 0;
        } else {
            ops_since_sub = ops_since_sub.saturating_add(1);
        }
    }

    if !jcc_mnemonic.is_empty()
        && let (Some(mask), Some((fa, fb))) = (ah_test_mask, ah_float_cmp.clone()) {
            let av = cv(&fa);
            let bv = cv(&fb);
            return float_cc_via_mask(&jcc_mnemonic, mask, &av, &bv);
        }

    if let Some((a, b)) = bit_test {
        let av = cv(&a);
        let bv = cv(&b);
        let expr = format!("(({} >> {}) & 1)", av, bv);
        return match jcc_mnemonic.as_str() {
            "jc" | "jb" | "jnae" => format!("{} != 0", expr),
            "jnc" | "jae" | "jnb" => format!("{} == 0", expr),
            _ => "cond".into(),
        };
    }

    if let Some((a, b, is_test)) = cmp_pair {
        if let Some((kind, fa, fb, dst)) = &flag_setter
            && kind == "sub"
            && cmp_follows_sub
            && cmp_tests_flag_result(&a, &b, is_test, dst)
            && let Some(cond) = flag_condition(
                kind,
                &cv(fa),
                &cv(fb),
                &jcc_mnemonic,
                cmp_size,
                is_test,
            )
        {
            return cond;
        }
        let av = cv(&a);
        let bv = cv(&b);
        return jcc_to_expr(&jcc_mnemonic, &av, &bv, is_test, cmp_size);
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

fn cmp_tests_flag_result(a: &PVar, b: &PVar, is_test: bool, dst: &str) -> bool {
    if is_test {
        return fmt_var(a) == dst && fmt_var(b) == dst;
    }
    let zero = |v: &PVar| matches!(v, PVar::Const(0) | PVar::Addr(0));
    (fmt_var(a) == dst && zero(b)) || (fmt_var(b) == dst && zero(a))
}

fn flag_condition(
    kind: &str,
    a: &str,
    b: &str,
    jcc: &str,
    size: u32,
    is_test: bool,
) -> Option<String> {
    match kind {
        "sub" => {
            let cond = jcc_to_expr(jcc, a, b, false, size);
            (cond != "cond").then_some(cond)
        }
        "and" | "or" | "xor" => {
            let op = match kind {
                "and" => "&",
                "or" => "|",
                _ => "^",
            };
            let expr = format!("({} {} {})", a, op, b);
            let cond = result_cond(jcc, &expr);
            (cond != "cond").then_some(cond)
        }
        "add" => {
            if !is_test {
                return None;
            }
            let expr = format!("({} + {})", a, b);
            let cond = result_cond(jcc, &expr);
            (cond != "cond").then_some(cond)
        }
        _ => None,
    }
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

pub(crate) fn jcc_to_expr(jcc: &str, a: &str, b: &str, is_test: bool, size: u32) -> String {
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
    let unsigned = if size >= 8 { "ulonglong" } else { "uint" };
    match jcc {
        "je" | "jz" => format!("{} == {}", a, b),
        "jne" | "jnz" => format!("{} != {}", a, b),
        "jl" | "jnge" => format!("{} < {}", a, b),
        "jle" | "jng" => format!("{} <= {}", a, b),
        "jg" | "jnle" => format!("{} > {}", a, b),
        "jge" | "jnl" => format!("{} >= {}", a, b),
        "jb" | "jnae" | "jc" => format!("({unsigned}){a} < ({unsigned}){b}"),
        "jbe" | "jna" => format!("({unsigned}){a} <= ({unsigned}){b}"),
        "ja" | "jnbe" => format!("({unsigned}){a} > ({unsigned}){b}"),
        "jae" | "jnb" | "jnc" => format!("({unsigned}){a} >= ({unsigned}){b}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_absolute_addresses_are_immediates_on_x64() {
        set_addr_is_64(true);
        assert_eq!(fmt_var(&PVar::Addr(0xffff_ffff)), "0xffffffff");
        assert_eq!(fmt_var(&PVar::Addr(0x1_8000_0000)), "DAT_180000000");
        set_addr_is_64(false);
        assert_eq!(fmt_var(&PVar::Addr(0x2000)), "DAT_2000");
        set_addr_is_64(true);
    }

    #[test]
    fn subtraction_condition_folds_to_a_comparison() {
        assert_eq!(
            flag_condition("sub", "msg", "0x300", "je", 4, false).as_deref(),
            Some("msg == 0x300")
        );
        assert_eq!(
            flag_condition("sub", "a", "b", "jb", 8, false).as_deref(),
            Some("(ulonglong)a < (ulonglong)b")
        );
        assert_eq!(
            flag_condition("and", "a", "b", "je", 4, false).as_deref(),
            Some("(a & b) == 0")
        );
        assert_eq!(flag_condition("add", "a", "b", "je", 4, false), None);
    }

    #[test]
    fn cmp_of_flag_result_detects_the_same_register() {
        let rax = PVar::Reg("rax");
        assert!(cmp_tests_flag_result(&rax, &rax, true, "rax"));
        assert!(cmp_tests_flag_result(&rax, &PVar::Const(0), false, "rax"));
        assert!(cmp_tests_flag_result(&PVar::Const(0), &rax, false, "rax"));
        assert!(!cmp_tests_flag_result(&rax, &PVar::Const(1), false, "rax"));
        assert!(!cmp_tests_flag_result(&rax, &rax, true, "rbx"));
    }

    #[test]
    fn unsigned_casts_follow_operand_width() {
        assert_eq!(
            jcc_to_expr("jb", "a", "b", false, 4),
            "(uint)a < (uint)b"
        );
        assert_eq!(
            jcc_to_expr("jae", "a", "b", false, 8),
            "(ulonglong)a >= (ulonglong)b"
        );
    }
}
