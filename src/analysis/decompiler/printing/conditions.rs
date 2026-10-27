use super::super::*;
use super::{
    ABI_ARG_REGS, PVal, SSE_ARG_REGS, TypeHints, WIN64_ARG_REGS, c_type_for_size, fmt_const,
    mentions_reg, pval_str, resolve_pval,
};
use crate::analysis::decompiler::pcode::StackBase;
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

fn push_call_regs(out: &mut Vec<&'static str>) {
    out.extend_from_slice(&ABI_ARG_REGS);
    out.extend_from_slice(&WIN64_ARG_REGS);
    out.extend_from_slice(&SSE_ARG_REGS);
    out.extend_from_slice(&["rax", "rsp", "eax", "esp"]);
}

#[inline]
fn dst_addr_regs(dst: &PVar, out: &mut Vec<&'static str>) {
    if !matches!(dst, PVar::Reg(_)) {
        collect_pvar_regs(dst, out);
    }
}

fn reads_regs_into(op: &POp, out: &mut Vec<&'static str>) {
    match op {
        POp::Copy { dst, src, .. } => {
            dst_addr_regs(dst, out);
            collect_pvar_regs(src, out);
        }
        POp::IntAdd { dst, a, b, .. }
        | POp::IntSub { dst, a, b, .. }
        | POp::IntMul { dst, a, b, .. }
        | POp::IntDiv { dst, a, b, .. }
        | POp::IntSDiv { dst, a, b, .. }
        | POp::IntAnd { dst, a, b, .. }
        | POp::IntOr { dst, a, b, .. }
        | POp::IntXor { dst, a, b, .. }
        | POp::IntLeft { dst, a, b, .. }
        | POp::IntShr { dst, a, b, .. }
        | POp::IntSar { dst, a, b, .. } => {
            dst_addr_regs(dst, out);
            collect_pvar_regs(a, out);
            collect_pvar_regs(b, out);
        }
        POp::FloatBinop { a, b, .. }
        | POp::FloatCmp { a, b, .. }
        | POp::Cmp { a, b, .. }
        | POp::Test { a, b, .. }
        | POp::BitTest { a, b, .. } => {
            collect_pvar_regs(a, out);
            collect_pvar_regs(b, out);
        }
        POp::Zext { src, .. }
        | POp::Sext { src, .. }
        | POp::Cvt { src, .. }
        | POp::Push { src, .. } => collect_pvar_regs(src, out),
        POp::Load { addr, .. } => collect_pvar_regs(addr, out),
        POp::Store { addr, src, .. } => {
            collect_pvar_regs(addr, out);
            collect_pvar_regs(src, out);
        }
        POp::CondCopy { dst, src, .. } => {
            collect_pvar_regs(dst, out);
            collect_pvar_regs(src, out);
        }
        POp::BitModify { dst, bit, .. } => {
            collect_pvar_regs(dst, out);
            collect_pvar_regs(bit, out);
        }
        POp::Cmpxchg { addr, src, .. } => {
            collect_pvar_regs(addr, out);
            collect_pvar_regs(src, out);
            out.push("rax");
        }
        POp::AddrOf { base, index, .. } => {
            if let Some(b) = base {
                collect_pvar_regs(b, out);
            }
            if let Some(i) = index {
                collect_pvar_regs(i, out);
            }
        }
        POp::BranchInd { target } => collect_pvar_regs(target, out),
        POp::CallInd { target } => {
            collect_pvar_regs(target, out);
            push_call_regs(out);
        }
        POp::Call { .. } => push_call_regs(out),
        POp::Return | POp::ReturnPop { .. } => {
            out.extend_from_slice(&["rax", "rbp", "rsp", "eax", "ebp", "esp", "xmm0"]);
        }
        _ => {}
    }
}

pub(crate) fn reads_regs(op: &POp) -> Vec<&'static str> {
    let mut out = Vec::with_capacity(8);
    reads_regs_into(op, &mut out);
    out
}

pub(crate) fn written_reg(op: &POp) -> Option<&'static str> {
    let dst = match op {
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
        | POp::AddrOf { dst, .. }
        | POp::CondCopy { dst, .. }
        | POp::BitModify { dst, .. }
        | POp::Cvt { dst, .. }
        | POp::FloatBinop { dst, .. } => dst,
        POp::Cmpxchg { .. } => return Some("rax"),
        _ => return None,
    };
    match dst {
        PVar::Reg(r) => Some(*r),
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
    let (sym, size, a, b) = match op {
        POp::IntAdd { a, b, size, .. } => ("+", *size, a, b),
        POp::IntMul { a, b, size, .. } => ("*", *size, a, b),
        POp::IntAnd { a, b, size, .. } => ("&", *size, a, b),
        POp::IntOr { a, b, size, .. } => ("|", *size, a, b),
        POp::IntXor { a, b, size, .. } => ("^", *size, a, b),
        POp::IntSub { a, b, size, .. } => ("-", *size, a, b),
        _ => return None,
    };
    written_reg(op)?;
    let mut pa = pval_str(&resolve_pval(a, reg_values));
    let mut pb = pval_str(&resolve_pval(b, reg_values));
    if sym != "-" && pa > pb {
        std::mem::swap(&mut pa, &mut pb);
    }
    let mut oregs = Vec::with_capacity(4);
    collect_pvar_regs(a, &mut oregs);
    collect_pvar_regs(b, &mut oregs);
    oregs.sort_unstable();
    oregs.dedup();
    Some((format!("{}|{}|{}|{}", sym, size, pa, pb), oregs))
}

pub(crate) fn cse_invalidate(
    cse: &mut HashMap<String, (&'static str, Vec<&'static str>)>,
    w: &str,
) {
    cse.retain(|_, (holder, oregs)| *holder != w && !oregs.contains(&w));
}

pub(crate) fn clobber_call(reg_values: &mut HashMap<&'static str, PVal>, _is64: bool) {
    for r in CALL_CLOBBERED.iter().chain(SSE_ARG_REGS.iter()) {
        reg_values.remove(*r);
    }
    if reg_values.is_empty() {
        return;
    }
    for (k, v) in reg_values.iter_mut() {
        if CALL_CLOBBERED
            .iter()
            .chain(SSE_ARG_REGS.iter())
            .any(|r| mentions_reg(v, r))
        {
            *v = PVal::Opaque(k);
        }
    }
}

pub(crate) fn collect_call_args(
    reg_values: &HashMap<&'static str, PVal>,
    is64: bool,
    is_win64: bool,
) -> Vec<String> {
    if !is64 {
        return Vec::new();
    }
    let regs: &[&str] = if is_win64 {
        &WIN64_ARG_REGS
    } else {
        &ABI_ARG_REGS
    };
    let mut args: Vec<String> = Vec::with_capacity(regs.len());
    let mut known = 0usize;
    for (i, r) in regs.iter().enumerate() {
        let s = match reg_values.get(*r) {
            Some(v) => {
                let s = pval_str(v);
                if s != *r || matches!(v, PVal::Opaque(_)) {
                    known = i + 1;
                }
                s
            }
            None => (*r).to_string(),
        };
        args.push(s);
    }
    args.truncate(known);
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
        let mut args = take_call_args(reg_values, is64, is_win64, push_args);
        if !params.is_empty() {
            args.truncate(params.len());
        }
        return args;
    }
    push_args.clear();
    let mut out = Vec::with_capacity(params.len());
    let (mut gp, mut sse) = (0usize, 0usize);
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
        out.push(
            reg_values
                .get(reg)
                .map(pval_str)
                .unwrap_or_else(|| reg.to_string()),
        );
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
        return push_args.drain(..).rev().map(|v| pval_str(&v)).collect();
    }
    push_args.clear();
    collect_call_args(reg_values, is64, is_win64)
}

pub(crate) fn struct_member_expr(
    base: &PVar,
    off: i64,
    size: usize,
    base_text: &str,
    hints: Option<&TypeHints>,
) -> Option<String> {
    let hints = hints?;
    let PVar::Reg(r) = base else {
        return None;
    };
    if base_text.contains(['+', '-']) {
        return None;
    }
    let (st, display) = match hints.value_structs.get(base_text) {
        Some(st) => (
            st,
            st.owner.clone().unwrap_or_else(|| base_text.to_string()),
        ),
        None => (hints.structs.get(*r)?, base_text.to_string()),
    };
    let field = st.field_sized(off, size)?;
    if field.starts_with("field_0x") {
        return None;
    }
    Some(format!("{}->{}", display, field))
}

#[inline]
fn stack_key(base: &StackBase, off: i64, h: &TypeHints) -> (u8, i64) {
    if *base == StackBase::Rbp {
        (0, off + h.rbp_delta)
    } else {
        (1, off + h.rsp_at.get(&h.cur_pc.get()).copied().unwrap_or(0))
    }
}

fn stack_var_name(h: &TypeHints, b: u8, off: i64) -> String {
    let pc = h.cur_pc.get();
    h.var_names
        .as_ref()
        .and_then(|vn| {
            vn.read_stack
                .get(&(pc, b, off))
                .or_else(|| vn.write_stack.get(&(pc, b, off)))
                .or_else(|| vn.stack_by_raw.get(&(b, off)))
        })
        .cloned()
        .unwrap_or_else(|| fallback_slot_name(off, h))
}

fn subst_reg(v: &PVar, reg_values: &HashMap<&'static str, PVal>) -> String {
    let s = fmt_var(v);
    match reg_values.get(s.as_str()) {
        Some(pv) => pval_str(pv),
        None => s,
    }
}

fn is_compound(s: &str) -> bool {
    let mut depth = 0i32;
    for (i, c) in s.bytes().enumerate() {
        match c {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'*' | b'-' | b'&' | b'!' | b'~' if i == 0 => {}
            b' ' | b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' | b'<' | b'>' | b'?'
                if depth == 0 =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn paren(s: &str) -> std::borrow::Cow<'_, str> {
    if is_compound(s) {
        std::borrow::Cow::Owned(format!("({})", s))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

fn deref_disp(ty: &str, base: &str, disp: i64) -> String {
    match disp {
        0 => format!("*({} *){}", ty, paren(base)),
        d if d > 0 => format!("*({} *)({} + {:#x})", ty, base, d),
        d => format!("*({} *)({} - {:#x})", ty, base, d.unsigned_abs()),
    }
}

fn fmt_plain_deref(inner: &str, disp: i64) -> String {
    match disp {
        0 => format!("*({})", inner),
        d if d > 0 => format!("*({} + {:#x})", inner, d),
        d => format!("*({} - {:#x})", inner, d.unsigned_abs()),
    }
}

pub(crate) fn fmt_load(
    addr: &PVar,
    size: u32,
    reg_values: &HashMap<&'static str, PVal>,
    float_hint: Option<bool>,
    hints: Option<&TypeHints>,
) -> String {
    let ty: &str = match float_hint {
        Some(true) if size == 8 => "double",
        Some(true) => "float",
        _ => c_type_for_size(size),
    };
    let usz = size as usize;
    match addr {
        PVar::StackSlot { base, off } => {
            let Some(h) = hints else {
                return format!("*({0} *)&{1}", ty, fmt_var(addr));
            };
            let (b, norm) = stack_key(base, *off, h);
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
                let field = st.fields.iter().find(|(o, fs, _)| *o == rel && *fs == usz);
                if st.is_union
                    && let Some((_, _, fname)) = field
                {
                    return format!("{}.{}", base_name, fname);
                }
                if norm == st.base_norm && usz >= st.size {
                    return base_name;
                }
                if let Some((_, _, fname)) = field {
                    return format!("{}.{}", base_name, fname);
                }
            }
            if let Some((name, local_size)) = h.stack_names.get(&norm)
                && *local_size == usz
            {
                return name.clone();
            }
            let name = stack_var_name(h, b, *off);
            if h.var_names
                .as_ref()
                .is_some_and(|vn| vn.size_of.get(&name).copied() == Some(size))
            {
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
            if let Some(m) = struct_member_expr(addr, 0, usz, &base, hints) {
                return m;
            }
            format!("*({} *){}", ty, paren(&base))
        }
        PVar::Mem(base, disp) => {
            let b = subst_reg(base, reg_values);
            if let Some(m) = struct_member_expr(base, *disp, usz, &b, hints) {
                return m;
            }
            deref_disp(ty, &b, *disp)
        }
        PVar::Scaled {
            base,
            index,
            scale,
            disp,
        } => {
            let b = subst_reg(base, reg_values);
            let i = subst_reg(index, reg_values);
            let inner = if *scale == 1 {
                format!("{} + {}", b, i)
            } else {
                format!("{} + {} * {}", b, paren(&i), scale)
            };
            deref_disp(ty, &inner, *disp)
        }
        other => format!("*({} *){}", ty, paren(&fmt_var(other))),
    }
}

pub(crate) fn fallback_slot_name(off: i64, hints: &TypeHints) -> String {
    if off < 0 {
        return format!("local_{:X}", off.unsigned_abs());
    }
    let spill = hints.spill_slots.contains(&off);
    let local = hints.local_slots.contains(&off);
    match (spill, local) {
        (true, false) => format!("stk_{:X}", off),
        (_, true) => format!("local_{:X}", off),
        _ if hints.param_slots.contains(&off) => format!("param_{:X}", off),
        _ => format!("arg_{:X}", off),
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
        PVar::Mem(base, disp) => fmt_plain_deref(&fmt_var(base), *disp),
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
            fmt_plain_deref(&inner, *disp)
        }
        PVar::Addr(a) if is_small_abs_addr(*a) || is_shift_constant(*a) => fmt_const(*a as i64),
        PVar::Addr(a) => format!("DAT_{:x}", a),
        PVar::Tmp(i) => format!("tmp_{}", i),
    }
}

pub(crate) fn fmt_var_with_hints(v: &PVar, hints: &TypeHints) -> String {
    match v {
        PVar::StackSlot { base, off } => {
            let (b, norm) = stack_key(base, *off, hints);
            if let Some((name, _size)) = hints.stack_names.get(&norm) {
                return name.clone();
            }
            stack_var_name(hints, b, *off)
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
        other => PVal::E(fmt_var_with_hints(other, hints)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlagSrc {
    None,
    Cmp,
    Float,
    Bit,
    Setter,
    AhMask,
}

fn is_cond_jump(m: &str) -> bool {
    m.starts_with('j') && !matches!(m, "jmp" | "jecxz" | "jrcxz" | "jcxz")
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
    let Some(ops) = bops.get(block_id) else {
        return "cond".into();
    };

    let cv = |v: &PVar| -> String {
        if let PVar::Reg(r) = v
            && let Some(Lattice::Const(c)) = consts.get(r)
        {
            return fmt_const(*c);
        }
        match hints {
            Some(h) => fmt_var_with_hints(v, h),
            None => fmt_var(v),
        }
    };

    let mut cmp_pair: Option<(&PVar, &PVar, bool)> = None;
    let mut cmp_size: u32 = 8;
    let mut float_cmp_pair: Option<(&PVar, &PVar)> = None;
    let mut bit_test: Option<(&PVar, &PVar)> = None;
    let mut flag_setter: Option<(&'static str, &PVar, &PVar, &PVar)> = None;
    let mut jcc = String::new();
    let mut ah_test_mask: Option<i64> = None;
    let mut last = FlagSrc::None;
    let mut ops_since_sub: usize = usize::MAX;
    let mut cmp_follows_sub = false;

    for &(addr, op) in ops {
        let di = imap_get(imap, addr);
        if let Some(d) = di {
            let m = d.mnem();
            if is_cond_jump(m) {
                jcc = m.to_string();
                break;
            }
            if m == "lahf" || m == "sahf" {
                continue;
            }
        }
        match op {
            POp::Cmp { a, b, size } => {
                cmp_pair = Some((a, b, false));
                cmp_size = *size;
                cmp_follows_sub = ops_since_sub <= 1;
                last = FlagSrc::Cmp;
            }
            POp::Test { a, b, size } => {
                cmp_size = *size;
                cmp_follows_sub = ops_since_sub <= 1;
                let is_ah = matches!(a, PVar::Reg(_))
                    && di.is_some_and(|d| {
                        d.ops()
                            .as_bytes()
                            .get(..2)
                            .is_some_and(|p| p.eq_ignore_ascii_case(b"ah"))
                    });
                if is_ah {
                    if float_cmp_pair.is_some()
                        && let PVar::Const(mask) = b
                    {
                        ah_test_mask = Some(*mask);
                        last = FlagSrc::AhMask;
                    }
                } else {
                    cmp_pair = Some((a, b, true));
                    last = FlagSrc::Cmp;
                }
            }
            POp::FloatCmp { a, b, .. } => {
                float_cmp_pair = Some((a, b));
                ah_test_mask = None;
                last = FlagSrc::Float;
            }
            POp::BitTest { a, b, .. } => {
                bit_test = Some((a, b));
                last = FlagSrc::Bit;
            }
            POp::IntAdd { dst, a, b, .. } => {
                flag_setter = Some(("add", a, b, dst));
                last = FlagSrc::Setter;
            }
            POp::IntSub { dst, a, b, .. } => {
                flag_setter = Some(("sub", a, b, dst));
                last = FlagSrc::Setter;
            }
            POp::IntAnd { dst, a, b, .. } => {
                flag_setter = Some(("and", a, b, dst));
                last = FlagSrc::Setter;
            }
            POp::IntOr { dst, a, b, .. } => {
                flag_setter = Some(("or", a, b, dst));
                last = FlagSrc::Setter;
            }
            POp::IntXor { dst, a, b, .. } => {
                flag_setter = Some(("xor", a, b, dst));
                last = FlagSrc::Setter;
            }
            POp::IntLeft { dst, a, b, .. } => {
                flag_setter = Some(("shl", a, b, dst));
                last = FlagSrc::Setter;
            }
            POp::IntShr { dst, a, b, .. } => {
                flag_setter = Some(("shr", a, b, dst));
                last = FlagSrc::Setter;
            }
            POp::IntSar { dst, a, b, .. } => {
                flag_setter = Some(("sar", a, b, dst));
                last = FlagSrc::Setter;
            }
            _ => {}
        }
        ops_since_sub = if matches!(op, POp::IntSub { .. }) {
            0
        } else {
            ops_since_sub.saturating_add(1)
        };
    }

    let has_jcc = !jcc.is_empty();
    let jcc = jcc.as_str();

    match last {
        FlagSrc::AhMask if has_jcc => {
            if let (Some(mask), Some((fa, fb))) = (ah_test_mask, float_cmp_pair) {
                return float_cc_via_mask(jcc, mask, &cv(fa), &cv(fb));
            }
        }
        FlagSrc::Bit => {
            if let Some((a, b)) = bit_test {
                let expr = format!("(({} >> {}) & 1)", cv(a), cv(b));
                return match jcc {
                    "jc" | "jb" | "jnae" => format!("{} != 0", expr),
                    "jnc" | "jae" | "jnb" => format!("{} == 0", expr),
                    _ => "cond".into(),
                };
            }
        }
        FlagSrc::Cmp => {
            if let Some((a, b, is_test)) = cmp_pair {
                if !has_jcc {
                    return "cond".into();
                }
                if let Some((kind, fa, fb, dst)) = flag_setter
                    && kind == "sub"
                    && cmp_follows_sub
                    && cmp_tests_flag_result(a, b, is_test, &fmt_var(dst))
                    && let Some(cond) =
                        flag_condition(kind, &cv(fa), &cv(fb), jcc, cmp_size, is_test)
                {
                    return cond;
                }
                return jcc_to_expr(jcc, &cv(a), &cv(b), is_test, cmp_size);
            }
        }
        FlagSrc::Float => {
            if let Some((a, b)) = float_cmp_pair {
                let (av, bv) = (cv(a), cv(b));
                return match jcc {
                    "je" | "jz" => format!("{av} == {bv}"),
                    "jne" | "jnz" => format!("{av} != {bv}"),
                    "ja" | "jnbe" => format!("{av} > {bv}"),
                    "jae" | "jnb" | "jnc" => format!("{av} >= {bv}"),
                    "jb" | "jnae" | "jc" => format!("{av} < {bv}"),
                    "jbe" | "jna" => format!("{av} <= {bv}"),
                    "jp" | "jpe" => format!("isnan({av}) || isnan({bv})"),
                    "jnp" | "jpo" => format!("!isnan({av}) && !isnan({bv})"),
                    _ => "cond".into(),
                };
            }
        }
        FlagSrc::Setter => {
            if let Some((kind, a, b, dst)) = flag_setter {
                let expr = match kind {
                    "add" => format!("({} + {})", cv(a), cv(b)),
                    "sub" => format!("({} - {})", cv(a), cv(b)),
                    "and" => format!("({} & {})", cv(a), cv(b)),
                    "or" => format!("({} | {})", cv(a), cv(b)),
                    "xor" => format!("({} ^ {})", cv(a), cv(b)),
                    _ => cv(dst),
                };
                let cond = match kind {
                    "and" | "or" | "xor" => logic_result_cond(jcc, &expr),
                    "shl" | "shr" | "sar" => match jcc {
                        "jz" | "je" | "jnz" | "jne" | "js" | "jns" | "jl" | "jnge" | "jle"
                        | "jng" | "jg" | "jnle" | "jge" | "jnl" => result_cond(jcc, &expr),
                        _ => "cond".into(),
                    },
                    _ => result_cond(jcc, &expr),
                };
                if cond != "cond" {
                    return cond;
                }
            }
        }
        _ => {}
    }

    if has_jcc {
        jcc_only_expr(jcc)
    } else {
        "cond".into()
    }
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
            let cond = logic_result_cond(jcc, &format!("({} {} {})", a, op, b));
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
    const AH: [i64; 4] = [0x00, 0x01, 0x40, 0x45];
    let mut taken = 0u8;
    for (i, ah) in AH.iter().enumerate() {
        let v = (*ah & mask) & 0xff;
        let zf = v == 0;
        let pf = v.count_ones().is_multiple_of(2);
        let hit = match jcc {
            "je" | "jz" | "jbe" | "jna" | "jle" | "jng" => zf,
            "jne" | "jnz" | "ja" | "jnbe" | "jg" | "jnle" => !zf,
            "jp" | "jpe" => pf,
            "jnp" | "jpo" => !pf,
            "jb" | "jnae" | "jc" | "jl" | "jnge" | "js" | "jo" => false,
            "jae" | "jnb" | "jnc" | "jge" | "jnl" | "jns" | "jno" => true,
            _ => return "cond".into(),
        };
        taken |= (hit as u8) << i;
    }
    match taken {
        0b0001 => format!("{a} > {b}"),
        0b0010 => format!("{a} < {b}"),
        0b0100 => format!("{a} == {b}"),
        0b0101 => format!("{a} >= {b}"),
        0b0110 => format!("{a} <= {b}"),
        0b0011 => format!("({a} < {b} || {a} > {b})"),
        0b1011 => format!("{a} != {b}"),
        0b1100 => format!("{a} == {b}"),
        0b1110 => format!("!({a} > {b})"),
        0b1101 => format!("!({a} < {b})"),
        0b1010 => format!("!({a} >= {b})"),
        0b1001 => format!("!({a} <= {b})"),
        0b1000 => format!("isnan({a}) || isnan({b})"),
        0b0111 => format!("!isnan({a}) && !isnan({b})"),
        _ => "cond".into(),
    }
}

pub(crate) fn logic_result_cond(jcc: &str, expr: &str) -> String {
    match jcc {
        "jz" | "je" | "jbe" | "jna" => format!("{} == 0", expr),
        "jnz" | "jne" | "ja" | "jnbe" => format!("{} != 0", expr),
        "js" | "jl" | "jnge" => format!("{} < 0", expr),
        "jns" | "jge" | "jnl" => format!("{} >= 0", expr),
        "jle" | "jng" => format!("{} <= 0", expr),
        "jg" | "jnle" => format!("{} > 0", expr),
        "jb" | "jnae" | "jc" | "jo" => "0".into(),
        "jae" | "jnb" | "jnc" | "jno" => "1".into(),
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
        let expr = if a == b {
            a.to_string()
        } else {
            format!("({} & {})", a, b)
        };
        let cond = logic_result_cond(jcc, &expr);
        return if cond == "cond" { expr } else { cond };
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
        _ => "cond".into(),
    }
}

pub(crate) fn jcc_only_expr(jcc: &str) -> String {
    let s: &str = match jcc {
        "jz" | "je" => "ZF",
        "jnz" | "jne" => "!ZF",
        "js" => "SF",
        "jns" => "!SF",
        "jc" | "jb" | "jnae" => "CF",
        "jnc" | "jnb" | "jae" => "!CF",
        "jo" => "OF",
        "jno" => "!OF",
        "jp" | "jpe" => "PF",
        "jnp" | "jpo" => "!PF",
        "jbe" | "jna" => "CF || ZF",
        "ja" | "jnbe" => "!CF && !ZF",
        "jl" | "jnge" => "SF != OF",
        "jge" | "jnl" => "SF == OF",
        "jle" | "jng" => "ZF || SF != OF",
        "jg" | "jnle" => "!ZF && SF == OF",
        _ => "cond",
    };
    s.into()
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
        assert_eq!(jcc_to_expr("jb", "a", "b", false, 4), "(uint)a < (uint)b");
        assert_eq!(
            jcc_to_expr("jae", "a", "b", false, 8),
            "(ulonglong)a >= (ulonglong)b"
        );
    }

    #[test]
    fn test_instruction_covers_signed_and_unsigned_jumps() {
        assert_eq!(jcc_to_expr("jg", "x", "x", true, 4), "x > 0");
        assert_eq!(jcc_to_expr("jle", "x", "x", true, 4), "x <= 0");
        assert_eq!(jcc_to_expr("jl", "a", "b", true, 4), "(a & b) < 0");
        assert_eq!(jcc_to_expr("ja", "x", "x", true, 4), "x != 0");
    }

    #[test]
    fn x87_status_word_masks() {
        assert_eq!(float_cc_via_mask("je", 0x45, "a", "b"), "a > b");
        assert_eq!(float_cc_via_mask("jne", 0x41, "a", "b"), "!(a > b)");
        assert_eq!(float_cc_via_mask("jne", 0x40, "a", "b"), "a == b");
        assert_eq!(float_cc_via_mask("jp", 0x44, "a", "b"), "a != b");
    }

    #[test]
    fn deref_parenthesises_compound_bases_and_survives_min_disp() {
        assert_eq!(deref_disp("int", "rax", 0), "*(int *)rax");
        assert_eq!(deref_disp("int", "rax + rcx", 0), "*(int *)(rax + rcx)");
        assert_eq!(deref_disp("int", "rax", -8), "*(int *)(rax - 0x8)");
        let _ = deref_disp("int", "rax", i64::MIN);
    }

    #[test]
    fn jcc_only_covers_unsigned_and_signed() {
        assert_eq!(jcc_only_expr("jbe"), "CF || ZF");
        assert_eq!(jcc_only_expr("jg"), "!ZF && SF == OF");
    }

    #[test]
    fn call_args_keep_positions_for_missing_registers() {
        let mut regs: HashMap<&'static str, PVal> = HashMap::default();
        regs.insert("rdi", PVal::C(1));
        regs.insert("rdx", PVal::C(3));
        assert_eq!(collect_call_args(&regs, true, false), vec!["1", "rsi", "3"]);
    }
}
