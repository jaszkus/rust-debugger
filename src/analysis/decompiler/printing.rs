pub mod conditions;

pub(crate) use conditions::*;

use super::expr;
use super::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

pub(crate) const ABI_ARG_REGS: [&str; 6] = ["rcx", "rdx", "r8", "r9", "rdi", "rsi"];

#[derive(Debug, Clone)]
pub(crate) enum PVal {
    C(i64),
    E(String),
    X(crate::analysis::expr::Expr),
    Opaque(&'static str),
}

pub(crate) fn rewrite_x86_reg_names(text: &str, map: &[(&str, &str)]) -> String {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        let rest = &text[i..];
        let mut hit: Option<(&str, &str)> = None;
        for m in map {
            if let Some(suffix) = rest.strip_prefix(m.0) {
                let before_ok = i == 0 || !is_word(text[..i].chars().last().unwrap());
                let after_ok = suffix.chars().next().is_none_or(|c| !is_word(c));
                if before_ok && after_ok {
                    hit = Some(*m);
                    break;
                }
            }
        }
        match hit {
            Some((from, to)) => {
                out.push_str(to);
                i += from.len();
            }
            None => {
                let c = rest.chars().next().unwrap();
                out.push(c);
                i += c.len_utf8();
            }
        }
    }
    out
}

pub(crate) fn pval_str(v: &PVal) -> String {
    match v {
        PVal::C(c) => fmt_const(*c),
        PVal::E(s) => s.clone(),
        PVal::X(e) => e.render(),
        PVal::Opaque(r) => r.to_string(),
    }
}

pub(crate) fn fmt_const(c: i64) -> String {
    if c < 0 {
        match c.checked_neg() {
            Some(pos) if pos > 9 => format!("-{:#x}", pos),
            Some(pos) => format!("-{}", pos),
            None => "(-0x8000000000000000)".into(),
        }
    } else if c > 9 {
        format!("{:#x}", c)
    } else {
        format!("{}", c)
    }
}

pub(crate) fn resolve_pval(v: &PVar, reg_values: &HashMap<&'static str, PVal>) -> PVal {
    match v {
        PVar::Reg(r) => reg_values
            .get(r)
            .cloned()
            .unwrap_or_else(|| PVal::E(r.to_string())),
        PVar::Const(c) => PVal::C(*c),
        other => PVal::E(fmt_var(other)),
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StructHint {
    pub(crate) fields: Vec<(i64, String)>,
    
    
    
    pub(crate) owner: Option<String>,
}

impl StructHint {
    pub(crate) fn field(&self, off: i64) -> Option<&str> {
        self.fields
            .iter()
            .find(|(o, _)| *o == off)
            .map(|(_, n)| n.as_str())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StackStructHint {
    pub(crate) base_reg: u8,
    pub(crate) base: i64,
    pub(crate) size: usize,
    
    pub(crate) fields: Vec<(i64, usize, String)>,
}

#[derive(Default)]
pub(crate) struct TypeHints {
    pub(crate) floats: HashSet<String>,
    pub(crate) float_slots: HashSet<i64>,
    pub(crate) spill_slots: HashSet<i64>,
    pub(crate) local_slots: HashSet<i64>,
    pub(crate) param_slots: HashSet<i64>,
    pub(crate) imports: HashMap<u64, String>,
    pub(crate) structs: HashMap<String, StructHint>,
    pub(crate) value_structs: HashMap<String, StructHint>,
    pub(crate) stack_structs: Vec<StackStructHint>,
    pub(crate) local_types: HashMap<String, String>,
    pub(crate) last_cmp: std::cell::RefCell<Option<(String, String, bool)>>,
    pub(crate) out_bytes: std::cell::Cell<usize>,
    pub(crate) out_truncated: std::cell::Cell<bool>,
    pub(crate) cur_pc: std::cell::Cell<u64>,
    pub(crate) var_names: Option<std::sync::Arc<crate::analysis::flow::variables::VarNames>>,
}

pub(crate) fn render_op(
    op: &POp,
    addr: u64,
    func_lookup: &HashMap<u64, String>,
    reg_values: &mut HashMap<&'static str, PVal>,
    is64: bool,
    hints: &TypeHints,
    push_args: &mut Vec<PVal>,
) -> Option<(String, LineKind)> {
    hints.cur_pc.set(addr);
    match op {
        POp::Push { .. }
        | POp::Pop { .. }
        | POp::Call { .. }
        | POp::CallInd { .. }
        | POp::CallOther { .. }
        | POp::Return
        | POp::ReturnPop { .. } => {}
        _ => {
            if matches!(written_reg(op), Some("rsp") | Some("esp")) {
                push_args.clear();
            }
        }
    }
    match op {
        POp::Copy { dst, src, .. } => {
            let v = resolve_pval_with_hints(src, reg_values, hints);
            track(reg_values, dst, v.clone());
            Some((
                format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
                LineKind::Assignment,
            ))
        }
        POp::IntAdd { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "+", hints),
        POp::IntSub { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "-", hints),
        POp::IntMul { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "*", hints),
        POp::IntDiv { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "/", hints),
        POp::IntSDiv { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "/", hints),
        POp::IntAnd { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "&", hints),
        POp::IntOr { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "|", hints),
        POp::IntXor { dst, a, b, .. } => {
            let av = resolve_pval_with_hints(a, reg_values, hints);
            let bv = resolve_pval_with_hints(b, reg_values, hints);
            let v = match (&av, &bv) {
                (PVal::C(x), PVal::C(y)) => PVal::C(x ^ y),
                _ => match expr::Expr::from_sym("^", pval_to_expr(&av), pval_to_expr(&bv)) {
                    Some(tree) => PVal::X(tree.simplify()),
                    None => PVal::E(format!("{} ^ {}", pval_str(&av), pval_str(&bv))),
                },
            };
            track(reg_values, dst, v.clone());
            Some((
                format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
                LineKind::Assignment,
            ))
        }
        POp::IntLeft { dst, a, b, .. } => binop_render(reg_values, dst, a, b, "<<", hints),
        POp::IntShr { dst, a, b, .. } => binop_render(reg_values, dst, a, b, ">>", hints),
        POp::IntSar { dst, a, b, .. } => binop_render(reg_values, dst, a, b, ">>", hints),
        POp::Zext {
            dst,
            src,
            from_size,
            to_size,
        } => {
            let v = resolve_pval_with_hints(src, reg_values, hints);
            track(reg_values, dst, v.clone());
            if from_size == to_size {
                Some((
                    format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
                    LineKind::Assignment,
                ))
            } else {
                Some((
                    format!(
                        "{} = {};  // zero-extend",
                        fmt_var_with_hints(dst, hints),
                        pval_str(&v)
                    ),
                    LineKind::Assignment,
                ))
            }
        }
        POp::Sext {
            dst,
            src,
            from_size,
            to_size,
        } => {
            let v = resolve_pval_with_hints(src, reg_values, hints);
            track(reg_values, dst, v.clone());
            if from_size == to_size {
                Some((
                    format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
                    LineKind::Assignment,
                ))
            } else {
                Some((
                    format!(
                        "{} = {};  // sign-extend",
                        fmt_var_with_hints(dst, hints),
                        pval_str(&v)
                    ),
                    LineKind::Assignment,
                ))
            }
        }
        POp::Load { dst, addr, size } => {
            let is_f = hints.floats.contains(&fmt_var(dst))
                || matches!(addr, PVar::StackSlot { off: o, .. } if hints.float_slots.contains(o));
            let v = fmt_load(addr, *size, reg_values, Some(is_f), Some(hints));
            track(reg_values, dst, PVal::E(v.clone()));
            Some((format!("{} = {};", fmt_var(dst), v), LineKind::Assignment))
        }
        POp::Store { addr, src, size } => {
            let src_f = hints.floats.contains(&fmt_var(src));
            let slot_f =
                matches!(addr, PVar::StackSlot { off: o, .. } if hints.float_slots.contains(o));
            let v = fmt_load(addr, *size, reg_values, Some(src_f || slot_f), Some(hints));
            Some((
                format!(
                    "{} = {};",
                    v,
                    pval_str(&resolve_pval_with_hints(src, reg_values, hints))
                ),
                LineKind::Assignment,
            ))
        }
        POp::LeaAddr { dst, addr } => {
            let v = format!("&DAT_{:X}", addr);
            track(reg_values, dst, PVal::E(v.clone()));
            Some((format!("{} = {};", fmt_var(dst), v), LineKind::Assignment))
        }
        POp::AddrOf {
            dst,
            base,
            index,
            scale,
            disp,
        } => {
            let mut parts = Vec::new();
            if let Some(b) = base {
                parts.push(pval_str(&resolve_pval_with_hints(b, reg_values, hints)));
            }
            if let Some(idx) = index {
                if *scale > 1 {
                    parts.push(format!(
                        "{} * {}",
                        pval_str(&resolve_pval_with_hints(idx, reg_values, hints)),
                        scale
                    ));
                } else {
                    parts.push(pval_str(&resolve_pval_with_hints(idx, reg_values, hints)));
                }
            }
            let mut expr = parts.join(" + ");
            if *disp > 0 {
                if expr.is_empty() {
                    expr = format!("0x{:x}", disp);
                } else {
                    expr = format!("{} + {:#x}", expr, disp);
                }
            } else if *disp < 0 {
                if expr.is_empty() {
                    expr = format!("-{:#x}", -disp);
                } else {
                    expr = format!("{} - {:#x}", expr, -disp);
                }
            }
            if expr.is_empty() {
                expr = "0".into();
            }
            let v = format!("({})", expr);
            track(reg_values, dst, PVal::E(v.clone()));
            Some((
                format!("{} = {};", fmt_var_with_hints(dst, hints), v),
                LineKind::Assignment,
            ))
        }
        POp::Push { src, .. } => {
            let v = resolve_pval_with_hints(src, reg_values, hints);
            push_args.push(v.clone());
            Some((format!("// push {}", pval_str(&v)), LineKind::Comment))
        }
        POp::Pop { dst, .. } => {
            push_args.pop();
            Some((
                format!("// pop {}", fmt_var_with_hints(dst, hints)),
                LineKind::Comment,
            ))
        }
        POp::Call { target } => {
            let name = func_lookup
                .get(target)
                .cloned()
                .unwrap_or_else(|| format!("FUN_{:X}", target));
            let args = take_call_args(reg_values, is64, push_args);
            let line = if args.is_empty() {
                format!("{}();", name)
            } else {
                format!("{}({});", name, args.join(", "))
            };
            clobber_call(reg_values, is64);
            Some((line, LineKind::Call))
        }
        POp::CallInd { target } => {
            let args = take_call_args(reg_values, is64, push_args);
            let import_name = match target {
                PVar::Addr(a) => hints.imports.get(a).cloned(),
                _ => None,
            };
            let line = if let Some(name) = import_name {
                if args.is_empty() {
                    format!("{}();", name)
                } else {
                    format!("{}({});", name, args.join(", "))
                }
            } else {
                let t = resolve_pval(target, reg_values);
                let ts = pval_str(&t);
                let mut line = if args.is_empty() {
                    format!("(*{})();", ts)
                } else {
                    format!("(*{})({});", ts, args.join(", "))
                };
                if ts.starts_with("*(") || ts.contains(" + 0x") {
                    line.push_str("  // virtual call via vtable");
                }
                line
            };
            clobber_call(reg_values, is64);
            Some((line, LineKind::Call))
        }
        POp::Return | POp::ReturnPop { .. } => {
            let ret_val = match reg_values.get("rax") {
                Some(PVal::Opaque(r)) => r.to_string(),
                other => other
                    .map(pval_str)
                    .filter(|v| v != "rax")
                    .unwrap_or_default(),
            };
            if ret_val.is_empty() {
                Some(("return;".into(), LineKind::Return))
            } else {
                Some((format!("return {};", ret_val), LineKind::Return))
            }
        }
        POp::Cmp { a, b, .. } => {
            let av = pval_str(&resolve_pval_with_hints(a, reg_values, hints));
            let bv = pval_str(&resolve_pval_with_hints(b, reg_values, hints));
            *hints.last_cmp.borrow_mut() = Some((av, bv, false));
            None
        }
        POp::Test { a, b, .. } => {
            let av = pval_str(&resolve_pval_with_hints(a, reg_values, hints));
            let bv = pval_str(&resolve_pval_with_hints(b, reg_values, hints));
            *hints.last_cmp.borrow_mut() = Some((av, bv, true));
            None
        }
        POp::FloatCmp { .. } => {
            *hints.last_cmp.borrow_mut() = None;
            None
        }
        POp::BitTest { .. } => None,
        POp::CondCopy { dst, src, cond, .. } => {
            let cond_expr = hints
                .last_cmp
                .borrow()
                .as_ref()
                .map(|(a, b, is_test)| jcc_to_expr(&format!("j{}", cond), a, b, *is_test))
                .unwrap_or_else(|| format!("({})", cond));
            let sv = pval_str(&resolve_pval_with_hints(src, reg_values, hints));
            let dv = fmt_var_with_hints(dst, hints);
            let v = format!("({}) ? {} : {}", cond_expr, sv, dv);
            track(reg_values, dst, PVal::E(v.clone()));
            Some((format!("{} = {};", dv, v), LineKind::Assignment))
        }
        POp::BitModify { dst, bit, kind, .. } => {
            let dv = fmt_var_with_hints(dst, hints);
            let bv = pval_str(&resolve_pval_with_hints(bit, reg_values, hints));
            let one = format!("(1 << {})", bv);
            let v = match kind.as_str() {
                "set" => format!("{} | {}", dv, one),
                "reset" => format!("{} & ~{}", dv, one),
                _ => format!("{} ^ {}", dv, one),
            };
            if matches!(dst, PVar::Reg(_)) {
                track(reg_values, dst, PVal::E(v.clone()));
            }
            Some((format!("{} = {};", dv, v), LineKind::Assignment))
        }
        POp::Cmpxchg { addr, src, size } => {
            let mem = fmt_load(addr, *size, reg_values, None, Some(hints));
            let sv = pval_str(&resolve_pval_with_hints(src, reg_values, hints));
            let call = format!("atomic_cmpxchg(&{}, {})", mem, sv);
            let rax = PVar::Reg("rax");
            track(reg_values, &rax, PVal::E(call.clone()));
            Some((
                format!("rax = {};  // returns the old value", call),
                LineKind::Assignment,
            ))
        }
        POp::Opaque(text) => Some((format!("// {}", text), LineKind::Comment)),
        POp::Branch { .. } => None,
        POp::BranchInd { target } => Some((
            format!(
                "goto *{};",
                pval_str(&resolve_pval_with_hints(target, reg_values, hints))
            ),
            LineKind::Branch,
        )),
        POp::CBranch { .. } => None,
        POp::SetCC { dst, cond, .. } => {
            let v = format!("({}) ? 1 : 0", cond);
            track(reg_values, dst, PVal::E(v.clone()));
            Some((format!("{} = {};", fmt_var(dst), v), LineKind::Assignment))
        }
        POp::FloatBinop {
            kind, dst, a, b, ..
        } => {
            let sym = match kind.as_str() {
                "add" => "+",
                "sub" => "-",
                "mul" => "*",
                "div" => "/",
                _ => "?",
            };
            binop_render(reg_values, dst, a, b, sym, hints)
        }
        POp::Cvt { kind, dst, src } => {
            let sv = resolve_pval_with_hints(src, reg_values, hints);
            let f = match kind.as_str() {
                "f2i" => format!("(int)({})", pval_str(&sv)),
                "i2f" => format!("(float)({})", pval_str(&sv)),
                "f2f" => format!("(float)(double)({})", pval_str(&sv)),
                _ => pval_str(&sv),
            };
            let v = PVal::E(f);
            track(reg_values, dst, v.clone());
            Some((
                format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
                LineKind::Assignment,
            ))
        }
        POp::Nop => None,
        POp::SegmentOp {
            dst,
            segment,
            addr,
            size,
            is_store,
        } => {
            let a = match addr {
                PVar::Addr(v) => format!("{:#x}", v),
                _ => pval_str(&resolve_pval(addr, reg_values)),
            };
            if *is_store {
                Some((
                    format!(
                        "*({}:{} + {}) = {};  // TLS/PEB",
                        segment,
                        size * 8,
                        a,
                        fmt_var(dst)
                    ),
                    LineKind::Assignment,
                ))
            } else {
                let v = PVal::E(format!("*({}:{} + {})", segment, size * 8, a));
                track(reg_values, dst, v.clone());
                Some((
                    format!(
                        "{} = {};  // TLS/PEB via {}",
                        fmt_var(dst),
                        pval_str(&v),
                        segment
                    ),
                    LineKind::Assignment,
                ))
            }
        }
        POp::CallOther { name } => {
            let args = take_call_args(reg_values, is64, push_args);
            let line = if args.is_empty() {
                format!("{}();  // trap/syscall", name)
            } else {
                format!("{}({});  // trap/syscall", name, args.join(", "))
            };
            clobber_call(reg_values, is64);
            Some((line, LineKind::Call))
        }
        POp::Rotate {
            dst,
            a,
            b,
            size,
            left,
        } => {
            let op = if *left { "rol" } else { "ror" };
            let av = resolve_pval_with_hints(a, reg_values, hints);
            let bv = resolve_pval_with_hints(b, reg_values, hints);
            let v = PVal::E(format!(
                "{}({}, {}, {})",
                op,
                pval_str(&av),
                pval_str(&bv),
                size * 8
            ));
            track(reg_values, dst, v.clone());
            Some((
                format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
                LineKind::Assignment,
            ))
        }
        POp::Bswap { dst, src, size } => {
            let v = PVal::E(format!(
                "bswap({}, {})",
                pval_str(&resolve_pval_with_hints(src, reg_values, hints)),
                size * 8
            ));
            track(reg_values, dst, v.clone());
            Some((
                format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
                LineKind::Assignment,
            ))
        }
        POp::Unimplemented(text) => Some((format!("\u{1}{}", text), LineKind::Comment)),
    }
}

pub(crate) fn binop_render(
    reg_values: &mut HashMap<&'static str, PVal>,
    dst: &PVar,
    a: &PVar,
    b: &PVar,
    op_sym: &str,
    hints: &TypeHints,
) -> Option<(String, LineKind)> {
    let av = resolve_pval_with_hints(a, reg_values, hints);
    let bv = resolve_pval_with_hints(b, reg_values, hints);
    let v = match (&av, &bv) {
        (PVal::C(x), PVal::C(y)) => fold_const(op_sym, *x, *y),
        _ => match expr::Expr::from_sym(op_sym, pval_to_expr(&av), pval_to_expr(&bv)) {
            Some(tree) => PVal::X(tree.simplify()),
            None => peephole(op_sym, &av, &bv).unwrap_or_else(|| {
                PVal::E(format!("{} {} {}", pval_str(&av), op_sym, pval_str(&bv)))
            }),
        },
    };
    track(reg_values, dst, v.clone());
    Some((
        format!("{} = {};", fmt_var_with_hints(dst, hints), pval_str(&v)),
        LineKind::Assignment,
    ))
}

pub(crate) fn pval_to_expr(v: &PVal) -> expr::Expr {
    match v {
        PVal::C(c) => expr::Expr::c(*c),
        PVal::X(e) => e.clone(),
        PVal::E(s) => expr::Expr::var(s.clone()),
        PVal::Opaque(r) => expr::Expr::var(*r),
    }
}

pub(crate) fn peephole(op: &str, av: &PVal, bv: &PVal) -> Option<PVal> {
    let is_zero = |v: &PVal| matches!(v, PVal::C(0));
    let is_one = |v: &PVal| matches!(v, PVal::C(1));
    let is_neg1 = |v: &PVal| matches!(v, PVal::C(-1));
    let same = pval_str(av) == pval_str(bv);
    let r = match op {
        "+" => {
            if is_zero(bv) {
                av.clone()
            } else if is_zero(av) {
                bv.clone()
            } else {
                return None;
            }
        }
        "-" => {
            if is_zero(bv) {
                av.clone()
            } else if same {
                PVal::C(0)
            } else {
                return None;
            }
        }
        "*" => {
            if is_one(bv) {
                av.clone()
            } else if is_one(av) {
                bv.clone()
            } else if is_zero(bv) || is_zero(av) {
                PVal::C(0)
            } else {
                return None;
            }
        }
        "&" => {
            if is_zero(bv) || is_zero(av) {
                PVal::C(0)
            } else if is_neg1(bv) {
                av.clone()
            } else if is_neg1(av) {
                bv.clone()
            } else if same {
                av.clone()
            } else {
                return None;
            }
        }
        "|" => {
            if is_zero(bv) {
                av.clone()
            } else if is_zero(av) {
                bv.clone()
            } else if is_neg1(bv) || is_neg1(av) {
                PVal::C(-1)
            } else if same {
                av.clone()
            } else {
                return None;
            }
        }
        "^" => {
            if is_zero(bv) {
                av.clone()
            } else if is_zero(av) {
                bv.clone()
            } else if same {
                PVal::C(0)
            } else {
                return None;
            }
        }
        "<<" | ">>" => {
            if is_zero(bv) {
                av.clone()
            } else {
                return None;
            }
        }
        "/" => {
            if is_one(bv) {
                av.clone()
            } else if is_zero(av) {
                PVal::C(0)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(r)
}

pub(crate) fn fold_const(op: &str, x: i64, y: i64) -> PVal {
    let r = match op {
        "+" => x.wrapping_add(y),
        "-" => x.wrapping_sub(y),
        "*" => x.wrapping_mul(y),
        "/" => {
            if y == 0 {
                return PVal::E(format!("{} / {}", fmt_const(x), fmt_const(y)));
            }
            x.wrapping_div(y)
        }
        "&" => x & y,
        "|" => x | y,
        "<<" => x.wrapping_shl((y as u32) & 63),
        ">>" => ((x as u64).wrapping_shr((y as u32) & 63)) as i64,
        _ => return PVal::E(format!("{} {} {}", fmt_const(x), op, fmt_const(y))),
    };
    PVal::C(r)
}

pub(crate) fn track(reg_values: &mut HashMap<&'static str, PVal>, dst: &PVar, value: PVal) {
    if let PVar::Reg(r) = dst {
        let r: &'static str = r;
        if !reg_values.is_empty() {
            let stale: Vec<&'static str> = reg_values
                .iter()
                .filter(|(k, v)| **k != r && mentions_reg(v, r))
                .map(|(k, _)| *k)
                .collect();
            for k in stale {
                reg_values.insert(k, PVal::Opaque(k));
            }
        }
        if matches!(value, PVal::Opaque(_)) {
            reg_values.insert(r, PVal::Opaque(r));
        } else if pval_len_bound(&value, MAX_TRACKED_EXPR) > MAX_TRACKED_EXPR {
            EXPR_OVERFLOWS.with(|c| c.set(c.get().wrapping_add(1)));
            reg_values.insert(r, PVal::Opaque(r));
        } else {
            reg_values.insert(r, value);
        }
    }
}

pub(crate) fn mentions_reg(v: &PVal, r: &str) -> bool {
    match v {
        PVal::C(_) => false,
        PVal::E(s) => whole_word_contains(s, r),
        PVal::X(e) => e.uses_var(r),
        PVal::Opaque(_) => false,
    }
}

pub(crate) fn whole_word_contains(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    hb.windows(nb.len()).enumerate().any(|(i, w)| {
        w == nb
            && (i == 0 || !is_word(hb[i - 1]))
            && (i + nb.len() >= hb.len() || !is_word(hb[i + nb.len()]))
    })
}

pub(crate) fn pval_len_bound(v: &PVal, limit: usize) -> usize {
    match v {
        PVal::C(_) => 21,
        PVal::E(s) => s.len(),
        PVal::X(e) => e.len_bound(limit),
        PVal::Opaque(r) => r.len(),
    }
}

pub(crate) fn c_type_for_size(size: u32) -> &'static str {
    match size {
        1 => "int8_t",
        2 => "int16_t",
        4 => "int32_t",
        _ => "int64_t",
    }
}

pub fn render_pseudocode(p: &Pseudocode) -> Vec<(String, LineKind, Option<u64>)> {
    p.lines
        .iter()
        .map(|l| {
            let indent = "    ".repeat((l.indent as usize).min(64));
            (format!("{}{}", indent, l.text), l.kind, l.source_addr)
        })
        .collect()
}
