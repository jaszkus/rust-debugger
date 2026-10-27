use super::alias;
use super::pcode::StackBase;
use super::printing::*;
use super::state_machine;
use super::structure::{
    GotoClass, Loops, Postdom, WalkCtx, classify_gotos, cleanup_labels, code_part, compute_dowhile,
    elide_else_after_terminal, inline_terminal_block_regions, inline_terminal_gotos,
    prune_unreachable_returns, retarget_goto_chains, squash_empty_branches, walk_block,
};
use super::*;
use crate::analysis::flow::cfg::CFG;
use crate::analysis::flow::stack::StackFrame;
use crate::analysis::flow::variables;
use crate::analysis::operands::canonical_reg;
use crate::analysis::symbols::debug_types::{DebugBase, DebugField, DebugStruct, DebugTypes};
use crate::disasm::DisasmInstruction;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

type Env = HashMap<&'static str, Lattice>;

const MAX_HINT_PASSES: usize = 8;

const STATE_MACHINE_UNTHREAD: bool = false;

#[derive(Clone, Copy)]
pub struct LiftInput<'a> {
    pub cfg: &'a CFG,
    pub pinstrs_in_func: &'a [PInstr],
    pub imap: &'a [DisasmInstruction],
    pub stack: &'a StackFrame,
    pub func_name: &'a str,
    pub func_lookup: &'a HashMap<u64, String>,
    pub is64: bool,
    pub is_win64: bool,
    pub thunk_targets: &'a HashMap<u64, u64>,
    pub imports: &'a HashMap<u64, String>,
    pub switches: &'a [crate::analysis::advanced::SwitchTable],
    pub debug_types: Option<&'a std::sync::Arc<DebugTypes>>,
    pub cancel: Option<&'a AtomicBool>,
}

#[derive(Debug, Clone, Default)]
pub struct DecompStats {
    pub blocks: usize,
    pub back_edges: usize,
    pub dead_ops: usize,
    pub expr_overflows: usize,
    pub unmodeled_instrs: usize,
    pub emitted_lines: usize,
    pub output_bytes: usize,
    pub skipped_too_large: bool,
    pub cancelled: bool,
    pub truncated: bool,
    pub t_hints: Duration,
    pub t_dataflow: Duration,
    pub t_structure: Duration,
    pub t_total: Duration,
}

impl std::fmt::Display for DecompStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "blocks={} back_edges={} dead_ops={} expr_overflows={} unmodeled={} lines={} bytes={} \
             hints={:.1?} dataflow={:.1?} structure={:.1?} total={:.1?}",
            self.blocks,
            self.back_edges,
            self.dead_ops,
            self.expr_overflows,
            self.unmodeled_instrs,
            self.emitted_lines,
            self.output_bytes,
            self.t_hints,
            self.t_dataflow,
            self.t_structure,
            self.t_total
        )?;
        if self.skipped_too_large {
            write!(f, " [skipped: too many blocks]")?;
        }
        if self.cancelled {
            write!(f, " [cancelled]")?;
        }
        if self.truncated {
            write!(f, " [truncated]")?;
        }
        Ok(())
    }
}

#[inline]
fn is_cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::Relaxed))
}

fn make_pseudocode(cfg: &CFG, func_name: &str, lines: Vec<PseudoLine>) -> Pseudocode {
    Pseudocode {
        func_entry: cfg.func_entry,
        func_name: func_name.into(),
        lines,
    }
}

fn finish_cancelled(cfg: &CFG, func_name: &str, mut lines: Vec<PseudoLine>) -> Pseudocode {
    lines.push(PseudoLine {
        indent: 1,
        text: "// decompilation cancelled".into(),
        kind: LineKind::Comment,
        source_addr: None,
    });
    lines.push(PseudoLine {
        indent: 0,
        text: "}".into(),
        kind: LineKind::CloseBrace,
        source_addr: None,
    });
    make_pseudocode(cfg, func_name, lines)
}

fn function_struct_hints(cfg: &CFG, pinstrs: &[PInstr]) -> HashMap<String, StructHint> {
    use crate::analysis::type_reconstruction::TypeReconstructor;
    let entry = cfg.func_entry;
    let end = cfg.blocks.iter().map(|b| b.end).max().unwrap_or(entry);
    if end <= entry {
        return HashMap::default();
    }
    let mut tr = TypeReconstructor::new();
    tr.analyze_function(pinstrs, entry, end);
    tr.function_fields(entry)
        .into_iter()
        .map(|(reg, fields)| {
            (
                reg,
                StructHint {
                    fields,
                    field_sizes: Vec::new(),
                    owner: None,
                },
            )
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArgOrigin {
    Param(usize),
    Stack(u8, i64),
    AddrOfStack(u8, i64),
}

#[derive(Default)]
struct ArchiveLocalTypes {
    params: Vec<(usize, crate::analysis::symbols::type_archive::StructShape)>,
    param_types: Vec<(usize, String)>,
    stack: Vec<(
        (u8, i64),
        (crate::analysis::symbols::type_archive::StructShape, u64),
    )>,
    stack_scalars: Vec<((u8, i64), (String, usize))>,
    regs: Vec<(
        &'static str,
        crate::analysis::symbols::type_archive::StructShape,
    )>,
}

fn stack_base_id(base: StackBase) -> u8 {
    if base == StackBase::Rbp { 0 } else { 1 }
}

fn archive_local_types(
    cfg: &CFG,
    pinstrs: &[PInstr],
    idx: &'static crate::analysis::symbols::type_archive::ArchiveIndex,
    resolve_callee: &dyn Fn(u64) -> Option<String>,
    is64: bool,
    is_win64: bool,
) -> ArchiveLocalTypes {
    let mut out = ArchiveLocalTypes::default();
    let entry = cfg.func_entry;
    let end = cfg.blocks.iter().map(|b| b.end).max().unwrap_or(entry);
    if !is64 || end <= entry {
        return out;
    }
    let arg_regs = archive_arg_registers(is_win64);
    let mut prov: HashMap<&'static str, ArgOrigin> = HashMap::default();
    for (i, r) in arg_regs.iter().enumerate() {
        prov.insert(*r, ArgOrigin::Param(i));
    }
    let mut param_shapes: Vec<Option<crate::analysis::symbols::type_archive::StructShape>> =
        vec![None; arg_regs.len()];
    let mut param_pointer_types: Vec<Option<(String, Option<usize>)>> = vec![None; arg_regs.len()];
    for pi in pinstrs {
        if pi.address < entry || pi.address >= end {
            continue;
        }
        for op in &pi.ops {
            if let POp::Call { target } = op
                && let Some(name) = resolve_callee(*target)
                && let Some(sig) = idx.signature(&name)
            {
                for i in 0..sig.params.len() {
                    let Some(reg) = arg_regs.get(i).copied() else {
                        break;
                    };
                    let shape = sig.param_shapes.get(i).and_then(|s| s.as_ref()).cloned();
                    let ptr_ty = sig.param_pointer_types.get(i).and_then(|t| t.clone());
                    let ptr_size = sig.param_pointee_sizes.get(i).copied().flatten();
                    match prov.get(reg) {
                        Some(ArgOrigin::Param(k)) => {
                            if let Some(shape) = &shape
                                && param_shapes[*k].is_none()
                            {
                                param_shapes[*k] = Some(shape.clone());
                            }
                            if let Some(ptr_ty) = &ptr_ty
                                && param_pointer_types[*k].is_none()
                            {
                                param_pointer_types[*k] = Some((ptr_ty.clone(), ptr_size));
                            }
                        }
                        Some(ArgOrigin::AddrOfStack(b, o)) => {
                            if let Some(shape) = &shape
                                && !out.stack.iter().any(|(k, _)| k == &(*b, *o))
                            {
                                out.stack.push(((*b, *o), (shape.clone(), pi.address)));
                            }
                            if let (Some(ptr_ty), Some(size)) = (&ptr_ty, ptr_size)
                                && !out.stack_scalars.iter().any(|(k, _)| k == &(*b, *o))
                            {
                                out.stack_scalars.push(((*b, *o), (ptr_ty.clone(), size)));
                            }
                        }
                        _ => {}
                    }
                }
            }

            archive_track_provenance(op, &mut prov);
        }
    }

    for (i, shape) in param_shapes.iter().enumerate() {
        if let Some(shape) = shape {
            out.params.push((i, shape.clone()));
        }
    }
    for (i, ty) in param_pointer_types.iter().enumerate() {
        if let Some((ty, _)) = ty {
            out.param_types.push((i, ty.clone()));
        }
    }

    let mut ptr: HashMap<&'static str, crate::analysis::symbols::type_archive::StructShape> =
        HashMap::default();
    for (i, shape) in &out.params {
        if let Some(reg) = arg_regs.get(*i) {
            ptr.insert(*reg, shape.clone());
        }
    }
    let param_regs: HashSet<&'static str> = arg_regs.iter().copied().collect();
    for pi in pinstrs {
        if pi.address < entry || pi.address >= end {
            continue;
        }
        for op in &pi.ops {
            match op {
                POp::Copy {
                    dst: PVar::Reg(d),
                    src: PVar::Reg(s),
                    ..
                } => match ptr.get(*s).cloned() {
                    Some(t) => {
                        ptr.insert(*d, t);
                    }
                    None => {
                        ptr.remove(*d);
                    }
                },
                POp::Load {
                    dst: PVar::Reg(d),
                    addr: PVar::Mem(base, disp),
                    size,
                } => {
                    let next = match &**base {
                        PVar::Reg(r) => ptr.get(*r).and_then(|a| {
                            a.pointee_of(*disp as usize, *size as usize)
                                .and_then(|n| idx.aggregate_named(n))
                        }),
                        _ => None,
                    };
                    match next {
                        Some(t) => {
                            ptr.insert(*d, t);
                        }
                        None => {
                            ptr.remove(*d);
                        }
                    }
                }
                _ => {
                    if let Some(w) = written_reg(op) {
                        ptr.remove(w);
                    }
                }
            }
        }
    }
    for (reg, shape) in ptr {
        if param_regs.contains(reg) {
            continue;
        }
        out.regs.push((reg, shape));
    }
    out.regs.sort_by_key(|(r, _)| *r);
    out
}

fn archive_track_provenance(op: &POp, prov: &mut HashMap<&'static str, ArgOrigin>) {
    match op {
        POp::Copy {
            dst: PVar::Reg(d),
            src,
            ..
        } => match src {
            PVar::Reg(s) => match prov.get(*s).copied() {
                Some(o) => {
                    prov.insert(*d, o);
                }
                None => {
                    prov.remove(*d);
                }
            },
            PVar::StackSlot { base, off } => {
                prov.insert(*d, ArgOrigin::Stack(stack_base_id(*base), *off));
            }
            _ => {
                prov.remove(*d);
            }
        },
        POp::AddrOf {
            dst: PVar::Reg(d),
            base,
            index,
            disp,
            ..
        } => {
            let mut origin = None;
            if index.is_none()
                && let Some(PVar::Reg(r)) = base.as_deref()
            {
                match *r {
                    "rbp" | "ebp" => origin = Some(ArgOrigin::AddrOfStack(0, *disp)),
                    "rsp" | "esp" => origin = Some(ArgOrigin::AddrOfStack(1, *disp)),
                    _ => {
                        if let Some(ArgOrigin::Stack(b, o)) = prov.get(*r).copied() {
                            origin = Some(ArgOrigin::AddrOfStack(b, o));
                        }
                    }
                }
            }
            match origin {
                Some(o) => {
                    prov.insert(*d, o);
                }
                None => {
                    prov.remove(*d);
                }
            }
        }
        POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. } => {
            for r in CALL_CLOBBERED {
                prov.remove(*r);
            }
        }
        _ => {
            if let Some(w) = written_reg(op) {
                prov.remove(w);
            }
        }
    }
}

fn archive_arg_registers(is_win64: bool) -> &'static [&'static str] {
    if is_win64 {
        &["rcx", "rdx", "r8", "r9"]
    } else {
        &["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    }
}

fn fmt_frame_slot(base_reg: &str, off: i64) -> String {
    if off < 0 {
        format!("[{}-{:#x}]", base_reg, off.unsigned_abs())
    } else {
        format!("[{}+{:#x}]", base_reg, off)
    }
}

fn is_stack_bookkeeping(text: &str, bp_is_frame: bool) -> bool {
    let t = text
        .split("//")
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches(';')
        .trim();
    let Some((lhs, rhs)) = t.split_once(" = ") else {
        return false;
    };
    let (lhs, rhs) = (lhs.trim(), rhs.trim());
    let is_sp = |s: &str| matches!(s, "rsp" | "esp");
    let is_bp = |s: &str| matches!(s, "rbp" | "ebp");
    if !(is_sp(lhs) || (bp_is_frame && is_bp(lhs))) {
        return false;
    }
    if rhs == lhs || is_sp(rhs) || is_bp(rhs) {
        return true;
    }
    let reg_plus_const = |reg: &str| -> bool {
        let Some(rest) = rhs.strip_prefix(reg) else {
            return false;
        };
        if rest.trim().is_empty() {
            return true;
        }
        let Some(num) = rest.trim_start().strip_prefix(['+', '-']) else {
            return false;
        };
        parse_c_int(num.trim()).is_some()
    };
    if (is_bp(lhs) && reg_plus_const("rsp")) || (is_sp(lhs) && reg_plus_const("rbp")) {
        return true;
    }
    let Some(rest) = rhs.strip_prefix(lhs) else {
        return false;
    };
    let Some(num) = rest.trim_start().strip_prefix(['+', '-']) else {
        return false;
    };
    parse_c_int(num.trim()).is_some()
}

fn is_float_mnemonic(mn: &str) -> bool {
    let base = match mn.strip_prefix('v') {
        Some(rest) if !rest.is_empty() => rest,
        _ => mn,
    };
    if base.starts_with("fmadd")
        || base.starts_with("fmsub")
        || base.starts_with("fnmadd")
        || base.starts_with("fnmsub")
    {
        return true;
    }
    matches!(
        base,
        "movss"
            | "movsd"
            | "movaps"
            | "movapd"
            | "movups"
            | "movupd"
            | "addss"
            | "addsd"
            | "addps"
            | "addpd"
            | "subss"
            | "subsd"
            | "subps"
            | "subpd"
            | "mulss"
            | "mulsd"
            | "mulps"
            | "mulpd"
            | "divss"
            | "divsd"
            | "divps"
            | "divpd"
            | "sqrtss"
            | "sqrtsd"
            | "sqrtps"
            | "sqrtpd"
            | "minss"
            | "minsd"
            | "maxss"
            | "maxsd"
            | "comiss"
            | "comisd"
            | "ucomiss"
            | "ucomisd"
            | "cvtss2sd"
            | "cvtsd2ss"
            | "cvtsi2ss"
            | "cvtsi2sd"
            | "cvtss2si"
            | "cvtsd2si"
            | "cvttss2si"
            | "cvttsd2si"
            | "roundss"
            | "roundsd"
            | "andps"
            | "andpd"
            | "andnps"
            | "andnpd"
            | "orps"
            | "orpd"
            | "fld"
            | "fst"
            | "fstp"
            | "fadd"
            | "faddp"
            | "fsub"
            | "fsubp"
            | "fsubr"
            | "fsubrp"
            | "fmul"
            | "fmulp"
            | "fdiv"
            | "fdivp"
            | "fdivr"
            | "fdivrp"
            | "fcom"
            | "fcomp"
            | "fcompp"
            | "fucom"
            | "fucomp"
            | "fucompp"
            | "fcomi"
            | "fcomip"
            | "fucomi"
            | "fucomip"
            | "fchs"
            | "fabs"
            | "fsqrt"
            | "fxch"
            | "xorps"
            | "xorpd"
            | "shufps"
            | "shufpd"
            | "unpcklps"
            | "unpcklpd"
            | "movhps"
            | "movlps"
            | "movhpd"
            | "movlpd"
            | "movlhps"
            | "movhlps"
            | "maxps"
            | "maxpd"
            | "minps"
            | "minpd"
            | "cvtps2pd"
            | "cvtpd2ps"
            | "rsqrtss"
            | "rcpss"
            | "fild"
            | "fist"
            | "fistp"
            | "fisttp"
            | "fld1"
            | "fldz"
    )
}

fn is_fp_reg(tok: &str) -> bool {
    let t = tok.trim();
    let has = |p: &str| {
        t.len() >= p.len() && t.is_char_boundary(p.len()) && t[..p.len()].eq_ignore_ascii_case(p)
    };
    for p in ["xmm", "ymm", "zmm"] {
        if has(p) {
            let r = &t[p.len()..];
            let d = r.bytes().take_while(u8::is_ascii_digit).count();
            return (1..=2).contains(&d)
                && !r[d..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
        }
    }
    has("st") && {
        let r = &t[2..];
        r.is_empty() || r.starts_with('(') || (r.len() == 1 && r.as_bytes()[0].is_ascii_digit())
    }
}

struct TypeScan {
    floats: HashSet<String>,
    float_slots: HashSet<i64>,
    read_pos_slots: HashSet<i64>,
    written_pos_slots: HashSet<i64>,
}

#[derive(Debug, Clone)]
struct ByValueParam {
    type_name: String,
    size: usize,
    is_union: bool,
    fields: Vec<(i64, usize, String)>,
}

fn struct_is_union(ds: &DebugStruct) -> bool {
    ds.fields
        .iter()
        .filter(|f| f.offset == 0 && f.bitfield.is_none())
        .count()
        > 1
}

fn primitive_field_size(name: &str) -> Option<usize> {
    let name = name.trim();
    if name.ends_with('*') {
        return Some(8);
    }
    let name = name
        .strip_prefix("const ")
        .or_else(|| name.strip_prefix("volatile "))
        .unwrap_or(name)
        .trim();
    Some(match name {
        "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" | "byte" | "bool"
        | "_Bool" => 1,
        "short" | "unsigned short" | "int16_t" | "uint16_t" | "wchar_t" => 2,
        "int" | "unsigned int" | "int32_t" | "uint32_t" | "long" | "unsigned long" | "float" => 4,
        "longlong" | "ulonglong" | "int64_t" | "uint64_t" | "long long" | "unsigned long long"
        | "double" => 8,
        _ => return None,
    })
}

fn array_parts(dbg: &DebugTypes, f: &DebugField) -> Option<(usize, usize, String)> {
    let ty = f.type_name.trim();
    let open = ty.rfind('[')?;
    if !ty.ends_with(']') {
        return None;
    }
    let count: usize = ty[open + 1..ty.len() - 1].trim().parse().ok()?;
    if count == 0 || count > 64 {
        return None;
    }
    let mut base = ty[..open].trim();
    while let Some(rest) = base
        .strip_prefix("const ")
        .or_else(|| base.strip_prefix("volatile "))
        .or_else(|| base.strip_prefix("struct "))
        .or_else(|| base.strip_prefix("union "))
    {
        base = rest.trim_start();
    }
    let size = match dbg.struct_named(base) {
        Some(s) => s.size,
        None => primitive_field_size(base)?,
    };
    if size == 0 || size.saturating_mul(count) > f.size.max(size) {
        return None;
    }
    Some((size, count, base.to_string()))
}

fn flattened_struct_fields(dbg: &DebugTypes, ds: &DebugStruct) -> Vec<(i64, usize, String)> {
    fn walk(
        dbg: &DebugTypes,
        ds: &DebugStruct,
        base: i64,
        prefix: &str,
        depth: usize,
        out: &mut Vec<(i64, usize, String)>,
    ) {
        if depth >= 4 {
            return;
        }
        for f in &ds.fields {
            let ty = f.type_name.trim();
            if ty.ends_with('*') || ty.contains('[') {
                continue;
            }
            let mut name = ty;
            while let Some(rest) = name
                .strip_prefix("const ")
                .or_else(|| name.strip_prefix("volatile "))
                .or_else(|| name.strip_prefix("struct "))
                .or_else(|| name.strip_prefix("union "))
            {
                name = rest.trim_start();
            }
            let Some(sub) = dbg.struct_named(name) else {
                continue;
            };
            let path = if prefix.is_empty() {
                f.name.clone()
            } else {
                format!("{}.{}", prefix, f.name)
            };
            for sf in &sub.fields {
                out.push((
                    base + f.offset as i64 + sf.offset as i64,
                    sf.size,
                    format!("{}.{}", path, sf.name),
                ));
            }
            walk(dbg, sub, base + f.offset as i64, &path, depth + 1, out);
        }
    }

    let mut out: Vec<(i64, usize, String)> = ds
        .fields
        .iter()
        .map(|f| (f.offset as i64, f.size, f.name.clone()))
        .collect();
    walk(dbg, ds, 0, "", 0, &mut out);
    for f in &ds.fields {
        let Some((elem, count, base_ty)) = array_parts(dbg, f) else {
            continue;
        };
        out.retain(|(off, _, name)| name != &f.name || *off != f.offset as i64);
        for i in 0..count {
            let off = f.offset as i64 + (i * elem) as i64;
            match dbg.struct_named(&base_ty) {
                Some(sub) => {
                    for sf in &sub.fields {
                        out.push((
                            off + sf.offset as i64,
                            sf.size,
                            format!("{}[{}].{}", f.name, i, sf.name),
                        ));
                    }
                }
                None => out.push((off, elem, format!("{}[{}]", f.name, i))),
            }
        }
    }
    out
}

fn call_result_addrs(pinstrs: &[PInstr], return_reads_rax: bool) -> HashSet<u64> {
    let mut out: HashSet<u64> = HashSet::default();
    let mut pending: Option<u64> = None;
    for pi in pinstrs {
        for op in &pi.ops {
            if matches!(
                op,
                POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. }
            ) {
                pending = Some(pi.address);
                continue;
            }
            if pending.is_some()
                && (matches!(
                    op,
                    POp::Branch { .. } | POp::BranchInd { .. } | POp::CBranch { .. }
                ) || (!return_reads_rax && matches!(op, POp::Return | POp::ReturnPop { .. })))
            {
                pending = None;
            }
            if let Some(pc) = pending {
                let writes = written_reg(op) == Some("rax");
                let uses = reads_regs(op).contains(&"rax");
                let narrow_use = match op {
                    POp::Zext { src, .. } | POp::Sext { src, .. } => {
                        matches!(src, PVar::Reg("rax"))
                    }
                    POp::IntAnd { a, .. }
                    | POp::IntOr { a, .. }
                    | POp::IntShr { a, .. }
                    | POp::IntSar { a, .. } => matches!(a, PVar::Reg("rax")),
                    _ => false,
                };
                if uses && (!writes || narrow_use) {
                    out.insert(pc);
                    pending = None;
                } else if writes {
                    pending = None;
                }
            }
            if matches!(
                op,
                POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. }
            ) {
                pending = Some(pi.address);
            }
        }
    }
    out
}

struct PointerUses {
    regs: HashSet<&'static str>,
    slots: HashSet<(u8, i64)>,
    param_slots: HashMap<&'static str, Vec<(u8, i64)>>,
}

fn slot_key(v: &PVar) -> Option<(u8, i64)> {
    match v {
        PVar::StackSlot { base, off } => Some((if *base == StackBase::Rbp { 0 } else { 1 }, *off)),
        _ => None,
    }
}

fn address_regs(v: &PVar) -> Vec<&'static str> {
    fn walk(v: &PVar, out: &mut Vec<&'static str>) {
        match v {
            PVar::Mem(base, _) => walk(base, out),
            PVar::Scaled { base, index, .. } => {
                walk(base, out);
                walk(index, out);
            }
            PVar::Reg(r) => out.push(r),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

fn pointer_uses(pinstrs: &[PInstr]) -> PointerUses {
    let mut uses = PointerUses {
        regs: HashSet::default(),
        slots: HashSet::default(),
        param_slots: HashMap::default(),
    };
    let mut clobbered: HashSet<&'static str> = HashSet::default();
    for pi in pinstrs {
        for op in &pi.ops {
            if let POp::Store {
                addr: PVar::StackSlot { base, off },
                src: PVar::Reg(r),
                ..
            } = op
                && !clobbered.contains(r)
            {
                uses.param_slots
                    .entry(r)
                    .or_default()
                    .push((if *base == StackBase::Rbp { 0 } else { 1 }, *off));
            }
            if let Some(r) = written_reg(op) {
                clobbered.insert(r);
            }
            if matches!(
                op,
                POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. }
            ) {
                for r in crate::analysis::pcode::CALL_CLOBBERED {
                    clobbered.insert(*r);
                }
            }
        }
    }

    let mut clobbered: HashSet<&'static str> = HashSet::default();
    let mut aliases: HashMap<&'static str, (u8, i64)> = HashMap::default();
    for pi in pinstrs {
        for op in &pi.ops {
            match op {
                POp::Load { dst, addr, .. } => {
                    if let PVar::Reg(r) = dst
                        && let Some(key) = slot_key(addr)
                        && uses.param_slots.values().any(|v| v.contains(&key))
                    {
                        aliases.insert(r, key);
                    }
                    for r in address_regs(addr) {
                        if clobbered.contains(r) {
                            continue;
                        }
                        uses.regs.insert(r);
                        if let Some(key) = aliases.get(r) {
                            uses.slots.insert(*key);
                        }
                    }
                }
                POp::Store { addr, .. } => {
                    for r in address_regs(addr) {
                        if clobbered.contains(r) {
                            continue;
                        }
                        uses.regs.insert(r);
                        if let Some(key) = aliases.get(r) {
                            uses.slots.insert(*key);
                        }
                    }
                }
                _ => {}
            }
            if let Some(r) = written_reg(op) {
                clobbered.insert(r);
                aliases.remove(r);
            }
            if matches!(
                op,
                POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. }
            ) {
                for r in crate::analysis::pcode::CALL_CLOBBERED {
                    clobbered.insert(*r);
                    aliases.remove(*r);
                }
            }
        }
    }
    uses
}

fn mark_slot(set: &mut HashSet<i64>, v: &PVar) {
    if let PVar::StackSlot { off, .. } = v {
        set.insert(*off);
    }
}

fn scan_types(imap: &[DisasmInstruction], pinstrs_in_func: &[PInstr]) -> TypeScan {
    let mut floats: HashSet<String> = HashSet::default();
    let mut float_slots: HashSet<i64> = HashSet::default();
    for di in imap {
        if !is_float_mnemonic(di.mnemonic) {
            continue;
        }
        for tok in di.ops().split(',') {
            let t = tok.split_whitespace().next().unwrap_or("");
            if is_fp_reg(t) {
                floats.insert(t.to_ascii_lowercase());
            }
        }
    }

    let mut read_pos_slots: HashSet<i64> = HashSet::default();
    let mut written_pos_slots: HashSet<i64> = HashSet::default();
    for pi in pinstrs_in_func {
        for op in &pi.ops {
            match op {
                POp::Copy { src, .. } => mark_slot(&mut read_pos_slots, src),
                POp::Load { addr, .. } => mark_slot(&mut read_pos_slots, addr),
                POp::Push { src, .. } => mark_slot(&mut read_pos_slots, src),
                POp::Store {
                    addr: PVar::StackSlot { off, .. },
                    ..
                } if *off >= 0 => {
                    written_pos_slots.insert(*off);
                }
                POp::FloatBinop { a, b, .. }
                | POp::Cmp { a, b, .. }
                | POp::Test { a, b, .. }
                | POp::FloatCmp { a, b, .. }
                | POp::IntAdd { a, b, .. }
                | POp::IntSub { a, b, .. }
                | POp::IntMul { a, b, .. }
                | POp::IntAnd { a, b, .. }
                | POp::IntOr { a, b, .. }
                | POp::IntXor { a, b, .. }
                | POp::IntLeft { a, b, .. }
                | POp::IntShr { a, b, .. }
                | POp::IntSar { a, b, .. }
                | POp::IntDiv { a, b, .. }
                | POp::IntSDiv { a, b, .. } => {
                    mark_slot(&mut read_pos_slots, a);
                    mark_slot(&mut read_pos_slots, b);
                }
                _ => {}
            }
        }
    }

    for _ in 0..MAX_HINT_PASSES {
        let before = (floats.len(), float_slots.len());
        for pi in pinstrs_in_func {
            for op in &pi.ops {
                match op {
                    POp::Copy { dst, src, .. } if floats.contains(&fmt_var(src)) => {
                        floats.insert(fmt_var(dst));
                    }
                    POp::Cvt { kind, dst, .. } if kind == "i2f" || kind == "f2f" => {
                        floats.insert(fmt_var(dst));
                    }
                    POp::Load {
                        dst,
                        addr: PVar::StackSlot { off, .. },
                        ..
                    } if float_slots.contains(off) => {
                        floats.insert(fmt_var(dst));
                    }
                    POp::Store {
                        addr: PVar::StackSlot { off, .. },
                        src,
                        ..
                    } if floats.contains(&fmt_var(src)) => {
                        float_slots.insert(*off);
                    }
                    _ => {}
                }
            }
        }
        if before == (floats.len(), float_slots.len()) {
            break;
        }
    }
    TypeScan {
        floats,
        float_slots,
        read_pos_slots,
        written_pos_slots,
    }
}

fn goto_line_count(pc: &Pseudocode) -> usize {
    pc.lines
        .iter()
        .filter(|l| l.text.trim_start().starts_with("goto LAB_"))
        .count()
}

fn renders_switch(pc: &Pseudocode) -> bool {
    pc.lines
        .iter()
        .any(|l| l.text.trim_start().starts_with("switch ("))
}

pub fn decompile(input: LiftInput<'_>) -> Pseudocode {
    let first = decompile_with_stats(input).0;
    if !renders_switch(&first) {
        return first;
    }
    let second = decompile_with_stats(LiftInput {
        switches: &[],
        ..input
    })
    .0;
    if goto_line_count(&second) < goto_line_count(&first)
        && second.lines.len() <= first.lines.len() + first.lines.len() / 5
    {
        second
    } else {
        first
    }
}

pub fn decompile_with_stats(input: LiftInput<'_>) -> (Pseudocode, DecompStats) {
    let t_total = Instant::now();
    let LiftInput {
        cfg,
        pinstrs_in_func,
        imap,
        stack,
        func_name,
        func_lookup,
        is64,
        is_win64,
        thunk_targets,
        imports,
        switches,
        debug_types,
        cancel,
    } = input;
    set_addr_is_64(is64);
    let mut stats = DecompStats {
        blocks: cfg.blocks.len(),
        ..Default::default()
    };

    if cfg.blocks.len() > MAX_DECOMP_BLOCKS {
        stats.skipped_too_large = true;
        let lines = vec![PseudoLine {
            indent: 0,
            text: format!(
                "// WARNING: function '{}' has {} CFG blocks (> {}), structured decompilation skipped to avoid OOM; use disassemble_function / analyze_control_flow instead",
                func_name,
                cfg.blocks.len(),
                MAX_DECOMP_BLOCKS
            ),
            kind: LineKind::Comment,
            source_addr: None,
        }];
        stats.emitted_lines = lines.len();
        stats.t_total = t_total.elapsed();
        return (make_pseudocode(cfg, func_name, lines), stats);
    }
    if cfg.blocks.is_empty() {
        let lines = vec![
            PseudoLine {
                indent: 0,
                text: format!("void {}(void)", func_name),
                kind: LineKind::Signature,
                source_addr: None,
            },
            PseudoLine {
                indent: 0,
                text: "{".into(),
                kind: LineKind::OpenBrace,
                source_addr: None,
            },
            PseudoLine {
                indent: 0,
                text: "}".into(),
                kind: LineKind::CloseBrace,
                source_addr: None,
            },
        ];
        stats.emitted_lines = lines.len();
        stats.t_total = t_total.elapsed();
        return (make_pseudocode(cfg, func_name, lines), stats);
    }
    EXPR_OVERFLOWS.with(|c| c.set(0));
    let mut lines = Vec::new();
    let sp = if is64 { "rsp" } else { "esp" };
    let bp = if is64 { "rbp" } else { "ebp" };

    let t_phase = Instant::now();
    let TypeScan {
        floats,
        float_slots,
        read_pos_slots,
        written_pos_slots,
    } = scan_types(imap, pinstrs_in_func);
    let bops = build_block_ops_from_slice(cfg, pinstrs_in_func);
    debug_state_candidates(func_name, &bops);
    let recovery = if imap.is_empty() {
        None
    } else {
        Some(variables::recover_with_ops(
            cfg,
            &bops,
            is64,
            if !is64 {
                variables::Abi::Auto
            } else if is_win64 {
                variables::Abi::MsX64
            } else {
                variables::Abi::SysV64
            },
        ))
    };
    let mut recovery = recovery;
    let debug = debug_types.map(|a| a.as_ref());
    let debug_sig = debug.and_then(|d| d.function(cfg.func_entry));
    let archive_lookup = crate::analysis::symbols::type_archive::index(if is64 { 8 } else { 4 });
    let archive_sig = if debug_sig.is_none() {
        archive_lookup.and_then(|idx| idx.signature(func_name).cloned())
    } else {
        None
    };
    let callee_params = build_callee_params(debug, imports, thunk_targets);
    let param_names: HashSet<String> = debug_sig
        .map(|s| s.params.iter().map(|p| p.name.clone()).collect())
        .unwrap_or_default();

    let mut param_renames: HashMap<String, String> = HashMap::default();
    let mut preferred_structs: HashMap<String, String> = HashMap::default();
    let mut value_structs: HashMap<String, StructHint> = HashMap::default();
    let mut owner_by_reg: HashMap<String, String> = HashMap::default();
    let mut param_types_by_reg: HashMap<String, String> = HashMap::default();
    let mut by_value_by_reg: HashMap<String, ByValueParam> = HashMap::default();
    let mut by_value_display: HashMap<String, String> = HashMap::default();
    let mut direct_stack_params: Vec<(u8, i64, i64, ByValueParam)> = Vec::new();
    let mut used_names: HashSet<String> = recovery
        .as_ref()
        .map(|rv| rv.vars.iter().map(|v| v.name.clone()).collect())
        .unwrap_or_default();
    if let (Some(sig), Some(rv)) = (debug_sig, recovery.as_mut())
        && rv.params.len() == sig.params.len()
    {
        for (i, &id) in rv.params.iter().enumerate() {
            let Some(dp) = sig.params.get(i) else {
                break;
            };
            let v = &mut rv.vars[id as usize];
            let old_name = v.name.clone();
            let fallback = v.name.clone();
            let mut new_name = sanitize_param_name(&dp.name, &fallback);
            if new_name != v.name {
                let base = new_name.clone();
                let mut n = 2u32;
                while used_names.contains(&new_name) && new_name != v.name {
                    new_name = format!("{}_{}", base, n);
                    n += 1;
                }
                if new_name != v.name {
                    used_names.insert(new_name.clone());
                    param_renames.insert(v.name.clone(), new_name.clone());
                    v.name = new_name;
                }
            }
            let is_pointer = dp.type_name.trim_end().ends_with('*');
            let shape = dp.struct_name.as_deref().and_then(|sname| {
                debug.and_then(|dbg| {
                    dbg.struct_named(sname).map(|ds| ByValueParam {
                        type_name: dp.type_name.clone(),
                        size: ds.size,
                        is_union: struct_is_union(ds),
                        fields: flattened_struct_fields(dbg, ds),
                    })
                })
            });
            match v.storage {
                variables::Loc::Reg(reg) => {
                    param_types_by_reg.insert(reg.to_string(), dp.type_name.clone());
                    if let Some(shape) = shape {
                        if is_pointer {
                            preferred_structs.insert(
                                reg.to_string(),
                                dp.struct_name.clone().unwrap_or_default(),
                            );
                            owner_by_reg.insert(reg.to_string(), old_name.clone());
                            value_structs.insert(
                                old_name.clone(),
                                StructHint {
                                    field_sizes: Vec::new(),
                                    fields: shape
                                        .fields
                                        .iter()
                                        .map(|(o, _, n)| (*o, n.clone()))
                                        .collect(),
                                    owner: Some(old_name),
                                },
                            );
                        } else {
                            by_value_by_reg.insert(reg.to_string(), shape);
                            by_value_display.insert(reg.to_string(), v.name.clone());
                        }
                    }
                }
                variables::Loc::Stack { base, off } => {
                    if let Some(shape) = shape
                        && !is_pointer
                    {
                        direct_stack_params.push((base, off, v.norm_off, shape));
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(sig) = archive_sig.as_ref()
        && let Some(rv) = recovery.as_mut()
    {
        for (i, &id) in rv.params.iter().enumerate() {
            let Some((dp_ty, dp_name)) = sig.params.get(i) else {
                break;
            };
            let v = &mut rv.vars[id as usize];
            let old_name = v.name.clone();
            let mut new_name = sanitize_param_name(dp_name, &old_name);
            if new_name != v.name {
                let base = new_name.clone();
                let mut n = 2u32;
                while used_names.contains(&new_name) && new_name != v.name {
                    new_name = format!("{}_{}", base, n);
                    n += 1;
                }
                if new_name != v.name {
                    used_names.insert(new_name.clone());
                    param_renames.insert(v.name.clone(), new_name.clone());
                    v.name = new_name;
                }
            }
            let _ = dp_ty;
        }
        for (i, &id) in rv.params.iter().enumerate() {
            let Some(shape) = sig.param_shapes.get(i).and_then(|s| s.as_ref()) else {
                continue;
            };
            let name = rv.vars[id as usize].name.clone();
            value_structs
                .entry(name)
                .or_insert_with(|| StructHint::from_shape(shape));
        }
    }

    if let Some(shape) = archive_lookup.and_then(|idx| idx.windows_struct("PEB")) {
        value_structs
            .entry("ProcessEnvironmentBlock".to_string())
            .or_insert_with(|| StructHint::from_shape(&shape));
    }

    let archive_types = if let (Some(rv), Some(idx)) = (recovery.as_ref(), archive_lookup) {
        let callee_name = |target: u64| -> Option<String> {
            let real = thunk_targets.get(&target).copied().unwrap_or(target);
            imports
                .get(&real)
                .or_else(|| imports.get(&target))
                .or_else(|| func_lookup.get(&real))
                .or_else(|| func_lookup.get(&target))
                .map(|n| n.rsplit('!').next().unwrap_or(n).to_string())
        };
        let mut types =
            archive_local_types(cfg, pinstrs_in_func, idx, &callee_name, is64, is_win64);
        for (index, shape) in &types.params {
            if let Some(id) = rv.params.get(*index)
                && let Some(v) = rv.vars.get(*id as usize)
            {
                value_structs
                    .entry(v.name.clone())
                    .or_insert_with(|| StructHint::from_shape(shape));
            }
        }
        for (slot, shape) in &types.stack {
            if let Some(name) = rv.names.stack_by_raw.get(slot) {
                value_structs
                    .entry(name.clone())
                    .or_insert_with(|| StructHint::from_shape(&shape.0));
            }
        }
        types.regs.retain(|(_, shape)| !shape.fields.is_empty());
        Some(types)
    } else {
        None
    };

    let final_param_names: HashSet<String> = recovery
        .as_ref()
        .map(|rv| {
            rv.params
                .iter()
                .map(|&id| rv.vars[id as usize].name.clone())
                .collect()
        })
        .unwrap_or_default();

    let mut structs = function_struct_hints(cfg, pinstrs_in_func);
    if let Some(types) = &archive_types {
        for (reg, shape) in &types.regs {
            let hint = StructHint::from_shape(shape);
            structs.entry((*reg).to_string()).or_insert(hint);
        }
    }
    if let Some(dbg) = debug {
        for (reg, sname) in &preferred_structs {
            if let Some(ds) = dbg.struct_named(sname) {
                let hint = structs.entry(reg.clone()).or_default();
                for (off, _, name) in flattened_struct_fields(dbg, ds) {
                    if hint.field(off).is_none() {
                        hint.fields.push((off, name));
                    }
                }
                hint.fields.sort_by_key(|(o, _)| *o);
            }
        }
        for (reg, hint) in structs.iter_mut() {
            let offsets: Vec<i64> = hint.fields.iter().map(|(o, _)| *o).collect();
            let preferred = preferred_structs.get(reg).map(String::as_str);
            if let Some(ds) = dbg.struct_for_offsets(&offsets, preferred) {
                for (off, name) in hint.fields.iter_mut() {
                    if let Some(f) = ds.field_at(*off) {
                        *name = f.name.clone();
                    }
                }
            }
        }
    }

    if let (Some(dbg), Some(rv)) = (debug, recovery.as_ref()) {
        let mut hint_by_reg: HashMap<&str, StructHint> = HashMap::default();
        for (reg, sname) in &preferred_structs {
            if let Some(ds) = dbg.struct_named(sname) {
                hint_by_reg.insert(
                    reg.as_str(),
                    StructHint {
                        field_sizes: Vec::new(),
                        fields: flattened_struct_fields(dbg, ds)
                            .into_iter()
                            .map(|(off, _, name)| (off, name))
                            .collect(),
                        owner: None,
                    },
                );
            }
        }
        if !hint_by_reg.is_empty() {
            let mut writes: HashMap<(u8, i64), usize> = HashMap::default();
            for pi in pinstrs_in_func {
                for op in &pi.ops {
                    if let POp::Store {
                        addr: PVar::StackSlot { base, off },
                        ..
                    } = op
                    {
                        let b = match base {
                            StackBase::Rbp => 0u8,
                            StackBase::Rsp => 1u8,
                        };
                        *writes.entry((b, *off)).or_default() += 1;
                    }
                }
            }
            let mut clobbered: HashSet<&'static str> = HashSet::default();
            for pi in pinstrs_in_func {
                for op in &pi.ops {
                    if let POp::Store {
                        addr: PVar::StackSlot { base, off },
                        src: PVar::Reg(reg),
                        ..
                    } = op
                        && !clobbered.contains(reg)
                        && let Some(hint) = hint_by_reg.get(reg)
                    {
                        let b = match base {
                            StackBase::Rbp => 0u8,
                            StackBase::Rsp => 1u8,
                        };
                        if let Some(name) = rv.names.stack_by_raw.get(&(b, *off)) {
                            let mut h = hint.clone();

                            if writes.get(&(b, *off)).copied() == Some(1) {
                                h.owner = owner_by_reg.get(*reg).cloned();
                            }
                            value_structs.insert(name.clone(), h);
                        }
                    }
                    if let Some(w) = written_reg(op) {
                        clobbered.insert(w);
                    }
                }
            }
        }
    }

    let mut stack_structs: Vec<StackStructHint> = Vec::new();
    let mut local_types: HashMap<String, String> = HashMap::default();
    if let Some(types) = &archive_types
        && let Some(rv) = recovery.as_ref()
    {
        for (index, ty) in &types.param_types {
            if let Some(id) = rv.params.get(*index)
                && let Some(v) = rv.vars.get(*id as usize)
            {
                local_types
                    .entry(v.name.clone())
                    .or_insert_with(|| ty.clone());
            }
        }
        for (slot, (ty, size)) in &types.stack_scalars {
            let Some(name) = rv.names.stack_by_raw.get(slot) else {
                continue;
            };
            if rv.names.size_of.get(name).map(|s| *s as usize) == Some(*size) {
                local_types
                    .entry(name.clone())
                    .or_insert_with(|| ty.clone());
            }
        }
        for (slot, (shape, pc)) in &types.stack {
            let (base, raw_off) = *slot;
            if shape.size == 0 {
                continue;
            }
            let display = rv
                .names
                .stack_by_raw
                .get(&(base, raw_off))
                .cloned()
                .unwrap_or_else(|| fallback_slot_name(raw_off, &TypeHints::default()));
            let base_norm = if base == 0 {
                rv.rbp_delta + raw_off
            } else {
                raw_off + rv.rsp_at.get(pc).copied().unwrap_or(0)
            };
            if stack_structs
                .iter()
                .any(|s| s.base_reg == base && s.base_norm == base_norm)
            {
                continue;
            }
            stack_structs.push(StackStructHint {
                base_reg: base,
                base: raw_off,
                base_norm,
                base_display: Some(display),
                size: shape.size,
                is_union: shape.is_union,
                fields: shape
                    .fields
                    .iter()
                    .map(|f| (f.offset as i64, f.size, f.name.clone()))
                    .collect(),
            });
        }
    }
    let mut hidden_locals: HashSet<String> = HashSet::default();
    if let Some(rv) = recovery.as_ref() {
        let mut seen: HashSet<(u8, i64)> = HashSet::default();
        for (base, off, norm_off, shape) in &direct_stack_params {
            if seen.insert((*base, *off)) {
                let base_norm = *norm_off;
                stack_structs.push(StackStructHint {
                    base_reg: *base,
                    base: *off,
                    base_norm,
                    base_display: None,
                    size: shape.size,
                    is_union: shape.is_union,
                    fields: shape.fields.clone(),
                });
                if let Some(name) = rv.names.stack_by_raw.get(&(*base, *off)) {
                    local_types.insert(name.clone(), shape.type_name.clone());
                }
            }
        }
        let mut clobbered: HashSet<&'static str> = HashSet::default();
        for pi in pinstrs_in_func {
            for op in &pi.ops {
                if let POp::Store {
                    addr: PVar::StackSlot { base, off },
                    src: PVar::Reg(reg),
                    ..
                } = op
                    && !clobbered.contains(reg)
                {
                    let b = match base {
                        StackBase::Rbp => 0u8,
                        StackBase::Rsp => 1u8,
                    };
                    if let Some(shape) = by_value_by_reg.get(*reg)
                        && seen.insert((b, *off))
                    {
                        let base_norm = if b == 0 {
                            *off + rv.rbp_delta
                        } else {
                            *off + rv.rsp_at.get(&pi.address).copied().unwrap_or(0)
                        };
                        stack_structs.push(StackStructHint {
                            base_reg: b,
                            base: *off,
                            base_norm,
                            base_display: None,
                            size: shape.size,
                            is_union: shape.is_union,
                            fields: shape.fields.clone(),
                        });
                    }
                    if let Some(ty) = param_types_by_reg.get(*reg)
                        && let Some(name) = rv.names.stack_by_raw.get(&(b, *off))
                    {
                        local_types.insert(name.clone(), ty.clone());
                    }
                }
                if let Some(w) = written_reg(op) {
                    clobbered.insert(w);
                }
            }
        }
    }

    let mut stack_names: HashMap<i64, (String, usize)> = HashMap::default();

    if let (Some(dbg), Some(sig), Some(rv)) = (debug, debug_sig, recovery.as_ref()) {
        let uses_rbp = rv
            .vars
            .iter()
            .any(|v| matches!(v.storage, variables::Loc::Stack { base: 0, .. }));
        let ptr = if is64 { 8 } else { 4 };

        let rsp_body = {
            let mut freq: HashMap<i64, usize> = HashMap::default();
            for &d in rv.rsp_at.values() {
                *freq.entry(d).or_default() += 1;
            }
            freq.into_iter()
                .max_by_key(|&(d, c)| (c, std::cmp::Reverse(d)))
                .map(|(d, _)| d)
                .unwrap_or(0)
        };
        for local in &sig.locals {
            let target_norm = match local.base {
                DebugBase::Cfa => {
                    if uses_rbp {
                        rv.rbp_delta + 2 * ptr + local.offset
                    } else {
                        ptr + local.offset
                    }
                }
                DebugBase::Rbp => rv.rbp_delta + local.offset,
                DebugBase::Rsp => rsp_body + local.offset,
            };
            let Some(v) = rv.vars.iter().find(|v| {
                matches!(v.storage, variables::Loc::Stack { .. }) && v.norm_off == target_norm
            }) else {
                continue;
            };
            let (b, raw_off) = match v.storage {
                variables::Loc::Stack { base, off } => (base, off),
                _ => continue,
            };
            let old_name = v.name.clone();
            let is_param_spill = param_names.contains(&local.name);
            if is_param_spill {
                hidden_locals.insert(old_name.clone());
                let display = sig
                    .params
                    .iter()
                    .position(|p| p.name == local.name)
                    .and_then(|i| rv.params.get(i))
                    .map(|&id| rv.vars[id as usize].name.clone())
                    .unwrap_or_else(|| sanitize_param_name(&local.name, &old_name));
                if let Some(sname) = local.struct_name.as_deref()
                    && let Some(ds) = dbg.struct_named(sname)
                {
                    let flat = flattened_struct_fields(dbg, ds);
                    if local.type_name.trim_end().ends_with('*') {
                        let hint = StructHint {
                            field_sizes: Vec::new(),
                            fields: flat.iter().map(|(o, _, n)| (*o, n.clone())).collect(),
                            owner: Some(display.clone()),
                        };
                        value_structs.insert(old_name.clone(), hint.clone());
                        value_structs.insert(display.clone(), hint);
                    } else {
                        stack_structs.push(StackStructHint {
                            base_reg: b,
                            base: raw_off,
                            base_norm: target_norm,
                            base_display: Some(display.clone()),
                            size: local.size,
                            is_union: struct_is_union(ds),
                            fields: flat,
                        });
                    }
                }
                local_types.insert(old_name.clone(), normalize_type(&local.type_name));
                stack_names.insert(target_norm, (display, local.size));
                continue;
            }
            let mut new_name = sanitize_param_name(&local.name, &old_name);
            if new_name != old_name {
                let base = new_name.clone();
                let mut n = 2u32;
                while used_names.contains(&new_name) {
                    new_name = format!("{}_{}", base, n);
                    n += 1;
                }
                used_names.insert(new_name.clone());
                param_renames.insert(old_name.clone(), new_name.clone());
            }
            local_types.insert(old_name.clone(), normalize_type(&local.type_name));
            stack_names.insert(target_norm, (new_name.clone(), local.size));
            if let Some(sname) = local.struct_name.as_deref()
                && let Some(ds) = dbg.struct_named(sname)
            {
                let flat = flattened_struct_fields(dbg, ds);
                if local.type_name.trim_end().ends_with('*') {
                    let hint = StructHint {
                        field_sizes: Vec::new(),
                        fields: flat.iter().map(|(o, _, n)| (*o, n.clone())).collect(),
                        owner: Some(new_name.clone()),
                    };
                    value_structs.insert(old_name.clone(), hint.clone());
                    value_structs.insert(new_name.clone(), hint);
                } else {
                    stack_structs.push(StackStructHint {
                        base_reg: b,
                        base: raw_off,
                        base_norm: target_norm,
                        base_display: None,
                        size: local.size,
                        is_union: struct_is_union(ds),
                        fields: flat,
                    });
                    for other in &rv.vars {
                        if other.name != old_name
                            && other.norm_off >= target_norm
                            && other.norm_off < target_norm.saturating_add(local.size as i64)
                        {
                            hidden_locals.insert(other.name.clone());
                        }
                    }
                }
            }
        }
    }

    if let Some(rv) = recovery.as_ref() {
        let ptr = pointer_uses(pinstrs_in_func);
        for &id in &rv.params {
            let v = &rv.vars[id as usize];
            let is_pointer = match v.storage {
                variables::Loc::Reg(reg) => {
                    ptr.regs.contains(reg)
                        || ptr
                            .param_slots
                            .get(reg)
                            .is_some_and(|slots| slots.iter().any(|s| ptr.slots.contains(s)))
                }
                variables::Loc::Stack { base, off } => {
                    ptr.slots.contains(&(if base == 0 { 0 } else { 1 }, off))
                }
                _ => false,
            };
            if is_pointer && !local_types.contains_key(&v.name) {
                local_types.insert(v.name.clone(), "longlong *".to_string());
            }
        }
    }

    let mut enum_variants: HashMap<String, Vec<(String, i64)>> = HashMap::default();
    let mut enum_fields: HashMap<String, String> = HashMap::default();
    let mut bitfields: Vec<(String, u8, u8, String)> = Vec::new();
    if let Some(dbg) = debug {
        for e in &dbg.enums {
            enum_variants.insert(e.name.clone(), e.variants.clone());
        }
        let mut ambiguous: HashSet<String> = HashSet::default();
        for st in &dbg.structs {
            for f in &st.fields {
                let ty = f.type_name.trim().trim_start_matches("enum ").trim();
                if enum_variants.contains_key(ty) {
                    match enum_fields.get(&f.name) {
                        Some(prev) if prev != ty => {
                            ambiguous.insert(f.name.clone());
                        }
                        _ => {
                            enum_fields.insert(f.name.clone(), ty.to_string());
                        }
                    }
                }
            }
            let mut first_by_off: HashMap<usize, String> = HashMap::default();
            for f in &st.fields {
                first_by_off
                    .entry(f.offset)
                    .or_insert_with(|| f.name.clone());
            }
            for f in &st.fields {
                if let Some((bit, width)) = f.bitfield
                    && let Some(first) = first_by_off.get(&f.offset)
                {
                    bitfields.push((first.clone(), bit, width, f.name.clone()));
                }
            }
        }
        enum_fields.retain(|k, _| !ambiguous.contains(k));
        let used: HashSet<&str> = structs
            .values()
            .chain(value_structs.values())
            .flat_map(|h| h.fields.iter().map(|(_, n)| n.as_str()))
            .chain(
                stack_structs
                    .iter()
                    .flat_map(|s| s.fields.iter().map(|(_, _, n)| n.as_str())),
            )
            .map(|n| n.rsplit('.').next().unwrap_or(n))
            .collect();
        enum_fields.retain(|k, _| used.contains(k.as_str()));
        bitfields.retain(|(base, ..)| used.contains(base.as_str()));
    }
    let hints = TypeHints {
        floats,
        float_slots,
        spill_slots: written_pos_slots
            .difference(&read_pos_slots)
            .copied()
            .collect(),
        local_slots: recovery
            .as_ref()
            .map(|r| r.local_slots.iter().map(|(_, off)| *off).collect())
            .unwrap_or_default(),
        param_slots: recovery
            .as_ref()
            .map(|r| r.param_slots.iter().map(|(_, off)| *off).collect())
            .unwrap_or_default(),
        imports: imports.clone(),
        is_win64,
        thunk_targets: thunk_targets.clone(),
        callee_params,
        ret_type: debug_sig
            .map(|s| s.ret.clone())
            .or_else(|| archive_sig.as_ref().map(|s| s.ret.clone())),
        structs,
        value_structs,
        stack_structs,
        local_types,
        stack_names,
        enum_variants,
        enum_fields,
        bitfields,
        rbp_delta: recovery.as_ref().map(|r| r.rbp_delta).unwrap_or(0),
        rsp_at: recovery
            .as_ref()
            .map(|r| r.rsp_at.clone())
            .unwrap_or_default(),
        hidden_locals,
        call_result_addrs: call_result_addrs(pinstrs_in_func, {
            let debug_ret = debug_sig.is_some_and(|s| {
                let t = s.ret.trim();
                !t.is_empty() && !t.eq_ignore_ascii_case("void")
            });
            let archive_ret = archive_sig.as_ref().is_some_and(|s| {
                let t = s.ret.trim();
                !t.is_empty() && !t.eq_ignore_ascii_case("void")
            });
            debug_ret || archive_ret
        }),
        var_names: recovery
            .as_ref()
            .map(|r| std::sync::Arc::new(r.names.clone())),
        ..Default::default()
    };
    stats.t_hints = t_phase.elapsed();

    let ptr_ty = if is64 { "int64_t" } else { "int32_t" };
    let (ret_ty_str, params): (String, Vec<String>) = if let Some(sig) = debug_sig {
        let ret = if sig.ret.trim().is_empty() {
            "void".to_string()
        } else {
            normalize_type(&sig.ret)
        };
        let params = sig
            .params
            .iter()
            .enumerate()
            .map(|(i, dp)| {
                let name = recovery
                    .as_ref()
                    .and_then(|rv| rv.params.get(i).and_then(|id| rv.vars.get(*id as usize)))
                    .map(|v| v.name.clone())
                    .unwrap_or_else(|| sanitize_param_name(&dp.name, &format!("param_{}", i + 1)));
                format!("{} {}", normalize_type(&dp.type_name), name)
            })
            .collect();
        (ret, params)
    } else if let Some(sig) = archive_sig.as_ref() {
        let ret = if sig.ret.trim().is_empty() {
            "void".to_string()
        } else {
            sig.ret.clone()
        };
        let mut params: Vec<String> = Vec::with_capacity(sig.params.len());
        for (i, (ty, pname)) in sig.params.iter().enumerate() {
            let name = recovery
                .as_ref()
                .and_then(|rv| rv.params.get(i).and_then(|id| rv.vars.get(*id as usize)))
                .map(|v| v.name.clone())
                .unwrap_or_else(|| sanitize_param_name(pname, &format!("param_{}", i + 1)));
            params.push(format!("{} {}", ty, name));
        }
        if sig.varargs {
            params.push("...".to_string());
        }
        if let Some(rv) = recovery.as_ref() {
            for &id in rv.params.iter().skip(sig.params.len()) {
                let v = &rv.vars[id as usize];
                let ty = hints
                    .local_types
                    .get(&v.name)
                    .cloned()
                    .unwrap_or_else(|| v.ty.c_str().to_string());
                params.push(format!("{} {}", ty, v.name));
            }
        }
        (ret, params)
    } else {
        let ret = recovery
            .as_ref()
            .map(|r| r.ret_type.c_str().to_string())
            .unwrap_or_else(|| ptr_ty.to_string());
        let params: Vec<String> = if let Some(rv) = &recovery {
            rv.params
                .iter()
                .map(|&id| {
                    let v = &rv.vars[id as usize];
                    let ty = hints
                        .local_types
                        .get(&v.name)
                        .cloned()
                        .unwrap_or_else(|| v.ty.c_str().to_string());
                    format!("{} {}", ty, v.name)
                })
                .collect()
        } else {
            stack
                .variables
                .iter()
                .filter(|v| matches!(v.kind, crate::analysis::stack::VarKind::Parameter))
                .map(|v| format!("{} {}", ptr_ty, v.name))
                .collect()
        };
        (ret, params)
    };
    let sig = if params.is_empty() {
        format!("{} {}(void)", ret_ty_str, func_name)
    } else {
        format!("{} {}({})", ret_ty_str, func_name, params.join(", "))
    };
    lines.push(PseudoLine {
        indent: 0,
        text: sig,
        kind: LineKind::Signature,
        source_addr: None,
    });
    lines.push(PseudoLine {
        indent: 0,
        text: "{".into(),
        kind: LineKind::OpenBrace,
        source_addr: None,
    });

    if let Some(rv) = &recovery {
        for &id in &rv.locals {
            let v = &rv.vars[id as usize];
            if hints.hidden_locals.contains(&v.name) {
                continue;
            }
            let comment = match v.storage {
                variables::Loc::Stack { base, off } => {
                    let reg = if base == 0 { bp } else { sp };
                    format!("  // {}", fmt_frame_slot(reg, off))
                }
                _ => String::new(),
            };
            let decl = match hints.local_types.get(&v.name) {
                Some(t) => fmt_decl(t, &v.name),
                None => v.ty.decl(&v.name),
            };
            lines.push(PseudoLine {
                indent: 1,
                text: format!("{};{}", decl, comment),
                kind: LineKind::Declaration,
                source_addr: None,
            });
        }
        for v in &rv.vars {
            if hints.hidden_locals.contains(&v.name) {
                continue;
            }
            if matches!(v.storage, variables::Loc::Reg(_))
                && v.kind == variables::VarKind::Register
                && v.keep
                && v.use_count > 1
            {
                let decl = match hints.local_types.get(&v.name) {
                    Some(t) => fmt_decl(t, &v.name),
                    None => v.ty.decl(&v.name),
                };
                lines.push(PseudoLine {
                    indent: 1,
                    text: format!("{};", decl),
                    kind: LineKind::Declaration,
                    source_addr: None,
                });
            }
        }
    } else {
        let mut locals: Vec<&crate::analysis::stack::StackVar> = stack
            .variables
            .iter()
            .filter(|v| matches!(v.kind, crate::analysis::stack::VarKind::Local))
            .collect();
        locals.sort_by_key(|v| v.offset);
        for v in &locals {
            if hints.hidden_locals.contains(&v.name) {
                continue;
            }
            let ty = hints.local_types.get(&v.name).cloned().unwrap_or_else(|| {
                if hints.float_slots.contains(&v.offset) {
                    if v.size == 8 {
                        "double".to_string()
                    } else {
                        "float".to_string()
                    }
                } else {
                    c_type_for_size(v.size).to_string()
                }
            });
            let base = if stack.frame_size > 0 && v.offset >= 0 {
                sp
            } else {
                bp
            };
            lines.push(PseudoLine {
                indent: 1,
                text: format!(
                    "{};  // {}",
                    fmt_decl(&ty, &v.name),
                    fmt_frame_slot(base, v.offset)
                ),
                kind: LineKind::Declaration,
                source_addr: None,
            });
        }
    }
    let has_locals = lines
        .last()
        .is_some_and(|l| l.kind == LineKind::Declaration);
    if has_locals {
        lines.push(PseudoLine {
            indent: 0,
            text: "".into(),
            kind: LineKind::Comment,
            source_addr: None,
        });
    }

    let t_phase = Instant::now();
    let unthreaded: Option<CFG> = if STATE_MACHINE_UNTHREAD {
        state_machine::unthread(cfg, &bops, imap)
    } else {
        None
    };
    let cfg: &CFG = unthreaded.as_ref().unwrap_or(cfg);
    let graph = GraphView::from_cfg(cfg);

    let entry_id = entry_block(cfg);
    let back_edge_list = graph.back_edge_list(entry_id);
    let back_edges: HashMap<usize, usize> = back_edge_list.iter().copied().collect();
    stats.back_edges = back_edge_list.len();

    let param_seed: HashMap<&'static str, String> = recovery
        .as_ref()
        .map(|rv| {
            let mut m = HashMap::default();
            for &id in &rv.params {
                let v = &rv.vars[id as usize];
                if let variables::Loc::Reg(r) = v.storage {
                    m.insert(r, v.name.clone());
                }
            }
            m
        })
        .unwrap_or_default();
    let block_consts =
        compute_block_consts_cancellable(&graph, entry_id, &bops, is64, &param_seed, cancel);
    if is_cancelled(cancel) {
        stats.cancelled = true;
        stats.t_total = t_total.elapsed();
        return (finish_cancelled(cfg, func_name, lines), stats);
    }

    let dowhile = compute_dowhile(cfg, &bops, imap, &back_edges, &block_consts, &hints);
    let postdom = Postdom::compute(cfg);
    let loops = Loops::compute(cfg, entry_id, &back_edge_list);
    let t_ssa = Instant::now();
    let ssa = ssa::SsaFunction::build(cfg, &bops);
    let t_ssa_build = t_ssa.elapsed();
    if ssa.is_none() && std::env::var_os("RD_DEBUG_SSA").is_some() {
        eprintln!("[ssa] {func_name}: skipped ({} blocks)", cfg.blocks.len());
    }
    if let Some(view) = &ssa
        && std::env::var_os("RD_DEBUG_SSA").is_some()
        && let Err(err) = view.validate(cfg)
    {
        eprintln!("[ssa] {func_name}: {err}");
    }
    if let Some(view) = &ssa
        && std::env::var_os("RD_DEBUG_CANARY").is_some()
    {
        for v in &view.state_vars {
            eprintln!(
                "[ssa-state] {func_name}: header={} base={:?} kind={:?} dispatch={:?} consts={:?}",
                v.header,
                v.base,
                v.kind,
                v.dispatch.as_ref().map(|d| d.values.clone()),
                v.const_writes
            );
        }
    }
    let t_dce = Instant::now();
    let mut dead = compute_dead_ops_g(&graph, entry_id, &bops, cancel);
    if let Some(view) = &ssa {
        dead.extend(view.dead_stmts(cfg, &bops));
    }
    let t_ssa_dce = t_dce.elapsed();
    let mut safe_locals: HashSet<String> = HashSet::default();
    if let (Some(view), Some(rv)) = (&ssa, &recovery) {
        let mut stack_vars = 0usize;
        let mut one_def = 0usize;
        for v in &rv.vars {
            let variables::Loc::Stack { base, off } = v.storage else {
                continue;
            };
            stack_vars += 1;
            if view.def_count(ssa::BaseVar::Stack(base, off)) != 1 {
                continue;
            }
            one_def += 1;
            if let Some(name) = rv.names.stack_by_raw.get(&(base, off)) {
                safe_locals.insert(name.clone());
            }
        }
        if std::env::var_os("RD_DEBUG_CANARY").is_some() && stack_vars > 0 {
            eprintln!(
                "[safelocals] {func_name}: vars={} stack={stack_vars} one={one_def} safe={}",
                rv.vars.len(),
                safe_locals.len()
            );
        }
    }
    stats.dead_ops = dead.len();
    stats.t_dataflow = t_phase.elapsed();
    if is_cancelled(cancel) {
        stats.cancelled = true;
        stats.t_total = t_total.elapsed();
        return (finish_cancelled(cfg, func_name, lines), stats);
    }

    let t_phase = Instant::now();
    let mut visited: HashSet<usize> = HashSet::default();
    let ctx = WalkCtx {
        cfg,
        bops: &bops,
        imap,
        func_lookup,
        back_edges: &back_edges,
        block_consts: &block_consts,
        dowhile: &dowhile,
        dead: &dead,
        cancel,
        postdom: &postdom,
        loops: &loops,
        is64,
        hints: &hints,
        switches,
        ssa: ssa.as_ref(),
        clone: false,
        clone_depth: 0,
    };
    walk_block(&ctx, entry_id, &mut visited, &mut lines, 1, 0);
    debug_check_braces("walk_block", func_name, &lines, 1);
    stats.t_structure = t_phase.elapsed();
    stats.expr_overflows = EXPR_OVERFLOWS.with(|c| c.get()) as usize;
    if is_cancelled(cancel) {
        stats.cancelled = true;
        stats.t_total = t_total.elapsed();
        return (finish_cancelled(cfg, func_name, lines), stats);
    }

    let mut unmodeled = 0usize;
    let mut first_unmodeled: Option<String> = None;
    lines.retain(|l| {
        if l.text.starts_with('\u{1}') {
            unmodeled += 1;
            if first_unmodeled.is_none() {
                first_unmodeled = Some(l.text[1..].trim().to_string());
            }
            false
        } else {
            true
        }
    });
    stats.unmodeled_instrs = unmodeled;
    if unmodeled > 0 {
        lines.push(PseudoLine {
            indent: 1,
            text: format!(
                "// [{} instruction(s) not modeled by the lifter were omitted; first: {}]",
                unmodeled,
                first_unmodeled.unwrap_or_default()
            ),
            kind: LineKind::Comment,
            source_addr: None,
        });
    }

    if let Some(rv) = &recovery {
        variables::apply_names(&mut lines, rv);
    }
    if !param_renames.is_empty() {
        for line in lines.iter_mut() {
            line.text = rename_identifiers(&line.text, &param_renames);
        }
    }

    if !is64 {
        const X86_NAMES: &[(&str, &str)] = &[
            ("rax", "eax"),
            ("rbx", "ebx"),
            ("rcx", "ecx"),
            ("rdx", "edx"),
            ("rsi", "esi"),
            ("rdi", "edi"),
            ("rbp", "ebp"),
            ("rsp", "esp"),
        ];
        for line in lines.iter_mut() {
            line.text = rewrite_x86_reg_names(&line.text, X86_NAMES);
        }
    }

    drop_stack_canary(&mut lines);
    debug_check_braces("drop_stack_canary", func_name, &lines, 1);
    let bp_is_frame = recovery.as_ref().is_none_or(|rv| {
        rv.vars
            .iter()
            .any(|v| matches!(v.storage, variables::Loc::Stack { base: 0, .. }))
    });
    lines.retain(|l| !is_stack_bookkeeping(&l.text, bp_is_frame));
    drop_save_restore_comments(&mut lines);
    alias::propagate_aliases(&mut lines);
    alias::drop_callee_saved_bookkeeping(&mut lines);
    let t_forward = Instant::now();
    alias::drop_saved_register_restores(&mut lines);
    for _ in 0..2 {
        alias::forward_single_use_locals(&mut lines, &safe_locals);
        alias::forward_readonly_copies(&mut lines);
    }
    let t_forward = t_forward.elapsed();

    alias::inline_single_assignment_registers(&mut lines);
    alias::cse_repeated_expressions(&mut lines);
    alias::propagate_aliases(&mut lines);
    alias::drop_dead_register_assignments(&mut lines);
    alias::inline_single_use_temps(&mut lines);
    alias::drop_self_assignments(&mut lines);
    alias::propagate_aliases(&mut lines);
    alias::reuse_assigned_subexpressions(&mut lines);
    debug_check_braces("alias", func_name, &lines, 1);
    substitute_enum_values(&mut lines, &hints);
    fold_bitfield_accesses(&mut lines, &hints);
    fold_bitfield_stores(&mut lines, &hints);
    debug_check_braces("enum+bitfield", func_name, &lines, 1);
    squash_empty_branches(&mut lines);
    debug_check_braces("squash_empty_branches", func_name, &lines, 1);
    drop_call_arg_setups(&mut lines, is64, is_win64);
    drop_hidden_local_spills(&mut lines, &hints.hidden_locals, &final_param_names);
    debug_check_braces("tail passes", func_name, &lines, 1);

    if hints.out_truncated.get() {
        stats.truncated = true;
        lines.push(PseudoLine {
            indent: 1,
            text: format!(
                "// ... truncated: output budget reached, {} of {} blocks not emitted; use disassemble_function for the rest",
                cfg.blocks.len().saturating_sub(visited.len()),
                cfg.blocks.len()
            ),
            kind: LineKind::Comment,
            source_addr: None,
        });
    }
    lines.push(PseudoLine {
        indent: 0,
        text: "}".into(),
        kind: LineKind::CloseBrace,
        source_addr: None,
    });

    retarget_goto_chains(&mut lines);
    inline_terminal_block_regions(cfg, &mut lines);
    inline_terminal_gotos(&mut lines);
    retarget_goto_chains(&mut lines);
    inline_terminal_gotos(&mut lines);
    debug_check_braces("inline_terminal_gotos", func_name, &lines, 0);
    prune_unreachable_returns(&mut lines);
    debug_check_braces("prune_unreachable_returns", func_name, &lines, 0);
    elide_else_after_terminal(&mut lines);
    debug_check_braces("elide_else", func_name, &lines, 0);
    cleanup_labels(&mut lines);
    debug_check_braces("cleanup_labels", func_name, &lines, 0);
    alias::name_remaining_registers(&mut lines, !bp_is_frame);
    alias::inline_single_use_temps(&mut lines);
    alias::propagate_aliases(&mut lines);
    let t_tmp = Instant::now();
    if let Some(view) = &ssa {
        let existing = alias::collect_identifiers(&lines);
        let plan = view.temp_name_plan(&bops, &existing);
        alias::name_temporary_values(&mut lines, &plan);
    }
    let t_tmp = t_tmp.elapsed();
    alias::drop_self_assignments(&mut lines);
    ghidra_type_names(&mut lines);
    ghidra_function_names(&mut lines);
    let writes_rax = pinstrs_in_func
        .iter()
        .flat_map(|p| p.ops.iter())
        .any(|op| written_reg(op) == Some("rax"));
    infer_void_return(&mut lines, !writes_rax);
    alias::remove_unused_declarations(&mut lines);
    debug_goto_classes(func_name, &lines);
    debug_line_histogram(func_name, &lines);
    debug_other_shapes(func_name, &lines);

    if std::env::var_os("RD_DEBUG_TIME").is_some() {
        eprintln!(
            "[t] {:x} b={} T={} S={} D={} H={} F={} M={}",
            cfg.func_entry,
            cfg.blocks.len(),
            t_total.elapsed().as_micros(),
            t_ssa_build.as_micros(),
            t_ssa_dce.as_micros(),
            stats.t_hints.as_micros(),
            t_forward.as_micros(),
            t_tmp.as_micros()
        );
    }
    stats.emitted_lines = lines.len();
    stats.output_bytes = lines.iter().map(|l| l.text.len()).sum();
    stats.t_total = t_total.elapsed();
    (make_pseudocode(cfg, func_name, lines), stats)
}

fn infer_void_return(lines: &mut [PseudoLine], allow: bool) {
    if !allow {
        return;
    }
    let mut has_return = false;
    let mut has_value_return = false;
    for line in lines.iter().skip(1) {
        if line.kind != LineKind::Return {
            continue;
        }
        has_return = true;
        if line.text.trim() != "return;" {
            has_value_return = true;
            break;
        }
    }
    if !has_return || has_value_return {
        return;
    }
    let Some(sig) = lines.first_mut() else {
        return;
    };
    if sig.kind != LineKind::Signature {
        return;
    }
    let Some(space) = sig.text.find(' ') else {
        return;
    };
    if !matches!(&sig.text[..space], "longlong" | "int" | "long") {
        return;
    }
    sig.text = format!("void {}", &sig.text[space + 1..]);
}

fn ghidra_type_name(name: &str) -> Option<&'static str> {
    Some(match name {
        "int8_t" => "char",
        "uint8_t" => "byte",
        "int16_t" => "short",
        "uint16_t" => "ushort",
        "int32_t" => "int",
        "uint32_t" => "uint",
        "int64_t" => "longlong",
        "uint64_t" => "ulonglong",
        "intptr_t" => "longlong",
        "uintptr_t" => "ulonglong",
        _ => return None,
    })
}

fn ghidra_type_names(lines: &mut [PseudoLine]) {
    for line in lines.iter_mut() {
        if line.kind == LineKind::Comment {
            continue;
        }
        let (code, comment) = match line.text.find("//") {
            Some(i) => line.text.split_at(i),
            None => (line.text.as_str(), ""),
        };
        let bytes = code.as_bytes();
        let mut out = String::with_capacity(code.len() + 8);
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_alphabetic() || c == b'_' {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &code[start..i];
                out.push_str(ghidra_type_name(word).unwrap_or(word));
            } else {
                let ch = code[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        out.push_str(comment);
        line.text = out;
    }
}

fn ghidra_function_names(lines: &mut [PseudoLine]) {
    for line in lines.iter_mut() {
        if line.kind == LineKind::Comment {
            continue;
        }
        let (code, comment) = match line.text.find("//") {
            Some(i) => line.text.split_at(i),
            None => (line.text.as_str(), ""),
        };
        let bytes = code.as_bytes();
        let mut out = String::with_capacity(code.len() + 8);
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_alphabetic() || c == b'_' {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &code[start..i];
                let renamed = word
                    .strip_prefix("thunk_sub_")
                    .filter(|hex| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
                    .map(|hex| format!("thunk_FUN_{hex}"))
                    .or_else(|| {
                        word.strip_prefix("sub_")
                            .filter(|hex| {
                                !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
                            })
                            .map(|hex| format!("FUN_{hex}"))
                    });
                out.push_str(renamed.as_deref().unwrap_or(word));
            } else {
                let ch = code[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        out.push_str(comment);
        line.text = out;
    }
}

fn parse_c_int(s: &str) -> Option<i64> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let v = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else {
        s.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}

fn substitute_enum_values(lines: &mut [PseudoLine], hints: &TypeHints) {
    if hints.enum_fields.is_empty() || hints.enum_variants.is_empty() {
        return;
    }
    let by_value: HashMap<&str, HashMap<i64, &str>> = hints
        .enum_variants
        .iter()
        .map(|(e, vs)| {
            (
                e.as_str(),
                vs.iter().map(|(n, v)| (*v, n.as_str())).collect(),
            )
        })
        .collect();
    const OPS: [&str; 7] = [" >= ", " <= ", " == ", " != ", " > ", " < ", " = "];

    for line in lines.iter_mut() {
        if !line.text.contains('.') {
            continue;
        }
        let text = line.text.as_str();
        let bytes = text.as_bytes();
        let mut out = String::new();
        let mut copied = 0usize;
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] != b'.' {
                i += 1;
                continue;
            }
            let fs = i + 1;
            let mut fe = fs;
            while fe < bytes.len() && (bytes[fe].is_ascii_alphanumeric() || bytes[fe] == b'_') {
                fe += 1;
            }
            i = fe.max(fs);
            let Some(enum_name) = hints.enum_fields.get(&text[fs..fe]) else {
                continue;
            };
            let Some(op) = OPS.iter().find(|op| text[fe..].starts_with(**op)) else {
                continue;
            };
            let vs = fe + op.len();
            let mut ve = vs;
            while ve < bytes.len() && (bytes[ve].is_ascii_alphanumeric() || bytes[ve] == b'-') {
                ve += 1;
            }
            let Some(val) = parse_c_int(&text[vs..ve]) else {
                continue;
            };
            let Some(name) = by_value.get(enum_name.as_str()).and_then(|m| m.get(&val)) else {
                continue;
            };
            out.push_str(&text[copied..vs]);
            out.push_str(name);
            copied = ve;
        }
        if copied > 0 {
            out.push_str(&text[copied..]);
            line.text = out;
        }
    }
}

fn fold_bitfield_accesses(lines: &mut [PseudoLine], hints: &TypeHints) {
    struct Pat<'a> {
        needle: String,
        tails: Vec<String>,
        name: &'a str,
    }
    let pats: Vec<Pat> = hints
        .bitfields
        .iter()
        .filter(|(_, bit, width, _)| *width > 0 && *bit as u32 + *width as u32 <= 32)
        .map(|(base, bit, width, name)| {
            let mask = (1u64 << *width) - 1;
            let mut forms = vec![format!("{:#x}", mask)];
            let upper = format!("0x{:X}", mask);
            if upper != forms[0] {
                forms.push(upper);
            }
            Pat {
                needle: format!(".{base}"),
                tails: forms
                    .iter()
                    .map(|f| {
                        if *bit == 0 {
                            format!(" & {}", f)
                        } else {
                            format!(" >> {} & {}", bit, f)
                        }
                    })
                    .collect(),
                name: name.as_str(),
            }
        })
        .collect();
    if pats.is_empty() {
        return;
    }
    for line in lines.iter_mut() {
        let mut text = std::mem::take(&mut line.text);
        for p in &pats {
            if !text.contains(&p.needle) {
                continue;
            }
            for tail in &p.tails {
                let mut from = 0;
                while let Some(rel) = text[from..].find(&p.needle) {
                    let at = from + rel;
                    let after = at + p.needle.len();
                    if text[after..].starts_with(tail.as_str())
                        && !text[after + tail.len()..]
                            .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                        && let Some(start) = field_expr_start(&text, at)
                    {
                        let repl = format!("{}.{}", &text[start..at], p.name);
                        text.replace_range(start..after + tail.len(), &repl);
                        from = start + repl.len();
                    } else {
                        from = after;
                    }
                }
            }
        }
        line.text = text;
    }
}

fn field_expr_start(text: &str, dot: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut start = dot;
    while start > 0 {
        let c = bytes[start - 1] as char;
        if c.is_ascii_alphanumeric() || c == '_' || c == '>' || c == '-' {
            start -= 1;
        } else {
            break;
        }
    }
    let first = text[start..dot].chars().next()?;
    (first.is_ascii_alphabetic() || first == '_').then_some(start)
}

fn bitfield_store_value(rhs: &str, lhs: &str, hints: &TypeHints) -> Option<(String, String)> {
    let and_at = rhs.find(" & ")?;
    let or_at = rhs[and_at + 3..].find(" | ")? + and_at + 3;
    let src = rhs[..and_at].trim().trim_matches(|c| c == '(' || c == ')');
    if src != lhs {
        return None;
    }
    let mask_text = rhs[and_at + 3..or_at]
        .trim()
        .trim_matches(|c| c == '(' || c == ')');
    let value_text = rhs[or_at + 3..]
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_matches(|c| c == '(' || c == ')');
    let mask = parse_c_int(mask_text)? as u64;
    let value = parse_c_int(value_text)? as u64;
    let field = lhs.rsplit('.').next()?;
    let (base, _) = lhs.split_once('.')?;
    for (bf_base, bit, width, bf_name) in &hints.bitfields {
        if bf_base != field || *width == 0 || *width > 31 {
            continue;
        }
        let run = ((1u64 << *width) - 1) << *bit;
        if mask & run != 0 || (mask | run) != u32::MAX as u64 {
            continue;
        }
        if value & !run != 0 {
            continue;
        }
        return Some((format!("{}.{}", base, bf_name), (value >> bit).to_string()));
    }
    None
}

fn fold_bitfield_stores(lines: &mut Vec<PseudoLine>, hints: &TypeHints) {
    if hints.bitfields.is_empty() {
        return;
    }
    let mut remove: HashSet<usize> = HashSet::default();
    for i in 0..lines.len() {
        if lines[i].kind == LineKind::Comment {
            continue;
        }
        let Some((lhs, rhs)) = alias::assignment_parts(&lines[i].text) else {
            continue;
        };
        if let Some((target, value)) = bitfield_store_value(rhs, lhs, hints) {
            lines[i].text = format!("{} = {};", target, value);
            continue;
        }
        if i + 1 >= lines.len() || remove.contains(&(i + 1)) {
            continue;
        }
        if lines[i + 1].kind == LineKind::Comment {
            continue;
        }
        let Some((next_lhs, next_rhs)) = alias::assignment_parts(&lines[i + 1].text) else {
            continue;
        };
        if next_rhs.trim_end_matches(';').trim() != lhs {
            continue;
        }
        if let Some((target, value)) = bitfield_store_value(rhs, next_lhs, hints) {
            lines[i].text = format!("{} = {};", target, value);
            remove.insert(i + 1);
        }
    }
    if !remove.is_empty() {
        let mut idx = 0;
        lines.retain(|_| {
            let keep = !remove.contains(&idx);
            idx += 1;
            keep
        });
    }
}

fn debug_check_braces(stage: &str, name: &str, lines: &[PseudoLine], expected: i32) {
    if std::env::var_os("RDDB_DEBUG_BRACES").is_none() {
        return;
    }
    let (mut depth, mut min) = (0i32, 0i32);
    for l in lines {
        for ch in code_part(&l.text).chars() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    min = min.min(depth);
                }
                _ => {}
            }
        }
    }
    if depth != expected || min < 0 {
        eprintln!("[braces] {name}: after {stage}: depth={depth} (expected {expected}) min={min}");
    }
}

fn debug_goto_classes(name: &str, lines: &[PseudoLine]) {
    if std::env::var_os("RDDB_DEBUG_GOTOS").is_none() {
        return;
    }
    let (mut tail, mut back, mut irr) = (0usize, 0usize, 0usize);
    let mut back_targets: HashMap<String, usize> = HashMap::default();
    for (i, class) in classify_gotos(lines) {
        match class {
            GotoClass::SharedTail => tail += 1,
            GotoClass::Backward => {
                back += 1;
                if let Some(t) = lines[i].text.trim().strip_prefix("goto ") {
                    *back_targets
                        .entry(t.trim_end_matches(';').to_string())
                        .or_default() += 1;
                }
            }
            GotoClass::Irreducible => irr += 1,
        }
    }
    if tail + back + irr > 0 {
        let mut top: Vec<(&String, &usize)> = back_targets.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let top: Vec<String> = top
            .iter()
            .take(5)
            .map(|&(k, v)| format!("{k}x{v}"))
            .collect();
        eprintln!(
            "[gotos] {name}: shared_tail={tail} backward={back} irreducible={irr} backward_targets={} top=[{}]",
            back_targets.len(),
            top.join(",")
        );
    }
}

fn debug_line_histogram(name: &str, lines: &[PseudoLine]) {
    if std::env::var_os("RDDB_DEBUG_HIST").is_none() {
        return;
    }
    let (mut blank, mut comments, mut braces, mut gotos, mut labels, mut decls, mut other) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for l in lines {
        let t = l.text.trim();
        if t.is_empty() {
            blank += 1;
        } else if t.starts_with("//") {
            comments += 1;
        } else if t == "}" || t == "} else {" || t == "{" {
            braces += 1;
        } else if t.starts_with("goto ") {
            gotos += 1;
        } else if t.starts_with("LAB_") && t.ends_with(':') {
            labels += 1;
        } else if l.kind == LineKind::Declaration {
            decls += 1;
        } else {
            other += 1;
        }
    }
    eprintln!(
        "[hist] {name}: total={} decl={decls} comment={comments} brace={braces} goto={gotos} label={labels} blank={blank} other={other}",
        lines.len()
    );
}

fn debug_state_candidates(name: &str, bops: &[Vec<(u64, &POp)>]) {
    if std::env::var_os("RDDB_DEBUG_SM").is_none() {
        return;
    }
    use super::state_machine::{StateSlot, const_value, slot_of, state_write};
    let mut writes: HashMap<StateSlot, HashSet<usize>> = HashMap::default();
    let mut cmps: HashMap<StateSlot, HashSet<usize>> = HashMap::default();
    for (blk, ops) in bops.iter().enumerate() {
        let mut loaded: HashMap<String, StateSlot> = HashMap::default();
        for &(_, op) in ops {
            match op {
                POp::Load { dst, addr, .. } => {
                    if let Some(slot) = slot_of(addr) {
                        loaded.insert(fmt_var(dst), slot);
                    }
                }
                POp::Copy { dst, src, .. } => {
                    if !matches!(dst, PVar::Reg(_) | PVar::Tmp(_)) {
                        continue;
                    }
                    if let Some(slot) = slot_of(src) {
                        loaded.insert(fmt_var(dst), slot);
                    } else if let Some(slot) = loaded.get(&fmt_var(src)).cloned() {
                        loaded.insert(fmt_var(dst), slot);
                    }
                }
                POp::Cmp { a, b, .. } => {
                    if const_value(b).is_some()
                        && let Some(slot) = loaded.get(&fmt_var(a))
                    {
                        cmps.entry(slot.clone()).or_default().insert(blk);
                    }
                }
                _ => {}
            }
            if let Some((slot, src, _)) = state_write(op)
                && const_value(src).is_some()
            {
                writes.entry(slot).or_default().insert(blk);
            }
        }
    }
    let mut best: Vec<(StateSlot, usize, usize)> = writes
        .iter()
        .map(|(k, w)| (k.clone(), w.len(), cmps.get(k).map_or(0, |c| c.len())))
        .collect();
    best.sort_by_key(|(k, w, c)| (std::cmp::Reverse((*w).min(*c)), format!("{k:?}")));
    for (k, w, c) in best.into_iter().take(3) {
        if w.min(c) >= 4 {
            eprintln!("[sm] {name}: slot={k:?} const_write_blocks={w} cmp_blocks={c}");
        } else if bops.len() > 50 {
            eprintln!("[sm-top] {name}: slot={k:?} const_write_blocks={w} cmp_blocks={c}");
        }
    }
}

fn line_shape(t: &str) -> String {
    let b = t.as_bytes();
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let s = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let word = &t[s..i];
            if matches!(
                word,
                "if" | "while" | "switch" | "return" | "else" | "break" | "continue"
            ) {
                out.push_str(word);
            } else if b.get(i) == Some(&b'(') {
                out.push('F');
            } else {
                out.push('v');
            }
        } else if c.is_ascii_digit() {
            while i < b.len() && b[i].is_ascii_alphanumeric() {
                i += 1;
            }
            out.push('N');
        } else {
            let ch = t[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn debug_other_shapes(name: &str, lines: &[PseudoLine]) {
    if std::env::var_os("RDDB_DEBUG_SHAPES").is_none() || lines.len() < 500 {
        return;
    }
    let mut shapes: HashMap<String, usize> = HashMap::default();
    for l in lines {
        let t = l.text.trim();
        if t.is_empty()
            || t.starts_with("//")
            || t == "}"
            || t == "} else {"
            || t == "{"
            || t.starts_with("goto ")
            || (t.starts_with("LAB_") && t.ends_with(':'))
            || l.kind == LineKind::Declaration
        {
            continue;
        }
        *shapes.entry(line_shape(t)).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = shapes.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (shape, count) in v.into_iter().take(12) {
        eprintln!("[shapes] {name}: {count:>5}  {shape}");
    }
}

const HIDE_SAVE_RESTORE_COMMENTS: bool = true;

fn drop_save_restore_comments(lines: &mut Vec<PseudoLine>) {
    if !HIDE_SAVE_RESTORE_COMMENTS {
        return;
    }
    lines.retain(|l| {
        if l.kind != LineKind::Comment {
            return true;
        }
        let t = l.text.trim();
        let Some(rest) = t
            .strip_prefix("// push ")
            .or_else(|| t.strip_prefix("// pop "))
        else {
            return true;
        };
        let rest = rest.trim();
        let is_reg =
            !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        !is_reg
    });
}

fn drop_stack_canary(lines: &mut Vec<PseudoLine>) {
    let mut remove: HashSet<usize> = HashSet::default();
    let mut canary_locals: HashSet<String> = HashSet::default();
    for i in 0..lines.len() {
        let t = lines[i].text.trim();
        let is_canary_load = (t.contains("*(fs:") || t.contains("*(gs:"))
            && (t.contains("+ 0x28") || t.contains("+ 0x14"));
        let is_cookie_init = t.contains("^ rsp");
        if !is_canary_load && !is_cookie_init {
            continue;
        }
        remove.insert(i);
        let Some((dest, _)) = t.split_once(" = ") else {
            continue;
        };
        let dest = dest.trim();
        if dest.starts_with("local_") || dest.starts_with("tmp_") || dest.starts_with("stk_") {
            canary_locals.insert(dest.to_string());
        }
        let Some(j) = (i + 1..lines.len()).find(|&j| !lines[j].text.trim().is_empty()) else {
            continue;
        };
        let Some((lhs, rhs)) = lines[j].text.split_once(" = ") else {
            continue;
        };
        let rhs = rhs
            .split("//")
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches(';')
            .trim();
        let lhs = lhs.trim();
        let same_cookie = rhs.contains("*(fs:") || rhs.contains("*(gs:");
        if (rhs == dest || same_cookie)
            && (lhs.starts_with("local_") || lhs.starts_with("tmp_") || lhs.starts_with("stk_"))
        {
            canary_locals.insert(lhs.to_string());
            remove.insert(j);
        }
    }
    if remove.is_empty() {
        if std::env::var_os("RD_DEBUG_CANARY").is_some() {
            for line in lines.iter().filter(|l| l.text.contains("^ rsp")).take(4) {
                eprintln!("[canary] seen: {:?}", line.text);
            }
        }
        return;
    }
    if std::env::var_os("RD_DEBUG_CANARY").is_some() {
        eprintln!("[canary] removing {} line(s)", remove.len());
    }
    for (i, line) in lines.iter().enumerate() {
        if line.text.contains(['{', '}']) {
            continue;
        }
        if line.text.contains("__stack_chk_fail")
            || line.text.contains("__security_check_cookie")
            || line.text.contains("__security_cookie")
        {
            remove.insert(i);
        }
        let c = line.text.split("//").next().unwrap_or("").trim();
        if c.contains("^ rsp") {
            remove.insert(i);
        }
    }
    for (i, line) in lines.iter().enumerate() {
        let t = line.text.split("//").next().unwrap_or("").trim();
        if line.kind == LineKind::Declaration
            && t.split_whitespace()
                .last()
                .is_some_and(|w| canary_locals.contains(w.trim_end_matches(';')))
        {
            remove.insert(i);
            continue;
        }
        let Some((lhs, rhs)) = t.split_once(" = ") else {
            continue;
        };
        let rhs = rhs.trim().trim_end_matches(';').trim();
        let lhs = lhs.trim();
        if canary_locals.contains(lhs) && canary_locals.contains(rhs) {
            remove.insert(i);
        }
        if canary_locals.contains(rhs) && lhs != rhs {
            remove.insert(i);
        }
    }
    let mut idx = 0usize;
    lines.retain(|_| {
        let keep = !remove.contains(&idx);
        idx += 1;
        keep
    });
}

fn fmt_decl(ty: &str, name: &str) -> String {
    let ty = normalize_type(ty);
    if let Some(p) = ty.find("(*)") {
        format!("{}(*{}){}", &ty[..p], name, &ty[p + 3..])
    } else if let Some(p) = ty.find('[') {
        format!("{} {}{}", ty[..p].trim_end(), name, &ty[p..])
    } else {
        format!("{} {}", ty, name)
    }
}

fn normalize_type(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_space = false;
    for ch in text.trim().chars() {
        if ch == ' ' {
            if !last_space {
                out.push(ch);
            }
            last_space = true;
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out
}

fn sanitize_param_name(name: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let mut out = out.trim_matches('_').to_string();
    if out.is_empty() {
        return fallback.to_string();
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    if is_c_keyword(&out) {
        format!("p_{}", out)
    } else {
        out
    }
}

fn is_c_keyword(s: &str) -> bool {
    matches!(
        s,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Bool"
            | "bool"
            | "true"
            | "false"
            | "NULL"
            | "_Atomic"
            | "_Noreturn"
    )
}

fn rename_identifiers(text: &str, map: &HashMap<String, String>) -> String {
    if map.is_empty() {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut copied) = (0usize, 0usize);
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            if let Some(rep) = map.get(&text[start..i]) {
                out.push_str(&text[copied..start]);
                out.push_str(rep);
                copied = i;
            }
        } else if c.is_ascii_digit() {
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

fn param_is_float(type_name: &str) -> bool {
    let t = type_name.trim();
    if t.contains('*') || t.contains('[') || t.contains("long double") {
        return false;
    }
    t.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|tok| {
            matches!(
                tok,
                "float" | "double" | "_Float16" | "_Float32" | "_Float64" | "FLOAT" | "DOUBLE"
            )
        })
}

fn build_callee_params(
    debug: Option<&DebugTypes>,
    imports: &HashMap<u64, String>,
    thunk_targets: &HashMap<u64, u64>,
) -> HashMap<u64, Vec<bool>> {
    let mut map: HashMap<u64, Vec<bool>> = debug
        .map(|d| {
            d.functions
                .iter()
                .map(|(&a, f)| {
                    (
                        a,
                        f.params
                            .iter()
                            .map(|p| param_is_float(&p.type_name))
                            .collect(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    for (&addr, name) in imports {
        if let Some(n) = known_import_param_count(name) {
            map.entry(addr).or_insert_with(|| vec![false; n]);
        }
    }
    for &from in thunk_targets.keys() {
        let mut to = from;
        for _ in 0..8 {
            match thunk_targets.get(&to) {
                Some(&t) if t != to => to = t,
                _ => break,
            }
        }
        if to != from
            && let Some(sig) = map.get(&to).cloned()
        {
            map.insert(from, sig);
        }
    }
    map
}

fn known_import_param_count(name: &str) -> Option<usize> {
    let base = name.rsplit('!').next().unwrap_or(name);
    let base = base.trim_start_matches("__imp_").to_ascii_lowercase();
    if let Some((_, n)) = base.rsplit_once('@')
        && let Ok(bytes) = n.parse::<usize>()
        && bytes % 4 == 0
    {
        return Some(bytes / 4);
    }
    match base.as_str() {
        "__stack_chk_fail" | "__stack_chk_fail_local" => Some(0),
        "abort" => Some(0),
        "getlasterror" | "getprocessid" | "getcurrentprocessid" => Some(0),
        "free" | "malloc" | "strlen" | "puts" | "exit" | "_exit" | "sleep" | "closehandle"
        | "exitprocess" | "fclose" | "close" | "loadlibrarya" | "loadlibraryw"
        | "getmodulehandlea" | "getmodulehandlew" => Some(1),
        "memcpy" | "memmove" | "memset" | "strncmp" | "strncpy" | "heapalloc" | "heapfree"
        | "read" | "write" => Some(3),
        "strcpy" | "strcmp" | "calloc" | "realloc" | "strcat" | "fopen" | "getprocaddress" => {
            Some(2)
        }
        _ => None,
    }
}

fn drop_hidden_local_spills(
    lines: &mut Vec<PseudoLine>,
    hidden: &HashSet<String>,
    params: &HashSet<String>,
) {
    if hidden.is_empty() || params.is_empty() {
        return;
    }
    lines.retain(|line| {
        let t = line.text.split("//").next().unwrap_or("").trim();
        let Some((lhs, rhs)) = t.split_once(" = ") else {
            return true;
        };
        if !hidden.contains(lhs.trim()) {
            return true;
        }
        !params.contains(rhs.trim())
    });
}

fn drop_call_arg_setups(lines: &mut Vec<PseudoLine>, is64: bool, is_win64: bool) {
    if !is64 {
        return;
    }
    let is_arg = |reg: &str| {
        if is_win64 {
            WIN64_ARG_REGS.contains(&reg) || matches!(reg, "xmm0" | "xmm1" | "xmm2" | "xmm3")
        } else {
            ABI_ARG_REGS.contains(&reg) || SSE_ARG_REGS.contains(&reg)
        }
    };
    let mut drop = vec![false; lines.len()];
    for i in 0..lines.len() {
        if lines[i].kind != LineKind::Call {
            continue;
        }
        let mut j = i;
        while j > 0 {
            j -= 1;
            if drop[j] {
                continue;
            }
            let t = lines[j].text.trim();
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            let Some((lhs, _)) = t.split_once(" = ") else {
                break;
            };
            if is_arg(canonical_reg(lhs.trim())) {
                drop[j] = true;
            } else {
                break;
            }
        }
    }
    let mut k = 0;
    lines.retain(|_| {
        let keep = !drop[k];
        k += 1;
        keep
    });
}

fn entry_block(cfg: &CFG) -> usize {
    cfg.block_at.get(&cfg.func_entry).copied().unwrap_or(0)
}

pub(crate) struct GraphView {
    succs: Vec<Vec<usize>>,
    preds: Vec<Vec<usize>>,
}

impl GraphView {
    pub(crate) fn from_cfg(cfg: &CFG) -> Self {
        let n = cfg.blocks.len();
        let succs: Vec<Vec<usize>> = cfg
            .blocks
            .iter()
            .map(|b| {
                b.successors
                    .iter()
                    .map(|e| e.target)
                    .filter(|&t| t < n)
                    .collect()
            })
            .collect();
        Self::from_succs(succs)
    }

    fn from_succs(mut succs: Vec<Vec<usize>>) -> Self {
        for ss in succs.iter_mut() {
            match ss.len() {
                0 | 1 => {}
                2 => {
                    if ss[0] == ss[1] {
                        ss.pop();
                    }
                }
                _ => {
                    let mut seen: HashSet<usize> = HashSet::default();
                    ss.retain(|s| seen.insert(*s));
                }
            }
        }
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); succs.len()];
        for (b, ss) in succs.iter().enumerate() {
            for &s in ss {
                preds[s].push(b);
            }
        }
        Self { succs, preds }
    }

    fn len(&self) -> usize {
        self.succs.len()
    }

    fn dfs(&self, entry: usize) -> (Vec<usize>, Vec<(usize, usize)>) {
        let n = self.len();
        let mut post = Vec::new();
        let mut back = Vec::new();
        if entry >= n {
            return (post, back);
        }
        let mut state = vec![0u8; n];
        let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
        state[entry] = 1;
        while let Some(top) = stack.last_mut() {
            let (b, i) = *top;
            match self.succs[b].get(i) {
                Some(&t) => {
                    top.1 += 1;
                    match state[t] {
                        0 => {
                            state[t] = 1;
                            stack.push((t, 0));
                        }
                        1 => back.push((t, b)),
                        _ => {}
                    }
                }
                None => {
                    state[b] = 2;
                    post.push(b);
                    stack.pop();
                }
            }
        }
        (post, back)
    }

    #[allow(dead_code)]
    fn back_edges(&self, entry: usize) -> HashMap<usize, usize> {
        self.dfs(entry).1.into_iter().collect()
    }

    fn back_edge_list(&self, entry: usize) -> Vec<(usize, usize)> {
        self.dfs(entry).1
    }

    fn reverse_post_order(&self, entry: usize) -> Vec<usize> {
        let mut post = self.dfs(entry).0;
        post.reverse();
        post
    }
}

pub(crate) fn build_block_ops_from_slice<'a>(
    cfg: &CFG,
    pinstrs: &'a [PInstr],
) -> Vec<Vec<(u64, &'a POp)>> {
    let mut order: Vec<&'a PInstr> = pinstrs.iter().collect();
    if !order.is_sorted_by_key(|p| p.address) {
        order.sort_by_key(|p| p.address);
    }
    let mut table: Vec<Vec<(u64, &'a POp)>> = Vec::with_capacity(cfg.blocks.len());
    for block in &cfg.blocks {
        let lo = order.partition_point(|p| p.address < block.start);
        let hi = order.partition_point(|p| p.address < block.end).max(lo);
        let mut ops = Vec::new();
        for pi in order[lo..hi].iter().copied() {
            for op in &pi.ops {
                ops.push((pi.address, op));
            }
        }
        table.push(ops);
    }
    table
}
fn intern(s: &str) -> &'static str {
    static POOL: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let mut pool = POOL
        .get_or_init(|| Mutex::new(HashSet::default()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(&hit) = pool.get(s) {
        return hit;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    pool.insert(leaked);
    leaked
}

fn slot_var_name(off: i64) -> &'static str {
    thread_local! {
        static CACHE: RefCell<HashMap<i64, &'static str>> = RefCell::new(HashMap::default());
    }
    CACHE.with(|c| {
        let cached = c.borrow().get(&off).copied();
        if let Some(n) = cached {
            return n;
        }
        let s = if off < 0 {
            format!("local_{:X}", off.unsigned_abs())
        } else {
            format!("arg_{:X}", off)
        };
        let n = intern(&s);
        c.borrow_mut().insert(off, n);
        n
    })
}

fn meet_env(acc: &mut Env, other: &Env) {
    acc.retain(|k, v| match other.get(k) {
        Some(o) if *o == *v => true,
        Some(_) => {
            *v = Lattice::Top;
            true
        }
        None => false,
    });
}
pub(crate) fn compute_block_consts_cancellable(
    graph: &GraphView,
    entry: usize,
    bops: &[Vec<(u64, &POp)>],
    is64: bool,
    param_seed: &HashMap<&'static str, String>,
    cancel: Option<&AtomicBool>,
) -> Vec<HashMap<&'static str, Lattice>> {
    let n = graph.len();
    if n == 0 {
        return Vec::new();
    }
    let seed_env: Env = if is64 {
        param_seed
            .iter()
            .map(|(r, name)| (*r, Lattice::Var(intern(name))))
            .collect()
    } else {
        Env::default()
    };

    let mut order = graph.reverse_post_order(entry);
    if order.len() < n {
        let mut seen = vec![false; n];
        for &b in &order {
            seen[b] = true;
        }
        order.extend((0..n).filter(|&b| !seen[b]));
    }
    let mut queue: VecDeque<usize> = order.into();
    let mut queued = vec![true; n];
    let mut ins: Vec<Env> = vec![Env::default(); n];
    let mut outs: Vec<Option<Env>> = vec![None; n];
    let budget = n.saturating_mul(64).saturating_add(1024);
    let mut steps = 0usize;

    while let Some(b) = queue.pop_front() {
        queued[b] = false;
        steps += 1;
        if steps > budget || (steps & 0xFF == 0 && is_cancelled(cancel)) {
            return vec![Env::default(); n];
        }

        let mut acc: Option<Env> = (b == entry).then(|| seed_env.clone());
        for &p in &graph.preds[b] {
            if let Some(po) = &outs[p] {
                acc = Some(match acc.take() {
                    None => po.clone(),
                    Some(mut a) => {
                        meet_env(&mut a, po);
                        a
                    }
                });
            }
        }
        let in_state = acc.unwrap_or_default();

        let mut env = in_state.clone();
        for (_, op) in &bops[b] {
            transfer(op, &mut env);
        }
        ins[b] = in_state;

        if outs[b].as_ref() != Some(&env) {
            outs[b] = Some(env);
            for &s in &graph.succs[b] {
                if !queued[s] {
                    queued[s] = true;
                    queue.push_back(s);
                }
            }
        }
    }
    ins
}

fn const_of(v: &PVar, env: &Env) -> Option<i64> {
    match v {
        PVar::Const(c) => Some(*c),
        PVar::Reg(r) => match env.get(r) {
            Some(Lattice::Const(c)) => Some(*c),
            _ => None,
        },
        _ => None,
    }
}

fn var_of(v: &PVar, env: &Env) -> Option<&'static str> {
    match v {
        PVar::Reg(r) => match env.get(r) {
            Some(Lattice::Var(n)) => Some(*n),
            _ => None,
        },
        _ => None,
    }
}

fn set_reg(env: &mut Env, dst: &PVar, val: Lattice) {
    if let PVar::Reg(r) = dst {
        env.insert(*r, val);
    }
}

fn same_reg(a: &PVar, b: &PVar) -> bool {
    matches!((a, b), (PVar::Reg(x), PVar::Reg(y)) if x == y)
}

fn wrap(v: i64, size: u32) -> i64 {
    match size {
        1 => v as u8 as i64,
        2 => v as u16 as i64,
        4 => v as u32 as i64,
        _ => v,
    }
}

fn sext(v: i64, size: u32) -> i64 {
    match size {
        1 => v as i8 as i64,
        2 => v as i16 as i64,
        4 => v as i32 as i64,
        _ => v,
    }
}

pub(crate) fn transfer(op: &POp, env: &mut HashMap<&'static str, Lattice>) {
    match op {
        POp::Copy { dst, src, .. } => {
            let v = if let Some(c) = const_of(src, env) {
                Lattice::Const(c)
            } else if let Some(n) = var_of(src, env) {
                Lattice::Var(n)
            } else {
                Lattice::Top
            };
            set_reg(env, dst, v);
        }
        POp::IntAdd { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(wrap(x.wrapping_add(y), *size)),
                (None, Some(0)) => var_of(a, env).map_or(Lattice::Top, Lattice::Var),
                (Some(0), None) => var_of(b, env).map_or(Lattice::Top, Lattice::Var),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntSub { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(wrap(x.wrapping_sub(y), *size)),
                (None, Some(0)) => var_of(a, env).map_or(Lattice::Top, Lattice::Var),
                _ if same_reg(a, b) => Lattice::Const(0),
                _ => match (var_of(a, env), var_of(b, env)) {
                    (Some(x), Some(y)) if x == y => Lattice::Const(0),
                    _ => Lattice::Top,
                },
            };
            set_reg(env, dst, v);
        }
        POp::IntMul { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(wrap(x.wrapping_mul(y), *size)),
                (Some(0), _) | (_, Some(0)) => Lattice::Const(0),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntAnd { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(wrap(x & y, *size)),
                (Some(0), _) | (_, Some(0)) => Lattice::Const(0),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntOr { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(wrap(x | y, *size)),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntXor { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(wrap(x ^ y, *size)),
                _ if same_reg(a, b) => Lattice::Const(0),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntLeft { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => {
                    let bits = (*size * 8).max(1);
                    Lattice::Const(wrap(x.wrapping_shl((y as u32) & (bits - 1)), *size))
                }
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntShr { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => {
                    let bits = (*size * 8).max(1);
                    Lattice::Const(wrap(
                        ((x as u64).wrapping_shr((y as u32) & (bits - 1))) as i64,
                        *size,
                    ))
                }
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntSar { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => {
                    let bits = (*size * 8).max(1);
                    Lattice::Const(wrap(
                        sext(x, *size).wrapping_shr((y as u32) & (bits - 1)),
                        *size,
                    ))
                }
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntDiv { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) if y != 0 => {
                    let x = wrap(x, *size) as u64;
                    let y = wrap(y, *size) as u64;
                    Lattice::Const(wrap((x / y) as i64, *size))
                }
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntSDiv { dst, a, b, size } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) if y != 0 && !(x == i64::MIN && y == -1) => {
                    Lattice::Const(wrap(sext(x, *size).wrapping_div(sext(y, *size)), *size))
                }
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::Load { dst, addr, .. } => {
            let v = match addr {
                PVar::StackSlot { off, .. } => Lattice::Var(slot_var_name(*off)),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::Store { addr, .. } => {
            if let PVar::StackSlot { off, .. } = addr {
                let name = slot_var_name(*off);
                for v in env.values_mut() {
                    if matches!(*v, Lattice::Var(n) if n == name) {
                        *v = Lattice::Top;
                    }
                }
            }
        }
        POp::Zext { dst, .. }
        | POp::Sext { dst, .. }
        | POp::SetCC { dst, .. }
        | POp::Pop { dst, .. }
        | POp::FloatBinop { dst, .. }
        | POp::Cvt { dst, .. } => set_reg(env, dst, Lattice::Top),
        POp::Call { .. } | POp::CallInd { .. } => {
            for r in CALL_CLOBBERED {
                env.insert(r, Lattice::Top);
            }
        }
        _ => {
            if let Some(w) = written_reg(op) {
                env.insert(w, Lattice::Top);
            }
        }
    }
}

#[inline]
fn bit_set(bits: &mut [u64], i: usize) {
    bits[i / 64] |= 1u64 << (i % 64);
}

#[inline]
fn bit_clear(bits: &mut [u64], i: usize) {
    bits[i / 64] &= !(1u64 << (i % 64));
}

#[inline]
fn bit_test(bits: &[u64], i: usize) -> bool {
    bits[i / 64] & (1u64 << (i % 64)) != 0
}

fn reg_id(ids: &mut HashMap<&'static str, usize>, r: &'static str) -> usize {
    let next = ids.len();
    *ids.entry(r).or_insert(next)
}

fn solve_liveness(
    graph: &GraphView,
    uses: &[Vec<u64>],
    defs: &[Vec<u64>],
    words: usize,
    entry: usize,
    cancel: Option<&AtomicBool>,
) -> Option<Vec<Vec<u64>>> {
    let n = graph.len();
    let mut live_in = vec![vec![0u64; words]; n];
    let mut order = graph.dfs(entry).0;
    let mut seen = vec![false; n];
    for &b in &order {
        seen[b] = true;
    }
    order.extend((0..n).filter(|&b| !seen[b]));
    let mut queue: VecDeque<usize> = order.into();
    let mut queued = vec![true; n];
    let mut out = vec![0u64; words];
    let mut steps = 0usize;
    while let Some(b) = queue.pop_front() {
        queued[b] = false;
        steps += 1;
        if steps & 0xFF == 0 && is_cancelled(cancel) {
            return None;
        }
        out.fill(0);
        for &s in &graph.succs[b] {
            for (o, l) in out.iter_mut().zip(&live_in[s]) {
                *o |= *l;
            }
        }
        let mut changed = false;
        for w in 0..words {
            let new = uses[b][w] | (out[w] & !defs[b][w]);
            if new != live_in[b][w] {
                live_in[b][w] = new;
                changed = true;
            }
        }
        if changed {
            for &p in &graph.preds[b] {
                if !queued[p] {
                    queued[p] = true;
                    queue.push_back(p);
                }
            }
        }
    }
    Some(live_in)
}
pub(crate) fn compute_dead_ops_g(
    graph: &GraphView,
    entry: usize,
    bops: &[Vec<(u64, &POp)>],
    cancel: Option<&AtomicBool>,
) -> HashSet<(usize, usize)> {
    let n = graph.len();
    let mut dead = HashSet::default();
    if n == 0 {
        return dead;
    }
    struct OpRw {
        r0: u32,
        r1: u32,
        w: u32,
        pure: bool,
    }
    const NO_W: u32 = u32::MAX;

    let mut ids: HashMap<&'static str, usize> = HashMap::default();
    let mut arena: Vec<usize> = Vec::new();
    let mut guarded = vec![false; n];
    let rw: Vec<Vec<OpRw>> = bops
        .iter()
        .take(n)
        .enumerate()
        .map(|(b, ops)| {
            ops.iter()
                .map(|(_, op)| {
                    if matches!(op, POp::CBranch { .. }) {
                        guarded[b] = true;
                    }
                    let r0 = arena.len() as u32;
                    for r in reads_regs(op) {
                        arena.push(reg_id(&mut ids, r));
                    }
                    let r1 = arena.len() as u32;
                    let w = written_reg(op).map_or(NO_W, |w| reg_id(&mut ids, w) as u32);
                    OpRw {
                        r0,
                        r1,
                        w,
                        pure: is_pure(op),
                    }
                })
                .collect()
        })
        .collect();

    let words = ids.len().div_ceil(64).max(1);
    let mut uses = vec![vec![0u64; words]; n];
    let mut defs = vec![vec![0u64; words]; n];
    for (b, ops) in rw.iter().enumerate() {
        for o in ops {
            for &id in &arena[o.r0 as usize..o.r1 as usize] {
                if !bit_test(&defs[b], id) {
                    bit_set(&mut uses[b], id);
                }
            }
            if o.w != NO_W {
                bit_set(&mut defs[b], o.w as usize);
            }
        }
    }
    let Some(live_in) = solve_liveness(graph, &uses, &defs, words, entry, cancel) else {
        return HashSet::default();
    };
    let mut live = vec![0u64; words];
    for (b, ops) in rw.iter().enumerate() {
        if guarded[b] {
            continue;
        }
        live.fill(0);
        for &s in &graph.succs[b] {
            for (l, i) in live.iter_mut().zip(&live_in[s]) {
                *l |= *i;
            }
        }
        for (i, o) in ops.iter().enumerate().rev() {
            if o.w != NO_W {
                let w = o.w as usize;
                if o.pure && !bit_test(&live, w) {
                    dead.insert((b, i));
                    continue;
                }
                bit_clear(&mut live, w);
            }
            for &id in &arena[o.r0 as usize..o.r1 as usize] {
                bit_set(&mut live, id);
            }
        }
    }
    dead
}
#[cfg(test)]
mod graph_tests {
    use super::*;

    fn graph(n: usize, edges: &[(usize, usize)]) -> GraphView {
        let mut succs = vec![Vec::new(); n];
        for &(a, b) in edges {
            succs[a].push(b);
        }
        GraphView::from_succs(succs)
    }

    fn pl(text: &str, kind: LineKind) -> PseudoLine {
        PseudoLine {
            indent: 0,
            text: text.into(),
            kind,
            source_addr: None,
        }
    }

    #[test]
    fn switch_selection_uses_the_lower_goto_count() {
        let with_switch = Pseudocode {
            func_entry: 0,
            func_name: "f".into(),
            lines: vec![
                pl("switch (x) {", LineKind::Branch),
                pl("goto LAB_10;", LineKind::Branch),
                pl("}", LineKind::Branch),
            ],
        };
        let without_switch = Pseudocode {
            func_entry: 0,
            func_name: "f".into(),
            lines: vec![pl("if (x) { return; }", LineKind::Branch)],
        };
        assert!(renders_switch(&with_switch));
        assert!(!renders_switch(&without_switch));
        assert_eq!(goto_line_count(&with_switch), 1);
        assert_eq!(goto_line_count(&without_switch), 0);
    }

    #[test]
    fn finds_simple_back_edge() {
        let g = graph(4, &[(0, 1), (1, 2), (2, 1), (2, 3)]);
        assert_eq!(g.back_edges(0).get(&1), Some(&2));
        assert_eq!(g.back_edges(0).len(), 1);
    }

    #[test]
    fn self_loop_is_a_back_edge() {
        let g = graph(2, &[(0, 1), (1, 1)]);
        assert_eq!(g.back_edges(0).get(&1), Some(&1));
    }

    #[test]
    fn forward_and_cross_edges_are_not_back_edges() {
        let g = graph(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        assert!(g.back_edges(0).is_empty());
    }

    #[test]
    fn deep_chain_neither_overflows_the_stack_nor_loses_the_back_edge() {
        const N: usize = 200_000;
        let mut edges: Vec<(usize, usize)> = (0..N - 1).map(|i| (i, i + 1)).collect();
        edges.push((N - 1, 0));
        let g = graph(N, &edges);
        assert_eq!(g.back_edges(0).get(&0), Some(&(N - 1)));
    }

    #[test]
    fn all_latches_of_a_loop_are_reported() {
        let g = graph(4, &[(0, 1), (1, 2), (1, 3), (2, 1), (3, 1)]);
        let mut list = g.dfs(0).1;
        list.sort();
        assert_eq!(list, vec![(1, 2), (1, 3)]);
    }

    #[test]
    fn reverse_post_order_visits_predecessors_first() {
        let g = graph(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let rpo = g.reverse_post_order(0);
        let pos = |b: usize| rpo.iter().position(|&x| x == b).unwrap();
        assert_eq!(rpo.len(), 4);
        assert_eq!(pos(0), 0);
        assert!(pos(1) < pos(3) && pos(2) < pos(3));
    }

    #[test]
    fn duplicate_edges_do_not_duplicate_predecessors() {
        let g = graph(2, &[(0, 1), (0, 1)]);
        assert_eq!(g.preds[1], vec![0]);
    }

    #[test]
    fn liveness_converges_on_a_chain_that_runs_against_the_block_order() {
        const N: usize = 1000;
        let edges: Vec<(usize, usize)> = (1..N).map(|i| (i, i - 1)).collect();
        let g = graph(N, &edges);
        let mut uses = vec![vec![0u64; 1]; N];
        let defs = vec![vec![0u64; 1]; N];
        bit_set(&mut uses[0], 0);
        let live = solve_liveness(&g, &uses, &defs, 1, 0, None).unwrap();
        assert!(bit_test(&live[N - 1], 0));
    }

    #[test]
    fn a_definition_stops_liveness() {
        let g = graph(4, &[(3, 2), (2, 1), (1, 0)]);
        let mut uses = vec![vec![0u64; 1]; 4];
        let mut defs = vec![vec![0u64; 1]; 4];
        bit_set(&mut uses[0], 5);
        bit_set(&mut defs[1], 5);
        let live = solve_liveness(&g, &uses, &defs, 1, 0, None).unwrap();
        assert!(bit_test(&live[0], 5));
        assert!(!bit_test(&live[1], 5));
        assert!(!bit_test(&live[3], 5));
    }

    #[test]
    fn liveness_flows_around_a_loop() {
        let g = graph(3, &[(0, 1), (1, 2), (2, 1)]);
        let mut uses = vec![vec![0u64; 1]; 3];
        let mut defs = vec![vec![0u64; 1]; 3];
        bit_set(&mut uses[1], 2);
        bit_set(&mut defs[0], 2);
        let live = solve_liveness(&g, &uses, &defs, 1, 0, None).unwrap();
        assert!(bit_test(&live[1], 2));
        assert!(bit_test(&live[2], 2));
        assert!(!bit_test(&live[0], 2));
    }

    #[test]
    fn bit_helpers_work_across_word_boundaries() {
        let mut bits = vec![0u64; 3];
        for i in [0usize, 63, 64, 130] {
            bit_set(&mut bits, i);
            assert!(bit_test(&bits, i));
        }
        bit_clear(&mut bits, 64);
        assert!(!bit_test(&bits, 64) && bit_test(&bits, 63));
    }

    #[test]
    fn fp_register_detection() {
        assert!(is_fp_reg("xmm0") && is_fp_reg("XMM15") && is_fp_reg("st(1)") && is_fp_reg("st"));
        assert!(!is_fp_reg("stack_ptr") && !is_fp_reg("rax") && !is_fp_reg("dword ptr [rsp]"));
    }

    #[test]
    fn fp_reg_rejects_memory_operands() {
        assert!(!is_fp_reg("xmmword ptr [rsp+0x10]") && !is_fp_reg("ymmword ptr [rax]"));
        assert!(is_fp_reg("xmm15") && is_fp_reg("st(1)"));
    }

    #[test]
    fn sanitize_param_name_cases() {
        assert_eq!(sanitize_param_name("2d", "p"), "_2d");
        assert_eq!(sanitize_param_name("<lambda>", "p"), "lambda");
        assert_eq!(sanitize_param_name("register", "p"), "p_register");
        assert_eq!(sanitize_param_name("!!!", "p"), "p");
    }

    #[test]
    fn rename_identifiers_keeps_utf8_and_numbers() {
        let mut m: HashMap<String, String> = HashMap::default();
        m.insert("a".into(), "b".into());
        assert_eq!(
            rename_identifiers("a = \"za\u{17c}\u{f3}\u{142}\u{107}\" + 0xa;", &m),
            "b = \"za\u{17c}\u{f3}\u{142}\u{107}\" + 0xa;"
        );
    }

    #[test]
    fn enum_substitution_respects_token_boundaries() {
        let mut hints = TypeHints::default();
        hints.enum_fields.insert("mode".into(), "Mode".into());
        hints
            .enum_variants
            .insert("Mode".into(), vec![("MODE_A".into(), 1)]);
        let mut lines = vec![
            pl("x.mode = 10;", LineKind::Assignment),
            pl("x.mode = 1;", LineKind::Assignment),
        ];
        substitute_enum_values(&mut lines, &hints);
        assert_eq!(lines[0].text, "x.mode = 10;");
        assert_eq!(lines[1].text, "x.mode = MODE_A;");
    }

    #[test]
    fn rbp_as_gpr_is_not_bookkeeping() {
        assert!(!is_stack_bookkeeping("rbp = rbp + 1;", false));
        assert!(is_stack_bookkeeping("rsp = rsp - 0x28;", false));
        assert!(is_stack_bookkeeping("rsp = rsp + -0x40;", false));
        assert!(is_stack_bookkeeping("rbp = rsp;", true));
        assert!(is_stack_bookkeeping("rbp = rsp - 0x20;", true));
    }

    #[test]
    fn win64_keeps_rsi_before_call() {
        let mut lines = vec![
            pl("rsi = rax;", LineKind::Assignment),
            pl("rcx = rbx;", LineKind::Assignment),
            pl("foo();", LineKind::Call),
        ];
        drop_call_arg_setups(&mut lines, true, true);
        let out: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(out, ["rsi = rax;", "foo();"]);
    }

    #[test]
    fn multi_latch_loop_reports_both_edges() {
        let g = graph(4, &[(0, 1), (1, 2), (1, 3), (2, 1), (3, 1)]);
        assert_eq!(g.back_edge_list(0).len(), 2);
    }

    #[test]
    fn transfer_wraps_32bit_constants() {
        let mut env: Env = HashMap::default();
        transfer(
            &POp::IntAdd {
                dst: PVar::Reg("eax"),
                a: PVar::Const(0xFFFF_FFFF),
                b: PVar::Const(1),
                size: 4,
            },
            &mut env,
        );
        assert_eq!(env.get("eax"), Some(&Lattice::Const(0)));
    }

    #[test]
    fn transfer_uses_the_operation_width_for_shifts() {
        let mut env: Env = HashMap::default();
        transfer(
            &POp::IntShr {
                dst: PVar::Reg("eax"),
                a: PVar::Const(0x8000_0000),
                b: PVar::Const(31),
                size: 4,
            },
            &mut env,
        );
        assert_eq!(env.get("eax"), Some(&Lattice::Const(1)));
    }

    #[test]
    fn float_mnemonics_include_vex_and_x87() {
        for m in [
            "addss",
            "vaddsd",
            "vmovss",
            "cvttsd2si",
            "vfmadd231ss",
            "fadd",
            "fucomip",
        ] {
            assert!(is_float_mnemonic(m), "{m}");
        }
        for m in ["mov", "add", "verw", "lea", "pxor"] {
            assert!(!is_float_mnemonic(m), "{m}");
        }
    }

    #[test]
    fn exact_width_types_use_ghidra_spellings() {
        let mut lines = vec![
            pl("int64_t local_10;", LineKind::Declaration),
            pl("*(uint32_t *)(param_1 + 4) = 1;", LineKind::Assignment),
            pl("uint8_t buf[16];", LineKind::Declaration),
            pl("return (int16_t)param_2;", LineKind::Return),
        ];
        ghidra_type_names(&mut lines);
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            text,
            vec![
                "longlong local_10;",
                "*(uint *)(param_1 + 4) = 1;",
                "byte buf[16];",
                "return (short)param_2;"
            ]
        );
    }

    #[test]
    fn unnamed_functions_use_ghidra_prefix() {
        let mut lines = vec![
            pl("return sub_180001000(param_1);", LineKind::Return),
            pl("thunk_sub_180002000();", LineKind::Call),
            pl("// sub_180003000 stays in comments", LineKind::Comment),
        ];
        ghidra_function_names(&mut lines);
        assert_eq!(lines[0].text, "return FUN_180001000(param_1);");
        assert_eq!(lines[1].text, "thunk_FUN_180002000();");
        assert!(lines[2].text.contains("sub_180003000"));
    }

    #[test]
    fn msvc_cookie_bookkeeping_is_removed() {
        fn pl(text: &str, kind: LineKind) -> PseudoLine {
            PseudoLine {
                indent: 0,
                text: text.into(),
                kind,
                source_addr: None,
            }
        }
        let mut lines = vec![
            pl(
                "uVar1 = *(longlong *)&DAT_1800c1230 ^ rsp + -0x110;",
                LineKind::Assignment,
            ),
            pl("local_48 = uVar1;", LineKind::Assignment),
            pl("FUN_180084C50(local_48 ^ rsp);", LineKind::Call),
            pl("uVar1 = 3;", LineKind::Assignment),
            pl("return;", LineKind::Return),
        ];
        drop_stack_canary(&mut lines);
        let out = lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!out.contains("DAT_1800c1230"), "{out}");
        assert!(!out.contains("local_48"), "{out}");
        assert!(!out.contains("FUN_180084C50"), "{out}");
        assert!(out.contains("uVar1 = 3;"), "{out}");
    }

    #[test]
    fn stack_canary_bookkeeping_is_removed() {
        fn pl(text: &str, kind: LineKind) -> PseudoLine {
            PseudoLine {
                indent: 0,
                text: text.into(),
                kind,
                source_addr: None,
            }
        }
        let mut lines = vec![
            pl(
                "rax = *(fs:64 + 0x28);  // TLS/PEB via fs",
                LineKind::Assignment,
            ),
            pl("local_10 = *(fs:64 + 0x28);", LineKind::Assignment),
            pl("int64_t local_10;  // [rbp-0x8]", LineKind::Declaration),
            pl("rdx = local_10;", LineKind::Assignment),
            pl("if (c != 0xff) {", LineKind::Branch),
            pl("__stack_chk_fail();", LineKind::Call),
            pl("}", LineKind::Branch),
            pl("return rax;", LineKind::Return),
        ];
        drop_stack_canary(&mut lines);
        let out = lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!out.contains("fs:"), "{out}");
        assert!(!out.contains("local_10"), "{out}");
        assert!(!out.contains("__stack_chk_fail"), "{out}");
        assert!(out.contains("return rax;"), "{out}");
    }

    #[test]
    fn save_restore_comments_are_dropped() {
        fn pl(text: &str, kind: LineKind) -> PseudoLine {
            PseudoLine {
                indent: 0,
                text: text.into(),
                kind,
                source_addr: None,
            }
        }
        let mut lines = vec![
            pl("// push rbx", LineKind::Comment),
            pl("rax = 1;", LineKind::Assignment),
            pl("// pop rbx", LineKind::Comment),
            pl("// WARNING: something", LineKind::Comment),
            pl("// push rbx rcx", LineKind::Comment),
        ];
        drop_save_restore_comments(&mut lines);
        let out: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            out,
            ["rax = 1;", "// WARNING: something", "// push rbx rcx"]
        );
    }
    fn dbg_struct(name: &str, size: usize, fields: Vec<(&str, usize, &str, usize)>) -> DebugStruct {
        DebugStruct {
            name: name.to_string(),
            size,
            fields: fields
                .into_iter()
                .map(|(n, off, ty, sz)| DebugField {
                    name: n.to_string(),
                    offset: off,
                    type_name: ty.to_string(),
                    size: sz,
                    bitfield: None,
                })
                .collect(),
        }
    }

    fn dbg_types(structs: Vec<DebugStruct>) -> DebugTypes {
        DebugTypes {
            structs,
            enums: Vec::new(),
            functions: Default::default(),
        }
    }

    #[test]
    fn flattened_fields_expand_primitive_arrays() {
        let dt = dbg_types(vec![dbg_struct(
            "Buf",
            12,
            vec![("data", 0, "int32_t[3]", 12)],
        )]);
        let buf = dt.struct_named("Buf").unwrap();
        let flat = flattened_struct_fields(&dt, buf);
        assert_eq!(
            flat,
            vec![
                (0, 4, "data[0]".to_string()),
                (4, 4, "data[1]".to_string()),
                (8, 4, "data[2]".to_string()),
            ]
        );
    }

    #[test]
    fn flattened_fields_expand_struct_arrays_with_nested_names() {
        let dt = dbg_types(vec![
            dbg_struct("Arr", 16, vec![("pts", 0, "Point[2]", 16)]),
            dbg_struct(
                "Point",
                8,
                vec![("x", 0, "int32_t", 4), ("y", 4, "int32_t", 4)],
            ),
        ]);
        let arr = dt.struct_named("Arr").unwrap();
        let flat = flattened_struct_fields(&dt, arr);
        assert_eq!(
            flat,
            vec![
                (0, 4, "pts[0].x".to_string()),
                (4, 4, "pts[0].y".to_string()),
                (8, 4, "pts[1].x".to_string()),
                (12, 4, "pts[1].y".to_string()),
            ]
        );
    }

    #[test]
    fn flattened_fields_keep_pointer_and_unknown_array_fields() {
        let dt = dbg_types(vec![dbg_struct(
            "Mixed",
            24,
            vec![("next", 0, "Node *", 8), ("blob", 8, "SomeUnknown[2]", 16)],
        )]);
        let mixed = dt.struct_named("Mixed").unwrap();
        let flat = flattened_struct_fields(&dt, mixed);
        assert_eq!(
            flat,
            vec![(0, 8, "next".to_string()), (8, 16, "blob".to_string()),]
        );
    }
}
