use super::printing::*;
use super::structure::{
    Loops, Postdom, WalkCtx, cleanup_labels, compute_dowhile, squash_empty_branches,
    walk_block,
};
use super::*;
use super::alias;
use crate::analysis::flow::cfg::CFG;
use crate::analysis::flow::stack::StackFrame;
use crate::analysis::flow::variables;
use crate::disasm::DisasmInstruction;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

type Env = HashMap<&'static str, Lattice>;

const MAX_HINT_PASSES: usize = 8;

pub struct LiftInput<'a> {
    pub cfg: &'a CFG,
    pub pinstrs_in_func: &'a [PInstr],
    pub imap: &'a [DisasmInstruction],
    pub stack: &'a StackFrame,
    pub func_name: &'a str,
    pub func_lookup: &'a HashMap<u64, String>,
    pub is64: bool,
    pub imports: &'a HashMap<u64, String>,
    pub cancel: Option<&'a AtomicBool>,
}

#[derive(Debug, Clone, Default)]
pub struct DecompStats {
    pub blocks: usize,
    pub back_edges: usize,
    pub dead_ops: usize,
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
            "blocks={} back_edges={} dead_ops={} unmodeled={} lines={} bytes={} \
             hints={:.1?} dataflow={:.1?} structure={:.1?} total={:.1?}",
            self.blocks,
            self.back_edges,
            self.dead_ops,
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
    let end = cfg.blocks.last().map(|b| b.end).unwrap_or(entry);
    if end <= entry {
        return HashMap::default();
    }
    let mut tr = TypeReconstructor::new();
    tr.analyze_function(pinstrs, entry, end);
    tr.function_fields(entry)
        .into_iter()
        .map(|(reg, fields)| (reg, StructHint { fields }))
        .collect()
}

fn fmt_frame_slot(base_reg: &str, off: i64) -> String {
    if off < 0 {
        format!("[{}-{:#x}]", base_reg, off.unsigned_abs())
    } else {
        format!("[{}+{:#x}]", base_reg, off)
    }
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
        "movss" | "movsd" | "movaps" | "movapd" | "movups" | "movupd"
            | "addss" | "addsd" | "addps" | "addpd"
            | "subss" | "subsd" | "subps" | "subpd"
            | "mulss" | "mulsd" | "mulps" | "mulpd"
            | "divss" | "divsd" | "divps" | "divpd"
            | "sqrtss" | "sqrtsd" | "sqrtps" | "sqrtpd"
            | "minss" | "minsd" | "maxss" | "maxsd"
            | "comiss" | "comisd" | "ucomiss" | "ucomisd"
            | "cvtss2sd" | "cvtsd2ss" | "cvtsi2ss" | "cvtsi2sd"
            | "cvtss2si" | "cvtsd2si" | "cvttss2si" | "cvttsd2si"
            | "roundss" | "roundsd"
            | "andps" | "andpd" | "andnps" | "andnpd" | "orps" | "orpd"
            | "fld" | "fst" | "fstp" | "fadd" | "faddp" | "fsub" | "fsubp" | "fsubr"
            | "fsubrp" | "fmul" | "fmulp" | "fdiv" | "fdivp" | "fdivr" | "fdivrp"
            | "fcom" | "fcomp" | "fcompp" | "fucom" | "fucomp" | "fucompp" | "fcomi"
            | "fcomip" | "fucomi" | "fucomip" | "fchs" | "fabs" | "fsqrt" | "fxch"
    )
}

fn is_fp_reg(tok: &str) -> bool {
    let b = tok.as_bytes();
    let has_prefix = |p: &str| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p.as_bytes());
    if has_prefix("xmm") || has_prefix("ymm") || has_prefix("zmm") {
        return true;
    }
    has_prefix("st") && (b.len() == 2 || b[2] == b'(' || b[2].is_ascii_digit())
}

struct TypeScan {
    floats: HashSet<String>,
    float_slots: HashSet<i64>,
    read_pos_slots: HashSet<i64>,
    written_pos_slots: HashSet<i64>,
}

fn scan_types(imap: &[DisasmInstruction], pinstrs_in_func: &[PInstr]) -> TypeScan {
    let mut floats: HashSet<String> = HashSet::default();
    let mut float_slots: HashSet<i64> = HashSet::default();
    for di in imap {
        if !is_float_mnemonic(di.mnemonic) {
            continue;
        }
        for tok in di.ops().split(',') {
            let t = tok.trim();
            if is_fp_reg(t) {
                floats.insert(t.to_ascii_lowercase());
            }
        }
    }

    let mut read_pos_slots: HashSet<i64> = HashSet::default();
    let mut written_pos_slots: HashSet<i64> = HashSet::default();
    for _ in 0..MAX_HINT_PASSES {
        let before = (floats.len(), float_slots.len());
        for pi in pinstrs_in_func {
            for op in &pi.ops {
                match op {
                    POp::Copy { dst, src, .. } => {
                        if floats.contains(&fmt_var(src)) {
                            floats.insert(fmt_var(dst));
                        }
                        if let PVar::StackSlot { off: o, .. } = src {
                            read_pos_slots.insert(*o);
                        }
                    }
                    POp::Cvt { kind, dst, .. } => {
                        if kind == "i2f" || kind == "f2f" {
                            floats.insert(fmt_var(dst));
                        }
                    }
                    POp::Load { dst, addr, .. } => {
                        if let PVar::StackSlot { off: o, .. } = addr {
                            read_pos_slots.insert(*o);
                        }
                        if matches!(addr, PVar::StackSlot { off: o, .. } if float_slots.contains(o))
                        {
                            floats.insert(fmt_var(dst));
                        }
                    }
                    POp::Store { addr, src, .. } => {
                        if floats.contains(&fmt_var(src))
                            && let PVar::StackSlot { off: o, .. } = addr {
                                float_slots.insert(*o);
                            }
                        if let PVar::StackSlot { off: o, .. } = addr
                            && *o >= 0 {
                                written_pos_slots.insert(*o);
                            }
                    }
                    POp::FloatBinop { a, b, .. }
                    | POp::Cmp { a, b, .. }
                    | POp::Test { a, b, .. }
                    | POp::FloatCmp { a, b, .. } => {
                        for v in [a, b] {
                            if let PVar::StackSlot { off: o, .. } = v {
                                read_pos_slots.insert(*o);
                            }
                        }
                    }
                    POp::IntAdd { a, b, .. }
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
                        for v in [a, b] {
                            if let PVar::StackSlot { off: o, .. } = v {
                                read_pos_slots.insert(*o);
                            }
                        }
                    }
                    POp::Push {
                        src: PVar::StackSlot { off: o, .. },
                        ..
                    } => {
                        read_pos_slots.insert(*o);
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


pub fn decompile(input: LiftInput<'_>) -> Pseudocode {
    decompile_with_stats(input).0
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
        imports,
        cancel,
    } = input;
    let mut stats = DecompStats {
        blocks: cfg.blocks.len(),
        ..Default::default()
    };

    if cfg.blocks.len() > MAX_DECOMP_BLOCKS {
        stats.skipped_too_large = true;
        let lines = vec![PseudoLine {
            indent: 0,
            text: format!("// WARNING: function '{}' has {} CFG blocks (> {}), structured decompilation skipped to avoid OOM; use disassemble_function / analyze_control_flow instead", func_name, cfg.blocks.len(), MAX_DECOMP_BLOCKS),
            kind: LineKind::Comment,
            source_addr: None,
        }];
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
    let recovery = if imap.is_empty() {
        None
    } else {
        Some(variables::recover(cfg, pinstrs_in_func, imap, is64))
    };
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
        structs: function_struct_hints(cfg, pinstrs_in_func),
        var_names: recovery.as_ref().map(|r| std::sync::Arc::new(r.names.clone())),
        ..Default::default()
    };
    stats.t_hints = t_phase.elapsed();

    let ptr_ty = if is64 { "int64_t" } else { "int32_t" };
    let ret_ty_str = recovery
        .as_ref()
        .map(|r| r.ret_type.c_str())
        .unwrap_or(ptr_ty);
    let params: Vec<String> = if let Some(rv) = &recovery {
        rv.params
            .iter()
            .map(|&id| {
                let v = &rv.vars[id as usize];
                format!("{} {}", v.ty.c_str(), v.name)
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
            let off = match v.storage {
                variables::Loc::Stack { base, off } => {
                    let reg = if base == 0 { bp } else { sp };
                    fmt_frame_slot(reg, off)
                }
                _ => String::new(),
            };
            lines.push(PseudoLine {
                indent: 1,
                text: format!("{} {};  // {}", v.ty.c_str(), v.name, off),
                kind: LineKind::Declaration,
                source_addr: None,
            });
        }
        for v in &rv.vars {
            if matches!(v.storage, variables::Loc::Reg(_))
                && v.kind == variables::VarKind::Register
                && v.keep
                && v.use_count > 1
            {
                lines.push(PseudoLine {
                    indent: 1,
                    text: format!("{} {};", v.ty.c_str(), v.name),
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
            let ty = if hints.float_slots.contains(&v.offset) {
                if v.size == 8 {
                    "double"
                } else {
                    "float"
                }
            } else {
                c_type_for_size(v.size)
            };
            let base = if stack.frame_size > 0 && v.offset >= 0 {
                sp
            } else {
                bp
            };
            lines.push(PseudoLine {
                indent: 1,
                text: format!("{} {};  // {}", ty, v.name, fmt_frame_slot(base, v.offset)),
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
    let graph = GraphView::from_cfg(cfg);
    let bops = build_block_ops_from_slice(cfg, pinstrs_in_func);

    let entry_id = entry_block(cfg);
    let back_edge_list = graph.back_edge_list(entry_id);
    let back_edges: HashMap<usize, usize> = back_edge_list.iter().copied().collect();
    stats.back_edges = back_edges.len();

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
    let dead = compute_dead_ops_g(&graph, &bops, cancel);
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
    };
    walk_block(&ctx, entry_id, &mut visited, &mut lines, 1, 0);
    cleanup_labels(&mut lines);
    stats.t_structure = t_phase.elapsed();

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
            indent: 0,
            text: format!(
                "// [{} instruction(s) not modeled by the lifter were omitted; first: {}]",
                unmodeled,
                first_unmodeled.unwrap_or_default()
            ),
            kind: LineKind::Comment,
            source_addr: None,
        });
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

    if let Some(rv) = &recovery {
        variables::apply_names(&mut lines, rv);
    }

    
    
    
    fn is_stack_bookkeeping(text: &str) -> bool {
        let t = text.trim().strip_suffix(';').unwrap_or(text.trim());
        let Some((lhs, rhs)) = t.split_once('=') else {
            return false;
        };
        let lhs = lhs.trim();
        let rhs = rhs.trim();
        let is_sp = |s: &str| matches!(s, "rsp" | "esp" | "rbp" | "ebp");
        if !is_sp(lhs) {
            return false;
        }
        if rhs == lhs || is_sp(rhs) {
            return true;
        }
        if let Some(rest) = rhs.strip_prefix(lhs) {
            let rest = rest.trim_start();
            if rest.starts_with('+') || rest.starts_with('-') {
                return true;
            }
        }
        false
    }
    lines.retain(|l| !is_stack_bookkeeping(&l.text));
    alias::propagate_aliases(&mut lines);
    alias::cse_repeated_expressions(&mut lines);
    alias::propagate_aliases(&mut lines);
    alias::drop_dead_register_assignments(&mut lines);
    alias::inline_single_use_temps(&mut lines);
    alias::propagate_aliases(&mut lines);
    squash_empty_branches(&mut lines);

    if hints.out_truncated.get() {
        stats.truncated = true;
        lines.push(PseudoLine {
            indent: 0,
            text: format!(
                "// ... truncated: output budget reached, {} of {} blocks not emitted; use disassemble_function for the rest",
                cfg.blocks.len().saturating_sub(visited.len()),
                cfg.blocks.len()
            ),
            kind: LineKind::Comment,
            source_addr: None,
        });
    }
    let total_bytes: usize = lines.iter().map(|l| l.text.len()).sum();
    if total_bytes > (1 << 20) {
        eprintln!(
            "[decompiler] {}: {} lines, {} bytes",
            func_name,
            lines.len(),
            total_bytes
        );
    }
    lines.push(PseudoLine {
        indent: 0,
        text: "}".into(),
        kind: LineKind::CloseBrace,
        source_addr: None,
    });

    stats.emitted_lines = lines.len();
    stats.output_bytes = total_bytes;
    stats.t_total = t_total.elapsed();
    (make_pseudocode(cfg, func_name, lines), stats)
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

    fn from_succs(succs: Vec<Vec<usize>>) -> Self {
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); succs.len()];
        for (b, ss) in succs.iter().enumerate() {
            for &s in ss {
                preds[s].push(b);
            }
        }
        for p in preds.iter_mut() {
            p.dedup();
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

#[allow(dead_code)]
pub(crate) fn compute_back_edges(cfg: &CFG, entry: usize) -> HashMap<usize, usize> {
    GraphView::from_cfg(cfg).back_edges(entry)
}

#[allow(dead_code)]
pub(crate) fn compute_back_edge_list(cfg: &CFG, entry: usize) -> Vec<(usize, usize)> {
    GraphView::from_cfg(cfg).dfs(entry).1
}

pub(crate) fn build_block_ops_from_slice<'a>(
    cfg: &CFG,
    pinstrs: &'a [PInstr],
) -> Vec<Vec<(u64, &'a POp)>> {
    let mut order: Vec<&'a PInstr> = pinstrs.iter().collect();
    order.sort_by_key(|p| p.address);
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

#[allow(dead_code)]
pub(crate) fn build_block_ops_table<'a>(
    cfg: &CFG,
    pmap: &'a HashMap<u64, &PInstr>,
) -> Vec<Vec<(u64, &'a POp)>> {
    let mut sorted: Vec<(u64, &'a PInstr)> = pmap.iter().map(|(&a, &p)| (a, p)).collect();
    sorted.sort_unstable_by_key(|x| x.0);
    let mut table: Vec<Vec<(u64, &'a POp)>> = Vec::with_capacity(cfg.blocks.len());
    for block in &cfg.blocks {
        let lo = sorted.partition_point(|x| x.0 < block.start);
        let hi = sorted.partition_point(|x| x.0 < block.end).max(lo);
        let mut ops = Vec::new();
        for &(addr, pi) in &sorted[lo..hi] {
            for op in &pi.ops {
                ops.push((addr, op));
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

#[allow(dead_code)]
pub(crate) fn compute_block_consts(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    is64: bool,
    param_seed: &HashMap<&'static str, String>,
) -> Vec<HashMap<&'static str, Lattice>> {
    compute_block_consts_cancellable(
        &GraphView::from_cfg(cfg),
        entry_block(cfg),
        bops,
        is64,
        param_seed,
        None,
    )
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
        POp::IntAdd { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x.wrapping_add(y)),
                (None, Some(0)) => var_of(a, env).map_or(Lattice::Top, Lattice::Var),
                (Some(0), None) => var_of(b, env).map_or(Lattice::Top, Lattice::Var),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntSub { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x.wrapping_sub(y)),
                (None, Some(0)) => var_of(a, env).map_or(Lattice::Top, Lattice::Var),
                _ if same_reg(a, b) => Lattice::Const(0),
                _ => match (var_of(a, env), var_of(b, env)) {
                    (Some(x), Some(y)) if x == y => Lattice::Const(0),
                    _ => Lattice::Top,
                },
            };
            set_reg(env, dst, v);
        }
        POp::IntMul { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x.wrapping_mul(y)),
                (Some(0), _) | (_, Some(0)) => Lattice::Const(0),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntAnd { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x & y),
                (Some(0), _) | (_, Some(0)) => Lattice::Const(0),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntOr { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x | y),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntXor { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x ^ y),
                _ if same_reg(a, b) => Lattice::Const(0),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntLeft { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x.wrapping_shl((y as u32) & 63)),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntShr { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => {
                    Lattice::Const(((x as u64).wrapping_shr((y as u32) & 63)) as i64)
                }
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntSar { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) => Lattice::Const(x.wrapping_shr((y as u32) & 63)),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntDiv { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) if y != 0 => Lattice::Const(((x as u64) / (y as u64)) as i64),
                _ => Lattice::Top,
            };
            set_reg(env, dst, v);
        }
        POp::IntSDiv { dst, a, b, .. } => {
            let v = match (const_of(a, env), const_of(b, env)) {
                (Some(x), Some(y)) if y != 0 && !(x == i64::MIN && y == -1) => {
                    Lattice::Const(x.wrapping_div(y))
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
    cancel: Option<&AtomicBool>,
) -> Option<Vec<Vec<u64>>> {
    let n = graph.len();
    let mut live_in = vec![vec![0u64; words]; n];
    let mut queue: VecDeque<usize> = (0..n).rev().collect();
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

#[allow(dead_code)]
pub(crate) fn compute_dead_ops(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    cancel: Option<&AtomicBool>,
) -> HashSet<(usize, usize)> {
    compute_dead_ops_g(&GraphView::from_cfg(cfg), bops, cancel)
}

pub(crate) fn compute_dead_ops_g(
    graph: &GraphView,
    bops: &[Vec<(u64, &POp)>],
    cancel: Option<&AtomicBool>,
) -> HashSet<(usize, usize)> {
    let n = graph.len();
    let mut dead = HashSet::default();
    if n == 0 {
        return dead;
    }

    let mut ids: HashMap<&'static str, usize> = HashMap::default();
    for ops in bops.iter().take(n) {
        for (_, op) in ops {
            for r in reads_regs(op) {
                reg_id(&mut ids, r);
            }
            if let Some(w) = written_reg(op) {
                reg_id(&mut ids, w);
            }
        }
    }
    let words = ids.len().div_ceil(64).max(1);

    let mut uses = vec![vec![0u64; words]; n];
    let mut defs = vec![vec![0u64; words]; n];
    let mut guarded = vec![false; n];
    for (b, ops) in bops.iter().enumerate().take(n) {
        for (_, op) in ops {
            if matches!(op, POp::CBranch { .. }) {
                guarded[b] = true;
            }
            for r in reads_regs(op) {
                let id = reg_id(&mut ids, r);
                if !bit_test(&defs[b], id) {
                    bit_set(&mut uses[b], id);
                }
            }
            if let Some(w) = written_reg(op) {
                let id = reg_id(&mut ids, w);
                bit_set(&mut defs[b], id);
            }
        }
    }

    let live_in = match solve_liveness(graph, &uses, &defs, words, cancel) {
        Some(l) => l,
        None => return HashSet::default(),
    };

    let mut live = vec![0u64; words];
    for (b, ops) in bops.iter().enumerate().take(n) {
        if guarded[b] {
            continue;
        }
        live.fill(0);
        for &s in &graph.succs[b] {
            for (l, i) in live.iter_mut().zip(&live_in[s]) {
                *l |= *i;
            }
        }
        for (i, (_, op)) in ops.iter().enumerate().rev() {
            if let Some(w) = written_reg(op) {
                let wid = reg_id(&mut ids, w);
                if is_pure(op) && !bit_test(&live, wid) {
                    dead.insert((b, i));
                    continue;
                }
                bit_clear(&mut live, wid);
            }
            for r in reads_regs(op) {
                let id = reg_id(&mut ids, r);
                bit_set(&mut live, id);
            }
        }
    }
    dead
}

#[allow(dead_code)]
pub(crate) fn live_in_successors(
    cfg: &CFG,
    live_in: &[HashSet<&'static str>],
    bi: usize,
    out: &mut HashSet<&'static str>,
) {
    out.clear();
    for e in &cfg.blocks[bi].successors {
        if e.target < live_in.len() {
            out.extend(live_in[e.target].iter().cloned());
        }
    }
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
        let live = solve_liveness(&g, &uses, &defs, 1, None).unwrap();
        assert!(bit_test(&live[N - 1], 0));
    }

    #[test]
    fn a_definition_stops_liveness() {
        let g = graph(4, &[(3, 2), (2, 1), (1, 0)]);
        let mut uses = vec![vec![0u64; 1]; 4];
        let mut defs = vec![vec![0u64; 1]; 4];
        bit_set(&mut uses[0], 5);
        bit_set(&mut defs[1], 5);
        let live = solve_liveness(&g, &uses, &defs, 1, None).unwrap();
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
        let live = solve_liveness(&g, &uses, &defs, 1, None).unwrap();
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
    fn float_mnemonics_include_vex_and_x87() {
        for m in ["addss", "vaddsd", "vmovss", "cvttsd2si", "vfmadd231ss", "fadd", "fucomip"] {
            assert!(is_float_mnemonic(m), "{m}");
        }
        for m in ["mov", "add", "verw", "lea", "pxor"] {
            assert!(!is_float_mnemonic(m), "{m}");
        }
    }
}