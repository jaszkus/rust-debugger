use super::printing::*;
use super::*;
use crate::analysis::flow::cfg::{CFG, EdgeKind, parse_addr};
use crate::analysis::operands::canonical_reg;
use crate::disasm::DisasmInstruction;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

pub(crate) fn compute_dowhile(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    imap: &[DisasmInstruction],
    back_edges: &HashMap<usize, usize>,
    block_consts: &[HashMap<&'static str, Lattice>],
    hints: &TypeHints,
) -> HashSet<usize> {
    let mut out = HashSet::default();
    for (header, latch) in back_edges {
        let hconsts = block_consts.get(*header).cloned().unwrap_or_default();
        if recover_condition(cfg, bops, imap, *header, &hconsts, Some(hints)) != "cond" {
            continue;
        }
        let lconsts = block_consts.get(*latch).cloned().unwrap_or_default();
        if recover_condition(cfg, bops, imap, *latch, &lconsts, Some(hints)) != "cond" {
            out.insert(*header);
        }
    }
    out
}







pub(crate) struct Postdom {
    ipdom: Vec<usize>,
    exit: usize,
}

impl Postdom {
    pub(crate) fn compute(cfg: &CFG) -> Self {
        let n = cfg.blocks.len();
        let exit = n;
        let mut rev: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
        for (b, blk) in cfg.blocks.iter().enumerate() {
            for e in &blk.successors {
                if e.target < n {
                    rev[e.target].push(b);
                }
            }
            if blk.successors.is_empty() {
                rev[exit].push(b);
            }
        }
        let idom = compute_idoms(&rev, exit);
        Self {
            ipdom: idom.into_iter().take(n).collect(),
            exit,
        }
    }

    
    
    pub(crate) fn join_of(&self, block: usize) -> Option<usize> {
        let j = *self.ipdom.get(block)?;
        (j < self.exit).then_some(j)
    }
}


fn compute_idoms(succs: &[Vec<usize>], entry: usize) -> Vec<usize> {
    let n = succs.len();
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (b, ss) in succs.iter().enumerate() {
        for &s in ss {
            if s < n {
                preds[s].push(b);
            }
        }
    }

    
    let mut state = vec![0u8; n];
    let mut post = Vec::with_capacity(n);
    if entry < n {
        state[entry] = 1;
        let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
        while let Some(top) = stack.last_mut() {
            let (b, i) = *top;
            match succs[b].get(i) {
                Some(&t) if t < n => {
                    top.1 += 1;
                    if state[t] == 0 {
                        state[t] = 1;
                        stack.push((t, 0));
                    }
                }
                Some(_) => top.1 += 1,
                None => {
                    state[b] = 2;
                    post.push(b);
                    stack.pop();
                }
            }
        }
    }
    let rpo: Vec<usize> = post.into_iter().rev().collect();
    let mut rpo_index = vec![usize::MAX; n];
    for (i, &b) in rpo.iter().enumerate() {
        rpo_index[b] = i;
    }

    let mut idom = vec![usize::MAX; n];
    if entry < n {
        idom[entry] = entry;
    }
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == entry {
                continue;
            }
            let mut new_idom = usize::MAX;
            for &p in &preds[b] {
                if idom[p] == usize::MAX {
                    continue;
                }
                new_idom = if new_idom == usize::MAX {
                    p
                } else {
                    intersect(p, new_idom, &idom, &rpo_index)
                };
            }
            if new_idom != usize::MAX && idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom
}

fn intersect(mut a: usize, mut b: usize, idom: &[usize], rpo_index: &[usize]) -> usize {
    while a != b {
        while rpo_index[a] > rpo_index[b] {
            a = idom[a];
        }
        while rpo_index[b] > rpo_index[a] {
            b = idom[b];
        }
    }
    a
}

pub(crate) struct LoopInfo {
    pub(crate) header: usize,
    pub(crate) body: HashSet<usize>,
    pub(crate) exits: HashSet<usize>,
}



pub(crate) struct Loops {
    infos: HashMap<usize, LoopInfo>,
}

impl Loops {
    pub(crate) fn compute(cfg: &CFG, entry: usize, back: &[(usize, usize)]) -> Self {
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
        let idom = compute_idoms(&succs, entry);
        let mut infos: HashMap<usize, LoopInfo> = HashMap::default();

        for &(header, latch) in back {
            if header >= n || latch >= n || !dominates(&idom, header, latch) {
                continue;
            }
            let mut body: HashSet<usize> = HashSet::default();
            body.insert(header);
            let mut stack = vec![latch];
            while let Some(b) = stack.pop() {
                if b >= n || !body.insert(b) {
                    continue;
                }
                for &p in &cfg.blocks[b].predecessors {
                    stack.push(p);
                }
            }
            let info = infos.entry(header).or_insert_with(|| LoopInfo {
                header,
                body: HashSet::default(),
                exits: HashSet::default(),
            });
            info.body.extend(body);
        }

        for info in infos.values_mut() {
            let mut exits: HashSet<usize> = HashSet::default();
            for &b in &info.body {
                for e in &cfg.blocks[b].successors {
                    if e.target < n && !info.body.contains(&e.target) {
                        exits.insert(e.target);
                    }
                }
            }
            info.exits = exits;
        }

        Self { infos }
    }

    pub(crate) fn get(&self, header: usize) -> Option<&LoopInfo> {
        self.infos.get(&header)
    }

    
    pub(crate) fn enclosing(&self, block: usize) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .infos
            .values()
            .filter(|info| info.body.contains(&block))
            .map(|info| info.header)
            .collect();
        out.sort_by_key(|h| self.infos[h].body.len());
        out
    }

    pub(crate) fn edge_action(&self, from: usize, target: usize) -> Option<EdgeAction> {
        for h in self.enclosing(from) {
            let Some(info) = self.infos.get(&h) else {
                continue;
            };
            if target == h {
                return Some(EdgeAction::Continue);
            }
            if info.exits.contains(&target) {
                return Some(EdgeAction::Break);
            }
        }
        None
    }
}

impl LoopInfo {
    pub(crate) fn body_entry(&self, cfg: &CFG) -> Option<usize> {
        let header = cfg.blocks.get(self.header)?;
        header
            .successors
            .iter()
            .map(|e| e.target)
            .find(|t| self.body.contains(t))
    }

    pub(crate) fn exit_edge(&self, cfg: &CFG) -> Option<(usize, EdgeKind)> {
        let header = cfg.blocks.get(self.header)?;
        header
            .successors
            .iter()
            .find(|e| !self.body.contains(&e.target) && self.exits.contains(&e.target))
            .map(|e| (e.target, e.kind))
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum EdgeAction {
    Break,
    Continue,
}

fn dominates(idom: &[usize], a: usize, mut b: usize) -> bool {
    loop {
        if b == a {
            return true;
        }
        let d = idom.get(b).copied().unwrap_or(usize::MAX);
        if d == b || d == usize::MAX {
            return false;
        }
        b = d;
    }
}

fn negate_cond(cond: &str) -> String {
    if cond == "cond" {
        return "cond".into();
    }
    if let Some(inner) = cond.strip_prefix("!(").and_then(|s| s.strip_suffix(')')) {
        return inner.to_string();
    }
    for (op, inv) in [
        (" == ", " != "),
        (" != ", " == "),
        (" <= ", " > "),
        (" >= ", " < "),
        (" < ", " >= "),
        (" > ", " <= "),
    ] {
        if let Some((a, b)) = cond.split_once(op) {
            return format!("{}{}{}", a, inv, b);
        }
    }
    format!("!({})", cond)
}

fn sets_flags(op: &POp) -> bool {
    matches!(
        op,
        POp::Cmp { .. }
            | POp::Test { .. }
            | POp::FloatCmp { .. }
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
    )
}

fn dead_safe(op: &POp) -> bool {
    is_pure(op) || matches!(op, POp::Cvt { .. })
}

#[derive(Clone, Copy)]
pub(crate) struct WalkCtx<'a> {
    pub(crate) cfg: &'a CFG,
    pub(crate) bops: &'a [Vec<(u64, &'a POp)>],
    pub(crate) imap: &'a [DisasmInstruction],
    pub(crate) func_lookup: &'a HashMap<u64, String>,
    pub(crate) back_edges: &'a HashMap<usize, usize>,
    pub(crate) block_consts: &'a [HashMap<&'static str, Lattice>],
    pub(crate) dowhile: &'a HashSet<usize>,
    pub(crate) dead: &'a HashSet<(usize, usize)>,
    pub(crate) cancel: Option<&'a std::sync::atomic::AtomicBool>,
    pub(crate) postdom: &'a Postdom,
    pub(crate) loops: &'a Loops,
    pub(crate) is64: bool,
    pub(crate) hints: &'a TypeHints,
}

pub(crate) fn walk_block(
    ctx: &WalkCtx<'_>,
    block_id: usize,
    visited: &mut HashSet<usize>,
    lines: &mut Vec<PseudoLine>,
    indent: u32,
    depth: usize,
) {
    walk_region(ctx, block_id, visited, lines, indent, depth, &[]);
}

fn walk_region(
    ctx: &WalkCtx<'_>,
    block_id: usize,
    visited: &mut HashSet<usize>,
    lines: &mut Vec<PseudoLine>,
    indent: u32,
    depth: usize,
    stops: &[usize],
) {
    if stops.contains(&block_id) {
        return;
    }
    let WalkCtx {
        cfg,
        bops,
        imap,
        func_lookup,
        back_edges,
        block_consts,
        dowhile,
        dead,
        cancel,
        postdom,
        loops,
        is64,
        hints,
    } = *ctx;
    if depth > 5_000 {
        return;
    }
    if visited.contains(&block_id) {
        return;
    }
    if lines.len() > MAX_DECOMP_LINES || hints.out_bytes.get() > MAX_DECOMP_BYTES {
        hints.out_truncated.set(true);
        return;
    }
    if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
        return;
    }
    visited.insert(block_id);

    if block_id >= cfg.blocks.len() {
        return;
    }
    let block = &cfg.blocks[block_id];

    let loop_info = loops.get(block_id);
    let is_loop_header = loop_info.is_some();
    let is_dowhile = dowhile.contains(&block_id);
    let body_indent = if is_loop_header || is_dowhile {
        indent + 1
    } else {
        indent
    };
    let mut loop_exit: Option<usize> = None;
    let mut loop_body_entry: Option<usize> = None;

    if is_dowhile {
        lines.push(PseudoLine {
            indent,
            text: "do {".into(),
            kind: LineKind::Branch,
            source_addr: Some(block.start),
        });
    } else if let Some(info) = loop_info {
        if let Some((exit, kind)) = info.exit_edge(cfg) {
            let consts = block_consts.get(block_id).cloned().unwrap_or_default();
            let base = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
            let cond = match kind {
                EdgeKind::BranchTrue => negate_cond(&base),
                _ => base,
            };
            lines.push(PseudoLine {
                indent,
                text: format!("while ({}) {{", cond),
                kind: LineKind::Branch,
                source_addr: Some(block.start),
            });
            loop_exit = Some(exit);
            loop_body_entry = info.body_entry(cfg);
        } else {
            lines.push(PseudoLine {
                indent,
                text: "while (1) {".into(),
                kind: LineKind::Branch,
                source_addr: Some(block.start),
            });
            loop_body_entry = info.body_entry(cfg);
        }
    } else if block.predecessors.len() > 1 || (block_id != 0 && block.predecessors.is_empty()) {
        lines.push(PseudoLine {
            indent: 0,
            text: format!("LAB_{:X}:", block.start),
            kind: LineKind::Label,
            source_addr: Some(block.start),
        });
    }

    
    
    let loop_indent = indent;
    macro_rules! finish {
        () => {{
            if is_dowhile {
                close_dowhile(ctx, block_id, visited, lines, loop_indent, depth, stops);
            }
            return;
        }};
    }

    let seed: HashMap<&'static str, Lattice> =
        block_consts.get(block_id).cloned().unwrap_or_default();
    let mut reg_values: HashMap<&'static str, PVal> = seed
        .into_iter()
        .filter_map(|(k, v)| match v {
            Lattice::Const(c) => Some((k, PVal::C(c))),
            Lattice::Var(n) => Some((k, PVal::E(n.to_string()))),
            Lattice::Top => None,
        })
        .collect();

    let ops: &[(u64, &POp)] = &bops[block_id];
    let addrs: Vec<u64> = ops.iter().map(|(a, _)| *a).collect();

    let block_has_jcc = addrs.iter().any(|a| {
        imap_get(imap, *a)
            .map(|d| d.mnemonic.starts_with('j') && d.mnem() != "jmp")
            .unwrap_or(false)
    });
    let mut last_use: HashMap<&'static str, usize> = HashMap::default();
    let mut live_out: rustc_hash::FxHashSet<&'static str> = rustc_hash::FxHashSet::default();
    for s in &block.successors {
        if s.target >= bops.len() {
            continue;
        }
        for (_, op) in &bops[s.target] {
            for r in reads_regs(op) {
                live_out.insert(r);
            }
        }
    }
    for (i, (_, op)) in ops.iter().enumerate() {
        for r in reads_regs(op) {
            last_use.insert(r, i);
        }
    }

    let ov_before = EXPR_OVERFLOWS.with(|c| c.get());
    hints.last_cmp.borrow_mut().take();
    let lines_before = lines.len();
    let mut cse_map: HashMap<String, (&'static str, Vec<&'static str>)> = HashMap::default();
    let mut push_args: Vec<PVal> = Vec::new();

    for (i, (addr, op)) in ops.iter().enumerate() {
        if dead_safe(op)
            && let Some(dst_reg) = written_reg(op)
        {
            let dead_local = last_use.get(dst_reg).map(|&u| u <= i).unwrap_or(true);
            let removable = !block_has_jcc || !sets_flags(op);
            if removable && dead_local && !live_out.contains(dst_reg) {
                continue;
            }
        }
        if dead.contains(&(block_id, i)) {
            continue;
        }
        let ck = if !block_has_jcc {
            cse_key(op, &reg_values)
        } else {
            None
        };
        if let Some((ref key, _)) = ck
            && let Some(holder) = cse_map.get(key).map(|(h, _)| *h)
            && let Some(dst) = written_reg(op)
        {
            if holder != dst {
                let dstv = PVar::Reg(canonical_reg(dst));
                track(&mut reg_values, &dstv, PVal::E(holder.to_string()));
                lines.push(PseudoLine {
                    indent: body_indent,
                    text: format!("{} = {};", fmt_var(&dstv), holder),
                    kind: LineKind::Assignment,
                    source_addr: Some(*addr),
                });
            }
            cse_invalidate(&mut cse_map, dst);
            continue;
        }
        let rendered = render_op(
            op,
            *addr,
            func_lookup,
            &mut reg_values,
            is64,
            hints,
            &mut push_args,
        );
        if !block_has_jcc && let Some(w) = written_reg(op) {
            cse_invalidate(&mut cse_map, w);
        }
        if let Some((text, kind)) = rendered {
            lines.push(PseudoLine {
                indent: body_indent,
                text,
                kind,
                source_addr: Some(*addr),
            });
            if let Some((key, oregs)) = ck
                && let Some(dst) = written_reg(op)
            {
                cse_map.insert(key, (dst, oregs));
            }
        }
    }

    let ov_after = EXPR_OVERFLOWS.with(|c| c.get());
    if ov_after != ov_before {
        eprintln!(
            "[decompiler] block {:#x}: {} tracked value(s) exceeded {} bytes (expression blow-up)",
            block.start,
            ov_after.wrapping_sub(ov_before),
            MAX_TRACKED_EXPR
        );
    }
    let emitted: usize = lines[lines_before..].iter().map(|l| l.text.len() + 8).sum();
    hints.out_bytes.set(hints.out_bytes.get() + emitted);
    let succs = &block.successors;
    if is_loop_header && !is_dowhile {
        if let Some(entry) = loop_body_entry
            && !visited.contains(&entry)
        {
            walk_region(ctx, entry, visited, lines, body_indent, depth + 1, stops);
        }
        lines.push(PseudoLine {
            indent,
            text: "}".into(),
            kind: LineKind::Branch,
            source_addr: None,
        });
        if let Some(exit) = loop_exit
            && !visited.contains(&exit)
            && !stops.contains(&exit)
        {
            walk_region(ctx, exit, visited, lines, indent, depth + 1, stops);
        }
        return;
    }
    if let Some(&last_addr) = addrs.last()
        && let Some(di) = imap_get(imap, last_addr)
    {
        let m = di.mnemonic;
        let has_true = succs.iter().any(|e| e.kind == EdgeKind::BranchTrue);
        if m.starts_with('j') && m != "jmp" && m != "jecxz" && !has_true {
            let target = parse_addr(&di.ops());
            let consts = block_consts.get(block_id).cloned().unwrap_or_default();
            let cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
            let text = match target {
                Some(target) => match func_lookup.get(&target) {
                    Some(name) => format!(
                        "if ({}) {{ return {}(); }}  // conditional tail call",
                        cond, name
                    ),
                    None => format!(
                        "if ({}) {{ goto 0x{:x}; }}  // target outside decoded function range",
                        cond, target
                    ),
                },
                None => format!(
                    "// WARNING: branch '{} {}' target not decoded here; check disasm",
                    m, di.operands
                ),
            };
            lines.push(PseudoLine {
                indent,
                text,
                kind: LineKind::Branch,
                source_addr: Some(last_addr),
            });
        }
    }
    if succs.is_empty() {
        if let Some((last_addr, last_op)) = ops.last()
            && let POp::Branch { target } = &**last_op
        {
            let target = *target;
            let real_target = hints.thunk_targets.get(&target).copied().unwrap_or(target);
            let args = if let Some(sig) = hints.callee_params.get(&real_target) {
                take_call_args_sig(&reg_values, is64, hints.is_win64, sig, &mut push_args)
            } else {
                take_call_args(&reg_values, is64, hints.is_win64, &mut push_args)
            };
            let (text, kind) = match func_lookup.get(&real_target) {
                Some(name) if args.is_empty() => (
                    format!("return {}();  // tail call", name),
                    LineKind::Return,
                ),
                Some(name) => (
                    format!("return {}({});  // tail call", name, args.join(", ")),
                    LineKind::Return,
                ),
                None => (
                    format!(
                        "goto 0x{:x};  // tail call - target outside this function",
                        target
                    ),
                    LineKind::Branch,
                ),
            };
            lines.push(PseudoLine {
                indent,
                text,
                kind,
                source_addr: Some(*last_addr),
            });
        }
    } else if succs.len() == 1 {
        let edge = &succs[0];
        if let Some(action) = loop_action(loops, visited, block_id, edge.target) {
            push_edge_action(lines, indent, action);
        } else {
            match edge.kind {
                EdgeKind::Jump => {
                    if stops.contains(&edge.target) {
                        
                    } else if !visited.contains(&edge.target)
                        && (cfg.blocks[edge.target].predecessors.len() == 1
                            || loops.get(edge.target).is_some())
                    {
                        walk_region(
                            ctx,
                            edge.target,
                            visited,
                            lines,
                            body_indent,
                            depth + 1,
                            stops,
                        );
                    } else {
                        lines.push(PseudoLine {
                            indent,
                            text: format!("goto LAB_{:X};", cfg.blocks[edge.target].start),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                    }
                }
                _ => {
                    if !visited.contains(&edge.target) {
                        walk_region(
                            ctx,
                            edge.target,
                            visited,
                            lines,
                            body_indent,
                            depth + 1,
                            stops,
                        );
                    }
                }
            }
        }
    } else {
        
        
        let indent = body_indent;
        let true_edge = succs.iter().find(|e| e.kind == EdgeKind::BranchTrue);
        let false_edge = succs.iter().find(|e| e.kind == EdgeKind::BranchFalse);

        if let (Some(t), Some(f)) = (true_edge, false_edge) {
            let enclosing = loops.enclosing(block_id);
            let t_loops_back = enclosing.contains(&t.target);
            let f_loops_back = enclosing.contains(&f.target);

            
            
            let is_dowhile_latch = dowhile
                .iter()
                .any(|h| back_edges.get(h) == Some(&block_id) && visited.contains(h));
            if is_dowhile_latch {
                finish!();
            }

            
            let t_action = loop_action(loops, visited, block_id, t.target);
            let f_action = loop_action(loops, visited, block_id, f.target);
            if t_action.is_some() || f_action.is_some() {
                let consts = block_consts.get(block_id).cloned().unwrap_or_default();
                let mut cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
                match (t_action, f_action) {
                    (Some(ta), Some(fa)) => {
                        lines.push(PseudoLine {
                            indent,
                            text: format!("if ({}) {{", cond),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                        push_edge_action(lines, indent + 1, ta);
                        lines.push(PseudoLine {
                            indent,
                            text: "} else {".into(),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                        push_edge_action(lines, indent + 1, fa);
                        lines.push(PseudoLine {
                            indent,
                            text: "}".into(),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                    }
                    (Some(ta), None) => {
                        lines.push(PseudoLine {
                            indent,
                            text: format!("if ({}) {{", cond),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                        push_edge_action(lines, indent + 1, ta);
                        lines.push(PseudoLine {
                            indent,
                            text: "}".into(),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                        if !visited.contains(&f.target) {
                            walk_region(ctx, f.target, visited, lines, indent, depth + 1, stops);
                        }
                    }
                    (None, Some(fa)) => {
                        cond = negate_cond(&cond);
                        lines.push(PseudoLine {
                            indent,
                            text: format!("if ({}) {{", cond),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                        push_edge_action(lines, indent + 1, fa);
                        lines.push(PseudoLine {
                            indent,
                            text: "}".into(),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                        if !visited.contains(&t.target) {
                            walk_region(ctx, t.target, visited, lines, indent, depth + 1, stops);
                        }
                    }
                    (None, None) => {}
                }
                finish!();
            }

            if t_loops_back || f_loops_back {
                let consts = block_consts.get(block_id).cloned().unwrap_or_default();
                let cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
                if f_loops_back {
                    lines.push(PseudoLine {
                        indent,
                        text: format!("if ({}) {{", cond),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&t.target) {
                        walk_region(ctx, t.target, visited, lines, indent + 1, depth + 1, stops);
                    } else {
                        lines.push(PseudoLine {
                            indent: indent + 1,
                            text: format!("goto LAB_{:X};", cfg.blocks[t.target].start),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                    }
                    lines.push(PseudoLine {
                        indent,
                        text: "}".into(),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&f.target) {
                        walk_region(ctx, f.target, visited, lines, indent, depth + 1, stops);
                    }
                } else if t_loops_back {
                    lines.push(PseudoLine {
                        indent,
                        text: format!("if (!({})) {{", cond),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&f.target) {
                        walk_region(ctx, f.target, visited, lines, indent + 1, depth + 1, stops);
                    } else {
                        lines.push(PseudoLine {
                            indent: indent + 1,
                            text: format!("goto LAB_{:X};", cfg.blocks[f.target].start),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                    }
                    lines.push(PseudoLine {
                        indent,
                        text: "}".into(),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&t.target) {
                        walk_region(ctx, t.target, visited, lines, indent, depth + 1, stops);
                    }
                }
                finish!();
            }

            
            
            
            
            
            
            
            let join = if is_dowhile {
                back_edges.get(&block_id).copied()
            } else {
                postdom.join_of(block_id)
            };
            if let Some(join) = join
                && join != block_id
                && !visited.contains(&join)
            {
                let consts = block_consts.get(block_id).cloned().unwrap_or_default();
                let mut cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
                let mut arm_stops = stops.to_vec();
                if !arm_stops.contains(&join) {
                    arm_stops.push(join);
                }
                let single_arm = if t.target == join {
                    cond = negate_cond(&cond);
                    Some(f.target)
                } else if f.target == join {
                    Some(t.target)
                } else {
                    None
                };
                lines.push(PseudoLine {
                    indent,
                    text: format!("if ({}) {{", cond),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
                if let Some(arm) = single_arm {
                    walk_arm(ctx, arm, visited, lines, indent + 1, depth, &arm_stops);
                } else {
                    walk_arm(ctx, t.target, visited, lines, indent + 1, depth, &arm_stops);
                    lines.push(PseudoLine {
                        indent,
                        text: "} else {".into(),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    walk_arm(ctx, f.target, visited, lines, indent + 1, depth, &arm_stops);
                }
                lines.push(PseudoLine {
                    indent,
                    text: "}".into(),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
                if !stops.contains(&join) && !visited.contains(&join) {
                    walk_region(ctx, join, visited, lines, indent, depth + 1, stops);
                }
                finish!();
            }

            
            
            
            
            let t_exit = reaches_only_exit(cfg, t.target, &[f.target]);
            let f_exit = reaches_only_exit(cfg, f.target, &[t.target]);
            if t_exit != f_exit {
                let consts = block_consts.get(block_id).cloned().unwrap_or_default();
                let mut cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
                let (arm, cont) = if t_exit {
                    (t.target, f.target)
                } else {
                    cond = negate_cond(&cond);
                    (f.target, t.target)
                };
                lines.push(PseudoLine {
                    indent,
                    text: format!("if ({}) {{", cond),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
                walk_arm(ctx, arm, visited, lines, indent + 1, depth, stops);
                lines.push(PseudoLine {
                    indent,
                    text: "}".into(),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
                if !visited.contains(&cont) {
                    walk_region(ctx, cont, visited, lines, indent, depth + 1, stops);
                }
                finish!();
            }

            let consts = block_consts.get(block_id).cloned().unwrap_or_default();
            let cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
            lines.push(PseudoLine {
                indent,
                text: format!("if ({}) {{", cond),
                kind: LineKind::Branch,
                source_addr: None,
            });
            if !visited.contains(&t.target) {
                walk_region(ctx, t.target, visited, lines, indent + 1, depth + 1, stops);
            } else {
                lines.push(PseudoLine {
                    indent: indent + 1,
                    text: format!("goto LAB_{:X};", cfg.blocks[t.target].start),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
            }
            lines.push(PseudoLine {
                indent,
                text: "} else {".into(),
                kind: LineKind::Branch,
                source_addr: None,
            });
            if !visited.contains(&f.target) {
                walk_region(ctx, f.target, visited, lines, indent + 1, depth + 1, stops);
            } else {
                lines.push(PseudoLine {
                    indent: indent + 1,
                    text: format!("goto LAB_{:X};", cfg.blocks[f.target].start),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
            }
            lines.push(PseudoLine {
                indent,
                text: "}".into(),
                kind: LineKind::Branch,
                source_addr: None,
            });
        }
    }

    if is_dowhile {
        close_dowhile(ctx, block_id, visited, lines, indent, depth, stops);
    } else if is_loop_header {
        lines.push(PseudoLine {
            indent,
            text: "}".into(),
            kind: LineKind::Branch,
            source_addr: None,
        });
    }
}

fn close_dowhile(
    ctx: &WalkCtx<'_>,
    block_id: usize,
    visited: &mut HashSet<usize>,
    lines: &mut Vec<PseudoLine>,
    indent: u32,
    depth: usize,
    stops: &[usize],
) {
    let WalkCtx {
        cfg,
        bops,
        imap,
        back_edges,
        block_consts,
        hints,
        ..
    } = *ctx;
    let Some(latch) = back_edges.get(&block_id).copied() else {
        
        lines.push(PseudoLine {
            indent,
            text: "} while (1);".into(),
            kind: LineKind::Branch,
            source_addr: None,
        });
        return;
    };
    let consts = block_consts.get(latch).cloned().unwrap_or_default();
    let cond = recover_condition(cfg, bops, imap, latch, &consts, Some(hints));
    let repeats = cfg.blocks[latch]
        .successors
        .iter()
        .any(|e| e.target == block_id && e.kind == EdgeKind::BranchTrue);
    lines.push(PseudoLine {
        indent,
        text: if repeats {
            format!("}} while ({});", cond)
        } else {
            format!("}} while (!({}));", cond)
        },
        kind: LineKind::Branch,
        source_addr: None,
    });
    for e in &cfg.blocks[latch].successors {
        if e.target != block_id
            && !visited.contains(&e.target)
            && !stops.contains(&e.target)
        {
            walk_region(ctx, e.target, visited, lines, indent, depth + 1, stops);
        }
    }
}

fn walk_arm(
    ctx: &WalkCtx<'_>,
    block: usize,
    visited: &mut HashSet<usize>,
    lines: &mut Vec<PseudoLine>,
    indent: u32,
    depth: usize,
    stops: &[usize],
) {
    if block >= ctx.cfg.blocks.len() {
        return;
    }
    if visited.contains(&block) {
        lines.push(PseudoLine {
            indent,
            text: format!("goto LAB_{:X};", ctx.cfg.blocks[block].start),
            kind: LineKind::Branch,
            source_addr: None,
        });
    } else {
        walk_region(ctx, block, visited, lines, indent, depth + 1, stops);
    }
}



fn reaches_only_exit(cfg: &CFG, start: usize, avoid: &[usize]) -> bool {
    let mut seen: HashSet<usize> = HashSet::default();
    let mut stack = vec![start];
    let mut terminal = false;
    while let Some(b) = stack.pop() {
        if avoid.contains(&b) {
            return false;
        }
        if !seen.insert(b) {
            continue;
        }
        let Some(block) = cfg.blocks.get(b) else {
            continue;
        };
        if block.successors.is_empty() {
            terminal = true;
            continue;
        }
        for e in &block.successors {
            stack.push(e.target);
        }
    }
    terminal
}




fn loop_action(
    loops: &Loops,
    visited: &HashSet<usize>,
    from: usize,
    target: usize,
) -> Option<EdgeAction> {
    let header = loops.enclosing(from).into_iter().next()?;
    if !visited.contains(&header) {
        return None;
    }
    loops.edge_action(from, target)
}

fn push_edge_action(lines: &mut Vec<PseudoLine>, indent: u32, action: EdgeAction) {
    lines.push(PseudoLine {
        indent,
        text: match action {
            EdgeAction::Break => "break;".into(),
            EdgeAction::Continue => "continue;".into(),
        },
        kind: LineKind::Branch,
        source_addr: None,
    });
}

fn label_of(text: &str) -> Option<&str> {
    let t = text.trim();
    let name = t.strip_suffix(':')?;
    name.starts_with("LAB_").then_some(name)
}

fn goto_target(text: &str) -> Option<&str> {
    let t = text.trim();
    let rest = t.strip_prefix("goto ")?;
    let name = rest.strip_suffix(';')?;
    name.starts_with("LAB_").then_some(name)
}

type CopiedLine = (String, LineKind, Option<u64>, u32);




pub(crate) fn inline_terminal_gotos(lines: &mut Vec<PseudoLine>) {
    let Some(close) = lines
        .iter()
        .rposition(|l| l.kind == LineKind::CloseBrace && l.indent == 0)
    else {
        return;
    };
    let mut labels: HashMap<String, (usize, usize)> = HashMap::default();
    let label_positions: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| label_of(&l.text).is_some())
        .map(|(i, _)| i)
        .collect();
    for (n, &i) in label_positions.iter().enumerate() {
        let name = label_of(&lines[i].text).unwrap_or_default().to_string();
        let end = label_positions.get(n + 1).copied().unwrap_or(close);
        labels.insert(name, (i, end));
    }
    if labels.is_empty() {
        return;
    }

    let mut replacements: Vec<(usize, Vec<PseudoLine>)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(target) = goto_target(&line.text) else {
            continue;
        };
        let Some(&(label_idx, end)) = labels.get(target) else {
            continue;
        };
        let mut seen: HashSet<String> = HashSet::default();
        let Some(body) =
            terminal_return_body(lines, label_idx + 1, end, Some(&labels), &mut seen, 0)
        else {
            continue;
        };
        let copied: Vec<PseudoLine> = body
            .into_iter()
            .map(|(text, kind, source_addr, _)| PseudoLine {
                indent: line.indent,
                text,
                kind,
                source_addr,
            })
            .collect();
        replacements.push((i, copied));
    }
    for (idx, copied) in replacements.into_iter().rev() {
        lines.splice(idx..=idx, copied);
    }
}




pub(crate) fn retarget_goto_chains(lines: &mut [PseudoLine]) {
    let Some(close) = lines
        .iter()
        .rposition(|l| l.kind == LineKind::CloseBrace && l.indent == 0)
    else {
        return;
    };
    let mut alias: HashMap<String, String> = HashMap::default();
    let mut i = 0;
    while i < lines.len() {
        let Some(name) = label_of(&lines[i].text).map(str::to_string) else {
            i += 1;
            continue;
        };
        let mut next = i + 1;
        while next < lines.len() && lines[next].text.trim().is_empty() {
            next += 1;
        }
        if next < close
            && lines[next].kind != LineKind::Label
            && let Some(target) = goto_target(&lines[next].text)
            && target != name
        {
            alias.insert(name, target.to_string());
        }
        i = next.max(i + 1);
    }
    if alias.is_empty() {
        return;
    }
    for line in lines.iter_mut() {
        let Some(mut target) = goto_target(&line.text).map(str::to_string) else {
            continue;
        };
        let mut seen: HashSet<String> = HashSet::default();
        while let Some(next) = alias.get(&target) {
            if !seen.insert(target.clone()) {
                break;
            }
            target.clone_from(next);
        }
        line.text = format!("goto {};", target);
    }
}

fn terminal_return_body(
    lines: &[PseudoLine],
    start: usize,
    end: usize,
    labels: Option<&HashMap<String, (usize, usize)>>,
    seen: &mut HashSet<String>,
    depth: usize,
) -> Option<Vec<CopiedLine>> {
    if depth > 8 {
        return None;
    }
    let mut out = Vec::new();
    for line in &lines[start..end.min(lines.len())] {
        let t = line.text.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("return") {
            out.push((line.text.clone(), line.kind, line.source_addr, line.indent));
            return Some(out);
        }
        if let Some(target) = goto_target(t)
            && let Some(labels) = labels
            && let Some(&(label_idx, label_end)) = labels.get(target)
        {
            if !seen.insert(target.to_string()) {
                return None;
            }
            let rest = terminal_return_body(
                lines,
                label_idx + 1,
                label_end,
                Some(labels),
                seen,
                depth + 1,
            )?;
            out.extend(rest);
            return Some(out);
        }
        if t == "{" || t.starts_with('}') || label_of(t).is_some() {
            return None;
        }
        if t.starts_with("if ")
            || t.starts_with("if(")
            || t.starts_with("while")
            || t.starts_with("do")
            || t.starts_with("for")
            || t.starts_with("switch")
            || t.starts_with("goto ")
            || t.starts_with("break;")
            || t.starts_with("continue;")
            || t.starts_with("else")
        {
            return None;
        }
        if !t.starts_with("//") {
            out.push((line.text.clone(), line.kind, line.source_addr, line.indent));
        }
    }
    None
}



pub(crate) fn prune_unreachable_returns(lines: &mut Vec<PseudoLine>) {
    loop {
        let mut refs: HashSet<String> = HashSet::default();
        for l in lines.iter() {
            if let Some(t) = goto_target(&l.text) {
                refs.insert(t.to_string());
            }
        }
        let mut remove: Option<(usize, usize)> = None;
        for (i, l) in lines.iter().enumerate() {
            let Some(name) = label_of(&l.text) else {
                continue;
            };
            if refs.contains(name) {
                continue;
            }
            let prev = lines[..i].iter().rposition(|p| !p.text.trim().is_empty());
            let unreachable = prev.is_some_and(|p| {
                let t = lines[p].text.trim();
                t.starts_with("return")
                    || t.starts_with("goto ")
                    || t == "break;"
                    || t == "continue;"
            });
            if !unreachable {
                continue;
            }
            let next_label = lines[i + 1..]
                .iter()
                .position(|p| label_of(&p.text).is_some())
                .map(|p| i + 1 + p)
                .unwrap_or(lines.len());
            if terminal_return_body(
                lines,
                i + 1,
                next_label,
                None,
                &mut HashSet::default(),
                0,
            )
            .is_some()
            {
                remove = Some((i, next_label));
                break;
            }
        }
        if let Some((start, end)) = remove {
            lines.drain(start..end);
        } else {
            break;
        }
    }
}



pub(crate) fn cleanup_labels(lines: &mut Vec<PseudoLine>) {
    loop {
        let mut refs: HashSet<String> = HashSet::default();
        for l in lines.iter() {
            if let Some(t) = goto_target(&l.text) {
                refs.insert(t.to_string());
            }
        }
        let before = lines.len();
        lines.retain(|l| {
            l.kind != LineKind::Label || label_of(&l.text).is_some_and(|name| refs.contains(name))
        });
        let mut i = 0;
        while i < lines.len() {
            let target = goto_target(&lines[i].text).map(str::to_string);
            if let Some(target) = target {
                let next = lines[i + 1..].iter().find(|l| !l.text.trim().is_empty());
                if next.is_some_and(|l| {
                    l.kind == LineKind::Label && label_of(&l.text) == Some(target.as_str())
                }) {
                    lines.remove(i);
                    continue;
                }
            }
            i += 1;
        }
        if lines.len() == before {
            break;
        }
    }
    drop_redundant_continues(lines);
}




fn drop_redundant_continues(lines: &mut Vec<PseudoLine>) {
    let mut loop_close: HashSet<usize> = HashSet::default();
    let mut stack: Vec<bool> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let code = l.text.split("//").next().unwrap_or("");
        let t = l.text.trim_start();
        let mut open_is_loop = t.starts_with("while")
            || t.starts_with("do")
            || t.starts_with("for")
            || t.starts_with("loop");
        if t.starts_with("} else") {
            open_is_loop = false;
        }
        for ch in code.chars() {
            match ch {
                '{' => stack.push(open_is_loop),
                '}' if stack.pop().unwrap_or(false) => {
                    loop_close.insert(i);
                }
                _ => {}
            }
        }
    }

    let mut i = 0;
    while i < lines.len() {
        if lines[i].text.trim() == "continue;" {
            let next = (i + 1..lines.len()).find(|&j| !lines[j].text.trim().is_empty());
            if next.is_some_and(|j| loop_close.contains(&j)) {
                lines.remove(i);
                continue;
            }
        }
        i += 1;
    }
}





pub(crate) fn squash_empty_branches(lines: &mut Vec<PseudoLine>) {
    loop {
        let mut changed = false;
        let mut i = 0;
        while i < lines.len() {
            if !is_if_open(&lines[i].text) {
                i += 1;
                continue;
            }
            let Some(then_close) = find_block_close(lines, i, false) else {
                i += 1;
                continue;
            };
            let else_open = lines[then_close].text.trim_start().starts_with("} else");
            if !else_open {
                if only_comments(lines, i + 1, then_close) {
                    
                    
                    lines.remove(then_close);
                    lines.remove(i);
                    changed = true;
                    continue;
                }
                i += 1;
                continue;
            }
            let Some(else_close) = find_block_close(lines, then_close, true) else {
                i += 1;
                continue;
            };
            let then_empty = then_close == i + 1;
            let else_empty = else_close == then_close + 1;
            if then_empty && else_empty {
                lines.drain(i..=else_close);
            } else if then_empty {
                lines[i].text = negate_if_line(&lines[i].text);
                lines.drain(i + 1..=then_close);
            } else if else_empty {
                lines[then_close].text = "}".into();
                lines.remove(else_close);
            } else {
                i += 1;
                continue;
            }
            changed = true;
        }
        if !changed {
            break;
        }
    }
}

fn is_if_open(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with("if (") && t.ends_with('{')
}

fn only_comments(lines: &[PseudoLine], from: usize, to: usize) -> bool {
    lines.get(from..to).is_some_and(|body| {
        body.iter()
            .all(|l| l.text.trim().is_empty() || l.kind == LineKind::Comment)
    })
}

fn negate_if_line(text: &str) -> String {
    let indent_len = text.len() - text.trim_start().len();
    let indent = &text[..indent_len];
    let t = text.trim_start();
    if let Some(rest) = t.strip_prefix("if (")
        && let Some(cond) = rest.strip_suffix(") {")
    {
        return format!("{indent}if ({}) {{", negate_cond(cond));
    }
    text.to_string()
}




fn find_block_close(lines: &[PseudoLine], start: usize, after_else: bool) -> Option<usize> {
    let mut depth = if after_else { 1 } else { 0 };
    let mut opened = after_else;
    for (j, line) in lines.iter().enumerate().skip(start) {
        let code = code_part(&line.text);
        let mut skipped_open = j > start || !after_else;
        for c in code.chars() {
            if !skipped_open {
                if c == '{' {
                    skipped_open = true;
                }
                continue;
            }
            match c {
                '{' => {
                    depth += 1;
                    opened = true;
                }
                '}' => {
                    depth -= 1;
                    if opened && depth == 0 {
                        return Some(j);
                    }
                }
                _ => {}
            }
        }
        if after_else && j == start && !skipped_open {
            return None;
        }
    }
    None
}


fn code_part(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        if c == '"' || c == '\'' {
            quote = Some(c);
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            break;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    fn line(text: &str, kind: LineKind) -> PseudoLine {
        PseudoLine {
            indent: 0,
            text: text.into(),
            kind,
            source_addr: None,
        }
    }

    #[test]
    fn inlines_terminal_return_gotos() {
        let mut lines = vec![
            line("if (x) {", LineKind::Branch),
            line("goto LAB_10;", LineKind::Branch),
            line("}", LineKind::Branch),
            line("LAB_10:", LineKind::Label),
            line("// pop rbx", LineKind::Comment),
            line("return;", LineKind::Return),
            line("}", LineKind::CloseBrace),
        ];
        inline_terminal_gotos(&mut lines);
        assert!(
            !lines.iter().any(|l| l.text.contains("goto LAB_")),
            "goto should be inlined: {:?}",
            lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>()
        );
        assert!(lines.iter().any(|l| l.text == "return;"));
    }

    #[test]
    fn inlines_goto_chain_to_return() {
        let mut lines = vec![
            line("if (x) {", LineKind::Branch),
            line("goto LAB_10;", LineKind::Branch),
            line("}", LineKind::Branch),
            line("LAB_10:", LineKind::Label),
            line("goto LAB_20;", LineKind::Branch),
            line("LAB_20:", LineKind::Label),
            line("return 7;", LineKind::Return),
            line("}", LineKind::CloseBrace),
        ];
        retarget_goto_chains(&mut lines);
        inline_terminal_gotos(&mut lines);
        assert!(
            !lines.iter().any(|l| l.text.contains("goto LAB_")),
            "goto chain to return should be inlined: {:?}",
            lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>()
        );
        assert!(lines.iter().any(|l| l.text == "return 7;"));
    }

    #[test]
    fn does_not_inline_fallthrough_block() {
        let mut lines = vec![
            line("goto LAB_10;", LineKind::Branch),
            line("LAB_10:", LineKind::Label),
            line("rax = 1;", LineKind::Assignment),
            line("}", LineKind::CloseBrace),
        ];
        inline_terminal_gotos(&mut lines);
        assert!(
            lines.iter().any(|l| l.text == "goto LAB_10;"),
            "fallthrough block must keep its goto"
        );
    }

    #[test]
    fn keeps_continue_inside_nested_if() {
        let mut lines = vec![
            line("while (x) {", LineKind::Branch),
            line("if (y) {", LineKind::Branch),
            line("continue;", LineKind::Branch),
            line("}", LineKind::Branch),
            line("rax = 1;", LineKind::Assignment),
            line("}", LineKind::Branch),
        ];
        drop_redundant_continues(&mut lines);
        assert!(lines.iter().any(|l| l.text == "continue;"), "continue in if kept");
    }

    #[test]
    fn drops_continue_at_loop_end() {
        let mut lines = vec![
            line("while (x) {", LineKind::Branch),
            line("rax = 1;", LineKind::Assignment),
            line("continue;", LineKind::Branch),
            line("}", LineKind::Branch),
        ];
        drop_redundant_continues(&mut lines);
        assert!(!lines.iter().any(|l| l.text == "continue;"), "redundant continue dropped");
    }

    #[test]
    fn empty_then_branch_is_inverted() {
        let mut lines = vec![
            line("if (a) {", LineKind::Branch),
            line("} else {", LineKind::Branch),
            line("x = 1;", LineKind::Assignment),
            line("}", LineKind::Branch),
        ];
        squash_empty_branches(&mut lines);
        assert_eq!(
            lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            vec!["if (!(a)) {", "x = 1;", "}"]
        );
    }

    #[test]
    fn empty_else_branch_is_removed() {
        let mut lines = vec![
            line("if (a) {", LineKind::Branch),
            line("x = 1;", LineKind::Assignment),
            line("} else {", LineKind::Branch),
            line("}", LineKind::Branch),
        ];
        squash_empty_branches(&mut lines);
        assert_eq!(
            lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            vec!["if (a) {", "x = 1;", "}"]
        );
    }

    #[test]
    fn both_empty_branches_are_removed() {
        let mut lines = vec![
            line("if (a) {", LineKind::Branch),
            line("} else {", LineKind::Branch),
            line("}", LineKind::Branch),
            line("y = 2;", LineKind::Assignment),
        ];
        squash_empty_branches(&mut lines);
        assert_eq!(
            lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            vec!["y = 2;"]
        );
    }

    #[test]
    fn comment_only_branch_keeps_the_comment() {
        let mut lines = vec![
            line("if (a) {", LineKind::Branch),
            line("// WARNING: missing branch", LineKind::Comment),
            line("}", LineKind::Branch),
            line("y = 2;", LineKind::Assignment),
        ];
        squash_empty_branches(&mut lines);
        assert_eq!(
            lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            vec!["// WARNING: missing branch", "y = 2;"]
        );
    }
}
