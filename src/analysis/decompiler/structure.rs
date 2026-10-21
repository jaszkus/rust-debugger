use super::printing::*;
use super::*;
use crate::analysis::flow::cfg::{CFG, EdgeKind, parse_addr};
use crate::analysis::operands::canonical_reg;
use crate::disasm::DisasmInstruction;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};


const MAX_CLONE_BLOCKS: usize = 32;
const MAX_CLONE_LINES: usize = 200;

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

    
    pub(crate) fn reaches_exit(&self, block: usize) -> bool {
        let mut cur = block;
        for _ in 0..=self.ipdom.len() {
            if cur == self.exit {
                return true;
            }
            let Some(&next) = self.ipdom.get(cur) else {
                return false;
            };
            if next == cur {
                return next == self.exit;
            }
            cur = next;
        }
        false
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
    pub(crate) switches: &'a [crate::analysis::advanced::SwitchTable],
    
    
    pub(crate) clone: bool,
    
    pub(crate) clone_depth: u8,
}







fn clone_terminal_region(
    ctx: &WalkCtx<'_>,
    target: usize,
    visited: &HashSet<usize>,
    indent: u32,
    depth: usize,
    stops: &[usize],
) -> Option<Vec<PseudoLine>> {
    if ctx.clone_depth >= 2
        || target >= ctx.cfg.blocks.len()
        || !ctx.postdom.reaches_exit(target)
        || ctx.loops.get(target).is_some()
        || !ctx.loops.enclosing(target).is_empty()
    {
        return None;
    }
    let mut region: HashSet<usize> = HashSet::default();
    let mut queue = vec![target];
    while let Some(b) = queue.pop() {
        if !region.insert(b) {
            continue;
        }
        if region.len() > MAX_CLONE_BLOCKS {
            return None;
        }
        for edge in &ctx.cfg.blocks[b].successors {
            let t = edge.target;
            if t >= ctx.cfg.blocks.len()
                || ctx.loops.get(t).is_some()
                || !ctx.loops.enclosing(t).is_empty()
            {
                return None;
            }
            if t <= b {
                return None;
            }
            queue.push(t);
        }
    }
    let mut cv = visited.clone();
    for b in &region {
        cv.remove(b);
    }
    let bytes_before = ctx.hints.out_bytes.get();
    let clone_ctx = WalkCtx {
        clone: true,
        clone_depth: ctx.clone_depth + 1,
        ..*ctx
    };
    let mut out = Vec::new();
    walk_region(&clone_ctx, target, &mut cv, &mut out, indent, depth + 1, stops);
    let text = out.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n");
    let mut balance = 0i32;
    for ch in text.chars() {
        match ch {
            '{' => balance += 1,
            '}' => balance -= 1,
            _ => {}
        }
        if balance < 0 {
            ctx.hints.out_bytes.set(bytes_before);
            return None;
        }
    }
    if out.is_empty()
        || out.len() > MAX_CLONE_LINES
        || balance != 0
        || text.contains("LAB_")
        || text.contains("goto ")
        || text.contains("break;")
        || text.contains("continue;")
        || text.contains("WARNING")
        || text.contains("truncated")
    {
        ctx.hints.out_bytes.set(bytes_before);
        return None;
    }
    Some(out)
}





fn clone_arm_region(
    ctx: &WalkCtx<'_>,
    target: usize,
    stop: usize,
    visited: &HashSet<usize>,
    indent: u32,
    depth: usize,
    stops: &[usize],
) -> Option<Vec<PseudoLine>> {
    if ctx.clone_depth >= 2
        || target >= ctx.cfg.blocks.len()
        || target == stop
        || stops.contains(&target)
        || ctx.loops.get(target).is_some()
        || !ctx.loops.enclosing(target).is_empty()
    {
        return None;
    }
    let mut region: HashSet<usize> = HashSet::default();
    let mut queue = vec![target];
    let mut reaches_stop = false;
    while let Some(b) = queue.pop() {
        if b == stop {
            reaches_stop = true;
            continue;
        }
        if stops.contains(&b) {
            return None;
        }
        if !region.insert(b) {
            continue;
        }
        if region.len() > MAX_CLONE_BLOCKS {
            return None;
        }
        for edge in &ctx.cfg.blocks[b].successors {
            let t = edge.target;
            if t == stop {
                reaches_stop = true;
                continue;
            }
            if stops.contains(&t)
                || t >= ctx.cfg.blocks.len()
                || ctx.loops.get(t).is_some()
                || !ctx.loops.enclosing(t).is_empty()
                || t <= b
            {
                return None;
            }
            queue.push(t);
        }
    }
    if !reaches_stop {
        return None;
    }
    let mut cv = visited.clone();
    for b in &region {
        cv.remove(b);
    }
    let bytes_before = ctx.hints.out_bytes.get();
    let clone_ctx = WalkCtx {
        clone: true,
        clone_depth: ctx.clone_depth + 1,
        ..*ctx
    };
    let mut out = Vec::new();
    walk_region(
        &clone_ctx,
        target,
        &mut cv,
        &mut out,
        indent,
        depth + 1,
        &[stop],
    );
    let text = out.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n");
    let mut balance = 0i32;
    for ch in text.chars() {
        match ch {
            '{' => balance += 1,
            '}' => balance -= 1,
            _ => {}
        }
        if balance < 0 {
            ctx.hints.out_bytes.set(bytes_before);
            return None;
        }
    }
    if out.is_empty()
        || out.len() > MAX_CLONE_LINES
        || balance != 0
        || text.contains("LAB_")
        || text.contains("goto ")
        || text.contains("break;")
        || text.contains("continue;")
        || text.contains("WARNING")
        || text.contains("truncated")
    {
        ctx.hints.out_bytes.set(bytes_before);
        return None;
    }
    Some(out)
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

fn indirect_index(var: &PVar) -> String {
    match var {
        PVar::Scaled { index, .. } => fmt_var(index),
        PVar::Mem(base, _) => indirect_index(base),
        _ => fmt_var(var),
    }
}

fn switch_expression(bops: &[Vec<(u64, &POp)>], block_id: usize) -> String {
    bops.get(block_id)
        .and_then(|ops| {
            ops.iter().rev().find_map(|(_, op)| match op {
                POp::BranchInd { target } => Some(indirect_index(target)),
                _ => None,
            })
        })
        .unwrap_or_else(|| "index".to_string())
}

fn switch_groups(
    cfg: &CFG,
    table: &crate::analysis::advanced::SwitchTable,
) -> Option<Vec<(u64, Vec<usize>)>> {
    let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
    for (index, &target) in table.case_targets.iter().enumerate() {
        if !cfg.block_at.contains_key(&target) {
            return None;
        }
        if let Some((_, cases)) = groups.iter_mut().find(|(t, _)| *t == target) {
            cases.push(index);
        } else {
            groups.push((target, vec![index]));
        }
    }
    (groups.len() >= 2).then_some(groups)
}

struct CompareCase {
    value: String,
    target: usize,
}

struct CompareChain {
    expr: String,
    cases: Vec<CompareCase>,
    checks: Vec<usize>,
    default: Option<usize>,
    join: usize,
}

type SwitchGroup = (u64, Vec<usize>, Option<u64>);

fn switch_fallthrough_order(
    cfg: &CFG,
    groups: &[(u64, Vec<usize>)],
    join: Option<usize>,
) -> Option<Vec<SwitchGroup>> {
    if groups.len() < 2 {
        return None;
    }
    let mut targets: Vec<usize> = Vec::with_capacity(groups.len());
    for (addr, _) in groups {
        targets.push(*cfg.block_at.get(addr)?);
    }
    let mut next_group: Vec<Option<usize>> = vec![None; groups.len()];
    for (index, &start) in targets.iter().enumerate() {
        let mut cur = start;
        let mut seen: HashSet<usize> = HashSet::default();
        for _ in 0..16 {
            if !seen.insert(cur) {
                return None;
            }
            let block = cfg.blocks.get(cur)?;
            if block.successors.len() != 1 {
                break;
            }
            let next = block.successors[0].target;
            if join == Some(next) || next >= cfg.blocks.len() {
                break;
            }
            if let Some(target_index) = targets.iter().position(|target| *target == next) {
                if target_index != index {
                    next_group[index] = Some(target_index);
                }
                break;
            }
            cur = next;
        }
    }
    let mut state = vec![0u8; groups.len()];
    let mut order: Vec<usize> = Vec::with_capacity(groups.len());
    fn visit(
        index: usize,
        next_group: &[Option<usize>],
        state: &mut [u8],
        order: &mut Vec<usize>,
    ) -> bool {
        match state[index] {
            1 => return false,
            2 => return true,
            _ => {}
        }
        state[index] = 1;
        if let Some(next) = next_group[index]
            && !visit(next, next_group, state, order)
        {
            return false;
        }
        state[index] = 2;
        order.push(index);
        true
    }
    for index in 0..groups.len() {
        if !visit(index, &next_group, &mut state, &mut order) {
            return None;
        }
    }
    order.reverse();
    let mut out = Vec::with_capacity(groups.len());
    for (position, &index) in order.iter().enumerate() {
        let (target, cases) = groups.get(index)?;
        let fallthrough = next_group[index]
            .filter(|next| order.get(position + 1) == Some(next))
            .and_then(|next| groups.get(next).map(|(target, _)| *target));
        out.push((*target, cases.clone(), fallthrough));
    }
    Some(out)
}

fn is_const_token(value: &str) -> bool {
    let value = value.trim();
    let value = value.strip_prefix('-').unwrap_or(value);
    !value.is_empty()
        && (value.starts_with("0x")
            || value.starts_with("0X")
            || value.chars().all(|c| c.is_ascii_digit()))
}

fn parse_equality(cond: &str) -> Option<(String, String, bool)> {
    if cond.contains(" && ") || cond.contains(" || ") {
        return None;
    }
    for (op, case_true) in [(" == ", true), (" != ", false)] {
        let Some((left, right)) = cond.split_once(op) else {
            continue;
        };
        let (expr, value) = if is_const_token(right) && !is_const_token(left) {
            (left, right)
        } else if is_const_token(left) && !is_const_token(right) {
            (right, left)
        } else {
            return None;
        };
        let expr = expr.trim();
        let value = value.trim();
        if expr.is_empty() || value.is_empty() {
            return None;
        }
        return Some((expr.to_string(), value.to_string(), case_true));
    }
    None
}

fn dispatch_block_is_pure(ctx: &WalkCtx<'_>, block: usize) -> bool {
    ctx.bops.get(block).is_some_and(|ops| {
        ops.iter().all(|(_, op)| {
            matches!(
                op,
                POp::Cmp { .. }
                    | POp::Test { .. }
                    | POp::CBranch { .. }
                    | POp::Branch { .. }
            )
        })
    })
}

fn detect_compare_chain(ctx: &WalkCtx<'_>, start: usize, join: usize) -> Option<CompareChain> {
    let n = ctx.cfg.blocks.len();
    if start >= n || join >= n {
        return None;
    }
    let mut cur = start;
    let mut expr: Option<String> = None;
    let mut cases: Vec<CompareCase> = Vec::new();
    let mut checks: Vec<usize> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::default();

    for _ in 0..64 {
        if cur >= n || !seen.insert(cur) || !dispatch_block_is_pure(ctx, cur) {
            break;
        }
        let block = &ctx.cfg.blocks[cur];
        if block.successors.len() != 2 {
            break;
        }
        let true_edge = block
            .successors
            .iter()
            .find(|e| e.kind == EdgeKind::BranchTrue);
        let false_edge = block
            .successors
            .iter()
            .find(|e| e.kind == EdgeKind::BranchFalse);
        let (Some(true_edge), Some(false_edge)) = (true_edge, false_edge) else {
            break;
        };
        let consts = ctx.block_consts.get(cur).cloned().unwrap_or_default();
        let cond = recover_condition(
            ctx.cfg,
            ctx.bops,
            ctx.imap,
            cur,
            &consts,
            Some(ctx.hints),
        );
        let Some((cond_expr, value, case_true)) = parse_equality(&cond) else {
            break;
        };
        if let Some(prev) = &expr {
            if prev != &cond_expr {
                break;
            }
        } else {
            expr = Some(cond_expr);
        }
        if cases.iter().any(|c| c.value == value) {
            break;
        }
        let (case, next) = if case_true {
            (true_edge.target, false_edge.target)
        } else {
            (false_edge.target, true_edge.target)
        };
        if case == next
            || case == start
            || case == join
            || checks.contains(&case)
            || cases.iter().any(|c| c.target == case)
        {
            break;
        }
        cases.push(CompareCase { value, target: case });
        checks.push(cur);
        cur = next;
    }

    if cases.len() < 2 || checks.contains(&join) || cur == start || cur >= n {
        return None;
    }
    let default = (cur != join && !checks.contains(&cur)).then_some(cur);
    if default.is_some_and(|d| cases.iter().any(|c| c.target == d)) {
        return None;
    }
    Some(CompareChain {
        expr: expr?,
        cases,
        checks,
        default,
        join,
    })
}

fn region_hits_forbidden(
    ctx: &WalkCtx<'_>,
    start: usize,
    join: usize,
    forbidden: &HashSet<usize>,
) -> bool {
    let mut seen: HashSet<usize> = HashSet::default();
    let mut stack = vec![start];
    while let Some(block) = stack.pop() {
        if block == join || !seen.insert(block) || block >= ctx.cfg.blocks.len() {
            continue;
        }
        if block != start && ctx.loops.get(block).is_some() {
            continue;
        }
        if block != start && forbidden.contains(&block) {
            return true;
        }
        for edge in &ctx.cfg.blocks[block].successors {
            stack.push(edge.target);
        }
    }
    false
}

fn compare_chain_is_safe(ctx: &WalkCtx<'_>, chain: &CompareChain) -> bool {
    let mut forbidden: HashSet<usize> = chain.checks.iter().copied().collect();
    forbidden.extend(chain.cases.iter().map(|c| c.target));
    if let Some(default) = chain.default {
        forbidden.insert(default);
    }
    for case in &chain.cases {
        if case.target == chain.join {
            continue;
        }
        let mut excluded = forbidden.clone();
        excluded.remove(&case.target);
        if region_hits_forbidden(ctx, case.target, chain.join, &excluded) {
            return false;
        }
    }
    if let Some(default) = chain.default
        && default != chain.join
    {
        let mut excluded = forbidden;
        excluded.remove(&default);
        if region_hits_forbidden(ctx, default, chain.join, &excluded) {
            return false;
        }
    }
    true
}

fn switch_case_ends_terminally(lines: &[PseudoLine], start: usize) -> bool {
    lines[start..]
        .iter()
        .rev()
        .find(|l| l.kind != LineKind::Comment && !l.text.trim().is_empty())
        .is_some_and(|l| {
            let text = l.text.trim();
            text.starts_with("return")
                || text.starts_with("goto ")
                || text == "break;"
                || text == "continue;"
        })
}

#[allow(clippy::too_many_arguments)]
fn try_render_compare_switch(
    ctx: &WalkCtx<'_>,
    block_id: usize,
    visited: &mut HashSet<usize>,
    lines: &mut Vec<PseudoLine>,
    indent: u32,
    depth: usize,
    stops: &[usize],
) -> bool {
    let Some(join) = ctx.postdom.join_of(block_id) else {
        return false;
    };
    let Some(chain) = detect_compare_chain(ctx, block_id, join) else {
        return false;
    };
    if !compare_chain_is_safe(ctx, &chain)
        || chain.cases.iter().any(|c| visited.contains(&c.target))
        || chain
            .default
            .is_some_and(|d| d != join && visited.contains(&d))
    {
        return false;
    }

    let saved_visited = visited.clone();
    let saved_bytes = ctx.hints.out_bytes.get();
    let start_lines = lines.len();
    for check in &chain.checks {
        visited.insert(*check);
    }

    let mut case_stops = stops.to_vec();
    if !case_stops.contains(&join) {
        case_stops.push(join);
    }
    for case in &chain.cases {
        if !case_stops.contains(&case.target) {
            case_stops.push(case.target);
        }
    }
    if let Some(default) = chain.default
        && !case_stops.contains(&default)
    {
        case_stops.push(default);
    }

    let case_ctx = WalkCtx {
        clone: true,
        clone_depth: ctx.clone_depth + 1,
        ..*ctx
    };

    lines.push(PseudoLine {
        indent,
        text: format!("switch ({}) {{", chain.expr),
        kind: LineKind::Branch,
        source_addr: Some(ctx.cfg.blocks[block_id].start),
    });

    let mut groups: Vec<(usize, Vec<String>)> = Vec::new();
    for case in &chain.cases {
        if let Some((_, values)) = groups.iter_mut().find(|(target, _)| *target == case.target) {
            values.push(case.value.clone());
        } else {
            groups.push((case.target, vec![case.value.clone()]));
        }
    }
    for (target, values) in groups {
        for value in values {
            lines.push(PseudoLine {
                indent: indent + 1,
                text: format!("case {value}:"),
                kind: LineKind::Branch,
                source_addr: Some(ctx.cfg.blocks[target].start),
            });
        }
        let body_start = lines.len();
        if target != join && !visited.contains(&target) {
            let arm_stops: Vec<usize> = case_stops
                .iter()
                .copied()
                .filter(|stop| *stop != target)
                .collect();
            walk_arm(
                &case_ctx,
                target,
                visited,
                lines,
                indent + 1,
                depth,
                &arm_stops,
                Some(join),
            );
        }
        if !switch_case_ends_terminally(lines, body_start) {
            lines.push(PseudoLine {
                indent: indent + 1,
                text: "break;".into(),
                kind: LineKind::Branch,
                source_addr: None,
            });
        }
    }

    if let Some(default) = chain.default
        && default != join
    {
        lines.push(PseudoLine {
            indent: indent + 1,
            text: "default:".into(),
            kind: LineKind::Branch,
            source_addr: Some(ctx.cfg.blocks[default].start),
        });
        let body_start = lines.len();
        if !visited.contains(&default) {
            let arm_stops: Vec<usize> = case_stops
                .iter()
                .copied()
                .filter(|stop| *stop != default)
                .collect();
            walk_arm(
                &case_ctx,
                default,
                visited,
                lines,
                indent + 1,
                depth,
                &arm_stops,
                Some(join),
            );
        }
        if !switch_case_ends_terminally(lines, body_start) {
            lines.push(PseudoLine {
                indent: indent + 1,
                text: "break;".into(),
                kind: LineKind::Branch,
                source_addr: None,
            });
        }
    }

    lines.push(PseudoLine {
        indent,
        text: "}".into(),
        kind: LineKind::Branch,
        source_addr: None,
    });
    if !visited.contains(&join) && !stops.contains(&join) {
        let join_needs_label = ctx.cfg.blocks[join].predecessors.iter().any(|p| {
            !chain.checks.contains(p)
                && !chain.cases.iter().any(|c| c.target == *p)
                && chain.default != Some(*p)
        });
        let join_ctx = if join_needs_label { ctx } else { &case_ctx };
        walk_region(
            join_ctx,
            join,
            visited,
            lines,
            indent,
            depth + 1,
            stops,
        );
    }

    let rendered = lines[start_lines..]
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if rendered.contains("goto ")
        || rendered.contains("LAB_")
        || rendered.contains("WARNING")
        || rendered.contains("truncated")
    {
        lines.truncate(start_lines);
        *visited = saved_visited;
        ctx.hints.out_bytes.set(saved_bytes);
        return false;
    }

    let added: usize = lines[start_lines..]
        .iter()
        .map(|l| l.text.len() + 8)
        .sum();
    ctx.hints.out_bytes.set(saved_bytes + added);
    true
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
        switches,
        ..
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
    let switch_table = switches
        .iter()
        .find(|s| s.jump_addr >= block.start && s.jump_addr < block.end);
    let switch_groups = switch_table.and_then(|table| switch_groups(cfg, table));
    let switch_join = postdom.join_of(block_id);
    let switch_active = switch_table.is_some()
        && switch_groups.is_some()
        && switch_join.is_none_or(|join| !visited.contains(&join));

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
    } else if !ctx.clone
        && (block.predecessors.len() > 1 || (block_id != 0 && block.predecessors.is_empty()))
    {
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
        
        
        if switch_active && matches!(op, POp::BranchInd { .. }) {
            continue;
        }
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
    if switch_active {
        let table = switch_table.expect("switch_active requires a table");
        let groups = switch_groups.as_ref().expect("switch_active requires groups");
        let ordered = switch_fallthrough_order(cfg, groups, switch_join).unwrap_or_else(|| {
            groups
                .iter()
                .map(|(target, cases)| (*target, cases.clone(), None))
                .collect()
        });
        let saved_visited = visited.clone();
        let saved_bytes = hints.out_bytes.get();
        let switch_start = lines.len();
        let mut case_stops = stops.to_vec();
        if let Some(join) = switch_join
            && !case_stops.contains(&join)
        {
            case_stops.push(join);
        }
        let case_ctx = WalkCtx {
            clone: true,
            clone_depth: ctx.clone_depth + 1,
            ..*ctx
        };
        lines.push(PseudoLine {
            indent,
            text: format!("switch ({}) {{", switch_expression(bops, block_id)),
            kind: LineKind::Branch,
            source_addr: Some(table.jump_addr),
        });
        for (target, cases, fallthrough) in &ordered {
            for &case in cases {
                lines.push(PseudoLine {
                    indent: indent + 1,
                    text: format!("case {case}:"),
                    
                    
                    
                    kind: LineKind::Branch,
                    source_addr: Some(*target),
                });
            }
            let Some(&case_block) = cfg.block_at.get(target) else {
                continue;
            };
            let mut body_stops = case_stops.clone();
            if let Some(fallthrough) = fallthrough
                && let Some(&next_block) = cfg.block_at.get(fallthrough)
                && !body_stops.contains(&next_block)
            {
                body_stops.push(next_block);
            }
            let body_start = lines.len();
            if case_block != block_id {
                if visited.contains(&case_block) {
                    walk_arm(
                        &case_ctx,
                        case_block,
                        visited,
                        lines,
                        indent + 1,
                        depth,
                        &body_stops,
                        switch_join,
                    );
                } else {
                    walk_region(
                        &case_ctx,
                        case_block,
                        visited,
                        lines,
                        indent + 1,
                        depth + 1,
                        &body_stops,
                    );
                }
            }
            if fallthrough.is_none() && !switch_case_ends_terminally(lines, body_start) {
                lines.push(PseudoLine {
                    indent: indent + 1,
                    text: "break;".into(),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
            }
        }
        lines.push(PseudoLine {
            indent,
            text: "}".into(),
            kind: LineKind::Branch,
            source_addr: None,
        });
        if let Some(join) = switch_join
            && !visited.contains(&join)
            && !stops.contains(&join)
        {
            walk_region(ctx, join, visited, lines, indent, depth + 1, stops);
        }
        let rendered = lines[switch_start..]
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if rendered.contains("goto ") || rendered.contains("LAB_") || rendered.contains("WARNING") {
            lines.truncate(switch_start);
            hints.out_bytes.set(saved_bytes);
            *visited = saved_visited;
            let fallback = ops.iter().rev().find_map(|(addr, op)| match op {
                POp::BranchInd { .. } => render_op(
                    op,
                    *addr,
                    func_lookup,
                    &mut reg_values,
                    is64,
                    hints,
                    &mut push_args,
                )
                .map(|(text, kind)| (text, kind, *addr)),
                _ => None,
            });
            if let Some((text, kind, addr)) = fallback {
                lines.push(PseudoLine {
                    indent,
                    text,
                    kind,
                    source_addr: Some(addr),
                });
            }
        }
        return;
    }
    if try_render_compare_switch(ctx, block_id, visited, lines, indent, depth, stops) {
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
                    } else if let Some(cloned) =
                        clone_terminal_region(ctx, edge.target, visited, indent, depth, stops)
                    {
                        lines.extend(cloned);
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
                    } else if let Some(cloned) =
                        clone_terminal_region(ctx, t.target, visited, indent + 1, depth, stops)
                    {
                        lines.extend(cloned);
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
                    } else if let Some(cloned) =
                        clone_terminal_region(ctx, f.target, visited, indent + 1, depth, stops)
                    {
                        lines.extend(cloned);
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
                    walk_arm(
                        ctx,
                        arm,
                        visited,
                        lines,
                        indent + 1,
                        depth,
                        &arm_stops,
                        Some(join),
                    );
                } else {
                    walk_arm(
                        ctx,
                        t.target,
                        visited,
                        lines,
                        indent + 1,
                        depth,
                        &arm_stops,
                        Some(join),
                    );
                    lines.push(PseudoLine {
                        indent,
                        text: "} else {".into(),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    walk_arm(
                        ctx,
                        f.target,
                        visited,
                        lines,
                        indent + 1,
                        depth,
                        &arm_stops,
                        Some(join),
                    );
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
                walk_arm(ctx, arm, visited, lines, indent + 1, depth, stops, None);
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
            } else if let Some(cloned) =
                clone_terminal_region(ctx, t.target, visited, indent + 1, depth, stops)
            {
                lines.extend(cloned);
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
            } else if let Some(cloned) =
                clone_terminal_region(ctx, f.target, visited, indent + 1, depth, stops)
            {
                lines.extend(cloned);
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

#[allow(clippy::too_many_arguments)]
fn walk_arm(
    ctx: &WalkCtx<'_>,
    block: usize,
    visited: &mut HashSet<usize>,
    lines: &mut Vec<PseudoLine>,
    indent: u32,
    depth: usize,
    stops: &[usize],
    clone_stop: Option<usize>,
) {
    if block >= ctx.cfg.blocks.len() {
        return;
    }
    if visited.contains(&block) {
        
        
        
        let cloned = clone_terminal_region(ctx, block, visited, indent, depth, stops).or_else(|| {
            let stop = clone_stop?;
            clone_arm_region(ctx, block, stop, visited, indent, depth, stops)
        });
        if let Some(cloned) = cloned {
            lines.extend(cloned);
        } else {
            lines.push(PseudoLine {
                indent,
                text: format!("goto LAB_{:X};", ctx.cfg.blocks[block].start),
                kind: LineKind::Branch,
                source_addr: None,
            });
        }
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

    #[test]
    fn visited_arm_target_clones_a_terminal_region_instead_of_goto() {
        use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
        let blk = |id: usize, succ: Vec<usize>| BasicBlock {
            id,
            start: 0x1000 + id as u64 * 0x10,
            end: 0x1000 + id as u64 * 0x10 + 0x10,
            instr_indices: id..id + 1,
            successors: succ
                .into_iter()
                .map(|target| Edge {
                    target,
                    kind: EdgeKind::Jump,
                })
                .collect(),
            predecessors: vec![],
        };
        let cfg = CFG {
            func_entry: 0x1000,
            blocks: vec![blk(0, vec![1]), blk(1, vec![])],
            block_at: Default::default(),
        };
        let ret = POp::Return;
        let bops: Vec<Vec<(u64, &POp)>> = vec![vec![], vec![(0x1010, &ret)]];
        let block_consts: Vec<HashMap<&'static str, Lattice>> =
            vec![HashMap::default(), HashMap::default()];
        let func_lookup = HashMap::default();
        let back_edges = HashMap::default();
        let dowhile = HashSet::default();
        let dead = HashSet::default();
        let postdom = Postdom::compute(&cfg);
        let loops = Loops::compute(&cfg, 0, &[]);
        let hints = TypeHints::default();
        let ctx = WalkCtx {
            cfg: &cfg,
            bops: &bops,
            imap: &[],
            func_lookup: &func_lookup,
            back_edges: &back_edges,
            block_consts: &block_consts,
            dowhile: &dowhile,
            dead: &dead,
            cancel: None,
            postdom: &postdom,
            loops: &loops,
            is64: true,
            hints: &hints,
            switches: &[],
            clone: false,
            clone_depth: 0,
        };
        let mut visited: HashSet<usize> = HashSet::default();
        visited.insert(1);
        let mut lines = Vec::new();
        walk_arm(&ctx, 1, &mut visited, &mut lines, 1, 0, &[], None);
        assert!(
            lines.iter().any(|l| l.text.starts_with("return")),
            "terminal arm should be cloned: {:?}",
            lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>()
        );
        assert!(
            !lines.iter().any(|l| l.text.contains("goto LAB_")),
            "visited terminal arm must not fall back to a goto"
        );
    }

    #[test]
    fn renders_jump_table_as_switch_cases() {
        use crate::analysis::advanced::SwitchTable;
        use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
        let blk = |id: usize, succ: Vec<usize>| BasicBlock {
            id,
            start: 0x1000 + id as u64 * 0x10,
            end: 0x1000 + id as u64 * 0x10 + 0x10,
            instr_indices: id..id + 1,
            successors: succ
                .into_iter()
                .map(|target| Edge {
                    target,
                    kind: EdgeKind::Jump,
                })
                .collect(),
            predecessors: vec![],
        };
        let mut block_at = HashMap::default();
        for id in 0..3 {
            block_at.insert(0x1000 + id as u64 * 0x10, id);
        }
        let cfg = CFG {
            func_entry: 0x1000,
            blocks: vec![blk(0, vec![1, 2]), blk(1, vec![]), blk(2, vec![])],
            block_at,
        };
        let target = PVar::Scaled {
            base: Box::new(PVar::Reg("table")),
            index: Box::new(PVar::Reg("rax")),
            scale: 4,
            disp: 0,
        };
        let indirect = POp::BranchInd { target };
        let ret = POp::Return;
        let bops: Vec<Vec<(u64, &POp)>> = vec![
            vec![(0x1000, &indirect)],
            vec![(0x1010, &ret)],
            vec![(0x1020, &ret)],
        ];
        let block_consts: Vec<HashMap<&'static str, Lattice>> = vec![
            HashMap::default(),
            HashMap::default(),
            HashMap::default(),
        ];
        let switches = [SwitchTable {
            jump_addr: 0x1000,
            table_addr: 0x2000,
            case_count: 2,
            case_targets: vec![0x1010, 0x1020],
        }];
        let func_lookup = HashMap::default();
        let back_edges = HashMap::default();
        let dowhile = HashSet::default();
        let dead = HashSet::default();
        let postdom = Postdom::compute(&cfg);
        let loops = Loops::compute(&cfg, 0, &[]);
        let hints = TypeHints::default();
        let ctx = WalkCtx {
            cfg: &cfg,
            bops: &bops,
            imap: &[],
            func_lookup: &func_lookup,
            back_edges: &back_edges,
            block_consts: &block_consts,
            dowhile: &dowhile,
            dead: &dead,
            cancel: None,
            postdom: &postdom,
            loops: &loops,
            is64: true,
            hints: &hints,
            switches: &switches,
            clone: false,
            clone_depth: 0,
        };
        let mut visited = HashSet::default();
        let mut lines = Vec::new();
        walk_region(&ctx, 0, &mut visited, &mut lines, 1, 0, &[]);
        let text = lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("switch (rax)"), "{}", text);
        assert!(text.contains("case 0:"), "{}", text);
        assert!(text.contains("case 1:"), "{}", text);
        assert!(!text.contains("goto *"), "{}", text);
    }

    #[test]
    fn visited_arm_target_can_clone_until_the_if_join() {
        use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
        let blk = |id: usize, succ: Vec<usize>| BasicBlock {
            id,
            start: 0x1000 + id as u64 * 0x10,
            end: 0x1000 + id as u64 * 0x10 + 0x10,
            instr_indices: id..id + 1,
            successors: succ
                .into_iter()
                .map(|target| Edge {
                    target,
                    kind: EdgeKind::Jump,
                })
                .collect(),
            predecessors: vec![],
        };
        let cfg = CFG {
            func_entry: 0x1000,
            blocks: vec![blk(0, vec![1]), blk(1, vec![2]), blk(2, vec![0])],
            block_at: Default::default(),
        };
        let call = POp::Call { target: 0x2000 };
        
        
        
        let branch = POp::Branch { target: 0x1000 };
        let bops: Vec<Vec<(u64, &POp)>> = vec![
            vec![],
            vec![(0x1010, &call)],
            vec![(0x1020, &branch)],
        ];
        let block_consts: Vec<HashMap<&'static str, Lattice>> = vec![
            HashMap::default(),
            HashMap::default(),
            HashMap::default(),
        ];
        let func_lookup = HashMap::default();
        let back_edges = HashMap::default();
        let dowhile = HashSet::default();
        let dead = HashSet::default();
        let postdom = Postdom::compute(&cfg);
        let loops = Loops::compute(&cfg, 0, &[]);
        let hints = TypeHints::default();
        let ctx = WalkCtx {
            cfg: &cfg,
            bops: &bops,
            imap: &[],
            func_lookup: &func_lookup,
            back_edges: &back_edges,
            block_consts: &block_consts,
            dowhile: &dowhile,
            dead: &dead,
            cancel: None,
            postdom: &postdom,
            loops: &loops,
            is64: true,
            hints: &hints,
            switches: &[],
            clone: false,
            clone_depth: 0,
        };
        let mut visited: HashSet<usize> = HashSet::default();
        visited.insert(1);
        let mut lines = Vec::new();
        walk_arm(&ctx, 1, &mut visited, &mut lines, 1, 0, &[2], Some(2));
        assert!(
            lines.iter().any(|l| l.text.contains("FUN_2000")),
            "arm body should be cloned: {:?}",
            lines.iter().map(|l| l.text.clone()).collect::<Vec<_>>()
        );
        assert!(
            !lines.iter().any(|l| l.text.contains("goto")),
            "join clone must not emit a goto"
        );
    }

    #[test]
    fn compare_chain_renders_a_switch_without_gotos() {
        use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
        use crate::disasm::operand_enum::OperandList;
        use crate::disasm::{DisasmInstruction, InsnBytes};

        let edge = |target: usize, kind: EdgeKind| Edge { target, kind };
        let mut blocks = vec![
            BasicBlock {
                id: 0,
                start: 0x1000,
                end: 0x1010,
                instr_indices: 0..1,
                successors: vec![edge(3, EdgeKind::BranchTrue), edge(1, EdgeKind::BranchFalse)],
                predecessors: vec![],
            },
            BasicBlock {
                id: 1,
                start: 0x1010,
                end: 0x1020,
                instr_indices: 1..2,
                successors: vec![edge(4, EdgeKind::BranchTrue), edge(2, EdgeKind::BranchFalse)],
                predecessors: vec![],
            },
            BasicBlock {
                id: 2,
                start: 0x1020,
                end: 0x1030,
                instr_indices: 2..3,
                successors: vec![edge(5, EdgeKind::BranchTrue), edge(6, EdgeKind::BranchFalse)],
                predecessors: vec![],
            },
            BasicBlock {
                id: 3,
                start: 0x1030,
                end: 0x1040,
                instr_indices: 3..4,
                successors: vec![edge(7, EdgeKind::Jump)],
                predecessors: vec![],
            },
            BasicBlock {
                id: 4,
                start: 0x1040,
                end: 0x1050,
                instr_indices: 4..5,
                successors: vec![edge(7, EdgeKind::Jump)],
                predecessors: vec![],
            },
            BasicBlock {
                id: 5,
                start: 0x1050,
                end: 0x1060,
                instr_indices: 5..6,
                successors: vec![edge(7, EdgeKind::Jump)],
                predecessors: vec![],
            },
            BasicBlock {
                id: 6,
                start: 0x1060,
                end: 0x1070,
                instr_indices: 6..7,
                successors: vec![edge(7, EdgeKind::Jump)],
                predecessors: vec![],
            },
            BasicBlock {
                id: 7,
                start: 0x1070,
                end: 0x1080,
                instr_indices: 7..8,
                successors: vec![],
                predecessors: vec![],
            },
        ];
        for source in 0..blocks.len() {
            for edge in blocks[source].successors.clone() {
                blocks[edge.target].predecessors.push(source);
            }
        }
        let cfg = CFG {
            func_entry: 0x1000,
            blocks,
            block_at: Default::default(),
        };

        let cmp1 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(1),
            size: 8,
        };
        let cmp2 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(2),
            size: 8,
        };
        let cmp3 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(3),
            size: 8,
        };
        let br1 = POp::CBranch {
            target: 0x1030,
            cond: "je".into(),
        };
        let br2 = POp::CBranch {
            target: 0x1040,
            cond: "je".into(),
        };
        let br3 = POp::CBranch {
            target: 0x1050,
            cond: "je".into(),
        };
        let case1 = POp::Branch { target: 0x1070 };
        let case2 = POp::Branch { target: 0x1070 };
        let case3 = POp::Branch { target: 0x1070 };
        let default = POp::Branch { target: 0x1070 };
        let ret = POp::Return;
        let bops: Vec<Vec<(u64, &POp)>> = vec![
            vec![(0x1000, &cmp1), (0x1002, &br1)],
            vec![(0x1010, &cmp2), (0x1012, &br2)],
            vec![(0x1020, &cmp3), (0x1022, &br3)],
            vec![(0x1030, &case1)],
            vec![(0x1040, &case2)],
            vec![(0x1050, &case3)],
            vec![(0x1060, &default)],
            vec![(0x1070, &ret)],
        ];
        let insn = |address: u64, mnemonic: &'static str, operands: &str| DisasmInstruction {
            address,
            bytes: InsnBytes::from_slice(&[0x90]),
            mnemonic,
            operands: OperandList::Text(operands.into()),
        };
        let imap = vec![
            insn(0x1000, "cmp", "rax, 1"),
            insn(0x1002, "je", "0x1030"),
            insn(0x1010, "cmp", "rax, 2"),
            insn(0x1012, "je", "0x1040"),
            insn(0x1020, "cmp", "rax, 3"),
            insn(0x1022, "je", "0x1050"),
        ];
        let block_consts: Vec<HashMap<&'static str, Lattice>> =
            (0..cfg.blocks.len()).map(|_| HashMap::default()).collect();
        let func_lookup = HashMap::default();
        let back_edges = HashMap::default();
        let dowhile = HashSet::default();
        let dead = HashSet::default();
        let postdom = Postdom::compute(&cfg);
        let loops = Loops::compute(&cfg, 0, &[]);
        let hints = TypeHints::default();
        let ctx = WalkCtx {
            cfg: &cfg,
            bops: &bops,
            imap: &imap,
            func_lookup: &func_lookup,
            back_edges: &back_edges,
            block_consts: &block_consts,
            dowhile: &dowhile,
            dead: &dead,
            cancel: None,
            postdom: &postdom,
            loops: &loops,
            is64: true,
            hints: &hints,
            switches: &[],
            clone: false,
            clone_depth: 0,
        };
        let mut visited: HashSet<usize> = HashSet::default();
        assert_eq!(postdom.join_of(0), Some(7));
        let chain = detect_compare_chain(&ctx, 0, 7).expect("compare chain");
        assert_eq!(chain.cases.len(), 3);
        let mut lines = Vec::new();
        walk_block(&ctx, 0, &mut visited, &mut lines, 0, 0);
        let text = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("switch (rax) {"), "{text}");
        assert!(text.contains("case 1:"), "{text}");
        assert!(text.contains("case 2:"), "{text}");
        assert!(text.contains("case 3:"), "{text}");
        assert!(text.contains("default:"), "{text}");
        assert!(!text.contains("goto "), "{text}");
        assert!(!text.contains("LAB_"), "{text}");
    }

    #[test]
    fn state_machine_loop_renders_switch_and_continues() {
        use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
        use crate::disasm::operand_enum::OperandList;
        use crate::disasm::{DisasmInstruction, InsnBytes};

        let edge = |target: usize, kind: EdgeKind| Edge { target, kind };
        let spec: Vec<Vec<(usize, EdgeKind)>> = vec![
            vec![(1, EdgeKind::Jump), (8, EdgeKind::BranchFalse)],
            vec![(4, EdgeKind::BranchTrue), (2, EdgeKind::BranchFalse)],
            vec![(5, EdgeKind::BranchTrue), (3, EdgeKind::BranchFalse)],
            vec![(6, EdgeKind::BranchTrue), (7, EdgeKind::BranchFalse)],
            vec![(0, EdgeKind::Jump)],
            vec![(0, EdgeKind::Jump)],
            vec![(0, EdgeKind::Jump)],
            vec![(0, EdgeKind::Jump)],
            vec![],
        ];
        let mut blocks: Vec<BasicBlock> = spec
            .into_iter()
            .enumerate()
            .map(|(id, succ)| BasicBlock {
                id,
                start: 0x2000 + id as u64 * 0x10,
                end: 0x2010 + id as u64 * 0x10,
                instr_indices: id..id + 1,
                successors: succ.into_iter().map(|(t, k)| edge(t, k)).collect(),
                predecessors: vec![],
            })
            .collect();
        for source in 0..blocks.len() {
            for edge in blocks[source].successors.clone() {
                blocks[edge.target].predecessors.push(source);
            }
        }
        let cfg = CFG {
            func_entry: 0x2000,
            blocks,
            block_at: Default::default(),
        };

        let cmp0 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(0),
            size: 8,
        };
        let cmp1 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(1),
            size: 8,
        };
        let cmp2 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(2),
            size: 8,
        };
        let cmp3 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(3),
            size: 8,
        };
        let br0 = POp::CBranch {
            target: 0x2010,
            cond: "jne".into(),
        };
        let br1 = POp::CBranch {
            target: 0x2040,
            cond: "je".into(),
        };
        let br2 = POp::CBranch {
            target: 0x2050,
            cond: "je".into(),
        };
        let br3 = POp::CBranch {
            target: 0x2060,
            cond: "je".into(),
        };
        let back1 = POp::Branch { target: 0x2000 };
        let back2 = POp::Branch { target: 0x2000 };
        let back3 = POp::Branch { target: 0x2000 };
        let back4 = POp::Branch { target: 0x2000 };
        let ret = POp::Return;
        let bops: Vec<Vec<(u64, &POp)>> = vec![
            vec![(0x2000, &cmp0), (0x2002, &br0)],
            vec![(0x2010, &cmp1), (0x2012, &br1)],
            vec![(0x2020, &cmp2), (0x2022, &br2)],
            vec![(0x2030, &cmp3), (0x2032, &br3)],
            vec![(0x2040, &back1)],
            vec![(0x2050, &back2)],
            vec![(0x2060, &back3)],
            vec![(0x2070, &back4)],
            vec![(0x2080, &ret)],
        ];
        let insn = |address: u64, mnemonic: &'static str, operands: &str| DisasmInstruction {
            address,
            bytes: InsnBytes::from_slice(&[0x90]),
            mnemonic,
            operands: OperandList::Text(operands.into()),
        };
        let imap = vec![
            insn(0x2000, "cmp", "rax, 0"),
            insn(0x2002, "jne", "0x2010"),
            insn(0x2010, "cmp", "rax, 1"),
            insn(0x2012, "je", "0x2040"),
            insn(0x2020, "cmp", "rax, 2"),
            insn(0x2022, "je", "0x2050"),
            insn(0x2030, "cmp", "rax, 3"),
            insn(0x2032, "je", "0x2060"),
        ];
        let block_consts: Vec<HashMap<&'static str, Lattice>> =
            (0..cfg.blocks.len()).map(|_| HashMap::default()).collect();
        let func_lookup = HashMap::default();
        let mut back_edges = HashMap::default();
        back_edges.insert(0, 4);
        let dowhile = HashSet::default();
        let dead = HashSet::default();
        let postdom = Postdom::compute(&cfg);
        let loops = Loops::compute(&cfg, 0, &[(0, 4), (0, 5), (0, 6), (0, 7)]);
        let hints = TypeHints::default();
        let ctx = WalkCtx {
            cfg: &cfg,
            bops: &bops,
            imap: &imap,
            func_lookup: &func_lookup,
            back_edges: &back_edges,
            block_consts: &block_consts,
            dowhile: &dowhile,
            dead: &dead,
            cancel: None,
            postdom: &postdom,
            loops: &loops,
            is64: true,
            hints: &hints,
            switches: &[],
            clone: false,
            clone_depth: 0,
        };
        let mut visited: HashSet<usize> = HashSet::default();
        let mut lines = Vec::new();
        walk_block(&ctx, 0, &mut visited, &mut lines, 0, 0);
        let text = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("switch (rax) {"), "{text}");
        assert!(text.contains("case 1:"), "{text}");
        assert!(text.contains("continue;"), "{text}");
        assert!(!text.contains("goto "), "{text}");
        assert!(!text.contains("LAB_"), "{text}");
    }

    #[test]
    fn switch_groups_follow_unconditional_fallthrough_order() {
        use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
        let block = |id: usize, target: Option<usize>| BasicBlock {
            id,
            start: 0x3000 + id as u64 * 0x10,
            end: 0x3010 + id as u64 * 0x10,
            instr_indices: id..id + 1,
            successors: target
                .map(|target| vec![Edge { target, kind: EdgeKind::Jump }])
                .unwrap_or_default(),
            predecessors: vec![],
        };
        let cfg = CFG {
            func_entry: 0x3000,
            blocks: vec![block(0, Some(1)), block(1, None)],
            block_at: [(0x3000, 0), (0x3010, 1)].into_iter().collect(),
        };
        let groups = vec![(0x3000, vec![0]), (0x3010, vec![1])];
        let order = switch_fallthrough_order(&cfg, &groups, None).expect("order");
        assert_eq!(order.len(), 2);
        assert_eq!(order[0].0, 0x3000);
        assert_eq!(order[0].2, Some(0x3010));
        assert_eq!(order[1].0, 0x3010);
        assert_eq!(order[1].2, None);
    }

    #[test]
    fn postdom_reaches_exit_for_terminal_regions() {
        use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
        let blk = |id: usize, succ: Vec<usize>| BasicBlock {
            id,
            start: 0x1000 + id as u64 * 0x10,
            end: 0x1000 + id as u64 * 0x10 + 0x10,
            instr_indices: id..id + 1,
            successors: succ
                .into_iter()
                .map(|target| Edge { target, kind: EdgeKind::Jump })
                .collect(),
            predecessors: vec![],
        };
        let cfg = CFG {
            func_entry: 0x1000,
            blocks: vec![
                blk(0, vec![1, 2]),
                blk(1, vec![3]),
                blk(2, vec![3]),
                blk(3, vec![]),
            ],
            block_at: Default::default(),
        };
        let pd = Postdom::compute(&cfg);
        assert!(pd.reaches_exit(0));
        assert!(pd.reaches_exit(1));
        assert!(pd.reaches_exit(3));
        assert_eq!(pd.join_of(0), Some(3));
    }
}
