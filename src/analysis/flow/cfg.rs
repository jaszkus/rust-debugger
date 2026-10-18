use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashMap as HashMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub start: u64,
    pub end: u64,
    pub instr_indices: std::ops::Range<usize>,
    pub successors: Vec<Edge>,
    pub predecessors: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub target: usize,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EdgeKind {
    Fallthrough,
    Jump,
    BranchTrue,
    BranchFalse,
}

#[allow(dead_code)]
pub type IntraProcCFG = CFG;

#[derive(Debug, Clone)]
pub struct CFG {
    pub func_entry: u64,
    pub blocks: Vec<BasicBlock>,
    pub block_at: HashMap<u64, usize>,
}

pub fn build_cfg(insns: &[DisasmInstruction], func_entry: u64, func_end: u64) -> CFG {
    let start = insns.partition_point(|i| i.address < func_entry);
    let end = insns.partition_point(|i| i.address < func_end);
    let func_insns: Vec<usize> = (start..end).collect();

    if func_insns.is_empty() {
        return CFG {
            func_entry,
            blocks: vec![],
            block_at: HashMap::default(),
        };
    }

    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(func_entry);

    for &i in &func_insns {
        let ins = &insns[i];
        let m = ins.mnemonic;

        if is_terminator(m) {
            if i + 1 < end {
                leaders.insert(insns[i + 1].address);
            }
        } else if is_uncond_jmp(m) || is_cond_jump(m) {
            if let Some(target) = parse_addr(&ins.ops()) {
                if target >= func_entry && target < func_end {
                    leaders.insert(target);
                }
            }
            if i + 1 < end {
                leaders.insert(insns[i + 1].address);
            }
        }
    }

    let leader_vec: Vec<u64> = leaders.into_iter().collect();
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut block_at: HashMap<u64, usize> = HashMap::default();

    let mut insn_i = 0usize;
    for (bi, &leader) in leader_vec.iter().enumerate() {
        let block_end = leader_vec.get(bi + 1).copied().unwrap_or(func_end);

        while insn_i < func_insns.len() && insns[func_insns[insn_i]].address < leader {
            insn_i += 1;
        }
        let mut j = insn_i;
        let first_idx = insn_i;
        while j < func_insns.len() && insns[func_insns[j]].address < block_end {
            j += 1;
        }

        if j > first_idx {
            let id = blocks.len();
            blocks.push(BasicBlock {
                id,
                start: leader,
                end: block_end,
                instr_indices: func_insns[first_idx]..func_insns[j - 1] + 1,
                successors: Vec::new(),
                predecessors: Vec::new(),
            });
            block_at.insert(leader, id);
        }
    }

    let block_count = blocks.len();
    for blk in blocks.iter_mut() {
        let last_idx = match blk.instr_indices.end.checked_sub(1) {
            Some(i) if i >= blk.instr_indices.start => i,
            _ => continue,
        };
        let last = &insns[last_idx];
        let m = last.mnemonic;
        let block_end = blk.end;

        if is_terminator(m) {
        } else if is_uncond_jmp(m) {
            if let Some(target) = parse_addr(&last.ops()) {
                if target == func_end {
                } else if let Some(&tid) = block_at.get(&target) {
                    blk.successors.push(Edge {
                        target: tid,
                        kind: EdgeKind::Jump,
                    });
                }
            }
        } else if is_cond_jump(m) {
            if let Some(target) = parse_addr(&last.ops()) {
                if let Some(&tid) = block_at.get(&target) {
                    blk.successors.push(Edge {
                        target: tid,
                        kind: EdgeKind::BranchTrue,
                    });
                }
            }
            if let Some(&fid) = block_at.get(&block_end) {
                blk.successors.push(Edge {
                    target: fid,
                    kind: EdgeKind::BranchFalse,
                });
            }
        } else {
            if let Some(&fid) = block_at.get(&block_end) {
                blk.successors.push(Edge {
                    target: fid,
                    kind: EdgeKind::Fallthrough,
                });
            }
        }
    }

    for bi in 0..block_count {
        let succs: Vec<usize> = blocks[bi].successors.iter().map(|e| e.target).collect();
        for s in succs {
            if s < block_count {
                blocks[s].predecessors.push(bi);
            }
        }
    }

    let entry_id = block_at.get(&func_entry).copied().unwrap_or(0);
    if blocks.len() > 1 && entry_id < blocks.len() {
        let mut pinned = vec![false; blocks.len()];
        for blk in &blocks {
            let last_idx = match blk.instr_indices.end.checked_sub(1) {
                Some(i) if i >= blk.instr_indices.start => i,
                _ => continue,
            };
            let last = &insns[last_idx];
            if is_uncond_jmp(last.mnemonic) {
                match parse_addr(&last.ops()) {
                    Some(target) => {
                        if target < func_entry || target >= func_end {
                            if let Some(&fid) = block_at.get(&blk.end) {
                                pinned[fid] = true;
                            }
                        }
                    }
                    None => {
                        if let Some(&fid) = block_at.get(&blk.end) {
                            pinned[fid] = true;
                        }
                    }
                }
            }
        }
        let mut reachable = vec![false; blocks.len()];
        let mut stack = vec![entry_id];
        reachable[entry_id] = true;
        while let Some(b) = stack.pop() {
            for e in &blocks[b].successors {
                if e.target < blocks.len() && !reachable[e.target] {
                    reachable[e.target] = true;
                    stack.push(e.target);
                }
            }
        }
        for (i, p) in pinned.iter().enumerate() {
            if *p {
                reachable[i] = true;
            }
        }
        if reachable.iter().any(|r| !r) {
            let mut remap = vec![usize::MAX; blocks.len()];
            let mut new_blocks = Vec::new();
            for (i, b) in blocks.iter().enumerate() {
                if reachable[i] {
                    remap[i] = new_blocks.len();
                    let mut nb = b.clone();
                    nb.id = remap[i];
                    new_blocks.push(nb);
                }
            }
            for nb in new_blocks.iter_mut() {
                nb.successors
                    .retain(|e| e.target < blocks.len() && remap[e.target] != usize::MAX);
                for e in nb.successors.iter_mut() {
                    e.target = remap[e.target];
                }
                nb.predecessors = nb
                    .predecessors
                    .iter()
                    .filter(|&&p| remap[p] != usize::MAX)
                    .map(|&p| remap[p])
                    .collect();
            }
            let new_block_at: HashMap<u64, usize> =
                new_blocks.iter().map(|b| (b.start, b.id)).collect();
            blocks = new_blocks;
            block_at = new_block_at;
        }
    }

    CFG {
        func_entry,
        blocks,
        block_at,
    }
}

fn is_terminator(m: &str) -> bool {
    matches!(
        m,
        "ret"
            | "retn"
            | "retf"
            | "retq"
            | "retw"
            | "iret"
            | "iretd"
            | "iretq"
            | "int3"
            | "hlt"
            | "ud1"
            | "ud2"
    )
}

fn is_uncond_jmp(m: &str) -> bool {
    m == "jmp"
}

fn is_cond_jump(m: &str) -> bool {
    if m == "jmp" {
        return false;
    }
    m.starts_with('j') || m.starts_with("loop")
}

fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let first = s.split(',').next().unwrap_or(s).trim();
    let tok: &str = first
        .split([' ', '\t', '<', ';', '('])
        .next()
        .unwrap_or(first)
        .trim();
    let tok = tok
        .trim()
        .trim_end_matches(',')
        .trim_end_matches(')')
        .trim();
    if tok.is_empty() {
        return None;
    }
    if let Some(h) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        let hex: &str = h
            .split(|c: char| !c.is_ascii_hexdigit())
            .next()
            .unwrap_or(h);
        if hex.is_empty() {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if tok.len() > 1 && (tok.ends_with('h') || tok.ends_with('H')) {
        let hex = &tok[..tok.len() - 1];
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                return Some(v);
            }
        }
    }
    if tok.starts_with('-') || tok.starts_with('+') {
        return None;
    }
    tok.parse::<u64>().ok()
}

pub fn graph_layout(cfg: &CFG, max_lines: usize) -> (Vec<[f32; 2]>, Vec<f32>, Vec<i32>) {
    let n = cfg.blocks.len();
    if n == 0 {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    const LINE_H: f32 = 15.0;
    const PAD: f32 = 6.0;
    const NODE_W: f32 = 300.0;
    const H_GAP: f32 = 36.0;
    const V_GAP: f32 = 54.0;

    let mut heights = vec![0.0f32; n];
    for (i, b) in cfg.blocks.iter().enumerate() {
        let lines = 1 + b.instr_indices.len().min(max_lines);
        heights[i] = PAD * 2.0 + lines as f32 * LINE_H;
    }
    let entry_idx = cfg.block_at.get(&cfg.func_entry).copied().unwrap_or(0);
    let mut levels = vec![-1i32; n];
    let mut queue = std::collections::VecDeque::new();
    if entry_idx < n {
        levels[entry_idx] = 0;
        queue.push_back(entry_idx);
    }
    while let Some(b) = queue.pop_front() {
        for e in &cfg.blocks[b].successors {
            let t = e.target;
            if t < n && levels[t] < 0 {
                levels[t] = levels[b] + 1;
                queue.push_back(t);
            }
        }
    }
    let max_lvl = levels.iter().copied().max().unwrap_or(0).max(0);
    for l in levels.iter_mut() {
        if *l < 0 {
            *l = max_lvl + 1;
        }
    }
    let mut by_level: std::collections::BTreeMap<i32, Vec<usize>> = Default::default();
    for (i, &lvl) in levels.iter().enumerate() {
        by_level.entry(lvl).or_default().push(i);
    }
    for g in by_level.values_mut() {
        g.sort_by_key(|&i| cfg.blocks[i].start);
    }
    let mut pos = vec![[0.0f32; 2]; n];
    let mut y = 0.0f32;
    for g in by_level.values() {
        let h = g.iter().map(|&i| heights[i]).fold(0.0f32, f32::max);
        let total_w = g.len() as f32 * (NODE_W + H_GAP) - H_GAP;
        let mut x = -total_w / 2.0;
        for &b in g {
            pos[b] = [x, y];
            x += NODE_W + H_GAP;
        }
        y += h + V_GAP;
    }
    (pos, heights, levels)
}
