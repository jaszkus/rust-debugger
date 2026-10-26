use super::printing::*;
use super::*;
use crate::analysis::flow::cfg::{CFG, EdgeKind};
use crate::analysis::flow::variables;
use crate::analysis::operands::canonical_reg;
use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashSet as HashSet;

fn norm(v: i64, size: u32) -> i64 {
    match size {
        1 => v as u8 as i64,
        2 => v as u16 as i64,
        4 => v as u32 as i64,
        _ => v,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum StateSlot {
    Stack(u8, i64),
    Field(String),
}

fn addr_is_plain(v: &PVar) -> bool {
    match v {
        PVar::Reg(_) | PVar::Const(_) | PVar::Addr(_) => true,
        PVar::Mem(inner, _) => addr_is_plain(inner),
        PVar::Scaled { base, index, .. } => addr_is_plain(base) && addr_is_plain(index),
        _ => false,
    }
}

pub(crate) fn slot_of(v: &PVar) -> Option<StateSlot> {
    match v {
        PVar::StackSlot { base, off } => Some(StateSlot::Stack(variables::base_id(base), *off)),
        PVar::Addr(_) => Some(StateSlot::Field(fmt_var(v))),
        PVar::Mem(..) | PVar::Scaled { .. } if addr_is_plain(v) => {
            Some(StateSlot::Field(fmt_var(v)))
        }
        _ => None,
    }
}

pub(crate) fn state_write(op: &POp) -> Option<(StateSlot, &PVar, u32)> {
    match op {
        POp::Store { addr, src, size, .. } => Some((slot_of(addr)?, src, *size)),
        POp::Copy { dst, src, size, .. } => Some((slot_of(dst)?, src, *size)),
        _ => None,
    }
}

pub(crate) fn const_value(v: &PVar) -> Option<i64> {
    match v {
        PVar::Const(c) => Some(*c),
        PVar::Addr(a) => Some(*a as i64),
        _ => None,
    }
}

#[derive(Clone)]
struct DispBlock {
    load: Option<(&'static str, StateSlot)>,
    base_regs: Vec<&'static str>,
    lhs: &'static str,
    value: i64,
    size: u32,
    taken_on_equal: bool,
}

fn parse_dispatch_block(
    ops: &[(u64, &POp)],
    imap: &[DisasmInstruction],
) -> Option<DispBlock> {
    let mut holder: Option<(String, StateSlot, Vec<&'static str>)> = None;
    let mut load: Option<(&'static str, StateSlot)> = None;
    let mut base_regs: Vec<&'static str> = Vec::new();
    let mut cmp: Option<(&'static str, i64, u32)> = None;
    let mut taken_on_equal: Option<bool> = None;
    for &(addr, op) in ops {
        match op {
            POp::Load {
                dst,
                addr: src_addr,
                ..
            } if cmp.is_none() => {
                let slot = slot_of(src_addr)?;
                let regs = reads_regs(op)
                    .into_iter()
                    .map(|x| canonical_reg(x))
                    .collect();
                holder = Some((fmt_var(dst), slot, regs));
            }
            POp::Copy { dst, src, .. } if cmp.is_none() => {
                if !matches!(dst, PVar::Reg(_) | PVar::Tmp(_)) {
                    return None;
                }
                let src_key = fmt_var(src);
                if let Some(h) = &holder
                    && h.0 == src_key
                {
                    holder = Some((fmt_var(dst), h.1.clone(), h.2.clone()));
                } else {
                    let slot = slot_of(src)?;
                    holder = Some((fmt_var(dst), slot, Vec::new()));
                }
            }
            POp::Cmp {
                a: a @ PVar::Reg(r),
                b,
                size,
            } if cmp.is_none() => {
                if let Some(h) = &holder {
                    if h.0 != fmt_var(a) {
                        return None;
                    }
                    load = Some((canonical_reg(r), h.1.clone()));
                    base_regs = h.2.clone();
                }
                let k = const_value(b)?;
                cmp = Some((canonical_reg(r), k, *size));
            }
            POp::CBranch { .. } => {
                taken_on_equal = Some(match imap_get(imap, addr).map(|d| d.mnemonic)? {
                    "je" | "jz" => true,
                    "jne" | "jnz" => false,
                    _ => return None,
                });
            }
            POp::Branch { .. } => {}
            _ => return None,
        }
    }
    let (lhs, value, size) = cmp?;
    Some(DispBlock {
        load,
        base_regs,
        lhs,
        value: norm(value, size),
        size,
        taken_on_equal: taken_on_equal?,
    })
}

struct Dispatch {
    start: usize,
    checks: Vec<usize>,
    slot: StateSlot,
    base_regs: Vec<&'static str>,
    reg: &'static str,
    size: u32,
    cases: Vec<(i64, usize)>,
}

fn parse_chain(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    imap: &[DisasmInstruction],
    start: usize,
) -> Option<Dispatch> {
    let n = cfg.blocks.len();
    let first = parse_dispatch_block(bops.get(start)?, imap)?;
    let (reg, slot) = first.load.clone()?;
    if reg != first.lhs {
        return None;
    }
    let base_regs = first.base_regs.clone();
    let size = first.size;
    let mut checks: Vec<usize> = Vec::new();
    let mut cases: Vec<(i64, usize)> = Vec::new();
    let mut cur = start;
    let mut d = first;
    loop {
        let blk = &cfg.blocks[cur];
        if blk.successors.len() != 2 {
            break;
        }
        let (Some(t), Some(f)) = (
            blk.successors
                .iter()
                .find(|e| e.kind == EdgeKind::BranchTrue),
            blk.successors
                .iter()
                .find(|e| e.kind == EdgeKind::BranchFalse),
        ) else {
            break;
        };
        let (case, next) = if d.taken_on_equal {
            (t.target, f.target)
        } else {
            (f.target, t.target)
        };
        if case >= n
            || next >= n
            || case == next
            || case == start
            || checks.contains(&case)
            || cases.iter().any(|&(v, _)| v == d.value)
        {
            break;
        }
        cases.push((d.value, case));
        checks.push(cur);
        if checks.contains(&next) || next == start || cfg.blocks[next].predecessors.len() != 1 {
            break;
        }
        match parse_dispatch_block(&bops[next], imap) {
            Some(follow) if follow.load.is_none() && follow.lhs == reg && follow.size == size => {
                cur = next;
                d = follow;
            }
            _ => break,
        }
    }
    if cases.len() < 2 {
        return None;
    }
    Some(Dispatch {
        start,
        checks,
        slot,
        base_regs,
        reg,
        size,
        cases,
    })
}

fn scc_of(cfg: &CFG, start: usize) -> HashSet<usize> {
    let n = cfg.blocks.len();
    let mut fwd: HashSet<usize> = HashSet::default();
    let mut st = vec![start];
    while let Some(b) = st.pop() {
        if b >= n || !fwd.insert(b) {
            continue;
        }
        st.extend(cfg.blocks[b].successors.iter().map(|e| e.target));
    }
    let mut bwd: HashSet<usize> = HashSet::default();
    st = vec![start];
    while let Some(b) = st.pop() {
        if b >= n || !bwd.insert(b) {
            continue;
        }
        st.extend(cfg.blocks[b].predecessors.iter().copied());
    }
    fwd.intersection(&bwd).copied().collect()
}

fn last_state_const(ops: &[(u64, &POp)], slot: &StateSlot, size: u32) -> Option<i64> {
    let is_field = matches!(slot, StateSlot::Field(_));
    let mut state: Option<i64> = None;
    for &(_, op) in ops {
        if is_field
            && matches!(
                op,
                POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. }
            )
        {
            state = None;
            continue;
        }
        if let Some((s, src, sz)) = state_write(op)
            && s == *slot
        {
            state = match const_value(src) {
                Some(k) if sz == size => Some(norm(k, size)),
                _ => None,
            };
        }
    }
    state
}

fn field_base_is_stable(
    base_regs: &[&'static str],
    scc: &HashSet<usize>,
    bops: &[Vec<(u64, &POp)>],
) -> bool {
    let clobbered_by_call = base_regs.iter().any(|r| CALL_CLOBBERED.contains(r));
    for &b in scc {
        let Some(ops) = bops.get(b) else {
            return false;
        };
        for &(_, op) in ops {
            if let Some(w) = written_reg(op)
                && base_regs.contains(&canonical_reg(w))
            {
                return false;
            }
            if clobbered_by_call
                && matches!(
                    op,
                    POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. }
                )
            {
                return false;
            }
        }
    }
    true
}

fn reg_live_after(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    block: usize,
    reg: &'static str,
) -> bool {
    const LIMIT: usize = 96;
    let n = cfg.blocks.len();
    let mut seen: HashSet<usize> = HashSet::default();
    let mut stack: Vec<usize> = cfg.blocks[block]
        .successors
        .iter()
        .map(|e| e.target)
        .collect();
    while let Some(b) = stack.pop() {
        if b >= n || b >= bops.len() || !seen.insert(b) {
            continue;
        }
        if seen.len() > LIMIT {
            return true;
        }
        let mut killed = false;
        for &(_, op) in &bops[b] {
            if reads_regs(op).into_iter().any(|r| canonical_reg(r) == reg) {
                return true;
            }
            if written_reg(op).map(canonical_reg) == Some(reg) {
                killed = true;
                break;
            }
        }
        if !killed {
            stack.extend(cfg.blocks[b].successors.iter().map(|e| e.target));
        }
    }
    false
}

pub(crate) fn unthread(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    imap: &[DisasmInstruction],
) -> Option<CFG> {
    let n = cfg.blocks.len();
    if n < 4 || bops.len() < n {
        return None;
    }
    let mut redirects: Vec<(usize, usize, usize)> = Vec::new();
    let mut claimed: HashSet<usize> = HashSet::default();
    for start in 0..n {
        if cfg.blocks[start].successors.len() != 2 {
            continue;
        }
        let Some(d) = parse_chain(cfg, bops, imap, start) else {
            continue;
        };
        let scc = scc_of(cfg, start);
        if scc.len() < 3 {
            continue;
        }
        if matches!(d.slot, StateSlot::Field(_)) && !field_base_is_stable(&d.base_regs, &scc, bops)
        {
            continue;
        }
        let mut members: Vec<usize> = scc.iter().copied().collect();
        members.sort_unstable();
        for from in members {
            if from == d.start || d.checks.contains(&from) || claimed.contains(&from) {
                continue;
            }
            let [edge] = cfg.blocks[from].successors.as_slice() else {
                continue;
            };
            let target = edge.target;
            if target == d.start || target >= n {
                continue;
            }
            let wanted: Vec<i64> = d.cases
                .iter()
                .filter(|&&(_, t)| t == target)
                .map(|&(v, _)| v)
                .collect();
            if wanted.is_empty() {
                continue;
            }
            let Some(k) = last_state_const(&bops[from], &d.slot, d.size) else {
                continue;
            };
            if !wanted.contains(&k) || reg_live_after(cfg, bops, from, d.reg) {
                continue;
            }
            redirects.push((from, target, d.start));
            claimed.insert(from);
        }
    }
    if redirects.is_empty() {
        return None;
    }
    if std::env::var_os("RDDB_DEBUG_SM").is_some() {
        eprintln!(
            "[sm] unthread: {} edge(s) redirected to dispatcher",
            redirects.len()
        );
    }
    let mut out = cfg.clone();
    for &(from, old, header) in &redirects {
        out.blocks[from].successors[0].target = header;
        if let Some(pos) = out.blocks[old]
            .predecessors
            .iter()
            .position(|&p| p == from)
        {
            out.blocks[old].predecessors.remove(pos);
        }
        if !out.blocks[header].predecessors.contains(&from) {
            out.blocks[header].predecessors.push(from);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
    use crate::analysis::decompiler::pcode::StackBase;
    use crate::disasm::operand_enum::OperandList;
    use crate::disasm::{DisasmInstruction, InsnBytes};

    #[test]
    fn bypass_edge_is_redirected_to_the_dispatcher() {
        let spec: Vec<Vec<(usize, EdgeKind)>> = vec![
            vec![(2, EdgeKind::BranchTrue), (1, EdgeKind::BranchFalse)],
            vec![(3, EdgeKind::BranchTrue), (4, EdgeKind::BranchFalse)],
            vec![(3, EdgeKind::Jump)],
            vec![(0, EdgeKind::Jump)],
            vec![],
        ];
        let mut blocks: Vec<BasicBlock> = spec
            .into_iter()
            .enumerate()
            .map(|(id, succ)| BasicBlock {
                id,
                start: 0x1000 + id as u64 * 0x10,
                end: 0x1010 + id as u64 * 0x10,
                instr_indices: id..id + 1,
                successors: succ
                    .into_iter()
                    .map(|(target, kind)| Edge { target, kind })
                    .collect(),
                predecessors: vec![],
            })
            .collect();
        for s in 0..blocks.len() {
            for e in blocks[s].successors.clone() {
                blocks[e.target].predecessors.push(s);
            }
        }
        let cfg = CFG {
            func_entry: 0x1000,
            blocks,
            block_at: Default::default(),
        };
        let slot = PVar::StackSlot {
            base: StackBase::Rbp,
            off: -8,
        };
        let load = POp::Load {
            dst: PVar::Reg("rax"),
            addr: slot.clone(),
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
        let br1 = POp::CBranch {
            target: 0x1020,
            cond: "je".into(),
        };
        let br2 = POp::CBranch {
            target: 0x1030,
            cond: "je".into(),
        };
        let st2 = POp::Store {
            addr: slot.clone(),
            src: PVar::Const(2),
            size: 8,
        };
        let st1 = POp::Store {
            addr: slot.clone(),
            src: PVar::Const(1),
            size: 8,
        };
        let j3 = POp::Branch { target: 0x1030 };
        let j0 = POp::Branch { target: 0x1000 };
        let ret = POp::Return;
        let bops: Vec<Vec<(u64, &POp)>> = vec![
            vec![(0x1000, &load), (0x1001, &cmp1), (0x1002, &br1)],
            vec![(0x1010, &cmp2), (0x1012, &br2)],
            vec![(0x1020, &st2), (0x1022, &j3)],
            vec![(0x1030, &st1), (0x1032, &j0)],
            vec![(0x1040, &ret)],
        ];
        let insn = |address: u64, mnemonic: &'static str| DisasmInstruction {
            address,
            bytes: InsnBytes::from_slice(&[0x90]),
            mnemonic,
            operands: OperandList::Text("0x0".into()),
        };
        let imap = vec![insn(0x1002, "je"), insn(0x1012, "je")];
        let out = unthread(&cfg, &bops, &imap).expect("bypass edge expected");
        assert_eq!(out.blocks[2].successors[0].target, 0);
        assert_eq!(out.blocks[3].predecessors, vec![1]);
        assert!(out.blocks[0].predecessors.contains(&2));
    }
}
