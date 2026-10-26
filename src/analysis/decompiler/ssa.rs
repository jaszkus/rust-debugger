use super::pcode::{reg_size, POp, PVar, StackBase};
use crate::analysis::flow::cfg::CFG;
use crate::analysis::operands::canonical_reg;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

pub(crate) const MAX_SSA_VARS: usize = 65_536;
pub(crate) const MAX_SSA_PHIS: usize = 32_768;

pub(crate) const ALL_REGS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
    "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
];

pub(crate) const CALL_DEFS: &[&str] = &[
    "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "xmm0", "xmm1", "xmm2", "xmm3",
    "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14",
    "xmm15",
];

pub(crate) const CALL_USES: &[&str] = &[
    "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "xmm0", "xmm1", "xmm2", "xmm3",
    "xmm4", "xmm5", "xmm6", "xmm7",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum BaseVar {
    Reg(&'static str),
    Stack(u8, i64),
    Tmp(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct VarId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DefSite {
    pub block: usize,
    pub index: usize,
    pub phi: bool,
    pub input: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct SsaVar {
    pub base: BaseVar,
    #[allow(dead_code)]
    pub version: u32,
    pub def: DefSite,
    pub size: u32,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SsaStmt {
    pub defs: Vec<VarId>,
    pub uses: Vec<VarId>,
}

#[derive(Clone, Debug)]
pub(crate) struct Phi {
    pub def: VarId,
    pub base: BaseVar,
    pub operands: Vec<Option<VarId>>,
    pub size: u32,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SsaBlock {
    pub phis: Vec<Phi>,
    pub stmts: Vec<SsaStmt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoopVarKind {
    State,
    Induction,
    Accumulator,
    Pointer,
    PhiCopy,
}

#[derive(Clone, Debug)]
pub(crate) struct DispatchInfo {
    pub block: usize,
    pub values: Vec<i64>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct LoopStateVar {
    pub header: usize,
    pub base: BaseVar,
    pub kind: LoopVarKind,
    pub dispatch: Option<DispatchInfo>,
    pub const_writes: Vec<i64>,
}

#[derive(Clone, Debug)]
pub(crate) struct SsaLoop {
    #[allow(dead_code)]
    pub header: usize,
    #[allow(dead_code)]
    pub back_edges: Vec<(usize, usize)>,
    pub blocks: Vec<usize>,
}

pub(crate) struct SsaFunction {
    pub blocks: Vec<SsaBlock>,
    pub vars: Vec<SsaVar>,
    pub idom: Vec<usize>,
    pub reachable: Vec<bool>,
    #[allow(dead_code)]
    pub rpo_index: Vec<usize>,
    pub loops: Vec<SsaLoop>,
    pub state_vars: Vec<LoopStateVar>,
    pub dispatch_sites: Vec<DispatchInfo>,
    pub entry: usize,
}

fn base_of(v: &PVar) -> Option<BaseVar> {
    match v {
        PVar::Reg(r) => Some(BaseVar::Reg(canonical_reg(r))),
        PVar::StackSlot { base, off } => Some(BaseVar::Stack(stack_base_id(base), *off)),
        PVar::Tmp(i) => Some(BaseVar::Tmp(*i)),
        _ => None,
    }
}

fn stack_base_id(base: &StackBase) -> u8 {
    match base {
        StackBase::Rbp => 0,
        StackBase::Rsp => 1,
    }
}

fn visit(var: &PVar, f: &mut impl FnMut(&PVar)) {
    f(var);
    match var {
        PVar::Mem(inner, _) => visit(inner, f),
        PVar::Scaled { base, index, .. } => {
            visit(base, f);
            visit(index, f);
        }
        _ => {}
    }
}


pub(crate) fn for_each_read(op: &POp, f: &mut impl FnMut(&PVar)) {
    match op {
        POp::Copy { src, .. } => visit(src, f),
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
        | POp::IntSar { a, b, .. }
        | POp::Cmp { a, b, .. }
        | POp::Test { a, b, .. }
        | POp::FloatCmp { a, b, .. }
        | POp::BitTest { a, b, .. } => {
            visit(a, f);
            visit(b, f);
        }
        POp::Zext { src, .. } | POp::Sext { src, .. } => visit(src, f),
        POp::Load { addr, .. } => visit(addr, f),
        POp::Store { addr, src, .. } => {
            visit(addr, f);
            visit(src, f);
        }
        POp::BranchInd { target } => visit(target, f),
        POp::CallInd { target } => {
            visit(target, f);
            for r in CALL_USES {
                f(&PVar::Reg(r));
            }
        }
        POp::Call { .. } => {
            for r in CALL_USES {
                f(&PVar::Reg(r));
            }
        }
        POp::CallOther { .. } => {
            for r in CALL_USES {
                f(&PVar::Reg(r));
            }
        }
        POp::Return | POp::ReturnPop { .. } => {
            f(&PVar::Reg("rax"));
            f(&PVar::Reg("xmm0"));
        }
        POp::Push { src, .. } => visit(src, f),
        POp::AddrOf { base, index, .. } => {
            if let Some(b) = base {
                visit(b, f);
            }
            if let Some(i) = index {
                visit(i, f);
            }
        }
        POp::SetCC { .. } => {}
        POp::CondCopy { src, .. } => visit(src, f),
        POp::BitModify { dst, bit, .. } => {
            visit(dst, f);
            visit(bit, f);
        }
        POp::Cmpxchg { addr, src, .. } => {
            visit(addr, f);
            visit(src, f);
            f(&PVar::Reg("rax"));
        }
        POp::Opaque(_) | POp::Unimplemented(_) => {
            for r in ALL_REGS {
                f(&PVar::Reg(r));
            }
        }
        POp::FloatBinop { a, b, .. } => {
            visit(a, f);
            visit(b, f);
        }
        POp::Cvt { src, .. } => visit(src, f),
        POp::SegmentOp { addr, .. } => visit(addr, f),
        POp::Rotate { a, b, .. } => {
            visit(a, f);
            visit(b, f);
        }
        POp::Bswap { src, .. } => visit(src, f),
        POp::Branch { .. } | POp::CBranch { .. } | POp::Pop { .. } | POp::Nop | POp::LeaAddr { .. } => {}
    }
}

pub(crate) fn for_each_write(op: &POp, f: &mut impl FnMut(&PVar)) {
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
        | POp::Pop { dst, .. }
        | POp::LeaAddr { dst, .. }
        | POp::AddrOf { dst, .. }
        | POp::SetCC { dst, .. }
        | POp::CondCopy { dst, .. }
        | POp::BitModify { dst, .. }
        | POp::FloatBinop { dst, .. }
        | POp::Cvt { dst, .. }
        | POp::Rotate { dst, .. }
        | POp::Bswap { dst, .. } => visit(dst, f),
        POp::Cmpxchg { .. } => f(&PVar::Reg("rax")),
        POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. } => {
            for r in CALL_DEFS {
                f(&PVar::Reg(r));
            }
        }
        POp::Opaque(_) | POp::Unimplemented(_) => {
            for r in ALL_REGS {
                f(&PVar::Reg(r));
            }
        }
        POp::SegmentOp { dst, is_store, .. } => {
            if !*is_store {
                visit(dst, f);
            }
        }
        POp::Push { .. } => f(&PVar::Reg("rsp")),
        POp::Store { .. } | POp::Branch { .. } | POp::CBranch { .. } | POp::Return
        | POp::ReturnPop { .. } | POp::Nop | POp::Cmp { .. } | POp::Test { .. }
        | POp::FloatCmp { .. } | POp::BitTest { .. } | POp::BranchInd { .. } => {}
    }
}

pub(crate) fn op_is_pure(op: &POp) -> bool {
    matches!(
        op,
        POp::Copy { dst, .. } if !matches!(dst, PVar::StackSlot { .. } | PVar::Mem(..) | PVar::Scaled { .. })
    ) || matches!(
        op,
        POp::IntAdd { .. }
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
            | POp::LeaAddr { .. }
            | POp::AddrOf { .. }
            | POp::SetCC { .. }
            | POp::CondCopy { .. }
            | POp::BitTest { .. }
            | POp::BitModify { .. }
            | POp::Cmp { .. }
            | POp::Test { .. }
            | POp::FloatCmp { .. }
            | POp::FloatBinop { .. }
            | POp::Cvt { .. }
            | POp::Rotate { .. }
            | POp::Bswap { .. }
            | POp::Nop
    )
}

pub(crate) fn op_sets_flags(op: &POp) -> bool {
    matches!(
        op,
        POp::IntAdd { .. }
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
            | POp::Cmp { .. }
            | POp::Test { .. }
            | POp::FloatCmp { .. }
            | POp::BitTest { .. }
            | POp::BitModify { .. }
            | POp::Cmpxchg { .. }
            | POp::Rotate { .. }
    )
}
fn write_size(op: &POp) -> u32 {
    match op {
        POp::Copy { size, .. }
        | POp::IntAdd { size, .. }
        | POp::IntSub { size, .. }
        | POp::IntMul { size, .. }
        | POp::IntDiv { size, .. }
        | POp::IntSDiv { size, .. }
        | POp::IntAnd { size, .. }
        | POp::IntOr { size, .. }
        | POp::IntXor { size, .. }
        | POp::IntLeft { size, .. }
        | POp::IntShr { size, .. }
        | POp::IntSar { size, .. }
        | POp::Load { size, .. }
        | POp::Pop { size, .. }
        | POp::SetCC { size, .. }
        | POp::CondCopy { size, .. }
        | POp::BitModify { size, .. }
        | POp::FloatBinop { size, .. }
        | POp::Rotate { size, .. }
        | POp::Bswap { size, .. }
        | POp::Store { size, .. }
        | POp::Push { size, .. }
        | POp::Cmp { size, .. }
        | POp::Test { size, .. }
        | POp::FloatCmp { size, .. }
        | POp::BitTest { size, .. }
        | POp::SegmentOp { size, .. } => *size,
        POp::Zext { to_size, .. } | POp::Sext { to_size, .. } => *to_size,
        POp::LeaAddr { .. } | POp::AddrOf { .. } | POp::Cmpxchg { .. } => 8,
        POp::Cvt {
            dst: PVar::Reg(r),
            ..
        } => reg_size(r),
        POp::Cvt { .. } => 8,
        _ => 8,
    }
}

fn read_bases(op: &POp) -> Vec<BaseVar> {
    let mut out = Vec::new();
    for_each_read(op, &mut |v| {
        if let Some(b) = base_of(v)
            && !out.contains(&b)
        {
            out.push(b);
        }
    });
    out
}

fn write_bases(op: &POp) -> Vec<BaseVar> {
    let mut out = Vec::new();
    for_each_write(op, &mut |v| {
        if let Some(b) = base_of(v)
            && !out.contains(&b)
        {
            out.push(b);
        }
    });
    out
}

fn dfs_order(cfg: &CFG, entry: usize) -> (Vec<usize>, Vec<bool>, Vec<usize>) {
    let n = cfg.blocks.len();
    let mut seen = vec![false; n];
    let mut post = Vec::new();
    let mut stack = vec![(entry, 0usize)];
    if entry < n {
        seen[entry] = true;
    }
    while let Some((b, i)) = stack.pop() {
        let succs = &cfg.blocks[b].successors;
        if i < succs.len() {
            stack.push((b, i + 1));
            let s = succs[i].target;
            if s < n && !seen[s] {
                seen[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(b);
        }
    }
    let mut rpo: Vec<usize> = post.into_iter().rev().collect();
    let mut rpo_index = vec![usize::MAX; n];
    for (i, &b) in rpo.iter().enumerate() {
        rpo_index[b] = i;
    }
    if rpo.is_empty() {
        rpo.push(entry.min(n.saturating_sub(1)));
    }
    (rpo, seen, rpo_index)
}

fn intersect(a: usize, b: usize, idom: &[usize], rpo_index: &[usize]) -> usize {
    let mut a = a;
    let mut b = b;
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

fn compute_idoms(cfg: &CFG, entry: usize, rpo: &[usize], rpo_index: &[usize]) -> Vec<usize> {
    let n = cfg.blocks.len();
    let mut idom = vec![usize::MAX; n];
    if entry >= n || rpo.is_empty() {
        return idom;
    }
    idom[entry] = entry;
    for _ in 0..(n.max(1) * 4 + 16) {
        let mut changed = false;
        for &b in &rpo[1..] {
            let mut new = usize::MAX;
            for pred in &cfg.blocks[b].predecessors {
                let p = *pred;
                if p >= n || idom[p] == usize::MAX {
                    continue;
                }
                new = if new == usize::MAX {
                    p
                } else {
                    intersect(new, p, &idom, rpo_index)
                };
            }
            if new != usize::MAX && idom[b] != new {
                idom[b] = new;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    idom
}

fn compute_df(cfg: &CFG, idom: &[usize], reachable: &[bool]) -> Vec<Vec<usize>> {
    let n = cfg.blocks.len();
    let mut df: Vec<Vec<usize>> = vec![Vec::new(); n];
    for b in 0..n {
        if !reachable[b] || cfg.blocks[b].predecessors.len() < 2 {
            continue;
        }
        let stop = idom[b];
        for &p in &cfg.blocks[b].predecessors {
            if p >= n || !reachable[p] {
                continue;
            }
            let mut runner = p;
            let mut steps = 0usize;
            while runner != stop && runner < n && steps <= n {
                steps += 1;
                if !df[runner].contains(&b) {
                    df[runner].push(b);
                }
                let next = idom[runner];
                if next == usize::MAX || next == runner {
                    break;
                }
                runner = next;
            }
        }
    }
    df
}

#[derive(Clone, Debug)]
pub(crate) struct TempName {
    pub name: String,
    pub size: u32,
    pub float: bool,
    pub signed: bool,
}

fn temp_op_kind(op: &POp) -> (bool, bool) {
    match op {
        POp::FloatBinop { .. } | POp::FloatCmp { .. } => (true, false),
        POp::Cvt { kind, .. } => {
            if kind == "f2i" {
                (false, true)
            } else {
                (true, false)
            }
        }
        POp::Sext { .. } | POp::IntSar { .. } | POp::IntSDiv { .. } => (false, true),
        _ => (false, false),
    }
}

impl SsaFunction {
    pub(crate) fn temp_name_plan(
        &self,
        bops: &[Vec<(u64, &POp)>],
        existing: &HashSet<String>,
    ) -> HashMap<u32, TempName> {
        struct Info {
            first: (usize, usize),
            size: u32,
            float: bool,
            signed: bool,
        }
        let mut info: HashMap<u32, Info> = HashMap::default();
        let note = |base: BaseVar, pos: (usize, usize), size: u32, op: &POp,
                        info: &mut HashMap<u32, Info>| {
            let BaseVar::Tmp(id) = base else {
                return;
            };
            let (float, signed) = temp_op_kind(op);
            info.entry(id)
                .and_modify(|i| {
                    if pos < i.first {
                        i.first = pos;
                    }
                    i.size = i.size.max(size);
                    i.float |= float;
                    i.signed |= signed;
                })
                .or_insert(Info {
                    first: pos,
                    size,
                    float,
                    signed,
                });
        };
        for (b, block) in self.blocks.iter().enumerate() {
            let Some(ops) = bops.get(b) else {
                continue;
            };
            for (i, stmt) in block.stmts.iter().enumerate() {
                let Some((_, op)) = ops.get(i) else {
                    continue;
                };
                for d in &stmt.defs {
                    let v = &self.vars[d.0 as usize];
                    note(v.base, (b, i), v.size, op, &mut info);
                }
                for u in &stmt.uses {
                    let v = &self.vars[u.0 as usize];
                    note(v.base, (b, i), v.size, op, &mut info);
                }
            }
        }
        let mut entries: Vec<(u32, Info)> = info.into_iter().collect();
        entries.sort_by_key(|(id, i)| (i.first, *id));
        let mut counters: HashMap<&'static str, u32> = HashMap::default();
        let mut used: HashSet<String> = existing.clone();
        let mut out: HashMap<u32, TempName> = HashMap::default();
        for (id, info) in entries {
            let prefix = if info.float && !info.signed {
                "fVar"
            } else if info.signed {
                "iVar"
            } else {
                "uVar"
            };
            let counter = counters.entry(prefix).or_insert(0);
            let name = loop {
                *counter += 1;
                let candidate = format!("{prefix}{counter}");
                if !used.contains(&candidate) {
                    break candidate;
                }
            };
            used.insert(name.clone());
            out.insert(
                id,
                TempName {
                    name,
                    size: info.size.clamp(1, 16),
                    float: info.float && !info.signed,
                    signed: info.signed,
                },
            );
        }
        out
    }
}
impl SsaFunction {
    pub(crate) fn build(cfg: &CFG, bops: &[Vec<(u64, &POp)>]) -> Option<SsaFunction> {
        let n = cfg.blocks.len();
        if n == 0 || bops.len() < n {
            if std::env::var_os("RD_DEBUG_SSA").is_some() {
                eprintln!("[ssa] block/ops mismatch: {} {}", n, bops.len());
            }
            return None;
        }
        let entry = cfg
            .blocks
            .iter()
            .position(|b| b.start == cfg.func_entry)
            .unwrap_or(0);
        let (rpo, reachable, rpo_index) = dfs_order(cfg, entry);
        let idom = compute_idoms(cfg, entry, &rpo, &rpo_index);
        let df = compute_df(cfg, &idom, &reachable);

        let mut def_blocks: HashMap<BaseVar, Vec<usize>> = HashMap::default();
        let mut sizes: HashMap<BaseVar, u32> = HashMap::default();
        for &b in &rpo {
            if b >= bops.len() {
                continue;
            }
            for (_, op) in &bops[b] {
                for base in write_bases(op) {
                    let list = def_blocks.entry(base).or_default();
                    if list.last() != Some(&b) {
                        list.push(b);
                    }
                    let size = write_size(op).clamp(1, 16);
                    sizes
                        .entry(base)
                        .and_modify(|s| *s = (*s).max(size))
                        .or_insert(size);
                }
            }
        }
        if def_blocks.len() > MAX_SSA_VARS {
            if std::env::var_os("RD_DEBUG_SSA").is_some() {
                eprintln!("[ssa] too many vars: {}", def_blocks.len());
            }
            return None;
        }
        let mut bases: Vec<BaseVar> = def_blocks.keys().copied().collect();
        bases.sort_unstable();

        let mut blocks: Vec<SsaBlock> = (0..n).map(|_| SsaBlock::default()).collect();
        let mut phi_index: Vec<HashMap<BaseVar, usize>> = vec![HashMap::default(); n];
        let mut phi_total = 0usize;
        for base in bases {
            let mut work: Vec<usize> = def_blocks.get(&base).cloned().unwrap_or_default();
            let mut has: HashSet<usize> = work.iter().copied().collect();
            let mut i = 0usize;
            while i < work.len() {
                let b = work[i];
                i += 1;
                if b >= n {
                    continue;
                }
                for &f in &df[b] {
                    if !has.insert(f) {
                        continue;
                    }
                    let idx = blocks[f].phis.len();
                    phi_total += 1;
                    if phi_total > MAX_SSA_PHIS {
                        if std::env::var_os("RD_DEBUG_SSA").is_some() {
                            eprintln!("[ssa] too many phis: {phi_total}");
                        }
                        return None;
                    }
                    let preds = cfg.blocks[f].predecessors.len();
                    blocks[f].phis.push(Phi {
                        def: VarId(u32::MAX),
                        base,
                        operands: vec![None; preds],
                        size: sizes.get(&base).copied().unwrap_or(8),
                    });
                    phi_index[f].insert(base, idx);
                    work.push(f);
                }
            }
        }

        let mut vars: Vec<SsaVar> = Vec::new();
        let mut stacks: HashMap<BaseVar, Vec<VarId>> = HashMap::default();
        let mut inputs: HashMap<BaseVar, VarId> = HashMap::default();
        let mut next_version: HashMap<BaseVar, u32> = HashMap::default();

        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &b in &rpo {
            if b != entry && idom[b] != usize::MAX && idom[b] != b {
                children[idom[b]].push(b);
            }
        }
        for list in children.iter_mut() {
            list.sort_unstable();
        }

        struct Frame {
            block: usize,
            next_child: usize,
            entered: bool,
            pushed: Vec<BaseVar>,
        }

        let mut frames = vec![Frame {
            block: entry,
            next_child: 0,
            entered: false,
            pushed: Vec::new(),
        }];

        let mut fresh = |base: BaseVar, def: DefSite, vars: &mut Vec<SsaVar>| -> VarId {
            let v = next_version.entry(base).or_insert(0);
            let id = VarId(vars.len() as u32);
            vars.push(SsaVar {
                base,
                version: *v,
                def,
                size: sizes.get(&base).copied().unwrap_or(8),
            });
            *v += 1;
            id
        };

        while let Some(frame) = frames.last_mut() {
            if !frame.entered {
                frame.entered = true;
                let b = frame.block;
                for idx in 0..blocks[b].phis.len() {
                    let base = blocks[b].phis[idx].base;
                    let size = blocks[b].phis[idx].size;
                    let v = fresh(
                        base,
                        DefSite {
                            block: b,
                            index: idx,
                            phi: true,
                            input: false,
                        },
                        &mut vars,
                    );
                    vars[v.0 as usize].size = size;
                    blocks[b].phis[idx].def = v;
                    stacks.entry(base).or_default().push(v);
                    frame.pushed.push(base);
                }
                let op_count = bops[b].len();
                blocks[b].stmts.reserve(op_count);
                for (i, (_, op)) in bops[b].iter().enumerate() {
                    let op = *op;
                    let reads = read_bases(op);
                    let mut uses = Vec::with_capacity(reads.len());
                    for base in reads {
                        let v = if let Some(top) = stacks.get(&base).and_then(|s| s.last()).copied()
                        {
                            top
                        } else if let Some(v) = inputs.get(&base).copied() {
                            v
                        } else {
                            let v = fresh(
                                base,
                                DefSite {
                                    block: entry,
                                    index: 0,
                                    phi: false,
                                    input: true,
                                },
                                &mut vars,
                            );
                            inputs.insert(base, v);
                            v
                        };
                        uses.push(v);
                    }
                    let writes = write_bases(op);
                    let mut defs = Vec::with_capacity(writes.len());
                    for base in writes {
                        let v = fresh(
                            base,
                            DefSite {
                                block: b,
                                index: i,
                                phi: false,
                                input: false,
                            },
                            &mut vars,
                        );
                        stacks.entry(base).or_default().push(v);
                        frame.pushed.push(base);
                        defs.push(v);
                    }
                    blocks[b].stmts.push(SsaStmt { defs, uses });
                }
                for edge in &cfg.blocks[b].successors {
                    let s = edge.target;
                    if s >= n || !reachable[s] {
                        continue;
                    }
                    let Some(pos) = cfg.blocks[s].predecessors.iter().position(|&p| p == b) else {
                        continue;
                    };
                    if let Some(map) = phi_index.get(s) {
                        for (&base, &idx) in map {
                            let v = stacks
                                .get(&base)
                                .and_then(|st| st.last())
                                .copied()
                                .or_else(|| inputs.get(&base).copied());
                            if let Some(v) = v {
                                blocks[s].phis[idx].operands[pos] = Some(v);
                            }
                        }
                    }
                }
            }
            let b = frame.block;
            if frame.next_child < children[b].len() {
                let c = children[b][frame.next_child];
                frame.next_child += 1;
                frames.push(Frame {
                    block: c,
                    next_child: 0,
                    entered: false,
                    pushed: Vec::new(),
                });
                continue;
            }
            let pushed = std::mem::take(&mut frame.pushed);
            for base in pushed.into_iter().rev() {
                if let Some(st) = stacks.get_mut(&base) {
                    st.pop();
                }
            }
            frames.pop();
        }

        let mut ssa = SsaFunction {
            blocks,
            vars,
            idom,
            reachable,
            rpo_index,
            loops: Vec::new(),
            state_vars: Vec::new(),
            dispatch_sites: Vec::new(),
            entry,
        };
        ssa.simplify(cfg);
        ssa.compute_loops(cfg);
        ssa.detect_state_vars(cfg, bops);
        Some(ssa)
    }

    fn resolve_impl(subst: &[u32], mut v: VarId) -> VarId {
        let mut steps = 0usize;
        while (subst[v.0 as usize] as usize) < subst.len()
            && subst[v.0 as usize] != v.0
            && steps < subst.len()
        {
            v = VarId(subst[v.0 as usize]);
            steps += 1;
        }
        v
    }

    fn simplify(&mut self, cfg: &CFG) {
        let count = self.vars.len();
        let mut subst: Vec<u32> = (0..count as u32).collect();
        let mut removed: HashSet<u32> = HashSet::default();

        for _ in 0..8 {
            let mut changed = false;
            for b in 0..self.blocks.len() {
                for p in 0..self.blocks[b].phis.len() {
                    let def = self.blocks[b].phis[p].def;
                    if removed.contains(&def.0) {
                        continue;
                    }
                    let mut same: Option<VarId> = None;
                    let mut has_self = false;
                    let mut unknown = false;
                    let mut distinct = false;
                    for (pos, op) in self.blocks[b].phis[p].operands.iter().enumerate() {
                        match op {
                            None => {
                                let pred = cfg.blocks[b].predecessors[pos];
                                if self.reachable.get(pred).copied().unwrap_or(false) {
                                    unknown = true;
                                }
                            }
                            Some(v) => {
                                let r = Self::resolve_impl(&subst, *v);
                                if r == Self::resolve_impl(&subst, def) {
                                    has_self = true;
                                    continue;
                                }
                                match same {
                                    None => same = Some(r),
                                    Some(s) if s == r => {}
                                    Some(_) => {
                                        distinct = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if unknown || distinct || same.is_none() {
                        continue;
                    }
                    if has_self {
                        continue;
                    }
                    let s = same.unwrap();
                    let dr = Self::resolve_impl(&subst, def);
                    if dr != s {
                        subst[dr.0 as usize] = s.0;
                        changed = true;
                    }
                    removed.insert(def.0);
                }
            }
            if !changed {
                break;
            }
        }

        let mut used = vec![false; self.vars.len()];
        loop {
            used.iter_mut().for_each(|u| *u = false);
            mark_used_versions(&self.blocks, &removed, &subst, &mut used);
            let mut changed = false;
            for b in 0..self.blocks.len() {
                for p in 0..self.blocks[b].phis.len() {
                    let def = self.blocks[b].phis[p].def;
                    if removed.contains(&def.0) {
                        continue;
                    }
                    let dr = Self::resolve_impl(&subst, def);
                    if !used[dr.0 as usize] {
                        removed.insert(def.0);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }

        let mut stmt_defs: HashSet<u32> = HashSet::default();
        for block in &self.blocks {
            for stmt in &block.stmts {
                for d in &stmt.defs {
                    stmt_defs.insert(Self::resolve_impl(&subst, *d).0);
                }
            }
        }
        let mut keep: HashSet<u32> = stmt_defs;
        for block in self.blocks.iter_mut() {
            for stmt in block.stmts.iter_mut() {
                for d in stmt.defs.iter_mut() {
                    *d = Self::resolve_impl(&subst, *d);
                }
                for u in stmt.uses.iter_mut() {
                    *u = Self::resolve_impl(&subst, *u);
                }
            }
            let mut new_phis = Vec::new();
            for phi in block.phis.drain(..) {
                if removed.contains(&phi.def.0) {
                    continue;
                }
                let mut phi = phi;
                phi.def = Self::resolve_impl(&subst, phi.def);
                for v in phi.operands.iter_mut().flatten() {
                    *v = Self::resolve_impl(&subst, *v);
                }
                if !keep.insert(phi.def.0) {
                    continue;
                }
                new_phis.push(phi);
            }
            block.phis = new_phis;
        }
    }
    pub(crate) fn dominates(&self, a: usize, mut b: usize) -> bool {
        if a >= self.idom.len() || b >= self.idom.len() {
            return false;
        }
        let mut steps = 0usize;
        loop {
            if a == b {
                return self.reachable[a];
            }
            let next = self.idom[b];
            if next == usize::MAX || next == b || steps > self.idom.len() {
                return false;
            }
            b = next;
            steps += 1;
        }
    }

    fn compute_loops(&mut self, cfg: &CFG) {
        let n = cfg.blocks.len();
        let mut by_header: HashMap<usize, Vec<(usize, usize)>> = HashMap::default();
        for u in 0..n {
            if !self.reachable[u] {
                continue;
            }
            for edge in &cfg.blocks[u].successors {
                let h = edge.target;
                if h < n && self.reachable[h] && self.dominates(h, u) {
                    by_header.entry(h).or_default().push((u, h));
                }
            }
        }
        let mut headers: Vec<usize> = by_header.keys().copied().collect();
        headers.sort_unstable();
        for h in headers {
            let back = by_header.remove(&h).unwrap_or_default();
            let mut blocks: HashSet<usize> = HashSet::default();
            blocks.insert(h);
            let mut stack: Vec<usize> = back.iter().map(|&(u, _)| u).collect();
            while let Some(b) = stack.pop() {
                if b >= n || !blocks.insert(b) {
                    continue;
                }
                for &p in &cfg.blocks[b].predecessors {
                    if p != h && !blocks.contains(&p) {
                        stack.push(p);
                    }
                }
            }
            let mut list: Vec<usize> = blocks.into_iter().collect();
            list.sort_unstable();
            self.loops.push(SsaLoop {
                header: h,
                back_edges: back,
                blocks: list,
            });
        }
    }

    fn value_origin(op: &POp) -> Option<(BaseVar, &'static str)> {
        match op {
            POp::Copy { dst, src, .. } => {
                let PVar::Reg(r) = dst else {
                    return None;
                };
                let r = canonical_reg(r);
                let base = base_of(src)?;
                Some((base, r))
            }
            POp::Load { dst, addr, .. } => {
                let PVar::Reg(r) = dst else {
                    return None;
                };
                let r = canonical_reg(r);
                let base = base_of(addr).or_else(|| match addr {
                    PVar::Mem(inner, _) => base_of(inner),
                    _ => None,
                })?;
                Some((base, r))
            }
            _ => None,
        }
    }

    fn detect_state_vars(&mut self, cfg: &CFG, bops: &[Vec<(u64, &POp)>]) {
        let mut dispatch_sites: Vec<DispatchInfo> = Vec::new();
        for (b, ops) in bops.iter().enumerate().take(cfg.blocks.len()) {
            let mut origins: HashMap<&'static str, BaseVar> = HashMap::default();
            let mut per_base: HashMap<BaseVar, Vec<i64>> = HashMap::default();
            for (_, op) in ops {
                match op {
                    POp::Cmp { a, b, .. } if matches!(b, PVar::Const(_)) => {
                        let lhs = match a {
                            PVar::Reg(r) => origins
                                .get(canonical_reg(r))
                                .copied()
                                .or_else(|| base_of(a)),
                            other => base_of(other),
                        };
                        let Some(base) = lhs else {
                            origins.clear();
                            continue;
                        };
                        let PVar::Const(k) = b else { continue };
                        let list = per_base.entry(base).or_default();
                        if !list.contains(k) {
                            list.push(*k);
                        }
                    }
                    POp::Call { .. }
                    | POp::CallInd { .. }
                    | POp::CallOther { .. }
                    | POp::Branch { .. }
                    | POp::BranchInd { .. }
                    | POp::Return
                    | POp::ReturnPop { .. } => origins.clear(),
                    _ => {
                        if let Some((base, r)) = Self::value_origin(op) {
                            origins.insert(r, base);
                        } else if let Some(PVar::Reg(r)) = write_reg_of(op) {
                            origins.remove(canonical_reg(r));
                        }
                    }
                }
            }
            let mut best: Option<DispatchInfo> = None;
            for (base, values) in per_base {
                if values.len() < 2 {
                    continue;
                }
                let _ = base;
                if best.as_ref().is_none_or(|d| d.values.len() < values.len()) {
                    best = Some(DispatchInfo {
                        block: b,
                        values,
                    });
                }
            }
            if let Some(d) = best {
                dispatch_sites.push(d);
            }
        }
        dispatch_sites.sort_by_key(|d| d.block);
        self.dispatch_sites = dispatch_sites;

        let mut state_vars = Vec::new();
        for lp in &self.loops {
            let phis: Vec<(BaseVar, Vec<Option<VarId>>)> = self.blocks[lp.header]
                .phis
                .iter()
                .map(|p| (p.base, p.operands.clone()))
                .collect();
            for (base, operands) in phis {
                let mut carried = false;
                for op in operands.iter() {
                    let Some(def) = op else { continue };
                    let dblock = self.vars[def.0 as usize].def.block;
                    if dblock < cfg.blocks.len()
                        && lp.blocks.contains(&dblock)
                        && dblock != lp.header
                    {
                        carried = true;
                        break;
                    }
                }
                if !carried {
                    continue;
                }
                let mut const_writes = Vec::new();
                let mut arith = false;
                let mut loads = false;
                let mut copies = 0usize;
                let mut dispatch: Option<DispatchInfo> = None;
                for &b in &lp.blocks {
                    let Some(ops) = bops.get(b) else { continue };
                    for (_, op) in ops {
                        let writes = write_bases(op);
                        if !writes.contains(&base) {
                            continue;
                        }
                        match op {
                            POp::Copy { src, .. } => match src {
                                PVar::Const(k) => const_writes.push(*k),
                                PVar::Addr(a) => const_writes.push(*a as i64),
                                _ => copies += 1,
                            },
                            POp::IntAdd { a, b, .. } | POp::IntSub { a, b, .. } => {
                                if matches!(a, PVar::Const(_)) || matches!(b, PVar::Const(_)) {
                                    arith = true;
                                } else {
                                    copies += 1;
                                }
                            }
                            POp::IntAnd { .. } | POp::IntOr { .. } | POp::IntXor { .. }
                            | POp::IntLeft { .. } | POp::IntShr { .. } | POp::IntSar { .. } => {
                                arith = true;
                            }
                            POp::Load { .. } => loads = true,
                            _ => {}
                        }
                    }
                    if let Some(d) = self
                        .dispatch_sites
                        .iter()
                        .find(|d| d.block == b && lp.blocks.contains(&b))
                        && dispatch.as_ref().is_none_or(|old| old.values.len() < d.values.len())
                    {
                        dispatch = Some(d.clone());
                    }
                }
                let kind = if dispatch.is_some() {
                    LoopVarKind::State
                } else if arith {
                    LoopVarKind::Induction
                } else if loads {
                    LoopVarKind::Pointer
                } else if copies > 0 {
                    LoopVarKind::PhiCopy
                } else {
                    LoopVarKind::Accumulator
                };
                state_vars.push(LoopStateVar {
                    header: lp.header,
                    base,
                    kind,
                    dispatch,
                    const_writes,
                });
            }
        }
        self.state_vars = state_vars;
    }

    #[allow(dead_code)]
    pub(crate) fn loop_state_var(&self, header: usize) -> Option<&LoopStateVar> {
        self.state_vars.iter().find(|v| v.header == header)
    }

    #[allow(dead_code)]
    pub(crate) fn state_var_for_block(&self, block: usize) -> Option<&DispatchInfo> {
        self.dispatch_sites
            .iter()
            .find(|d| d.block == block)
    }

    #[allow(dead_code)]
    pub(crate) fn input_version(&self, base: BaseVar) -> Option<VarId> {
        self.vars
            .iter()
            .position(|v| v.base == base && v.def.input)
            .map(|i| VarId(i as u32))
    }

    #[allow(dead_code)]
    pub(crate) fn version_at(&self, block: usize, index: usize, base: BaseVar) -> Option<VarId> {
        self.blocks
            .get(block)?
            .stmts
            .get(index)?
            .defs
            .iter()
            .find(|v| self.vars[v.0 as usize].base == base)
            .copied()
    }

    pub(crate) fn validate(&self, cfg: &CFG) -> Result<(), String> {
        let mut defs: Vec<Option<DefSite>> = vec![None; self.vars.len()];
        for (i, v) in self.vars.iter().enumerate() {
            if v.def.input {
                if v.def.block != self.entry {
                    return Err(format!("input var {i} not defined at entry"));
                }
                defs[i] = Some(v.def);
            }
        }
        for (b, block) in self.blocks.iter().enumerate() {
            for (p, phi) in block.phis.iter().enumerate() {
                let id = phi.def.0 as usize;
                if defs[id].is_some() {
                    return Err(format!("duplicate phi def {id}"));
                }
                defs[id] = Some(DefSite {
                    block: b,
                    index: p,
                    phi: true,
                    input: false,
                });
                if phi.operands.len() != cfg.blocks[b].predecessors.len() {
                    return Err(format!("phi at {b} has wrong operand count"));
                }
                for (pos, op) in phi.operands.iter().enumerate() {
                    let Some(v) = op else { continue };
                    let pred = cfg.blocks[b].predecessors[pos];
                    let dv = &self.vars[v.0 as usize];
                    if *v == phi.def {
                        continue;
                    }
                    if dv.def.block == pred {
                        continue;
                    }
                    if !self.dominates(dv.def.block, pred) {
                        return Err(format!(
                            "phi operand {v:?} at block {b} does not dominate pred {pred}"
                        ));
                    }
                }
            }
            for (i, stmt) in block.stmts.iter().enumerate() {
                for d in &stmt.defs {
                    let id = d.0 as usize;
                    if defs[id].is_some() {
                        return Err(format!("duplicate stmt def {id}"));
                    }
                    defs[id] = Some(DefSite {
                        block: b,
                        index: i,
                        phi: false,
                        input: false,
                    });
                }
                for u in &stmt.uses {
                    let dv = &self.vars[u.0 as usize];
                    if dv.def.input {
                        continue;
                    }
                    let db = dv.def.block;
                    if db == b {
                        continue;
                    }
                    if !self.dominates(db, b) {
                        return Err(format!("use {u:?} not dominated by def block {db}"));
                    }
                }
            }
        }
        let mut referenced = vec![false; self.vars.len()];
        for block in &self.blocks {
            for stmt in &block.stmts {
                for v in stmt.uses.iter().chain(stmt.defs.iter()) {
                    referenced[v.0 as usize] = true;
                }
            }
            for phi in &block.phis {
                referenced[phi.def.0 as usize] = true;
                for op in phi.operands.iter().flatten() {
                    referenced[op.0 as usize] = true;
                }
            }
        }
        if let Some(missing) = (0..self.vars.len()).find(|&i| referenced[i] && defs[i].is_none()) {
            return Err(format!("var {missing} has no def site"));
        }
        Ok(())
    }

    pub(crate) fn dead_stmts(
        &self,
        cfg: &CFG,
        bops: &[Vec<(u64, &POp)>],
    ) -> HashSet<(usize, usize)> {
        let n = cfg.blocks.len();
        let mut dead = HashSet::default();
        if n == 0 {
            return dead;
        }
        let mut ids: HashMap<BaseVar, usize> = HashMap::default();
        let mut order: Vec<BaseVar> = Vec::new();
        for block in &self.blocks {
            for stmt in &block.stmts {
                for v in stmt.uses.iter().chain(stmt.defs.iter()) {
                    let base = self.vars[v.0 as usize].base;
                    if let std::collections::hash_map::Entry::Vacant(e) = ids.entry(base) {
                        e.insert(order.len());
                        order.push(base);
                    }
                }
            }
            for phi in &block.phis {
                if let std::collections::hash_map::Entry::Vacant(e) = ids.entry(phi.base) {
                    e.insert(order.len());
                    order.push(phi.base);
                }
            }
        }
        let words = order.len().div_ceil(64).max(1);
        let mut uses = vec![vec![0u64; words]; n];
        let mut defs = vec![vec![0u64; words]; n];
        for b in 0..n {
            for phi in &self.blocks[b].phis {
                if let Some(&id) = ids.get(&phi.base) {
                    defs[b][id / 64] |= 1u64 << (id % 64);
                }
            }
            for stmt in &self.blocks[b].stmts {
                for v in &stmt.uses {
                    let base = self.vars[v.0 as usize].base;
                    if let Some(&id) = ids.get(&base)
                        && !test_bit(&defs[b], id)
                    {
                        uses[b][id / 64] |= 1u64 << (id % 64);
                    }
                }
                for v in &stmt.defs {
                    let base = self.vars[v.0 as usize].base;
                    if let Some(&id) = ids.get(&base) {
                        defs[b][id / 64] |= 1u64 << (id % 64);
                    }
                }
            }
        }
        let mut live_in = vec![vec![0u64; words]; n];
        let mut phi_edge = vec![vec![0u64; words]; n];
        for (b, edge_bits) in phi_edge.iter_mut().enumerate() {
            for edge in &cfg.blocks[b].successors {
                let s = edge.target;
                if s >= n {
                    continue;
                }
                let Some(pos) = cfg.blocks[s].predecessors.iter().position(|&p| p == b) else {
                    continue;
                };
                for phi in &self.blocks[s].phis {
                    let Some(v) = phi.operands.get(pos).copied().flatten() else {
                        continue;
                    };
                    let base = self.vars[v.0 as usize].base;
                    if let Some(&id) = ids.get(&base) {
                        edge_bits[id / 64] |= 1u64 << (id % 64);
                    }
                }
            }
        }
        let mut changed = true;
        let mut rounds = 0usize;
        while changed && rounds < n.max(1) * 8 + 16 {
            changed = false;
            rounds += 1;
            for b in (0..n).rev() {
                if !self.reachable[b] {
                    continue;
                }
                let mut out = phi_edge[b].clone();
                for edge in &cfg.blocks[b].successors {
                    let s = edge.target;
                    if s < n && self.reachable[s] {
                        for (o, l) in out.iter_mut().zip(&live_in[s]) {
                            *o |= *l;
                        }
                    }
                }
                let mut new = vec![0u64; words];
                for w in 0..words {
                    new[w] = uses[b][w] | (out[w] & !defs[b][w]);
                }
                if new != live_in[b] {
                    live_in[b] = new;
                    changed = true;
                }
            }
        }
        for b in 0..n {
            if !self.reachable[b] || b >= bops.len() {
                continue;
            }
            let mut live = phi_edge[b].clone();
            for edge in &cfg.blocks[b].successors {
                let s = edge.target;
                if s < n && self.reachable[s] {
                    for (l, i) in live.iter_mut().zip(&live_in[s]) {
                        *l |= *i;
                    }
                }
            }
            for i in (0..self.blocks[b].stmts.len()).rev() {
                let stmt = &self.blocks[b].stmts[i];
                let op = bops[b][i].1;
                let mut removed = false;
                if stmt.defs.len() == 1 && op_is_pure(op) && !op_sets_flags(op) {
                    let v = stmt.defs[0];
                    let base = self.vars[v.0 as usize].base;
                    if let Some(&id) = ids.get(&base)
                        && !test_bit(&live, id) {
                            dead.insert((b, i));
                            removed = true;
                        }
                }
                if !removed {
                    for v in &stmt.defs {
                        let base = self.vars[v.0 as usize].base;
                        if let Some(&id) = ids.get(&base) {
                            live[id / 64] &= !(1u64 << (id % 64));
                        }
                    }
                }
                for v in &stmt.uses {
                    let base = self.vars[v.0 as usize].base;
                    if let Some(&id) = ids.get(&base) {
                        live[id / 64] |= 1u64 << (id % 64);
                    }
                }
            }
        }
        dead
    }
}

fn mark_used_versions(
    blocks: &[SsaBlock],
    removed: &HashSet<u32>,
    subst: &[u32],
    used: &mut [bool],
) {
    for block in blocks {
        for stmt in &block.stmts {
            for u in &stmt.uses {
                used[SsaFunction::resolve_impl(subst, *u).0 as usize] = true;
            }
        }
    }
    for block in blocks {
        for phi in &block.phis {
            if removed.contains(&phi.def.0) {
                continue;
            }
            for op in phi.operands.iter().flatten() {
                used[SsaFunction::resolve_impl(subst, *op).0 as usize] = true;
            }
        }
    }
}
fn test_bit(bits: &[u64], i: usize) -> bool {
    bits.get(i / 64)
        .is_some_and(|w| w & (1u64 << (i % 64)) != 0)
}

fn write_reg_of(op: &POp) -> Option<&PVar> {
    match op {
        POp::Copy { dst, .. }
        | POp::IntAdd { dst, .. }
        | POp::IntSub { dst, .. }
        | POp::IntMul { dst, .. }
        | POp::IntAnd { dst, .. }
        | POp::IntOr { dst, .. }
        | POp::IntXor { dst, .. }
        | POp::Zext { dst, .. }
        | POp::Sext { dst, .. }
        | POp::Load { dst, .. }
        | POp::LeaAddr { dst, .. }
        | POp::AddrOf { dst, .. }
        | POp::SetCC { dst, .. }
        | POp::CondCopy { dst, .. }
        | POp::Pop { dst, .. } => Some(dst),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::flow::cfg::{BasicBlock, Edge, EdgeKind};
    use crate::analysis::decompiler::pcode::StackBase;

    fn make_cfg(spec: &[&[(usize, EdgeKind)]]) -> CFG {
        let mut blocks: Vec<BasicBlock> = spec
            .iter()
            .enumerate()
            .map(|(id, succ)| BasicBlock {
                id,
                start: 0x1000 + id as u64 * 0x10,
                end: 0x1010 + id as u64 * 0x10,
                instr_indices: id..id + 1,
                successors: succ
                    .iter()
                    .map(|&(target, kind)| Edge { target, kind })
                    .collect(),
                predecessors: Vec::new(),
            })
            .collect();
        for s in 0..blocks.len() {
            for e in blocks[s].successors.clone() {
                blocks[e.target].predecessors.push(s);
            }
        }
        let mut block_at = HashMap::default();
        for b in &blocks {
            block_at.insert(b.start, b.id);
        }
        CFG {
            func_entry: 0x1000,
            blocks,
            block_at,
        }
    }

    fn make_bops(ops: Vec<Vec<POp>>) -> &'static [Vec<(u64, &'static POp)>] {
        let leaked: &'static Vec<Vec<POp>> = Box::leak(Box::new(ops));
        let mut out: Vec<Vec<(u64, &'static POp)>> = Vec::new();
        for (b, block) in leaked.iter().enumerate() {
            let mut row = Vec::new();
            for (i, op) in block.iter().enumerate() {
                row.push((0x1000 + b as u64 * 0x10 + i as u64, op));
            }
            out.push(row);
        }
        Box::leak(Box::new(out))
    }

    fn copy_rax(v: i64) -> POp {
        POp::Copy {
            dst: PVar::Reg("rax"),
            src: PVar::Const(v),
            size: 8,
        }
    }

    #[test]
    fn diamond_inserts_a_phi_and_validates() {
        let cfg = make_cfg(&[
            &[(1, EdgeKind::BranchTrue), (2, EdgeKind::BranchFalse)],
            &[(3, EdgeKind::Jump)],
            &[(3, EdgeKind::Jump)],
            &[],
        ]);
        let bops = make_bops(vec![
            vec![copy_rax(1)],
            vec![copy_rax(2)],
            vec![copy_rax(3)],
            vec![POp::Copy {
                dst: PVar::Reg("rbx"),
                src: PVar::Reg("rax"),
                size: 8,
            }, POp::Store {
                addr: PVar::StackSlot {
                    base: StackBase::Rsp,
                    off: -8,
                },
                src: PVar::Reg("rbx"),
                size: 8,
            }],
        ]);
        let ssa = SsaFunction::build(&cfg, bops).expect("ssa");
        ssa.validate(&cfg).expect("valid ssa");
        assert_eq!(ssa.blocks[3].phis.len(), 1);
        let phi = &ssa.blocks[3].phis[0];
        assert_eq!(phi.base, BaseVar::Reg("rax"));
        assert_eq!(phi.operands.len(), 2);
        assert!(phi.operands.iter().all(|o| o.is_some()));
        assert!(ssa.dominates(0, 3));
        assert!(!ssa.dominates(1, 2));
        assert!(!ssa.dominates(2, 1));
    }

    #[test]
    fn dead_copy_is_elided_but_flag_writes_are_kept() {
        let cfg = make_cfg(&[
            &[(1, EdgeKind::BranchTrue), (1, EdgeKind::BranchFalse)],
            &[],
        ]);
        let bops = make_bops(vec![
            vec![
                POp::Copy {
                    dst: PVar::Reg("rdx"),
                    src: PVar::Const(5),
                    size: 8,
                },
                POp::IntXor {
                    dst: PVar::Reg("r8"),
                    a: PVar::Reg("r8"),
                    b: PVar::Reg("r8"),
                    size: 8,
                },
                POp::CBranch {
                    target: 0x1010,
                    cond: "je".into(),
                },
                POp::Return,
            ],
            vec![POp::Return],
        ]);
        let ssa = SsaFunction::build(&cfg, bops).expect("ssa");
        ssa.validate(&cfg).expect("valid ssa");
        let dead = ssa.dead_stmts(&cfg, bops);
        assert!(dead.contains(&(0, 0)));
        assert!(!dead.contains(&(0, 1)));
    }

    #[test]
    fn loop_state_variable_and_dispatch_are_detected() {
        let cfg = make_cfg(&[
            &[(1, EdgeKind::Jump)],
            &[(2, EdgeKind::BranchTrue), (1, EdgeKind::Fallthrough)],
            &[(1, EdgeKind::Jump)],
            &[(1, EdgeKind::Jump)],
            &[],
        ]);
        let cmp = |v: i64| POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(v),
            size: 8,
        };
        let br = |t: u64| POp::CBranch {
            target: t,
            cond: "je".into(),
        };
        let mut cmp2 = POp::Cmp {
            a: PVar::Reg("rax"),
            b: PVar::Const(2),
            size: 8,
        };
        let bops = make_bops(vec![
            vec![copy_rax(0)],
            vec![
                cmp(1),
                br(0x1020),
                std::mem::replace(&mut cmp2, POp::Nop),
                br(0x1030),
                POp::Branch { target: 0x1040 },
            ],
            vec![copy_rax(2), POp::Branch { target: 0x1010 }],
            vec![copy_rax(1), POp::Branch { target: 0x1010 }],
            vec![POp::Return],
        ]);
        let ssa = SsaFunction::build(&cfg, bops).expect("ssa");
        ssa.validate(&cfg).expect("valid ssa");
        assert!(!ssa.loops.is_empty());
        let state = ssa.loop_state_var(1).expect("state var");
        assert_eq!(state.base, BaseVar::Reg("rax"));
        assert_eq!(state.kind, LoopVarKind::State);
        let dispatch = state.dispatch.as_ref().expect("dispatch");
        assert!(dispatch.values.len() >= 2);
    }

    #[test]
    fn irreducible_cfg_builds_and_validates() {
        let cfg = make_cfg(&[
            &[(1, EdgeKind::BranchTrue), (2, EdgeKind::BranchFalse)],
            &[(2, EdgeKind::Jump), (3, EdgeKind::BranchTrue)],
            &[(1, EdgeKind::Jump)],
            &[],
        ]);
        let bops = make_bops(vec![
            vec![copy_rax(1)],
            vec![POp::IntAdd {
                dst: PVar::Reg("rax"),
                a: PVar::Reg("rax"),
                b: PVar::Const(1),
                size: 8,
            }, POp::CBranch {
                target: 0x1020,
                cond: "jne".into(),
            }],
            vec![POp::Copy {
                dst: PVar::Reg("rax"),
                src: PVar::Reg("rax"),
                size: 8,
            }],
            vec![POp::Return],
        ]);
        let ssa = SsaFunction::build(&cfg, bops).expect("ssa");
        ssa.validate(&cfg).expect("valid ssa");
    }
}
