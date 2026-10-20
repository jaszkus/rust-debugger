
use crate::analysis::decompiler::pcode::{PInstr, POp, PVar, StackBase, CALL_CLOBBERED};
use crate::analysis::flow::cfg::CFG;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

pub const ABI_X64_MS: &[&str] = &["rcx", "rdx", "r8", "r9"];
pub const ABI_X64_SYSV: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
pub const ABI_X64_FLOAT: &[&str] = &["xmm0", "xmm1", "xmm2", "xmm3"];
pub const ABI_X64_SYSV_FLOAT: &[&str] = &["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"];

const MAX_FLOW_PASSES: usize = 64;
const MS_SHADOW_SPACE: i64 = 0x20;
const FILL_PARAM_GAPS: bool = true;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Loc {
    Reg(&'static str),
    Stack { base: u8, off: i64 },
    Tmp(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarKind { Param, Local, Register, SavedReg, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Abi {
    #[default]
    Auto,
    MsX64,
    SysV64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarType {
    Void, Bool, Char, UChar, Short, UShort, Int, UInt, Long, ULong, Float, Double, Pointer, Undefined(u32),
}
impl VarType {
    pub fn c_str(&self) -> &'static str {
        match self {
            VarType::Void => "void",
            VarType::Bool => "bool",
            VarType::Char => "int8_t",
            VarType::UChar => "uint8_t",
            VarType::Short => "int16_t",
            VarType::UShort => "uint16_t",
            VarType::Int => "int32_t",
            VarType::UInt => "uint32_t",
            VarType::Long => "int64_t",
            VarType::ULong => "uint64_t",
            VarType::Float => "float",
            VarType::Double => "double",
            VarType::Pointer => "int64_t *",
            VarType::Undefined(1) => "int8_t",
            VarType::Undefined(2) => "int16_t",
            VarType::Undefined(4) => "int32_t",
            VarType::Undefined(_) => "int64_t",
        }
    }
    pub fn type_prefix(&self) -> &'static str {
        match self {
            VarType::Bool | VarType::UChar => "b", VarType::Char => "c",
            VarType::Short | VarType::UShort => "s", VarType::Int => "i",
            VarType::UInt => "u", VarType::Long => "l", VarType::ULong => "ul",
            VarType::Float => "f", VarType::Double => "d", VarType::Pointer => "p",
            _ => "u",
        }
    }
    pub fn size(&self) -> u32 {
        match self {
            VarType::Void => 0,
            VarType::Bool | VarType::Char | VarType::UChar => 1,
            VarType::Short | VarType::UShort => 2,
            VarType::Int | VarType::UInt | VarType::Float => 4,
            VarType::Long | VarType::ULong | VarType::Double | VarType::Pointer => 8,
            VarType::Undefined(n) => *n,
        }
    }
    pub fn is_float(&self) -> bool {
        matches!(self, VarType::Float | VarType::Double)
    }
    pub fn from_size(sz: u32) -> VarType {
        match sz {
            1 => VarType::Char,
            2 => VarType::Short,
            4 => VarType::Int,
            8 => VarType::Long,
            n => VarType::Undefined(n),
        }
    }
    pub fn from_float_size(sz: u32) -> VarType {
        if sz == 4 { VarType::Float } else { VarType::Double }
    }
    pub fn decl(&self, name: &str) -> String {
        match self {
            VarType::Undefined(n) if *n > 8 => format!("uint8_t {}[{}]", name, n),
            VarType::Pointer => format!("{}{}", self.c_str(), name),
            _ => format!("{} {}", self.c_str(), name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveredVar {
    pub id: u32, pub name: String, pub storage: Loc, pub size: u32,
    pub kind: VarKind, pub ty: VarType, pub first_pc: u64, pub last_pc: u64,
    pub def_count: u32, pub use_count: u32, pub keep: bool,
    
    pub norm_off: i64,
}

#[derive(Debug, Clone, Default)]
pub struct VarNames {
    pub write_reg: HashMap<(u64, &'static str), String>,
    pub read_reg: HashMap<(u64, &'static str), String>,
    pub write_stack: HashMap<(u64, u8, i64), String>,
    pub read_stack: HashMap<(u64, u8, i64), String>,
    
    
    
    
    pub stack_by_raw: HashMap<(u8, i64), String>,
    pub type_of: HashMap<String, VarType>,
    pub size_of: HashMap<String, u32>,
    pub kept: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct RecoveredFunction {
    pub vars: Vec<RecoveredVar>,
    pub names: VarNames,
    pub ret_type: VarType,
    pub params: Vec<u32>,
    pub locals: Vec<u32>,
    pub local_slots: HashSet<(u8, i64)>,
    pub param_slots: HashSet<(u8, i64)>,
    
    pub rbp_delta: i64,
    
    pub rsp_at: HashMap<u64, i64>,
}

impl RecoveredFunction {
    pub fn param_vars(&self) -> impl Iterator<Item = &RecoveredVar> + '_ {
        self.params.iter().filter_map(move |&i| self.vars.get(i as usize))
    }
    pub fn local_vars(&self) -> impl Iterator<Item = &RecoveredVar> + '_ {
        self.locals.iter().filter_map(move |&i| self.vars.get(i as usize))
    }
    pub fn var_by_name(&self, name: &str) -> Option<&RecoveredVar> {
        self.vars.iter().find(|v| v.name == name)
    }
    pub fn stack_name(&self, pc: u64, base: u8, off: i64, write: bool) -> Option<&str> {
        let m = if write { &self.names.write_stack } else { &self.names.read_stack };
        m.get(&(pc, base, off)).map(|s| s.as_str())
    }
    pub fn reg_name(&self, pc: u64, reg: &'static str) -> Option<&str> {
        self.names.read_reg.get(&(pc, reg)).map(|s| s.as_str())
    }
    pub fn signature(&self, fn_name: &str) -> String {
        let params: Vec<String> = self.param_vars().map(|v| v.ty.decl(&v.name)).collect();
        let list = if params.is_empty() { "void".to_string() } else { params.join(", ") };
        format!("{} {}({})", self.ret_type.c_str(), fn_name, list)
    }
}


#[derive(Debug, Clone, Copy)]
struct StackAccess {
    pc: u64,
    base: u8,
    off: i64,
    size: u32,
    write: bool,
    taken: bool,
    float: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct InputRead {
    reg: &'static str,
    pc: u64,
    size: u32,
    push: bool,
    spill: Option<(u8, i64)>,
}

#[derive(Debug, Clone, Copy)]
struct RegUse { uses: u32, size: u32, first_pc: u64, last_pc: u64 }

#[derive(Debug, Clone)]
struct RegParam {
    name: String,
    reg: &'static str,
    ty: VarType,
    size: u32,
    uses: u32,
    first_pc: u64,
    last_pc: u64,
    synthetic: bool,
}

#[derive(Debug, Clone, Copy)]
struct SlotAgg {
    size: u32,
    reads: u32,
    writes: u32,
    taken: u32,
    total: u32,
    first_pc: u64,
    last_pc: u64,
    float_hits: u32,
    float_size: u32,
    float_mixed: bool,
    raw: (u8, i64),
    raw_pc: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotClass { Local, ShadowLocal, Param, Spill, RetAddr }

#[derive(Debug, Clone, Copy)]
struct StackCtx {
    ptr: i64,
    param_start: i64,
    word: i64,
    param_base: usize,
}


pub fn recover(cfg: &CFG, pinstrs: &[PInstr], _imap: &[crate::disasm::DisasmInstruction], is64: bool) -> RecoveredFunction {
    recover_with_abi(cfg, pinstrs, is64, Abi::Auto)
}

pub fn recover_with_abi(cfg: &CFG, pinstrs: &[PInstr], is64: bool, abi_hint: Abi) -> RecoveredFunction {
    let n = cfg.blocks.len();
    if n == 0 {
        return empty_function(is64);
    }
    let entry = match cfg.block_at.get(&cfg.func_entry).copied() {
        Some(e) if e < n => e,
        _ => 0,
    };

    let block_ops = build_block_ops(cfg, pinstrs);
    let (order, reachable) = reverse_postorder(cfg, entry);
    let (rbp_delta, rsp_at) = compute_deltas(cfg, &block_ops, &order, entry);

    let norm_off = |base: u8, off: i64, pc: u64| -> i64 {
        if base == 0 { rbp_delta.unwrap_or(0) + off }
        else { rsp_at.get(&pc).copied().unwrap_or(0) + off }
    };

    let ptr: i64 = if is64 { 8 } else { 4 };
    let accesses = scan_stack_accesses(&block_ops, ptr as u32);
    let input_reads = if is64 { entry_value_reads(cfg, &block_ops, &order, &reachable) } else { Vec::new() };

    let abi = if !is64 {
        Abi::Auto
    } else if abi_hint == Abi::Auto {
        detect_abi(&input_reads, &norm_off)
    } else {
        abi_hint
    };
    let usage = reg_usage(&input_reads);
    let reg_params = if is64 { build_reg_params(abi, &usage) } else { Vec::new() };
    let n_xmm = reg_params.iter().filter(|p| p.reg.starts_with("xmm")).count();

    let ctx = match (is64, abi) {
        (true, Abi::SysV64) => StackCtx { ptr: 8, param_start: 8, word: 8, param_base: 6 + n_xmm },
        (true, _) => StackCtx { ptr: 8, param_start: 8 + MS_SHADOW_SPACE, word: 8, param_base: 4 },
        (false, _) => StackCtx { ptr: 4, param_start: 4, word: 4, param_base: 0 },
    };

    let mut slots: HashMap<i64, SlotAgg> = HashMap::default();
    let mut access_noff: Vec<i64> = Vec::with_capacity(accesses.len());
    for a in &accesses {
        let noff = norm_off(a.base, a.off, a.pc);
        access_noff.push(noff);
        let s = slots.entry(noff).or_insert(SlotAgg {
            size: 0, reads: 0, writes: 0, taken: 0, total: 0,
            first_pc: a.pc, last_pc: a.pc,
            float_hits: 0, float_size: 0, float_mixed: false,
            raw: (a.base, a.off), raw_pc: a.pc,
        });
        if a.size > s.size { s.size = a.size; }
        if a.taken { s.taken += 1; } else if a.write { s.writes += 1; } else { s.reads += 1; }
        s.total += 1;
        if a.pc < s.first_pc { s.first_pc = a.pc; }
        if a.pc > s.last_pc { s.last_pc = a.pc; }
        if let Some(fs) = a.float {
            s.float_hits += 1;
            if s.float_size == 0 { s.float_size = fs; } else if s.float_size != fs { s.float_mixed = true; }
        }
        let better = (a.base == 0 && s.raw.0 != 0) || (a.base == s.raw.0 && a.pc < s.raw_pc);
        if better { s.raw = (a.base, a.off); s.raw_pc = a.pc; }
    }

    let mut noffs: Vec<i64> = slots.keys().copied().collect();
    noffs.sort_unstable();

    let mut vn = VarNames::default();
    let mut vars: Vec<RecoveredVar> = Vec::new();
    let mut slot_info: HashMap<i64, (String, SlotClass)> = HashMap::default();

    for &noff in &noffs {
        let s = slots[&noff];
        let write_only = s.reads == 0 && s.taken == 0 && s.writes > 0;
        let class = classify_slot(noff, write_only, &ctx);
        let name = slot_name(noff, class, &ctx);
        let size = if s.size > 0 { s.size } else if s.taken > 0 { ptr as u32 } else { 4 };
        let all_float = s.float_hits == s.total && !s.float_mixed && (s.float_size == 4 || s.float_size == 8);
        let ty = if all_float { VarType::from_float_size(s.float_size) } else { VarType::from_size(size) };
        let (kind, keep) = match class {
            SlotClass::Local | SlotClass::ShadowLocal => (VarKind::Local, true),
            SlotClass::Param => (VarKind::Param, true),
            SlotClass::Spill | SlotClass::RetAddr => (VarKind::Unknown, false),
        };
        vn.type_of.insert(name.clone(), ty.clone());
        vn.size_of.insert(name.clone(), size);
        vn.kept.insert(name.clone());
        vars.push(RecoveredVar {
            id: vars.len() as u32,
            name: name.clone(),
            storage: Loc::Stack { base: s.raw.0, off: s.raw.1 },
            size, kind, ty,
            first_pc: s.first_pc, last_pc: s.last_pc,
            def_count: s.writes, use_count: s.reads + s.taken,
            keep,
            norm_off: noff,
        });
        slot_info.insert(noff, (name, class));
    }

    let mut raw_class: HashMap<(u8, i64), (u64, SlotClass)> = HashMap::default();
    for (i, a) in accesses.iter().enumerate() {
        let (name, class) = &slot_info[&access_noff[i]];
        if !a.taken {
            if a.write { vn.write_stack.insert((a.pc, a.base, a.off), name.clone()); }
            else { vn.read_stack.insert((a.pc, a.base, a.off), name.clone()); }
            vn.stack_by_raw
                .entry((a.base, a.off))
                .or_insert_with(|| name.clone());
        }
        let cl = *class;
        let e = raw_class.entry((a.base, a.off)).or_insert((a.pc, cl));
        if a.pc < e.0 { *e = (a.pc, cl); }
    }
    let mut local_slots: HashSet<(u8, i64)> = HashSet::default();
    let mut param_slots: HashSet<(u8, i64)> = HashSet::default();
    for (key, (_, class)) in &raw_class {
        match class {
            SlotClass::Local | SlotClass::ShadowLocal => { local_slots.insert(*key); }
            SlotClass::Param => { param_slots.insert(*key); }
            _ => {}
        }
    }

    let mut reg_names: HashMap<&'static str, String> = HashMap::default();
    for p in &reg_params {
        reg_names.insert(p.reg, p.name.clone());
        vn.type_of.insert(p.name.clone(), p.ty.clone());
        vn.size_of.insert(p.name.clone(), p.size);
        vn.kept.insert(p.name.clone());
        vars.push(RecoveredVar {
            id: vars.len() as u32,
            name: p.name.clone(),
            storage: Loc::Reg(p.reg),
            size: p.size,
            kind: VarKind::Param,
            ty: p.ty.clone(),
            first_pc: p.first_pc,
            last_pc: p.last_pc,
            def_count: if p.synthetic { 0 } else { 1 },
            use_count: p.uses,
            keep: true,
            norm_off: 0,
        });
    }
    for r in &input_reads {
        if let Some(name) = reg_names.get(r.reg) {
            vn.read_reg.insert((r.pc, r.reg), name.clone());
        }
    }

    let mut params_list: Vec<u32> = Vec::new();
    for v in &vars {
        if v.kind == VarKind::Param && matches!(v.storage, Loc::Reg(_)) { params_list.push(v.id); }
    }
    for v in &vars {
        if v.kind == VarKind::Param && matches!(v.storage, Loc::Stack { .. }) { params_list.push(v.id); }
    }
    let locals_list: Vec<u32> = vars.iter().filter(|v| v.kind == VarKind::Local).map(|v| v.id).collect();

    RecoveredFunction {
        vars,
        names: vn,
        ret_type: ret_type(is64),
        params: params_list,
        locals: locals_list,
        local_slots,
        param_slots,
        rbp_delta: rbp_delta.unwrap_or(0),
        rsp_at,
    }
}

fn ret_type(is64: bool) -> VarType {
    if is64 { VarType::Long } else { VarType::Int }
}

fn empty_function(is64: bool) -> RecoveredFunction {
    RecoveredFunction {
        vars: Vec::new(),
        names: VarNames::default(),
        ret_type: ret_type(is64),
        params: Vec::new(),
        locals: Vec::new(),
        local_slots: HashSet::default(),
        param_slots: HashSet::default(),
        rbp_delta: 0,
        rsp_at: HashMap::default(),
    }
}


fn build_block_ops<'a>(cfg: &CFG, pinstrs: &'a [PInstr]) -> Vec<Vec<(u64, &'a POp)>> {
    let n = cfg.blocks.len();
    let mut idx: Vec<usize> = (0..pinstrs.len()).collect();
    idx.sort_by_key(|&i| pinstrs[i].address);
    let mut out: Vec<Vec<(u64, &'a POp)>> = vec![Vec::new(); n];
    for (b, block) in cfg.blocks.iter().enumerate() {
        let start = block.start;
        let end = block.end;
        let lo = idx.partition_point(|&i| pinstrs[i].address < start);
        for &i in &idx[lo..] {
            let pi = &pinstrs[i];
            if pi.address >= end { break; }
            for op in &pi.ops {
                out[b].push((pi.address, op));
            }
        }
    }
    out
}

fn reverse_postorder(cfg: &CFG, entry: usize) -> (Vec<usize>, Vec<bool>) {
    let n = cfg.blocks.len();
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
    for b in 0..n {
        for &p in &cfg.blocks[b].predecessors {
            if p < n { succs[p].push(b); }
        }
    }
    let mut seen = vec![false; n];
    let mut post: Vec<usize> = Vec::with_capacity(n);
    let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
    seen[entry] = true;
    while let Some(&(b, i)) = stack.last() {
        if i < succs[b].len() {
            if let Some(top) = stack.last_mut() { top.1 += 1; }
            let s = succs[b][i];
            if !seen[s] {
                seen[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(b);
            stack.pop();
        }
    }
    post.reverse();
    for (b, s) in seen.iter().enumerate() {
        if !*s { post.push(b); }
    }
    (post, seen)
}


fn is_sp(r: &str) -> bool { r == "rsp" || r == "esp" }
fn is_bp(r: &str) -> bool { r == "rbp" || r == "ebp" }
fn is_xmm(r: &str) -> bool { r.starts_with("xmm") || r.starts_with("ymm") }
fn is_sp_var(v: &PVar) -> bool { pvar_reg(v).is_some_and(is_sp) }
fn is_bp_var(v: &PVar) -> bool { pvar_reg(v).is_some_and(is_bp) }

fn step_stack(op: &POp, rsp: &mut i64, rbp: &mut Option<i64>) {
    match op {
        POp::Push { size, .. } => *rsp -= *size as i64,
        POp::Pop { size, .. } => *rsp += *size as i64,
        POp::IntSub { dst, b: PVar::Const(c), .. } if is_sp_var(dst) => {
            *rsp -= *c;
        }
        POp::IntAdd { dst, b: PVar::Const(c), .. } if is_sp_var(dst) => {
            *rsp += *c;
        }
        POp::Copy { dst, src, .. } => {
            if is_sp_var(dst) && is_bp_var(src) {
                if let Some(rd) = *rbp { *rsp = rd; }
            } else if is_bp_var(dst) && is_sp_var(src) {
                *rbp = Some(*rsp);
            }
        }
        POp::AddrOf { dst, base: Some(base), index: None, disp, .. } => {
            if is_sp_var(dst) && is_bp_var(base) {
                if let Some(rd) = *rbp { *rsp = rd + *disp; }
            } else if is_bp_var(dst) && is_sp_var(base) {
                *rbp = Some(*rsp + *disp);
            }
        }
        _ => {}
    }
}

fn compute_deltas(
    cfg: &CFG,
    block_ops: &[Vec<(u64, &POp)>],
    order: &[usize],
    entry: usize,
) -> (Option<i64>, HashMap<u64, i64>) {
    let n = cfg.blocks.len();
    let mut block_entry: Vec<Option<i64>> = vec![None; n];
    let mut block_exit: Vec<Option<i64>> = vec![None; n];
    block_entry[entry] = Some(0);
    let mut rbp_delta: Option<i64> = None;

    for round in 0..2 {
        let mut changed = true;
        let mut passes = 0;
        while changed && passes < MAX_FLOW_PASSES {
            changed = false;
            passes += 1;
            for &b in order {
                if block_entry[b].is_none() {
                    for &p in &cfg.blocks[b].predecessors {
                        if p < n
                            && let Some(v) = block_exit[p] {
                                block_entry[b] = Some(v);
                                break;
                            }
                    }
                }
                let mut rsp = match block_entry[b] {
                    Some(v) => v,
                    None => continue,
                };
                let mut rbp = rbp_delta;
                for &(_, op) in &block_ops[b] {
                    step_stack(op, &mut rsp, &mut rbp);
                }
                if rbp_delta.is_none() { rbp_delta = rbp; }
                if block_exit[b] != Some(rsp) {
                    block_exit[b] = Some(rsp);
                    changed = true;
                }
            }
        }
        if round == 0 {
            match block_exit[entry] {
                Some(fallback) => {
                    for entry_slot in block_entry.iter_mut() {
                        if entry_slot.is_none() { *entry_slot = Some(fallback); }
                    }
                }
                None => break,
            }
        }
    }

    let mut rsp_at: HashMap<u64, i64> = HashMap::default();
    for &b in order {
        let mut rsp = match block_entry[b] {
            Some(v) => v,
            None => continue,
        };
        let mut rbp = rbp_delta;
        let mut last_pc: Option<u64> = None;
        for &(pc, op) in &block_ops[b] {
            if last_pc != Some(pc) {
                rsp_at.insert(pc, rsp);
                last_pc = Some(pc);
            }
            step_stack(op, &mut rsp, &mut rbp);
        }
    }
    (rbp_delta, rsp_at)
}


#[inline]
fn base_id(b: &StackBase) -> u8 {
    if matches!(b, StackBase::Rbp) { 0 } else { 1 }
}

fn pvar_reg(v: &PVar) -> Option<&'static str> {
    match v {
        PVar::Reg(r) => Some(*r),
        _ => None,
    }
}

fn pvar_loc(v: &PVar) -> Option<Loc> {
    match v {
        PVar::Reg(r) => Some(Loc::Reg(r)),
        PVar::StackSlot { base, off } => Some(Loc::Stack { base: base_id(base), off: *off }),
        PVar::Tmp(t) => Some(Loc::Tmp(*t)),
        _ => None,
    }
}

fn is_zeroing(op: &POp) -> bool {
    match op {
        POp::IntXor { a, b, .. } | POp::IntSub { a, b, .. } => match (pvar_reg(a), pvar_reg(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
        _ => false,
    }
}

fn collect_reads(op: &POp, out: &mut Vec<(Loc, bool)>) {
    fn visit(v: &PVar, as_addr: bool, o: &mut Vec<(Loc, bool)>) {
        match v {
            PVar::Reg(r) => o.push((Loc::Reg(r), as_addr)),
            PVar::StackSlot { base, off } => o.push((Loc::Stack { base: base_id(base), off: *off }, as_addr)),
            PVar::Tmp(t) => o.push((Loc::Tmp(*t), as_addr)),
            PVar::Mem(bv, _) => visit(bv, true, o),
            PVar::Scaled { base, index, .. } => { visit(base, true, o); visit(index, true, o); }
            _ => {}
        }
    }
    if is_zeroing(op) {
        return;
    }
    match op {
        POp::Copy { src, .. } => visit(src, false, out),
        POp::Load { addr, .. } => visit(addr, false, out),
        POp::Store { addr, src, .. } => {
            if !matches!(addr, PVar::StackSlot { .. }) { visit(addr, false, out); }
            visit(src, false, out);
        }
        POp::IntAdd { a, b, .. } | POp::IntSub { a, b, .. } | POp::IntMul { a, b, .. }
        | POp::IntDiv { a, b, .. } | POp::IntSDiv { a, b, .. } | POp::IntAnd { a, b, .. }
        | POp::IntOr { a, b, .. } | POp::IntXor { a, b, .. } | POp::IntLeft { a, b, .. }
        | POp::IntShr { a, b, .. } | POp::IntSar { a, b, .. } => { visit(a, false, out); visit(b, false, out); }
        POp::Zext { src, .. } | POp::Sext { src, .. } | POp::Cvt { src, .. } => visit(src, false, out),
        POp::FloatBinop { a, b, .. } => { visit(a, false, out); visit(b, false, out); }
        POp::FloatCmp { a, b, .. } => { visit(a, false, out); visit(b, false, out); }
        POp::Cmp { a, b, .. } | POp::Test { a, b, .. } => { visit(a, false, out); visit(b, false, out); }
        POp::Push { src, .. } => visit(src, false, out),
        POp::AddrOf { base, index, .. } => {
            if let Some(b) = base { visit(b, true, out); }
            if let Some(i) = index { visit(i, true, out); }
        }
        POp::BranchInd { target } | POp::CallInd { target } => visit(target, false, out),
        POp::Rotate { a, b, .. } => { visit(a, false, out); visit(b, false, out); }
        POp::Bswap { src, .. } => visit(src, false, out),
        POp::SegmentOp { addr, .. } => visit(addr, false, out),
        _ => {}
    }
}

fn write_loc(op: &POp) -> Option<Loc> {
    match op {
        POp::Copy { dst, .. } => pvar_loc(dst),
        POp::IntAdd { dst, .. } | POp::IntSub { dst, .. } | POp::IntMul { dst, .. }
        | POp::IntDiv { dst, .. } | POp::IntSDiv { dst, .. } | POp::IntAnd { dst, .. }
        | POp::IntOr { dst, .. } | POp::IntXor { dst, .. } | POp::IntLeft { dst, .. }
        | POp::IntShr { dst, .. } | POp::IntSar { dst, .. } | POp::Zext { dst, .. }
        | POp::Sext { dst, .. } | POp::Load { dst, .. } | POp::SetCC { dst, .. }
        | POp::LeaAddr { dst, .. } | POp::AddrOf { dst, .. } | POp::FloatBinop { dst, .. }
        | POp::Cvt { dst, .. } | POp::Rotate { dst, .. } | POp::Bswap { dst, .. }
        | POp::SegmentOp { dst, .. } => pvar_loc(dst),
        POp::Pop { dst, .. } => pvar_loc(dst),
        POp::Store { addr, .. } => match addr {
            PVar::StackSlot { .. } => pvar_loc(addr),
            _ => None,
        },
        _ => None,
    }
}

fn addr_taken(op: &POp) -> Option<(u8, i64)> {
    if let POp::AddrOf { dst, base: Some(b), disp, .. } = op {
        if pvar_reg(dst).is_some_and(|r| is_sp(r) || is_bp(r)) {
            return None;
        }
        match pvar_reg(b) {
            Some(r) if is_bp(r) => return Some((0, *disp)),
            Some(r) if is_sp(r) => return Some((1, *disp)),
            _ => {}
        }
    }
    None
}

fn spill_target(op: &POp) -> Option<(u8, i64)> {
    let (dst, src) = match op {
        POp::Copy { dst, src, .. } => (dst, src),
        POp::Store { addr, src, .. } => (addr, src),
        _ => return None,
    };
    pvar_reg(src)?;
    match dst {
        PVar::StackSlot { base, off } => Some((base_id(base), *off)),
        _ => None,
    }
}

fn write_size(op: &POp) -> u32 {
    match op {
        POp::Copy { size, .. } | POp::Load { size, .. } | POp::Store { size, .. }
        | POp::IntAdd { size, .. } | POp::IntSub { size, .. } | POp::IntMul { size, .. }
        | POp::IntDiv { size, .. } | POp::IntSDiv { size, .. } | POp::IntAnd { size, .. }
        | POp::IntOr { size, .. } | POp::IntXor { size, .. } | POp::IntLeft { size, .. }
        | POp::IntShr { size, .. } | POp::IntSar { size, .. } | POp::SetCC { size, .. }
        | POp::FloatBinop { size, .. } | POp::Rotate { size, .. } | POp::Bswap { size, .. }
        | POp::SegmentOp { size, .. } => *size,
        POp::Zext { to_size, .. } | POp::Sext { to_size, .. } => *to_size,
        POp::LeaAddr { .. } | POp::AddrOf { .. } => 8,
        _ => 4,
    }
}

fn read_size(op: &POp) -> u32 {
    match op {
        POp::Zext { from_size, .. } => *from_size,
        POp::Sext { .. } | POp::Cvt { .. } => 0,
        POp::Push { size, .. } => *size,
        POp::Pop { size, .. } => *size,
        _ => write_size(op),
    }
}

fn float_hint(op: &POp) -> Option<u32> {
    let is_x = |v: &PVar| pvar_reg(v).is_some_and(is_xmm);
    match op {
        POp::FloatBinop { size, .. } => Some(*size),
        POp::Copy { dst, src, size, .. } => if is_x(dst) || is_x(src) { Some(*size) } else { None },
        POp::Load { dst, size, .. } => if is_x(dst) { Some(*size) } else { None },
        POp::Store { src, size, .. } => if is_x(src) { Some(*size) } else { None },
        _ => None,
    }
}


fn scan_stack_accesses(block_ops: &[Vec<(u64, &POp)>], ptr: u32) -> Vec<StackAccess> {
    let mut out: Vec<StackAccess> = Vec::new();
    let mut rlocs: Vec<(Loc, bool)> = Vec::new();
    for ops in block_ops {
        for &(pc, op) in ops {
            rlocs.clear();
            collect_reads(op, &mut rlocs);
            let fh = float_hint(op);
            for &(rl, as_addr) in &rlocs {
                if let Loc::Stack { base, off } = rl {
                    let size = if as_addr { ptr } else { read_size(op) };
                    out.push(StackAccess {
                        pc, base, off, size,
                        write: false, taken: false,
                        float: if as_addr { None } else { fh },
                    });
                }
            }
            if let Some(Loc::Stack { base, off }) = write_loc(op) {
                out.push(StackAccess {
                    pc, base, off, size: write_size(op),
                    write: true, taken: false, float: fh,
                });
            }
            if let Some((base, off)) = addr_taken(op) {
                out.push(StackAccess {
                    pc, base, off, size: 0,
                    write: false, taken: true, float: None,
                });
            }
        }
    }
    out
}

fn classify_slot(noff: i64, write_only: bool, ctx: &StackCtx) -> SlotClass {
    if write_only {
        SlotClass::Spill
    } else if noff < 0 {
        SlotClass::Local
    } else if noff < ctx.ptr {
        SlotClass::RetAddr
    } else if noff < ctx.param_start {
        SlotClass::ShadowLocal
    } else {
        SlotClass::Param
    }
}

fn slot_name(noff: i64, class: SlotClass, ctx: &StackCtx) -> String {
    match class {
        SlotClass::Spill => {
            if noff < 0 { format!("stk_{:x}", noff.unsigned_abs()) } else { format!("stk_p{:x}", noff) }
        }
        SlotClass::Local => format!("local_{:x}", noff.unsigned_abs()),
        SlotClass::ShadowLocal => format!("local_res{:x}", noff),
        SlotClass::RetAddr => {
            if noff == 0 { "retaddr".to_string() } else { format!("retaddr_{:x}", noff) }
        }
        SlotClass::Param => {
            let rel = noff - ctx.param_start;
            let idx = ctx.param_base as i64 + 1 + rel / ctx.word;
            let sub = rel % ctx.word;
            if sub == 0 { format!("param_{}", idx) } else { format!("param_{}_{:x}", idx, sub) }
        }
    }
}


fn reg_bit(r: &str) -> Option<u32> {
    Some(match r {
        "rcx" => 0, "rdx" => 1, "r8" => 2, "r9" => 3, "rdi" => 4, "rsi" => 5,
        "xmm0" => 6, "xmm1" => 7, "xmm2" => 8, "xmm3" => 9,
        "xmm4" => 10, "xmm5" => 11, "xmm6" => 12, "xmm7" => 13,
        _ => return None,
    })
}
const ALL_TRACKED: u32 = (1 << 14) - 1;

fn transfer_mask(ops: &[(u64, &POp)], mut mask: u32, mut rec: Option<&mut Vec<InputRead>>) -> u32 {
    let mut rlocs: Vec<(Loc, bool)> = Vec::new();
    for &(pc, op) in ops {
        rlocs.clear();
        collect_reads(op, &mut rlocs);
        for &(rl, _) in &rlocs {
            if let Loc::Reg(r) = rl
                && let Some(bit) = reg_bit(r)
                    && mask & (1u32 << bit) != 0
                        && let Some(v) = rec.as_deref_mut() {
                            v.push(InputRead {
                                reg: r,
                                pc,
                                size: read_size(op),
                                push: matches!(op, POp::Push { .. }),
                                spill: spill_target(op),
                            });
                        }
        }
        if let Some(Loc::Reg(w)) = write_loc(op)
            && let Some(bit) = reg_bit(w) { mask &= !(1u32 << bit); }
        if matches!(op, POp::Call { .. } | POp::CallInd { .. } | POp::CallOther { .. }) {
            for r in CALL_CLOBBERED {
                if let Some(bit) = reg_bit(r) { mask &= !(1u32 << bit); }
            }
        }
    }
    mask
}

fn entry_value_reads(
    cfg: &CFG,
    block_ops: &[Vec<(u64, &POp)>],
    order: &[usize],
    reachable: &[bool],
) -> Vec<InputRead> {
    let n = cfg.blocks.len();
    let mut out_mask: Vec<u32> = vec![ALL_TRACKED; n];
    let mut in_mask: Vec<u32> = vec![0; n];

    let mut changed = true;
    let mut passes = 0;
    while changed && passes < MAX_FLOW_PASSES {
        changed = false;
        passes += 1;
        for &b in order {
            if !reachable[b] { continue; }
            let mut m = ALL_TRACKED;
            for &p in &cfg.blocks[b].predecessors {
                if p < n && reachable[p] { m &= out_mask[p]; }
            }
            in_mask[b] = m;
            let new_out = transfer_mask(&block_ops[b], m, None);
            if new_out != out_mask[b] {
                out_mask[b] = new_out;
                changed = true;
            }
        }
    }

    let mut reads: Vec<InputRead> = Vec::new();
    for &b in order {
        if reachable[b] {
            transfer_mask(&block_ops[b], in_mask[b], Some(&mut reads));
        }
    }
    reads
}

fn detect_abi<F: Fn(u8, i64, u64) -> i64>(reads: &[InputRead], norm: &F) -> Abi {
    let mut sysv_real = false;
    let mut sysv_weak = false;
    let mut ms_home = false;
    let mut ms_plain = false;
    for r in reads {
        let is_spill = r.spill.is_some();
        let home = match r.spill {
            Some((base, off)) => norm(base, off, r.pc) >= 8,
            None => false,
        };
        if home { ms_home = true; }
        match r.reg {
            "rdi" | "rsi" => {
                if r.push { continue; }
                if is_spill {
                    if !home { sysv_weak = true; }
                } else {
                    sysv_real = true;
                }
            }
            "rcx" | "rdx" | "r8" | "r9"
                if !r.push && !is_spill => { ms_plain = true; }
            _ => {}
        }
    }
    if sysv_real || (sysv_weak && !ms_home && !ms_plain) { Abi::SysV64 } else { Abi::MsX64 }
}

fn reg_usage(reads: &[InputRead]) -> HashMap<&'static str, RegUse> {
    let mut m: HashMap<&'static str, RegUse> = HashMap::default();
    for r in reads {
        let u = m.entry(r.reg).or_insert(RegUse { uses: 0, size: 0, first_pc: r.pc, last_pc: r.pc });
        u.uses += 1;
        if r.size > u.size { u.size = r.size; }
        if r.pc < u.first_pc { u.first_pc = r.pc; }
        if r.pc > u.last_pc { u.last_pc = r.pc; }
    }
    m
}

fn make_int_param(idx: usize, reg: &'static str, u: Option<&RegUse>) -> RegParam {
    let (size, uses, first_pc, last_pc) = match u {
        Some(u) => (u.size, u.uses, u.first_pc, u.last_pc),
        None => (0, 0, 0, 0),
    };
    let (ty, size) = if u.is_none() {
        (VarType::Long, 8)
    } else {
        match size {
            1 => (VarType::Char, 1),
            2 => (VarType::Short, 2),
            0 | 4 => (VarType::Int, 4),
            _ => (VarType::Long, 8),
        }
    };
    RegParam { name: format!("param_{}", idx), reg, ty, size, uses, first_pc, last_pc, synthetic: u.is_none() }
}

fn make_float_param(idx: usize, reg: &'static str, u: Option<&RegUse>) -> RegParam {
    let (size, uses, first_pc, last_pc) = match u {
        Some(u) => (u.size, u.uses, u.first_pc, u.last_pc),
        None => (0, 0, 0, 0),
    };
    let (ty, size) = if size == 4 { (VarType::Float, 4) } else { (VarType::Double, 8) };
    RegParam { name: format!("param_{}", idx), reg, ty, size, uses, first_pc, last_pc, synthetic: false }
}

fn build_reg_params(abi: Abi, usage: &HashMap<&'static str, RegUse>) -> Vec<RegParam> {
    let mut out: Vec<RegParam> = Vec::new();
    match abi {
        Abi::SysV64 => {
            let mut hi: Option<usize> = None;
            for (i, &r) in ABI_X64_SYSV.iter().enumerate() {
                if usage.contains_key(r) { hi = Some(i); }
            }
            let n_int = hi.map_or(0, |h| h + 1);
            for (i, &reg) in ABI_X64_SYSV.iter().take(n_int).enumerate() {
                out.push(make_int_param(i + 1, reg, usage.get(reg)));
            }
            let mut k = 0usize;
            for &reg in ABI_X64_SYSV_FLOAT {
                if let Some(u) = usage.get(reg) {
                    out.push(make_float_param(n_int + 1 + k, reg, Some(u)));
                    k += 1;
                }
            }
        }
        _ => {
            let mut hi: Option<usize> = None;
            for i in 0..ABI_X64_MS.len() {
                if usage.contains_key(ABI_X64_MS[i]) || usage.contains_key(ABI_X64_FLOAT[i]) {
                    hi = Some(i);
                }
            }
            if let Some(hi) = hi {
                for i in 0..=hi {
                    let ireg = ABI_X64_MS[i];
                    let freg = ABI_X64_FLOAT[i];
                    if let Some(u) = usage.get(ireg) {
                        out.push(make_int_param(i + 1, ireg, Some(u)));
                    } else if let Some(u) = usage.get(freg) {
                        out.push(make_float_param(i + 1, freg, Some(u)));
                    } else {
                        out.push(make_int_param(i + 1, ireg, None));
                    }
                }
            }
        }
    }
    if !FILL_PARAM_GAPS {
        out.retain(|p| !p.synthetic);
    }
    out
}


fn sub_aliases(r: &str) -> &'static [(&'static str, u8)] {
    match r {
        "rax" => &[("eax", 32), ("ax", 16), ("al", 8)],
        "rbx" => &[("ebx", 32), ("bx", 16), ("bl", 8)],
        "rcx" => &[("ecx", 32), ("cx", 16), ("cl", 8)],
        "rdx" => &[("edx", 32), ("dx", 16), ("dl", 8)],
        "rsi" => &[("esi", 32), ("si", 16), ("sil", 8)],
        "rdi" => &[("edi", 32), ("di", 16), ("dil", 8)],
        "rbp" => &[("ebp", 32), ("bp", 16), ("bpl", 8)],
        "rsp" => &[("esp", 32), ("sp", 16), ("spl", 8)],
        "r8" => &[("r8d", 32), ("r8w", 16), ("r8b", 8)],
        "r9" => &[("r9d", 32), ("r9w", 16), ("r9b", 8)],
        "r10" => &[("r10d", 32), ("r10w", 16), ("r10b", 8)],
        "r11" => &[("r11d", 32), ("r11w", 16), ("r11b", 8)],
        "r12" => &[("r12d", 32), ("r12w", 16), ("r12b", 8)],
        "r13" => &[("r13d", 32), ("r13w", 16), ("r13b", 8)],
        "r14" => &[("r14d", 32), ("r14w", 16), ("r14b", 8)],
        "r15" => &[("r15d", 32), ("r15w", 16), ("r15b", 8)],
        _ => &[],
    }
}

pub fn aliases(r: &'static str) -> Vec<&'static str> {
    let mut v = vec![r];
    for &(a, bits) in sub_aliases(r) {
        if bits == 32 { v.push(a); }
    }
    v
}

#[derive(Default)]
struct PcNames {
    read: Vec<(&'static str, String)>,
    write: Vec<(&'static str, String)>,
}

fn expand_aliases(reg: &'static str, name: &str, partial_casts: bool, out: &mut Vec<(&'static str, String)>) {
    out.push((reg, name.to_string()));
    for &(alias, bits) in sub_aliases(reg) {
        match bits {
            32 => out.push((alias, name.to_string())),
            16 if partial_casts => out.push((alias, format!("(uint16_t){}", name))),
            8 if partial_casts => out.push((alias, format!("(uint8_t){}", name))),
            _ => {}
        }
    }
}

pub fn apply_names(lines: &mut [crate::analysis::decompiler::PseudoLine], rv: &RecoveredFunction) {
    let vn = &rv.names;
    if vn.read_reg.is_empty() && vn.write_reg.is_empty() {
        return;
    }
    let mut by_pc: HashMap<u64, PcNames> = HashMap::default();
    for (&(pc, reg), name) in &vn.read_reg {
        expand_aliases(reg, name, true, &mut by_pc.entry(pc).or_default().read);
    }
    for (&(pc, reg), name) in &vn.write_reg {
        expand_aliases(reg, name, false, &mut by_pc.entry(pc).or_default().write);
    }
    for line in lines.iter_mut() {
        let pc = match line.source_addr {
            Some(p) => p,
            None => continue,
        };
        let pn = match by_pc.get(&pc) {
            Some(p) => p,
            None => continue,
        };
        let new_text = rewrite_line(&line.text, pn);
        line.text = new_text;
    }
}

fn rewrite_line(text: &str, pn: &PcNames) -> String {
    if let Some(eq) = text.find(" = ") {
        let (lhs, rest) = text.split_at(eq);
        let rhs = &rest[3..];
        let plain_target = lhs.bytes().all(|c| is_ident_char(c) || c == b' ');
        let new_lhs = if plain_target {
            rewrite_idents(lhs, &pn.write, true)
        } else {
            rewrite_idents(lhs, &pn.read, false)
        };
        let new_rhs = rewrite_idents(rhs, &pn.read, false);
        format!("{} = {}", new_lhs, new_rhs)
    } else {
        rewrite_idents(text, &pn.read, false)
    }
}

fn is_ident_start(c: u8) -> bool { c.is_ascii_alphabetic() || c == b'_' }
fn is_ident_char(c: u8) -> bool { c.is_ascii_alphanumeric() || c == b'_' }

fn lookup<'m>(map: &'m [(&'static str, String)], tok: &str) -> Option<&'m str> {
    map.iter().find(|(from, _)| *from == tok).map(|(_, to)| to.as_str())
}

fn rewrite_idents(s: &str, map: &[(&'static str, String)], first_only: bool) -> String {
    if map.is_empty() {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + 8);
    let mut replaced = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if is_ident_start(c) {
            let start = i;
            while i < bytes.len() && is_ident_char(bytes[i]) { i += 1; }
            let tok = &s[start..i];
            if !(first_only && replaced)
                && let Some(rep) = lookup(map, tok) {
                    out.push_str(rep);
                    replaced = true;
                    continue;
                }
            out.push_str(tok);
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && is_ident_char(bytes[i]) { i += 1; }
            out.push_str(&s[start..i]);
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        pairs.iter().map(|&(a, b)| (a, b.to_string())).collect()
    }

    #[test]
    fn rewrite_respects_word_boundaries() {
        let m = map(&[("rcx", "param_1")]);
        assert_eq!(rewrite_idents("rcx + 8", &m, false), "param_1 + 8");
        assert_eq!(rewrite_idents("rcxx + xrcx + rcx_1", &m, false), "rcxx + xrcx + rcx_1");
        assert_eq!(rewrite_idents("rcx + rcx", &m, true), "param_1 + rcx");
        assert_eq!(rewrite_idents("0x10 + 3rcx", &m, false), "0x10 + 3rcx");
    }

    #[test]
    fn rewrite_line_splits_on_assignment() {
        let mut pn = PcNames::default();
        expand_aliases("rcx", "param_1", true, &mut pn.read);
        assert_eq!(rewrite_line("rax = ecx + 1", &pn), "rax = param_1 + 1");
        assert_eq!(rewrite_line("*(int32_t *)(rcx + 8) = 5", &pn), "*(int32_t *)(param_1 + 8) = 5");
        assert_eq!(rewrite_line("rax = cl", &pn), "rax = (uint8_t)param_1");
    }

    #[test]
    fn aliases_keep_the_old_contract() {
        assert_eq!(aliases("rcx"), vec!["rcx", "ecx"]);
        assert_eq!(aliases("r8"), vec!["r8", "r8d"]);
        assert_eq!(aliases("xmm0"), vec!["xmm0"]);
    }

    #[test]
    fn c_types_keep_signedness() {
        assert_eq!(VarType::UInt.c_str(), "uint32_t");
        assert_eq!(VarType::UChar.c_str(), "uint8_t");
        assert_eq!(VarType::Undefined(4).c_str(), "int32_t");
        assert_eq!(VarType::Undefined(16).decl("buf"), "uint8_t buf[16]");
        assert_eq!(VarType::Long.decl("x"), "int64_t x");
        assert_eq!(VarType::Pointer.decl("p"), "int64_t *p");
        assert_eq!(VarType::from_size(4), VarType::Int);
        assert_eq!(VarType::from_size(3), VarType::Undefined(3));
    }

    #[test]
    fn stack_slots_are_named_like_ghidra() {
        let ms = StackCtx { ptr: 8, param_start: 0x28, word: 8, param_base: 4 };
        assert_eq!(classify_slot(-0x18, false, &ms), SlotClass::Local);
        assert_eq!(slot_name(-0x18, SlotClass::Local, &ms), "local_18");
        assert_eq!(classify_slot(0, false, &ms), SlotClass::RetAddr);
        assert_eq!(classify_slot(0x10, false, &ms), SlotClass::ShadowLocal);
        assert_eq!(slot_name(0x10, SlotClass::ShadowLocal, &ms), "local_res10");
        assert_eq!(classify_slot(0x28, false, &ms), SlotClass::Param);
        assert_eq!(slot_name(0x28, SlotClass::Param, &ms), "param_5");
        assert_eq!(slot_name(0x38, SlotClass::Param, &ms), "param_7");
        assert_eq!(slot_name(0x2c, SlotClass::Param, &ms), "param_5_4");
        assert_eq!(classify_slot(-8, true, &ms), SlotClass::Spill);
        assert_eq!(slot_name(-8, SlotClass::Spill, &ms), "stk_8");
        assert_eq!(slot_name(8, SlotClass::Spill, &ms), "stk_p8");
    }

    fn rd(reg: &'static str, pc: u64, push: bool, spill: Option<(u8, i64)>) -> InputRead {
        InputRead { reg, pc, size: 8, push, spill }
    }

    #[test]
    fn abi_detection_ignores_callee_saved_rdi_rsi() {
        let norm = |_b: u8, off: i64, _pc: u64| off;
        let ms = vec![rd("rdi", 0x10, true, None), rd("rsi", 0x11, true, None), rd("rcx", 0x12, false, None)];
        assert_eq!(detect_abi(&ms, &norm), Abi::MsX64);
        let ms2 = vec![rd("rdi", 0x10, false, Some((1, 0x10))), rd("rcx", 0x14, false, None)];
        assert_eq!(detect_abi(&ms2, &norm), Abi::MsX64);
        let sv = vec![rd("rdi", 0x10, false, None)];
        assert_eq!(detect_abi(&sv, &norm), Abi::SysV64);
        let sv2 = vec![rd("rdi", 0x10, false, Some((0, -0x14))), rd("rsi", 0x13, false, Some((0, -0x18)))];
        assert_eq!(detect_abi(&sv2, &norm), Abi::SysV64);
    }

    fn usage_of(regs: &[&'static str]) -> HashMap<&'static str, RegUse> {
        let mut m: HashMap<&'static str, RegUse> = HashMap::default();
        for &r in regs {
            m.insert(r, RegUse { uses: 1, size: 4, first_pc: 0x10, last_pc: 0x10 });
        }
        m
    }

    #[test]
    fn ms_params_are_positional_and_gaps_are_filled() {
        let p = build_reg_params(Abi::MsX64, &usage_of(&["rdx", "xmm2"]));
        let names: Vec<(&str, &str)> = p.iter().map(|x| (x.name.as_str(), x.reg)).collect();
        assert_eq!(names, vec![("param_1", "rcx"), ("param_2", "rdx"), ("param_3", "xmm2")]);
        assert!(p[0].synthetic && !p[1].synthetic);
        assert_eq!(p[2].ty, VarType::Float);
    }

    #[test]
    fn sysv_params_use_integer_positions_then_xmm() {
        let p = build_reg_params(Abi::SysV64, &usage_of(&["rsi", "xmm0"]));
        let names: Vec<&str> = p.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["param_1", "param_2", "param_3"]);
        assert_eq!(p[2].reg, "xmm0");
    }

    #[test]
    fn tracked_registers_fit_in_the_mask() {
        assert_eq!(reg_bit("rcx"), Some(0));
        assert_eq!(reg_bit("xmm7"), Some(13));
        assert_eq!(reg_bit("rax"), None);
        assert_eq!(ALL_TRACKED, 0x3fff);
    }
}