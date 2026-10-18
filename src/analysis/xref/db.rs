use crate::analysis::operands::{parse_insn_operands, Operand};
use crate::disasm::DisasmInstruction;
use crate::parser::ParsedBinary;
use rustc_hash::FxHashMap as HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum XRefKind {
    Call,
    Jump,
    CallIndirect,
    JumpIndirect,
    TailCall,
    Thunk,
    DataRead,
    DataWrite,
    DataAddr,
    StringRef,
}

impl XRefKind {
    pub fn is_call_edge(self) -> bool {
        matches!(self, XRefKind::Call | XRefKind::TailCall)
    }
    pub fn is_flow(self) -> bool {
        matches!(
            self,
            XRefKind::Call
                | XRefKind::Jump
                | XRefKind::CallIndirect
                | XRefKind::JumpIndirect
                | XRefKind::TailCall
                | XRefKind::Thunk
        )
    }
}

#[derive(Debug, Clone)]
pub struct XRef {
    pub from: u64,
    pub to: u64,
    pub kind: XRefKind,
    pub note: Option<Arc<str>>,
    pub is_primary: bool,
    pub op_index: i32,
}

impl XRef {
    #[allow(dead_code)]
    pub fn new(from: u64, to: u64, kind: XRefKind, note: String) -> Self {
        let note = if note.is_empty() {
            None
        } else {
            Some(Arc::from(note.as_str()))
        };
        XRef {
            from,
            to,
            kind,
            note,
            is_primary: true,
            op_index: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct XRefDB {
    pub all: Vec<XRef>,
    pub by_to: HashMap<u64, Vec<usize>>,
    pub by_from: HashMap<u64, Vec<usize>>,
    taken: rustc_hash::FxHashSet<(u64, i32)>,
}

impl XRefDB {
    pub fn add(&mut self, xref: XRef) {
        let idx = self.all.len();
        self.by_to.entry(xref.to).or_default().push(idx);
        self.by_from.entry(xref.from).or_default().push(idx);
        self.taken.insert((xref.from, xref.op_index));
        self.all.push(xref);
    }

    pub fn add_ref(&mut self, from: u64, to: u64, kind: XRefKind, note: String, op_index: i32) {
        let is_primary = !self.taken.contains(&(from, op_index));
        let note = if note.is_empty() {
            None
        } else {
            Some(Arc::from(note.as_str()))
        };
        self.add(XRef {
            from,
            to,
            kind,
            note,
            is_primary,
            op_index,
        });
    }

    pub fn retrack(&mut self) {
        self.taken.clear();
        for x in &self.all {
            self.taken.insert((x.from, x.op_index));
        }
    }

    pub fn from_parts(
        all: Vec<XRef>,
        by_to: HashMap<u64, Vec<usize>>,
        by_from: HashMap<u64, Vec<usize>>,
    ) -> Self {
        let mut db = Self {
            all,
            by_to,
            by_from,
            taken: Default::default(),
        };
        db.retrack();
        db
    }

    #[allow(dead_code)]
    pub fn set_primary(&mut self, from: u64, op_index: i32, to: u64) -> bool {
        self.set_primary_batch(&[(from, op_index, to)]) == 1
    }

    pub fn set_primary_batch(&mut self, picks: &[(u64, i32, u64)]) -> usize {
        if picks.is_empty() {
            return 0;
        }
        let lookup: rustc_hash::FxHashMap<(u64, i32), u64> =
            picks.iter().map(|(f, o, t)| ((*f, *o), *t)).collect();
        let mut found = 0usize;
        let mut seen: rustc_hash::FxHashSet<(u64, i32)> = rustc_hash::FxHashSet::default();
        for x in self.all.iter_mut() {
            if let Some(want_to) = lookup.get(&(x.from, x.op_index)) {
                let want = x.to == *want_to;
                x.is_primary = want;
                if want && seen.insert((x.from, x.op_index)) {
                    found += 1;
                }
            }
        }
        found
    }

    #[allow(dead_code)]
    pub fn primary_from(&self, addr: u64) -> Vec<&XRef> {
        self.by_from
            .get(&addr)
            .map(|v| {
                v.iter()
                    .map(|&i| &self.all[i])
                    .filter(|x| x.is_primary)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn xrefs_to(&self, addr: u64) -> Vec<&XRef> {
        self.by_to
            .get(&addr)
            .map(|v| v.iter().map(|&i| &self.all[i]).collect())
            .unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn xrefs_from(&self, addr: u64) -> Vec<&XRef> {
        self.by_from
            .get(&addr)
            .map(|v| v.iter().map(|&i| &self.all[i]).collect())
            .unwrap_or_default()
    }

    pub fn merge(&mut self, other: XRefDB) {
        self.all.reserve(other.all.len());
        for x in other.all {
            self.add(x);
        }
    }
}

fn is_mapped_addr(binary: &ParsedBinary, addr: u64) -> bool {
    binary
        .sections
        .iter()
        .any(|s| s.vaddr != 0 && addr >= s.vaddr && addr < s.vaddr.saturating_add(s.size))
}

pub(crate) fn direct_target_ok(binary: &ParsedBinary, target: u64) -> bool {
    if target == 0 {
        return false;
    }
    if binary.sections.is_empty() {
        return true;
    }
    is_mapped_addr(binary, target)
}

#[inline]
fn cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::Relaxed))
}

#[derive(Default)]
struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    fn from_ranges(iter: impl Iterator<Item = (u64, u64)>) -> Self {
        let mut v: Vec<(u64, u64)> = iter.filter(|(lo, hi)| lo < hi).collect();
        v.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(v.len());
        for (lo, hi) in v {
            match merged.last_mut() {
                Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
                _ => merged.push((lo, hi)),
            }
        }
        Ranges(merged)
    }

    #[inline]
    fn contains(&self, addr: u64) -> bool {
        let i = self.0.partition_point(|&(lo, _)| lo <= addr);
        i > 0 && addr < self.0[i - 1].1
    }
}

struct Lookups<'a> {
    strings: HashMap<u64, &'a str>,
    symbols: HashMap<u64, &'a str>,
    imports: HashMap<u64, String>,
    code: Ranges,
    mapped: Ranges,
    no_sections: bool,
}

impl<'a> Lookups<'a> {
    fn new(binary: &'a ParsedBinary) -> Self {
        let mut strings: HashMap<u64, &'a str> = HashMap::default();
        for s in &binary.strings {
            strings.entry(s.vaddr).or_insert(&s.content);
        }
        let mut symbols: HashMap<u64, &'a str> = HashMap::default();
        for sym in &binary.symbols {
            symbols.entry(sym.addr).or_insert(&sym.name);
        }
        let mut imports: HashMap<u64, String> = HashMap::default();
        for imp in binary.all_imports() {
            if imp.offset != 0 {
                let name = if imp.library.is_empty() {
                    imp.name.clone()
                } else {
                    format!("{}!{}", imp.library, imp.name)
                };
                imports.insert(imp.offset, name);
            }
        }
        let code = Ranges::from_ranges(
            binary
                .sections
                .iter()
                .filter(|s| s.is_executable)
                .map(|s| (s.vaddr, s.vaddr.saturating_add(s.size))),
        );
        let mapped = Ranges::from_ranges(
            binary
                .sections
                .iter()
                .filter(|s| s.vaddr != 0)
                .map(|s| (s.vaddr, s.vaddr.saturating_add(s.size))),
        );
        Lookups {
            strings,
            symbols,
            imports,
            code,
            mapped,
            no_sections: binary.sections.is_empty(),
        }
    }

    #[inline]
    fn is_code(&self, a: u64) -> bool {
        self.code.contains(a)
    }

    #[inline]
    fn is_mapped(&self, a: u64) -> bool {
        self.mapped.contains(a)
    }

    #[inline]
    fn is_string(&self, a: u64) -> bool {
        self.strings.contains_key(&a)
    }

    fn is_ref_target(&self, a: u64) -> bool {
        self.strings.contains_key(&a)
            || self.symbols.contains_key(&a)
            || self.imports.contains_key(&a)
    }

    fn direct_target_ok(&self, a: u64) -> bool {
        a != 0 && (self.no_sections || self.is_mapped(a))
    }

    fn note_for(&self, a: u64) -> String {
        if let Some(s) = self.strings.get(&a) {
            s.to_string()
        } else if let Some(s) = self.symbols.get(&a) {
            s.to_string()
        } else if let Some(s) = self.imports.get(&a) {
            s.clone()
        } else {
            String::new()
        }
    }
}

fn add_branch_ref(
    db: &mut XRefDB,
    lk: &Lookups,
    insn: &DisasmInstruction,
    op: &Operand,
    direct: XRefKind,
    indirect: XRefKind,
) {
    match op {
        Operand::Addr(a) => {
            if lk.direct_target_ok(*a) {
                db.add_ref(insn.address, *a, direct, lk.note_for(*a), 0);
            }
        }
        Operand::Imm(v) if *v > 0 => {
            let a = *v as u64;
            if lk.direct_target_ok(a) {
                db.add_ref(insn.address, a, direct, lk.note_for(a), 0);
            }
        }
        Operand::Mem { .. } => {
            if let Some(target) = resolve_abs_mem(op, insn) {
                db.add_ref(insn.address, target, indirect, lk.note_for(target), 0);
            }
        }
        Operand::Reg(r) => {
            db.add_ref(insn.address, 0, indirect, r.to_string(), 0);
        }
        _ => {}
    }
}

fn add_addr_operand_ref(
    db: &mut XRefDB,
    lk: &Lookups,
    insn: &DisasmInstruction,
    a: u64,
    op_index: i32,
) {
    if lk.is_mapped(a) && (lk.is_ref_target(a) || !lk.is_code(a)) {
        let kind = if lk.is_string(a) {
            XRefKind::StringRef
        } else {
            XRefKind::DataAddr
        };
        db.add_ref(insn.address, a, kind, lk.note_for(a), op_index);
    }
}

fn scan_range(
    db: &mut XRefDB,
    insns: &[DisasmInstruction],
    lk: &Lookups,
    cancel: Option<&AtomicBool>,
) -> bool {
    for (i, insn) in insns.iter().enumerate() {
        if i & 0xFFF == 0 && cancelled(cancel) {
            return true;
        }
        let m = insn.mnemonic;
        let parsed: Vec<Operand> = parse_insn_operands(insn);

        if m.starts_with("call") {
            if let Some(op) = parsed.first() {
                add_branch_ref(db, lk, insn, op, XRefKind::Call, XRefKind::CallIndirect);
            }
        } else if m.starts_with('j') {
            if let Some(op) = parsed.first() {
                add_branch_ref(db, lk, insn, op, XRefKind::Jump, XRefKind::JumpIndirect);
            }
        } else if m == "lea" {
            if let [_, src] = parsed.as_slice() {
                let target = resolve_abs_mem(src, insn).or(match src {
                    Operand::Addr(a) => Some(*a),
                    _ => None,
                });
                if let Some(target) = target {
                    let kind = if lk.is_string(target) {
                        XRefKind::StringRef
                    } else {
                        XRefKind::DataAddr
                    };
                    db.add_ref(insn.address, target, kind, lk.note_for(target), 1);
                }
            }
        } else if matches!(m, "mov" | "movzx" | "movsx" | "movsxd") {
            if let [dst, src] = parsed.as_slice() {
                let produced_by: i32 = if resolve_abs_mem(dst, insn).is_some() {
                    0
                } else {
                    1
                };
                if let Some((target, is_write)) = mov_data_ref(dst, src, insn) {
                    if target != 0 {
                        let from_imm =
                            matches!(src, Operand::Addr(_)) && !matches!(dst, Operand::Mem { .. });
                        if from_imm {
                            add_addr_operand_ref(db, lk, insn, target, produced_by);
                        } else {
                            let kind = if lk.is_string(target) {
                                XRefKind::StringRef
                            } else if is_write {
                                XRefKind::DataWrite
                            } else {
                                XRefKind::DataRead
                            };
                            db.add_ref(
                                insn.address,
                                target,
                                kind,
                                lk.note_for(target),
                                produced_by,
                            );
                        }
                    }
                }
            }
        } else if matches!(
            m,
            "cmp" | "test" | "add" | "sub" | "and" | "or" | "xor" | "inc" | "dec" | "push"
        ) {
            for (op_idx, op) in parsed.iter().enumerate() {
                if let Some(target) = resolve_abs_mem(op, insn) {
                    if lk.is_ref_target(target) {
                        let kind = if lk.is_string(target) {
                            XRefKind::StringRef
                        } else {
                            XRefKind::DataRead
                        };
                        db.add_ref(
                            insn.address,
                            target,
                            kind,
                            lk.note_for(target),
                            op_idx as i32,
                        );
                    }
                } else if let Operand::Addr(a) = op {
                    add_addr_operand_ref(db, lk, insn, *a, op_idx as i32);
                }
            }
        } else if matches!(m, "movabs" | "movq") {
            if let [_, Operand::Addr(a)] = parsed.as_slice() {
                add_addr_operand_ref(db, lk, insn, *a, 1);
            }
        }
    }
    false
}

pub fn build_xrefs(
    insns: &[DisasmInstruction],
    binary: &ParsedBinary,
    cancel: Option<&AtomicBool>,
) -> XRefDB {
    if insns.len() >= crate::util::parallel::PAR_INSNS && crate::util::parallel::workers() >= 2 {
        return build_xrefs_parallel(insns, binary, cancel);
    }
    let lk = Lookups::new(binary);
    let mut db = XRefDB::default();
    if scan_range(&mut db, insns, &lk, cancel) {
        return db;
    }
    build_data_xrefs(&mut db, binary, &lk, cancel);
    db
}

pub fn build_xrefs_parallel(
    insns: &[DisasmInstruction],
    binary: &ParsedBinary,
    cancel: Option<&AtomicBool>,
) -> XRefDB {
    use rayon::prelude::*;
    let lk = Lookups::new(binary);
    let n_threads = crate::util::parallel::workers().max(1);
    let chunk = (insns.len() / (n_threads * 4)).max(4096);
    let lk_ref = &lk;
    let partials: Vec<XRefDB> = crate::util::parallel::install(|| {
        insns
            .par_chunks(chunk)
            .map(|part| {
                let mut local = XRefDB::default();
                scan_range(&mut local, part, lk_ref, cancel);
                local
            })
            .collect()
    });
    let mut db = XRefDB::default();
    for part in partials {
        db.merge(part);
    }
    if cancelled(cancel) {
        return db;
    }
    build_data_xrefs(&mut db, binary, &lk, cancel);
    db
}

fn resolve_abs_mem(op: &Operand, insn: &DisasmInstruction) -> Option<u64> {
    match op {
        Operand::Mem {
            base, index, disp, ..
        } => {
            if *base == Some("rip") && index.is_none() {
                let next_ip = insn.address.wrapping_add(insn.bytes.len() as u64);
                return Some(next_ip.wrapping_add(*disp as u64));
            }
            if base.is_none() && index.is_none() {
                return Some(*disp as u64);
            }
            None
        }
        _ => None,
    }
}

fn build_data_xrefs(
    db: &mut XRefDB,
    binary: &ParsedBinary,
    lk: &Lookups,
    cancel: Option<&AtomicBool>,
) {
    let ptr_size: usize = if matches!(binary.arch.as_str(), "x86_64" | "aarch64") {
        8
    } else {
        4
    };
    const MAX_DATA_XREFS: usize = 250_000;
    const MAX_PER_SECTION: usize = 32_768;

    let data_len = binary.data.len() as u64;
    let eligible: Vec<(u64, usize, usize)> = binary
        .sections
        .iter()
        .filter(|s| !s.is_executable && s.vaddr != 0 && s.size != 0 && s.size <= 0x1000_0000)
        .filter(|s| s.offset <= data_len && s.offset.saturating_add(s.size) <= data_len)
        .map(|s| (s.vaddr, s.offset as usize, (s.offset + s.size) as usize))
        .collect();

    let scan_one = |&(vaddr, start, end): &(u64, usize, usize)| -> Vec<XRef> {
        let mut out = Vec::new();
        for (n, word) in binary.data[start..end].chunks_exact(ptr_size).enumerate() {
            if out.len() >= MAX_PER_SECTION {
                break;
            }
            if n & 0xFFFF == 0xFFFF && cancelled(cancel) {
                break;
            }
            let target = if ptr_size == 8 {
                u64::from_le_bytes(word.try_into().unwrap())
            } else {
                u32::from_le_bytes(word.try_into().unwrap()) as u64
            };
            if target != 0 && lk.is_code(target) {
                let note: Option<Arc<str>> = lk
                    .strings
                    .get(&target)
                    .or_else(|| lk.symbols.get(&target))
                    .map(|s| Arc::from(*s));
                out.push(XRef {
                    from: vaddr.saturating_add((n * ptr_size) as u64),
                    to: target,
                    kind: XRefKind::DataAddr,
                    note,
                    is_primary: false,
                    op_index: -1,
                });
            }
        }
        out
    };
    let scanned: Vec<Vec<XRef>> = if eligible.len() >= crate::util::parallel::PAR_SECTIONS {
        use rayon::prelude::*;
        crate::util::parallel::install(|| eligible.par_iter().map(scan_one).collect())
    } else {
        eligible.iter().map(scan_one).collect()
    };
    let mut added: usize = 0;
    for vec in scanned {
        for x in vec {
            if added >= MAX_DATA_XREFS || cancelled(cancel) {
                return;
            }
            db.add(x);
            added += 1;
        }
    }
}

fn mov_data_ref(dst: &Operand, src: &Operand, insn: &DisasmInstruction) -> Option<(u64, bool)> {
    if let Some(addr) = resolve_abs_mem(dst, insn) {
        return Some((addr, true));
    }
    if let Some(addr) = resolve_abs_mem(src, insn) {
        return Some((addr, false));
    }
    if let Operand::Addr(a) = src {
        return Some((*a, false));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_merge_and_contains() {
        let r = Ranges::from_ranges(vec![(10u64, 20u64), (20, 30), (50, 60), (5, 5)].into_iter());
        assert!(r.contains(10));
        assert!(r.contains(29));
        assert!(!r.contains(30));
        assert!(!r.contains(5));
        assert!(r.contains(55));
        assert!(!r.contains(60));
        assert!(!Ranges::default().contains(0));
    }

    #[test]
    fn primary_flags_follow_first_ref_and_can_be_repicked() {
        let mut db = XRefDB::default();
        db.add_ref(0x10, 0x100, XRefKind::Call, String::new(), 0);
        db.add_ref(0x10, 0x200, XRefKind::Call, String::new(), 0);
        assert!(db.all[0].is_primary && !db.all[1].is_primary);
        assert_eq!(db.set_primary_batch(&[(0x10, 0, 0x200)]), 1);
        assert!(!db.all[0].is_primary && db.all[1].is_primary);
        assert_eq!(db.xrefs_to(0x200).len(), 1);
        assert_eq!(db.set_primary_batch(&[]), 0);
    }
}
