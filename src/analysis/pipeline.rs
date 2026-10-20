pub mod decompile;

pub use decompile::{decompile_on_demand, decompile_snapshot};
use decompile::{decompile_parallel, DecompileJob};

use super::advanced;
use super::advanced::{StubInfo, StubKind, SwitchTable};
use super::binary::{golang, pe_resources};
use super::decompiler::pcode;
use super::decompiler::Pseudocode;
use super::flow::cfg::CFG;
use super::flow::function::{DetectedFunction, FuncSource};
use super::flow::stack::StackFrame;
use super::flow::{cfg, constprop, function, function_id, noreturn, stack, unwind};
use super::symbols::debug_types::DebugTypes;
use super::symbols::{debug_symbols, demangle, dwarf_types};
use super::type_reconstruction;
use super::xref::db as xref;
use super::xref::db::{XRefDB, XRefKind};
use crate::disasm::DisasmResult;
use crate::parser::ParsedBinary;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const TOTAL_PHASES: usize = 13;
const MAX_EAGER_BLOCKS: usize = 200;
const DEFAULT_EAGER_DECOMPILE_CAP: usize = 1_500;
const ALIGNED_START_ALIGNMENT: u64 = 16;
const MAX_DATA_POINTER_CANDIDATES: usize = 8192;

#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    pub functions: Vec<DetectedFunction>,
    pub xrefs: XRefDB,
    pub cfgs: HashMap<u64, CFG>,
    pub stack_frames: HashMap<u64, StackFrame>,
    pub pseudocode: HashMap<u64, Pseudocode>,
    pub callers: HashMap<u64, Vec<u64>>,
    pub callees: HashMap<u64, Vec<u64>>,
    pub stubs: HashMap<u64, StubInfo>,
    pub switches: Vec<SwitchTable>,
    pub noreturn_functions: HashSet<u64>,
    pub pe_resources: Option<pe_resources::PEResourceAnalyzer>,
    pub debug_symbols: Option<debug_symbols::DebugSymbolsAnalyzer>,
    pub function_signatures: HashMap<u64, function_id::FunctionSignature>,
    pub reconstructed_types: HashMap<u64, type_reconstruction::ReconstructedType>,
    pub debug_types: Option<Arc<DebugTypes>>,
    pub is_win64: bool,
}

pub type ProgressFn<'a> = &'a (dyn Fn(&str, &str, usize, usize) + Send + Sync);

struct FuncRanges {
    ranges: Vec<(u64, u64)>,
    max_end: Vec<u64>,
}

impl FuncRanges {
    fn new(functions: &[DetectedFunction]) -> Self {
        let mut ranges: Vec<(u64, u64)> = functions.iter().map(|f| (f.entry, f.end)).collect();
        ranges.sort_unstable();
        let mut running = 0u64;
        let max_end = ranges
            .iter()
            .map(|&(_, end)| {
                running = running.max(end);
                running
            })
            .collect();
        Self { ranges, max_end }
    }

    
    
    
    fn find(&self, addr: u64) -> Option<(u64, u64)> {
        let mut i = self.ranges.partition_point(|&(start, _)| start <= addr);
        while i > 0 {
            i -= 1;
            if self.max_end[i] <= addr {
                return None;
            }
            let (start, end) = self.ranges[i];
            if addr < end {
                return Some((start, end));
            }
        }
        None
    }

    fn strictly_inside_any(&self, addr: u64) -> bool {
        let idx = self.ranges.partition_point(|&(start, _)| start < addr);
        idx > 0 && self.max_end[idx - 1] > addr
    }
}

fn new_discovered_function(entry: u64, end: u64, name: String) -> DetectedFunction {
    DetectedFunction {
        entry,
        end,
        name,
        has_frame: false,
        stack_size: 0,
        source: FuncSource::CallTarget,
        is_thunk: false,
        thunk_target: None,
    }
}


fn exec_section_end(binary: &ParsedBinary, addr: u64) -> Option<u64> {
    binary
        .sections
        .iter()
        .filter(|s| s.is_executable && s.size > 0)
        .find(|s| addr >= s.vaddr && addr - s.vaddr < s.size)
        .map(|s| s.vaddr.saturating_add(s.size))
}




fn function_end(binary: &ParsedBinary, sorted_starts: &[u64], addr: u64, min_end: u64) -> u64 {
    let next = sorted_starts
        .get(sorted_starts.partition_point(|&s| s <= addr))
        .copied();
    let end = match (next, exec_section_end(binary, addr)) {
        (Some(n), Some(s)) => n.min(s),
        (Some(n), None) => n,
        (None, Some(s)) => s,
        (None, None) => min_end,
    };
    end.max(min_end)
}





fn propagate_noreturn(edges: &[(u64, u64)], noreturn: &mut HashSet<u64>) -> bool {
    if edges.is_empty() || noreturn.is_empty() {
        return false;
    }
    let mut uniq: Vec<(u64, u64)> = edges.to_vec();
    uniq.sort_unstable();
    uniq.dedup();
    let mut remaining: HashMap<u64, usize> = HashMap::default();
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::default();
    for &(src, dst) in &uniq {
        *remaining.entry(src).or_insert(0) += 1;
        preds.entry(dst).or_default().push(src);
    }
    let mut work: Vec<u64> = noreturn
        .iter()
        .copied()
        .filter(|n| preds.contains_key(n))
        .collect();
    let mut changed = false;
    while let Some(dst) = work.pop() {
        let Some(srcs) = preds.get(&dst) else {
            continue;
        };
        for &src in srcs {
            if noreturn.contains(&src) {
                continue;
            }
            let Some(left) = remaining.get_mut(&src) else {
                continue;
            };
            *left -= 1;
            if *left == 0 {
                noreturn.insert(src);
                changed = true;
                work.push(src);
            }
        }
    }
    changed
}

fn add_missed_import_thunks(
    functions: &mut Vec<DetectedFunction>,
    disasm: &DisasmResult,
    binary: &ParsedBinary,
) {
    let iat_slots: HashSet<u64> = binary
        .all_imports()
        .filter(|i| i.offset != 0)
        .map(|i| i.offset)
        .collect();
    if iat_slots.is_empty() {
        return;
    }
    let existing: HashSet<u64> = functions.iter().map(|f| f.entry).collect();
    let covered = FuncRanges::new(functions);
    let mut new_entries: Vec<(u64, u64)> = Vec::new();
    for ins in disasm.instructions.iter() {
        if ins.mnemonic != "jmp" {
            continue;
        }
        let ops = ins.ops();
        if !ops.starts_with('[') && !ops.contains("ptr [") {
            continue;
        }
        let size = ins.bytes.len() as u64;
        let Some(slot) = advanced::extract_iat_slot(&ops, ins.address, size) else {
            continue;
        };
        if iat_slots.contains(&slot)
            && !existing.contains(&ins.address)
            && !covered.strictly_inside_any(ins.address)
        {
            new_entries.push((ins.address, size));
        }
    }
    functions.extend(new_entries.into_iter().map(|(addr, size)| {
        new_discovered_function(
            addr,
            addr.saturating_add(size.max(1)),
            format!("ImportThunk_{:X}", addr),
        )
    }));
}

fn add_aligned_function_starts(
    functions: &mut Vec<DetectedFunction>,
    disasm: &DisasmResult,
    binary: &ParsedBinary,
) {
    let existing: HashSet<u64> = functions.iter().map(|f| f.entry).collect();
    let covered = FuncRanges::new(functions);
    let new_entries: Vec<(u64, u64)> = disasm
        .instructions
        .iter()
        .filter(|ins| ins.address % ALIGNED_START_ALIGNMENT == 0)
        .filter(|ins| matches!(ins.mnemonic, "ret" | "push" | "endbr64" | "endbr32"))
        .filter(|ins| {
            !existing.contains(&ins.address) && !covered.strictly_inside_any(ins.address)
        })
        .map(|ins| (ins.address, ins.bytes.len() as u64))
        .collect();
    if new_entries.is_empty() {
        return;
    }
    
    
    let mut starts: Vec<u64> = existing.into_iter().collect();
    starts.extend(new_entries.iter().map(|&(addr, _)| addr));
    starts.sort_unstable();
    starts.dedup();
    functions.extend(new_entries.into_iter().map(|(addr, size)| {
        let min_end = addr.saturating_add(size.max(1));
        new_discovered_function(
            addr,
            function_end(binary, &starts, addr, min_end),
            format!("sub_{:X}", addr),
        )
    }));
}

#[allow(dead_code)]
pub fn auto_analyze(disasm: &DisasmResult, binary: &ParsedBinary) -> AnalysisResult {
    static NEVER_CANCEL: AtomicBool = AtomicBool::new(false);
    auto_analyze_with_progress(
        disasm,
        binary,
        &HashMap::default(),
        &function_id::FunctionIDMatcher::new(),
        &NEVER_CANCEL,
        &|_, _, _, _| {},
    )
}

pub fn auto_analyze_with_progress(
    disasm: &DisasmResult,
    binary: &ParsedBinary,
    user_names: &HashMap<u64, String>,
    extra_fid: &function_id::FunctionIDMatcher,
    cancel: &AtomicBool,
    progress: ProgressFn,
) -> AnalysisResult {
    let debug_types = DebugTypes::load(binary, None);
    auto_analyze_inner(
        disasm,
        binary,
        user_names,
        &HashMap::default(),
        extra_fid,
        cancel,
        progress,
        debug_types,
    )
}



pub fn auto_analyze_with_source(
    disasm: &DisasmResult,
    binary: &ParsedBinary,
    source_path: Option<&str>,
    user_names: &HashMap<u64, String>,
    extra_fid: &function_id::FunctionIDMatcher,
    cancel: &AtomicBool,
    progress: ProgressFn,
) -> AnalysisResult {
    let pdb_names = debug_symbols::load_pdb_function_names(binary, source_path);
    let debug_types = DebugTypes::load(binary, source_path);
    auto_analyze_inner(
        disasm,
        binary,
        user_names,
        &pdb_names,
        extra_fid,
        cancel,
        progress,
        debug_types,
    )
}

#[allow(clippy::too_many_arguments)]
fn auto_analyze_inner(
    disasm: &DisasmResult,
    binary: &ParsedBinary,
    user_names: &HashMap<u64, String>,
    pdb_names: &HashMap<u64, String>,
    extra_fid: &function_id::FunctionIDMatcher,
    cancel: &AtomicBool,
    progress: ProgressFn,
    debug_types: Option<DebugTypes>,
) -> AnalysisResult {
    let debug_types = debug_types.map(Arc::new);
    let is_win64 = binary.format.starts_with("PE") || binary.format == "COFF";
    let total_phases = TOTAL_PHASES;
    let stopped = || cancel.load(Ordering::Relaxed);

    progress(
        "Function Discovery",
        "Scanning entry point, symbols, call targets, prologues",
        1,
        total_phases,
    );
    let mut unwind_extra = unwind::function_starts(binary);
    {
        let exec: Vec<(u64, u64)> = binary
            .sections
            .iter()
            .filter(|s| s.is_executable && s.size > 0)
            .map(|s| (s.vaddr, s.vaddr.saturating_add(s.size)))
            .collect();
        if !exec.is_empty() {
            for va in golang::pclntab_functions(&binary.data, &exec) {
                unwind_extra.push((va, FuncSource::UnwindInfo));
            }
        }
    }
    let mut dwarf_names: HashMap<u64, String> = HashMap::default();
    if binary.format == "ELF" && unwind::has_debug_info(binary) {
        for (addr, name) in dwarf_types::dwarf_function_names(binary) {
            unwind_extra.push((addr, FuncSource::SymbolTable));
            dwarf_names.entry(addr).or_insert(name);
        }
    }
    let mut functions = function::detect_functions_with_extra(
        &disasm.instructions,
        binary.entry_point,
        &binary.symbols,
        &unwind_extra,
        Some(cancel),
    );

    add_missed_import_thunks(&mut functions, disasm, binary);
    add_aligned_function_starts(&mut functions, disasm, binary);

    
    
    
    
    {
        let candidates = function::scan_data_pointer_candidates(
            binary,
            &disasm.instructions,
            MAX_DATA_POINTER_CANDIDATES,
        );
        if !candidates.is_empty() {
            let covered = FuncRanges::new(&functions);
            let extra: Vec<(u64, FuncSource)> = candidates
                .into_iter()
                .filter(|a| covered.find(*a).is_none())
                .map(|a| (a, FuncSource::DataPointer))
                .collect();
            if !extra.is_empty() {
                let mut all_extra = unwind_extra.clone();
                all_extra.extend(extra);
                functions = function::detect_functions_with_extra(
                    &disasm.instructions,
                    binary.entry_point,
                    &binary.symbols,
                    &all_extra,
                    Some(cancel),
                );
                add_missed_import_thunks(&mut functions, disasm, binary);
                add_aligned_function_starts(&mut functions, disasm, binary);
            }
        }
    }
    add_debug_function_starts(&mut functions, disasm, debug_types.as_deref());
    functions.sort_by_key(|f| f.entry);

    for func in functions.iter_mut() {
        if let Some(name) = pdb_names.get(&func.entry) {
            func.name.clone_from(name);
        }
        if let Some(name) = dwarf_names.get(&func.entry) {
            func.name.clone_from(name);
        }
    }
    drop(dwarf_names);
    if stopped() {
        return AnalysisResult::default();
    }

    progress(
        "NoReturn Analysis",
        "Detecting non-returning functions",
        2,
        total_phases,
    );
    let mut noreturn_analyzer = noreturn::NoReturnAnalyzer::new();
    noreturn_analyzer.analyze(
        &disasm.instructions,
        &binary.imports,
        &functions,
        Some(cancel),
    );
    let mut noreturn_functions = noreturn_analyzer.get_noreturn_functions().clone();

    function::apply_noreturn_ends(&mut functions, &disasm.instructions, &noreturn_functions);
    if stopped() {
        return AnalysisResult::default();
    }

    progress(
        "Name Demangling",
        "Demangling Rust/C++ function names",
        3,
        total_phases,
    );
    let rename = |func: &mut DetectedFunction| {
        if stopped() {
            return;
        }
        if let Some(usr) = user_names.get(&func.entry) {
            func.name.clone_from(usr);
            return;
        }
        let demangled = demangle::demangle_name(&func.name);
        if demangled != func.name {
            func.name = demangled;
        }
    };
    if functions.len() >= crate::util::parallel::PAR_FUNCS {
        use rayon::prelude::*;
        crate::util::parallel::install(|| functions.par_iter_mut().for_each(rename));
    } else {
        functions.iter_mut().for_each(&rename);
    }
    if stopped() {
        return AnalysisResult::default();
    }

    progress(
        "Stub Detection",
        "Finding import thunks and tail calls",
        4,
        total_phases,
    );
    let stubs = advanced::build_stub_map(&disasm.instructions, &functions, binary, Some(cancel));
    if stopped() {
        return AnalysisResult::default();
    }
    apply_import_thunk_names(&mut functions, &stubs, user_names);
    {
        let stub_by_entry: HashMap<u64, &StubInfo> =
            stubs.values().map(|s| (s.func_entry, s)).collect();
        for f in functions.iter_mut() {
            if let Some(stub) = stub_by_entry.get(&f.entry) {
                match stub.kind {
                    StubKind::ImportThunk => {
                        f.is_thunk = true;
                        f.thunk_target = None;
                    }
                    StubKind::TailCall => {
                        f.is_thunk = true;
                        f.thunk_target = stub.target_addr;
                    }
                }
            }
        }
    }
    {
        let thunk_edges: Vec<(u64, u64)> = functions
            .iter()
            .filter(|f| f.is_thunk)
            .filter_map(|f| f.thunk_target.map(|t| (f.entry, t)))
            .collect();
        if propagate_noreturn(&thunk_edges, &mut noreturn_functions) {
            function::apply_noreturn_ends(
                &mut functions,
                &disasm.instructions,
                &noreturn_functions,
            );
        }
    }

    progress(
        "Reference Analysis",
        &format!(
            "Building xref database ({} insns)",
            disasm.instructions.len()
        ),
        5,
        total_phases,
    );
    let mut xrefs = xref::build_xrefs(&disasm.instructions, binary, Some(cancel));
    if stopped() {
        return AnalysisResult::default();
    }
    for stub in stubs.values() {
        let from = if stub.jump_addr != 0 {
            stub.jump_addr
        } else {
            stub.func_entry
        };
        match stub.kind {
            StubKind::TailCall => {
                if let Some(target) = stub.target_addr {
                    xrefs.add_ref(
                        from,
                        target,
                        XRefKind::TailCall,
                        stub.target_name.clone(),
                        0,
                    );
                    xrefs.add_ref(from, target, XRefKind::Thunk, stub.target_name.clone(), -2);
                }
            }
            StubKind::ImportThunk => {
                if let Some(slot) =
                    crate::analysis::import_xref::resolve_iat_slot(binary, &stub.target_name)
                {
                    xrefs.add_ref(from, slot, XRefKind::Thunk, stub.target_name.clone(), -2);
                }
            }
        }
    }
    {
        let entry_set: HashSet<u64> = functions.iter().map(|f| f.entry).collect();
        let ranges = FuncRanges::new(&functions);
        const COLD_SUFFIXES: &[&str] = &[".cold", "_cold", "$cold"];
        let cold_set: HashSet<u64> = functions
            .iter()
            .filter(|f| COLD_SUFFIXES.iter().any(|s| f.name.ends_with(s)))
            .map(|f| f.entry)
            .collect();
        let jmp_addrs: HashSet<u64> = disasm
            .instructions
            .iter()
            .filter(|i| i.mnemonic == "jmp")
            .map(|i| i.address)
            .collect();
        let mut jumps: Vec<(u64, u64)> = Vec::new();
        let mut tail_set: HashSet<(u64, u64)> = HashSet::default();
        let mut flow_targets: HashMap<u64, (u64, bool)> = HashMap::default();
        for x in &xrefs.all {
            if x.kind.is_flow() {
                let slot = flow_targets.entry(x.from).or_insert((x.to, false));
                slot.1 |= slot.0 != x.to;
            }
            match x.kind {
                XRefKind::Jump => jumps.push((x.from, x.to)),
                XRefKind::TailCall => {
                    tail_set.insert((x.from, x.to));
                }
                _ => {}
            }
        }
        let shared_guard = |&(from, to): &(u64, u64)| -> bool {
            entry_set.contains(&to)
                && !cold_set.contains(&to)
                && !tail_set.contains(&(from, to))
                && jmp_addrs.contains(&from)
                && !flow_targets.get(&from).is_some_and(|&(_, multi)| multi)
                && ranges.find(from).is_some_and(|(func, func_end)| {
                    !cold_set.contains(&func) && func != to && !(to > func && to < func_end)
                })
        };
        let to_add: Vec<(u64, u64)> = if jumps.len() >= crate::util::parallel::PAR_INSNS {
            use rayon::prelude::*;
            crate::util::parallel::install(|| {
                jumps
                    .par_iter()
                    .filter(|x| shared_guard(x))
                    .copied()
                    .collect()
            })
        } else {
            jumps.into_iter().filter(|p| shared_guard(p)).collect()
        };
        for (from, to) in to_add {
            xrefs.add_ref(from, to, XRefKind::TailCall, String::new(), 0);
        }
        let mut ret_addrs: Vec<u64> = disasm
            .instructions
            .iter()
            .filter(|i| i.mnemonic.starts_with("ret"))
            .map(|i| i.address)
            .collect();
        ret_addrs.sort_unstable();
        let has_ret = |start: u64, end: u64| -> bool {
            let i = ret_addrs.partition_point(|&a| a < start);
            ret_addrs.get(i).is_some_and(|&a| a < end)
        };
        let tail_edges: Vec<(u64, u64)> = xrefs
            .all
            .iter()
            .filter(|x| matches!(x.kind, XRefKind::TailCall))
            .filter_map(|x| {
                let (src, src_end) = ranges.find(x.from)?;
                (!has_ret(src, src_end)).then_some((src, x.to))
            })
            .collect();
        if propagate_noreturn(&tail_edges, &mut noreturn_functions) {
            function::apply_noreturn_ends(
                &mut functions,
                &disasm.instructions,
                &noreturn_functions,
            );
        }
    }
    if stopped() {
        return AnalysisResult::default();
    }

    functions.sort_by(|a, b| a.entry.cmp(&b.entry).then(b.end.cmp(&a.end)));
    functions.dedup_by_key(|f| f.entry);

    {
        let ranges = FuncRanges::new(&functions);
        let mut reg_sites: Vec<(u64, (u64, u64), bool, String)> = Vec::new();
        for x in xrefs.all.iter() {
            let is_call = match x.kind {
                XRefKind::CallIndirect => true,
                XRefKind::JumpIndirect => false,
                _ => continue,
            };
            if x.to != 0 {
                continue;
            }
            let Some(reg) = x
                .note
                .as_ref()
                .filter(|n| crate::analysis::types::is_register(n))
            else {
                continue;
            };
            if let Some(func) = ranges.find(x.from) {
                reg_sites.push((x.from, func, is_call, reg.to_string()));
            }
        }
        reg_sites.sort_by_key(|&(_, (entry, _), _, _)| entry);
        if !reg_sites.is_empty() {
            let mut recovered: Vec<(u64, u64, bool)> = Vec::new();
            let mut last_entry: Option<u64> = None;
            let mut cp = constprop::ConstantPropagator::new();
            for (site, (func_entry, func_end), is_call, reg) in &reg_sites {
                if last_entry != Some(*func_entry) {
                    cp.propagate(&disasm.instructions, *func_entry, *func_end);
                    last_entry = Some(*func_entry);
                }
                if let Some(constprop::RegValue::Known(v)) = cp.get_register_value(reg)
                    && v != 0 && xref::direct_target_ok(binary, v) {
                        recovered.push((*site, v, *is_call));
                    }
            }
            let mut known: HashSet<u64> = functions.iter().map(|f| f.entry).collect();
            for &(site, target, is_call) in &recovered {
                let kind = if is_call {
                    XRefKind::Call
                } else {
                    XRefKind::Jump
                };
                xrefs.add_ref(site, target, kind, "const-recovered".to_string(), 0);
                if known.insert(target) {
                    let name = user_names
                        .get(&target)
                        .cloned()
                        .unwrap_or_else(|| format!("sub_{:X}", target));
                    functions.push(new_discovered_function(target, target, name));
                }
            }
            if !recovered.is_empty() {
                functions.sort_by_key(|f| f.entry);
            }
        }
    }

    let func_count = functions.len();
    let mut cfgs: HashMap<u64, CFG> =
        HashMap::with_capacity_and_hasher(func_count, Default::default());
    if func_count < crate::util::parallel::PAR_FUNCS {
        for (i, func) in functions.iter().enumerate() {
            if i % 32 == 0 {
                progress(
                    "CFG Construction",
                    &format!("Building basic blocks ({}/{})", i, func_count),
                    6,
                    total_phases,
                );
            }
            if stopped() {
                break;
            }
            let c = cfg::build_cfg(&disasm.instructions, func.entry, func.end);
            if !c.blocks.is_empty() {
                cfgs.insert(func.entry, c);
            }
        }
    } else {
        use rayon::prelude::*;
        use std::sync::atomic::AtomicUsize;
        let done = AtomicUsize::new(0);
        let insns_ref = &disasm.instructions;
        let partials: Vec<(u64, CFG)> = crate::util::parallel::install(|| {
            functions
                .par_iter()
                .filter_map(|func| {
                    if cancel.load(Ordering::Relaxed) {
                        return None;
                    }
                    let c = cfg::build_cfg(insns_ref, func.entry, func.end);
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if d.is_multiple_of(32) {
                        progress(
                            "CFG Construction",
                            &format!(
                                "Building basic blocks ({}/{})",
                                d.min(func_count),
                                func_count
                            ),
                            6,
                            total_phases,
                        );
                    }
                    if c.blocks.is_empty() {
                        None
                    } else {
                        Some((func.entry, c))
                    }
                })
                .collect()
        });
        cfgs.extend(partials);
    }
    if stopped() {
        return AnalysisResult::default();
    }

    let mut stack_frames: HashMap<u64, StackFrame> =
        HashMap::with_capacity_and_hasher(cfgs.len(), Default::default());
    if func_count < crate::util::parallel::PAR_FUNCS {
        for (i, func) in functions.iter().enumerate() {
            if i % 64 == 0 {
                progress(
                    "Stack Analysis",
                    &format!("Analyzing locals/params ({}/{})", i, func_count),
                    7,
                    total_phases,
                );
            }
            if stopped() {
                break;
            }
            if !cfgs.contains_key(&func.entry) {
                continue;
            }
            let func_pinstrs = pcode::lift_func(&disasm.instructions, func.entry, func.end);
            let sf = stack::analyze_stack(
                &func_pinstrs,
                func.entry,
                func.end,
                func.has_frame,
                func.stack_size,
            );
            stack_frames.insert(func.entry, sf);
        }
    } else {
        use rayon::prelude::*;
        use std::sync::atomic::AtomicUsize;
        let done = AtomicUsize::new(0);
        let stack_total = cfgs.len();
        let insns_ref = &disasm.instructions;
        let partials: Vec<(u64, StackFrame)> = crate::util::parallel::install(|| {
            functions
                .par_iter()
                .filter(|f| cfgs.contains_key(&f.entry))
                .filter_map(|func| {
                    if cancel.load(Ordering::Relaxed) {
                        return None;
                    }
                    let func_pinstrs = pcode::lift_func(insns_ref, func.entry, func.end);
                    let sf = stack::analyze_stack(
                        &func_pinstrs,
                        func.entry,
                        func.end,
                        func.has_frame,
                        func.stack_size,
                    );
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if d.is_multiple_of(64) {
                        progress(
                            "Stack Analysis",
                            &format!(
                                "Analyzing locals/params ({}/{})",
                                d.min(stack_total),
                                stack_total
                            ),
                            7,
                            total_phases,
                        );
                    }
                    Some((func.entry, sf))
                })
                .collect()
        });
        for (entry, sf) in partials {
            stack_frames.insert(entry, sf);
        }
    }
    if stopped() {
        return AnalysisResult::default();
    }

    let mut func_lookup: HashMap<u64, String> = functions
        .iter()
        .map(|f| (f.entry, f.name.clone()))
        .collect();
    let thunk_targets: HashMap<u64, u64> = functions
        .iter()
        .filter_map(|f| f.thunk_target.map(|t| (f.entry, t)))
        .collect();
    for (&from, &to) in &thunk_targets {
        if let Some(name) = func_lookup.get(&to).cloned() {
            func_lookup.insert(from, name);
        }
    }

    let import_lookup: HashMap<u64, String> = binary
        .all_imports()
        .filter(|imp| imp.offset != 0 && !imp.name.is_empty())
        .map(|imp| {
            let full = if imp.name.contains('!') || imp.library.is_empty() {
                imp.name.clone()
            } else {
                format!("{}!{}", imp.library, imp.name)
            };
            (imp.offset, full)
        })
        .collect();

    let mut decompilable: Vec<&DetectedFunction> = functions
        .iter()
        .filter(|f| matches!(cfgs.get(&f.entry), Some(c) if c.blocks.len() <= MAX_EAGER_BLOCKS))
        .collect();
    decompilable.sort_by_key(|f| {
        std::cmp::Reverse(xrefs.by_to.get(&f.entry).map_or(0, |v| v.len()))
    });
    let eager_decompile_cap: usize = std::env::var("RD_MAX_DECOMP")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_EAGER_DECOMPILE_CAP);
    decompilable.truncate(eager_decompile_cap);
    let dec_total = decompilable.len();

    let pseudocode = decompile_parallel(DecompileJob {
        funcs: &decompilable,
        cfgs: &cfgs,
        stack_frames: &stack_frames,
        all_insns: &disasm.instructions,
        func_lookup: &func_lookup,
        import_lookup: &import_lookup,
        cancel,
        is64: disasm.arch.contains("64"),
        is_win64,
        debug_types: debug_types.as_ref(),
        thunk_targets: &thunk_targets,
        progress_fn: &|name, i| {
            if i % 8 == 0 {
                progress(
                    "Decompilation",
                    &format!("Decompiling {} ({}/{})", name, i, dec_total),
                    8,
                    total_phases,
                );
            }
        },
    });
    if stopped() {
        return AnalysisResult::default();
    }

    progress("Switch Recovery", "Detecting jump tables", 9, total_phases);
    let switches = advanced::detect_switch_tables(&disasm.instructions, binary, Some(cancel));

    progress(
        "Call Graph",
        "Building caller/callee relationships",
        10,
        total_phases,
    );
    let mut callers: HashMap<u64, Vec<u64>> = HashMap::default();
    let mut callees: HashMap<u64, Vec<u64>> = HashMap::default();

    let func_ranges = FuncRanges::new(&functions);

    let entry_set: HashSet<u64> = functions.iter().map(|f| f.entry).collect();

    let thunk_map: HashMap<u64, u64> = {
        let direct: HashMap<u64, u64> = functions
            .iter()
            .filter(|f| f.is_thunk)
            .filter_map(|f| f.thunk_target.map(|t| (f.entry, t)))
            .collect();
        let mut resolved: HashMap<u64, u64> = HashMap::default();
        for f in functions.iter().filter(|f| f.is_thunk) {
            let mut cur = f.entry;
            let mut seen: HashSet<u64> = HashSet::default();
            loop {
                if !seen.insert(cur) {
                    break;
                }
                match direct.get(&cur) {
                    Some(next) => {
                        cur = *next;
                    }
                    None => break,
                }
            }
            if cur != f.entry && entry_set.contains(&cur) {
                resolved.insert(f.entry, cur);
            }
        }
        resolved
    };
    let resolve_thunk = |entry: u64| -> u64 { thunk_map.get(&entry).copied().unwrap_or(entry) };

    let find_func = |addr: u64| -> Option<u64> { func_ranges.find(addr).map(|(entry, _)| entry) };

    let mut edges: Vec<(u64, u64)> = if xrefs.all.len() >= crate::util::parallel::PAR_INSNS {
        use rayon::prelude::*;
        crate::util::parallel::install(|| {
            xrefs
                .all
                .par_iter()
                .filter_map(|xr| {
                    if cancel.load(Ordering::Relaxed) {
                        return None;
                    }
                    if !matches!(
                        xr.kind,
                        XRefKind::Call | XRefKind::TailCall | XRefKind::CallIndirect
                    ) {
                        return None;
                    }
                    let from_func = find_func(xr.from)?;
                    let to_func = if entry_set.contains(&xr.to) {
                        Some(xr.to)
                    } else {
                        find_func(xr.to)
                    };
                    to_func.map(|to| (from_func, resolve_thunk(to)))
                })
                .collect()
        })
    } else {
        let mut edges = Vec::new();
        for (xi, xr) in xrefs.all.iter().enumerate() {
            if xi % 65536 == 0 && stopped() {
                return AnalysisResult::default();
            }
            if !matches!(
                xr.kind,
                XRefKind::Call | XRefKind::TailCall | XRefKind::CallIndirect
            ) {
                continue;
            }
            let from_func = find_func(xr.from);
            let to_func = if entry_set.contains(&xr.to) {
                Some(xr.to)
            } else {
                find_func(xr.to)
            };
            if let (Some(fr), Some(to)) = (from_func, to_func) {
                edges.push((fr, resolve_thunk(to)));
            }
        }
        edges
    };
    edges.sort_unstable();
    edges.dedup();
    if stopped() {
        return AnalysisResult::default();
    }
    for (fr, to) in edges {
        callees.entry(fr).or_default().push(to);
        callers.entry(to).or_default().push(fr);
    }

    progress(
        "PE Resources",
        "Analyzing PE resources and debug symbols",
        11,
        total_phases,
    );
    let mut pe_res = pe_resources::PEResourceAnalyzer::new();
    pe_res.analyze(binary);
    let pe_resources = if pe_res.get_resource_count() > 0 {
        Some(pe_res)
    } else {
        None
    };

    let mut debug_sym = debug_symbols::DebugSymbolsAnalyzer::new();
    debug_sym.analyze(binary);
    let debug_symbols = if !debug_sym.symbols.is_empty() {
        Some(debug_sym)
    } else {
        None
    };

    progress(
        "FunctionID",
        "Matching known function signatures",
        12,
        total_phases,
    );
    let mut fid_matcher = function_id::FunctionIDMatcher::new();
    fid_matcher.merge(extra_fid);
    fid_matcher.set_reloc_mask(&binary.relocations);
    let bodies: Vec<(u64, u64)> = functions.iter().map(|f| (f.entry, f.end)).collect();
    let function_signatures = fid_matcher
        .identify_with_context(
            &disasm.instructions,
            &bodies,
            &callers,
            &callees,
            Some(cancel),
        )
        .into_iter()
        .map(|(k, m)| {
            (
                k,
                function_id::FunctionSignature {
                    hash: m.full,
                    specific: m.specific,
                    name: m.name,
                    library: m.library,
                    size: m.size,
                    score: m.score,
                },
            )
        })
        .collect();

    progress(
        "Type Reconstruction",
        "Rebuilding structs and pointer chains",
        13,
        total_phases,
    );
    let mut type_recon = type_reconstruction::TypeReconstructor::new();
    let eligible: Vec<&DetectedFunction> = functions
        .iter()
        .filter(|f| !matches!(cfgs.get(&f.entry), Some(c) if c.blocks.len() > MAX_EAGER_BLOCKS))
        .collect();
    if eligible.len() < crate::util::parallel::PAR_FUNCS {
        for (i, func) in eligible.iter().enumerate() {
            if i % 64 == 0 && stopped() {
                return AnalysisResult::default();
            }
            let func_pinstrs = pcode::lift_func(&disasm.instructions, func.entry, func.end);
            type_recon.analyze_function(&func_pinstrs, func.entry, func.end);
        }
    } else {
        use rayon::prelude::*;
        const LIFT_CHUNK: usize = 512;
        let insns_ref = &disasm.instructions;
        for start in (0..eligible.len()).step_by(LIFT_CHUNK) {
            let stop = (start + LIFT_CHUNK).min(eligible.len());
            let lifts: Vec<(u64, u64, Vec<pcode::PInstr>)> =
                crate::util::parallel::install(|| {
                    eligible[start..stop]
                        .par_iter()
                        .filter_map(|func| {
                            if cancel.load(Ordering::Relaxed) {
                                return None;
                            }
                            let pinstrs = pcode::lift_func(insns_ref, func.entry, func.end);
                            Some((func.entry, func.end, pinstrs))
                        })
                        .collect()
                });
            if stopped() {
                return AnalysisResult::default();
            }
            for (i_in, (entry, func_end, pinstrs)) in lifts.iter().enumerate() {
                let i = start + i_in;
                if i % 64 == 0 && stopped() {
                    return AnalysisResult::default();
                }
                type_recon.analyze_function(pinstrs, *entry, *func_end);
            }
        }
    }
    let reconstructed_types = type_recon.get_all_types().clone();
    if stopped() {
        return AnalysisResult::default();
    }

    progress("Done", "Analysis complete", total_phases, total_phases);

    AnalysisResult {
        functions,
        xrefs,
        cfgs,
        stack_frames,
        pseudocode,
        callers,
        callees,
        stubs,
        switches,
        noreturn_functions,
        pe_resources,
        debug_symbols,
        function_signatures,
        reconstructed_types,
        debug_types,
        is_win64,
    }
}

fn add_debug_function_starts(
    functions: &mut Vec<function::DetectedFunction>,
    disasm: &DisasmResult,
    debug_types: Option<&DebugTypes>,
) {
    let Some(debug) = debug_types else {
        return;
    };
    if debug.functions.is_empty() {
        return;
    }
    let last_addr = disasm
        .instructions
        .iter()
        .map(|i| i.address.saturating_add(i.bytes.len() as u64))
        .max()
        .unwrap_or(0);
    let entries: Vec<u64> = functions.iter().map(|f| f.entry).collect();
    let mut added = Vec::new();
    for (&addr, sig) in &debug.functions {
        if addr == 0 || entries.contains(&addr) {
            continue;
        }
        let end = entries
            .iter()
            .copied()
            .filter(|&e| e > addr)
            .min()
            .unwrap_or(last_addr)
            .max(addr.saturating_add(1));
        added.push(function::DetectedFunction {
            entry: addr,
            end,
            name: sig.name.clone(),
            stack_size: 0,
            source: function::FuncSource::SymbolTable,
            has_frame: false,
            is_thunk: false,
            thunk_target: None,
        });
    }
    if !added.is_empty() {
        functions.extend(added);
    }
}

fn apply_import_thunk_names(
    functions: &mut [DetectedFunction],
    stubs: &HashMap<u64, StubInfo>,
    user_names: &HashMap<u64, String>,
) {
    let mut used: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
    for f in functions.iter_mut() {
        if user_names.contains_key(&f.entry) {
            continue;
        }
        let Some(stub) = stubs.get(&f.entry) else {
            continue;
        };
        if !matches!(stub.kind, StubKind::ImportThunk) {
            continue;
        }
        let Some((_, short)) = stub.target_name.rsplit_once('!') else {
            if stub.target_name.starts_with('[') || stub.target_name.contains("ptr [") {
                let cand = format!("ImportThunk_{:X}", f.entry);
                if !used.contains(&cand) {
                    used.insert(cand.clone());
                    f.name = cand;
                }
            }
            continue;
        };
        let short = short.trim();
        if short.is_empty()
            || !short
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@' || c == '$')
        {
            continue;
        }
        if f.name == short {
            continue;
        }
        let base = demangle::demangle_name(short);
        let mut candidate = base.clone();
        let mut n = 2;
        while used.contains(&candidate) {
            candidate = format!("{}_{}", base, n);
            n += 1;
        }
        used.insert(candidate.clone());
        f.name = candidate;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(entry: u64, end: u64) -> DetectedFunction {
        new_discovered_function(entry, end, format!("f_{entry:X}"))
    }

    #[test]
    fn func_ranges_find_uses_last_entry_at_or_before_addr() {
        let r = FuncRanges::new(&[func(0x20, 0x30), func(0x10, 0x18)]);
        assert_eq!(r.find(0x0F), None);
        assert_eq!(r.find(0x10), Some((0x10, 0x18)));
        assert_eq!(r.find(0x17), Some((0x10, 0x18)));
        assert_eq!(r.find(0x18), None);
        assert_eq!(r.find(0x2F), Some((0x20, 0x30)));
        assert_eq!(r.find(0x30), None);
    }

    #[test]
    fn strictly_inside_any_handles_nested_functions() {
        let r = FuncRanges::new(&[func(0x100, 0x200), func(0x120, 0x140)]);
        assert!(r.strictly_inside_any(0x130));
        assert!(r.strictly_inside_any(0x150));
        assert!(!r.strictly_inside_any(0x100), "an entry is not strictly inside itself");
        assert!(!r.strictly_inside_any(0x200));
        assert!(!r.strictly_inside_any(0x50));
    }

    #[test]
    fn noreturn_propagates_through_chains_regardless_of_edge_order() {
        let mut noreturn: HashSet<u64> = HashSet::default();
        noreturn.insert(3);
        let edges = [(1, 2), (2, 3)];
        assert!(propagate_noreturn(&edges, &mut noreturn));
        assert!(noreturn.contains(&1) && noreturn.contains(&2));
        assert!(!propagate_noreturn(&edges, &mut noreturn), "second run is a no-op");
    }

    #[test]
    fn noreturn_requires_every_distinct_tail_target_to_be_noreturn() {
        let mut noreturn: HashSet<u64> = HashSet::default();
        noreturn.insert(10);
        noreturn.insert(20);
        
        
        let edges = [(1, 10), (1, 20), (1, 20), (2, 10), (2, 99), (3, 10)];
        assert!(propagate_noreturn(&edges, &mut noreturn));
        assert!(noreturn.contains(&1));
        assert!(noreturn.contains(&3));
        assert!(!noreturn.contains(&2));
    }

    #[test]
    fn noreturn_is_not_inferred_from_a_returning_or_empty_target_set() {
        let mut noreturn: HashSet<u64> = HashSet::default();
        noreturn.insert(10);
        let edges = [(1, 10), (1, 11)];
        assert!(!propagate_noreturn(&edges, &mut noreturn));
        assert!(!noreturn.contains(&1));

        let mut empty_targets: HashSet<u64> = HashSet::default();
        assert!(!propagate_noreturn(&[], &mut empty_targets));
        assert!(empty_targets.is_empty());
    }
}
