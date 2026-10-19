use super::super::decompiler::{self, pcode, Pseudocode};
use super::super::flow::cfg::{self, CFG};
use super::super::flow::function::DetectedFunction;
use super::super::flow::stack::{self, StackFrame};
use super::AnalysisResult;
use crate::analysis::symbols::debug_types::DebugTypes;
use crate::disasm::DisasmResult;
use rustc_hash::FxHashMap as HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub(crate) struct DecompileJob<'a> {
    pub funcs: &'a [&'a DetectedFunction],
    pub cfgs: &'a HashMap<u64, CFG>,
    pub stack_frames: &'a HashMap<u64, StackFrame>,
    pub all_insns: &'a [crate::disasm::DisasmInstruction],
    pub func_lookup: &'a HashMap<u64, String>,
    pub import_lookup: &'a HashMap<u64, String>,
    pub debug_types: Option<&'a Arc<DebugTypes>>,
    pub cancel: &'a AtomicBool,
    pub is64: bool,
    pub progress_fn: &'a (dyn Fn(&str, usize) + Send + Sync),
}

pub(crate) fn decompile_parallel(job: DecompileJob<'_>) -> HashMap<u64, Pseudocode> {
    let DecompileJob {
        funcs,
        cfgs,
        stack_frames,
        all_insns,
        func_lookup,
        import_lookup,
        debug_types,
        cancel,
        is64,
        progress_fn,
    } = job;
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let counter = AtomicUsize::new(0);

    let all: HashMap<u64, Pseudocode> = crate::util::parallel::install(|| {
        funcs
            .par_iter()
            .filter_map(|func| {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let c = match cfgs.get(&func.entry) {
                    Some(c) => c,
                    None => return None,
                };
                let sf = match stack_frames.get(&func.entry) {
                    Some(s) => s,
                    None => return None,
                };

                let func_pinstrs = pcode::lift_func(all_insns, func.entry, func.end);

                let pc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decompiler::decompile(decompiler::LiftInput {
                        cfg: c,
                        pinstrs_in_func: &func_pinstrs,
                        imap: all_insns,
                        stack: sf,
                        func_name: &func.name,
                        func_lookup,
                        is64,
                        imports: import_lookup,
                        debug_types,
                        cancel: Some(cancel),
                    })
                }))
                .ok();
                let pc = match pc {
                    Some(pc) => pc,
                    None => return None,
                };
                let done = counter.fetch_add(1, Ordering::Relaxed) + 1;
                if done.is_multiple_of(8) {
                    progress_fn(&func.name, done);
                }
                Some((func.entry, pc))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect()
    });
    all
}

pub fn decompile_on_demand(
    disasm: &crate::disasm::DisasmResult,
    binary: &crate::parser::ParsedBinary,
    analysis: &mut AnalysisResult,
    addr: u64,
) -> Result<u64, String> {
    let entry = analysis
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
        .map(|f| f.entry)
        .ok_or("Address not in any function")?;
    if analysis.pseudocode.contains_key(&entry) {
        return Ok(entry);
    }
    let all_imports: Vec<crate::parser::Import> = binary.all_imports().cloned().collect();
    let (c, sf, pc) = decompile_snapshot(disasm, &all_imports, analysis, addr)?;
    analysis.cfgs.insert(entry, c);
    analysis.stack_frames.insert(entry, sf);
    analysis.pseudocode.insert(entry, pc);
    Ok(entry)
}

pub fn decompile_snapshot(
    disasm: &DisasmResult,
    imports: &[crate::parser::Import],
    analysis: &AnalysisResult,
    addr: u64,
) -> Result<(CFG, StackFrame, Pseudocode), String> {
    let f = analysis
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
        .ok_or("Address not in any function")?;
    let c = if let Some(c) = analysis.cfgs.get(&f.entry) {
        c.clone()
    } else {
        let c = cfg::build_cfg(&disasm.instructions, f.entry, f.end);
        if c.blocks.is_empty() {
            return Err("CFG is empty (no instructions in range)".into());
        }
        c
    };
    if c.blocks.len() > decompiler::MAX_DECOMP_BLOCKS {
        return Err(format!(
            "{} blocks exceeds MAX_DECOMP_BLOCKS={}",
            c.blocks.len(),
            decompiler::MAX_DECOMP_BLOCKS
        ));
    }
    let sf = if let Some(sf) = analysis.stack_frames.get(&f.entry) {
        sf.clone()
    } else {
        let fp = pcode::lift_func(&disasm.instructions, f.entry, f.end);

        stack::analyze_stack(&fp, f.entry, f.end, f.has_frame, f.stack_size)
    };
    let func_pinstrs = pcode::lift_func(&disasm.instructions, f.entry, f.end);
    let func_lookup: HashMap<u64, String> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.clone()))
        .collect();
    let import_lookup: HashMap<u64, String> = imports
        .iter()
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
    let fname = f.name.clone();
    let is64 = disasm.arch.contains("64");
    let pc = if c.blocks.len() > decompiler::BIG_STACK_BLOCKS {
        let imap_arc = disasm.instructions.clone();
        let debug_types = analysis.debug_types.clone();
        std::thread::Builder::new()
            .name("decompile-big".into())
            .stack_size(decompiler::BIG_STACK_SIZE)
            .spawn(move || {
                let pc = decompiler::decompile(decompiler::LiftInput {
                    cfg: &c,
                    pinstrs_in_func: &func_pinstrs,
                    imap: &imap_arc,
                    stack: &sf,
                    func_name: &fname,
                    func_lookup: &func_lookup,
                    is64,
                    imports: &import_lookup,
                    debug_types: debug_types.as_ref(),
                    cancel: None,
                });
                (c, sf, pc)
            })
            .map_err(|e| {
                format!(
                    "cannot spawn decompile thread ({} MiB stack): {e}",
                    decompiler::BIG_STACK_SIZE >> 20
                )
            })?
            .join()
            .map_err(|_| "decompiler panicked on this function".to_string())?
    } else {
        let pc = decompiler::decompile(decompiler::LiftInput {
            cfg: &c,
            pinstrs_in_func: &func_pinstrs,
            imap: &disasm.instructions,
            stack: &sf,
            func_name: &fname,
            func_lookup: &func_lookup,
            is64,
            imports: &import_lookup,
            debug_types: analysis.debug_types.as_ref(),
            cancel: None,
        });
        (c, sf, pc)
    };
    Ok(pc)
}
