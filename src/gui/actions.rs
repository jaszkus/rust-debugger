use super::state::*;

pub(crate) fn va_for_offset(sections: &[crate::parser::Section], off: u64) -> u64 {
    for s in sections {
        if off >= s.offset && off < s.offset.saturating_add(s.size) {
            return s.vaddr + (off - s.offset);
        }
    }
    0
}

pub(crate) fn offset_for_va(sections: &[crate::parser::Section], va: u64) -> Option<u64> {
    for s in sections {
        if va >= s.vaddr && va < s.vaddr.saturating_add(s.size) {
            return Some(s.offset + (va - s.vaddr));
        }
    }
    None
}

pub(crate) fn functions_filtered(
    analysis: &crate::analysis::AnalysisResult,
    filter_lc: &str,
    sort_idx: usize,
) -> Vec<usize> {
    let mut out: Vec<usize> = (0..analysis.functions.len())
        .filter(|&i| {
            if filter_lc.is_empty() {
                return true;
            }
            let f = &analysis.functions[i];
            crate::gui::views::contains_ci(&f.name, filter_lc) || {
                let mut buf = [0u8; 16];
                let hex = format_hex_small(f.entry, &mut buf);
                crate::gui::views::contains_ci(hex, filter_lc)
            }
        })
        .collect();
    match sort_idx {
        1 => out.sort_by(|&a, &b| analysis.functions[a].name.cmp(&analysis.functions[b].name)),
        2 => out.sort_by(|&a, &b| {
            let sa = analysis.functions[a].end - analysis.functions[a].entry;
            let sb = analysis.functions[b].end - analysis.functions[b].entry;
            sb.cmp(&sa)
        }),
        3 => out.sort_by(|&a, &b| {
            let xa = analysis
                .xrefs
                .by_to
                .get(&analysis.functions[a].entry)
                .map(|v| v.len())
                .unwrap_or(0);
            let xb = analysis
                .xrefs
                .by_to
                .get(&analysis.functions[b].entry)
                .map(|v| v.len())
                .unwrap_or(0);
            xb.cmp(&xa)
        }),
        _ => out.sort_by_key(|&i| analysis.functions[i].entry),
    }
    out
}

pub(crate) fn toggle_mcp(state: &mut AppState) {
    if state.mcp_server.is_some() {
        if let Some(mut srv) = state.mcp_server.take() {
            srv.stop();
        }
        state.mcp_started_ms = None;
        state.status_msg = "MCP server stopped".into();
    } else {
        if let Err(e) = state.apply_mcp_port_buf() {
            state.status_msg = e;
            return;
        }
        let shared = match state.mcp_shared_state.clone() {
            Some(s) => s,
            None => {
                state.status_msg = "MCP shared state not initialized".into();
                return;
            }
        };
        match crate::mcp::McpServer::start(state.mcp_port, shared) {
            Ok(srv) => {
                state.status_msg = format!(
                    "MCP server started at http://127.0.0.1:{}/mcp",
                    srv.actual_port
                );
                state.mcp_port = srv.actual_port;
                state.mcp_started_ms = Some(crate::mcp::tools::activity::now_ms());
                state.mcp_server = Some(srv);
            }
            Err(e) => {
                state.status_msg = format!("MCP start failed: {}", e);
            }
        }
    }
}




pub(crate) fn auto_import_debug_types(state: &mut AppState) {
    if state.program.types.len() > 16 {
        return;
    }
    let file_path = state.program.file_path.clone();
    let source_path = (!file_path.is_empty()).then_some(file_path.as_str());
    let Some(bin) = state.program.binary.as_ref() else {
        return;
    };
    if bin.format.starts_with("PE") || bin.format == "COFF" {
        let Some(stats) = crate::analysis::symbols::pdb_types::import_pdb_types_from_binary(
            bin,
            source_path,
            &mut state.program.types,
        ) else {
            return;
        };
        let total = stats.structs + stats.unions + stats.enums + stats.typedefs;
        if total > 0 {
            state.status_msg = format!(
                "Imported PDB types: {} structs, {} unions, {} enums, {} typedefs",
                stats.structs, stats.unions, stats.enums, stats.typedefs
            );
        }
    } else if bin.format == "ELF" {
        let stats =
            crate::analysis::symbols::dwarf_types::import_dwarf_types(bin, &mut state.program.types);
        let total = stats.structs + stats.unions + stats.enums + stats.typedefs;
        if total > 0 {
            state.status_msg = format!(
                "Imported DWARF types: {} structs, {} unions, {} enums, {} typedefs",
                stats.structs, stats.unions, stats.enums, stats.typedefs
            );
        }
    }
}

pub(crate) fn run_analysis(state: &mut AppState) {
    if state.analysis_progress.is_some() {
        state.status_msg = "Analysis already running".into();
        return;
    }
    if let (Some(disasm), Some(bin)) = (state.disasm.clone(), state.binary.clone()) {
        state.status_msg = "Starting analysis...".into();
        let user_names = state.user_func_names.clone();
        let fid_shared = state.fid_shared();
        let source_path = (!state.file_path.is_empty()).then(|| state.file_path.clone());
        let disasm_shared = std::sync::Arc::new(disasm);
        let bin_shared = std::sync::Arc::new(bin);

        let progress = std::sync::Arc::new(std::sync::Mutex::new(AnalysisProgress {
            phase: "Starting".into(),
            message: "Initializing...".into(),
            current: 0,
            total: 13,
            done: false,
            started_at: Some(std::time::Instant::now()),
            result: None,
            cancel: false,
            log: Vec::new(),
        }));
        state.analysis_progress = Some(progress.clone());

        std::thread::spawn(move || {
            let p = progress.clone();
            let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            {
                let wflag = cancel_flag.clone();
                let wp = p.clone();
                std::thread::spawn(move || {
                    let mut contended: u32 = 0;
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        let stop = match wp.try_lock() {
                            Ok(g) => {
                                contended = 0;
                                if g.cancel {
                                    wflag.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                                g.cancel || g.done
                            }
                            Err(std::sync::TryLockError::Poisoned(p)) => {
                                let g = p.into_inner();
                                if g.cancel {
                                    wflag.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                                true
                            }
                            Err(std::sync::TryLockError::WouldBlock) => {
                                contended = contended.saturating_add(1);
                                false
                            }
                        };
                        let _ = contended;
                        if stop {
                            break;
                        }
                    }
                });
            }
            let flag = cancel_flag.clone();
            let source_path = source_path.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::analysis::auto_analyze_with_source(
                    &disasm_shared,
                    &bin_shared,
                    source_path.as_deref(),
                    &user_names,
                    &fid_shared,
                    &flag,
                    &move |phase: &str, msg: &str, cur: usize, total: usize| {
                        let mut g = match p.try_lock() {
                            Ok(g) => g,
                            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
                            Err(std::sync::TryLockError::WouldBlock) => return,
                        };
                        if g.cancel {
                            cancel_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        g.phase = phase.into();
                        g.message = msg.into();
                        g.current = cur;
                        g.total = total;
                        let line = format!("[{}] {}", phase, msg);
                        if g.log.last() != Some(&line) {
                            g.log.push(line);
                            let cap = 64;
                            let excess = g.log.len().saturating_sub(cap);
                            if excess > 0 {
                                g.log.drain(..excess);
                            }
                        }
                    },
                )
            }));
            {
                let mut g = lock_recover(&progress);
                if !g.cancel
                    && let Ok(r) = result {
                        g.result = Some(r);
                    }
                g.done = true;
            }
        });
    } else {
        state.status_msg = "Load a binary first".to_string();
    }
}

pub fn reset_program_scoped_state(state: &mut AppState) {
    state.binary_generation = state.binary_generation.wrapping_add(1);
    let prev_name = state.current_program_label();
    if state.binary.is_some() && !state.program_slots.iter().any(|s| s.name == prev_name) {
        let _ = save_program_slot(state, prev_name);
    }
    let (_, _) = state.transact(ProgramEvent::Batch(0), |s| {
        s.comments.clear();
        s.comments_ex.clear();
        s.bookmarks.clear();
        s.patches.clear();
        s.patch_seq = 0;
        s.user_func_names.clear();
        s.user_labels.clear();
        s.label_sources.clear();
        s.function_tags.clear();
        s.annotation_undo = crate::gui::AnnotationUndo::default();
        s.user_xrefs.clear();
        s.data_types_at.clear();
        s.types = crate::type_system::DataTypeManager::new();
    });
    state.selected_func = None;
    state.selected_insn = None;
    state.search_results.clear();
    state.search_query.clear();
    state.search_last_query.clear();
    crate::gui::state::invalidate_analysis_caches(state);
    state.comments_sorted_cache = (u64::MAX, Vec::new());
    state.tags_sorted_cache = (u64::MAX, Vec::new());
    state.refresh_bp_set();
    state.func_filter.clear();
    state.search_buf.clear();
    state.history.clear();
    state.history_idx = 0;
    state.hex_offset = 0;
    state.disasm_scroll = 0;
    state.db_fp_modif = u64::MAX;
    state.db_fp_value = 0;
    state.db_saved_fp = 0;
    state.status_msg = String::new();
}

pub(crate) fn load_raw(state: &mut AppState, path: String) {
    let base = u64::from_str_radix(
        state
            .import_base_addr_buf
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .unwrap_or(0);
    let arch = ARCH_OPTIONS[clamp_arch_idx(state.import_arch_idx)].to_string();
    spawn_async_load(state, Some(base), Some(arch), path);
}

pub(crate) fn spawn_async_load(
    state: &mut AppState,
    raw_base: Option<u64>,
    raw_arch: Option<String>,
    path: String,
) {
    if state.pending_load.is_some() {
        state.status_msg = "Already loading a file".into();
        return;
    }
    let progress = std::sync::Arc::new(std::sync::Mutex::new(LoadProgress::new()));
    state.pending_load = Some(progress.clone());
    state.status_msg = format!("Loading {} ...", path);

    std::thread::spawn(move || {
        let set_phase = |ph: &str| {
            if let Some(mut g) = try_lock_recover(&progress) {
                g.phase = ph.into();
            }
        };
        let result = (|| -> Result<LoadedProgram, String> {
            let bin = match raw_base {
                Some(base) => {
                    set_phase("parsing raw dump");
                    crate::parser::parse_raw(
                        std::path::Path::new(&path),
                        base,
                        raw_arch.as_deref().unwrap_or("x86_64"),
                    )
                }
                None => {
                    set_phase("parsing headers");
                    crate::parser::parse_file(std::path::Path::new(&path))
                }
            }?;

            if raw_base.is_none() {
                let db_path = crate::project::resolve_db_path(&path);
                set_phase("loading project DB");
                if let Some(snap) = crate::project::load_project_db_checked(&db_path)
                    && snap.source_path == path {
                        let mut analysis = snap.analysis;
                        let mut pe = crate::analysis::pe_resources::PEResourceAnalyzer::new();
                        pe.analyze(&bin);
                        if pe.get_resource_count() > 0 {
                            analysis.pe_resources = Some(pe);
                        }
                        let mut ds = crate::analysis::debug_symbols::DebugSymbolsAnalyzer::new();
                        ds.analyze_with_source(&bin, Some(path.as_str()));
                        if !ds.symbols.is_empty() {
                            analysis.debug_symbols = Some(ds);
                        }
                        set_phase("done (from DB)");
                        return Ok(LoadedProgram {
                            path,
                            bin,
                            disasm: snap.disasm,
                            analysis: Some(analysis),
                            annotations: Some(snap.annotations),
                            project_name: Some(snap.project_name),
                        });
                    }
            }

            set_phase("disassembling");
            let d = crate::disasm::disassemble_binary(&bin)?;
            set_phase("done");
            Ok(LoadedProgram {
                path,
                bin,
                disasm: d,
                analysis: None,
                annotations: None,
                project_name: None,
            })
        })();
        {
            let mut g = lock_recover(&progress);
            g.result = Some(result);
            g.done = true;
        }
    });
}

#[allow(dead_code)]
pub(crate) fn poll_load(state: &mut AppState) {
    let Some(arc) = state.pending_load.clone() else {
        return;
    };
    let done = {
        match arc.try_lock() {
            Ok(g) => g.done,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().done,
            Err(std::sync::TryLockError::WouldBlock) => return,
        }
    };
    if !done {
        if let Some(g) = try_lock_recover(&arc) {
            state.status_msg = format!("Loading... ({})", g.phase);
        }
        return;
    }
    let result = {
        match arc.try_lock() {
            Ok(mut g) => g.result.take(),
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().result.take(),
            Err(_) => return,
        }
    };
    state.pending_load = None;
    let elapsed = try_lock_recover(&arc)
        .map(|g| g.started_at.elapsed().as_secs_f32())
        .unwrap_or(0.0);
    match result {
        Some(Ok(lp)) => {
            reset_program_scoped_state(state);
            let n_insns = lp.disasm.instructions.len();
            let fmt = lp.bin.format.clone();
            let arch = lp.bin.arch.clone();
            let from_db = lp.analysis.is_some();
            state.file_path = lp.path.clone();
            state.binary = Some(lp.bin);
            state.disasm = Some(lp.disasm);
            if let (Some(a), Some(ann)) = (lp.analysis, lp.annotations) {
                state.analysis = Some(std::sync::Arc::new(a));
                state.analysis_seq = state.analysis_seq.wrapping_add(1);
                state.analysis_error = None;
                crate::project::apply_annotations(&mut state.program, &ann);
                if let Some(name) = lp.project_name
                    && !name.is_empty() {
                        state.current_program_name = name;
                    }
                crate::gui::state::invalidate_analysis_caches(state);
            } else {
                crate::gui::state::invalidate_analysis_caches(state);
            }
            if let Some(name) = state.pending_project_name.take()
                && !name.is_empty() {
                    state.current_program_name = name;
                }
            touch_recent(state, &lp.path);
            state.db_last_save_attempt = Some(std::time::Instant::now());
            if from_db {
                state.status_msg = format!(
                    "{} | {} insns | loaded from project DB in {:.1}s (no re-analysis needed)",
                    lp.path, n_insns, elapsed
                );
            } else {
                state.status_msg = format!(
                    "Loaded {} | {} insns | {} {} | {:.1}s — press Analyze (F5)",
                    lp.path, n_insns, fmt, arch, elapsed
                );
            }
        }
        Some(Err(e)) => {
            state.status_msg = format!("Load error: {}", e);
        }
        None => {
            state.status_msg = "Load cancelled".into();
        }
    }
}

#[allow(dead_code)]
pub fn open_file_into_program(
    state: &mut AppState,
    path: &str,
    name: Option<String>,
) -> Result<(), String> {
    open_file_into_program_with_auto_analysis(state, path, name, false)
}

pub fn open_file_into_program_with_auto_analysis(
    state: &mut AppState,
    path: &str,
    name: Option<String>,
    auto_analysis: bool,
) -> Result<(), String> {
    let bin = crate::parser::parse_file(std::path::Path::new(path))?;
    let db_path = crate::project::resolve_db_path(path);
    let snap = crate::project::load_project_db_checked(&db_path)
        .filter(|s| s.source_path == path);
    let db_project_name = snap.as_ref().map(|s| s.project_name.clone());
    let (d, mut analysis, annotations) = match snap {
        Some(s) => (s.disasm, Some(s.analysis), Some(s.annotations)),
        None => (crate::disasm::disassemble_binary(&bin)?, None, None),
    };
    if let Some(a) = &mut analysis {
        let mut pe = crate::analysis::pe_resources::PEResourceAnalyzer::new();
        pe.analyze(&bin);
        if pe.get_resource_count() > 0 {
            a.pe_resources = Some(pe);
        }
        let mut ds = crate::analysis::debug_symbols::DebugSymbolsAnalyzer::new();
        ds.analyze_with_source(&bin, Some(path));
        if !ds.symbols.is_empty() {
            a.debug_symbols = Some(ds);
        }
    }
    reset_program_scoped_state(state);
    let n = name.unwrap_or_else(|| {
        db_project_name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| {
                std::path::Path::new(path)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unnamed".into())
            })
    });
    state.current_program_name = n;
    state.file_path = path.to_string();
    let arch = bin.arch.clone();
    state.program.types.set_arch(&arch);
    state.binary = Some(bin);
    state.disasm = Some(d);
    state.analysis = analysis.map(std::sync::Arc::new);
    if let Some(ann) = annotations {
        crate::project::apply_annotations(&mut state.program, &ann);
    }
    crate::gui::state::invalidate_analysis_caches(state);
    touch_recent(state, path);
    if auto_analysis && state.analysis.is_none() {
        state.mcp_request_analysis = true;
        state.status_msg = format!("Loaded {} — analysis queued", path);
    } else {
        state.status_msg = format!("Loaded {} — press Analyze (F5)", path);
    }
    Ok(())
}

pub(crate) fn goto_address(state: &mut AppState, addr: u64) {
    const HISTORY_CAP: usize = 500;
    let mut found = false;
    if let Some(ref disasm) = state.disasm {
        let pos = disasm.instructions.partition_point(|i| i.address < addr);
        if pos < disasm.instructions.len() {
            state.disasm_scroll = pos;
            state.scroll_request = Some(pos);
            found = true;
        }
    }
    if let Some(ref bin) = state.binary
        && let Some(off) = offset_for_va(&bin.sections, addr) {
            state.hex_offset = off as usize;
            found = true;
        }

    if found && !state.navigating {
        if state.history_idx + 1 < state.history.len() {
            state.history.truncate(state.history_idx + 1);
        }
        if state.history.last() != Some(&addr) {
            state.history.push(addr);
            if state.history.len() > HISTORY_CAP {
                let drop = state.history.len() - HISTORY_CAP;
                state.history.drain(..drop);
            }
            state.history_idx = state.history.len().saturating_sub(1);
        }
    }
}

pub(crate) fn history_back(state: &mut AppState) {
    if state.history_idx > 0 {
        state.history_idx -= 1;
        let addr = state.history[state.history_idx];
        state.navigating = true;
        goto_address(state, addr);
        state.navigating = false;
    }
}

pub(crate) fn history_forward(state: &mut AppState) {
    if state.history_idx + 1 < state.history.len() {
        state.history_idx += 1;
        let addr = state.history[state.history_idx];
        state.navigating = true;
        goto_address(state, addr);
        state.navigating = false;
    }
}

pub(crate) fn toggle_breakpoint(state: &mut AppState, addr: u64) {
    if let Some(pos) = state
        .debug_state
        .breakpoints
        .iter()
        .position(|b| b.address == addr)
    {
        let orig = state.debug_state.breakpoints[pos].original_byte;
        state.debug_state.breakpoints.remove(pos);
        state.refresh_bp_set();
        if state.debug_state.is_attached && orig != 0 {
            state.debug_state.mem_request_seq += 1;
            let id = state.debug_state.mem_request_seq;
            state.debug_state.mem_write_request = Some(crate::debugger::MemWriteRequest {
                id,
                address: addr,
                bytes: vec![orig],
            });
            state.debug_state.signal.notify();
            state.status_msg = format!("BP removed {:012X} (restoring {:#04x})", addr, orig);
        } else {
            state.status_msg = format!("BP removed {:012X}", addr);
        }
        return;
    }
    if let Some(ref disasm) = state.disasm {
        let pos = disasm.instructions.partition_point(|i| i.address < addr);
        let ok = pos < disasm.instructions.len() && disasm.instructions[pos].address == addr;
        if !ok {
            state.status_msg = format!("Not an instruction start: {:#x}", addr);
            return;
        }
    }
    if state.debug_state.is_attached {
        state.debug_state.mem_request_seq += 1;
        let id = state.debug_state.mem_request_seq;
        state.debug_state.arm_int3_request = Some((id, addr));
        state.pending_bp_arm = Some((id, addr));
        state.debug_state.signal.notify();
        state.status_msg = format!("BP arming {:012X}...", addr);
    } else {
        state
            .debug_state
            .breakpoints
            .push(crate::debugger::Breakpoint {
                address: addr,
                enabled: true,
                original_byte: 0,
                name: format!("bp_{:X}", addr),
                kind: crate::debugger::BpKind::SwExec,
                len: 1,
                planted: false,
            });
        state.refresh_bp_set();
        state.status_msg = format!("BP set {:012X}", addr);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn poll_bp_arm(state: &mut AppState) {
    let (id, addr) = match state.pending_bp_arm {
        Some(v) => v,
        None => return,
    };
    let result = match &state.debug_state.arm_int3_result {
        Some((rid, _)) if *rid == id => state.debug_state.arm_int3_result.take(),
        _ => return,
    };
    state.pending_bp_arm = None;
    let (_, r) = result.unwrap();
    match r {
        Ok(orig) => {
            if let Some(bp) = state
                .debug_state
                .breakpoints
                .iter_mut()
                .find(|b| b.address == addr)
            {
                bp.original_byte = orig;
                bp.enabled = true;
            } else {
                state
                    .debug_state
                    .breakpoints
                    .push(crate::debugger::Breakpoint {
                        address: addr,
                        enabled: true,
                        original_byte: orig,
                        name: format!("bp_{:X}", addr),
                        kind: crate::debugger::BpKind::SwExec,
                        len: 1,
                        planted: true,
                    });
            }
            state.refresh_bp_set();
            state.status_msg = format!("BP set {:012X}", addr);
        }
        Err(e) => {
            state.status_msg = format!("BP failed {:#x}: {}", addr, e);
        }
    }
}

pub(crate) fn fmt_flags(f: u32) -> String {
    let mut v = Vec::new();
    if f & 1 != 0 {
        v.push("CF");
    }
    if f & (1 << 6) != 0 {
        v.push("ZF");
    }
    if f & (1 << 7) != 0 {
        v.push("SF");
    }
    if f & (1 << 11) != 0 {
        v.push("OF");
    }
    if f & (1 << 10) != 0 {
        v.push("DF");
    }
    v.join(" ")
}

pub(crate) fn format_hex_small(v: u64, buf: &mut [u8; 16]) -> &str {
    if v == 0 {
        buf[0] = b'0';
        return std::str::from_utf8(&buf[..1]).unwrap_or("0");
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 16;
    let mut x = v;
    while x > 0 {
        i -= 1;
        buf[i] = HEX[(x & 0xf) as usize];
        x >>= 4;
    }
    std::str::from_utf8(&buf[i..]).unwrap_or("0")
}
