use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

pub fn cancel_analysis(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let was_running = s.analysis_progress.is_some();
    if let Some(arc) = &s.analysis_progress
        && let Ok(mut g) = arc.lock()
            && !g.done {
                g.cancel = true;
                g.message = "Cancelling...".into();
            }
    s.status_msg = "Analysis cancelling...".into();
    Ok(json!({
        "ok": true,
        "was_running": was_running,
        "note": "Run aborts cooperatively; the progress slot clears itself on completion."
    }))
}

pub fn create_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let name_opt = args
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.clone().ok_or("No binary loaded")?;
    let dis = s.disasm.clone().ok_or("No disassembly loaded")?;
    if !bin.sections.iter().any(|sec| {
        sec.is_executable && addr >= sec.vaddr && addr < sec.vaddr.saturating_add(sec.size)
    }) {
        return Err(format!(
            "Address {:#x} is not in an executable section",
            addr
        ));
    }
    if !dis.instructions.iter().any(|i| i.address == addr) {
        return Err(format!(
            "Address {:#x} is not a decoded instruction (see find_code_gaps)",
            addr
        ));
    }
    if s.analysis.is_none() {
        s.analysis = Some(std::sync::Arc::new(
            crate::analysis::AnalysisResult::default(),
        ));
    }
    let analysis = std::sync::Arc::make_mut(s.analysis.as_mut().unwrap());
    if analysis.functions.iter().any(|f| f.entry == addr) {
        return Err(format!("Function already exists at {:#x}", addr));
    }
    if analysis
        .functions
        .iter()
        .any(|f| addr > f.entry && addr < f.end)
    {
        return Err(format!(
            "Address {:#x} is inside an existing function (delete it first or pick a gap)",
            addr
        ));
    }
    let next_entry = analysis
        .functions
        .iter()
        .map(|f| f.entry)
        .filter(|e| *e > addr)
        .min();
    let sec_end = bin
        .sections
        .iter()
        .filter(|sec| {
            sec.is_executable && addr >= sec.vaddr && addr < sec.vaddr.saturating_add(sec.size)
        })
        .map(|sec| sec.vaddr.saturating_add(sec.size))
        .max()
        .unwrap_or(addr + 16);
    let mut end = next_entry.unwrap_or(sec_end).min(sec_end);
    if end <= addr {
        end = addr + 1;
    }
    if let Some(last) = dis
        .instructions
        .iter()
        .rfind(|i| i.address >= addr && (next_entry.is_none_or(|n| i.address < n)))
    {
        let last_end = last
            .address
            .saturating_add(last.bytes_slice().len() as u64)
            .max(addr + 1);
        end = end.min(last_end.max(addr + 1));
    }
    let name = name_opt.unwrap_or_else(|| format!("sub_{:x}", addr));
    analysis
        .functions
        .push(crate::analysis::function::DetectedFunction {
            entry: addr,
            end,
            name: name.clone(),
            has_frame: false,
            stack_size: 0,
            source: crate::analysis::function::FuncSource::UserDefined,
            is_thunk: false,
            thunk_target: None,
        });
    analysis.functions.sort_by_key(|f| f.entry);
    s.analysis_version += 1;
    s.disasm_cache = None;
    s.program.modification_number = s.program.modification_number.wrapping_add(1);
    s.program.dirty = true;
    s.status_msg = format!("Created function {} at {:#x}", name, addr);
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": name,
        "end": format!("{:#x}", end),
        "size": end - addr,
        "source": "user",
        "note": "CFGs/xrefs refresh on the next run_analysis"
    }))
}

pub fn delete_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    if s.analysis.is_none() {
        return Err("No analysis loaded - run the run_analysis tool first".into());
    }
    let analysis = std::sync::Arc::make_mut(s.analysis.as_mut().unwrap());
    let pos = analysis
        .functions
        .iter()
        .position(|f| f.entry == addr)
        .ok_or(format!("No function starts at {:#x}", addr))?;
    let removed = analysis.functions.remove(pos);
    analysis.cfgs.remove(&addr);
    analysis.stack_frames.remove(&addr);
    analysis.pseudocode.remove(&addr);
    analysis.callers.remove(&addr);
    analysis.callees.remove(&addr);
    analysis.stubs.remove(&addr);
    s.user_func_names.remove(&addr);
    s.analysis_version += 1;
    s.disasm_cache = None;
    s.program.modification_number = s.program.modification_number.wrapping_add(1);
    s.program.dirty = true;
    s.status_msg = format!("Deleted function {} at {:#x}", removed.name, addr);
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": removed.name,
        "deleted": true
    }))
}

pub fn resolve_thunk(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let by_entry: std::collections::HashMap<u64, &crate::analysis::function::DetectedFunction> =
        analysis.functions.iter().map(|f| (f.entry, f)).collect();
    let mut chain = vec![format!("{:#x}", addr)];
    let mut cur = addr;
    for _ in 0..8 {
        let f = match by_entry.get(&cur) {
            Some(f) => *f,
            None => break,
        };
        if !f.is_thunk {
            break;
        }
        if let Some(next) = f.thunk_target {
            chain.push(format!("{:#x}", next));
            cur = next;
            continue;
        }
        if let Some(xr) = analysis
            .xrefs
            .all
            .iter()
            .find(|x| x.from == cur && matches!(x.kind, crate::analysis::XRefKind::Thunk))
        {
            chain.push(format!("{:#x}", xr.to));
            let import = bin.imports.iter().find(|imp| imp.offset == xr.to);
            return Ok(json!({
                "address": format!("{:#x}", addr),
                "is_thunk": true,
                "destination": format!("{:#x}", xr.to),
                "import": import.map(|imp| if imp.library.is_empty() {
                    imp.name.clone()
                } else {
                    format!("{}!{}", imp.library, imp.name)
                }),
                "chain": chain,
                "note": xr.note.as_deref().unwrap_or(""),
            }));
        }
        break;
    }
    let f = by_entry.get(&addr);
    Ok(json!({
        "address": format!("{:#x}", addr),
        "is_thunk": f.is_some_and(|f| f.is_thunk),
        "destination": format!("{:#x}", cur),
        "chain": chain,
        "hops": chain.len() - 1,
    }))
}

pub fn find_callsites_to_import(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let name = crate::mcp::tools::schemas::arg_str_alias(args, &["name", "import_name", "import"])?;
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(500)
        .clamp(1, 100_000) as usize;

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let empty_disasm = crate::disasm::DisasmResult {
        instructions: std::sync::Arc::new(vec![]),
        arch: bin.arch.clone(),
    };
    let dis = s.disasm.as_ref().unwrap_or(&empty_disasm);

    let iat_slot = crate::analysis::import_xref::resolve_iat_slot(bin, &name);
    if iat_slot.is_none() {
        return Ok(json!({
            "name": name,
            "import_found": false,
            "matches": 0,
            "items": [],
            "note": "Import not found in the import table. Check spelling or use 'DLL!Name' form (see list_imports). If it's resolved at runtime via GetProcAddress there is no IAT slot to scan."
        }));
    }

    let sites = crate::analysis::import_xref::find_callsites(bin, dis, &name);
    if sites.is_empty() {
        return Ok(json!({
            "name": name,
            "import_found": true,
            "iat_slot": format!("{:#x}", iat_slot.unwrap()),
            "matches": 0,
            "items": [],
            "note": "IAT slot resolved but no direct call/jmp and no call-to-thunk found in executable sections."
        }));
    }

    let items: Vec<Value> = sites
        .iter()
        .take(limit)
        .map(|s| {
            json!({
                "address": format!("{:#x}", s.address),
                "kind": match s.kind {
                    crate::analysis::import_xref::CallKind::DirectCall => "direct_call",
                    crate::analysis::import_xref::CallKind::DirectJump => "direct_jump",
                    crate::analysis::import_xref::CallKind::ThunkedCall => "thunked_call",
                },
                "asm": s.asm,
                "bytes": s.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
                "thunk_address": s.thunk_address.map(|a| format!("{:#x}", a)),
            })
        })
        .collect();

    Ok(json!({
        "name": name,
        "import_found": true,
        "iat_slot": format!("{:#x}", iat_slot.unwrap()),
        "matches": sites.len(),
        "returned": items.len(),
        "items": items,
    }))
}
