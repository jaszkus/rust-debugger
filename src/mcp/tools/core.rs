use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::{arg_addr, arg_int, arg_str, arg_str_opt};
use super::parse_addr;
use crate::gui::AppState;

fn require_args(_args: &Value) {}

pub fn get_metadata(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    if let Some(ref bin) = s.binary {
        Ok(json!({
            "format": bin.format,
            "arch": bin.arch,
            "entry_point": format!("{:#x}", bin.entry_point),
            "image_base": format!("{:#x}", bin.image_base),
            "is_dll": bin.is_dll,
            "section_count": bin.sections.len(),
            "import_count": bin.imports.len(),
            "export_count": bin.exports.len(),
            "string_count": bin.strings.len(),
            "file_path": s.file_path,
            "data_size": bin.data.len(),
            "analysis_loaded": s.analysis.is_some(),
            "overlay": bin.overlay.map(|(off, size)| json!({ "offset": off, "size": size })),
            "has_rich": bin.has_rich,
            "tls_callback_count": bin.tls_callbacks.len(),
            "tls_callbacks": bin.tls_callbacks.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>(),
            "delay_import_count": bin.delay_imports.len(),
            "libraries": bin.libraries,
            "rpaths": bin.rpaths,
            "macho_uuid": bin.macho_uuid,
            "relocation_count": bin.relocations.len(),
        }))
    } else {
        Err("No binary loaded".to_string())
    }
}

pub fn get_function_count(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let count = s.analysis.as_ref().map(|a| a.functions.len()).unwrap_or(0);
    Ok(json!({ "count": count }))
}

pub fn get_entry_points(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    if let Some(ref bin) = s.binary {
        Ok(json!({ "entry_points": [format!("{:#x}", bin.entry_point)] }))
    } else {
        Err("No binary loaded".to_string())
    }
}

pub fn run_analysis(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(600_000)
        .clamp(5_000, 3_600_000);
    let start_seq = {
        let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        if s.binary.is_none() {
            return Err("No binary loaded".to_string());
        }
        s.analysis_error = None;
        s.mcp_request_analysis = true;
        s.analysis_seq
    };
    let t0 = std::time::Instant::now();
    const GRACE_MS: u64 = 30_000;
    let mut fell_back = false;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let snap = {
            let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
            (
                s.analysis_seq,
                s.analysis_error.clone(),
                s.analysis
                    .as_ref()
                    .map(|a| (a.functions.len(), a.xrefs.all.len())),
                s.analysis_progress.is_some(),
            )
        };
        let (seq, err, counts, progress_slot) = snap;
        if seq != start_seq {
            if let Some(e) = err {
                return Err(format!("Analysis failed: {}", e));
            }
            let (funcs, xrefs) = counts.unwrap_or((0, 0));
            return Ok(json!({
                "status": "done",
                "functions": funcs,
                "xrefs": xrefs,
                "elapsed_ms": t0.elapsed().as_millis() as u64,
                "inline": fell_back,
            }));
        }
        if !fell_back && !progress_slot && t0.elapsed().as_millis() as u64 > GRACE_MS {
            eprintln!(
                "[run_analysis] background consumer silent for {} ms, running inline",
                GRACE_MS
            );
            fell_back = true;
            let snap2 = {
                let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
                (
                    s.disasm.clone(),
                    s.binary.clone(),
                    s.user_func_names.clone(),
                    s.fid_shared(),
                )
            };
            let (disasm, bin, user_names, fid_shared) = snap2;
            let (d, b) = match (disasm, bin) {
                (Some(d), Some(b)) => (d, b),
                _ => return Err("Binary/disassembly vanished mid-run".to_string()),
            };
            let never_cancel = std::sync::atomic::AtomicBool::new(false);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::analysis::auto_analyze_with_progress(
                    &d,
                    &b,
                    &user_names,
                    &fid_shared,
                    &never_cancel,
                    &|_, _, _, _| {},
                )
            }));
            let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
            match r {
                Ok(r) => {
                    let (_, _) = s.transact(crate::gui::ProgramEvent::AnalysisReplaced, |s| {
                        s.analysis = Some(std::sync::Arc::new(r));
                    });
                    crate::gui::state::invalidate_analysis_caches(&mut s);
                    s.analysis_progress = None;
                    s.analysis_error = None;
                    s.analysis_seq = s.analysis_seq.wrapping_add(1);
                }
                Err(_) => {
                    s.analysis_error = Some("Inline analysis panicked".into());
                    s.analysis_seq = s.analysis_seq.wrapping_add(1);
                }
            }
        }
        if t0.elapsed().as_millis() as u64 > timeout_ms {
            return Err(format!(
                "Analysis still running after {} ms (use timeout_ms to wait longer; get_analysis_status to poll, cancel_analysis to abort)",
                timeout_ms
            ));
        }
    }
}

pub fn get_analysis_status(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    if let Some(arc) = &s.analysis_progress
        && let Ok(g) = arc.lock() {
            return Ok(json!({
                "running": !g.done,
                "phase": g.phase,
                "message": g.message,
                "current": g.current,
                "total": g.total,
                "elapsed_secs": g.started_at.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0),
                "seq": s.analysis_seq,
                "error": s.analysis_error
            }));
        }
    let analyzed = s.analysis.is_some();
    let mut out = json!({ "running": false, "analyzed": analyzed, "seq": s.analysis_seq, "error": s.analysis_error });
    if !analyzed {
        out["hint"] = json!("No analysis in memory: it was never run, or it was dropped by a patch/undo/revert/program switch (invalidate_analysis). Call run_analysis.");
    }
    Ok(out)
}

pub fn int_convert(args: &Value) -> Result<Value, String> {
    let s = arg_str(args, "value")?;
    let trimmed = s.trim();
    let (radix, body) = if let Some(b) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        (16, b)
    } else if let Some(b) = trimmed.strip_prefix("0b") {
        (2, b)
    } else {
        (10, trimmed)
    };
    let n = i64::from_str_radix(body, radix)
        .map(|v| v as u64)
        .or_else(|_| u64::from_str_radix(body, radix))
        .map_err(|e| format!("Parse failed: {}", e))?;
    let u = n;
    let bytes_le: Vec<u8> = u.to_le_bytes().to_vec();
    let bytes_be: Vec<u8> = u.to_be_bytes().to_vec();
    let ascii: String = bytes_le
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    Ok(json!({
        "decimal": serde_json::Value::from(u),
        "unsigned": u,
        "hex": format!("{:#x}", u),
        "binary": format!("{:b}", u),
        "bytes_le": bytes_le.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
        "bytes_be": bytes_be.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
        "ascii": ascii,
    }))
}

pub fn list_functions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let (limit, limit_requested) = super::schemas::arg_ranged(args, "limit", 100, 1, 1000)?;
    if let Some(v) = args.get("offset")
        && !v.is_number() {
            return Err("Invalid params: offset must be integer".to_string());
        }
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let hex_filter = super::schemas::hex_needle(&filter);

    let filtered: Vec<&crate::analysis::DetectedFunction> = analysis
        .functions
        .iter()
        .filter(|f| {
            filter.is_empty()
                || f.name.to_lowercase().contains(&filter)
                || hex_filter
                    .as_deref()
                    .is_some_and(|h| format!("{:x}", f.entry).contains(h))
        })
        .collect();
    let total = filtered.len();

    let items: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|f| {
            let xrefs_to = analysis
                .xrefs
                .by_to
                .get(&f.entry)
                .map(|v| v.len())
                .unwrap_or(0);
            let bb = analysis
                .cfgs
                .get(&f.entry)
                .map(|c| c.blocks.len())
                .unwrap_or(0);
            json!({
                "address": format!("{:#x}", f.entry),
                "end": format!("{:#x}", f.end),
                "name": f.name,
                "size": f.end - f.entry,
                "has_frame": f.has_frame,
                "stack_size": f.stack_size,
                "basic_blocks": bb,
                "xrefs_to": xrefs_to,
                "source": format!("{:?}", f.source)
            })
        })
        .collect();

    let mut out = json!({ "total": total, "offset": offset, "limit": limit, "items": items });
    if let Some(req) = limit_requested {
        super::schemas::push_warning(
            &mut out,
            format!(
                "limit {} exceeds the maximum 1000; clamped to {}",
                req, limit
            ),
        );
    }
    Ok(out)
}

pub fn lookup_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let q = super::arg_query(args)?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;

    let by_addr = parse_addr(&q).and_then(|a| analysis.functions.iter().find(|f| f.entry == a));
    let func = by_addr.or_else(|| analysis.functions.iter().find(|f| f.name == q));

    match func {
        Some(f) => Ok(json!({
            "address": format!("{:#x}", f.entry),
            "end": format!("{:#x}", f.end),
            "name": f.name,
            "size": f.end - f.entry,
            "has_frame": f.has_frame,
            "stack_size": f.stack_size,
        })),
        None => Err(format!("Function not found: {}", q)),
    }
}

pub fn decompile_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let (disasm, bin, analysis_clone) = {
        let s = super::lock::lock_state(state)?;
        (
            s.disasm.clone().ok_or("No disassembly loaded")?,
            s.binary.clone().ok_or("No binary loaded")?,
            s.analysis
                .clone()
                .ok_or("No analysis loaded - run the run_analysis tool first")?,
        )
    };
    let mut working = (*analysis_clone).clone();
    if let Some(f) = working
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
    {
        let blocks = working
            .cfgs
            .get(&f.entry)
            .map(|c| c.blocks.len())
            .unwrap_or(0);
        if blocks > crate::analysis::decompiler::MAX_DECOMP_BLOCKS
            || (blocks == 0
                && f.end.saturating_sub(f.entry)
                    > 64 * crate::analysis::decompiler::MAX_DECOMP_BLOCKS as u64)
        {
            return Err(format!(
                "Function at {:#x} too large for structured decompilation ({} blocks, {} bytes, cap {} blocks): use disassemble_function / analyze_control_flow instead",
                f.entry, blocks, f.end.saturating_sub(f.entry),
                crate::analysis::decompiler::MAX_DECOMP_BLOCKS
            ));
        }
    }
    let entry = crate::analysis::decompile_on_demand(&disasm, &bin, &mut working, addr)?;
    let pc = working
        .pseudocode
        .get(&entry)
        .ok_or("Decompilation failed")?;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let max_bytes = args
        .get("max_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(200_000)
        .clamp(1_000, 400_000) as usize;
    let line_count = pc.lines.len();
    let mut code = String::new();
    let mut next = offset.min(line_count);
    while next < line_count {
        let l = &pc.lines[next];
        let indent = (l.indent as usize).min(64) * 4;
        let add = indent + l.text.len() + 1;
        if next > offset && code.len() + add > max_bytes {
            break;
        }
        code.try_reserve(add)
            .map_err(|_| "out of memory while building the response page".to_string())?;
        if next > offset {
            code.push('\n');
        }
        for _ in 0..indent {
            code.push(' ');
        }
        code.push_str(&l.text);
        next += 1;
    }
    let truncated = next < line_count;
    {
        let mut s = super::lock::lock_state(state)?;
        if let Some(a) = s.analysis.as_mut() {
            let a = std::sync::Arc::make_mut(a);
            if let std::collections::hash_map::Entry::Vacant(e) = a.pseudocode.entry(entry)
                && let Some(fresh) = working.pseudocode.get(&entry) {
                    e.insert(fresh.clone());
                }
        }
    }
    Ok(json!({
        "address": format!("{:#x}", entry),
        "code": code,
        "line_count": line_count,
        "offset": offset,
        "next_offset": if truncated { Some(next) } else { None },
        "truncated": truncated
    }))
}

pub fn disassemble_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let disasm = s.disasm.as_ref().ok_or("No disassembly loaded")?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;

    let func = analysis
        .functions
        .iter()
        .find(|f| f.entry == addr)
        .ok_or("Function not found at that address")?;
    let start = disasm
        .instructions
        .partition_point(|i| i.address < func.entry);
    let mut end = disasm
        .instructions
        .partition_point(|i| i.address < func.end);
    if end < start {
        end = start;
    }

    let lines: Vec<Value> = disasm.instructions[start..end].iter().map(|ins| {
        json!({
            "address": format!("{:#x}", ins.address),
            "bytes": ins.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
            "mnemonic": ins.mnemonic,
            "operands": ins.ops().as_ref()
        })
    }).collect();

    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": func.name,
        "instruction_count": lines.len(),
        "instructions": lines
    }))
}

pub fn get_function_callers(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let empty = vec![];
    let callers = analysis.callers.get(&addr).unwrap_or(&empty);
    let lookup: std::collections::HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();
    let items: Vec<Value> = callers
        .iter()
        .map(|&c| {
            json!({
                "address": format!("{:#x}", c),
                "name": lookup.get(&c).copied().unwrap_or("?")
            })
        })
        .collect();
    Ok(json!({ "address": format!("{:#x}", addr), "callers": items, "count": callers.len() }))
}

pub fn get_function_callees(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let empty = vec![];
    let callees = analysis.callees.get(&addr).unwrap_or(&empty);
    let lookup: std::collections::HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();
    let items: Vec<Value> = callees
        .iter()
        .map(|&c| {
            json!({
                "address": format!("{:#x}", c),
                "name": lookup.get(&c).copied().unwrap_or("?")
            })
        })
        .collect();
    Ok(json!({ "address": format!("{:#x}", addr), "callees": items, "count": callees.len() }))
}

pub fn get_function_pcode(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let disasm = s.disasm.as_ref().ok_or("No disassembly loaded")?;
    let func = analysis
        .functions
        .iter()
        .find(|f| f.entry == addr)
        .ok_or("Function not found")?;

    let pinstrs = crate::analysis::pcode::lift_func(&disasm.instructions, func.entry, func.end);

    let pcode: Vec<Value> = pinstrs
        .iter()
        .map(|pi| {
            let ops: Vec<String> = pi.ops.iter().map(|op| format!("{:?}", op)).collect();
            json!({
                "address": format!("{:#x}", pi.address),
                "mnemonic": pi.mnemonic,
                "ops": ops
            })
        })
        .collect();

    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": func.name,
        "pcode_count": pcode.len(),
        "pcode": pcode
    }))
}

pub fn get_stack_frame(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let sf = analysis
        .stack_frames
        .get(&addr)
        .ok_or("No stack frame for that function")?;
    let vars: Vec<Value> = sf
        .variables
        .iter()
        .map(|v| {
            json!({
                "offset": v.offset,
                "size": v.size,
                "kind": format!("{:?}", v.kind),
                "name": v.name,
                "access_count": v.access_count
            })
        })
        .collect();
    Ok(json!({
        "address": format!("{:#x}", addr),
        "frame_size": sf.frame_size,
        "variable_count": vars.len(),
        "variables": vars
    }))
}

pub fn get_xrefs_to(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let empty = vec![];
    let idxs = analysis.xrefs.by_to.get(&addr).unwrap_or(&empty);
    let items: Vec<Value> = idxs
        .iter()
        .map(|&i| {
            let xr = &analysis.xrefs.all[i];
            json!({
                "from": format!("{:#x}", xr.from),
                "to": format!("{:#x}", xr.to),
                "kind": format!("{:?}", xr.kind),
                "note": xr.note.as_deref().unwrap_or("")
            })
        })
        .collect();
    Ok(json!({ "address": format!("{:#x}", addr), "count": items.len(), "xrefs": items }))
}

pub fn get_xrefs_from(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let empty = vec![];
    let idxs = analysis.xrefs.by_from.get(&addr).unwrap_or(&empty);
    let items: Vec<Value> = idxs
        .iter()
        .map(|&i| {
            let xr = &analysis.xrefs.all[i];
            json!({
                "from": format!("{:#x}", xr.from),
                "to": format!("{:#x}", xr.to),
                "kind": format!("{:?}", xr.kind),
                "note": xr.note.as_deref().unwrap_or("")
            })
        })
        .collect();
    Ok(json!({ "address": format!("{:#x}", addr), "count": items.len(), "xrefs": items }))
}

#[allow(dead_code)]
fn _unused(_args: &Value) {
    require_args(_args);
}
