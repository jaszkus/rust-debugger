use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::parse_addr;
use std::collections::{HashMap, HashSet};

pub fn get_function_at(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let func = analysis
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
        .ok_or("Address not in any function")?;
    Ok(json!({
        "address": format!("{:#x}", addr),
        "function_address": format!("{:#x}", func.entry),
        "function_name": func.name,
        "function_end": format!("{:#x}", func.end),
        "size": func.end - func.entry,
        "offset_in_function": addr - func.entry
    }))
}

pub fn get_section_at(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    for sec in &bin.sections {
        if addr >= sec.vaddr && addr < sec.vaddr + sec.size {
            return Ok(json!({
                "address": format!("{:#x}", addr),
                "section": sec.name,
                "vaddr": format!("{:#x}", sec.vaddr),
                "size": sec.size,
                "executable": sec.is_executable,
                "offset_in_section": addr - sec.vaddr
            }));
        }
    }
    Err(format!("Address {:#x} not in any section", addr))
}

pub fn address_info(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    if !is_mapped(bin, addr) {
        let n = s
            .analysis
            .as_ref()
            .and_then(|a| a.xrefs.by_to.get(&addr))
            .map_or(0, |v| v.len());
        return Err(if n > 0 {
            format!(
                "Address {:#x} not in any section ({} xrefs target it; see get_xrefs_to)",
                addr, n
            )
        } else {
            format!("Address {:#x} not in any section", addr)
        });
    }

    let section = bin
        .sections
        .iter()
        .find(|sec| addr >= sec.vaddr && addr < sec.vaddr + sec.size)
        .map(|sec| {
            json!({
                "name": sec.name,
                "vaddr": format!("{:#x}", sec.vaddr),
                "executable": sec.is_executable
            })
        });

    let mut function: Option<Value> = None;
    let mut basic_block: Option<Value> = None;
    let mut xrefs_to_count = 0;
    let mut xrefs_from_count = 0;
    let mut instruction: Option<Value> = None;

    if let Some(ref analysis) = s.analysis {
        if let Some(f) = analysis
            .functions
            .iter()
            .find(|f| addr >= f.entry && addr < f.end)
        {
            function = Some(json!({
                "address": format!("{:#x}", f.entry),
                "name": f.name,
                "size": f.end - f.entry
            }));
            if let Some(cfg) = analysis.cfgs.get(&f.entry)
                && let Some(bb) = cfg.blocks.iter().find(|b| addr >= b.start && addr < b.end) {
                    basic_block = Some(json!({
                        "id": bb.id,
                        "start": format!("{:#x}", bb.start),
                        "end": format!("{:#x}", bb.end),
                        "instr_count": bb.instr_indices.len(),
                        "predecessors": bb.predecessors.len(),
                        "successors": bb.successors.len()
                    }));
                }
        }
        xrefs_to_count = analysis
            .xrefs
            .by_to
            .get(&addr)
            .map(|v| v.len())
            .unwrap_or(0);
        xrefs_from_count = analysis
            .xrefs
            .by_from
            .get(&addr)
            .map(|v| v.len())
            .unwrap_or(0);
    }

    if let Some(ref disasm) = s.disasm
        && let Some(ins) = disasm.instructions.iter().find(|i| i.address == addr) {
            instruction = Some(json!({
                "mnemonic": ins.mnemonic,
                "operands": ins.ops().as_ref(),
                "bytes": ins.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
            }));
        }

    let string_here = bin.strings.iter().find(|s| s.vaddr == addr).map(|s| {
        let enc = match s.encoding {
            crate::parser::StringEncoding::Ascii => "ascii",
            crate::parser::StringEncoding::Utf16Le => "utf16le",
            crate::parser::StringEncoding::Utf32Le => "utf32le",
            crate::parser::StringEncoding::Pascal => "pascal",
        };
        json!({ "encoding": enc, "content": s.content, "score": s.score, "label": crate::parser::string_label(s.vaddr) })
    });

    let symbol = bin.symbols.iter().find(|sy| sy.addr == addr).map(|sy| {
        json!({
            "name": sy.name, "is_function": sy.is_function
        })
    });

    let comment = s.comments.get(&addr).cloned();

    Ok(json!({
        "address": format!("{:#x}", addr),
        "section": section,
        "function": function,
        "basic_block": basic_block,
        "instruction": instruction,
        "string": string_here,
        "symbol": symbol,
        "comment": comment,
        "xrefs_to_count": xrefs_to_count,
        "xrefs_from_count": xrefs_from_count
    }))
}

pub fn get_basic_block_at(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let disasm = s.disasm.as_ref().ok_or("No disasm")?;

    for (entry, cfg) in &analysis.cfgs {
        if let Some(bb) = cfg.blocks.iter().find(|b| addr >= b.start && addr < b.end) {
            let func_name = analysis
                .functions
                .iter()
                .find(|f| f.entry == *entry)
                .map(|f| f.name.clone())
                .unwrap_or_default();
            let succ: Vec<Value> = bb
                .successors
                .iter()
                .map(|e| {
                    let target_bb = &cfg.blocks[e.target];
                    json!({
                        "target": format!("{:#x}", target_bb.start),
                        "kind": format!("{:?}", e.kind)
                    })
                })
                .collect();
            let preds: Vec<String> = bb
                .predecessors
                .iter()
                .map(|&p| format!("{:#x}", cfg.blocks[p].start))
                .collect();
            let instructions: Vec<Value> = bb
                .instr_indices
                .clone()
                .filter_map(|i| disasm.instructions.get(i))
                .map(|ins| {
                    json!({
                        "address": format!("{:#x}", ins.address),
                        "mnemonic": ins.mnemonic,
                        "operands": ins.ops().as_ref()
                    })
                })
                .collect();
            return Ok(json!({
                "function": format!("{:#x}", entry),
                "function_name": func_name,
                "block_id": bb.id,
                "start": format!("{:#x}", bb.start),
                "end": format!("{:#x}", bb.end),
                "predecessors": preds,
                "successors": succ,
                "instructions": instructions
            }));
        }
    }
    Err(format!("No basic block contains {:#x}", addr))
}

pub fn list_basic_blocks(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let entry = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let cfg = analysis
        .cfgs
        .get(&entry)
        .ok_or("No CFG for that function")?;
    let blocks: Vec<Value> = cfg
        .blocks
        .iter()
        .map(|bb| {
            json!({
                "id": bb.id,
                "start": format!("{:#x}", bb.start),
                "end": format!("{:#x}", bb.end),
                "instr_count": bb.instr_indices.len(),
                "predecessor_count": bb.predecessors.len(),
                "successor_count": bb.successors.len(),
                "successors": bb.successors.iter().map(|e| json!({
                    "target": format!("{:#x}", cfg.blocks[e.target].start),
                    "kind": format!("{:?}", e.kind)
                })).collect::<Vec<_>>()
            })
        })
        .collect();
    Ok(json!({
        "function": format!("{:#x}", entry),
        "block_count": blocks.len(),
        "blocks": blocks
    }))
}

pub fn get_function_summary(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let disasm = s.disasm.as_ref().ok_or("No disasm")?;
    let bin = s.binary.as_ref().ok_or("No binary")?;
    let f = function_containing(analysis, addr).ok_or_else(|| not_in_function(addr))?;
    let queried = addr;
    let addr = f.entry;

    let cfg = analysis.cfgs.get(&addr);
    let sf = analysis.stack_frames.get(&addr);
    let bb_count = cfg.map(|c| c.blocks.len()).unwrap_or(0);
    let xrefs_to_count = analysis
        .xrefs
        .by_to
        .get(&addr)
        .map(|v| v.len())
        .unwrap_or(0);
    let callers = analysis.callers.get(&addr).cloned().unwrap_or_default();
    let callees = analysis.callees.get(&addr).cloned().unwrap_or_default();

    let s_idx = disasm.instructions.partition_point(|i| i.address < f.entry);
    let e_idx = disasm.instructions.partition_point(|i| i.address < f.end);
    let preview: Vec<Value> = disasm.instructions[s_idx..e_idx]
        .iter()
        .take(15)
        .map(|ins| {
            json!({
                "addr": format!("{:#x}", ins.address),
                "mnemonic": ins.mnemonic,
                "operands": ins.ops().as_ref()
            })
        })
        .collect();

    let import_addrs: HashMap<u64, &str> = bin
        .imports
        .iter()
        .map(|i| (i.offset, i.name.as_str()))
        .collect();
    let mut used_imports: HashSet<&str> = HashSet::new();
    for ins in &disasm.instructions[s_idx..e_idx] {
        if (ins.mnemonic.starts_with("call") || ins.mnem() == "jmp")
            && let Some(target) = parse_addr(extract_hex_token(&ins.ops()).unwrap_or(&ins.ops()))
                && let Some(name) = import_addrs.get(&target) {
                    used_imports.insert(name);
                }
    }

    let mut used_strings: Vec<Value> = Vec::new();
    for ins in &disasm.instructions[s_idx..e_idx] {
        if let Some(refs) = analysis.xrefs.by_from.get(&ins.address) {
            for &i in refs {
                let xr = &analysis.xrefs.all[i];
                if matches!(xr.kind, crate::analysis::XRefKind::StringRef) && xr.note.is_some() {
                    used_strings.push(json!({
                        "from": format!("{:#x}", xr.from),
                        "to": format!("{:#x}", xr.to),
                        "content": xr.note.as_deref().unwrap_or("")
                    }));
                    if used_strings.len() >= 30 {
                        break;
                    }
                }
            }
        }
        if used_strings.len() >= 30 {
            break;
        }
    }

    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();

    let stub = analysis.stubs.get(&addr).map(|st| {
        json!({
            "kind": format!("{:?}", st.kind),
            "target": st.target_name
        })
    });

    let mut out = json!({
        "address": format!("{:#x}", f.entry),
        "name": f.name,
        "end": format!("{:#x}", f.end),
        "size": f.end - f.entry,
        "source": format!("{:?}", f.source),
        "has_frame": f.has_frame,
        "stack_size": f.stack_size,
        "basic_blocks": bb_count,
        "xrefs_to_count": xrefs_to_count,
        "callers_count": callers.len(),
        "callees_count": callees.len(),
        "stack_variables": sf.map(|s| s.variables.len()).unwrap_or(0),
        "is_stub": stub,
        "callers_names": callers.iter().take(10).map(|a| {
            json!({ "address": format!("{:#x}", a),
                    "name": func_lookup.get(a).copied().unwrap_or("?") })
        }).collect::<Vec<_>>(),
        "callees_names": callees.iter().take(20).map(|a| {
            json!({ "address": format!("{:#x}", a),
                    "name": func_lookup.get(a).copied().unwrap_or("?") })
        }).collect::<Vec<_>>(),
        "used_imports": used_imports.iter().collect::<Vec<_>>(),
        "used_strings": used_strings,
        "preview_first_instructions": preview,
        "decompiled_available": analysis.pseudocode.contains_key(&addr)
    });
    if queried != addr {
        out["queried_address"] = json!(format!("{:#x}", queried));
    }
    Ok(out)
}

pub fn get_annotated_disasm(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let disasm = s.disasm.as_ref().ok_or("No disasm")?;
    let f = function_containing(analysis, addr).ok_or_else(|| not_in_function(addr))?;

    let s_idx = disasm.instructions.partition_point(|i| i.address < f.entry);
    let e_idx = disasm.instructions.partition_point(|i| i.address < f.end);

    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();

    let mut lines: Vec<Value> = Vec::new();
    for ins in &disasm.instructions[s_idx..e_idx] {
        let mut annotations: Vec<String> = Vec::new();
        if let Some(c) = s.comments.get(&ins.address) {
            annotations.push(format!("// {}", c));
        }
        if (ins.mnemonic.starts_with("call") || ins.mnem() == "jmp")
            && let Some(target) = parse_addr(extract_hex_token(&ins.ops()).unwrap_or(&ins.ops()))
                && let Some(name) = func_lookup.get(&target) {
                    annotations.push(format!("→ {}", name));
                }
        if let Some(refs) = analysis.xrefs.by_from.get(&ins.address) {
            for &i in refs {
                let xr = &analysis.xrefs.all[i];
                if let Some(n) = &xr.note {
                    annotations.push(format!("[{:?}] {}", xr.kind, n));
                }
            }
        }
        let xref_in = analysis
            .xrefs
            .by_to
            .get(&ins.address)
            .map(|v| v.len())
            .unwrap_or(0);
        lines.push(json!({
            "address": format!("{:#x}", ins.address),
            "mnemonic": ins.mnemonic,
            "operands": ins.ops().as_ref(),
            "bytes": ins.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
            "xrefs_to_here": xref_in,
            "annotations": annotations
        }));
    }
    Ok(json!({
        "function": f.name,
        "address": format!("{:#x}", f.entry),
        "instruction_count": lines.len(),
        "lines": lines
    }))
}
