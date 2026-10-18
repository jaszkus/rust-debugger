use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::schemas::arg_query;
use std::collections::HashMap;

pub fn list_stubs(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 200).max(1) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();

    let mut all: Vec<(&u64, &crate::analysis::StubInfo)> = analysis.stubs.iter().collect();
    all.sort_by_key(|(a, _)| **a);
    let total = all.len();
    let items: Vec<Value> = all
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(addr, info)| {
            json!({
                "address": format!("{:#x}", addr),
                "function_name": func_lookup.get(addr).copied().unwrap_or("?"),
                "kind": format!("{:?}", info.kind),
                "target": info.target_name
            })
        })
        .collect();
    Ok(json!({ "total": total, "offset": offset, "limit": limit, "items": items }))
}

pub fn list_switch_tables(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 200).max(1) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let items: Vec<Value> = analysis
        .switches
        .iter()
        .take(limit)
        .map(|sw| {
            json!({
                "jump_address": format!("{:#x}", sw.jump_addr),
                "table_address": format!("{:#x}", sw.table_addr),
                "case_count": sw.case_count,
                "targets": sw.case_targets.iter().map(|t| format!("{:#x}", t)).collect::<Vec<_>>()
            })
        })
        .collect();
    Ok(json!({ "total": analysis.switches.len(), "items": items }))
}

pub fn find_format_strings(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 200).max(1) as usize;
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let mut items: Vec<Value> = Vec::new();
    let mut total = 0usize;
    for st in &bin.strings {
        if has_format_specifier(&st.content) {
            if total >= offset && items.len() < limit {
                items.push(json!({
                    "address": format!("{:#x}", st.vaddr),
                    "encoding": match st.encoding {
                        crate::parser::StringEncoding::Ascii => "ascii",
                        crate::parser::StringEncoding::Utf16Le => "utf16le",
                        crate::parser::StringEncoding::Utf32Le => "utf32le",
                        crate::parser::StringEncoding::Pascal => "pascal",
                    },
                    "content": st.content
                }));
            }
            total += 1;
        }
    }
    let returned = items.len();
    let has_more = offset + returned < total;
    let mut out = json!({
        "total": total,
        "count": returned,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
        "items": items
    });
    if has_more {
        out["next_offset"] = json!(offset + returned);
    }
    Ok(out)
}

fn has_format_specifier(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 1 < bytes.len() {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit()
                    || bytes[j] == b'.'
                    || bytes[j] == b'-'
                    || bytes[j] == b'+'
                    || bytes[j] == b' '
                    || bytes[j] == b'#'
                    || bytes[j] == b'l'
                    || bytes[j] == b'h')
            {
                j += 1;
            }
            if j < bytes.len() {
                match bytes[j] {
                    b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'c' | b's' | b'f' | b'e' | b'E'
                    | b'g' | b'G' | b'p' => return true,
                    _ => {}
                }
            }
        }
        i += 1;
    }
    false
}

pub fn search_in_decompiled(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let q = arg_query(args)?.to_lowercase();
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();

    let mut hits: Vec<Value> = Vec::new();
    for (entry, pc) in &analysis.pseudocode {
        for line in &pc.lines {
            if line.text.to_lowercase().contains(&q) {
                hits.push(json!({
                    "function_address": format!("{:#x}", entry),
                    "function_name": func_lookup.get(entry).copied().unwrap_or("?"),
                    "source_address": line.source_addr.map(|a| format!("{:#x}", a)),
                    "line": line.text.clone()
                }));
                if hits.len() >= limit {
                    break;
                }
            }
        }
        if hits.len() >= limit {
            break;
        }
    }
    Ok(json!({ "query": q, "count": hits.len(), "hits": hits }))
}

pub fn search_instruction_pattern(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let pattern = arg_str(args, "pattern")?;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let mnemonics: Vec<String> = pattern
        .split([';', ','])
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if mnemonics.is_empty() {
        return Err("Empty pattern".to_string());
    }

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let disasm = s.disasm.as_ref().ok_or("No disasm")?;

    let n = disasm.instructions.len();
    let mut hits: Vec<Value> = Vec::new();
    let mut seen = 0usize;
    let mut has_more = false;
    let plen = mnemonics.len();
    let mut i = 0;
    while i + plen <= n {
        let mut matched = true;
        for (k, m) in mnemonics.iter().enumerate() {
            if disasm.instructions[i + k].mnem() != m {
                matched = false;
                break;
            }
        }
        if matched {
            seen += 1;
            if seen <= offset {
                i += plen;
                continue;
            }
            if hits.len() >= limit {
                has_more = true;
                break;
            }
            let seq: Vec<Value> = (i..i + plen)
                .map(|j| {
                    let ins = &disasm.instructions[j];
                    json!({
                        "address": format!("{:#x}", ins.address),
                        "mnemonic": ins.mnemonic,
                        "operands": ins.ops().as_ref()
                    })
                })
                .collect();
            hits.push(json!({
                "start_address": format!("{:#x}", disasm.instructions[i].address),
                "sequence": seq
            }));
            i += plen;
        } else {
            i += 1;
        }
    }
    let mut out = json!({
        "pattern": pattern,
        "count": hits.len(),
        "offset": offset,
        "has_more": has_more,
        "hits": hits
    });
    if has_more {
        out["next_offset"] = json!(offset + hits.len());
    }
    Ok(out)
}

pub fn find_immediate_refs(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let limit = arg_int(args, "limit", 200).clamp(1, 1 << 16) as usize;
    let only_executable = args
        .get("only_executable")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let arch_is_64 = bin.arch == "x86_64" || bin.arch == "aarch64";
    let needle32 = (addr as u32).to_le_bytes();
    let needle64 = addr.to_le_bytes();

    let mut refs32: Vec<Value> = Vec::new();
    let mut refs64: Vec<Value> = Vec::new();

    'outer: for sec in &bin.sections {
        if only_executable && !sec.is_executable {
            continue;
        }
        let so = sec.offset as usize;
        let se = (so + sec.size as usize).min(bin.data.len());
        if se <= so {
            continue;
        }
        let slice = &bin.data[so..se];

        if slice.len() >= 4 {
            let mut i = 0;
            while i + 4 <= slice.len() {
                if slice[i..i + 4] == needle32 {
                    let off = so + i;
                    let vaddr = sec.vaddr + (off as u64 - sec.offset);
                    refs32.push(json!({
                        "section": sec.name,
                        "offset": off,
                        "address": format!("{:#x}", vaddr),
                        "preceding_byte": format!("{:#04x}", if off > 0 { bin.data[off - 1] } else { 0 }),
                    }));
                    if refs32.len() + refs64.len() >= limit {
                        break 'outer;
                    }
                }
                i += 1;
            }
        }
        if arch_is_64 && slice.len() >= 8 {
            let mut i = 0;
            while i + 8 <= slice.len() {
                if slice[i..i + 8] == needle64 {
                    let off = so + i;
                    let vaddr = sec.vaddr + (off as u64 - sec.offset);
                    refs64.push(json!({
                        "section": sec.name,
                        "offset": off,
                        "address": format!("{:#x}", vaddr),
                    }));
                    if refs32.len() + refs64.len() >= limit {
                        break 'outer;
                    }
                }
                i += 1;
            }
        }
    }

    Ok(json!({
        "target": format!("{:#x}", addr),
        "arch": bin.arch,
        "only_executable": only_executable,
        "matches_32bit": refs32.len(),
        "matches_64bit": refs64.len(),
        "refs_32bit": refs32,
        "refs_64bit": refs64,
    }))
}

pub fn scan_rtti(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 100).clamp(1, 1000) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let mut classes = crate::analysis::rtti::scan_msvc_rtti(bin);
    let mut flavor = "msvc";
    if classes.is_empty() {
        classes = crate::analysis::rtti::scan_itanium_rtti(bin);
        flavor = "itanium";
    }
    let total = classes.len();
    let filtered: Vec<&crate::analysis::rtti::RttiClass> = classes
        .iter()
        .filter(|c| filter.is_empty() || c.name.to_lowercase().contains(&filter))
        .collect();

    let items: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|c| {
            json!({
                "name": c.name,
                "type_descriptor": format!("{:#x}", c.type_descriptor),
                "col": format!("{:#x}", c.col),
                "vftable": c.vftable.map(|v| format!("{:#x}", v)),
                "first_vfunc": c.first_vfunc.map(|v| format!("{:#x}", v)),
            })
        })
        .collect();

    Ok(json!({
        "total": total,
        "returned": items.len(),
        "offset": offset,
        "items": items,
        "arch": bin.arch,
        "flavor": flavor,
        "note": "MSVC: x64 COLs validated via self-RVA, vftables by pointer sweep. Itanium fallback: _ZTV paired with _ZTI/_ZTS by demangled name, vftable = sym + 2*ptr."
    }))
}
