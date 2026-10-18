use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::{arg_int, arg_str_opt};
use crate::gui::AppState;

fn coff_chars(c: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if c & 0x0001 != 0 {
        v.push("RELOCS_STRIPPED");
    }
    if c & 0x0002 != 0 {
        v.push("EXECUTABLE_IMAGE");
    }
    if c & 0x0004 != 0 {
        v.push("LINE_NUMS_STRIPPED");
    }
    if c & 0x0008 != 0 {
        v.push("LOCAL_SYMS_STRIPPED");
    }
    if c & 0x0020 != 0 {
        v.push("LARGE_ADDRESS_AWARE");
    }
    if c & 0x0100 != 0 {
        v.push("32BIT_MACHINE");
    }
    if c & 0x0200 != 0 {
        v.push("DEBUG_STRIPPED");
    }
    if c & 0x1000 != 0 {
        v.push("SYSTEM");
    }
    if c & 0x2000 != 0 {
        v.push("DLL");
    }
    v
}

fn dll_chars(c: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if c & 0x0020 != 0 {
        v.push("HIGH_ENTROPY_VA");
    }
    if c & 0x0040 != 0 {
        v.push("DYNAMIC_BASE (ASLR)");
    }
    if c & 0x0080 != 0 {
        v.push("FORCE_INTEGRITY");
    }
    if c & 0x0100 != 0 {
        v.push("NX_COMPAT (DEP)");
    }
    if c & 0x0200 != 0 {
        v.push("NO_ISOLATION");
    }
    if c & 0x0400 != 0 {
        v.push("NO_SEH");
    }
    if c & 0x0800 != 0 {
        v.push("NO_BIND");
    }
    if c & 0x1000 != 0 {
        v.push("APPCONTAINER");
    }
    if c & 0x2000 != 0 {
        v.push("WDM_DRIVER");
    }
    if c & 0x4000 != 0 {
        v.push("GUARD_CF (CFG)");
    }
    if c & 0x8000 != 0 {
        v.push("TERMINAL_SERVER_AWARE");
    }
    v
}

pub fn get_pe_info(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    if !bin.format.starts_with("PE") {
        return Err(format!("Not a PE binary (format: {})", bin.format));
    }
    Ok(json!({
        "format": bin.format,
        "arch": bin.arch,
        "is_dll": bin.is_dll,
        "image_base": format!("{:#x}", bin.image_base),
        "entry_point": format!("{:#x}", bin.entry_point),
        "entry_point_rva": format!("{:#x}", bin.entry_point.wrapping_sub(bin.image_base)),
        "size": bin.data.len(),
        "section_count": bin.sections.len(),
        "import_count": bin.imports.len(),
        "export_count": bin.exports.len(),
        "coff_characteristics": format!("{:#06x}", bin.pe_characteristics),
        "coff_flags": coff_chars(bin.pe_characteristics),
        "dll_characteristics": format!("{:#06x}", bin.dll_characteristics),
        "dll_flags": dll_chars(bin.dll_characteristics),
    }))
}

pub fn list_exports_full(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 200).clamp(1, 10_000) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let only_forwarders = args
        .get("only_forwarders")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let filtered: Vec<&crate::parser::Export> = bin
        .exports
        .iter()
        .filter(|e| {
            (filter.is_empty() || e.name.to_lowercase().contains(&filter))
                && (!only_forwarders || e.forwarder.is_some())
        })
        .collect();
    let total = filtered.len();

    let items: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|e| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), Value::String(e.name.clone()));
            if e.ordinal != 0 {
                obj.insert("ordinal".into(), Value::from(e.ordinal));
            }
            if e.offset != 0 {
                obj.insert("address".into(), Value::String(format!("{:#x}", e.offset)));
                obj.insert(
                    "rva".into(),
                    Value::String(format!("{:#x}", e.offset.wrapping_sub(bin.image_base))),
                );
            }
            if let Some(fw) = &e.forwarder {
                obj.insert("forwarder".into(), Value::String(fw.clone()));
            }
            Value::Object(obj)
        })
        .collect();

    Ok(json!({
        "total": total,
        "returned": items.len(),
        "items": items,
    }))
}

pub fn lookup_export(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let ordinal = args
        .get("ordinal")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    if name.is_none() && ordinal.is_none() {
        return Err("Provide either 'name' or 'ordinal'".into());
    }

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let hit = bin.exports.iter().find(|e| {
        if let Some(n) = &name {
            return e.name == *n;
        }
        if let Some(o) = ordinal {
            return e.ordinal == o;
        }
        false
    });
    let hit = hit.ok_or("Export not found")?;
    Ok(json!({
        "name": hit.name,
        "ordinal": hit.ordinal,
        "address": format!("{:#x}", hit.offset),
        "rva": format!("{:#x}", hit.offset.wrapping_sub(bin.image_base)),
        "forwarder": hit.forwarder,
    }))
}

pub fn list_imported_libraries(
    _args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let mut by_lib: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for imp in &bin.imports {
        by_lib
            .entry(imp.library.clone())
            .or_default()
            .push(imp.name.clone());
    }
    let items: Vec<Value> = by_lib
        .into_iter()
        .map(|(lib, names)| {
            json!({
                "library": lib,
                "import_count": names.len(),
                "imports": names,
            })
        })
        .collect();
    Ok(json!({
        "library_count": items.len(),
        "libraries": items,
    }))
}

pub fn dll_export_summary(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let total = bin.exports.len();
    let forwarders = bin.exports.iter().filter(|e| e.forwarder.is_some()).count();
    let ordinal_only = bin
        .exports
        .iter()
        .filter(|e| e.name.starts_with("Ordinal"))
        .count();
    let named = total - ordinal_only;

    Ok(json!({
        "is_dll": bin.is_dll,
        "total_exports": total,
        "named_count": named,
        "ordinal_only_count": ordinal_only,
        "forwarder_count": forwarders,
        "real_code_count": total.saturating_sub(forwarders),
    }))
}
