use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

pub fn list_data_items(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let include_code = args
        .get("include_code_strings")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut items: Vec<Value> = Vec::new();
    for str_ in &bin.strings {
        let Some(sec) = bin
            .sections
            .iter()
            .find(|sec| str_.vaddr >= sec.vaddr && str_.vaddr < sec.vaddr.saturating_add(sec.size))
        else {
            continue;
        };
        if sec.is_executable && !include_code {
            continue;
        }
        if !filter.is_empty() && !str_.content.to_lowercase().contains(&filter) {
            continue;
        }
        items.push(json!({
            "address": addr_str(str_.vaddr),
            "value": str_.content,
            "type": if str_.encoding == crate::parser::StringEncoding::Utf16Le { "unicode" } else { "string" },
            "section": sec.name
        }));
    }
    let total = items.len();
    let page = paginate(&items, offset, limit);
    Ok(json!({ "total": total, "count": page.len(), "items": page }))
}

pub fn list_globals(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let mut items: Vec<Value> = Vec::new();
    for sym in &bin.symbols {
        let sec = section_name_for(bin, sym.addr);
        if sec.is_empty() {
            continue;
        }
        items.push(json!({
            "address": addr_str(sym.addr),
            "name": sym.name,
            "size": sym.size,
            "section": sec,
            "is_function": sym.is_function
        }));
    }
    let total = items.len();
    let page = paginate(&items, offset, limit);
    Ok(json!({ "total": total, "count": page.len(), "items": page }))
}

pub fn list_namespaces(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let mut namespaces: HashMap<String, usize> = HashMap::new();
    for f in &a.functions {
        if let Some(idx) = f.name.find("::") {
            *namespaces.entry(f.name[..idx].to_string()).or_insert(0) += 1;
        }
    }
    let mut rows: Vec<Value> = namespaces
        .iter()
        .map(|(n, c)| json!({ "namespace": n, "function_count": c }))
        .collect();
    rows.sort_by(|a, b| {
        a["function_count"]
            .as_u64()
            .cmp(&b["function_count"].as_u64())
            .reverse()
    });
    Ok(json!({ "count": rows.len(), "namespaces": rows }))
}

pub fn list_classes(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let mut classes: HashMap<String, usize> = HashMap::new();
    for f in &a.functions {
        let name = f.name.clone();
        if let Some(idx) = name.find("::") {
            *classes.entry(name[..idx].to_string()).or_insert(0) += 1;
        }
    }
    let mut rows: Vec<Value> = classes
        .iter()
        .map(|(n, c)| json!({ "class": n, "method_count": c }))
        .collect();
    rows.sort_by(|a, b| {
        a["method_count"]
            .as_u64()
            .cmp(&b["method_count"].as_u64())
            .reverse()
    });
    Ok(json!({ "count": rows.len(), "classes": rows }))
}

pub fn list_calling_conventions(_state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Ok(json!({
        "conventions": [
            {"name": "__cdecl", "arch": "x86", "description": "caller cleans the stack"},
            {"name": "__stdcall", "arch": "x86", "description": "callee cleans the stack"},
            {"name": "__thiscall", "arch": "x86", "description": "this in ECX"},
            {"name": "__fastcall", "arch": "x86", "description": "first args in ECX/EDX"},
            {"name": "Microsoft x64", "arch": "x86_64", "description": "RCX/RDX/R8/R9, 32-byte shadow space"},
            {"name": "System V AMD64", "arch": "x86_64", "description": "RDI/RSI/RDX/RCX/R8/R9"},
            {"name": "AAPCS64", "arch": "aarch64", "description": "X0-X7, stack aligned 16"}
        ]
    }))
}

pub fn list_valid_data_types(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let primitives: Vec<String> = s
        .types
        .all()
        .iter()
        .filter(|(_, dt)| {
            matches!(
                dt,
                crate::type_system::DataType::Primitive { .. }
                    | crate::type_system::DataType::String
            )
        })
        .map(|(id, _)| s.types.type_name(*id))
        .collect();
    Ok(json!({
        "types": primitives,
        "derived": ["T*", "T[N]", "struct", "union", "enum", "typedef"],
        "aliases": {
            "byte": "uchar", "word": "ushort", "dword": "uint", "qword": "ulonglong",
            "int8_t": "char", "uint8_t": "uchar", "int16_t": "short", "uint16_t": "ushort",
            "int32_t": "int", "uint32_t": "uint", "int64_t": "longlong", "uint64_t": "ulonglong",
            "unicode": "string"
        },
        "note": "Aliases and derived forms (e.g. 'char*', 'char[10]', 'dword') are accepted everywhere a type name is expected."
    }))
}
