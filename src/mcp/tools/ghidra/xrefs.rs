use serde_json::{json, Value};

use std::sync::{Arc, Mutex};

use crate::analysis::XRefKind;
use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::parse_addr;

fn xref_kind_str(k: &XRefKind) -> &'static str {
    match k {
        XRefKind::Call => "call",
        XRefKind::Jump => "jump",
        XRefKind::CallIndirect => "call_indirect",
        XRefKind::JumpIndirect => "jump_indirect",
        XRefKind::TailCall => "tail_call",
        XRefKind::Thunk => "thunk",
        XRefKind::DataRead => "data_read",
        XRefKind::DataWrite => "data_write",
        XRefKind::DataAddr => "data_addr",
        XRefKind::StringRef => "string_ref",
    }
}

pub fn get_function_xrefs(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let addr = arg_addr(args, "address")?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let f = a
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
        .ok_or("Address not in any function")?;
    let mut to_fn: Vec<Value> = Vec::new();
    let mut from_fn: Vec<Value> = Vec::new();
    for x in &a.xrefs.all {
        if x.to >= f.entry && x.to < f.end {
            to_fn.push(json!({
                "from": addr_str(x.from),
                "to": addr_str(x.to),
                "kind": xref_kind_str(&x.kind),
                "note": x.note.as_deref().unwrap_or("")
            }));
        }
        if x.from >= f.entry && x.from < f.end {
            from_fn.push(json!({
                "from": addr_str(x.from),
                "to": addr_str(x.to),
                "kind": xref_kind_str(&x.kind),
                "note": x.note.as_deref().unwrap_or("")
            }));
        }
    }
    Ok(json!({
        "function": addr_str(f.entry),
        "name": f.name,
        "xrefs_to_function": to_fn.len(),
        "xrefs_from_function": from_fn.len(),
        "to": to_fn,
        "from": from_fn
    }))
}

pub fn get_bulk_xrefs(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let list = args
        .get("addresses")
        .and_then(|v| v.as_array())
        .ok_or("Missing required argument: addresses (array of hex strings)")?;
    let mut results: Vec<Value> = Vec::new();
    for item in list {
        let raw = item.as_str().unwrap_or("");
        if let Some(addr) = parse_addr(raw) {
            let refs: Vec<Value> = a
                .xrefs
                .xrefs_to(addr)
                .iter()
                .map(|x| {
                    json!({
                        "from": addr_str(x.from),
                        "kind": xref_kind_str(&x.kind),
                        "note": x.note.as_deref().unwrap_or("")
                    })
                })
                .collect();
            results.push(
                json!({ "address": addr_str(addr), "xref_count": refs.len(), "xrefs": refs }),
            );
        }
    }
    Ok(json!({ "count": results.len(), "results": results }))
}

pub fn add_memory_reference(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let from = arg_addr(args, "from")?;
    let to = arg_addr(args, "to")?;
    let note = arg_str_opt(args, "note");
    let kind = args
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let op_index = args.get("op_index").and_then(|v| v.as_i64()).unwrap_or(-1) as i32;
    s.user_xrefs.push(crate::gui::UserXRef {
        from,
        to,
        note: note.clone(),
        kind: kind.clone(),
        op_index,
    });
    Ok(
        json!({ "ok": true, "from": addr_str(from), "to": addr_str(to), "note": note, "kind": kind, "op_index": op_index }),
    )
}

pub fn remove_reference(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let from = arg_addr(args, "from")?;
    let to = arg_addr(args, "to")?;
    let kind = args.get("kind").and_then(|v| v.as_str());
    let op = args
        .get("op_index")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let before = s.user_xrefs.len();
    s.user_xrefs.retain(|x| {
        if x.from != from || x.to != to {
            return true;
        }
        if let Some(k) = kind {
            if x.kind != k {
                return true;
            }
        }
        if let Some(o) = op {
            if x.op_index != o {
                return true;
            }
        }
        false
    });
    Ok(json!({ "ok": true, "removed": before - s.user_xrefs.len() }))
}

pub fn list_memory_references(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let rows: Vec<Value> = s.user_xrefs.iter()
        .map(|x| json!({ "from": addr_str(x.from), "to": addr_str(x.to), "note": x.note, "kind": x.kind, "op_index": x.op_index }))
        .collect();
    Ok(json!({ "count": rows.len(), "references": rows }))
}
