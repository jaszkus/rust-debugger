use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::parse_addr;

pub fn start_trace(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let max = arg_int(args, "max", 4096).clamp(16, 1_000_000) as usize;
    let mut s = try_state(state)?;
    s.debug_state.trace_active = true;
    s.debug_state.trace_max = max;
    s.debug_state.trace_buffer.clear();
    Ok(json!({ "ok": true, "max": max }))
}

pub fn stop_trace(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = try_state(state)?;
    s.debug_state.trace_active = false;
    Ok(json!({ "ok": true, "captured": s.debug_state.trace_buffer.len() }))
}

pub fn read_trace(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 1000).clamp(1, 1_000_000) as usize;
    let s = try_state(state)?;
    let total = s.debug_state.trace_buffer.len();
    let items: Vec<Value> = s
        .debug_state
        .trace_buffer
        .iter()
        .take(limit)
        .map(|t| {
            json!({
                "rip": format!("{:#x}", t.rip),
                "rax": format!("{:#x}", t.rax),
                "rcx": format!("{:#x}", t.rcx),
                "rdx": format!("{:#x}", t.rdx),
                "rsp": format!("{:#x}", t.rsp),
                "t": t.ts,
            })
        })
        .collect();
    Ok(json!({
        "total": total,
        "returned": items.len(),
        "active": s.debug_state.trace_active,
        "items": items,
    }))
}

pub fn save_trace(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let s = try_state(state)?;
    let items: Vec<Value> = s
        .debug_state
        .trace_buffer
        .iter()
        .map(|t| {
            json!({
                "rip": format!("{:#x}", t.rip),
                "rax": format!("{:#x}", t.rax),
                "rcx": format!("{:#x}", t.rcx),
                "rdx": format!("{:#x}", t.rdx),
                "rsp": format!("{:#x}", t.rsp),
                "t": t.ts,
            })
        })
        .collect();
    let text = serde_json::to_string(&items).map_err(|e| format!("trace serialize: {}", e))?;
    std::fs::write(&path, text).map_err(|e| format!("trace write {}: {}", path, e))?;
    Ok(json!({ "ok": true, "path": path, "saved": items.len() }))
}

pub fn load_trace(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let mut s = try_state(state)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("trace read {}: {}", path, e))?;
    let items: Vec<Value> =
        serde_json::from_str(&text).map_err(|e| format!("trace parse: {}", e))?;
    let mut loaded = 0usize;
    s.debug_state.trace_buffer.clear();
    for item in items {
        if s.debug_state.trace_buffer.len() >= s.debug_state.trace_max {
            break;
        }
        let num = |k: &str| -> u64 {
            item.get(k)
                .and_then(|v| v.as_str().and_then(parse_addr).or_else(|| v.as_u64()))
                .unwrap_or(0)
        };
        s.debug_state
            .trace_buffer
            .push(crate::debugger::TraceEntry {
                rip: num("rip"),
                rax: num("rax"),
                rcx: num("rcx"),
                rdx: num("rdx"),
                rsp: num("rsp"),
                ts: num("t"),
                snap: 0,
                instant: None,
            });
        loaded += 1;
    }
    s.debug_state.trace_buffer.sort_by_key(|t| t.ts);
    Ok(json!({ "ok": true, "path": path, "loaded": loaded }))
}
