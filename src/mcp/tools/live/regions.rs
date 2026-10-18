use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn list_memory_regions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let only_executable = args
        .get("only_executable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let only_writable = args
        .get("only_writable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let regions: Vec<crate::debugger::MemoryRegion> = wait_for(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.mem_regions_result = None;
            s.debug_state.mem_regions_request = Some(id);
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.mem_regions_result
                && *rid == id {
                    let (_, r) = s.debug_state.mem_regions_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        3000,
    )?;

    let items: Vec<Value> = regions
        .iter()
        .filter(|r| {
            let exec = matches!(r.protection & 0xf0, 0x10 | 0x20 | 0x40 | 0x80);
            let writ = matches!(r.protection & 0x0f, 0x04 | 0x08)
                || matches!(r.protection & 0xf0, 0x40 | 0x80);
            (!only_executable || exec) && (!only_writable || writ)
        })
        .map(|r| {
            let mut o = serde_json::Map::new();
            o.insert("base".into(), Value::String(format!("{:#x}", r.base)));
            o.insert("size".into(), Value::from(r.size));
            o.insert(
                "end".into(),
                Value::String(format!("{:#x}", r.base.saturating_add(r.size))),
            );
            o.insert(
                "protection".into(),
                Value::String(fmt_protection(r.protection).into()),
            );
            o.insert("type".into(), Value::String(fmt_region_type(r.kind).into()));
            if let Some(f) = &r.mapped_file {
                o.insert("mapped_file".into(), Value::String(f.clone()));
            }
            Value::Object(o)
        })
        .collect();

    Ok(json!({
        "count": items.len(),
        "regions": items,
    }))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn list_memory_regions(_args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn list_modules(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let modules: Vec<crate::debugger::ModuleInfo> = wait_for(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.modules_result = None;
            s.debug_state.modules_request = Some(id);
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.modules_result
                && *rid == id {
                    let (_, r) = s.debug_state.modules_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        3000,
    )?;

    let items: Vec<Value> = modules
        .iter()
        .map(|m| {
            json!({
                "name": m.name,
                "base": format!("{:#x}", m.base),
                "size": m.size,
                "end": format!("{:#x}", m.base.saturating_add(m.size)),
                "path": m.path,
            })
        })
        .collect();

    Ok(json!({
        "count": items.len(),
        "modules": items,
    }))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn list_modules(_args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn list_threads(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let tids: Vec<u32> = wait_for(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.threads_result = None;
            s.debug_state.threads_request = Some(id);
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.threads_result
                && *rid == id {
                    let (_, r) = s.debug_state.threads_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        3000,
    )?;
    let (active_tid, current_rip, is_running) = {
        let s = try_state(state)?;
        (
            s.debug_state.active_tid,
            s.debug_state.current_rip,
            s.debug_state.is_running,
        )
    };
    let threads: Vec<Value> = tids
        .iter()
        .map(|tid| {
            let is_active = *tid == active_tid;
            json!({
                "tid": tid,
                "state": if is_running { "running" } else { "parked" },
                "rip": format!("{:#x}", if is_active { current_rip } else { 0 }),
                "active": is_active
            })
        })
        .collect();
    Ok(json!({
        "count": tids.len(),
        "thread_ids": tids,
        "threads": threads,
        "active_tid": active_tid,
    }))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn list_threads(_args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}
