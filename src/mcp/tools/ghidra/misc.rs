use serde_json::{json, Value};

use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

pub fn check_connection(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let name = s
        .file_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("<none>")
        .to_string();
    Ok(json!({
        "connected": true,
        "program": name,
        "message": format!("Connected: rust-debugger plugin running with program '{}'", name)
    }))
}

pub fn health(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    Ok(json!({
        "status": "ok",
        "binary_loaded": s.binary.is_some(),
        "analysis_loaded": s.analysis.is_some(),
        "debugger_attached": s.debug_state.is_attached,
        "breakpoints": s.debug_state.breakpoints.len(),
        "patches": s.patches.len(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

pub fn get_version(_state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": "rust-debugger",
        "features": ["disasm", "analysis", "decompiler", "pcode", "patching", "live-debugger", "mcp"]
    }))
}

pub fn debugger_stack_trace(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let max_frames = 64usize;
    let mut frames: Vec<Value> = Vec::new();
    let ptr_size = {
        let s = lock(state)?;
        s.binary
            .as_ref()
            .map(|b| if b.arch.contains("64") { 8usize } else { 4 })
            .unwrap_or(8)
    };
    let regs = {
        let s = lock(state)?;
        if !s.debug_state.is_attached {
            return Err("No debugger attached".into());
        }
        let r = s.debug_state.registers.clone();
        (r.rbp, r.rip, r.rsp)
    };
    let (mut cur, rip, rsp) = regs;
    let need = ptr_size * 2;
    let mut depth = 0;
    while cur != 0 && depth < max_frames {
        let data = match crate::mcp::tools::live::read_proc_mem_blocking(state, cur, need) {
            Ok(d) => d,
            Err(_) => break,
        };
        if data.len() < need {
            break;
        }
        let read_word = |off: usize| -> u64 {
            let bytes = &data[off..off + ptr_size];
            let mut v = [0u8; 8];
            v[..ptr_size].copy_from_slice(bytes);
            u64::from_le_bytes(v)
        };
        let next_fp = read_word(0);
        let ret = read_word(ptr_size);
        let name = function_name_at(state, ret).unwrap_or_else(|| "??".to_string());
        frames.push(json!({
            "frame": depth,
            "return_address": addr_str(ret),
            "ebp": addr_str(cur),
            "function": name
        }));
        if next_fp <= cur {
            break;
        }
        cur = next_fp;
        depth += 1;
    }
    if frames.is_empty() {
        return Ok(json!({
            "frames": [],
            "note": "no classic EBP chain (frame-pointer omission); use debugger_status for registers",
            "rsp": addr_str(rsp),
            "rip": addr_str(rip)
        }));
    }
    Ok(json!({ "frames": frames, "count": frames.len() }))
}

fn function_name_at(state: &Arc<Mutex<AppState>>, addr: u64) -> Option<String> {
    let s = lock(state).ok()?;
    let a = s.analysis.as_ref()?;
    for f in &a.functions {
        if addr >= f.entry && addr < f.end {
            return Some(f.name.clone());
        }
    }
    let bin = s.binary.as_ref()?;
    for sym in &bin.symbols {
        if sym.addr == addr {
            return Some(sym.name.clone());
        }
    }
    None
}
