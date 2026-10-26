use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::{arg_addr, arg_int, arg_str, arg_str_opt, parse_hex_pattern, vaddr_to_offset};
use super::parse_addr;
use crate::gui::AppState;

pub fn dump_section(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let section_name = arg_str(args, "section")?;
    let path = arg_str(args, "path")?;
    let (data, vaddr, name, size) = {
        let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        let sec = bin
            .sections
            .iter()
            .find(|s| s.name == section_name)
            .ok_or(format!("Section not found: {}", section_name))?;
        let start = sec.offset as usize;
        if start >= bin.data.len() {
            return Err(format!(
                "Section '{}' starts at file offset {:#x}, past end of file ({:#x})",
                sec.name,
                start,
                bin.data.len()
            ));
        }
        let end = start
            .saturating_add(sec.size as usize)
            .min(bin.data.len());
        (
            bin.data[start..end].to_vec(),
            sec.vaddr,
            sec.name.clone(),
            end - start,
        )
    };
    std::fs::write(&path, &data[..]).map_err(|e| format!("Write failed: {}", e))?;
    Ok(json!({
        "section": name,
        "vaddr": format!("{:#x}", vaddr),
        "size_written": size,
        "path": path
    }))
}

pub fn dump_range(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let size = arg_int(args, "size", 0).clamp(1, 1 << 28) as usize;
    let path = arg_str(args, "path")?;
    let (data, written) = {
        let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        let off = vaddr_to_offset(bin, addr).ok_or("Address not in any section")?;
        if off >= bin.data.len() {
            return Err(format!("Address {:#x} maps past end of file", addr));
        }
        let end = off.saturating_add(size).min(bin.data.len());
        (bin.data[off..end].to_vec(), end - off)
    };
    std::fs::write(&path, &data[..]).map_err(|e| format!("Write failed: {}", e))?;
    Ok(json!({
        "address": format!("{:#x}", addr),
        "size_written": written,
        "path": path
    }))
}

pub fn dump_full_binary(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let (data, size) = {
        let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        (bin.data.clone(), bin.data.len())
    };
    std::fs::write(&path, &data[..]).map_err(|e| format!("Write failed: {}", e))?;
    Ok(json!({
        "size": size,
        "path": path
    }))
}

pub fn load_binary(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let p = std::path::Path::new(&path);
    let bin = crate::parser::parse_file(p).map_err(|e| format!("Parse failed: {}", e))?;
    let disasm =
        crate::disasm::disassemble_binary(&bin).map_err(|e| format!("Disasm failed: {}", e))?;

    let format = bin.format.clone();
    let arch = bin.arch.clone();
    let entry = bin.entry_point;
    let size = bin.data.len();
    let n_sections = bin.sections.len();
    let n_imports = bin.imports.len();
    let n_exports = bin.exports.len();
    let n_strings = bin.strings.len();

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    s.binary = Some(bin);
    s.binary_generation = s.binary_generation.wrapping_add(1);
    s.disasm = Some(disasm);
    crate::gui::drop_analysis(&mut s);
    s.patches.clear();
    s.patch_seq = 0;
    s.file_path = path.clone();
    s.current_program_name.clear();
    s.program_slots.retain(|slot| slot.data.file_path != path);
    s.status_msg = format!("Loaded binary: {} ({}, {})", path, format, arch);

    Ok(json!({
        "path": path,
        "format": format,
        "arch": arch,
        "entry_point": format!("{:#x}", entry),
        "size": size,
        "sections": n_sections,
        "imports": n_imports,
        "exports": n_exports,
        "strings": n_strings,
        "ok": true,
        "note": "Run `run_analysis` to detect functions/xrefs."
    }))
}

pub fn load_memory_dump(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let base_addr = parse_addr(&arg_str_opt(args, "base_address")).unwrap_or(0);
    let arch = {
        let a = arg_str_opt(args, "arch");
        if a.is_empty() {
            "x86_64".to_string()
        } else {
            a
        }
    };

    let mut header4 = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open(&path) {
        use std::io::Read;
        let _ = f.read_exact(&mut header4);
    }
    let is_mdmp = crate::parser::minidump::looks_like_minidump(&header4);

    let (bin, kind_note) = if is_mdmp {
        let data = std::fs::read(&path).map_err(|e| format!("Read failed: {}", e))?;
        match crate::parser::minidump::parse_minidump_binary(data) {
            Ok(b) => {
                let ranges = b.sections.len();
                (
                    b,
                    format!("minidump ({} memory regions mapped at real VAs)", ranges),
                )
            }
            Err(e) => return Err(format!("Minidump parse failed: {}", e)),
        }
    } else {
        let p = std::path::Path::new(&path);
        let bin = crate::parser::parse_raw(p, base_addr, &arch)
            .map_err(|e| format!("Load failed: {}", e))?;
        (bin, "raw".to_string())
    };
    let disasm =
        crate::disasm::disassemble_binary(&bin).map_err(|e| format!("Disasm failed: {}", e))?;

    let n_sections = bin.sections.len();
    let n_modules = bin
        .symbols
        .iter()
        .filter(|s| s.name.starts_with("module_"))
        .count();
    let entry = bin.entry_point;
    let first_va = bin.sections.first().map(|s| s.vaddr).unwrap_or(0);
    let last_va = bin.sections.last().map(|s| s.vaddr + s.size).unwrap_or(0);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    s.binary = Some(bin);
    s.binary_generation = s.binary_generation.wrapping_add(1);
    s.disasm = Some(disasm);
    crate::gui::drop_analysis(&mut s);
    s.patches.clear();
    s.patch_seq = 0;
    s.file_path = path.clone();
    s.current_program_name.clear();
    s.status_msg = format!("Loaded dump: {} ({})", path, kind_note);

    Ok(json!({
        "path": path,
        "kind": if is_mdmp { "minidump" } else { "raw" },
        "base_address": format!("{:#x}", first_va),
        "va_range": [format!("{:#x}", first_va), format!("{:#x}", last_va)],
        "regions": n_sections,
        "modules": n_modules,
        "entry_point": format!("{:#x}", entry),
        "arch": arch,
        "ok": true,
        "note": "Addresses are real virtual addresses; dump_range/search work per-VA."
    }))
}

pub fn load_map_file(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let base_offset = parse_addr(&arg_str_opt(args, "base_offset")).unwrap_or(0);

    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read map file '{}': {}", path, e))?;
    let mut syms = crate::parser::mapfile::parse_msvc_map(&text);
    if syms.is_empty() {
        return Err(format!(
            "No public symbols found in '{}' (expected MSVC linker map format)",
            path
        ));
    }
    if base_offset != 0 {
        for s in syms.iter_mut() {
            s.addr = s.addr.wrapping_add(base_offset);
        }
    }

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = match s.binary.as_mut() {
        Some(b) => b,
        None => return Err("No binary loaded. Call load_binary first.".into()),
    };
    let arch_note = bin.arch.clone();
    let is_auto = |n: &str| n.starts_with("sub_") || n.starts_with("loc_") || n.starts_with("FUN_");
    let before = bin.symbols.len();
    for sym in syms.drain(..) {
        match bin.symbols.iter_mut().find(|e| e.addr == sym.addr) {
            Some(existing) => {
                if is_auto(&existing.name) {
                    existing.name = sym.name;
                    existing.is_function = true;
                }
            }
            None => bin.symbols.push(sym),
        }
    }
    bin.symbols.sort_by_key(|x| x.addr);
    let added = bin.symbols.len() - before;
    Ok(json!({
        "path": path,
        "symbols_added": added,
        "symbols_total": bin.symbols.len(),
        "arch": arch_note,
        "note": "Run run_analysis again to rebuild function names/xrefs with the imported symbols."
    }))
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn read_process_memory(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let size = arg_int(args, "size", 256).clamp(1, 1 << 22) as usize;

    let id = {
        let mut s = super::lock::lock_state(state)?;
        if !s.debug_state.is_attached {
            return Err("No debugger attached. Call debugger_start first.".into());
        }
        s.debug_state.mem_request_seq += 1;
        let id = s.debug_state.mem_request_seq;
        s.debug_state.mem_read_result = None;
        s.debug_state.mem_read_request = Some(crate::debugger::MemReadRequest {
            id,
            address: addr,
            size,
        });
        id
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    {
        if let Ok(s) = state.try_lock() {
            s.debug_state.signal.notify();
        }
    }
    loop {
        let mut s = match state.try_lock() {
            Ok(g) => g,
            Err(_) => {
                if std::time::Instant::now() >= deadline {
                    return Err(
                        "Service unavailable (503): state busy waiting for debugger read".into(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
        };
        if let Some(res) = &s.debug_state.mem_read_result
            && res.id == id {
                let res = s.debug_state.mem_read_result.take().unwrap();
                let bytes = res.data?;
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                let ascii: String = bytes
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                return Ok(json!({
                    "address": format!("{:#x}", res.address),
                    "size": bytes.len(),
                    "hex": hex,
                    "ascii": ascii,
                }));
            }
        let sig = s.debug_state.signal.clone();
        drop(s);
        sig.wait(std::time::Duration::from_millis(5));
        if std::time::Instant::now() >= deadline {
            return Err("Timed out waiting for the debugger thread to service the read (target paused on an unhandled debug event? try debugger_continue)".into());
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn read_process_memory(_args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn write_process_memory(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let bytes_str = arg_str(args, "bytes")?;
    let bytes = parse_hex_pattern(&bytes_str)?;
    if bytes.is_empty() {
        return Err("Empty bytes".into());
    }

    let id = {
        let mut s = super::lock::lock_state(state)?;
        if !s.debug_state.is_attached {
            return Err("No debugger attached. Call debugger_start first.".into());
        }
        s.debug_state.mem_request_seq += 1;
        let id = s.debug_state.mem_request_seq;
        s.debug_state.mem_write_result = None;
        s.debug_state.mem_write_request = Some(crate::debugger::MemWriteRequest {
            id,
            address: addr,
            bytes: bytes.clone(),
        });
        id
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    {
        if let Ok(s) = state.try_lock() {
            s.debug_state.signal.notify();
        }
    }
    loop {
        let mut s = match state.try_lock() {
            Ok(g) => g,
            Err(_) => {
                if std::time::Instant::now() >= deadline {
                    return Err(
                        "Service unavailable (503): state busy waiting for debugger write".into(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
        };
        if let Some(res) = &s.debug_state.mem_write_result
            && res.id == id {
                let res = s.debug_state.mem_write_result.take().unwrap();
                let written = res.written?;
                return Ok(json!({
                    "address": format!("{:#x}", res.address),
                    "size": bytes.len(),
                    "written": written,
                    "ok": true,
                }));
            }
        let sig = s.debug_state.signal.clone();
        drop(s);
        sig.wait(std::time::Duration::from_millis(5));
        if std::time::Instant::now() >= deadline {
            return Err("Timed out waiting for the debugger thread to service the write (target paused on an unhandled debug event? try debugger_continue)".into());
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn write_process_memory(_args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}

pub fn get_debugger_status(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = super::lock::lock_state(state)?;
    let d = &s.debug_state;
    Ok(json!({
        "is_attached": d.is_attached,
        "is_running": d.is_running,
        "process_id": d.process_id,
        "thread_id": d.thread_id,
        "current_rip": format!("{:#x}", d.current_rip),
        "registers": {
            "rax": format!("{:#x}", d.registers.rax),
            "rbx": format!("{:#x}", d.registers.rbx),
            "rcx": format!("{:#x}", d.registers.rcx),
            "rdx": format!("{:#x}", d.registers.rdx),
            "rsi": format!("{:#x}", d.registers.rsi),
            "rdi": format!("{:#x}", d.registers.rdi),
            "rbp": format!("{:#x}", d.registers.rbp),
            "rsp": format!("{:#x}", d.registers.rsp),
            "rip": format!("{:#x}", d.registers.rip),
            "eflags": format!("{:#x}", d.registers.eflags),
        },
        "breakpoint_count": d.breakpoints.len(),
        "events_recent": d.events.iter().rev().take(10).cloned().collect::<Vec<_>>(),
    }))
}

pub fn debugger_start(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    if let Some(p) = args.get("path").and_then(|v| v.as_str())
        && !p.is_empty() {
            s.file_path = p.to_string();
        }
    if s.file_path.is_empty() {
        return Err("Set state.file_path first (Open a binary, or pass `path`)".into());
    }
    s.debug_state.start_debug = true;
    Ok(json!({ "ok": true, "queued": "start_debug", "path": s.file_path.clone() }))
}

pub fn debugger_step_into(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    s.debug_state.step_into = true;
    Ok(json!({ "ok": true, "queued": "step_into" }))
}

pub fn debugger_step_over(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    s.debug_state.step_over = true;
    Ok(json!({ "ok": true, "queued": "step_over" }))
}

pub fn debugger_continue(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    s.debug_state.continue_exec = true;
    Ok(json!({ "ok": true, "queued": "continue" }))
}

pub fn debugger_pause(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    if !s.debug_state.is_attached {
        return Err("No debugger attached. Call debugger_start first.".into());
    }
    s.debug_state.break_exec = true;
    {
        let sig = s.debug_state.signal.clone();
        sig.notify();
    }
    Ok(json!({ "ok": true, "queued": "pause" }))
}

pub fn debugger_stop(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    s.debug_state.stop = true;
    Ok(json!({ "ok": true, "queued": "stop" }))
}

pub fn add_breakpoint(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let attached = {
        let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        s.debug_state.is_attached
    };
    if attached {
        return super::live::arm_software_breakpoint(
            &json!({ "address": format!("{:#x}", addr) }),
            state,
        );
    }
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    if s.debug_state.breakpoints.iter().any(|b| b.address == addr) {
        return Err(format!("Breakpoint already exists at {:#x}", addr));
    }
    s.debug_state.breakpoints.push(crate::debugger::Breakpoint {
        address: addr,
        enabled: true,
        original_byte: 0,
        name: format!("bp_{:X}", addr),
        kind: crate::debugger::BpKind::SwExec,
        len: 1,
        planted: false,
    });
    Ok(json!({ "address": format!("{:#x}", addr), "ok": true }))
}

pub fn remove_breakpoint(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let (original, attached) = {
        let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        let original = s
            .debug_state
            .breakpoints
            .iter()
            .find(|b| b.address == addr)
            .map(|b| b.original_byte)
            .unwrap_or(0);
        s.debug_state.breakpoints.retain(|b| b.address != addr);
        (original, s.debug_state.is_attached)
    };
    if attached && original != 0 && original != 0xCC {
        let _ = write_process_memory(
            &json!({ "address": format!("{:#x}", addr), "bytes": format!("{:02x}", original) }),
            state,
        );
    }
    Ok(json!({ "address": format!("{:#x}", addr), "removed": true }))
}

pub fn list_breakpoints(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let items: Vec<Value> = s
        .debug_state
        .breakpoints
        .iter()
        .map(|b| {
            json!({
                "address": format!("{:#x}", b.address),
                "enabled": b.enabled,
                "name": b.name,
                "kind": b.kind.as_str(),
                "len": b.len,
                "original_byte": format!("{:#04x}", b.original_byte)
            })
        })
        .collect();
    Ok(json!({ "count": items.len(), "breakpoints": items }))
}

pub fn list_watchpoints(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let items: Vec<Value> = s
        .debug_state
        .breakpoints
        .iter()
        .filter(|b| !matches!(b.kind, crate::debugger::BpKind::SwExec))
        .map(|b| {
            json!({
                "address": format!("{:#x}", b.address),
                "enabled": b.enabled,
                "name": b.name,
                "kind": b.kind.as_str(),
                "len": b.len
            })
        })
        .collect();
    Ok(json!({ "count": items.len(), "watchpoints": items }))
}
