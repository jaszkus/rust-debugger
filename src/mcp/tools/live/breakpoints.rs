use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn set_hardware_breakpoint(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let slot = arg_int(args, "slot", 0).clamp(0, 3) as u8;
    let kind_str = args
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("execute");
    let len_int = arg_int(args, "len", 1).clamp(1, 8);
    let kind = match kind_str {
        "execute" | "x" => crate::debugger::HwBpKind::Execute,
        "write" | "w" => crate::debugger::HwBpKind::Write,
        "read" | "r" => crate::debugger::HwBpKind::Read,
        "rw" | "readwrite" | "access" => crate::debugger::HwBpKind::ReadWrite,
        _ => {
            return Err(format!(
                "Unknown kind: {} (use execute/write/read/rw)",
                kind_str
            ))
        }
    };
    let len = match len_int {
        1 => crate::debugger::HwBpLen::One,
        2 => crate::debugger::HwBpLen::Two,
        4 => crate::debugger::HwBpLen::Four,
        8 => crate::debugger::HwBpLen::Eight,
        _ => return Err("len must be 1/2/4/8".into()),
    };

    let _: () = wait_for(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.hw_bp_result = None;
            s.debug_state.hw_bp_request = Some(crate::debugger::HwBpRequest::Set {
                id,
                slot,
                address: addr,
                kind,
                len,
            });
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.hw_bp_result
                && *rid == id {
                    let (_, r) = s.debug_state.hw_bp_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        3000,
    )?;
    {
        let mut s = try_state(state)?;
        let (bpkind, blen) = match kind {
            crate::debugger::HwBpKind::Execute => (crate::debugger::BpKind::HwExec, 1u8),
            crate::debugger::HwBpKind::Write => (crate::debugger::BpKind::Write, len_int as u8),
            crate::debugger::HwBpKind::Read => (crate::debugger::BpKind::Read, len_int as u8),
            crate::debugger::HwBpKind::ReadWrite => {
                (crate::debugger::BpKind::Access, len_int as u8)
            }
        };
        let name = format!("hw{}", slot);
        if let Some(bp) = s
            .debug_state
            .breakpoints
            .iter_mut()
            .find(|b| b.name == name)
        {
            bp.address = addr;
            bp.enabled = true;
            bp.kind = bpkind;
            bp.len = blen;
        } else {
            s.debug_state
                .breakpoints
                .retain(|b| b.address != addr || matches!(b.kind, crate::debugger::BpKind::SwExec));
            s.debug_state.breakpoints.push(crate::debugger::Breakpoint {
                address: addr,
                enabled: true,
                original_byte: 0,
                name,
                kind: bpkind,
                len: blen,
                planted: true,
            });
        }
    }
    Ok(json!({
        "ok": true,
        "slot": slot,
        "address": format!("{:#x}", addr),
        "kind": kind_str,
        "len": len_int,
    }))
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn clear_hardware_breakpoint(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let slot = arg_int(args, "slot", 0).clamp(0, 3) as u8;
    let _: () = wait_for(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.hw_bp_result = None;
            s.debug_state.hw_bp_request = Some(crate::debugger::HwBpRequest::Clear { id, slot });
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.hw_bp_result
                && *rid == id {
                    let (_, r) = s.debug_state.hw_bp_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        3000,
    )?;
    if let Ok(mut s) = state.try_lock() {
        let name = format!("hw{}", slot);
        s.debug_state.breakpoints.retain(|b| b.name != name);
    }
    Ok(json!({ "ok": true, "slot": slot }))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn set_hardware_breakpoint(
    _args: &Value,
    _state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn clear_hardware_breakpoint(
    _args: &Value,
    _state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}

pub fn arm_software_breakpoint(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let original: u8 = wait_for(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.arm_int3_result = None;
            s.debug_state.arm_int3_request = Some((id, addr));
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.arm_int3_result
                && *rid == id {
                    let (_, r) = s.debug_state.arm_int3_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        3000,
    )?;

    {
        let mut s = try_state(state)?;
        if let Some(bp) = s
            .debug_state
            .breakpoints
            .iter_mut()
            .find(|b| b.address == addr)
        {
            bp.original_byte = original;
            bp.enabled = true;
        } else {
            s.debug_state.breakpoints.push(crate::debugger::Breakpoint {
                address: addr,
                enabled: true,
                original_byte: original,
                name: format!("bp_{:X}", addr),
                kind: crate::debugger::BpKind::SwExec,
                len: 1,
                planted: true,
            });
        }
    }

    Ok(json!({
        "ok": true,
        "address": format!("{:#x}", addr),
        "original_byte": format!("{:#04x}", original),
    }))
}

pub fn run_until_address(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let timeout_ms = arg_int(args, "timeout_ms", 5000).clamp(100, 60_000) as u64;

    let _ = arm_software_breakpoint(&json!({ "address": format!("{:#x}", addr) }), state)?;

    let disarm_on_error = |state: &Arc<Mutex<AppState>>| {
        let original = {
            let s = match state.try_lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            s.debug_state
                .breakpoints
                .iter()
                .find(|b| b.address == addr)
                .map(|b| b.original_byte)
        };
        if let Some(orig) = original {
            if orig != 0 && orig != 0xCC {
                let _ = crate::mcp::tools::rw::write_process_memory(
                    &json!({ "address": format!("{:#x}", addr), "bytes": format!("{:02x}", orig) }),
                    state,
                );
            }
            if let Ok(mut s) = state.try_lock() {
                s.debug_state.breakpoints.retain(|b| b.address != addr);
            }
        }
    };

    {
        let mut s = try_state(state)?;
        s.debug_state.continue_exec = true;
    }

    let sig = {
        state
            .try_lock()
            .map(|s| s.debug_state.signal.clone())
            .unwrap_or_else(|_| crate::debugger::DebugSignal::new())
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        sig.wait(std::time::Duration::from_millis(40));
        if let Ok(s) = state.try_lock() {
            if !s.debug_state.is_attached {
                drop(s);
                disarm_on_error(state);
                return Err("Process exited before reaching target".into());
            }
            let rip = s.debug_state.current_rip;
            if !s.debug_state.is_running && (rip == addr || rip == addr + 1) {
                return Ok(json!({
                    "ok": true,
                    "stopped_at": format!("{:#x}", rip),
                    "target": format!("{:#x}", addr),
                    "registers": {
                        "rax": format!("{:#x}", s.debug_state.registers.rax),
                        "rbx": format!("{:#x}", s.debug_state.registers.rbx),
                        "rcx": format!("{:#x}", s.debug_state.registers.rcx),
                        "rdx": format!("{:#x}", s.debug_state.registers.rdx),
                        "rsi": format!("{:#x}", s.debug_state.registers.rsi),
                        "rdi": format!("{:#x}", s.debug_state.registers.rdi),
                        "rbp": format!("{:#x}", s.debug_state.registers.rbp),
                        "rsp": format!("{:#x}", s.debug_state.registers.rsp),
                        "r8":  format!("{:#x}", s.debug_state.registers.r8),
                        "r9":  format!("{:#x}", s.debug_state.registers.r9),
                        "rip": format!("{:#x}", s.debug_state.registers.rip),
                    },
                    "events": s.debug_state.events.iter().rev().take(15).cloned().collect::<Vec<_>>(),
                }));
            }
        }
        if std::time::Instant::now() >= deadline {
            disarm_on_error(state);
            return Err(format!("Did not hit {:#x} within {} ms", addr, timeout_ms));
        }
    }
}
