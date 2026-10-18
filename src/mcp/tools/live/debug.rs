use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

pub fn set_debug_options(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = try_state(state)?;
    if let Some(b) = args.get("forward_exceptions").and_then(|v| v.as_bool()) {
        s.debug_state.forward_exceptions = b;
    }
    if let Some(b) = args.get("auto_continue_after_bp").and_then(|v| v.as_bool()) {
        s.debug_state.auto_continue_after_bp = b;
    }
    if let Some(b) = args.get("stop_at_entry").and_then(|v| v.as_bool()) {
        s.debug_state.stop_at_entry = b;
    }
    if let Some(b) = args.get("stealth_patches").and_then(|v| v.as_bool()) {
        s.debug_state.stealth_patches = b;
    }
    Ok(json!({
        "forward_exceptions": s.debug_state.forward_exceptions,
        "auto_continue_after_bp": s.debug_state.auto_continue_after_bp,
        "stop_at_entry": s.debug_state.stop_at_entry,
        "stealth_patches": s.debug_state.stealth_patches,
        "exception_policies": s.debug_state.exception_policy.iter()
            .map(|(c, a)| json!({
                "code": format!("{:#010x}", c),
                "action": match a {
                    crate::debugger::ExceptionAction::Forward => "forward",
                    crate::debugger::ExceptionAction::Swallow => "swallow",
                    crate::debugger::ExceptionAction::Pause => "pause",
                }
            }))
            .collect::<Vec<_>>(),
    }))
}

pub fn set_exception_policy(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let code_str = match args.get("code") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Err("Missing required argument: code".into()),
    };
    let action = arg_str_opt(args, "action");
    let code = parse_code(&code_str)?;

    let mut s = try_state(state)?;
    let removed = s
        .debug_state
        .exception_policy
        .iter()
        .position(|(c, _)| *c == code);
    let result = match action.as_str() {
        "clear" => {
            if let Some(i) = removed {
                s.debug_state.exception_policy.remove(i);
                format!("cleared {:#010x}", code)
            } else {
                format!("{:#010x} had no override", code)
            }
        }
        a @ ("forward" | "swallow" | "pause") => {
            let act = match a {
                "forward" => crate::debugger::ExceptionAction::Forward,
                "swallow" => crate::debugger::ExceptionAction::Swallow,
                _ => crate::debugger::ExceptionAction::Pause,
            };
            match removed {
                Some(i) => {
                    s.debug_state.exception_policy[i].1 = act;
                }
                None => s.debug_state.exception_policy.push((code, act)),
            }
            format!("{:#010x} -> {}", code, a)
        }
        "" => return Err("Missing action: forward|swallow|pause|clear".into()),
        other => {
            return Err(format!(
                "Unknown action '{}': use forward|swallow|pause|clear",
                other
            ))
        }
    };
    Ok(json!({
        "ok": true,
        "result": result,
        "policies": s.debug_state.exception_policy.iter()
            .map(|(c, a)| json!({
                "code": format!("{:#010x}", c),
                "action": match a {
                    crate::debugger::ExceptionAction::Forward => "forward",
                    crate::debugger::ExceptionAction::Swallow => "swallow",
                    crate::debugger::ExceptionAction::Pause => "pause",
                }
            }))
            .collect::<Vec<_>>(),
    }))
}

fn parse_code(s: &str) -> Result<u32, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(t, 16)
        .or_else(|_| s.trim().parse::<u32>())
        .map_err(|e| format!("Invalid exception code '{}': {}", s, e))
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn debugger_attach(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let pid = arg_int(args, "pid", 0);
    if pid <= 0 {
        return Err("Provide a positive `pid`".into());
    }
    let pid = pid as u32;

    let _: () = wait_for_no_attach_check(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.attach_result = None;
            s.debug_state.attach_request = Some((id, pid));
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.attach_result
                && *rid == id {
                    let (_, r) = s.debug_state.attach_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        5000,
    )?;
    Ok(json!({ "ok": true, "pid": pid }))
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub fn debugger_detach(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let _: () = wait_for_no_attach_check(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.detach_result = None;
            s.debug_state.detach_request = Some(id);
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.detach_result
                && *rid == id {
                    let (_, r) = s.debug_state.detach_result.take().unwrap();
                    return Some(r);
                }
            None
        },
        5000,
    )?;
    Ok(json!({ "ok": true }))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn debugger_attach(_args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn debugger_detach(_args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    Err("Live debugger only available on Windows".into())
}
