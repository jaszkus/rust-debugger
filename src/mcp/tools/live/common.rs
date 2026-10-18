use std::sync::{Arc, Mutex};

use crate::gui::AppState;

pub(crate) use crate::mcp::tools::common::{arg_addr, arg_int, arg_str, arg_str_opt};

pub(crate) fn try_state<'a>(
    state: &'a Arc<Mutex<AppState>>,
) -> Result<std::sync::MutexGuard<'a, AppState>, String> {
    crate::mcp::tools::lock::lock_state(state)
}

pub(crate) fn wait_for<R, F1, F2>(
    state: &Arc<Mutex<AppState>>,
    enqueue: F1,
    pull: F2,
    timeout_ms: u64,
) -> Result<R, String>
where
    F1: FnOnce(&mut AppState) -> Result<u64, String>,
    F2: Fn(&mut AppState, u64) -> Option<Result<R, String>>,
{
    wait_for_inner(state, enqueue, pull, timeout_ms, true)
}

pub(crate) fn wait_for_no_attach_check<R, F1, F2>(
    state: &Arc<Mutex<AppState>>,
    enqueue: F1,
    pull: F2,
    timeout_ms: u64,
) -> Result<R, String>
where
    F1: FnOnce(&mut AppState) -> Result<u64, String>,
    F2: Fn(&mut AppState, u64) -> Option<Result<R, String>>,
{
    wait_for_inner(state, enqueue, pull, timeout_ms, false)
}

pub(crate) fn wait_for_inner<R, F1, F2>(
    state: &Arc<Mutex<AppState>>,
    enqueue: F1,
    pull: F2,
    timeout_ms: u64,
    require_attached: bool,
) -> Result<R, String>
where
    F1: FnOnce(&mut AppState) -> Result<u64, String>,
    F2: Fn(&mut AppState, u64) -> Option<Result<R, String>>,
{
    let id = {
        let mut s = try_state(state)?;
        if require_attached && !s.debug_state.is_attached {
            return Err("No debugger attached. Call debugger_start first.".into());
        }
        enqueue(&mut s)?
    };
    {
        if let Ok(s) = state.try_lock() {
            s.debug_state.signal.notify();
        }
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        {
            match state.try_lock() {
                Ok(mut s) => {
                    if let Some(r) = pull(&mut s, id) {
                        return r;
                    }
                    let sig = s.debug_state.signal.clone();
                    drop(s);
                    sig.wait(std::time::Duration::from_millis(5));
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(
                "Service unavailable (503): timed out waiting for the debugger thread".into(),
            );
        }
    }
}

pub(crate) fn fmt_protection(p: u32) -> &'static str {
    match p & 0xff {
        0x01 => "NOACCESS",
        0x02 => "READONLY",
        0x04 => "READWRITE",
        0x08 => "WRITECOPY",
        0x10 => "EXECUTE",
        0x20 => "EXECUTE_READ",
        0x40 => "EXECUTE_READWRITE",
        0x80 => "EXECUTE_WRITECOPY",
        _ => "?",
    }
}

pub(crate) fn fmt_region_type(t: u32) -> &'static str {
    match t {
        0x40000 => "MAPPED",
        0x20000 => "PRIVATE",
        0x1000000 => "IMAGE",
        _ => "?",
    }
}
