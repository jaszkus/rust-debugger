use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

pub const MAX_LOG: usize = 200;
pub const MAX_TARGET: usize = 60;
pub const MAX_SUMMARY: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpCallKind {
    Read,
    Write,
    Exec,
}

impl McpCallKind {
    pub fn label(self) -> &'static str {
        match self {
            McpCallKind::Read => "read",
            McpCallKind::Write => "write",
            McpCallKind::Exec => "exec",
        }
    }
}

#[derive(Debug, Clone)]
pub struct McpCallEvent {
    pub seq: u64,
    pub t_ms: u64,
    pub time_str: String,
    pub tool: String,
    pub kind: McpCallKind,
    pub target: String,
    pub summary: String,
    pub is_error: bool,
    pub addr: Option<u64>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn time_str(t_ms: u64) -> String {
    let s = (t_ms / 1000) % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

const OVERRIDES: &[(&str, McpCallKind)] = &[
    ("get_function_at", McpCallKind::Read),
    ("disassemble_function", McpCallKind::Read),
    ("decompile_function", McpCallKind::Read),
    ("get_function_summary", McpCallKind::Read),
    ("get_xrefs_to", McpCallKind::Read),
    ("get_xrefs_from", McpCallKind::Read),
    ("disassemble_range", McpCallKind::Read),
    ("disassemble_bytes", McpCallKind::Read),
    ("rename_function", McpCallKind::Write),
    ("set_comment", McpCallKind::Write),
    ("add_breakpoint", McpCallKind::Exec),
    ("arm_software_breakpoint", McpCallKind::Exec),
    ("run_until_address", McpCallKind::Exec),
    ("read_memory", McpCallKind::Read),
    ("get_bytes", McpCallKind::Read),
    ("search_strings", McpCallKind::Read),
];

pub fn classify_kind(name: &str) -> McpCallKind {
    if let Some((_, k)) = OVERRIDES.iter().find(|(n, _)| *n == name) {
        return *k;
    }
    let n = name;
    for p in [
        "break",
        "step",
        "run",
        "launch",
        "arm",
        "exec",
        "eval",
        "debugger_",
        "debug_",
        "process_memory",
        "start_trace",
        "stop_trace",
    ] {
        if n.starts_with(p) || n.contains("breakpoint") || n.contains("watchpoint") {
            return McpCallKind::Exec;
        }
    }
    for p in [
        "set_",
        "add_",
        "rename_",
        "delete_",
        "remove_",
        "create_",
        "update_",
        "write_",
        "patch_",
        "clear_",
        "nop_",
        "fill_",
        "copy_bytes",
        "search_and_replace",
        "tag_",
        "untag_",
        "label_",
        "comment",
        "bookmark",
        "undo_",
        "redo_",
        "revert_",
        "apply_",
        "import_",
        "open_program",
        "close_program",
        "switch_program",
        "save_",
        "export_",
        "assemble",
        "load_",
        "fid_ingest",
        "fid_import",
        "cancel_",
        "reanalyze",
        "run_analysis",
    ] {
        if n.starts_with(p) || n.contains("comment") || n.contains("bookmark") || n.contains("tag_")
        {
            return McpCallKind::Write;
        }
    }
    McpCallKind::Read
}

const TARGET_KEYS: &[&str] = &[
    "address", "addr", "va", "vaddr", "entry", "offset", "function", "func", "name", "query",
    "pattern", "path", "job_id", "tool", "id",
];

fn arg_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Some(format!("{u:#x}"))
            } else {
                Some(n.to_string())
            }
        }
        _ => None,
    }
}

pub fn extract_target(args: &Value) -> String {
    let obj = match args.as_object() {
        Some(o) => o,
        None => return String::new(),
    };
    let inner = obj
        .get("arguments")
        .and_then(|v| v.as_object())
        .unwrap_or(obj);
    for scope in [inner, obj] {
        for k in TARGET_KEYS {
            if let Some(v) = scope.get(*k).and_then(arg_to_string) {
                return truncate(&v, MAX_TARGET);
            }
        }
    }
    String::new()
}

pub fn extract_addr(args: &Value) -> Option<u64> {
    const ADDR_KEYS: &[&str] = &["address", "addr", "va", "vaddr", "entry", "offset"];
    let obj = args.as_object()?;
    let inner = obj
        .get("arguments")
        .and_then(|v| v.as_object())
        .unwrap_or(obj);
    for scope in [inner, obj] {
        for k in ADDR_KEYS {
            match scope.get(*k) {
                Some(Value::Number(n)) => {
                    if let Some(v) = n.as_u64() {
                        return Some(v);
                    }
                }
                Some(Value::String(s)) => {
                    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
                    if !t.is_empty() && t.len() <= 16 && t.chars().all(|c| c.is_ascii_hexdigit()) {
                        if let Ok(v) = u64::from_str_radix(t, 16) {
                            return Some(v);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

pub fn summarize_ok(payload: &Value) -> String {
    if let Some(o) = payload.as_object() {
        for k in ["count", "total", "matches", "returned"] {
            if let Some(n) = o.get(k).and_then(|v| v.as_u64()) {
                return format!("{n} {}", if n == 1 { "match" } else { "matches" });
            }
        }
        for k in ["items", "hits", "functions", "types", "patches", "labels"] {
            if let Some(a) = o.get(k).and_then(|v| v.as_array()) {
                let n = a.len();
                return format!("{n} {}", if n == 1 { "item" } else { "items" });
            }
        }
        for k in ["version", "status", "job_id", "name", "program"] {
            if let Some(s) = o.get(k).and_then(|v| v.as_str()) {
                if !s.is_empty() {
                    return truncate(s, MAX_SUMMARY);
                }
            }
        }
    }
    "ok".to_string()
}

fn push(state: &Arc<Mutex<AppState>>, ev: McpCallEvent) {
    let mut g = match state.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return,
    };
    g.mcp_call_seq = g.mcp_call_seq.wrapping_add(1);
    let seq = g.mcp_call_seq;
    let mut ev = ev;
    ev.seq = seq;
    g.mcp_call_log.push_back(ev);
    while g.mcp_call_log.len() > MAX_LOG {
        g.mcp_call_log.pop_front();
    }
    g.mcp_last_call_ms = Some(now_ms());
    if let Some(a) = g.mcp_call_log.back().and_then(|e| e.addr) {
        g.ai_cursor = Some((a, a));
    }
}

pub fn set_plan_tool(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let steps: Vec<String> = args
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or("Missing required argument: steps (array of strings)")?
        .iter()
        .filter_map(|s| s.as_str().map(|x| x.to_string()))
        .collect();
    let current = args.get("current").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    set_plan(state, steps.clone(), current);
    Ok(json!({ "ok": true, "steps": steps.len(), "current": current.min(steps.len()) }))
}
pub fn set_plan(state: &Arc<Mutex<AppState>>, steps: Vec<String>, current: usize) {
    let mut g = match state.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return,
    };
    g.ai_plan = steps
        .into_iter()
        .enumerate()
        .map(|(i, s)| {
            let s = truncate(&s, 80);
            (s, i < current)
        })
        .collect();
}

pub fn record_ok(state: &Arc<Mutex<AppState>>, name: &str, raw_args: &Value, payload: &Value) {
    let t = now_ms();
    push(
        state,
        McpCallEvent {
            seq: 0,
            t_ms: t,
            time_str: time_str(t),
            tool: name.to_string(),
            kind: classify_kind(name),
            target: extract_target(raw_args),
            summary: summarize_ok(payload),
            is_error: false,
            addr: extract_addr(raw_args),
        },
    );
}

pub fn record_err(state: &Arc<Mutex<AppState>>, name: &str, raw_args: &Value, msg: &str) {
    let t = now_ms();
    push(
        state,
        McpCallEvent {
            seq: 0,
            t_ms: t,
            time_str: time_str(t),
            tool: name.to_string(),
            kind: classify_kind(name),
            target: extract_target(raw_args),
            summary: truncate(msg, MAX_SUMMARY),
            is_error: true,
            addr: extract_addr(raw_args),
        },
    );
}
