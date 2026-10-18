use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

pub fn state_snapshot(s: &AppState) -> Value {
    json!({
        "program": if s.binary.is_some() { json!(s.current_program_label()) } else { Value::Null },
        "binary_loaded": s.binary.is_some(),
        "analyzed": s.analysis.is_some(),
        "function_count": s.analysis.as_ref().map(|a| a.functions.len()),
        "patch_count": s.patches.len(),
        "open_programs": s.open_program_count(),
        "debugger_attached": s.debug_state.is_attached,
        "debugger_pid": if s.debug_state.is_attached { json!(s.debug_state.process_id) } else { Value::Null },
        "target_running": s.debug_state.is_running,
    })
}

const NEXT_HINTS: &[(&str, &[&str])] = &[
    ("list_globals", &[
        "COFF symbols are often stripped from release binaries - import a linker .map via load_map_file(path)",
        "Try search_functions(query) for name substrings instead",
    ]),
    ("search_in_decompiled", &[
        "API calls render by import name after run_analysis (e.g. 'MessageBoxW')",
        "Try a shorter substring",
    ]),
    ("search_functions", &[
        "Unnamed functions are called sub_<hex address>: search by (part of) the hex address, '0x' prefix optional",
        "To find code by behaviour use search_strings, find_users_of_import or search_in_decompiled",
    ]),
    ("search_strings", &[
        "Try encoding='utf16le' - Windows stores most strings wide",
        "Shorten the query",
    ]),
    ("list_switch_tables", &[
        "No validated jump tables (>=2 targets, all in executable sections)",
    ]),
    ("find_xor_loops", &[
        "No XOR-decrypt loop pattern found; try detect_obfuscation for other packing styles",
    ]),
    ("find_callsites_to_import", &[]),
];

fn empty_indicator(payload: &Value) -> bool {
    for key in ["count", "total", "matches"] {
        if payload.get(key).and_then(|v| v.as_u64()) == Some(0) {
            return true;
        }
    }
    for key in [
        "items",
        "hits",
        "types",
        "functions",
        "gaps",
        "labels",
        "patches",
    ] {
        if payload
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.is_empty())
            == Some(true)
        {
            return true;
        }
    }
    false
}

fn attach_next_hints(tool: &str, payload: &mut Value) {
    let Some((_, hints)) = NEXT_HINTS.iter().find(|(t, _)| *t == tool) else {
        return;
    };
    if hints.is_empty() || !empty_indicator(payload) {
        return;
    }
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("next".into(), json!(hints));
    }
}

fn error_hint(msg: &str) -> Option<&'static str> {
    const RULES: &[(&str, &str)] = &[
        ("No analysis loaded", "Call run_analysis first (it blocks until done; reanalyze queues in background)."),
        ("No binary loaded", "Call load_binary(path) first."),
        ("No disas", "Call load_binary first - disassembly is built during load."),
        ("not in any section", "See list_sections for valid address ranges."),
        ("Unknown data type", "Call list_valid_data_types for accepted names, aliases ('dword') and derived forms ('char*')."),
        ("lock poisoned", "A panicking tool poisoned the mutex; retry once - the GUI recovers it."),
        ("Missing string param", "Check the tool schema via tools/list for required parameters."),
        ("No open program named", "Call list_open_programs to see slots."),
        ("Module '", "not found in target - call list_modules for exact names."),
        ("Import not found", "Use list_imports to check exact spelling / 'DLL!Name' form."),
        ("Invalid address", "Addresses accept hex like '0x140001000' or '140001000'."),
        ("No patches to undo", "Nothing recorded - apply a patch first."),
        ("Missing required argument", "Check the parameters with search_tools(query='<tool name>', include_schema=true); accepted aliases are named in the message."),
        ("Function not found", "Resolve it with lookup_function / search_functions (hex address, '0x' optional); get_function_at, decompile_function and get_function_summary also accept an address inside the function."),
        ("Invalid params", "A parameter has the wrong type or is out of range - see its inputSchema (search_tools with include_schema=true)."),
        ("denied by workbench settings", "Enable the switch named in the message under Settings -> AI and MCP."),
    ];
    RULES
        .iter()
        .find(|(needle, _)| msg.contains(needle))
        .map(|(_, hint)| *hint)
}

fn error_code(msg: &str) -> &'static str {
    const RULES: &[(&str, &str)] = &[
        ("Missing required argument", "missing_argument"),
        ("Missing string param", "missing_argument"),
        ("Invalid arguments", "invalid_argument"),
        ("Invalid params", "invalid_argument"),
        ("not async-eligible", "invalid_argument"),
        ("Invalid address", "invalid_address"),
        ("denied by workbench settings", "denied"),
        ("No analysis loaded", "no_analysis"),
        ("No binary loaded", "no_binary"),
        ("No disas", "no_disassembly"),
        ("not in any section", "address_unmapped"),
        ("Unknown tool", "unknown_tool"),
        ("timed out", "timeout"),
        ("Too many concurrent jobs", "busy"),
        ("lock poisoned", "internal"),
        ("panicked", "internal"),
        ("not found", "not_found"),
        ("Unknown job_id", "not_found"),
        ("Unknown data type", "not_found"),
        ("No open program named", "not_found"),
    ];
    RULES
        .iter()
        .find(|(needle, _)| msg.contains(needle))
        .map(|(_, code)| *code)
        .unwrap_or("error")
}

fn can_drop_analysis(name: &str) -> bool {
    name.starts_with("patch_")
        || matches!(
            name,
            "nop_range"
                | "fill_bytes"
                | "fill_pattern"
                | "copy_bytes"
                | "search_and_replace_bytes"
                | "undo_last_patch"
                | "undo_patch_at"
                | "revert_all_patches"
                | "import_patches"
        )
}

const CAPPED_WITHOUT_PAGING: &[(&str, i64)] = &[
    ("search_instructions", 100),
    ("search_functions_enhanced", 100),
    ("search_functions", 100),
    ("search_strings", 100),
    ("search_in_decompiled", 100),
    ("search_byte_patterns", 100),
    ("find_format_strings", 200),
    ("find_leaf_functions", 200),
    ("find_root_functions", 200),
];

fn flag_possible_truncation(tool: &str, args: &Value, payload: &mut Value) {
    let Some(&(_, default_limit)) = CAPPED_WITHOUT_PAGING.iter().find(|(t, _)| *t == tool) else {
        return;
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(default_limit)
        .max(1);
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    if obj.contains_key("has_more") || obj.contains_key("total") {
        return;
    }
    let mut count = obj.get("count").and_then(|v| v.as_i64());
    if count.is_none() {
        for key in ["items", "hits", "matches", "functions"] {
            if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                count = Some(arr.len() as i64);
                break;
            }
        }
    }
    if count == Some(limit) {
        obj.insert("possibly_truncated".into(), json!(true));
        obj.insert(
            "truncation_note".into(),
            json!(format!(
                "count equals limit ({}): more results may exist and this tool reports no total - raise limit or narrow the query",
                limit
            )),
        );
    }
}

fn collect_string_args(args: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(obj) = args.as_object() {
        for v in obj.values() {
            if let Some(s) = v.as_str() {
                out.push(s.to_string());
            } else if let Some(inner) = v.as_object() {
                for iv in inner.values() {
                    if let Some(s) = iv.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }
    out
}

fn strip_echo(payload: &mut Value, arg_strings: &[String]) {
    if arg_strings.is_empty() {
        return;
    }
    const ECHO_KEYS: &[&str] = &[
        "query", "pattern", "name", "line", "snippet", "text", "tool", "filter",
    ];
    strip_echo_inner(payload, arg_strings, ECHO_KEYS);
}

fn strip_echo_inner(v: &mut Value, arg_strings: &[String], echo_keys: &[&str]) {
    match v {
        Value::Object(obj) => {
            let remove: Vec<String> = obj
                .iter()
                .filter(|(k, val)| {
                    if !echo_keys.contains(&k.as_str()) {
                        return false;
                    }
                    matches!(val, Value::String(s) if arg_strings.iter().any(|a| a == s))
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in remove {
                obj.remove(&k);
            }
            for val in obj.values_mut() {
                strip_echo_inner(val, arg_strings, echo_keys);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_echo_inner(item, arg_strings, echo_keys);
            }
        }
        _ => {}
    }
}

fn compact_default() -> bool {
    match std::env::var("RUST_DEBUGGER_VERBOSE") {
        Ok(v) => v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false"),
        Err(_) => true,
    }
}

const STATE_TOOLS: &[&str] = &[
    "load_binary",
    "load_memory_dump",
    "import_file",
    "open_program",
    "close_program",
    "switch_program",
    "run_analysis",
    "reanalyze",
    "cancel_analysis",
    "debugger_start",
    "debugger_attach",
    "debugger_detach",
    "debugger_stop",
    "revert_all_patches",
    "health",
    "check_connection",
];

fn snapshot_default(name: &str) -> bool {
    static ALWAYS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let always = *ALWAYS.get_or_init(|| match std::env::var("RUST_DEBUGGER_SNAPSHOT") {
        Ok(v) => !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")),
        Err(_) => false,
    });
    always || STATE_TOOLS.contains(&name)
}

pub fn call_enveloped(name: &str, raw_args: &Value, state: &Arc<Mutex<AppState>>) -> Value {
    let verbose = raw_args
        .get("_verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let compact = !verbose && compact_default();
    let snapshot_pref = raw_args
        .get("_snapshot")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            raw_args
                .get("_meta")
                .and_then(|m| m.get("snapshot"))
                .and_then(|v| v.as_bool())
        });
    let want_snapshot_ok = snapshot_pref.unwrap_or_else(|| snapshot_default(name));
    let want_snapshot_err = snapshot_pref.unwrap_or(true);

    let mut args = raw_args.clone();
    if let Some(obj) = args.as_object_mut() {
        obj.remove("_compact");
        obj.remove("_verbose");
        obj.remove("_snapshot");
    }

    let analysis_before = if can_drop_analysis(name) {
        state.lock().ok().map(|s| s.analysis.is_some())
    } else {
        None
    };

    match super::call(name, &args, state) {
        Ok(mut payload) => {
            if compact {
                let arg_strings = collect_string_args(raw_args);
                strip_echo(&mut payload, &arg_strings);
            }
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("ok".into(), json!(true));
                if want_snapshot_ok && !obj.contains_key("state") {
                    if let Ok(s) = state.lock() {
                        obj.insert("state".into(), state_snapshot(&s));
                    }
                }
            }
            if let Some(had) = analysis_before {
                let dropped = had && state.lock().map(|s| s.analysis.is_none()).unwrap_or(false);
                if let Some(obj) = payload.as_object_mut() {
                    obj.entry("analysis_invalidated").or_insert(json!(dropped));
                    if dropped {
                        obj.entry("next").or_insert(json!([
                            "Analysis was dropped: call run_analysis (blocking) before decompile/xref/call-graph tools",
                            "Patch tools accept invalidate_analysis=false to keep the - then stale - analysis instead"
                        ]));
                    }
                }
            }
            flag_possible_truncation(name, raw_args, &mut payload);
            attach_next_hints(name, &mut payload);
            crate::mcp::tools::activity::record_ok(state, name, raw_args, &payload);
            payload
        }
        Err(msg) => {
            crate::mcp::tools::activity::record_err(state, name, raw_args, &msg);
            let mut obj = Map::new();
            obj.insert("ok".into(), json!(false));
            obj.insert("tool".into(), json!(name));
            obj.insert("code".into(), json!(error_code(&msg)));
            obj.insert("error".into(), json!(msg));
            if let Some(hint) = error_hint(&msg) {
                obj.insert("hint".into(), json!(hint));
            }
            if want_snapshot_err {
                if let Ok(s) = state.lock() {
                    obj.insert("state".into(), state_snapshot(&s));
                }
            }
            Value::Object(obj)
        }
    }
}

pub(crate) const JOB_ALLOWLIST: &[&str] = &[
    "search_process_memory",
    "detect_protections",
    "detect_anti_debug",
    "detect_anti_vm",
    "detect_packers",
    "detect_obfuscation",
    "detect_crypto",
    "search_in_decompiled",
    "search_instruction_pattern",
    "find_similar_functions",
    "search_bytes",
    "search_strings",
    "search_functions",
    "section_entropy",
    "find_pe_headers",
    "find_xor_loops",
    "find_aes_rcon_table",
    "get_binary_overview",
    "analyze_call_graph",
    "find_immediate_refs",
    "list_strings",
    "search_byte_patterns",
    "search_instructions",
    "search_functions_enhanced",
    "find_format_strings",
    "find_callsites_to_import",
    "find_users_of_import",
    "find_code_gaps",
    "find_recursive_functions",
    "find_leaf_functions",
    "find_root_functions",
    "list_switch_tables",
    "scan_rtti",
    "get_call_context",
];
const MAX_JOBS: usize = 32;
const MAX_CONCURRENT_JOBS: usize = 4;

struct Job {
    tool: String,
    started_ms: u128,
    timeout_ms: u128,
    done: bool,
    result: Option<Result<Value, String>>,
}

fn jobs() -> &'static Mutex<HashMap<String, Job>> {
    static JOBS: std::sync::OnceLock<Mutex<HashMap<String, Job>>> = std::sync::OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn job_slots() -> &'static Mutex<usize> {
    static SLOTS: std::sync::OnceLock<Mutex<usize>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(0))
}

fn job_enter() -> Result<(), String> {
    let m = job_slots();
    let mut n = m.lock().map_err(|_| "lock poisoned".to_string())?;
    if *n >= MAX_CONCURRENT_JOBS {
        return Err(format!(
            "Too many concurrent jobs (max {}): poll existing jobs before starting new ones",
            MAX_CONCURRENT_JOBS
        ));
    }
    *n += 1;
    Ok(())
}

fn job_leave() {
    if let Ok(mut n) = job_slots().lock() {
        *n = n.saturating_sub(1);
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn run_async(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let tool = args
        .get("tool")
        .and_then(|v| v.as_str())
        .ok_or("Missing required argument: tool")?
        .to_string();
    if !JOB_ALLOWLIST.contains(&tool.as_str()) {
        return Err(format!(
            "Tool '{}' is not async-eligible. Allowlist: {}",
            tool,
            JOB_ALLOWLIST.join(", ")
        ));
    }
    let tool_args = args.get("arguments").cloned().unwrap_or(json!({}));
    if !tool_args.is_object() {
        return Err("Invalid params: arguments must be an object".to_string());
    }
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_i64())
        .unwrap_or(120_000)
        .clamp(1_000, 600_000) as u128;
    job_enter()?;

    let id = format!("job_{:x}_{:04x}", now_ms(), fastrand());
    let job_id = id.clone();
    let state2 = Arc::clone(state);
    let tool2 = tool.clone();
    let started = now_ms();
    if let Err(e) = std::thread::Builder::new()
        .name(format!("mcp-job-{job_id}"))
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::call(&tool2, &tool_args, &state2)
            }));
            let result = match outcome {
                Ok(r) => r,
                Err(_) => Err("Internal error: tool panicked".into()),
            };
            if let Ok(mut map) = jobs().lock() {
                if let Some(job) = map.get_mut(&job_id) {
                    job.done = true;
                    job.result = Some(result);
                }
            }
            job_leave();
        })
    {
        job_leave();
        return Err(format!("Failed to spawn job thread: {}", e));
    }

    let mut map = jobs().lock().map_err(|_| "lock poisoned".to_string())?;
    while map.len() >= MAX_JOBS {
        let oldest_done = map
            .iter()
            .filter(|(_, j)| j.done)
            .min_by_key(|(_, j)| j.started_ms)
            .map(|(k, _)| k.clone());
        match oldest_done {
            Some(k) => {
                map.remove(&k);
            }
            None => break,
        }
    }
    map.insert(
        id.clone(),
        Job {
            tool,
            started_ms: started,
            timeout_ms,
            done: false,
            result: None,
        },
    );

    Ok(json!({
        "job_id": id,
        "status": "running",
        "timeout_ms": timeout_ms,
        "poll_with": "poll_job(job_id)",
        "note": "Fire-and-forget: keep working, poll periodically. Long scans no longer block the MCP timeout."
    }))
}

fn fastrand() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (std::process::id() << 3)) as u16
}

pub fn poll_job(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let _ = state;
    let id = args
        .get("job_id")
        .and_then(|v| v.as_str())
        .ok_or("Missing required argument: job_id")?;
    let mut map = jobs().lock().map_err(|_| "lock poisoned".to_string())?;
    let Some(job) = map.get_mut(id) else {
        return Err(format!("Unknown job_id: {}", id));
    };
    let age_ms = now_ms().saturating_sub(job.started_ms);
    if age_ms > job.timeout_ms && !job.done {
        let tool = job.tool.clone();
        let timeout = job.timeout_ms;
        map.remove(id);
        return Err(format!(
            "Job '{}' (tool '{}') timed out after {} ms (age {} ms)",
            id, tool, timeout, age_ms
        ));
    }
    if !job.done {
        return Ok(
            json!({ "job_id": id, "tool": job.tool, "done": false, "age_ms": age_ms, "timeout_ms": job.timeout_ms }),
        );
    }
    let result = job.result.take().expect("finished job always has a result");
    let done_flag = true;
    let mut out = match result {
        Ok(mut payload) => {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("ok".into(), json!(true));
            }
            payload
        }
        Err(msg) => json!({ "ok": false, "error": msg }),
    };
    if let Some(obj) = out.as_object_mut() {
        obj.insert("job_id".into(), json!(id));
        obj.insert("done".into(), json!(done_flag));
        obj.insert("age_ms".into(), json!(age_ms));
    }
    map.remove(id);
    Ok(out)
}
