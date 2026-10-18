use serde_json::{json, Value};

pub(crate) fn schema_list_mem_regions() -> Value {
    json!({
        "type": "object",
        "properties": {
            "only_executable": { "type": "boolean", "default": false },
            "only_writable": { "type": "boolean", "default": false }
        }
    })
}

pub(crate) fn schema_disasm_proc() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "count": { "type": "integer", "default": 32 },
            "arch": { "type": "string", "default": "x86_64" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_search_proc() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Hex bytes (default) or ASCII string with `s:` prefix" },
            "limit": { "type": "integer", "default": 100 },
            "only_executable": { "type": "boolean", "default": false },
            "only_writable": { "type": "boolean", "default": false }
        },
        "required": ["query"]
    })
}

pub(crate) fn schema_dump_proc() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "size": { "type": "integer" },
            "path": { "type": "string" }
        },
        "required": ["address", "size", "path"]
    })
}

pub(crate) fn schema_hw_bp_set() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "slot": { "type": "integer", "default": 0, "description": "DR slot 0..=3" },
            "kind": { "type": "string", "enum": ["execute","write","rw"], "default": "execute" },
            "len": { "type": "integer", "enum": [1,2,4,8], "default": 1 }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_hw_bp_clear() -> Value {
    json!({
        "type": "object",
        "properties": {
            "slot": { "type": "integer", "default": 0 }
        }
    })
}

pub(crate) fn schema_run_until() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "timeout_ms": { "type": "integer", "default": 5000 }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_start_trace() -> Value {
    json!({
        "type": "object",
        "properties": {
            "max": { "type": "integer", "default": 4096, "description": "Max trace entries before auto-stop" }
        }
    })
}

pub(crate) fn schema_read_trace() -> Value {
    json!({
        "type": "object",
        "properties": {
            "limit": { "type": "integer", "default": 1000 }
        }
    })
}

pub(crate) fn schema_debug_options() -> Value {
    json!({
        "type": "object",
        "properties": {
            "forward_exceptions": { "type": "boolean", "description": "true = pass unhandled exceptions to target's SEH/VEH (default)" },
            "auto_continue_after_bp": { "type": "boolean", "description": "true = auto-continue after every BP hit" },
            "stop_at_entry": { "type": "boolean", "default": true, "description": "Arm a hard breakpoint at the EXE entry point on start/attach; the session pauses before the first target instruction" },
            "stealth_patches": { "type": "boolean", "default": true, "description": "Patch PEB BeingDebugged / NtGlobalFlag / heap Flags at the initial break, before any target code runs" }
        }
    })
}

pub(crate) fn schema_exception_policy() -> Value {
    json!({
        "type": "object",
        "properties": {
            "code": { "type": "string", "description": "Exception code, hex or decimal (e.g. 'C0000005' for ACCESS_VIOLATION)" },
            "action": { "type": "string", "enum": ["forward", "swallow", "pause", "clear"], "description": "forward = SEH/VEH sees it; swallow = DBG_CONTINUE; pause = freeze on it; clear = remove override" }
        },
        "required": ["code"]
    })
}

pub(crate) fn schema_scan_rtti() -> Value {
    json!({
        "type": "object",
        "properties": {
            "offset": { "type": "integer", "default": 0 },
            "limit": { "type": "integer", "default": 100 },
            "filter": { "type": "string", "default": "", "description": "Substring match on class name" }
        }
    })
}

pub(crate) fn schema_emu_run() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Function entry (or any address inside it)" },
            "args": { "type": "array", "items": { "type": "integer" }, "description": "Integer args for rdi,rsi,rdx,rcx,r8,r9 (default [])" },
            "max_steps": { "type": "integer", "default": 200000, "description": "Instruction budget (infinite-loop guard)" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_attach() -> Value {
    json!({
        "type": "object",
        "properties": {
            "pid": { "type": "integer", "description": "Target process ID" }
        },
        "required": ["pid"]
    })
}
