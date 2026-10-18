use serde_json::{json, Value};

pub(crate) fn schema_type_name() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string", "description": "Data type name" }
        },
        "required": ["name"]
    })
}

pub(crate) fn schema_pointer_type() -> Value {
    json!({
        "type": "object",
        "properties": {
            "target": { "type": "string", "description": "Target type name the pointer points to (e.g. 'char', 'MyStruct', 'int')" }
        },
        "required": ["target"]
    })
}

pub(crate) fn schema_run_async() -> Value {
    json!({
        "type": "object",
        "properties": {
            "tool": { "type": "string", "description": "Tool name to execute in background (allowlisted long scans only)" },
            "arguments": { "type": "object", "description": "Arguments forwarded to the tool", "default": {} },
            "timeout_ms": { "type": "integer", "default": 120000, "description": "Job timeout in ms (1000..600000); poll_job errors after expiry" }
        },
        "required": ["tool"]
    })
}

pub(crate) fn schema_poll_job() -> Value {
    json!({
        "type": "object",
        "properties": {
            "job_id": { "type": "string", "description": "Job id returned by run_async" }
        },
        "required": ["job_id"]
    })
}

pub(crate) fn schema_search_tools() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Keywords (space/comma separated) matched against tool names and descriptions. Empty = browse by category." },
            "category": { "type": "string", "description": "Restrict to one category (names are listed in 'categories' when the query is empty)" },
            "limit": { "type": "integer", "default": 25, "description": "Max results, 1..100" },
            "offset": { "type": "integer", "default": 0 },
            "include_schema": { "type": "boolean", "default": false, "description": "Attach the full inputSchema of every returned tool" }
        },
        "required": []
    })
}

pub(crate) fn schema_create_enum() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "underlying": { "type": "string", "description": "Underlying type (default int)" }
        },
        "required": ["name"]
    })
}

pub(crate) fn schema_create_typedef() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "target": { "type": "string", "description": "Existing type name" }
        },
        "required": ["name", "target"]
    })
}

pub(crate) fn schema_create_array() -> Value {
    json!({
        "type": "object",
        "properties": {
            "element": { "type": "string", "description": "Element type name" },
            "count": { "type": "integer", "default": 1 }
        },
        "required": ["element"]
    })
}

pub(crate) fn schema_create_func_sig() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "return_type": { "type": "string", "default": "void" },
            "params": { "type": "array", "items": { "type": "object", "properties": { "name": { "type": "string" }, "type": { "type": "string" } } }, "default": [] },
            "calling_convention": { "type": "string", "default": "unknown" },
            "varargs": { "type": "boolean", "default": false }
        },
        "required": ["name"]
    })
}

pub(crate) fn schema_add_field() -> Value {
    json!({
        "type": "object",
        "properties": {
            "type": { "type": "string", "description": "Struct/union name" },
            "field": { "type": "string", "description": "Field name" },
            "field_type": { "type": "string", "description": "Field type name" },
            "offset": { "type": "integer", "description": "Explicit offset (default: after last field)" },
            "bit_width": { "type": "integer", "description": "Bitfield width (makes this a bitfield member, e.g. 3 for 'int x : 3')" },
            "bit_offset": { "type": "integer", "description": "Bit offset within the storage unit (default 0)" },
            "comment": { "type": "string", "default": "" }
        },
        "required": ["type", "field", "field_type"]
    })
}

pub(crate) fn schema_remove_field() -> Value {
    json!({
        "type": "object",
        "properties": {
            "type": { "type": "string" },
            "field": { "type": "string" }
        },
        "required": ["type", "field"]
    })
}

pub(crate) fn schema_enum_variant() -> Value {
    json!({
        "type": "object",
        "properties": {
            "type": { "type": "string", "description": "Enum name" },
            "name": { "type": "string", "description": "Variant name" },
            "value": { "type": "integer", "default": 0 }
        },
        "required": ["type", "name"]
    })
}

pub(crate) fn schema_rename_type() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "new_name": { "type": "string" }
        },
        "required": ["name", "new_name"]
    })
}

pub(crate) fn schema_apply_type() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Hex address" },
            "type": { "type": "string", "description": "Type name to define at the address" }
        },
        "required": ["address", "type"]
    })
}

pub(crate) fn schema_import_types() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Path to a JSON type export" },
            "types": { "type": "array", "description": "Inline types array (alternative to path)" }
        }
    })
}

pub(crate) fn schema_type_archive() -> Value {
    json!({
        "type": "object",
        "properties": {
            "archive": { "type": "string", "description": "Archive name: win32, crt or libc (see list_type_archives)" }
        },
        "required": ["archive"]
    })
}
