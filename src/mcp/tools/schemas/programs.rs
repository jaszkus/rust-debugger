use serde_json::{json, Value};

pub(crate) fn schema_open_program() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "name": { "type": "string", "description": "Optional program name (default: file name)" }
        },
        "required": ["path"]
    })
}

pub(crate) fn schema_program_name() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string", "description": "Program name as shown by list_open_programs" }
        },
        "required": ["name"]
    })
}
pub(crate) fn schema_dump_section() -> Value {
    json!({
        "type": "object",
        "properties": {
            "section": { "type": "string" },
            "path": { "type": "string" }
        },
        "required": ["section", "path"]
    })
}

pub(crate) fn schema_dump_range() -> Value {
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

pub(crate) fn schema_load_dump() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "base_address": { "type": "string", "default": "0", "description": "Base virtual address for the dump (hex)" },
            "arch": { "type": "string", "enum": ["x86_64","x86","aarch64","arm"], "default": "x86_64" }
        },
        "required": ["path"]
    })
}
