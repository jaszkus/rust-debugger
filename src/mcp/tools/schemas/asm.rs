use serde_json::{json, Value};

pub(crate) fn schema_assemble() -> Value {
    json!({
        "type": "object",
        "properties": {
            "line": { "type": "string", "description": "One assembly instruction, e.g. 'mov eax, 1'" },
            "instruction": { "type": "string", "description": "Alias for line" },
            "address": { "type": "string", "description": "Address for relative branches (hex)" },
            "arch": { "type": "string", "enum": ["x86_64", "x86"], "default": "current binary arch" }
        },
        "required": []
    })
}

pub(crate) fn schema_assemble_snippet() -> Value {
    json!({
        "type": "object",
        "properties": {
            "snippet": { "type": "string", "description": "Multiple lines, one instruction each" },
            "address": { "type": "string", "description": "Start address (hex)" },
            "arch": { "type": "string", "enum": ["x86_64", "x86"] }
        },
        "required": ["snippet"]
    })
}

pub(crate) fn schema_disasm_range() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "count": { "type": "integer", "default": 32, "description": "Max instructions to return" },
            "end_address": { "type": "string", "description": "Optional stop boundary" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_disasm_bytes() -> Value {
    json!({
        "type": "object",
        "properties": {
            "bytes": { "type": "string", "description": "Hex byte string" },
            "hex": { "type": "string", "description": "Alias for bytes" },
            "base_address": { "type": "string", "default": "0" },
            "base": { "type": "string", "description": "Alias for base_address" },
            "arch": { "type": "string", "enum": ["x86_64","x86","aarch64","arm"], "default": "x86_64" }
        },
        "required": []
    })
}

pub(crate) fn schema_find_imm_refs() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Target address whose value is searched as an immediate" },
            "limit": { "type": "integer", "default": 200 },
            "only_executable": { "type": "boolean", "default": true, "description": "Restrict scan to executable sections" }
        },
        "required": ["address"]
    })
}
