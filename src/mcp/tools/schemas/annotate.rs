use serde_json::{json, Value};

pub(crate) fn schema_set_comment() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "text": { "type": "string" },
            "kind": { "type": "string", "description": "eol (default), pre, post, plate, repeatable" }
        },
        "required": ["address", "text"]
    })
}

pub(crate) fn schema_set_plan() -> Value {
    json!({
        "type": "object",
        "properties": {
            "steps": { "type": "array", "items": { "type": "string" }, "description": "Ordered plan step labels (empty clears the plan card)" },
            "current": { "type": "integer", "default": 0, "description": "Index of the in-progress step (earlier steps show done)" }
        },
        "required": ["steps"]
    })
}

pub(crate) fn schema_set_bookmark() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "note": { "type": "string", "default": "" },
            "kind": { "type": "string", "description": "note (default), info, error, analysis" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_rename_function() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "name": { "type": "string" }
        },
        "required": ["address", "name"]
    })
}

pub(crate) fn schema_create_function() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Hex entry address of the new function" },
            "name": { "type": "string", "description": "Optional name (default sub_<addr>)" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_lookup_name() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string", "description": "Import name (e.g. 'CreateFileW') or 'lib!name' form" },
            "import_name": { "type": "string", "description": "Alias for name" }
        },
        "required": []
    })
}

pub(crate) fn schema_addr_depth() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "max_depth": { "type": "integer", "default": 3 }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_similar() -> Value {
    json!({
        "type": "object",
        "properties": {
            "min_size": { "type": "integer", "default": 16, "description": "Minimum function size in bytes" },
            "limit": { "type": "integer", "default": 50, "description": "Max GROUPS to return (not functions — a single group can hold thousands of dup functions)" },
            "per_group_limit": { "type": "integer", "default": 25, "description": "Max function entries listed per group (group_total keeps the true count)" },
            "min_dups": { "type": "integer", "default": 2, "description": "Only groups with at least this many duplicates" }
        }
    })
}

pub(crate) fn schema_fid_ingest() -> Value {
    json!({
        "type": "object",
        "properties": {
            "library": { "type": "string", "description": "Library name for the ingested signatures (e.g. 'msvcrt', 'myapp-1.2')" }
        },
        "required": ["library"]
    })
}

pub(crate) fn schema_fid_list() -> Value {
    json!({
        "type": "object",
        "properties": {
            "filter": { "type": "string", "description": "Substring filter over signature/library names" },
            "limit": { "type": "integer", "default": 50 },
            "offset": { "type": "integer", "default": 0 }
        }
    })
}
