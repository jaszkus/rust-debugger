use serde_json::{json, Value};

pub(crate) fn schema_empty() -> Value {
    json!({ "type": "object", "properties": {}, "required": [] })
}

pub(crate) fn schema_addr() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Hex address (e.g. 0x140001000 or 140001000)" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_decompile() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Hex address (e.g. 0x140001000 or 140001000)" },
            "offset": { "type": "integer", "description": "First pseudocode line of the response page (default 0)" },
            "max_bytes": { "type": "integer", "description": "Response page budget in bytes, 1000..400000 (default 200000)" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_lookup() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Function address (hex) or name" }
        },
        "required": ["query"]
    })
}

pub(crate) fn schema_timeout() -> Value {
    json!({
        "type": "object",
        "properties": {
            "timeout_ms": { "type": "integer", "description": "How long to wait for completion, 5000..3600000 (default 600000)" }
        }
    })
}

pub(crate) fn schema_list_paginated() -> Value {
    json!({
        "type": "object",
        "properties": {
            "offset": { "type": "integer", "default": 0 },
            "limit": { "type": "integer", "default": 100 },
            "filter": { "type": "string", "default": "" }
        }
    })
}

pub(crate) fn schema_list_functions() -> Value {
    json!({
        "type": "object",
        "properties": {
            "offset": { "type": "integer", "default": 0, "minimum": 0 },
            "limit": { "type": "integer", "default": 100, "minimum": 1, "maximum": 1000, "description": "1..1000. Values above 1000 are clamped (reported in 'warnings'); values below 1 are rejected" },
            "filter": { "type": "string", "default": "", "description": "Substring of the function name or of its hex address ('0x' prefix optional)" }
        }
    })
}

pub(crate) fn schema_dotnet_token() -> Value {
    json!({
        "type": "object",
        "properties": {
            "token": { "type": "string", "description": "Metadata token hex (e.g. 0x0A000003 for MemberRef row 3)" }
        },
        "required": ["token"]
    })
}

pub(crate) fn schema_list_strings() -> Value {
    json!({
        "type": "object",
        "properties": {
            "offset": { "type": "integer", "default": 0 },
            "limit": { "type": "integer", "default": 100, "minimum": 1, "maximum": 5000, "description": "1..5000; larger values are clamped. A page is also cut at a response-size budget: follow next_offset while has_more is true" },
            "filter": { "type": "string", "default": "" },
            "encoding": { "type": "string", "enum": ["any", "ascii", "utf16le", "utf32le", "pascal"], "default": "any" },
            "min_length": { "type": "integer", "default": 8, "description": "Drop strings shorter than this (filters register-save prolog garbage like UVAVWATAWAUSH)" },
            "printable_ratio": { "type": "number", "default": 0.9, "description": "Fraction of printable chars required (0..1)" },
            "dedup": { "type": "boolean", "default": false, "description": "Keep only the first occurrence of identical content" },
            "include_exec": { "type": "boolean", "default": false, "description": "Include strings found in executable sections (code fragments)" }
        }
    })
}

pub(crate) fn schema_search() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" },
            "pattern": { "type": "string", "description": "Alias for query" },
            "limit": { "type": "integer", "default": 100 }
        },
        "required": []
    })
}

pub(crate) fn schema_search_paged() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Hex bytes, '??' = any byte (e.g. '80 3D ?? ?? ?? ?? 74')" },
            "pattern": { "type": "string", "description": "Alias for query" },
            "limit": { "type": "integer", "default": 100, "description": "Max matches returned per call" },
            "offset": { "type": "integer", "default": 0, "description": "Skip this many matches (pass next_offset while has_more is true)" }
        },
        "required": []
    })
}

pub(crate) fn schema_get_bytes() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "size": { "type": "integer", "default": 16 }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_get_int() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "type": { "type": "string", "enum": ["u8","u16","u32","u64","i8","i16","i32","i64"], "default": "u32" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_int_convert() -> Value {
    json!({
        "type": "object",
        "properties": {
            "value": { "type": "string", "description": "Number in dec or hex (0x prefix)" }
        },
        "required": ["value"]
    })
}
