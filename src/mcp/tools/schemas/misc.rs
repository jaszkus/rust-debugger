use serde_json::{json, Value};

pub(crate) fn schema_list_exports_full() -> Value {
    json!({
        "type": "object",
        "properties": {
            "offset": { "type": "integer", "default": 0 },
            "limit": { "type": "integer", "default": 200 },
            "filter": { "type": "string", "default": "" },
            "only_forwarders": { "type": "boolean", "default": false }
        }
    })
}

pub(crate) fn schema_lookup_export() -> Value {
    json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" },
            "ordinal": { "type": "integer" }
        }
    })
}

pub(crate) fn schema_find_pe_headers() -> Value {
    json!({
        "type": "object",
        "properties": {
            "limit": { "type": "integer", "default": 32 }
        }
    })
}

pub(crate) fn schema_find_xor_loops() -> Value {
    json!({
        "type": "object",
        "properties": {
            "limit": { "type": "integer", "default": 50 }
        }
    })
}

pub(crate) fn schema_create_label() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Hex address" },
            "name": { "type": "string", "description": "Label name" }
        },
        "required": ["address", "name"]
    })
}

pub(crate) fn schema_tag_function() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Hex address of the function" },
            "tag": { "type": "string", "description": "Tag name (e.g. crypto, network, reviewed)" }
        },
        "required": ["address", "tag"]
    })
}

pub(crate) fn schema_tags_query() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Optional hex address — omit to list all tagged functions" }
        }
    })
}

pub(crate) fn schema_search_insns() -> Value {
    json!({
        "type": "object",
        "properties": {
            "mnemonic": { "type": "string", "description": "Substring of mnemonic (e.g. 'mov')" },
            "operand": { "type": "string", "description": "Substring of operand (e.g. '0x40ad321')" },
            "limit": { "type": "integer", "description": "Max results (default 100)" }
        }
    })
}

pub(crate) fn schema_search_funcs_enh() -> Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "description": "Name substring" },
            "min_size": { "type": "integer", "description": "Min function size in bytes" },
            "max_size": { "type": "integer", "description": "Max function size in bytes" },
            "limit": { "type": "integer", "description": "Max results (default 100)" }
        }
    })
}

pub(crate) fn schema_bulk_xrefs() -> Value {
    json!({
        "type": "object",
        "properties": {
            "addresses": { "type": "array", "items": { "type": "string" }, "description": "Array of hex addresses" }
        },
        "required": ["addresses"]
    })
}

pub(crate) fn schema_mem_ref() -> Value {
    json!({
        "type": "object",
        "properties": {
            "from": { "type": "string", "description": "Source hex address" },
            "to": { "type": "string", "description": "Target hex address" },
            "note": { "type": "string", "description": "Optional note" },
            "kind": { "type": "string", "description": "Reference kind (call/jump/data/...) — narrows remove_reference" },
            "op_index": { "type": "integer", "description": "Operand index (-1 = unknown) — narrows remove_reference" }
        },
        "required": ["from", "to"]
    })
}

pub(crate) fn schema_batch_comments() -> Value {
    json!({
        "type": "object",
        "properties": {
            "comments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "address": { "type": "string" },
                        "kind": { "type": "string" },
                        "text": { "type": "string" }
                    },
                    "required": ["address", "text"]
                }
            }
        },
        "required": ["comments"]
    })
}

pub(crate) fn schema_find_gaps() -> Value {
    json!({
        "type": "object",
        "properties": {
            "min_gap": { "type": "integer", "description": "Minimum gap size in bytes (default 16)" },
            "limit": { "type": "integer", "description": "Max results (default 100)" }
        }
    })
}

pub(crate) fn schema_inspect_mem() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Hex address" },
            "size": { "type": "integer", "description": "Bytes to inspect (default 32)" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_asm_ctx() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Target hex address" },
            "before": { "type": "integer", "description": "Instructions before (default 8)" },
            "after": { "type": "integer", "description": "Instructions after (default 8)" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_diff_funcs() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address_a": { "type": "string", "description": "First function address" },
            "address_b": { "type": "string", "description": "Second function address" }
        },
        "required": ["address_a", "address_b"]
    })
}

pub(crate) fn schema_func_sig() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Function address" },
            "bytes": { "type": "integer", "description": "Signature length in bytes (default 16)" }
        },
        "required": ["address"]
    })
}
