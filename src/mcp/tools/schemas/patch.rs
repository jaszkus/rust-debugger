use serde_json::{json, Value};

pub(crate) fn schema_pattern() -> Value {
    json!({
        "type": "object",
        "properties": {
            "pattern": { "type": "string", "description": "Mnemonic sequence (e.g. 'push;mov;call' or 'xor,xor,mov')" },
            "limit": { "type": "integer", "default": 100 },
            "offset": { "type": "integer", "default": 0, "description": "Skip this many matches (pass next_offset while has_more is true)" }
        },
        "required": ["pattern"]
    })
}
pub(crate) fn schema_path() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Filesystem path" }
        },
        "required": ["path"]
    })
}

pub(crate) fn schema_path_plus_offset() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "description": "Path to the .map file" },
            "base_offset": { "type": "string", "description": "Optional hex offset added to every symbol address (use when the analyzed image is rebased vs the map's preferred base)" }
        },
        "required": ["path"]
    })
}

pub(crate) fn schema_patch_bytes() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "bytes": { "type": "string", "description": "Hex bytes (e.g. '90 90 90' or '909090')" },
            "invalidate_analysis": { "type": "boolean", "default": true },
            "description": { "type": "string", "description": "Optional free-form note for the patch", "default": "" }
        },
        "required": ["address", "bytes"]
    })
}

pub(crate) fn schema_patch_bytes_aliased() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "bytes": { "type": "string", "description": "Hex bytes (e.g. '90 90 90' or '909090')" },
            "hex": { "type": "string", "description": "Alias for bytes" },
            "invalidate_analysis": { "type": "boolean", "default": true, "description": "Drop the analysis after patching (default true; the response reports analysis_invalidated). Pass false to keep the - then stale - analysis" },
            "description": { "type": "string", "description": "Optional free-form note for the patch", "default": "" }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_nop_range() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "size": { "type": "integer", "default": 1 },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["address", "size"]
    })
}

pub(crate) fn schema_fill_bytes() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "size": { "type": "integer", "default": 1 },
            "value": { "type": "integer", "description": "Byte value (0..255)", "default": 0 },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["address", "size"]
    })
}

pub(crate) fn schema_fill_pattern() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "size": { "type": "integer" },
            "pattern": { "type": "string", "description": "Hex pattern to repeat (e.g. 'CC CC')" },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["address", "size", "pattern"]
    })
}

pub(crate) fn schema_patch_string() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "text": { "type": "string" },
            "null_terminate": { "type": "boolean", "default": true },
            "invalidate_analysis": { "type": "boolean", "default": false }
        },
        "required": ["address", "text"]
    })
}

pub(crate) fn schema_patch_int() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "value": { "type": ["integer", "string"], "description": "Number (decimal) or '0x..' / '-0x..' string" },
            "type": { "type": "string", "enum": ["u8","u16","u32","u64","i8","i16","i32","i64"], "default": "u32" },
            "big_endian": { "type": "boolean", "default": false },
            "invalidate_analysis": { "type": "boolean", "default": false }
        },
        "required": ["address", "value"]
    })
}

pub(crate) fn schema_copy_bytes() -> Value {
    json!({
        "type": "object",
        "properties": {
            "src_address": { "type": "string" },
            "dst_address": { "type": "string" },
            "size": { "type": "integer" },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["src_address", "dst_address", "size"]
    })
}

pub(crate) fn schema_search_replace() -> Value {
    json!({
        "type": "object",
        "properties": {
            "find": { "type": "string", "description": "Hex pattern to find" },
            "replace": { "type": "string", "description": "Hex pattern to write (must be same length as 'find')" },
            "max_replacements": { "type": "integer", "default": 0, "description": "0 = unlimited" },
            "section": { "type": "string", "default": "", "description": "Restrict to a single section by name" },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["find", "replace"]
    })
}

pub(crate) fn schema_patch_nop_instruction() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Must be the start of an instruction (per current disasm)" },
            "count": { "type": "integer", "default": 1, "description": "Number of consecutive instructions to NOP out" },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["address"]
    })
}

pub(crate) fn schema_patch_jmp() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string" },
            "target": { "type": "string", "description": "Virtual address to jump to" },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["address", "target"]
    })
}

pub(crate) fn schema_patch_return_value() -> Value {
    json!({
        "type": "object",
        "properties": {
            "address": { "type": "string", "description": "Function entry virtual address" },
            "value": { "type": ["integer", "string"], "description": "Return value (must fit in 32 bits; 0 uses xor eax,eax)" },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["address", "value"]
    })
}

pub(crate) fn schema_import_patches() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "verify_originals": { "type": "boolean", "default": true, "description": "Skip patches whose recorded original bytes don't match current file content" },
            "invalidate_analysis": { "type": "boolean", "default": true }
        },
        "required": ["path"]
    })
}

pub(crate) fn schema_diff_with_file() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "max_diffs": { "type": "integer", "default": 1024 }
        },
        "required": ["path"]
    })
}
