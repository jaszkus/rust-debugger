use serde_json::{json, Value};

use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

pub fn get_current_program_info(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    Ok(json!({
        "name": s.file_path.rsplit(['/', '\\']).next().unwrap_or(""),
        "path": s.file_path,
        "language": bin.arch,
        "format": bin.format,
        "image_base": addr_str(bin.image_base),
        "entry_point": addr_str(bin.entry_point),
        "sections": bin.sections.len(),
        "imports": bin.imports.len(),
        "exports": bin.exports.len(),
        "strings": bin.strings.len(),
        "analysis_loaded": s.analysis.is_some(),
        "function_count": s.analysis.as_ref().map(|a| a.functions.len()).unwrap_or(0),
    }))
}

pub fn reanalyze(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    if s.binary.is_none() {
        return Err(no_binary());
    }
    s.mcp_request_analysis = true;
    Ok(json!({ "status": "queued" }))
}

pub fn save_program(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    crate::mcp::tools::rw::dump_full_binary(args, state)
}
