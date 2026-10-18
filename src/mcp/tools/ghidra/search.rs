use serde_json::{json, Value};

use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::core::decompile_function;
use crate::mcp::tools::search::search_bytes;

pub fn search_instructions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let d = s.disasm.as_ref().ok_or("No disassembly loaded")?;
    let mnemonic = arg_str_opt(args, "mnemonic").to_lowercase();
    let operand = arg_str_opt(args, "operand").to_lowercase();
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    if mnemonic.is_empty() && operand.is_empty() {
        return Err("Provide mnemonic and/or operand".into());
    }
    let mut rows = Vec::new();
    for insn in d.instructions.iter() {
        let m = insn.mnemonic.to_lowercase();
        let o = insn.ops().to_lowercase();
        if !mnemonic.is_empty() && !m.contains(&mnemonic) {
            continue;
        }
        if !operand.is_empty() && !o.contains(&operand) {
            continue;
        }
        rows.push(json!({
            "address": addr_str(insn.address),
            "mnemonic": insn.mnemonic,
            "operands": insn.ops().as_ref(),
            "bytes": insn.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
        }));
        if rows.len() >= limit {
            break;
        }
    }
    Ok(json!({ "count": rows.len(), "instructions": rows }))
}

pub fn search_functions_enhanced(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let s = lock(state)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let query = arg_str_opt(args, "query").to_lowercase();
    let min_size = arg_int(args, "min_size", 0);
    let max_size = arg_int(args, "max_size", i64::MAX);
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let mut rows = Vec::new();
    for f in &a.functions {
        let size = f.end.saturating_sub(f.entry);
        if (size as i64) < min_size || (size as i64) > max_size {
            continue;
        }
        if !query.is_empty() && !f.name.to_lowercase().contains(&query) {
            continue;
        }
        rows.push(json!({
            "address": addr_str(f.entry),
            "name": f.name,
            "size": size,
            "callers": a.callers.get(&f.entry).map(|v| v.len()).unwrap_or(0),
            "callees": a.callees.get(&f.entry).map(|v| v.len()).unwrap_or(0)
        }));
        if rows.len() >= limit {
            break;
        }
    }
    Ok(json!({ "count": rows.len(), "functions": rows }))
}

pub fn search_byte_patterns(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    search_bytes(args, state)
}

pub fn force_decompile(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    decompile_function(args, state)
}
