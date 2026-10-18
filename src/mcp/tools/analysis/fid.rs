use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use std::collections::HashMap;

pub fn get_function_hash(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let disasm = s.disasm.as_ref().ok_or("No disasm")?;
    let f = function_containing(analysis, addr).ok_or_else(|| not_in_function(addr))?;

    let s_idx = disasm.instructions.partition_point(|i| i.address < f.entry);
    let e_idx = disasm.instructions.partition_point(|i| i.address < f.end);
    let h = crate::analysis::function_id::hash_range(&disasm.instructions[s_idx..e_idx]);
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": f.name,
        "instruction_count": e_idx - s_idx,
        "hash": format!("{:016x}", h.full),
        "full": format!("{:016x}", h.full),
        "specific": format!("{:016x}", h.specific),
        "note": "full ignores operand values (masks immediates/registers); specific folds them back in"
    }))
}

pub fn find_similar_functions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let min_size = arg_int(args, "min_size", 16).max(1) as u64;
    let limit = arg_int(args, "limit", 50).max(1) as usize;
    let per_group_limit = arg_int(args, "per_group_limit", 25).max(1) as usize;
    let min_dups = arg_int(args, "min_dups", 2).max(2) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let disasm = s.disasm.as_ref().ok_or("No disasm")?;

    let mut groups: HashMap<u64, Vec<&crate::analysis::DetectedFunction>> = HashMap::new();
    for f in &analysis.functions {
        if f.end - f.entry < min_size {
            continue;
        }
        let s_idx = disasm.instructions.partition_point(|i| i.address < f.entry);
        let e_idx = disasm.instructions.partition_point(|i| i.address < f.end);
        let h = crate::analysis::function_id::hash_range(&disasm.instructions[s_idx..e_idx]);
        groups.entry(h.full).or_default().push(f);
    }

    let mut clusters: Vec<&Vec<&crate::analysis::DetectedFunction>> =
        groups.values().filter(|v| v.len() >= min_dups).collect();
    clusters.sort_by_key(|c| std::cmp::Reverse(c.len()));

    let result: Vec<Value> = clusters
        .iter()
        .take(limit)
        .map(|cluster| {
            let group_total = cluster.len();
            let funcs: Vec<Value> = cluster
                .iter()
                .take(per_group_limit)
                .map(|f| {
                    json!({
                        "address": format!("{:#x}", f.entry),
                        "name": f.name,
                        "size": f.end - f.entry
                    })
                })
                .collect();
            json!({
                "duplicate_count": group_total,
                "group_total": group_total,
                "truncated": group_total > per_group_limit,
                "functions": funcs
            })
        })
        .collect();

    Ok(json!({
        "total_groups": clusters.len(),
        "groups": result
    }))
}

pub fn fid_ingest_library(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let library = arg_str(args, "library")?;
    let (insns, funcs, relocs) = {
        let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        let analysis = s
            .analysis
            .as_ref()
            .ok_or("No analysis loaded - run the run_analysis tool first")?;
        let disasm = s.disasm.as_ref().ok_or("No disasm")?;
        let funcs: Vec<(u64, u64, String)> = analysis
            .functions
            .iter()
            .map(|f| (f.entry, f.end, f.name.clone()))
            .collect();
        let relocs = s
            .binary
            .as_ref()
            .map(|b| b.relocations.clone())
            .unwrap_or_default();
        (disasm.instructions.clone(), funcs, relocs)
    };
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    s.fid_db.set_reloc_mask(&relocs);
    let added = s.fid_db.ingest_functions(&insns, &funcs, &library);
    Ok(json!({
        "library": library,
        "ingested": added,
        "db_size": s.fid_db.len(),
        "note": "Only named (non-sub_) functions become signatures; re-run analysis to apply"
    }))
}

pub fn fid_export_db(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let n = s.fid_db.export_db(std::path::Path::new(&path))?;
    Ok(json!({ "path": path, "exported": n }))
}

pub fn fid_import_db(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let n = s.fid_db.import_db(std::path::Path::new(&path))?;
    Ok(json!({ "path": path, "imported": n, "db_size": s.fid_db.len() }))
}

pub fn fid_list(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 50).max(1) as usize;
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let mut sigs: Vec<_> = s.fid_db.signatures_iter().collect();
    sigs.sort_by(|a, b| a.name.cmp(&b.name).then(a.hash.cmp(&b.hash)));
    if !filter.is_empty() {
        sigs.retain(|sig| {
            sig.name.to_lowercase().contains(&filter)
                || sig.library.to_lowercase().contains(&filter)
        });
    }
    let total = sigs.len();
    let page: Vec<Value> = sigs
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|sig| {
            json!({
                "name": sig.name,
                "library": sig.library,
                "full": format!("{:016x}", sig.hash),
                "specific": format!("{:016x}", sig.specific),
                "size": sig.size,
            })
        })
        .collect();
    Ok(json!({ "total": total, "offset": offset, "count": page.len(), "signatures": page }))
}
