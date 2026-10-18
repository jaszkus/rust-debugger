use serde_json::{json, Value};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

pub fn analyze_call_graph(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let n = a.functions.len();
    let mut indegree: HashMap<u64, usize> = HashMap::new();
    let mut outdegree: HashMap<u64, usize> = HashMap::new();
    let mut roots = 0usize;
    let mut leaves = 0usize;
    let mut max_indegree = 0usize;
    let mut max_outdegree = 0usize;
    let mut max_indegree_fn = 0u64;
    let mut max_outdegree_fn = 0u64;
    for f in &a.functions {
        let in_ = a.callers.get(&f.entry).map(|v| v.len()).unwrap_or(0);
        let out = a.callees.get(&f.entry).map(|v| v.len()).unwrap_or(0);
        indegree.insert(f.entry, in_);
        outdegree.insert(f.entry, out);
        if in_ == 0 {
            roots += 1;
        }
        if out == 0 {
            leaves += 1;
        }
        if in_ > max_indegree {
            max_indegree = in_;
            max_indegree_fn = f.entry;
        }
        if out > max_outdegree {
            max_outdegree = out;
            max_outdegree_fn = f.entry;
        }
    }
    Ok(json!({
        "function_count": n,
        "root_functions": roots,
        "leaf_functions": leaves,
        "avg_indegree": if n > 0 { indegree.values().sum::<usize>() as f64 / n as f64 } else { 0.0 },
        "avg_outdegree": if n > 0 { outdegree.values().sum::<usize>() as f64 / n as f64 } else { 0.0 },
        "max_indegree": max_indegree,
        "max_indegree_function": addr_str(max_indegree_fn),
        "max_outdegree": max_outdegree,
        "max_outdegree_function": addr_str(max_outdegree_fn)
    }))
}

pub fn analyze_control_flow(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let addr = arg_addr(args, "address")?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let f = a
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
        .ok_or("Address not in any function")?;
    let cfg = a.cfgs.get(&f.entry).ok_or("No CFG for function")?;
    let blocks = cfg.blocks.len();
    let edges: usize = cfg.blocks.iter().map(|b| b.successors.len()).sum();
    let branches: usize = cfg
        .blocks
        .iter()
        .map(|b| b.successors.len().saturating_sub(1))
        .sum();
    let size = f.end.saturating_sub(f.entry);
    Ok(json!({
        "function": addr_str(f.entry),
        "name": f.name,
        "size": size,
        "basic_blocks": blocks,
        "edges": edges,
        "branch_points": branches,
        "avg_block_size": if blocks > 0 { size as f64 / blocks as f64 } else { 0.0 },
        "is_linear": blocks <= 1
    }))
}

pub fn find_code_gaps(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let min_gap = arg_int(args, "min_gap", 16) as u64;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let mut entries: Vec<u64> = a.functions.iter().map(|f| f.entry).collect();
    entries.sort();
    let mut gaps: Vec<Value> = Vec::new();
    for sec in &bin.sections {
        if !sec.is_executable {
            continue;
        }
        let mut prev_end: Option<u64> = None;
        let start = sec.vaddr;
        let end = sec.vaddr + sec.size;
        for &e in &entries {
            if e < start || e >= end {
                continue;
            }
            if let Some(p) = prev_end {
                if e > p && e - p >= min_gap {
                    gaps.push(json!({
                        "start": addr_str(p),
                        "end": addr_str(e),
                        "size": e - p,
                        "section": sec.name
                    }));
                }
            } else if e > start && e - start >= min_gap {
                gaps.push(json!({
                    "start": addr_str(start),
                    "end": addr_str(e),
                    "size": e - start,
                    "section": sec.name
                }));
            }
            prev_end = Some(
                a.functions
                    .iter()
                    .find(|f| f.entry == e)
                    .map(|f| f.end)
                    .unwrap_or(e),
            );
        }
    }
    gaps.sort_by(|a, b| b["size"].as_u64().cmp(&a["size"].as_u64()));
    gaps.truncate(limit);
    Ok(json!({ "count": gaps.len(), "gaps": gaps }))
}

pub fn find_next_undefined_function(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let s = lock(state)?;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let addr = arg_addr(args, "address")?;
    let mut candidates: Vec<(u64, u64)> = Vec::new();
    for sec in &bin.sections {
        if !sec.is_executable {
            continue;
        }
        let start = sec.vaddr;
        let end = sec.vaddr + sec.size;
        let mut entries: Vec<u64> = a
            .functions
            .iter()
            .map(|f| f.entry)
            .filter(|e| *e >= start && *e < end)
            .collect();
        entries.sort();
        let mut prev = start;
        for e in entries {
            if e > prev {
                candidates.push((prev, e - prev));
            }
            prev = a
                .functions
                .iter()
                .find(|f| f.entry == e)
                .map(|f| f.end)
                .unwrap_or(e);
        }
        if end > prev {
            candidates.push((prev, end - prev));
        }
    }
    candidates.retain(|(s_, sz)| *s_ + *sz > addr);
    if let Some((s_, sz)) = candidates.first() {
        Ok(json!({ "address": addr_str(*s_), "size": *sz, "end": addr_str(s_ + sz) }))
    } else {
        Ok(json!({ "address": null, "size": 0 }))
    }
}
