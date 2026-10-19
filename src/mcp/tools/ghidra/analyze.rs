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
    let import_edges = s
        .binary
        .as_ref()
        .map(|bin| crate::analysis::xref::import_edges::function_import_callees(bin, a));
    let n = a.functions.len();
    let mut indegree: HashMap<u64, usize> = HashMap::new();
    let mut outdegree: HashMap<u64, usize> = HashMap::new();
    let mut roots = 0usize;
    let mut leaves = 0usize;
    let mut max_indegree = 0usize;
    let mut max_outdegree = 0usize;
    let mut max_indegree_fn = 0u64;
    let mut max_outdegree_fn = 0u64;
    let mut import_edges_total = 0usize;
    for f in &a.functions {
        let in_ = a.callers.get(&f.entry).map(|v| v.len()).unwrap_or(0);
        let out = a.callees.get(&f.entry).map(|v| v.len()).unwrap_or(0)
            + import_edges
                .as_ref()
                .and_then(|m| m.get(&f.entry))
                .map(|v| v.len())
                .unwrap_or(0);
        import_edges_total += import_edges
            .as_ref()
            .and_then(|m| m.get(&f.entry))
            .map(|v| v.len())
            .unwrap_or(0);
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
        "import_call_edges": import_edges_total,
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
    let include_padding = args
        .get("include_padding")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    
    let classify = |start: u64, end: u64| -> (&'static str, u64) {
        let mut pad = 0u64;
        let mut ok = 0u64;
        for sec in &bin.sections {
            let sec_end = sec.vaddr.saturating_add(sec.size);
            if end <= sec.vaddr || start >= sec_end {
                continue;
            }
            let a0 = start.max(sec.vaddr) - sec.vaddr;
            let a1 = end.min(sec_end) - sec.vaddr;
            let f0 = sec.offset.saturating_add(a0) as usize;
            let f1 = sec.offset.saturating_add(a1) as usize;
            if f0 >= f1 || f1 > bin.data.len() {
                continue;
            }
            for &b in &bin.data[f0..f1] {
                ok += 1;
                if matches!(b, 0xCC | 0x90 | 0x00) {
                    pad += 1;
                }
            }
        }
        if ok > 0 && pad == ok {
            ("padding", pad)
        } else {
            ("unclaimed", ok)
        }
    };

    let mut gaps: Vec<Value> = Vec::new();
    let mut padding_gaps = 0usize;
    for sec in &bin.sections {
        if !sec.is_executable {
            continue;
        }
        let start = sec.vaddr;
        let end = sec.vaddr.saturating_add(sec.size);
        
        
        
        let mut ranges: Vec<(u64, u64)> = a
            .functions
            .iter()
            .filter(|f| f.entry < end && f.end > start)
            .map(|f| (f.entry.max(start), f.end.min(end)))
            .collect();
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (rs, re) in ranges {
            if let Some(last) = merged.last_mut()
                && rs <= last.1
            {
                last.1 = last.1.max(re);
                continue;
            }
            merged.push((rs, re));
        }
        let mut cursor = start;
        for (rs, re) in merged {
            if rs > cursor && rs - cursor >= min_gap {
                let (kind, _bytes) = classify(cursor, rs);
                if kind == "padding" {
                    padding_gaps += 1;
                    if !include_padding {
                        cursor = re.max(cursor);
                        continue;
                    }
                }
                gaps.push(json!({
                    "start": addr_str(cursor),
                    "end": addr_str(rs),
                    "size": rs - cursor,
                    "section": sec.name,
                    "kind": kind,
                }));
            }
            cursor = cursor.max(re);
        }
        if end > cursor && end - cursor >= min_gap {
            let (kind, _bytes) = classify(cursor, end);
            if kind == "padding" {
                padding_gaps += 1;
                if !include_padding {
                    continue;
                }
            }
            gaps.push(json!({
                "start": addr_str(cursor),
                "end": addr_str(end),
                "size": end - cursor,
                "section": sec.name,
                "kind": kind,
            }));
        }
    }
    gaps.sort_by(|a, b| b["size"].as_u64().cmp(&a["size"].as_u64()));
    let total = gaps.len();
    gaps.truncate(limit);
    Ok(json!({
        "count": gaps.len(),
        "total_count": total,
        "padding_gaps_hidden": padding_gaps,
        "gaps": gaps
    }))
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
