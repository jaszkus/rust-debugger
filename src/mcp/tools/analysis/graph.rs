use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use std::collections::{HashMap, HashSet};

pub fn find_imports_called_by(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let f = function_containing(analysis, addr).ok_or_else(|| not_in_function(addr))?;

    let edges = crate::analysis::xref::import_edges::function_import_callees(bin, analysis);
    let mut found: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(list) = edges.get(&f.entry) {
        for c in list {
            let key = format!("{}!{}", c.library, c.name);
            if seen.insert(key.clone()) {
                found.push(json!({
                    "import_address": format!("{:#x}", c.import_offset),
                    "library": c.library,
                    "name": c.name,
                    "via": format!("{:#x}", c.via)
                }));
            }
        }
    }

    Ok(json!({
        "function": f.name,
        "address": format!("{:#x}", f.entry),
        "imports_used": found
    }))
}

pub fn find_strings_referenced_by(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let f = function_containing(analysis, addr).ok_or_else(|| not_in_function(addr))?;

    let mut found: Vec<Value> = Vec::new();
    let mut seen_addrs: HashSet<u64> = HashSet::new();

    for xr in &analysis.xrefs.all {
        if xr.from < f.entry || xr.from >= f.end {
            continue;
        }
        if !matches!(xr.kind, crate::analysis::XRefKind::StringRef) {
            continue;
        }
        if !seen_addrs.insert(xr.to) {
            continue;
        }
        found.push(json!({
            "from": format!("{:#x}", xr.from),
            "to": format!("{:#x}", xr.to),
            "content": xr.note.as_deref().unwrap_or("")
        }));
    }

    Ok(json!({
        "function": f.name,
        "address": format!("{:#x}", f.entry),
        "strings_count": found.len(),
        "strings": found
    }))
}

fn norm_lib(l: &str) -> String {
    let l = l.trim().to_ascii_lowercase();
    l.strip_suffix(".dll").unwrap_or(&l).to_string()
}

fn import_name_matches(want: &str, lib: &str, name: &str) -> bool {
    match want.split_once('!') {
        Some((wl, wn)) => norm_lib(wl) == norm_lib(lib) && wn.trim().eq_ignore_ascii_case(name),
        None => want.trim().eq_ignore_ascii_case(name),
    }
}

pub fn find_users_of_import(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    use crate::analysis::XRefKind;
    let import_name =
        crate::mcp::tools::schemas::arg_str_alias(args, &["name", "import_name", "import"])?;
    let s = crate::mcp::tools::lock::lock_state(state)?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;

    let import_addrs: Vec<u64> = bin
        .imports
        .iter()
        .chain(bin.delay_imports.iter())
        .filter(|i| import_name_matches(&import_name, &i.library, &i.name))
        .map(|i| i.offset)
        .collect();
    if import_addrs.is_empty() {
        return Err(format!("Import not found: {}", import_name));
    }

    let mut targets: HashSet<u64> = import_addrs.iter().copied().collect();
    let mut thunk_entries: HashSet<u64> = HashSet::new();
    for (stub_addr, stub) in &analysis.stubs {
        if let Some((lib, name)) = stub.target_name.split_once('!')
            && import_name_matches(&import_name, lib, name) {
                targets.insert(*stub_addr);
                targets.insert(stub.func_entry);
                thunk_entries.insert(stub.func_entry);
            }
    }

    let mut callers: HashSet<u64> = HashSet::new();
    for &t in &targets {
        if let Some(idxs) = analysis.xrefs.by_to.get(&t) {
            for &i in idxs {
                let xr = &analysis.xrefs.all[i];
                if matches!(
                    xr.kind,
                    XRefKind::Call
                        | XRefKind::Jump
                        | XRefKind::CallIndirect
                        | XRefKind::JumpIndirect
                        | XRefKind::TailCall
                ) {
                    callers.insert(xr.from);
                }
            }
        }
    }

    let mut spans: Vec<(u64, u64)> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.end))
        .collect();
    spans.sort_unstable();
    let owner = |addr: u64| -> Option<u64> {
        let k = spans.partition_point(|&(e, _)| e <= addr).checked_sub(1)?;
        let (e, end) = spans[k];
        (addr >= e && addr < end).then_some(e)
    };

    let mut user_funcs: Vec<u64> = callers
        .iter()
        .filter_map(|&a| owner(a))
        .filter(|e| !thunk_entries.contains(e))
        .collect();
    user_funcs.sort_unstable();
    user_funcs.dedup();

    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();
    let users: Vec<Value> = user_funcs
        .iter()
        .map(|a| {
            json!({
                "address": format!("{:#x}", a),
                "name": func_lookup.get(a).copied().unwrap_or("?"),
            })
        })
        .collect();

    let mut thunks: Vec<u64> = thunk_entries.into_iter().collect();
    thunks.sort_unstable();

    Ok(json!({
        "import": import_name,
        "import_addresses": import_addrs.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>(),
        "thunks": thunks.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>(),
        "user_function_count": users.len(),
        "users": users,
    }))
}

pub fn get_call_tree(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let entry = arg_addr(args, "address")?;
    let max_depth = arg_int(args, "max_depth", 3).clamp(1, 64) as u32;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();
    let import_edges = s.binary.as_ref().map(|bin| {
        crate::analysis::xref::import_edges::function_import_callees(bin, analysis)
    });
    let no_imports: rustc_hash::FxHashMap<
        u64,
        Vec<crate::analysis::xref::import_edges::ImportCallee>,
    > = rustc_hash::FxHashMap::default();
    let import_edges = import_edges.as_ref().unwrap_or(&no_imports);

    fn walk(
        addr: u64,
        depth: u32,
        max: u32,
        visited: &mut HashSet<u64>,
        analysis: &crate::analysis::AnalysisResult,
        lookup: &HashMap<u64, &str>,
        import_edges: &rustc_hash::FxHashMap<
            u64,
            Vec<crate::analysis::xref::import_edges::ImportCallee>,
        >,
    ) -> Value {
        if depth >= max {
            return Value::Null;
        }
        if !visited.insert(addr) {
            return json!({ "address": format!("{:#x}", addr), "cycle": true });
        }
        let empty = vec![];
        let callees = analysis.callees.get(&addr).unwrap_or(&empty);
        let mut children: Vec<Value> = callees
            .iter()
            .take(50)
            .map(|c| walk(*c, depth + 1, max, visited, analysis, lookup, import_edges))
            .filter(|v| !v.is_null())
            .collect();
        if let Some(imports) = import_edges.get(&addr) {
            for c in imports.iter().take(50) {
                children.push(json!({
                    "address": format!("{:#x}", c.import_offset),
                    "name": c.name,
                    "library": c.library,
                    "via": format!("{:#x}", c.via),
                    "import": true,
                    "depth": depth + 1,
                    "callees": [],
                }));
            }
        }
        json!({
            "address": format!("{:#x}", addr),
            "name": lookup.get(&addr).copied().unwrap_or("?"),
            "depth": depth,
            "callees": children
        })
    }

    let mut visited = HashSet::new();
    let tree = walk(
        entry,
        0,
        max_depth,
        &mut visited,
        analysis,
        &func_lookup,
        import_edges,
    );
    Ok(json!({
        "root": format!("{:#x}", entry),
        "max_depth": max_depth,
        "unique_functions_visited": visited.len(),
        "tree": tree
    }))
}

pub fn find_callers_chain(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let entry = arg_addr(args, "address")?;
    let max_depth = arg_int(args, "max_depth", 3).clamp(1, 64) as u32;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();

    let mut visited: HashSet<u64> = HashSet::new();
    let mut layers: Vec<Vec<u64>> = vec![vec![entry]];
    visited.insert(entry);

    for _ in 0..max_depth {
        let last = layers.last().unwrap().clone();
        let mut next = Vec::new();
        for addr in last {
            if let Some(callers) = analysis.callers.get(&addr) {
                for &c in callers {
                    if visited.insert(c) {
                        next.push(c);
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        layers.push(next);
    }

    let json_layers: Vec<Value> = layers
        .iter()
        .enumerate()
        .map(|(d, layer)| {
            let funcs: Vec<Value> = layer
                .iter()
                .map(|a| {
                    json!({
                        "address": format!("{:#x}", a),
                        "name": func_lookup.get(a).copied().unwrap_or("?")
                    })
                })
                .collect();
            json!({ "depth": d, "functions": funcs })
        })
        .collect();

    Ok(json!({
        "root": format!("{:#x}", entry),
        "max_depth": max_depth,
        "total_unique_callers": visited.len() - 1,
        "layers": json_layers
    }))
}

pub fn find_recursive_functions(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let func_lookup: HashMap<u64, &str> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.name.as_str()))
        .collect();

    let recursive: Vec<Value> = analysis
        .callees
        .iter()
        .filter(|(addr, callees)| callees.contains(addr))
        .map(|(addr, _)| {
            json!({
                "address": format!("{:#x}", addr),
                "name": func_lookup.get(addr).copied().unwrap_or("?")
            })
        })
        .collect();

    Ok(json!({ "count": recursive.len(), "functions": recursive }))
}

pub fn find_leaf_functions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 200).max(1) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let import_edges = s
        .binary
        .as_ref()
        .map(|bin| crate::analysis::xref::import_edges::function_import_callees(bin, analysis));
    let leaves: Vec<Value> = analysis
        .functions
        .iter()
        .filter(|f| {
            let no_calls = analysis
                .callees
                .get(&f.entry)
                .is_none_or(|v| v.is_empty());
            let no_imports = import_edges
                .as_ref()
                .and_then(|m| m.get(&f.entry))
                .is_none_or(|v| v.is_empty());
            no_calls && no_imports
        })
        .take(limit)
        .map(|f| {
            json!({
                "address": format!("{:#x}", f.entry),
                "name": f.name,
                "size": f.end - f.entry
            })
        })
        .collect();
    Ok(json!({ "count": leaves.len(), "functions": leaves }))
}

pub fn find_root_functions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 200).max(1) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let roots: Vec<Value> = analysis
        .functions
        .iter()
        .filter(|f| {
            !analysis.callers.contains_key(&f.entry)
                || analysis.callers.get(&f.entry).is_none_or(|v| v.is_empty())
        })
        .take(limit)
        .map(|f| {
            json!({
                "address": format!("{:#x}", f.entry),
                "name": f.name,
                "size": f.end - f.entry,
                "callees_count": analysis.callees.get(&f.entry).map(|v| v.len()).unwrap_or(0)
            })
        })
        .collect();
    Ok(json!({ "count": roots.len(), "functions": roots }))
}
