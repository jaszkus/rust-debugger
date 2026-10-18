use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::parse_addr;
use crate::gui::AppState;

fn lock(state: &Arc<Mutex<AppState>>) -> Result<std::sync::MutexGuard<'_, AppState>, String> {
    state.lock().map_err(|_| "lock poisoned".to_string())
}

pub fn get_binary_overview(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let (bin, dis_opt, func_counts, patch_count) = {
        let s = super::lock::lock_state(state)?;
        let bin = s.binary.clone().ok_or("No binary loaded")?;
        let dis = s.disasm.clone();
        let funcs = s.analysis.as_ref().map(|a| a.functions.len());
        let decomp = s.analysis.as_ref().map(|a| a.pseudocode.len());
        let patches = s.patches.len();
        (bin, dis, (funcs, decomp), patches)
    };
    let bin_ref = &bin;

    use rayon::prelude::*;
    let mut rows: Vec<(u64, f64, Value)> = crate::util::parallel::install(|| {
        bin_ref
            .sections
            .par_iter()
            .map(|sec| {
                let h =
                    (super::unpack::section_entropy_value(bin_ref, sec) * 100.0).round() / 100.0;
                (
                    sec.vaddr,
                    h,
                    json!({
                        "name": sec.name,
                        "vaddr": format!("{:#x}", sec.vaddr),
                        "size": sec.size,
                        "executable": sec.is_executable,
                        "entropy": h,
                        "verdict": super::unpack::entropy_verdict(h),
                    }),
                )
            })
            .collect()
    });
    rows.sort_by_key(|(va, _, _)| *va);
    let packed_names: Vec<Value> = rows
        .iter()
        .filter(|(_, h, _)| *h > 7.5)
        .map(|(_, _, v)| v["name"].clone())
        .collect();
    let exec_hot = rows
        .iter()
        .any(|(_, h, v)| *h > 6.8 && v["executable"] == true);
    let entropy_summary = json!({
        "max": rows.iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(_, h, v)| json!({ "section": v["name"], "entropy": h })),
        "packed_or_encrypted": packed_names,
        "verdict": if !packed_names.is_empty() {
            "likely_packed"
        } else if exec_hot {
            "suspicious_executable_entropy"
        } else {
            "normal"
        },
    });
    let sections: Vec<Value> = rows.into_iter().map(|(_, _, v)| v).collect();

    let mut lib_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for imp in &bin_ref.imports {
        *lib_counts.entry(imp.library.as_str()).or_insert(0) += 1;
    }
    let mut libs: Vec<(String, usize)> = lib_counts
        .into_iter()
        .map(|(l, c)| (l.to_string(), c))
        .collect();
    libs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let total_imports: usize = libs.iter().map(|(_, c)| c).sum();

    let protections = dis_opt.as_ref().map(|dis| {
        let report = crate::analysis::detect::detect_all(bin_ref, dis);
        let mut by_cat: std::collections::BTreeMap<&str, usize> = Default::default();
        let mut by_sev: std::collections::BTreeMap<&str, usize> = Default::default();
        for f in &report.findings {
            *by_cat.entry(f.category.as_str()).or_insert(0) += 1;
            *by_sev.entry(f.severity.as_str()).or_insert(0) += 1;
        }
        json!({
            "total_findings": report.findings.len(),
            "by_category": by_cat,
            "by_severity": by_sev,
            "note": "Counts only - call detect_protections for full findings.",
        })
    });

    Ok(json!({
        "format": bin.format,
        "arch": bin.arch,
        "image_base": format!("{:#x}", bin.image_base),
        "entry_point": format!("{:#x}", bin.entry_point),
        "size_bytes": bin.data.len(),
        "is_dll": bin.is_dll,
        "sections": sections,
        "entropy_summary": entropy_summary,
        "imports": {
            "total": total_imports,
            "libraries": libs.iter().take(15).map(|(l, c)| json!({
                "library": l, "count": c
            })).collect::<Vec<_>>(),
            "library_count": libs.len(),
        },
        "export_count": bin.exports.len(),
        "string_count": bin.strings.len(),
        "functions_detected": func_counts.0,
        "decompiled_cached": func_counts.1,
        "is_dotnet": crate::parser::dotnet::is_dotnet(&bin),
        "protections": protections,
        "patch_count": patch_count,
    }))
}

pub fn get_call_context(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr_s = args
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or("Missing string param: address")?;
    let addr = parse_addr(addr_s).ok_or_else(|| format!("Invalid address: {}", addr_s))?;

    let func_entry = {
        let s = lock(state)?;
        let analysis = s
            .analysis
            .as_ref()
            .ok_or("No analysis loaded - run run_analysis first")?;
        let f = analysis
            .functions
            .iter()
            .find(|f| addr >= f.entry && addr < f.end)
            .ok_or_else(|| format!("Address {} is not inside any detected function", addr_s))?;
        f.entry
    };
    let at_entry = json!({ "address": format!("{:#x}", func_entry) });

    let decompilation =
        super::core::decompile_function(&at_entry, state).unwrap_or_else(|e| json!({ "error": e }));
    let callers = super::core::get_function_callers(&at_entry, state)
        .unwrap_or_else(|e| json!({ "error": e }));
    let callees = super::core::get_function_callees(&at_entry, state)
        .unwrap_or_else(|e| json!({ "error": e }));
    let imports_called = super::analysis::find_imports_called_by(&at_entry, state)
        .unwrap_or_else(|e| json!({ "error": e }));
    let strings_referenced = super::analysis::find_strings_referenced_by(&at_entry, state)
        .unwrap_or_else(|e| json!({ "error": e }));

    Ok(json!({
        "requested_address": addr_s,
        "resolved_function": format!("{:#x}", func_entry),
        "decompiled": decompilation.get("code").cloned()
            .unwrap_or_else(|| decompilation.get("error").cloned().unwrap_or(Value::Null)),
        "callers": callers.get("callers").cloned().unwrap_or(Value::Null),
        "callees": callees.get("callees").cloned().unwrap_or(Value::Null),
        "imports_called": imports_called.get("imports_used")
            .or_else(|| imports_called.get("error")).cloned().unwrap_or(Value::Null),
        "strings_referenced": strings_referenced.get("strings")
            .or_else(|| strings_referenced.get("error")).cloned().unwrap_or(Value::Null),
    }))
}
