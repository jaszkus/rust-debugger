use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::analysis::detect;
use crate::gui::AppState;

use super::format;

fn locked<F, T>(state: &Arc<Mutex<AppState>>, f: F) -> Result<T, String>
where
    F: FnOnce(&AppState) -> Result<T, String>,
{
    let s = super::lock::lock_state(state)?;
    f(&s)
}

fn snapshot_bin_dis(
    state: &Arc<Mutex<AppState>>,
) -> Result<(crate::parser::ParsedBinary, crate::disasm::DisasmResult), String> {
    let (bin, dis) = {
        let s = super::lock::lock_state(state)?;
        (
            s.binary.clone().ok_or("No binary loaded")?,
            s.disasm.clone().ok_or("No disassembly loaded")?,
        )
    };
    Ok((bin, dis))
}

#[allow(dead_code)]
fn require(
    s: &AppState,
) -> Result<(&crate::parser::ParsedBinary, &crate::disasm::DisasmResult), String> {
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let dis = s.disasm.as_ref().ok_or("No disassembly loaded")?;
    Ok((bin, dis))
}

pub fn detect_protections(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let (bin, dis) = snapshot_bin_dis(state)?;
    let report = detect::detect_all(&bin, &dis);
    Ok(format::protections_report(&report))
}

fn wrap_findings(findings: Vec<detect::Finding>) -> Value {
    json!({
        "count": findings.len(),
        "findings": findings.iter().map(format::finding).collect::<Vec<_>>(),
    })
}

pub fn detect_anti_debug(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let (bin, dis) = snapshot_bin_dis(state)?;
    Ok(wrap_findings(detect::detect_anti_debug(&bin, &dis)))
}

pub fn detect_anti_vm(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let (bin, dis) = snapshot_bin_dis(state)?;
    Ok(wrap_findings(detect::detect_anti_vm(&bin, &dis)))
}

pub fn detect_packers(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let bin = {
        let s = super::lock::lock_state(state)?;
        s.binary.clone().ok_or("No binary loaded")?
    };
    Ok(wrap_findings(detect::detect_packers(&bin)))
}

pub fn detect_obfuscation(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let dis = {
        let s = super::lock::lock_state(state)?;
        s.disasm.clone().ok_or("No disassembly loaded")?
    };
    Ok(wrap_findings(detect::detect_obfuscation(&dis)))
}

pub fn detect_crypto(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let bin = {
        let s = super::lock::lock_state(state)?;
        s.binary.clone().ok_or("No binary loaded")?
    };
    Ok(wrap_findings(detect::detect_crypto(&bin)))
}

pub fn is_dotnet_assembly(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    locked(state, |s| {
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        Ok(json!({ "is_dotnet": crate::parser::dotnet::is_dotnet(bin) }))
    })
}

pub fn dotnet_info(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    locked(state, |s| {
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        let info = crate::parser::dotnet::parse(bin)?;
        Ok(json!({
            "runtime_version": info.runtime_version,
            "cor20_flags": format!("{:#x}", info.cor20_flags),
            "entry_point_token": format!("{:#x}", info.entry_point_token),
            "metadata_rva": format!("{:#x}", info.metadata_rva),
            "metadata_size": info.metadata_size,
            "streams": info.streams.iter().map(|s| json!({
                "name": s.name,
                "size": s.size,
            })).collect::<Vec<_>>(),
            "heaps": {
                "strings": info.strings_heap_size,
                "blob": info.blob_heap_size,
                "guid": info.guid_heap_size,
                "user_strings": info.user_strings_heap_size,
            },
            "tables_present_count": info.tables_present.len(),
            "type_count": info.typedefs.len(),
            "method_count": info.methods.len(),
            "member_ref_count": info.member_refs.len(),
            "type_ref_count": info.type_refs.len(),
            "entry_point": crate::parser::dotnet::resolve_token(&info, info.entry_point_token),
        }))
    })
}

pub fn list_dotnet_types(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = args
        .get("offset")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0) as usize;
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(200)
        .clamp(1, 5000) as usize;
    let filter = args
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    locked(state, |s| {
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        let info = crate::parser::dotnet::parse(bin)?;
        let total = info.typedefs.len();
        let items: Vec<Value> = info
            .typedefs
            .iter()
            .filter(|t| {
                filter.is_empty()
                    || t.name.to_lowercase().contains(&filter)
                    || t.namespace.to_lowercase().contains(&filter)
            })
            .skip(offset)
            .take(limit)
            .map(|t| {
                let qualified = if t.namespace.is_empty() {
                    t.name.clone()
                } else {
                    format!("{}.{}", t.namespace, t.name)
                };
                json!({
                    "name": qualified,
                    "flags": format!("{:#x}", t.flags),
                })
            })
            .collect();
        Ok(json!({
            "total": total,
            "returned": items.len(),
            "items": items,
        }))
    })
}

pub fn list_dotnet_methods(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = args
        .get("offset")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0) as usize;
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(200)
        .clamp(1, 5000) as usize;
    let filter = args
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    locked(state, |s| {
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        let info = crate::parser::dotnet::parse(bin)?;
        let total = info.methods.len();
        let items: Vec<Value> = info
            .methods
            .iter()
            .filter(|m| {
                filter.is_empty()
                    || m.name.to_lowercase().contains(&filter)
                    || m.owner_type.to_lowercase().contains(&filter)
            })
            .skip(offset)
            .take(limit)
            .map(|m| {
                json!({
                    "name": if m.owner_type.is_empty() {
                        m.name.clone()
                    } else {
                        format!("{}::{}", m.owner_type, m.name)
                    },
                    "rva": format!("{:#x}", m.rva),
                    "flags": format!("{:#x}", m.flags),
                    "impl_flags": format!("{:#x}", m.impl_flags),
                })
            })
            .collect();
        Ok(json!({
            "total": total,
            "returned": items.len(),
            "items": items,
        }))
    })
}

pub fn list_dotnet_member_refs(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let offset = args
        .get("offset")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0) as usize;
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(200)
        .clamp(1, 5000) as usize;
    let filter = args
        .get("filter")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    locked(state, |s| {
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        let info = crate::parser::dotnet::parse(bin)?;
        let total = info.member_refs.len();
        let items: Vec<Value> = info
            .member_refs
            .iter()
            .filter(|m| {
                filter.is_empty()
                    || m.name.to_lowercase().contains(&filter)
                    || m.parent.to_lowercase().contains(&filter)
            })
            .skip(offset)
            .take(limit)
            .map(|m| {
                json!({
                    "name": format!("{}::{}", m.parent, m.name),
                    "parent": m.parent,
                    "member": m.name,
                })
            })
            .collect();
        Ok(json!({
            "total": total,
            "returned": items.len(),
            "items": items,
        }))
    })
}

pub fn resolve_dotnet_token(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let raw = args.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let token = u32::from_str_radix(
        raw.trim().trim_start_matches("0x").trim_start_matches("0X"),
        16,
    )
    .map_err(|_| format!("Invalid token: {}", raw))?;
    locked(state, |s| {
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        let info = crate::parser::dotnet::parse(bin)?;
        Ok(json!({
            "token": format!("{:#x}", token),
            "resolved": crate::parser::dotnet::resolve_token(&info, token),
        }))
    })
}
