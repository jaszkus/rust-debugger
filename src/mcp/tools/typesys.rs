use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::{arg_addr, arg_bool, arg_int, arg_str, arg_str_opt};
use crate::gui::AppState;

fn lock(state: &Arc<Mutex<AppState>>) -> Result<std::sync::MutexGuard<'_, AppState>, String> {
    state.lock().map_err(|_| "lock poisoned".to_string())
}

fn type_id_of(
    m: &mut crate::type_system::DataTypeManager,
    name: &str,
) -> Result<crate::type_system::TypeId, String> {
    m.resolve_type_name(name)
}

pub fn list_data_types(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let types: Vec<Value> = s
        .types
        .all()
        .iter()
        .map(|(id, _)| {
            json!({
                "id": id,
                "name": s.types.type_name(*id),
                "size": s.types.size_of(*id),
                "decl": s.types.to_c_decl(*id, 0),
            })
        })
        .collect();
    Ok(json!({ "count": types.len(), "types": types }))
}

pub fn get_data_type(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let name = arg_str(args, "name")?;
    let id = type_id_of(&mut s.types, &name)?;
    Ok(json!({
        "id": id,
        "name": s.types.type_name(id),
        "size": s.types.size_of(id),
        "decl": s.types.to_c_decl(id, 0),
    }))
}

pub fn create_struct(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let mut s = lock(state)?;
    let id = s.types.create_struct(&name)?;
    Ok(json!({ "id": id, "name": name, "kind": "struct", "ok": true }))
}

pub fn create_union(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let mut s = lock(state)?;
    let id = s.types.create_union(&name)?;
    Ok(json!({ "id": id, "name": name, "kind": "union", "ok": true }))
}

pub fn create_enum(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let underlying = arg_str_opt(args, "underlying");
    let mut s = lock(state)?;
    let base = if underlying.is_empty() {
        crate::type_system::ID_INT
    } else {
        type_id_of(&mut s.types, &underlying)?
    };
    let id = s.types.create_enum(&name, base)?;
    Ok(
        json!({ "id": id, "name": name, "kind": "enum", "underlying": s.types.type_name(base), "ok": true }),
    )
}

pub fn create_typedef(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let target = arg_str(args, "target")?;
    let mut s = lock(state)?;
    let tid = type_id_of(&mut s.types, &target)?;
    let id = s.types.create_typedef(&name, tid)?;
    Ok(json!({ "id": id, "name": name, "target": target, "ok": true }))
}

pub fn create_pointer_type(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let target = arg_str(args, "target")?;
    let mut s = lock(state)?;
    let tid = type_id_of(&mut s.types, &target)?;
    let id = s.types.create_pointer(tid)?;
    Ok(json!({ "id": id, "name": s.types.type_name(id), "ok": true }))
}

pub fn create_array_type(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let element = arg_str(args, "element")?;
    let count = arg_int(args, "count", 1).max(1) as usize;
    let mut s = lock(state)?;
    let eid = type_id_of(&mut s.types, &element)?;
    let id = s.types.create_array(eid, count)?;
    Ok(json!({ "id": id, "name": s.types.type_name(id), "ok": true }))
}

pub fn create_function_signature(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let ret = arg_str_opt(args, "return_type");
    let cc = arg_str_opt(args, "calling_convention");
    let varargs = arg_bool(args, "varargs", false);
    let mut s = lock(state)?;
    let rid = if ret.is_empty() {
        crate::type_system::ID_VOID
    } else {
        type_id_of(&mut s.types, &ret)?
    };
    let mut params: Vec<(crate::type_system::TypeId, String)> = Vec::new();
    if let Some(arr) = args.get("params").and_then(|v| v.as_array()) {
        for p in arr {
            let pname = p
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("param")
                .to_string();
            let ptype = p.get("type").and_then(|v| v.as_str()).unwrap_or("int");
            let ptid = type_id_of(&mut s.types, ptype)?;
            params.push((ptid, pname));
        }
    }
    let id = s.types.create_function_sig(
        &name,
        rid,
        params,
        if cc.is_empty() { "unknown" } else { &cc },
        varargs,
    )?;
    Ok(json!({ "id": id, "name": name, "ok": true }))
}

pub fn add_struct_field(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let type_name = arg_str(args, "type")?;
    let field = arg_str(args, "field")?;
    let field_type = arg_str(args, "field_type")?;
    let comment = arg_str_opt(args, "comment");
    let offset: Option<usize> = match args.get("offset") {
        None | Some(Value::Null) => None,
        Some(v) if v.is_number() => Some(v.as_i64().unwrap_or(0).max(0) as usize),
        Some(v) if v.is_string() && !v.as_str().unwrap_or("").trim().is_empty() => {
            Some(arg_int(args, "offset", 0).max(0) as usize)
        }
        _ => None,
    };
    let mut s = lock(state)?;
    let id = type_id_of(&mut s.types, &type_name)?;
    let ft = type_id_of(&mut s.types, &field_type)?;
    let bit_width: Option<u8> = args
        .get("bit_width")
        .and_then(|v| v.as_u64())
        .map(|v| v.min(255) as u8);
    let bit_offset: u8 = args
        .get("bit_offset")
        .and_then(|v| v.as_u64())
        .map(|v| v.min(255) as u8)
        .unwrap_or(0);
    if let Some(w) = bit_width {
        let byte_off = offset.unwrap_or(0);
        let f = s
            .types
            .add_bitfield(id, &field, ft, byte_off, bit_offset, w)?;
        return Ok(
            json!({ "type": type_name, "field": f.name, "offset": f.offset,
            "bit_offset": f.bit_offset, "bit_width": f.bit_width, "ok": true }),
        );
    }
    let f = s.types.add_field(id, &field, ft, offset, &comment)?;
    Ok(json!({ "type": type_name, "field": f.name, "offset": f.offset, "ok": true }))
}

pub fn remove_struct_field(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let type_name = arg_str(args, "type")?;
    let field = arg_str(args, "field")?;
    let mut s = lock(state)?;
    let id = type_id_of(&mut s.types, &type_name)?;
    s.types.remove_field(id, &field)?;
    Ok(json!({ "type": type_name, "field": field, "ok": true }))
}

pub fn add_enum_variant(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let type_name = arg_str(args, "type")?;
    let name = arg_str(args, "name")?;
    let value = arg_int(args, "value", 0);
    let mut s = lock(state)?;
    let id = type_id_of(&mut s.types, &type_name)?;
    s.types.add_enum_variant(id, &name, value)?;
    Ok(json!({ "type": type_name, "variant": name, "value": value, "ok": true }))
}

pub fn rename_data_type(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let new_name = arg_str(args, "new_name")?;
    let mut s = lock(state)?;
    let id = type_id_of(&mut s.types, &name)?;
    s.types.rename(id, &new_name)?;
    Ok(json!({ "old": name, "new": new_name, "ok": true }))
}

pub fn delete_data_type(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let mut s = lock(state)?;
    let id = type_id_of(&mut s.types, &name)?;
    s.types.delete(id)?;
    Ok(json!({ "deleted": name, "ok": true }))
}

pub fn apply_data_type(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let name = arg_str(args, "type")?;
    let mut s = lock(state)?;
    let id = type_id_of(&mut s.types, &name)?;
    s.data_types_at.insert(addr, id);
    Ok(json!({
        "address": format!("{:#x}", addr),
        "type": name,
        "size": s.types.size_of(id),
        "ok": true
    }))
}

pub fn get_data_type_at(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = lock(state)?;
    match s.data_types_at.get(&addr) {
        Some(id) => Ok(json!({
            "address": format!("{:#x}", addr),
            "type": s.types.type_name(*id),
            "decl": s.types.to_c_decl(*id, 0)
        })),
        None => Ok(json!({ "address": format!("{:#x}", addr), "type": null })),
    }
}

pub fn list_applied_types(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let mut items: Vec<Value> = s
        .data_types_at
        .iter()
        .map(|(a, t)| {
            json!({
                "address": format!("{:#x}", a),
                "type": s.types.type_name(*t)
            })
        })
        .collect();
    items.sort_by_key(|v| {
        v.get("address")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string()
    });
    Ok(json!({ "count": items.len(), "items": items }))
}

pub fn export_types(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    Ok(s.types.to_json())
}

pub fn import_types(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let path = arg_str_opt(args, "path");
    let doc: Value = if !path.is_empty() {
        let raw = std::fs::read_to_string(&path).map_err(|e| format!("Read failed: {}", e))?;
        serde_json::from_str(&raw).map_err(|e| format!("Parse failed: {}", e))?
    } else {
        args.get("types")
            .cloned()
            .ok_or("Provide 'types' array or 'path'")?
    };
    s.types.from_json(&doc)?;
    Ok(json!({ "ok": true, "count": s.types.len() }))
}

pub fn import_dwarf_types(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let bin = s.binary.clone().ok_or("No binary loaded")?;
    let stats = crate::analysis::dwarf_types::import_dwarf_types(&bin, &mut s.types);
    Ok(json!({
        "ok": true,
        "structs": stats.structs,
        "unions": stats.unions,
        "enums": stats.enums,
        "typedefs": stats.typedefs,
        "arrays": stats.arrays,
        "pointers": stats.pointers,
        "functions_named": stats.functions_named,
        "skipped": stats.skipped,
        "total_types": s.types.len(),
    }))
}

pub fn import_pdb(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let path_arg = arg_str_opt(args, "path");
    let path = if path_arg.is_empty() {
        let fp = s.file_path.as_str();
        if fp.is_empty() {
            return Err("No binary loaded and no path given".into());
        }
        std::path::PathBuf::from(fp).with_extension("pdb")
    } else {
        std::path::PathBuf::from(path_arg)
    };
    let stats = crate::analysis::pdb_types::import_pdb_types(&path, &mut s.types)?;
    Ok(json!({
        "ok": true,
        "path": path.display().to_string(),
        "structs": stats.structs,
        "unions": stats.unions,
        "enums": stats.enums,
        "skipped": stats.skipped,
        "total_types": s.types.len(),
    }))
}

pub fn list_type_archives(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let _ = state;
    Ok(json!({
        "archives": [
            { "name": "win32", "description": "Win32 base types: BYTE/WORD/DWORD/HANDLE/GUID/FILETIME/SYSTEMTIME/POINT/RECT/LARGE_INTEGER/..." },
            { "name": "crt", "description": "C runtime: time_t/div_t/tm/timeval/timespec/FILE/..." },
            { "name": "libc", "description": "POSIX/libc: pid_t/in_addr/sockaddr_in/pollfd/..." },
        ],
        "note": "Ghidra .gdt equivalent (native seeds; idempotent)"
    }))
}

pub fn load_type_archive(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let archive = arg_str(args, "archive")?;
    let mut s = lock(state)?;
    let added = s.types.seed_archive(&archive)?;
    s.analysis_version += 1;
    Ok(json!({ "archive": archive, "added": added, "total": s.types.len() }))
}

pub fn assemble(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let line = super::schemas::arg_str_alias(args, &["line", "instruction"])?;
    let address = if arg_str_opt(args, "address").is_empty() {
        0
    } else {
        arg_addr(args, "address")?
    };
    let s = lock(state)?;
    let arch = arg_str_opt(args, "arch");
    let arch = if arch.is_empty() {
        s.binary
            .as_ref()
            .map(|b| b.arch.clone())
            .unwrap_or_else(|| "x86_64".into())
    } else {
        arch
    };
    let bytes = crate::asm::assemble(&arch, address, &line)?;
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(json!({
        "line": line,
        "arch": arch,
        "bytes": hex,
        "size": bytes.len(),
        "ok": true
    }))
}

pub fn assemble_snippet(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let snippet = arg_str(args, "snippet")?;
    let address = if arg_str_opt(args, "address").is_empty() {
        0
    } else {
        arg_addr(args, "address")?
    };
    let s = lock(state)?;
    let arch = arg_str_opt(args, "arch");
    let arch = if arch.is_empty() {
        s.binary
            .as_ref()
            .map(|b| b.arch.clone())
            .unwrap_or_else(|| "x86_64".into())
    } else {
        arch
    };
    let (bytes, errors) = crate::asm::assemble_snippet(&arch, address, &snippet)?;
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(json!({
        "arch": arch,
        "bytes": hex,
        "size": bytes.len(),
        "errors": errors,
        "ok": errors.is_empty()
    }))
}

pub fn patch_asm(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let address = arg_addr(args, "address")?;
    let line = super::schemas::arg_str_alias(args, &["line", "instruction"])?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);
    let mut s = lock(state)?;
    let arch = s
        .binary
        .as_ref()
        .map(|b| b.arch.clone())
        .ok_or("No binary loaded")?;
    let bytes = crate::asm::assemble(&arch, address, &line)?;
    let (id, original, off) = crate::mcp::tools::patch::apply_patch_internal(
        &mut s,
        address,
        &bytes,
        &format!("asm: {}", line),
        invalidate,
    )?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", address),
        "bytes": bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        "original": original.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        "ok": true
    }))
}

pub fn list_asm_mnemonics(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let _guard = lock(state)?;
    let m = crate::asm::supported_mnemonics();
    Ok(json!({ "count": m.len(), "mnemonics": m }))
}

fn same_file(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn unique_program_name(s: &AppState, base: &str) -> String {
    let cur = if s.binary.is_some() {
        Some(s.current_program_label())
    } else {
        None
    };
    let taken =
        |n: &str| s.program_slots.iter().any(|sl| sl.name == n) || cur.as_deref() == Some(n);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|i| format!("{} ({})", base, i))
        .find(|n| !taken(n))
        .unwrap_or_else(|| base.to_string())
}

pub fn open_program(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let name = arg_str_opt(args, "name");
    {
        let mut s = lock(state)?;
        if s.binary.is_some() && same_file(&s.file_path, &path) {
            let program = s.current_program_label();
            return Ok(json!({
                "program": program,
                "path": path,
                "open_programs": s.open_program_count(),
                "already_open": true,
                "ok": true
            }));
        }
        let parked = |st: &AppState| {
            st.program_slots.iter().position(|slot| {
                slot.data.binary.is_some() && same_file(&slot.data.file_path, &path)
            })
        };
        if parked(&s).is_some() {
            if s.binary.is_some() {
                let cur = s.current_program_label();
                let _ = crate::gui::save_program_slot(&mut s, cur);
            }
            if let Some(idx) = parked(&s) {
                let program = s.program_slots[idx].name.clone();
                crate::gui::restore_program_slot(&mut s, idx)?;
                return Ok(json!({
                    "program": program,
                    "path": path,
                    "open_programs": s.open_program_count(),
                    "already_open": true,
                    "switched": true,
                    "ok": true
                }));
            }
        }
    }
    let bin = crate::parser::parse_file(std::path::Path::new(&path))?;
    let disasm = crate::disasm::disassemble_binary(&bin)?;
    let base = if name.is_empty() {
        std::path::Path::new(&path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".into())
    } else {
        name
    };
    let mut s = lock(state)?;
    let n = unique_program_name(&s, &base);
    if s.binary.is_some() {
        let cur = s.current_program_label();
        let _ = crate::gui::save_program_slot(&mut s, cur);
    }
    crate::gui::reset_program_scoped_state(&mut s);
    s.current_program_name = n.clone();
    s.file_path = path.clone();
    s.binary = Some(bin);
    s.disasm = Some(disasm);
    s.analysis = None;
    s.analysis_version += 1;
    s.disasm_cache = None;
    let open_count = s.open_program_count();
    Ok(json!({ "program": n, "path": path, "open_programs": open_count, "ok": true }))
}

pub fn close_program(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let mut s = lock(state)?;
    let cur = s.current_program_label();
    if name == cur {
        s.program_slots.retain(|slot| slot.name != cur);
        if let Some(idx) = s.program_slots.len().checked_sub(1) {
            let slot_name = s.program_slots[idx].name.clone();
            s.program.binary = None;
            crate::gui::restore_program_slot(&mut s, idx)?;
            Ok(json!({
                "closed": name,
                "switched_to": slot_name,
                "open_programs": s.open_program_count(),
                "ok": true
            }))
        } else {
            s.binary = None;
            s.disasm = None;
            s.analysis = None;
            s.current_program_name.clear();
            s.file_path.clear();
            Ok(json!({ "closed": name, "ok": true }))
        }
    } else if let Some(i) = s.program_slots.iter().position(|slot| slot.name == name) {
        s.program_slots.remove(i);
        Ok(json!({ "closed": name, "ok": true }))
    } else {
        Err(format!("No open program named '{}'", name))
    }
}

pub fn list_open_programs_real(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let cur = s.current_program_label();
    let has_cur = s.binary.is_some();
    let mut programs: Vec<Value> = Vec::with_capacity(s.program_slots.len() + 1);
    if has_cur {
        programs.push(json!({
            "name": cur,
            "path": s.file_path,
            "has_binary": true,
            "analyzed": s.analysis.is_some(),
            "current": true,
        }));
    }
    for slot in &s.program_slots {
        if has_cur && (slot.name == cur || same_file(&slot.data.file_path, &s.file_path)) {
            continue;
        }
        if programs.iter().any(|p| p["name"] == slot.name.as_str()) {
            continue;
        }
        programs.push(json!({
            "name": slot.name,
            "path": slot.data.file_path,
            "has_binary": slot.data.binary.is_some(),
            "analyzed": slot.data.analysis.is_some(),
        }));
    }
    Ok(json!({ "count": programs.len(), "programs": programs }))
}

pub fn switch_program_real(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let name = arg_str(args, "name")?;
    let mut s = lock(state)?;
    let cur = s.current_program_label();
    if name == cur {
        return Ok(json!({ "switched": name, "already_current": true, "ok": true }));
    }
    let idx = s
        .program_slots
        .iter()
        .position(|slot| slot.name == name)
        .ok_or_else(|| format!("No open program named '{}'", name))?;
    if s.binary.is_some() {
        let _ = crate::gui::save_program_slot(&mut s, cur);
    }
    crate::gui::restore_program_slot(&mut s, idx)?;
    Ok(json!({ "switched": name, "ok": true }))
}
