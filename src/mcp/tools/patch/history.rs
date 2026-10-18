use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::*;
use crate::gui::{AppState, PatchRecord};

pub fn list_patches(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let items: Vec<Value> = s.patches.iter().map(record_to_json).collect();
    Ok(json!({
        "count": items.len(),
        "patches": items
    }))
}

pub fn get_patch_diff(_state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = _state.lock().map_err(|_| "lock poisoned".to_string())?;
    let mut items: Vec<&PatchRecord> = s.patches.iter().collect();
    items.sort_by_key(|p| p.offset);
    let result: Vec<Value> = items
        .into_iter()
        .map(|p| {
            json!({
                "offset": p.offset,
                "address": format!("{:#x}", p.vaddr),
                "size": p.new.len(),
                "before": hex(&p.original),
                "after": hex(&p.new),
                "description": p.description,
            })
        })
        .collect();
    Ok(json!({
        "total_changes": result.len(),
        "changes": result
    }))
}

pub fn undo_last_patch(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let p = s.patches.pop().ok_or("No patches to undo")?;
    {
        let bin = s.binary.as_mut().ok_or("No binary loaded")?;
        let end = p.offset + p.original.len();
        if end > bin.data.len() {
            return Err("Patch range past end of data (corrupt history?)".into());
        }
        Arc::make_mut(&mut bin.data)[p.offset..end].copy_from_slice(&p.original);
    }
    if let Some(bin) = s.binary.as_ref() {
        if let Ok(disasm) = crate::disasm::disassemble_binary(bin) {
            s.disasm = Some(disasm);
        }
    }
    crate::gui::drop_analysis(&mut s);
    s.status_msg = format!("Undid patch #{} at {:#x}", p.id, p.vaddr);
    Ok(json!({
        "undone": record_to_json(&p),
        "remaining": s.patches.len(),
        "ok": true
    }))
}

pub fn undo_patch_at(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;

    let idx_opt = s.patches.iter().enumerate().rev().find_map(|(i, p)| {
        if p.vaddr <= addr && addr < p.vaddr + p.new.len() as u64 {
            Some(i)
        } else {
            None
        }
    });
    let idx = idx_opt.ok_or_else(|| format!("No patch covers {:#x}", addr))?;
    let p = s.patches.remove(idx);
    {
        let bin = s.binary.as_mut().ok_or("No binary loaded")?;
        let end = p.offset + p.original.len();
        if end > bin.data.len() || p.offset >= end {
            return Err("Patch range past end of data (corrupt history?)".into());
        }
        Arc::make_mut(&mut bin.data)[p.offset..end].copy_from_slice(&p.original);
    }
    if let Some(bin) = s.binary.as_ref() {
        if let Ok(disasm) = crate::disasm::disassemble_binary(bin) {
            s.disasm = Some(disasm);
        }
    }
    crate::gui::drop_analysis(&mut s);
    s.status_msg = format!("Undid patch #{} at {:#x}", p.id, p.vaddr);
    Ok(json!({
        "undone": record_to_json(&p),
        "remaining": s.patches.len(),
        "ok": true
    }))
}

pub fn revert_all_patches(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let total = s.patches.len();
    if total == 0 {
        return Ok(json!({ "reverted": 0, "analysis_invalidated": false, "ok": true }));
    }
    while let Some(p) = s.patches.pop() {
        if let Some(bin) = s.binary.as_mut() {
            let end = p.offset + p.original.len();
            if end <= bin.data.len() {
                Arc::make_mut(&mut bin.data)[p.offset..end].copy_from_slice(&p.original);
            }
        }
    }
    if let Some(bin) = s.binary.as_ref() {
        if let Ok(disasm) = crate::disasm::disassemble_binary(bin) {
            s.disasm = Some(disasm);
        }
    }
    crate::gui::drop_analysis(&mut s);
    s.status_msg = format!("Reverted {} patches", total);
    Ok(json!({ "reverted": total, "ok": true }))
}

pub fn clear_patch_history(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let n = s.patches.len();
    s.patches.clear();
    Ok(json!({ "cleared": n, "ok": true,
        "note": "Patch tracking cleared. Existing modifications to binary.data remain." }))
}

pub fn export_patches(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let doc = json!({
        "format": "rust-debugger-patches/v1",
        "source_file": s.file_path,
        "binary_size": bin.data.len(),
        "binary_format": bin.format,
        "arch": bin.arch,
        "patches": s.patches.iter().map(|p| json!({
            "id": p.id,
            "offset": p.offset,
            "address": format!("{:#x}", p.vaddr),
            "original": hex(&p.original),
            "new": hex(&p.new),
            "description": p.description,
            "timestamp": p.timestamp,
        })).collect::<Vec<_>>()
    });
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap())
        .map_err(|e| format!("Write failed: {}", e))?;
    Ok(json!({
        "path": path,
        "patch_count": s.patches.len(),
        "ok": true
    }))
}

pub fn import_patches(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let verify_originals = arg_bool(args, "verify_originals", true);
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let raw = std::fs::read_to_string(&path).map_err(|e| format!("Read failed: {}", e))?;
    let doc: Value = serde_json::from_str(&raw).map_err(|e| format!("Parse failed: {}", e))?;
    let arr = doc
        .get("patches")
        .and_then(|v| v.as_array())
        .ok_or("File missing 'patches' array")?;

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let mut applied = 0usize;
    let mut skipped: Vec<Value> = Vec::new();

    for entry in arr {
        let off_raw = entry
            .get("offset")
            .and_then(|v| v.as_u64())
            .ok_or("missing offset")?;
        let off = usize::try_from(off_raw).map_err(|_| "offset too large")?;
        let new_hex = entry
            .get("new")
            .and_then(|v| v.as_str())
            .ok_or("missing new")?;
        let new_bytes = parse_hex_pattern(new_hex)?;
        if verify_originals {
            if let Some(orig_hex) = entry.get("original").and_then(|v| v.as_str()) {
                let original = parse_hex_pattern(orig_hex)?;
                let bin = s.binary.as_ref().ok_or("No binary loaded")?;
                let end = off
                    .checked_add(original.len())
                    .ok_or("Patch offset overflow")?;
                if end > bin.data.len() || &bin.data[off..end] != original.as_slice() {
                    skipped.push(json!({
                        "offset": off_raw,
                        "reason": "original bytes don't match"
                    }));
                    continue;
                }
            }
        }
        let desc = entry
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("imported")
            .to_string();
        apply_offset_patch(&mut s, off, &new_bytes, &desc)?;
        applied += 1;
    }

    if let Some(bin) = s.binary.as_ref() {
        if let Ok(disasm) = crate::disasm::disassemble_binary(bin) {
            s.disasm = Some(disasm);
        }
    }
    if invalidate {
        crate::gui::drop_analysis(&mut s);
    }
    s.status_msg = format!("Imported {} patches from {}", applied, path);

    Ok(json!({
        "path": path,
        "applied": applied,
        "skipped": skipped,
        "ok": true
    }))
}

pub fn diff_with_file(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let max_diffs = arg_int(args, "max_diffs", 1024).clamp(1, 1 << 20) as usize;

    let other = std::fs::read(&path).map_err(|e| format!("Read failed: {}", e))?;
    let (current, sections, patches_len) = {
        let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        (bin.data.clone(), bin.sections.clone(), s.patches.len())
    };

    let n = current.len().min(other.len());
    let mut diffs: Vec<Value> = Vec::new();
    let mut diff_bytes: usize = 0;

    let mut i = 0;
    while i < n {
        if current[i] != other[i] {
            let start = i;
            while i < n && current[i] != other[i] && (i - start) < 256 {
                i += 1;
            }
            diff_bytes += i - start;
            if diffs.len() < max_diffs {
                let vaddr = sections
                    .iter()
                    .find(|s| {
                        (start as u64) >= s.offset
                            && (start as u64) < s.offset.saturating_add(s.size)
                    })
                    .map(|s| s.vaddr + (start as u64 - s.offset))
                    .unwrap_or(start as u64);
                diffs.push(json!({
                    "offset": start,
                    "address": format!("{:#x}", vaddr),
                    "size": i - start,
                    "current": hex(&current[start..i]),
                    "other": hex(&other[start..i]),
                }));
            }
        } else {
            i += 1;
        }
    }
    let size_diff = current.len() as i64 - other.len() as i64;

    Ok(json!({
        "current_size": current.len(),
        "other_size": other.len(),
        "size_difference": size_diff,
        "byte_differences": diff_bytes,
        "diffs": diffs,
        "diffs_truncated": diffs.len() == max_diffs && diff_bytes > diffs.iter().filter_map(|d| d.get("size").and_then(|s| s.as_u64())).sum::<u64>() as usize,
        "patches_applied": patches_len,
    }))
}

pub fn save_patched_binary(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let path = arg_str(args, "path")?;
    let (data, patches_len) = {
        let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
        let bin = s.binary.as_ref().ok_or("No binary loaded")?;
        (bin.data.clone(), s.patches.len())
    };
    std::fs::write(&path, &data[..]).map_err(|e| format!("Write failed: {}", e))?;
    Ok(json!({
        "path": path,
        "size": data.len(),
        "patches_applied": patches_len,
        "ok": true
    }))
}
