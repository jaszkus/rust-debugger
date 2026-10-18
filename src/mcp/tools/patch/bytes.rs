use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::*;
use crate::gui::AppState;
use crate::mcp::tools::schemas::arg_str_alias;

pub fn patch_bytes(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let bytes_str = arg_str_alias(args, &["bytes", "hex"])?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);
    let description = {
        let d = arg_str_opt(args, "description");
        if d.is_empty() {
            "patch_bytes".into()
        } else {
            d
        }
    };
    let needle = parse_hex_pattern(&bytes_str)?;

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) =
        apply_patch_internal(&mut s, addr, &needle, &description, invalidate)?;

    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": needle.len(),
        "original_bytes": hex(&original),
        "new_bytes": hex(&needle),
        "ok": true
    }))
}

pub fn nop_range(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let size = arg_int(args, "size", 1).clamp(1, 65536) as usize;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let nops = vec![0x90u8; size];
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) = apply_patch_internal(&mut s, addr, &nops, "nop_range", invalidate)?;

    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": size,
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn fill_bytes(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let size = arg_int(args, "size", 1).clamp(1, 1 << 24) as usize;
    let value = arg_int(args, "value", 0).clamp(0, 0xff) as u8;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let buf = vec![value; size];
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) = apply_patch_internal(
        &mut s,
        addr,
        &buf,
        &format!("fill_bytes(0x{:02x})", value),
        invalidate,
    )?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": size,
        "value": format!("0x{:02x}", value),
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn fill_pattern(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let size = arg_int(args, "size", 1).clamp(1, 1 << 24) as usize;
    let pattern = parse_hex_pattern(&arg_str(args, "pattern")?)?;
    if pattern.is_empty() {
        return Err("Empty pattern".into());
    }
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let take = (size - buf.len()).min(pattern.len());
        buf.extend_from_slice(&pattern[..take]);
    }

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) = apply_patch_internal(&mut s, addr, &buf, "fill_pattern", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": size,
        "pattern": hex(&pattern),
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn patch_string(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let text = arg_str(args, "text")?;
    let null_terminate = arg_bool(args, "null_terminate", true);
    let invalidate = arg_bool(args, "invalidate_analysis", false);

    let mut buf = text.as_bytes().to_vec();
    if null_terminate {
        buf.push(0);
    }
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) = apply_patch_internal(&mut s, addr, &buf, "patch_string", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": buf.len(),
        "text": text,
        "null_terminated": null_terminate,
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn patch_wide_string(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let text = arg_str(args, "text")?;
    let null_terminate = arg_bool(args, "null_terminate", true);
    let invalidate = arg_bool(args, "invalidate_analysis", false);

    let mut buf: Vec<u8> = Vec::with_capacity(text.len() * 2 + 2);
    for cu in text.encode_utf16() {
        buf.extend_from_slice(&cu.to_le_bytes());
    }
    if null_terminate {
        buf.extend_from_slice(&[0, 0]);
    }
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) =
        apply_patch_internal(&mut s, addr, &buf, "patch_wide_string", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": buf.len(),
        "text": text,
        "null_terminated": null_terminate,
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn patch_int(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let ty = {
        let t = arg_str_opt(args, "type");
        if t.is_empty() {
            "u32".into()
        } else {
            t
        }
    };
    let big_endian = arg_bool(args, "big_endian", false);
    let invalidate = arg_bool(args, "invalidate_analysis", false);

    let value_raw = args
        .get("value")
        .ok_or("Missing required argument: value")?;
    let value_i: i128 = if let Some(s) = value_raw.as_str() {
        let t = s.trim();
        if let Some(stripped) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            i128::from_str_radix(stripped, 16).map_err(|e| e.to_string())?
        } else if let Some(stripped) = t.strip_prefix("-0x").or_else(|| t.strip_prefix("-0X")) {
            -(i128::from_str_radix(stripped, 16).map_err(|e| e.to_string())?)
        } else {
            t.parse::<i128>().map_err(|e| e.to_string())?
        }
    } else if let Some(n) = value_raw.as_i64() {
        n as i128
    } else if let Some(n) = value_raw.as_u64() {
        n as i128
    } else {
        return Err("'value' must be number or string".into());
    };

    let buf: Vec<u8> = match ty.as_str() {
        "u8" | "i8" => {
            let v = value_i as i64;
            if !(-128..=255).contains(&v) {
                return Err(format!("Value {} out of range for {}", v, ty));
            }
            vec![(v as u32 & 0xff) as u8]
        }
        "u16" | "i16" => {
            let v = value_i as i64;
            if !(-32768..=65535).contains(&v) {
                return Err(format!("Value {} out of range for {}", v, ty));
            }
            let bytes = (v as u16).to_le_bytes();
            if big_endian {
                bytes.iter().rev().cloned().collect()
            } else {
                bytes.to_vec()
            }
        }
        "u32" | "i32" => {
            let v = value_i as i64;
            if !((-1i64 << 31)..=((1u64 << 32) as i64 - 1)).contains(&v) {
                return Err(format!("Value {} out of range for {}", v, ty));
            }
            let bytes = (v as u32).to_le_bytes();
            if big_endian {
                bytes.iter().rev().cloned().collect()
            } else {
                bytes.to_vec()
            }
        }
        "u64" | "i64" => {
            let v = value_i;
            if v < i64::MIN as i128 || v > u64::MAX as i128 {
                return Err(format!("Value {} out of range for {}", v, ty));
            }
            let bytes = (v as u64).to_le_bytes();
            if big_endian {
                bytes.iter().rev().cloned().collect()
            } else {
                bytes.to_vec()
            }
        }
        other => return Err(format!("Unsupported type: {}", other)),
    };

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) = apply_patch_internal(
        &mut s,
        addr,
        &buf,
        &format!("patch_int({})", ty),
        invalidate,
    )?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "type": ty,
        "big_endian": big_endian,
        "size": buf.len(),
        "new_bytes": hex(&buf),
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn copy_bytes(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let src = arg_addr(args, "src_address")?;
    let dst = arg_addr(args, "dst_address")?;
    let size = arg_int(args, "size", 1).clamp(1, 1 << 24) as usize;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let payload = read_bytes_at(&s, src, size)?;
    let (id, original, off) = apply_patch_internal(
        &mut s,
        dst,
        &payload,
        &format!("copy_bytes(from {:#x})", src),
        invalidate,
    )?;
    Ok(json!({
        "patch_id": id,
        "src": format!("{:#x}", src),
        "dst": format!("{:#x}", dst),
        "offset": off,
        "size": size,
        "original_bytes": hex(&original),
        "new_bytes": hex(&payload),
        "ok": true
    }))
}

pub fn search_and_replace_bytes(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let find = parse_hex_pattern(&arg_str(args, "find")?)?;
    let replace = parse_hex_pattern(&arg_str(args, "replace")?)?;
    let max_replacements = arg_int(args, "max_replacements", 0).clamp(0, 65536);
    let section_filter = arg_str_opt(args, "section");
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    if find.is_empty() {
        return Err("'find' is empty".into());
    }
    if find.len() != replace.len() {
        return Err(format!(
            "find ({} bytes) and replace ({} bytes) must be the same length",
            find.len(),
            replace.len()
        ));
    }

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let mut ranges: Vec<(usize, u64, usize)> = Vec::new();
    for sec in &bin.sections {
        if !section_filter.is_empty() && sec.name != section_filter {
            continue;
        }
        let so = sec.offset as usize;
        let se = (so + sec.size as usize).min(bin.data.len());
        if se > so {
            ranges.push((so, sec.vaddr, se - so));
        }
    }

    let mut matches: Vec<(usize, u64)> = Vec::new();
    for (off, vaddr, len) in ranges {
        if len < find.len() {
            continue;
        }
        let slice = &bin.data[off..off + len];
        let mut i = 0;
        while i + find.len() <= slice.len() {
            if &slice[i..i + find.len()] == find.as_slice() {
                matches.push((off + i, vaddr + i as u64));
                i += find.len();
            } else {
                i += 1;
            }
        }
    }

    if max_replacements > 0 {
        matches.truncate(max_replacements as usize);
    }

    let mut applied: Vec<Value> = Vec::new();
    for (_off, vaddr) in matches.iter().cloned() {
        let (id, original, off) = apply_patch_internal_impl(
            &mut s,
            vaddr,
            &replace,
            "search_and_replace_bytes",
            false,
            false,
        )?;
        applied.push(json!({
            "patch_id": id,
            "offset": off,
            "address": format!("{:#x}", vaddr),
            "original_bytes": hex(&original),
        }));
    }
    if let Some(bin) = s.binary.as_ref() {
        if let Ok(disasm) = crate::disasm::disassemble_binary(bin) {
            s.disasm = Some(disasm);
        }
    }
    if invalidate {
        crate::gui::drop_analysis(&mut s);
    }
    s.status_msg = format!(
        "search_and_replace_bytes: {} patches applied",
        applied.len()
    );

    Ok(json!({
        "find": hex(&find),
        "replace": hex(&replace),
        "matches_found": applied.len(),
        "patches": applied,
        "ok": true
    }))
}
