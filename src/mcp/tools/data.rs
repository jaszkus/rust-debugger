use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::{arg_addr, arg_int, arg_str_opt, vaddr_to_offset};
use super::schemas::{arg_ranged, push_warning};
use crate::gui::AppState;
use crate::parser::ParsedBinary;

fn bytes_at(bin: &ParsedBinary, addr: u64, size: usize) -> Result<&[u8], String> {
    let off = vaddr_to_offset(bin, addr).ok_or("Address not in any section")?;
    if off >= bin.data.len() {
        return Err(format!(
            "Address {:#x} maps to offset {:#x} past end of file ({:#x})",
            addr,
            off,
            bin.data.len()
        ));
    }
    let end = off.saturating_add(size).min(bin.data.len());
    Ok(&bin.data[off..end])
}

pub fn get_bytes(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    const MAX_GET_BYTES: i64 = 4096;
    let addr = arg_addr(args, "address")?;
    let (size, size_requested) = arg_ranged(args, "size", 16, 1, MAX_GET_BYTES)?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let bytes = bytes_at(bin, addr, size)?;
    let mut out = json!({
        "address": format!("{:#x}", addr),
        "size": bytes.len(),
        "truncated": size_requested.is_some() || bytes.len() < size,
        "hex": bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        "ascii": bytes.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect::<String>()
    });
    if let Some(req) = size_requested {
        out["requested_size"] = json!(req);
        out["next_address"] = json!(format!("{:#x}", addr.saturating_add(bytes.len() as u64)));
        push_warning(&mut out, format!(
            "size {} exceeds the per-call maximum {}; returned {} bytes. Continue at next_address, or use dump_range to write a larger range to a file",
            req, MAX_GET_BYTES, bytes.len()
        ));
    } else if bytes.len() < size {
        push_warning(
            &mut out,
            format!(
                "only {} of {} requested bytes exist before the end of the file",
                bytes.len(),
                size
            ),
        );
    }
    Ok(out)
}

pub fn get_string(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let off = vaddr_to_offset(bin, addr).ok_or("Address not in any section")?;
    if off >= bin.data.len() {
        return Err(format!("Address {:#x} maps past end of file", addr));
    }

    let mut ascii = String::new();
    let mut i = off;
    while i < bin.data.len() && bin.data[i] != 0 {
        let b = bin.data[i];
        if (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r' {
            ascii.push(b as char);
        } else {
            break;
        }
        i += 1;
        if i - off > 4096 {
            break;
        }
    }

    let mut utf16 = String::new();
    let mut j = off;
    while j + 1 < bin.data.len() {
        let lo = bin.data[j];
        let hi = bin.data[j + 1];
        if lo == 0 && hi == 0 {
            break;
        }
        if hi == 0 && ((0x20..0x7f).contains(&lo) || lo == b'\t' || lo == b'\n' || lo == b'\r') {
            utf16.push(lo as char);
            j += 2;
        } else {
            break;
        }
        if j - off > 8192 {
            break;
        }
    }

    Ok(json!({
        "address": format!("{:#x}", addr),
        "ascii": ascii,
        "ascii_length": i - off,
        "utf16le": utf16,
        "utf16le_length": (j - off) / 2
    }))
}

pub fn get_int(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let ty = arg_str_opt(args, "type");
    let ty = if ty.is_empty() { "u32".to_string() } else { ty };

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let off = vaddr_to_offset(bin, addr).ok_or("Address not in any section")?;
    let data = &bin.data;

    fn read_le(data: &[u8], off: usize, size: usize) -> Option<u64> {
        if off + size > data.len() {
            return None;
        }
        let mut v: u64 = 0;
        for i in 0..size {
            v |= (data[off + i] as u64) << (i * 8);
        }
        Some(v)
    }

    let (raw, signed) = match ty.as_str() {
        "u8" => (read_le(data, off, 1).ok_or("OOB")?, false),
        "u16" => (read_le(data, off, 2).ok_or("OOB")?, false),
        "u32" => (read_le(data, off, 4).ok_or("OOB")?, false),
        "u64" => (read_le(data, off, 8).ok_or("OOB")?, false),
        "i8" => (read_le(data, off, 1).ok_or("OOB")?, true),
        "i16" => (read_le(data, off, 2).ok_or("OOB")?, true),
        "i32" => (read_le(data, off, 4).ok_or("OOB")?, true),
        "i64" => (read_le(data, off, 8).ok_or("OOB")?, true),
        _ => return Err(format!("Unknown type: {}", ty)),
    };

    let signed_val: i64 = if signed {
        match ty.as_str() {
            "i8" => raw as i8 as i64,
            "i16" => raw as i16 as i64,
            "i32" => raw as i32 as i64,
            "i64" => raw as i64,
            _ => raw as i64,
        }
    } else {
        raw as i64
    };

    let value = if signed {
        serde_json::Value::from(signed_val)
    } else {
        serde_json::Value::from(raw)
    };

    Ok(json!({
        "address": format!("{:#x}", addr),
        "type": ty,
        "value": value,
        "hex": format!("{:#x}", raw),
        "raw": raw
    }))
}

pub fn list_strings(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    const MAX_LIST_STRINGS: i64 = 5000;
    const PAGE_BUDGET_BYTES: usize = 400_000;
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let (limit, limit_requested) = arg_ranged(args, "limit", 100, 1, MAX_LIST_STRINGS)?;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let encoding = arg_str_opt(args, "encoding");
    let min_length = arg_int(args, "min_length", 8).max(1) as usize;
    let printable_ratio = {
        let r = args
            .get("printable_ratio")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.9);
        r.clamp(0.0, 1.0)
    };
    let dedup = args.get("dedup").and_then(|v| v.as_bool()).unwrap_or(false);
    let include_exec = args
        .get("include_exec")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let only_words = args
        .get("only_words")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let min_score = args
        .get("min_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(f64::MIN);

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let in_section = |va: u64| -> Option<&crate::parser::Section> {
        bin.sections
            .iter()
            .find(|sec| va >= sec.vaddr && va < sec.vaddr + sec.size)
    };
    fn ratio_ok(s: &str, min_ratio: f64) -> bool {
        if s.is_empty() {
            return false;
        }
        let printable = s.bytes().filter(|&b| (0x20..0x7f).contains(&b)).count();
        (printable as f64) / (s.len() as f64) >= min_ratio
    }

    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let filtered: Vec<&crate::parser::ExtractedString> = bin
        .strings
        .iter()
        .filter(|s| {
            if s.content.len() < min_length {
                return false;
            }
            if !ratio_ok(&s.content, printable_ratio) {
                return false;
            }
            if s.score < min_score {
                return false;
            }
            if only_words && !crate::parser::string_model::is_high_confidence(&s.content) {
                return false;
            }
            if !include_exec {
                match in_section(s.vaddr) {
                    Some(sec) if sec.is_executable => return false,
                    _ => {}
                }
            }
            if !filter.is_empty() && !s.content.to_lowercase().contains(&filter) {
                return false;
            }
            match encoding.as_str() {
                "ascii" => matches!(s.encoding, crate::parser::StringEncoding::Ascii),
                "utf16le" => matches!(s.encoding, crate::parser::StringEncoding::Utf16Le),
                "utf32le" | "utf32" => matches!(s.encoding, crate::parser::StringEncoding::Utf32Le),
                "pascal" => matches!(s.encoding, crate::parser::StringEncoding::Pascal),
                _ => true,
            }
        })
        .filter(|s| {
            if !dedup {
                return true;
            }
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            s.content.hash(&mut h);
            seen.insert(h.finish())
        })
        .collect();
    let total = filtered.len();

    let wanted = limit.min(total.saturating_sub(offset));
    let mut items: Vec<Value> = Vec::new();
    let mut spent = 0usize;
    for s in filtered.iter().skip(offset).take(limit) {
        let cost = s.content.len() + 160;
        if !items.is_empty() && spent + cost > PAGE_BUDGET_BYTES {
            break;
        }
        spent += cost;
        let enc = match s.encoding {
            crate::parser::StringEncoding::Ascii => "ascii",
            crate::parser::StringEncoding::Utf16Le => "utf16le",
            crate::parser::StringEncoding::Utf32Le => "utf32le",
            crate::parser::StringEncoding::Pascal => "pascal",
        };
        items.push(json!({
            "address": format!("{:#x}", s.vaddr),
            "encoding": enc,
            "length": s.content.len(),
            "score": s.score,
            "label": crate::parser::string_label(s.vaddr),
            "content": s.content
        }));
    }
    let next_offset = offset + items.len();
    let has_more = next_offset < total;

    let mut out = json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "returned": items.len(),
        "has_more": has_more,
        "items": items,
        "filters": {
            "min_length": min_length,
            "printable_ratio": printable_ratio,
            "dedup": dedup,
            "include_exec": include_exec,
        }
    });
    if has_more {
        out["next_offset"] = json!(next_offset);
    }
    if let Some(req) = limit_requested {
        push_warning(
            &mut out,
            format!(
                "limit {} exceeds the maximum {}; clamped to {}",
                req, MAX_LIST_STRINGS, limit
            ),
        );
    }
    if items.len() < wanted {
        push_warning(
            &mut out,
            format!(
                "page cut after {} items at the response-size budget; continue with offset={}",
                items.len(),
                next_offset
            ),
        );
    }
    Ok(out)
}

pub fn list_imports(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let filtered: Vec<&crate::parser::Import> = bin
        .imports
        .iter()
        .filter(|i| {
            filter.is_empty()
                || i.name.to_lowercase().contains(&filter)
                || i.library.to_lowercase().contains(&filter)
        })
        .collect();
    let total = filtered.len();

    let items: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|i| {
            json!({
                "address": format!("{:#x}", i.offset),
                "library": i.library,
                "name": i.name
            })
        })
        .collect();

    Ok(json!({ "total": total, "offset": offset, "limit": limit, "items": items }))
}

pub fn list_exports(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let filtered: Vec<&crate::parser::Export> = bin
        .exports
        .iter()
        .filter(|e| filter.is_empty() || e.name.to_lowercase().contains(&filter))
        .collect();
    let total = filtered.len();

    let items: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|e| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), Value::String(e.name.clone()));
            if e.ordinal != 0 {
                obj.insert("ordinal".into(), Value::from(e.ordinal));
            }
            if e.offset != 0 {
                obj.insert("address".into(), Value::String(format!("{:#x}", e.offset)));
            }
            if let Some(fw) = &e.forwarder {
                obj.insert("forwarder".into(), Value::String(fw.clone()));
            }
            Value::Object(obj)
        })
        .collect();

    Ok(json!({ "total": total, "offset": offset, "limit": limit, "items": items }))
}

pub fn list_symbols(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let filter = arg_str_opt(args, "filter").to_lowercase();
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let filtered: Vec<&crate::parser::Symbol> = bin
        .symbols
        .iter()
        .filter(|s| filter.is_empty() || s.name.to_lowercase().contains(&filter))
        .collect();
    let total = filtered.len();

    let items: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|s| {
            json!({
                "address": format!("{:#x}", s.addr),
                "name": s.name,
                "size": s.size,
                "is_function": s.is_function
            })
        })
        .collect();

    Ok(json!({ "total": total, "offset": offset, "limit": limit, "items": items }))
}

pub fn list_sections(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let items: Vec<Value> = bin
        .sections
        .iter()
        .map(|sec| {
            json!({
                "name": sec.name,
                "vaddr": format!("{:#x}", sec.vaddr),
                "size": sec.size,
                "file_offset": sec.offset,
                "executable": sec.is_executable,
                "readable": sec.readable,
                "writable": sec.writable,
                "initialized": sec.initialized,
                "permissions": sec.perms()
            })
        })
        .collect();
    Ok(json!({ "count": items.len(), "sections": items }))
}

pub fn list_relocations(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let offset = arg_int(args, "offset", 0).max(0) as usize;
    let limit = arg_int(args, "limit", 100).clamp(1, 1000) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let total = bin.relocations.len();
    let items: Vec<Value> = bin
        .relocations
        .iter()
        .skip(offset)
        .take(limit)
        .map(|r| {
            json!({
                "address": format!("{:#x}", r.va),
                "size": r.size,
                "type": r.rel_type,
                "symbol": r.symbol,
                "addend": r.addend,
                "artificial": r.is_artificial
            })
        })
        .collect();
    Ok(json!({ "total": total, "offset": offset, "limit": limit, "items": items }))
}
