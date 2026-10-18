use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::arg_int;
use crate::gui::AppState;

pub fn search_functions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let q = super::arg_query(args)?.to_lowercase();
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let analysis = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;

    let hex_q = super::schemas::hex_needle(&q);

    let items: Vec<Value> = analysis
        .functions
        .iter()
        .filter(|f| {
            f.name.to_lowercase().contains(&q)
                || hex_q
                    .as_deref()
                    .is_some_and(|h| format!("{:x}", f.entry).contains(h))
        })
        .take(limit)
        .map(|f| {
            json!({
                "address": format!("{:#x}", f.entry),
                "name": f.name,
                "size": f.end - f.entry,
            })
        })
        .collect();

    let mut out = json!({ "query": q, "count": items.len(), "items": items });
    if items.is_empty() {
        let total = analysis.functions.len();
        let named = analysis
            .functions
            .iter()
            .filter(|f| !f.name.starts_with("sub_"))
            .count();
        out["total_functions"] = json!(total);
        out["named_functions"] = json!(named);
        if named == 0 {
            out["note"] = json!("All functions are auto-named sub_<hex address>, so only address queries can match. Locate code by behaviour with search_strings, find_users_of_import or search_in_decompiled.");
        }
    }
    Ok(out)
}

pub fn search_strings(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let q = super::arg_query(args)?;
    let qlow = q.to_lowercase();
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let items: Vec<Value> = bin
        .strings
        .iter()
        .filter(|s| s.content.to_lowercase().contains(&qlow))
        .take(limit)
        .map(|s| {
            let enc = match s.encoding {
                crate::parser::StringEncoding::Ascii => "ascii",
                crate::parser::StringEncoding::Utf16Le => "utf16le",
                crate::parser::StringEncoding::Utf32Le => "utf32le",
                crate::parser::StringEncoding::Pascal => "pascal",
            };
            json!({
                "address": format!("{:#x}", s.vaddr),
                "encoding": enc,
                "content": s.content
            })
        })
        .collect();

    Ok(json!({ "query": q, "count": items.len(), "items": items }))
}

pub fn search_bytes(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let q = super::arg_query(args)?;
    let limit = arg_int(args, "limit", 100).max(1) as usize;
    let offset = arg_int(args, "offset", 0).max(0) as usize;

    let pat = parse_pattern(&q)?;

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;

    let anchor = match pat.iter().position(|p| p.is_some()) {
        Some(i) => i,
        None => {
            return Err(
                "Pattern must contain at least one concrete byte (only wildcards given)".into(),
            )
        }
    };
    let anchor_byte = pat[anchor].unwrap();

    let data = &bin.data;
    let mut items = Vec::new();
    let mut seen = 0usize;
    let mut has_more = false;
    if pat.len() <= data.len() {
        let mut search_from = 0usize;
        'outer: while let Some(rel) = memchr::memchr(anchor_byte, &data[search_from..]) {
            let anchor_pos = search_from + rel;
            search_from = anchor_pos + 1;
            if anchor_pos < anchor {
                continue;
            }
            let start = anchor_pos - anchor;
            if start + pat.len() > data.len() {
                break;
            }
            for (i, p) in pat.iter().enumerate() {
                if let Some(b) = p
                    && data[start + i] != *b {
                        continue 'outer;
                    }
            }
            seen += 1;
            if seen <= offset {
                continue;
            }
            if items.len() >= limit {
                has_more = true;
                break;
            }
            let mut vaddr = start as u64;
            for sec in &bin.sections {
                if (start as u64) >= sec.offset && (start as u64) < sec.offset + sec.size {
                    vaddr = sec.vaddr + (start as u64 - sec.offset);
                    break;
                }
            }
            items.push(json!({
                "file_offset": start,
                "address": format!("{:#x}", vaddr)
            }));
        }
    }

    let mut out = json!({
        "query": q,
        "pattern_length": pat.len(),
        "count": items.len(),
        "offset": offset,
        "has_more": has_more,
        "matches": items
    });
    if has_more {
        out["next_offset"] = json!(offset + items.len());
    }
    Ok(out)
}

pub fn parse_pattern(q: &str) -> Result<Vec<Option<u8>>, String> {
    let chars: Vec<char> = q.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.is_empty() {
        return Err("Empty pattern".into());
    }
    let mut pat = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i].to_ascii_lowercase();
        if c == '?' {
            if i + 1 < chars.len() && chars[i + 1] == '?' {
                pat.push(None);
                i += 2;
            } else {
                pat.push(None);
                i += 1;
            }
        } else if c.is_ascii_hexdigit() {
            let hi = c.to_digit(16).unwrap() as u8;
            if i + 1 >= chars.len() {
                return Err(format!(
                    "Dangling hex digit '{}' at end of pattern (pairs only)",
                    c
                ));
            }
            let n = chars[i + 1].to_ascii_lowercase();
            if n == '?' {
                return Err(
                    "Nibble masks ('8?') are not supported; use '??' for whole-byte wildcards"
                        .into(),
                );
            }
            if !n.is_ascii_hexdigit() {
                return Err(format!("Invalid character '{}' in pattern", chars[i + 1]));
            }
            pat.push(Some((hi << 4) | n.to_digit(16).unwrap() as u8));
            i += 2;
        } else {
            return Err(format!("Invalid character '{}' in pattern", chars[i]));
        }
    }
    Ok(pat)
}

#[cfg(test)]
mod tests {
    use super::parse_pattern;

    #[test]
    fn wildcard_patterns_parse() {
        let p = parse_pattern("80 3D ?? ?? ?? ?? 74 16").unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p[0], Some(0x80));
        assert_eq!(p[1], Some(0x3D));
        assert!(p[2..6].iter().all(|b| b.is_none()));
        assert_eq!(p[6], Some(0x74));
        assert_eq!(p[7], Some(0x16));

        let p2 = parse_pattern("803D????74").unwrap();
        assert_eq!(p2, vec![Some(0x80), Some(0x3D), None, None, Some(0x74)]);

        assert_eq!(parse_pattern("48 89 E5").unwrap().len(), 3);
        assert_eq!(parse_pattern("4889e5").unwrap().len(), 3);

        assert!(parse_pattern("8? 90").is_err());
        assert!(parse_pattern("zz 90").is_err());
    }
}
