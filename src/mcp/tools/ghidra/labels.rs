use serde_json::{json, Value};

use std::sync::{Arc, Mutex};

use crate::gui::{AnnotationChange, AppState, CommentKind, SourceType};

use super::common::*;
use crate::mcp::tools::parse_addr;

fn label_snapshot(s: &AppState, addr: u64) -> Option<(String, SourceType)> {
    s.user_labels.get(&addr).map(|name| {
        (
            name.clone(),
            s.label_sources
                .get(&addr)
                .copied()
                .unwrap_or(SourceType::User),
        )
    })
}

pub fn get_function_labels(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
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
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;

    let mut rows: Vec<(u64, &str, &str)> = Vec::new();
    for (laddr, name) in &s.user_labels {
        if *laddr >= f.entry && *laddr < f.end {
            rows.push((*laddr, name.as_str(), "user"));
        }
    }
    for sym in &bin.symbols {
        if sym.addr >= f.entry && sym.addr < f.end {
            rows.push((sym.addr, &*sym.name, "symbol"));
        }
    }
    rows.sort_by_key(|&(a, _, src)| (a, src != "user"));
    let labels: Vec<Value> = rows
        .into_iter()
        .map(|(a, name, src)| json!({ "address": addr_str(a), "name": name, "source": src }))
        .collect();
    Ok(json!({ "function": addr_str(f.entry), "labels": labels }))
}

pub fn create_label(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let name = arg_str(args, "name")?.trim().to_string();
    if name.is_empty() {
        return Err("Label name must not be empty".to_string());
    }
    let mut s = lock(state)?;
    let old = label_snapshot(&s, addr);
    s.set_label(addr, name.clone(), SourceType::User);
    s.annotation_undo.push(AnnotationChange::Label {
        addr,
        old,
        new: Some((name.clone(), SourceType::User)),
    });
    Ok(json!({ "ok": true, "address": addr_str(addr), "name": name, "source": "user" }))
}

pub fn delete_label(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let addr = arg_addr(args, "address")?;
    let old = label_snapshot(&s, addr);
    let removed = s.remove_label(addr);
    if removed {
        s.annotation_undo.push(AnnotationChange::Label {
            addr,
            old,
            new: None,
        });
    }
    Ok(json!({ "ok": true, "removed": removed, "address": addr_str(addr) }))
}

pub fn list_labels(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let mut sorted: Vec<(u64, &String)> = s.user_labels.iter().map(|(a, n)| (*a, n)).collect();
    sorted.sort_unstable_by_key(|&(a, _)| a);
    let rows: Vec<Value> = sorted
        .into_iter()
        .map(|(a, n)| {
            json!({
                "address": addr_str(a),
                "name": n,
                "source": s.label_sources.get(&a).copied().unwrap_or(SourceType::User).as_str(),
            })
        })
        .collect();
    Ok(json!({ "count": rows.len(), "labels": rows }))
}

pub fn tag_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let tag = arg_str(args, "tag")?.trim().to_string();
    if tag.is_empty() {
        return Err("Tag must not be empty".to_string());
    }
    let mut s = lock(state)?;
    let entry = s.function_tags.entry(addr).or_default();
    let added = !entry.contains(&tag);
    if added {
        entry.push(tag.clone());
        s.annotation_undo.push(AnnotationChange::Tag {
            addr,
            tag: tag.clone(),
            added: true,
        });
    }
    Ok(json!({ "ok": true, "address": addr_str(addr), "tag": tag, "added": added }))
}

pub fn untag_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let addr = arg_addr(args, "address")?;
    let tag = arg_str(args, "tag")?;
    let mut removed = false;
    let mut now_empty = false;
    if let Some(entry) = s.function_tags.get_mut(&addr) {
        let before = entry.len();
        entry.retain(|t| t != &tag);
        removed = entry.len() != before;
        now_empty = entry.is_empty();
    }
    if removed {
        if now_empty {
            s.function_tags.remove(&addr);
        }
        s.annotation_undo.push(AnnotationChange::Tag {
            addr,
            tag: tag.clone(),
            added: false,
        });
    }
    Ok(json!({ "ok": true, "address": addr_str(addr), "tag": tag, "removed": removed }))
}

pub fn list_function_tags(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    if args.get("address").is_some_and(|v| !v.is_null()) {
        let addr = arg_addr(args, "address")?;
        let tags = s.function_tags.get(&addr).cloned().unwrap_or_default();
        return Ok(json!({ "address": addr_str(addr), "tags": tags }));
    }
    let mut sorted: Vec<(u64, &Vec<String>)> =
        s.function_tags.iter().map(|(a, t)| (*a, t)).collect();
    sorted.sort_unstable_by_key(|&(a, _)| a);
    let rows: Vec<Value> = sorted
        .into_iter()
        .map(|(a, tags)| json!({ "address": addr_str(a), "tags": tags }))
        .collect();
    Ok(json!({ "count": rows.len(), "tagged": rows }))
}

pub fn label_strings(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = lock(state)?;
    let (targets, skipped): (Vec<u64>, usize) = {
        let bin = s.binary.as_ref().ok_or_else(no_binary)?;
        let mut targets = Vec::with_capacity(bin.strings.len());
        let mut skipped = 0usize;
        for st in &bin.strings {
            if s.user_labels.contains_key(&st.vaddr) {
                skipped += 1;
            } else {
                targets.push(st.vaddr);
            }
        }
        (targets, skipped)
    };
    let mut batch: Vec<AnnotationChange> = Vec::with_capacity(targets.len());
    for vaddr in targets {
        if s.user_labels.contains_key(&vaddr) {
            continue;
        }
        let name = crate::parser::string_label(vaddr);
        s.set_label(vaddr, name.clone(), SourceType::Analysis);
        batch.push(AnnotationChange::Label {
            addr: vaddr,
            old: None,
            new: Some((name, SourceType::Analysis)),
        });
    }
    let labeled = batch.len();
    if !batch.is_empty() {
        s.annotation_undo.push(AnnotationChange::Batch(batch));
    }
    Ok(json!({ "labeled": labeled, "skipped_existing": skipped }))
}

pub fn batch_set_comments(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let list = args
        .get("comments")
        .and_then(|v| v.as_array())
        .ok_or("Missing required argument: comments (array of {address, kind, text})")?;
    let mut s = lock(state)?;
    let mut batch: Vec<AnnotationChange> = Vec::with_capacity(list.len());
    let mut skipped: Vec<Value> = Vec::new();
    for (index, item) in list.iter().enumerate() {
        let raw = item.get("address").and_then(|v| v.as_str()).unwrap_or("");
        let Some(addr) = parse_addr(raw) else {
            skipped.push(json!({ "index": index, "reason": "invalid or missing address" }));
            continue;
        };
        let Some(text) = item.get("text").and_then(|v| v.as_str()) else {
            skipped.push(json!({ "index": index, "reason": "missing text" }));
            continue;
        };
        let kind = CommentKind::parse(item.get("kind").and_then(|v| v.as_str()).unwrap_or("eol"));
        let new = (!text.is_empty()).then(|| text.to_string());
        let old = s.get_comment_kind(addr, kind).cloned();
        s.set_comment_kind(addr, kind, new.clone());
        batch.push(AnnotationChange::Comment {
            addr,
            kind,
            old,
            new,
        });
    }
    let applied = batch.len();
    if !batch.is_empty() {
        s.annotation_undo.push(AnnotationChange::Batch(batch));
    }
    Ok(json!({ "ok": true, "applied": applied, "skipped": skipped }))
}
