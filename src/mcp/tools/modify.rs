use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::{arg_addr, arg_str, arg_str_opt};
use crate::gui::{AnnotationChange, AppState, Bookmark, BookmarkKind, CommentKind};

pub fn set_comment(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let text = arg_str(args, "text")?;
    let kind = CommentKind::parse(&arg_str_opt(args, "kind"));
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let old = s.get_comment_kind(addr, kind).cloned();
    s.set_comment_kind(addr, kind, Some(text.clone()));
    s.annotation_undo.push(AnnotationChange::Comment {
        addr,
        kind,
        old,
        new: Some(text.clone()),
    });
    Ok(
        json!({ "address": format!("{:#x}", addr), "kind": kind.as_str(), "text": text, "ok": true }),
    )
}

pub fn delete_comment(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let kind = CommentKind::parse(&arg_str_opt(args, "kind"));
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let old = s.get_comment_kind(addr, kind).cloned();
    s.set_comment_kind(addr, kind, None);
    let removed = old.is_some();
    if removed {
        s.annotation_undo.push(AnnotationChange::Comment {
            addr,
            kind,
            old,
            new: None,
        });
    }
    Ok(json!({ "address": format!("{:#x}", addr), "kind": kind.as_str(), "removed": removed }))
}

pub fn list_comments(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let mut items: Vec<Value> = s
        .comments_ex
        .iter()
        .map(|((addr, kind), text)| {
            json!({
                "address": format!("{:#x}", addr),
                "kind": kind.as_str(),
                "text": text
            })
        })
        .collect();
    items.sort_by(|a, b| {
        let ka = a
            .get("address")
            .and_then(|x| x.as_str())
            .and_then(super::parse_addr)
            .unwrap_or(u64::MAX);
        let kb = b
            .get("address")
            .and_then(|x| x.as_str())
            .and_then(super::parse_addr)
            .unwrap_or(u64::MAX);
        ka.cmp(&kb).then(
            a.get("kind")
                .and_then(|x| x.as_str())
                .cmp(&b.get("kind").and_then(|x| x.as_str())),
        )
    });
    Ok(json!({ "count": items.len(), "comments": items }))
}

pub fn set_bookmark(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let note = arg_str_opt(args, "note");
    let kind = BookmarkKind::parse(&arg_str_opt(args, "kind"));
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let note = if note.is_empty() {
        format!("BM {:#x}", addr)
    } else {
        note
    };
    let old = s.bookmarks.iter().find(|b| b.addr == addr).cloned();
    s.bookmarks.retain(|b| b.addr != addr);
    let bm = Bookmark {
        addr,
        note: note.clone(),
        kind,
    };
    s.bookmarks.push(bm.clone());
    s.annotation_undo.push(AnnotationChange::Bookmark {
        addr,
        old,
        new: Some(bm),
    });
    Ok(
        json!({ "address": format!("{:#x}", addr), "note": note, "kind": kind.as_str(), "ok": true }),
    )
}

pub fn list_bookmarks(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let items: Vec<Value> = s
        .bookmarks
        .iter()
        .map(|b| {
            json!({
                "address": format!("{:#x}", b.addr),
                "note": b.note,
                "kind": b.kind.as_str()
            })
        })
        .collect();
    Ok(json!({ "count": items.len(), "bookmarks": items }))
}

pub fn delete_bookmark(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let old = s.bookmarks.iter().find(|b| b.addr == addr).cloned();
    let before = s.bookmarks.len();
    s.bookmarks.retain(|b| b.addr != addr);
    let removed = s.bookmarks.len() != before;
    if removed {
        s.annotation_undo.push(AnnotationChange::Bookmark {
            addr,
            old,
            new: None,
        });
    }
    Ok(json!({ "address": format!("{:#x}", addr), "removed": removed }))
}

pub fn rename_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let name = arg_str(args, "name")?;
    if name.is_empty() {
        return Err("Empty name".to_string());
    }
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let old = s.user_func_names.get(&addr).cloned();
    match &mut s.analysis {
        Some(a) => {
            let a = std::sync::Arc::make_mut(a);
            if !a.functions.iter().any(|f| f.entry == addr) {
                return Err(format!("Function not found at {:#x}", addr));
            }
            if let Some(f) = a.functions.iter_mut().find(|f| f.entry == addr) {
                f.name = name.clone();
            }
        }
        None => return Err("No analysis loaded - run the run_analysis tool first".to_string()),
    }
    s.user_func_names.insert(addr, name.clone());
    s.annotation_undo.push(AnnotationChange::Rename {
        addr,
        old,
        new: Some(name.clone()),
    });
    Ok(json!({ "address": format!("{:#x}", addr), "name": name, "ok": true }))
}

pub fn undo_annotation(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    match s.undo_annotation() {
        Some(desc) => Ok(json!({ "ok": true, "undone": desc,
            "undo_depth": s.annotation_undo.undo_len(), "redo_depth": s.annotation_undo.redo_len() })),
        None => Ok(json!({ "ok": false, "undone": null, "note": "nothing to undo" })),
    }
}

pub fn redo_annotation(state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    match s.redo_annotation() {
        Some(desc) => Ok(json!({ "ok": true, "redone": desc,
            "undo_depth": s.annotation_undo.undo_len(), "redo_depth": s.annotation_undo.redo_len() })),
        None => Ok(json!({ "ok": false, "redone": null, "note": "nothing to redo" })),
    }
}
