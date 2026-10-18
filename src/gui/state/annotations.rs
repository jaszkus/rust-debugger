use super::*;
use crate::analysis::AnalysisResult;
use crate::disasm::DisasmResult;

#[derive(Debug, Clone, Default)]
pub struct ProgramData {
    pub binary: Option<crate::parser::ParsedBinary>,
    pub disasm: Option<DisasmResult>,
    pub analysis: Option<std::sync::Arc<AnalysisResult>>,
    pub file_path: String,
    pub comments: rustc_hash::FxHashMap<u64, String>,
    pub comments_ex: rustc_hash::FxHashMap<(u64, CommentKind), String>,
    pub user_func_names: rustc_hash::FxHashMap<u64, String>,
    pub bookmarks: Vec<Bookmark>,
    pub patches: Vec<PatchRecord>,
    pub patch_seq: u64,
    pub user_labels: rustc_hash::FxHashMap<u64, String>,
    pub label_sources: rustc_hash::FxHashMap<u64, SourceType>,
    pub function_tags: rustc_hash::FxHashMap<u64, Vec<String>>,
    pub annotation_undo: AnnotationUndo,
    pub user_xrefs: Vec<UserXRef>,
    pub types: crate::type_system::DataTypeManager,
    pub data_types_at: rustc_hash::FxHashMap<u64, crate::type_system::TypeId>,
    pub current_program_name: String,
    pub modification_number: u64,
    pub dirty: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ProgramEvent {
    Comment(u64),
    Rename(u64),
    Label(u64),
    Bookmark(u64),
    Tag(u64),
    Patch(u64),
    Type,
    Xref,
    AnalysisReplaced,
    Batch(usize),
}

impl ProgramData {
    pub fn transact<T>(
        &mut self,
        event: ProgramEvent,
        f: impl FnOnce(&mut Self) -> T,
    ) -> (T, ProgramEvent) {
        let out = f(self);
        self.modification_number = self.modification_number.wrapping_add(1);
        self.dirty = true;
        (out, event)
    }

    pub fn is_changed(&self) -> bool {
        self.dirty
    }

    pub fn mark_saved(&mut self) {
        self.dirty = false;
    }

    #[allow(dead_code)]
    fn set_analysis_raw(&mut self, a: AnalysisResult) {
        self.analysis = Some(std::sync::Arc::new(a));
    }

    #[allow(dead_code)]
    pub fn set_analysis(&mut self, a: AnalysisResult) {
        let (_, _) = self.transact(ProgramEvent::AnalysisReplaced, |s| {
            s.set_analysis_raw(a);
        });
    }

    #[allow(dead_code)]
    fn clear_analysis_raw(&mut self) {
        self.analysis = None;
    }

    #[allow(dead_code)]
    pub fn clear_analysis(&mut self) {
        let (_, _) = self.transact(ProgramEvent::AnalysisReplaced, |s| {
            s.clear_analysis_raw();
        });
    }

    fn set_comment_kind_raw(&mut self, addr: u64, kind: CommentKind, text: Option<String>) {
        match text {
            Some(t) => {
                self.comments_ex.insert((addr, kind), t.clone());
                if kind == CommentKind::Eol {
                    self.comments.insert(addr, t);
                }
            }
            None => {
                self.comments_ex.remove(&(addr, kind));
                if kind == CommentKind::Eol {
                    self.comments.remove(&addr);
                }
            }
        }
    }

    pub fn set_comment_kind(&mut self, addr: u64, kind: CommentKind, text: Option<String>) {
        let ev = ProgramEvent::Comment(addr);
        let (_, _) = self.transact(ev, |s| {
            s.set_comment_kind_raw(addr, kind, text);
        });
    }

    pub fn get_comment_kind(&self, addr: u64, kind: CommentKind) -> Option<&String> {
        self.comments_ex.get(&(addr, kind))
    }

    fn set_label_raw(&mut self, addr: u64, name: String, source: SourceType) {
        self.user_labels.insert(addr, name);
        self.label_sources.insert(addr, source);
    }

    pub fn set_label(&mut self, addr: u64, name: String, source: SourceType) {
        let (_, _) = self.transact(ProgramEvent::Label(addr), |s| {
            s.set_label_raw(addr, name, source);
        });
    }

    fn remove_label_raw(&mut self, addr: u64) -> bool {
        self.label_sources.remove(&addr);
        self.user_labels.remove(&addr).is_some()
    }

    pub fn remove_label(&mut self, addr: u64) -> bool {
        if !self.user_labels.contains_key(&addr) && !self.label_sources.contains_key(&addr) {
            return false;
        }
        let (out, _) = self.transact(ProgramEvent::Label(addr), |s| s.remove_label_raw(addr));
        out
    }

    fn set_rename_raw(&mut self, addr: u64, name: Option<String>) {
        match name {
            Some(n) => {
                self.user_func_names.insert(addr, n.clone());
            }
            None => {
                self.user_func_names.remove(&addr);
            }
        }
    }

    pub fn set_rename(&mut self, addr: u64, name: Option<String>) {
        let (_, _) = self.transact(ProgramEvent::Rename(addr), |s| {
            s.set_rename_raw(addr, name.clone());
            s.sync_analysis_rename_raw(addr, name.as_deref());
        });
    }

    fn sync_analysis_rename_raw(&mut self, addr: u64, name: Option<&str>) {
        if let Some(a) = self.analysis.as_mut() {
            if let Some(a) = std::sync::Arc::get_mut(a) {
                if let Some(f) = a.functions.iter_mut().find(|f| f.entry == addr) {
                    if let Some(n) = name {
                        f.name = n.to_string();
                    }
                }
            }
        }
    }

    pub(crate) fn apply_change_raw(&mut self, change: &AnnotationChange, forward: bool) {
        match change {
            AnnotationChange::Batch(items) => {
                if forward {
                    for c in items {
                        self.apply_change_raw(c, true);
                    }
                } else {
                    for c in items.iter().rev() {
                        self.apply_change_raw(c, false);
                    }
                }
            }
            AnnotationChange::Comment {
                addr,
                kind,
                old,
                new,
            } => {
                let v = if forward { new } else { old };
                self.set_comment_kind_raw(*addr, *kind, v.clone());
            }
            AnnotationChange::Bookmark { addr, old, new } => {
                let v = if forward { new } else { old };
                self.bookmarks.retain(|b| b.addr != *addr);
                if let Some(b) = v {
                    self.bookmarks.push(b.clone());
                }
            }
            AnnotationChange::Label { addr, old, new } => {
                let v = if forward { new } else { old };
                match v {
                    Some((name, src)) => self.set_label_raw(*addr, name.clone(), *src),
                    None => {
                        self.remove_label_raw(*addr);
                    }
                }
            }
            AnnotationChange::Rename { addr, old, new } => {
                let v = if forward { new } else { old };
                match v {
                    Some(n) => {
                        self.set_rename_raw(*addr, Some(n.clone()));
                        self.sync_analysis_rename_raw(*addr, Some(n));
                    }
                    None => {
                        self.set_rename_raw(*addr, None);
                    }
                }
            }
            AnnotationChange::Tag { addr, tag, added } => {
                let want_present = if forward { *added } else { !*added };
                let entry = self.function_tags.entry(*addr).or_default();
                if want_present {
                    if !entry.contains(tag) {
                        entry.push(tag.clone());
                    }
                } else {
                    entry.retain(|t| t != tag);
                }
                if entry.is_empty() {
                    self.function_tags.remove(addr);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn apply_change(&mut self, change: &AnnotationChange, forward: bool) {
        let ev = match change {
            AnnotationChange::Comment { addr, .. } => ProgramEvent::Comment(*addr),
            AnnotationChange::Bookmark { addr, .. } => ProgramEvent::Bookmark(*addr),
            AnnotationChange::Label { addr, .. } => ProgramEvent::Label(*addr),
            AnnotationChange::Rename { addr, .. } => ProgramEvent::Rename(*addr),
            AnnotationChange::Tag { addr, .. } => ProgramEvent::Tag(*addr),
            AnnotationChange::Batch(items) => ProgramEvent::Batch(items.len()),
        };
        let (_, _) = self.transact(ev, |s| {
            s.apply_change_raw(change, forward);
        });
    }

    fn undo_event(change: &AnnotationChange) -> ProgramEvent {
        match change {
            AnnotationChange::Comment { addr, .. } => ProgramEvent::Comment(*addr),
            AnnotationChange::Bookmark { addr, .. } => ProgramEvent::Bookmark(*addr),
            AnnotationChange::Label { addr, .. } => ProgramEvent::Label(*addr),
            AnnotationChange::Rename { addr, .. } => ProgramEvent::Rename(*addr),
            AnnotationChange::Tag { addr, .. } => ProgramEvent::Tag(*addr),
            AnnotationChange::Batch(items) => ProgramEvent::Batch(items.len()),
        }
    }

    pub fn undo_annotation(&mut self) -> Option<String> {
        let change = self.annotation_undo.pop_undo()?;
        let desc = change.describe();
        let ev = Self::undo_event(&change);
        let (_, _) = self.transact(ev, |s| {
            s.apply_change_raw(&change, false);
            s.annotation_undo.push_redo(change);
        });
        Some(desc)
    }

    pub fn redo_annotation(&mut self) -> Option<String> {
        let change = self.annotation_undo.pop_redo()?;
        let desc = change.describe();
        let ev = Self::undo_event(&change);
        let (_, _) = self.transact(ev, |s| {
            s.apply_change_raw(&change, true);
            s.annotation_undo.push_undo_raw(change);
        });
        Some(desc)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentKind {
    Eol,
    Pre,
    Post,
    Plate,
    Repeatable,
}

impl CommentKind {
    pub fn label(self) -> &'static str {
        match self {
            CommentKind::Eol => "eol",
            CommentKind::Pre => "pre",
            CommentKind::Post => "post",
            CommentKind::Plate => "plate",
            CommentKind::Repeatable => "repeatable",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "pre" => CommentKind::Pre,
            "post" => CommentKind::Post,
            "plate" => CommentKind::Plate,
            "repeatable" | "repeat" => CommentKind::Repeatable,
            _ => CommentKind::Eol,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            CommentKind::Eol => "eol",
            CommentKind::Pre => "pre",
            CommentKind::Post => "post",
            CommentKind::Plate => "plate",
            CommentKind::Repeatable => "repeatable",
        }
    }
    pub fn tag(self) -> u8 {
        match self {
            CommentKind::Eol => 0,
            CommentKind::Pre => 1,
            CommentKind::Post => 2,
            CommentKind::Plate => 3,
            CommentKind::Repeatable => 4,
        }
    }
    pub fn from_tag(t: u8) -> Self {
        match t {
            1 => CommentKind::Pre,
            2 => CommentKind::Post,
            3 => CommentKind::Plate,
            4 => CommentKind::Repeatable,
            _ => CommentKind::Eol,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Analysis,
    User,
    Default,
    Imported,
    Ai,
}

impl SourceType {
    pub fn tag(self) -> u8 {
        match self {
            SourceType::Analysis => 0,
            SourceType::User => 1,
            SourceType::Default => 2,
            SourceType::Imported => 3,
            SourceType::Ai => 4,
        }
    }
    pub fn from_tag(t: u8) -> Self {
        match t {
            0 => SourceType::Analysis,
            2 => SourceType::Default,
            3 => SourceType::Imported,
            4 => SourceType::Ai,
            _ => SourceType::User,
        }
    }
    pub fn from_tag_v2(t: u8) -> Self {
        match t {
            1 => SourceType::Imported,
            2 => SourceType::Analysis,
            3 => SourceType::Default,
            _ => SourceType::User,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            SourceType::User => "user",
            SourceType::Imported => "imported",
            SourceType::Analysis => "analysis",
            SourceType::Default => "default",
            SourceType::Ai => "ai",
        }
    }
}

#[derive(Debug, Clone)]
pub enum AnnotationChange {
    Comment {
        addr: u64,
        kind: CommentKind,
        old: Option<String>,
        new: Option<String>,
    },
    Bookmark {
        addr: u64,
        old: Option<Bookmark>,
        new: Option<Bookmark>,
    },
    Label {
        addr: u64,
        old: Option<(String, SourceType)>,
        new: Option<(String, SourceType)>,
    },
    Rename {
        addr: u64,
        old: Option<String>,
        new: Option<String>,
    },
    Tag {
        addr: u64,
        tag: String,
        added: bool,
    },
    Batch(Vec<AnnotationChange>),
}

impl AnnotationChange {
    pub fn describe(&self) -> String {
        match self {
            AnnotationChange::Comment { addr, kind, .. } => {
                format!("comment({}) at {:#x}", kind.as_str(), addr)
            }
            AnnotationChange::Bookmark { addr, .. } => format!("bookmark at {:#x}", addr),
            AnnotationChange::Label { addr, .. } => format!("label at {:#x}", addr),
            AnnotationChange::Rename { addr, .. } => format!("rename at {:#x}", addr),
            AnnotationChange::Tag { addr, tag, added } => {
                format!(
                    "tag '{}' {} at {:#x}",
                    tag,
                    if *added { "add" } else { "remove" },
                    addr
                )
            }
            AnnotationChange::Batch(items) => format!("batch of {} edits", items.len()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AnnotationUndo {
    undo: Vec<AnnotationChange>,
    redo: Vec<AnnotationChange>,
}

impl AnnotationUndo {
    const CAP: usize = 512;
    pub fn push(&mut self, change: AnnotationChange) {
        if let Some(last) = self.undo.last_mut() {
            let coalesced = match (last, &change) {
                (
                    AnnotationChange::Comment {
                        addr: a1,
                        kind: k1,
                        new: n1,
                        ..
                    },
                    AnnotationChange::Comment {
                        addr: a2,
                        kind: k2,
                        new: n2,
                        ..
                    },
                ) if a1 == a2 && k1 == k2 => {
                    *n1 = n2.clone();
                    true
                }
                (
                    AnnotationChange::Label {
                        addr: a1, new: n1, ..
                    },
                    AnnotationChange::Label {
                        addr: a2, new: n2, ..
                    },
                ) if a1 == a2 => {
                    *n1 = n2.clone();
                    true
                }
                (
                    AnnotationChange::Rename {
                        addr: a1, new: n1, ..
                    },
                    AnnotationChange::Rename {
                        addr: a2, new: n2, ..
                    },
                ) if a1 == a2 => {
                    *n1 = n2.clone();
                    true
                }
                _ => false,
            };
            if coalesced {
                self.redo.clear();
                return;
            }
        }
        self.undo.push(change);
        if self.undo.len() > Self::CAP {
            self.undo.remove(0);
        }
        self.redo.clear();
    }
    pub fn pop_undo(&mut self) -> Option<AnnotationChange> {
        self.undo.pop()
    }
    pub fn pop_redo(&mut self) -> Option<AnnotationChange> {
        self.redo.pop()
    }
    pub fn push_redo(&mut self, change: AnnotationChange) {
        self.redo.push(change);
    }
    pub fn push_undo_raw(&mut self, change: AnnotationChange) {
        self.undo.push(change);
        if self.undo.len() > Self::CAP {
            self.undo.remove(0);
        }
    }
    pub fn undo_len(&self) -> usize {
        self.undo.len()
    }
    pub fn redo_len(&self) -> usize {
        self.redo.len()
    }
}

#[derive(Debug, Clone)]
pub struct PatchRecord {
    pub id: u64,
    pub offset: usize,
    pub vaddr: u64,
    pub original: Vec<u8>,
    pub new: Vec<u8>,
    pub description: String,
    pub timestamp: u64,
}
