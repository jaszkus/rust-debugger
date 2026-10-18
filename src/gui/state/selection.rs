use super::*;

#[derive(Debug, Clone)]
pub struct ProgramSlot {
    pub name: String,
    pub data: ProgramData,
}

pub fn save_program_slot(state: &mut AppState, name: String) -> usize {
    let slot = ProgramSlot {
        name: name.clone(),
        data: state.program.clone(),
    };
    if let Some(i) = state.program_slots.iter().position(|s| s.name == name) {
        state.program_slots[i] = slot;
        i
    } else {
        state.program_slots.push(slot);
        state.program_slots.len() - 1
    }
}

pub fn restore_program_slot(state: &mut AppState, idx: usize) -> Result<(), String> {
    if idx >= state.program_slots.len() {
        return Err("No such program slot".into());
    }
    let cur_name = state.current_program_label();
    if state.program.binary.is_some() && !state.program_slots.iter().any(|s| s.name == cur_name) {
        let _ = save_program_slot(state, cur_name);
    }
    let slot = state.program_slots[idx].clone();
    state.program = slot.data;
    state.binary_generation = state.binary_generation.wrapping_add(1);
    state.program.current_program_name = slot.name.clone();
    crate::gui::state::invalidate_analysis_caches(state);
    state.scroll_request = None;
    state.selected_func = None;
    state.selected_insn = None;
    state.pending_load = None;
    state.analysis_progress = None;
    state.mcp_request_analysis = false;
    state.pending_bp_arm = None;
    state.db_save_rx = None;
    state.db_pending_fp = 0;
    state.db_saved_fp = 0;
    state.db_last_save_attempt = None;
    state.history.clear();
    state.history_idx = 0;
    state.hex_offset = 0;
    state.search_results.clear();
    state.status_msg = format!("Switched to program '{}'", slot.name);
    Ok(())
}

#[derive(Debug, Clone)]
pub struct UserXRef {
    pub from: u64,
    pub to: u64,
    pub note: String,
    pub kind: String,
    pub op_index: i32,
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub addr: u64,
    pub label: String,
    pub kind: SearchKind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SearchKind {
    String,
    Function,
    Symbol,
    Import,
    Hex,
}

#[derive(Debug, Clone)]
pub struct Bookmark {
    pub addr: u64,
    pub note: String,
    pub kind: BookmarkKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkKind {
    Note,
    Info,
    Error,
    Analysis,
}

impl BookmarkKind {
    pub fn label(self) -> &'static str {
        match self {
            BookmarkKind::Note => "note",
            BookmarkKind::Info => "info",
            BookmarkKind::Error => "error",
            BookmarkKind::Analysis => "analysis",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => BookmarkKind::Info,
            "error" => BookmarkKind::Error,
            "analysis" => BookmarkKind::Analysis,
            _ => BookmarkKind::Note,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            BookmarkKind::Note => "note",
            BookmarkKind::Info => "info",
            BookmarkKind::Error => "error",
            BookmarkKind::Analysis => "analysis",
        }
    }
}
