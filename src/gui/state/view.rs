use super::*;
use crate::debugger::DebugState;

pub type SigSortedCache = (u64, u64, Vec<(u64, String, String, usize)>);
pub type DecompCache = (
    u64,
    u64,
    Vec<(String, crate::analysis::LineKind, Option<u64>)>,
);

pub struct AppState {
    pub program: ProgramData,
    pub debug_state: DebugState,
    pub hex_offset: usize,
    pub hex_bytes_per_row: usize,
    pub selected_section: usize,
    pub disasm_scroll: usize,
    pub search_buf: String,
    pub goto_addr_buf: String,
    pub show_import_dialog: bool,
    pub status_msg: String,
    pub import_base_addr_buf: String,
    pub import_arch_idx: usize,
    pub selected_func: Option<u64>,
    pub func_filter: String,
    pub func_sort: usize,
    pub cfg_zoom: f32,
    pub cfg_pan: [f32; 2],
    pub cfg_selected_block: Option<usize>,
    pub cfg_view_func: Option<u64>,
    pub show_search: bool,
    pub search_query: String,
    pub search_kind: usize,
    pub search_results: Vec<SearchResult>,
    pub show_rename: bool,
    pub rename_target: u64,
    pub rename_buf: String,
    pub show_comment: bool,
    pub comment_target: u64,
    pub comment_buf: String,
    pub history: Vec<u64>,
    pub history_idx: usize,
    pub navigating: bool,
    pub show_add_bookmark: bool,
    pub add_bookmark_target: u64,
    pub add_bookmark_buf: String,
    pub scroll_request: Option<usize>,
    pub analysis_progress: Option<std::sync::Arc<std::sync::Mutex<AnalysisProgress>>>,
    pub mcp_shared_state: Option<std::sync::Arc<std::sync::Mutex<AppState>>>,
    pub mcp_server: Option<crate::mcp::McpServer>,
    pub mcp_port: u16,
    pub allow_changes: bool,
    pub allow_execution: bool,
    pub mcp_call_log: std::collections::VecDeque<crate::mcp::tools::activity::McpCallEvent>,
    pub mcp_call_seq: u64,
    pub mcp_started_ms: Option<u64>,
    pub mcp_last_call_ms: Option<u64>,
    pub ai_cursor: Option<(u64, u64)>,
    pub ai_plan: Vec<(String, bool)>,
    pub mcp_port_buf: String,
    pub mcp_request_analysis: bool,
    pub analysis_seq: u64,
    pub analysis_error: Option<String>,
    pub fid_db: crate::analysis::function_id::FunctionIDMatcher,
    pub fid_epoch: u64,
    pub exit_requested: bool,
    pub pending_bp_arm: Option<(u64, u64)>,
    pub asm_overrun_armed: Option<u64>,
    pub db_pending_fp: u64,
    pub db_save_rx: Option<std::sync::mpsc::Receiver<bool>>,
    pub comment_kind: CommentKind,
    pub add_bookmark_kind: BookmarkKind,
    pub tag_buf: String,
    pub selected_insn: Option<u64>,
    pub program_slots: Vec<ProgramSlot>,
    pub show_asm_dialog: bool,
    pub asm_target: u64,
    pub asm_buf: String,
    pub asm_arch: String,
    pub show_type_dialog: bool,
    pub type_dialog_kind: usize,
    pub type_dialog_buf: String,
    pub search_last_query: String,
    pub search_dirty: bool,
    pub pending_load: Option<std::sync::Arc<std::sync::Mutex<LoadProgress>>>,
    pub analysis_version: u64,
    pub binary_generation: u64,
    pub disasm_cache: Option<DisasmCache>,
    pub strings_cache: (u64, String, Vec<usize>),
    pub funcs_cache: (u64, String, usize, Vec<usize>),
    pub recent_projects: Vec<String>,
    pub show_startup: bool,
    pub new_project_mode: bool,
    pub new_project_buf: String,
    pub pending_project_name: Option<String>,
    pub search_last_run: Option<std::time::Instant>,
    pub db_saved_fp: u64,
    pub db_last_save_attempt: Option<std::time::Instant>,
    pub db_fp_modif: u64,
    pub db_fp_value: u64,
    pub db_fp_checked: Option<std::time::Instant>,
    pub bp_addr_set: std::collections::HashSet<u64>,
    pub bp_set_len: usize,
    pub comments_sorted_cache: (u64, Vec<(u64, CommentKind, String)>),
    pub tags_sorted_cache: (u64, Vec<(u64, Vec<String>)>),
    pub sig_sorted_cache: SigSortedCache,
    pub decomp_cache: DecompCache,
    pub cfg_layout_cache: (u64, u64, Vec<[f32; 2]>, Vec<f32>, f32, f32),
    #[allow(dead_code)]
    pub types_user_cache: (usize, Vec<(u32, String)>),
}

#[derive(Default)]
pub struct DisasmCache {
    pub func_lookup: std::collections::HashMap<u64, String>,
    pub xref_to_func: std::collections::HashMap<u64, usize>,
    pub string_at: std::collections::HashMap<u64, String>,
    pub string_ranges: Vec<(u64, u64)>,
    pub sorted_func_entries: Vec<u64>,
    pub sorted_xref_addrs: Vec<u64>,
}

pub(crate) fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub(crate) fn try_lock_recover<T>(m: &std::sync::Mutex<T>) -> Option<std::sync::MutexGuard<'_, T>> {
    match m.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

pub(crate) enum SaveState {
    #[allow(dead_code)]
    Idle { saved_fp: u64 },
    Saving {
        #[allow(dead_code)]
        saved_fp: u64,
        pending_fp: u64,
    },
}

pub(crate) fn save_state_of(state: &AppState) -> SaveState {
    if state.db_save_rx.is_some() {
        SaveState::Saving {
            saved_fp: state.db_saved_fp,
            pending_fp: state.db_pending_fp,
        }
    } else {
        SaveState::Idle {
            saved_fp: state.db_saved_fp,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct Layout {
    pub menu_h: f32,
    pub toolbar_h: f32,
    pub status_h: f32,
    pub top: f32,
    pub work_h: f32,
    pub right_w: f32,
    pub left_w: f32,
    pub bottom_h: f32,
    pub top_h: f32,
}

impl Layout {
    #[allow(dead_code)]
    pub(crate) fn compute(dw: f32, dh: f32, frame_h: f32) -> Self {
        let menu_h = frame_h;
        let toolbar_h = 30.0;
        let status_h = 20.0;
        let top = menu_h + toolbar_h;
        let work_h = (dh - top - status_h).max(100.0);
        let right_w = (dw * 0.20).clamp(260.0, 360.0);
        let left_w = dw - right_w;
        let bottom_h = (work_h * 0.33).max(150.0);
        let top_h = work_h - bottom_h;
        Self {
            menu_h,
            toolbar_h,
            status_h,
            top,
            work_h,
            right_w,
            left_w,
            bottom_h,
            top_h,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ProgressSnapshot {
    pub phase: String,
    pub current: usize,
    pub total: usize,
    pub elapsed: f32,
    pub cancelling: bool,
    pub arc: std::sync::Arc<std::sync::Mutex<AnalysisProgress>>,
}

#[allow(dead_code)]
pub(crate) fn snapshot_progress(state: &AppState) -> Option<ProgressSnapshot> {
    let arc = state.analysis_progress.clone()?;
    let g = try_lock_recover(&arc)?;
    if g.done {
        return None;
    }
    Some(ProgressSnapshot {
        phase: g.phase.clone(),
        current: g.current,
        total: g.total,
        elapsed: g
            .started_at
            .map(|t| t.elapsed().as_secs_f32())
            .unwrap_or(0.0),
        cancelling: g.cancel,
        arc: arc.clone(),
    })
}

#[allow(dead_code)]
pub const BUILTIN_COUNT: u32 = 16;

impl AppState {
    pub fn new() -> Self {
        Self {
            program: ProgramData::default(),
            debug_state: DebugState::new(),
            decomp_cache: (u64::MAX, u64::MAX, Vec::new()),
            cfg_layout_cache: (u64::MAX, u64::MAX, Vec::new(), Vec::new(), 0.0, 0.0),
            types_user_cache: (0, Vec::new()),
            hex_offset: 0,
            hex_bytes_per_row: 16,
            selected_section: 0,
            disasm_scroll: 0,
            search_buf: String::new(),
            goto_addr_buf: String::new(),
            show_import_dialog: false,
            status_msg: "Ready".to_string(),
            import_base_addr_buf: "0".to_string(),
            import_arch_idx: 0,
            selected_func: None,
            func_filter: String::new(),
            func_sort: 0,
            cfg_zoom: 1.0,
            cfg_pan: [0.0, 0.0],
            cfg_selected_block: None,
            cfg_view_func: None,
            show_search: false,
            search_query: String::new(),
            search_kind: 0,
            search_results: Vec::new(),
            show_rename: false,
            rename_target: 0,
            rename_buf: String::new(),
            show_comment: false,
            comment_target: 0,
            comment_buf: String::new(),
            history: Vec::new(),
            history_idx: 0,
            navigating: false,
            show_add_bookmark: false,
            add_bookmark_target: 0,
            add_bookmark_buf: String::new(),
            scroll_request: None,
            analysis_progress: None,
            mcp_shared_state: None,
            mcp_server: None,
            mcp_port: 8765,
            allow_changes: true,
            allow_execution: false,
            mcp_call_log: std::collections::VecDeque::new(),
            mcp_call_seq: 0,
            mcp_started_ms: None,
            mcp_last_call_ms: None,
            ai_cursor: None,
            ai_plan: Vec::new(),
            mcp_port_buf: "8765".to_string(),
            mcp_request_analysis: false,
            analysis_seq: 0,
            analysis_error: None,
            fid_db: crate::analysis::function_id::FunctionIDMatcher::new(),
            fid_epoch: 0,
            selected_insn: None,
            program_slots: Vec::new(),
            show_asm_dialog: false,
            asm_target: 0,
            asm_buf: String::new(),
            asm_arch: "x86_64".to_string(),
            show_type_dialog: false,
            type_dialog_kind: 0,
            type_dialog_buf: String::new(),
            search_last_query: String::new(),
            search_dirty: false,
            pending_load: None,
            analysis_version: 0,
            binary_generation: 0,
            disasm_cache: None,
            strings_cache: (u64::MAX, String::new(), Vec::new()),
            funcs_cache: (u64::MAX, String::new(), 0, Vec::new()),
            recent_projects: load_recents(),
            show_startup: true,
            new_project_mode: false,
            new_project_buf: String::new(),
            pending_project_name: None,
            search_last_run: None,
            db_saved_fp: 0,
            db_last_save_attempt: None,
            db_fp_modif: u64::MAX,
            db_fp_value: 0,
            db_fp_checked: None,
            bp_addr_set: std::collections::HashSet::new(),
            bp_set_len: usize::MAX,
            comments_sorted_cache: (u64::MAX, Vec::new()),
            tags_sorted_cache: (u64::MAX, Vec::new()),
            sig_sorted_cache: (u64::MAX, u64::MAX, Vec::new()),
            exit_requested: false,
            pending_bp_arm: None,
            asm_overrun_armed: None,
            db_pending_fp: 0,
            db_save_rx: None,
            comment_kind: CommentKind::Eol,
            add_bookmark_kind: BookmarkKind::Note,
            tag_buf: String::new(),
        }
    }

    pub fn apply_mcp_port_buf(&mut self) -> Result<u16, String> {
        let t = self.mcp_port_buf.trim();
        let p: u32 = t.parse().map_err(|_| format!("Bad MCP port '{}'", t))?;
        if !(1..=65535).contains(&p) {
            return Err(format!("MCP port {} out of range 1..=65535", p));
        }
        self.mcp_port = p as u16;
        Ok(self.mcp_port)
    }

    pub fn current_program_label(&self) -> String {
        if self.program.current_program_name.is_empty() {
            std::path::Path::new(&self.program.file_path)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "unnamed".into())
        } else {
            self.program.current_program_name.clone()
        }
    }

    pub fn open_program_count(&self) -> usize {
        let has_cur = self.program.binary.is_some();
        let cur = self.current_program_label();
        let parked = self
            .program_slots
            .iter()
            .filter(|s| !(has_cur && s.name == cur))
            .count();
        parked + usize::from(has_cur)
    }

    #[allow(dead_code)]
    pub fn bp_set(&mut self) -> &std::collections::HashSet<u64> {
        self.refresh_bp_set_if_needed();
        &self.bp_addr_set
    }

    pub fn refresh_bp_set_if_needed(&mut self) {
        let n = self.debug_state.breakpoints.len();
        if n != self.bp_set_len || self.bp_addr_set.len() != n {
            self.refresh_bp_set();
        }
    }

    pub fn refresh_bp_set(&mut self) {
        self.bp_addr_set.clear();
        self.bp_addr_set
            .extend(self.debug_state.breakpoints.iter().map(|b| b.address));
        self.bp_set_len = self.debug_state.breakpoints.len();
    }

    pub fn rebuild_disasm_cache(&mut self) {
        crate::gui::state::rebuild_disasm_cache(self);
    }

    pub fn attach_mcp_shared(&mut self, shared: std::sync::Arc<std::sync::Mutex<AppState>>) {
        if self.mcp_shared_state.is_none() {
            self.mcp_shared_state = Some(shared);
        }
    }

    pub fn fid_shared(&self) -> std::sync::Arc<crate::analysis::function_id::FunctionIDMatcher> {
        std::sync::Arc::new(self.fid_db.clone())
    }

    pub fn fid_clear(&mut self) {
        self.fid_db = crate::analysis::function_id::FunctionIDMatcher::new();
        self.fid_epoch = self.fid_epoch.wrapping_add(1);
    }

    #[allow(dead_code)]
    pub fn fid_touch(&mut self) {
        self.fid_epoch = self.fid_epoch.wrapping_add(1);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for AppState {
    type Target = ProgramData;
    fn deref(&self) -> &ProgramData {
        &self.program
    }
}

impl std::ops::DerefMut for AppState {
    fn deref_mut(&mut self) -> &mut ProgramData {
        &mut self.program
    }
}
