use std::sync::{Arc, Mutex};

use iced::Size;

use super::super::state::*;
use super::super::theme;
use super::super::{actions, views};
use super::input::*;
use super::message::*;
use super::{subscription, theme as app_theme, title, update};

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct UiSettings {
    pub(crate) theme: usize,
    pub(crate) compact: bool,
    pub(crate) collapsed: bool,
    pub(crate) side_ratio: f32,
    pub(crate) bottom_ratio: f32,
    pub(crate) bottom_tab: usize,
    pub(crate) side_tab: usize,
    #[serde(default)]
    pub(crate) show_recent_startup: bool,
    #[serde(default)]
    pub(crate) restore_last: bool,
    #[serde(default = "default_true")]
    pub(crate) confirm_close: bool,
    #[serde(default = "default_true")]
    pub(crate) analyze_on_open: bool,
    #[serde(default = "default_true")]
    pub(crate) recover_strings: bool,
    #[serde(default = "default_max_func_kb")]
    pub(crate) max_func_size_kb: u32,
    #[serde(default = "default_true")]
    pub(crate) allow_changes: bool,
    #[serde(default)]
    pub(crate) allow_execution: bool,
    #[serde(default = "default_ui_scale")]
    pub(crate) ui_scale: f32,
}
fn default_true() -> bool {
    true
}
fn default_ui_scale() -> f32 {
    1.0
}
pub(crate) fn default_max_func_kb() -> u32 {
    64
}
pub(crate) fn settings_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("RD_SETTINGS_PATH") {
        return path.into();
    }
    if cfg!(test) {
        return std::env::temp_dir()
            .join(format!("rd-ui-tests-{}", std::process::id()))
            .join("settings.json");
    }
    let root = std::env::var_os("APPDATA")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(std::path::PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".config")))
        .unwrap_or_else(std::env::temp_dir);
    root.join("rust-debugger").join("ui-settings.json")
}

pub(crate) type CfgInsnsCache = std::cell::RefCell<Option<(u64, u64, Arc<Vec<Vec<String>>>)>>;
pub(crate) type FunctionNamesCache =
    std::cell::RefCell<Option<(u64, Arc<std::collections::HashMap<u64, String>>)>>;
pub(crate) type AnnotationMaps = (
    Arc<std::collections::HashSet<u64>>,
    Arc<rustc_hash::FxHashMap<u64, String>>,
    Arc<rustc_hash::FxHashMap<u64, String>>,
);
pub(crate) type ViewAnnotations = std::cell::RefCell<AnnotationMaps>;

pub struct Shell {
    pub now: std::time::Instant,
    pub started: std::time::Instant,
    pub anims: super::super::anim::Anims,
    pub toasts: views::toast::Toasts,
    pub last_status: String,
    pub last_analysis_error: Option<String>,
    pub auto_analyzed: Option<u64>,
    pub feed_open: std::collections::HashSet<u64>,
    pub feed_seen: std::collections::HashMap<u64, (std::time::Instant, usize)>,
    pub startup_raw: bool,
    pub recent_removals: Vec<(String, usize, std::time::Instant)>,
    pub modal_dismiss: Option<(std::time::Instant, Box<Shell>)>,
    pub app: Arc<Mutex<AppState>>,
    pub view_state: std::cell::RefCell<AppState>,
    pub view_key: Option<(u64, u64, u64)>,
    pub table_cache: views::bottom::ViewCache,
    pub(crate) listing_maps: std::cell::RefCell<Option<(u64, views::listing::SharedMaps)>>,
    pub(crate) listing_rows: std::rc::Rc<views::listing::RowCache>,
    pub cfg_insns: CfgInsnsCache,
    pub function_names: FunctionNamesCache,
    pub view_annotations: ViewAnnotations,
    pub snap_binary: Option<Arc<crate::parser::ParsedBinary>>,
    pub search_epoch: u64,
    pub search_pending: bool,
    pub search_rows: Arc<Vec<SearchResult>>,
    pub search_first: usize,
    pub fonts: theme::Fonts,

    pub side_w: f32,
    pub bottom_h: f32,
    pub side_ratio: f32,
    pub bottom_ratio: f32,
    pub win_size: Size,

    pub bottom_tab: usize,
    pub side_tab: usize,
    pub bottom_scroll: usize,
    pub hex_scroll: Option<usize>,
    pub side_scroll: usize,
    pub listing_first: usize,
    pub funcs_first: usize,

    pub rename: Option<(u64, String)>,
    pub comment: Option<(u64, CommentKind, String)>,
    pub bookmark: Option<(u64, BookmarkKind, String)>,
    pub show_import: bool,
    pub import_path: String,
    pub comment_editor: iced::widget::text_editor::Content,
    pub show_search: bool,
    pub show_startup: bool,
    pub show_type_dialog: bool,
    pub type_kind: usize,
    pub type_name: String,
    pub closing: bool,
    pub system_dark: Option<bool>,

    pub decomp_lines: DecompileLines,
    pub decomp_key: Option<DecompileKey>,
    pub decomp_pending: Option<DecompileKey>,
    pub decomp_cache: std::collections::HashMap<DecompileKey, DecompileLines>,
    pub decomp_revision: u64,
    pub snap_path: String,
    pub snap_generation: Option<u64>,
    pub snap_strings: Arc<Vec<crate::parser::ExtractedString>>,
    pub snap_symbols: Arc<Vec<crate::parser::Symbol>>,
    pub snap_imports: Arc<Vec<crate::parser::Import>>,
    pub snap_exports: Arc<Vec<crate::parser::Export>>,
    pub snap_sections: Arc<Vec<crate::parser::Section>>,
    pub nav: usize,
    pub sidebar_collapsed: bool,
    pub theme_mode: theme::AppThemeMode,
    pub compact_rows: bool,
    pub show_settings: bool,
    pub show_settings_modal: bool,
    pub settings_tab: usize,
    pub ai_log_filter: usize,
    pub ai_feed_paused: bool,
    pub ai_frozen: Vec<crate::mcp::tools::activity::McpCallEvent>,
    pub ai_last_seen_seq: u64,
    pub ai_fresh: Vec<u64>,
    pub ai_pulse_on: bool,
    pub ai_cursor_view: Option<(f32, f32)>,
    pub ai_cursor_seen: Option<(u64, u64)>,
    pub follow_ai: bool,
    pub recent_on_startup: bool,
    pub restore_last: bool,
    pub confirm_close: bool,
    pub analyze_on_open: bool,
    pub recover_strings: bool,
    pub max_func_size_kb: u32,
    pub allow_changes: bool,
    pub allow_execution: bool,
    pub ui_scale: f32,
    pub startup_opened_by_user: bool,
}

impl Shell {
    pub fn with<R>(&self, f: impl FnOnce(&mut AppState) -> R) -> R {
        let mut g = self.app.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g)
    }

    pub fn read<R>(&self, f: impl FnOnce(&mut AppState) -> R) -> R {
        f(&mut self.view_state.borrow_mut())
    }

    pub fn refresh_view_state(&mut self) {
        let Ok(mut s) = self.app.try_lock() else {
            return;
        };
        let key = (
            s.binary_generation,
            s.analysis_version,
            s.modification_number,
        );
        let mut view = self.view_state.borrow_mut();
        if self.view_key != Some(key) {
            self.table_cache = views::bottom::ViewCache::default();
            let analysis_changed = self.view_key.map(|k| (k.0, k.1)) != Some((key.0, key.1));
            if analysis_changed {
                *self.listing_maps.borrow_mut() = None;
                *self.cfg_insns.borrow_mut() = None;
                *self.function_names.borrow_mut() = None;
            } else if view.user_func_names != s.user_func_names {
                if let Some((_, maps)) = self.listing_maps.borrow_mut().as_mut() {
                    let names = Arc::make_mut(&mut maps.func_lookup);
                    for (addr, name) in &s.user_func_names {
                        names.insert(*addr, name.clone());
                    }
                    for addr in view
                        .user_func_names
                        .keys()
                        .filter(|a| !s.user_func_names.contains_key(a))
                    {
                        if let Some(f) = s
                            .analysis
                            .as_ref()
                            .and_then(|a| a.functions.iter().find(|f| f.entry == *addr))
                        {
                            names.insert(*addr, f.name.clone());
                        }
                    }
                }
                *self.function_names.borrow_mut() = None;
            }
            self.listing_rows.borrow_mut().2.clear();
            if view.binary_generation != s.binary_generation
                || view.binary.is_none()
                || self.view_key.map(|k| k.1) != Some(s.analysis_version)
            {
                view.binary = s.binary.clone();
            }
            view.disasm = s.disasm.clone();
            view.analysis = s.analysis.clone();
            view.file_path = s.file_path.clone();
            view.comments = s.comments.clone();
            view.comments_ex = s.comments_ex.clone();
            view.user_func_names = s.user_func_names.clone();
            view.bookmarks = s.bookmarks.clone();
            view.patches = s.patches.clone();
            view.patch_seq = s.patch_seq;
            view.user_labels = s.user_labels.clone();
            view.label_sources = s.label_sources.clone();
            view.function_tags = s.function_tags.clone();
            view.user_xrefs = s.user_xrefs.clone();
            view.types = s.types.clone();
            view.data_types_at = s.data_types_at.clone();
            view.current_program_name = s.current_program_name.clone();
            view.modification_number = s.modification_number;
            view.dirty = s.dirty;
            view.binary_generation = s.binary_generation;
            view.analysis_version = s.analysis_version;
            if self.view_key.map(|k| (k.0, k.1)) != Some((key.0, key.1)) {
                invalidate_analysis_caches(&mut view);
            }
            view.analysis_version = s.analysis_version;
            let mut annotations = self.view_annotations.borrow_mut();
            annotations.1 = Arc::new(s.user_labels.clone());
            annotations.2 = Arc::new(s.comments.clone());
            self.view_key = Some(key);
        }
        view.selected_insn = s.selected_insn;
        view.selected_func = s.selected_func;
        view.disasm_scroll = s.disasm_scroll;
        view.hex_offset = s.hex_offset;
        view.func_filter = s.func_filter.clone();
        view.func_sort = s.func_sort;
        view.status_msg = s.status_msg.clone();
        view.debug_state.registers = s.debug_state.registers.clone();
        view.debug_state.stack_data = s.debug_state.stack_data.clone();
        view.debug_state.breakpoints = s.debug_state.breakpoints.clone();
        view.debug_state.current_rip = s.debug_state.current_rip;
        view.debug_state.is_running = s.debug_state.is_running;
        view.debug_state.is_attached = s.debug_state.is_attached;
        view.analysis_progress = s.analysis_progress.clone();
        view.pending_load = s.pending_load.clone();
        view.mcp_port = s.mcp_port;
        view.mcp_port_buf = s.mcp_port_buf.clone();
        view.mcp_started_ms = s.mcp_started_ms;
        view.mcp_last_call_ms = s.mcp_last_call_ms;
        view.mcp_call_seq = s.mcp_call_seq;
        view.mcp_call_log = s
            .mcp_call_log
            .iter()
            .rev()
            .take(200)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        view.ai_plan = s.ai_plan.clone();
        view.ai_cursor = s.ai_cursor;
        view.goto_addr_buf = s.goto_addr_buf.clone();
        view.search_query = s.search_query.clone();
        view.search_kind = s.search_kind;
        view.search_dirty = s.search_dirty;
        view.hex_bytes_per_row = s.hex_bytes_per_row;
        view.import_base_addr_buf = s.import_base_addr_buf.clone();
        view.import_arch_idx = s.import_arch_idx;
        view.recent_projects = s.recent_projects.clone();
        view.fid_epoch = s.fid_epoch;
        if view.program_slots.len() != s.program_slots.len() {
            view.program_slots = s.program_slots.clone();
        }
        view.refresh_bp_set();
        s.refresh_bp_set_if_needed();
        let mut annotations = self.view_annotations.borrow_mut();
        if *annotations.0 != s.bp_addr_set {
            annotations.0 = Arc::new(s.bp_addr_set.clone());
        }
    }

    pub(super) fn restore_settings(&mut self) {
        if cfg!(test) {
            return;
        }
        let Ok(bytes) = std::fs::read(settings_path()) else {
            return;
        };
        let Ok(settings) = serde_json::from_slice::<UiSettings>(&bytes) else {
            return;
        };
        if !settings.side_ratio.is_finite() || !settings.bottom_ratio.is_finite() {
            return;
        }
        self.theme_mode = theme::AppThemeMode::from_idx(settings.theme);
        self.compact_rows = false;
        self.ui_scale = [0.9f32, 1.0, 1.1]
            .into_iter()
            .find(|s| (s - settings.ui_scale).abs() < 0.01)
            .unwrap_or(1.0);
        self.sidebar_collapsed = false;
        self.side_ratio = settings.side_ratio.clamp(0.15, 0.5);
        self.bottom_ratio = settings.bottom_ratio.clamp(0.15, 0.6);
        self.bottom_tab = settings.bottom_tab.min(BOTTOM_TABS.len() - 1);
        self.side_tab = settings.side_tab.min(SIDE_TABS.len() - 1);
        if self.startup_opened_by_user {
            sync_window(self, self.win_size);
            return;
        }
        self.recent_on_startup = settings.show_recent_startup;
        self.show_startup = self.recent_on_startup && self.show_startup;
        self.restore_last = settings.restore_last;
        self.confirm_close = settings.confirm_close;
        self.analyze_on_open = settings.analyze_on_open;
        self.recover_strings = settings.recover_strings;
        self.max_func_size_kb = settings.max_func_size_kb.clamp(1, 65536);
        self.allow_changes = settings.allow_changes;
        self.allow_execution = settings.allow_execution;
        if self.restore_last && !self.show_startup
            && let Some(path) = self
                .app
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .recent_projects
                .first()
                .cloned()
            {
                self.with(|s| actions::spawn_async_load(s, None, None, path));
            }
        sync_window(self, self.win_size);
    }

    pub(super) fn save_settings(&self) -> Result<(), String> {
        let settings = UiSettings {
            theme: self.theme_mode.idx(),
            compact: self.compact_rows,
            collapsed: self.sidebar_collapsed,
            side_ratio: self.side_ratio,
            bottom_ratio: self.bottom_ratio,
            bottom_tab: self.bottom_tab,
            side_tab: self.side_tab,
            show_recent_startup: self.recent_on_startup,
            restore_last: self.restore_last,
            confirm_close: self.confirm_close,
            analyze_on_open: self.analyze_on_open,
            recover_strings: self.recover_strings,
            max_func_size_kb: self.max_func_size_kb,
            allow_changes: self.allow_changes,
            allow_execution: self.allow_execution,
            ui_scale: self.ui_scale,
        };
        let path = settings_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&settings).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        std::fs::rename(tmp, path).map_err(|e| e.to_string())
    }

    pub fn server_on(&self) -> bool {
        self.read(|s| s.mcp_started_ms.is_some())
    }

    pub fn is_light(&self) -> bool {
        self.theme_mode == theme::AppThemeMode::Light
            || (self.theme_mode == theme::AppThemeMode::System && self.system_dark == Some(false))
    }

    pub fn has_overlay(&self) -> bool {
        self.show_startup
            || self.rename.is_some()
            || self.comment.is_some()
            || self.bookmark.is_some()
            || self.show_import
            || self.show_search
            || self.show_type_dialog
            || self.show_settings_modal
            || self.show_settings
    }
}

impl Shell {
    pub fn from_shared(app: Arc<Mutex<AppState>>) -> Shell {
        Self::build(app, true)
    }

    pub(super) fn presentation_twin(app: Arc<Mutex<AppState>>) -> Shell {
        Self::build(app, false)
    }

    fn build(app: Arc<Mutex<AppState>>, restore: bool) -> Shell {
        let show_startup = app
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .binary
            .is_none();
        let mut shell = Shell {
            now: std::time::Instant::now(),
            started: std::time::Instant::now(),
            anims: Default::default(),
            toasts: Default::default(),
            last_status: String::new(),
            last_analysis_error: None,
            auto_analyzed: None,
            feed_open: Default::default(),
            feed_seen: Default::default(),
            startup_raw: false,
            recent_removals: Vec::new(),
            modal_dismiss: None,
            app,
            view_state: std::cell::RefCell::new(AppState::new()),
            view_key: None,
            table_cache: views::bottom::ViewCache::default(),
            listing_maps: std::cell::RefCell::new(None),
            listing_rows: std::rc::Rc::new(std::cell::RefCell::new((
                u64::MAX,
                0,
                Default::default(),
            ))),
            cfg_insns: std::cell::RefCell::new(None),
            function_names: std::cell::RefCell::new(None),
            view_annotations: std::cell::RefCell::new((
                Arc::new(Default::default()),
                Arc::new(Default::default()),
                Arc::new(Default::default()),
            )),
            snap_binary: None,
            search_epoch: 0,
            search_pending: false,
            search_rows: Arc::new(Vec::new()),
            search_first: 0,
            fonts: theme::Fonts::load(),
            side_w: 330.0,
            bottom_h: 250.0,
            side_ratio: 330.0 / (1680.0 - 224.0 - 10.0),
            bottom_ratio: 250.0 / (960.0 - 54.0 - 10.0),
            win_size: Size::new(1680.0, 960.0),
            bottom_tab: 6,
            side_tab: 0,
            bottom_scroll: 0,
            hex_scroll: None,
            side_scroll: 0,
            listing_first: 0,
            funcs_first: 0,
            rename: None,
            comment: None,
            bookmark: None,
            show_import: false,
            import_path: String::new(),
            comment_editor: iced::widget::text_editor::Content::new(),
            show_search: false,
            show_startup,
            recent_on_startup: true,
            show_type_dialog: false,
            type_kind: 0,
            type_name: String::new(),
            closing: false,
            system_dark: None,
            decomp_lines: Arc::new(Vec::new()),
            decomp_key: None,
            decomp_pending: None,
            decomp_cache: std::collections::HashMap::new(),
            decomp_revision: 0,
            snap_path: String::new(),
            snap_generation: None,
            snap_strings: Arc::new(Vec::new()),
            snap_symbols: Arc::new(Vec::new()),
            snap_imports: Arc::new(Vec::new()),
            snap_exports: Arc::new(Vec::new()),
            snap_sections: Arc::new(Vec::new()),
            nav: 0,
            sidebar_collapsed: false,
            theme_mode: theme::AppThemeMode::default(),
            compact_rows: false,
            show_settings: false,
            show_settings_modal: false,
            settings_tab: 0,
            ai_log_filter: 0,
            ai_feed_paused: false,
            ai_frozen: Vec::new(),
            ai_last_seen_seq: 0,
            ai_fresh: Vec::new(),
            ai_pulse_on: true,
            ai_cursor_view: None,
            ai_cursor_seen: None,
            follow_ai: false,
            restore_last: false,
            confirm_close: true,
            analyze_on_open: true,
            recover_strings: true,
            max_func_size_kb: 64,
            allow_changes: true,
            allow_execution: false,
            ui_scale: 1.0,
            startup_opened_by_user: false,
        };
        if restore {
            shell.restore_settings();
        }
        if shell.show_startup {
            shell.anims.start(("modal", 0), 0.0, 1.0, 260, shell.now);
            shell
                .anims
                .start_css(("backdrop", 0), 0.0, 1.0, 200, shell.now);
        }
        shell.refresh_view_state();
        shell
    }

    pub fn run(self) -> iced::Result {
        let cell = std::cell::RefCell::new(Some(self));
        iced::application(
            move || {
                let mut shell = cell.borrow_mut().take().expect("iced booted twice");
                shell.refresh_snapshots();
                (shell, boot_task())
            },
            update,
            crate::gui::views::workbench_view,
        )
        .settings(iced::Settings {
            vsync: std::env::var("RD_VSYNC").as_deref() != Ok("0"),
            default_text_size: iced::Pixels(theme::BODY_SIZE),
            ..iced::Settings::default()
        })
        .antialiasing(true)
        .subscription(subscription)
        .title(title)
        .theme(app_theme)
        .scale_factor(|shell: &Shell| shell.ui_scale as _)
        .font(theme::ICON_FONT_BYTES)
        .font(theme::INTER_400_BYTES)
        .font(theme::INTER_500_BYTES)
        .font(theme::INTER_600_BYTES)
        .font(theme::JBM_400_BYTES)
        .font(theme::JBM_500_BYTES)
        .default_font(iced::Font {
            family: iced::font::Family::Name(theme::UI_FONT_NAME),
            ..iced::Font::DEFAULT
        })
        .window(window_settings())
        .run()
    }
}
