use super::super::state::*;
use super::super::widgets::split::Drag;
use super::views;
use iced::Size;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum Message {
    OpenFile,
    LoadPicked(Option<String>),
    ImportPathEdited(String),
    ImportBrowse,
    ImportPicked(Option<String>),
    CopyText(String),
    CopyAddress(u64),
    CopyBytes(u64),
    BookmarkRemove(u64),
    ProgramSave,
    ProgramSwitch(usize),
    ProgramClose(usize),
    PatchUndo(u64),
    PatchesRevert,
    SignatureClear,
    ImportBaseEdited(String),
    ImportArchPicked(usize),
    ImportConfirm,
    ImportCancel,
    StartupImportOpen,
    CloseStartup,
    RecentClicked(String),
    RecentRemove(String),
    CloseRequested,
    Exit,
    ShutdownFinished(Result<(), String>),
    DismissOverlay,
    ConfirmOverlay,
    Noop,
    StartupOpen,
    StartupRawBack,
    ToastDismiss(u64),
    AnimationTick,
    ToastWake,
    AiDetailsToggle(u64),

    Analyze,
    CancelAnalysis,
    DecompileFinished(DecompileKey, Result<DecompileLines, String>),

    McpToggle,
    McpPortEdited(String),

    GoEdited(String),
    GoSubmit,
    HistoryBack,
    HistoryForward,
    ListingClicked(u64),
    ListingOpen(u64),
    ListingScroll(usize),
    ListingCtxAction(views::CtxAction, u64),
    ListingMenuDismissed,
    FuncPicked(u64),
    FuncScroll(usize),
    FuncFilterEdited(String),
    FuncCtxAction(views::CtxAction, u64),
    FuncMenuDismissed,
    BottomTabPicked(usize),
    SideTabPicked(usize),
    BottomScroll(usize),
    SideScroll(usize),
    SearchOpen,
    SearchQueryEdited(String),
    SearchKindPicked(usize),
    SearchDismissed,
    SearchPicked(u64),
    SearchRun,
    SearchScroll(usize),
    SearchFinished(u64, u64, Vec<SearchResult>),
    SearchFailed(u64, String),
    CommandPicked(usize),
    RowGoto(u64),

    RenameSelected,
    RenameRequest(u64),
    RenameEdited(String),
    RenameConfirm,
    RenameCancel,
    CommentRequest(u64),
    CommentSelected,
    CommentEdited(String),
    CommentEditorAction(iced::widget::text_editor::Action),
    CommentKindPicked(usize),
    CommentConfirm,
    CommentDelete,
    CommentCancel,
    BookmarkRequest(u64),
    BookmarkEdited(String),
    BookmarkKindPicked(usize),
    BookmarkConfirm,
    BookmarkCancel,
    Undo,
    Redo,

    DebugRun,
    DebugStepInto,
    DebugStepOver,
    DebugContinue,
    DebugStop,

    TypeKindPicked(usize),
    TypeNameEdited(String),
    TypeCreate,
    TypeCancel,
    TypeExport,

    HexBprEdited(String),
    HexScroll(Option<usize>),

    SplitDrag(Drag, bool),
    WindowResized(Size),
    AutoScroll,
    SyncWindow(Size),
    Tick,

    NavPicked(usize),
    SidebarToggle,
    SettingsToggle,
    SettingsMore,
    SettingsModalClose,
    SettingsTabPicked(usize),
    ThemePicked(usize),
    CompactToggled,
    FocusSearch,
    AiPoll,
    AiFeedPauseToggle,
    FollowAiToggle,
    AiEventGoto(u64),
    SystemThemeChanged(iced::theme::Mode),
    AiLogFilterPicked(usize),
    AiLogClear,

    RecentStartupToggled,
    RestoreLastToggled,
    ConfirmCloseToggled,
    AnalyzeOnOpenToggled,
    RecoverStringsToggled,
    UiScalePicked(usize),
    DebugAttach(u32),
    ToggleBreakpointDebug,
    MaxFuncSizeCommitted(String),
    AllowChangesToggled,
    AllowExecutionToggled,
}

pub const UI_SCALES: [&str; 3] = ["90%", "100%", "110%"];

pub const BOTTOM_TABS: &[&str] = &[
    "Hex",
    "Strings",
    "Imports",
    "Exports",
    "Symbols",
    "Sections",
    "Functions",
    "XRefs",
    "Decompiler",
    "CFG",
    "Stack",
    "PCode",
    "Resources",
    "Debug",
    "Types",
    "Signatures",
    "Comments",
    "Tags",
    "Patches",
    "Programs",
];

pub const SIDE_TABS: &[&str] = &["Func", "Regs", "Stack", "BP", "Marks"];

pub const NAV_ITEMS: &[&str] = &[
    "AI Live",
    "AI Logs",
    "Disassembly",
    "Functions",
    "Strings",
    "Imports",
    "XRefs",
    "Hex",
    "Debug",
];
pub const NAV_GROUPS: &[(&str, usize, usize)] =
    &[("AI", 0, 2), ("Analysis", 2, 8), ("Runtime", 8, 9)];
pub const NAV_LIVE: usize = 0;
pub const NAV_LOGS: usize = 1;
pub const NAV_DISASM: usize = 2;
pub const NAV_DEBUG: usize = 8;

pub const SEARCH_INPUT_ID: &str = "top-search";
pub const DIALOG_INPUT_ID: &str = "dialog-input";

pub fn nav_bottom_tab(nav: usize) -> Option<usize> {
    let name = match nav {
        3 => "Functions",
        4 => "Strings",
        5 => "Imports",
        6 => "XRefs",
        7 => "Hex",
        _ => return None,
    };
    BOTTOM_TABS.iter().position(|t| *t == name)
}

pub const SIDE_SCROLL_ID: &str = "side-panel";

pub const SIDE_SCROLL_MAX: usize = 1_000_000;

pub fn mmss(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}", s / 60, s % 60)
}

pub type DecompileLines = Arc<Vec<(String, crate::analysis::LineKind, Option<u64>)>>;
pub type DecompileKey = (u64, u64, u64);
