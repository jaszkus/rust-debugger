use std::sync::{Arc, Mutex};

use iced::keyboard::key::Named;
use iced::keyboard::{self, Key, Modifiers};
use iced::{Size, Subscription, Task, Theme};

use super::state::*;
use super::theme;
use super::widgets::split::Drag;
use super::{actions, views};

pub mod input;
pub mod menus;
pub mod panels;
pub mod shell;

use input::*;
use menus::*;
use panels::*;

pub use menus::command_list;
pub use panels::{poll_analysis_install, poll_load_install, rail_y};
pub use shell::Shell;
#[cfg(test)]
pub(crate) use shell::UiSettings;

pub mod message;
#[cfg(test)]
mod tests;

pub use message::*;

pub fn title(shell: &Shell) -> String {
    let prog = shell.read(|s| s.current_program_label());
    if prog.is_empty() {
        "Rust Debugger".into()
    } else {
        format!("{prog} — Rust Debugger")
    }
}

pub fn theme(shell: &Shell) -> Theme {
    theme::app_theme(shell.is_light())
}

pub fn update(shell: &mut Shell, message: Message) -> Task<Message> {
    shell.now = std::time::Instant::now();
    if let Some((_, ghost)) = shell.modal_dismiss.as_mut() {
        ghost.now = shell.now;
    }
    let before = AnimState::capture(shell);
    let is_cancel = matches!(
        &message,
        Message::DismissOverlay
            | Message::CloseStartup
            | Message::SettingsModalClose
            | Message::RenameCancel
            | Message::CommentCancel
            | Message::BookmarkCancel
            | Message::ImportCancel
            | Message::TypeCancel
            | Message::SearchDismissed
    );
    if is_cancel && shell.has_overlay() && shell.modal_dismiss.is_none() {
        let mut ghost = Shell::presentation_twin(shell.app.clone());
        ghost.now = shell.now;
        ghost.anims = Default::default();
        ghost
            .anims
            .start_css(("closing", 0), 0.0, 1.0, 180, shell.now);
        ghost.show_startup = shell.show_startup;
        ghost.startup_raw = shell.startup_raw;
        ghost.show_import = shell.show_import;
        ghost.import_path = shell.import_path.clone();
        ghost.rename = shell.rename.clone();
        ghost.comment = shell.comment.clone();
        ghost.comment_editor =
            iced::widget::text_editor::Content::with_text(&shell.comment_editor.text());
        ghost.bookmark = shell.bookmark.clone();
        ghost.show_type_dialog = shell.show_type_dialog;
        ghost.type_kind = shell.type_kind;
        ghost.type_name = shell.type_name.clone();
        ghost.show_search = shell.show_search;
        ghost.search_rows = shell.search_rows.clone();
        ghost.show_settings_modal = shell.show_settings_modal;
        ghost.settings_tab = shell.settings_tab;
        ghost.theme_mode = shell.theme_mode;
        ghost.system_dark = shell.system_dark;
        let task = update_inner(shell, message);
        shell.modal_dismiss = Some((shell.now, Box::new(ghost)));
        shell
            .anims
            .start(("modal_out", 0), 0.0, 1.0, 180, shell.now);
        shell.refresh_view_state();
        sync_anims(shell, before);
        return task;
    }
    if shell.modal_dismiss.is_some()
        && !matches!(
            &message,
            Message::AnimationTick
                | Message::Tick
                | Message::ToastWake
                | Message::AiPoll
                | Message::CloseRequested
                | Message::ShutdownFinished(_)
                | Message::SearchOpen
                | Message::RenameRequest(_)
                | Message::CommentRequest(_)
                | Message::BookmarkRequest(_)
                | Message::StartupImportOpen
                | Message::StartupOpen
                | Message::SettingsMore
                | Message::SettingsToggle
        )
    {
        return Task::none();
    }
    if matches!(
        &message,
        Message::SearchOpen
            | Message::RenameRequest(_)
            | Message::CommentRequest(_)
            | Message::BookmarkRequest(_)
            | Message::StartupImportOpen
            | Message::StartupOpen
            | Message::SettingsMore
            | Message::SettingsToggle
    ) {
        shell.modal_dismiss = None;
    }
    if shell.modal_dismiss.as_ref().is_some_and(|(t, _)| {
        shell.now.saturating_duration_since(*t) >= std::time::Duration::from_millis(180)
    }) {
        shell.modal_dismiss = None;
    }
    let task = update_inner(shell, message);
    shell.refresh_view_state();
    sync_anims(shell, before);
    task
}

fn update_inner(shell: &mut Shell, message: Message) -> Task<Message> {
    let settings_changed = matches!(
        &message,
        Message::ThemePicked(_)
            | Message::CompactToggled
            | Message::RecentStartupToggled
            | Message::RestoreLastToggled
            | Message::ConfirmCloseToggled
            | Message::AnalyzeOnOpenToggled
            | Message::RecoverStringsToggled
            | Message::UiScalePicked(_)
            | Message::MaxFuncSizeCommitted(_)
            | Message::AllowChangesToggled
            | Message::AllowExecutionToggled
            | Message::SidebarToggle
            | Message::BottomTabPicked(_)
            | Message::SideTabPicked(_)
            | Message::SplitDrag(Drag { active: false, .. }, _)
    );
    if shell.closing && !matches!(message, Message::ShutdownFinished(_)) {
        return Task::none();
    }
    if shell.has_overlay()
        && matches!(
            message,
            Message::Analyze
                | Message::Undo
                | Message::Redo
                | Message::RenameSelected
                | Message::CommentSelected
                | Message::HistoryBack
                | Message::HistoryForward
                | Message::FocusSearch
                | Message::DebugRun
                | Message::DebugAttach(_)
                | Message::DebugStepInto
                | Message::DebugStepOver
                | Message::DebugContinue
                | Message::DebugStop
        )
    {
        return Task::none();
    }
    let task = match message {
        msg @ (Message::GoEdited(..)
        | Message::GoSubmit
        | Message::HistoryBack
        | Message::HistoryForward
        | Message::SearchQueryEdited(..)
        | Message::SearchKindPicked(..)
        | Message::SearchOpen
        | Message::SearchDismissed
        | Message::SearchPicked(..)
        | Message::SearchScroll(..)
        | Message::SearchRun
        | Message::SearchFailed(..)
        | Message::SearchFinished(..)
        | Message::FocusSearch
        | Message::WindowResized(..)
        | Message::SyncWindow(..)
        | Message::AutoScroll
        | Message::Tick) => input::update(shell, msg),
        msg @ (Message::StartupOpen
        | Message::StartupRawBack
        | Message::DismissOverlay
        | Message::ConfirmOverlay
        | Message::OpenFile
        | Message::LoadPicked(..)
        | Message::CloseStartup
        | Message::ImportPathEdited(..)
        | Message::ImportBrowse
        | Message::ImportPicked(..)
        | Message::CopyText(..)
        | Message::CopyAddress(..)
        | Message::CopyBytes(..)
        | Message::ProgramSave
        | Message::ProgramSwitch(..)
        | Message::ProgramClose(..)
        | Message::PatchUndo(..)
        | Message::PatchesRevert
        | Message::SignatureClear
        | Message::BookmarkRemove(..)
        | Message::ImportBaseEdited(..)
        | Message::ImportArchPicked(..)
        | Message::ImportConfirm
        | Message::ImportCancel
        | Message::StartupImportOpen
        | Message::RecentClicked(..)
        | Message::RecentRemove(..)
        | Message::CloseRequested
        | Message::Exit
        | Message::ShutdownFinished(..)
        | Message::CommandPicked(..)
        | Message::SettingsToggle
        | Message::SettingsMore
        | Message::SettingsModalClose
        | Message::SettingsTabPicked(..)
        | Message::ThemePicked(..)
        | Message::CompactToggled
        | Message::RecentStartupToggled
        | Message::RestoreLastToggled
        | Message::ConfirmCloseToggled
        | Message::AnalyzeOnOpenToggled
        | Message::RecoverStringsToggled
        | Message::UiScalePicked(..)
        | Message::MaxFuncSizeCommitted(..)
        | Message::AllowChangesToggled
        | Message::AllowExecutionToggled
        | Message::RenameSelected
        | Message::RenameRequest(..)
        | Message::RenameEdited(..)
        | Message::RenameConfirm
        | Message::RenameCancel
        | Message::CommentSelected
        | Message::CommentRequest(..)
        | Message::CommentEdited(..)
        | Message::CommentEditorAction(..)
        | Message::CommentKindPicked(..)
        | Message::CommentConfirm
        | Message::CommentDelete
        | Message::CommentCancel
        | Message::BookmarkRequest(..)
        | Message::BookmarkEdited(..)
        | Message::BookmarkKindPicked(..)
        | Message::BookmarkConfirm
        | Message::BookmarkCancel
        | Message::Undo
        | Message::Redo
        | Message::TypeKindPicked(..)
        | Message::TypeNameEdited(..)
        | Message::TypeCreate
        | Message::TypeCancel
        | Message::TypeExport) => menus::update(shell, msg),
        msg @ (Message::DecompileFinished(..)
        | Message::Noop
        | Message::ToggleBreakpointDebug
        | Message::DebugRun
        | Message::AnimationTick
        | Message::ToastWake
        | Message::ToastDismiss(..)
        | Message::AiDetailsToggle(..)
        | Message::Analyze
        | Message::CancelAnalysis
        | Message::McpToggle
        | Message::McpPortEdited(..)
        | Message::ListingClicked(..)
        | Message::ListingOpen(..)
        | Message::ListingScroll(..)
        | Message::ListingCtxAction(..)
        | Message::ListingMenuDismissed
        | Message::FuncMenuDismissed
        | Message::RowGoto(..)
        | Message::FuncPicked(..)
        | Message::FuncScroll(..)
        | Message::FuncFilterEdited(..)
        | Message::FuncCtxAction(..)
        | Message::BottomTabPicked(..)
        | Message::SideTabPicked(..)
        | Message::BottomScroll(..)
        | Message::HexScroll(..)
        | Message::SideScroll(..)
        | Message::NavPicked(..)
        | Message::SidebarToggle
        | Message::AiPoll
        | Message::AiFeedPauseToggle
        | Message::FollowAiToggle
        | Message::SystemThemeChanged(..)
        | Message::AiLogFilterPicked(..)
        | Message::AiLogClear
        | Message::AiEventGoto(..)
        | Message::DebugAttach(..)
        | Message::DebugStepInto
        | Message::DebugStepOver
        | Message::DebugContinue
        | Message::DebugStop
        | Message::HexBprEdited(..)
        | Message::SplitDrag(..)) => panels::update(shell, msg),
    };
    if settings_changed {
        if let Err(e) = shell.save_settings() {
            shell.with(|s| s.status_msg = format!("Settings save failed: {e}"));
        }
    }
    shell.refresh_view_state();
    Task::batch([task, refresh_decompile_lines(shell)])
}
