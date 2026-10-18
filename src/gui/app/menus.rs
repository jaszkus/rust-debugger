use super::*;

pub(crate) fn apply_ctx_action(
    shell: &mut Shell,
    action: views::CtxAction,
    addr: u64,
) -> Task<Message> {
    use views::CtxAction as C;
    match action {
        C::Select => {
            shell.with(|s| {
                s.selected_insn = Some(addr);
                if let Some(a) = &s.analysis {
                    if let Some(f) = a.functions.iter().find(|f| addr >= f.entry && addr < f.end) {
                        s.selected_func = Some(f.entry);
                    }
                }
            });
        }
        C::ToggleBp => shell.with(|s| actions::toggle_breakpoint(s, addr)),
        C::Comment => return update(shell, Message::CommentRequest(addr)),
        C::Bookmark => return update(shell, Message::BookmarkRequest(addr)),
        C::Rename => return update(shell, Message::RenameRequest(addr)),
        C::Goto => goto_addr(shell, addr),
    }
    Task::none()
}

pub(crate) fn dismiss_all_overlays(shell: &mut Shell) {
    shell.rename = None;
    shell.comment = None;
    shell.bookmark = None;
    shell.show_import = false;
    shell.show_search = false;
    shell.show_type_dialog = false;
    shell.show_startup = false;
    shell.show_settings_modal = false;
    shell.show_settings = false;
}

pub(crate) fn dismiss_overlay(shell: &mut Shell) {
    if shell.show_startup {
        shell.show_startup = false;
    } else if shell.rename.is_some() {
        shell.rename = None;
    } else if shell.comment.is_some() {
        shell.comment = None;
    } else if shell.bookmark.is_some() {
        shell.bookmark = None;
    } else if shell.show_import {
        shell.show_import = false;
    } else if shell.show_type_dialog {
        shell.show_type_dialog = false;
    } else if shell.show_search {
        shell.show_search = false;
    } else if shell.show_settings_modal {
        shell.show_settings_modal = false;
    } else {
        shell.show_settings = false;
    }
}

pub(crate) fn start_search(shell: &mut Shell) -> Task<Message> {
    if !shell.show_search || shell.search_pending || !shell.with(|s| s.search_dirty) {
        return Task::none();
    }
    shell.refresh_snapshots();
    let (query, kind, generation, analysis) = shell.with(|s| {
        s.search_dirty = false;
        (
            s.search_query.clone(),
            s.search_kind,
            s.binary_generation,
            s.analysis.clone(),
        )
    });
    let binary = shell.snap_binary.clone();
    let epoch = shell.search_epoch;
    shell.search_pending = true;
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                binary
                    .map(|b| views::search_snapshot(&query, kind, &b, analysis.as_deref()))
                    .unwrap_or_default()
            })
            .await
        },
        move |result| match result {
            Ok(rows) => Message::SearchFinished(epoch, generation, rows),
            Err(e) => Message::SearchFailed(epoch, format!("Search worker failed: {e}")),
        },
    )
}

pub fn command_list() -> Vec<(String, Message)> {
    let mut commands = vec![
        ("Open file".into(), Message::OpenFile),
        ("Import raw dump".into(), Message::StartupImportOpen),
        ("Settings".into(), Message::SettingsMore),
    ];
    commands.extend(
        BOTTOM_TABS
            .iter()
            .enumerate()
            .map(|(i, name)| (format!("Show {name}"), Message::BottomTabPicked(i))),
    );
    commands
}

#[derive(Debug, Clone)]
pub(crate) enum ToastEvent {
    FileLoaded(String),
    FileOpenError(String),
    AnalysisDone { funcs: usize },
    OpDone { title: String, detail: String },
    OpError { title: String, detail: String },
    McpStarted(u16),
    McpStopped(u16),
    BreakpointSet(u64),
    BreakpointRemoved(u64),
    Ignore,
}

impl ToastEvent {
    pub(crate) fn parse(msg: &str) -> ToastEvent {
        let m = msg.trim();
        if m.starts_with("Loaded ") {
            let name = m
                .trim_start_matches("Loaded ")
                .split(" | ")
                .next()
                .unwrap_or("");
            return ToastEvent::FileLoaded(
                name.rsplit(['/', '\\']).next().unwrap_or(name).to_string(),
            );
        }
        if m.starts_with("Load error: ") {
            return ToastEvent::FileOpenError(m.trim_start_matches("Load error: ").to_string());
        }
        if m.starts_with("Analysis done in ") {
            let funcs = m
                .split(" | ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);
            return ToastEvent::AnalysisDone { funcs };
        }
        if let Some(rest) = m.strip_prefix("MCP server started") {
            let port = rest
                .split(":")
                .nth(1)
                .and_then(|s| s.split("/").next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);
            return ToastEvent::McpStarted(port);
        }
        if m == "MCP server stopped" {
            return ToastEvent::McpStopped(8765);
        }
        if m.starts_with("BP set ") {
            if let Ok(a) = u64::from_str_radix(m.trim_start_matches("BP set "), 16) {
                return ToastEvent::BreakpointSet(a);
            }
        }
        if m.starts_with("BP removed ") {
            if let Ok(a) = u64::from_str_radix(
                m.trim_start_matches("BP removed ")
                    .split_whitespace()
                    .next()
                    .unwrap_or(""),
                16,
            ) {
                return ToastEvent::BreakpointRemoved(a);
            }
        }
        if let Some(rest) = m.strip_prefix("BP failed ") {
            return ToastEvent::OpError {
                title: "Breakpoint".into(),
                detail: rest.into(),
            };
        }
        if m.starts_with("Not an instruction start: ") {
            return ToastEvent::OpError {
                title: "Breakpoint".into(),
                detail: m.into(),
            };
        }
        if let Some(rest) = m.strip_prefix("MCP start failed: ") {
            return ToastEvent::OpError {
                title: "MCP server".into(),
                detail: rest.into(),
            };
        }
        if m == "MCP shared state not initialized" {
            return ToastEvent::OpError {
                title: "MCP server".into(),
                detail: m.into(),
            };
        }
        if let Some(rest) = m.strip_prefix("Decompile failed: ") {
            return ToastEvent::OpError {
                title: "Decompile failed".into(),
                detail: rest.into(),
            };
        }
        if let Some(rest) = m.strip_prefix("Save failed; window kept open: ") {
            return ToastEvent::OpError {
                title: "Save failed".into(),
                detail: rest.into(),
            };
        }
        if let Some(rest) = m.strip_prefix("Settings save failed: ") {
            return ToastEvent::OpError {
                title: "Settings".into(),
                detail: rest.into(),
            };
        }
        if let Some(rest) = m.strip_prefix("Undid ") {
            return ToastEvent::OpDone {
                title: "Undo".into(),
                detail: rest.into(),
            };
        }
        if let Some(rest) = m.strip_prefix("Redid ") {
            return ToastEvent::OpDone {
                title: "Redo".into(),
                detail: rest.into(),
            };
        }
        if let Some(rest) = m.strip_prefix("Created ") {
            return ToastEvent::OpDone {
                title: "Created".into(),
                detail: rest.into(),
            };
        }
        if m.starts_with("Exported ") {
            return ToastEvent::OpDone {
                title: "Export".into(),
                detail: m.into(),
            };
        }
        if m == "Nothing selected to rename" {
            return ToastEvent::OpDone {
                title: "Rename".into(),
                detail: m.into(),
            };
        }
        if m == "Load a binary first"
            || m == "Choose a raw dump first"
            || m == "Already loading a file"
            || m.starts_with("Attach: ")
        {
            return ToastEvent::OpDone {
                title: "Hint".into(),
                detail: m.into(),
            };
        }
        if m == "Analysis already running" {
            return ToastEvent::OpDone {
                title: "Analysis".into(),
                detail: m.into(),
            };
        }
        if m == "Target process exited" {
            return ToastEvent::OpDone {
                title: "Debugger".into(),
                detail: m.into(),
            };
        }
        if m.starts_with("Starting analysis")
            || m.starts_with("Loading")
            || m.starts_with("Load cancelled")
            || m.starts_with("Cancelling")
            || m.starts_with("Switched to program")
            || m.starts_with("Debugging:")
            || m.starts_with("Attached to PID")
            || m.starts_with("Detached")
            || m.starts_with("Stepping")
            || m.starts_with("Running")
            || m.starts_with("Break requested")
            || m.starts_with("BP arming")
            || m.starts_with("Saving project")
        {
            return ToastEvent::Ignore;
        }
        let lower = m.to_lowercase();
        if ["error", "failed", "crashed", "timed out", "aborted"]
            .iter()
            .any(|w| lower.contains(w))
        {
            return ToastEvent::OpError {
                title: "Error".into(),
                detail: m.to_string(),
            };
        }
        ToastEvent::Ignore
    }

    pub(crate) fn render(self) -> (String, String, &'static str, bool) {
        use crate::gui::theme::ic;
        match self {
            ToastEvent::FileLoaded(name) => ("File opened".into(), name, ic::FO, false),
            ToastEvent::FileOpenError(e) => ("Load failed".into(), e, ic::FO, true),
            ToastEvent::AnalysisDone { funcs } => (
                "Analysis complete".into(),
                format!("{funcs} functions found"),
                ic::DIS,
                false,
            ),
            ToastEvent::OpDone { title, detail } => (title, detail, ic::INFO, false),
            ToastEvent::OpError { title, detail } => (title, detail, ic::INFO, true),
            ToastEvent::McpStarted(port) => (
                "MCP server started".into(),
                format!("127.0.0.1:{port}"),
                ic::MCP,
                false,
            ),
            ToastEvent::McpStopped(port) => (
                "MCP server stopped".into(),
                if port != 0 {
                    format!("Port {port} released")
                } else {
                    "Port released".into()
                },
                ic::MCP,
                false,
            ),
            ToastEvent::BreakpointSet(addr) => (
                "Breakpoint set".into(),
                format!("0x{addr:X}"),
                ic::DIS,
                false,
            ),
            ToastEvent::BreakpointRemoved(addr) => (
                "Breakpoint removed".into(),
                format!("0x{addr:X}"),
                ic::DIS,
                false,
            ),
            ToastEvent::Ignore => unreachable!("parse never yields Ignore with a toast"),
        }
    }
}

pub(crate) fn update(shell: &mut Shell, message: Message) -> Task<Message> {
    match message {
        Message::StartupOpen => {
            dismiss_all_overlays(shell);
            shell.show_startup = true;
            shell.startup_raw = false;
            Task::none()
        }
        Message::StartupRawBack => {
            shell.startup_raw = false;
            Task::none()
        }
        Message::DismissOverlay => {
            dismiss_overlay(shell);
            Task::none()
        }
        Message::ConfirmOverlay => {
            let action = if shell.rename.is_some() {
                Message::RenameConfirm
            } else if shell.comment.is_some() {
                Message::CommentConfirm
            } else if shell.bookmark.is_some() {
                Message::BookmarkConfirm
            } else if shell.show_import || (shell.show_startup && shell.startup_raw) {
                Message::ImportConfirm
            } else if shell.show_type_dialog {
                Message::TypeCreate
            } else if shell.show_search {
                Message::SearchRun
            } else {
                Message::Noop
            };
            super::update(shell, action)
        }

        Message::OpenFile => Task::perform(
            async {
                rfd::AsyncFileDialog::new()
                    .add_filter(
                        "Executables & objects",
                        &["exe", "dll", "sys", "elf", "so", "o", "obj", "bin", "dmp"],
                    )
                    .add_filter("All files", &["*"])
                    .pick_file()
                    .await
                    .map(|h| h.path().display().to_string())
            },
            Message::LoadPicked,
        ),
        Message::LoadPicked(Some(path)) => {
            shell.with(|s| {
                actions::spawn_async_load(s, None, None, path);
            });
            shell.show_startup = false;
            Task::none()
        }
        Message::LoadPicked(None) => Task::none(),
        Message::CloseStartup => {
            shell.show_startup = false;
            Task::none()
        }

        Message::ImportPathEdited(p) => {
            shell.import_path = p;
            Task::none()
        }
        Message::ImportBrowse => Task::perform(
            async {
                rfd::AsyncFileDialog::new()
                    .pick_file()
                    .await
                    .map(|h| h.path().display().to_string())
            },
            Message::ImportPicked,
        ),
        Message::ImportPicked(path) => {
            if let Some(path) = path {
                shell.import_path = path;
            }
            Task::none()
        }

        Message::CopyText(text) => iced::clipboard::write(text),
        Message::CopyAddress(addr) => iced::clipboard::write(format!("{addr:#X}")),
        Message::CopyBytes(addr) => {
            let bytes = shell.with(|s| {
                s.disasm
                    .as_ref()
                    .and_then(|d| {
                        let pos = d.instructions.partition_point(|i| i.address < addr);
                        d.instructions
                            .get(pos)
                            .filter(|i| i.address == addr)
                            .map(|i| {
                                i.bytes
                                    .iter()
                                    .map(|b| format!("{b:02X}"))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                    })
                    .unwrap_or_default()
            });
            iced::clipboard::write(bytes)
        }

        Message::ProgramSave => {
            shell.with(|s| {
                let name = s.current_program_label();
                save_program_slot(s, name);
            });
            Task::none()
        }
        Message::ProgramSwitch(i) => {
            shell.with(|s| {
                if let Err(e) = restore_program_slot(s, i) {
                    s.status_msg = e;
                }
            });
            shell.listing_first = 0;
            shell.refresh_snapshots();
            Task::none()
        }
        Message::ProgramClose(i) => {
            shell.with(|s| {
                if i < s.program_slots.len() {
                    s.program_slots.remove(i);
                }
            });
            Task::none()
        }

        Message::PatchUndo(addr) => {
            let result = crate::mcp::tools::patch::undo_patch_at(
                &serde_json::json!({"address": format!("{addr:#x}")}),
                &shell.app,
            );
            shell.with(|s| match result {
                Ok(_) => {
                    s.dirty = true;
                    s.modification_number = s.modification_number.wrapping_add(1);
                }
                Err(e) => s.status_msg = e,
            });
            Task::none()
        }
        Message::PatchesRevert => {
            let result = crate::mcp::tools::patch::revert_all_patches(&shell.app);
            shell.with(|s| match result {
                Ok(_) => {
                    s.dirty = true;
                    s.modification_number = s.modification_number.wrapping_add(1);
                }
                Err(e) => s.status_msg = e,
            });
            Task::none()
        }
        Message::SignatureClear => {
            shell.with(|s| s.fid_clear());
            Task::none()
        }

        Message::BookmarkRemove(addr) => {
            shell.with(|s| {
                let old = s.bookmarks.iter().find(|b| b.addr == addr).cloned();
                s.transact(ProgramEvent::Bookmark(addr), |p| {
                    p.bookmarks.retain(|b| b.addr != addr)
                });
                s.annotation_undo.push(AnnotationChange::Bookmark {
                    addr,
                    old,
                    new: None,
                });
            });
            Task::none()
        }

        Message::ImportBaseEdited(b) => {
            shell.with(|s| s.import_base_addr_buf = b);
            Task::none()
        }
        Message::ImportArchPicked(i) => {
            shell.with(|s| s.import_arch_idx = clamp_arch_idx(i));
            Task::none()
        }
        Message::ImportConfirm => {
            let path = shell.import_path.clone();
            if path.trim().is_empty() {
                shell.with(|s| s.status_msg = "Choose a raw dump first".into());
                return Task::none();
            }
            shell.with(|s| actions::load_raw(s, path));
            shell.show_import = false;
            shell.show_startup = false;
            shell.startup_raw = false;
            Task::none()
        }
        Message::ImportCancel => {
            shell.show_import = false;
            Task::none()
        }
        Message::StartupImportOpen if shell.show_startup => {
            shell.startup_raw = true;
            Task::none()
        }
        Message::StartupImportOpen => {
            dismiss_all_overlays(shell);
            shell.import_path = shell.with(|s| s.file_path.clone());
            shell.show_import = true;
            iced::widget::operation::focus(DIALOG_INPUT_ID)
        }

        Message::RecentClicked(path) => {
            shell.with(|s| {
                actions::spawn_async_load(s, None, None, path);
            });
            shell.show_startup = false;
            Task::none()
        }
        Message::RecentRemove(path) => {
            let index = shell.read(|s| s.recent_projects.iter().position(|p| p == &path));
            if let Some(index) = index {
                shell.recent_removals.push((path.clone(), index, shell.now));
                shell
                    .anims
                    .start(("recent", index as u64), 0.0, 1.0, 260, shell.now);
            }
            shell.with(|s| {
                s.recent_projects.retain(|p| p != &path);
                save_recents(&s.recent_projects);
            });
            Task::none()
        }

        Message::CloseRequested | Message::Exit => {
            shell.closing = true;
            shell.with(|s| s.status_msg = "Saving project…".into());
            let app = shell.app.clone();
            Task::perform(
                async move {
                    tokio::task::spawn_blocking(move || shutdown(&app))
                        .await
                        .unwrap_or_else(|e| Err(format!("Shutdown worker failed: {e}")))
                },
                Message::ShutdownFinished,
            )
        }
        Message::ShutdownFinished(result) => match result {
            Ok(()) => iced::exit(),
            Err(e) => {
                shell.closing = false;
                shell.with(|s| s.status_msg = format!("Save failed; window kept open: {e}"));
                Task::none()
            }
        },

        Message::CommandPicked(i) => {
            shell.show_search = false;
            let commands = command_list();
            commands
                .get(i)
                .map(|(_, msg)| super::update(shell, msg.clone()))
                .unwrap_or_else(Task::none)
        }

        Message::SettingsToggle => {
            let open = !shell.show_settings_modal;
            dismiss_all_overlays(shell);
            shell.show_settings_modal = open;
            Task::none()
        }
        Message::SettingsMore => {
            shell.show_settings = false;
            shell.show_settings_modal = true;
            Task::none()
        }
        Message::SettingsModalClose => {
            shell.show_settings_modal = false;
            Task::none()
        }
        Message::SettingsTabPicked(i) => {
            shell.settings_tab = i.min(4);
            Task::none()
        }
        Message::ThemePicked(i) => {
            shell.theme_mode = theme::AppThemeMode::from_idx(i);
            Task::none()
        }
        Message::CompactToggled => {
            shell.compact_rows = !shell.compact_rows;
            Task::none()
        }
        Message::RecentStartupToggled => {
            shell.recent_on_startup = !shell.recent_on_startup;
            Task::none()
        }
        Message::RestoreLastToggled => {
            shell.restore_last = !shell.restore_last;
            Task::none()
        }
        Message::ConfirmCloseToggled => {
            shell.confirm_close = !shell.confirm_close;
            Task::none()
        }
        Message::AnalyzeOnOpenToggled => {
            shell.analyze_on_open = !shell.analyze_on_open;
            Task::none()
        }
        Message::RecoverStringsToggled => {
            shell.recover_strings = !shell.recover_strings;
            Task::none()
        }
        Message::UiScalePicked(i) => {
            shell.ui_scale = [0.9f32, 1.0, 1.1][i.min(2)];
            Task::none()
        }
        Message::MaxFuncSizeCommitted(text) => {
            let kb: u32 = text
                .trim()
                .trim_end_matches(" KB")
                .trim()
                .parse()
                .unwrap_or(64);
            shell.max_func_size_kb = kb.clamp(1, 65536);
            Task::none()
        }
        Message::AllowChangesToggled => {
            shell.allow_changes = !shell.allow_changes;
            Task::none()
        }
        Message::AllowExecutionToggled => {
            shell.allow_execution = !shell.allow_execution;
            Task::none()
        }

        Message::RenameSelected => {
            let sel = shell.with(|s| s.selected_func.or(s.selected_insn));
            match sel {
                Some(addr) => return super::update(shell, Message::RenameRequest(addr)),
                None => {
                    shell.with(|s| s.status_msg = "Nothing selected to rename".into());
                }
            }
            Task::none()
        }
        Message::RenameRequest(addr) => {
            let cur = shell.with(|s| {
                s.user_func_names
                    .get(&addr)
                    .cloned()
                    .or_else(|| {
                        s.analysis.as_ref().and_then(|a| {
                            a.functions
                                .iter()
                                .find(|f| f.entry == addr)
                                .map(|f| f.name.clone())
                        })
                    })
                    .unwrap_or_default()
            });
            dismiss_all_overlays(shell);
            shell.rename = Some((addr, cur));
            iced::widget::operation::focus(DIALOG_INPUT_ID)
        }
        Message::RenameEdited(t) => {
            if let Some((_, buf)) = &mut shell.rename {
                *buf = t;
            }
            Task::none()
        }
        Message::RenameConfirm => {
            if let Some((addr, name)) = shell.rename.take() {
                let name = name.trim().to_string();
                if !name.is_empty() {
                    shell.with(|s| {
                        let old = s.user_func_names.get(&addr).cloned();
                        s.set_rename(addr, Some(name.clone()));
                        s.annotation_undo
                            .push(crate::gui::AnnotationChange::Rename {
                                addr,
                                old,
                                new: Some(name),
                            });
                    });
                }
            }
            Task::none()
        }
        Message::RenameCancel => {
            shell.rename = None;
            Task::none()
        }

        Message::CommentSelected => {
            let addr = shell.with(|s| s.selected_insn.or(s.selected_func));
            addr.map(|a| super::update(shell, Message::CommentRequest(a)))
                .unwrap_or_else(Task::none)
        }
        Message::CommentRequest(addr) => {
            let buf = shell.with(|s| {
                s.get_comment_kind(addr, CommentKind::Eol)
                    .cloned()
                    .unwrap_or_default()
            });
            shell.comment_editor = iced::widget::text_editor::Content::with_text(&buf);
            dismiss_all_overlays(shell);
            shell.comment = Some((addr, CommentKind::Eol, buf));
            iced::widget::operation::focus(DIALOG_INPUT_ID)
        }
        Message::CommentEdited(t) => {
            if let Some((_, _, buf)) = &mut shell.comment {
                *buf = t;
            }
            Task::none()
        }
        Message::CommentEditorAction(action) => {
            shell.comment_editor.perform(action);
            if let Some((_, _, buf)) = &mut shell.comment {
                *buf = shell.comment_editor.text();
            }
            Task::none()
        }
        Message::CommentKindPicked(k) => {
            if let Some((addr, _, _)) = shell.comment.as_ref() {
                let addr = *addr;
                let kind = views::comment_kind_idx(k);
                let buf =
                    shell.with(|s| s.get_comment_kind(addr, kind).cloned().unwrap_or_default());
                shell.comment_editor = iced::widget::text_editor::Content::with_text(&buf);
                shell.comment = Some((addr, kind, buf));
            }
            Task::none()
        }
        Message::CommentConfirm => {
            if let Some((addr, kind, buf)) = shell.comment.take() {
                shell.with(|s| {
                    let old = s.get_comment_kind(addr, kind).cloned();
                    if buf.is_empty() {
                        s.set_comment_kind(addr, kind, None);
                    } else {
                        s.set_comment_kind(addr, kind, Some(buf));
                    }
                    let new = s.get_comment_kind(addr, kind).cloned();
                    if old != new {
                        s.annotation_undo
                            .push(crate::gui::AnnotationChange::Comment {
                                addr,
                                kind,
                                old,
                                new,
                            });
                    }
                });
            }
            Task::none()
        }
        Message::CommentDelete => {
            if let Some((addr, kind, _)) = shell.comment.take() {
                shell.with(|s| {
                    let old = s.get_comment_kind(addr, kind).cloned();
                    s.set_comment_kind(addr, kind, None);
                    if old.is_some() {
                        s.annotation_undo
                            .push(crate::gui::AnnotationChange::Comment {
                                addr,
                                kind,
                                old,
                                new: None,
                            });
                    }
                });
            }
            Task::none()
        }
        Message::CommentCancel => {
            shell.comment = None;
            Task::none()
        }

        Message::BookmarkRequest(addr) => {
            dismiss_all_overlays(shell);
            shell.bookmark = Some((addr, BookmarkKind::Note, String::new()));
            iced::widget::operation::focus(DIALOG_INPUT_ID)
        }
        Message::BookmarkEdited(t) => {
            if let Some((_, _, buf)) = &mut shell.bookmark {
                *buf = t;
            }
            Task::none()
        }
        Message::BookmarkKindPicked(k) => {
            if let Some((_, kind, _)) = &mut shell.bookmark {
                *kind = views::bookmark_kind_idx(k);
            }
            Task::none()
        }
        Message::BookmarkConfirm => {
            if let Some((addr, kind, buf)) = shell.bookmark.take() {
                let note = if buf.trim().is_empty() {
                    format!("BM {addr:#x}")
                } else {
                    buf.trim().to_string()
                };
                shell.with(|s| {
                    let bm = crate::gui::Bookmark { addr, note, kind };
                    let old = s.bookmarks.iter().find(|b| b.addr == addr).cloned();
                    let new = Some(bm.clone());
                    let (_, _) = s.transact(ProgramEvent::Bookmark(addr), |st| {
                        st.bookmarks.retain(|b| b.addr != addr);
                        st.bookmarks.push(bm);
                    });
                    s.annotation_undo
                        .push(crate::gui::AnnotationChange::Bookmark { addr, old, new });
                });
            }
            Task::none()
        }
        Message::BookmarkCancel => {
            shell.bookmark = None;
            Task::none()
        }

        Message::Undo => {
            shell.with(|s| {
                if let Some(desc) = s.undo_annotation() {
                    s.status_msg = format!("Undid {desc}");
                }
            });
            Task::none()
        }
        Message::Redo => {
            shell.with(|s| {
                if let Some(desc) = s.redo_annotation() {
                    s.status_msg = format!("Redid {desc}");
                }
            });
            Task::none()
        }

        Message::TypeKindPicked(k) => {
            dismiss_all_overlays(shell);
            shell.type_kind = k.min(4);
            shell.show_type_dialog = true;
            iced::widget::operation::focus(DIALOG_INPUT_ID)
        }
        Message::TypeNameEdited(t) => {
            shell.type_name = t;
            Task::none()
        }
        Message::TypeCreate => {
            let (kind, name) = (shell.type_kind, shell.type_name.trim().to_string());
            if !name.is_empty() {
                shell.with(|s| {
                    let res = match kind {
                        1 => s.types.create_union(&name),
                        2 => s.types.create_enum(&name, crate::type_system::ID_INT),
                        3 => s.types.create_typedef(&name, crate::type_system::ID_INT),
                        4 => s.types.create_function_sig(
                            &name,
                            crate::type_system::ID_VOID,
                            Vec::new(),
                            "unknown",
                            false,
                        ),
                        _ => s.types.create_struct(&name),
                    };
                    match res {
                        Ok(id) => s.status_msg = format!("Created '{name}' (id {id})"),
                        Err(e) => s.status_msg = e,
                    }
                });
                shell.type_name.clear();
                shell.show_type_dialog = false;
            }
            Task::none()
        }
        Message::TypeCancel => {
            shell.show_type_dialog = false;
            Task::none()
        }
        Message::TypeExport => {
            shell.with(|s| {
                let mut out = String::new();
                for (id, _) in s.types.all() {
                    out.push_str(&s.types.to_c_decl(id, 0));
                    out.push('\n');
                }
                eprintln!("=== DATA TYPES ===\n{out}");
                s.status_msg = format!("Exported {} type declarations (stderr)", s.types.len());
            });
            Task::none()
        }

        _ => Task::none(),
    }
}
