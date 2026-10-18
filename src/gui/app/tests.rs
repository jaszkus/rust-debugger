use super::*;

mod sketch_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn toast_events_cover_user_action_results() {
        for (msg, title) in [
            ("Undid rename 0x401000", Some("Undo")),
            ("Redid rename 0x401000", Some("Redo")),
            ("Created 'Point' (id 3)", Some("Created")),
            ("Exported 12 type declarations (stderr)", Some("Export")),
            ("Nothing selected to rename", Some("Rename")),
            ("Load a binary first", Some("Hint")),
            ("Choose a raw dump first", Some("Hint")),
            ("Already loading a file", Some("Hint")),
            (
                "Attach: enter a PID via MCP debugger_attach first",
                Some("Hint"),
            ),
            ("Analysis already running", Some("Analysis")),
            ("Target process exited", Some("Debugger")),
            ("BP failed 0x401000: no debugger", Some("Breakpoint")),
            ("Not an instruction start: 0x401001", Some("Breakpoint")),
            ("MCP start failed: port busy", Some("MCP server")),
            ("MCP shared state not initialized", Some("MCP server")),
            ("Decompile failed: oom", Some("Decompile failed")),
            (
                "Save failed; window kept open: disk full",
                Some("Save failed"),
            ),
            ("Settings save failed: disk full", Some("Settings")),
            ("Something failed badly", Some("Error")),
            ("Starting analysis...", None),
            ("Loading foo ...", None),
            ("Load cancelled", None),
            ("Cancelling analysis...", None),
            ("Saving project…", None),
            ("Switched to program 'x'", None),
            ("Stepping over", None),
            ("BP arming 000000401000...", None),
        ] {
            match ToastEvent::parse(msg) {
                ToastEvent::Ignore => assert!(title.is_none(), "{msg} should toast"),
                e => {
                    let (t, _, _, _) = e.render();
                    assert_eq!(Some(t.as_str()), title, "{msg}");
                }
            }
        }
        let (_, _, _, err) = ToastEvent::parse("BP failed 0x1: x").render();
        assert!(err);
        let (_, _, _, err) = ToastEvent::parse("Undid x").render();
        assert!(!err);
    }

    #[test]
    fn removed_controls_have_no_shortcuts_or_commands() {
        for key in [
            Named::F5,
            Named::F7,
            Named::F8,
            Named::F9,
            Named::F10,
            Named::F11,
        ] {
            assert!(handle_key(Key::Named(key), Modifiers::empty()).is_none());
        }
        for key in ["z", "y", "k"] {
            assert!(handle_key(Key::Character(key.into()), Modifiers::CTRL).is_none());
        }
        for key in [Named::ArrowLeft, Named::ArrowRight] {
            assert!(handle_key(Key::Named(key), Modifiers::CTRL).is_none());
        }
        assert!(command_list().iter().all(|(_, m)| !matches!(
            m,
            Message::Analyze
                | Message::Undo
                | Message::Redo
                | Message::HistoryBack
                | Message::HistoryForward
                | Message::DebugRun
                | Message::DebugContinue
                | Message::DebugStepInto
                | Message::DebugStepOver
        )));
    }
    #[test]
    fn automatic_analysis_attempt_is_generation_scoped_even_after_failure() {
        let mut a = AppState::new();
        a.binary = Some(crate::parser::parse_raw_bytes(vec![0xc3], 0x1000, "x86_64").unwrap());
        a.disasm = Some(crate::disasm::disassemble_binary(a.binary.as_ref().unwrap()).unwrap());
        let mut shell = Shell::from_shared(Arc::new(Mutex::new(a)));
        shell.auto_analyze();
        let first = shell.with(|a| a.analysis_progress.clone().unwrap());
        shell.auto_analyze();
        assert!(shell.with(|a| Arc::ptr_eq(&first, a.analysis_progress.as_ref().unwrap())));
        first.lock().unwrap().cancel = true;
        shell.with(|a| a.analysis_progress = None);
        shell.auto_analyze();
        assert!(
            shell.with(|a| a.analysis_progress.is_none()),
            "cancel must not create a retry loop"
        );
        shell.with(|a| {
            a.binary_generation += 1;
            a.analysis = Some(Arc::new(Default::default()));
        });
        shell.auto_analyze();
        assert_eq!(shell.auto_analyzed, Some(1));
        assert!(
            shell.with(|a| a.analysis_progress.is_none()),
            "cached analysis must be reused"
        );
    }
    #[test]
    fn sync_anim_tracks_rail_switches_toasts_and_idle() {
        let mut shell = Shell::from_shared(Arc::new(Mutex::new(AppState::new())));
        shell.show_startup = false;
        shell.now = Instant::now();
        shell.anims = Default::default();
        let before = AnimState::capture(&shell);
        shell.nav = 8;
        shell.with(|a| a.status_msg = "Load error: test".into());
        shell.refresh_view_state();
        sync_anims(&mut shell, before);
        assert!(shell.animating());
        assert!((shell.anims.value(("rail", 0), rail_y(8), shell.now) - rail_y(0)).abs() < 0.1);
        assert_eq!(shell.toasts.list.len(), 1);
        assert!(shell.toasts.list[0].error);
        let id = shell.toasts.list[0].id;
        shell.toasts.dismiss(id, shell.now);
        shell.now += Duration::from_millis(800);
        shell.toasts.tick(shell.now);
        shell.anims.gc(shell.now);
        assert!(!shell.animating());
        assert!(shell.toasts.is_idle());
    }
    #[test]
    fn watcher_emits_changes_but_not_idle_redraws() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use iced::futures::StreamExt;
            let app = Arc::new(Mutex::new(AppState::new()));
            let stream = state_watch(&SharedWatch(app.clone()));
            iced::futures::pin_mut!(stream);
            assert!(matches!(stream.next().await, Some(Message::Tick)));
            assert!(
                tokio::time::timeout(Duration::from_millis(750), stream.next())
                    .await
                    .is_err()
            );
            app.lock().unwrap().status_msg = "changed via MCP".into();
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(1), stream.next())
                    .await
                    .unwrap(),
                Some(Message::Tick)
            ));
        });
    }
}

#[cfg(test)]
mod stage1_tests {
    use super::*;
    use crate::analysis::{AnalysisResult, DetectedFunction, FuncSource};

    fn shell() -> Shell {
        let mut s = AppState::new();
        s.binary =
            Some(crate::parser::parse_raw_bytes(vec![0x90, 0x90, 0xc3], 0x1000, "x86_64").unwrap());
        s.disasm = Some(crate::disasm::disassemble_binary(s.binary.as_ref().unwrap()).unwrap());
        let mut analysis = AnalysisResult::default();
        analysis.functions.push(DetectedFunction {
            entry: 0x1000,
            end: 0x1003,
            name: "test_func".into(),
            has_frame: false,
            stack_size: 0,
            source: FuncSource::EntryPoint,
            is_thunk: false,
            thunk_target: None,
        });
        s.analysis = Some(Arc::new(analysis));
        Shell::from_shared(Arc::new(Mutex::new(s)))
    }

    #[test]
    fn stage1_navigation_reveals_listing_from_every_source() {
        for msg in [
            Message::RowGoto(0x1001),
            Message::FuncPicked(0x1000),
            Message::SearchPicked(0x1001),
            Message::AiEventGoto(0x1001),
            Message::ListingCtxAction(views::CtxAction::Goto, 0x1001),
        ] {
            let mut shell = shell();
            shell.nav = 4;
            let _ = update(&mut shell, msg);
            assert_eq!(shell.nav, NAV_DISASM);
            assert!(shell.with(|s| !s.history.is_empty()));
            assert!(shell.decomp_pending.is_none());
        }
    }

    #[test]
    fn stage1_boot_and_idle_pump_need_no_keyboard_input() {
        let shell = shell();
        assert!(boot_task().units() >= 2);
        assert!(!window_settings().exit_on_close_request);
        assert_eq!(window_settings().min_size, Some(Size::new(1100.0, 680.0)));
        assert_eq!(pump_interval(false).as_millis(), 500);
        assert_eq!(pump_interval(true).as_millis(), 100);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            use iced::futures::StreamExt;
            let mut idle = shell;
            idle.nav = NAV_DISASM;
            let recipes = iced::advanced::subscription::into_recipes(subscription(&idle));
            let streams = recipes
                .into_iter()
                .map(|r| r.stream(Box::pin(iced::futures::stream::pending())));
            let mut stream = iced::futures::stream::select_all(streams);
            let msg = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(msg, Message::Tick));
            idle.with(|s| s.mcp_request_analysis = true);
            let _ = update(&mut idle, msg);
            assert!(!idle.with(|s| s.mcp_request_analysis));
            assert!(idle.with(|s| s.analysis_progress.is_some()));
            idle.with(|s| s.analysis_progress.as_ref().unwrap().lock().unwrap().cancel = true);
        });
    }

    #[test]
    fn stage1_modal_focus_escape_and_shortcut_isolation() {
        let mut shell = shell();
        assert!(update(&mut shell, Message::SearchOpen).units() > 0);
        assert!(shell.show_search);
        assert!(update(&mut shell, Message::Analyze).units() == 0);
        assert!(shell.with(|s| s.analysis_progress.is_none()));
        assert!(update(&mut shell, Message::RenameRequest(0x1000)).units() > 0);
        assert!(!shell.show_search);
        assert!(shell.rename.is_some());
        let escape = handle_key(Key::Named(Named::Escape), Modifiers::empty()).unwrap();
        let _ = update(&mut shell, escape);
        assert!(!shell.has_overlay());
        assert!(handle_key(Key::Character("a".into()), Modifiers::empty()).is_none());
        let _ = update(&mut shell, Message::CommentRequest(0x1000));
        let _ = update(&mut shell, Message::CommentEdited("saved by Enter".into()));
        let _ = update(&mut shell, Message::ConfirmOverlay);
        assert_eq!(
            shell.with(|s| s.comments.get(&0x1000).cloned()),
            Some("saved by Enter".into())
        );
        for msg in [
            Message::BookmarkRequest(0x1000),
            Message::StartupImportOpen,
            Message::SettingsMore,
            Message::SettingsToggle,
        ] {
            let _ = update(&mut shell, msg);
            assert!(shell.has_overlay());
            let _ = update(&mut shell, Message::DismissOverlay);
            assert!(!shell.has_overlay());
        }
    }

    #[test]
    fn stage1_hidden_decompiler_never_requests_work() {
        let mut shell = shell();
        shell.bottom_tab = BOTTOM_TABS.iter().position(|t| *t == "Decompiler").unwrap();
        shell.with(|s| s.selected_func = Some(0x1000));
        shell.bottom_tab = 6;
        for nav in [NAV_DISASM, NAV_LIVE, NAV_LOGS, NAV_DEBUG] {
            shell.nav = nav;
            assert_eq!(refresh_decompile_lines(&mut shell).units(), 0);
            assert!(shell.decomp_pending.is_none());
        }
        shell.nav = NAV_DISASM;
        shell.bottom_tab = BOTTOM_TABS.iter().position(|t| *t == "Decompiler").unwrap();
        assert!(refresh_decompile_lines(&mut shell).units() > 0);
        assert_eq!(
            refresh_decompile_lines(&mut shell).units(),
            0,
            "only one worker may run"
        );
    }

    #[test]
    fn stage1_decompiler_worker_cache_and_stale_result() {
        let mut shell = shell();
        shell.nav = 3;
        shell.bottom_tab = BOTTOM_TABS.iter().position(|t| *t == "Decompiler").unwrap();
        shell.with(|s| s.selected_func = Some(0x1000));
        let analysis = shell.with(|s| s.analysis.clone().unwrap());
        let disasm = shell.with(|s| s.disasm.clone().unwrap());
        let key = (0, 0, 0x1000);
        let _ = refresh_decompile_lines(&mut shell);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let lines = rt
            .block_on(decompile_work(
                key,
                analysis.clone(),
                disasm,
                shell.snap_imports.clone(),
            ))
            .unwrap();
        assert!(!lines.is_empty());
        assert!(
            analysis.pseudocode.is_empty(),
            "shared analysis must stay immutable"
        );
        assert!(Arc::ptr_eq(
            &analysis,
            &shell.with(|s| s.analysis.clone().unwrap())
        ));
        let mut owned_analysis = (*analysis).clone();
        assert_eq!(
            crate::analysis::decompile_on_demand(
                &shell.with(|s| s.disasm.clone().unwrap()),
                &shell.with(|s| s.binary.clone().unwrap()),
                &mut owned_analysis,
                key.2
            ),
            Ok(key.2)
        );
        assert_eq!(
            *lines,
            crate::analysis::decompiler::render_pseudocode(&owned_analysis.pseudocode[&key.2])
        );
        let _ = update(
            &mut shell,
            Message::DecompileFinished(key, Ok(lines.clone())),
        );
        assert!(Arc::ptr_eq(&shell.decomp_lines, &lines));
        assert_eq!(
            refresh_decompile_lines(&mut shell).units(),
            0,
            "cache hit must not enqueue work"
        );
        shell.decomp_pending = Some(key);
        shell.with(|s| s.binary_generation += 1);
        shell.nav = NAV_DISASM;
        shell.decomp_cache.clear();
        let _ = update(&mut shell, Message::DecompileFinished(key, Ok(lines)));
        assert!(
            shell.decomp_cache.is_empty(),
            "foreign-generation results must be rejected"
        );
        assert_ne!(shell.decomp_pending, Some(key));
        assert!(shell.decomp_lines.is_empty());
    }

    #[test]
    fn stage1_parser_snapshot_reuses_arcs_and_reloads_same_path() {
        let mut shell = shell();
        shell.with(|s| s.file_path = "same-path".into());
        shell.refresh_snapshots();
        let old = shell.snap_sections.clone();
        for _ in 0..20 {
            shell.refresh_snapshots();
        }
        assert!(Arc::ptr_eq(&old, &shell.snap_sections));
        shell.with(|s| {
            s.binary_generation += 1;
            s.binary.as_mut().unwrap().sections[0].vaddr = 0x2000;
        });
        shell.refresh_snapshots();
        assert!(!Arc::ptr_eq(&old, &shell.snap_sections));
        assert_eq!(shell.snap_sections[0].vaddr, 0x2000);
        shell.with(|s| {
            s.binary_generation += 1;
            s.binary = None;
        });
        shell.refresh_snapshots();
        assert!(shell.snap_sections.is_empty());
    }

    #[test]
    fn stage1_snapshot_timing_on_large_string_table() {
        use std::time::Instant;
        let mut shell = shell();
        shell.with(|s| {
            s.binary.as_mut().unwrap().strings = (0..500_000)
                .map(|i| crate::parser::ExtractedString {
                    vaddr: 0x1000 + i,
                    content: format!("representative string {i}"),
                    encoding: crate::parser::StringEncoding::Ascii,
                    score: 1.0,
                })
                .collect();
        });
        let start = Instant::now();
        shell.refresh_snapshots();
        let first = start.elapsed();
        assert_eq!(shell.snap_strings.len(), 500_000);
        let old = shell.snap_strings.clone();
        let start = Instant::now();
        for _ in 0..100 {
            shell.refresh_snapshots();
        }
        let cached = start.elapsed();
        assert!(Arc::ptr_eq(&old, &shell.snap_strings));
        let start = Instant::now();
        for _ in 0..5 {
            shell.with(|s| {
                std::hint::black_box(s.binary.as_ref().unwrap().strings.clone());
            });
        }
        let baseline = start.elapsed() / 5;
        println!("stage1 snapshot 500k strings: first clone={first:?}; old clone per pump={baseline:?}; 100 unchanged pumps={cached:?}");
    }

    fn save_fixture(name: &str) -> (Shell, std::path::PathBuf, String) {
        let mut shell = shell();
        let dir = std::env::temp_dir().join(format!("rd-stage1-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("source.bin");
        std::fs::write(&src, [0x90, 0x90, 0xc3]).unwrap();
        let path = src.to_string_lossy().to_string();
        let db = crate::project::db_path_for(&path);
        std::fs::write(&db, []).unwrap();
        shell.with(|s| {
            s.file_path = path;
            s.set_comment_kind(0x1000, CommentKind::Eol, Some("persistent".into()));
        });
        shell.refresh_snapshots();
        (shell, dir, db)
    }

    #[test]
    fn stage1_shutdown_waits_for_autosave_and_persists_final_snapshot() {
        let (shell, dir, db) = save_fixture("shutdown");
        let (tx, rx) = std::sync::mpsc::channel();
        shell.with(|s| s.db_save_rx = Some(rx));
        let app = shell.app.clone();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_worker = done.clone();
        let worker = std::thread::spawn(move || {
            shutdown(&app).unwrap();
            done_worker.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!done.load(std::sync::atomic::Ordering::SeqCst));
        assert!(
            shell.app.try_lock().is_ok(),
            "disk wait must not hold shared mutex"
        );
        tx.send(true).unwrap();
        worker.join().unwrap();
        let saved = crate::project::load_project_db(&db).expect("valid final project DB");
        assert_eq!(
            saved.annotations.comments.get(&0x1000).map(String::as_str),
            Some("persistent")
        );
        assert!(!shell.with(|s| s.dirty));
        assert!(shell.with(|s| s.debug_state.stop));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stage1_failed_close_keeps_window_open_and_allows_retry() {
        let mut shell = shell();
        assert!(update(&mut shell, Message::CloseRequested).units() > 0);
        assert!(shell.closing);
        assert_eq!(update(&mut shell, Message::CloseRequested).units(), 0);
        let _ = update(&mut shell, Message::CommentRequest(0x1000));
        assert!(shell.comment.is_none());
        let _ = update(
            &mut shell,
            Message::ShutdownFinished(Err("disk full".into())),
        );
        assert!(!shell.closing);
        assert!(shell.with(|s| s.status_msg.contains("disk full")));
        assert!(update(&mut shell, Message::Exit).units() > 0);
    }

    #[test]
    fn stage1_shutdown_write_error_does_not_clear_dirty() {
        let (shell, dir, db) = save_fixture("write-error");
        std::fs::remove_file(&db).unwrap();
        std::fs::create_dir(&db).unwrap();
        assert!(shutdown(&shell.app).is_err());
        assert!(shell.with(|s| s.dirty));
        std::fs::remove_dir(&db).unwrap();
        std::fs::write(&db, []).unwrap();
        shutdown(&shell.app).unwrap();
        assert!(crate::project::load_project_db(&db).is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn workbench_snapshot_stays_readable_during_mcp_lock() {
        let mut shell = shell();
        shell.refresh_view_state();
        let shared = shell.app.clone();
        let guard = shared.lock().unwrap();
        shell.refresh_view_state();
        assert!(shell.read(|s| s.binary.is_some()));
        let view = views::workbench_view(&shell);
        assert!(view.as_widget().size().height == iced::Length::Fill);
        drop(guard);
    }

    #[test]
    fn workbench_import_draft_never_changes_loaded_source() {
        let mut shell = shell();
        shell.with(|s| s.file_path = "original.exe".into());
        let _ = update(&mut shell, Message::StartupImportOpen);
        let _ = update(&mut shell, Message::ImportPicked(Some("dump.raw".into())));
        let _ = update(&mut shell, Message::ImportPathEdited("another.raw".into()));
        let _ = update(&mut shell, Message::ImportCancel);
        assert_eq!(shell.with(|s| s.file_path.clone()), "original.exe");
        assert_eq!(shell.import_path, "another.raw");
    }

    #[test]
    fn workbench_comments_reload_each_flavor_and_keep_multiline() {
        let mut shell = shell();
        shell.with(|s| {
            s.set_comment_kind(0x1000, CommentKind::Eol, Some("eol".into()));
            s.set_comment_kind(0x1000, CommentKind::Plate, Some("line1\nline2".into()));
        });
        let _ = update(&mut shell, Message::CommentRequest(0x1000));
        let _ = update(&mut shell, Message::CommentKindPicked(3));
        assert_eq!(shell.comment.as_ref().unwrap().2, "line1\nline2");
        let _ = update(&mut shell, Message::CommentConfirm);
        assert_eq!(
            shell.with(|s| s.get_comment_kind(0x1000, CommentKind::Eol).cloned()),
            Some("eol".into())
        );
    }

    #[test]
    fn workbench_all_tabs_are_reachable_and_decompiler_is_lazy() {
        let mut shell = shell();
        shell.with(|s| s.selected_func = Some(0x1000));
        for i in 0..BOTTOM_TABS.len() {
            shell.nav = NAV_LIVE;
            let _ = update(&mut shell, Message::BottomTabPicked(i));
            assert_eq!(shell.nav, NAV_DISASM);
            assert_eq!(shell.bottom_tab, i);
        }
        for i in 0..SIDE_TABS.len() {
            let _ = update(&mut shell, Message::SideTabPicked(i));
            assert_eq!(shell.side_tab, i);
        }
    }

    #[test]
    fn workbench_search_is_explicit_hex_and_generation_checked() {
        let mut shell = shell();
        let binary = shell.with(|s| s.binary.clone().unwrap());
        assert!(views::search_snapshot("9090", 0, &binary, None).is_empty());
        let matches = views::search_snapshot("hex:9090", 0, &binary, None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].addr, 0x1000);
        shell.search_epoch = 2;
        let _ = update(&mut shell, Message::SearchFinished(1, 0, matches.clone()));
        assert!(shell.search_rows.is_empty());
        let _ = update(&mut shell, Message::SearchFinished(2, 0, matches));
        assert_eq!(shell.search_rows.len(), 1);
        let _ = update(&mut shell, Message::SearchOpen);
        shell.with(|s| s.search_query = "@1001".into());
        let _ = update(&mut shell, Message::SearchRun);
        assert_eq!(shell.nav, NAV_DISASM);
        assert_eq!(shell.with(|s| s.selected_insn), Some(0x1001));
    }

    #[test]
    fn workbench_layout_ratios_survive_resize() {
        let mut shell = shell();
        shell.side_ratio = 0.25;
        shell.bottom_ratio = 0.35;
        sync_window(&mut shell, Size::new(1680.0, 960.0));
        let original = (shell.side_w, shell.bottom_h);
        sync_window(&mut shell, Size::new(1100.0, 680.0));
        sync_window(&mut shell, Size::new(1680.0, 960.0));
        assert_eq!(original, (shell.side_w, shell.bottom_h));
        let json = serde_json::to_vec(&UiSettings {
            theme: 2,
            compact: true,
            collapsed: true,
            side_ratio: 0.25,
            bottom_ratio: 0.35,
            bottom_tab: 9,
            side_tab: 4,
            show_recent_startup: true,
            restore_last: false,
            confirm_close: true,
            analyze_on_open: true,
            recover_strings: true,
            max_func_size_kb: 64,
            allow_changes: true,
            allow_execution: false,
            ui_scale: 1.1,
        })
        .unwrap();
        let settings: UiSettings = serde_json::from_slice(&json).unwrap();
        assert_eq!(settings.bottom_tab, 9);
        assert!(settings.compact && settings.collapsed);
        assert!((settings.ui_scale - 1.1).abs() < 1e-6);
    }

    #[test]
    fn stage1_idle_ai_poll_runs_autosave() {
        let (mut shell, dir, db) = save_fixture("autosave");
        let _ = update(&mut shell, Message::AiPoll);
        assert!(shell.with(|s| s.db_save_rx.is_some()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while shell.with(|s| s.db_save_rx.is_some()) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
            let _ = update(&mut shell, Message::Tick);
        }
        assert!(crate::project::load_project_db(&db).is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
