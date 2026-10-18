use super::*;

impl Shell {
    pub(crate) fn refresh_snapshots(&mut self) {
        let old_path = &self.snap_path;
        let old_generation = self.snap_generation;
        let snapshot = self.with(|s| {
            if old_generation == Some(s.binary_generation) && *old_path == s.file_path {
                return None;
            }
            let path = s.file_path.clone();
            let vectors = match &s.binary {
                Some(b) => (
                    path,
                    Arc::new(b.strings.clone()),
                    Arc::new(b.symbols.clone()),
                    Arc::new(b.imports.clone()),
                    Arc::new(b.exports.clone()),
                    Arc::new(b.sections.clone()),
                ),
                None => (
                    path,
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                    Arc::new(Vec::new()),
                ),
            };
            Some((
                s.binary_generation,
                s.binary.as_ref().map(|b| Arc::new(b.clone())),
                vectors,
            ))
        });
        if let Some((generation, binary, (path, strings, symbols, imports, exports, sections))) =
            snapshot
        {
            self.snap_binary = binary;
            self.snap_generation = Some(generation);
            self.snap_path = path;
            self.snap_strings = strings;
            self.snap_symbols = symbols;
            self.snap_imports = imports;
            self.snap_exports = exports;
            self.snap_sections = sections;
        }
    }
}

pub(crate) fn goto_parsed(shell: &mut Shell) {
    let text = shell.with(|s| s.goto_addr_buf.clone());
    let t = text
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .trim()
        .to_string();
    if let Ok(a) = u64::from_str_radix(&t, 16) {
        goto_addr(shell, a);
    }
}

pub fn goto_addr(shell: &mut Shell, addr: u64) {
    let idx = shell.with(|s| {
        actions::goto_address(s, addr);
        s.selected_insn = Some(addr);
        if let Some(a) = &s.analysis {
            s.selected_func = a
                .functions
                .iter()
                .find(|f| addr >= f.entry && addr < f.end)
                .map(|f| f.entry);
        }
        s.scroll_request.take()
    });
    if let Some(i) = idx {
        shell.listing_first = i;
    }
    shell.nav = NAV_DISASM;
}

pub(crate) fn sync_listing_scroll(shell: &mut Shell) {
    let idx = shell.with(|s| s.scroll_request.take());
    if let Some(i) = idx {
        shell.listing_first = i;
        shell.nav = NAV_DISASM;
    }
}

pub fn refresh_decompile_lines(shell: &mut Shell) -> Task<Message> {
    let visible = !shell.closing
        && !shell.has_overlay()
        && !matches!(shell.nav, NAV_LIVE | NAV_LOGS)
        && BOTTOM_TABS.get(shell.bottom_tab) == Some(&"Decompiler");
    if !visible {
        return Task::none();
    }
    let snapshot = shell.with(|s| {
        Some((
            (s.binary_generation, s.analysis_version, s.selected_func?),
            s.analysis.clone()?,
            s.disasm.clone()?,
        ))
    });
    let Some((key, analysis, disasm)) = snapshot else {
        shell.decomp_key = None;
        shell.decomp_lines = Arc::new(Vec::new());
        return Task::none();
    };
    shell
        .decomp_cache
        .retain(|k, _| (k.0, k.1) == (key.0, key.1));
    if shell.decomp_key != Some(key) {
        shell.decomp_key = Some(key);
        shell.decomp_lines = Arc::new(Vec::new());
        shell.decomp_revision = shell.decomp_revision.wrapping_add(1);
    }
    if let Some(lines) = shell.decomp_cache.get(&key) {
        shell.decomp_lines = lines.clone();
        return Task::none();
    }
    if shell.decomp_pending.is_some() {
        return Task::none();
    }
    shell.refresh_snapshots();
    let imports = shell.snap_imports.clone();
    shell.decomp_pending = Some(key);
    Task::perform(
        decompile_work(key, analysis, disasm, imports),
        move |result| Message::DecompileFinished(key, result),
    )
}

pub(crate) async fn decompile_work(
    key: DecompileKey,
    analysis: Arc<crate::analysis::AnalysisResult>,
    disasm: crate::disasm::DisasmResult,
    imports: Arc<Vec<crate::parser::Import>>,
) -> Result<DecompileLines, String> {
    tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(pc) = analysis.pseudocode.get(&key.2) {
                Ok(Arc::new(crate::analysis::decompiler::render_pseudocode(pc)))
            } else {
                crate::analysis::decompile_snapshot(&disasm, &imports, &analysis, key.2)
                    .map(|(_, _, pc)| Arc::new(crate::analysis::decompiler::render_pseudocode(&pc)))
                    .map_err(|e| format!("function {:#x}: {e}", key.2))
            }
        }))
        .unwrap_or_else(|_| Err(format!("worker panicked at {:#x}", key.2)))
    })
    .await
    .unwrap_or_else(|e| Err(format!("worker failed: {e}")))
}

#[derive(Clone)]
pub(crate) struct AnimState {
    view: (usize, usize, usize),
    mview: (usize, bool),
    modal: u8,
    switches: [bool; 8],
    open: std::collections::HashSet<u64>,
}
impl AnimState {
    pub(crate) fn capture(s: &Shell) -> Self {
        let modal = if s.show_startup {
            1
        } else if s.rename.is_some() {
            2
        } else if s.comment.is_some() {
            3
        } else if s.bookmark.is_some() {
            4
        } else if s.show_import {
            5
        } else if s.show_type_dialog {
            6
        } else if s.show_search {
            7
        } else if s.show_settings_modal {
            8
        } else {
            0
        };
        Self {
            view: (s.nav, s.bottom_tab, s.side_tab),
            mview: (s.settings_tab, s.startup_raw),
            modal,
            switches: [
                s.server_on(),
                s.follow_ai,
                false,
                s.recent_on_startup,
                s.restore_last,
                s.analyze_on_open,
                s.allow_changes,
                s.allow_execution,
            ],
            open: s.feed_open.clone(),
        }
    }
}

pub fn rail_y(nav: usize) -> f32 {
    let group = if nav < 2 {
        0
    } else if nav < 8 {
        1
    } else {
        2
    };
    14.0 + 58.0 + 39.0 * (group + 1) as f32 + 36.0 * nav as f32
}

pub(crate) fn sync_anims(s: &mut Shell, before: AnimState) {
    let after = AnimState::capture(s);
    if before.view != after.view {
        s.anims.start_view(("view", 0), 0.0, 1.0, 300, s.now);
    }
    if before.mview != after.mview {
        s.anims.start_view(("mview", 0), 0.0, 1.0, 300, s.now);
    }
    if before.view.0 != after.view.0 {
        let from = s.anims.value(("rail", 0), rail_y(before.view.0), s.now);
        s.anims
            .start_soft(("rail", 0), from, rail_y(s.nav), 320, s.now);
    }
    if before.modal != after.modal && after.modal != 0 {
        s.anims.start(("modal", 0), 0.0, 1.0, 260, s.now);
        s.anims.start_css(("backdrop", 0), 0.0, 1.0, 200, s.now);
    }
    for i in 0..8 {
        if before.switches[i] != after.switches[i] {
            let from = s.anims.value(
                ("switch", i as u64),
                u8::from(before.switches[i]) as f32,
                s.now,
            );
            s.anims.start_soft(
                ("switch", i as u64),
                from,
                u8::from(after.switches[i]) as f32,
                220,
                s.now,
            );
            if i == 0 && after.switches[i] {
                s.anims.start(("mcp_tick", 0), 0.0, 1.0, 470, s.now);
            }
        }
    }
    for id in before.open.symmetric_difference(&after.open) {
        let from = s.anims.value(
            ("expand", *id),
            if before.open.contains(id) { 1.0 } else { 0.0 },
            s.now,
        );
        s.anims.start_soft(
            ("expand", *id),
            from,
            if after.open.contains(id) { 1.0 } else { 0.0 },
            300,
            s.now,
        );
        let angle = s.anims.value(("chevron", *id), from, s.now);
        s.anims.start_soft(
            ("chevron", *id),
            angle,
            if after.open.contains(id) { 1.0 } else { 0.0 },
            280,
            s.now,
        );
    }
    let events: Vec<u64> = if s.ai_feed_paused {
        s.ai_frozen.iter().map(|e| e.seq).take(40).collect()
    } else {
        s.read(|a| {
            a.mcp_call_log
                .iter()
                .rev()
                .take(40)
                .map(|e| e.seq)
                .collect()
        })
    };
    let entering = before.view.0 != NAV_LIVE && after.view.0 == NAV_LIVE;
    let first = s.feed_seen.is_empty();
    for (i, id) in events.iter().enumerate() {
        if entering || !s.feed_seen.contains_key(id) {
            s.feed_seen
                .insert(*id, (s.now, if first || entering { i } else { usize::MAX }));
            s.anims.start(
                ("feed", *id),
                0.0,
                1.0,
                if first || entering {
                    450 + i as u64 * 50 + 200
                } else {
                    750
                },
                s.now,
            );
        }
    }
    s.feed_seen.retain(|id, _| events.contains(id));
    s.feed_open.retain(|id| events.contains(id));
    let (status, error) = s.read(|a| (a.status_msg.clone(), a.analysis_error.clone()));
    if !status.is_empty() && status != s.last_status {
        let event = ToastEvent::parse(&status);
        if !matches!(event, ToastEvent::Ignore) {
            let (title, body, icon, is_err) = event.render();
            s.toasts.push(s.now, title, body, icon, is_err);
        }
        s.last_status = status;
    }
    if error != s.last_analysis_error {
        if let Some(e) = &error {
            s.toasts
                .push(s.now, "Analysis failed", e.clone(), theme::ic::DIS, true);
        }
        s.last_analysis_error = error;
    }
    s.toasts.tick(s.now);
    s.recent_removals.retain(|(_, _, start)| {
        s.now.saturating_duration_since(*start) < std::time::Duration::from_millis(260)
    });
    s.anims.gc(s.now);
}

impl Shell {
    pub fn animating(&self) -> bool {
        self.anims.active(self.now)
            || self.toasts.animating(self.now)
            || self.read(|s| {
                s.analysis_progress.is_some()
                    || (s.mcp_started_ms.is_some()
                        && s.ai_plan.iter().any(|(_, done)| !done)
                        && self.nav == NAV_LIVE
                        && !self.ai_feed_paused)
            })
    }
    pub fn switch_value(&self, id: u64, on: bool) -> f32 {
        self.anims
            .value(("switch", id), u8::from(on) as f32, self.now)
    }
    pub(crate) fn auto_analyze(&mut self) {
        if !self.analyze_on_open {
            return;
        }
        let attempted = self.auto_analyzed;
        let generation = self.with(|s| {
            if s.pending_load.is_some() || s.binary.is_none() || s.disasm.is_none() {
                return None;
            }
            if attempted != Some(s.binary_generation) {
                if s.analysis.is_none() && s.analysis_progress.is_none() {
                    actions::run_analysis(s);
                }
                return Some(s.binary_generation);
            }
            None
        });
        if let Some(generation) = generation {
            self.auto_analyzed = Some(generation);
        }
    }
}

#[derive(Clone)]
pub(crate) struct SharedWatch(pub(crate) Arc<Mutex<AppState>>);
impl PartialEq for SharedWatch {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for SharedWatch {}
impl std::hash::Hash for SharedWatch {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        std::hash::Hash::hash(&(Arc::as_ptr(&self.0) as usize), h);
    }
}
pub(crate) fn state_watch(shared: &SharedWatch) -> impl iced::futures::Stream<Item = Message> {
    let app = shared.0.clone();
    iced::futures::stream::unfold(
        (app, None, std::time::Instant::now()),
        |(app, mut previous, mut last)| async move {
            loop {
                tokio::time::sleep(pump_interval(previous.is_none())).await;
                let snapshot = app.try_lock().ok().map(|s| {
                    (
                        (
                            s.binary_generation,
                            s.analysis_version,
                            s.modification_number,
                            s.analysis_seq,
                            s.mcp_call_seq,
                            s.status_msg.clone(),
                            s.mcp_request_analysis,
                            s.debug_state.current_rip,
                            s.debug_state.is_running,
                            s.debug_state.is_attached,
                            s.debug_state.breakpoints.len(),
                            (
                                s.mcp_started_ms,
                                s.debug_state
                                    .signal
                                    .mutex
                                    .try_lock()
                                    .map(|g| *g)
                                    .unwrap_or(0),
                            ),
                        ),
                        s.pending_load.is_some()
                            || s.analysis_progress.is_some()
                            || s.pending_bp_arm.is_some()
                            || s.db_save_rx.is_some(),
                    )
                });
                if let Some((key, busy)) = snapshot {
                    let changed = previous.as_ref() != Some(&key);
                    previous = Some(key);
                    if changed || busy || last.elapsed().as_secs() >= 60 {
                        last = std::time::Instant::now();
                        return Some((Message::Tick, (app, previous, last)));
                    }
                }
            }
        },
    )
}

pub(crate) fn toast_wake(
    deadline: &std::time::Instant,
) -> impl iced::futures::Stream<Item = Message> {
    let deadline = *deadline;
    iced::futures::stream::once(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        Message::ToastWake
    })
}

pub fn poll_analysis_install(app: &mut AppState) {
    if app.mcp_request_analysis {
        app.mcp_request_analysis = false;
        if app.analysis_progress.is_none() {
            actions::run_analysis(app);
        }
    }
    let Some(arc) = app.analysis_progress.clone() else {
        return;
    };
    let dead = match arc.try_lock() {
        Ok(g) => {
            g.done
                && g.result.is_none()
                && !g.cancel
                && g.started_at
                    .map(|t| t.elapsed().as_secs() > 10)
                    .unwrap_or(false)
        }
        Err(std::sync::TryLockError::Poisoned(_)) => true,
        Err(std::sync::TryLockError::WouldBlock) => false,
    };
    if dead {
        app.analysis_progress = None;
        app.analysis_error = Some("Analysis worker crashed (see gui log)".into());
        app.analysis_seq = app.analysis_seq.wrapping_add(1);
        app.status_msg = "Analysis crashed".into();
        return;
    }
    let mut take_result = None;
    {
        let mut g = match arc.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if g.done {
            take_result = g.result.take();
        }
    }
    if let Some(r) = take_result {
        let elapsed = arc
            .lock()
            .ok()
            .and_then(|g| g.started_at)
            .map(|t| t.elapsed().as_secs_f32())
            .unwrap_or(0.0);
        app.status_msg = format!(
            "Analysis done in {:.1}s | {} funcs, {} xrefs, {} CFGs, {} decompiled, {} stubs, {} switches",
            elapsed,
            r.functions.len(),
            r.xrefs.all.len(),
            r.cfgs.len(),
            r.pseudocode.len(),
            r.stubs.len(),
            r.switches.len()
        );
        let (_, _) = app.transact(ProgramEvent::AnalysisReplaced, |s| {
            s.analysis = Some(Arc::new(r));
        });
        crate::gui::state::invalidate_analysis_caches(app);
        app.analysis_progress = None;
        app.analysis_error = None;
        app.analysis_seq = app.analysis_seq.wrapping_add(1);
        app.db_last_save_attempt = None;
    } else {
        let (cancelled, timed_out) = arc
            .lock()
            .ok()
            .map(|g| {
                (
                    g.cancel && g.done,
                    !g.cancel
                        && g.started_at
                            .map(|t| t.elapsed().as_secs() > 600)
                            .unwrap_or(false),
                )
            })
            .unwrap_or((false, false));
        if cancelled {
            app.analysis_progress = None;
            app.analysis_error = Some("Analysis cancelled".into());
            app.analysis_seq = app.analysis_seq.wrapping_add(1);
            app.status_msg = "Analysis cancelled".into();
        } else if timed_out {
            app.analysis_progress = None;
            app.analysis_error = Some("Analysis timed out".into());
            app.analysis_seq = app.analysis_seq.wrapping_add(1);
            app.status_msg = "Analysis aborted (timed out)".into();
        }
    }
}

pub fn poll_load_install(app: &mut AppState) {
    let Some(arc) = app.pending_load.clone() else {
        return;
    };
    let done = match arc.try_lock() {
        Ok(g) => g.done,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().done,
        Err(std::sync::TryLockError::WouldBlock) => {
            if let Some(g) = try_lock_recover(&arc) {
                app.status_msg = format!("Loading... ({})", g.phase);
            }
            return;
        }
    };
    if !done {
        if let Some(g) = try_lock_recover(&arc) {
            app.status_msg = format!("Loading... ({})", g.phase);
        }
        return;
    }
    let result = match arc.try_lock() {
        Ok(mut g) => g.result.take(),
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner().result.take(),
        Err(_) => return,
    };
    app.pending_load = None;
    let elapsed = try_lock_recover(&arc)
        .map(|g| g.started_at.elapsed().as_secs_f32())
        .unwrap_or(0.0);
    match result {
        Some(Ok(lp)) => {
            actions::reset_program_scoped_state(app);
            let n_insns = lp.disasm.instructions.len();
            let fmt = lp.bin.format.clone();
            let arch = lp.bin.arch.clone();
            let from_db = lp.analysis.is_some();
            app.file_path = lp.path.clone();
            app.binary = Some(lp.bin);
            app.disasm = Some(lp.disasm);
            if let (Some(a), Some(ann)) = (lp.analysis, lp.annotations) {
                app.analysis = Some(Arc::new(a));
                app.analysis_seq = app.analysis_seq.wrapping_add(1);
                app.analysis_error = None;
                crate::project::apply_annotations(&mut app.program, &ann);
                if let Some(name) = lp.project_name {
                    if !name.is_empty() {
                        app.current_program_name = name;
                    }
                }
                crate::gui::state::invalidate_analysis_caches(app);
            } else {
                app.analysis = None;
                crate::gui::state::invalidate_analysis_caches(app);
            }
            if let Some(name) = app.pending_project_name.take() {
                if !name.is_empty() {
                    app.current_program_name = name;
                }
            }
            touch_recent(app, &lp.path);
            app.db_last_save_attempt = Some(std::time::Instant::now());
            app.status_msg = if from_db {
                format!(
                    "{} | {} insns | loaded from project DB in {:.1}s",
                    lp.path, n_insns, elapsed
                )
            } else {
                format!(
                    "Loaded {} | {} insns | {} {} | {:.1}s",
                    lp.path, n_insns, fmt, arch, elapsed
                )
            };
        }
        Some(Err(e)) => app.status_msg = format!("Load error: {e}"),
        None => app.status_msg = "Load cancelled".into(),
    }
}

pub(crate) fn shutdown(app: &Arc<Mutex<AppState>>) -> Result<(), String> {
    let (autosave, server) = {
        let mut s = app.lock().unwrap_or_else(|p| p.into_inner());
        s.debug_state.stop = true;
        if let Some(progress) = &s.analysis_progress {
            progress.lock().unwrap_or_else(|p| p.into_inner()).cancel = true;
        }
        (s.db_save_rx.take(), s.mcp_server.take())
    };
    if let Some(mut server) = server {
        server.stop();
    }
    if let Some(rx) = autosave {
        let _ = rx.recv();
    }
    let program = {
        let s = app.lock().unwrap_or_else(|p| p.into_inner());
        if s.binary.is_none() || s.disasm.is_none() || s.file_path.is_empty() {
            return Ok(());
        }
        s.program.clone()
    };
    let db = crate::project::resolve_db_path(&program.file_path);
    crate::project::save_project_db(&program, &db)?;
    let mut s = app.lock().unwrap_or_else(|p| p.into_inner());
    if s.file_path == program.file_path && s.modification_number == program.modification_number {
        s.program.mark_saved();
    }
    println!("Project DB saved to {db}");
    Ok(())
}

pub(crate) fn update(shell: &mut Shell, message: Message) -> Task<Message> {
    match message {
        Message::DecompileFinished(key, result) => {
            if shell.decomp_pending == Some(key) {
                shell.decomp_pending = None;
                let current = shell.with(|s| (s.binary_generation, s.analysis_version));
                if (key.0, key.1) == current {
                    let lines = match result {
                        Ok(lines) => lines,
                        Err(e) => {
                            shell.with(|s| s.status_msg = format!("Decompile failed: {e}"));
                            Arc::new(Vec::new())
                        }
                    };
                    if shell.decomp_cache.len() >= 16 {
                        shell.decomp_cache.clear();
                    }
                    shell.decomp_cache.insert(key, lines.clone());
                    if shell.decomp_key == Some(key) {
                        shell.decomp_lines = lines;
                        shell.decomp_revision = shell.decomp_revision.wrapping_add(1);
                    }
                }
            }
            Task::none()
        }
        Message::Noop => Task::none(),
        Message::ToggleBreakpointDebug => {
            let addr = shell.with(|s| s.selected_insn);
            if let Some(a) = addr {
                shell.with(|s| actions::toggle_breakpoint(s, a));
            }
            Task::none()
        }
        Message::DebugRun => {
            shell.with(|s| s.debug_state.start_debug = true);
            Task::none()
        }
        Message::AnimationTick | Message::ToastWake => {
            shell.toasts.tick(shell.now);
            Task::none()
        }
        Message::ToastDismiss(id) => {
            shell.toasts.dismiss(id, shell.now);
            Task::none()
        }
        Message::AiDetailsToggle(id) => {
            if !shell.feed_open.remove(&id) {
                shell.feed_open.insert(id);
            }
            Task::none()
        }

        Message::Analyze => {
            shell.with(actions::run_analysis);
            Task::none()
        }
        Message::CancelAnalysis => {
            shell.with(|s| {
                if let Some(p) = &s.analysis_progress {
                    if let Ok(mut g) = p.try_lock() {
                        g.cancel = true;
                    }
                }
                s.status_msg = "Cancelling analysis...".into();
            });
            Task::none()
        }

        Message::McpToggle => {
            shell.with(actions::toggle_mcp);
            Task::none()
        }
        Message::McpPortEdited(p) => {
            shell.with(|s| s.mcp_port_buf = p);
            Task::none()
        }

        Message::ListingClicked(addr) => {
            shell.with(|s| {
                s.selected_insn = Some(addr);
                if let Some(a) = &s.analysis {
                    if let Some(f) = a.functions.iter().find(|f| addr >= f.entry && addr < f.end) {
                        s.selected_func = Some(f.entry);
                    }
                }
            });
            Task::none()
        }
        Message::ListingOpen(addr) => {
            let target = shell.with(|s| {
                s.disasm.as_ref().and_then(|d| {
                    let pos = d.instructions.partition_point(|x| x.address < addr);
                    d.instructions
                        .get(pos)
                        .filter(|x| x.address == addr)
                        .and_then(|x| views::first_addr_in_operands(&x.ops()))
                })
            });
            if let Some(t) = target {
                goto_addr(shell, t);
            }
            Task::none()
        }
        Message::ListingScroll(first) => {
            shell.listing_first = first;
            Task::none()
        }
        Message::ListingCtxAction(action, addr) => apply_ctx_action(shell, action, addr),
        Message::ListingMenuDismissed | Message::FuncMenuDismissed => Task::none(),
        Message::RowGoto(addr) => {
            goto_addr(shell, addr);
            Task::none()
        }

        Message::FuncPicked(entry) => {
            shell.with(|s| s.selected_func = Some(entry));
            goto_addr(shell, entry);
            Task::none()
        }
        Message::FuncScroll(first) => {
            shell.funcs_first = first;
            Task::none()
        }
        Message::FuncFilterEdited(f) => {
            shell.with(|s| s.func_filter = f);
            Task::none()
        }
        Message::FuncCtxAction(action, addr) => apply_ctx_action(shell, action, addr),
        Message::BottomTabPicked(i) => {
            shell.nav = NAV_DISASM;
            shell.bottom_tab = i.min(BOTTOM_TABS.len() - 1);
            shell.bottom_scroll = 0;
            shell.funcs_first = 0;
            shell.hex_scroll = None;
            Task::none()
        }
        Message::SideTabPicked(i) => {
            shell.side_tab = i.min(SIDE_TABS.len() - 1);
            shell.side_scroll = 0;
            iced::widget::operation::scroll_to(
                SIDE_SCROLL_ID,
                iced::widget::scrollable::AbsoluteOffset {
                    x: 0.0f32,
                    y: 0.0f32,
                },
            )
        }
        Message::BottomScroll(first) => {
            shell.bottom_scroll = first;
            Task::none()
        }
        Message::HexScroll(first) => {
            shell.hex_scroll = first;
            Task::none()
        }
        Message::SideScroll(first) => {
            shell.side_scroll = first.min(SIDE_SCROLL_MAX);
            Task::none()
        }

        Message::NavPicked(i) => {
            shell.nav = i.min(NAV_ITEMS.len() - 1);
            if let Some(tab) = nav_bottom_tab(shell.nav) {
                shell.bottom_tab = tab;
                shell.bottom_scroll = 0;
                shell.funcs_first = 0;
                shell.hex_scroll = None;
            }
            Task::none()
        }
        Message::SidebarToggle => {
            shell.sidebar_collapsed = !shell.sidebar_collapsed;
            Task::none()
        }

        Message::AiPoll => {
            if !shell.ai_feed_paused {
                let seen = shell.ai_last_seen_seq;
                let (seq, fresh, ticking, cursor_rows, cursor) = shell.with(|s| {
                    let mut fresh: Vec<u64> = s
                        .mcp_call_log
                        .iter()
                        .filter(|e| e.seq > seen)
                        .map(|e| e.seq)
                        .collect();
                    if fresh.len() > 20 {
                        fresh.drain(..fresh.len() - 20);
                    }
                    let cursor_rows = s.ai_cursor.and_then(|(a, b)| {
                        let ins = s.disasm.as_ref().map(|d| &d.instructions)?;
                        let r0 = ins.partition_point(|x| x.address < a);
                        let r1 = ins.partition_point(|x| x.address < b);
                        let r0 = r0.min(ins.len().saturating_sub(1));
                        let r1 = r1.max(r0).min(ins.len().saturating_sub(1));
                        Some((r0 as f32, r1 as f32))
                    });
                    (
                        s.mcp_call_seq,
                        fresh,
                        s.mcp_server.is_some(),
                        cursor_rows,
                        s.ai_cursor,
                    )
                });
                shell.ai_last_seen_seq = seq;
                shell.ai_fresh = fresh;
                if ticking {
                    shell.ai_pulse_on = !shell.ai_pulse_on;
                }
                match (shell.ai_cursor_view, cursor_rows) {
                    (_, None) => shell.ai_cursor_view = None,
                    (None, Some(t)) => shell.ai_cursor_view = Some(t),
                    (Some((c0, c1)), Some((t0, t1))) => {
                        let n0 = c0 + (t0 - c0) * 0.25;
                        let n1 = c1 + (t1 - c1) * 0.25;
                        shell.ai_cursor_view = if (n0 - t0).abs() + (n1 - t1).abs() > 0.5 {
                            Some((n0, n1))
                        } else {
                            Some((t0, t1))
                        };
                    }
                }
                if shell.follow_ai && shell.nav == NAV_LIVE {
                    if cursor != shell.ai_cursor_seen {
                        shell.ai_cursor_seen = cursor;
                        if let Some((r0, _)) = cursor_rows {
                            shell.listing_first = (r0 as usize).saturating_sub(4);
                        }
                    }
                } else {
                    shell.ai_cursor_seen = cursor;
                }
            }
            pump(shell);
            Task::none()
        }
        Message::AiFeedPauseToggle => {
            if shell.ai_feed_paused {
                shell.ai_feed_paused = false;
                shell.ai_frozen.clear();
            } else {
                let snap = shell.with(|s| {
                    s.mcp_call_log
                        .iter()
                        .rev()
                        .take(40)
                        .cloned()
                        .collect::<Vec<_>>()
                });
                shell.ai_frozen = snap;
                shell.ai_feed_paused = true;
            }
            Task::none()
        }
        Message::FollowAiToggle => {
            shell.follow_ai = !shell.follow_ai;
            Task::none()
        }
        Message::SystemThemeChanged(mode) => {
            use iced::theme::Mode as M;
            shell.system_dark = Some(!matches!(mode, M::Light));
            Task::none()
        }
        Message::AiLogFilterPicked(i) => {
            shell.ai_log_filter = i.min(4);
            Task::none()
        }
        Message::AiLogClear => {
            shell.with(|s| s.mcp_call_log.clear());
            shell.ai_frozen.clear();
            shell.ai_fresh.clear();
            Task::none()
        }
        Message::AiEventGoto(addr) => {
            shell.with(|s| {
                s.selected_insn = Some(addr);
                if let Some(a) = &s.analysis {
                    if let Some(f) = a.functions.iter().find(|f| addr >= f.entry && addr < f.end) {
                        s.selected_func = Some(f.entry);
                    }
                }
            });
            goto_addr(shell, addr);
            Task::none()
        }

        Message::DebugAttach(_pid) => {
            shell.with(|s| {
                s.status_msg = "Attach: enter a PID via MCP debugger_attach first".into()
            });
            Task::none()
        }
        Message::DebugStepInto => {
            shell.with(|s| s.debug_state.step_into = true);
            Task::none()
        }
        Message::DebugStepOver => {
            shell.with(|s| s.debug_state.step_over = true);
            Task::none()
        }
        Message::DebugContinue => {
            shell.with(|s| s.debug_state.continue_exec = true);
            Task::none()
        }
        Message::DebugStop => {
            shell.with(|s| s.debug_state.stop = true);
            Task::none()
        }

        Message::HexBprEdited(t) => {
            shell.with(|s| {
                if let Ok(n) = t.trim().parse::<usize>() {
                    s.hex_bytes_per_row = n.clamp(4, 64);
                }
            });
            Task::none()
        }

        Message::SplitDrag(drag, horizontal) => {
            let (w, h) = (shell.win_size.width, shell.win_size.height);
            if horizontal {
                shell.bottom_h =
                    (h - theme::PANEL_GAP - drag.pos.y).clamp(120.0, (h - 285.0).max(120.0));
                shell.bottom_ratio =
                    shell.bottom_h / (h - theme::TOP_H - theme::PANEL_GAP).max(1.0);
            } else {
                let available = w - theme::RAIL_W - theme::PANEL_GAP;
                shell.side_w = (w - theme::PANEL_GAP - drag.pos.x)
                    .clamp(220.0, (available - 420.0).max(220.0));
                shell.side_ratio = shell.side_w / available.max(1.0);
            }
            Task::none()
        }

        _ => Task::none(),
    }
}