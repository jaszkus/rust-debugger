use super::*;

pub fn subscription(shell: &Shell) -> Subscription<Message> {
    let mut subs = Vec::new();
    subs.push(Subscription::run_with(
        SharedWatch(shell.app.clone()),
        state_watch,
    ));
    if shell.show_search && shell.read(|s| s.search_dirty) {
        subs.push(
            iced::time::every(std::time::Duration::from_millis(250)).map(|_| Message::SearchRun),
        );
    }
    {
        let ai_visible = shell.nav == NAV_LIVE || shell.nav == NAV_LOGS;
        let server_on = shell.server_on();
        if server_on && ai_visible {
            subs.push(
                iced::time::every(std::time::Duration::from_millis(500)).map(|_| Message::AiPoll),
            );
        }
    }
    subs.push(iced::event::listen_with(|event, status, _| match event {
        iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
            if key == Key::Named(Named::Escape) {
                Some(Message::DismissOverlay)
            } else if status == iced::event::Status::Ignored {
                handle_key(key, modifiers)
            } else {
                None
            }
        }
        _ => None,
    }));
    subs.push(iced::window::resize_events().map(|(_, size)| Message::WindowResized(size)));
    if matches!(shell.theme_mode, theme::AppThemeMode::System) {
        subs.push(iced::system::theme_changes().map(Message::SystemThemeChanged));
    }
    if shell.animating() {
        subs.push(iced::window::frames().map(|_| Message::AnimationTick));
    }
    if let Some(deadline) = shell.toasts.deadline() {
        subs.push(Subscription::run_with(deadline, toast_wake));
    }
    if std::env::var_os("RD_AUTOSCROLL").is_some() {
        subs.push(
            iced::time::every(std::time::Duration::from_millis(100)).map(|_| Message::AutoScroll),
        );
    }
    subs.push(iced::event::listen_with(
        |event, _status, _id| match event {
            iced::Event::Window(iced::window::Event::CloseRequested) => {
                Some(Message::CloseRequested)
            }
            _ => None,
        },
    ));
    Subscription::batch(subs)
}

pub(crate) fn handle_key(key: Key, mods: Modifiers) -> Option<Message> {
    handle_key_scoped(key, mods, NAV_DEBUG)
}

pub(crate) fn handle_key_scoped(key: Key, mods: Modifiers, _nav: usize) -> Option<Message> {
    let ctrl = mods.control();
    if ctrl {
        return None;
    }
    handle_key_core(key, mods)
}

pub(crate) fn handle_key_core(key: Key, mods: Modifiers) -> Option<Message> {
    let ctrl = mods.control();
    Some(match (key, ctrl) {
        (Key::Named(Named::Escape), _) => Message::DismissOverlay,
        (Key::Named(Named::Enter), _) => Message::ConfirmOverlay,
        (Key::Named(Named::F2), _) => Message::RenameSelected,
        (Key::Character(c), false) if c.eq_ignore_ascii_case("g") => Message::SearchOpen,
        (Key::Character(c), false) if c.eq_ignore_ascii_case("n") => Message::RenameSelected,
        (Key::Character(c), false) if c == ";" => Message::CommentSelected,
        (Key::Character(c), false) if c.eq_ignore_ascii_case("x") => Message::BottomTabPicked(7),
        (Key::Named(Named::Space), false) => Message::BottomTabPicked(9),
        (Key::Character(c), true) if c.eq_ignore_ascii_case("f") => Message::SearchOpen,
        _ => return None,
    })
}

pub(crate) fn window_settings() -> iced::window::Settings {
    iced::window::Settings {
        size: Size::new(1680.0, 960.0),
        min_size: Some(Size::new(1100.0, 680.0)),
        position: iced::window::Position::Centered,
        exit_on_close_request: false,
        icon: theme::logo_window_icon(),
        ..Default::default()
    }
}

pub(crate) fn boot_task() -> Task<Message> {
    let size = iced::window::latest().then(|id| match id {
        Some(id) => iced::window::size(id).map(Message::SyncWindow),
        None => Task::none(),
    });
    Task::batch([size, iced::system::theme().map(Message::SystemThemeChanged)])
}

pub(crate) fn pump_interval(busy: bool) -> std::time::Duration {
    std::time::Duration::from_millis(if busy { 100 } else { 500 })
}

pub(crate) fn pump(shell: &mut Shell) {
    shell.with(|s| {
        poll_load_install(s);
        poll_analysis_install(s);
        autosave_check(s);
    });
    shell.auto_analyze();
    shell.refresh_snapshots();
}

pub(crate) fn sync_window(shell: &mut Shell, size: Size) {
    shell.win_size = size;
    let (w, h) = (size.width, size.height);
    let available = w - theme::RAIL_W - theme::PANEL_GAP;
    shell.side_w = (available * shell.side_ratio).clamp(220.0, (available - 420.0).max(220.0));
    shell.bottom_h = ((h - theme::TOP_H - theme::PANEL_GAP) * shell.bottom_ratio)
        .clamp(120.0, (h - 285.0).max(120.0));
}

pub(crate) fn update(shell: &mut Shell, message: Message) -> Task<Message> {
    match message {
        Message::GoEdited(t) => {
            shell.with(|s| {
                s.goto_addr_buf = t.clone();
                s.search_query = t;
            });
            Task::none()
        }
        Message::GoSubmit => {
            goto_parsed(shell);
            Task::none()
        }
        Message::HistoryBack => {
            shell.with(actions::history_back);
            sync_listing_scroll(shell);
            Task::none()
        }
        Message::HistoryForward => {
            shell.with(actions::history_forward);
            sync_listing_scroll(shell);
            Task::none()
        }

        Message::SearchQueryEdited(q) => {
            shell.search_epoch = shell.search_epoch.wrapping_add(1);
            shell.with(|s| {
                s.search_query = q;
                s.search_dirty = true;
            });
            Task::none()
        }
        Message::SearchKindPicked(k) => {
            shell.search_epoch = shell.search_epoch.wrapping_add(1);
            shell.with(|s| {
                s.search_kind = k;
                s.search_dirty = true;
            });
            Task::none()
        }
        Message::SearchOpen => {
            dismiss_all_overlays(shell);
            shell.show_search = true;
            shell.search_epoch = shell.search_epoch.wrapping_add(1);
            shell.with(|s| {
                s.search_dirty = true;
            });
            iced::widget::operation::focus(DIALOG_INPUT_ID)
        }
        Message::SearchDismissed => {
            shell.show_search = false;
            Task::none()
        }
        Message::SearchPicked(addr) => {
            shell.show_search = false;
            goto_addr(shell, addr);
            Task::none()
        }
        Message::SearchScroll(first) => {
            shell.search_first = first;
            Task::none()
        }
        Message::SearchRun => {
            let query = shell.with(|s| s.search_query.clone());
            if let Some(addr) = query
                .strip_prefix('@')
                .and_then(|q| views::parse_addr_str(q.trim()))
            {
                shell.show_search = false;
                goto_addr(shell, addr);
                Task::none()
            } else {
                start_search(shell)
            }
        }
        Message::SearchFailed(epoch, error) => {
            shell.search_pending = false;
            shell.with(|s| s.status_msg = error);
            if epoch != shell.search_epoch {
                start_search(shell)
            } else {
                Task::none()
            }
        }
        Message::SearchFinished(epoch, generation, results) => {
            shell.search_pending = false;
            if epoch == shell.search_epoch && generation == shell.read(|s| s.binary_generation) {
                shell.search_rows = Arc::new(results);
                shell.search_first = 0;
            }
            start_search(shell)
        }

        Message::FocusSearch => super::update(shell, Message::SearchOpen),

        Message::WindowResized(size) => {
            if size.width > 0.0 && size.height > 0.0 {
                sync_window(shell, size);
            }
            Task::none()
        }
        Message::SyncWindow(size) => {
            if size.width > 0.0 && size.height > 0.0 {
                sync_window(shell, size);
            }
            Task::none()
        }
        Message::AutoScroll => {
            if std::env::var_os("RD_AUTOSCROLL").is_some() {
                shell.listing_first = shell.listing_first.saturating_add(3);
            }
            Task::none()
        }
        Message::Tick => {
            pump(shell);
            Task::none()
        }

        _ => Task::none(),
    }
}
