use super::*;
use crate::disasm::{DisasmInstruction, InsnBytes};

fn di(addr: u64) -> DisasmInstruction {
    DisasmInstruction {
        address: addr,
        bytes: InsnBytes::from_slice(&[0x90]),
        mnemonic: "nop",
        operands: "".into(),
    }
}

fn state_with_disasm() -> AppState {
    let mut s = AppState::new();
    s.disasm = Some(crate::disasm::DisasmResult {
        instructions: std::sync::Arc::new(vec![di(0x1000), di(0x1001), di(0x1002)]),
        arch: "x86_64".into(),
    });
    s
}

#[test]
fn goto_records_only_found_addresses_with_cap() {
    let mut s = state_with_disasm();
    goto_address(&mut s, 0x1001);
    assert_eq!(s.history, vec![0x1001]);
    assert_eq!(s.scroll_request, Some(1));
    goto_address(&mut s, 0xDEAD);
    assert_eq!(s.history, vec![0x1001]);
    for i in 0..600u64 {
        s.navigating = false;
        goto_address(&mut s, if i % 2 == 0 { 0x1000 } else { 0x1002 });
    }
    assert!(s.history.len() <= 500, "len {}", s.history.len());
    assert_eq!(s.history_idx, s.history.len() - 1);
}

#[test]
fn goto_back_forward_roundtrip() {
    let mut s = state_with_disasm();
    goto_address(&mut s, 0x1000);
    goto_address(&mut s, 0x1002);
    history_back(&mut s);
    assert_eq!(s.history_idx, 0);
    assert_eq!(s.scroll_request, Some(0));
    history_forward(&mut s);
    assert_eq!(s.history_idx, 1);
    assert_eq!(s.scroll_request, Some(2));
    history_back(&mut s);
    goto_address(&mut s, 0x1001);
    assert_eq!(s.history, vec![0x1000, 0x1001]);
}

#[test]
fn toggle_breakpoint_validates_insn_start() {
    let mut s = state_with_disasm();
    toggle_breakpoint(&mut s, 0x1001);
    assert_eq!(s.debug_state.breakpoints.len(), 1);
    toggle_breakpoint(&mut s, 0xBEEF);
    assert_eq!(s.debug_state.breakpoints.len(), 1);
    assert!(s.status_msg.contains("Not an instruction"));
    toggle_breakpoint(&mut s, 0x1001);
    assert!(s.debug_state.breakpoints.is_empty());
}

#[test]
fn toggle_breakpoint_detached_records_placeholder() {
    let mut s = state_with_disasm();
    assert!(!s.debug_state.is_attached);
    toggle_breakpoint(&mut s, 0x1000);
    assert_eq!(s.debug_state.breakpoints[0].original_byte, 0);
    assert!(
        s.pending_bp_arm.is_none(),
        "detached toggle must not queue arm"
    );
}

#[test]
fn poll_bp_arm_materializes_record() {
    let mut s = state_with_disasm();
    s.pending_bp_arm = Some((7, 0x1000));
    s.debug_state.arm_int3_result = Some((7, Ok(0xAB)));
    poll_bp_arm(&mut s);
    assert!(s.pending_bp_arm.is_none());
    let bp = &s.debug_state.breakpoints[0];
    assert_eq!((bp.address, bp.original_byte), (0x1000, 0xAB));
    s.pending_bp_arm = Some((8, 0x1001));
    s.debug_state.arm_int3_result = Some((9, Ok(0xCC)));
    poll_bp_arm(&mut s);
    assert_eq!(s.debug_state.breakpoints.len(), 1);
    assert!(s.pending_bp_arm.is_some());
}

#[test]
fn reset_clears_new_annotation_maps() {
    let mut s = state_with_disasm();
    s.set_comment_kind(0x1, CommentKind::Plate, Some("p".into()));
    s.set_label(0x2, "l".into(), SourceType::Analysis);
    s.function_tags.insert(0x3, vec!["t".into()]);
    s.annotation_undo.push(AnnotationChange::Tag {
        addr: 0x3,
        tag: "t".into(),
        added: true,
    });
    reset_program_scoped_state(&mut s);
    assert!(s.comments_ex.is_empty());
    assert!(s.label_sources.is_empty());
    assert!(s.function_tags.is_empty());
    assert_eq!(s.annotation_undo.undo_len(), 0);
}

#[test]
fn fingerprint_sees_content_edits() {
    let mut s = AppState::new();
    s.set_comment_kind(0x1, CommentKind::Eol, Some("aaa".into()));
    let a = db_fingerprint(&s);
    s.set_comment_kind(0x1, CommentKind::Eol, Some("bbb".into()));
    assert_ne!(db_fingerprint(&s), a, "same count, different text");
    s.set_comment_kind(0x2, CommentKind::Pre, Some("x".into()));
    s.function_tags.insert(0x9, vec!["z".into()]);
    let b = db_fingerprint(&s);
    s.function_tags.remove(&0x9);
    assert_ne!(db_fingerprint(&s), b, "tag add/remove visible");
}

#[test]
fn clip_len_saturates() {
    assert_eq!(clip_len(10), 10);
    assert_eq!(clip_len(usize::MAX), i32::MAX);
}

#[test]
fn cancel_aborts_tickless_phase_promptly() {
    use crate::disasm::{DisasmInstruction, InsnBytes};
    let mut s = AppState::new();
    let n = 1_000_000usize;
    let mut insns = Vec::with_capacity(n + 1);
    for i in 0..n {
        insns.push(DisasmInstruction {
            address: 0x1000 + i as u64 * 5,
            bytes: InsnBytes::from_slice(&[0xE8, 0, 0, 0, 0]),
            mnemonic: "call",
            operands: "0x15000".into(),
        });
    }
    insns.push(DisasmInstruction {
        address: 0x1000 + n as u64 * 5,
        bytes: InsnBytes::from_slice(&[0xC3]),
        mnemonic: "ret",
        operands: "".into(),
    });
    s.disasm = Some(crate::disasm::DisasmResult {
        instructions: std::sync::Arc::new(insns),
        arch: "x86_64".into(),
    });
    s.binary = Some(crate::parser::ParsedBinary {
        format: "RAW".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: vec![crate::parser::Section {
            name: ".raw".into(),
            vaddr: 0x1000,
            size: n as u64 * 5 + 1,
            offset: 0,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        }],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: std::sync::Arc::new(vec![0u8; 16]),
        image_base: 0x1000,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        has_rich: false,
        libraries: Vec::new(),
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    });
    run_analysis(&mut s);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut saw_phase = false;
    while std::time::Instant::now() < deadline {
        let phase = s
            .analysis_progress
            .as_ref()
            .and_then(|a| a.lock().ok().map(|g| (g.phase.clone(), g.done)));
        match phase {
            Some((ph, _)) if ph == "Reference Analysis" => {
                saw_phase = true;
                break;
            }
            None => break,
            _ => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    assert!(saw_phase, "worker never reached Reference Analysis");
    if let Some(a) = &s.analysis_progress {
        if let Ok(mut g) = a.lock() {
            g.cancel = true;
        }
    }
    let t0 = std::time::Instant::now();
    while std::time::Instant::now() < deadline {
        poll_analysis(&mut s);
        if s.analysis_progress.is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        s.analysis_progress.is_none(),
        "cancel did not clear the slot in time"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(20),
        "cancel took too long ({:?}) — watcher not arming?",
        t0.elapsed()
    );
    assert!(
        s.analysis.is_none(),
        "cancelled run must not install an analysis"
    );
    assert!(s.status_msg.contains("cancelled"));
}

#[test]
fn poll_analysis_clears_cancelled_run() {
    let mut s = AppState::new();
    let prog = std::sync::Arc::new(std::sync::Mutex::new(AnalysisProgress {
        phase: "x".into(),
        message: "y".into(),
        current: 1,
        total: 13,
        done: true,
        started_at: None,
        result: None,
        cancel: true,
        log: Vec::new(),
    }));
    s.analysis_progress = Some(prog);
    poll_analysis(&mut s);
    assert!(s.analysis_progress.is_none());
    assert!(s.status_msg.contains("cancelled"));
}

#[test]
fn mono_font_advance_is_uniform_and_matches_column_width() {
    use iced::advanced::graphics::text::{cosmic_text, font_system, to_attributes};

    {
        let mut fs = font_system().write().expect("font system");
        fs.raw()
            .db_mut()
            .load_font_data(crate::gui::theme::JBM_400_BYTES.to_vec());
    }
    let advance = |text: &str| -> f32 {
        let mut fs = font_system().write().expect("font system");
        let metrics = cosmic_text::Metrics::new(12.5, 19.0);
        let fs = fs.raw();
        let mut buf = cosmic_text::Buffer::new(fs, metrics);
        buf.set_text(
            fs,
            text,
            &to_attributes(crate::gui::theme::mono_font()),
            cosmic_text::Shaping::Basic,
            None,
        );
        buf.layout_runs()
            .next()
            .map(|run| run.line_w)
            .unwrap_or(-1.0)
    };

    let zero = advance("0");
    let wide = advance("W");
    let narrow = advance("i");
    let space = advance(" ");
    println!(
        "mono advance @12.5px: '0'={zero} 'W'={wide} 'i'={narrow} ' '={space} (MONO_CHAR_W=7.5)"
    );

    assert!(zero > 0.0, "bundled JetBrains Mono failed to load");
    for (name, w) in [("W", wide), ("i", narrow), ("space", space)] {
        assert!(
            (w - zero).abs() < 0.05,
            "'{name}' advance {w} != '0' advance {zero}: JetBrains Mono is not monospaced"
        );
    }
    assert!(
        (zero - 7.5).abs() < 0.5,
        "measured advance {zero} is too far from MONO_CHAR_W=7.5 — column layout is off"
    );
}

#[test]
fn stage1_modal_widget_blocks_background_and_centers_empty_state() {
    use crate::gui::app::Message;
    use iced::advanced::{
        layout,
        widget::{operation, Tree},
        Layout,
    };
    use iced::widget::{button, container, text_input};
    use iced::{Element, Event, Length, Point, Rectangle, Size, Theme};
    let instance = iced::wgpu::Instance::default();
    let adapter = iced::futures::executor::block_on(instance.request_adapter(&Default::default()))
        .expect("wgpu adapter for UI regression test");
    let (device, queue) =
        iced::futures::executor::block_on(adapter.request_device(&Default::default()))
            .expect("wgpu device");
    let engine = iced_wgpu::Engine::new(
        &adapter,
        device,
        queue,
        iced::wgpu::TextureFormat::Bgra8UnormSrgb,
        None,
        iced::advanced::graphics::Shell::headless(),
    );
    let renderer = iced::Renderer::new(engine, iced::Font::DEFAULT, iced::Pixels(13.0));
    let bounds = Size::new(1100.0, 680.0);
    let limits = layout::Limits::new(Size::ZERO, bounds);
    let viewport = Rectangle::with_size(bounds);

    let mut empty = views::empty_state("Empty".into(), "Body".into());
    let mut tree = Tree::new(empty.as_widget());
    let node = empty.as_widget_mut().layout(&mut tree, &renderer, &limits);
    assert_eq!(node.size(), bounds);
    let content = node.children().first().unwrap().bounds();
    assert!((content.center_y() - bounds.height / 2.0).abs() < 1.0);

    let base: Element<'_, Message> = text_input("background", "")
        .id("background-input")
        .on_input(Message::GoEdited)
        .width(Length::Fill)
        .into();
    let mut base = base;
    let mut base_tree = Tree::new(base.as_widget());
    let base_node = base
        .as_widget_mut()
        .layout(&mut base_tree, &renderer, &limits);
    base.as_widget_mut().operate(
        &mut base_tree,
        Layout::new(&base_node),
        &renderer,
        &mut operation::focusable::focus::<()>("background-input".into()),
    );
    let mut inert = widgets::inert(base);
    let key = Event::Keyboard(iced::keyboard::Event::KeyPressed {
        key: iced::keyboard::Key::Character("a".into()),
        modified_key: iced::keyboard::Key::Character("a".into()),
        physical_key: iced::keyboard::key::Physical::Unidentified(
            iced::keyboard::key::NativeCode::Unidentified,
        ),
        location: iced::keyboard::Location::Standard,
        modifiers: iced::keyboard::Modifiers::empty(),
        text: Some("a".into()),
        repeat: false,
    });
    let mut messages = Vec::new();
    let mut clipboard = iced::advanced::clipboard::Null;
    inert.as_widget_mut().update(
        &mut base_tree,
        &key,
        Layout::new(&base_node),
        iced::mouse::Cursor::Unavailable,
        &renderer,
        &mut clipboard,
        &mut iced::advanced::Shell::new(&mut messages),
        &viewport,
    );
    assert!(
        messages.is_empty(),
        "focused base field must not receive modal keystrokes"
    );

    let base: Element<'_, Message> = container(button("Background").on_press(Message::Analyze))
        .width(Length::Fill)
        .height(Length::Fill)
        .into();
    let card: Element<'_, Message> = container(button("Save").on_press(Message::RenameConfirm))
        .width(200)
        .height(100)
        .into();
    let mut root: Element<'_, Message> = iced::widget::stack![
        widgets::inert(base),
        views::dialogs::modal_layer(card, Message::DismissOverlay)
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .into();
    let mut tree = Tree::new(root.as_widget());
    let node = root.as_widget_mut().layout(&mut tree, &renderer, &limits);
    for (point, event, expected) in [
        (
            Point::new(20.0, 20.0),
            Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left)),
            0,
        ),
        (
            Point::new(455.0, 295.0),
            Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left)),
            1,
        ),
        (
            Point::new(455.0, 295.0),
            Event::Mouse(iced::mouse::Event::ButtonReleased(
                iced::mouse::Button::Left,
            )),
            2,
        ),
        (
            Point::new(20.0, 20.0),
            Event::Mouse(iced::mouse::Event::WheelScrolled {
                delta: iced::mouse::ScrollDelta::Lines { x: 0.0, y: -3.0 },
            }),
            3,
        ),
    ] {
        messages.clear();
        root.as_widget_mut().update(
            &mut tree,
            &event,
            Layout::new(&node),
            iced::mouse::Cursor::Available(point),
            &renderer,
            &mut clipboard,
            &mut iced::advanced::Shell::new(&mut messages),
            &viewport,
        );
        match expected {
            0 => assert!(messages
                .iter()
                .any(|m| matches!(m, Message::DismissOverlay))),
            1 => assert!(messages.is_empty()),
            2 => assert!(messages.iter().any(|m| matches!(m, Message::RenameConfirm))),
            _ => assert!(messages.iter().all(|m| matches!(m, Message::Noop))),
        }
        assert!(!messages.iter().any(|m| matches!(m, Message::Analyze)));
    }
    for theme in [Theme::Dark, Theme::Light] {
        let style = theme::tooltip_style(&theme);
        assert!(style.background.is_some());
        assert!(style.text_color.is_some());
        assert!(style.border.width > 0.0);
    }
}
