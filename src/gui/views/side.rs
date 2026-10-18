use iced::widget::{button, column, container, row, scrollable, Space};
use iced::{Element, Length, Theme};

use crate::gui::app::{Message, Shell, SIDE_SCROLL_ID, SIDE_TABS};
use crate::gui::theme::{self, label, mono, T};

pub fn view<'a>(
    shell: &'a Shell,
    _fonts: &'a theme::Fonts,
) -> Element<'a, Message, Theme, iced::Renderer> {
    let tab = shell.side_tab;
    let content: Element<'_, Message, Theme, iced::Renderer> = match SIDE_TABS.get(tab) {
        Some(&"Func") => func_details(shell),
        Some(&"Regs") => regs(shell),
        Some(&"Stack") => stack(shell),
        Some(&"BP") => breakpoints(shell),
        Some(&"Marks") => bookmarks(shell),
        _ => Space::new().height(0).into(),
    };
    scrollable(container(content).padding(16))
        .id(iced::widget::Id::new(SIDE_SCROLL_ID))
        .style(theme::scroll_style)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn card<'a>(
    content: impl Into<Element<'a, Message, Theme, iced::Renderer>>,
) -> Element<'a, Message, Theme, iced::Renderer> {
    let content = content.into();
    column![
        content,
        container(Space::new())
            .width(Length::Fill)
            .height(1)
            .style(|t| iced::widget::container::Style {
                background: Some(theme::line_c(t).into()),
                ..Default::default()
            }),
    ]
    .spacing(14)
    .into()
}

fn h4<'a>(title: &str, count: &str) -> Element<'a, Message, Theme, iced::Renderer> {
    row![
        label(title.to_string(), T::Mute).size(12),
        Space::new().width(Length::Fill),
        label(count.to_string(), T::Mute).size(12),
    ]
    .align_y(iced::alignment::Vertical::Center)
    .into()
}

fn li_row<'a>(
    left: String,
    note: String,
    msg: Option<Message>,
) -> Element<'a, Message, Theme, iced::Renderer> {
    let body = row![
        container(mono(left, T::Base).size(12)).width(Length::Fill),
        container(label(note, T::Mute).size(11)).align_x(iced::alignment::Horizontal::Right),
    ]
    .align_y(iced::alignment::Vertical::Center);
    let b = button(container(body).padding(theme::pad4(5.0, 8.0, 5.0, 8.0)))
        .padding(0)
        .width(Length::Fill)
        .style(|t: &Theme, status| iced::widget::button::Style {
            background: if matches!(status, iced::widget::button::Status::Hovered) {
                Some(theme::s2_c(t).into())
            } else {
                None
            },
            text_color: theme::text_c(t),
            border: iced::Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: 5.0.into(),
            },
            ..Default::default()
        });
    match msg {
        Some(m) => b.on_press(m).into(),
        None => b.into(),
    }
}

fn white_mono<'a>(
    s: String,
    size: f32,
    weight: iced::font::Weight,
) -> iced::widget::Text<'a, Theme, iced::Renderer> {
    iced::widget::text(s)
        .size(size)
        .font(theme::ui_font(weight))
        .style(|t: &Theme| iced::widget::text::Style {
            color: Some(theme::text_c(t)),
        })
}

fn sig<'a>(name: String, rest: String) -> Element<'a, Message, Theme, iced::Renderer> {
    column![
        white_mono(name, 12.0, iced::font::Weight::Medium).font(theme::mono_font()),
        mono(rest, T::Dim).size(12),
    ]
    .spacing(2)
    .into()
}

fn kv_table<'a>(pairs: Vec<(String, String)>) -> Element<'a, Message, Theme, iced::Renderer> {
    let mut col = column![].spacing(5);
    for (k, v) in pairs {
        col = col.push(
            row![
                container(label(k, T::Mute).size(12)).width(Length::Fill),
                container(mono(v, T::Base).size(12)).align_x(iced::alignment::Horizontal::Right),
            ]
            .align_y(iced::alignment::Vertical::Center),
        );
    }
    col.into()
}

fn panel_empty(title: &str, body: &str) -> Element<'static, Message, Theme, iced::Renderer> {
    column![
        label(title.to_string(), T::Strong).size(13),
        label(body.to_string(), T::Mute).size(11.5)
    ]
    .spacing(4)
    .align_x(iced::alignment::Horizontal::Center)
    .into()
}

fn func_details(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let data = shell.read(|s| {
        let Some(a) = &s.analysis else {
            return Err((
                "No analysis".to_string(),
                "Open a file and run the analysis to inspect functions.".to_string(),
            ));
        };
        let Some(cur) = s.selected_func else {
            return Err((
                "No function selected".to_string(),
                "Pick a function in the listing or the Functions tab.".to_string(),
            ));
        };
        let Some(f) = a.functions.iter().find(|f| f.entry == cur) else {
            return Err((
                "Unknown function".to_string(),
                "The selection no longer exists — pick another function.".to_string(),
            ));
        };
        let ver = s.analysis_version;
        let names = {
            let cell = &shell.function_names;
            match &*cell.borrow() {
                Some((v, m)) if *v == ver => m.clone(),
                _ => std::sync::Arc::new(
                    a.functions
                        .iter()
                        .map(|f| (f.entry, f.name.clone()))
                        .collect(),
                ),
            }
        };
        *shell.function_names.borrow_mut() = Some((ver, names.clone()));
        let name_of = |c: u64| {
            names
                .get(&c)
                .cloned()
                .unwrap_or_else(|| format!("sub_{c:X}"))
        };

        let callees: Vec<(u64, String)> = a
            .callees
            .get(&cur)
            .map(|v| v.iter().take(30).map(|&c| (c, name_of(c))).collect())
            .unwrap_or_default();
        let callers: Vec<(u64, String)> = a
            .callers
            .get(&cur)
            .map(|v| v.iter().take(30).map(|&c| (c, name_of(c))).collect())
            .unwrap_or_default();
        let sig_text = a.stack_frames.get(&cur).map(|sf| {
            let params: Vec<String> = sf
                .variables
                .iter()
                .filter(|v| matches!(v.kind, crate::analysis::VarKind::Parameter))
                .map(|v| format!("int64_t {}", v.name))
                .collect();
            if params.is_empty() {
                format!("int64_t {}(void)", f.name)
            } else {
                format!("int64_t {}({})", f.name, params.join(", "))
            }
        });
        let frame_bytes = f.stack_size.max(0) as u64;
        Ok((
            f.name.clone(),
            f.entry,
            f.end - f.entry,
            f.has_frame,
            frame_bytes,
            sig_text,
            callees,
            callers,
        ))
    });
    let Ok((name, entry, size, has_frame, frame_bytes, sig_text, callees, callers)) = data else {
        return match data {
            Err((title, body)) => card(panel_empty(&title, &body)),
            Ok(_) => unreachable!(),
        };
    };
    let sig_card = card(match sig_text {
        Some(s) => Element::<Message, Theme, iced::Renderer>::from(sig(name.clone(), s)),
        None => Element::new(white_mono(name.clone(), 13.0, iced::font::Weight::Medium)),
    });
    let kv_card = card(kv_table(vec![
        ("Address".into(), format!("{entry:#x}")),
        ("Size".into(), format!("{size} B")),
        (
            "Frame".into(),
            if has_frame {
                format!("{frame_bytes:#x}")
            } else {
                "none".into()
            },
        ),
        ("Convention".into(), "unknown".into()),
    ]));
    let mut col = column![sig_card, kv_card].spacing(14);
    col = col.push(h4("Calls", &callees.len().to_string()));
    if callees.is_empty() {
        col = col.push(label("(none)".to_string(), T::Mute).size(11));
    }
    for (c, n) in &callees {
        col = col.push(li_row(
            n.clone(),
            format!("{c:#x}"),
            Some(Message::RowGoto(*c)),
        ));
    }
    col = col.push(h4("Called by", &callers.len().to_string()));
    if callers.is_empty() {
        col = col.push(label("(none / external)".to_string(), T::Mute).size(11));
    }
    for (c, n) in &callers {
        col = col.push(li_row(
            n.clone(),
            format!("{c:#x}"),
            Some(Message::RowGoto(*c)),
        ));
    }
    col.spacing(10).into()
}

fn regs(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let data = shell.read(|s| {
        if !s.debug_state.is_attached && !s.debug_state.is_running {
            return None;
        }
        Some(s.debug_state.registers.clone())
    });
    let Some(r) = data else {
        return column![label(
            "Not attached. Values appear while debugging.".to_string(),
            T::Mute
        )
        .size(12),]
        .into();
    };
    let reg = |name: &str, val: u64| (name.to_string(), format!("{val:016x}"));
    card(kv_table(vec![
        reg("rax", r.rax),
        reg("rbx", r.rbx),
        reg("rcx", r.rcx),
        reg("rdx", r.rdx),
        reg("rsi", r.rsi),
        reg("rdi", r.rdi),
        reg("rbp", r.rbp),
        reg("rsp", r.rsp),
        reg("r8", r.r8),
        reg("r9", r.r9),
        reg("r10", r.r10),
        reg("r11", r.r11),
        reg("r12", r.r12),
        reg("r13", r.r13),
        reg("r14", r.r14),
        reg("r15", r.r15),
        reg("rip", r.rip),
    ]))
}

fn stack(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let data = shell.read(|s| {
        if !s.debug_state.is_attached && !s.debug_state.is_running {
            return None;
        }
        Some((
            s.debug_state.registers.rsp,
            s.debug_state.stack_data.clone(),
        ))
    });
    let Some((rsp, stack_data)) = data else {
        return label(
            "Not attached. Values appear while debugging.".to_string(),
            T::Mute,
        )
        .size(12)
        .into();
    };
    if stack_data.is_empty() {
        return label("No stack data yet.".to_string(), T::Mute)
            .size(12)
            .into();
    }
    let mut col = column![].spacing(0);
    for (i, chunk) in stack_data.chunks(8).enumerate() {
        let addr = rsp + (i * 8) as u64;
        let val = chunk
            .iter()
            .rev()
            .fold(0u64, |acc, &b| (acc << 8) | b as u64);
        col = col.push(li_row(
            format!("{val:016x}"),
            format!("+{:#x}", i * 8),
            Some(Message::CopyAddress(addr)),
        ));
    }
    card(scrollable(col).style(theme::scroll_style))
}

fn breakpoints(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let bps: Vec<(u64, String, bool)> = shell.read(|s| {
        s.debug_state
            .breakpoints
            .iter()
            .map(|b| (b.address, b.kind.as_str().to_string(), b.enabled))
            .collect()
    });
    if bps.is_empty() {
        return label(
            "Click a gutter dot in the listing to arm one.".to_string(),
            T::Mute,
        )
        .size(12)
        .into();
    }
    let mut col = column![].spacing(0);
    for (addr, kind, enabled) in bps {
        col = col.push(li_row(
            format!("{addr:012x} [{kind}]"),
            if enabled { "on".into() } else { "off".into() },
            Some(Message::RowGoto(addr)),
        ));
    }
    card(col)
}

fn bookmarks(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let bms: Vec<(u64, String)> = shell.read(|s| {
        s.bookmarks
            .iter()
            .map(|b| (b.addr, b.note.clone()))
            .collect()
    });
    let mut col = column![].spacing(0);
    col = col.push(
        button(
            container(
                row![
                    theme::icon(theme::icon::ADD, 13.0, theme::mute_c_for_light(false)),
                    label("Add Current", T::Base),
                ]
                .spacing(4)
                .align_y(iced::alignment::Vertical::Center),
            )
            .padding(theme::pad4(5.0, 8.0, 5.0, 8.0)),
        )
        .padding(0)
        .width(Length::Fill)
        .style(|t: &Theme, status| iced::widget::button::Style {
            background: if matches!(status, iced::widget::button::Status::Hovered) {
                Some(theme::s2_c(t).into())
            } else {
                None
            },
            text_color: theme::text_c(t),
            border: iced::Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: 5.0.into(),
            },
            ..Default::default()
        })
        .on_press_maybe(
            shell
                .read(|s| s.selected_insn.or(s.selected_func))
                .map(Message::BookmarkRequest),
        ),
    );
    if bms.is_empty() {
        col = col.push(
            label(
                "Bookmark the current address to pin it here.".to_string(),
                T::Mute,
            )
            .size(12),
        );
    }
    for (addr, note) in bms {
        col = col.push(li_row(
            note,
            format!("{addr:012x}"),
            Some(Message::RowGoto(addr)),
        ));
    }
    card(col)
}
