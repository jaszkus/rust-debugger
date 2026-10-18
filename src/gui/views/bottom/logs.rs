use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Color, Element, Length, Theme};

use super::super::empty_state;
use super::table_tokens;
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, mono, Btn, T};
use crate::mcp::tools::activity::{McpCallEvent, McpCallKind};

const LOG_FILTERS: &[(usize, &str)] = &[
    (0, "All"),
    (1, "Reads"),
    (2, "Writes"),
    (3, "Runtime"),
    (4, "Errors"),
];

pub(crate) fn log_kind_match(filter: usize, kind: McpCallKind, is_err: bool) -> bool {
    match filter {
        0 => true,
        1 => kind == McpCallKind::Read,
        2 => kind == McpCallKind::Write,
        3 => kind == McpCallKind::Exec,
        4 => is_err,
        _ => true,
    }
}

pub(crate) fn badge<'a>(
    kind: &str,
    is_err: bool,
    t: crate::gui::theme::Tokens,
) -> Element<'a, Message, Theme, iced::Renderer> {
    let (bg, fg) = if is_err {
        (t.brk.scale_alpha(0.12), t.brk)
    } else {
        match kind {
            "write" => (t.annot.scale_alpha(0.15), t.annot),
            "exec" => (t.select, t.link),
            _ => (t.hover, t.dim),
        }
    };
    container(mono(kind.to_string(), T::Base).size(11))
        .padding([2, 7])
        .style(move |_| iced::widget::container::Style {
            background: Some(bg.into()),
            border: iced::Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: iced::border::Radius {
                    top_left: 5.0,
                    top_right: 5.0,
                    bottom_right: 5.0,
                    bottom_left: 5.0,
                },
            },
            text_color: Some(fg),
            ..Default::default()
        })
        .into()
}

const LOG_PAGE: usize = 100;

const LOG_COLS: [Length; 5] = [
    Length::Fixed(64.0),
    Length::Fixed(64.0),
    Length::Fixed(200.0),
    Length::Fixed(240.0),
    Length::Fill,
];
const LOG_GAP: f32 = 12.0;

pub fn ai_logs_view(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let filter = shell.ai_log_filter;
    let t = table_tokens(shell);
    let (events, total) = shell.read(|s| {
        let v: Vec<McpCallEvent> = s.mcp_call_log.iter().rev().cloned().collect();
        let total = s.mcp_call_log.len();
        (v, total)
    });
    let rows: Vec<McpCallEvent> = events
        .into_iter()
        .filter(|e| log_kind_match(filter, e.kind, e.is_error))
        .collect();
    let shown: Vec<McpCallEvent> = rows.into_iter().take(LOG_PAGE).collect();

    let mut seg = row![].spacing(2);
    for (i, name) in LOG_FILTERS {
        seg = seg.push(seg_button(
            name.to_string(),
            *i == filter,
            Message::AiLogFilterPicked(*i),
        ));
    }
    let toolbar = container(
        row![
            container(seg).padding([2, 2]),
            label(format!("{total} actions this session"), T::Mute).size(12),
            row![].width(Length::Fill),
            button(label("Clear", T::Dim).size(12))
                .style(Btn::Bar.style_fn2())
                .on_press(Message::AiLogClear),
        ]
        .spacing(14)
        .padding([12, 20])
        .align_y(iced::alignment::Vertical::Center),
    )
    .width(Length::Fill)
    .style(crate::gui::theme::flat_style);

    let body: Element<'_, Message, Theme, iced::Renderer> = if shown.is_empty() {
        empty_state(
            "No entries".to_string(),
            if total == 0 {
                "Nothing logged yet.".to_string()
            } else {
                "Nothing matches this filter.".to_string()
            },
        )
    } else {
        let header = container(
            row![
                container(label("Time".to_string(), T::Mute).size(11.5)).width(LOG_COLS[0]),
                container(label("Type".to_string(), T::Mute).size(11.5)).width(LOG_COLS[1]),
                container(label("Tool".to_string(), T::Mute).size(11.5)).width(LOG_COLS[2]),
                container(label("Target".to_string(), T::Mute).size(11.5)).width(LOG_COLS[3]),
                container(label("Result".to_string(), T::Mute).size(11.5)).width(LOG_COLS[4]),
            ]
            .spacing(LOG_GAP)
            .align_y(iced::alignment::Vertical::Center),
        )
        .padding([9, 20])
        .width(Length::Fill)
        .style(crate::gui::theme::flat_style);
        let mut col: iced::widget::Column<'_, Message, Theme, iced::Renderer> =
            column![].spacing(0);
        for ev in &shown {
            let result_el: Element<'_, Message, Theme, iced::Renderer> = if ev.is_error {
                text(ev.summary.clone()).size(12).color(t.brk).into()
            } else {
                label(ev.summary.clone(), T::Dim).size(12).into()
            };
            let inner = row![
                container(mono(ev.time_str.clone(), T::Dim).size(12)).width(LOG_COLS[0]),
                container(badge(ev.kind.label(), ev.is_error, t)).width(LOG_COLS[1]),
                container(mono(ev.tool.clone(), T::Base).size(12)).width(LOG_COLS[2]),
                container(mono(ev.target.clone(), T::Dim).size(12)).width(LOG_COLS[3]),
                container(result_el).width(LOG_COLS[4]),
            ]
            .spacing(LOG_GAP)
            .align_y(iced::alignment::Vertical::Center);
            let padded = container(inner).padding([9, 20]).width(Length::Fill);
            let row_btn: Element<'_, Message, Theme, iced::Renderer> = match ev.addr {
                Some(a) => button(padded)
                    .style(Btn::Quiet.style_fn2())
                    .on_press(Message::AiEventGoto(a))
                    .width(Length::Fill)
                    .into(),
                None => button(padded)
                    .style(Btn::Quiet.style_fn2())
                    .width(Length::Fill)
                    .into(),
            };
            col = col.push(row_btn);
            let hairline: Element<'_, Message, Theme, iced::Renderer> =
                container(iced::widget::Space::new())
                    .width(Length::Fill)
                    .height(1)
                    .style(|theme: &Theme| iced::widget::container::Style {
                        background: Some(crate::gui::theme::line_c(theme).into()),
                        ..Default::default()
                    })
                    .into();
            col = col.push(hairline);
        }
        if total > shown.len() && filter == 0 {
            col = col.push(
                container(
                    label(
                        format!("showing latest {} of {total}", shown.len()),
                        T::Mute,
                    )
                    .size(11),
                )
                .padding([8, 20]),
            );
        }
        let rows: Element<'_, Message, Theme, iced::Renderer> = scrollable(col)
            .style(crate::gui::theme::scroll_style)
            .into();
        column![
            header,
            iced::widget::rule::horizontal(1).style(|theme| iced::widget::rule::Style {
                color: crate::gui::theme::line_c(theme),
                radius: iced::border::Radius::default(),
                fill_mode: iced::widget::rule::FillMode::Full,
                snap: true,
            }),
            rows,
        ]
        .spacing(0)
        .into()
    };

    let _ = toolbar;
    body
}

pub fn seg_button<'a>(
    name: String,
    active: bool,
    msg: Message,
) -> Element<'a, Message, Theme, iced::Renderer> {
    let inner = container(label(name, if active { T::Strong } else { T::Dim }).size(11.5))
        .padding([3, 8])
        .style(move |theme: &Theme| {
            if active {
                iced::widget::container::Style {
                    background: Some(crate::gui::theme::hover_c(theme).into()),
                    border: iced::Border {
                        color: Color::TRANSPARENT,
                        width: 0.0,
                        radius: iced::border::Radius {
                            top_left: 5.0,
                            top_right: 5.0,
                            bottom_right: 5.0,
                            bottom_left: 5.0,
                        },
                    },
                    ..Default::default()
                }
            } else {
                iced::widget::container::Style::default()
            }
        });
    button(inner)
        .style(Btn::Quiet.style_fn2())
        .on_press(msg)
        .into()
}
