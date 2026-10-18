use std::time::Duration;

use iced::alignment::{Horizontal, Vertical};
use iced::widget::{button, column, container, row, scrollable, stack, text, tooltip, Space};
use iced::{Color, Element, Length, Theme};

use crate::gui::app::Message;
use crate::gui::theme::{
    self, acc_c, app_bg_c, dim_c, icon_t, label, label_c, line2_c, line_c, mono_c, mute_c,
    on_acc_c, s1_c, s2_c, switch_off_c, text_c, ui_font, Btn, R_CTRL, R_NAV, T,
};

pub type El<'a> = Element<'a, Message, Theme, iced::Renderer>;

pub fn mix(a: Color, b: Color, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    Color {
        r: a.r + (b.r - a.r) * t,
        g: a.g + (b.g - a.g) * t,
        b: a.b + (b.b - a.b) * t,
        a: a.a + (b.a - a.a) * t,
    }
}

pub fn fade(c: Color, a: f32) -> Color {
    c.scale_alpha(a.clamp(0.0, 1.0))
}

pub fn hairline_h() -> iced::widget::Rule<'static, Theme> {
    iced::widget::rule::horizontal(1).style(|theme: &Theme| iced::widget::rule::Style {
        color: line_c(theme),
        radius: iced::border::Radius::default(),
        fill_mode: iced::widget::rule::FillMode::Full,
        snap: true,
    })
}

pub fn hairline_v() -> iced::widget::Rule<'static, Theme> {
    iced::widget::rule::vertical(1).style(|theme: &Theme| iced::widget::rule::Style {
        color: line_c(theme),
        radius: iced::border::Radius::default(),
        fill_mode: iced::widget::rule::FillMode::Full,
        snap: true,
    })
}

pub fn tip<'a>(content: impl Into<El<'a>>, s: impl Into<String>, pos: tooltip::Position) -> El<'a> {
    tooltip::Tooltip::new(
        content,
        container(
            text(s.into())
                .size(12)
                .font(ui_font(iced::font::Weight::Medium)),
        )
        .padding([6, 10])
        .max_width(260)
        .style(theme::tooltip_style),
        pos,
    )
    .gap(8)
    .padding(0)
    .snap_within_viewport(true)
    .delay(Duration::from_millis(400))
    .into()
}

pub fn btn_fg(kind: Btn, light: bool) -> Color {
    match kind {
        Btn::Primary | Btn::Run => theme::on_acc_c_for_light(light),
        Btn::Bar | Btn::Dial => theme::text_c_for_light(light),
        Btn::Quiet | Btn::Nav => theme::dim_c_for_light(light),
    }
}

pub fn btn<'a>(s: impl Into<String>, kind: Btn, small: bool, on: Option<Message>) -> El<'a> {
    let weight = if matches!(kind, Btn::Primary | Btn::Run) {
        iced::font::Weight::Semibold
    } else {
        iced::font::Weight::Medium
    };
    let h = if small { 26.0 } else { 30.0 };
    let content = container(text(s.into()).size(13).font(ui_font(weight)))
        .height(h)
        .padding([0, if small { 10 } else { 14 }])
        .align_y(Vertical::Center);
    button(content)
        .padding(0)
        .style(kind.style())
        .on_press_maybe(on)
        .into()
}

pub fn btn_icon<'a>(
    paths: &'static str,
    s: impl Into<String>,
    kind: Btn,
    light: bool,
    small: bool,
    on: Option<Message>,
) -> El<'a> {
    let weight = if matches!(kind, Btn::Primary | Btn::Run) {
        iced::font::Weight::Semibold
    } else {
        iced::font::Weight::Medium
    };
    let h = if small { 26.0 } else { 30.0 };
    let content = container(
        row![
            theme::svg_icon(paths, 17.0, btn_fg(kind, light)),
            text(s.into()).size(13).font(ui_font(weight)),
        ]
        .spacing(7)
        .align_y(Vertical::Center),
    )
    .height(h)
    .padding([0, if small { 10 } else { 14 }])
    .align_y(Vertical::Center);
    button(content)
        .padding(0)
        .style(kind.style())
        .on_press_maybe(on)
        .into()
}

pub fn icon_btn<'a>(paths: &'static str, light: bool, tip_s: &'static str, msg: Message) -> El<'a> {
    icon_btn_sized(paths, light, tip_s, msg, 32.0, 18.0)
}

pub fn icon_btn_sized<'a>(
    paths: &'static str,
    light: bool,
    tip_s: &'static str,
    msg: Message,
    side: f32,
    glyph: f32,
) -> El<'a> {
    let b = button(
        container(theme::svg_icon(paths, glyph, theme::dim_c_for_light(light)))
            .width(side)
            .height(side)
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center),
    )
    .padding(0)
    .style(Btn::Nav.style())
    .on_press(msg);
    tip(b, tip_s, tooltip::Position::Bottom)
}

pub fn switch<'a>(t: f32, msg: Message) -> El<'a> {
    let t = t.clamp(0.0, 1.0);
    let knob = container(Space::new())
        .width(14)
        .height(14)
        .style(move |theme: &Theme| {
            let off = if theme::is_light(theme) {
                Color::WHITE
            } else {
                theme::Palette::TEXT_MUTE
            };
            container::Style {
                background: Some(mix(off, on_acc_c(theme), t).into()),
                border: iced::Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: 7.0.into(),
                },
                ..Default::default()
            }
        });
    let track = container(row![Space::new().width(3.0 + 14.0 * t), knob].align_y(Vertical::Center))
        .width(34)
        .height(20)
        .align_y(Vertical::Center)
        .style(move |theme: &Theme| container::Style {
            background: Some(mix(switch_off_c(theme), acc_c(theme), t).into()),
            border: iced::Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 10.0.into(),
            },
            ..Default::default()
        });
    button(track)
        .padding(0)
        .style(|_: &Theme, _| button::Style::default())
        .on_press(msg)
        .into()
}

pub fn chip<'a>(s: impl Into<String>, on: bool) -> El<'a> {
    let s: String = s.into();
    text(s)
        .size(12)
        .font(ui_font(if on {
            iced::font::Weight::Semibold
        } else {
            iced::font::Weight::Normal
        }))
        .style(move |theme: &Theme| text::Style {
            color: Some(if on { text_c(theme) } else { mute_c(theme) }),
        })
        .into()
}

pub fn kbd<'a>(s: impl Into<String>) -> El<'a> {
    container(
        text(s.into())
            .size(11)
            .font(theme::mono_font())
            .style(|theme: &Theme| text::Style {
                color: Some(mute_c(theme)),
            }),
    )
    .padding([1, 5])
    .style(|theme: &Theme| container::Style {
        border: iced::Border {
            color: line_c(theme),
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    })
    .into()
}

pub fn seg<'a>(options: &[&str], active: usize, on_pick: impl Fn(usize) -> Message) -> El<'a> {
    let mut r = row![].spacing(0);
    for (i, name) in options.iter().enumerate() {
        let on = i == active;
        let b = button(
            container(text(name.to_string()).size(13))
                .padding([4, 12])
                .align_y(Vertical::Center),
        )
        .padding(0)
        .style(move |theme: &Theme, status| {
            let hovered = matches!(status, button::Status::Hovered);
            button::Style {
                background: if on { Some(s2_c(theme).into()) } else { None },
                text_color: if on || hovered {
                    text_c(theme)
                } else {
                    dim_c(theme)
                },
                border: iced::Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: 5.0.into(),
                },
                ..Default::default()
            }
        })
        .on_press(on_pick(i));
        r = r.push(b);
    }
    container(r)
        .padding(2)
        .style(|theme: &Theme| container::Style {
            background: Some(app_bg_c(theme).into()),
            border: iced::Border {
                color: line_c(theme),
                width: 1.0,
                radius: R_NAV,
            },
            ..Default::default()
        })
        .into()
}

pub fn tabs<'a>(items: Vec<(String, bool, Message)>) -> El<'a> {
    let mut r = row![].spacing(2);
    for (name, on, msg) in items {
        let underline = container(container(Space::new()).width(Length::Fill).height(2).style(
            move |theme: &Theme| container::Style {
                background: if on { Some(acc_c(theme).into()) } else { None },
                ..Default::default()
            },
        ))
        .padding(theme::pad4(0.0, 8.0, 0.0, 8.0));
        let b = button(
            column![
                container(text(name).size(13))
                    .height(41)
                    .padding([0, 12])
                    .align_y(Vertical::Center),
                underline,
            ]
            .spacing(0),
        )
        .padding(0)
        .style(move |theme: &Theme, status| {
            let hovered = matches!(status, button::Status::Hovered);
            button::Style {
                background: None,
                text_color: if on || hovered {
                    text_c(theme)
                } else {
                    mute_c(theme)
                },
                border: iced::Border::default(),
                ..Default::default()
            }
        })
        .on_press(msg);
        r = r.push(b);
    }
    column![
        container(
            scrollable(r)
                .direction(scrollable::Direction::Horizontal(
                    scrollable::Scrollbar::new()
                        .width(3.0)
                        .scroller_width(3.0)
                        .margin(0.0),
                ))
                .style(theme::scroll_style)
        )
        .height(43)
        .padding(theme::pad4(0.0, 8.0, 0.0, 8.0)),
        hairline_h(),
    ]
    .spacing(0)
    .into()
}

pub fn bar<'a>(title: &str, left: Vec<El<'a>>, right: Vec<El<'a>>) -> El<'a> {
    let mut r = row![label(title.to_string(), T::Strong).size(15)]
        .spacing(12)
        .align_y(Vertical::Center);
    for l in left {
        r = r.push(l);
    }
    r = r.push(Space::new().width(Length::Fill));
    let mut rt = row![].spacing(10).align_y(Vertical::Center);
    for x in right {
        rt = rt.push(x);
    }
    r = r.push(rt);
    column![
        container(r)
            .height(49)
            .width(Length::Fill)
            .padding([0, 22])
            .align_y(Vertical::Center),
        hairline_h(),
    ]
    .spacing(0)
    .into()
}

pub fn empty_page<'a>(
    light: bool,
    icon_paths: &'static str,
    title: String,
    body: String,
    action: Option<(String, Message)>,
) -> El<'a> {
    let mut col = column![
        theme::svg_icon(icon_paths, 34.0, theme::mute_c_for_light(light)),
        Space::new().height(4),
        label(title, T::Strong).size(18),
        label(body, T::Mute),
    ]
    .spacing(6)
    .align_x(Horizontal::Center);
    if let Some((s, msg)) = action {
        col = col.push(Space::new().height(6));
        col = col.push(btn(s, Btn::Primary, false, Some(msg)));
    }
    container(col)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
}

pub fn setting_row<'a>(title: &str, desc: Option<&str>, control: El<'a>, last: bool) -> El<'a> {
    let mut left = column![label_c(
        title.to_string(),
        13.0,
        iced::font::Weight::Medium,
        Color::TRANSPARENT
    )
    .style(|theme: &Theme| text::Style {
        color: Some(text_c(theme))
    })]
    .spacing(2)
    .width(Length::Fill);
    if let Some(d) = desc {
        left = left.push(label(d.to_string(), T::Mute).size(12.5));
    }
    let r = row![left, control].spacing(24).align_y(Vertical::Center);
    let body = container(r).padding([16, 0]).width(Length::Fill);
    if last {
        body.into()
    } else {
        column![body, hairline_h()].spacing(0).into()
    }
}

pub fn value_text<'a>(s: impl Into<String>) -> El<'a> {
    text(s.into())
        .size(13)
        .font(theme::mono_font())
        .style(|theme: &Theme| text::Style {
            color: Some(dim_c(theme)),
        })
        .into()
}

pub fn fade_in<'a>(content: impl Into<El<'a>>, t: f32, bg: fn(&Theme) -> Color) -> El<'a> {
    let content = content.into();
    if t >= 0.999 {
        return content;
    }
    let a = 1.0 - t.clamp(0.0, 1.0);
    let overlay = container(Space::new())
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |theme: &Theme| container::Style {
            background: Some(fade(bg(theme), a).into()),
            ..Default::default()
        });
    stack![content, overlay].into()
}

pub fn fade_in_r<'a>(
    content: impl Into<El<'a>>,
    t: f32,
    bg: fn(&Theme) -> Color,
    radius: iced::border::Radius,
) -> El<'a> {
    let content = content.into();
    if t >= 0.999 {
        return content;
    }
    let a = 1.0 - t.clamp(0.0, 1.0);
    let overlay = container(Space::new())
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |theme: &Theme| container::Style {
            background: Some(fade(bg(theme), a).into()),
            border: iced::Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius,
            },
            ..Default::default()
        });
    stack![content, overlay].into()
}

pub fn live_feed(shell: &crate::gui::app::Shell) -> El<'_> {
    use crate::gui::anim::{progress_delayed, view_ease};
    let events = if shell.ai_feed_paused {
        shell.ai_frozen.clone()
    } else {
        shell.read(|s| {
            s.mcp_call_log
                .iter()
                .rev()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
        })
    };
    let plan = shell.read(|s| s.ai_plan.clone());
    let heading = plan
        .iter()
        .find(|(_, done)| !done)
        .map(|(s, _)| s.clone())
        .unwrap_or_else(|| {
            if shell.ai_feed_paused {
                "Live updates paused".into()
            } else if events.is_empty() {
                "Waiting for the AI client".into()
            } else {
                "Waiting for the next call".into()
            }
        });
    let pulsing = !shell.ai_feed_paused && plan.iter().any(|(_, done)| !done);
    let opacity = if pulsing {
        crate::gui::anim::pulse(shell.now, shell.started)
    } else {
        0.0
    };
    let dot = container(Space::new())
        .width(8)
        .height(8)
        .style(move |t: &Theme| container::Style {
            background: Some(theme::accent(t).scale_alpha(opacity).into()),
            border: iced::Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        });
    let mut feed = column![container(
        column![
            row![label(heading, T::Strong).size(24), dot]
                .spacing(12)
                .align_y(Vertical::Center),
            label(
                if shell.ai_feed_paused {
                    "Paused"
                } else {
                    "Completed calls appear below"
                },
                T::Mute
            )
        ]
        .spacing(5)
    )
    .padding(theme::pad4(0.0, 12.0, 28.0, 12.0))]
    .spacing(0);
    for (step, done) in &plan {
        let row = row![
            theme::svg_path_draw(
                theme::ic::CHECK16,
                14.0,
                if *done { 1.0 } else { 0.0 },
                1.8,
                16.0,
                theme::text_c_for_light(shell.is_light())
            ),
            label(step.clone(), if *done { T::Dim } else { T::Base })
        ]
        .spacing(12)
        .align_y(Vertical::Center);
        feed = feed.push(container(row).height(48).padding([0, 12]));
    }
    for (index, e) in events.iter().enumerate() {
        let (born, stagger) = shell
            .feed_seen
            .get(&e.seq)
            .copied()
            .unwrap_or((shell.now, index));
        let new = stagger == usize::MAX;
        let delay = if new { 0 } else { stagger as u64 * 50 };
        let p = view_ease(progress_delayed(
            shell.now,
            born,
            delay,
            if new { 550 } else { 450 },
        ));
        let check = crate::gui::anim::bezier(
            progress_delayed(shell.now, born, if new { 350 } else { delay + 200 }, 400),
            0.0,
            0.0,
            0.58,
            1.0,
        );
        let open = shell.feed_open.contains(&e.seq);
        let expanded =
            shell
                .anims
                .value(("expand", e.seq), if open { 1.0 } else { 0.0 }, shell.now);
        let rotation =
            shell
                .anims
                .value(("chevron", e.seq), if open { 1.0 } else { 0.0 }, shell.now)
                * 90.0;
        let color = fade(theme::text_c_for_light(shell.is_light()), p);
        let ck = theme::svg_path_draw(theme::ic::CHECK16, 14.0, check, 1.8, 16.0, color);
        let title = label_c(
            format!(
                "{}{}{}",
                e.tool,
                if e.target.is_empty() { "" } else { " " },
                e.target
            ),
            14.0,
            iced::font::Weight::Normal,
            color,
        );
        let time = mono_c(
            e.time_str.clone(),
            12.0,
            fade(theme::mute_c_for_light(shell.is_light()), p),
        );
        let chevron = theme::svg_icon_ex(theme::ic::FW, 24.0, 1.6, rotation, 15.0, color);
        let head = button(
            container(
                row![
                    ck,
                    container(title).width(Length::Fill),
                    time,
                    tip(
                        container(chevron)
                            .width(28)
                            .height(28)
                            .align_x(Horizontal::Center)
                            .align_y(Vertical::Center),
                        if open { "Hide details" } else { "Show details" },
                        tooltip::Position::Bottom
                    )
                ]
                .spacing(12)
                .align_y(Vertical::Center),
            )
            .height(48)
            .padding(theme::pad4(0.0, 10.0, 0.0, 12.0))
            .align_y(Vertical::Center),
        )
        .padding(0)
        .width(Length::Fill)
        .on_press(Message::AiDetailsToggle(e.seq))
        .style(Btn::Quiet.style());
        let mut details = column![].spacing(9);
        for (k, v) in [
            ("Tool", e.tool.clone()),
            ("Arguments", e.target.clone()),
            ("Result", e.summary.clone()),
        ] {
            details = details.push(
                row![
                    container(label(k, T::Mute)).width(96),
                    container(mono_c(
                        v,
                        12.5,
                        if e.is_error {
                            theme::brk_c_for_light(shell.is_light())
                        } else {
                            theme::text_c_for_light(shell.is_light())
                        }
                    ))
                    .width(Length::Fill)
                ]
                .spacing(16),
            );
        }
        if let Some(addr) = e.addr {
            details = details.push(btn(
                format!("Go to {addr:#x}"),
                Btn::Quiet,
                true,
                Some(Message::AiEventGoto(addr)),
            ));
        }
        let details = container(container(details).padding(theme::pad4(4.0, 14.0, 20.0, 44.0)))
            .height(140.0 * expanded)
            .width(Length::Fill)
            .clip(true);
        let card = container(column![head, details]).style(move |t: &Theme| container::Style {
            background: Some(fade(s1_c(t), expanded).into()),
            border: iced::Border {
                radius: theme::R_ROW,
                ..Default::default()
            },
            ..Default::default()
        });
        let row: El<'_> = if new && p < 1.0 {
            container(fade_in_r(card, p, theme::bg, theme::R_ROW))
                .height((48.0 + 8.0) * p)
                .clip(true)
                .into()
        } else {
            container(fade_in_r(card, p, theme::bg, theme::R_ROW))
                .padding(theme::pad4(8.0 * (1.0 - p), 0.0, 8.0, 0.0))
                .into()
        };
        feed = feed.push(row);
    }
    scrollable(
        container(feed)
            .max_width(760)
            .width(Length::Fill)
            .padding(theme::pad4(56.0, 24.0, 40.0, 24.0))
            .center_x(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(theme::scroll_style)
    .into()
}

pub fn close_glyph<'a>() -> El<'a> {
    icon_t(theme::icon::CLOSE, 18.0, T::Dim).into()
}

pub fn mono_fixed<'a>(s: impl Into<String>, size: f32, c: Color) -> El<'a> {
    mono_c(s.into(), size, c).into()
}

pub fn bordered(theme: &Theme, fill: Color, radius: iced::border::Radius) -> container::Style {
    container::Style {
        background: Some(fill.into()),
        border: iced::Border {
            color: line2_c(theme),
            width: 1.0,
            radius,
        },
        ..Default::default()
    }
}

pub fn bg_s1(theme: &Theme) -> Color {
    s1_c(theme)
}

pub fn bg_main(theme: &Theme) -> Color {
    app_bg_c(theme)
}

pub const CTRL: iced::border::Radius = R_CTRL;

#[cfg(test)]
mod render_tests {
    use super::*;
    use crate::gui::app::{update, Shell};
    use crate::gui::state::AppState;
    use iced::advanced::{layout, widget::Tree, Layout};

    #[test]
    fn sketch_widgets_render_and_settings_switch_routes_real_click() {
        let instance = iced::wgpu::Instance::default();
        let adapter =
            iced::futures::executor::block_on(instance.request_adapter(&Default::default()))
                .unwrap();
        let (device, queue) =
            iced::futures::executor::block_on(adapter.request_device(&Default::default())).unwrap();
        let engine = iced_wgpu::Engine::new(
            &adapter,
            device,
            queue,
            iced::wgpu::TextureFormat::Bgra8UnormSrgb,
            None,
            iced::advanced::graphics::Shell::headless(),
        );
        for font in theme::ALL_FONT_BYTES {
            iced::advanced::graphics::text::font_system()
                .write()
                .unwrap()
                .load_font(std::borrow::Cow::Borrowed(font));
        }
        let mut renderer = iced::Renderer::new(
            engine,
            theme::ui_font(iced::font::Weight::Normal),
            iced::Pixels(13.0),
        );
        let mut shell =
            Shell::from_shared(std::sync::Arc::new(std::sync::Mutex::new(AppState::new())));
        shell.show_startup = false;
        shell.now += std::time::Duration::from_secs(1);
        shell.anims.gc(shell.now);
        let bounds = iced::Size::new(1100.0, 680.0);
        let limits = layout::Limits::new(iced::Size::ZERO, bounds);
        let viewport = iced::Rectangle::with_size(bounds);
        for state in 0..9 {
            shell.theme_mode = if state == 4 {
                theme::AppThemeMode::Light
            } else {
                theme::AppThemeMode::Dark
            };
            shell.nav = if state >= 5 {
                crate::gui::app::NAV_DISASM
            } else {
                crate::gui::app::NAV_LIVE
            };
            if state >= 5 {
                shell.with(|s| {
                    if s.binary.is_none() {
                        s.binary = Some(
                            crate::parser::parse_raw_bytes(vec![0x90, 0xc3], 0x1000, "x86_64")
                                .unwrap(),
                        );
                        s.disasm = Some(
                            crate::disasm::disassemble_binary(s.binary.as_ref().unwrap()).unwrap(),
                        );
                    }
                });
                shell.refresh_view_state();
            }
            let theme = crate::gui::app::theme(&shell);
            shell.show_startup = state == 1;
            shell.show_settings_modal = state == 2;
            shell.show_search = state == 6;
            shell.show_import = state == 7;
            shell.show_type_dialog = state == 8;
            if state == 4 {
                shell.toasts.push(
                    shell.now - std::time::Duration::from_secs(1),
                    "Toast",
                    "Rendered toast",
                    theme::ic::INFO,
                    false,
                );
            }
            shell.rename = if state == 3 {
                Some((0x1000, "test".into()))
            } else {
                None
            };
            let mut root = crate::gui::views::workbench_view(&shell);
            let mut tree = Tree::new(root.as_widget());
            let node = root.as_widget_mut().layout(&mut tree, &renderer, &limits);
            assert_eq!(node.size(), bounds);
            fn check(node: &layout::Node, parent: iced::Size) {
                let b = node.bounds();
                assert!(
                    b.x >= -0.01
                        && b.y >= -0.01
                        && b.x + b.width <= parent.width + 1.0
                        && b.y + b.height <= parent.height + 1.0,
                    "child out of parent: {b:?} / {parent:?}"
                );
                for child in node.children() {
                    check(child, b.size());
                }
            }
            if state <= 3 {
                check(&node, bounds);
            }
            root.as_widget().draw(
                &tree,
                &mut renderer,
                &theme,
                &iced::advanced::renderer::Style {
                    text_color: theme::text(&theme),
                },
                Layout::new(&node),
                iced::mouse::Cursor::Unavailable,
                &viewport,
            );
            let rgba = renderer.screenshot(
                &iced::advanced::graphics::Viewport::with_physical_size(
                    iced::Size::new(1100, 680),
                    1.0,
                ),
                theme::shell_c(&theme),
            );
            assert_eq!(rgba.len(), 1100 * 680 * 4);
            assert!(
                rgba.as_chunks::<4>().0.iter().any(|px| px[0] > 150),
                "text/logo must actually render"
            );
            if let Some(dir) = std::env::var_os("RD_UI_CAPTURE_DIR") {
                let dir = std::path::PathBuf::from(dir);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join(format!("view-{state}.rgba")), &rgba).unwrap();
            }
            iced::advanced::Renderer::reset(&mut renderer, viewport);
        }
        let mut widget = switch(1.0, Message::CompactToggled);
        let mut tree = Tree::new(widget.as_widget());
        let node = widget.as_widget_mut().layout(&mut tree, &renderer, &limits);
        assert_eq!(node.size(), iced::Size::new(34.0, 20.0));
        let mut messages = vec![];
        for event in [
            iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left),
            iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left),
        ] {
            widget.as_widget_mut().update(
                &mut tree,
                &iced::Event::Mouse(event),
                Layout::new(&node),
                iced::mouse::Cursor::Available(iced::Point::new(17.0, 10.0)),
                &renderer,
                &mut iced::advanced::clipboard::Null,
                &mut iced::advanced::Shell::new(&mut messages),
                &viewport,
            );
        }
        drop(widget);
        assert!(messages
            .iter()
            .any(|m| matches!(m, Message::CompactToggled)));
        shell.rename = None;
        let old = shell.compact_rows;
        for m in messages {
            let _ = update(&mut shell, m);
        }
        assert_ne!(shell.compact_rows, old);
    }
}
