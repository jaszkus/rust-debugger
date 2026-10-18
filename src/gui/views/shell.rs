use super::{bottom, dialogs, listing, side, startup, toast, ui};
use crate::gui::app::{
    Message, Shell, NAV_DEBUG, NAV_DISASM, NAV_GROUPS, NAV_ITEMS, NAV_LIVE, NAV_LOGS,
};
use crate::gui::theme::{self, ic, label, ui_font, Btn, Fonts, T};
use iced::widget::{button, column, container, row, scrollable, Space};
use iced::{Element, Length, Theme};

pub fn workbench_view(shell: &Shell) -> Element<'_, Message> {
    build(shell, &shell.fonts)
}
pub fn empty_state(title: String, body: String) -> Element<'static, Message> {
    container(
        column![label(title, T::Strong).size(18), label(body, T::Mute)]
            .spacing(6)
            .align_x(iced::alignment::Horizontal::Center),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

pub(crate) fn modal_content(shell: &Shell) -> Option<Element<'_, Message>> {
    if shell.show_startup {
        Some(startup::overlay(shell, &shell.fonts))
    } else if let Some(d) = dialogs::view(shell) {
        Some(d)
    } else if shell.show_settings_modal {
        Some(dialogs::settings_modal(shell))
    } else {
        None
    }
}

fn build<'a>(shell: &'a Shell, fonts: &'a Fonts) -> Element<'a, Message> {
    let panel = container(content_view(shell, fonts))
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(1)
        .style(theme::panel_frame_style);
    let main = column![
        topbar(shell),
        container(panel)
            .padding(theme::pad4(0.0, 10.0, 10.0, 0.0))
            .width(Length::Fill)
            .height(Length::Fill)
    ]
    .width(Length::Fill)
    .height(Length::Fill);
    let base = container(row![sidebar_view(shell), main])
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::shell_style);
    let base: Element<'a, Message> =
        if shell.has_overlay() || shell.closing || shell.modal_dismiss.is_some() {
            crate::gui::widgets::inert(base.into())
        } else {
            base.into()
        };
    let overlay = if shell.closing {
        Some(dialogs::modal_layer(
            container(label("Saving project…", T::Strong))
                .padding(24)
                .style(theme::card_style)
                .into(),
            Message::Noop,
        ))
    } else if let Some((_, ghost)) = &shell.modal_dismiss {
        modal_content(ghost)
    } else {
        modal_content(shell)
    };
    let mut layers = iced::widget::stack![base]
        .width(Length::Fill)
        .height(Length::Fill);
    if let Some(overlay) = overlay {
        layers = layers.push(if shell.modal_dismiss.is_some() {
            crate::gui::widgets::inert(overlay)
        } else {
            overlay
        });
    }
    if let Some(t) = toast::layer(&shell.toasts, shell.now, shell.is_light()) {
        layers = layers.push(t);
    }
    layers.into()
}

const NAV_ICONS: [&str; 9] = [
    ic::LIVE,
    ic::LOGS,
    ic::DIS,
    ic::FN,
    ic::STR,
    ic::IMP,
    ic::XR,
    ic::HX,
    ic::BUG,
];
const TIPS: [&str; 9] = [
    "Watch the AI work in real time",
    "Full history of AI tool calls",
    "Read and annotate code",
    "All functions found in the binary",
    "Text found in the binary",
    "Functions the binary imports",
    "Where an address is referenced",
    "Raw bytes of the file",
    "Run and step through the program",
];
fn sidebar_view(shell: &Shell) -> Element<'_, Message> {
    let name = shell.read(|s| {
        if s.binary.is_none() {
            "No file open".into()
        } else {
            s.current_program_label()
        }
    });
    let brand = button(
        container(
            row![
                theme::logo_svg(26.0, shell.is_light()),
                label(name, T::Strong).size(14)
            ]
            .spacing(10)
            .align_y(iced::alignment::Vertical::Center),
        )
        .padding(8)
        .height(50)
        .align_y(iced::alignment::Vertical::Center),
    )
    .padding(0)
    .width(Length::Fill)
    .style(Btn::Nav.style())
    .on_press(Message::StartupOpen);
    let brand = ui::tip(
        brand,
        "Open or switch project",
        iced::widget::tooltip::Position::Right,
    );
    let mut nav = column![brand, Space::new().height(8)].spacing(0);
    for (group, start, end) in NAV_GROUPS {
        nav = nav.push(
            container(label(*group, T::Mute).size(12))
                .height(39)
                .padding(theme::pad4(16.0, 10.0, 4.0, 10.0)),
        );
        for i in *start..*end {
            let active = i == shell.nav;
            let item = button(
                container(
                    row![
                        theme::svg_icon(
                            NAV_ICONS[i],
                            17.0,
                            if active {
                                theme::acc_c_for_light(shell.is_light())
                            } else {
                                theme::dim_c_for_light(shell.is_light())
                            }
                        ),
                        label(NAV_ITEMS[i], if active { T::Strong } else { T::Dim })
                            .size(13.5)
                            .font(ui_font(if active {
                                iced::font::Weight::Medium
                            } else {
                                iced::font::Weight::Normal
                            })),
                    ]
                    .spacing(11)
                    .align_y(iced::alignment::Vertical::Center),
                )
                .height(34)
                .padding([0, 10])
                .align_y(iced::alignment::Vertical::Center),
            )
            .padding(0)
            .width(Length::Fill)
            .style(Btn::Nav.style())
            .on_press(Message::NavPicked(i));
            nav = nav.push(ui::tip(
                item,
                TIPS[i],
                iced::widget::tooltip::Position::Right,
            ));
            nav = nav.push(Space::new().height(2));
        }
    }
    let y = shell
        .anims
        .value(("rail", 0), crate::gui::app::rail_y(shell.nav), shell.now)
        - 14.0;
    let highlight = container(
        container(Space::new())
            .width(Length::Fill)
            .height(34)
            .style(Btn::nav_active),
    )
    .padding(theme::pad4(y, 0.0, 0.0, 0.0))
    .width(Length::Fill);
    container(
        scrollable(iced::widget::stack![nav].push_under(highlight)).style(theme::scroll_style),
    )
    .width(theme::RAIL_W)
    .height(Length::Fill)
    .padding(theme::pad4(14.0, 12.0, 12.0, 12.0))
    .style(theme::sidebar_style)
    .into()
}

fn topbar(shell: &Shell) -> Element<'_, Message> {
    let progress = shell.read(|s| {
        s.analysis_progress.as_ref().and_then(|p| {
            p.try_lock()
                .ok()
                .map(|g| (g.phase.clone(), g.current as f32 / g.total.max(1) as f32))
        })
    });
    let mut r = row![].spacing(6).align_y(iced::alignment::Vertical::Center);
    if let Some((phase, fraction)) = progress {
        let a = crate::gui::anim::pulse(shell.now, shell.started);
        let light = shell.is_light();
        let dot = container(Space::new())
            .width(8)
            .height(8)
            .style(move |t: &Theme| iced::widget::container::Style {
                background: Some(theme::acc_c(t).scale_alpha(a).into()),
                border: iced::Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            });
        let fill = container(Space::new())
            .width(160.0 * fraction.clamp(0.0, 1.0))
            .height(3)
            .style(move |_| iced::widget::container::Style {
                background: Some(theme::acc_c_for_light(light).into()),
                ..Default::default()
            });
        r = r.push(
            row![
                dot,
                label(phase, T::Dim).size(12),
                container(fill)
                    .width(160)
                    .style(|t| iced::widget::container::Style {
                        background: Some(theme::line_c(t).into()),
                        ..Default::default()
                    }),
                ui::btn("Cancel", Btn::Nav, true, Some(Message::CancelAnalysis))
            ]
            .spacing(10)
            .align_y(iced::alignment::Vertical::Center),
        );
    }
    r = r.push(Space::new().width(Length::Fill));
    let on = shell.server_on();
    let tick = shell
        .anims
        .value(("mcp_tick", 0), if on { 1.0 } else { 0.0 }, shell.now);
    let mut contents = row![
        theme::svg_icon(ic::MCP, 18.0, theme::dim_c_for_light(shell.is_light())),
        label("MCP", T::Dim)
    ]
    .spacing(7)
    .align_y(iced::alignment::Vertical::Center);
    if on {
        contents = contents.push(theme::svg_path_draw(
            ic::TICK16,
            16.0,
            ((tick * 470.0 - 120.0) / 350.0).clamp(0.0, 1.0),
            2.0,
            14.0,
            theme::text_c_for_light(shell.is_light()),
        ));
    }
    let mcp = button(
        container(contents)
            .height(30)
            .padding([0, 14])
            .align_y(iced::alignment::Vertical::Center),
    )
    .padding(0)
    .on_press(Message::McpToggle)
    .style(move |t: &Theme, status| {
        let hover = matches!(status, iced::widget::button::Status::Hovered);
        iced::widget::button::Style {
            background: if on || hover {
                Some(theme::s2_c(t).into())
            } else {
                None
            },
            text_color: theme::dim_c(t),
            border: iced::Border {
                color: if on {
                    theme::line2_c(t)
                } else {
                    theme::line_c(t)
                },
                width: 1.0,
                radius: theme::R_CTRL,
            },
            ..Default::default()
        }
    });
    r = r.push(ui::tip(
        mcp,
        if on {
            "MCP server is running. Click to stop it."
        } else {
            "MCP server is stopped. Click to start it."
        },
        iced::widget::tooltip::Position::Bottom,
    ));
    r = r.push(ui::tip(
        ui::btn_icon(
            ic::COG,
            "Settings",
            Btn::Nav,
            shell.is_light(),
            false,
            Some(Message::SettingsToggle),
        ),
        "Open settings",
        iced::widget::tooltip::Position::Bottom,
    ));
    container(r)
        .height(theme::TOP_H)
        .width(Length::Fill)
        .padding(theme::pad4(0.0, 14.0, 0.0, 8.0))
        .align_y(iced::alignment::Vertical::Center)
        .style(theme::toolbar_style)
        .into()
}

fn empty_of(shell: &Shell) -> Option<Element<'_, Message>> {
    let loaded = shell.read(|s| s.binary.is_some());
    let nav = shell.nav.min(8);
    let (title, body, action) = if nav == NAV_LIVE && !shell.server_on() {
        (
            "MCP server is stopped".into(),
            "Start it, then call a tool from your AI client.".into(),
            Some(("Start MCP server".into(), Message::McpToggle)),
        )
    } else if nav == NAV_LOGS && shell.read(|s| s.mcp_call_log.is_empty()) {
        (
            "No MCP calls recorded yet".into(),
            "Calls from your AI client will show up here.".into(),
            None,
        )
    } else if !loaded {
        (
            if nav == NAV_LIVE {
                "Waiting for a file"
            } else {
                "No file open"
            }
            .into(),
            format!("Open a file to see its {}.", NAV_ITEMS[nav].to_lowercase()),
            Some(("Open file…".into(), Message::StartupOpen)),
        )
    } else {
        return None;
    };
    Some(ui::empty_page(
        shell.is_light(),
        NAV_ICONS[nav],
        title,
        body,
        action,
    ))
}

fn content_view<'a>(shell: &'a Shell, fonts: &'a Fonts) -> Element<'a, Message> {
    if let Some(empty) = empty_of(shell) {
        return container(column![
            ui::bar(NAV_ITEMS[shell.nav], vec![], vec![]),
            empty
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::region_style(theme::bg, theme::R_PANEL))
        .into();
    }
    let body = match shell.nav {
        NAV_LIVE => bottom::ai_live_view(shell, fonts),
        NAV_LOGS => bottom::ai_logs_view(shell),
        NAV_DISASM => return dock_view(shell, fonts),
        NAV_DEBUG => bottom::debug_view(shell),
        _ => bottom::view(shell, fonts),
    };
    let mut right = vec![];
    if shell.nav == NAV_LIVE {
        right.push(ui::chip("Follow AI", false));
        right.push(ui::switch(
            shell.switch_value(1, shell.follow_ai),
            Message::FollowAiToggle,
        ));
        right.push(ui::btn(
            if shell.ai_feed_paused {
                "Resume"
            } else {
                "Pause"
            },
            Btn::Bar,
            true,
            Some(Message::AiFeedPauseToggle),
        ));
    } else if shell.nav == NAV_LOGS {
        right.push(ui::btn("Clear", Btn::Bar, true, Some(Message::AiLogClear)));
    }
    let bar = container(ui::bar(NAV_ITEMS[shell.nav], vec![], right)).style(theme::region_style(
        theme::bg,
        theme::corners(9.0, 9.0, 0.0, 0.0),
    ));
    let t = shell.anims.value(("view", 0), 1.0, shell.now);
    let body = container(ui::fade_in(body, t, theme::bg))
        .padding(theme::pad4(6.0 * (1.0 - t), 0.0, 0.0, 0.0))
        .height(Length::Fill)
        .width(Length::Fill);
    column![bar, body].spacing(0).into()
}

fn dock_view<'a>(shell: &'a Shell, fonts: &'a Fonts) -> Element<'a, Message> {
    use crate::gui::app::{BOTTOM_TABS, SIDE_TABS};
    use crate::gui::widgets::split::{split, Axis};
    let mut order = vec![8, 16, 18, 14];
    order.extend((0..BOTTOM_TABS.len()).filter(|i| ![8, 16, 18, 14].contains(i)));
    let tabs = ui::tabs(
        order
            .iter()
            .map(|i| {
                (
                    BOTTOM_TABS[*i].to_string(),
                    shell.bottom_tab == *i,
                    Message::BottomTabPicked(*i),
                )
            })
            .collect(),
    );
    let bottom = container(column![tabs, bottom::view(shell, fonts)])
        .height(shell.bottom_h)
        .width(Length::Fill)
        .style(theme::region_style(
            theme::s1,
            theme::corners(0.0, 0.0, 0.0, 9.0),
        ));
    let bar = container(ui::bar("Disassembly", vec![], vec![])).style(theme::region_style(
        theme::bg,
        theme::corners(9.0, 0.0, 0.0, 0.0),
    ));
    let t = shell.anims.value(("view", 0), 1.0, shell.now);
    let listing = container(ui::fade_in(listing::view(shell, fonts), t, theme::bg))
        .padding(theme::pad4(6.0 * (1.0 - t), 0.0, 0.0, 0.0))
        .height(Length::Fill)
        .width(Length::Fill);
    let center = column![
        bar,
        listing,
        split(Axis::Horizontal)
            .color(theme::line_c(&crate::gui::app::theme(shell)))
            .into_element()
            .map(|d| Message::SplitDrag(d, true)),
        bottom
    ]
    .width(Length::Fill)
    .height(Length::Fill);
    let side_tabs = ui::tabs(
        SIDE_TABS
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    n.to_string(),
                    shell.side_tab == i,
                    Message::SideTabPicked(i),
                )
            })
            .collect(),
    );
    let side = container(column![side_tabs, side::view(shell, fonts)])
        .width(shell.side_w)
        .height(Length::Fill)
        .style(theme::region_style(
            theme::s1,
            theme::corners(0.0, 9.0, 9.0, 0.0),
        ));
    row![
        center,
        split(Axis::Vertical)
            .color(theme::line_c(&crate::gui::app::theme(shell)))
            .into_element()
            .map(|d| Message::SplitDrag(d, false)),
        side
    ]
    .height(Length::Fill)
    .into()
}
