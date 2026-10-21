use super::{ui, BOOKMARK_KINDS, COMMENT_KINDS};
use crate::gui::app::{Message, Shell, DIALOG_INPUT_ID};
use crate::gui::theme::{self, ic, label, Btn, T};
use iced::widget::{column, container, row, text_input, Space};
use iced::{Element, Length, Theme};

pub fn modal_layer<'a>(card: Element<'a, Message>, dismiss: Message) -> Element<'a, Message> {
    modal_geometry(card, dismiss, 1.0, 0.0)
}
fn scrim<'a>(dismiss: Message, alpha: f32) -> Element<'a, Message> {
    iced::widget::opaque(
        iced::widget::mouse_area(
            container(Space::new())
                .width(Length::Fill)
                .height(Length::Fill)
                .style(move |_| iced::widget::container::Style {
                    background: Some(iced::Color::from_rgba(0.0, 0.0, 0.0, 0.62 * alpha).into()),
                    ..Default::default()
                }),
        )
        .on_press(dismiss)
        .on_scroll(|_| Message::Noop),
    )
}
fn modal_geometry<'a>(
    card: Element<'a, Message>,
    dismiss: Message,
    alpha: f32,
    slide: f32,
) -> Element<'a, Message> {
    iced::widget::stack![
        scrim(dismiss, alpha),
        container(iced::widget::opaque(card))
            .padding(theme::pad4(slide * 2.0, 0.0, 0.0, 0.0))
            .center_x(Length::Fill)
            .center_y(Length::Fill)
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .into()
}
fn fade_card<'a>(card: Element<'a, Message>, pop: f32, backdrop: f32) -> Element<'a, Message> {
    if pop >= 0.999 {
        return card;
    }
    let a = 1.0 - pop.clamp(0.0, 1.0);
    let k = 0.62 * backdrop.clamp(0.0, 1.0);
    let veil = container(Space::new())
        .width(Length::Fill)
        .height(Length::Fill)
        .style(move |t: &Theme| {
            let base = theme::app_bg_c(t);
            let behind =
                iced::Color::from_rgb(base.r * (1.0 - k), base.g * (1.0 - k), base.b * (1.0 - k));
            iced::widget::container::Style {
                background: Some(ui::fade(behind, a).into()),
                border: iced::Border {
                    color: iced::Color::TRANSPARENT,
                    width: 0.0,
                    radius: theme::R_POP,
                },
                ..Default::default()
            }
        });
    iced::widget::stack![card, veil].into()
}

pub fn modal_layer_animated<'a>(
    shell: &Shell,
    card: Element<'a, Message>,
    dismiss: Message,
) -> Element<'a, Message> {
    if shell.anims.is_active(("closing", 0), shell.now) {
        let out = shell.anims.value(("closing", 0), 0.0, shell.now);
        return scrim(dismiss, 1.0 - out);
    }
    let pop = shell.anims.value(("modal", 0), 1.0, shell.now);
    let backdrop = shell.anims.value(("backdrop", 0), 1.0, shell.now);
    modal_geometry(
        fade_card(card, pop, backdrop),
        dismiss,
        backdrop,
        10.0 * (1.0 - pop),
    )
}
fn modal<'a>(
    shell: &Shell,
    title: &str,
    width: f32,
    content: Element<'a, Message>,
) -> Element<'a, Message> {
    let card =
        container(column![label(title.to_string(), T::Strong).size(17), content].spacing(20))
            .padding([28, 30])
            .width(width)
            .style(theme::card_style);
    modal_layer_animated(shell, card.into(), Message::DismissOverlay)
}
fn input<'a>(
    value: impl Into<String>,
    placeholder: &'a str,
    on_input: fn(String) -> Message,
    on_submit: Message,
) -> iced::widget::TextInput<'a, Message> {
    text_input(placeholder, &value.into())
        .id(DIALOG_INPUT_ID)
        .width(Length::Fill)
        .on_input(on_input)
        .on_submit(on_submit)
        .font(theme::mono_font())
        .size(13)
        .padding([6, 10])
        .style(theme::input_style)
}
fn actions(save: (&str, Message), cancel: Message) -> Element<'static, Message> {
    row![
        ui::btn(save.0, Btn::Primary, false, Some(save.1)),
        ui::btn("Cancel", Btn::Quiet, false, Some(cancel))
    ]
    .spacing(8)
    .into()
}
pub fn view(shell: &Shell) -> Option<Element<'_, Message>> {
    if let Some((addr, buf)) = &shell.rename {
        return Some(modal(
            shell,
            &format!("Rename — {addr:#x}"),
            480.0,
            column![
                input(
                    buf.clone(),
                    "New name…",
                    Message::RenameEdited,
                    Message::RenameConfirm
                ),
                actions(("Rename", Message::RenameConfirm), Message::RenameCancel)
            ]
            .spacing(16)
            .into(),
        ));
    }
    if let Some((addr, kind, _)) = shell.comment {
        let active = COMMENT_KINDS.iter().position(|k| *k == kind).unwrap_or(0);
        let choices: Vec<&str> = COMMENT_KINDS.iter().map(|k| k.label()).collect();
        return Some(modal(
            shell,
            &format!("Comment — {addr:#x}"),
            620.0,
            column![
                ui::seg(&choices, active, Message::CommentKindPicked),
                iced::widget::text_editor(&shell.comment_editor)
                    .id(DIALOG_INPUT_ID)
                    .on_action(Message::CommentEditorAction)
                    .height(
                        if matches!(
                            kind,
                            crate::gui::CommentKind::Plate | crate::gui::CommentKind::Pre
                        ) {
                            180
                        } else {
                            90
                        }
                    )
                    .font(theme::mono_font())
                    .size(13)
                    .style(theme::editor_style),
                row![
                    ui::btn("Save", Btn::Primary, false, Some(Message::CommentConfirm)),
                    ui::btn("Delete", Btn::Quiet, false, Some(Message::CommentDelete)),
                    ui::btn("Cancel", Btn::Quiet, false, Some(Message::CommentCancel))
                ]
                .spacing(8)
            ]
            .spacing(16)
            .into(),
        ));
    }
    if let Some((addr, kind, buf)) = &shell.bookmark {
        let active = BOOKMARK_KINDS.iter().position(|k| k == kind).unwrap_or(0);
        let choices: Vec<&str> = BOOKMARK_KINDS.iter().map(|k| k.label()).collect();
        return Some(modal(
            shell,
            &format!("Bookmark — {addr:#x}"),
            540.0,
            column![
                ui::seg(&choices, active, Message::BookmarkKindPicked),
                input(
                    buf.clone(),
                    "Bookmark note…",
                    Message::BookmarkEdited,
                    Message::BookmarkConfirm
                ),
                actions(("Add", Message::BookmarkConfirm), Message::BookmarkCancel)
            ]
            .spacing(16)
            .into(),
        ));
    }
    if shell.show_import {
        let (base, arch) = shell.read(|s| (s.import_base_addr_buf.clone(), s.import_arch_idx));
        return Some(modal(
            shell,
            "Import raw dump",
            600.0,
            column![
                input(
                    shell.import_path.clone(),
                    "Raw file path",
                    Message::ImportPathEdited,
                    Message::ImportConfirm
                ),
                ui::btn("Browse…", Btn::Quiet, false, Some(Message::ImportBrowse)),
                input(
                    base,
                    "Base address (hex)",
                    Message::ImportBaseEdited,
                    Message::ImportConfirm
                ),
                ui::seg(
                    crate::gui::state::ARCH_OPTION_LABELS,
                    arch,
                    Message::ImportArchPicked
                ),
                label(
                    "Unsupported architectures report a load error; no data is fabricated.",
                    T::Mute
                )
                .size(12),
                actions(("Import", Message::ImportConfirm), Message::ImportCancel)
            ]
            .spacing(16)
            .into(),
        ));
    }
    if shell.show_type_dialog {
        return Some(modal(
            shell,
            "Create data type",
            540.0,
            column![
                ui::seg(
                    &["Struct", "Union", "Enum", "Typedef", "Function"],
                    shell.type_kind,
                    Message::TypeKindPicked
                ),
                input(
                    shell.type_name.clone(),
                    "Type name…",
                    Message::TypeNameEdited,
                    Message::TypeCreate
                ),
                actions(("Create", Message::TypeCreate), Message::TypeCancel)
            ]
            .spacing(16)
            .into(),
        ));
    }
    if shell.show_search {
        return Some(search_dialog(shell));
    }
    None
}
fn search_dialog(shell: &Shell) -> Element<'_, Message> {
    let (query, kind) = shell.read(|s| (s.search_query.clone(), s.search_kind));
    let results = shell.search_rows.clone();
    let mut body = column![
        input(
            query.clone(),
            "Search, > command, @ address, hex: bytes",
            Message::SearchQueryEdited,
            Message::SearchRun
        ),
        ui::seg(
            &["All", "Strings", "Functions", "Symbols", "Imports", "Hex"],
            kind,
            Message::SearchKindPicked
        ),
        row![
            ui::chip(format!("{} results", results.len()), false),
            Space::new().width(Length::Fill),
            ui::btn(
                "Clear",
                Btn::Quiet,
                false,
                Some(Message::SearchQueryEdited(String::new()))
            ),
            ui::btn("Close", Btn::Quiet, false, Some(Message::SearchDismissed))
        ]
        .spacing(8),
    ]
    .spacing(12);
    if let Some(q) = query.strip_prefix('>') {
        for (i, (name, _)) in crate::gui::app::command_list().iter().enumerate() {
            if super::contains_ci(name, &q.trim().to_lowercase()) {
                body = body.push(ui::btn(
                    name,
                    Btn::Quiet,
                    false,
                    Some(Message::CommandPicked(i)),
                ));
            }
        }
    } else {
        struct SearchData {
            rows: std::sync::Arc<Vec<crate::gui::state::SearchResult>>,
            first: usize,
            tokens: theme::Tokens,
            epoch: u64,
        }
        impl crate::gui::widgets::vlist::VListData for SearchData {
            type Message = Message;
            fn len(&self) -> usize {
                self.rows.len()
            }
            fn first(&self) -> usize {
                self.first
            }
            fn selected(&self) -> Option<usize> {
                None
            }
            fn revision(&self) -> u64 {
                self.epoch
            }
            fn scroll_msg(&self, first: usize) -> Message {
                Message::SearchScroll(first)
            }
            fn row_action(&self, i: usize) -> Option<Message> {
                self.rows.get(i).map(|r| Message::SearchPicked(r.addr))
            }
            fn copy_action(&self, i: usize) -> Option<Message> {
                self.rows.get(i).map(|r| Message::CopyText(r.label.clone()))
            }
            fn paint_row(
                &self,
                i: usize,
                top: f32,
                line_h: f32,
                _cw: f32,
                frame: &mut iced::widget::canvas::Frame,
            ) {
                let Some(r) = self.rows.get(i) else {
                    return;
                };
                if !crate::gui::widgets::vlist::text_fits(top, frame.height()) {
                    return;
                }
                frame.fill_text(iced::widget::canvas::Text {
                    content: crate::gui::widgets::vlist::truncate_cols(
                        &format!("{:016X}  {:?}  {}", r.addr, r.kind, r.label),
                        (frame.width() / 7.8) as usize,
                    ),
                    position: iced::Point::new(8.0, top),
                    color: self.tokens.text,
                    size: iced::Pixels(13.0),
                    font: theme::mono_font(),
                    line_height: iced::advanced::text::LineHeight::Absolute(iced::Pixels(line_h)),
                    ..Default::default()
                });
            }
        }
        body = body.push(
            container(crate::gui::widgets::vlist::vlist(SearchData {
                rows: results.clone(),
                first: shell.search_first,
                tokens: theme::Tokens::resolve(shell.is_light()),
                epoch: shell.search_epoch,
            }))
            .height(350),
        );
    }
    if results.is_empty() {
        body = body.push(super::empty_state(
            "No results".into(),
            "Nothing matches. Try another query or kind.".into(),
        ));
    }
    modal(
        shell,
        "Search",
        760.0,
        iced::widget::scrollable(body)
            .style(theme::scroll_style)
            .height(480)
            .into(),
    )
}

const SETTINGS: [(&str, &str); 5] = [
    ("General", ic::SL),
    ("Appearance", ic::SN),
    ("Analysis", ic::BOLT),
    ("AI and MCP", ic::LIVE),
    ("About", ic::INFO),
];
pub fn settings_modal(shell: &Shell) -> Element<'_, Message> {
    let tab = shell.settings_tab.min(4);
    let mut cats = column![container(label("Settings", T::Strong).size(15))
        .width(Length::Fill)
        .padding(theme::pad4(2.0, 10.0, 14.0, 10.0))]
    .spacing(2)
    .width(Length::Fill);
    for (i, (name, paths)) in SETTINGS.iter().enumerate() {
        let active = i == tab;
        let item = iced::widget::button(
            container(
                row![
                    theme::svg_icon(
                        paths,
                        17.0,
                        if active {
                            theme::text_c_for_light(shell.is_light())
                        } else {
                            theme::dim_c_for_light(shell.is_light())
                        }
                    ),
                    label(*name, if active { T::Strong } else { T::Dim }).size(13.5)
                ]
                .spacing(11)
                .align_y(iced::alignment::Vertical::Center),
            )
            .width(Length::Fill)
            .height(34)
            .padding([0, 10])
            .align_y(iced::alignment::Vertical::Center)
            .style(move |t: &Theme| {
                if active {
                    Btn::nav_active(t)
                } else {
                    Default::default()
                }
            }),
        )
        .padding(0)
        .width(Length::Fill)
        .on_press(Message::SettingsTabPicked(i))
        .style(Btn::Nav.style());
        cats = cats.push(item);
    }
    let left = container(cats)
        .width(219)
        .height(Length::Fill)
        .padding([18, 12])
        .style(theme::region_style(
            theme::bg,
            theme::corners(11.0, 0.0, 0.0, 11.0),
        ));
    let header = container(
        row![
            label(SETTINGS[tab].0, T::Strong).size(17),
            Space::new().width(Length::Fill),
            ui::icon_btn_sized(
                ic::X,
                shell.is_light(),
                "Close (Esc)",
                Message::SettingsModalClose,
                28.0,
                14.0
            )
        ]
        .width(Length::Fill)
        .align_y(iced::alignment::Vertical::Center),
    )
    .width(Length::Fill)
    .height(60)
    .align_y(iced::alignment::Vertical::Center)
    .padding(theme::pad4(0.0, 20.0, 0.0, 28.0));
    let right = container(
        column![
            header,
            container(
                iced::widget::scrollable(ui::fade_in(
                    settings_content(shell, tab),
                    shell.anims.value(("mview", 0), 1.0, shell.now),
                    theme::s1
                ))
                .width(Length::Fill)
                .style(theme::scroll_style)
            )
            .width(Length::Fill)
            .padding(theme::pad4(0.0, 28.0, 20.0, 28.0))
            .height(Length::Fill)
        ]
        .width(Length::Fill),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(theme::region_style(
        theme::s1,
        theme::corners(0.0, 11.0, 11.0, 0.0),
    ));
    let card = container(row![left, ui::hairline_v(), right].height(538))
        .width(860)
        .padding(1)
        .style(theme::card_style);
    modal_layer_animated(shell, card.into(), Message::SettingsModalClose)
}
fn settings_content(shell: &Shell, tab: usize) -> Element<'_, Message> {
    let rows = match tab {
        0 => column![
            ui::setting_row(
                "Show recent projects on startup",
                Some("Open the start screen when the app launches."),
                ui::switch(
                    shell.switch_value(3, shell.recent_on_startup),
                    Message::RecentStartupToggled
                ),
                false
            ),
            ui::setting_row(
                "Restore last project",
                Some("Reopen the project you were working on."),
                ui::switch(
                    shell.switch_value(4, shell.restore_last),
                    Message::RestoreLastToggled
                ),
                true
            ),
        ],
        1 => column![
            ui::setting_row(
                "Theme",
                Some("Choose how the workbench looks."),
                ui::seg(
                    &["System", "Dark", "Light"],
                    match shell.theme_mode {
                        theme::AppThemeMode::System => 0,
                        theme::AppThemeMode::Dark => 1,
                        theme::AppThemeMode::Light => 2,
                    },
                    |i| Message::ThemePicked([0, 2, 1][i])
                ),
                false
            ),
            ui::setting_row(
                "Interface scale",
                Some("Size of text and controls."),
                ui::seg(
                    &crate::gui::app::UI_SCALES,
                    match shell.ui_scale {
                        s if (s - 0.9).abs() < 0.01 => 0,
                        s if (s - 1.1).abs() < 0.01 => 2,
                        _ => 1,
                    },
                    Message::UiScalePicked
                ),
                true
            ),
        ],
        2 => column![
            ui::setting_row(
                "Analyze on open",
                Some("Start analysis as soon as a file loads."),
                ui::switch(
                    shell.switch_value(5, shell.analyze_on_open),
                    Message::AnalyzeOnOpenToggled
                ),
                true
            ),
        ],
        3 => {
            let (on, port) = shell.read(|s| (s.mcp_started_ms.is_some(), s.mcp_port_buf.clone()));
            column![
                ui::setting_row(
                    "MCP server",
                    Some("Let an AI client connect to the workbench."),
                    ui::switch(shell.switch_value(0, on), Message::McpToggle),
                    false
                ),
                ui::setting_row(
                    "Port",
                    Some("Local port for the MCP server (1–65535)."),
                    text_input("Port", &port)
                        .width(120)
                        .font(theme::mono_font())
                        .on_input(Message::McpPortEdited)
                        .style(theme::input_style)
                        .into(),
                    false
                ),
                ui::setting_row(
                    "Allow changes",
                    Some("Let the AI rename and comment."),
                    ui::switch(
                        shell.switch_value(6, shell.allow_changes),
                        Message::AllowChangesToggled
                    ),
                    false
                ),
                ui::setting_row(
                    "Allow execution",
                    Some("Let the AI run and step the program."),
                    ui::switch(
                        shell.switch_value(7, shell.allow_execution),
                        Message::AllowExecutionToggled
                    ),
                    true
                ),
            ]
        }
        _ => column![ui::setting_row(
            "Rust Debugger",
            Some("Binary analysis workbench"),
            ui::value_text(format!("v{}", env!("CARGO_PKG_VERSION"))),
            true
        )],
    };
    rows.spacing(0).into()
}
