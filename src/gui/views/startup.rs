use super::ui;
use crate::gui::app::{Message, Shell, DIALOG_INPUT_ID};
use crate::gui::theme::{self, ic, label, mono, Btn, Fonts, T};
use iced::alignment::Vertical;
use iced::widget::{button, column, container, row, scrollable, text_input, Space};
use iced::{Element, Length};

fn action<'a>(
    shell: &Shell,
    icon: &'static str,
    title: &str,
    primary: bool,
    msg: Message,
) -> Element<'a, Message> {
    let kind = if primary { Btn::Primary } else { Btn::Bar };
    button(
        container(
            row![
                theme::svg_icon(icon, 17.0, ui::btn_fg(kind, shell.is_light())),
                iced::widget::text(title.to_string())
                    .font(theme::ui_font(iced::font::Weight::Medium))
                    .size(13)
            ]
            .spacing(10)
            .align_y(Vertical::Center),
        )
        .height(42)
        .padding([0, 14])
        .align_y(Vertical::Center),
    )
    .width(Length::Fill)
    .padding(0)
    .style(kind.style())
    .on_press(msg)
    .into()
}

pub fn view<'a>(shell: &'a Shell, _: &'a Fonts) -> Element<'a, Message> {
    let left = container(
        column![
            theme::logo_svg(52.0, shell.is_light()),
            Space::new().height(10),
            label("Rust Debugger", T::Strong).size(22),
            label("Binary analysis workbench", T::Dim),
            mono(format!("v{}", env!("CARGO_PKG_VERSION")), T::Mute).size(12),
            Space::new().height(16),
            action(shell, ic::FO, "Open file…", true, Message::OpenFile),
            action(
                shell,
                ic::IMP,
                "Import raw…",
                false,
                Message::StartupImportOpen
            ),
            Space::new().height(Length::Fill),
        ]
        .spacing(8),
    )
    .width(289)
    .height(Length::Fill)
    .padding(theme::pad4(32.0, 24.0, 22.0, 24.0))
    .style(theme::region_style(
        theme::s1,
        theme::corners(11.0, 0.0, 0.0, 11.0),
    ));
    let right = if shell.startup_raw {
        raw_form(shell)
    } else {
        recents(shell)
    };
    container(row![left, ui::hairline_v(), right].height(420))
        .width(780)
        .padding(1)
        .style(theme::card_style)
        .into()
}

fn recents(shell: &Shell) -> Element<'_, Message> {
    let mut recents: Vec<(String, Option<std::time::Instant>)> = shell.read(|s| {
        s.recent_projects
            .iter()
            .cloned()
            .map(|p| (p, None))
            .collect()
    });
    for (path, index, start) in &shell.recent_removals {
        recents.insert((*index).min(recents.len()), (path.clone(), Some(*start)));
    }
    let mut list = column![].spacing(0);
    if recents.is_empty() {
        list = list.push(
            container(label(
                "No recent projects yet. Open a file to get started.",
                T::Mute,
            ))
            .padding([10, 12]),
        );
    }
    for (path, removed) in recents {
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());
        let open = button(
            container(
                column![
                    label(name, T::Base).size(14),
                    mono(path.clone(), T::Mute).size(12)
                ]
                .spacing(3),
            )
            .padding([11, 12])
            .width(Length::Fill),
        )
        .width(Length::Fill)
        .padding(0)
        .style(Btn::Quiet.style())
        .on_press(Message::RecentClicked(path.clone()));
        let remove = ui::tip(
            ui::icon_btn(
                ic::X,
                shell.is_light(),
                "Remove from recent",
                Message::RecentRemove(path),
            ),
            "Remove from recent",
            iced::widget::tooltip::Position::Bottom,
        );
        let item = row![open, remove].align_y(Vertical::Center);
        if let Some(start) = removed {
            let fade_p =
                crate::gui::anim::css_ease(crate::gui::anim::progress(shell.now, start, 220));
            let height_p =
                crate::gui::anim::css_ease(crate::gui::anim::progress(shell.now, start, 260));
            list = list.push(
                container(
                    iced::widget::pin(ui::fade_in(item, 1.0 - fade_p, theme::bg)).x(14.0 * fade_p),
                )
                .height(64.0 * (1.0 - height_p))
                .clip(true),
            );
        } else {
            list = list.push(item);
        }
    }
    right_panel(
        column![
            row![
                container(label("Recent projects", T::Dim))
                    .width(Length::Fill)
                    .padding([0, 12]),
                ui::btn("Close", Btn::Bar, false, Some(Message::CloseStartup))
            ]
            .align_y(Vertical::Center),
            scrollable(list)
                .height(Length::Fill)
                .style(theme::scroll_style),
        ]
        .spacing(10)
        .into(),
    )
}

fn raw_form(shell: &Shell) -> Element<'_, Message> {
    let (base, arch) = shell.read(|s| (s.import_base_addr_buf.clone(), s.import_arch_idx));
    let active = arch.min(crate::gui::state::ARCH_OPTIONS.len() - 1);
    let form = column![
        row![
            container(label("Import raw binary", T::Dim)).width(Length::Fill),
            ui::btn("Close", Btn::Bar, false, Some(Message::CloseStartup))
        ]
        .align_y(Vertical::Center),
        label(
            "A file with no headers. Tell the workbench how to read it.",
            T::Mute
        ),
        ui::setting_row(
            "Architecture",
            None,
            ui::seg(
                crate::gui::state::ARCH_OPTION_LABELS,
                active,
                Message::ImportArchPicked
            ),
            false
        ),
        ui::setting_row(
            "Base address",
            None,
            text_input("0x00000000", &base)
                .on_input(Message::ImportBaseEdited)
                .on_submit(Message::ImportConfirm)
                .width(170)
                .style(theme::input_style)
                .font(theme::mono_font())
                .into(),
            false
        ),
        text_input("Raw file path", &shell.import_path)
            .id(DIALOG_INPUT_ID)
            .on_input(Message::ImportPathEdited)
            .style(theme::input_style)
            .font(theme::mono_font()),
        ui::btn("Browse…", Btn::Quiet, false, Some(Message::ImportBrowse)),
        Space::new().height(Length::Fill),
        row![
            ui::btn("Import", Btn::Primary, false, Some(Message::ImportConfirm)),
            ui::btn("Back", Btn::Bar, false, Some(Message::StartupRawBack))
        ]
        .spacing(8),
    ]
    .spacing(10)
    .height(Length::Fill);
    right_panel(ui::fade_in(
        form,
        shell.anims.value(("mview", 0), 1.0, shell.now),
        theme::bg,
    ))
}
fn right_panel(content: Element<'_, Message>) -> Element<'_, Message> {
    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(theme::pad4(20.0, 16.0, 22.0, 16.0))
        .style(theme::region_style(
            theme::bg,
            theme::corners(0.0, 11.0, 11.0, 0.0),
        ))
        .into()
}
pub fn overlay<'a>(shell: &'a Shell, fonts: &'a Fonts) -> Element<'a, Message> {
    super::dialogs::modal_layer_animated(shell, view(shell, fonts), Message::CloseStartup)
}
