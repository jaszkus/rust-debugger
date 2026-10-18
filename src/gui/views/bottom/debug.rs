use iced::widget::column;
use iced::{Element, Length, Theme};

use super::{table_header, Column};
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{mono, T};

pub fn debug_view(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let live = shell.read(|s| {
        if !s.debug_state.is_attached && !s.debug_state.is_running {
            return None;
        }
        Some((
            s.debug_state.registers.rip,
            s.debug_state.breakpoints.len(),
            crate::gui::actions::fmt_flags(s.debug_state.registers.eflags),
        ))
    });
    match live {
        None => {
            let proj = shell.read(|s| {
                std::path::Path::new(&s.file_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "the project".into())
            });
            use crate::gui::theme::{self};
            use iced::widget::{button, column, container, row, Space};
            let launch = button(
                container(
                    iced::widget::text(format!("Launch {proj}"))
                        .size(13)
                        .font(theme::ui_font(iced::font::Weight::Semibold)),
                )
                .padding([7, 14]),
            )
            .padding(0)
            .style(crate::gui::theme::Btn::Primary.style())
            .on_press(Message::DebugRun);
            let attach = button(
                container(iced::widget::text("Attach to process…").size(13)).padding([7, 14]),
            )
            .padding(0)
            .style(crate::gui::theme::Btn::Bar.style())
            .on_press(Message::DebugAttach(0));
            let hint =
                iced::widget::text("run · step over · step into · breakpoint (buttons above)")
                    .size(12)
                    .font(theme::mono_font())
                    .style(|t| iced::widget::text::Style {
                        color: Some(crate::gui::theme::mute_c(t)),
                    });
            container(
                column![
                    theme::svg_icon(theme::ic::BUG, 34.0, {
                        let l = shell.is_light();
                        theme::mute_c_for_light(l)
                    }),
                    Space::new().height(8),
                    iced::widget::text("No process attached")
                        .size(18)
                        .font(theme::ui_font(iced::font::Weight::Semibold))
                        .style(|t| iced::widget::text::Style {
                            color: Some(crate::gui::theme::text_c(t)),
                        }),
                    iced::widget::text(format!(
                        "Launch {proj} or attach to a running process to debug."
                    ))
                    .size(12)
                    .style(|t| iced::widget::text::Style {
                        color: Some(crate::gui::theme::mute_c(t)),
                    }),
                    Space::new().height(10),
                    row![launch, attach].spacing(8),
                    Space::new().height(14),
                    hint,
                ]
                .spacing(6)
                .align_x(iced::alignment::Horizontal::Center),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
        }
        Some((rip, nbp, flags)) => column![
            table_header(&[
                Column {
                    title: "Register",
                    width_cols: 10
                },
                Column {
                    title: "Value",
                    width_cols: 18
                }
            ]),
            mono(format!("RIP  {rip:016X}"), T::Base),
            mono(format!("FLG  {flags}"), T::Dim),
            mono(format!("{nbp} breakpoint(s) armed"), T::Dim),
        ]
        .spacing(6)
        .padding(20)
        .into(),
    }
}
