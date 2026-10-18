use iced::widget::{button, column, row, scrollable};
use iced::{Element, Theme};

use super::super::empty_state;
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, Btn, T};

pub(crate) fn programs_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let (cur, slots): (String, Vec<String>) = shell.read(|s| {
        (
            s.current_program_label(),
            s.program_slots.iter().map(|p| p.name.clone()).collect(),
        )
    });
    let mut col = column![
        label(format!("* {cur} (current)"), T::Strong),
        button(label("Save current slot", T::Base))
            .style(Btn::Quiet.style())
            .on_press(Message::ProgramSave)
    ]
    .spacing(4)
    .padding(8);
    for (i, name) in slots.iter().enumerate() {
        col = col.push(
            row![
                button(label(format!("{i}. {name}"), T::Base))
                    .style(Btn::Quiet.style())
                    .on_press(Message::ProgramSwitch(i)),
                button(label("Close slot", T::Dim))
                    .style(Btn::Quiet.style())
                    .on_press(Message::ProgramClose(i)),
            ]
            .spacing(8),
        );
    }
    if slots.is_empty() {
        col = col.push(empty_state(
            "No saved slots".to_string(),
            "Open another program to switch between binaries here.".to_string(),
        ));
    }
    scrollable(col)
        .style(crate::gui::theme::scroll_style)
        .into()
}
