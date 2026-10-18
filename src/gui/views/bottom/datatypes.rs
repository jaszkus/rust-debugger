use iced::widget::{button, column, row, scrollable};
use iced::{Element, Theme};

use super::super::empty_state;
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, mono, Btn, T};

pub(crate) fn types_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let (decls, applied, sel) = shell.read(|s| {
        let decls: Vec<(u32, String)> = s
            .types
            .all()
            .iter()
            .filter(|(id, _)| *id >= 16)
            .map(|(id, _)| (*id, s.types.to_c_decl(*id, 0)))
            .collect();
        let applied: Vec<(u64, String)> = {
            let mut v: Vec<(u64, String)> = s
                .data_types_at
                .iter()
                .map(|(a, t)| (*a, s.types.type_name(*t)))
                .collect();
            v.sort_by_key(|(a, _)| *a);
            v
        };
        (decls, applied, s.selected_insn.or(s.selected_func))
    });

    let mut col = column![row![
        button(label("+ Struct", T::Base))
            .style(Btn::Quiet.style_fn())
            .on_press(Message::TypeKindPicked(0)),
        button(label("+ Union", T::Base))
            .style(Btn::Quiet.style_fn())
            .on_press(Message::TypeKindPicked(1)),
        button(label("+ Enum", T::Base))
            .style(Btn::Quiet.style_fn())
            .on_press(Message::TypeKindPicked(2)),
        button(label("+ Typedef", T::Base))
            .style(Btn::Quiet.style_fn())
            .on_press(Message::TypeKindPicked(3)),
        button(label("Export C", T::Base))
            .style(Btn::Quiet.style_fn())
            .on_press(Message::TypeExport),
    ]
    .spacing(6),]
    .spacing(6);

    for (addr, tname) in &applied {
        col = col.push(
            row![
                mono(format!("{addr:012X}  "), T::Dim),
                label(tname.clone(), T::Strong),
            ]
            .spacing(4),
        );
    }
    for (_, decl) in &decls {
        col = col.push(mono(decl.clone(), T::Base));
    }
    if decls.is_empty() && applied.is_empty() {
        col = col.push(empty_state(
            "No user types".to_string(),
            "Create one with the + buttons above or import via MCP.".to_string(),
        ));
    }
    if let Some(sel) = sel {
        col = col.push(label(
            format!("Selected: {sel:#x} — apply via MCP or the + buttons"),
            T::Mute,
        ));
    }
    scrollable(col.padding(8))
        .style(crate::gui::theme::scroll_style)
        .into()
}
