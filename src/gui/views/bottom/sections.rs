use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn sections_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows = shell.snap_sections.clone();
    struct SecData {
        rows: Arc<Vec<crate::parser::Section>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for SecData {
        type Message = Message;
        fn len(&self) -> usize {
            self.rows.len()
        }
        fn first(&self) -> usize {
            self.first
        }
        fn scroll_msg(&self, f: usize) -> Message {
            Message::BottomScroll(f)
        }
        fn selected(&self) -> Option<usize> {
            None
        }
        fn row_action(&self, i: usize) -> Option<Message> {
            self.rows.get(i).map(|sec| Message::RowGoto(sec.vaddr))
        }
        fn revision(&self) -> u64 {
            self.rev
        }
        fn paint_row(
            &self,
            i: usize,
            top: f32,
            line_h: f32,
            char_w: f32,
            frame: &mut iced::widget::canvas::Frame,
        ) {
            let t = self.tok;
            let Some(sec) = self.rows.get(i) else { return };
            let name = crate::gui::widgets::vlist::truncate_cols(&sec.name, 14);
            put_text(frame, 8.0, top, line_h, format!("{name:<14}"), t.mnemonic);
            put_text(
                frame,
                8.0 + 15.0 * char_w,
                top,
                line_h,
                format!("{:012X}  ", sec.vaddr),
                t.addr,
            );
            put_text(
                frame,
                8.0 + 29.0 * char_w,
                top,
                line_h,
                format!("{:>8}  ", sec.size),
                t.dim,
            );
            put_text(
                frame,
                8.0 + 39.0 * char_w,
                top,
                line_h,
                if sec.is_executable {
                    "X".into()
                } else {
                    "-".into()
                },
                if sec.is_executable { t.run } else { t.mute },
            );
        }
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    if rows.is_empty() {
        return empty_state(
            "No sections".to_string(),
            "Open a binary to list its sections.".to_string(),
        );
    }
    vlist(SecData {
        rows,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell),
    })
    .into()
}
