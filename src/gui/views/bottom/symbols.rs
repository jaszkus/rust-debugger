use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn symbols_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows = shell.snap_symbols.clone();
    struct SymData {
        rows: Arc<Vec<crate::parser::Symbol>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for SymData {
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
            self.rows.get(i).map(|s| Message::RowGoto(s.addr))
        }
        fn menu_entries(&self, i: usize) -> Vec<(String, Message)> {
            self.rows
                .get(i)
                .map(|s| {
                    vec![
                        ("Go to address".to_string(), Message::RowGoto(s.addr)),
                        (
                            "Rename Function…".to_string(),
                            Message::RenameRequest(s.addr),
                        ),
                        (
                            "Add Bookmark…".to_string(),
                            Message::BookmarkRequest(s.addr),
                        ),
                    ]
                })
                .unwrap_or_default()
        }
        fn menu_open_action(&self) -> Option<Message> {
            Some(Message::AnimationTick)
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
            let Some(sym) = self.rows.get(i) else { return };
            let c = if sym.is_function { t.mnemonic } else { t.dim };
            put_text(
                frame,
                8.0,
                top,
                line_h,
                format!("{:012X}  ", sym.addr),
                t.addr,
            );
            put_text(frame, 8.0 + 14.0 * char_w, top, line_h, sym.name.clone(), c);
        }
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    if rows.is_empty() {
        return empty_state(
            "No symbols".to_string(),
            if shell.read(|s| s.binary.is_some()) {
                "This binary carries no symbol table.".to_string()
            } else {
                "Open a binary to list its symbols.".to_string()
            },
        );
    }
    vlist(SymData {
        rows,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell),
    })
    .into()
}
