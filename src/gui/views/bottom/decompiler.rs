use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn decompiler_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let lines = shell.decomp_lines.clone();
    struct DecData {
        lines: Arc<Vec<(String, crate::analysis::LineKind, Option<u64>)>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for DecData {
        type Message = Message;
        fn len(&self) -> usize {
            self.lines.len()
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
            self.lines
                .get(i)
                .and_then(|(_, _, a)| a.map(Message::RowGoto))
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
            let Some((txt, kind, _)) = self.lines.get(i) else {
                return;
            };
            let c = match kind {
                crate::analysis::LineKind::Signature => t.mint,
                crate::analysis::LineKind::Declaration => t.mnemonic,
                crate::analysis::LineKind::Call => t.mnemonic,
                crate::analysis::LineKind::Branch => t.annot,
                crate::analysis::LineKind::Return => t.brk,
                crate::analysis::LineKind::Label => t.annot,
                crate::analysis::LineKind::Comment => t.mute,
                _ => t.text,
            };
            put_text(frame, 8.0, top, line_h, txt.clone(), c);
            let _ = char_w;
        }
    }
    if lines.is_empty() {
        return empty_state(
            if shell.decomp_pending == shell.decomp_key && shell.decomp_pending.is_some() {
                "Decompiling…".to_string()
            } else {
                "No pseudocode".to_string()
            },
            "Select an analyzed function; pseudocode is generated here on demand.".to_string(),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, lines.len());
    vlist(DecData {
        lines,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell).wrapping_add(shell.decomp_revision),
    })
    .into()
}
