use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

type StackRow = (i64, u64, String, usize, String);

pub(crate) fn stack_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<StackRow>> = shell.read(|s| {
        let Some(a) = &s.analysis else {
            return Arc::new(Vec::<StackRow>::new());
        };
        let cur = s
            .selected_func
            .or_else(|| a.functions.first().map(|f| f.entry));
        let Some(cur) = cur else {
            return Arc::new(Vec::<StackRow>::new());
        };
        match a.stack_frames.get(&cur) {
            Some(sf) => Arc::new(
                sf.variables
                    .iter()
                    .map(|v| {
                        let kind = match v.kind {
                            crate::analysis::VarKind::Local => "LOCAL",
                            crate::analysis::VarKind::Parameter => "PARAM",
                            crate::analysis::VarKind::SavedReg => "SAVED",
                            crate::analysis::VarKind::Unknown => "?",
                        };
                        (
                            v.offset,
                            v.size as u64,
                            kind.to_string(),
                            v.access_count as usize,
                            v.name.clone(),
                        )
                    })
                    .collect(),
            ),
            None => Arc::new(Vec::new()),
        }
    });
    struct StkData {
        rows: Arc<Vec<StackRow>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for StkData {
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
        fn row_action(&self, _: usize) -> Option<Message> {
            None
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
            let Some((off, size, kind, refs, name)) = self.rows.get(i) else {
                return;
            };
            let off_str = if *off < 0 {
                format!("rbp-{:#x}", off.unsigned_abs())
            } else {
                format!("rbp+{off:#x}")
            };
            let c = match kind.as_str() {
                "LOCAL" => t.mnemonic,
                "PARAM" => t.annot,
                _ => t.dim,
            };
            put_text(
                frame,
                8.0,
                top,
                line_h,
                format!("{off_str:<10} {size:<5} "),
                t.addr,
            );
            put_text(
                frame,
                8.0 + 18.0 * char_w,
                top,
                line_h,
                format!("{kind:<7} "),
                c,
            );
            put_text(
                frame,
                8.0 + 26.0 * char_w,
                top,
                line_h,
                format!("{refs:<5} "),
                t.dim,
            );
            put_text(
                frame,
                8.0 + 32.0 * char_w,
                top,
                line_h,
                name.clone(),
                t.text,
            );
        }
    }
    if rows.is_empty() {
        return empty_state(
            "No stack variables".to_string(),
            "Select a function after automatic analysis to inspect its frame.".to_string(),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    vlist(StkData {
        rows,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell),
    })
    .into()
}
