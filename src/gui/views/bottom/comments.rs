use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, lock, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn comments_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<(u64, String, String)>> = shell.read(|s| {
        let mut cache = lock(&shell.table_cache.comments);
        if cache.0 == s.modification_number && cache.1 == s.comments_ex.len() {
            if let Some(rows) = &cache.2 {
                return rows.clone();
            }
        }
        let mut v: Vec<(u64, String, String)> = s
            .comments_ex
            .iter()
            .map(|((a, k), t)| (*a, k.as_str().to_string(), t.clone()))
            .collect();
        v.sort_by_key(|(a, k, _)| (*a, k.clone()));
        let rows = Arc::new(v);
        *cache = (
            s.modification_number,
            s.comments_ex.len(),
            Some(rows.clone()),
        );
        rows
    });
    struct CmtData {
        rows: Arc<Vec<(u64, String, String)>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for CmtData {
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
            self.rows.get(i).map(|(a, _, _)| Message::RowGoto(*a))
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
            let Some((addr, kind, text)) = self.rows.get(i) else {
                return;
            };
            put_text(
                frame,
                8.0,
                top,
                line_h,
                format!("{addr:012X}  [{kind:<10}] "),
                t.annot,
            );
            put_text(
                frame,
                8.0 + 28.0 * char_w,
                top,
                line_h,
                text.clone(),
                t.text,
            );
        }
    }
    if rows.is_empty() {
        return empty_state(
            "No comments".to_string(),
            "Add one from the listing context menu or via MCP set_comment.".to_string(),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    vlist(CmtData {
        rows,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell),
    })
    .into()
}
