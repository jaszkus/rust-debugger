use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, lock, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn tags_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<(u64, Vec<String>)>> = shell.read(|s| {
        let mut cache = lock(&shell.table_cache.tags);
        if cache.0 == s.modification_number && cache.1 == s.function_tags.len()
            && let Some(rows) = &cache.2 {
                return rows.clone();
            }
        let mut v: Vec<(u64, Vec<String>)> = s
            .function_tags
            .iter()
            .map(|(a, t)| (*a, t.clone()))
            .collect();
        v.sort_by_key(|(a, _)| *a);
        let rows = Arc::new(v);
        *cache = (
            s.modification_number,
            s.function_tags.len(),
            Some(rows.clone()),
        );
        rows
    });
    struct TagData {
        rows: Arc<Vec<(u64, Vec<String>)>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for TagData {
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
            self.rows.get(i).map(|(a, _)| Message::RowGoto(*a))
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
            let Some((addr, tags)) = self.rows.get(i) else {
                return;
            };
            put_text(frame, 8.0, top, line_h, format!("{addr:012X}  "), t.addr);
            put_text(
                frame,
                8.0 + 14.0 * char_w,
                top,
                line_h,
                tags.join("  ·  "),
                t.annot,
            );
        }
    }
    if rows.is_empty() {
        return empty_state(
            "No tags".to_string(),
            "Tag a function via MCP tag_function to classify it here.".to_string(),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    vlist(TagData {
        rows,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell),
    })
    .into()
}
