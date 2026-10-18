use std::sync::Arc;

use iced::widget::{button, column};
use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, lock, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, Btn, T};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn signatures_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<(u64, String, String, usize)>> = shell.read(|s| {
        let len = s
            .analysis
            .as_ref()
            .map(|a| a.function_signatures.len())
            .unwrap_or(0);
        let mut cache = lock(&shell.table_cache.signatures);
        if cache.0 == s.modification_number && cache.1 == s.fid_epoch && cache.2 == len {
            if let Some(rows) = &cache.3 {
                return rows.clone();
            }
        }
        let rows: Arc<Vec<(u64, String, String, usize)>> = match &s.analysis {
            None => Arc::new(Vec::new()),
            Some(a) => {
                let mut v: Vec<(u64, String, String, usize)> = a
                    .function_signatures
                    .iter()
                    .map(|(addr, sig)| (*addr, sig.name.clone(), sig.library.clone(), sig.size))
                    .collect();
                v.sort_by_key(|(a, _, _, _)| *a);
                Arc::new(v)
            }
        };
        *cache = (s.modification_number, s.fid_epoch, len, Some(rows.clone()));
        rows
    });
    let fid_len = shell.read(|s| s.fid_db.len());
    struct SigData {
        rows: Arc<Vec<(u64, String, String, usize)>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for SigData {
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
            self.rows.get(i).map(|(a, _, _, _)| Message::RowGoto(*a))
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
            let Some((addr, name, lib, size)) = self.rows.get(i) else {
                return;
            };
            put_text(frame, 8.0, top, line_h, format!("{addr:012X}  "), t.addr);
            put_text(
                frame,
                8.0 + 14.0 * char_w,
                top,
                line_h,
                format!("{name} "),
                t.string,
            );
            put_text(
                frame,
                8.0 + 14.0 * char_w + (name.chars().count() + 1) as f32 * char_w,
                top,
                line_h,
                format!("({lib}, {size} bytes)"),
                t.mute,
            );
        }
    }
    if rows.is_empty() {
        return empty_state(
            "No signature matches".to_string(),
            format!(
                "Session FID library holds {fid_len} signatures — no known functions matched. Ingest a library via MCP fid_ingest_library."
            ),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    column![
        button(label("Clear session FID library", T::Dim))
            .style(Btn::Quiet.style())
            .on_press(Message::SignatureClear),
        vlist(SigData {
            rows,
            first,
            tok: table_tokens(shell),
            rev: table_rev(shell)
        })
    ]
    .into()
}
