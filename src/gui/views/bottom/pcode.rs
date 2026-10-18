use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, lock, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn pcode_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<(u64, String, String)>> = shell.read(|s| {
        let entry = s.selected_func;
        let mut cache = lock(&shell.table_cache.pcode);
        if cache.0 == s.analysis_version && cache.1 == s.modification_number && cache.2 == entry
            && let Some(rows) = &cache.3 {
                return rows.clone();
            }
        let rows: Arc<Vec<(u64, String, String)>> = match (&s.analysis, &s.disasm, entry) {
            (Some(a), Some(d), Some(entry)) => {
                match a.functions.iter().find(|f| f.entry == entry) {
                    Some(f) => {
                        let pinstrs =
                            crate::analysis::pcode::lift_func(&d.instructions, f.entry, f.end);
                        Arc::new(
                            pinstrs
                                .iter()
                                .flat_map(|pi| {
                                    let mut v =
                                        vec![(pi.address, pi.mnemonic.to_string(), String::new())];
                                    for op in &pi.ops {
                                        v.push((pi.address, String::new(), format!("{op:?}")));
                                    }
                                    v
                                })
                                .collect(),
                        )
                    }
                    None => Arc::new(Vec::new()),
                }
            }
            _ => Arc::new(Vec::new()),
        };
        *cache = (
            s.analysis_version,
            s.modification_number,
            entry,
            Some(rows.clone()),
        );
        rows
    });
    struct PcData {
        rows: Arc<Vec<(u64, String, String)>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for PcData {
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
            let Some((addr, mn, op)) = self.rows.get(i) else {
                return;
            };
            if !mn.is_empty() {
                put_text(
                    frame,
                    8.0,
                    top,
                    line_h,
                    format!("{addr:012X}  {mn}"),
                    t.mnemonic,
                );
            } else {
                put_text(frame, 8.0 + 4.0 * char_w, top, line_h, op.clone(), t.text);
            }
        }
    }
    if rows.is_empty() {
        return empty_state(
            "No p-code".to_string(),
            "Select a function to lift its p-code here.".to_string(),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    vlist(PcData {
        rows,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell),
    })
    .into()
}
