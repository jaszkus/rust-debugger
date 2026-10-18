use std::sync::Arc;

use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, lock, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn debug_symbols_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<(u64, String, bool)>> = shell.read(|s| {
        let len = s
            .analysis
            .as_ref()
            .and_then(|a| a.debug_symbols.as_ref())
            .map(|ds| ds.symbols.len())
            .unwrap_or(0);
        let mut cache = lock(&shell.table_cache.debug);
        if cache.0 == s.analysis_version && cache.1 == s.modification_number && cache.2 == len {
            if let Some(rows) = &cache.3 {
                return rows.clone();
            }
        }
        let rows: Arc<Vec<(u64, String, bool)>> = match &s.analysis {
            Some(a) => match &a.debug_symbols {
                Some(ds) => Arc::new(
                    ds.symbols
                        .iter()
                        .map(|sym| (sym.addr, sym.name.clone(), sym.is_function))
                        .collect(),
                ),
                None => Arc::new(Vec::new()),
            },
            None => Arc::new(Vec::new()),
        };
        *cache = (
            s.analysis_version,
            s.modification_number,
            len,
            Some(rows.clone()),
        );
        rows
    });
    struct DbgData {
        rows: Arc<Vec<(u64, String, bool)>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for DbgData {
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
            let Some((a, n, is_fn)) = self.rows.get(i) else {
                return;
            };
            let c = if *is_fn { t.mnemonic } else { t.dim };
            put_text(frame, 8.0, top, line_h, format!("{a:012X}  "), t.addr);
            put_text(frame, 8.0 + 14.0 * char_w, top, line_h, n.clone(), c);
        }
    }
    if rows.is_empty() {
        return empty_state(
            "No debug symbols".to_string(),
            "This binary has no usable debug symbols (PDB/DWARF).".to_string(),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    vlist(DbgData {
        rows,
        first,
        tok: table_tokens(shell),
        rev: table_rev(shell),
    })
    .into()
}
