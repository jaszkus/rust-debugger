use std::sync::Arc;

use iced::widget::column;
use iced::{Element, Theme};

use super::super::empty_state;
use super::XREF_COLUMNS;
use super::{clamp_tab_first, lock, paint_columns, table_header, table_rev, table_tokens, XrefRow};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn xrefs_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<XrefRow>> = shell.read(|s| {
        let len = s.analysis.as_ref().map(|a| a.xrefs.all.len()).unwrap_or(0);
        let mut cache = lock(&shell.table_cache.xrefs);
        if cache.0 == s.analysis_version && cache.1 == s.modification_number && cache.2 == len {
            if let Some(rows) = &cache.3 {
                return rows.clone();
            }
        }
        let rows: Arc<Vec<XrefRow>> = match &s.analysis {
            None => Arc::new(Vec::new()),
            Some(a) => Arc::new(
                a.xrefs
                    .all
                    .iter()
                    .map(|xr| (xr.from, xr.to, xr.kind, xr.note.clone()))
                    .collect(),
            ),
        };
        *cache = (
            s.analysis_version,
            s.modification_number,
            len,
            Some(rows.clone()),
        );
        rows
    });
    struct XrData {
        rows: Arc<Vec<XrefRow>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for XrData {
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
            self.rows
                .get(i)
                .map(|(from, _, _, _)| Message::RowGoto(*from))
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
            use crate::analysis::XRefKind as K;
            let Some((from, to, kind, note)) = self.rows.get(i) else {
                return;
            };
            let (label, kc) = match kind {
                K::Call => ("CALL", t.mnemonic),
                K::Jump => ("JMP", t.annot),
                K::CallIndirect => ("CALLI", t.dim),
                K::JumpIndirect => ("JMPI", t.annot),
                K::TailCall => ("TAIL", t.mnemonic),
                K::Thunk => ("THUNK", t.mnemonic),
                K::DataRead => ("RD", t.dim),
                K::DataWrite => ("WR", t.brk),
                K::DataAddr => ("ADDR", t.dim),
                K::StringRef => ("STR", t.string),
            };
            paint_columns(
                frame,
                XREF_COLUMNS,
                &[
                    (format!("{from:016X}"), t.addr),
                    (format!("{to:016X}"), t.addr),
                    (label.into(), kc),
                    (note.as_deref().unwrap_or("").into(), t.mute),
                ],
                top,
                line_h,
                char_w,
            );
        }
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    let list: Element<'_, Message, Theme, iced::Renderer> = if rows.is_empty() {
        empty_state(
            "No cross-references".to_string(),
            "Analysis starts automatically after opening a file.".to_string(),
        )
    } else {
        vlist(XrData {
            rows,
            first,
            tok: table_tokens(shell),
            rev: table_rev(shell),
        })
        .into()
    };
    column![table_header(XREF_COLUMNS), list].spacing(0).into()
}
