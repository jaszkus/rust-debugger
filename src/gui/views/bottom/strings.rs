use std::sync::Arc;

use iced::widget::{column, row, text_input};
use iced::{Element, Theme};

use super::super::empty_state;
use super::STRING_COLUMNS;
use super::{clamp_tab_first, paint_columns, table_header, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, T};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn strings_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let filter = shell.read(|s| s.func_filter.clone());
    let snap = shell.snap_strings.clone();
    let total = snap.len();
    let indices: Vec<usize> = shell.read(|s| {
        if s.strings_cache.0 == s.analysis_version && s.strings_cache.1 == filter {
            return s.strings_cache.2.clone();
        }
        let idx: Vec<usize> = snap
            .iter()
            .enumerate()
            .filter(|(_, st)| filter.is_empty() || st.content.contains(filter.as_str()))
            .map(|(i, _)| i)
            .collect();
        s.strings_cache = (s.analysis_version, filter.clone(), idx.clone());
        idx
    });

    struct StringsData {
        strings: Arc<Vec<crate::parser::ExtractedString>>,
        indices: Vec<usize>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for StringsData {
        type Message = Message;
        fn len(&self) -> usize {
            self.indices.len()
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
            self.indices
                .get(i)
                .and_then(|&si| self.strings.get(si))
                .map(|s| Message::RowGoto(s.vaddr))
        }
        fn menu_entries(&self, i: usize) -> Vec<(String, Message)> {
            self.row_action(i)
                .and_then(|m| match m {
                    Message::RowGoto(a) => Some(a),
                    _ => None,
                })
                .map(|addr| {
                    vec![
                        ("Go to address".to_string(), Message::RowGoto(addr)),
                        ("Add Bookmark…".to_string(), Message::BookmarkRequest(addr)),
                    ]
                })
                .unwrap_or_default()
        }
        fn copy_action(&self, i: usize) -> Option<Message> {
            self.indices
                .get(i)
                .and_then(|&i| self.strings.get(i))
                .map(|s| Message::CopyText(s.content.clone()))
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
            let Some(si) = self.indices.get(i).and_then(|&si| self.strings.get(si)) else {
                return;
            };
            let preview: &str = match si.content.char_indices().nth(90) {
                Some((idx, _)) => &si.content[..idx],
                None => &si.content,
            };
            let enc = match si.encoding {
                crate::parser::StringEncoding::Ascii => ("ASC", t.string),
                crate::parser::StringEncoding::Utf16Le => ("U16", t.mnemonic),
                crate::parser::StringEncoding::Utf32Le => ("U32", t.mnemonic),
                crate::parser::StringEncoding::Pascal => ("PAS", t.annot),
            };
            paint_columns(
                frame,
                STRING_COLUMNS,
                &[
                    (format!("{:016X}", si.vaddr), t.addr),
                    (enc.0.into(), t.dim),
                    (format!("\"{preview}\""), enc.1),
                ],
                top,
                line_h,
                char_w,
            );
        }
    }

    let first = clamp_tab_first(shell.bottom_scroll, indices.len());
    let shown = indices.len();
    let list: Element<'_, Message, Theme, iced::Renderer> = if indices.is_empty() {
        empty_state(
            "No strings found".to_string(),
            if total == 0 {
                "Open a binary to extract its strings.".to_string()
            } else {
                "Nothing matches this filter. Clear the filter to see all strings.".to_string()
            },
        )
    } else {
        vlist(StringsData {
            strings: snap,
            indices,
            first,
            tok: table_tokens(shell),
            rev: table_rev(shell),
        })
        .into()
    };
    column![
        row![
            text_input("Filter…", &filter)
                .width(220)
                .on_input(Message::FuncFilterEdited)
                .style(crate::gui::theme::input_style),
            label(format!("({shown} of {total})"), T::Mute),
        ]
        .spacing(8),
        table_header(STRING_COLUMNS),
        list
    ]
    .spacing(6)
    .into()
}
