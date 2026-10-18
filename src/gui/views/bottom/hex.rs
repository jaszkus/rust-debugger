use std::sync::Arc;

use iced::widget::{button, column, row, text_input};
use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, Btn, T};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn hex_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let bpr = shell.read(|s| s.hex_bytes_per_row);
    let (payload, follow_row) = shell.read(|s| {
        let payload = s
            .binary
            .as_ref()
            .map(|b| (b.data.clone(), b.sections.clone()));
        let pos = s.disasm_scroll;
        let row = s.binary.as_ref().and_then(|b| {
            let va = s
                .disasm
                .as_ref()
                .and_then(|d| {
                    d.instructions
                        .get(pos.min(d.instructions.len().saturating_sub(1)))
                        .map(|i| i.address)
                })
                .unwrap_or(0);
            crate::gui::actions::offset_for_va(&b.sections, va).map(|o| o as usize / bpr.max(1))
        });
        (payload, row)
    });
    let (data, sections) = payload
        .map(|(d, sec)| (d, std::sync::Arc::new(sec)))
        .unwrap_or_default();
    let rows_count = (data.len() + bpr - 1) / bpr.max(1);
    if rows_count == 0 {
        return empty_state(
            "No binary loaded".to_string(),
            "Open a binary to inspect its bytes here.".to_string(),
        );
    }

    struct HexData {
        data: Arc<Vec<u8>>,
        sections: Arc<Vec<crate::parser::Section>>,
        bpr: usize,
        first: usize,
        count: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for HexData {
        type Message = Message;
        fn len(&self) -> usize {
            self.count
        }
        fn first(&self) -> usize {
            self.first
        }
        fn scroll_msg(&self, f: usize) -> Message {
            Message::HexScroll(Some(f))
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
            let off = i * self.bpr;
            let end = (off + self.bpr).min(self.data.len());
            if off >= self.data.len() {
                return;
            }
            let mut hex = String::with_capacity(self.bpr * 3);
            let mut asc = String::with_capacity(self.bpr);
            for &b in &self.data[off..end] {
                hex.push_str(&format!("{b:02X} "));
                asc.push(if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                });
            }
            let va = crate::gui::actions::va_for_offset(&self.sections, off as u64);
            if va != 0 {
                put_text(
                    frame,
                    8.0,
                    top,
                    line_h,
                    format!("{va:012X}  {off:08X}  "),
                    t.mute,
                );
                put_text(
                    frame,
                    8.0 + 24.0 * char_w,
                    top,
                    line_h,
                    format!("{hex:<64} {asc}"),
                    t.dim,
                );
            } else {
                put_text(
                    frame,
                    8.0,
                    top,
                    line_h,
                    format!("{:>12}  {off:08X}  {hex:<64} {asc}", ""),
                    t.dim,
                );
            }
            let _ = char_w;
        }
    }

    let first = clamp_tab_first(
        shell.hex_scroll.unwrap_or(follow_row.unwrap_or(0)),
        rows_count,
    );

    column![
        row![
            text_input("bytes per row", &bpr.to_string())
                .width(80)
                .on_input(Message::HexBprEdited)
                .style(crate::gui::theme::input_style),
            button(label("Sync from listing", T::Dim))
                .style(Btn::Quiet.style_fn())
                .on_press_maybe(follow_row.map(|_| Message::HexScroll(None))),
        ]
        .spacing(8),
        vlist(HexData {
            data,
            sections,
            bpr,
            first,
            count: rows_count,
            tok: table_tokens(shell),
            rev: table_rev(shell)
        })
    ]
    .spacing(6)
    .into()
}
