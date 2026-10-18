use std::sync::Arc;

use iced::widget::column;
use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, paint_columns, table_header, table_rev, table_tokens};
use super::{EXPORT_COLUMNS, IMPORT_COLUMNS};
use crate::gui::app::{Message, Shell};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn imports_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    imports_or_exports(shell, true)
}

pub(crate) fn exports_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    imports_or_exports(shell, false)
}

pub(crate) fn imports_or_exports(
    shell: &Shell,
    imports: bool,
) -> Element<'_, Message, Theme, iced::Renderer> {
    if imports {
        let rows = shell.snap_imports.clone();
        struct ImpData {
            rows: Arc<Vec<crate::parser::Import>>,
            first: usize,
            tok: crate::gui::theme::Tokens,
            rev: u64,
        }
        impl VListData for ImpData {
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
                self.rows.get(i).map(|im| Message::RowGoto(im.offset))
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
                let Some(im) = self.rows.get(i) else { return };
                paint_columns(
                    frame,
                    IMPORT_COLUMNS,
                    &[
                        (format!("{:016X}", im.offset), t.addr),
                        (format!("{}!{}", im.library, im.name), t.text),
                    ],
                    top,
                    line_h,
                    char_w,
                );
            }
        }
        let first = clamp_tab_first(shell.bottom_scroll, rows.len());
        if rows.is_empty() {
            return empty_state(
                "No imports".to_string(),
                if shell.read(|s| s.binary.is_some()) {
                    "This binary declares no imports.".to_string()
                } else {
                    "Open a binary to list its imports.".to_string()
                },
            );
        }
        return column![
            table_header(IMPORT_COLUMNS),
            vlist(ImpData {
                rows,
                first,
                tok: table_tokens(shell),
                rev: table_rev(shell)
            })
        ]
        .spacing(0)
        .into();
    }
    let rows = shell.snap_exports.clone();
    struct ExpData {
        rows: Arc<Vec<crate::parser::Export>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for ExpData {
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
            self.rows.get(i).and_then(|ex| {
                if ex.offset != 0 {
                    Some(Message::RowGoto(ex.offset))
                } else {
                    None
                }
            })
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
            let Some(ex) = self.rows.get(i) else { return };
            let color = if ex.forwarder.is_some() {
                t.annot
            } else {
                t.string
            };
            paint_columns(
                frame,
                EXPORT_COLUMNS,
                &[
                    (format!("{:016X}", ex.offset), t.addr),
                    (ex.ordinal.to_string(), t.dim),
                    (
                        format!(
                            "{}{}",
                            ex.name,
                            ex.forwarder
                                .as_deref()
                                .map(|f| format!(" -> {f}"))
                                .unwrap_or_default()
                        ),
                        color,
                    ),
                ],
                top,
                line_h,
                char_w,
            );
        }
    }
    let first = clamp_tab_first(shell.bottom_scroll, rows.len());
    if rows.is_empty() {
        return empty_state(
            "No exports".to_string(),
            if shell.read(|s| s.binary.is_some()) {
                "This binary declares no exports.".to_string()
            } else {
                "Open a binary to list its exports.".to_string()
            },
        );
    }
    column![
        table_header(EXPORT_COLUMNS),
        vlist(ExpData {
            rows,
            first,
            tok: table_tokens(shell),
            rev: table_rev(shell)
        })
    ]
    .spacing(0)
    .into()
}
