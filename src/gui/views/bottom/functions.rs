use std::sync::Arc;

use iced::widget::{column, row, text_input};
use iced::{Element, Theme};

use super::super::empty_state;
use super::FUNCTION_COLUMNS;
use super::{clamp_tab_first, lock, paint_columns, table_header, table_rev, table_tokens, FuncRow};
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, T};
use crate::gui::widgets::vlist::{vlist, VListData};

pub(crate) fn functions_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let filter = shell.read(|s| s.func_filter.clone());
    let filter_lc = filter.to_lowercase();
    let sort = shell.read(|s| s.func_sort);
    let total = shell.read(|s| s.analysis.as_ref().map(|a| a.functions.len()).unwrap_or(0));
    let rows: Arc<Vec<FuncRow>> = shell.read(|s| {
        let mut cache = lock(&shell.table_cache.functions);
        if cache.0 == s.analysis_version
            && cache.1 == s.modification_number
            && cache.2 == filter_lc
            && cache.3 == sort
            && let Some(rows) = &cache.4 {
                return rows.clone();
            }
        let rows: Arc<Vec<FuncRow>> = match &s.analysis {
            None => Arc::new(Vec::new()),
            Some(a) => {
                let idx = crate::gui::actions::functions_filtered(a, &filter_lc, sort);
                Arc::new(
                    idx.iter()
                        .filter_map(|&i| a.functions.get(i))
                        .map(|f| {
                            let src = match f.source {
                                crate::analysis::FuncSource::EntryPoint => "EP",
                                crate::analysis::FuncSource::SymbolTable => "SY",
                                crate::analysis::FuncSource::CallTarget => "CT",
                                crate::analysis::FuncSource::Prologue => "PR",
                                crate::analysis::FuncSource::AfterReturn => "AR",
                                crate::analysis::FuncSource::UnwindInfo => "UW",
                                crate::analysis::FuncSource::UserDefined => "US",
                                crate::analysis::FuncSource::DataPointer => "DP",
                            };
                            let xrefs = a.xrefs.by_to.get(&f.entry).map(|v| v.len()).unwrap_or(0);
                            let name = match a.stubs.get(&f.entry) {
                                Some(st) => format!("{}  → {}", f.name, st.target_name),
                                None => s.user_func_names.get(&f.entry).unwrap_or(&f.name).clone(),
                            };
                            (
                                f.entry,
                                src.to_string(),
                                name,
                                f.end - f.entry,
                                xrefs,
                                f.has_frame,
                            )
                        })
                        .collect(),
                )
            }
        };
        *cache = (
            s.analysis_version,
            s.modification_number,
            filter_lc.clone(),
            sort,
            Some(rows.clone()),
        );
        rows
    });

    struct FuncData {
        rows: Arc<Vec<FuncRow>>,
        first: usize,
        selected: Option<usize>,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for FuncData {
        type Message = Message;
        fn len(&self) -> usize {
            self.rows.len()
        }
        fn first(&self) -> usize {
            self.first
        }
        fn scroll_msg(&self, f: usize) -> Message {
            Message::FuncScroll(f)
        }
        fn selected(&self) -> Option<usize> {
            self.selected
        }
        fn row_action(&self, i: usize) -> Option<Message> {
            self.rows
                .get(i)
                .map(|(e, _, _, _, _, _)| Message::FuncPicked(*e))
        }
        fn menu_entries(&self, i: usize) -> Vec<(String, Message)> {
            self.rows
                .get(i)
                .map(|(e, _, _, _, _, _)| {
                    vec![
                        ("Rename (F2)".to_string(), Message::RenameRequest(*e)),
                        ("Add Bookmark…".to_string(), Message::BookmarkRequest(*e)),
                        ("Go to address".to_string(), Message::RowGoto(*e)),
                    ]
                })
                .unwrap_or_default()
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
            let Some((entry, src, name, size, xrefs, has_frame)) = self.rows.get(i) else {
                return;
            };
            paint_columns(
                frame,
                FUNCTION_COLUMNS,
                &[
                    (format!("{entry:016X}"), t.addr),
                    (src.clone(), t.mint),
                    (if *has_frame { "yes" } else { "no" }.into(), t.mute),
                    (size.to_string(), t.dim),
                    (xrefs.to_string(), t.dim),
                    (name.clone(), t.text),
                ],
                top,
                line_h,
                char_w,
            );
        }
    }

    let first = clamp_tab_first(shell.funcs_first, rows.len());
    let list: Element<'_, Message, Theme, iced::Renderer> = if rows.is_empty() {
        empty_state(
            "No functions".to_string(),
            if total == 0 {
                "Analysis starts automatically after opening a file.".to_string()
            } else {
                "Nothing matches this filter. Clear the filter to see all functions.".to_string()
            },
        )
    } else {
        let selected_addr = shell.read(|s| s.selected_func);
        let selected = selected_addr.and_then(|addr| rows.iter().position(|r| r.0 == addr));
        vlist(FuncData {
            rows,
            first,
            selected,
            tok: table_tokens(shell),
            rev: table_rev(shell),
        })
        .into()
    };
    column![
        row![
            text_input("Filter (name/addr)", &filter)
                .width(220)
                .on_input(Message::FuncFilterEdited)
                .style(crate::gui::theme::input_style),
            label(format!("({total} total)"), T::Mute),
        ]
        .spacing(8),
        table_header(FUNCTION_COLUMNS),
        list
    ]
    .spacing(6)
    .into()
}
