use std::sync::Arc;

use iced::widget::{button, column};
use iced::{Element, Theme};

use super::super::empty_state;
use super::{clamp_tab_first, put_text, table_rev, table_tokens};
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, Btn, T};
use crate::gui::widgets::vlist::{vlist, VListData};

type PatchRow = (u64, usize, u64, usize, String);

pub(crate) fn patches_tab(shell: &Shell) -> Element<'_, Message, Theme, iced::Renderer> {
    let rows: Arc<Vec<PatchRow>> = shell.read(|s| {
        Arc::new(
            s.patches
                .iter()
                .map(|p| (p.id, p.offset, p.vaddr, p.new.len(), p.description.clone()))
                .collect(),
        )
    });
    let count = rows.len();
    struct PatData {
        rows: Arc<Vec<PatchRow>>,
        first: usize,
        tok: crate::gui::theme::Tokens,
        rev: u64,
    }
    impl VListData for PatData {
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
            self.rows.get(i).map(|(_, _, v, _, _)| Message::RowGoto(*v))
        }
        fn menu_entries(&self, i: usize) -> Vec<(String, Message)> {
            self.rows
                .get(i)
                .map(|(_, _, v, _, _)| vec![("Undo patch here".into(), Message::PatchUndo(*v))])
                .unwrap_or_default()
        }
        fn menu_open_action(&self) -> Option<Message> {
            Some(Message::AnimationTick)
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
            let Some((id, off, vaddr, size, desc)) = self.rows.get(i) else {
                return;
            };
            put_text(frame, 8.0, top, line_h, format!("#{id:<4} "), t.mint);
            put_text(
                frame,
                8.0 + 6.0 * char_w,
                top,
                line_h,
                format!("{off:#010x}  "),
                t.addr,
            );
            put_text(
                frame,
                8.0 + 18.0 * char_w,
                top,
                line_h,
                format!("{vaddr:#012x}  "),
                t.addr,
            );
            put_text(
                frame,
                8.0 + 32.0 * char_w,
                top,
                line_h,
                format!("{size:<6} "),
                t.dim,
            );
            put_text(
                frame,
                8.0 + 39.0 * char_w,
                top,
                line_h,
                desc.clone(),
                t.text,
            );
        }
    }
    if count == 0 {
        return empty_state(
            "No patches".to_string(),
            "Apply one with the MCP patch tools or Assemble to track it here.".to_string(),
        );
    }
    let first = clamp_tab_first(shell.bottom_scroll, count);
    column![
        button(label("Revert all patches", T::Base))
            .style(Btn::Quiet.style())
            .on_press(Message::PatchesRevert),
        vlist(PatData {
            rows,
            first,
            tok: table_tokens(shell),
            rev: table_rev(shell)
        })
    ]
    .into()
}
