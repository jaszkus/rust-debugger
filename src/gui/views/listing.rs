use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use iced::widget::container;
use iced::{Color, Element, Theme};

use super::{empty_state, escape_str, first_addr_in_operands, parse_addr_str};
use crate::gui::app::{Message, Shell};
use crate::gui::theme::Fonts;
use crate::gui::views::CtxAction;
use crate::gui::widgets::vlist::{vlist, VListData};

pub struct ListingSnap {
    pub instructions: std::sync::Arc<Vec<crate::disasm::DisasmInstruction>>,
    pub func_lookup: Arc<HashMap<u64, String>>,
    pub xref_to_func: Arc<HashMap<u64, usize>>,
    pub string_at: Arc<HashMap<u64, String>>,
    pub string_ranges: Arc<Vec<(u64, u64)>>,
    pub sorted_func_entries: Arc<Vec<u64>>,
    pub sorted_xref_addrs: Arc<Vec<u64>>,
    pub bp_set: Arc<HashSet<u64>>,
    pub rip: u64,
    pub selected: Option<u64>,
    pub labels: Arc<rustc_hash::FxHashMap<u64, String>>,
    pub comments: Arc<rustc_hash::FxHashMap<u64, String>>,
    pub address_digits: usize,
    pub(crate) row_cache: std::rc::Rc<RowCache>,
    pub first: usize,
    pub has_binary: bool,
    pub tokens: crate::gui::theme::Tokens,
    pub compact: bool,
    pub row_fp: u64,
}

#[derive(Clone, Default)]
pub(crate) struct SharedMaps {
    pub(crate) func_lookup: Arc<HashMap<u64, String>>,
    xref_to_func: Arc<HashMap<u64, usize>>,
    string_at: Arc<HashMap<u64, String>>,
    string_ranges: Arc<Vec<(u64, u64)>>,
    sorted_func_entries: Arc<Vec<u64>>,
    sorted_xref_addrs: Arc<Vec<u64>>,
}

fn shared_maps(shell: &Shell, version: u64, build: impl FnOnce() -> SharedMaps) -> SharedMaps {
    if let Some((v, m)) = shell.listing_maps.borrow().as_ref() {
        if *v == version {
            return m.clone();
        }
    }
    let m = build();
    *shell.listing_maps.borrow_mut() = Some((version, m.clone()));
    m
}

impl ListingSnap {
    pub fn take(shell: &Shell) -> ListingSnap {
        let light = shell.is_light();
        let compact = shell.compact_rows;
        shell.read(|s| {
            if s.disasm_cache.is_none() {
                s.rebuild_disasm_cache();
            }
            let version = s.analysis_version;
            let shared = shared_maps(shell, version, || {
                s.disasm_cache
                    .as_ref()
                    .map(|c| SharedMaps {
                        func_lookup: Arc::new(
                            c.func_lookup
                                .iter()
                                .map(|(addr, name)| {
                                    (*addr, s.user_func_names.get(addr).unwrap_or(name).clone())
                                })
                                .collect(),
                        ),
                        xref_to_func: Arc::new(c.xref_to_func.clone()),
                        string_at: Arc::new(c.string_at.clone()),
                        string_ranges: Arc::new(c.string_ranges.clone()),
                        sorted_func_entries: Arc::new(c.sorted_func_entries.clone()),
                        sorted_xref_addrs: Arc::new(c.sorted_xref_addrs.clone()),
                    })
                    .unwrap_or_default()
            });
            s.refresh_bp_set_if_needed();
            let row_fp = version
                .wrapping_mul(0xBF58476D1CE4E5B9)
                .wrapping_add(s.modification_number.wrapping_mul(0x94D049BB133111EB));
            let row_fp = row_fp
                .wrapping_add(if light { 0x51ab3c9d2f4e11 } else { 0 })
                .wrapping_add(if compact { 0x1f7a5c3d9e2b40 } else { 0 });
            ListingSnap {
                instructions: s
                    .disasm
                    .as_ref()
                    .map(|d| d.instructions.clone())
                    .unwrap_or_default(),
                func_lookup: shared.func_lookup,
                xref_to_func: shared.xref_to_func,
                string_at: shared.string_at,
                string_ranges: shared.string_ranges,
                sorted_func_entries: shared.sorted_func_entries,
                sorted_xref_addrs: shared.sorted_xref_addrs,
                bp_set: shell.view_annotations.borrow().0.clone(),
                rip: s.debug_state.current_rip,
                selected: s.selected_insn,
                labels: shell.view_annotations.borrow().1.clone(),
                comments: shell.view_annotations.borrow().2.clone(),
                row_cache: shell.listing_rows.clone(),
                address_digits: if s
                    .disasm
                    .as_ref()
                    .map(|d| d.arch.contains("64"))
                    .unwrap_or(false)
                {
                    16
                } else {
                    8
                },
                first: 0,
                has_binary: s.binary.is_some(),
                row_fp,
                tokens: crate::gui::theme::Tokens::resolve(light),
                compact,
            }
        })
    }
}

impl VListData for &ListingSnap {
    type Message = Message;

    fn len(&self) -> usize {
        self.instructions.len()
    }

    fn first(&self) -> usize {
        self.first
    }

    fn revision(&self) -> u64 {
        self.row_fp
    }

    fn scroll_msg(&self, first: usize) -> Message {
        Message::ListingScroll(first)
    }

    fn selected(&self) -> Option<usize> {
        let sel = self.selected?;
        let pos = self.instructions.partition_point(|x| x.address < sel);
        match self.instructions.get(pos) {
            Some(insn) if insn.address == sel => Some(pos),
            _ => None,
        }
    }

    fn row_action(&self, i: usize) -> Option<Message> {
        self.instructions
            .get(i)
            .map(|x| Message::ListingClicked(x.address))
    }

    fn open_action(&self, i: usize) -> Option<Message> {
        self.instructions
            .get(i)
            .map(|x| Message::ListingOpen(x.address))
    }
    fn copy_action(&self, i: usize) -> Option<Message> {
        self.instructions
            .get(i)
            .map(|x| Message::CopyAddress(x.address))
    }
    fn gutter_action(&self, i: usize) -> Option<Message> {
        self.instructions
            .get(i)
            .map(|x| Message::ListingCtxAction(CtxAction::ToggleBp, x.address))
    }

    fn menu_entries(&self, i: usize) -> Vec<(String, Message)> {
        let Some(insn) = self.instructions.get(i) else {
            return Vec::new();
        };
        let addr = insn.address;
        let mut v = vec![
            (
                "Toggle Breakpoint".to_string(),
                Message::ListingCtxAction(CtxAction::ToggleBp, addr),
            ),
            (
                "Add Comment…".to_string(),
                Message::ListingCtxAction(CtxAction::Comment, addr),
            ),
            (
                "Add Bookmark…".to_string(),
                Message::ListingCtxAction(CtxAction::Bookmark, addr),
            ),
            (
                "Copy Address  Ctrl+C".to_string(),
                Message::CopyAddress(addr),
            ),
            ("Copy Bytes".to_string(), Message::CopyBytes(addr)),
            ("Rename  N / F2".to_string(), Message::RenameRequest(addr)),
        ];
        if let Some(target) = first_addr_in_operands(&insn.ops()) {
            v.push((
                "Jump to Operand".to_string(),
                Message::ListingCtxAction(CtxAction::Goto, target),
            ));
        }
        v
    }

    fn row_wash(&self, i: usize) -> Option<Color> {
        let insn = self.instructions.get(i)?;
        if self.bp_set.contains(&insn.address) {
            return Some(self.tokens.brk.scale_alpha(0.10));
        }
        if self.rip != 0 && self.rip == insn.address {
            return Some(self.tokens.run.scale_alpha(0.12));
        }
        None
    }

    fn paint_chrome(
        &self,
        i: usize,
        top: f32,
        line_h: f32,
        hover: bool,
        frame: &mut iced::widget::canvas::Frame,
    ) {
        if let Some(insn) = self.instructions.get(i) {
            if self.selected == Some(insn.address) || self.rip == insn.address {
                frame.fill_rectangle(
                    iced::Point::new(0.0, top),
                    iced::Size::new(3.0, line_h),
                    if self.rip == insn.address {
                        self.tokens.run
                    } else {
                        self.tokens.mint
                    },
                );
            }
        }
        if let Some(insn) = self.instructions.get(i) {
            let cx = 12.5;
            let cy = top + line_h / 2.0;
            let is_bp = self.bp_set.contains(&insn.address);
            let is_rip = self.rip == insn.address;
            let is_sel = self.selected == Some(insn.address);
            if is_bp || is_rip || is_sel || hover {
                use iced::widget::canvas::{Path, Stroke};
                let dot = Path::circle(iced::Point::new(cx, cy), 4.5);
                if is_bp {
                    frame.fill(&dot, self.tokens.mint);
                } else if is_rip {
                    frame.fill(&dot, self.tokens.run);
                } else {
                    frame.stroke(
                        &dot,
                        Stroke::default()
                            .with_color(self.tokens.mint.scale_alpha(if hover && !is_sel {
                                0.4
                            } else {
                                1.0
                            }))
                            .with_width(1.5),
                    );
                }
            }
        }
    }

    fn paint_row(
        &self,
        i: usize,
        top: f32,
        line_h: f32,
        char_w: f32,
        frame: &mut iced::widget::canvas::Frame,
    ) {
        use crate::gui::widgets::vlist::{text_fits, truncate_cols, MONO_CHAR_W};
        use iced::advanced::text::{Alignment, LineHeight, Shaping};
        use iced::widget::canvas::Text as CText;
        if line_h <= 0.0 {
            return;
        }
        let (w, h) = (frame.width(), frame.height());
        if w <= 0.0 || h <= 0.0 {
            return;
        }
        if !text_fits(top, h) {
            return;
        }
        let tokens = cached_row_tokens(self, i, self.row_fp, char_w);
        for tok in tokens.iter() {
            if tok.x >= w {
                continue;
            }
            let max_cols = (((w - tok.x) / MONO_CHAR_W) as usize).saturating_sub(2);
            let owned;
            let text: &str = if tok.text.chars().count() <= max_cols {
                &tok.text
            } else if max_cols < 4 {
                continue;
            } else {
                owned = truncate_cols(&tok.text, max_cols);
                &owned
            };
            if text.is_empty() {
                continue;
            }
            frame.fill_text(CText {
                content: text.to_owned(),
                position: iced::Point::new(tok.x, top),
                color: tok.color,
                size: iced::Pixels(tok.size),
                line_height: LineHeight::Absolute(iced::Pixels(line_h)),
                font: tok.font.unwrap_or_else(crate::gui::theme::mono_font),
                align_x: Alignment::Left,
                align_y: iced::alignment::Vertical::Top,
                shaping: Shaping::Basic,
                max_width: f32::INFINITY,
            });
        }
    }
}

#[derive(Clone)]
pub(crate) struct RowToken {
    x: f32,
    text: String,
    color: Color,
    font: Option<iced::Font>,
    size: f32,
}

pub(crate) type RowCache = RefCell<(u64, u32, HashMap<usize, Arc<Vec<RowToken>>>)>;

const ROW_CACHE_CAP: usize = 4096;

fn cached_row_tokens(
    snap: &ListingSnap,
    i: usize,
    fp: u64,
    char_w: f32,
) -> std::sync::Arc<Vec<RowToken>> {
    let cw = char_w.to_bits();
    if let Some(hit) = {
        let cache = snap.row_cache.borrow();
        (cache.0 == fp && cache.1 == cw)
            .then(|| cache.2.get(&i).cloned())
            .flatten()
    } {
        return hit;
    }
    let tokens = std::sync::Arc::new(build_row_tokens(snap, i, char_w));
    {
        let (cfp, ccw, map) = &mut *snap.row_cache.borrow_mut();
        if *cfp != fp || *ccw != cw {
            *cfp = fp;
            *ccw = cw;
            map.clear();
        }
        if map.len() >= ROW_CACHE_CAP {
            map.clear();
        }
        map.insert(i, tokens.clone());
    }
    tokens
}

fn emit_operand_tokens(
    emit: &mut impl FnMut(f32, String, Color),
    x: f32,
    ops: &str,
    t: crate::gui::theme::Tokens,
    char_w: f32,
) {
    let mut offset = 0;
    for token in ops.split_inclusive(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        let word = token
            .trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        let color = if word.starts_with("0x") || word.chars().all(|c| c.is_ascii_digit()) {
            t.annot
        } else if matches!(
            word.as_str(),
            "rax"
                | "rbx"
                | "rcx"
                | "rdx"
                | "rsi"
                | "rdi"
                | "rsp"
                | "rbp"
                | "eax"
                | "ebx"
                | "ecx"
                | "edx"
                | "esi"
                | "edi"
                | "esp"
                | "ebp"
                | "rip"
        ) || (word.starts_with('r') && word[1..].chars().all(|c| c.is_ascii_digit()))
        {
            t.link
        } else if token.contains('[') || token.contains(']') {
            t.mint
        } else {
            t.operand
        };
        emit(x + offset as f32 * char_w, token.into(), color);
        offset += token.chars().count();
    }
}

fn build_row_tokens(snap: &ListingSnap, i: usize, char_w: f32) -> Vec<RowToken> {
    use crate::gui::widgets::vlist::truncate_cols;
    let mut out: Vec<RowToken> = Vec::new();
    let mut emit = |x: f32, text: String, color: Color| {
        if !text.is_empty() {
            out.push(RowToken {
                x,
                text,
                color,
                font: None,
                size: 12.5,
            });
        }
    };
    let t = snap.tokens;

    let Some(insn) = snap.instructions.get(i) else {
        return out;
    };
    let addr_x = 24.0;
    let address_w = 118.0_f32.max(snap.address_digits as f32 * char_w + 8.0);
    let mn_x = addr_x + address_w + 30.0;
    let ops_x = mn_x + 72.0;

    let sidx = snap
        .string_ranges
        .partition_point(|&(s, _)| s <= insn.address);
    let in_str = sidx > 0 && insn.address < snap.string_ranges[sidx - 1].1;
    if in_str {
        let start = snap.string_ranges[sidx - 1].0;
        if start == insn.address {
            let content = snap.string_at.get(&start).map(|c| c.as_str()).unwrap_or("");
            emit(
                addr_x,
                format!(
                    "{:0width$X}  db \"{}\",0",
                    insn.address,
                    escape_str(content),
                    width = snap.address_digits
                ),
                t.string,
            );
        } else {
            emit(
                addr_x,
                format!(
                    "{:0width$X}  ...",
                    insn.address,
                    width = snap.address_digits
                ),
                t.mute,
            );
        }
        return out;
    }

    let function_note = snap.func_lookup.get(&insn.address).map(|name| {
        format!(
            "// {name}  XREF[{}]",
            snap.xref_to_func.get(&insn.address).copied().unwrap_or(0)
        )
    });
    if let Some(note) = function_note.as_ref() {
        emit(ops_x + 220.0, note.clone(), t.mint);
    }

    let mut emit = |x: f32, text: String, color: Color| {
        if !text.is_empty() {
            out.push(RowToken {
                x,
                text,
                color,
                font: None,
                size: 12.5,
            });
        }
    };
    if let Some(l) = snap.labels.get(&insn.address) {
        emit(ops_x + 220.0, format!("{}:", truncate_cols(l, 24)), t.mint);
    }
    emit(
        addr_x,
        format!("{:0width$X}", insn.address, width = snap.address_digits),
        t.addr,
    );

    let is_flow = insn.mnemonic.starts_with('j')
        || insn.mnemonic.starts_with("call")
        || insn.mnemonic.starts_with("ret")
        || insn.mnemonic.starts_with("loop");
    emit(
        mn_x,
        insn.mnemonic.to_string(),
        if is_flow { t.link } else { t.mnemonic },
    );
    let ops = insn.ops();
    if is_flow {
        match parse_addr_str(&ops)
            .and_then(|tgt| snap.func_lookup.get(&tgt).map(|n| (tgt, n.as_str())))
        {
            Some((tgt, n)) => {
                let head = format!("{tgt:#x} ");
                emit(ops_x, head.clone(), t.operand);
                emit(
                    ops_x + head.chars().count() as f32 * char_w,
                    format!("<{n}>"),
                    t.mint,
                );
            }
            None => emit_operand_tokens(&mut emit, ops_x, &ops, t, char_w),
        }
    } else {
        emit_operand_tokens(&mut emit, ops_x, &ops, t, char_w);
    }

    let ops_cols = insn.ops().chars().count();
    let eol_x = ops_x + (ops_cols + 1) as f32 * char_w;
    if let Some(c) = snap.comments.get(&insn.address) {
        emit(eol_x, format!("; {c}"), t.annot);
    } else if let Some(count) = snap.xref_to_func.get(&insn.address) {
        if *count > 0 {
            emit(
                eol_x,
                format!(
                    "loc_{:X} ({} xref{})",
                    insn.address,
                    count,
                    if *count == 1 { "" } else { "s" }
                ),
                t.annot,
            );
        }
    } else if let Some(target) = first_addr_in_operands(&insn.ops()) {
        if let Some(s) = snap.string_at.get(&target) {
            let preview: &str = match s.char_indices().nth(60) {
                Some((idx, _)) => &s[..idx],
                None => s,
            };
            emit(eol_x, format!("; \"{preview}\""), t.string);
        }
    }
    out
}

pub fn view<'a>(shell: &'a Shell, fonts: &'a Fonts) -> Element<'a, Message, Theme, iced::Renderer> {
    let snap = ListingSnap::take(shell);
    if snap.instructions.is_empty() {
        return empty_state(
            "No binary loaded".to_string(),
            "Open a file to disassemble it here.".to_string(),
        );
    }
    let first = shell.listing_first;
    let line_h = 25.0;
    let tokens = snap.tokens;
    let data = ListingViewData {
        snap,
        first,
        cursor: shell.ai_cursor_view,
    };
    let list = vlist(data)
        .font(fonts.mono())
        .font_size(12.5)
        .line_h(line_h)
        .hover(tokens.hover)
        .selected(tokens.select)
        .cursor(tokens.select, tokens.mint);
    container(list)
        .width(iced::Length::Fill)
        .height(iced::Length::Fill)
        .style(crate::gui::theme::reading_style)
        .into()
}

struct ListingViewData {
    snap: ListingSnap,
    first: usize,
    cursor: Option<(f32, f32)>,
}

impl VListData for ListingViewData {
    type Message = Message;

    fn len(&self) -> usize {
        self.snap.instructions.len()
    }
    fn first(&self) -> usize {
        self.first
    }
    fn revision(&self) -> u64 {
        self.snap.row_fp
    }
    fn ai_cursor(&self) -> Option<(f32, f32)> {
        self.cursor
    }
    fn scroll_msg(&self, first: usize) -> Message {
        Message::ListingScroll(first)
    }
    fn selected(&self) -> Option<usize> {
        VListData::selected(&&self.snap)
    }
    fn row_action(&self, i: usize) -> Option<Message> {
        VListData::row_action(&&self.snap, i)
    }
    fn open_action(&self, i: usize) -> Option<Message> {
        VListData::open_action(&&self.snap, i)
    }
    fn copy_action(&self, i: usize) -> Option<Message> {
        VListData::copy_action(&&self.snap, i)
    }
    fn gutter_action(&self, i: usize) -> Option<Message> {
        VListData::gutter_action(&&self.snap, i)
    }
    fn menu_entries(&self, i: usize) -> Vec<(String, Message)> {
        VListData::menu_entries(&&self.snap, i)
    }
    fn paint_chrome(
        &self,
        i: usize,
        top: f32,
        line_h: f32,
        hover: bool,
        frame: &mut iced::widget::canvas::Frame,
    ) {
        VListData::paint_chrome(&&self.snap, i, top, line_h, hover, frame);
    }
    fn row_wash(&self, i: usize) -> Option<Color> {
        VListData::row_wash(&&self.snap, i)
    }
    fn paint_row(
        &self,
        i: usize,
        top: f32,
        line_h: f32,
        char_w: f32,
        frame: &mut iced::widget::canvas::Frame,
    ) {
        VListData::paint_row(&&self.snap, i, top, line_h, char_w, frame);
    }
}
