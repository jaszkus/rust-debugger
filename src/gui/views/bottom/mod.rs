use std::sync::{Arc, Mutex};

use iced::widget::{container, row};
use iced::{Color, Element, Theme};

use super::empty_state;
use crate::gui::app::{Message, Shell, BOTTOM_TABS};
use crate::gui::theme::{label, Fonts, T};
use crate::gui::widgets::vlist::{Cell, VListData};

#[derive(Clone)]
pub struct RowCells {
    pub cells: Vec<Cell>,
    pub addr: Option<u64>,
}

pub struct RowsData {
    pub rows: Vec<RowCells>,
    pub first: usize,
    pub selected: Option<usize>,
    pub rev: u64,
}

impl VListData for RowsData {
    type Message = Message;

    fn len(&self) -> usize {
        self.rows.len()
    }
    fn first(&self) -> usize {
        self.first
    }
    fn scroll_msg(&self, first: usize) -> Message {
        Message::BottomScroll(first)
    }
    fn selected(&self) -> Option<usize> {
        self.selected
    }
    fn row_action(&self, i: usize) -> Option<Message> {
        self.rows.get(i).and_then(|r| r.addr).map(Message::RowGoto)
    }
    fn menu_entries(&self, i: usize) -> Vec<(String, Message)> {
        match self.rows.get(i).and_then(|r| r.addr) {
            Some(addr) => vec![
                ("Go to address".to_string(), Message::RowGoto(addr)),
                ("Copy Address".to_string(), Message::CopyAddress(addr)),
                (
                    "Add Comment…".to_string(),
                    crate::gui::app::Message::CommentRequest(addr),
                ),
                ("Add Bookmark…".to_string(), Message::BookmarkRequest(addr)),
            ],
            None => Vec::new(),
        }
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
        let Some(row) = self.rows.get(i) else { return };
        let mut x = 8.0;
        for cell in &row.cells {
            let cx = x;
            put_text(frame, cx, top, line_h, cell.text.clone(), cell.color);
            let advance = match cell.width_cols {
                Some(cols) => cols as f32 * char_w,
                None => cell.text.chars().count() as f32 * char_w + char_w,
            };
            if !cell.inline {
                x += advance;
            } else {
                x += cell.text.chars().count() as f32 * char_w;
            }
        }
    }
}

fn table_tokens(shell: &Shell) -> crate::gui::theme::Tokens {
    crate::gui::theme::Tokens::resolve(shell.is_light())
}

fn table_rev(shell: &Shell) -> u64 {
    shell.read(|s| {
        s.analysis_version
            .wrapping_mul(0xBF58476D1CE4E5B9)
            .wrapping_add(s.modification_number.wrapping_mul(0x94D049BB133111EB))
    })
}

fn put_text(
    frame: &mut iced::widget::canvas::Frame,
    x: f32,
    top: f32,
    line_h: f32,
    s: String,
    color: Color,
) {
    use iced::advanced::text::{Alignment, LineHeight, Shaping};
    use iced::widget::canvas::Text as CText;
    if line_h <= 0.0 || s.is_empty() {
        return;
    }
    let (w, h) = (frame.width(), frame.height());
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    if !crate::gui::widgets::vlist::text_fits(top, h) {
        return;
    }
    let max_cols = (((w - x) / 7.8) as usize).saturating_sub(2);
    let s = crate::gui::widgets::vlist::truncate_cols(&s, max_cols.max(4));
    if s.is_empty() {
        return;
    }
    frame.fill_text(CText {
        content: s,
        position: iced::Point::new(x, top),
        color,
        size: iced::Pixels(13.0),
        line_height: LineHeight::Absolute(iced::Pixels(line_h)),
        font: crate::gui::theme::mono_font(),
        align_x: Alignment::Left,
        align_y: iced::alignment::Vertical::Top,
        shaping: Shaping::Basic,
        max_width: f32::INFINITY,
    });
}

fn mc(s: impl Into<String>, c: Color) -> Cell {
    Cell::new(s, c)
}

fn clamp_tab_first(first: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        first.min(len - 1)
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

type FuncRow = (u64, String, String, u64, usize, bool);
type XrefRow = (
    u64,
    u64,
    crate::analysis::XRefKind,
    Option<std::sync::Arc<str>>,
);

type FunctionsCache = Mutex<(u64, u64, String, usize, Option<Arc<Vec<FuncRow>>>)>;
type XrefsCache = Mutex<(u64, u64, usize, Option<Arc<Vec<XrefRow>>>)>;
type CommentsCache = Mutex<(u64, usize, Option<Arc<Vec<(u64, String, String)>>>)>;
type TagsCache = Mutex<(u64, usize, Option<Arc<Vec<(u64, Vec<String>)>>>)>;
type SignaturesCache = Mutex<(
    u64,
    u64,
    usize,
    Option<Arc<Vec<(u64, String, String, usize)>>>,
)>;
type PcodeCache = Mutex<(
    u64,
    u64,
    Option<u64>,
    Option<Arc<Vec<(u64, String, String)>>>,
)>;
type DebugCache = Mutex<(u64, u64, usize, Option<Arc<Vec<(u64, String, bool)>>>)>;

pub struct ViewCache {
    functions: FunctionsCache,
    xrefs: XrefsCache,
    comments: CommentsCache,
    tags: TagsCache,
    signatures: SignaturesCache,
    pcode: PcodeCache,
    debug: DebugCache,
}
impl Default for ViewCache {
    fn default() -> Self {
        Self {
            functions: Mutex::new((u64::MAX, u64::MAX, String::new(), 0, None)),
            xrefs: Mutex::new((u64::MAX, u64::MAX, 0, None)),
            comments: Mutex::new((u64::MAX, 0, None)),
            tags: Mutex::new((u64::MAX, 0, None)),
            signatures: Mutex::new((u64::MAX, u64::MAX, 0, None)),
            pcode: Mutex::new((u64::MAX, u64::MAX, None, None)),
            debug: Mutex::new((u64::MAX, u64::MAX, 0, None)),
        }
    }
}

pub fn view<'a>(shell: &'a Shell, fonts: &'a Fonts) -> Element<'a, Message, Theme, iced::Renderer> {
    let tab = shell.bottom_tab;
    let content: Element<'_, Message, Theme, iced::Renderer> = match BOTTOM_TABS[tab] {
        "Hex" => hex_tab(shell),
        "Strings" => strings_tab(shell),
        "Imports" => imports_tab(shell),
        "Exports" => exports_tab(shell),
        "Symbols" => symbols_tab(shell),
        "Sections" => sections_tab(shell),
        "Functions" => functions_tab(shell),
        "XRefs" => xrefs_tab(shell),
        "Decompiler" => decompiler_tab(shell),
        "CFG" => super::cfg::view(shell, fonts),
        "Stack" => stack_tab(shell),
        "PCode" => pcode_tab(shell),
        "Resources" => resources_tab(shell),
        "Debug" => debug_symbols_tab(shell),
        "Types" => types_tab(shell),
        "Signatures" => signatures_tab(shell),
        "Comments" => comments_tab(shell),
        "Tags" => tags_tab(shell),
        "Patches" => patches_tab(shell),
        "Programs" => programs_tab(shell),
        _ => empty_state(
            "Unknown tab".to_string(),
            "This tab is not implemented yet.".to_string(),
        ),
    };
    content
}

#[derive(Clone, Copy)]
struct Column {
    title: &'static str,
    width_cols: usize,
}
const FUNCTION_COLUMNS: &[Column] = &[
    Column {
        title: "Address",
        width_cols: 18,
    },
    Column {
        title: "Source",
        width_cols: 7,
    },
    Column {
        title: "Frame",
        width_cols: 6,
    },
    Column {
        title: "Size",
        width_cols: 10,
    },
    Column {
        title: "XRefs",
        width_cols: 7,
    },
    Column {
        title: "Name",
        width_cols: 60,
    },
];
const IMPORT_COLUMNS: &[Column] = &[
    Column {
        title: "Address",
        width_cols: 18,
    },
    Column {
        title: "Library!Function",
        width_cols: 70,
    },
];
const EXPORT_COLUMNS: &[Column] = &[
    Column {
        title: "Address",
        width_cols: 18,
    },
    Column {
        title: "Ordinal",
        width_cols: 9,
    },
    Column {
        title: "Name / Forwarder",
        width_cols: 60,
    },
];
const STRING_COLUMNS: &[Column] = &[
    Column {
        title: "Address",
        width_cols: 18,
    },
    Column {
        title: "Encoding",
        width_cols: 10,
    },
    Column {
        title: "Value",
        width_cols: 80,
    },
];
const XREF_COLUMNS: &[Column] = &[
    Column {
        title: "From",
        width_cols: 18,
    },
    Column {
        title: "Target",
        width_cols: 18,
    },
    Column {
        title: "Type",
        width_cols: 8,
    },
    Column {
        title: "Note",
        width_cols: 60,
    },
];
fn paint_columns(
    frame: &mut iced::widget::canvas::Frame,
    columns: &[Column],
    values: &[(String, Color)],
    top: f32,
    line_h: f32,
    char_w: f32,
) {
    let mut x = 8.0;
    for (col, (value, color)) in columns.iter().zip(values) {
        put_text(
            frame,
            x,
            top,
            line_h,
            crate::gui::widgets::vlist::truncate_cols(value, col.width_cols.saturating_sub(2)),
            *color,
        );
        x += col.width_cols as f32 * char_w;
    }
}
fn table_header<'a>(cols: &[Column]) -> Element<'a, Message, Theme, iced::Renderer> {
    use iced::widget::column;
    column![
        container(
            row(cols
                .iter()
                .map(|c| container(
                    label(c.title, T::Dim)
                        .size(11)
                        .font(crate::gui::theme::mono_font())
                )
                .width(c.width_cols as f32 * 7.8)
                .into())
                .collect::<Vec<Element<'a, Message, Theme, iced::Renderer>>>())
            .spacing(0),
        )
        .padding(crate::gui::theme::pad4(6.0, 8.0, 6.0, 8.0))
        .style(|theme| iced::widget::container::Style {
            background: Some(crate::gui::theme::app_bg_c(theme).into()),
            ..Default::default()
        }),
        iced::widget::rule::horizontal(1).style(|theme| iced::widget::rule::Style {
            color: crate::gui::theme::line_c(theme),
            radius: iced::border::Radius::default(),
            fill_mode: iced::widget::rule::FillMode::Full,
            snap: true,
        }),
    ]
    .spacing(0)
    .into()
}

mod comments;
mod datatypes;
mod debug;
mod debug_symbols;
mod decompiler;
mod functions;
mod hex;
mod imports;
mod live;
mod logs;
mod patches;
mod pcode;
mod programs;
mod resources;
mod sections;
mod signatures;
mod stack;
mod strings;
mod symbols;
mod tags;
mod xrefs;

use comments::comments_tab;
use datatypes::types_tab;
use debug_symbols::debug_symbols_tab;
use decompiler::decompiler_tab;
use functions::functions_tab;
use hex::hex_tab;
use imports::{exports_tab, imports_tab};
use patches::patches_tab;
use pcode::pcode_tab;
use programs::programs_tab;
use resources::resources_tab;
use sections::sections_tab;
use signatures::signatures_tab;
use stack::stack_tab;
use strings::strings_tab;
use symbols::symbols_tab;
use tags::tags_tab;
use xrefs::xrefs_tab;

pub use debug::debug_view;
pub use live::ai_live_view;
pub use logs::{ai_logs_view, seg_button};
