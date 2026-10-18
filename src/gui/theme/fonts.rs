use iced::widget::text as text_widget;
use iced::{Color, Font, Theme};

use super::colors::*;

pub const INTER_400_BYTES: &[u8] = include_bytes!("../../../assets/Inter-400.ttf");
pub const INTER_500_BYTES: &[u8] = include_bytes!("../../../assets/Inter-500.ttf");
pub const INTER_600_BYTES: &[u8] = include_bytes!("../../../assets/Inter-600.ttf");
pub const JBM_400_BYTES: &[u8] = include_bytes!("../../../assets/JetBrainsMono-400.ttf");
pub const JBM_500_BYTES: &[u8] = include_bytes!("../../../assets/JetBrainsMono-500.ttf");

pub const UI_FONT_NAME: &str = "Inter";
pub const MONO_FONT_NAME: &str = "JetBrains Mono";

pub fn ui_font(weight: iced::font::Weight) -> Font {
    Font {
        family: iced::font::Family::Name(UI_FONT_NAME),
        weight,
        ..Font::DEFAULT
    }
}

pub fn mono_font() -> Font {
    Font {
        family: iced::font::Family::Name(MONO_FONT_NAME),
        ..Font::DEFAULT
    }
}

pub struct Fonts {
    pub mono: Font,
    pub ui: Font,
}

pub const ALL_FONT_BYTES: [&[u8]; 5] = [
    INTER_400_BYTES,
    INTER_500_BYTES,
    INTER_600_BYTES,
    JBM_400_BYTES,
    JBM_500_BYTES,
];

impl Fonts {
    pub fn load() -> Self {
        Self {
            mono: mono_font(),
            ui: ui_font(iced::font::Weight::Normal),
        }
    }
    pub fn mono(&self) -> Font {
        self.mono
    }
    pub fn ui(&self) -> Font {
        self.ui
    }
}

pub const CAPTION_SIZE: f32 = 11.0;
pub const BODY_SIZE: f32 = 13.0;
pub const TITLE_SIZE: f32 = 15.0;
pub const HEADING_SIZE: f32 = 22.0;
pub const DATA_SIZE: f32 = 12.5;

#[derive(Clone, Copy)]
pub enum T {
    Strong,
    Base,
    Dim,
    Mute,
}

impl T {
    pub fn color(self) -> Color {
        match self {
            T::Strong | T::Base => Palette::TEXT,
            T::Dim => Palette::TEXT_DIM,
            T::Mute => Palette::TEXT_MUTE,
        }
    }

    pub fn color_in(self, theme: &Theme) -> Color {
        match self {
            T::Strong | T::Base => text_c(theme),
            T::Dim => dim_c(theme),
            T::Mute => mute_c(theme),
        }
    }
}

pub fn mono<'a>(s: impl text_widget::IntoFragment<'a>, strength: T) -> text_widget::Text<'a> {
    text_widget(s)
        .size(DATA_SIZE)
        .font(mono_font())
        .style(move |theme: &Theme| text_widget::Style {
            color: Some(strength.color_in(theme)),
        })
}

pub fn label<'a>(s: impl text_widget::IntoFragment<'a>, strength: T) -> text_widget::Text<'a> {
    text_widget(s)
        .size(BODY_SIZE)
        .font(ui_font(if matches!(strength, T::Strong) {
            iced::font::Weight::Semibold
        } else {
            iced::font::Weight::Normal
        }))
        .style(move |theme: &Theme| text_widget::Style {
            color: Some(strength.color_in(theme)),
        })
}

pub fn label_c<'a>(
    s: impl text_widget::IntoFragment<'a>,
    size: f32,
    weight: iced::font::Weight,
    c: Color,
) -> text_widget::Text<'a> {
    text_widget(s)
        .size(size)
        .font(ui_font(weight))
        .style(move |_: &Theme| text_widget::Style { color: Some(c) })
}

pub fn mono_c<'a>(
    s: impl text_widget::IntoFragment<'a>,
    size: f32,
    c: Color,
) -> text_widget::Text<'a> {
    text_widget(s)
        .size(size)
        .font(mono_font())
        .style(move |_: &Theme| text_widget::Style { color: Some(c) })
}

pub const ICON_FONT_BYTES: &[u8] = include_bytes!("../../../assets/MaterialSymbolsRounded.ttf");
pub const ICON_FONT_NAME: &str = "Material Symbols Rounded";

#[allow(dead_code)]
pub mod icon {
    pub const COMMENT: &str = "\u{e0b9}";
    pub const LINK: &str = "\u{e157}";
    pub const PLAY: &str = "\u{e037}";
    pub const SETTINGS: &str = "\u{e8b8}";
    pub const STOP: &str = "\u{e047}";
    pub const CHEVRON_LEFT: &str = "\u{e408}";
    pub const CHEVRON_RIGHT: &str = "\u{e409}";
    pub const CLOSE: &str = "\u{e14c}";
    pub const SEARCH: &str = "\u{e8b6}";
    pub const UNDO: &str = "\u{e166}";
    pub const REDO: &str = "\u{e15a}";
    pub const FOLDER_OPEN: &str = "\u{e2c8}";
    pub const MEMORY: &str = "\u{e322}";
    pub const BUG: &str = "\u{e868}";
    pub const CIRCLE: &str = "\u{ef4a}";
    pub const CIRCLE_O: &str = "\u{e836}";
    pub const ANALYZE: &str = "\u{ef3e}";
    pub const RUN: &str = "\u{e1c4}";
    pub const IMPORT: &str = "\u{e2c8}";
    pub const BOOKMARK: &str = "\u{e866}";
    pub const ADD: &str = "\u{e145}";
    pub const HISTORY: &str = "\u{e28e}";
    pub const COPY: &str = "\u{e14d}";
    pub const EDIT: &str = "\u{e150}";
    pub const DELETE: &str = "\u{e872}";
    pub const SAVE: &str = "\u{e161}";
    pub const CANCEL: &str = "\u{f08c}";
    pub const PROGRESS: &str = "\u{e9d0}";
    pub const WARNING: &str = "\u{f083}";
    pub const STEP_INTO: &str = "\u{eb8e}";
    pub const STEP_OVER: &str = "\u{eacd}";
    pub const CONTINUE: &str = "\u{e037}";
    pub const CHECK: &str = "\u{e668}";
    pub const FLAG: &str = "\u{e153}";
    pub const IDENTITY: &str = "\u{f10d}";
}

pub mod ic {
    pub const LIVE: &str =
        r#"<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>"#;
    pub const LOGS: &str = r#"<path d="M4 6h16M4 12h16M4 18h10"/>"#;
    pub const DIS: &str =
        r#"<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 10h6M9 14h4"/>"#;
    pub const FN: &str = r#"<path d="M8 4c-2 0-3 1-3 3v3c0 1-1 2-2 2 1 0 2 1 2 2v3c0 2 1 3 3 3M16 4c2 0 3 1 3 3v3c0 1 1 2 2 2-1 0-2 1-2 2v3c0 2-1 3-3 3"/>"#;
    pub const STR: &str = r#"<path d="M5 8V6h14v2M12 6v12M9 18h6"/>"#;
    pub const IMP: &str = r#"<path d="M12 4v10M8 10l4 4 4-4M5 19h14"/>"#;
    pub const XR: &str = r#"<path d="M10 14a4 4 0 0 0 5.6 0l3-3a4 4 0 0 0-5.6-5.6l-1 1M14 10a4 4 0 0 0-5.6 0l-3 3a4 4 0 0 0 5.6 5.6l1-1"/>"#;
    pub const HX: &str = r#"<path d="M9 4L7 20M17 4l-2 16M4 9h16M3 15h16"/>"#;
    pub const BUG: &str = r#"<rect x="8" y="9" width="8" height="10" rx="4"/><path d="M9 6l1.5 2M15 6l-1.5 2M4 13h4M16 13h4M5 19l3-2M19 19l-3-2"/>"#;
    pub const COG: &str = r#"<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>"#;
    pub const SL: &str = r#"<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>"#;
    pub const SN: &str = r#"<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6L7 7M17 17l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4"/>"#;
    pub const BOLT: &str = r#"<path d="M13 3L5 14h6l-1 7 8-11h-6z"/>"#;
    pub const INFO: &str = r#"<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>"#;
    pub const X: &str = r#"<path d="M6 6l12 12M18 6L6 18"/>"#;
    pub const MCP: &str = r#"<path d="M9 5H7a3 3 0 0 0-3 3v8a3 3 0 0 0 3 3h2"/><path d="M15 5h2a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3h-2"/><path d="M8.5 12h7"/>"#;
    pub const FO: &str =
        r#"<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>"#;
    pub const FW: &str = r#"<path d="M9 6l6 6-6 6"/>"#;
    pub const BUG_BIG: &str = BUG;
    pub const CHECK16: &str = "M3.5 8.5l3 3 6-7";
    pub const TICK16: &str = "M3 8.5l3.2 3.2L13 4.5";
}

fn hex_op(c: Color) -> (String, f32) {
    (
        format!(
            "#{:02x}{:02x}{:02x}",
            (c.r.clamp(0.0, 1.0) * 255.0).round() as u8,
            (c.g.clamp(0.0, 1.0) * 255.0).round() as u8,
            (c.b.clamp(0.0, 1.0) * 255.0).round() as u8
        ),
        c.a.clamp(0.0, 1.0),
    )
}

pub fn svg_icon_ex(
    paths: &str,
    vb: f32,
    sw: f32,
    rot: f32,
    size: f32,
    color: Color,
) -> iced::widget::Svg<'static, iced::Theme> {
    let (hex, op) = hex_op(color);
    let c = vb / 2.0;
    let doc = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {vb} {vb}\" fill=\"none\" stroke=\"{hex}\" stroke-opacity=\"{op:.3}\" stroke-width=\"{sw}\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><g transform=\"rotate({rot:.1} {c} {c})\">{paths}</g></svg>"
    );
    iced::widget::Svg::new(iced::widget::svg::Handle::from_memory(doc.into_bytes()))
        .width(iced::Length::Fixed(size))
        .height(iced::Length::Fixed(size))
}

pub fn svg_icon(paths: &str, size: f32, color: Color) -> iced::widget::Svg<'static, iced::Theme> {
    svg_icon_ex(paths, 24.0, 1.6, 0.0, size, color)
}

pub fn svg_path_draw(
    d: &str,
    len: f32,
    p: f32,
    sw: f32,
    size: f32,
    color: Color,
) -> iced::widget::Svg<'static, iced::Theme> {
    let markup = if p >= 1.0 {
        format!("<path d=\"{d}\"/>")
    } else {
        format!(
            "<path d=\"{d}\" stroke-dasharray=\"{len}\" stroke-dashoffset=\"{:.2}\"/>",
            len * (1.0 - p.clamp(0.0, 1.0))
        )
    };
    svg_icon_ex(&markup, 16.0, sw, 0.0, size, color)
}

pub fn logo_svg(size: f32, light: bool) -> iced::widget::Svg<'static, iced::Theme> {
    let (bg, fg) = if light {
        ("#111111", "#ffffff")
    } else {
        ("#ffffff", "#000000")
    };
    let doc = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><rect width=\"32\" height=\"32\" rx=\"8\" fill=\"{bg}\"/><path d=\"M12 8H8v16h4M20 8h4v16h-4\" fill=\"none\" stroke=\"{fg}\" stroke-width=\"2.6\"/><circle cx=\"16\" cy=\"16\" r=\"3.2\" fill=\"{fg}\"/></svg>"
    );
    iced::widget::Svg::new(iced::widget::svg::Handle::from_memory(doc.into_bytes()))
        .width(iced::Length::Fixed(size))
        .height(iced::Length::Fixed(size))
}

fn seg_dist(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let dx = bx - ax;
    let dy = by - ay;
    let denom = dx * dx + dy * dy;
    let t = if denom <= 0.0 {
        0.0
    } else {
        (((px - ax) * dx + (py - ay) * dy) / denom).clamp(0.0, 1.0)
    };
    let qx = ax + t * dx - px;
    let qy = ay + t * dy - py;
    (qx * qx + qy * qy).sqrt()
}

fn poly_dist(px: f32, py: f32, pts: &[[f32; 2]]) -> f32 {
    pts.windows(2)
        .map(|w| seg_dist(px, py, w[0][0], w[0][1], w[1][0], w[1][1]))
        .fold(f32::INFINITY, f32::min)
}

fn in_logo_box(px: f32, py: f32) -> bool {
    const R: f32 = 8.0;
    if px < 0.0 || py < 0.0 || px > 32.0 || py > 32.0 {
        return false;
    }
    let cx = px.clamp(R, 32.0 - R);
    let cy = py.clamp(R, 32.0 - R);
    let dx = px - cx;
    let dy = py - cy;
    dx * dx + dy * dy <= R * R
}

pub fn logo_rgba(size: u32, inverted: bool) -> Vec<u8> {
    const LEFT: &[[f32; 2]] = &[[12.0, 8.0], [8.0, 8.0], [8.0, 24.0], [12.0, 24.0]];
    const RIGHT: &[[f32; 2]] = &[[20.0, 8.0], [24.0, 8.0], [24.0, 24.0], [20.0, 24.0]];
    const HALF_STROKE: f32 = 1.3;
    const DOT_R: f32 = 3.2;
    let (br, bg, bb) = if inverted {
        (255, 255, 255)
    } else {
        (17, 17, 17)
    };
    let (gr, gg, gb) = if inverted { (0, 0, 0) } else { (255, 255, 255) };
    let s = size.max(8);
    let mut out = Vec::with_capacity((s * s * 4) as usize);
    for y in 0..s {
        for x in 0..s {
            let mut bg_hit = 0u32;
            let mut gl_hit = 0u32;
            for (oy, ox) in [(0.25, 0.25), (0.25, 0.75), (0.75, 0.25), (0.75, 0.75)] {
                let px = (x as f32 + ox) / s as f32 * 32.0;
                let py = (y as f32 + oy) / s as f32 * 32.0;
                if in_logo_box(px, py) {
                    bg_hit += 1;
                }
                let dx = px - 16.0;
                let dy = py - 16.0;
                if poly_dist(px, py, LEFT) <= HALF_STROKE
                    || poly_dist(px, py, RIGHT) <= HALF_STROKE
                    || dx * dx + dy * dy <= DOT_R * DOT_R
                {
                    gl_hit += 1;
                }
            }
            if gl_hit > 0 {
                out.extend_from_slice(&[gr, gg, gb, (gl_hit * 255 / 4) as u8]);
            } else {
                out.extend_from_slice(&[br, bg, bb, (bg_hit * 255 / 4) as u8]);
            }
        }
    }
    out
}

pub fn logo_window_icon() -> Option<iced::window::Icon> {
    const SIZE: u32 = 64;
    iced::window::icon::from_rgba(logo_rgba(SIZE, true), SIZE, SIZE).ok()
}

pub fn icon<'a>(glyph: &str, size: f32, color: Color) -> text_widget::Text<'a> {
    text_widget(glyph.to_string())
        .font(Font::with_name(ICON_FONT_NAME))
        .size(size)
        .style(move |_| text_widget::Style { color: Some(color) })
}

pub fn icon_t<'a>(glyph: &str, size: f32, strength: T) -> text_widget::Text<'a> {
    text_widget(glyph.to_string())
        .font(Font::with_name(ICON_FONT_NAME))
        .size(size)
        .style(move |theme: &Theme| text_widget::Style {
            color: Some(strength.color_in(theme)),
        })
}

pub fn icon_acc<'a>(glyph: &str, size: f32) -> text_widget::Text<'a> {
    text_widget(glyph.to_string())
        .font(Font::with_name(ICON_FONT_NAME))
        .size(size)
        .style(move |theme: &Theme| text_widget::Style {
            color: Some(acc_c(theme)),
        })
}

pub fn icon_text<'a>(
    glyph: &str,
    label_s: impl text_widget::IntoFragment<'a>,
    strength: T,
    icon_size: f32,
) -> iced::widget::Row<'a, crate::gui::app::Message, Theme, iced::Renderer> {
    iced::widget::row![
        icon(glyph, icon_size, strength.color()),
        label(label_s, strength)
    ]
    .spacing(4)
    .align_y(iced::alignment::Vertical::Center)
}
