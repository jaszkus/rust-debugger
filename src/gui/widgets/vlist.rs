use iced::advanced::text::{Alignment, LineHeight, Shaping};
use iced::mouse::{self, Cursor, Interaction, ScrollDelta};
use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke, Text as CanvasText};
use iced::{Color, Element, Font, Length, Point, Rectangle, Size, Theme};
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Instant;

pub const OVERSCAN: usize = 0;

const MIN_THUMB: f32 = 32.0;
const TRACK_W: f32 = 8.0;
const TRACK_HIT: f32 = 14.0;
const MENU_PAD_X: f32 = 12.0;
const MENU_PAD_Y: f32 = 6.0;
const MENU_GAP: f32 = 8.0;
const MENU_OPEN_MS: u64 = 140;

static MENU_OPENED: Mutex<Option<Instant>> = Mutex::new(None);

fn mark_menu_open() {
    if let Ok(mut slot) = MENU_OPENED.lock() {
        *slot = Some(Instant::now());
    }
}

fn mark_menu_closed() {
    if let Ok(mut slot) = MENU_OPENED.lock() {
        *slot = None;
    }
}

pub fn menu_animating() -> bool {
    MENU_OPENED
        .lock()
        .ok()
        .and_then(|slot| *slot)
        .is_some_and(|start| start.elapsed().as_millis() < MENU_OPEN_MS as u128)
}

pub trait VListData {
    type Message: Clone + 'static;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn first(&self) -> usize;

    fn revision(&self) -> u64;

    fn scroll_msg(&self, first: usize) -> Self::Message;

    fn selected(&self) -> Option<usize>;

    fn row_action(&self, i: usize) -> Option<Self::Message>;

    fn open_action(&self, i: usize) -> Option<Self::Message> {
        self.row_action(i)
    }
    fn copy_action(&self, i: usize) -> Option<Self::Message> {
        self.row_action(i)
    }

    fn gutter_action(&self, i: usize) -> Option<Self::Message> {
        self.row_action(i)
    }

    fn menu_entries(&self, i: usize) -> Vec<(String, Self::Message)> {
        let _ = i;
        Vec::new()
    }

    fn menu_open_action(&self) -> Option<Self::Message> {
        None
    }

    fn row_wash(&self, i: usize) -> Option<Color> {
        let _ = i;
        None
    }

    fn paint_row(&self, i: usize, top: f32, line_h: f32, char_w: f32, frame: &mut Frame);

    fn paint_chrome(&self, _i: usize, _top: f32, _line_h: f32, _hover: bool, _frame: &mut Frame) {}

    fn ai_cursor(&self) -> Option<(f32, f32)> {
        None
    }
}

#[derive(Clone)]
pub struct Cell {
    pub text: String,
    pub color: Color,
    pub width_cols: Option<usize>,
    pub inline: bool,
}

impl Cell {
    pub fn new(text: impl Into<String>, color: Color) -> Self {
        Self {
            text: text.into(),
            color,
            width_cols: None,
            inline: false,
        }
    }

    #[allow(dead_code)]
    pub fn fixed(text: impl Into<String>, color: Color, cols: usize) -> Self {
        Self {
            text: text.into(),
            color,
            width_cols: Some(cols),
            inline: false,
        }
    }

    #[allow(dead_code)]
    pub fn inline(text: impl Into<String>, color: Color) -> Self {
        Self {
            text: text.into(),
            color,
            width_cols: None,
            inline: true,
        }
    }
}

pub struct VList<'a, D: VListData> {
    data: Rc<D>,
    font: Font,
    font_size: f32,
    line_h: f32,
    char_w: f32,
    grid: Option<Color>,
    scrollbar: Color,
    hover: Color,
    selected: Color,
    cursor_fill: Color,
    cursor_border: Color,
    _lt: std::marker::PhantomData<&'a ()>,
}

pub fn vlist<'a, D: VListData>(data: D) -> VList<'a, D> {
    VList {
        data: Rc::new(data),
        font: crate::gui::theme::mono_font(),
        font_size: 13.0,
        line_h: 25.0,
        char_w: 7.8,
        grid: None,
        scrollbar: crate::gui::theme::Palette::LINE2,
        hover: crate::gui::theme::Palette::S2,
        selected: crate::gui::theme::Palette::SEL,
        cursor_fill: Color::TRANSPARENT,
        cursor_border: Color::TRANSPARENT,
        _lt: std::marker::PhantomData,
    }
}

impl<'a, D: VListData> VList<'a, D> {
    pub fn font(mut self, font: Font) -> Self {
        self.font = font;
        self
    }
    pub fn font_size(mut self, px: f32) -> Self {
        self.font_size = px;
        self.char_w = px * 0.6;
        self
    }
    pub fn line_h(mut self, px: f32) -> Self {
        self.line_h = px;
        self
    }
    pub fn grid(mut self, color: Option<Color>) -> Self {
        self.grid = color;
        self
    }
    pub fn scrollbar(mut self, color: Color) -> Self {
        self.scrollbar = color;
        self
    }
    pub fn hover(mut self, color: Color) -> Self {
        self.hover = color;
        self
    }
    pub fn selected(mut self, color: Color) -> Self {
        self.selected = color;
        self
    }
    pub fn cursor(mut self, fill: Color, border: Color) -> Self {
        self.cursor_fill = fill;
        self.cursor_border = border;
        self
    }

    fn menu_style(&self) -> MenuStyle {
        MenuStyle {
            font: self.font,
            font_size: self.font_size,
            line_h: self.line_h,
            char_w: self.char_w,
        }
    }

    fn menu_layer(&self) -> MenuLayer<D> {
        MenuLayer {
            data: Rc::clone(&self.data),
            style: self.menu_style(),
        }
    }
}

type RowsKey = (usize, usize, u64, u32, u32, u32, u32, bool);

#[derive(Default)]
pub struct Interact {
    hover: Option<usize>,
    drag: Option<(f32, usize)>,
    pending_px: f32,
    focused: bool,
    keyboard_row: Option<usize>,
    modifiers: iced::keyboard::Modifiers,
    last_click: Option<(usize, std::time::Instant)>,
    rows: canvas::Cache<iced::Renderer>,
    rows_key: std::cell::Cell<Option<RowsKey>>,
}

type MenuEntries<M> = Vec<(String, M)>;

#[derive(Clone, Copy)]
struct MenuStyle {
    font: Font,
    font_size: f32,
    line_h: f32,
    char_w: f32,
}

struct OpenMenu<M> {
    point: Point,
    entries: Vec<(String, M)>,
    hover: Option<usize>,
    opened_at: Instant,
}

struct MenuLayerState<M> {
    open: Option<OpenMenu<M>>,
    cache: canvas::Cache<iced::Renderer>,
}

impl<M> Default for MenuLayerState<M> {
    fn default() -> Self {
        Self {
            open: None,
            cache: canvas::Cache::default(),
        }
    }
}

impl<M> MenuLayerState<M> {
    fn close(&mut self) -> bool {
        if self.open.take().is_some() {
            self.cache.clear();
            mark_menu_closed();
            true
        } else {
            false
        }
    }
}

struct MenuLayer<D: VListData> {
    data: Rc<D>,
    style: MenuStyle,
}

impl<D: VListData> MenuLayer<D> {
    fn menu_target(
        &self,
        p: Point,
        bounds: Rectangle,
    ) -> Option<(Point, MenuEntries<D::Message>)> {
        let line_h = self.style.line_h;
        if line_h <= 0.0 {
            return None;
        }
        let len = self.data.len();
        let visible = visible_rows(bounds.height, line_h);
        if len > visible && p.x >= bounds.width - TRACK_HIT {
            return None;
        }
        let first = clamp_first(self.data.first(), len, visible);
        let row = first + (p.y / line_h) as usize;
        if row >= len {
            return None;
        }
        let entries = self.data.menu_entries(row);
        (!entries.is_empty()).then_some((p, entries))
    }
}

impl<D: VListData> canvas::Program<D::Message> for MenuLayer<D> {
    type State = MenuLayerState<D::Message>;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &iced::Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: Cursor,
    ) -> Vec<Geometry> {
        let Some(menu) = &state.open else {
            return Vec::new();
        };
        let layout = menu_layout(&menu.entries, menu.point, bounds, &self.style);

        if menu.opened_at.elapsed().as_millis() < MENU_OPEN_MS as u128 {
            let t = crate::gui::anim::ease_out(crate::gui::anim::progress(
                Instant::now(),
                menu.opened_at,
                MENU_OPEN_MS,
            ));
            if t <= 0.0 {
                return Vec::new();
            }
            let mut frame = Frame::new(renderer, bounds.size());
            paint_menu(&mut frame, menu, &layout, &self.style, theme, t);
            return vec![frame.into_geometry()];
        }

        vec![state.cache.draw(renderer, bounds.size(), |frame| {
            paint_menu(frame, menu, &layout, &self.style, theme, 1.0);
        })]
    }

    fn update(
        &self,
        state: &mut Self::State,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: Cursor,
    ) -> Option<canvas::Action<D::Message>> {
        match event {
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Right)) => {
                let target = cursor
                    .position_in(bounds)
                    .and_then(|p| self.menu_target(p, bounds));
                match target {
                    Some((point, entries)) => {
                        state.open = Some(OpenMenu {
                            point,
                            entries,
                            hover: None,
                            opened_at: Instant::now(),
                        });
                        state.cache.clear();
                        mark_menu_open();
                        Some(match self.data.menu_open_action() {
                            Some(msg) => canvas::Action::publish(msg).and_capture(),
                            None => canvas::Action::request_redraw().and_capture(),
                        })
                    }
                    None => state.close().then(canvas::Action::request_redraw),
                }
            }

            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                let menu = state.open.as_ref()?;
                let p = cursor.position_in(bounds);
                let msg =
                    p.and_then(|p| menu_hit(&menu.entries, menu.point, p, bounds, &self.style));
                state.close();
                match (msg, p) {
                    (Some(msg), _) => Some(canvas::Action::publish(msg).and_capture()),
                    (None, Some(_)) => Some(canvas::Action::request_redraw().and_capture()),
                    (None, None) => Some(canvas::Action::request_redraw()),
                }
            }

            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                let menu = state.open.as_ref()?;
                let hover = cursor.position_in(bounds).and_then(|p| {
                    menu_slot(&menu.entries, menu.point, p, bounds, &self.style)
                });
                if hover == menu.hover {
                    return None;
                }
                if let Some(menu) = state.open.as_mut() {
                    menu.hover = hover;
                }
                state.cache.clear();
                Some(canvas::Action::request_redraw())
            }

            canvas::Event::Mouse(mouse::Event::WheelScrolled { .. }) if state.open.is_some() => {
                state.close();
                Some(canvas::Action::request_redraw())
            }

            canvas::Event::Keyboard(iced::keyboard::Event::KeyPressed { key, .. })
                if state.open.is_some() =>
            {
                use iced::keyboard::{key::Named, Key};
                if matches!(key, Key::Named(Named::Escape)) {
                    state.close();
                    Some(canvas::Action::request_redraw().and_capture())
                } else {
                    None
                }
            }

            _ => None,
        }
    }

    fn mouse_interaction(
        &self,
        state: &Self::State,
        bounds: Rectangle,
        cursor: Cursor,
    ) -> Interaction {
        let (Some(menu), Some(p)) = (&state.open, cursor.position_in(bounds)) else {
            return Interaction::None;
        };
        if menu_slot(&menu.entries, menu.point, p, bounds, &self.style).is_some() {
            Interaction::Pointer
        } else {
            Interaction::None
        }
    }
}

impl<'a, D: VListData> canvas::Program<D::Message> for VList<'a, D> {
    type State = Interact;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &iced::Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: Cursor,
    ) -> Vec<Geometry> {
        let tokens = crate::gui::theme::Tokens::resolve(crate::gui::theme::is_light(theme));
        let mut wash = Frame::new(renderer, bounds.size());
        let line_h = self.line_h;
        let len = self.data.len();
        let first = self.data.first();
        let visible = visible_rows(bounds.height, line_h);
        let start = clamp_first(first, len, visible);
        let end = (start + visible + OVERSCAN).min(len);

        let paint_clipped = |frame: &mut Frame, i: usize, top: f32| {
            if top >= bounds.height || top + line_h <= 0.0 {
                return;
            }
            self.data.paint_row(i, top, line_h, self.char_w, frame);
        };
        let row_visible = |top: f32| top < bounds.height && top + line_h > 0.0;

        let row_top = |i: usize| (i - start) as f32 * line_h;
        if let Some(i) = state.keyboard_row.or(self.data.selected())
            && i >= start && i < end && row_visible(row_top(i)) {
                wash.fill_rectangle(
                    Point::new(0.0, row_top(i)),
                    Size::new(bounds.width, line_h),
                    tokens.select,
                );
                wash.fill_rectangle(
                    Point::new(0.0, row_top(i)),
                    Size::new(2.0, line_h),
                    tokens.mint,
                );
            }
        if let Some(i) = state.hover
            && i >= start && i < end && Some(i) != self.data.selected() && row_visible(row_top(i)) {
                wash.fill_rectangle(
                    Point::new(0.0, row_top(i)),
                    Size::new(bounds.width, line_h),
                    tokens.hover,
                );
            }
        for i in start..end {
            let top = row_top(i);
            if !row_visible(top) {
                continue;
            }
            if let Some(w) = self.data.row_wash(i) {
                wash.fill_rectangle(Point::new(0.0, top), Size::new(bounds.width, line_h), w);
            }
        }

        let key = (
            start,
            len,
            self.data.revision(),
            bounds.width.to_bits(),
            bounds.height.to_bits(),
            self.line_h.to_bits(),
            self.font_size.to_bits(),
            crate::gui::theme::is_light(theme),
        );
        if state.rows_key.get() != Some(key) {
            state.rows.clear();
            state.rows_key.set(Some(key));
        }
        let paint_rows = |frame: &mut Frame| {
            for i in start..end {
                paint_clipped(frame, i, row_top(i));
            }

            if let Some(grid) = self.grid {
                let stroke = Stroke::default().with_color(grid).with_width(1.0);
                let y0 = 0.0f32;
                let y1 = bounds.height;
                let mut y = y0 + line_h;
                while y < y1 {
                    frame.stroke(
                        &Path::line(Point::new(0.0, y), Point::new(bounds.width, y)),
                        stroke,
                    );
                    y += line_h;
                }
            }
        };
        let paint_chrome = |frame: &mut Frame| {
            if len > visible && bounds.height > 0.0 && bounds.width > TRACK_W {
                let content_h = len as f32 * line_h;
                let track_x = bounds.width - TRACK_W;
                let thumb_h = thumb_h(bounds.height, content_h);
                let max_first = max_first(len, visible);
                let t = if max_first == 0 {
                    0.0
                } else {
                    start as f32 / max_first as f32
                };
                let travel = (bounds.height - thumb_h).max(0.0);
                let thumb_y = (t * travel).clamp(0.0, travel);
                frame.fill_rectangle(
                    Point::new(track_x + 2.0, thumb_y),
                    Size::new(TRACK_W - 4.0, thumb_h),
                    crate::gui::theme::line2_c(theme),
                );
            }

            for i in start..end {
                let top = row_top(i);
                if row_visible(top) {
                    self.data
                        .paint_chrome(i, top, line_h, state.hover == Some(i), frame);
                }
            }

            if let Some((r0, r1)) = self.data.ai_cursor() {
                let r0 = r0.round();
                let r1 = r1.round().max(r0);
                let top = (r0 - start as f32) * line_h;
                let bottom = top + ((r1 - r0) + 1.0) * line_h;
                let y0 = top.max(0.0);
                let y1 = bottom.min(bounds.height);
                if y1 > y0 {
                    let rect = Path::rounded_rectangle(
                        Point::new(2.0, y0),
                        Size::new((bounds.width - 4.0).max(0.0), y1 - y0),
                        iced::border::Radius::from(5.0),
                    );
                    frame.fill(&rect, self.cursor_fill);
                    frame.stroke(
                        &rect,
                        Stroke::default()
                            .with_color(self.cursor_border)
                            .with_width(1.5),
                    );
                }
            }
        };

        let rows_geo = state.rows.draw(renderer, bounds.size(), paint_rows);
        let mut chrome = Frame::new(renderer, bounds.size());
        paint_chrome(&mut chrome);

        vec![wash.into_geometry(), rows_geo, chrome.into_geometry()]
    }

    fn update(
        &self,
        state: &mut Self::State,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: Cursor,
    ) -> Option<canvas::Action<D::Message>> {
        let line_h = self.line_h;
        let len = self.data.len();
        let visible = visible_rows(bounds.height, line_h);
        let first = clamp_first(self.data.first(), len, visible);
        let pos = |cursor: &Cursor| cursor.position_in(bounds);

        match event {
            canvas::Event::Keyboard(iced::keyboard::Event::ModifiersChanged(mods)) => {
                state.modifiers = *mods;
                None
            }
            canvas::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key, modifiers, ..
            }) if state.focused => {
                use iced::keyboard::{key::Named, Key};
                if len == 0 {
                    return None;
                }
                let current = state
                    .keyboard_row
                    .or(self.data.selected())
                    .unwrap_or(first)
                    .min(len - 1);
                let target = match key {
                    Key::Named(Named::ArrowUp) => current.saturating_sub(1),
                    Key::Named(Named::ArrowDown) => (current + 1).min(len - 1),
                    Key::Named(Named::PageUp) => current.saturating_sub(visible),
                    Key::Named(Named::PageDown) => (current + visible).min(len - 1),
                    Key::Named(Named::Home) => 0,
                    Key::Named(Named::End) => len - 1,
                    Key::Named(Named::Enter) => {
                        return self
                            .data
                            .open_action(current)
                            .map(|m| canvas::Action::publish(m).and_capture())
                    }
                    Key::Character(c) if modifiers.command() && c.eq_ignore_ascii_case("c") => {
                        return self
                            .data
                            .copy_action(current)
                            .map(|m| canvas::Action::publish(m).and_capture())
                    }
                    _ => return None,
                };
                state.keyboard_row = Some(target);
                let next_first = if target < first {
                    target
                } else if target >= first + visible {
                    target + 1 - visible.max(1)
                } else {
                    first
                };
                Some(canvas::Action::publish(self.data.scroll_msg(next_first)).and_capture())
            }
            canvas::Event::Mouse(mouse::Event::WheelScrolled { delta })
                if pos(&cursor).is_some() =>
            {
                if line_h <= 0.0 {
                    return None;
                }
                let dy_px = match delta {
                    ScrollDelta::Pixels { y, .. } => *y,
                    ScrollDelta::Lines { y, .. } => {
                        *y * line_h
                            * if state.modifiers.control() {
                                visible as f32
                            } else if state.modifiers.shift() {
                                30.0
                            } else {
                                3.0
                            }
                    }
                };
                state.pending_px += dy_px;
                let rows = (state.pending_px / line_h).trunc();
                let raw = self.data.first();
                if rows == 0.0 {
                    if raw != first {
                        return Some(canvas::Action::publish(self.data.scroll_msg(first)));
                    }
                    return None;
                }
                state.pending_px -= rows * line_h;
                let mf = max_first(len, visible) as f32;
                let new = clamp_f(first as f32 - rows, 0.0, mf);
                state.hover = pos(&cursor)
                    .map(|p| new as usize + (p.y / line_h) as usize)
                    .filter(|i| *i < len);
                if new as usize != raw {
                    return Some(canvas::Action::publish(self.data.scroll_msg(new as usize)));
                }
                None
            }

            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                if let Some((grab_y, grab_first)) = state.drag {
                    if cursor.is_over(bounds) || true {
                        let content_h = len as f32 * line_h;
                        if len > visible && bounds.height > 1.0 && content_h > 0.0 {
                            let th = thumb_h(bounds.height, content_h);
                            let max_first = max_first(len, visible);
                            let travel = bounds.height - th;
                            if travel < 1.0 {
                                return None;
                            }
                            let dy = cursor.position().unwrap_or_default().y - grab_y;
                            let new = clamp_f(
                                grab_first as f32 + dy / travel * max_first as f32,
                                0.0,
                                max_first as f32,
                            );
                            if new as usize != self.data.first() {
                                return Some(canvas::Action::publish(
                                    self.data.scroll_msg(new as usize),
                                ));
                            }
                        }
                    }
                    return None;
                }
                let hover = pos(&cursor)
                    .map(|p| (first + (p.y / line_h) as usize).min(len.saturating_sub(1)));
                if hover != state.hover {
                    state.hover = hover;
                    return Some(canvas::Action::request_redraw());
                }
                None
            }

            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                let Some(p) = pos(&cursor) else {
                    state.focused = false;
                    return None;
                };
                state.focused = true;
                if len > visible && p.x >= bounds.width - TRACK_HIT {
                    state.drag = Some((cursor.position().unwrap_or_default().y, first));
                    return Some(canvas::Action::capture());
                }
                let row = first + (p.y / line_h) as usize;
                if row < len {
                    state.keyboard_row = Some(row);
                    let now = std::time::Instant::now();
                    let double = state
                        .last_click
                        .map(|(i, t)| i == row && now.duration_since(t).as_millis() < 400)
                        .unwrap_or(false);
                    state.last_click = Some((row, now));
                    let msg = if double && p.x >= 30.0 {
                        self.data.open_action(row)
                    } else if p.x < 30.0 {
                        self.data.gutter_action(row)
                    } else {
                        self.data.row_action(row)
                    };
                    if let Some(msg) = msg {
                        return Some(canvas::Action::publish(msg));
                    }
                }
                None
            }

            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)) => {
                if state.drag.take().is_some() {
                    return Some(canvas::Action::capture());
                }
                None
            }

            _ => None,
        }
    }

    fn mouse_interaction(
        &self,
        _state: &Self::State,
        bounds: Rectangle,
        cursor: Cursor,
    ) -> Interaction {
        if let Some(p) = cursor.position_in(bounds)
            && self.data.len() > visible_rows(bounds.height, self.line_h)
                && p.x >= bounds.width - TRACK_HIT
            {
                return Interaction::Grab;
            }
        Interaction::None
    }
}

fn menu_entry_h(style: &MenuStyle) -> f32 {
    (style.line_h * 1.2).max(30.0)
}

struct MenuLayout {
    rect: Rectangle,
    entry_h: f32,
}

fn menu_layout<M>(
    entries: &[(String, M)],
    point: Point,
    bounds: Rectangle,
    style: &MenuStyle,
) -> MenuLayout {
    let entry_h = menu_entry_h(style);
    let text_w = entries
        .iter()
        .map(|(s, _)| s.chars().count())
        .max()
        .unwrap_or(8) as f32
        * style.char_w;
    let w = (text_w + MENU_PAD_X * 2.0)
        .max(178.0)
        .min((bounds.width - 16.0).max(120.0));
    let h = entries.len() as f32 * entry_h + MENU_PAD_Y * 2.0;
    let max_x = (bounds.width - w - 8.0).max(0.0);
    let x = (point.x - 4.0).max(8.0).min(max_x.max(8.0));
    let max_y = (bounds.height - h - 8.0).max(8.0);
    let above = point.y - h - MENU_GAP;
    let y = if above >= 8.0 {
        above
    } else {
        (point.y + MENU_GAP).min(max_y)
    };
    MenuLayout {
        rect: Rectangle {
            x,
            y,
            width: w,
            height: h,
        },
        entry_h,
    }
}

fn paint_menu<M>(
    frame: &mut Frame,
    menu: &OpenMenu<M>,
    layout: &MenuLayout,
    style: &MenuStyle,
    theme: &Theme,
    t: f32,
) {
    if menu.entries.is_empty() {
        return;
    }
    let tokens = crate::gui::theme::Tokens::resolve(crate::gui::theme::is_light(theme));

    let x = layout.rect.x.round();
    let y = (layout.rect.y + (1.0 - t) * 4.0).round();
    let w = layout.rect.width.round();
    let h = layout.rect.height.round();
    let radius = iced::border::Radius::from(8.0 + 2.0 * t);

    for (dx, dy, alpha) in [(1.0_f32, 6.0_f32, 0.28_f32), (0.0, 3.0, 0.16)] {
        let shadow =
            Path::rounded_rectangle(Point::new(x + dx, y + dy), Size::new(w, h), radius);
        frame.fill(&shadow, Color::BLACK.scale_alpha(alpha * t));
    }

    let rect = Path::rounded_rectangle(Point::new(x, y), Size::new(w, h), radius);
    frame.fill(&rect, crate::gui::theme::panel_bg_c(theme));
    let border = Path::rounded_rectangle(
        Point::new(x + 0.5, y + 0.5),
        Size::new((w - 1.0).max(0.0), (h - 1.0).max(0.0)),
        radius,
    );
    frame.stroke(
        &border,
        Stroke::default()
            .with_color(crate::gui::theme::line_c(theme))
            .with_width(1.0),
    );

    if style.font_size <= 0.0 {
        return;
    }
    let max_cols = (((w - MENU_PAD_X * 2.0) / style.char_w.max(1.0)) as usize).max(4);
    let text_x = x + MENU_PAD_X;
    for (i, (label, _)) in menu.entries.iter().enumerate() {
        let ey = y + MENU_PAD_Y + i as f32 * layout.entry_h;
        let hovered = menu.hover == Some(i);
        if hovered {
            let highlight = Path::rounded_rectangle(
                Point::new(x + 4.0, ey + 1.0),
                Size::new((w - 8.0).max(0.0), layout.entry_h - 2.0),
                iced::border::Radius::from(6.0),
            );
            frame.fill(&highlight, tokens.select);
        }
        let color = if hovered { tokens.mint } else { tokens.text };
        frame.fill_text(CanvasText {
            content: truncate_cols(label, max_cols),
            position: Point::new(text_x, (ey + layout.entry_h * 0.5).round()),
            color,
            size: iced::Pixels(style.font_size),
            line_height: LineHeight::Absolute(iced::Pixels((style.font_size * 1.3).round())),
            font: style.font,
            align_x: Alignment::Left,
            align_y: iced::alignment::Vertical::Center,
            shaping: Shaping::Basic,
            max_width: f32::INFINITY,
        });
    }
}

fn menu_index(p: Point, rect: Rectangle, entry_h: f32, len: usize) -> Option<usize> {
    if !rect.contains(p) || entry_h <= 0.0 {
        return None;
    }
    let rel = p.y - rect.y - MENU_PAD_Y;
    if rel < 0.0 {
        return None;
    }
    let i = (rel / entry_h) as usize;
    (i < len).then_some(i)
}

fn menu_slot<M>(
    entries: &[(String, M)],
    menu_point: Point,
    p: Point,
    bounds: Rectangle,
    style: &MenuStyle,
) -> Option<usize> {
    if entries.is_empty() {
        return None;
    }
    let layout = menu_layout(entries, menu_point, bounds, style);
    menu_index(p, layout.rect, layout.entry_h, entries.len())
}

fn menu_hit<M: Clone>(
    entries: &[(String, M)],
    menu_point: Point,
    p: Point,
    bounds: Rectangle,
    style: &MenuStyle,
) -> Option<M> {
    menu_slot(entries, menu_point, p, bounds, style).map(|i| entries[i].1.clone())
}

#[cfg(test)]
fn menu_bounds<M>(
    entries: &[(String, M)],
    point: Point,
    bounds: Rectangle,
    style: &MenuStyle,
) -> Rectangle {
    menu_layout(entries, point, bounds, style).rect
}

pub const MONO_CHAR_W: f32 = 7.5;

pub const INK_SLACK: f32 = 16.0;

pub fn text_fits(top: f32, h: f32) -> bool {
    top >= -1.0 && top + INK_SLACK <= h + 0.5
}

pub fn truncate_cols(s: &str, max_cols: usize) -> String {
    let count = s.chars().count();
    if count <= max_cols {
        return s.to_string();
    }
    let keep = max_cols.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('\u{2026}');
    out
}

pub fn visible_rows(h: f32, line_h: f32) -> usize {
    if line_h <= 0.0 {
        return 0;
    }
    let fit_h = h + 0.5 - INK_SLACK;
    if fit_h < 0.0 {
        return 1;
    }
    ((fit_h / line_h).floor() as usize + 1).max(1)
}

pub fn max_first(len: usize, visible: usize) -> usize {
    len.saturating_sub(visible)
}

pub fn clamp_first(first: usize, len: usize, visible: usize) -> usize {
    first.min(max_first(len, visible))
}

fn clamp_f(v: f32, lo: f32, hi: f32) -> f32 {
    v.max(lo).min(hi)
}

fn thumb_h(h: f32, content_h: f32) -> f32 {
    if content_h <= 0.0 || h <= 0.0 {
        return h.max(0.0);
    }
    (h * h / content_h).clamp(MIN_THUMB.min(h), h)
}

impl<'a, D: VListData + 'a> From<VList<'a, D>> for Element<'a, D::Message, Theme, iced::Renderer> {
    fn from(list: VList<'a, D>) -> Self {
        let menu = list.menu_layer();
        let rows: Element<'a, D::Message, Theme, iced::Renderer> = Element::new(
            iced::widget::canvas(list)
                .width(Length::Fill)
                .height(Length::Fill),
        );
        let menu: Element<'a, D::Message, Theme, iced::Renderer> = Element::new(
            iced::widget::canvas(menu)
                .width(Length::Fill)
                .height(Length::Fill),
        );
        iced::widget::stack([rows, menu])
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod workbench_tests {
    use super::*;
    use iced::widget::canvas::Program;
    struct Data(usize);
    impl VListData for Data {
        type Message = usize;
        fn len(&self) -> usize {
            self.0
        }
        fn revision(&self) -> u64 {
            0
        }
        fn first(&self) -> usize {
            0
        }
        fn selected(&self) -> Option<usize> {
            None
        }
        fn scroll_msg(&self, first: usize) -> usize {
            first
        }
        fn row_action(&self, i: usize) -> Option<usize> {
            Some(i)
        }
        fn menu_entries(&self, _i: usize) -> Vec<(String, usize)> {
            vec![("Copy address".into(), 1), ("Rename".into(), 2)]
        }
        fn paint_row(&self, _i: usize, _top: f32, _lh: f32, _cw: f32, _f: &mut Frame) {}
    }
    #[test]
    fn workbench_menu_clamped_hit_test_matches_paint() {
        let list = vlist(Data(100));
        let style = list.menu_style();
        let bounds = Rectangle::with_size(Size::new(300.0, 120.0));
        let point = Point::new(295.0, 115.0);
        let entries = list.data.menu_entries(0);
        let rect = menu_bounds(&entries, point, bounds, &style);
        assert_eq!(
            menu_hit(
                &entries,
                point,
                Point::new(rect.x + 5.0, rect.y + 8.0),
                bounds,
                &style
            ),
            Some(1)
        );
        assert_eq!(
            menu_hit(
                &entries,
                point,
                Point::new(rect.x + 5.0, rect.y + 42.0),
                bounds,
                &style
            ),
            Some(2)
        );
    }
    #[test]
    fn workbench_menu_opens_above_cursor() {
        let list = vlist(Data(100));
        let style = list.menu_style();
        let bounds = Rectangle::with_size(Size::new(300.0, 240.0));
        let point = Point::new(150.0, 150.0);
        let entries = list.data.menu_entries(0);
        let rect = menu_bounds(&entries, point, bounds, &style);
        assert!(rect.y + rect.height <= point.y);
        assert!(rect.x >= 0.0);
        assert!(rect.x + rect.width <= bounds.width);
    }
    #[test]
    fn workbench_menu_layer_opens_picks_entry_and_closes() {
        let layer = vlist(Data(100)).menu_layer();
        let mut state = MenuLayerState::default();
        let bounds = Rectangle::with_size(Size::new(300.0, 120.0));
        let open = canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Right));
        assert!(layer
            .update(&mut state, &open, bounds, Cursor::Available(Point::new(60.0, 10.0)))
            .is_some());
        assert!(state.open.is_some());
        let click = canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left));
        assert!(layer
            .update(&mut state, &click, bounds, Cursor::Available(Point::new(60.0, 30.0)))
            .is_some());
        assert!(state.open.is_none());
    }
    #[test]
    fn workbench_menu_layer_ignores_scrollbar_right_click() {
        let layer = vlist(Data(100)).menu_layer();
        let mut state = MenuLayerState::default();
        let bounds = Rectangle::with_size(Size::new(300.0, 120.0));
        let open = canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Right));
        assert!(layer
            .update(&mut state, &open, bounds, Cursor::Available(Point::new(298.0, 10.0)))
            .is_none());
        assert!(state.open.is_none());
    }
    #[test]
    fn workbench_scrollbar_only_intercepts_when_visible() {
        let bounds = Rectangle::with_size(Size::new(300.0, 120.0));
        let cursor = Cursor::Available(Point::new(298.0, 20.0));
        assert_eq!(
            vlist(Data(2)).mouse_interaction(&Interact::default(), bounds, cursor),
            Interaction::None
        );
        assert_eq!(
            vlist(Data(100)).mouse_interaction(&Interact::default(), bounds, cursor),
            Interaction::Grab
        );
    }
    #[test]
    fn workbench_keyboard_and_wheel_update_local_selection() {
        let list = vlist(Data(100));
        let mut state = Interact::default();
        let bounds = Rectangle::with_size(Size::new(300.0, 120.0));
        let cursor = Cursor::Available(Point::new(60.0, 10.0));
        assert!(list
            .update(
                &mut state,
                &canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
                bounds,
                cursor
            )
            .is_some());
        assert!(state.focused);
        let event = iced::keyboard::Event::KeyPressed {
            key: iced::keyboard::Key::Named(iced::keyboard::key::Named::End),
            modified_key: iced::keyboard::Key::Named(iced::keyboard::key::Named::End),
            physical_key: iced::keyboard::key::Physical::Unidentified(
                iced::keyboard::key::NativeCode::Unidentified,
            ),
            location: iced::keyboard::Location::Standard,
            modifiers: iced::keyboard::Modifiers::empty(),
            text: None,
            repeat: false,
        };
        assert!(list
            .update(&mut state, &canvas::Event::Keyboard(event), bounds, cursor)
            .is_some());
        assert_eq!(state.keyboard_row, Some(99));
        let event = canvas::Event::Mouse(mouse::Event::WheelScrolled {
            delta: ScrollDelta::Lines { x: 0.0, y: -1.0 },
        });
        assert!(list.update(&mut state, &event, bounds, cursor).is_some());
        assert_eq!(state.hover, Some(3));
    }
}