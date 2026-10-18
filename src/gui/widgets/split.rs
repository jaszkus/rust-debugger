use iced::mouse::{self, Cursor, Interaction};
use iced::widget::canvas::{self, Frame, Geometry};
use iced::{Color, Element, Point, Rectangle, Size, Theme};

#[allow(dead_code)]
const HIT_W: f32 = 1.0;
const LINE_W: f32 = 1.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Axis {
    Horizontal,
    Vertical,
}

#[derive(Debug, Clone, Copy)]
pub struct Drag {
    pub pos: Point,
    pub active: bool,
}

pub struct Split {
    axis: Axis,
    color: Color,
    hover: Color,
}

pub fn split(axis: Axis) -> Split {
    Split {
        axis,
        color: crate::gui::theme::Palette::LINE,
        hover: crate::gui::theme::Palette::LINE2,
    }
}

impl Split {
    pub fn into_element<'a>(self) -> Element<'a, Drag> {
        let axis = self.axis;
        let canvas = iced::widget::canvas(self);
        match axis {
            Axis::Horizontal => canvas.width(iced::Length::Fill).height(HIT_W).into(),
            Axis::Vertical => canvas.width(HIT_W).height(iced::Length::Fill).into(),
        }
    }
    pub fn color(mut self, c: Color) -> Self {
        self.color = c;
        self
    }
    pub fn hover(mut self, c: Color) -> Self {
        self.hover = c;
        self
    }
}

#[derive(Default)]
pub struct State {
    armed: bool,
    hover: bool,
}

impl canvas::Program<Drag> for Split {
    type State = State;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &iced::Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: Cursor,
    ) -> Vec<Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let c = if state.armed || state.hover {
            crate::gui::theme::line2_c(theme)
        } else {
            crate::gui::theme::line_c(theme)
        };
        match self.axis {
            Axis::Horizontal => {
                let y = (bounds.height - LINE_W) / 2.0;
                frame.fill_rectangle(Point::new(0.0, y), Size::new(bounds.width, LINE_W), c);
            }
            Axis::Vertical => {
                let x = (bounds.width - LINE_W) / 2.0;
                frame.fill_rectangle(Point::new(x, 0.0), Size::new(LINE_W, bounds.height), c);
            }
        }
        vec![frame.into_geometry()]
    }

    fn update(
        &self,
        state: &mut Self::State,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: Cursor,
    ) -> Option<canvas::Action<Drag>> {
        match event {
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                if cursor.position_in(bounds).is_some() {
                    state.armed = true;
                    let pos = cursor.position().unwrap_or(Point::ORIGIN);
                    return Some(canvas::Action::publish(Drag { pos, active: true }).and_capture());
                }
            }
            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                if state.armed {
                    let pos = cursor.position().unwrap_or(Point::ORIGIN);
                    return Some(canvas::Action::publish(Drag { pos, active: true }));
                }
                let was = state.hover;
                state.hover = cursor.position_in(bounds).is_some();
                if was != state.hover {
                    return Some(canvas::Action::request_redraw());
                }
            }
            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left))
                if state.armed =>
            {
                state.armed = false;
                let pos = cursor.position().unwrap_or(Point::ORIGIN);
                return Some(canvas::Action::publish(Drag { pos, active: false }));
            }
            _ => {}
        }
        None
    }

    fn mouse_interaction(
        &self,
        _state: &Self::State,
        bounds: Rectangle,
        cursor: Cursor,
    ) -> Interaction {
        if cursor.position_in(bounds).is_some() {
            match self.axis {
                Axis::Horizontal => Interaction::ResizingVertically,
                Axis::Vertical => Interaction::ResizingHorizontally,
            }
        } else {
            Interaction::None
        }
    }
}

impl From<Split> for Element<'_, Drag, Theme, iced::Renderer> {
    fn from(s: Split) -> Self {
        Element::new(iced::widget::canvas(s))
    }
}

#[allow(dead_code)]
pub const MIN_PANE: f32 = 120.0;
#[allow(dead_code)]
pub const HIT_STRIP: f32 = HIT_W;
