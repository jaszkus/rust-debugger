use iced::border::Radius;
use iced::widget::{button, container, scrollable, text_input};
use iced::{color, Border, Color, Theme};

use super::colors::*;

pub fn pad4(top: f32, right: f32, bottom: f32, left: f32) -> iced::Padding {
    iced::Padding {
        top,
        right,
        bottom,
        left,
    }
}

const fn radius(r: f32) -> Radius {
    Radius {
        top_left: r,
        top_right: r,
        bottom_right: r,
        bottom_left: r,
    }
}

pub const R_NONE: Radius = radius(0.0);
pub const R_CTRL: Radius = radius(6.0);
pub const R_NAV: Radius = radius(7.0);
pub const R_ROW: Radius = radius(8.0);
pub const R_PANEL: Radius = radius(10.0);
pub const R_POP: Radius = radius(12.0);
pub const R_PILL: Radius = radius(99.0);

pub fn corners(tl: f32, tr: f32, br: f32, bl: f32) -> Radius {
    Radius {
        top_left: tl,
        top_right: tr,
        bottom_right: br,
        bottom_left: bl,
    }
}

#[allow(dead_code)]
pub fn panel_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(s1_c(theme).into()),
        border: Border {
            color: line_c(theme),
            width: 1.0,
            radius: R_NONE,
        },
        ..Default::default()
    }
}

pub fn reading_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(app_bg_c(theme).into()),
        ..Default::default()
    }
}

pub fn card_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(s1_c(theme).into()),
        border: Border {
            color: line2_c(theme),
            width: 1.0,
            radius: R_POP,
        },
        ..Default::default()
    }
}

pub fn tooltip_style(theme: &Theme) -> container::Style {
    let (bg, fg) = if is_light(theme) {
        (color!(0x1c1c1c), color!(0xf2f2f2))
    } else {
        (color!(0xf2f2f2), color!(0x111111))
    };
    container::Style {
        background: Some(bg.into()),
        text_color: Some(fg),
        border: Border {
            color: bg,
            width: 1.0,
            radius: R_NAV,
        },
        ..Default::default()
    }
}

#[allow(dead_code)]
pub fn flat_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(app_bg_c(theme).into()),
        border: Border::default(),
        ..Default::default()
    }
}

pub fn sidebar_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(shell_c(theme).into()),
        ..Default::default()
    }
}

pub fn toolbar_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(shell_c(theme).into()),
        ..Default::default()
    }
}

pub fn shell_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(shell_c(theme).into()),
        text_color: Some(text_c(theme)),
        ..Default::default()
    }
}

#[allow(dead_code)]
pub fn statusbar_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(shell_c(theme).into()),
        ..Default::default()
    }
}

pub fn panel_frame_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(app_bg_c(theme).into()),
        border: Border {
            color: line_c(theme),
            width: 1.0,
            radius: R_PANEL,
        },
        ..Default::default()
    }
}

pub fn region_style(bg: fn(&Theme) -> Color, r: Radius) -> impl Fn(&Theme) -> container::Style {
    move |theme| container::Style {
        background: Some(bg(theme).into()),
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: r,
        },
        ..Default::default()
    }
}

#[derive(Clone, Copy)]
pub enum Btn {
    Bar,
    #[allow(dead_code)]
    Dial,
    Primary,
    Run,
    Quiet,
    Nav,
}

impl Btn {
    pub fn style(self) -> impl Fn(&Theme, button::Status) -> button::Style {
        move |theme, status| self.style_at(theme, status)
    }

    pub fn style_fn(self) -> impl Fn(&Theme, button::Status) -> button::Style {
        self.style()
    }

    pub fn style_fn2(self) -> impl Fn(&Theme, button::Status) -> button::Style {
        self.style()
    }

    fn style_at(self, theme: &Theme, status: button::Status) -> button::Style {
        let light = is_light(theme);
        let txt = text_c(theme);
        let dim = dim_c(theme);
        let mute = mute_c(theme);
        let acc = acc_c(theme);
        let on_acc = on_acc_c(theme);
        let (bg, fg, border_c, radius) = match self {
            Btn::Bar | Btn::Dial => (s1_c(theme), txt, line_c(theme), R_CTRL),
            Btn::Primary | Btn::Run => (acc, on_acc, acc, R_CTRL),
            Btn::Quiet => (Color::TRANSPARENT, dim, Color::TRANSPARENT, R_CTRL),
            Btn::Nav => (Color::TRANSPARENT, dim, Color::TRANSPARENT, R_NAV),
        };
        let mut style = button::Style {
            background: Some(bg.into()),
            text_color: fg,
            border: Border {
                color: border_c,
                width: 1.0,
                radius,
            },
            ..Default::default()
        };
        match status {
            button::Status::Hovered => match self {
                Btn::Quiet => {
                    style.background = Some(s2_c(theme).into());
                    style.text_color = txt;
                }
                Btn::Nav => {
                    style.background = Some(s1_c(theme).into());
                    style.text_color = txt;
                }
                Btn::Bar | Btn::Dial => {
                    style.background = Some(s2_c(theme).into());
                }
                Btn::Primary | Btn::Run => {
                    let h = if light {
                        color!(0x333333)
                    } else {
                        color!(0xe5e5e5)
                    };
                    style.background = Some(h.into());
                    style.border.color = h;
                }
            },
            button::Status::Pressed => match self {
                Btn::Primary | Btn::Run => {
                    let h = if light {
                        color!(0x4a4a4a)
                    } else {
                        color!(0xcccccc)
                    };
                    style.background = Some(h.into());
                    style.border.color = h;
                }
                _ => style.background = Some(sel_c(theme).into()),
            },
            button::Status::Disabled => {
                style.text_color = mute;
                if matches!(self, Btn::Primary | Btn::Run) {
                    style.background = Some(s2_c(theme).into());
                    style.border.color = s2_c(theme);
                }
            }
            button::Status::Active => {}
        }
        style
    }

    pub fn nav_active(theme: &Theme) -> container::Style {
        container::Style {
            background: Some(s2_c(theme).into()),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: R_NAV,
            },
            ..Default::default()
        }
    }
}

fn input_with(theme: &Theme, status: text_input::Status, bg: Color) -> text_input::Style {
    let border = match status {
        text_input::Status::Focused { .. } => acc_c(theme),
        _ => line2_c(theme),
    };
    text_input::Style {
        background: bg.into(),
        border: Border {
            color: border,
            width: 1.0,
            radius: R_CTRL,
        },
        icon: dim_c(theme),
        placeholder: mute_c(theme),
        value: text_c(theme),
        selection: sel_c(theme),
    }
}

pub fn editor_style(
    theme: &Theme,
    status: iced::widget::text_editor::Status,
) -> iced::widget::text_editor::Style {
    iced::widget::text_editor::Style {
        background: bg(theme).into(),
        border: Border {
            color: if matches!(status, iced::widget::text_editor::Status::Focused { .. }) {
                accent(theme)
            } else {
                line2_c(theme)
            },
            width: 1.0,
            radius: R_CTRL,
        },
        placeholder: mute(theme),
        value: text_c(theme),
        selection: select(theme),
    }
}

pub fn input_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    input_with(theme, status, app_bg_c(theme))
}

pub fn input_bar_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    input_with(theme, status, s1_c(theme))
}

#[allow(dead_code)]
pub fn search_input_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let mut s = input_style(theme, status);
    s.background = Color::TRANSPARENT.into();
    s.border = Border {
        color: Color::TRANSPARENT,
        width: 0.0,
        radius: R_NONE,
    };
    s
}

#[allow(dead_code)]
pub fn search_box_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(s1_c(theme).into()),
        border: Border {
            color: line2_c(theme),
            width: 1.0,
            radius: R_CTRL,
        },
        ..Default::default()
    }
}

pub fn scroll_style(theme: &Theme, status: scrollable::Status) -> scrollable::Style {
    let _ = status;
    let thumb = line2_c(theme);
    let rail = scrollable::Rail {
        background: None,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: R_NONE,
        },
        scroller: scrollable::Scroller {
            background: thumb.into(),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: radius(4.0),
            },
        },
    };
    scrollable::Style {
        container: iced::widget::container::Style::default(),
        vertical_rail: rail,
        horizontal_rail: rail,
        gap: None,
        auto_scroll: scrollable::AutoScroll {
            background: s1_c(theme).into(),
            border: Border {
                color: line_c(theme),
                width: 1.0,
                radius: R_CTRL,
            },
            shadow: iced::Shadow::default(),
            icon: text_c(theme),
        },
    }
}
