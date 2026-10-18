use std::collections::VecDeque;
use std::time::Instant;

use iced::alignment::{Horizontal, Vertical};
use iced::widget::{button, column, container, row, Space};
use iced::{Color, Length, Theme};

use super::ui::{fade, El};
use crate::gui::anim::{css_ease, ease_out, progress};
use crate::gui::app::Message;
use crate::gui::theme::{self, ic, label_c, mono_c, R_PANEL};

pub const W: f32 = 340.0;
pub const H: f32 = 64.0;
pub const GAP: f32 = 8.0;
pub const IN_MS: u64 = 350;
pub const OUT_MS: u64 = 300;
const OUT_FADE_MS: u64 = 280;
pub const LIFE_MS: u64 = 5200;
pub const ADMIT_MS: u64 = 120;
pub const MAX_VISIBLE: usize = 5;
const SLIDE_IN: f32 = 28.0;
const SLIDE_OUT: f32 = 24.0;

#[derive(Debug, Clone)]
pub struct Toast {
    pub id: u64,
    pub title: String,
    pub body: String,
    pub icon: &'static str,
    pub error: bool,
    pub born: Instant,
    pub out_at: Option<Instant>,
}

#[derive(Debug, Clone)]
struct Pending {
    title: String,
    body: String,
    icon: &'static str,
    error: bool,
}

#[derive(Debug, Default)]
pub struct Toasts {
    next_id: u64,
    queue: VecDeque<Pending>,
    pub list: Vec<Toast>,
    last_admit: Option<Instant>,
    last_pushed: Option<(String, String)>,
}

impl Toasts {
    pub fn push(
        &mut self,
        now: Instant,
        title: impl Into<String>,
        body: impl Into<String>,
        icon: &'static str,
        error: bool,
    ) {
        let (title, body) = (title.into(), body.into());
        if self
            .last_pushed
            .as_ref()
            .is_some_and(|(t, b)| *t == title && *b == body)
        {
            return;
        }
        self.last_pushed = Some((title.clone(), body.clone()));
        self.queue.push_back(Pending {
            title,
            body,
            icon,
            error,
        });
        self.tick(now);
    }

    pub fn dismiss(&mut self, id: u64, now: Instant) {
        if let Some(t) = self.list.iter_mut().find(|t| t.id == id)
            && t.out_at.is_none() {
                t.out_at = Some(now);
            }
    }

    pub fn tick(&mut self, now: Instant) {
        for t in self.list.iter_mut() {
            if t.out_at.is_none()
                && now.saturating_duration_since(t.born).as_millis() as u64 >= LIFE_MS
            {
                t.out_at = Some(now);
            }
        }
        self.list.retain(|t| match t.out_at {
            Some(o) => (now.saturating_duration_since(o).as_millis() as u64) < OUT_MS + 20,
            None => true,
        });
        let visible = self.list.len();
        let ready = self
            .last_admit
            .map(|l| now.saturating_duration_since(l).as_millis() as u64 >= ADMIT_MS)
            .unwrap_or(true);
        if visible < MAX_VISIBLE && ready
            && let Some(p) = self.queue.pop_front() {
                self.next_id += 1;
                self.list.push(Toast {
                    id: self.next_id,
                    title: p.title,
                    body: p.body,
                    icon: p.icon,
                    error: p.error,
                    born: now,
                    out_at: None,
                });
                self.last_admit = Some(now);
            }
    }

    pub fn deadline(&self) -> Option<Instant> {
        use std::time::Duration;
        let mut next = self
            .list
            .iter()
            .map(|t| match t.out_at {
                Some(o) => o + Duration::from_millis(OUT_MS + 20),
                None => t.born + Duration::from_millis(LIFE_MS),
            })
            .min();
        if !self.queue.is_empty() && self.list.len() < MAX_VISIBLE
            && let Some(last) = self.last_admit {
                let admit = last + Duration::from_millis(ADMIT_MS);
                next = Some(next.map_or(admit, |n| n.min(admit)));
            }
        next
    }

    pub fn is_idle(&self) -> bool {
        self.list.is_empty() && self.queue.is_empty()
    }

    pub fn animating(&self, _now: Instant) -> bool {
        !self.list.is_empty()
    }
}

fn card_height(t: &Toast) -> f32 {
    let lines = t
        .body
        .lines()
        .map(|s| s.chars().count().max(1).div_ceil(30))
        .sum::<usize>()
        .max(1);
    (45.0 + 17.5 * lines as f32).clamp(H, 122.0)
}

const BAR_H: f32 = 4.0;

fn life_remaining(t: &Toast, now: Instant) -> f32 {
    let end = t.out_at.unwrap_or(now);
    let elapsed_ms = end.saturating_duration_since(t.born).as_millis() as f32;
    1.0 - (elapsed_ms / LIFE_MS as f32).clamp(0.0, 1.0)
}

fn card<'a>(t: &Toast, now: Instant, a: f32, light: bool) -> El<'a> {
    let text_c = fade(theme::text_c_for_light(light), a);
    let dim_c = fade(theme::dim_c_for_light(light), a);
    let mute_c = fade(theme::mute_c_for_light(light), a);
    let icon_c = if t.error {
        fade(theme::brk_c_for_light(light), a)
    } else {
        text_c
    };
    let id = t.id;
    let icon_paths = t.icon;
    let close = button(
        container(theme::svg_icon(ic::X, 14.0, mute_c))
            .width(24)
            .height(24)
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center),
    )
    .padding(0)
    .style(move |theme: &Theme, status| {
        let hovered = matches!(status, button::Status::Hovered);
        button::Style {
            background: if hovered {
                Some(
                    fade(
                        if theme::is_light(theme) {
                            Color::from_rgb8(0xdd, 0xdd, 0xdd)
                        } else {
                            Color::from_rgb8(0x3d, 0x3d, 0x3d)
                        },
                        a,
                    )
                    .into(),
                )
            } else {
                None
            },
            text_color: mute_c,
            border: iced::Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        }
    })
    .on_press(Message::ToastDismiss(id));

    let body = column![
        label_c(t.title.clone(), 13.5, iced::font::Weight::Semibold, text_c),
        mono_c(t.body.clone(), 12.5, dim_c),
    ]
    .spacing(2)
    .width(Length::Fill);

    let content = container(
        row![
            container(theme::svg_icon(icon_paths, 18.0, icon_c))
                .padding(theme::pad4(1.0, 0.0, 0.0, 0.0)),
            body,
            container(close).padding(theme::pad4(0.0, 0.0, 0.0, 0.0)),
        ]
        .spacing(12)
        .align_y(Vertical::Top),
    )
    .width(Length::Fill)
    .padding(theme::pad4(13.0, 12.0, 10.0, 14.0));

    let remaining = life_remaining(t, now);
    let fill_c = fade(
        if t.error {
            theme::brk_c_for_light(light)
        } else {
            theme::acc_c_for_light(light)
        },
        a,
    );
    let track_c = fade(
        if light {
            theme::Palette::LIGHT_LINE2
        } else {
            Color::from_rgb8(0x4a, 0x4a, 0x4a)
        },
        a,
    );
    let fill_radius = if remaining >= 0.985 {
        theme::corners(0.0, 0.0, 10.0, 10.0)
    } else {
        theme::corners(0.0, 0.0, 4.0, 10.0)
    };
    let bar = container(
        container(Space::new())
            .width((W * remaining).max(0.0))
            .height(BAR_H)
            .style(move |_: &Theme| container::Style {
                background: Some(fill_c.into()),
                border: iced::Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: fill_radius,
                },
                ..Default::default()
            }),
    )
    .width(Length::Fill)
    .height(BAR_H)
    .style(move |_: &Theme| container::Style {
        background: Some(track_c.into()),
        border: iced::Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: theme::corners(0.0, 0.0, 10.0, 10.0),
        },
        ..Default::default()
    });

    container(column![content, Space::new().height(Length::Fill), bar].spacing(0))
        .width(W)
        .height(card_height(t))
        .clip(true)
        .style(move |theme: &Theme| container::Style {
            background: Some(fade(theme::s2_c(theme), a).into()),
            border: iced::Border {
                color: fade(
                    if theme::is_light(theme) {
                        theme::Palette::LIGHT_LINE2
                    } else {
                        Color::from_rgb8(0x4a, 0x4a, 0x4a)
                    },
                    a,
                ),
                width: 1.0,
                radius: R_PANEL,
            },
            ..Default::default()
        })
        .into()
}

pub fn layer<'a>(toasts: &Toasts, now: Instant, light: bool) -> Option<El<'a>> {
    if toasts.list.is_empty() {
        return None;
    }
    let mut col = column![].spacing(0).align_x(Horizontal::Right);
    for t in &toasts.list {
        let in_p = ease_out(progress(now, t.born, IN_MS));
        let (out_fade, out_h) = t
            .out_at
            .map(|o| {
                (
                    css_ease(progress(now, o, OUT_FADE_MS)),
                    css_ease(progress(now, o, OUT_MS)),
                )
            })
            .unwrap_or((0.0, 0.0));
        let a = (in_p * (1.0 - out_fade)).clamp(0.0, 1.0);
        let shift = SLIDE_IN * (1.0 - in_p) + SLIDE_OUT * out_fade;
        let h = (card_height(t) + GAP) * (1.0 - out_h);
        let inner = iced::widget::pin(card(t, now, a, light)).x(shift).width(W);
        let wrapper = container(inner)
            .width(W)
            .height(Length::Fixed(h.max(0.0)))
            .clip(true);
        col = col.push(wrapper);
    }
    Some(
        container(col)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Horizontal::Right)
            .align_y(Vertical::Bottom)
            .padding(theme::pad4(0.0, 18.0, 10.0, 0.0))
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn throttle_cap_and_expiry() {
        let t0 = Instant::now();
        let mut ts = Toasts::default();
        for i in 0..8 {
            ts.push(t0, format!("t{i}"), "", ic::INFO, false);
        }
        assert_eq!(ts.list.len(), 1);
        assert_eq!(ts.queue.len(), 7);
        for _ in 0..4 {
            let last = ts.list.last().unwrap().born;
            ts.tick(last + Duration::from_millis(ADMIT_MS));
        }
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        assert_eq!(ts.queue.len(), 3);
        ts.tick(t0 + Duration::from_millis(ADMIT_MS * 10));
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        ts.tick(t0 + Duration::from_millis(LIFE_MS + 10));
        assert!(ts.list[0].out_at.is_some());
        ts.tick(t0 + Duration::from_millis(LIFE_MS + 10 + OUT_MS + 50));
        assert!(ts.list.iter().all(|t| t.title != "t0"));
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        assert_eq!(ts.queue.len(), 2);
    }

    #[test]
    fn dismissals_never_exceed_five_and_deadlines_are_exact() {
        let now = Instant::now();
        let mut ts = Toasts::default();
        for i in 0..9 {
            ts.push(now, format!("{i}"), "body", ic::INFO, false);
        }
        assert_eq!(ts.deadline(), Some(now + Duration::from_millis(ADMIT_MS)));
        while ts.list.len() < MAX_VISIBLE {
            let last = ts.list.last().unwrap().born;
            ts.tick(last + Duration::from_millis(ADMIT_MS));
        }
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        let t1 = ts.list.last().unwrap().born + Duration::from_millis(ADMIT_MS);
        ts.dismiss(ts.list[0].id, t1);
        ts.tick(t1);
        assert_eq!(
            ts.list.len(),
            MAX_VISIBLE,
            "a collapsing card still occupies a slot"
        );
        ts.tick(t1 + Duration::from_millis(OUT_MS + 50));
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        assert!(!ts.list.iter().any(|t| t.title == "0"));
    }

    #[test]
    fn queued_toasts_appear_after_manual_dismiss() {
        let t0 = Instant::now();
        let mut ts = Toasts::default();
        for i in 0..(MAX_VISIBLE + 2) {
            let at = t0 + Duration::from_millis(ADMIT_MS * 2 * i as u64);
            ts.push(at, format!("q{i}"), "body", ic::INFO, false);
            ts.tick(at);
        }
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        assert_eq!(ts.queue.len(), 2);
        let now = t0 + Duration::from_millis(ADMIT_MS * 2 * (MAX_VISIBLE + 2) as u64);
        ts.dismiss(ts.list[0].id, now);
        ts.tick(now + Duration::from_millis(OUT_MS + 50));
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        assert_eq!(ts.queue.len(), 1);
        assert!(ts.list.iter().any(|t| t.title == "q5"));
    }

    #[test]
    fn life_bar_depletes_and_freezes_on_dismiss() {
        let t0 = Instant::now();
        let mut t = Toast {
            id: 1,
            title: "t".into(),
            body: "b".into(),
            icon: ic::INFO,
            error: false,
            born: t0,
            out_at: None,
        };
        assert!((life_remaining(&t, t0) - 1.0).abs() < f32::EPSILON);
        let half = t0 + Duration::from_millis(LIFE_MS / 2);
        assert!((life_remaining(&t, half) - 0.5).abs() < 0.02);
        assert_eq!(
            life_remaining(&t, t0 + Duration::from_millis(LIFE_MS + 1000)),
            0.0
        );
        t.out_at = Some(half);
        assert!((life_remaining(&t, half + Duration::from_millis(5000)) - 0.5).abs() < 0.02);
    }

    #[test]
    fn animating_runs_for_whole_visible_life() {
        let t0 = Instant::now();
        let mut ts = Toasts::default();
        ts.push(t0, "t", "b", ic::INFO, false);
        assert!(ts.animating(t0 + Duration::from_millis(IN_MS + 1000)));
        assert!(ts.animating(t0 + Duration::from_millis(LIFE_MS - 100)));
        ts.tick(t0 + Duration::from_millis(LIFE_MS + 10));
        assert!(ts.animating(t0 + Duration::from_millis(LIFE_MS + 20)));
        ts.tick(t0 + Duration::from_millis(LIFE_MS + 10 + OUT_MS + 50));
        let gone = t0 + Duration::from_millis(LIFE_MS + 10 + OUT_MS + 50);
        assert!(!ts.animating(gone));
        assert!(ts.is_idle());
    }

    #[test]
    fn identical_notices_collapse() {
        let t0 = Instant::now();
        let mut ts = Toasts::default();
        ts.push(t0, "same", "body", ic::INFO, false);
        ts.push(t0, "same", "body", ic::INFO, false);
        assert_eq!(ts.list.len() + ts.queue.len(), 1);
    }

    #[test]
    fn retrigger_after_other_notice_is_admitted_again() {
        let t0 = Instant::now();
        let mut ts = Toasts::default();
        ts.push(t0, "Breakpoint set", "0x401000", ic::INFO, false);
        ts.push(t0, "Breakpoint set", "0x402000", ic::INFO, false);
        ts.push(t0, "Breakpoint set", "0x401000", ic::INFO, false);
        assert_eq!(ts.list.len() + ts.queue.len(), 3);
    }

    #[test]
    fn queued_toast_starts_lifetime_at_admission() {
        let t0 = Instant::now();
        let mut ts = Toasts::default();
        for i in 0..MAX_VISIBLE {
            let at = t0 + Duration::from_millis(ADMIT_MS * 2 * i as u64);
            ts.push(at, format!("v{i}"), "body", ic::INFO, false);
            ts.tick(at);
        }
        assert_eq!(ts.list.len(), MAX_VISIBLE);
        let pushed_at = t0 + Duration::from_millis(ADMIT_MS * 2 * MAX_VISIBLE as u64);
        ts.push(pushed_at, "late", "body", ic::INFO, false);
        assert_eq!(ts.queue.len(), 1);
        let admit_at = pushed_at + Duration::from_millis(3000);
        ts.dismiss(ts.list[0].id, admit_at);
        ts.tick(admit_at + Duration::from_millis(OUT_MS + 50));
        let late = ts.list.iter().find(|t| t.title == "late").unwrap();
        assert_eq!(late.born, admit_at + Duration::from_millis(OUT_MS + 50));
        assert!(
            (life_remaining(late, admit_at + Duration::from_millis(OUT_MS + 50)) - 1.0).abs()
                < 0.02
        );
        assert!(late.born - pushed_at >= Duration::from_millis(3000));
    }
}
