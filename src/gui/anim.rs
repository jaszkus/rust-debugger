use std::collections::HashMap;
use std::time::{Duration, Instant};

pub fn bezier(t: f32, x1: f32, y1: f32, x2: f32, y2: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    if t == 0.0 || t == 1.0 {
        return t;
    }
    let sample = |u: f32, a: f32, b: f32| {
        3.0 * (1.0 - u).powi(2) * u * a + 3.0 * (1.0 - u) * u * u * b + u * u * u
    };
    let (mut lo, mut hi) = (0.0, 1.0);
    for _ in 0..24 {
        let u = (lo + hi) * 0.5;
        if sample(u, x1, x2) < t {
            lo = u;
        } else {
            hi = u;
        }
    }
    sample((lo + hi) * 0.5, y1, y2)
}

pub fn ease_out(t: f32) -> f32 {
    bezier(t, 0.2, 0.8, 0.2, 1.0)
}
pub fn ease_out_soft(t: f32) -> f32 {
    bezier(t, 0.3, 0.8, 0.3, 1.0)
}
pub fn view_ease(t: f32) -> f32 {
    bezier(t, 0.2, 0.7, 0.2, 1.0)
}
pub fn css_ease(t: f32) -> f32 {
    bezier(t, 0.25, 0.1, 0.25, 1.0)
}
pub fn pulse(now: Instant, since: Instant) -> f32 {
    let phase = now.saturating_duration_since(since).as_secs_f32() % 1.8 / 0.9;
    let t = if phase < 1.0 { phase } else { 2.0 - phase };
    1.0 - 0.8 * bezier(t, 0.42, 0.0, 0.58, 1.0)
}

pub fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

pub fn progress(now: Instant, since: Instant, ms: u64) -> f32 {
    if ms == 0 {
        return 1.0;
    }
    let el = now.saturating_duration_since(since).as_secs_f32() * 1000.0;
    (el / ms as f32).clamp(0.0, 1.0)
}

pub fn running(now: Instant, since: Instant, ms: u64) -> bool {
    now.saturating_duration_since(since) < Duration::from_millis(ms)
}

pub fn progress_delayed(now: Instant, since: Instant, delay_ms: u64, ms: u64) -> f32 {
    let el = now.saturating_duration_since(since).as_secs_f32() * 1000.0 - delay_ms as f32;
    if ms == 0 {
        return if el >= 0.0 { 1.0 } else { 0.0 };
    }
    (el / ms as f32).clamp(0.0, 1.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Out,
    Soft,
    View,
    Css,
}

impl Curve {
    fn apply(self, p: f32) -> f32 {
        match self {
            Curve::Out => ease_out(p),
            Curve::Soft => ease_out_soft(p),
            Curve::View => view_ease(p),
            Curve::Css => css_ease(p),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Tween {
    pub from: f32,
    pub to: f32,
    pub start: Instant,
    pub ms: u64,
    curve: Curve,
}

impl Tween {
    pub fn new(from: f32, to: f32, start: Instant, ms: u64) -> Self {
        Self {
            from,
            to,
            start,
            ms,
            curve: Curve::Out,
        }
    }

    pub fn soft(mut self) -> Self {
        self.curve = Curve::Soft;
        self
    }

    pub fn css(mut self) -> Self {
        self.curve = Curve::Css;
        self
    }

    pub fn active(&self, now: Instant) -> bool {
        running(now, self.start, self.ms)
    }

    pub fn value(&self, now: Instant) -> f32 {
        let p = progress(now, self.start, self.ms);
        lerp(self.from, self.to, self.curve.apply(p))
    }
}

pub type Key = (&'static str, u64);

#[derive(Debug, Default)]
pub struct Anims {
    map: HashMap<Key, Tween>,
}

impl Anims {
    pub fn start(&mut self, key: Key, from: f32, to: f32, ms: u64, now: Instant) {
        self.map.insert(key, Tween::new(from, to, now, ms));
    }

    pub fn start_view(&mut self, key: Key, from: f32, to: f32, ms: u64, now: Instant) {
        let mut tween = Tween::new(from, to, now, ms);
        tween.curve = Curve::View;
        self.map.insert(key, tween);
    }

    pub fn start_soft(&mut self, key: Key, from: f32, to: f32, ms: u64, now: Instant) {
        self.map.insert(key, Tween::new(from, to, now, ms).soft());
    }

    pub fn start_css(&mut self, key: Key, from: f32, to: f32, ms: u64, now: Instant) {
        self.map.insert(key, Tween::new(from, to, now, ms).css());
    }

    pub fn value(&self, key: Key, settled: f32, now: Instant) -> f32 {
        match self.map.get(&key) {
            Some(t) if t.active(now) => t.value(now),
            _ => settled,
        }
    }

    pub fn is_active(&self, key: Key, now: Instant) -> bool {
        self.map.get(&key).map(|t| t.active(now)).unwrap_or(false)
    }

    pub fn active(&self, now: Instant) -> bool {
        self.map.values().any(|t| t.active(now))
    }

    pub fn gc(&mut self, now: Instant) {
        self.map.retain(|_, t| t.active(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ease_endpoints() {
        assert_eq!(ease_out(0.0), 0.0);
        assert_eq!(ease_out(1.0), 1.0);
        assert!(ease_out(0.5) > 0.5);
        assert_eq!(ease_out(5.0), 1.0);
    }

    #[test]
    fn curves_match_css_parameter_samples() {
        for (x1, y1, x2, y2) in [
            (0.2, 0.8, 0.2, 1.0),
            (0.3, 0.8, 0.3, 1.0),
            (0.2, 0.7, 0.2, 1.0),
        ] {
            let x = (3.0 * x1 + 3.0 * x2 + 1.0) / 8.0;
            let y = (3.0 * y1 + 3.0 * y2 + 1.0) / 8.0;
            assert!((bezier(x, x1, y1, x2, y2) - y).abs() < 0.00001);
        }
    }

    #[test]
    fn tween_runs_then_settles() {
        let t0 = Instant::now();
        let mut a = Anims::default();
        a.start(("x", 1), 0.0, 1.0, 100, t0);
        assert!(a.active(t0));
        assert!(a.value(("x", 1), 1.0, t0) < 0.01);
        let later = t0 + Duration::from_millis(150);
        assert!(!a.active(later));
        assert_eq!(a.value(("x", 1), 1.0, later), 1.0);
        a.gc(later);
        assert!(!a.is_active(("x", 1), later));
    }

    #[test]
    fn css_curve_is_selectable() {
        let t0 = Instant::now();
        let mut a = Anims::default();
        a.start_css(("c", 1), 1.0, 0.0, 100, t0);
        let mid = a.value(("c", 1), 1.0, t0 + Duration::from_millis(50));
        assert!(mid < 0.4, "{mid}");
    }

    #[test]
    fn delayed_progress() {
        let t0 = Instant::now();
        assert_eq!(progress_delayed(t0, t0, 100, 100), 0.0);
        assert_eq!(
            progress_delayed(t0 + Duration::from_millis(250), t0, 100, 100),
            1.0
        );
    }
}
