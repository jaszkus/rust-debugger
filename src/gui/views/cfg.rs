use iced::advanced::text::{Alignment, LineHeight, Shaping};
use iced::mouse::{self, Cursor, ScrollDelta};
use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke, Text as CText};
use iced::widget::{column, row};
use iced::{Element, Length, Point, Rectangle, Size, Theme};

use std::sync::Arc;

use super::empty_state;
use crate::gui::app::{Message, Shell};
use crate::gui::theme::{label, Fonts, Tokens, T};

const MAX_LINES: usize = 12;
const NODE_W: f32 = 300.0;

#[derive(Clone, PartialEq)]
struct Cam {
    func: Option<u64>,
    zoom: f32,
    pan: Point,
    selected: Option<usize>,
}

#[derive(Default)]
struct State {
    cam: Option<Cam>,
    dragging: bool,
    drag_start: Option<Point>,
    pan_at_drag: Option<Point>,
}

pub fn view<'a>(
    shell: &'a Shell,
    _fonts: &'a Fonts,
) -> Element<'a, Message, Theme, iced::Renderer> {
    let data = shell.read(|s| {
        let a = s.analysis.clone()?;
        let cur = s
            .selected_func
            .or_else(|| a.functions.first().map(|f| f.entry))?;
        let cfg = a.cfgs.get(&cur)?;
        let disasm = s.disasm.clone();
        let name = a
            .functions
            .iter()
            .find(|f| f.entry == cur)
            .map(|f| f.name.clone())
            .unwrap_or_default();
        let ver = s.analysis_version;
        let hit = s.cfg_layout_cache.0 == ver && s.cfg_layout_cache.1 == cur;
        let (base_pos, base_h, min_x, max_x) = if hit {
            let c = &s.cfg_layout_cache;
            (c.2.clone(), c.3.clone(), c.4, c.5)
        } else {
            let (pos, h, _levels) = crate::analysis::cfg::graph_layout(cfg, MAX_LINES);
            let min = pos.iter().map(|p| p[0]).fold(0.0f32, f32::min);
            let max = pos.iter().map(|p| p[0]).fold(0.0f32, f32::max) + NODE_W;
            s.cfg_layout_cache = (ver, cur, pos.clone(), h.clone(), min, max);
            (pos, h, min, max)
        };
        let insns: Arc<Vec<Vec<String>>> = if let Some(m) = {
            let cache = shell.cfg_insns.borrow();
            match &*cache {
                Some((v, f, m)) if *v == ver && *f == cur => Some(m.clone()),
                _ => None,
            }
        } {
            m
        } else {
            let mut v: Vec<Vec<String>> = Vec::with_capacity(cfg.blocks.len());
            if let Some(d) = &disasm {
                for block in &cfg.blocks {
                    let mut lines = Vec::with_capacity(block.instr_indices.len().min(MAX_LINES));
                    for ii in block.instr_indices.clone().take(MAX_LINES) {
                        if let Some(ins) = d.instructions.get(ii) {
                            lines.push(format!(
                                "{:08X} {} {}",
                                ins.address, ins.mnemonic, ins.operands
                            ));
                        }
                    }
                    v.push(lines);
                }
            }
            let m = Arc::new(v);
            *shell.cfg_insns.borrow_mut() = Some((ver, cur, m.clone()));
            m
        };
        Some((
            cur,
            name,
            cfg.blocks.len(),
            base_pos,
            base_h,
            min_x,
            max_x,
            insns,
            cfg.block_at.get(&cfg.func_entry).copied().unwrap_or(0),
            cfg.blocks
                .iter()
                .map(|b| b.successors.clone())
                .collect::<Vec<_>>(),
            cfg.blocks
                .iter()
                .map(|b| (b.start, b.end))
                .collect::<Vec<_>>(),
        ))
    });
    let (func, name, nblocks, base_pos, base_h, min_x, max_x, insns, entry_idx, succs, ranges) =
        match data {
            Some(v) => v,
            None => {
                let (title, body) = if shell.read(|s| s.analysis.is_some()) {
                    (
                        "No control-flow graph",
                        "Select a function to draw its graph.",
                    )
                } else {
                    (
                        "No functions analyzed",
                        "Open a file and wait for the analysis to finish.",
                    )
                };
                return empty_state(title.to_string(), body.to_string());
            }
        };

    let light = shell.is_light();
    let program = CfgView {
        func,
        name: name.clone(),
        nblocks,
        base_pos,
        base_h,
        min_x,
        max_x,
        insns,
        entry_idx,
        succs,
        ranges,
        tokens: Tokens::resolve(light),
    };
    let canvas_widget = iced::widget::Canvas::new(program)
        .width(Length::Fill)
        .height(Length::Fill);
    column![
        row![
            label(format!("{name} @ {func:#x}"), T::Strong),
            label(format!("({nblocks} basic blocks)"), T::Mute),
        ]
        .spacing(10),
        canvas_widget,
    ]
    .spacing(4)
    .into()
}

struct CfgView {
    func: u64,
    #[allow(dead_code)]
    name: String,
    nblocks: usize,
    base_pos: Vec<[f32; 2]>,
    base_h: Vec<f32>,
    min_x: f32,
    max_x: f32,
    insns: Arc<Vec<Vec<String>>>,
    entry_idx: usize,
    succs: Vec<Vec<crate::analysis::cfg::Edge>>,
    ranges: Vec<(u64, u64)>,
    tokens: Tokens,
}

impl canvas::Program<Message> for CfgView {
    type State = State;

    fn draw(
        &self,
        state: &Self::State,
        renderer: &iced::Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: Cursor,
    ) -> Vec<Geometry> {
        let cam = state.cam.clone().unwrap_or(Cam {
            func: Some(self.func),
            zoom: 1.0,
            pan: Point::new(20.0, 20.0),
            selected: None,
        });
        let zoom = cam.zoom;
        let mut frame = Frame::new(renderer, bounds.size());

        let n = self.nblocks;
        let line_h = 15.0 * zoom.max(0.6);
        let node_w = NODE_W * zoom;
        let mut pos: Vec<[f32; 2]> = Vec::with_capacity(n.max(self.base_pos.len()));
        pos.extend(self.base_pos.iter().map(|p| [p[0] * zoom, p[1] * zoom]));
        let mut node_h: Vec<f32> = Vec::with_capacity(n.max(self.base_h.len()));
        node_h.extend(self.base_h.iter().map(|h| h * zoom));

        let min_x = self.min_x * zoom;
        let max_x = self.max_x * zoom;
        let content_half = (max_x - min_x) / 2.0;
        let to_screen = |wx: f32, wy: f32| -> [f32; 2] {
            [
                bounds.width / 2.0 + (wx - min_x - content_half) + cam.pan.x,
                wy + cam.pan.y,
            ]
        };

        let t = self.tokens;
        let edge_color = |kind: &crate::analysis::EdgeKind| -> iced::Color {
            match kind {
                crate::analysis::EdgeKind::Fallthrough => t.mute,
                crate::analysis::EdgeKind::Jump => t.link,
                crate::analysis::EdgeKind::BranchTrue => t.run,
                crate::analysis::EdgeKind::BranchFalse => t.brk,
            }
        };
        for (si, edges) in self.succs.iter().enumerate() {
            if si >= n {
                break;
            }
            let p0 = to_screen(pos[si][0] + node_w / 2.0, pos[si][1] + node_h[si]);
            for e in edges {
                let ti = e.target;
                if ti >= n {
                    continue;
                }
                let p1 = to_screen(pos[ti][0] + node_w / 2.0, pos[ti][1]);
                let col = edge_color(&e.kind);
                let stroke = Stroke::default().with_color(col).with_width(1.5);
                if pos[ti][1] <= pos[si][1] {
                    let r0 = to_screen(
                        pos[si][0] + node_w + 8.0 * zoom,
                        pos[si][1] + node_h[si] / 2.0,
                    );
                    let r1 = to_screen(
                        pos[ti][0] + node_w + 8.0 * zoom,
                        pos[ti][1] + node_h[ti] / 2.0,
                    );
                    let mid_x = r0[0].max(r1[0]) + 10.0 * zoom;
                    frame.stroke(&Path::line(p(r0), p([mid_x, r0[1]])), stroke);
                    frame.stroke(&Path::line(p([mid_x, r0[1]]), p([mid_x, r1[1]])), stroke);
                    frame.stroke(&Path::line(p([mid_x, r1[1]]), p(r1)), stroke);
                    arrow_head(&mut frame, [r1[0], r1[1] - 4.0], [r1[0], r1[1]], col);
                } else {
                    let mid = (p0[1] + p1[1]) / 2.0;
                    let pts = Path::new(|b| {
                        b.move_to(p(p0));
                        b.line_to(p([p0[0], mid]));
                        b.line_to(p([p1[0], mid]));
                        b.line_to(p(p1));
                    });
                    frame.stroke(&pts, stroke);
                    arrow_head(
                        &mut frame,
                        [p1[0] - 4.0, p1[1] - 1.0],
                        [p1[0] + 4.0, p1[1] - 1.0],
                        col,
                    );
                    let _ = p1;
                }
            }
        }

        for bi in 0..n {
            if bi >= pos.len() || bi >= node_h.len() || bi >= self.ranges.len() {
                break;
            }
            let tl = to_screen(pos[bi][0], pos[bi][1]);
            let br = [tl[0] + node_w, tl[1] + node_h[bi]];
            if br[0] < 0.0 || tl[0] > bounds.width || br[1] < 0.0 || tl[1] > bounds.height {
                continue;
            }
            let selected = cam.selected == Some(bi);
            let is_entry = bi == self.entry_idx;
            frame.fill_rectangle(
                p(tl),
                Size::new(node_w, node_h[bi]),
                crate::gui::theme::accent_bg(self.tokens.is_light_flag),
            );
            let border = if selected {
                t.annot
            } else if is_entry {
                t.mint
            } else {
                t.dim
            };
            frame.stroke(
                &Path::rectangle(p(tl), Size::new(node_w, node_h[bi])),
                Stroke::default()
                    .with_color(border)
                    .with_width(if selected { 2.5 } else { 1.5 }),
            );
            let (start, end) = self.ranges[bi];
            let mut ty = tl[1] + 4.0;
            let tx = tl[0] + 6.0;
            put_text(
                &mut frame,
                tx,
                ty,
                line_h,
                &format!("BB_{bi} [{start:#x}-{end:#x}]"),
                t.mint,
                12.0 * zoom.max(0.6),
            );
            ty += line_h;
            if let Some(lines) = self.insns.get(bi) {
                for line in lines {
                    put_text(
                        &mut frame,
                        tx,
                        ty,
                        line_h,
                        line.as_str(),
                        t.text,
                        12.0 * zoom.max(0.6),
                    );
                    ty += line_h;
                }
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
    ) -> Option<canvas::Action<Message>> {
        let needs_reset = match &state.cam {
            Some(c) => c.func != Some(self.func),
            None => true,
        };
        if needs_reset {
            state.cam = Some(Cam {
                func: Some(self.func),
                zoom: 1.0,
                pan: Point::new(20.0, 20.0),
                selected: None,
            });
        }

        match event {
            canvas::Event::Mouse(mouse::Event::WheelScrolled { delta })
                if cursor.position_in(bounds).is_some() =>
            {
                let wf = match delta {
                    ScrollDelta::Pixels { y, .. } => y / 40.0,
                    ScrollDelta::Lines { y, .. } => *y * 0.15,
                };
                let cam = state.cam.as_mut().unwrap();
                let old = cam.zoom;
                let new = (old * (1.0 + wf * 0.12)).clamp(0.25, 3.0);
                if (new - old).abs() > f32::EPSILON {
                    cam.zoom = new;
                    return Some(canvas::Action::request_redraw());
                }
                None
            }
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                let p = cursor.position_in(bounds)?;
                let cam = state.cam.as_ref().unwrap().clone();
                let zoom = cam.zoom;
                let node_w = NODE_W * zoom;
                let mut pos: Vec<[f32; 2]> = Vec::with_capacity(self.base_pos.len());
                pos.extend(self.base_pos.iter().map(|p| [p[0] * zoom, p[1] * zoom]));
                let mut node_h: Vec<f32> = Vec::with_capacity(self.base_h.len());
                node_h.extend(self.base_h.iter().map(|h| h * zoom));
                let min_x = self.min_x * zoom;
                let max_x = self.max_x * zoom;
                let content_half = (max_x - min_x) / 2.0;
                let mut hit = None;
                for bi in (0..self.nblocks).rev() {
                    if bi >= pos.len() || bi >= node_h.len() {
                        break;
                    }
                    let sx = bounds.width / 2.0 + (pos[bi][0] - min_x - content_half) + cam.pan.x;
                    let sy = pos[bi][1] + cam.pan.y;
                    if p.x >= sx && p.x <= sx + node_w && p.y >= sy && p.y <= sy + node_h[bi] {
                        hit = Some(bi);
                        break;
                    }
                }
                let cam_mut = state.cam.as_mut().unwrap();
                cam_mut.selected = hit;
                if let Some(bi) = hit {
                    if let Some((start, _)) = self.ranges.get(bi) {
                        return Some(canvas::Action::publish(Message::RowGoto(*start)));
                    }
                }
                Some(canvas::Action::request_redraw())
            }
            canvas::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Right)) => {
                if cursor.position_in(bounds).is_some() {
                    state.dragging = true;
                    state.drag_start = cursor.position();
                    state.pan_at_drag = Some(state.cam.as_ref().unwrap().pan);
                    return Some(canvas::Action::capture());
                }
                None
            }
            canvas::Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                if state.dragging {
                    if let (Some(start), Some(pan0)) = (state.drag_start, state.pan_at_drag) {
                        let now = cursor.position().unwrap_or(start);
                        let cam = state.cam.as_mut().unwrap();
                        cam.pan =
                            Point::new(pan0.x + (now.x - start.x), pan0.y + (now.y - start.y));
                        return Some(canvas::Action::request_redraw());
                    }
                }
                None
            }
            canvas::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Right)) => {
                if state.dragging {
                    state.dragging = false;
                    return Some(canvas::Action::capture());
                }
                None
            }
            _ => None,
        }
    }

    fn mouse_interaction(
        &self,
        state: &Self::State,
        bounds: Rectangle,
        cursor: Cursor,
    ) -> mouse::Interaction {
        if state.dragging {
            return mouse::Interaction::Move;
        }
        if cursor.position_in(bounds).is_some() {
            mouse::Interaction::Crosshair
        } else {
            mouse::Interaction::None
        }
    }
}

fn p(v: [f32; 2]) -> Point {
    Point::new(v[0], v[1])
}

fn arrow_head(frame: &mut Frame, a: [f32; 2], b: [f32; 2], color: iced::Color) {
    frame.fill(
        &Path::new(|builder| {
            builder.move_to(Point::new(a[0], a[1]));
            builder.line_to(Point::new(b[0], b[1]));
            builder.line_to(Point::new(b[0], b[1] + 6.0));
            builder.close();
        }),
        color,
    );
}

fn put_text(
    frame: &mut Frame,
    x: f32,
    y: f32,
    line_h: f32,
    s: &str,
    color: iced::Color,
    size: f32,
) {
    if line_h <= 0.0 || size <= 0.0 || s.is_empty() {
        return;
    }
    let (w, h) = (frame.width(), frame.height());
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    if y < -size || y + line_h > h + size || x > w {
        return;
    }
    frame.fill_text(CText {
        content: s.to_owned(),
        position: Point::new(x, y),
        color,
        size: iced::Pixels(size),
        line_height: LineHeight::Absolute(iced::Pixels(line_h)),
        font: crate::gui::theme::mono_font(),
        align_x: Alignment::Left,
        align_y: iced::alignment::Vertical::Top,
        shaping: Shaping::Basic,
        max_width: f32::INFINITY,
    });
}
