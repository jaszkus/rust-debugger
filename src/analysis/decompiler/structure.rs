use super::printing::*;
use super::*;
use crate::analysis::flow::cfg::{EdgeKind, CFG};
use crate::analysis::operands::canonical_reg;
use crate::disasm::DisasmInstruction;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

pub(crate) fn compute_dowhile(
    cfg: &CFG,
    bops: &[Vec<(u64, &POp)>],
    imap: &[DisasmInstruction],
    back_edges: &HashMap<usize, usize>,
    block_consts: &[HashMap<&'static str, Lattice>],
    hints: &TypeHints,
) -> HashSet<usize> {
    let mut out = HashSet::default();
    for (header, latch) in back_edges {
        let hconsts = block_consts.get(*header).cloned().unwrap_or_default();
        if recover_condition(cfg, bops, imap, *header, &hconsts, Some(hints)) != "cond" {
            continue;
        }
        let lconsts = block_consts.get(*latch).cloned().unwrap_or_default();
        if recover_condition(cfg, bops, imap, *latch, &lconsts, Some(hints)) != "cond" {
            out.insert(*header);
        }
    }
    out
}

#[derive(Clone, Copy)]
pub(crate) struct WalkCtx<'a> {
    pub(crate) cfg: &'a CFG,
    pub(crate) bops: &'a [Vec<(u64, &'a POp)>],
    pub(crate) imap: &'a [DisasmInstruction],
    pub(crate) func_lookup: &'a HashMap<u64, String>,
    pub(crate) back_edges: &'a HashMap<usize, usize>,
    pub(crate) block_consts: &'a [HashMap<&'static str, Lattice>],
    pub(crate) dowhile: &'a HashSet<usize>,
    pub(crate) dead: &'a HashSet<(usize, usize)>,
    pub(crate) cancel: Option<&'a std::sync::atomic::AtomicBool>,
    pub(crate) is64: bool,
    pub(crate) hints: &'a TypeHints,
}

pub(crate) fn walk_block(
    ctx: &WalkCtx<'_>,
    block_id: usize,
    visited: &mut HashSet<usize>,
    lines: &mut Vec<PseudoLine>,
    indent: u32,
    depth: usize,
) {
    let WalkCtx {
        cfg,
        bops,
        imap,
        func_lookup,
        back_edges,
        block_consts,
        dowhile,
        dead,
        cancel,
        is64,
        hints,
    } = *ctx;
    if depth > 5_000 {
        return;
    }
    if visited.contains(&block_id) {
        return;
    }
    if lines.len() > MAX_DECOMP_LINES || hints.out_bytes.get() > MAX_DECOMP_BYTES {
        hints.out_truncated.set(true);
        return;
    }
    if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
        return;
    }
    visited.insert(block_id);

    if block_id >= cfg.blocks.len() {
        return;
    }
    let block = &cfg.blocks[block_id];

    let is_loop_header = back_edges.contains_key(&block_id);
    let is_dowhile = dowhile.contains(&block_id);

    if is_dowhile {
        lines.push(PseudoLine {
            indent,
            text: "do {".into(),
            kind: LineKind::Branch,
            source_addr: Some(block.start),
        });
    } else if is_loop_header {
        let back_src = back_edges[&block_id];
        let consts = block_consts.get(back_src).cloned().unwrap_or_default();
        let mut cond = recover_condition(cfg, bops, imap, back_src, &consts, Some(hints));
        if cond == "cond" {
            let hconsts = block_consts.get(block_id).cloned().unwrap_or_default();
            let hcond = recover_condition(cfg, bops, imap, block_id, &hconsts, Some(hints));
            if hcond != "cond" {
                cond = format!("!({})", hcond);
            }
        }
        lines.push(PseudoLine {
            indent,
            text: format!("while ({}) {{", cond),
            kind: LineKind::Branch,
            source_addr: Some(cfg.blocks[back_src].start),
        });
    } else if block.predecessors.len() > 1 || (block_id != 0 && block.predecessors.is_empty()) {
        lines.push(PseudoLine {
            indent: 0,
            text: format!("LAB_{:X}:", block.start),
            kind: LineKind::Label,
            source_addr: Some(block.start),
        });
    }

    let seed: HashMap<&'static str, Lattice> =
        block_consts.get(block_id).cloned().unwrap_or_default();
    let mut reg_values: HashMap<&'static str, PVal> = seed
        .into_iter()
        .filter_map(|(k, v)| match v {
            Lattice::Const(c) => Some((k, PVal::C(c))),
            Lattice::Var(n) => Some((k, PVal::E(n.to_string()))),
            Lattice::Top => None,
        })
        .collect();

    let ops: &[(u64, &POp)] = &bops[block_id];
    let addrs: Vec<u64> = ops.iter().map(|(a, _)| *a).collect();

    let block_has_jcc = addrs.iter().any(|a| {
        imap_get(imap, *a)
            .map(|d| d.mnemonic.starts_with('j') && d.mnem() != "jmp")
            .unwrap_or(false)
    });
    let mut last_use: HashMap<&'static str, usize> = HashMap::default();
    let mut live_out: rustc_hash::FxHashSet<&'static str> = rustc_hash::FxHashSet::default();
    for s in &block.successors {
        if s.target >= bops.len() {
            continue;
        }
        for (_, op) in &bops[s.target] {
            for r in reads_regs(op) {
                live_out.insert(r);
            }
        }
    }
    if !block_has_jcc {
        for (i, (_, op)) in ops.iter().enumerate() {
            for r in reads_regs(op) {
                last_use.insert(r, i);
            }
        }
    }

    let ov_before = EXPR_OVERFLOWS.with(|c| c.get());
    let lines_before = lines.len();
    let mut cse_map: HashMap<String, (&'static str, Vec<&'static str>)> = HashMap::default();
    let mut push_args: Vec<PVal> = Vec::new();

    for (i, (addr, op)) in ops.iter().enumerate() {
        if !block_has_jcc && is_pure(op)
            && let Some(dst_reg) = written_reg(op) {
                let dead_local = last_use.get(dst_reg).map(|&u| u <= i).unwrap_or(true);
                if dead_local && !live_out.contains(dst_reg) {
                    continue;
                }
            }
        if dead.contains(&(block_id, i)) {
            continue;
        }
        let ck = if !block_has_jcc {
            cse_key(op, &reg_values)
        } else {
            None
        };
        if let Some((ref key, _)) = ck
            && let Some(holder) = cse_map.get(key).map(|(h, _)| *h)
                && let Some(dst) = written_reg(op) {
                    if holder != dst {
                        let dstv = PVar::Reg(canonical_reg(dst));
                        track(&mut reg_values, &dstv, PVal::E(holder.to_string()));
                        lines.push(PseudoLine {
                            indent,
                            text: format!("{} = {};", fmt_var(&dstv), holder),
                            kind: LineKind::Assignment,
                            source_addr: Some(*addr),
                        });
                    }
                    cse_invalidate(&mut cse_map, dst);
                    continue;
                }
        let rendered = render_op(
            op,
            *addr,
            func_lookup,
            &mut reg_values,
            is64,
            hints,
            &mut push_args,
        );
        if !block_has_jcc
            && let Some(w) = written_reg(op) {
                cse_invalidate(&mut cse_map, w);
            }
        if let Some((text, kind)) = rendered {
            lines.push(PseudoLine {
                indent,
                text,
                kind,
                source_addr: Some(*addr),
            });
            if let Some((key, oregs)) = ck
                && let Some(dst) = written_reg(op) {
                    cse_map.insert(key, (dst, oregs));
                }
        }
    }

    let ov_after = EXPR_OVERFLOWS.with(|c| c.get());
    if ov_after != ov_before {
        eprintln!(
            "[decompiler] block {:#x}: {} tracked value(s) exceeded {} bytes (expression blow-up)",
            block.start,
            ov_after.wrapping_sub(ov_before),
            MAX_TRACKED_EXPR
        );
    }
    let emitted: usize = lines[lines_before..].iter().map(|l| l.text.len() + 8).sum();
    hints.out_bytes.set(hints.out_bytes.get() + emitted);
    let succs = &block.successors;
    if let Some(&last_addr) = addrs.last()
        && let Some(di) = imap_get(imap, last_addr) {
            let m = di.mnemonic;
            let has_true = succs.iter().any(|e| e.kind == EdgeKind::BranchTrue);
            if m.starts_with('j') && m != "jmp" && m != "jecxz" && !has_true {
                lines.push(PseudoLine {
                    indent,
                    text: format!(
                        "// WARNING: branch '{} {}' target not decoded here - guard/branch is MISSING from this render; check disasm",
                        m, di.operands
                    ),
                    kind: LineKind::Comment,
                    source_addr: Some(last_addr),
                });
            }
        }
    if succs.is_empty() {
        if let Some((last_addr, last_op)) = ops.last()
            && let POp::Branch { target } = &**last_op
        {
            let target = *target;
            let args = take_call_args(&reg_values, is64, &mut push_args);
            let (text, kind) = match func_lookup.get(&target) {
                Some(name) if args.is_empty() => {
                    (format!("return {}();  // tail call", name), LineKind::Return)
                }
                Some(name) => (
                    format!("return {}({});  // tail call", name, args.join(", ")),
                    LineKind::Return,
                ),
                None => (
                    format!(
                        "goto 0x{:x};  // tail call - target outside this function",
                        target
                    ),
                    LineKind::Branch,
                ),
            };
            lines.push(PseudoLine {
                indent,
                text,
                kind,
                source_addr: Some(*last_addr),
            });
        }
    } else if succs.len() == 1 {
        let edge = &succs[0];
        match edge.kind {
            EdgeKind::Jump => {
                if back_edges.contains_key(&edge.target) {
                } else if !visited.contains(&edge.target)
                    && cfg.blocks[edge.target].predecessors.len() == 1
                {
                    walk_block(ctx, edge.target, visited, lines, indent, depth + 1);
                } else {
                    lines.push(PseudoLine {
                        indent,
                        text: format!("goto LAB_{:X};", cfg.blocks[edge.target].start),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                }
            }
            _ => {
                if !visited.contains(&edge.target) {
                    walk_block(ctx, edge.target, visited, lines, indent, depth + 1);
                }
            }
        }
    } else {
        let true_edge = succs.iter().find(|e| e.kind == EdgeKind::BranchTrue);
        let false_edge = succs.iter().find(|e| e.kind == EdgeKind::BranchFalse);

        if let (Some(t), Some(f)) = (true_edge, false_edge) {
            let t_loops_back = back_edges.contains_key(&t.target);
            let f_loops_back = back_edges.contains_key(&f.target);

            let dw_close = if t_loops_back && dowhile.contains(&t.target) {
                Some((f.target, true))
            } else if f_loops_back && dowhile.contains(&f.target) {
                Some((t.target, false))
            } else {
                None
            };
            if let Some((exit, cond_repeats)) = dw_close {
                let consts = block_consts.get(block_id).cloned().unwrap_or_default();
                let cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
                let text = if cond_repeats {
                    format!("}} while ({});", cond)
                } else {
                    format!("}} while (!({}));", cond)
                };
                lines.push(PseudoLine {
                    indent: indent.saturating_sub(1),
                    text,
                    kind: LineKind::Branch,
                    source_addr: None,
                });
                if !visited.contains(&exit) {
                    walk_block(ctx, exit, visited, lines, indent, depth + 1);
                }
                return;
            }

            if t_loops_back || f_loops_back {
                let consts = block_consts.get(block_id).cloned().unwrap_or_default();
                let cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
                if f_loops_back {
                    lines.push(PseudoLine {
                        indent,
                        text: format!("if ({}) {{", cond),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&t.target) {
                        walk_block(ctx, t.target, visited, lines, indent + 1, depth + 1);
                    } else {
                        lines.push(PseudoLine {
                            indent: indent + 1,
                            text: format!("goto LAB_{:X};", cfg.blocks[t.target].start),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                    }
                    lines.push(PseudoLine {
                        indent,
                        text: "}".into(),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&f.target) {
                        walk_block(ctx, f.target, visited, lines, indent, depth + 1);
                    }
                } else if t_loops_back {
                    lines.push(PseudoLine {
                        indent,
                        text: format!("if (!({})) {{", cond),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&f.target) {
                        walk_block(ctx, f.target, visited, lines, indent + 1, depth + 1);
                    } else {
                        lines.push(PseudoLine {
                            indent: indent + 1,
                            text: format!("goto LAB_{:X};", cfg.blocks[f.target].start),
                            kind: LineKind::Branch,
                            source_addr: None,
                        });
                    }
                    lines.push(PseudoLine {
                        indent,
                        text: "}".into(),
                        kind: LineKind::Branch,
                        source_addr: None,
                    });
                    if !visited.contains(&t.target) {
                        walk_block(ctx, t.target, visited, lines, indent, depth + 1);
                    }
                }
                return;
            }

            let consts = block_consts.get(block_id).cloned().unwrap_or_default();
            let cond = recover_condition(cfg, bops, imap, block_id, &consts, Some(hints));
            lines.push(PseudoLine {
                indent,
                text: format!("if ({}) {{", cond),
                kind: LineKind::Branch,
                source_addr: None,
            });
            if !visited.contains(&t.target) {
                walk_block(ctx, t.target, visited, lines, indent + 1, depth + 1);
            } else {
                lines.push(PseudoLine {
                    indent: indent + 1,
                    text: format!("goto LAB_{:X};", cfg.blocks[t.target].start),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
            }
            lines.push(PseudoLine {
                indent,
                text: "} else {".into(),
                kind: LineKind::Branch,
                source_addr: None,
            });
            if !visited.contains(&f.target) {
                walk_block(ctx, f.target, visited, lines, indent + 1, depth + 1);
            } else {
                lines.push(PseudoLine {
                    indent: indent + 1,
                    text: format!("goto LAB_{:X};", cfg.blocks[f.target].start),
                    kind: LineKind::Branch,
                    source_addr: None,
                });
            }
            lines.push(PseudoLine {
                indent,
                text: "}".into(),
                kind: LineKind::Branch,
                source_addr: None,
            });
        }
    }

    if is_loop_header && !dowhile.contains(&block_id) {
        lines.push(PseudoLine {
            indent: indent.saturating_sub(1),
            text: "}".into(),
            kind: LineKind::Branch,
            source_addr: None,
        });
    }
}
