use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashSet as HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub struct DetectedFunction {
    pub entry: u64,
    pub end: u64,
    pub name: String,
    pub has_frame: bool,
    pub stack_size: i64,
    pub source: FuncSource,
    pub is_thunk: bool,
    pub thunk_target: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FuncSource {
    EntryPoint,
    SymbolTable,
    CallTarget,
    Prologue,
    AfterReturn,
    UnwindInfo,
    UserDefined,
}

pub fn detect_functions(
    insns: &[DisasmInstruction],
    entry_point: u64,
    symbols: &[crate::parser::Symbol],
) -> Vec<DetectedFunction> {
    detect_functions_impl(insns, entry_point, symbols, None)
}

pub fn detect_functions_impl(
    insns: &[DisasmInstruction],
    entry_point: u64,
    symbols: &[crate::parser::Symbol],
    cancel: Option<&AtomicBool>,
) -> Vec<DetectedFunction> {
    detect_functions_with_extra(insns, entry_point, symbols, &[], cancel)
}

pub fn detect_functions_with_extra(
    insns: &[DisasmInstruction],
    entry_point: u64,
    symbols: &[crate::parser::Symbol],
    extra: &[(u64, FuncSource)],
    cancel: Option<&AtomicBool>,
) -> Vec<DetectedFunction> {
    detect_functions_with_extra_opt(insns, entry_point, symbols, extra, cancel, true)
}

pub fn detect_functions_with_extra_opt(
    insns: &[DisasmInstruction],
    entry_point: u64,
    symbols: &[crate::parser::Symbol],
    extra: &[(u64, FuncSource)],
    cancel: Option<&AtomicBool>,
    assume_contiguous: bool,
) -> Vec<DetectedFunction> {
    let mut entries: Vec<(u64, FuncSource)> = Vec::new();
    let mut entry_set: HashSet<u64> = HashSet::default();

    let push_entry =
        |entries: &mut Vec<(u64, FuncSource)>, set: &mut HashSet<u64>, a: u64, src: FuncSource| {
            if set.insert(a) {
                entries.push((a, src));
            }
        };

    if entry_point != 0 {
        push_entry(
            &mut entries,
            &mut entry_set,
            entry_point,
            FuncSource::EntryPoint,
        );
    }

    for sym in symbols {
        if sym.is_function && sym.addr != 0 {
            push_entry(
                &mut entries,
                &mut entry_set,
                sym.addr,
                FuncSource::SymbolTable,
            );
        }
    }

    for (addr, src) in extra {
        if *addr != 0 {
            push_entry(&mut entries, &mut entry_set, *addr, src.clone());
        }
    }

    if insns.len() >= crate::util::parallel::PAR_INSNS {
        let ((call_targets, prologues), after_rets) = crate::util::parallel::install(|| {
            rayon::join(
                || {
                    rayon::join(
                        || {
                            use rayon::prelude::*;
                            insns
                                .par_iter()
                                .enumerate()
                                .filter(|(_, i)| i.mnemonic.starts_with("call"))
                                .filter_map(|(idx, i)| {
                                    let t = parse_addr_operand(&i.ops())?;
                                    let fall = insns.get(idx + 1).is_some_and(|n| n.address == t);
                                    if fall {
                                        None
                                    } else {
                                        Some(t)
                                    }
                                })
                                .collect::<Vec<u64>>()
                        },
                        || {
                            use rayon::prelude::*;
                            (0..insns.len())
                                .into_par_iter()
                                .filter(|&i| {
                                    matches_prologue(insns, i)
                                        && is_valid_subroutine_start(insns, i)
                                })
                                .map(|i| insns[i].address)
                                .collect::<Vec<u64>>()
                        },
                    )
                },
                || {
                    use rayon::prelude::*;
                    (0..insns.len().saturating_sub(1))
                        .into_par_iter()
                        .filter(|&i| {
                            let m = &insns[i].mnemonic;
                            (*m == "ret" || *m == "retn")
                                && after_return_is_function_start(insns, i + 1)
                        })
                        .map(|i| insns[i + 1].address)
                        .collect::<Vec<u64>>()
                },
            )
        });
        for t in call_targets {
            push_entry(&mut entries, &mut entry_set, t, FuncSource::CallTarget);
        }
        for a in prologues {
            if !entry_set.contains(&a) {
                push_entry(&mut entries, &mut entry_set, a, FuncSource::Prologue);
            }
        }
        for a in after_rets {
            if !entry_set.contains(&a) {
                push_entry(&mut entries, &mut entry_set, a, FuncSource::AfterReturn);
            }
        }
    } else {
        for (idx, insn) in insns.iter().enumerate() {
            if insn.mnemonic.starts_with("call")
                && let Some(target) = parse_addr_operand(&insn.ops()) {
                    let fall = insns.get(idx + 1).is_some_and(|n| n.address == target);
                    if !fall {
                        push_entry(&mut entries, &mut entry_set, target, FuncSource::CallTarget);
                    }
                }
        }

        for i in 0..insns.len() {
            let addr = insns[i].address;
            if entry_set.contains(&addr) {
                continue;
            }
            if matches_prologue(insns, i) && is_valid_subroutine_start(insns, i) {
                push_entry(&mut entries, &mut entry_set, addr, FuncSource::Prologue);
            }
        }

        for i in 0..insns.len().saturating_sub(1) {
            let m = insns[i].mnemonic;
            if m == "ret" || m == "retn" {
                let next_addr = insns[i + 1].address;
                if !entry_set.contains(&next_addr) && after_return_is_function_start(insns, i + 1) {

                    push_entry(
                        &mut entries,
                        &mut entry_set,
                        next_addr,
                        FuncSource::AfterReturn,
                    );
                }
            }
        }
    }

    entries.sort_by_key(|(a, _)| *a);

    let mut merged: Vec<(u64, FuncSource)> = Vec::with_capacity(entries.len());
    for (addr, src) in entries {
        let expanded = expand_entry_over_prologue(insns, addr);
        match expanded {
            Some(new_addr) if new_addr == addr => merged.push((addr, src)),
            Some(new_addr) => {
                let pos = merged.partition_point(|(p, _)| *p < new_addr);
                if pos >= merged.len() {
                    merged.push((new_addr, src));
                }
            }
            None => merged.push((addr, src)),
        }
    }
    let entries = merged;

    let sym_by_addr: rustc_hash::FxHashMap<u64, &str> = symbols
        .iter()
        .filter(|s| s.addr != 0)
        .map(|s| (s.addr, s.name.as_str()))
        .collect();
    let idx_of = |a: u64| -> Option<usize> {
        let i = insns.partition_point(|x| x.address < a);
        (i < insns.len() && insns[i].address == a).then_some(i)
    };
    let compute_one = |entry: u64,
                       src: &FuncSource,
                       next_entry: Option<u64>,
                       visited: &mut [u64],
                       stamp: &mut u64|
     -> Option<DetectedFunction> {
        let n = insns.len();
        let start_idx = idx_of(entry)?;
        let mut end = if assume_contiguous {
            next_entry.unwrap_or_else(|| {
                insns
                    .last()
                    .map(|x| x.address.saturating_add(x.bytes.len() as u64))
                    .unwrap_or(entry)
            })
        } else {
            insns
                .last()
                .map(|x| x.address.saturating_add(x.bytes.len() as u64))
                .unwrap_or(entry)
        };
        let span = insns
            .last()
            .map(|l| {
                l.address
                    .saturating_sub(insns.first().map(|f| f.address).unwrap_or(0))
            })
            .unwrap_or(0);
        let scaled = (span / 16).clamp(131_072, 8_388_608);
        let hard_cap = entry.saturating_add(scaled);
        let limit = end.min(hard_cap);
        let mut reachable_max: Option<u64> = None;
        let mut work = vec![start_idx];
        visited[start_idx] = *stamp;
        while let Some(idx) = work.pop() {
            if idx >= n {
                continue;
            }
            let insn = &insns[idx];
            if insn.address >= limit {
                continue;
            }
            let insn_end = insn.address.saturating_add(insn.bytes.len() as u64);
            reachable_max = Some(reachable_max.map_or(insn_end, |m: u64| m.max(insn_end)));
            if insn_end >= limit {
                continue;
            }
            let next_idx = idx + 1;
            let m = insn.mnemonic;
            if m == "ret" || m == "retn" {
                continue;
            } else if m == "jmp" {
                if let Some(t) = parse_addr_operand(&insn.ops())
                    && t >= entry && t < limit
                        && let Some(ti) = idx_of(t)
                            && visited[ti] != *stamp {
                                visited[ti] = *stamp;
                                work.push(ti);
                            }
            } else if m.starts_with('j') {
                if let Some(t) = parse_addr_operand(&insn.ops())
                    && t >= entry && t < limit
                        && let Some(ti) = idx_of(t)
                            && visited[ti] != *stamp {
                                visited[ti] = *stamp;
                                work.push(ti);
                            }
                if next_idx < n && insns[next_idx].address < limit && visited[next_idx] != *stamp {
                    visited[next_idx] = *stamp;
                    work.push(next_idx);
                }
            } else {
                if next_idx < n && insns[next_idx].address < limit && visited[next_idx] != *stamp {
                    visited[next_idx] = *stamp;
                    work.push(next_idx);
                }
            }
        }
        *stamp = stamp.wrapping_add(1).max(1);

        if let Some(m) = reachable_max
            && m < end {
                end = m;
            }

        if end <= entry {
            if let Some(insn) = insns.get(start_idx) {
                end = insn.address.saturating_add(insn.bytes.len() as u64);
            } else {
                end = entry;
            }
        }

        if *src == FuncSource::CallTarget
            && let Some(s) = idx_of(entry)
                && let Some(insn) = insns.get(s) {
                    let insn_end = insn.address.saturating_add(insn.bytes.len() as u64);
                    if insn.address == entry
                        && insn_end == end
                        && (insn.mnem() == "nop"
                            || insn.mnem() == "int3"
                            || insn.bytes.iter().all(|&b| b == 0x00))
                    {
                        return None;
                    }
                }

        let (has_frame, stack_size) = analyze_frame(insns, entry, end);
        let name = match src {
            FuncSource::EntryPoint => "entry".to_string(),
            FuncSource::SymbolTable => sym_by_addr
                .get(&entry)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("sub_{:X}", entry)),
            _ => format!("sub_{:X}", entry),
        };

        Some(DetectedFunction {
            entry,
            end,
            name,
            has_frame,
            stack_size,
            source: src.clone(),
            is_thunk: false,
            thunk_target: None,
        })
    };

    let mut functions = Vec::new();
    if entries.len() >= crate::util::parallel::PAR_FUNCS {
        use rayon::prelude::*;
        let indexed: Vec<(usize, &(u64, FuncSource))> = entries.iter().enumerate().collect();
        let mut parts: Vec<Vec<DetectedFunction>> = crate::util::parallel::install(|| {
            indexed
                .par_chunks(
                    (entries.len() + crate::util::parallel::workers() - 1)
                        / crate::util::parallel::workers().max(1),
                )
                .map(|chunk| {
                    let n = insns.len();
                    let mut visited = vec![0u64; n.max(1)];
                    let mut stamp: u64 = 1;
                    let mut local = Vec::with_capacity(chunk.len());
                    for (i, (entry, src)) in chunk {
                        if i % 256 == 0 && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                            return local;
                        }
                        let next_entry = entries.get(i + 1).map(|(a, _)| *a);
                        if let Some(f) =
                            compute_one(*entry, src, next_entry, &mut visited, &mut stamp)
                        {
                            local.push(f);
                        }
                    }
                    local
                })
                .collect()
        });
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Vec::new();
        }
        for mut p in parts.drain(..) {
            functions.append(&mut p);
        }
        functions.sort_by_key(|f| f.entry);
    } else {
        let n = insns.len();
        let mut visited = vec![0u64; n.max(1)];
        let mut stamp: u64 = 1;

        for (i, (entry, src)) in entries.iter().enumerate() {
            if i % 256 == 0 && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Vec::new();
            }
            let next_entry = entries.get(i + 1).map(|(a, _)| *a);
            if let Some(f) = compute_one(*entry, src, next_entry, &mut visited, &mut stamp) {
                functions.push(f);
            }
        }
    }

    functions
}

pub fn apply_noreturn_ends(
    functions: &mut [DetectedFunction],
    insns: &[DisasmInstruction],
    noreturn: &HashSet<u64>,
) {
    fn is_padding(x: &DisasmInstruction) -> bool {
        x.mnem() == "nop" || x.mnem() == "int3" || x.bytes.iter().all(|&b| b == 0x00)
    }
    for func in functions.iter_mut() {
        let start_idx = insns.partition_point(|x| x.address < func.entry);
        let end_idx = insns.partition_point(|x| x.address < func.end);
        if start_idx >= end_idx {
            continue;
        }
        let len = end_idx - start_idx;
        let mut suffix_pad = vec![true; len + 1];
        for k in (0..len).rev() {
            suffix_pad[k] = suffix_pad[k + 1] && is_padding(&insns[start_idx + k]);
        }
        let mut clip: Option<u64> = None;
        let mut i = start_idx;
        while i < end_idx {
            let insn = &insns[i];
            let is_nr = ((insn.mnem() == "call" || insn.mnem() == "jmp")
                && parse_addr_operand(&insn.ops()).is_some_and(|t| noreturn.contains(&t)))
                || (insn.mnem() == "int" && insn.ops().trim() == "0x29");
            if is_nr {
                let rel = i - start_idx;
                if suffix_pad[rel + 1] && clip.is_none() {
                    clip = Some(insn.address.saturating_add(insn.bytes.len() as u64));
                }
            }
            i += 1;
        }
        if let Some(c) = clip
            && c < func.end {
                func.end = c;
            }
    }
}

fn is_valid_subroutine_start(insns: &[DisasmInstruction], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let Some(prev) = insns.get(idx.wrapping_sub(1)) else {
        return true;
    };
    if prev.address.saturating_add(prev.bytes.len() as u64) != insns[idx].address {
        let prev_end = prev.address.saturating_add(prev.bytes.len() as u64);
        let hole = insns[idx].address.saturating_sub(prev_end);
        return hole < 15;
    }
    let m = prev.mnemonic;
    if m == "ret"
        || m == "retn"
        || m == "retf"
        || m == "jmp"
        || (m.starts_with('j') && m != "jmp")
        || matches!(m, "nop" | "int3" | "ud2" | "hlt")
    {
        return true;
    }
    false
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

fn eq_nospace_ci(ops: &str, pat: &str) -> bool {
    let mut a = ops.bytes().filter(|&b| b != b' ');
    let mut b = pat.bytes();
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) => {
                if !x.eq_ignore_ascii_case(&y) {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn starts_with_trim_ci(ops: &str, pat: &str) -> bool {
    let t = ops.trim_start();
    t.len() >= pat.len()
        && t.bytes()
            .take(pat.len())
            .zip(pat.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

fn matches_prologue(insns: &[DisasmInstruction], idx: usize) -> bool {
    if idx >= insns.len() {
        return false;
    }

    if insns[idx].mnem() == "push" {
        let op_owned = insns[idx].ops();
        let op = op_owned.trim();
        if eq_ci(op, "rbp") || eq_ci(op, "ebp") {
            if let Some(next) = insns.get(idx + 1) {
                if next.mnem() == "mov"
                    && (eq_nospace_ci(&next.ops(), "rbp,rsp")
                        || eq_nospace_ci(&next.ops(), "ebp,esp"))
                {
                    return true;
                }
                if next.mnem() == "push"
                    || (next.mnem() == "sub"
                        && (starts_with_trim_ci(&next.ops(), "rsp,")
                            || starts_with_trim_ci(&next.ops(), "esp,")))
                {
                    return true;
                }
            }
            return false;
        }
    }

    if insns[idx].mnem() == "sub"
        && (starts_with_trim_ci(&insns[idx].ops(), "rsp,")
            || starts_with_trim_ci(&insns[idx].ops(), "esp,"))
    {
        if let Some(next) = insns.get(idx + 1)
            && matches!(
                next.mnemonic,
                "push" | "mov" | "lea" | "sub" | "endbr64" | "endbr32"
            ) {
                return true;
            }
        return false;
    }

    if insns[idx].mnem() == "push" {
        let r_owned = insns[idx].ops();
        let r = r_owned.trim();
        if [
            "rbx", "rdi", "rsi", "r12", "r13", "r14", "r15", "ebp", "edi", "esi", "ebx",
        ]
        .iter()
        .any(|cand| eq_ci(r, cand))
            && let Some(next) = insns.get(idx + 1)
                && (next.mnem() == "push" || (next.mnem() == "sub" && next.ops().contains("rsp"))) {
                    return true;
                }
    }

    if insns[idx].mnem() == "mov" {
        let ops_owned = insns[idx].ops();
        let ops = ops_owned.trim_start();
        if (starts_with_trim_ci(ops, "qword ptr [rsp") || starts_with_trim_ci(ops, "[rsp"))
            && let Some(next) = insns.get(idx + 1)
                && next.mnem() == "mov"
                    && (starts_with_trim_ci(&next.ops(), "qword ptr [rsp")
                        || starts_with_trim_ci(&next.ops(), "[rsp"))
                {
                    return true;
                }
    }

    if insns[idx].mnem() == "endbr64" || insns[idx].mnem() == "endbr32" {
        return true;
    }

    false
}

fn is_32bit_reg_name(op: &str) -> bool {
    matches!(
        op,
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "r8d"
            | "r9d"
            | "r10d"
            | "r11d"
            | "r12d"
            | "r13d"
            | "r14d"
            | "r15d"
    )
}

fn expand_entry_over_prologue(insns: &[DisasmInstruction], entry: u64) -> Option<u64> {
    let idx = insns.partition_point(|x| x.address < entry);
    if idx >= insns.len() || insns[idx].address != entry {
        return None;
    }
    fn prologue_step(p: &DisasmInstruction) -> Option<bool> {
        let m = p.mnemonic;
        if m == "push" {
            let op_owned = p.ops();
            let op = op_owned.trim();
            if eq_ci(op, "ebp") || eq_ci(op, "rbp") {
                return Some(true);
            }
            return None;
        }
        if m == "sub" {
            if starts_with_trim_ci(&p.ops(), "rsp,") || starts_with_trim_ci(&p.ops(), "esp,") {
                return Some(true);
            }
            return None;
        }
        if m == "endbr64" || m == "endbr32" {
            return Some(true);
        }
        if m == "mov" {
            if eq_nospace_ci(&p.ops(), "rbp,rsp") || eq_nospace_ci(&p.ops(), "ebp,esp") {
                return Some(false);
            }
            return None;
        }
        None
    }
    let mut j = idx;
    let mut lowest = entry;
    let mut budget = 32u64;
    let mut steps = 0usize;
    let mut prologue_head: Option<u64> = None;
    while j > 0 && steps < 8 {
        let p = &insns[j - 1];
        if p.address.saturating_add(p.bytes.len() as u64) != lowest {
            break;
        }
        let m = p.mnemonic;
        if m == "call" {
            lowest = p.address;
            budget = budget.saturating_sub(p.bytes.len() as u64);
            j -= 1;
            steps += 1;
            if budget == 0 {
                break;
            }
            continue;
        }
        match prologue_step(p) {
            Some(is_head) => {
                if is_head {
                    prologue_head = Some(p.address);
                }
                lowest = p.address;
                budget = budget.saturating_sub(p.bytes.len() as u64);
                j -= 1;
                steps += 1;
                if budget == 0 {
                    break;
                }
            }
            None => break,
        }
    }
    prologue_head
}

fn after_return_is_function_start(insns: &[DisasmInstruction], idx: usize) -> bool {
    is_valid_subroutine_start(insns, idx) && matches_prologue(insns, idx)
}

fn parse_addr_operand(operands: &str) -> Option<u64> {
    let s = operands.trim();
    if s.is_empty() {
        return None;
    }
    let first = s.split(',').next().unwrap_or(s).trim();
    let tok: &str = first
        .split([' ', '\t', '<', ';', '('])
        .next()
        .unwrap_or(first)
        .trim();
    let tok = tok
        .trim()
        .trim_end_matches(',')
        .trim_end_matches(')')
        .trim();
    if tok.is_empty() || tok.starts_with('[') || tok.starts_with('-') || tok.starts_with('+') {
        return None;
    }
    if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        let hex: &str = hex
            .split(|c: char| !c.is_ascii_hexdigit())
            .next()
            .unwrap_or(hex);
        if hex.is_empty() {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if tok.len() > 1 && (tok.ends_with('h') || tok.ends_with('H')) {
        let hex = &tok[..tok.len() - 1];
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            && let Ok(v) = u64::from_str_radix(hex, 16) {
                return Some(v);
            }
    }
    if let Ok(v) = tok.parse::<u64>() {
        return Some(v);
    }
    u64::from_str_radix(tok, 16).ok()
}

fn analyze_frame(insns: &[DisasmInstruction], entry: u64, end: u64) -> (bool, i64) {
    let mut has_frame = false;
    let mut stack_size = 0i64;
    let mut pushed = 0i64;

    let start = insns.partition_point(|x| x.address < entry);
    for insn in insns.iter().skip(start) {
        if insn.address >= end {
            break;
        }

        if insn.mnem() == "push" {
            let op = insn.ops().trim().to_lowercase();
            if op == "rbp" || op == "ebp" {
                has_frame = true;
            }
            pushed += if is_32bit_reg_name(&op) { 4 } else { 8 };
        }
        if insn.mnem() == "pop" {
            let op = insn.ops().trim().to_lowercase();
            pushed -= if is_32bit_reg_name(&op) { 4 } else { 8 };
        }
        if insn.mnem() == "sub" {
            let ops = insn.ops().replace(" ", "");
            if let Some(rest) = ops.strip_prefix("rsp,") {
                let val: i64 = parse_imm(rest);
                if val > 0 && val < 0x100000 {
                    stack_size += val;
                    has_frame = true;
                }
            } else if let Some(rest) = ops.strip_prefix("esp,") {
                let val: i64 = parse_imm(rest);
                if val > 0 && val < 0x100000 {
                    stack_size += val;
                    has_frame = true;
                }
            }
        }
        if insn.mnem() == "add" {
            let ops = insn.ops().replace(" ", "");
            if let Some(rest) = ops.strip_prefix("rsp,") {
                let val: i64 = parse_imm(rest);
                if val > 0 {
                    stack_size -= val;
                }
            }
        }
    }

    if stack_size < 0 {
        stack_size = 0;
    }
    (has_frame, stack_size + pushed.max(0))
}

fn parse_imm(s: &str) -> i64 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        return i64::from_str_radix(h, 16).unwrap_or(0);
    }
    if let Some(h) = s.strip_prefix("-0x") {
        return -(i64::from_str_radix(h, 16).unwrap_or(0));
    }
    s.parse().unwrap_or(0)
}
