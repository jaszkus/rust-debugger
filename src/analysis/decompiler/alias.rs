























use super::{LineKind, PseudoLine};
use crate::analysis::operands::canonical_reg;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

pub(crate) fn propagate_aliases(lines: &mut Vec<PseudoLine>) {
    let mut aliases: HashMap<String, String> = HashMap::default();
    let mut scopes: Vec<Option<HashMap<String, String>>> = Vec::new();
    let mut candidates: Vec<(usize, String)> = Vec::new();
    let declared: HashSet<String> = lines
        .iter()
        .filter(|l| l.kind == LineKind::Declaration)
        .filter_map(|l| {
            l.text
                .split("//")
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .map(|w| w.trim_end_matches(';').to_string())
        })
        .collect();

    for (i, line) in lines.iter_mut().enumerate() {
        let kind = line.kind;
        let text = line.text.clone();
        let t = text.trim_start();

        if kind == LineKind::Comment || t.is_empty() {
            continue;
        }

        if t.starts_with("} else") {
            let restore = scopes.pop().flatten();
            aliases = restore.unwrap_or_default();
            scopes.push(None);
            continue;
        }
        if t.starts_with('}') {
            scopes.pop();
            aliases.clear();
            continue;
        }
        if t.ends_with('{') || t.contains(" {") {
            if t.starts_with("if (") {
                line.text = substitute_condition(&text, &aliases);
                scopes.push(Some(aliases.clone()));
            } else {
                
                aliases.clear();
                scopes.push(None);
            }
            continue;
        }
        if kind == LineKind::Label
            || t.starts_with("break;")
            || t.starts_with("continue;")
            || t.starts_with("goto ")
        {
            aliases.clear();
            continue;
        }
        if kind == LineKind::Return {
            line.text = substitute_tokens(&text, &aliases);
            aliases.clear();
            continue;
        }
        if kind == LineKind::Call {
            line.text = substitute_tokens(&text, &aliases);
            aliases.clear();
            continue;
        }
        if kind == LineKind::Declaration {
            continue;
        }

        let new_text = substitute_line(&text, &aliases);
        line.text = new_text.clone();

        if let Some((lhs, rhs)) = simple_assignment(&new_text) {
            aliases.remove(&lhs);
            aliases.retain(|k, v| k != &lhs && !tokens_contain(v, &lhs));
            if is_removable(&lhs) {
                candidates.push((i, lhs.clone()));
            }
            if !declared.contains(&lhs) || !is_register(&rhs) {
                aliases.insert(lhs, rhs);
            }
        } else if let Some(lhs) = assignment_lhs(&new_text) {
            aliases.remove(&lhs);
            aliases.retain(|k, v| k != &lhs && !tokens_contain(v, &lhs));
        }
    }

    let mut remove: HashSet<usize> = HashSet::default();
    for (idx, name) in candidates {
        if !used_as_read(lines, &name, idx) {
            remove.insert(idx);
        }
    }
    if !remove.is_empty() {
        let mut idx = 0;
        lines.retain(|_| {
            let keep = !remove.contains(&idx);
            idx += 1;
            keep
        });
    }
    drop_unused_declarations(lines);
}



fn callee_saved(name: &str) -> bool {
    matches!(
        canonical_reg(name),
        "rbx" | "rbp" | "r12" | "r13" | "r14" | "r15"
    )
}

pub(crate) fn drop_callee_saved_bookkeeping(lines: &mut Vec<PseudoLine>) {
    let mut saves: HashMap<String, (&'static str, usize)> = HashMap::default();
    let mut restores: HashMap<String, Vec<usize>> = HashMap::default();
    for (i, line) in lines.iter().enumerate() {
        let Some((lhs, rhs)) = assignment_parts(&line.text) else {
            continue;
        };
        if is_register(rhs) && callee_saved(rhs) && is_identifier(lhs) {
            saves.entry(lhs.to_string()).or_insert((canonical_reg(rhs), i));
        }
        if is_register(lhs) && callee_saved(lhs) && is_identifier(rhs) {
            restores.entry(rhs.to_string()).or_default().push(i);
        }
    }
    let mut remove: HashSet<usize> = HashSet::default();
    for (local, (_, save_idx)) in saves {
        if !local.starts_with("local_") && !local.starts_with("stk_") {
            continue;
        }
        let Some(restore_idxs) = restores.get(&local) else {
            continue;
        };
        let mut ok = true;
        let mut decl_idx = None;
        for (i, line) in lines.iter().enumerate() {
            if i == save_idx || restore_idxs.contains(&i) {
                continue;
            }
            if line.kind == LineKind::Declaration
                && declared_name(&line.text) == Some(local.as_str())
            {
                decl_idx = Some(i);
                continue;
            }
            if tokens_contain(line.text.split("//").next().unwrap_or(""), &local) {
                ok = false;
                break;
            }
        }
        if ok {
            remove.insert(save_idx);
            remove.extend(restore_idxs.iter().copied());
            if let Some(i) = decl_idx {
                remove.insert(i);
            }
        }
    }
    if !remove.is_empty() {
        let mut i = 0;
        lines.retain(|_| {
            let keep = !remove.contains(&i);
            i += 1;
            keep
        });
    }
}

pub(crate) fn inline_single_assignment_registers(lines: &mut Vec<PseudoLine>) {
    let mut writes: HashMap<&'static str, Vec<(usize, String)>> = HashMap::default();
    for (i, line) in lines.iter().enumerate() {
        let Some((lhs, rhs)) = assignment_parts(&line.text) else {
            continue;
        };
        if is_register(lhs) {
            writes
                .entry(canonical_reg(lhs))
                .or_default()
                .push((i, rhs.trim().to_string()));
        }
    }
    let mut candidates: Vec<(&'static str, usize, String)> = Vec::new();
    for (reg, list) in writes {
        if list.len() != 1 || matches!(reg, "rsp" | "rbp") || !callee_saved(reg) {
            continue;
        }
        let (idx, rhs) = &list[0];
        if !(is_identifier(rhs) || is_number(rhs)) || rhs == reg {
            continue;
        }
        if lines[..*idx].iter().any(|l| {
            l.kind != LineKind::Comment
                && l.kind != LineKind::Declaration
                && tokens_contain(l.text.split("//").next().unwrap_or(""), reg)
        }) {
            continue;
        }
        candidates.push((reg, *idx, rhs.clone()));
    }
    if candidates.is_empty() {
        return;
    }
    let mut aliases: HashMap<String, String> = HashMap::default();
    let mut assignments: HashSet<usize> = HashSet::default();
    for (reg, idx, rhs) in &candidates {
        aliases.insert((*reg).to_string(), rhs.clone());
        assignments.insert(*idx);
    }
    for (i, line) in lines.iter_mut().enumerate() {
        if assignments.contains(&i) {
            continue;
        }
        line.text = substitute_tokens(&line.text, &aliases);
    }
    let mut i = 0;
    lines.retain(|_| {
        let keep = !assignments.contains(&i);
        i += 1;
        keep
    });
}

fn register_width(name: &str) -> u32 {
    if name.starts_with("xmm") {
        return 16;
    }
    if name.starts_with("ymm") {
        return 32;
    }
    if name.starts_with("zmm") {
        return 64;
    }
    if matches!(
        name,
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp"
    ) || (name.starts_with('r')
        && name[1..].chars().all(|c| c.is_ascii_digit())
        && name.len() <= 3)
    {
        return 8;
    }
    if matches!(
        name,
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp"
    ) || (name.starts_with('r')
        && name.ends_with('d')
        && name[1..name.len() - 1].chars().all(|c| c.is_ascii_digit()))
    {
        return 4;
    }
    if matches!(
        name,
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp"
    ) || (name.starts_with('r')
        && name.ends_with('w')
        && name[1..name.len() - 1].chars().all(|c| c.is_ascii_digit()))
    {
        return 2;
    }
    1
}

fn cast_for_width(width: u32) -> &'static str {
    match width {
        1 => "byte",
        2 => "ushort",
        4 => "uint",
        _ => "ulonglong",
    }
}

pub(crate) fn name_remaining_registers(lines: &mut Vec<PseudoLine>) {
    let mut max_width: HashMap<&'static str, u32> = HashMap::default();
    let mut first_write: HashMap<&'static str, bool> = HashMap::default();
    let mut tokens: HashMap<String, (&'static str, u32)> = HashMap::default();
    let mut order: Vec<&'static str> = Vec::new();
    let mut existing: HashSet<String> = HashSet::default();
    for line in lines.iter() {
        let code = line.text.split("//").next().unwrap_or("");
        let assignment = assignment_parts(code);
        let lhs_reg = assignment
            .map(|(lhs, _)| lhs)
            .filter(|lhs| is_register(lhs))
            .map(canonical_reg);
        let mut rhs_reads: HashSet<&'static str> = HashSet::default();
        if let Some((_, rhs)) = assignment {
            for_each_ident(rhs, |word| {
                if is_register(word) {
                    rhs_reads.insert(canonical_reg(word));
                }
            });
        }
        for_each_ident(code, |word| {
            existing.insert(word.to_string());
            if !is_register(word) {
                return;
            }
            let reg = canonical_reg(word);
            if matches!(reg, "rip" | "rsp" | "rbp") {
                return;
            }
            if !max_width.contains_key(reg) {
                order.push(reg);
                first_write.insert(reg, lhs_reg == Some(reg) && !rhs_reads.contains(reg));
            }
            let width = register_width(word);
            max_width
                .entry(reg)
                .and_modify(|w| *w = (*w).max(width))
                .or_insert(width);
            tokens.insert(word.to_string(), (reg, width));
        });
    }
    if order.is_empty() {
        return;
    }
    let mut names: HashMap<&'static str, String> = HashMap::default();
    let mut decls: Vec<(String, u32, bool)> = Vec::new();
    let mut aliases: HashMap<String, String> = HashMap::default();
    let (mut ints, mut floats) = (0u32, 0u32);
    for reg in order {
        let width = max_width.get(reg).copied().unwrap_or(8);
        let float = width >= 16;
        let incoming = !first_write.get(reg).copied().unwrap_or(true);
        let base = if incoming {
            format!("in_{}", reg.to_ascii_uppercase())
        } else if float {
            loop {
                floats += 1;
                let name = format!("fVar{floats}");
                if !existing.contains(&name) {
                    break name;
                }
            }
        } else {
            loop {
                ints += 1;
                let name = format!("uVar{ints}");
                if !existing.contains(&name) {
                    break name;
                }
            }
        };
        if !incoming {
            decls.push((base.clone(), width, float));
        }
        names.insert(reg, base);
    }
    for (word, (reg, width)) in tokens {
        let Some(base) = names.get(reg) else {
            continue;
        };
        if width >= 16 || width == max_width.get(reg).copied().unwrap_or(width) {
            aliases.insert(word.clone(), base.clone());
        } else if word == "ah" || word == "bh" || word == "ch" || word == "dh" {
            aliases.insert(word.clone(), format!("(byte)({} >> 8)", base));
        } else {
            aliases.insert(
                word.clone(),
                format!("({}){}", cast_for_width(width), base),
            );
        }
    }
    for line in lines.iter_mut() {
        line.text = substitute_tokens(&line.text, &aliases);
    }
    let mut at = lines
        .iter()
        .position(|l| l.kind == LineKind::OpenBrace)
        .map(|i| i + 1)
        .unwrap_or(0);
    while at < lines.len() && lines[at].kind == LineKind::Declaration {
        at += 1;
    }
    for (name, width, float) in decls {
        let ty = if float {
            "float"
        } else {
            match width {
                1 => "byte",
                2 => "ushort",
                4 => "uint",
                _ => "undefined8",
            }
        };
        lines.insert(
            at,
            PseudoLine {
                indent: 1,
                text: format!("{} {};", ty, name),
                kind: LineKind::Declaration,
                source_addr: None,
            },
        );
        at += 1;
    }
}

pub(crate) fn drop_self_assignments(lines: &mut Vec<PseudoLine>) {
    lines.retain(|line| {
        let t = line.text.split("//").next().unwrap_or("").trim();
        let Some((lhs, rhs)) = t.strip_suffix(';').and_then(|t| t.split_once(" = ")) else {
            return true;
        };
        lhs.trim() != rhs.trim()
    });
}








pub(crate) fn drop_dead_register_assignments(lines: &mut Vec<PseudoLine>) {
    let mut remove: HashSet<usize> = HashSet::default();
    for (i, line) in lines.iter().enumerate() {
        let Some((lhs, _)) = assignment_parts(&line.text) else {
            continue;
        };
        if !is_register(lhs) {
            continue;
        }
        let reg = canonical_reg(lhs);
        let mut dead = false;
        'scan: for next in &lines[i + 1..] {
            let code = next.text.split("//").next().unwrap_or("");
            let t = code.trim_start();
            if next.kind == LineKind::Call || next.kind == LineKind::Label {
                break 'scan;
            }
            if code.trim().is_empty() || next.kind == LineKind::Comment {
                continue;
            }
            if next.kind == LineKind::Declaration {
                continue;
            }
            if t.starts_with('{')
                || t.starts_with('}')
                || t.starts_with("else")
                || t.starts_with("do {")
                || t.starts_with("while (")
                || t.starts_with("for (")
                || t.starts_with("if (")
                || t.starts_with("switch (")
                || t.starts_with("break;")
                || t.starts_with("continue;")
                || t.starts_with("goto ")
            {
                break 'scan;
            }
            if next.kind == LineKind::Return {
                
                
                let val = t
                    .strip_prefix("return")
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches(';')
                    .trim();
                if val.is_empty() {
                    
                    
                    break 'scan;
                } else {
                    dead = !tokens_contain_reg(val, reg);
                }
                break 'scan;
            }
            if line_reads_register(code, reg) {
                break 'scan;
            }
            if let Some((w, _)) = assignment_parts(code)
                && is_register(w)
                && canonical_reg(w) == reg
            {
                dead = true;
                break 'scan;
            }
        }
        if dead {
            remove.insert(i);
        }
    }
    if !remove.is_empty() {
        let mut idx = 0;
        lines.retain(|_| {
            let keep = !remove.contains(&idx);
            idx += 1;
            keep
        });
    }
}










pub(crate) fn cse_repeated_expressions(lines: &mut [PseudoLine]) {
    let mut exprs: HashMap<String, String> = HashMap::default();
    for line in lines.iter_mut() {
        let text = line.text.clone();
        let t = text.trim_start();
        if line.kind == LineKind::Comment || t.is_empty() {
            continue;
        }
        if line.kind == LineKind::Label
            || line.kind == LineKind::Call
            || line.kind == LineKind::Return
            || t.starts_with('{')
            || t.starts_with('}')
            || t.starts_with("else")
            || t.starts_with("if (")
            || t.starts_with("while (")
            || t.starts_with("for (")
            || t.starts_with("do {")
            || t.starts_with("switch (")
            || t.starts_with("break;")
            || t.starts_with("continue;")
            || t.starts_with("goto ")
        {
            exprs.clear();
            continue;
        }
        if line.kind == LineKind::Declaration {
            continue;
        }
        let Some((lhs, rhs)) = assignment_parts(&text) else {
            continue;
        };
        if lhs.starts_with("*(") {
            
            
            if let Some(holder) = exprs.get(rhs) {
                line.text = format!("{} = {};", lhs, holder);
            }
            exprs.clear();
            continue;
        }
        if !is_identifier(lhs) {
            continue;
        }
        let mut new_rhs = rhs.to_string();
        if let Some(holder) = exprs.get(rhs)
            && holder != lhs
        {
            new_rhs = holder.clone();
            line.text = format!("{} = {};", lhs, new_rhs);
        }
        exprs.retain(|expr, holder| holder != lhs && !tokens_contain(expr, lhs));
        if is_cse_expr(&new_rhs) {
            exprs.insert(new_rhs, lhs.to_string());
        }
    }
}

fn is_cse_expr(rhs: &str) -> bool {
    !rhs.is_empty()
        && !is_identifier(rhs)
        && !is_number(rhs)
        && !rhs.contains(" = ")
}












pub(crate) fn reuse_assigned_subexpressions(lines: &mut [PseudoLine]) {
    for _ in 0..4 {
        let mut changed = false;
        for i in 0..lines.len() {
            if lines[i].kind == LineKind::Comment || lines[i].kind == LineKind::Declaration {
                continue;
            }
            let Some((lhs, rhs)) = assignment_parts(&lines[i].text) else {
                continue;
            };
            if !is_identifier(lhs) || !is_cse_expr(rhs) || tokens_contain(rhs, lhs) {
                continue;
            }
            let Some(j) = (i + 1..lines.len()).find(|&j| !lines[j].text.trim().is_empty()) else {
                continue;
            };
            if j != i + 1 && lines[i + 1..j].iter().any(|l| l.kind != LineKind::Comment) {
                continue;
            }
            let next = lines[j].kind;
            if matches!(
                next,
                LineKind::Label
                    | LineKind::CloseBrace
                    | LineKind::Declaration
                    | LineKind::Return
                    | LineKind::Call
            ) {
                continue;
            }
            let text = lines[j].text.clone();
            let (code, comment) = match text.split_once("//") {
                Some((c, cm)) => (c, Some(cm)),
                None => (text.as_str(), None),
            };
            let (lhs_part, target) = match code.split_once(" = ") {
                Some((l, r)) => (Some(l), r.trim()),
                None => (None, code.trim()),
            };
            if target.is_empty() || !target.contains(rhs) || target == rhs {
                continue;
            }
            if lhs_part.is_some_and(|l| l.trim() == lhs) {
                continue;
            }
            let replaced = replace_expr(target, rhs, lhs);
            if replaced == target {
                continue;
            }
            let mut out = String::new();
            if let Some(l) = lhs_part {
                out.push_str(l);
                out.push_str(" = ");
            }
            out.push_str(&replaced);
            if let Some(cm) = comment {
                out.push_str("  //");
                out.push_str(cm);
            }
            if !out.ends_with(';') && code.trim_end().ends_with(';') {
                out.push(';');
            }
            if out != lines[j].text {
                lines[j].text = out;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn replace_expr(text: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    while let Some(rel) = text[pos..].find(from) {
        let at = pos + rel;
        let before = text[..at].chars().last();
        let after = text[at + from.len()..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        if boundary(before) && boundary(after) {
            out.push_str(&text[pos..at]);
            out.push_str(to);
            pos = at + from.len();
        } else {
            out.push_str(&text[pos..=at]);
            pos = at + 1;
        }
    }
    out.push_str(&text[pos..]);
    out
}











pub(crate) fn inline_single_use_temps(lines: &mut Vec<PseudoLine>) {
    for _ in 0..8 {
        if !inline_temps_pass(lines) {
            break;
        }
    }
}

fn inline_temps_pass(lines: &mut Vec<PseudoLine>) -> bool {
    let mut assign: HashMap<String, (usize, String)> = HashMap::default();
    let mut dup: HashSet<String> = HashSet::default();
    let mut reads: HashMap<String, usize> = HashMap::default();

    for (i, line) in lines.iter().enumerate() {
        let code = line.text.split("//").next().unwrap_or("");
        if let Some((lhs, rhs)) = assignment_parts(&line.text) {
            if is_inlinable(lhs)
                && assign
                    .insert(lhs.to_string(), (i, rhs.to_string()))
                    .is_some()
            {
                dup.insert(lhs.to_string());
            }
            for_each_ident(rhs, |w| {
                if is_inlinable(w) {
                    *reads.entry(w.to_string()).or_insert(0) += 1;
                }
            });
        } else {
            for_each_ident(code, |w| {
                if is_inlinable(w) {
                    *reads.entry(w.to_string()).or_insert(0) += 1;
                }
            });
        }
    }

    let mut remove: HashSet<usize> = HashSet::default();
    let mut replace: Vec<(usize, String, String)> = Vec::new();
    let mut removed: HashSet<usize> = HashSet::default();

    
    
    let mut order: Vec<(&String, &(usize, String))> = assign.iter().collect();
    order.sort_by_key(|(_, (idx, _))| std::cmp::Reverse(*idx));

    for (tmp, (idx, rhs)) in order {
        if dup.contains(tmp) || rhs.contains(" = ") {
            continue;
        }
        match reads.get(tmp).copied().unwrap_or(0) {
            0 => {
                if tmp.starts_with("tmp_") {
                    remove.insert(*idx);
                    removed.insert(*idx);
                }
            }
            1 => {
                let Some(j) = (*idx + 1..lines.len()).find(|&j| !lines[j].text.trim().is_empty()) else {
                    continue;
                };
                if j != idx + 1 || removed.contains(&j) {
                    continue;
                }
                let next = &lines[j];
                let t = next.text.trim_start();
                
                
                if t.starts_with('{')
                    || t.starts_with('}')
                    || t.starts_with("else")
                    || t.starts_with("while (")
                    || t.starts_with("for (")
                    || t.starts_with("do {")
                    || t.starts_with("switch (")
                    || t.starts_with("break;")
                    || t.starts_with("continue;")
                    || t.starts_with("goto ")
                {
                    continue;
                }
                if line_writes(&next.text, tmp) || ident_count(&next.text, tmp) != 1 {
                    continue;
                }
                if ident_preceded_by_amp(&next.text, tmp) {
                    continue;
                }
                let replacement = if rhs_needs_parens(rhs) {
                    format!("({})", rhs)
                } else {
                    rhs.clone()
                };
                replace.push((j, tmp.clone(), replacement));
                removed.insert(*idx);
            }
            _ => {}
        }
    }

    for (j, tmp, replacement) in &replace {
        if let Some(line) = lines.get_mut(*j) {
            line.text = replace_ident_once(&line.text, tmp, replacement);
        }
    }
    if remove.is_empty() && replace.is_empty() {
        return false;
    }
    if !remove.is_empty() {
        let mut idx = 0;
        lines.retain(|_| {
            let keep = !remove.contains(&idx);
            idx += 1;
            keep
        });
    }
    true
}

fn line_writes(text: &str, name: &str) -> bool {
    assignment_parts(text).is_some_and(|(lhs, _)| lhs == name)
}

fn is_inlinable(name: &str) -> bool {
    
    
    name.starts_with("tmp_")
}

fn ident_count(text: &str, name: &str) -> usize {
    let mut count = 0;
    for_each_ident(text.split("//").next().unwrap_or(text), |w| {
        if w == name {
            count += 1;
        }
    });
    count
}

fn ident_preceded_by_amp(text: &str, name: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if word == name {
                let prev = chars[..start].iter().rev().find(|c| !c.is_whitespace());
                return prev == Some(&'&');
            }
            continue;
        }
        i += 1;
    }
    false
}

fn replace_ident_once(text: &str, name: &str, replacement: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if word == name {
                out.push_str(replacement);
                out.extend(chars[i..].iter());
                return out;
            }
            out.push_str(&word);
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn rhs_needs_parens(rhs: &str) -> bool {
    rhs.starts_with('*') || rhs.chars().any(|c| c.is_whitespace())
}

fn assignment_parts(text: &str) -> Option<(&str, &str)> {
    let code = text.split("//").next().unwrap_or(text).trim();
    let t = code.strip_suffix(';')?;
    let (lhs, rhs) = t.split_once(" = ")?;
    Some((lhs.trim(), rhs.trim()))
}

fn is_register(name: &str) -> bool {
    let c = canonical_reg(name);
    matches!(
        c,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "rip"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
    ) || ["xmm", "ymm", "zmm", "st", "mm"].iter().any(|p| {
        c.strip_prefix(p)
            .is_some_and(|n| !n.is_empty() && n.chars().all(|ch| ch.is_ascii_digit()))
    })
}

fn line_reads_register(text: &str, reg: &str) -> bool {
    if let Some((lhs, rhs)) = assignment_parts(text) {
        tokens_contain_reg(rhs, reg)
            || (lhs.trim() != reg && tokens_contain_reg(lhs, reg))
    } else {
        tokens_contain_reg(text, reg)
    }
}

fn tokens_contain_reg(text: &str, reg: &str) -> bool {
    let mut found = false;
    for_each_ident(text, |word| {
        if !found && is_register(word) && canonical_reg(word) == reg {
            found = true;
        }
    });
    found
}



fn drop_unused_declarations(lines: &mut Vec<PseudoLine>) {
    let mut referenced: HashSet<String> = HashSet::default();
    for line in lines.iter() {
        if line.kind == LineKind::Declaration {
            continue;
        }
        for_each_ident(line.text.split("//").next().unwrap_or(""), |word| {
            referenced.insert(word.to_string());
        });
    }
    lines.retain(|line| {
        if line.kind != LineKind::Declaration {
            return true;
        }
        let Some(name) = declared_name(&line.text) else {
            return true;
        };
        !is_removable(name) || referenced.contains(name)
    });
    
    let mut i = 0;
    while i + 1 < lines.len() {
        if lines[i].text.trim() == "{" && lines[i + 1].text.trim().is_empty() {
            lines.remove(i + 1);
        } else {
            i += 1;
        }
    }
}

fn declared_name(text: &str) -> Option<&str> {
    let code = text.split("//").next().unwrap_or(text);
    let decl = code.trim().trim_end_matches(';').trim();
    let name = decl.split_whitespace().last()?;
    let name = name.trim_start_matches('*');
    let name = name.split('[').next().unwrap_or(name);
    is_identifier(name).then_some(name)
}

fn for_each_ident(text: &str, mut f: impl FnMut(&str)) {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            while i < chars.len() {
                let d = chars[i];
                i += 1;
                if d == quote {
                    break;
                }
            }
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            f(&word);
            continue;
        }
        i += 1;
    }
}


fn substitute_condition(text: &str, aliases: &HashMap<String, String>) -> String {
    substitute_tokens(text, aliases)
}



fn substitute_line(text: &str, aliases: &HashMap<String, String>) -> String {
    if let Some(pos) = text.find(" = ") {
        let (lhs, rhs) = text.split_at(pos + 3);
        format!("{}{}", lhs, substitute_tokens(rhs, aliases))
    } else {
        substitute_tokens(text, aliases)
    }
}

fn substitute_tokens(text: &str, aliases: &HashMap<String, String>) -> String {
    if aliases.is_empty() {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            out.push(c);
            i += 1;
            while i < chars.len() {
                let d = chars[i];
                out.push(d);
                i += 1;
                if d == quote && chars.get(i.wrapping_sub(2)) != Some(&'\\') {
                    break;
                }
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            out.extend(chars[i..].iter());
            break;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let prev = chars[..start].iter().rev().find(|c| !c.is_whitespace());
            if prev != Some(&'&')
                && let Some(replacement) = aliases.get(&word)
            {
                out.push_str(replacement);
                continue;
            }
            out.push_str(&word);
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn simple_assignment(text: &str) -> Option<(String, String)> {
    let code = text.split("//").next().unwrap_or(text).trim();
    let t = code.strip_suffix(';')?;
    let (lhs, rhs) = t.split_once(" = ")?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    if !is_identifier(lhs) {
        return None;
    }
    if is_identifier(rhs) || is_number(rhs) {
        Some((lhs.to_string(), rhs.to_string()))
    } else {
        None
    }
}

fn assignment_lhs(text: &str) -> Option<String> {
    let code = text.split("//").next().unwrap_or(text).trim();
    let t = code.strip_suffix(';')?;
    let (lhs, _) = t.split_once(" = ")?;
    let lhs = lhs.trim();
    is_identifier(lhs).then(|| lhs.to_string())
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_number(s: &str) -> bool {
    let s = s.trim();
    let s = s.strip_prefix('-').unwrap_or(s);
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
    }
}

fn is_removable(name: &str) -> bool {
    
    
    name.starts_with("local_") || name.starts_with("arg_") || name.starts_with("tmp_")
}



fn used_as_read(lines: &[PseudoLine], name: &str, skip: usize) -> bool {
    for (idx, line) in lines.iter().enumerate() {
        if idx == skip || line.kind == LineKind::Declaration {
            continue;
        }
        let text = line.text.split("//").next().unwrap_or("");
        let (lhs, rhs) = match text
            .trim()
            .strip_suffix(';')
            .and_then(|t| t.split_once(" = "))
        {
            Some((lhs, rhs)) => (lhs, rhs),
            None => ("", text),
        };
        if tokens_contain(rhs, name) {
            return true;
        }
        let lhs = lhs.trim();
        if lhs != name && tokens_contain(lhs, name) {
            return true;
        }
    }
    false
}

fn tokens_contain(text: &str, name: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            while i < chars.len() {
                let d = chars[i];
                i += 1;
                if d == quote {
                    break;
                }
            }
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            if chars[start..i].iter().copied().eq(name.chars()) {
                return true;
            }
            continue;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str, kind: LineKind) -> PseudoLine {
        PseudoLine {
            indent: 0,
            text: text.into(),
            kind,
            source_addr: None,
        }
    }

    #[test]
    fn remaining_registers_get_ghidra_names() {
        let mut lines = vec![
            line("{", LineKind::OpenBrace),
            line("rax = param_1;", LineKind::Assignment),
            line("if (eax == 0) {", LineKind::Branch),
            line("return rax;", LineKind::Return),
            line("}", LineKind::Branch),
        ];
        name_remaining_registers(&mut lines);
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(text[0], "{");
        assert_eq!(text[1], "undefined8 uVar1;");
        assert_eq!(text[2], "uVar1 = param_1;");
        assert_eq!(text[3], "if ((uint)uVar1 == 0) {");
        assert_eq!(text[4], "return uVar1;");
        assert!(!text.iter().any(|l| l.contains("rax") || l.contains("eax")));
    }

    #[test]
    fn incoming_register_is_not_declared_as_a_temp() {
        let mut lines = vec![
            line("{", LineKind::OpenBrace),
            line("if (rax == 0) {", LineKind::Branch),
            line("return rbx;", LineKind::Return),
            line("}", LineKind::Branch),
            line("}", LineKind::CloseBrace),
        ];
        name_remaining_registers(&mut lines);
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(text[0], "{");
        assert_eq!(text[1], "if (in_RAX == 0) {");
        assert_eq!(text[2], "return in_RBX;");
        assert!(!text.iter().any(|l| l.starts_with("undefined8")));
    }

    #[test]
    fn single_assignment_callee_saved_register_is_inlined() {
        let mut lines = vec![
            line("rbx = param_1;", LineKind::Assignment),
            line("if (rbx == 0) {", LineKind::Branch),
            line("return rbx;", LineKind::Return),
            line("}", LineKind::Branch),
        ];
        inline_single_assignment_registers(&mut lines);
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            text,
            vec!["if (param_1 == 0) {", "return param_1;", "}"]
        );
    }

    #[test]
    fn callee_saved_save_restore_pair_is_removed() {
        let mut lines = vec![
            line("longlong local_res20;", LineKind::Declaration),
            line("local_res20 = rbx;", LineKind::Assignment),
            line("rbx = param_1;", LineKind::Assignment),
            line("if (rbx == 0) {", LineKind::Branch),
            line("rbx = local_res20;", LineKind::Assignment),
            line("return;", LineKind::Return),
            line("}", LineKind::Branch),
            line("rbx = local_res20;", LineKind::Assignment),
        ];
        drop_callee_saved_bookkeeping(&mut lines);
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            text,
            vec!["rbx = param_1;", "if (rbx == 0) {", "return;", "}"]
        );
    }

    #[test]
    fn caller_saved_register_is_not_inlined() {
        let mut lines = vec![
            line("rax = 5;", LineKind::Assignment),
            line("foo();", LineKind::Call),
            line("return rax;", LineKind::Return),
        ];
        inline_single_assignment_registers(&mut lines);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2].text, "return rax;");
    }

    fn run(lines: Vec<PseudoLine>) -> Vec<String> {
        let mut lines = lines;
        propagate_aliases(&mut lines);
        lines.into_iter().map(|l| l.text).collect()
    }

    fn run_dead(lines: Vec<PseudoLine>) -> Vec<String> {
        let mut lines = lines;
        drop_dead_register_assignments(&mut lines);
        lines.into_iter().map(|l| l.text).collect()
    }

    fn run_cse(lines: Vec<PseudoLine>) -> Vec<String> {
        let mut lines = lines;
        cse_repeated_expressions(&mut lines);
        lines.into_iter().map(|l| l.text).collect()
    }

    fn run_inline(lines: Vec<PseudoLine>) -> Vec<String> {
        let mut lines = lines;
        inline_single_use_temps(&mut lines);
        lines.into_iter().map(|l| l.text).collect()
    }

    #[test]
    fn alias_reaches_condition_and_is_dropped() {
        let out = run(vec![
            line("local_18 = param_1;", LineKind::Assignment),
            line("if (local_18 != 0) {", LineKind::Branch),
            line("rax = *(int32_t *)local_18;", LineKind::Assignment),
            line("}", LineKind::Branch),
            line("return rax;", LineKind::Return),
        ]);
        assert_eq!(out[0], "if (param_1 != 0) {");
        assert_eq!(out[1], "rax = *(int32_t *)param_1;");
        assert!(!out.iter().any(|l| l.contains("local_18")), "{:?}", out);
    }

    #[test]
    fn alias_survives_into_else_branch() {
        let out = run(vec![
            line("local_8 = param_2;", LineKind::Assignment),
            line("if (x) {", LineKind::Branch),
            line("rax = local_8;", LineKind::Assignment),
            line("} else {", LineKind::Branch),
            line("rax = local_8;", LineKind::Assignment),
            line("}", LineKind::Branch),
        ]);
        assert!(!out.iter().any(|l| l.contains("local_8")), "{:?}", out);
        assert_eq!(out[1], "rax = param_2;");
        assert_eq!(out[3], "rax = param_2;");
    }

    #[test]
    fn alias_not_applied_to_address_of() {
        let out = run(vec![
            line("local_8 = param_1;", LineKind::Assignment),
            line("f(&local_8);", LineKind::Call),
        ]);
        assert!(out.iter().any(|l| l.contains("&local_8")), "{:?}", out);
        assert!(
            out.iter().any(|l| l.contains("local_8 = param_1")),
            "{:?}",
            out
        );
    }

    #[test]
    fn loop_condition_is_not_substituted() {
        let out = run(vec![
            line("local_8 = param_1;", LineKind::Assignment),
            line("while (local_8 != 0) {", LineKind::Branch),
            line("local_8 = local_8 - 1;", LineKind::Assignment),
            line("}", LineKind::Branch),
        ]);
        assert!(out[1].contains("local_8"), "{:?}", out);
        assert!(
            out.iter().any(|l| l.contains("local_8 = param_1")),
            "{:?}",
            out
        );
    }

    #[test]
    fn assignment_kept_when_read_after_branch() {
        let out = run(vec![
            line("local_8 = param_1;", LineKind::Assignment),
            line("if (x) {", LineKind::Branch),
            line("rax = 1;", LineKind::Assignment),
            line("}", LineKind::Branch),
            line("return local_8;", LineKind::Return),
        ]);
        assert!(
            out.iter().any(|l| l.contains("local_8 = param_1")),
            "{:?}",
            out
        );
    }

    #[test]
    fn unused_declaration_is_dropped() {
        let out = run(vec![
            line("int64_t local_18;", LineKind::Declaration),
            line("local_18 = param_1;", LineKind::Assignment),
            line("rax = param_1;", LineKind::Assignment),
            line("return rax;", LineKind::Return),
        ]);
        assert!(!out.iter().any(|l| l.contains("local_18")), "{:?}", out);
    }

    #[test]
    fn dead_register_before_overwrite_is_dropped() {
        let out = run_dead(vec![
            line("rax = 1;", LineKind::Assignment),
            line("rax = 2;", LineKind::Assignment),
            line("local_4 = rax;", LineKind::Assignment),
            line("return local_4;", LineKind::Return),
        ]);
        assert!(!out.iter().any(|l| l == "rax = 1;"), "{:?}", out);
        assert!(out.iter().any(|l| l == "rax = 2;"), "{:?}", out);
    }

    #[test]
    fn dead_register_before_explicit_return_is_dropped() {
        let out = run_dead(vec![
            line("rax = 1;", LineKind::Assignment),
            line("return 2;", LineKind::Return),
        ]);
        assert_eq!(out, vec!["return 2;"]);
    }

    #[test]
    fn rax_before_bare_return_is_kept() {
        let out = run_dead(vec![
            line("rax = 1;", LineKind::Assignment),
            line("return;", LineKind::Return),
        ]);
        assert_eq!(out, vec!["rax = 1;", "return;"]);
    }

    #[test]
    fn register_read_in_rhs_is_not_dead() {
        let out = run_dead(vec![
            line("rax = 1;", LineKind::Assignment),
            line("rax = rax + 1;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["rax = 1;", "rax = rax + 1;"]);
    }

    #[test]
    fn register_live_across_branch_is_kept() {
        let out = run_dead(vec![
            line("rax = 1;", LineKind::Assignment),
            line("if (x) {", LineKind::Branch),
            line("y = 2;", LineKind::Assignment),
            line("}", LineKind::Branch),
            line("return rax;", LineKind::Return),
        ]);
        assert!(out.iter().any(|l| l == "rax = 1;"), "{:?}", out);
    }

    #[test]
    fn dead_xmm_assignment_is_dropped() {
        let out = run_dead(vec![
            line("xmm0 = 1;", LineKind::Assignment),
            line("xmm0 = 2;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["xmm0 = 2;"]);
    }

    #[test]
    fn repeated_load_is_reused() {
        let out = run_cse(vec![
            line("r10 = *(int32_t *)param_1;", LineKind::Assignment),
            line("r11 = *(int32_t *)param_1;", LineKind::Assignment),
        ]);
        assert_eq!(
            out,
            vec!["r10 = *(int32_t *)param_1;", "r11 = r10;"]
        );
    }

    #[test]
    fn cse_stops_at_call() {
        let out = run_cse(vec![
            line("r10 = *(int32_t *)param_1;", LineKind::Assignment),
            line("f();", LineKind::Call),
            line("r11 = *(int32_t *)param_1;", LineKind::Assignment),
        ]);
        assert_eq!(out[2], "r11 = *(int32_t *)param_1;");
    }

    #[test]
    fn cse_stops_at_memory_store() {
        let out = run_cse(vec![
            line("r10 = *(int32_t *)param_1;", LineKind::Assignment),
            line("*(int32_t *)param_2 = 1;", LineKind::Assignment),
            line("r11 = *(int32_t *)param_1;", LineKind::Assignment),
        ]);
        assert_eq!(out[2], "r11 = *(int32_t *)param_1;");
    }

    #[test]
    fn cse_invalidated_by_base_write() {
        let out = run_cse(vec![
            line("r10 = *(int32_t *)param_1;", LineKind::Assignment),
            line("param_1 = 0;", LineKind::Assignment),
            line("r11 = *(int32_t *)param_1;", LineKind::Assignment),
        ]);
        assert_eq!(out[2], "r11 = *(int32_t *)param_1;");
    }

    #[test]
    fn repeated_address_is_reused() {
        let out = run_cse(vec![
            line("r10 = &DAT_140001000;", LineKind::Assignment),
            line("r11 = &DAT_140001000;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["r10 = &DAT_140001000;", "r11 = r10;"]);
    }

    #[test]
    fn repeated_arithmetic_is_reused() {
        let out = run_cse(vec![
            line("tmp_2 = rax & 0xff;", LineKind::Assignment),
            line("tmp_3 = rax & 0xff;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["tmp_2 = rax & 0xff;", "tmp_3 = tmp_2;"]);
    }

    #[test]
    fn commented_assignment_is_parsed() {
        let out = run(vec![
            line("local_8 = param_1;  // zero-extend", LineKind::Assignment),
            line("if (local_8 != 0) {", LineKind::Branch),
            line("}", LineKind::Branch),
        ]);
        assert_eq!(out[0], "if (param_1 != 0) {");
        assert!(!out.iter().any(|l| l.contains("local_8")), "{:?}", out);
    }

    #[test]
    fn dead_commented_register_is_dropped() {
        let out = run_dead(vec![
            line("rax = tmp_0;  // zero-extend", LineKind::Assignment),
            line("rax = 1;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["rax = 1;"]);
    }

    #[test]
    fn one_use_temp_is_inlined() {
        let out = run_inline(vec![
            line("tmp_0 = param_1->field_0x8;", LineKind::Assignment),
            line("local_4 = tmp_0;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["local_4 = param_1->field_0x8;"]);
    }

    #[test]
    fn arithmetic_temp_is_parenthesized() {
        let out = run_inline(vec![
            line("tmp_0 = rax & 0xff;", LineKind::Assignment),
            line("rdx = tmp_0 | 1;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["rdx = (rax & 0xff) | 1;"]);
    }

    #[test]
    fn unused_temp_is_dropped() {
        let out = run_inline(vec![
            line("tmp_0 = param_1->field_0x8;", LineKind::Assignment),
            line("local_4 = 1;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["local_4 = 1;"]);
    }

    #[test]
    fn temp_used_twice_is_kept() {
        let out = run_inline(vec![
            line("tmp_0 = param_1->field_0x8;", LineKind::Assignment),
            line("x = tmp_0;", LineKind::Assignment),
            line("y = tmp_0;", LineKind::Assignment),
        ]);
        assert_eq!(out.len(), 3, "{:?}", out);
    }

    #[test]
    fn temp_chain_is_folded() {
        let out = run_inline(vec![
            line("tmp_0 = param_1->field_0x8;", LineKind::Assignment),
            line("tmp_1 = tmp_0;", LineKind::Assignment),
            line("y = tmp_1;", LineKind::Assignment),
        ]);
        assert_eq!(out, vec!["y = param_1->field_0x8;"]);
    }

    #[test]
    fn address_of_temp_is_not_inlined() {
        let out = run_inline(vec![
            line("tmp_0 = param_1->field_0x8;", LineKind::Assignment),
            line("x = &tmp_0;", LineKind::Assignment),
        ]);
        assert_eq!(out.len(), 2, "{:?}", out);
    }

    #[test]
    fn loop_condition_temp_is_not_inlined() {
        let out = run_inline(vec![
            line("tmp_0 = param_1->field_0x8;", LineKind::Assignment),
            line("while (tmp_0) {", LineKind::Branch),
            line("}", LineKind::Branch),
        ]);
        assert_eq!(out.len(), 3, "{:?}", out);
    }

    #[test]
    fn declaration_kept_when_address_is_taken() {
        let out = run(vec![
            line("int64_t local_c;", LineKind::Declaration),
            line("local_c = param_2;", LineKind::Assignment),
            line("rax = &local_c;", LineKind::Assignment),
            line("return rax;", LineKind::Return),
        ]);
        assert!(
            out.iter().any(|l| l.contains("int64_t local_c")),
            "{:?}",
            out
        );
        assert!(
            out.iter().any(|l| l.contains("local_c = param_2")),
            "{:?}",
            out
        );
    }

    #[test]
    fn repeated_subexpression_uses_assigned_temp() {
        let mut lines = vec![
            line("rax = n->id;", LineKind::Assignment),
            line("rcx = rax + n->id;", LineKind::Assignment),
        ];
        reuse_assigned_subexpressions(&mut lines);
        assert_eq!(lines[1].text, "rcx = rax + rax;");
    }

    #[test]
    fn repeated_subexpression_does_not_cross_control_flow() {
        let mut lines = vec![
            line("rax = n->id;", LineKind::Assignment),
            line("LAB_1:", LineKind::Label),
            line("rcx = rax + n->id;", LineKind::Assignment),
        ];
        reuse_assigned_subexpressions(&mut lines);
        assert_eq!(lines[2].text, "rcx = rax + n->id;");
    }

    #[test]
    fn writes_invalidate_aliases_to_the_register() {
        let mut lines = vec![
            line("xmm0 = foo();", LineKind::Assignment),
            line("x = xmm0;", LineKind::Assignment),
            line("xmm0 = bar();", LineKind::Assignment),
            line("use(x);", LineKind::Call),
        ];
        propagate_aliases(&mut lines);
        assert_eq!(lines[3].text, "use(x);");
    }

    #[test]
    fn self_assignments_are_dropped() {
        let mut lines = vec![
            line("a = a;", LineKind::Assignment),
            line("x = x;", LineKind::Assignment),
            line("x = y;", LineKind::Assignment),
        ];
        drop_self_assignments(&mut lines);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "x = y;");
    }
}
