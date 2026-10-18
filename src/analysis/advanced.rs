use crate::disasm::DisasmInstruction;
use crate::parser::ParsedBinary;
use rustc_hash::FxHashMap as HashMap;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SwitchTable {
    pub jump_addr: u64,
    pub table_addr: u64,
    pub case_count: u32,
    pub case_targets: Vec<u64>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StubInfo {
    pub func_entry: u64,
    pub kind: StubKind,
    pub target_name: String,
    pub target_addr: Option<u64>,
    pub jump_addr: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum StubKind {
    ImportThunk,
    TailCall,
}

fn detect_stubs(
    insns: &[DisasmInstruction],
    func_entry: u64,
    func_end: u64,
    import_by_off: &HashMap<u64, &crate::parser::Import>,
    entries: &rustc_hash::FxHashSet<u64>,
    sym_by_addr: &HashMap<u64, &str>,
) -> Option<StubInfo> {
    let start = insns.partition_point(|i| i.address < func_entry);
    let end = insns.partition_point(|i| i.address < func_end);
    let func_insns = &insns[start..end];

    if func_insns.is_empty() {
        return None;
    }

    let is_padding = |i: &DisasmInstruction| {
        i.mnem() == "nop" || i.mnem() == "endbr64" || i.mnem() == "endbr32" || i.mnem() == "int3"
    };
    let is_prefix_shape = |i: &DisasmInstruction| {
        matches!(
            i.mnemonic,
            "mov"
                | "movzx"
                | "movsx"
                | "movsxd"
                | "lea"
                | "push"
                | "pop"
                | "nop"
                | "endbr64"
                | "endbr32"
        )
    };
    let mut count = 0usize;
    let mut prev: Option<&DisasmInstruction> = None;
    let mut last: Option<&DisasmInstruction> = None;
    let mut prefix_ok = true;
    for i in func_insns.iter() {
        if is_padding(i) {
            continue;
        }
        if count >= 4 {
            return None;
        }
        if let Some(p) = last {
            if !is_prefix_shape(p) {
                prefix_ok = false;
            }
        }
        prev = last;
        last = Some(i);
        count += 1;
    }
    let last = last?;

    if count == 2 {
        if let Some(p) = prev {
            if p.mnem() == "push" && last.mnem() == "ret" {
                if let Some(target) = parse_addr(p.ops().trim()) {
                    if target != func_entry {
                        if let Some(imp) = import_by_off.get(&target) {
                            return Some(StubInfo {
                                func_entry,
                                kind: StubKind::ImportThunk,
                                target_name: format!("{}!{}", imp.library, imp.name),
                                target_addr: None,
                                jump_addr: last.address,
                            });
                        }
                        if entries.contains(&target) {
                            let name = sym_by_addr
                                .get(&target)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| format!("sub_{:X}", target));
                            return Some(StubInfo {
                                func_entry,
                                kind: StubKind::TailCall,
                                target_name: name,
                                target_addr: Some(target),
                                jump_addr: last.address,
                            });
                        }
                    }
                }
                return None;
            }
        }
    }

    if last.mnem() != "jmp" {
        return None;
    }
    if count > 1 && !prefix_ok {
        return None;
    }

    {
        let ops_owned = last.ops();
        let ops = ops_owned.trim();
        if super::types::is_register(ops) {
            return Some(StubInfo {
                func_entry,
                kind: StubKind::ImportThunk,
                target_name: format!("*{}", ops),
                target_addr: None,
                jump_addr: last.address,
            });
        }
        if ops.starts_with('[') || ops.contains("ptr [") {
            let insn_addr = last.address;
            let insn_size = last.bytes.len() as u64;
            if let Some(slot) = extract_iat_slot(ops, insn_addr, insn_size) {
                if let Some(imp) = import_by_off.get(&slot) {
                    let full = if imp.library.is_empty() {
                        imp.name.clone()
                    } else {
                        format!("{}!{}", imp.library, imp.name)
                    };
                    return Some(StubInfo {
                        func_entry,
                        kind: StubKind::ImportThunk,
                        target_name: full,
                        target_addr: None,
                        jump_addr: last.address,
                    });
                }
            }
            return Some(StubInfo {
                func_entry,
                kind: StubKind::ImportThunk,
                target_name: ops.to_string(),
                target_addr: None,
                jump_addr: last.address,
            });
        }
        if let Some(target) = parse_addr(ops) {
            if let Some(imp) = import_by_off.get(&target) {
                return Some(StubInfo {
                    func_entry,
                    kind: StubKind::ImportThunk,
                    target_name: format!("{}!{}", imp.library, imp.name),
                    target_addr: None,
                    jump_addr: last.address,
                });
            }
            if target != func_entry && entries.contains(&target) {
                let name = sym_by_addr
                    .get(&target)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("sub_{:X}", target));
                return Some(StubInfo {
                    func_entry,
                    kind: StubKind::TailCall,
                    target_name: name,
                    target_addr: Some(target),
                    jump_addr: last.address,
                });
            }
        }
    }
    None
}

pub fn extract_iat_slot(ops: &str, insn_addr: u64, insn_size: u64) -> Option<u64> {
    let inner = ops.split('[').nth(1)?.split(']').next()?;
    let clean = inner.replace(" ", "");
    if let Some(rest) = clean.strip_prefix("rip+") {
        let disp = u64::from_str_radix(rest.trim_start_matches("0x"), 16).ok()?;
        return Some(insn_addr.wrapping_add(insn_size).wrapping_add(disp));
    }
    if let Some(rest) = clean.strip_prefix("rip-") {
        let disp = u64::from_str_radix(rest.trim_start_matches("0x"), 16).ok()?;
        return Some(insn_addr.wrapping_add(insn_size).wrapping_sub(disp));
    }
    clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

pub fn detect_switch_tables(
    insns: &[DisasmInstruction],
    binary: &ParsedBinary,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Vec<SwitchTable> {
    let candidates: Vec<usize> = insns
        .iter()
        .enumerate()
        .filter(|(_, insn)| {
            if insn.mnem() != "jmp" {
                return false;
            }
            let ops_owned = insn.ops();
            let ops = ops_owned.trim();
            ops.starts_with('[') || ops.contains("ptr [") || super::types::is_register(ops)
        })
        .map(|(i, _)| i)
        .collect();
    if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
        return Vec::new();
    }
    if candidates.len() < 4 {
        let mut tables = Vec::new();
        for i in candidates {
            if let Some(t) = switch_at(insns, binary, i) {
                tables.push(t);
            }
        }
        tables.sort_by_key(|t| t.jump_addr);
        return tables;
    }
    let mut tables: Vec<SwitchTable> = crate::util::parallel::install(|| {
        use rayon::prelude::*;
        candidates
            .par_iter()
            .filter_map(|&i| {
                if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                    return None;
                }
                switch_at(insns, binary, i)
            })
            .collect()
    });
    tables.sort_by_key(|t| t.jump_addr);
    tables
}

fn switch_at(insns: &[DisasmInstruction], binary: &ParsedBinary, i: usize) -> Option<SwitchTable> {
    if let Some(t) = msvc_rva_switch(insns, binary, i) {
        return Some(t);
    }
    let insn = &insns[i];

    let mut table_addr: Option<u64> = None;
    let mut case_limit: Option<u32> = None;

    for prev in &insns[i.saturating_sub(8)..i] {
        if prev.mnem() == "lea" {
            if let Some(addr) = extract_lea_addr(&prev.ops(), prev.address, prev.bytes.len() as u64)
            {
                table_addr = Some(addr);
            }
        }
        if prev.mnem() == "cmp" {
            let prev_ops = prev.ops();
            let parts: Vec<&str> = prev_ops.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                if let Some(n) = parse_addr(parts[1]) {
                    if n < 1000 {
                        case_limit = Some(n as u32);
                    }
                }
            }
        }
    }

    let table = table_addr?;
    let count = case_limit.unwrap_or(0) + 1;
    if count < 2 {
        return None;
    }
    let mut targets: Vec<u64> = Vec::new();
    let mut t8 = Vec::new();
    for k in 0..count.min(64) {
        let entry_addr = table.wrapping_add(k as u64 * 8);
        if let Some(target) = read_qword_at(binary, entry_addr) {
            t8.push(target);
        }
    }
    if !t8.is_empty() && t8.iter().all(|t| is_exec_addr(binary, *t)) {
        targets = t8;
    } else {
        let mut t4abs = Vec::new();
        for k in 0..count.min(64) {
            let entry_addr = table.wrapping_add(k as u64 * 4);
            if let Some(v) = read_dword_at(binary, entry_addr) {
                t4abs.push(v as u64);
            }
        }
        if !t4abs.is_empty() && t4abs.iter().all(|t| is_exec_addr(binary, *t)) {
            targets = t4abs;
        } else {
            let mut t4rel = Vec::new();
            for k in 0..count.min(64) {
                let entry_addr = table.wrapping_add(k as u64 * 4);
                if let Some(v) = read_dword_at(binary, entry_addr) {
                    let off = v as i32 as i64;
                    let tgt = (table as i64).wrapping_add(off) as u64;
                    t4rel.push(tgt);
                }
            }
            if !t4rel.is_empty() && t4rel.iter().all(|t| is_exec_addr(binary, *t)) {
                targets = t4rel;
            }
        }
    }
    if targets.is_empty() {
        return None;
    }

    Some(SwitchTable {
        jump_addr: insn.address,
        table_addr: table,
        case_count: count,
        case_targets: targets,
    })
}

fn rva_table_disp(ops: &str) -> Option<u64> {
    let (lb, rb) = (ops.find('[')?, ops.rfind(']')?);
    if rb <= lb {
        return None;
    }
    let inner: String = ops[lb + 1..rb]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if !inner.contains("*4") {
        return None;
    }
    inner
        .split('+')
        .filter_map(|t| t.strip_prefix("0x"))
        .next_back()
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

fn msvc_rva_switch(
    insns: &[DisasmInstruction],
    binary: &ParsedBinary,
    i: usize,
) -> Option<SwitchTable> {
    let insn = &insns[i];
    if !super::types::is_register(insn.ops().trim()) {
        return None;
    }
    let mut table_rva = None;
    let mut case_limit = None;
    let mut saw_add = false;
    for p in &insns[i.saturating_sub(12)..i] {
        let ops = p.ops();
        match p.mnem() {
            "add" => {
                let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
                if parts.len() == 2
                    && super::types::is_register(parts[0])
                    && super::types::is_register(parts[1])
                {
                    saw_add = true;
                }
            }
            "mov" | "movsxd" => {
                if let Some(d) = rva_table_disp(&ops) {
                    table_rva = Some(d);
                }
            }
            "cmp" => {
                let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
                if parts.len() == 2 {
                    if let Some(n) = parse_addr(parts[1]) {
                        if n < 1000 {
                            case_limit = Some(n as u32);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !saw_add {
        return None;
    }
    let table = binary.image_base.wrapping_add(table_rva?);
    let count = case_limit? + 1;
    if count < 2 {
        return None;
    }
    let mut targets = Vec::new();
    for k in 0..count.min(1024) {
        let v = read_dword_at(binary, table.wrapping_add(k as u64 * 4))?;
        let t = binary.image_base.wrapping_add(v as u64);
        if !is_exec_addr(binary, t) {
            return None;
        }
        targets.push(t);
    }
    Some(SwitchTable {
        jump_addr: insn.address,
        table_addr: table,
        case_count: count,
        case_targets: targets,
    })
}

fn extract_lea_addr(operands: &str, insn_addr: u64, insn_size: u64) -> Option<u64> {
    let parts: Vec<&str> = operands.split(',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return None;
    }
    let mem = parts[1];
    let inner = mem.strip_prefix('[').and_then(|x| x.strip_suffix(']'))?;
    let inner = inner.replace(" ", "");
    if let Some(rest) = inner.strip_prefix("rip+") {
        let v = parse_addr(rest)?;
        return Some(insn_addr.wrapping_add(insn_size).wrapping_add(v));
    }
    if let Some(rest) = inner.strip_prefix("rip-") {
        let v = parse_addr(rest)?;
        return Some(insn_addr.wrapping_add(insn_size).wrapping_sub(v));
    }
    if let Some(h) = inner.strip_prefix("0x") {
        return u64::from_str_radix(h, 16).ok();
    }
    None
}

fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        return u64::from_str_radix(h, 16).ok();
    }
    u64::from_str_radix(s, 16).ok()
}

fn is_exec_addr(binary: &ParsedBinary, vaddr: u64) -> bool {
    for sec in &binary.sections {
        if !sec.is_executable {
            continue;
        }
        if vaddr >= sec.vaddr && vaddr < sec.vaddr.saturating_add(sec.size) {
            return true;
        }
    }
    if binary.format == "RAW" {
        return (vaddr as usize) < binary.data.len();
    }
    false
}

fn read_qword_at(binary: &ParsedBinary, vaddr: u64) -> Option<u64> {
    for sec in &binary.sections {
        let sec_end = sec.vaddr.checked_add(sec.size)?;
        if vaddr >= sec.vaddr && vaddr.checked_add(8).is_some_and(|e| e <= sec_end) {
            let off = sec.offset.checked_add(vaddr - sec.vaddr)? as usize;
            if off.checked_add(8).is_some_and(|e| e <= binary.data.len()) {
                let bytes = &binary.data[off..off + 8];
                return Some(u64::from_le_bytes(bytes.try_into().ok()?));
            }
        }
    }
    if binary.format == "RAW"
        && vaddr
            .checked_add(8)
            .is_some_and(|e| e as usize <= binary.data.len())
    {
        let bytes = &binary.data[vaddr as usize..vaddr as usize + 8];
        return Some(u64::from_le_bytes(bytes.try_into().ok()?));
    }
    None
}

fn read_dword_at(binary: &ParsedBinary, vaddr: u64) -> Option<u32> {
    for sec in &binary.sections {
        if !sec.initialized {
            continue;
        }
        let sec_end = sec.vaddr.checked_add(sec.size)?;
        if vaddr >= sec.vaddr && vaddr.checked_add(4).is_some_and(|e| e <= sec_end) {
            let off = sec.offset.checked_add(vaddr - sec.vaddr)? as usize;
            if off.checked_add(4).is_some_and(|e| e <= binary.data.len()) {
                let bytes = &binary.data[off..off + 4];
                return Some(u32::from_le_bytes(bytes.try_into().ok()?));
            }
        }
    }
    if binary.format == "RAW"
        && vaddr
            .checked_add(4)
            .is_some_and(|e| e as usize <= binary.data.len())
    {
        let bytes = &binary.data[vaddr as usize..vaddr as usize + 4];
        return Some(u32::from_le_bytes(bytes.try_into().ok()?));
    }
    None
}

pub fn build_stub_map(
    insns: &[DisasmInstruction],
    functions: &[super::function::DetectedFunction],
    binary: &ParsedBinary,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> HashMap<u64, StubInfo> {
    let mut import_by_off: HashMap<u64, &crate::parser::Import> = HashMap::default();
    for imp in binary.all_imports() {
        if imp.offset != 0 {
            import_by_off.entry(imp.offset).or_insert(imp);
        }
    }
    let entries: rustc_hash::FxHashSet<u64> = functions.iter().map(|f| f.entry).collect();
    let sym_by_addr: HashMap<u64, &str> = {
        let mut m = HashMap::default();
        for s in &binary.symbols {
            if s.addr != 0 {
                m.entry(s.addr).or_insert(s.name.as_str());
            }
        }
        m
    };
    let mut map = HashMap::default();
    for f in functions {
        if let Some(imp) = import_by_off.get(&f.entry) {
            let full = if imp.library.is_empty() {
                imp.name.clone()
            } else {
                format!("{}!{}", imp.library, imp.name)
            };
            map.insert(
                f.entry,
                StubInfo {
                    func_entry: f.entry,
                    kind: StubKind::ImportThunk,
                    target_name: full,
                    target_addr: None,
                    jump_addr: f.entry,
                },
            );
        }
    }
    if functions.len() >= crate::util::parallel::PAR_FUNCS {
        use rayon::prelude::*;
        let found: Vec<(u64, StubInfo)> = crate::util::parallel::install(|| {
            functions
                .par_iter()
                .filter_map(|f| {
                    if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                        return None;
                    }
                    detect_stubs(
                        insns,
                        f.entry,
                        f.end,
                        &import_by_off,
                        &entries,
                        &sym_by_addr,
                    )
                    .map(|s| (f.entry, s))
                })
                .collect()
        });
        if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
            return map;
        }
        for (k, v) in found {
            map.entry(k).or_insert(v);
        }
    } else {
        for (fi, f) in functions.iter().enumerate() {
            if fi % 512 == 0 && cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            {
                return map;
            }
            if map.contains_key(&f.entry) {
                continue;
            }
            if let Some(stub) = detect_stubs(
                insns,
                f.entry,
                f.end,
                &import_by_off,
                &entries,
                &sym_by_addr,
            ) {
                map.insert(f.entry, stub);
            }
        }
    }
    let keys: Vec<u64> = map.keys().copied().collect();
    for k in keys {
        let mut seen = rustc_hash::FxHashSet::default();
        seen.insert(k);
        let mut cur = map.get(&k).and_then(|s| s.target_addr);
        let mut hops = 0;
        while let Some(t) = cur {
            if !seen.insert(t) {
                break;
            }
            match map.get(&t) {
                Some(next) if matches!(next.kind, StubKind::TailCall) => {
                    if let Some(nt) = next.target_addr {
                        cur = Some(nt);
                        hops += 1;
                        continue;
                    }
                    break;
                }
                _ => break,
            }
        }
        if let (Some(final_t), true) = (cur, hops > 0) {
            if let Some(stub) = map.get_mut(&k) {
                stub.target_addr = Some(final_t);
                if let Some(name) = sym_by_addr.get(&final_t) {
                    stub.target_name = name.to_string();
                } else {
                    stub.target_name = format!("sub_{:X}", final_t);
                }
            }
        }
    }
    map
}
