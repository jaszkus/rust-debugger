use super::arm64;
use super::operand_enum;
use super::types::{DisasmInstruction, DisasmResult, InsnBytes};
use crate::parser::ParsedBinary;
use iced_x86::{Code, Decoder, DecoderOptions, Formatter, IntelFormatter};
use std::cell::RefCell;
use std::sync::Arc;

#[inline]
fn bitness_for_arch(arch: &str) -> Option<u32> {
    match arch {
        "x86" => Some(32),
        "x86_64" => Some(64),
        _ => None,
    }
}

#[inline]
fn make_decoder<'a>(arch: &str, code: &'a [u8], ip: u64) -> Option<Decoder<'a>> {
    let bitness = bitness_for_arch(arch)?;
    let options = if arch == "x86_64" {
        DecoderOptions::AMD
    } else {
        DecoderOptions::NONE
    };
    Some(Decoder::with_ip(bitness, code, ip, options))
}

fn make_formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    {
        let opts = f.options_mut();
        opts.set_hex_prefix_string("0x".to_string());
        opts.set_hex_suffix_string(String::new());
        opts.set_uppercase_hex(false);
        opts.set_branch_leading_zeros(false);
        opts.set_rip_relative_addresses(true);
        opts.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
        opts.set_space_after_memory_bracket(false);
        opts.set_space_between_memory_add_operators(false);
        opts.set_signed_immediate_operands(false);
        opts.set_show_branch_size(false);
    }
    f
}

thread_local! {
    static CACHED_FORMATTER: RefCell<IntelFormatter> = RefCell::new(make_formatter());
}

const COMMON_MNEMONICS: &[&str] = &[
    "mov", "push", "pop", "call", "ret", "jmp", "je", "jne", "ja", "jb", "xor", "add", "sub",
    "cmp", "test", "lea", "nop", "and", "or", "inc", "dec", "shl", "shr", "int", "syscall", "xchg",
    "movzx", "movsx", "jz", "jnz", "jl", "jle", "jg", "jge", "jbe", "jae", "loop", "leave",
    "enter", "imul", "div", "idiv", "mul", "not", "neg", "adc", "sbb",
];

thread_local! {
    static MNEMONIC_LOCAL: RefCell<rustc_hash::FxHashSet<&'static str>> =
        RefCell::new(rustc_hash::FxHashSet::default());
}

fn intern_mnemonic_global(s: &str) -> &'static str {
    use std::sync::{Mutex, OnceLock};
    static GLOBAL: OnceLock<Mutex<rustc_hash::FxHashSet<&'static str>>> = OnceLock::new();
    let set = GLOBAL.get_or_init(|| {
        let mut m = rustc_hash::FxHashSet::default();
        m.reserve(256);
        for name in COMMON_MNEMONICS {
            m.insert(*name);
        }
        Mutex::new(m)
    });
    let mut guard = match set.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(v) = guard.get(s) {
        return v;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    guard.insert(leaked);
    leaked
}

#[inline]
pub(crate) fn intern_mnemonic(s: &str) -> &'static str {
    MNEMONIC_LOCAL.with(|local| {
        if let Some(v) = local.borrow().get(s) {
            return *v;
        }
        let v = intern_mnemonic_global(s);
        local.borrow_mut().insert(v);
        v
    })
}

#[derive(Debug, Default)]
pub(crate) struct Interner;

impl Interner {
    #[inline]
    pub(crate) fn new() -> Self {
        Interner
    }
    #[inline]
    pub(crate) fn intern(&mut self, s: &str) -> &'static str {
        intern_mnemonic(s)
    }
    #[inline]
    pub(crate) fn take(&mut self, s: &str) -> &'static str {
        self.intern(s)
    }
}

#[inline]
fn is_sorted_by_addr(insns: &[DisasmInstruction]) -> bool {
    insns.windows(2).all(|w| w[0].address <= w[1].address)
}

fn dedup_instructions(insns: &mut Vec<DisasmInstruction>) -> usize {
    if insns.len() < 2 {
        return 0;
    }
    if insns.windows(2).all(|w| w[0].address < w[1].address) {
        return 0;
    }
    insns.sort_by_key(|i| i.address);
    let mut conflicts = 0usize;
    let mut write = 1usize;
    for read in 1..insns.len() {
        if insns[read].address == insns[write - 1].address {
            if insns[read].bytes != insns[write - 1].bytes
                || insns[read].mnemonic != insns[write - 1].mnemonic
            {
                conflicts += 1;
            }
        } else {
            if write != read {
                insns.swap(write, read);
            }
            write += 1;
        }
    }
    insns.truncate(write);
    conflicts
}

#[inline]
fn insn_end(i: &DisasmInstruction) -> u64 {
    i.address.saturating_add(i.bytes.len() as u64)
}

#[inline]
fn insn_align(arch: &str) -> usize {
    if arch == "aarch64" {
        4
    } else {
        1
    }
}

#[inline]
fn addr_range(insns: &[DisasmInstruction], lo: u64, hi: u64) -> &[DisasmInstruction] {
    let a = insns.partition_point(|i| i.address < lo);
    let b = insns.partition_point(|i| i.address < hi);
    &insns[a..b.max(a)]
}

fn decode_section(arch: &str, code: &[u8], vaddr: u64) -> Vec<DisasmInstruction> {
    match arch {
        "aarch64" => return arm64::decode_section_arm64(code, vaddr),
        "x86" | "x86_64" => {}
        _ => return Vec::new(),
    }
    let mut decoded = Vec::with_capacity(code.len() / 4 + 8);
    decode_range(arch, code, vaddr, &mut decoded);
    gap_fill_section(arch, code, vaddr, &mut decoded);
    let _ = dedup_instructions(&mut decoded);
    decoded
}

fn supported_arch(arch: &str) -> Result<(), String> {
    match arch {
        "x86" | "x86_64" | "aarch64" => Ok(()),
        other => Err(format!(
            "Unsupported architecture for disassembly: '{}' (supported: x86, x86_64, aarch64)",
            other
        )),
    }
}

pub fn disassemble_binary(binary: &ParsedBinary) -> Result<DisasmResult, String> {
    use rayon::prelude::*;
    supported_arch(&binary.arch)?;
    let exec: Vec<(usize, usize, u64)> = binary
        .sections
        .iter()
        .filter(|s| s.is_executable)
        .filter_map(|s| {
            let start = s.offset as usize;
            let end = start.saturating_add(s.size as usize).min(binary.data.len());
            if start >= binary.data.len() || end <= start {
                return None;
            }
            Some((start, end, s.vaddr))
        })
        .collect();
    let total_bytes: usize = exec.iter().map(|(s, e, _)| e.saturating_sub(*s)).sum();
    let use_parallel = exec.len() >= crate::util::parallel::PAR_SECTIONS
        && crate::util::parallel::workers() >= 2
        && total_bytes > 64 * 1024;
    let parts: Vec<Vec<DisasmInstruction>> = if use_parallel {
        crate::util::parallel::install(|| {
            exec.par_iter()
                .map(|(start, end, vaddr)| {
                    decode_section(&binary.arch, &binary.data[*start..*end], *vaddr)
                })
                .collect::<Vec<_>>()
        })
    } else {
        exec.iter()
            .map(|(start, end, vaddr)| {
                decode_section(&binary.arch, &binary.data[*start..*end], *vaddr)
            })
            .collect()
    };
    let total: usize = parts.iter().map(Vec::len).sum();
    let mut all_instructions: Vec<DisasmInstruction> = Vec::with_capacity(total);
    for mut part in parts {
        all_instructions.append(&mut part);
    }

    let _conflicts = dedup_instructions(&mut all_instructions);

    Ok(DisasmResult {
        instructions: Arc::new(all_instructions),
        arch: binary.arch.clone(),
    })
}

fn gap_fill_section(arch: &str, code: &[u8], base: u64, insns: &mut Vec<DisasmInstruction>) {
    if insns.is_empty() {
        return;
    }
    if !is_sorted_by_addr(insns) {
        insns.sort_by_key(|i| i.address);
    }
    let sec_end = base.saturating_add(code.len() as u64);
    let mut extra: Vec<DisasmInstruction> = Vec::new();
    let mut prev_end = base;
    for i in insns.iter() {
        if i.address > prev_end {
            fill_gap(
                arch,
                code,
                base,
                prev_end,
                i.address.min(sec_end),
                &mut extra,
            );
        }
        prev_end = prev_end.max(insn_end(i));
    }
    if sec_end > prev_end {
        fill_gap(arch, code, base, prev_end, sec_end, &mut extra);
    }
    if !extra.is_empty() {
        insns.extend(extra);
        let _ = dedup_instructions(insns);
    }
}

fn fill_gap(
    arch: &str,
    code: &[u8],
    base: u64,
    gs: u64,
    ge: u64,
    out: &mut Vec<DisasmInstruction>,
) {
    let gstart = gs.saturating_sub(base) as usize;
    let gend = ge.saturating_sub(base) as usize;
    if gstart >= gend || gend > code.len() {
        return;
    }
    const PROBE: usize = 64;
    let gap_len = gend - gstart;
    let probe_len = PROBE.min(gap_len);

    let (mut best_off, mut best_count, mut best_len) = (0usize, 0usize, 0usize);
    for off in 0..15usize.min(gap_len) {
        let plen = probe_len.min(gap_len - off);
        if plen == 0 {
            break;
        }
        let (mut count, mut total_len) = (0usize, 0usize);
        walk_valid(
            arch,
            &code[gstart + off..gstart + off + plen],
            gs.wrapping_add(off as u64),
            |insn, _bytes| {
                let len = insn.len();
                if insn.ip().saturating_add(len as u64) > ge {
                    return false;
                }
                count += 1;
                total_len += len;
                true
            },
        );
        if (count, total_len) > (best_count, best_len) {
            best_count = count;
            best_len = total_len;
            best_off = off;
        }
    }
    if best_count == 0 {
        return;
    }
    let mut fill = Vec::new();
    decode_range(
        arch,
        &code[gstart + best_off..gend],
        gs + best_off as u64,
        &mut fill,
    );
    out.extend(fill.into_iter().filter(|i| {
        !i.bytes.is_empty()
            && i.bytes.len() <= 15
            && i.address.saturating_add(i.bytes.len() as u64) <= ge
    }));
}

pub fn disassemble_region(
    data: &[u8],
    base_addr: u64,
    arch: &str,
) -> Result<Vec<DisasmInstruction>, String> {
    supported_arch(arch)?;
    Ok(decode_section(arch, data, base_addr))
}

fn next_valid_offset(arch: &str, code: &[u8], base_addr: u64, pos: usize) -> Option<usize> {
    for skip in 0..15usize.min(code.len().saturating_sub(pos)) {
        let tp = pos + skip;
        let mut trial = make_decoder(arch, &code[tp..], base_addr.wrapping_add(tp as u64))?;
        if trial.can_decode() && trial.decode().code() != Code::INVALID {
            return Some(tp);
        }
    }
    None
}

fn walk_valid<F>(arch: &str, code: &[u8], base_addr: u64, mut visit: F)
where
    F: FnMut(&iced_x86::Instruction, &[u8]) -> bool,
{
    let Some(mut decoder) = make_decoder(arch, code, base_addr) else {
        return;
    };
    const MAX_INVALID_RUN: usize = 8;
    let mut invalid_run = 0usize;

    while decoder.can_decode() {
        let start = decoder.position();
        let insn = decoder.decode();
        if insn.code() == Code::INVALID {
            invalid_run += 1;
            if invalid_run > MAX_INVALID_RUN {
                if let Some(tp) = next_valid_offset(arch, code, base_addr, decoder.position()) {
                    let _ = decoder.set_position(tp);
                    decoder.set_ip(base_addr.wrapping_add(tp as u64));
                    invalid_run = 0;
                }
            }
            continue;
        }
        invalid_run = 0;
        let len = insn.len();
        debug_assert!(len <= 15, "x86 insn longer than 15 bytes");
        let Some(bytes) = code.get(start..start + len) else {
            break;
        };
        if !visit(&insn, bytes) {
            break;
        }
    }
}

fn decode_range(arch: &str, code: &[u8], base_addr: u64, out: &mut Vec<DisasmInstruction>) {
    CACHED_FORMATTER.with(|cell| {
        let mut formatter = cell.borrow_mut();
        decode_range_with(&mut formatter, arch, code, base_addr, out);
    });
}

fn make_operand_list(operands: &str) -> operand_enum::OperandList {
    let packed = operand_enum::parse_operands_text(operands)
        .as_deref()
        .and_then(operand_enum::PackedOps::from_list);
    match packed {
        Some(p) => {
            debug_assert_eq!(
                p.to_text(),
                operands,
                "packed round-trip broke on '{}'",
                operands
            );
            operand_enum::OperandList::Packed(p)
        }
        None => operand_enum::OperandList::Text(operand_enum::intern_text_local(operands)),
    }
}

fn decode_range_with(
    formatter: &mut IntelFormatter,
    arch: &str,
    code: &[u8],
    base_addr: u64,
    out: &mut Vec<DisasmInstruction>,
) {
    let mut interner = Interner::new();
    let mut mnemonic = String::with_capacity(16);
    let mut full = String::with_capacity(64);

    walk_valid(arch, code, base_addr, |insn, bytes| {
        mnemonic.clear();
        full.clear();
        formatter.format_mnemonic(insn, &mut mnemonic);
        formatter.format(insn, &mut full);
        let operands = full
            .strip_prefix(mnemonic.as_str())
            .map(|s| s.trim_start_matches(' '))
            .unwrap_or_default();
        out.push(DisasmInstruction {
            address: insn.ip(),
            bytes: InsnBytes::from_slice(bytes),
            mnemonic: interner.take(&mnemonic),
            operands: make_operand_list(operands),
        });
        true
    });
}

const PATCH_LOOKBEHIND: usize = 16;
const PATCH_LOOKAHEAD: usize = 64;

pub fn rebuild_after_patch(
    binary: &ParsedBinary,
    old: &DisasmResult,
    patched_ranges: &[(usize, usize)],
) -> DisasmResult {
    rebuild_after_patch_with_affected(binary, old, patched_ranges).0
}

fn find_resync(
    window: &[DisasmInstruction],
    old: &[DisasmInstruction],
    from: u64,
    to: u64,
) -> Option<u64> {
    window
        .iter()
        .filter(|n| n.address >= from && n.address < to)
        .find(|n| {
            old.binary_search_by_key(&n.address, |o| o.address)
                .is_ok_and(|idx| old[idx].bytes == n.bytes && old[idx].mnemonic == n.mnemonic)
        })
        .map(|n| n.address)
}

pub fn rebuild_after_patch_with_affected(
    binary: &ParsedBinary,
    old: &DisasmResult,
    patched_ranges: &[(usize, usize)],
) -> (DisasmResult, Vec<u64>) {
    if supported_arch(&binary.arch).is_err() {
        return (
            DisasmResult {
                instructions: Arc::clone(&old.instructions),
                arch: binary.arch.clone(),
            },
            Vec::new(),
        );
    }
    let align = insn_align(&binary.arch);
    let old_insns: &[DisasmInstruction] = &old.instructions;
    let mut new_insns: Vec<DisasmInstruction> = Vec::with_capacity(old_insns.len() + 64);
    let mut affected: Vec<u64> = Vec::new();

    for sec in binary.sections.iter() {
        if !sec.is_executable {
            continue;
        }
        let sec_file_start = sec.offset as usize;
        let sec_file_end = sec_file_start
            .saturating_add(sec.size as usize)
            .min(binary.data.len());
        let sec_vaddr_end = sec.vaddr.saturating_add(sec.size);
        let sec_old = addr_range(old_insns, sec.vaddr, sec_vaddr_end);

        if sec_file_start >= sec_file_end {
            new_insns.extend_from_slice(sec_old);
            continue;
        }

        let mut min_off = usize::MAX;
        let mut max_end = 0usize;
        for &(off, len) in patched_ranges {
            let p_end = off.saturating_add(len);
            if off < sec_file_end && sec_file_start < p_end {
                min_off = min_off.min(off.max(sec_file_start));
                max_end = max_end.max(p_end.min(sec_file_end));
            }
        }
        if min_off == usize::MAX || max_end <= min_off {
            new_insns.extend_from_slice(sec_old);
            continue;
        }

        let sec_len = sec_file_end - sec_file_start;
        let lookbehind =
            min_off.saturating_sub(PATCH_LOOKBEHIND).max(sec_file_start) - sec_file_start;
        let mut rel_start = lookbehind - lookbehind % align;

        let naive_start = sec.vaddr.saturating_add(rel_start as u64);
        let k = sec_old.partition_point(|o| o.address < naive_start);
        if k > 0 && insn_end(&sec_old[k - 1]) > naive_start {
            rel_start = (sec_old[k - 1].address - sec.vaddr) as usize;
        }

        let w_start = sec.vaddr.saturating_add(rel_start as u64);
        let patch_end_vaddr = sec.vaddr.saturating_add((max_end - sec_file_start) as u64);

        let mut look = PATCH_LOOKAHEAD;
        let (window_insns, w_end, resync) = loop {
            let mut rel_end = max_end.saturating_add(look).min(sec_file_end) - sec_file_start;
            rel_end = (rel_end.div_ceil(align) * align).min(sec_len);
            let rel_end = rel_end.max(rel_start);
            let w_end = sec.vaddr.saturating_add(rel_end as u64);
            let window = decode_section(
                &binary.arch,
                &binary.data[sec_file_start + rel_start..sec_file_start + rel_end],
                w_start,
            );
            let resync = find_resync(&window, sec_old, patch_end_vaddr, w_end);
            if resync.is_some() || rel_end >= sec_len {
                break (window, w_end, resync);
            }
            look = look.saturating_mul(4);
        };

        let tail_start = resync.unwrap_or(w_end);
        let tail_lo = sec_old.partition_point(|o| o.address < tail_start);
        let head_hi = sec_old.partition_point(|o| o.address < w_start);

        new_insns.extend(
            sec_old[..head_hi]
                .iter()
                .filter(|o| insn_end(o) <= w_start)
                .cloned(),
        );
        for n in window_insns {
            if n.address >= tail_start {
                break;
            }
            affected.push(n.address);
            new_insns.push(n);
        }
        new_insns.extend_from_slice(&sec_old[tail_lo..]);
        affected.extend(
            sec_old[..tail_lo]
                .iter()
                .filter(|o| insn_end(o) > w_start)
                .map(|o| o.address),
        );
    }
    let _conflicts = dedup_instructions(&mut new_insns);
    affected.sort_unstable();
    affected.dedup();
    (
        DisasmResult {
            instructions: Arc::new(new_insns),
            arch: binary.arch.clone(),
        },
        affected,
    )
}

#[allow(dead_code)]
pub fn peek_mnemonic(arch: &str, data: &[u8], addr: u64) -> Option<String> {
    let mut decoder = make_decoder(arch, data, addr)?;
    if !decoder.can_decode() {
        return None;
    }
    let insn = decoder.decode();
    if insn.code() == Code::INVALID {
        return None;
    }
    let mut out = String::new();
    CACHED_FORMATTER.with(|f| f.borrow_mut().format_mnemonic(&insn, &mut out));
    Some(out)
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    fn mk(addr: u64, byte: u8, mn: &'static str) -> DisasmInstruction {
        DisasmInstruction {
            address: addr,
            bytes: InsnBytes::from_slice(&[byte]),
            mnemonic: mn,
            operands: operand_enum::OperandList::Text(Arc::from("")),
        }
    }

    #[test]
    fn intern_mnemonic_is_process_wide() {
        let a = intern_mnemonic("zz_test_mnemonic");
        let b = intern_mnemonic("zz_test_mnemonic");
        assert_eq!(a, "zz_test_mnemonic");
        assert!(std::ptr::eq(a.as_ptr(), b.as_ptr()));
        let other = std::thread::spawn(|| intern_mnemonic("zz_test_mnemonic").as_ptr() as usize)
            .join()
            .unwrap();
        assert_eq!(a.as_ptr() as usize, other);
        let mut i = Interner::new();
        assert!(std::ptr::eq(
            i.take("zz_test_mnemonic").as_ptr(),
            a.as_ptr()
        ));
    }

    #[test]
    fn dedup_fast_path_and_conflicts() {
        let mut v = vec![mk(1, 0x90, "nop"), mk(2, 0x90, "nop"), mk(3, 0x90, "nop")];
        assert_eq!(dedup_instructions(&mut v), 0);
        assert_eq!(v.len(), 3);

        let mut v = vec![
            mk(3, 0x90, "nop"),
            mk(1, 0x90, "nop"),
            mk(1, 0xc3, "ret"),
            mk(2, 0x90, "nop"),
            mk(1, 0x90, "nop"),
        ];
        let conflicts = dedup_instructions(&mut v);
        assert_eq!(conflicts, 1);
        assert_eq!(
            v.iter().map(|i| i.address).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(v[0].mnemonic, "nop", "first occurrence wins");
    }

    #[test]
    fn addr_range_is_half_open() {
        let v: Vec<_> = (0..10u64).map(|i| mk(i * 4, 0x90, "nop")).collect();
        let got: Vec<u64> = addr_range(&v, 8, 20).iter().map(|i| i.address).collect();
        assert_eq!(got, vec![8, 12, 16]);
        assert!(addr_range(&v, 100, 200).is_empty());
        assert!(addr_range(&v, 20, 8).is_empty());
    }

    #[test]
    fn find_resync_requires_identical_old_instruction() {
        let old = vec![mk(0, 0x90, "nop"), mk(1, 0x90, "nop"), mk(2, 0xc3, "ret")];
        let window = vec![mk(0, 0xcc, "int3"), mk(1, 0x90, "nop"), mk(2, 0xc3, "ret")];
        assert_eq!(find_resync(&window, &old, 0, 10), Some(1));
        assert_eq!(find_resync(&window, &old, 2, 10), Some(2));
        assert_eq!(find_resync(&window, &old, 0, 1), None);
        assert_eq!(find_resync(&window[..1], &old, 0, 10), None);
    }

    #[test]
    fn insn_align_by_arch() {
        assert_eq!(insn_align("aarch64"), 4);
        assert_eq!(insn_align("x86_64"), 1);
        assert_eq!(insn_align("x86"), 1);
    }

    #[test]
    fn x86_region_decodes_with_cached_formatter() {
        let code = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        for _ in 0..2 {
            let out = disassemble_region(&code, 0x1000, "x86_64").unwrap();
            let got: Vec<(u64, &str)> = out.iter().map(|i| (i.address, i.mnemonic)).collect();
            assert_eq!(
                got,
                vec![
                    (0x1000, "push"),
                    (0x1001, "mov"),
                    (0x1004, "pop"),
                    (0x1005, "ret")
                ]
            );
        }
    }

    #[test]
    fn x86_32_region_decodes() {
        let code = [0x55, 0x89, 0xe5, 0x5d, 0xc3];
        let out = disassemble_region(&code, 0x1000, "x86").unwrap();
        let got: Vec<(u64, &str)> = out.iter().map(|i| (i.address, i.mnemonic)).collect();
        assert_eq!(
            got,
            vec![
                (0x1000, "push"),
                (0x1001, "mov"),
                (0x1003, "pop"),
                (0x1004, "ret")
            ]
        );
    }

    #[test]
    fn unsupported_arch_never_panics() {
        assert!(decode_section("riscv64", &[0x13, 0, 0, 0], 0).is_empty());
        assert!(disassemble_region(&[0x90], 0, "riscv64").is_err());
        assert_eq!(peek_mnemonic("riscv64", &[0x90], 0), None);
    }

    #[test]
    fn peek_mnemonic_does_not_panic_on_aarch64() {
        assert_eq!(peek_mnemonic("aarch64", &[0u8; 4], 0), None);
        assert_eq!(peek_mnemonic("x86_64", &[0xc3], 0).as_deref(), Some("ret"));
    }
}
