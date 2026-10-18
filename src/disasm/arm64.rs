use std::borrow::Cow;
use std::fmt::Write as _;
use std::sync::Arc;

use rayon::prelude::*;
use rustc_hash::FxHashMap;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::InstDecoder;

use super::operand_enum::{intern_text_local, OperandList};
use super::x86::Interner;
use super::{DisasmInstruction, InsnBytes};

const PAR_MIN_BYTES: usize = 512 * 1024;
const PAR_CHUNK_BYTES: usize = 128 * 1024;

pub fn decode_section_arm64(code: &[u8], base_vaddr: u64) -> Vec<DisasmInstruction> {
    let whole = code.len() - code.len() % 4;
    let code = &code[..whole];

    if whole >= PAR_MIN_BYTES && crate::util::parallel::workers() >= 2 {
        let parts: Vec<Vec<DisasmInstruction>> = crate::util::parallel::install(|| {
            code.par_chunks(PAR_CHUNK_BYTES)
                .enumerate()
                .map(|(n, chunk)| {
                    decode_chunk(chunk, base_vaddr.wrapping_add((n * PAR_CHUNK_BYTES) as u64))
                })
                .collect()
        });
        let total: usize = parts.iter().map(Vec::len).sum();
        let mut out = Vec::with_capacity(total);
        for mut part in parts {
            out.append(&mut part);
        }
        return out;
    }
    decode_chunk(code, base_vaddr)
}

fn decode_chunk(code: &[u8], base_vaddr: u64) -> Vec<DisasmInstruction> {
    debug_assert_eq!(code.len() % 4, 0);
    let decoder = InstDecoder::default();
    let mut out = Vec::with_capacity(code.len() / 4);
    let mut interner = Interner::new();
    let mut mnem_cache: FxHashMap<String, &'static str> = FxHashMap::default();
    let mut full = String::with_capacity(64);
    let mut ops = String::with_capacity(64);

    for (n, word) in code.as_chunks::<4>().0.iter().enumerate() {
        let addr = base_vaddr.wrapping_add((n as u64) * 4);
        full.clear();
        ops.clear();
        let mut rewritten = false;

        let mnemonic: &'static str = match decoder.decode(&mut U8Reader::new(word)) {
            Ok(insn) => {
                let _ = write!(full, "{}", insn);
                let (raw, rest) = split_mnemonic(&full);
                rewritten = rewrite_pcrel_into(rest, pcrel_base(raw, addr), &mut ops);
                mapped_mnemonic(&mut mnem_cache, &mut interner, raw)
            }
            Err(_) => {
                let w = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                let _ = write!(ops, "{:#x}", w);
                interner.take(".word")
            }
        };

        let text: Arc<str> = if rewritten {
            Arc::from(ops.as_str())
        } else {
            intern_text_local(&ops)
        };

        out.push(DisasmInstruction {
            address: addr,
            bytes: InsnBytes::from_slice(word),
            mnemonic,
            operands: OperandList::Text(text),
        });
    }
    out
}

#[inline]
fn split_mnemonic(full: &str) -> (&str, &str) {
    match full.find(' ') {
        Some(p) => (&full[..p], &full[p + 1..]),
        None => (full, ""),
    }
}

#[inline]
fn pcrel_base(raw_mnemonic: &str, addr: u64) -> u64 {
    if raw_mnemonic == "adrp" {
        addr & !0xfff
    } else {
        addr
    }
}

#[inline]
fn mapped_mnemonic(
    cache: &mut FxHashMap<String, &'static str>,
    interner: &mut Interner,
    raw: &str,
) -> &'static str {
    if let Some(m) = cache.get(raw) {
        return m;
    }
    let mapped = interner.take(&map_mnemonic(raw));
    cache.insert(raw.to_string(), mapped);
    mapped
}

fn map_mnemonic(m: &str) -> Cow<'static, str> {
    let fixed: &'static str = match m {
        "b" | "br" | "braa" | "brab" | "braaz" | "brabz" => "jmp",
        "bl" | "blr" | "blraa" | "blrab" | "blraaz" | "blrabz" => "call",
        "ret" | "retaa" | "retab" => "ret",
        "adr" | "adrp" => "lea",
        "cbz" | "tbz" => "jz",
        "cbnz" | "tbnz" => "jnz",
        other => {
            return match other.strip_prefix("b.") {
                Some(cond) => Cow::Owned(format!("j{}", bcond_suffix(cond))),
                None => Cow::Owned(other.to_string()),
            };
        }
    };
    Cow::Borrowed(fixed)
}

fn bcond_suffix(cond: &str) -> &str {
    match cond {
        "eq" => "e",
        "ne" => "ne",
        "hs" | "cs" => "ae",
        "lo" | "cc" => "b",
        "mi" => "s",
        "pl" => "ns",
        "vs" => "o",
        "vc" => "no",
        "hi" => "a",
        "ls" => "be",
        "ge" => "ge",
        "lt" => "l",
        "gt" => "g",
        "le" => "le",
        "al" | "nv" => "mp",
        other => other,
    }
}

fn rewrite_pcrel_into(s: &str, base: u64, out: &mut String) -> bool {
    let b = s.as_bytes();
    let mut rewritten = false;
    let mut last = 0usize;
    let mut i = 0usize;
    while let Some(rel) = b[i..].iter().position(|&c| c == b'$') {
        let d = i + rel;
        if d + 2 < b.len() && (b[d + 1] == b'+' || b[d + 1] == b'-') {
            let neg = b[d + 1] == b'-';
            let mut p = d + 2;
            if p + 1 < b.len() && b[p] == b'0' && (b[p + 1] | 0x20) == b'x' {
                p += 2;
            }
            let mut j = p;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > p {
                let v = u64::from_str_radix(&s[p..j], 16).unwrap_or(0);
                let target = if neg {
                    base.wrapping_sub(v)
                } else {
                    base.wrapping_add(v)
                };
                out.push_str(&s[last..d]);
                let _ = write!(out, "{:#x}", target);
                last = j;
                i = j;
                rewritten = true;
                continue;
            }
        }
        i = d + 1;
    }
    out.push_str(&s[last..]);
    rewritten
}

#[cfg(test)]
fn rewrite_pcrel(s: &str, addr: u64) -> String {
    let mut out = String::new();
    rewrite_pcrel_into(s, addr, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bl_maps_to_call_with_absolute_target() {
        let code = 0x94000009u32.to_le_bytes();
        let out = decode_section_arm64(&code, 0x400000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mnemonic, "call");
        assert_eq!(out[0].ops(), "0x400024");
    }

    #[test]
    fn branch_family_maps_and_resolves_targets() {
        let code: Vec<u8> = [0x14000002u32, 0x54000040u32, 0xb4000140u32]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let out = decode_section_arm64(&code, 0x1000);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].mnemonic, "jmp");
        assert_eq!(out[0].ops(), "0x1008");
        assert!(
            out[1].mnemonic.starts_with('j'),
            "b.eq → jcc, got {}",
            out[1].mnemonic
        );
        assert_eq!(out[2].mnemonic, "jz");
        assert!(
            out[2].ops().ends_with("0x1030"),
            "cbz target absolute: {}",
            out[2].ops()
        );
    }

    #[test]
    fn aliases_and_word_fallback() {
        let mut code: Vec<u8> = [0xd2800840u32]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        code.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        let out = decode_section_arm64(&code, 0x2000);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].mnemonic, "mov");
        assert_eq!(out[1].mnemonic, ".word");
        assert_eq!(out[1].address, 0x2004);
    }

    #[test]
    fn br_maps_to_jmp() {
        let code = 0xd61f0200u32.to_le_bytes();
        let out = decode_section_arm64(&code, 0x1000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mnemonic, "jmp");
        assert!(out[0].ops().contains("x16"), "got {}", out[0].ops());
    }

    #[test]
    fn map_mnemonic_table() {
        for (raw, want) in [
            ("b", "jmp"),
            ("br", "jmp"),
            ("braa", "jmp"),
            ("bl", "call"),
            ("blr", "call"),
            ("retaa", "ret"),
            ("adr", "lea"),
            ("adrp", "lea"),
            ("cbz", "jz"),
            ("tbnz", "jnz"),
            ("b.eq", "je"),
            ("b.lo", "jb"),
            ("b.al", "jmp"),
            ("ldr", "ldr"),
        ] {
            assert_eq!(map_mnemonic(raw), want, "raw={raw}");
        }
    }

    #[test]
    fn adrp_uses_page_base() {
        assert_eq!(pcrel_base("adrp", 0x400abc), 0x400000);
        assert_eq!(pcrel_base("adr", 0x400abc), 0x400abc);
        let code = 0xb0000000u32.to_le_bytes();
        let out = decode_section_arm64(&code, 0x400abc);
        assert_eq!(out[0].mnemonic, "lea");
        assert!(out[0].ops().ends_with("0x401000"), "got {}", out[0].ops());
    }

    #[test]
    fn rewrite_pcrel_handles_plus_minus() {
        assert_eq!(rewrite_pcrel("$+0x10", 0x4000), "0x4010");
        assert_eq!(rewrite_pcrel("$-0x40", 0x4000), "0x3fc0");
        assert_eq!(rewrite_pcrel("x0, [x1, #8]", 0x4000), "x0, [x1, #8]");
        assert_eq!(
            rewrite_pcrel("adrp x0, $+0x123000", 0x400000),
            "adrp x0, 0x523000"
        );
    }

    #[test]
    fn rewrite_pcrel_edge_cases() {
        assert_eq!(
            rewrite_pcrel("a, $+0x4, b, $-0x4", 0x100),
            "a, 0x104, b, 0xfc"
        );
        assert_eq!(rewrite_pcrel("$", 0x100), "$");
        assert_eq!(rewrite_pcrel("$+", 0x100), "$+");
        assert_eq!(rewrite_pcrel("$+zz", 0x100), "$+zz");
        assert_eq!(rewrite_pcrel("$-0x10", 0x8), "0xfffffffffffffff8");
        let mut out = String::new();
        assert!(rewrite_pcrel_into("x0, $+0x8", 0, &mut out));
        out.clear();
        assert!(!rewrite_pcrel_into("x0, [sp, #8]", 0, &mut out));
    }

    #[test]
    fn bcond_suffix_table() {
        assert_eq!(bcond_suffix("eq"), "e");
        assert_eq!(bcond_suffix("ne"), "ne");
        assert_eq!(bcond_suffix("hs"), "ae");
        assert_eq!(bcond_suffix("lo"), "b");
        assert_eq!(bcond_suffix("gt"), "g");
    }

    #[test]
    fn mnemonics_are_interned_across_calls() {
        let code = 0x94000009u32.to_le_bytes();
        let a = decode_section_arm64(&code, 0x1000);
        let b = decode_section_arm64(&code, 0x9000);
        assert!(std::ptr::eq(a[0].mnemonic.as_ptr(), b[0].mnemonic.as_ptr()));
    }

    #[test]
    fn chunked_decode_matches_serial() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let words = PAR_MIN_BYTES / 4 + 1000;
        let mut code = Vec::with_capacity(words * 4 + 3);
        for _ in 0..words {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            code.extend_from_slice(&(x as u32).to_le_bytes());
        }
        let aligned_len = code.len();
        code.extend_from_slice(&[1, 2, 3]);
        let a = decode_section_arm64(&code, 0x10_0000);
        let b = decode_chunk(&code[..aligned_len], 0x10_0000);
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), words);
        for (p, q) in a.iter().zip(&b) {
            assert_eq!(p.address, q.address);
            assert_eq!(p.bytes_slice(), q.bytes_slice());
            assert_eq!(p.mnemonic, q.mnemonic);
            assert_eq!(p.ops(), q.ops());
        }
    }
}
