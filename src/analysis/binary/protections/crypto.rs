use super::{Category, Finding, Severity, Source};

use crate::parser::ParsedBinary;

fn le_seq(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub fn detect_crypto(bin: &ParsedBinary) -> Vec<Finding> {
    let mut out = Vec::new();
    let patterns: Vec<(&'static str, &'static str, Vec<u8>, f64)> = vec![
        (
            "md5_sha1_init",
            "MD5/SHA-1 init state (67452301 EFCDAB89 98BADCFE 10325476)",
            le_seq(&[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]),
            0.9,
        ),
        (
            "sha1_k",
            "SHA-1 round constants (5A827999 6ED9EBA1 8F1BBCDC CA62C1D6)",
            le_seq(&[0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]),
            0.9,
        ),
        (
            "sha256_h",
            "SHA-256 initial hash (6A09E667 BB67AE85 3C6EF372 A54FF53A)",
            le_seq(&[0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A]),
            0.9,
        ),
        (
            "sha256_k",
            "SHA-256 round constants (428A2F98 71374491 B5C0FBCF E9B5DBA5)",
            le_seq(&[0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5]),
            0.9,
        ),
        (
            "crc32_table",
            "CRC-32 table (00000000 77073096 EE0E612C 990951BA)",
            le_seq(&[0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA]),
            0.85,
        ),
        (
            "aes_sbox",
            "AES S-box (63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76)",
            vec![
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
                0xAB, 0x76,
            ],
            0.95,
        ),
        (
            "chacha_sigma",
            "ChaCha/Salsa20 constant \"expand 32-byte k\"",
            b"expand 32-byte k".to_vec(),
            0.95,
        ),
    ];

    let mut ranges: Vec<(usize, usize, u64)> = Vec::new();
    for sec in &bin.sections {
        if sec.is_executable || !sec.initialized {
            continue;
        }
        let st = sec.offset as usize;
        let en = st.saturating_add(sec.size as usize).min(bin.data.len());
        if en > st {
            ranges.push((st, en, sec.vaddr));
        }
    }
    if ranges.is_empty() {
        ranges.push((0, bin.data.len(), 0));
    }

    for (id, desc, pat, conf) in &patterns {
        'ranges: for &(st, en, va) in &ranges {
            let hay = &bin.data[st..en];
            let first = pat[0];
            let mut i = 0usize;
            while i + pat.len() <= hay.len() {
                if hay[i] == first && &hay[i..i + pat.len()] == pat.as_slice() {
                    out.push(Finding {
                        category: Category::Crypto,
                        severity: Severity::Medium,
                        id,
                        description: desc.to_string(),
                        address: Some(va.wrapping_add(i as u64)),
                        evidence: Some(format!("file_offset=0x{:x}", st + i)),
                        source: Source::Heuristic,
                        confidence: *conf,
                    });
                    break 'ranges;
                }
                i += 1;
            }
        }
    }
    out
}
