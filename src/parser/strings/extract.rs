use super::string_model;
use crate::parser::model::{ExtractedString, Section, StringEncoding};

fn is_printable_ascii(b: u8) -> bool {
    (0x20..0x7f).contains(&b)
}

type Candidate = (u64, String, Option<f64>);

fn extract_ascii(data: &[u8], min_len: usize) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut run_start = 0usize;
    let mut run_len = 0usize;
    let flush = |start: usize, len: usize, out: &mut Vec<Candidate>| {
        if len >= min_len {
            let run = &data[start..start + len];
            if let Some(sc) = string_model::score_probable(run) {
                out.push((
                    start as u64,
                    String::from_utf8_lossy(run).into_owned(),
                    Some(sc),
                ));
            }
        }
    };
    for (i, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
        } else {
            flush(run_start, run_len, &mut out);
            run_len = 0;
        }
    }
    flush(run_start, run_len, &mut out);
    out
}

fn extract_utf16le(data: &[u8], min_len: usize) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut i = 0;

    while i + 1 < data.len() {
        if i + 3 < data.len() && data[i] == 0xFF && data[i + 1] == 0xFE {
            let start = i;
            i += 2;
            let mut current = String::new();
            while i + 1 < data.len() {
                let lo = data[i] as u16;
                let hi = data[i + 1] as u16;
                let code_unit = lo | (hi << 8);
                if code_unit == 0 {
                    break;
                }
                if (0x20..0x7F).contains(&code_unit) {
                    current.push(code_unit as u8 as char);
                } else if code_unit >= 0x80 {
                    if let Some(c) = char::from_u32(code_unit as u32) {
                        current.push(c);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
                i += 2;
            }
            if current.chars().count() >= min_len {
                out.push((start as u64, current, None));
            }
        } else {
            let lo = data[i] as u16;
            let hi = data[i + 1] as u16;
            let code_unit = lo | (hi << 8);
            if (0x20..0x7F).contains(&code_unit) && hi == 0 {
                let start = i;
                let mut current = String::new();
                let mut consecutive_ascii = 0usize;
                while i + 1 < data.len() {
                    let lo = data[i] as u16;
                    let hi = data[i + 1] as u16;
                    let cu = lo | (hi << 8);
                    if cu == 0 {
                        break;
                    }
                    if (0x20..0x7F).contains(&cu) {
                        current.push(cu as u8 as char);
                        consecutive_ascii += 1;
                        i += 2;
                    } else if cu >= 0x80 && hi != 0 {
                        if let Some(c) = char::from_u32(cu as u32) {
                            current.push(c);
                            i += 2;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if consecutive_ascii >= min_len {
                    out.push((start as u64, current, None));
                }
            } else {
                i += 1;
            }
        }
    }
    out
}

fn extract_utf32(data: &[u8], min_len: usize) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= data.len() {
        let le = data[i + 1] == 0
            && data[i + 2] == 0
            && data[i + 3] == 0
            && data[i] >= 0x20
            && data[i] < 0x7F;
        let be = data[i] == 0
            && data[i + 1] == 0
            && data[i + 2] == 0
            && data[i + 3] >= 0x20
            && data[i + 3] < 0x7F;
        if le || be {
            let start = i;
            let mut current = String::new();
            if le {
                while i + 4 <= data.len()
                    && data[i + 1] == 0
                    && data[i + 2] == 0
                    && data[i + 3] == 0
                    && data[i] >= 0x20
                    && data[i] < 0x7F
                {
                    current.push(data[i] as char);
                    i += 4;
                }
            } else {
                while i + 4 <= data.len()
                    && data[i] == 0
                    && data[i + 1] == 0
                    && data[i + 2] == 0
                    && data[i + 3] >= 0x20
                    && data[i + 3] < 0x7F
                {
                    current.push(data[i + 3] as char);
                    i += 4;
                }
            }
            if current.len() >= min_len {
                out.push((start as u64, current, None));
            }
        } else {
            i += 1;
        }
    }
    out
}

fn extract_pascal(data: &[u8], min_len: usize) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len < min_len || len > 255 || i + 1 + len > data.len() {
            i += 1;
            continue;
        }
        let first = data[i + 1];
        if !(0x20..0x7f).contains(&first) {
            i += 1;
            continue;
        }
        let last = data[i + len];
        if !(0x20..0x7f).contains(&last) {
            i += 1;
            continue;
        }
        {
            let body = &data[i + 1..i + 1 + len];
            if body.iter().all(|&b| (0x20..0x7F).contains(&b)) {
                let after = i + 1 + len;
                let terminated = after >= data.len() || data[after] == 0 || data[after] < 0x20;
                if terminated
                    && let Some(sc) = string_model::score_probable(body)
                        && let Ok(s) = std::str::from_utf8(body) {
                            out.push((i as u64, s.to_string(), Some(sc)));
                            i = after;
                            continue;
                        }
            }
        }
        i += 1;
    }
    out
}

fn build_offset_index(sections: &[Section]) -> Vec<&Section> {
    let mut v: Vec<&Section> = sections
        .iter()
        .filter(|s| s.initialized && s.vaddr != 0 && s.size != 0)
        .collect();
    v.sort_by_key(|s| s.offset);
    v
}

fn offset_to_vaddr_sorted(offset: u64, sorted: &[&Section]) -> Option<u64> {
    let lo = sorted.partition_point(|s| s.offset <= offset);
    for sec in sorted[..lo].iter().rev().take(8) {
        if offset < sec.offset.saturating_add(sec.size) {
            return Some(sec.vaddr.wrapping_add(offset - sec.offset));
        }
    }
    None
}

const MAX_STRINGS: usize = 1_000_000;

pub fn extract_all_strings(
    data: &[u8],
    sections: &[Section],
    min_len: usize,
) -> Vec<ExtractedString> {
    fn convert(
        src: Vec<Candidate>,
        encoding: StringEncoding,
        idx: &[&Section],
        out: &mut Vec<ExtractedString>,
    ) {
        for (off, content, pre) in src {
            if out.len() >= MAX_STRINGS {
                break;
            }
            let vaddr = match offset_to_vaddr_sorted(off, idx) {
                Some(v) => v,
                None if idx.is_empty() => off,
                None => continue,
            };
            let score = match pre {
                Some(sc) => sc,
                None => match string_model::score_probable(content.as_bytes()) {
                    Some(sc) => sc,
                    None => continue,
                },
            };
            out.push(ExtractedString {
                vaddr,
                content,
                encoding,
                score,
            });
        }
    }

    const PAR_FLOOR: usize = 64 * 1024;
    let idx = build_offset_index(sections);
    let mut out: Vec<ExtractedString> = Vec::new();
    if data.len() >= PAR_FLOOR {
        let ((a, b), (c, d)) = crate::util::parallel::install(|| {
            rayon::join(
                || {
                    rayon::join(
                        || extract_ascii(data, min_len),
                        || extract_utf16le(data, min_len),
                    )
                },
                || {
                    rayon::join(
                        || extract_utf32(data, min_len),
                        || extract_pascal(data, min_len),
                    )
                },
            )
        });
        convert(a, StringEncoding::Ascii, &idx, &mut out);
        convert(b, StringEncoding::Utf16Le, &idx, &mut out);
        convert(c, StringEncoding::Utf32Le, &idx, &mut out);
        convert(d, StringEncoding::Pascal, &idx, &mut out);
        out.sort_by_key(|s| s.vaddr);
        if out.len() > MAX_STRINGS {
            out.truncate(MAX_STRINGS);
        }
        return out;
    }

    convert(
        extract_ascii(data, min_len),
        StringEncoding::Ascii,
        &idx,
        &mut out,
    );
    convert(
        extract_utf16le(data, min_len),
        StringEncoding::Utf16Le,
        &idx,
        &mut out,
    );
    convert(
        extract_utf32(data, min_len),
        StringEncoding::Utf32Le,
        &idx,
        &mut out,
    );
    convert(
        extract_pascal(data, min_len),
        StringEncoding::Pascal,
        &idx,
        &mut out,
    );

    out.sort_by_key(|s| s.vaddr);
    if out.len() > MAX_STRINGS {
        out.truncate(MAX_STRINGS);
    }
    out
}

pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<(u64, String)> {
    extract_ascii(data, min_len)
        .into_iter()
        .map(|(off, s, _)| (off, s))
        .collect()
}
