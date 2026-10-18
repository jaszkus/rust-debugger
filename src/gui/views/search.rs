use super::utils::contains_ci;

pub fn perform_search(state: &mut crate::gui::state::AppState) {
    state.search_results = match state.binary.as_ref() {
        Some(binary) => search_snapshot(
            &state.search_query,
            state.search_kind,
            binary,
            state.analysis.as_deref(),
        ),
        None => Vec::new(),
    };
}
pub fn search_snapshot(
    query: &str,
    kind: usize,
    bin: &crate::parser::ParsedBinary,
    analysis: Option<&crate::analysis::AnalysisResult>,
) -> Vec<crate::gui::state::SearchResult> {
    use crate::gui::state::{SearchKind, SearchResult};
    let raw_query = query.trim();
    let explicit_hex = raw_query.strip_prefix("hex:");
    let q = explicit_hex.unwrap_or(raw_query).trim().to_lowercase();
    let empty_q = q.is_empty();
    let mut results = Vec::new();
    let push = |results: &mut Vec<SearchResult>, r| {
        if results.len() < 5000 {
            results.push(r);
        }
    };
    if kind == 0 || kind == 1 {
        for s in &bin.strings {
            if results.len() >= 5000 {
                break;
            }
            if empty_q || contains_ci(&s.content, &q) {
                let preview: String = s.content.chars().take(80).collect();
                let enc = match s.encoding {
                    crate::parser::StringEncoding::Ascii => "A",
                    crate::parser::StringEncoding::Utf16Le => "U16",
                    crate::parser::StringEncoding::Utf32Le => "U32",
                    crate::parser::StringEncoding::Pascal => "P",
                };
                push(
                    &mut results,
                    SearchResult {
                        addr: s.vaddr,
                        label: format!("[{enc}] \"{preview}\""),
                        kind: SearchKind::String,
                    },
                );
            }
        }
    }
    let q_hex = q.chars().all(|c| c.is_ascii_hexdigit());
    if (kind == 0 || kind == 2) && results.len() < 5000 {
        if let Some(a) = analysis {
            for f in &a.functions {
                if results.len() >= 5000 {
                    break;
                }
                if empty_q
                    || contains_ci(&f.name, &q)
                    || (q_hex && q.len() <= 16 && format!("{:x}", f.entry).contains(&q))
                {
                    push(
                        &mut results,
                        SearchResult {
                            addr: f.entry,
                            label: f.name.clone(),
                            kind: SearchKind::Function,
                        },
                    );
                }
            }
        }
    }
    if kind == 0 || kind == 3 {
        for s in &bin.symbols {
            if results.len() >= 5000 {
                break;
            }
            if empty_q || contains_ci(&s.name, &q) {
                push(
                    &mut results,
                    SearchResult {
                        addr: s.addr,
                        label: s.name.clone(),
                        kind: SearchKind::Symbol,
                    },
                );
            }
        }
    }
    if kind == 0 || kind == 4 {
        for i in &bin.imports {
            if results.len() >= 5000 {
                break;
            }
            if empty_q || contains_ci(&i.name, &q) || contains_ci(&i.library, &q) {
                push(
                    &mut results,
                    SearchResult {
                        addr: i.offset,
                        label: format!("{}!{}", i.library, i.name),
                        kind: SearchKind::Import,
                    },
                );
            }
        }
    }
    if !empty_q && (kind == 5 || explicit_hex.is_some()) {
        let bytes: Vec<u8> = q
            .split_whitespace()
            .filter_map(|t| u8::from_str_radix(t, 16).ok())
            .collect();
        let clean: String = q.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let bytes2: Vec<u8> = (0..clean.len() / 2)
            .filter_map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
            .collect();
        let needle = if q.split_whitespace().all(|t| t.len() == 2) {
            bytes
        } else {
            bytes2
        };
        if needle.len() >= 2 {
            let data = &bin.data[..];
            let mut i = 0;
            let mut hits = 0;
            while i + needle.len() <= data.len() {
                if &data[i..i + needle.len()] == needle.as_slice() {
                    let mut vaddr = i as u64;
                    for sec in &bin.sections {
                        let off = i as u64;
                        if off >= sec.offset && off < sec.offset + sec.size {
                            vaddr = sec.vaddr + (off - sec.offset);
                            break;
                        }
                    }
                    push(
                        &mut results,
                        SearchResult {
                            addr: vaddr,
                            label: format!("[hex match @ file+{i:#x}]"),
                            kind: SearchKind::Hex,
                        },
                    );
                    hits += 1;
                    if hits >= 500 {
                        break;
                    }
                }
                i += 1;
            }
        }
    }
    results
}
