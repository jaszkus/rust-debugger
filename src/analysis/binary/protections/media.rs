use super::{Category, Finding, Severity, Source};

use crate::parser::ParsedBinary;

pub fn detect_media(bin: &ParsedBinary) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for sec in &bin.sections {
        if sec.is_executable || !sec.initialized {
            continue;
        }
        let s = sec.offset as usize;
        let e = s.saturating_add(sec.size as usize).min(bin.data.len());
        if e > s {
            ranges.push((s, e));
        }
    }
    if let Some((off, size)) = bin.overlay {
        let s = off as usize;
        let e = s.saturating_add(size as usize).min(bin.data.len());
        if e > s {
            ranges.push((s, e));
        }
    }
    if ranges.is_empty() {
        ranges.push((0, bin.data.len()));
    }
    let mut seen: rustc_hash::FxHashSet<&'static str> = rustc_hash::FxHashSet::default();
    for (s, e) in ranges {
        let data = &bin.data[s..e];
        let checks: &[(&'static str, &[u8], &str)] = &[
            ("gif", b"GIF87a", "GIF image"),
            ("gif", b"GIF89a", "GIF image"),
            ("png", b"\x89PNG\r\n\x1a\n", "PNG image"),
            ("jpeg", b"\xFF\xD8\xFF", "JPEG image"),
            ("wave", b"RIFF", "WAVE/AVI (RIFF) media"),
            ("bmp", b"BM", "BMP image"),
        ];
        for (id, magic, desc) in checks {
            if memchr::memmem::find(data, magic).is_some() && seen.insert(id) {
                out.push(Finding {
                    category: Category::Media,
                    severity: Severity::Info,
                    id,
                    description: format!("{} magic found in non-executable data", desc),
                    address: None,
                    evidence: None,
                    source: Source::StaticSignature,
                    confidence: 1.0,
                });
            }
        }
        if memchr::memmem::find(data, b"MThd").is_some() && seen.insert("midi") {
            out.push(Finding {
                category: Category::Media,
                severity: Severity::Info,
                id: "midi",
                description: "MIDI (MThd) data found in non-executable data".into(),
                address: None,
                evidence: None,
                source: Source::StaticSignature,
                confidence: 1.0,
            });
        }
    }
    out
}
