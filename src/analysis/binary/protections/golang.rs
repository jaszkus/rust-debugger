use super::{Category, Finding, Severity, Source};

use crate::parser::ParsedBinary;

pub fn golang_version(data: &[u8]) -> Option<String> {
    for i in 0..data.len().saturating_sub(4) {
        if &data[i..i + 4] == b"go1." {
            let mut end = i + 4;
            while end < data.len()
                && end - i < 16
                && (data[end].is_ascii_alphanumeric() || data[end] == b'.')
            {
                end += 1;
            }
            if end > i + 4
                && let Ok(v) = std::str::from_utf8(&data[i..end]) {
                    return Some(v.to_string());
                }
        }
    }
    None
}

pub fn detect_golang(bin: &ParsedBinary) -> Vec<Finding> {
    let mut out = Vec::new();
    let has_pclntab = bin.data.windows(6).any(|w| {
        w[0] == 0xFB && w[1] == 0xFF && w[2] == 0xFF && w[3] == 0xFF && w[4] == 0x00 && w[5] == 0x00
    });
    let ver = golang_version(&bin.data);
    if has_pclntab {
        let exec: Vec<(u64, u64)> = bin
            .sections
            .iter()
            .filter(|s| s.is_executable && s.size > 0)
            .map(|s| (s.vaddr, s.vaddr.saturating_add(s.size)))
            .collect();
        let nfuncs = if exec.is_empty() {
            0
        } else {
            crate::analysis::golang::pclntab_functions(&bin.data, &exec).len()
        };
        out.push(Finding {
            category: Category::Golang,
            severity: Severity::Info,
            id: "gopclntab",
            description: format!(
                "Go pclntab present — Go-compiled binary, {} functions recoverable",
                nfuncs
            ),
            address: None,
            evidence: ver.clone(),
            source: Source::StaticSignature,
            confidence: 1.0,
        });
    }
    if let Some(v) = ver
        && !has_pclntab {
            out.push(Finding {
                category: Category::Golang,
                severity: Severity::Info,
                id: "go_buildinfo",
                description: format!("Go build version string {} found", v),
                address: None,
                evidence: Some(v),
                source: Source::Heuristic,
                confidence: 0.9,
            });
        }
    if !out.is_empty() {
        return out;
    }
    for needle in ["runtime.throw", "runtime.fatalpanic", "gopanic"] {
        if memchr::memmem::find(&bin.data, needle.as_bytes()).is_some() {
            out.push(Finding {
                category: Category::Golang,
                severity: Severity::Low,
                id: "go_runtime_string",
                description: format!("Go runtime string {:?} — likely Go binary", needle),
                address: None,
                evidence: None,
                source: Source::Heuristic,
                confidence: 0.6,
            });
            break;
        }
    }
    out
}
