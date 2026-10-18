use super::{Category, Finding, Severity, Source};

use crate::parser::ParsedBinary;

pub fn detect_objc_swift(bin: &ParsedBinary) -> Vec<Finding> {
    let mut out = Vec::new();
    if bin.sections.iter().any(|s| s.name.contains("__objc")) {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::Info,
            id: "objc_section",
            description: "Objective-C section (__objc_*) present — ObjC runtime metadata".into(),
            address: None,
            evidence: None,
            source: Source::StaticSignature,
            confidence: 1.0,
        });
    }
    let has_objc_msg = bin.strings.iter().any(|s| {
        (s.content.starts_with("-(") || s.content.starts_with("+(") || s.content.starts_with("-["))
            && s.content.contains(' ')
    });
    if has_objc_msg {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::Info,
            id: "objc_message",
            description: "Objective-C message-send string (-[/+[/-() — ObjC binary".into(),
            address: None,
            evidence: None,
            source: Source::StaticSignature,
            confidence: 0.9,
        });
    }
    if bin
        .symbols
        .iter()
        .any(|s| s.name.starts_with("$s") || s.name.starts_with("_T"))
    {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::Info,
            id: "swift_symbol",
            description: "Swift-mangled symbol ($s/_T) present — Swift binary".into(),
            address: None,
            evidence: None,
            source: Source::StaticSignature,
            confidence: 0.95,
        });
    }
    out
}
