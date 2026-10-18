use super::{Category, Finding, Severity, Source};

use crate::parser::ParsedBinary;

pub fn detect_dotnet(bin: &ParsedBinary) -> Vec<Finding> {
    let mut out = Vec::new();
    if !bin.format.starts_with("PE") {
        return out;
    }
    let has_mscoree = bin
        .imports
        .iter()
        .any(|i| i.library.eq_ignore_ascii_case("mscoree.dll"));
    if has_mscoree {
        out.push(Finding {
            category: Category::DotNet,
            severity: Severity::High,
            id: "mscoree_import",
            description:
                "Imports mscoree.dll — this is a managed .NET assembly, not native x86/x64".into(),
            address: None,
            evidence: Some(
                bin.imports
                    .iter()
                    .find(|i| i.library.eq_ignore_ascii_case("mscoree.dll"))
                    .map(|i| format!("{}!{}", i.library, i.name))
                    .unwrap_or_else(|| "mscoree.dll".into()),
            ),
            source: Source::StaticSignature,
            confidence: 1.0,
        });
    }
    if memchr::memmem::find(&bin.data, b"BSJB").is_some() {
        out.push(Finding {
            category: Category::DotNet,
            severity: Severity::Info,
            id: "bsjb_signature",
            description: "BSJB metadata-root signature present — managed assembly".into(),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.9,
        });
    }
    out
}
