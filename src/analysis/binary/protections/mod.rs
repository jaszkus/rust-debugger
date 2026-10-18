use crate::disasm::DisasmResult;
use crate::parser::ParsedBinary;
mod antidbg;
mod crypto;
mod dotnet;
mod golang;
mod media;
mod obfuscation;
mod objc;
mod packers;

pub use antidbg::{detect_anti_debug, detect_anti_vm};
pub use crypto::detect_crypto;
pub use dotnet::detect_dotnet;
pub use golang::{detect_golang, golang_version};
pub use media::detect_media;
pub use obfuscation::detect_obfuscation;
pub use objc::detect_objc_swift;
pub use packers::detect_packers;

#[cfg(test)]
pub(crate) use antidbg::string_hit_confidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    StaticSignature,
    Heuristic,
    Import,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::StaticSignature => "static_signature",
            Source::Heuristic => "heuristic",
            Source::Import => "import",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub id: &'static str,
    pub description: String,
    pub address: Option<u64>,
    pub evidence: Option<String>,
    pub source: Source,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    AntiDebug,
    AntiVm,
    Packer,
    Obfuscation,
    DotNet,
    Crypto,
    Golang,
    Media,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::AntiDebug => "anti_debug",
            Category::AntiVm => "anti_vm",
            Category::Packer => "packer",
            Category::Obfuscation => "obfuscation",
            Category::DotNet => "dotnet",
            Category::Crypto => "crypto",
            Category::Golang => "golang",
            Category::Media => "media",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtectionsReport {
    pub findings: Vec<Finding>,
}

pub fn detect_all(bin: &ParsedBinary, disasm: &DisasmResult) -> ProtectionsReport {
    let (ab, (pack_obf, (dot_cry, (golang, med_objc)))) = crate::util::parallel::install(|| {
        rayon::join(
            || {
                rayon::join(
                    || detect_anti_debug(bin, disasm),
                    || detect_anti_vm(bin, disasm),
                )
            },
            || {
                rayon::join(
                    || rayon::join(|| detect_packers(bin), || detect_obfuscation(disasm)),
                    || {
                        rayon::join(
                            || rayon::join(|| detect_dotnet(bin), || detect_crypto(bin)),
                            || {
                                rayon::join(
                                    || detect_golang(bin),
                                    || rayon::join(|| detect_media(bin), || detect_objc_swift(bin)),
                                )
                            },
                        )
                    },
                )
            },
        )
    });
    let (anti_debug, anti_vm) = ab;
    let (packers, obfuscation) = pack_obf;
    let (dotnet, crypto) = dot_cry;
    let (media, objc) = med_objc;
    let mut findings = Vec::new();
    findings.extend(anti_debug);
    findings.extend(anti_vm);
    findings.extend(packers);
    findings.extend(obfuscation);
    findings.extend(dotnet);
    findings.extend(crypto);
    findings.extend(golang);
    findings.extend(media);
    findings.extend(objc);
    ProtectionsReport { findings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Import, Section};

    fn f(source: Source, confidence: f64) -> Finding {
        Finding {
            category: Category::AntiDebug,
            severity: Severity::Medium,
            id: "test",
            description: "test finding".into(),
            address: None,
            evidence: None,
            source,
            confidence,
        }
    }

    fn pe_bin(sections: Vec<Section>, imports: usize, data: Vec<u8>) -> ParsedBinary {
        ParsedBinary {
            format: "PE".into(),
            arch: "x86_64".into(),
            entry_point: 0x140001000,
            sections,
            symbols: Vec::new(),
            imports: vec![
                Import {
                    name: "x".into(),
                    library: "k".into(),
                    offset: 0
                };
                imports
            ],
            exports: Vec::new(),
            strings: Vec::new(),
            data: std::sync::Arc::new(data),
            image_base: 0x140000000,
            is_dll: false,
            pe_characteristics: 0,
            dll_characteristics: 0,
            overlay: None,
            tls_callbacks: Vec::new(),
            delay_imports: Vec::new(),
            has_rich: false,
            libraries: Vec::new(),
            rpaths: Vec::new(),
            macho_uuid: None,
            relocations: Vec::new(),
        }
    }

    #[test]
    fn source_as_str_values() {
        assert_eq!(Source::StaticSignature.as_str(), "static_signature");
        assert_eq!(Source::Heuristic.as_str(), "heuristic");
        assert_eq!(Source::Import.as_str(), "import");
    }

    #[test]
    fn string_hit_confidence_tracks_specificity() {
        assert!(string_hit_confidence(Severity::High) > string_hit_confidence(Severity::Medium));
        assert!(string_hit_confidence(Severity::Medium) > string_hit_confidence(Severity::Low));
        assert!(string_hit_confidence(Severity::Low) > string_hit_confidence(Severity::Info));
    }

    #[test]
    fn confidence_is_bounded() {
        for c in [0.0f64, 0.5, 1.0] {
            assert!((0.0..=1.0).contains(&f(Source::Heuristic, c).confidence));
        }
    }

    #[test]
    fn packer_section_hits_are_static_full_confidence() {
        let bin = pe_bin(
            vec![Section {
                name: ".vmp0".into(),
                vaddr: 0x140001000,
                size: 0x1000,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            }],
            10,
            vec![0u8; 0x40000],
        );
        let findings = detect_packers(&bin);
        assert!(!findings.is_empty(), "vmp0 section must be detected");
        assert!(findings
            .iter()
            .all(|fd| fd.source == Source::StaticSignature && fd.confidence == 1.0));
    }

    #[test]
    fn high_entropy_is_heuristic_below_full_confidence() {
        let data: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(1103515245).wrapping_add(12345) >> 16) as u8)
            .collect();
        let bin = pe_bin(
            vec![Section {
                name: ".text".into(),
                vaddr: 0x140001000,
                size: data.len() as u64,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            }],
            10,
            data,
        );
        let findings = detect_packers(&bin);
        let he = findings.iter().find(|fd| fd.id == "high_entropy");
        let he = he.expect("high-entropy section must be detected");
        assert_eq!(he.source, Source::Heuristic);
        assert!(he.confidence < 1.0 && he.confidence >= 0.5);
    }

    #[test]
    fn format_finding_includes_provenance() {
        let v = crate::mcp::tools::format::finding(&f(Source::StaticSignature, 1.0));
        assert_eq!(v["source"], "static_signature");
        assert_eq!(v["confidence"], 1.0);
        let v = crate::mcp::tools::format::finding(&f(Source::Heuristic, 0.7));
        assert_eq!(v["source"], "heuristic");
        assert_eq!(v["confidence"], 0.7);
    }
}
