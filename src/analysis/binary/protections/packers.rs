use super::{Category, Finding, Severity, Source};

use crate::parser::ParsedBinary;

const PACKER_SECTIONS: &[(&str, &str, Severity)] = &[
    ("UPX0", "UPX", Severity::High),
    ("UPX1", "UPX", Severity::High),
    ("UPX2", "UPX", Severity::High),
    (".aspack", "ASPack", Severity::High),
    (".adata", "ASPack/Armadillo", Severity::Medium),
    (".pack", "Generic packer", Severity::Medium),
    (".themida", "Themida", Severity::High),
    ("Themida", "Themida", Severity::High),
    (".vmp0", "VMProtect", Severity::High),
    (".vmp1", "VMProtect", Severity::High),
    (".vmp2", "VMProtect", Severity::High),
    (".enigma1", "Enigma", Severity::High),
    (".enigma2", "Enigma", Severity::High),
    ("WinLicen", "WinLicense", Severity::High),
    (".petite", "Petite", Severity::High),
    ("pebundle", "PEBundle", Severity::High),
    (".MPRESS1", "MPRESS", Severity::High),
    (".MPRESS2", "MPRESS", Severity::High),
    (".RLPack", "RLPack", Severity::High),
    ("nsp0", "NsPack", Severity::High),
    ("nsp1", "NsPack", Severity::High),
    ("nsp2", "NsPack", Severity::High),
    (".ndata", "NSIS / Nullsoft data", Severity::Low),
    ("MEW", "MEW", Severity::High),
    ("PEC2", "PECompact 2", Severity::High),
    (".pec1", "PECompact 1", Severity::High),
    (".pec2", "PECompact 2", Severity::High),
    (".y0da", "yoda's crypter", Severity::High),
    (".yP", "yoda's protector", Severity::High),
    (".boom", "BOOM", Severity::High),
    ("BitArts", "BitArts protector", Severity::High),
    (
        "byfron",
        "Byfron Hyperion (Roblox anti-cheat)",
        Severity::High,
    ),
    (
        "tempest",
        "Tempest/Hyperion (Roblox anti-cheat)",
        Severity::High,
    ),
    (".tvm0", "Themida VM sections", Severity::High),
    (".tvm1", "Themida VM sections", Severity::High),
    (".them", "Themida", Severity::High),
    (".denuvo", "Denuvo Anti-Tamper", Severity::High),
    (".didata", "VMProtect/Denuvo data section", Severity::Medium),
    (".upx", "UPX", Severity::High),
    (".aspack_", "ASPack", Severity::High),
    (".ack", "ASPack variant", Severity::Medium),
    (".morrigan", "Morrigan crypter", Severity::High),
    (".perplex", "Perplexus protector", Severity::High),
    (".sedll", "StarForce / SE protected", Severity::High),
    (".sforce", "StarForce", Severity::High),
];

pub fn detect_packers(bin: &ParsedBinary) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: rustc_hash::FxHashSet<&str> = rustc_hash::FxHashSet::default();

    for sec in &bin.sections {
        for (sname, packer, sev) in PACKER_SECTIONS {
            fn norm(s: &str) -> &str {
                s.trim_start_matches('.')
            }
            let n = norm(&sec.name);
            let sn = norm(sname);
            let hit = n.eq_ignore_ascii_case(sn)
                || (n.len() > sn.len()
                    && !sn.starts_with("UPX")
                    && n.get(..sn.len())
                        .map(|p| p.eq_ignore_ascii_case(sn))
                        .unwrap_or(false));
            if hit && seen.insert(packer) {
                out.push(Finding {
                    category: Category::Packer,
                    severity: *sev,
                    id: sname,
                    description: format!("Section name {:?} indicates {}", sec.name, packer),
                    address: Some(sec.vaddr),
                    evidence: Some(format!("section: {}", sec.name)),
                    source: Source::StaticSignature,
                    confidence: 1.0,
                });
            }
        }
    }

    if bin.format == "PE" && bin.imports.len() < 5 && bin.data.len() > 64 * 1024 {
        out.push(Finding {
            category: Category::Packer,
            severity: Severity::Medium,
            id: "tiny_iat",
            description: format!(
                "Only {} imported APIs in a {}-byte PE — IAT likely rebuilt at runtime (packer)",
                bin.imports.len(),
                bin.data.len()
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.75,
        });
    }

    if let Some(sec) = bin
        .sections
        .iter()
        .filter(|s| s.is_executable)
        .max_by_key(|s| s.size)
    {
        let so = sec.offset as usize;
        let se = (so + sec.size as usize).min(bin.data.len());
        if se > so + 1024 {
            let e = entropy(&bin.data[so..se]);
            if e > 7.5 {
                out.push(Finding {
                    category: Category::Packer,
                    severity: Severity::High,
                    id: "high_entropy",
                    description: format!(
                        "Section {:?} entropy = {:.2} bits/byte (very high — likely packed/encrypted)",
                        sec.name, e
                    ),
                    address: Some(sec.vaddr),
                    evidence: Some(format!("entropy={:.2}", e)),
                    source: Source::Heuristic,
                    confidence: 0.8,
                });
            } else if e > 6.8 {
                out.push(Finding {
                    category: Category::Packer,
                    severity: Severity::Low,
                    id: "elevated_entropy",
                    description: format!(
                        "Section {:?} entropy = {:.2} bits/byte (elevated — possibly compressed)",
                        sec.name, e
                    ),
                    address: Some(sec.vaddr),
                    evidence: Some(format!("entropy={:.2}", e)),
                    source: Source::Heuristic,
                    confidence: 0.6,
                });
            }
        }
    }

    out
}

pub(crate) fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for f in freq.iter().copied() {
        if f > 0 {
            let p = f as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}
