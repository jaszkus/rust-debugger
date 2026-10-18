use crate::analysis::types::{canonical_reg, parse_operand, split_operands, Operand};
use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashMap as HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuncHash {
    pub full: u64,
    pub specific: u64,
    pub insn_count: u32,
}

#[derive(Debug, Clone)]
pub struct FidMatch {
    pub name: String,
    pub library: String,
    pub score: f64,
    pub full: u64,
    pub specific: u64,
    pub size: usize,
}

pub const SCORE_THRESHOLD: f64 = 8.0;

#[derive(Debug, Clone)]
pub struct RelocMask {
    sorted: Vec<u64>,
}

impl RelocMask {
    pub fn new(relocs: &[crate::parser::Relocation]) -> Self {
        let mut sorted: Vec<u64> = relocs.iter().map(|r| r.va).collect();
        sorted.sort_unstable();
        sorted.dedup();
        Self { sorted }
    }

    pub fn is_empty(&self) -> bool {
        self.sorted.is_empty()
    }

    pub fn covers(&self, lo: u64, hi: u64) -> bool {
        if hi <= lo {
            return false;
        }
        let start = self.sorted.partition_point(|&v| v.wrapping_add(8) <= lo);
        self.sorted[start..]
            .iter()
            .take_while(|&&v| v < hi)
            .any(|&v| v.wrapping_add(8) > lo)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FunctionIDMatcher {
    signatures: HashMap<u64, FunctionSignature>,
    by_specific: HashMap<u64, Vec<u64>>,
    reloc_mask: Option<RelocMask>,
}

#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub hash: u64,
    pub specific: u64,
    pub name: String,
    pub library: String,
    pub size: usize,
    pub score: f64,
}

fn fnv(h: u64, b: u8) -> u64 {
    (h ^ b as u64).wrapping_mul(0x100000001b3)
}

fn fnv_str(mut h: u64, s: &str) -> u64 {
    for b in s.as_bytes() {
        h = fnv(h, *b);
    }
    h
}

fn is_padding_insn(insn: &DisasmInstruction) -> bool {
    insn.mnem() == "nop" || insn.mnem() == "int3" || insn.bytes.iter().all(|&b| b == 0x00)
}

const PLACEHOLDER: [u8; 4] = 0xfeeddeadu32.to_le_bytes();

fn hash_placeholder(s: u64) -> u64 {
    PLACEHOLDER.iter().fold(s, |h, &b| fnv(h, b))
}

fn hash_one(
    full: u64,
    specific: u64,
    insn: &DisasmInstruction,
    mask: Option<&RelocMask>,
) -> (u64, u64) {
    let relocated = mask.is_some_and(|m| {
        !m.is_empty()
            && m.covers(
                insn.address,
                insn.address.wrapping_add(insn.bytes.len() as u64),
            )
    });
    let mut f = fnv_str(full, insn.mnemonic);
    let mut s = fnv_str(specific, insn.mnemonic);
    f = fnv(f, 0xFF);
    s = fnv(s, 0xFF);
    for op in split_operands(&insn.ops()) {
        match parse_operand(&op) {
            Operand::Reg(r) => {
                f = fnv_str(f, "R");
                s = fnv_str(s, canonical_reg(r));
            }
            Operand::Imm(v) => {
                f = fnv_str(f, "I");
                s = fnv_str(s, "I");
                if relocated {
                    s = hash_placeholder(s);
                } else {
                    for b in v.to_le_bytes() {
                        s = fnv(s, b);
                    }
                }
            }
            Operand::Addr(a) => {
                f = fnv_str(f, "A");
                s = fnv_str(s, "A");
                if relocated {
                    s = hash_placeholder(s);
                } else {
                    for b in (a & 0xFFF).to_le_bytes() {
                        s = fnv(s, b);
                    }
                }
            }
            Operand::Mem {
                base,
                index,
                scale,
                disp,
                size,
            } => {
                f = fnv_str(f, "M");
                f = fnv(f, if base.is_some() { b'b' } else { b'0' });
                f = fnv(f, if index.is_some() { b'i' } else { b'0' });
                for b in scale.to_le_bytes() {
                    f = fnv(f, b);
                }
                for b in size.to_le_bytes() {
                    f = fnv(f, b);
                }
                s = fnv_str(s, "M");
                if let Some(b) = base.as_ref() {
                    s = fnv_str(s, canonical_reg(b));
                }
                s = fnv(s, b':');
                if let Some(i) = index.as_ref() {
                    s = fnv_str(s, canonical_reg(i));
                }
                s = fnv(s, b':');
                for b in scale.to_le_bytes() {
                    s = fnv(s, b);
                }
                s = fnv(s, b':');
                if relocated {
                    s = hash_placeholder(s);
                } else {
                    for b in disp.to_le_bytes() {
                        s = fnv(s, b);
                    }
                }
                s = fnv(s, b':');
                for b in size.to_le_bytes() {
                    s = fnv(s, b);
                }
            }
            Operand::Unknown(t) => {
                f = fnv_str(f, "?");
                s = fnv_str(s, &t);
            }
        }
        f = fnv(f, 0xFE);
        s = fnv(s, 0xFE);
    }
    (f, s)
}

pub fn hash_range(insns: &[DisasmInstruction]) -> FuncHash {
    hash_range_with_mask(insns, None)
}

pub fn hash_range_with_mask(insns: &[DisasmInstruction], mask: Option<&RelocMask>) -> FuncHash {
    let mut full: u64 = 0xcbf29ce484222325;
    let mut specific: u64 = 0xcbf29ce484222325;
    let mut count = 0u32;
    for insn in insns.iter().take(4096) {
        if is_padding_insn(insn) {
            continue;
        }
        let (f, s) = hash_one(full, specific, insn, mask);
        full = f;
        specific = s;
        count += 1;
    }
    for b in count.to_le_bytes() {
        full = fnv(full, b);
        specific = fnv(specific, b);
    }
    FuncHash {
        full,
        specific,
        insn_count: count,
    }
}

impl FunctionIDMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_reloc_mask(&mut self, relocs: &[crate::parser::Relocation]) {
        self.reloc_mask = Some(RelocMask::new(relocs));
    }

    pub fn merge(&mut self, other: &FunctionIDMatcher) {
        let mut touched: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::default();
        for (k, sig) in &other.signatures {
            self.by_specific.entry(sig.specific).or_default().push(*k);
            touched.insert(sig.specific);
            self.signatures.insert(*k, sig.clone());
        }
        for t in touched {
            if let Some(v) = self.by_specific.get_mut(&t) {
                v.sort_unstable();
                v.dedup();
            }
        }
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn signatures_iter(&self) -> impl Iterator<Item = &FunctionSignature> {
        self.signatures.values()
    }

    #[allow(dead_code)]
    pub fn match_function(
        &self,
        insns: &[DisasmInstruction],
        entry: usize,
    ) -> Option<&FunctionSignature> {
        let h = hash_range(insns.get(entry..).unwrap_or(&[]));
        if let Some(sig) = self.signatures.get(&h.full) {
            return Some(sig);
        }
        self.by_specific
            .get(&h.specific)
            .and_then(|keys| {
                keys.iter()
                    .filter_map(|k| self.signatures.get(k))
                    .map(|sig| (score_key(h.insn_count as usize, sig), sig))
                    .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            })
            .map(|(_, sig)| sig)
    }

    #[allow(dead_code)]
    pub fn add_signature(&mut self, hash: u64, name: String, library: String, size: usize) {
        self.insert(FunctionSignature {
            hash,
            specific: hash,
            name,
            library,
            size,
            score: 0.0,
        });
    }

    pub fn insert(&mut self, sig: FunctionSignature) {
        self.by_specific
            .entry(sig.specific)
            .or_default()
            .push(sig.hash);
        self.signatures.insert(sig.hash, sig);
    }

    fn score_body(&self, h: FuncHash) -> Option<(f64, &FunctionSignature)> {
        let body_len = h.insn_count as usize;
        if let Some(sig) = self.signatures.get(&h.full) {
            let mx = body_len.max(sig.size).max(1) as f64;
            let diff = body_len.abs_diff(sig.size) as f64;
            if diff / mx <= 0.75 {
                let mut score = 10.0;
                score += size_bonus(body_len, sig.size);
                return Some((score, sig));
            }
        }
        if let Some(keys) = self.by_specific.get(&h.specific) {
            let mut best: Option<(f64, &FunctionSignature)> = None;
            for k in keys {
                if let Some(sig) = self.signatures.get(k) {
                    let score = 6.0 + size_bonus(body_len, sig.size);
                    if best.is_none_or(|(bs, _)| score > bs) {
                        best = Some((score, sig));
                    }
                }
            }
            if let Some((score, sig)) = best {
                return Some((score, sig));
            }
        }
        None
    }

    pub fn identify_with_context(
        &self,
        insns: &[DisasmInstruction],
        bodies: &[(u64, u64)],
        callers: &HashMap<u64, Vec<u64>>,
        callees: &HashMap<u64, Vec<u64>>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> HashMap<u64, FidMatch> {
        let mut first: HashMap<u64, (f64, FunctionSignature, FuncHash, usize)> = HashMap::default();
        let mask = self.reloc_mask.as_ref();
        if bodies.len() >= crate::util::parallel::PAR_FUNCS {
            use rayon::prelude::*;
            let partials: Vec<(u64, (f64, FunctionSignature, FuncHash, usize))> =
                crate::util::parallel::install(|| {
                    bodies
                        .par_iter()
                        .filter_map(|(entry, end)| {
                            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            {
                                return None;
                            }
                            let s_idx = insns.partition_point(|i| i.address < *entry);
                            let e_idx = insns.partition_point(|i| i.address < *end);
                            if s_idx >= e_idx || s_idx >= insns.len() {
                                return None;
                            }
                            let h = hash_range_with_mask(&insns[s_idx..e_idx], mask);
                            self.score_body(h).map(|(score, sig)| {
                                (*entry, (score, sig.clone(), h, h.insn_count as usize))
                            })
                        })
                        .collect()
                });
            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                return HashMap::default();
            }
            for (k, v) in partials {
                first.insert(k, v);
            }
        } else {
            for (bi, (entry, end)) in bodies.iter().enumerate() {
                if bi % 256 == 0
                    && cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                {
                    return HashMap::default();
                }
                let s_idx = insns.partition_point(|i| i.address < *entry);
                let e_idx = insns.partition_point(|i| i.address < *end);
                if s_idx >= e_idx || s_idx >= insns.len() {
                    continue;
                }
                let h = hash_range_with_mask(&insns[s_idx..e_idx], mask);
                if let Some((score, sig)) = self.score_body(h) {
                    first.insert(*entry, (score, sig.clone(), h, h.insn_count as usize));
                }
            }
        }
        let mut out = HashMap::default();
        let matched: rustc_hash::FxHashSet<u64> = first.keys().copied().collect();
        let mut entries: Vec<u64> = matched.iter().copied().collect();
        entries.sort_unstable();
        for entry in entries {
            let (mut score, sig, h, body_len) = match first.remove(&entry) {
                Some(v) => v,
                None => continue,
            };
            let mut bonus = 0u32;
            if let Some(cs) = callers.get(&entry) {
                bonus += cs.iter().filter(|c| matched.contains(c)).count() as u32;
            }
            if let Some(cs) = callees.get(&entry) {
                bonus += cs.iter().filter(|c| matched.contains(c)).count() as u32;
            }
            score += (bonus.min(4) as f64) * 1.0;
            if score >= SCORE_THRESHOLD {
                out.insert(
                    entry,
                    FidMatch {
                        name: sig.name.clone(),
                        library: sig.library.clone(),
                        score,
                        full: h.full,
                        specific: h.specific,
                        size: body_len,
                    },
                );
            }
        }
        out
    }

    pub fn ingest_functions(
        &mut self,
        insns: &[DisasmInstruction],
        functions: &[(u64, u64, String)],
        library: &str,
    ) -> usize {
        let mask = self.reloc_mask.clone();
        let mask = mask.as_ref();
        let mut added = 0usize;
        for (entry, end, name) in functions {
            if name.starts_with("sub_") || name == "entry" {
                continue;
            }
            let s_idx = insns.partition_point(|i| i.address < *entry);
            let e_idx = insns.partition_point(|i| i.address < *end);
            if s_idx >= e_idx || s_idx >= insns.len() {
                continue;
            }
            let h = hash_range_with_mask(&insns[s_idx..e_idx], mask);
            if h.insn_count < 4 || self.signatures.contains_key(&h.full) {
                continue;
            }
            self.insert(FunctionSignature {
                hash: h.full,
                specific: h.specific,
                name: name.clone(),
                library: library.to_string(),
                size: h.insn_count as usize,
                score: 0.0,
            });
            added += 1;
        }
        added
    }

    pub fn export_db(&self, path: &std::path::Path) -> Result<usize, String> {
        let sigs: Vec<serde_json::Value> = self
            .signatures
            .values()
            .map(|s| {
                serde_json::json!({
                    "full": format!("{:016x}", s.hash),
                    "specific": format!("{:016x}", s.specific),
                    "name": s.name,
                    "library": s.library,
                    "size": s.size,
                })
            })
            .collect();
        let doc = serde_json::json!({ "fidb_version": 1, "signatures": sigs });
        let text =
            serde_json::to_string_pretty(&doc).map_err(|e| format!("fidb serialize: {}", e))?;
        std::fs::write(path, text).map_err(|e| format!("fidb write {}: {}", path.display(), e))?;
        Ok(sigs.len())
    }

    pub fn import_db(&mut self, path: &std::path::Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("fidb read {}: {}", path.display(), e))?;
        let doc: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("fidb parse: {}", e))?;
        if doc.get("fidb_version").and_then(|v| v.as_u64()) != Some(1) {
            return Err("fidb: unsupported fidb_version (want 1)".into());
        }
        let arr = doc
            .get("signatures")
            .and_then(|v| v.as_array())
            .ok_or("fidb: missing signatures[]")?;
        let mut added = 0usize;
        for s in arr {
            let full = s
                .get("full")
                .and_then(|v| v.as_str())
                .and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok());
            let specific = s
                .get("specific")
                .and_then(|v| v.as_str())
                .and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok());
            let (Some(full), Some(specific)) = (full, specific) else {
                continue;
            };
            let name = s
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let library = s
                .get("library")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let size = s.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            if self.signatures.contains_key(&full) {
                continue;
            }
            self.insert(FunctionSignature {
                hash: full,
                specific,
                name,
                library,
                size,
                score: 0.0,
            });
            added += 1;
        }
        Ok(added)
    }
}

fn size_bonus(body_len: usize, sig_size: usize) -> f64 {
    let mx = body_len.max(sig_size).max(1) as f64;
    let diff = body_len.abs_diff(sig_size) as f64;
    2.0 * (1.0 - diff / mx)
}

#[allow(dead_code)]
fn score_key(body_len: usize, sig: &FunctionSignature) -> f64 {
    size_bonus(body_len, sig.size)
}
