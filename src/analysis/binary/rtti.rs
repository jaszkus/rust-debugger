use crate::parser::ParsedBinary;

#[derive(Debug, Clone)]
pub struct RttiClass {
    pub name: String,
    pub type_descriptor: u64,
    pub col: u64,
    pub vftable: Option<u64>,
    pub first_vfunc: Option<u64>,
}

struct Span {
    va: u64,
    off: usize,
    size: usize,
}

fn mapped_spans(bin: &ParsedBinary) -> Vec<Span> {
    bin.sections
        .iter()
        .filter_map(|s| {
            let off = s.offset as usize;
            let end = off.checked_add(s.size as usize)?;
            if off >= bin.data.len() || end > bin.data.len() {
                return None;
            }
            Some(Span {
                va: s.vaddr,
                off,
                size: end - off,
            })
        })
        .collect()
}

pub fn demangle_lite(raw: &str) -> String {
    let body = raw.strip_prefix(".?A").unwrap_or(raw);
    let body = match body.as_bytes().first() {
        Some(b'V') | Some(b'U') | Some(b'W') | Some(b'D') | Some(b'I') => &body[1..],
        _ => body,
    };
    let body = body.strip_suffix("@@").unwrap_or(body);
    if body.is_empty() {
        return raw.to_string();
    }
    let parts: Vec<&str> = body.split('@').filter(|p| !p.is_empty()).collect();
    parts.iter().rev().cloned().collect::<Vec<_>>().join("::")
}

fn find_type_descriptors(bin: &ParsedBinary) -> rustc_hash::FxHashMap<u64, String> {
    let mut by_rva: rustc_hash::FxHashMap<u64, String> = Default::default();
    let base = bin.image_base;
    for span in mapped_spans(bin) {
        if span.size < 24 {
            continue;
        }
        let d = &bin.data[span.off..span.off + span.size];
        let mut i = 16usize;
        while i + 5 <= span.size {
            if d[i] == b'.' && d[i + 1] == b'?' && d[i + 2] == b'A' {
                let mut j = i;
                while j < span.size && d[j] != 0 && j - i < 512 {
                    j += 1;
                }
                let ok_len = j > i + 3 && j - i < 512;
                let printable = ok_len && d[i..j].iter().all(|&b| (0x20..0x7f).contains(&b));
                if ok_len && printable {
                    let td_va = span.va + (i - 16) as u64;
                    by_rva.insert(
                        (td_va.wrapping_sub(base)) & 0xFFFF_FFFF,
                        String::from_utf8_lossy(&d[i..j]).into_owned(),
                    );
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
    }
    by_rva
}

pub fn scan_msvc_rtti(bin: &ParsedBinary) -> Vec<RttiClass> {
    use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

    let base = bin.image_base;
    let spans = mapped_spans(bin);
    if spans.is_empty() {
        return Vec::new();
    }

    let tds = find_type_descriptors(bin);
    if tds.is_empty() {
        return Vec::new();
    }
    let td_vas: HashSet<u64> = tds.keys().map(|rva| base.wrapping_add(*rva)).collect();

    let ptr_size: u64 = if bin.arch == "x86" { 4 } else { 8 };
    let is_x64 = ptr_size == 8;

    let mut cols: HashMap<u64, u64> = HashMap::default();
    'outer: for span in &spans {
        if span.size < 24 {
            continue;
        }
        let d = &bin.data[span.off..span.off + span.size];
        let mut i = 0usize;
        while i + 24 <= span.size {
            let sig = u32le(d, i);
            if sig != 0 && sig != 1 {
                i += 4;
                continue;
            }
            let col_va = span.va + i as u64;
            let col_rva = (col_va.wrapping_sub(base)) & 0xFFFF_FFFF;
            if is_x64 {
                let self_rva = u32le(d, i + 20);
                let td_rva = u32le(d, i + 12);
                if self_rva != col_rva as u32 {
                    i += 4;
                    continue;
                }
                if !tds.contains_key(&(td_rva as u64)) {
                    i += 4;
                    continue;
                }
                cols.insert(col_va, base + td_rva as u64);
            } else {
                let td_va = u32le(d, i + 12) as u64;
                if !td_vas.contains(&td_va) {
                    i += 4;
                    continue;
                }
                cols.insert(col_va, td_va);
            }
            i += 4;
        }
        if cols.len() > 200_000 {
            break 'outer;
        }
    }
    if cols.is_empty() {
        return Vec::new();
    }

    let mut vftables: HashMap<u64, Vec<u64>> = HashMap::default();
    let mut vt_count = 0usize;
    'sweep: for span in &spans {
        if span.size < ptr_size as usize {
            continue;
        }
        let d = &bin.data[span.off..span.off + span.size];
        let mut i = 0usize;
        while i + ptr_size as usize <= span.size {
            let v = if is_x64 {
                u64le(d, i)
            } else {
                u32le(d, i) as u64
            };
            if cols.contains_key(&v) {
                vftables
                    .entry(v)
                    .or_default()
                    .push(span.va + i as u64 + ptr_size);
                vt_count += 1;
                if vt_count > 400_000 {
                    break 'sweep;
                }
            }
            i += ptr_size as usize;
        }
    }

    let mut out: Vec<RttiClass> = Vec::with_capacity(cols.len());
    for (col_va, td_va) in &cols {
        let raw_name = tds
            .get(&(td_va.wrapping_sub(base) & 0xFFFF_FFFF))
            .cloned()
            .unwrap_or_default();
        let vts = vftables.get(col_va).cloned().unwrap_or_default();
        if vts.is_empty() {
            out.push(RttiClass {
                name: demangle_lite(&raw_name),
                type_descriptor: *td_va,
                col: *col_va,
                vftable: None,
                first_vfunc: None,
            });
            continue;
        }
        for vt in vts {
            let fv = lookup_ptr(bin, vt, ptr_size);
            out.push(RttiClass {
                name: demangle_lite(&raw_name),
                type_descriptor: *td_va,
                col: *col_va,
                vftable: Some(vt),
                first_vfunc: fv,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.vftable.cmp(&b.vftable)));
    out
}

fn lookup_ptr(bin: &ParsedBinary, va: u64, ptr_size: u64) -> Option<u64> {
    for s in &bin.sections {
        let start = s.offset as usize;
        let end = start.checked_add(s.size as usize)?;
        if va >= s.vaddr && va + ptr_size < s.vaddr + s.size {
            let off = start + (va - s.vaddr) as usize;
            if end < off + ptr_size as usize || off + ptr_size as usize > bin.data.len() {
                return None;
            }
            let d = &bin.data[off..off + ptr_size as usize];
            return Some(if ptr_size == 8 {
                u64le(d, 0)
            } else {
                u32le(d, 0) as u64
            });
        }
    }
    None
}

fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

pub fn scan_itanium_rtti(bin: &ParsedBinary) -> Vec<RttiClass> {
    use rustc_hash::FxHashMap as HashMap;
    let ptr_size: u64 = if bin.arch == "x86" { 4 } else { 8 };
    let mut tis: HashMap<String, (u64, u64)> = HashMap::default();
    let mut tvs: HashMap<String, u64> = HashMap::default();
    for sym in &bin.symbols {
        let n = sym.name.as_str();
        let (prefix, is_ti, is_ts, is_tv) = if n.starts_with("_ZTI") {
            ("_ZTI", true, false, false)
        } else if n.starts_with("_ZTS") {
            ("_ZTS", false, true, false)
        } else if n.starts_with("_ZTV") {
            ("_ZTV", false, false, true)
        } else {
            continue;
        };
        let _ = prefix;
        let readable = crate::analysis::symbols::demangle::demangle_name(n);
        if is_tv {
            tvs.entry(readable).or_insert(sym.addr);
        } else {
            let e = tis.entry(readable).or_insert((0, 0));
            if is_ti {
                e.0 = sym.addr;
            } else if is_ts {
                e.1 = sym.addr;
            }
        }
    }
    if tvs.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (name, vt_sym) in &tvs {
        let short = name.strip_prefix("vtable for ").unwrap_or(name).to_string();
        let ti = tis.get(name).or_else(|| tis.get(&short));
        let (td, col) = match ti {
            Some((zti, zts)) => (*zti.max(zts), *zti.max(zts)),
            None => (0, 0),
        };
        let vftable = vt_sym.wrapping_add(2 * ptr_size);
        let fv = lookup_ptr(bin, vftable, ptr_size);
        out.push(RttiClass {
            name: short,
            type_descriptor: td,
            col,
            vftable: Some(vftable),
            first_vfunc: fv,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}
fn u64le(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        d[o],
        d[o + 1],
        d[o + 2],
        d[o + 3],
        d[o + 4],
        d[o + 5],
        d[o + 6],
        d[o + 7],
    ])
}
