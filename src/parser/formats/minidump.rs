use crate::parser::{Export, ExtractedString, Import, ParsedBinary, Section, Symbol};

const MINIDUMP_MAGIC: u32 = 0x504D_444D;

const MEMORY64_LIST_STREAM: u32 = 9;
const MODULE_LIST_STREAM: u32 = 4;
const EXCEPTION_STREAM: u32 = 6;
const MEMORY_LIST_STREAM: u32 = 5;
const SYSTEM_INFO_STREAM: u32 = 7;
const MEMORY_INFO_LIST_STREAM: u32 = 16;

pub struct MinidumpRange {
    pub start_va: u64,
    pub size: u64,
    pub file_off: u64,
}

pub struct MinidumpModule {
    pub base: u64,
    pub size: u64,
    pub name: String,
}
pub struct MinidumpInfo {
    pub ranges: Vec<MinidumpRange>,
    pub modules: Vec<MinidumpModule>,
    pub exception_address: Option<u64>,
    pub machine: u16,
    pub mem_protect: Vec<(u64, u64, u32)>,
}

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64_at(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

pub fn parse_minidump(data: &[u8]) -> Result<MinidumpInfo, String> {
    if data.len() < 32 {
        return Err("File too small to be a minidump".into());
    }
    if u32_at(data, 0) != Some(MINIDUMP_MAGIC) {
        return Err("Not a minidump (missing MDMP signature)".into());
    }
    let n_streams = u32_at(data, 8).unwrap_or(0) as usize;
    let dir_rva = u32_at(data, 12).unwrap_or(0) as usize;
    if n_streams > 4096 || dir_rva.saturating_add(n_streams * 12) > data.len() {
        return Err(format!(
            "Corrupt minidump directory (streams={} dir_rva={:#x} size={:#x})",
            n_streams,
            dir_rva,
            data.len()
        ));
    }

    let mut info = MinidumpInfo {
        ranges: Vec::new(),
        modules: Vec::new(),
        exception_address: None,
        machine: 0x8664,
        mem_protect: Vec::new(),
    };

    for i in 0..n_streams {
        let e = dir_rva + i * 12;
        let stream_type = u32_at(data, e).unwrap_or(0);
        let stream_rva = u32_at(data, e + 8).unwrap_or(0) as usize;
        if stream_rva >= data.len() {
            continue;
        }
        match stream_type {
            MEMORY64_LIST_STREAM => {
                let n_ranges = u64_at(data, stream_rva).unwrap_or(0);
                let base_rva = u64_at(data, stream_rva + 8).unwrap_or(0);
                if n_ranges > 1_000_000
                    || base_rva as usize > data.len()
                    || stream_rva + 16 + n_ranges as usize * 16 > data.len()
                {
                    continue;
                }
                let mut file_off = base_rva;
                for r in 0..n_ranges as usize {
                    let desc = stream_rva + 16 + r * 16;
                    let start = u64_at(data, desc).unwrap_or(0);
                    let size = u64_at(data, desc + 8).unwrap_or(0);
                    if file_off.saturating_add(size) > data.len() as u64 {
                        break;
                    }
                    if size > 0 {
                        info.ranges.push(MinidumpRange {
                            start_va: start,
                            size,
                            file_off,
                        });
                    }
                    file_off += size;
                }
            }
            MODULE_LIST_STREAM => {
                let n_mods = u32_at(data, stream_rva).unwrap_or(0) as usize;
                if n_mods > 16384 {
                    continue;
                }
                for m in 0..n_mods {
                    let rec = stream_rva + 4 + m * 108;
                    if rec + 108 > data.len() {
                        break;
                    }
                    let base = u64_at(data, rec).unwrap_or(0);
                    let size = u32_at(data, rec + 8).unwrap_or(0) as u64;
                    let name_rva = u32_at(data, rec + 20).unwrap_or(0) as usize;
                    let mut name = String::new();
                    if name_rva + 4 <= data.len() {
                        let blen = u32_at(data, name_rva).unwrap_or(0) as usize;
                        let blen = blen.min(data.len().saturating_sub(name_rva + 4));
                        let units = blen / 2;
                        let mut wide = Vec::with_capacity(units);
                        for u in 0..units {
                            wide.push(u16_at(data, name_rva + 4 + u * 2).unwrap_or(0));
                        }
                        name = String::from_utf16_lossy(&wide);
                    }
                    if base != 0 {
                        info.modules.push(MinidumpModule { base, size, name });
                    }
                }
            }
            EXCEPTION_STREAM => {
                info.exception_address = u64_at(data, stream_rva + 0x18);
            }
            MEMORY_LIST_STREAM => {
                let n = u32_at(data, stream_rva).unwrap_or(0) as usize;
                if n > 1_000_000 {
                    continue;
                }
                for r in 0..n {
                    let desc = stream_rva + 4 + r * 16;
                    if desc + 16 > data.len() {
                        break;
                    }
                    let start = u64_at(data, desc).unwrap_or(0);
                    let size = u32_at(data, desc + 8).unwrap_or(0) as u64;
                    let rva = u32_at(data, desc + 12).unwrap_or(0) as u64;
                    if size == 0 || start == 0 {
                        continue;
                    }
                    if (rva as usize).saturating_add(size as usize) > data.len() {
                        continue;
                    }
                    info.ranges.push(MinidumpRange {
                        start_va: start,
                        size,
                        file_off: rva,
                    });
                }
            }
            SYSTEM_INFO_STREAM => {
                if let Some(arch) = u16_at(data, stream_rva) {
                    info.machine = match arch {
                        0 => 0x14c,
                        9 => 0x8664,
                        5 => 0x1c0,
                        12 => 0xaa64,
                        _ => arch,
                    };
                }
            }
            MEMORY_INFO_LIST_STREAM => {
                let hdr_sz = (u32_at(data, stream_rva).unwrap_or(16) as usize).max(16);
                let entry_sz = u32_at(data, stream_rva + 4).unwrap_or(0) as usize;
                let n = u64_at(data, stream_rva + 8).unwrap_or(0) as usize;
                if entry_sz < 48 || n > 1_000_000 {
                    continue;
                }
                for i in 0..n {
                    let rec = stream_rva + hdr_sz + i * entry_sz;
                    if rec + 48 > data.len() {
                        break;
                    }
                    let base = u64_at(data, rec).unwrap_or(0);
                    let _alloc_base = u64_at(data, rec + 8).unwrap_or(0);
                    let _alloc_prot = u32_at(data, rec + 16).unwrap_or(0);
                    let size = u64_at(data, rec + 24).unwrap_or(0);
                    let _state = u32_at(data, rec + 32).unwrap_or(0);
                    let protect = u32_at(data, rec + 36).unwrap_or(0);
                    let _type = u32_at(data, rec + 40).unwrap_or(0);
                    if base != 0 && size != 0 {
                        info.mem_protect.push((base, size, protect));
                    }
                }
            }
            _ => {}
        }
    }

    info.modules.sort_by_key(|m| m.base);
    info.mem_protect.sort_by_key(|e| e.0);
    info.ranges
        .sort_by_key(|r| (r.start_va, std::cmp::Reverse(r.size)));
    let mut kept: Vec<MinidumpRange> = Vec::with_capacity(info.ranges.len());
    let mut kept_end: u64 = 0;
    for r in info.ranges.drain(..) {
        let end = r.start_va.saturating_add(r.size);
        if !kept.is_empty() && end <= kept_end {
            continue;
        }
        kept_end = kept_end.max(end);
        kept.push(r);
    }
    info.ranges = kept;

    Ok(info)
}

pub fn parse_minidump_binary(data: Vec<u8>) -> Result<ParsedBinary, String> {
    let info = parse_minidump(&data)?;
    let dump_base = info.ranges.first().map(|r| r.start_va).unwrap_or(0);
    let arch = match info.machine {
        0x14c => "x86",
        0x8664 => "x86_64",
        0x1c0 => "arm",
        0xaa64 => "aarch64",
        _ => "x86_64",
    };

    let protect_of = |va: u64| -> Option<u32> {
        let i = info.mem_protect.partition_point(|e| e.0 <= va);
        let (base, size, prot) = *info.mem_protect.get(i.checked_sub(1)?)?;
        if va < base.saturating_add(size) {
            Some(prot)
        } else {
            None
        }
    };

    let mut sections: Vec<Section> = Vec::new();
    for (i, r) in info.ranges.iter().enumerate() {
        let prot = protect_of(r.start_va);
        let exec = prot.is_none_or(|p| (p & 0xF0) != 0);
        let writable = prot.is_none_or(|p| (p & 0xCC) != 0);
        let readable = prot.is_none_or(|p| (p & 0xFF) != 0x01);
        sections.push(Section {
            name: format!("mem{}", i),
            vaddr: r.start_va,
            size: r.size,
            offset: r.file_off,
            is_executable: exec,
            readable,
            writable,
            initialized: true,
        });
    }
    sections = merge_adjacent(sections);

    let symbols: Vec<Symbol> = info
        .modules
        .iter()
        .map(|m| Symbol {
            name: module_label(&m.name),
            addr: m.base,
            size: m.size,
            is_function: false,
        })
        .collect();

    let scan_section = |s: &Section| -> Vec<ExtractedString> {
        let end = (s.offset as usize)
            .saturating_add(s.size as usize)
            .min(data.len());
        if s.offset as usize >= data.len() {
            return Vec::new();
        }
        let tmp = Section {
            name: String::new(),
            vaddr: s.vaddr,
            size: s.size,
            offset: 0,
            is_executable: s.is_executable,
            readable: s.readable,
            writable: s.writable,
            initialized: true,
        };
        crate::parser::strings::extract::extract_all_strings(
            &data[s.offset as usize..end],
            std::slice::from_ref(&tmp),
            4,
        )
    };
    let mut strings: Vec<ExtractedString> = if sections.len() > 1 && data.len() >= 64 * 1024 {
        use rayon::prelude::*;
        crate::util::parallel::install(|| {
            sections.par_iter().map(&scan_section).collect::<Vec<_>>()
        })
        .into_iter()
        .flatten()
        .collect()
    } else {
        sections.iter().flat_map(scan_section).collect()
    };
    strings.sort_by_key(|s| s.vaddr);
    strings.truncate(1_000_000);

    let entry_point = info
        .exception_address
        .or_else(|| info.modules.first().map(|m| m.base))
        .unwrap_or(dump_base);

    let exports: Vec<Export> = Vec::new();
    let imports: Vec<Import> = Vec::new();

    Ok(ParsedBinary {
        format: "MINIDUMP".into(),
        arch: arch.into(),
        entry_point,
        sections,
        symbols,
        imports,
        exports,
        strings,
        data: std::sync::Arc::new(data),
        image_base: dump_base,
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
    })
}

pub fn looks_like_minidump(data: &[u8]) -> bool {
    data.len() >= 4 && u32_at(data, 0) == Some(MINIDUMP_MAGIC)
}

fn module_label(path: &str) -> String {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    format!("module_{}", base)
}

fn merge_adjacent(mut secs: Vec<Section>) -> Vec<Section> {
    secs.sort_by_key(|s| s.vaddr);
    let mut out: Vec<Section> = Vec::with_capacity(secs.len());
    for s in secs {
        match out.last_mut() {
            Some(prev)
                if prev.vaddr.saturating_add(prev.size) == s.vaddr
                    && prev.offset.saturating_add(prev.size) == s.offset
                    && prev.is_executable == s.is_executable
                    && prev.readable == s.readable
                    && prev.writable == s.writable =>
            {
                prev.size += s.size;
            }
            _ => out.push(s),
        }
    }
    out
}
