use crate::analysis::function::FuncSource;
use crate::parser::ParsedBinary;

pub fn function_starts(binary: &ParsedBinary) -> Vec<(u64, FuncSource)> {
    let mut out = Vec::new();
    if binary.format.starts_with("PE") {
        out.extend(pe_pdata_starts(binary));
    } else if binary.format == "ELF" {
        out.extend(elf_eh_starts(binary));
    } else if binary.format.starts_with("Mach") {
        out.extend(macho_function_starts(binary));
    }
    out.sort();
    out.dedup();
    out.into_iter()
        .map(|a| (a, FuncSource::UnwindInfo))
        .collect()
}

pub fn has_debug_info(binary: &ParsedBinary) -> bool {
    binary.format == "ELF"
        && binary
            .sections
            .iter()
            .any(|s| s.name == ".debug_info" && s.size > 0)
}

fn is_exec(binary: &ParsedBinary, addr: u64) -> bool {
    binary
        .sections
        .iter()
        .any(|s| s.is_executable && addr >= s.vaddr && addr < s.vaddr.saturating_add(s.size))
}

fn section_bytes<'a>(binary: &'a ParsedBinary, name: &str) -> Option<(u64, &'a [u8])> {
    let sec = binary.sections.iter().find(|s| s.name == name)?;
    if sec.size == 0 || sec.size > 0x2000_0000 {
        return None;
    }
    let end = sec.offset.checked_add(sec.size)? as usize;
    let start = sec.offset as usize;
    if end > binary.data.len() {
        return None;
    }
    Some((sec.vaddr, &binary.data[start..end]))
}

fn pe_pdata_starts(binary: &ParsedBinary) -> Vec<u64> {
    let mut out = Vec::new();
    let Some((_, data)) = section_bytes(binary, ".pdata") else {
        return out;
    };
    if binary.arch != "x86_64" {
        return out;
    }
    let count = data.len() / 12;
    for i in 0..count.min(500_000) {
        let o = i * 12;
        let begin = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let end = u32::from_le_bytes(data[o + 4..o + 8].try_into().unwrap());
        if end > begin {
            let va = binary.image_base.wrapping_add(begin as u64);
            if is_exec(binary, va) {
                out.push(va);
            }
        }
    }
    out
}

const EH_ABSPTR: u8 = 0x00;
const EH_ULEB: u8 = 0x01;
const EH_UDATA2: u8 = 0x02;
const EH_UDATA4: u8 = 0x03;
const EH_UDATA8: u8 = 0x04;
const EH_SLEB: u8 = 0x09;
const EH_SDATA2: u8 = 0x0A;
const EH_SDATA4: u8 = 0x0B;
const EH_SDATA8: u8 = 0x0C;
const EH_PCREL: u8 = 0x10;
const EH_DATAREL: u8 = 0x30;
const EH_OMIT: u8 = 0xFF;

fn read_uleb(d: &[u8], pos: &mut usize) -> Option<u64> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= d.len() || shift > 63 {
            return None;
        }
        let b = d[*pos];
        *pos += 1;
        val |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(val);
        }
    }
}

fn read_sleb(d: &[u8], pos: &mut usize) -> Option<i64> {
    let mut val = 0i64;
    let mut shift = 0u32;
    loop {
        if *pos >= d.len() || shift > 63 {
            return None;
        }
        let b = d[*pos];
        *pos += 1;
        val |= ((b & 0x7F) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                val |= !0i64 << shift;
            }
            return Some(val);
        }
    }
}

fn read_eh_encoded(
    d: &[u8],
    pos: &mut usize,
    enc: u8,
    addr_size: usize,
    field_vaddr: u64,
    datarel_base: u64,
) -> Option<u64> {
    if enc == EH_OMIT {
        return None;
    }
    let base_type = enc & 0x0F;
    if enc & 0x70 == 0x50 || enc & 0x70 == 0x20 || enc & 0x70 == 0x40 {
        return None;
    }
    let raw: i64 = match base_type {
        EH_ABSPTR => {
            if addr_size == 8 {
                if *pos + 8 > d.len() {
                    return None;
                }
                let v = u64::from_le_bytes(d[*pos..*pos + 8].try_into().unwrap());
                *pos += 8;
                v as i64
            } else {
                if *pos + 4 > d.len() {
                    return None;
                }
                let v = u32::from_le_bytes(d[*pos..*pos + 4].try_into().unwrap());
                *pos += 4;
                v as i64
            }
        }
        EH_ULEB => read_uleb(d, pos)? as i64,
        EH_UDATA2 => {
            if *pos + 2 > d.len() {
                return None;
            }
            let v = u16::from_le_bytes(d[*pos..*pos + 2].try_into().unwrap());
            *pos += 2;
            v as i64
        }
        EH_UDATA4 => {
            if *pos + 4 > d.len() {
                return None;
            }
            let v = u32::from_le_bytes(d[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            v as i64
        }
        EH_UDATA8 => {
            if *pos + 8 > d.len() {
                return None;
            }
            let v = u64::from_le_bytes(d[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            v as i64
        }
        EH_SLEB => read_sleb(d, pos)?,
        EH_SDATA2 => {
            if *pos + 2 > d.len() {
                return None;
            }
            let v = i16::from_le_bytes(d[*pos..*pos + 2].try_into().unwrap());
            *pos += 2;
            v as i64
        }
        EH_SDATA4 => {
            if *pos + 4 > d.len() {
                return None;
            }
            let v = i32::from_le_bytes(d[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            v as i64
        }
        EH_SDATA8 => {
            if *pos + 8 > d.len() {
                return None;
            }
            let v = i64::from_le_bytes(d[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            v
        }
        _ => return None,
    };
    let rel = enc & 0x70;
    if rel == EH_PCREL {
        Some(field_vaddr.wrapping_add(raw as u64))
    } else if rel == EH_DATAREL {
        Some(datarel_base.wrapping_add(raw as u64))
    } else {
        Some(raw as u64)
    }
}

fn elf_eh_starts(binary: &ParsedBinary) -> Vec<u64> {
    let addr_size = if binary.arch == "x86_64" { 8 } else { 4 };
    if let Some(v) = eh_frame_hdr_starts(binary, addr_size)
        && !v.is_empty() {
            return v;
        }
    eh_frame_scan(binary, addr_size)
}

fn eh_frame_hdr_starts(binary: &ParsedBinary, addr_size: usize) -> Option<Vec<u64>> {
    let (vaddr, data) = section_bytes(binary, ".eh_frame_hdr")?;
    if data.len() < 4 || data[0] != 1 {
        return None;
    }
    let eh_ptr_enc = data[1];
    let count_enc = data[2];
    let table_enc = data[3];
    if table_enc == EH_OMIT || count_enc == EH_OMIT {
        return None;
    }
    let mut pos = 4usize;
    let fv = vaddr.wrapping_add(pos as u64);
    read_eh_encoded(data, &mut pos, eh_ptr_enc, addr_size, fv, vaddr)?;
    let fv = vaddr.wrapping_add(pos as u64);
    let count = read_eh_encoded(data, &mut pos, count_enc, addr_size, fv, vaddr)? as usize;
    if count == 0 || count > 1_000_000 {
        return None;
    }
    let mut out = Vec::new();
    for _ in 0..count {
        if pos >= data.len() {
            break;
        }
        let fv = vaddr.wrapping_add(pos as u64);
        let Some(loc) = read_eh_encoded(data, &mut pos, table_enc, addr_size, fv, vaddr) else {
            break;
        };
        let fv = vaddr.wrapping_add(pos as u64);
        if read_eh_encoded(data, &mut pos, table_enc, addr_size, fv, vaddr).is_none() {
            break;
        }
        if loc != 0 && is_exec(binary, loc) {
            out.push(loc);
        }
    }
    Some(out)
}

struct CieInfo {
    fde_enc: u8,
}

fn eh_frame_scan(binary: &ParsedBinary, addr_size: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let Some((vaddr, data)) = section_bytes(binary, ".eh_frame") else {
        return out;
    };
    let mut cies: Vec<(u64, CieInfo)> = Vec::new();
    let mut pos = 0usize;
    let mut records = 0usize;
    while pos + 4 <= data.len() && records < 200_000 {
        records += 1;
        let len32 = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        if len32 == 0 {
            break;
        }
        let (rec_len, hdr): (u64, usize) = if len32 == 0xFFFF_FFFF {
            if pos + 12 > data.len() {
                break;
            }
            (
                u64::from_le_bytes(data[pos + 4..pos + 12].try_into().unwrap()),
                12,
            )
        } else {
            (len32 as u64, 4)
        };
        let rec_end = (pos as u64)
            .saturating_add(hdr as u64)
            .saturating_add(rec_len) as usize;
        if rec_end > data.len() || rec_end <= pos {
            break;
        }
        let is64 = hdr == 12;
        let id_pos = pos + hdr;
        let cie_id: u64 = if is64 {
            u64::from_le_bytes(data[id_pos..id_pos + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[id_pos..id_pos + 4].try_into().unwrap()) as u64
        };
        let mut p = id_pos + if is64 { 8 } else { 4 };
        if cie_id == 0 {
            if p >= rec_end {
                pos = rec_end;
                continue;
            }
            let version = data[p];
            p += 1;
            let aug_start = p;
            while p < rec_end && data[p] != 0 {
                p += 1;
            }
            let aug = &data[aug_start..p.min(rec_end)];
            if p < rec_end {
                p += 1;
            }
            if version == 1 {
                if read_uleb(data, &mut p).is_none() || read_sleb(data, &mut p).is_none() {
                    pos = rec_end;
                    continue;
                }
                p += 1;
            } else if version == 3 || version == 4 {
                if read_uleb(data, &mut p).is_none()
                    || read_sleb(data, &mut p).is_none()
                    || read_uleb(data, &mut p).is_none()
                {
                    pos = rec_end;
                    continue;
                }
                p += 1;
            } else {
                pos = rec_end;
                continue;
            }
            let mut fde_enc = EH_ABSPTR;
            if aug.first() == Some(&b'z') {
                let aug_len = read_uleb(data, &mut p).unwrap_or(0) as usize;
                let aug_end = p.saturating_add(aug_len).min(rec_end);
                let mut ai = 1usize;
                let mut ap = p;
                while ai < aug.len() && ap < aug_end {
                    match aug[ai] {
                        b'L' => {
                            ap += 1;
                        }
                        b'R' => {
                            if ap < aug_end {
                                fde_enc = data[ap];
                                ap += 1;
                            }
                        }
                        b'P' => {
                            if ap < aug_end {
                                let enc = data[ap];
                                ap += 1;
                                let mut tp = ap;
                                if read_eh_encoded(data, &mut tp, enc, addr_size, 0, 0).is_none() {
                                    break;
                                }
                                ap = tp;
                            }
                        }
                        _ => break,
                    }
                    ai += 1;
                }
            }
            cies.push(((pos) as u64, CieInfo { fde_enc }));
        } else {
            let cie_off = (id_pos as u64).wrapping_sub(cie_id);
            let fde_enc = cies
                .iter()
                .rev()
                .find(|(off, _)| *off == cie_off)
                .map(|(_, c)| c.fde_enc)
                .unwrap_or(EH_ABSPTR);
            let fv = vaddr.wrapping_add(p as u64);
            if let Some(loc) = read_eh_encoded(data, &mut p, fde_enc, addr_size, fv, vaddr)
                && loc != 0 && is_exec(binary, loc) {
                    out.push(loc);
                }
        }
        pos = rec_end;
    }
    out
}

fn read_u32_le(d: &[u8], o: usize) -> Option<u32> {
    if o + 4 <= d.len() {
        Some(u32::from_le_bytes(d[o..o + 4].try_into().unwrap()))
    } else {
        None
    }
}

fn macho_function_starts(binary: &ParsedBinary) -> Vec<u64> {
    let mut out = Vec::new();
    let d = &binary.data[..];
    if d.len() < 32 {
        return out;
    }
    let magic = read_u32_le(d, 0).unwrap_or(0);
    let is64 = matches!(magic, 0xfeed_facf | 0xcffa_edfe);
    let is32 = matches!(magic, 0xfeed_face | 0xcefa_edfe);
    if !is64 && !is32 {
        return out;
    }
    let be = magic == 0xcffa_edfe || magic == 0xcefa_edfe;
    let rd32 = |o: usize| -> Option<u32> {
        if o + 4 > d.len() {
            return None;
        }
        let b: [u8; 4] = d[o..o + 4].try_into().unwrap();
        Some(if be {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    let ncmds = rd32(if is64 { 16 } else { 12 }).unwrap_or(0) as usize;
    if ncmds == 0 || ncmds > 256 {
        return out;
    }
    let mut off = if is64 { 32 } else { 28 };
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SEGMENT: u32 = 0x1;
    const LC_FUNCTION_STARTS: u32 = 0x26;
    let mut text_vmaddr: Option<u64> = None;
    let mut fs_data: Option<(usize, usize)> = None;
    for _ in 0..ncmds {
        let (Some(cmd), Some(cmdsize_raw)) = (rd32(off), rd32(off + 4)) else {
            break;
        };
        let cmdsize = cmdsize_raw as usize;
        if cmdsize < 8 || off + cmdsize > d.len() {
            break;
        }
        if cmd == LC_SEGMENT_64 {
            let segname = &d[off + 8..off + 24];
            if segname.starts_with(b"__TEXT") {
                let raw: [u8; 8] = d[off + 24..off + 32].try_into().unwrap();
                text_vmaddr = Some(if be {
                    u64::from_be_bytes(raw)
                } else {
                    u64::from_le_bytes(raw)
                });
            }
        } else if cmd == LC_SEGMENT {
            let segname = &d[off + 8..off + 24];
            if segname.starts_with(b"__TEXT")
                && let Some(vm) = rd32(off + 24) {
                    text_vmaddr = Some(vm as u64);
                }
        } else if cmd == LC_FUNCTION_STARTS
            && let (Some(dataoff), Some(datasize)) = (rd32(off + 8), rd32(off + 12)) {
                let (dataoff, datasize) = (dataoff as usize, datasize as usize);
                if datasize > 0 && datasize < 0x1000_0000 && dataoff + datasize <= d.len() {
                    fs_data = Some((dataoff, datasize));
                }
            }
        off += cmdsize;
    }
    let Some((dataoff, datasize)) = fs_data else {
        return out;
    };
    let mut addr = 0u64;
    let mut p = dataoff;
    let end = dataoff + datasize;
    let mut count = 0usize;
    while p < end && count < 1_000_000 {
        count += 1;
        let mut val = 0u64;
        let mut shift = 0u32;
        loop {
            if p >= end || shift > 63 {
                break;
            }
            let b = d[p];
            p += 1;
            val |= ((b & 0x7F) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
        if val == 0 {
            continue;
        }
        addr = addr.wrapping_add(val);
        let mut placed = false;
        if let Some(base) = text_vmaddr {
            let va = base.wrapping_add(addr);
            if is_exec(binary, va) {
                out.push(va);
                placed = true;
            }
        }
        if !placed && is_exec(binary, addr) {
            out.push(addr);
        }
    }
    out
}
