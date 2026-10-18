use crate::parser::model::{Export, Import, ParsedBinary, Section, Symbol};
use crate::parser::strings::extract::extract_all_strings;

pub(crate) fn parse_pe(
    pe: &goblin::pe::PE,
    data: &std::sync::Arc<Vec<u8>>,
) -> Result<ParsedBinary, String> {
    let image_base = pe.image_base as u64;
    let sections: Vec<Section> = pe
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(
                &s.name[..s.name.iter().position(|&c| c == 0).unwrap_or(s.name.len())],
            )
            .to_string();
            let raw_avail = data.len().saturating_sub(s.pointer_to_raw_data as usize) as u64;
            let virt = s.virtual_size as u64;
            let raw = (s.size_of_raw_data as u64).min(raw_avail);
            Section {
                name,
                vaddr: image_base.wrapping_add(s.virtual_address as u64),
                size: if virt != 0 { virt } else { raw },
                offset: s.pointer_to_raw_data as u64,
                is_executable: s.characteristics & 0x20000000 != 0,
                readable: s.characteristics & 0x40000000 != 0,
                writable: s.characteristics & 0x80000000 != 0,
                initialized: s.characteristics & 0x00000080 == 0,
            }
        })
        .collect();

    let mut symbols = Vec::new();
    for (i, export) in pe.exports.iter().enumerate() {
        if pe_export_forwarder(pe, export).is_some() {
            continue;
        }
        if let Some(name) = export.name {
            symbols.push(Symbol {
                name: name.to_string(),
                addr: image_base.wrapping_add(export.rva as u64),
                size: 0,
                is_function: true,
            });
        }
        let _ = i;
    }

    let imports = pe
        .imports
        .iter()
        .map(|imp| Import {
            name: imp.name.to_string(),
            library: imp.dll.to_string(),
            offset: image_base.wrapping_add(imp.offset as u64),
        })
        .collect();

    let exports = pe
        .exports
        .iter()
        .enumerate()
        .map(|(i, exp)| {
            let name = match exp.name {
                Some(n) => n.to_string(),
                None => format!("Ordinal{}", pe_export_ordinal(pe, exp, i)),
            };
            let forwarder = pe_export_forwarder(pe, exp);
            let addr = if forwarder.is_some() {
                0
            } else {
                image_base.wrapping_add(exp.rva as u64)
            };
            Export {
                name,
                offset: addr,
                ordinal: pe_export_ordinal(pe, exp, i),
                forwarder,
            }
        })
        .collect();

    let strings = extract_all_strings(&data[..], &sections, 4);

    let pe_chars = pe.header.coff_header.characteristics;
    let is_dll = pe_chars & 0x2000 != 0;
    let dll_chars = pe
        .header
        .optional_header
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    let overlay = pe_overlay(&data[..], pe);
    let has_rich = pe_has_rich(&data[..]);
    let tls_callbacks = pe_tls_callbacks(&data[..], pe, image_base);
    let delay_imports = pe_delay_imports(&data[..], pe, image_base);
    let libraries: Vec<String> = pe.libraries.iter().map(|s| s.to_string()).collect();
    let relocations = pe_base_relocs(&data[..], pe, image_base);

    let mut seen: std::collections::HashSet<u64> = symbols.iter().map(|s| s.addr).collect();
    for cb in &tls_callbacks {
        if *cb != 0 && seen.insert(*cb) {
            symbols.push(Symbol {
                name: format!("tls_callback_{:x}", cb),
                addr: *cb,
                size: 0,
                is_function: true,
            });
        }
    }

    Ok(ParsedBinary {
        format: if is_dll {
            "PE DLL".into()
        } else {
            "PE EXE".into()
        },
        arch: if pe.is_64 { "x86_64" } else { "x86" }.to_string(),
        entry_point: image_base.wrapping_add(pe.entry as u64),
        sections,
        symbols,
        imports,
        exports,
        strings,
        data: std::sync::Arc::clone(data),
        image_base,
        is_dll,
        pe_characteristics: pe_chars,
        dll_characteristics: dll_chars,
        overlay,
        tls_callbacks,
        delay_imports,
        has_rich,
        libraries,
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations,
    })
}

fn pe_base_relocs(
    data: &[u8],
    pe: &goblin::pe::PE,
    image_base: u64,
) -> Vec<crate::parser::model::Relocation> {
    use crate::parser::model::Relocation;
    let mut out = Vec::new();
    let oh = match &pe.header.optional_header {
        Some(oh) => oh,
        None => return out,
    };
    let dd = match oh.data_directories.get_base_relocation_table() {
        Some(dd) => *dd,
        None => return out,
    };
    if dd.virtual_address == 0 || dd.size == 0 {
        return out;
    }
    let mut off = match pe_rva_to_offset(pe, dd.virtual_address) {
        Some(o) => o,
        None => return out,
    };
    let end = off.saturating_add(dd.size as usize).min(data.len());
    while off + 8 <= end && out.len() < 262_144 {
        let page = read_u32_le(data, off).unwrap_or(0);
        let size = read_u32_le(data, off + 4).unwrap_or(0) as usize;
        if size < 8 || off + size > end {
            break;
        }
        let n = (size - 8) / 2;
        for i in 0..n {
            let e = u16::from_le_bytes([data[off + 8 + i * 2], data[off + 8 + i * 2 + 1]]);
            let typ = (e >> 12) as u32;
            let disp = (e & 0x0fff) as u64;
            if typ == 0 {
                continue;
            }
            let (sz, rt) = match typ {
                3 => (4u8, 3u32),
                10 => (8u8, 10u32),
                _ => (0u8, typ),
            };
            if sz == 0 {
                continue;
            }
            out.push(Relocation {
                va: image_base.wrapping_add(page as u64).wrapping_add(disp),
                size: sz,
                rel_type: rt,
                symbol: None,
                addend: 0,
                is_artificial: false,
            });
            if out.len() >= 262_144 {
                break;
            }
        }
        if size == 0 {
            break;
        }
        off += size;
    }
    out
}

fn pe_overlay(data: &[u8], pe: &goblin::pe::PE) -> Option<(u64, u64)> {
    let mut end: usize = 0;
    for s in &pe.sections {
        let s_end = s.pointer_to_raw_data as usize + s.size_of_raw_data as usize;
        if s_end > end && s_end <= data.len() {
            end = s_end.min(data.len());
        }
    }
    if let Some(oh) = &pe.header.optional_header {
        if let Some(dd) = oh.data_directories.get_certificate_table() {
            let c_end = dd.virtual_address as usize + dd.size as usize;
            if c_end > end && c_end <= data.len() {
                end = c_end;
            }
        }
    }
    if end < data.len() {
        Some((end as u64, (data.len() - end) as u64))
    } else {
        None
    }
}

fn pe_has_rich(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    let lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if lfanew >= data.len() || lfanew < 0x40 {
        return false;
    }
    let stub = &data[..lfanew.min(data.len())];
    let mut has_dans = false;
    let mut has_rich = false;
    for w in stub.windows(4) {
        if w == b"DanS" {
            has_dans = true;
        }
        if w == b"Rich" {
            has_rich = true;
        }
        if has_dans && has_rich {
            break;
        }
    }
    has_dans && has_rich
}

fn pe_rva_to_offset(pe: &goblin::pe::PE, rva: u32) -> Option<usize> {
    for s in &pe.sections {
        let va = s.virtual_address as usize;
        let virt = s.virtual_size as usize;
        let raw = s.size_of_raw_data as usize;
        let vend = va.saturating_add(if virt != 0 { virt } else { raw });
        let r = rva as usize;
        if r < va || r >= vend {
            continue;
        }
        let delta = r - va;
        if delta >= raw {
            continue;
        }
        let off = (s.pointer_to_raw_data as usize).saturating_add(delta);
        return Some(off);
    }
    None
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn read_cstr(data: &[u8], off: usize) -> Option<String> {
    let mut end = off;
    while end < data.len() && data[end] != 0 && end - off < 256 {
        end += 1;
    }
    if end == off {
        return None;
    }
    std::str::from_utf8(&data[off..end])
        .ok()
        .map(|s| s.to_string())
}

fn pe_tls_callbacks(data: &[u8], pe: &goblin::pe::PE, _image_base: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let oh = match &pe.header.optional_header {
        Some(oh) => oh,
        None => return out,
    };
    let dd = match oh.data_directories.get_tls_table() {
        Some(dd) => *dd,
        None => return out,
    };
    if dd.virtual_address == 0 {
        return out;
    }
    let tls_off = match pe_rva_to_offset(pe, dd.virtual_address) {
        Some(o) => o,
        None => return out,
    };
    let cb_va = if pe.is_64 {
        let off = tls_off + 24;
        read_u64_le(data, off).unwrap_or(0)
    } else {
        let off = tls_off + 12;
        read_u32_le(data, off).unwrap_or(0) as u64
    };
    if cb_va == 0 {
        return out;
    }
    let image_base = pe.image_base as u64;
    let cb_rva = match cb_va.checked_sub(image_base) {
        Some(v) if v <= u32::MAX as u64 => v as u32,
        _ => return out,
    };
    let arr_off = match pe_rva_to_offset(pe, cb_rva) {
        Some(o) => o,
        None => return out,
    };
    let step = if pe.is_64 { 8 } else { 4 };
    for i in 0..20 {
        let va = if pe.is_64 {
            read_u64_le(data, arr_off + i * step).unwrap_or(0)
        } else {
            read_u32_le(data, arr_off + i * step).unwrap_or(0) as u64
        };
        if va == 0 {
            break;
        }
        out.push(va);
    }
    out
}

fn pe_delay_imports(data: &[u8], pe: &goblin::pe::PE, image_base: u64) -> Vec<Import> {
    let mut out = Vec::new();
    let oh = match &pe.header.optional_header {
        Some(oh) => oh,
        None => return out,
    };
    let dd = match oh.data_directories.get_delay_import_descriptor() {
        Some(dd) => *dd,
        None => return out,
    };
    if dd.virtual_address == 0 {
        return out;
    }
    let base = match pe_rva_to_offset(pe, dd.virtual_address) {
        Some(o) => o,
        None => return out,
    };
    let sec_end = base.saturating_add(dd.size as usize).min(data.len());
    for idx in 0..128 {
        let rec = base + idx * 32;
        if rec + 32 > sec_end {
            break;
        }
        let attrs = read_u32_le(data, rec).unwrap_or(0);
        let dll_rva = read_u32_le(data, rec + 4).unwrap_or(0);
        let iat_rva = read_u32_le(data, rec + 16).unwrap_or(0);
        let int_rva = read_u32_le(data, rec + 20).unwrap_or(0);
        if attrs == 0 && dll_rva == 0 && iat_rva == 0 && int_rva == 0 {
            break;
        }
        let dll = pe_rva_to_offset(pe, dll_rva)
            .and_then(|o| read_cstr(data, o))
            .unwrap_or_else(|| "delayed.dll".to_string());
        let int_off = match pe_rva_to_offset(pe, int_rva) {
            Some(o) => o,
            None => continue,
        };
        let step = if pe.is_64 { 8 } else { 4 };
        for j in 0..512 {
            if out.len() >= 4096 {
                break;
            }
            let thunk_rva = if pe.is_64 {
                let v = read_u64_le(data, int_off + j * step).unwrap_or(0);
                if v & 0x8000_0000_0000_0000 != 0 {
                    let ord = (v & 0xFFFF) as u32;
                    let iat_va =
                        image_base.wrapping_add((iat_rva as u64) + (j as u64) * (step as u64));
                    out.push(Import {
                        name: format!("Ordinal{}", ord),
                        library: dll.clone(),
                        offset: iat_va,
                    });
                    continue;
                }
                v as u32
            } else {
                let v = read_u32_le(data, int_off + j * step).unwrap_or(0);
                if v & 0x8000_0000 != 0 {
                    let ord = v & 0xFFFF;
                    let iat_va =
                        image_base.wrapping_add((iat_rva as u64) + (j as u64) * (step as u64));
                    out.push(Import {
                        name: format!("Ordinal{}", ord),
                        library: dll.clone(),
                        offset: iat_va,
                    });
                    continue;
                }
                v
            };
            if thunk_rva == 0 {
                break;
            }
            let hn_off = match pe_rva_to_offset(pe, thunk_rva) {
                Some(o) => o,
                None => continue,
            };
            if let Some(name) = read_cstr(data, hn_off + 2) {
                let iat_va = image_base.wrapping_add((iat_rva as u64) + (j as u64) * (step as u64));
                out.push(Import {
                    name,
                    library: dll.clone(),
                    offset: iat_va,
                });
            }
        }
    }
    out
}

fn pe_export_ordinal(pe: &goblin::pe::PE, exp: &goblin::pe::export::Export, idx: usize) -> u32 {
    if let Some(ed) = &pe.export_data {
        if let Some(&ord_index) = ed.export_ordinal_table.get(idx) {
            let ordinal = ed
                .export_directory_table
                .ordinal_base
                .wrapping_add(ord_index as u32);
            return ordinal;
        }
    }
    match &exp.reexport {
        Some(goblin::pe::export::Reexport::DLLOrdinal { ordinal, .. }) => *ordinal as u32,
        _ => 0,
    }
}

fn pe_export_forwarder(_pe: &goblin::pe::PE, exp: &goblin::pe::export::Export) -> Option<String> {
    match &exp.reexport {
        Some(goblin::pe::export::Reexport::DLLName { lib, export }) => {
            Some(format!("{}.{}", lib, export))
        }
        Some(goblin::pe::export::Reexport::DLLOrdinal { lib, ordinal }) => {
            Some(format!("{}.#{}", lib, ordinal))
        }
        None => None,
    }
}
