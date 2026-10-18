use goblin::Object;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::formats::elf::parse_elf;
use super::formats::macho::parse_macho_goblin;
use super::formats::pe::parse_pe;
use super::model::{ParsedBinary, Section, Symbol};
use super::strings::extract::extract_all_strings;

const MAX_FILE_SIZE: u64 = 1 << 29;

fn map_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("Cannot stat file: {}", e))?;
    if meta.len() > MAX_FILE_SIZE {
        return Err(format!(
            "File too large ({} MiB > 512 MiB limit)",
            meta.len() >> 20
        ));
    }
    let cap = usize::try_from(meta.len())
        .unwrap_or(u32::MAX as usize)
        .saturating_add(1)
        .min((MAX_FILE_SIZE + 1) as usize);
    let mut buf = Vec::with_capacity(cap);
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Cannot read file: {}", e))?;
    if buf.len() as u64 > MAX_FILE_SIZE {
        return Err(format!(
            "File too large ({} MiB > 512 MiB limit)",
            buf.len() >> 20
        ));
    }
    Ok(buf)
}

pub fn parse_file(path: &Path) -> Result<ParsedBinary, String> {
    let data = std::sync::Arc::new(map_file(path)?);

    let obj = Object::parse(&data).map_err(|e| format!("Parse error: {}", e))?;

    match obj {
        Object::PE(pe) => parse_pe(&pe, &data),
        Object::Elf(elf) => parse_elf(&elf, &data),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => parse_macho_goblin(&macho, &data),
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            let arches = fat.arches().map_err(|e| format!("Fat arch error: {}", e))?;
            for fa in arches.iter() {
                let start = fa.offset as usize;
                let Some(end) = start
                    .checked_add(fa.size as usize)
                    .filter(|&e| e <= data.len())
                else {
                    continue;
                };
                let slice = &data[start..end];
                if let Ok(macho) = goblin::mach::MachO::parse(slice, 0) {
                    let owned = std::sync::Arc::new(slice.to_vec());
                    return parse_macho_goblin(&macho, &owned);
                }
            }
            Err("No supported architecture in fat Mach-O".into())
        }
        Object::COFF(coff) => parse_coff(&coff, &data),
        Object::Archive(arch) => parse_archive(&arch, &data),
        _ => Err("Unsupported binary format (unknown header)".into()),
    }
}
fn parse_archive(
    arch: &goblin::archive::Archive,
    data: &std::sync::Arc<Vec<u8>>,
) -> Result<ParsedBinary, String> {
    let members = arch.members();
    if members.is_empty() {
        return Err("Empty archive (no members)".into());
    }
    for name in &members {
        if name == &"/" || name == &"//" || name.starts_with("__") || name.starts_with("/") {
            continue;
        }
        let bytes = arch
            .extract(name, &data[..])
            .map_err(|e| format!("Archive extract error for {}: {}", name, e))?;
        if let Ok(obj) = Object::parse(bytes) {
            let owned = std::sync::Arc::new(bytes.to_vec());
            let mut bin = match obj {
                Object::COFF(coff) => parse_coff(&coff, &owned)?,
                Object::PE(pe) => parse_pe(&pe, &owned)?,
                Object::Elf(elf) => parse_elf(&elf, &owned)?,
                _ => continue,
            };
            bin.format = format!("{} [{}]", bin.format, name);
            return Ok(bin);
        }
    }
    Err(format!(
        "Unsupported archive: no parseable COFF/PE/ELF member ({} member(s): {}{})",
        members.len(),
        members
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        if members.len() > 10 {
            format!(" ... and {} more", members.len() - 10)
        } else {
            String::new()
        }
    ))
}
fn parse_coff(
    coff: &goblin::pe::Coff,
    data: &std::sync::Arc<Vec<u8>>,
) -> Result<ParsedBinary, String> {
    let image_base = 0u64;
    let sections: Vec<Section> = coff
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(
                &s.name[..s.name.iter().position(|&c| c == 0).unwrap_or(s.name.len())],
            )
            .to_string();
            let raw_avail = data.len().saturating_sub(s.pointer_to_raw_data as usize) as u64;
            let sec_size = if s.virtual_size != 0 {
                s.virtual_size as u64
            } else {
                s.size_of_raw_data as u64
            };
            Section {
                name,
                vaddr: image_base.wrapping_add(s.virtual_address as u64),
                size: sec_size.min(raw_avail),
                offset: s.pointer_to_raw_data as u64,
                is_executable: s.characteristics & 0x2000_0000 != 0,
                readable: s.characteristics & 0x4000_0000 != 0,
                writable: s.characteristics & 0x8000_0000 != 0,
                initialized: s.characteristics & 0x0000_0080 == 0,
            }
        })
        .collect();

    let mut symbols = Vec::new();
    if let Some(symtab) = &coff.symbols {
        for (_, name, sym) in symtab.iter() {
            let Some(name) = name else { continue };
            if name.is_empty() {
                continue;
            }
            let addr = if sym.section_number > 0 {
                sections
                    .get(sym.section_number as usize - 1)
                    .map(|s| s.vaddr.wrapping_add(sym.value as u64))
                    .unwrap_or(sym.value as u64)
            } else {
                sym.value as u64
            };
            symbols.push(Symbol {
                name: name.to_string(),
                addr,
                size: 0,
                is_function: sym.typ & 0x20 != 0,
            });
        }
    }

    let arch = match coff.header.machine {
        0x8664 => "x86_64",
        0x14C => "x86",
        0xAA64 => "aarch64",
        0x1C0 | 0x1C4 => "arm",
        _ => "x86_64",
    };

    let strings = extract_all_strings(&data[..], &sections, 4);
    Ok(ParsedBinary {
        format: "COFF".into(),
        arch: arch.into(),
        entry_point: 0,
        sections,
        symbols,
        imports: Vec::new(),
        exports: Vec::new(),
        strings,
        data: std::sync::Arc::clone(data),
        image_base,
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

pub fn parse_raw(path: &Path, base_addr: u64, arch: &str) -> Result<ParsedBinary, String> {
    let data = map_file(path)?;
    parse_raw_bytes(data, base_addr, arch)
}

pub fn parse_raw_bytes(data: Vec<u8>, base_addr: u64, arch: &str) -> Result<ParsedBinary, String> {
    let size = data.len() as u64;
    let sections = vec![Section {
        name: ".raw".to_string(),
        vaddr: base_addr,
        size,
        offset: 0,
        is_executable: true,
        readable: true,
        writable: false,
        initialized: true,
    }];
    let strings = extract_all_strings(&data, &sections, 4);

    Ok(ParsedBinary {
        format: "RAW".to_string(),
        arch: arch.to_string(),
        entry_point: base_addr,
        sections,
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings,
        data: std::sync::Arc::new(data),
        image_base: base_addr,
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
