use crate::parser::model::{Export, Import, ParsedBinary, Section, Symbol};
use crate::parser::strings::extract::extract_all_strings;

pub(crate) fn parse_macho_goblin(
    mach: &goblin::mach::MachO,
    data: &std::sync::Arc<Vec<u8>>,
) -> Result<ParsedBinary, String> {
    let arch = match mach.header.cputype {
        0x01000007 => "x86_64",
        7 => "x86",
        0x0100000C => "aarch64",
        12 => "arm",
        _ => "unknown",
    };

    let mut sections = Vec::new();
    for seg in &mach.segments {
        let seg_name = seg.name().unwrap_or("?").to_string();
        if seg_name == "__PAGEZERO" {
            continue;
        }
        let prot = seg.initprot;
        if let Ok(sects) = seg.sections() {
            for (sect, _) in sects {
                let sect_name = sect.name().unwrap_or("?").to_string();
                let is_executable = prot & 0x4 != 0 && sect.flags & 0x8000_0400 != 0;
                let initialized = !matches!(sect.flags & 0xFF, 0x01 | 0x0C | 0x12);
                let raw_avail = data.len().saturating_sub(sect.offset as usize) as u64;
                sections.push(Section {
                    name: format!("{},{}", seg_name, sect_name),
                    vaddr: sect.addr,
                    size: sect.size.min(raw_avail),
                    offset: sect.offset as u64,
                    is_executable,
                    readable: prot & 0x1 != 0,
                    writable: prot & 0x2 != 0,
                    initialized,
                });
            }
        }
    }

    let mut symbols = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    let two_level = mach.header.flags & 0x80 != 0;

    if let Some(ref syms) = mach.symbols {
        for (name, nlist) in syms.iter().flatten() {
            if name.is_empty() {
                continue;
            }
            if nlist.n_type & 0xE0 != 0 {
                continue;
            }
            let is_undefined = nlist.is_undefined();
            let value = nlist.n_value;

            if is_undefined {
                let ord = ((nlist.n_desc >> 8) & 0xFF) as usize;
                let library = if two_level && ord > 0 && ord < 0xFE {
                    mach.libs
                        .get(ord)
                        .map(|s| s.to_string())
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                imports.push(Import {
                    name: name.to_string(),
                    library,
                    offset: 0,
                });
            } else if value != 0 {
                let is_function = if nlist.n_type & 0x0E == 0x0E && nlist.n_sect > 0 {
                    sections
                        .get(nlist.n_sect - 1)
                        .map(|s: &Section| s.is_executable)
                        .unwrap_or(true)
                } else {
                    true
                };
                symbols.push(Symbol {
                    name: name.to_string(),
                    addr: value,
                    size: 0,
                    is_function,
                });
                if nlist.n_type & 0x01 != 0 {
                    exports.push(Export {
                        name: name.to_string(),
                        offset: value,
                        ordinal: 0,
                        forwarder: None,
                    });
                }
            }
        }
    }

    let entry_point = mach.entry;
    let strings = extract_all_strings(data, &sections, 4);

    let filetype = mach.header.filetype;
    let format = match filetype {
        2 => "Mach-O EXE",
        6 => "Mach-O DYLIB",
        8 => "Mach-O BUNDLE",
        _ => "Mach-O",
    };
    let libraries: Vec<String> = mach
        .libs
        .iter()
        .filter(|s| **s != "self")
        .map(|s| s.to_string())
        .collect();
    let rpaths: Vec<String> = mach.rpaths.iter().map(|s| s.to_string()).collect();
    let uuid = macho_uuid(mach);
    let mut raw_end: usize = 0;
    for s in &sections {
        let e = (s.offset as usize).saturating_add(s.size as usize);
        if e > raw_end && e <= data.len() {
            raw_end = e;
        }
    }
    for seg in &mach.segments {
        let e = (seg.fileoff as usize).saturating_add(seg.filesize as usize);
        if e > raw_end && e <= data.len() {
            raw_end = e;
        }
    }
    let overlay = if raw_end < data.len() {
        Some((raw_end as u64, (data.len() - raw_end) as u64))
    } else {
        None
    };

    Ok(ParsedBinary {
        format: format.to_string(),
        arch: arch.to_string(),
        entry_point,
        sections,
        symbols,
        imports,
        exports,
        strings,
        data: std::sync::Arc::clone(data),
        image_base: 0,
        is_dll: filetype == 6,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay,
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        has_rich: false,
        libraries,
        rpaths,
        macho_uuid: uuid,
        relocations: Vec::new(),
    })
}

pub(crate) fn macho_uuid(mach: &goblin::mach::MachO) -> Option<String> {
    use goblin::mach::load_command::CommandVariant;
    for cmd in &mach.load_commands {
        if let CommandVariant::Uuid(u) = &cmd.command {
            let b = u.uuid;
            return Some(format!(
                "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
            ));
        }
    }
    None
}
