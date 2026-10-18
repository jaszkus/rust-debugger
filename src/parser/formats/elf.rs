use crate::parser::model::{Export, Import, ParsedBinary, Section, Symbol};
use crate::parser::strings::extract::extract_all_strings;

pub(crate) fn parse_elf(
    elf: &goblin::elf::Elf,
    data: &std::sync::Arc<Vec<u8>>,
) -> Result<ParsedBinary, String> {
    let pie_base: u64 = if elf.header.e_type == goblin::elf::header::ET_DYN {
        0x100000
    } else {
        0
    };
    let mut alloc_flags: Vec<bool> = Vec::new();
    let mut sections: Vec<Section> = elf
        .section_headers
        .iter()
        .filter_map(|s| {
            let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("");
            let alloc = s.sh_flags & 0x2 != 0;
            if !alloc && !name.starts_with(".debug_") {
                return None;
            }
            alloc_flags.push(alloc);
            let name = name.to_string();
            Some(Section {
                name,
                vaddr: s.sh_addr + pie_base,
                size: s.sh_size,
                offset: s.sh_offset,
                is_executable: s.sh_flags & 0x4 != 0,
                readable: true,
                writable: s.sh_flags & 0x1 != 0,
                initialized: s.sh_type != 8,
            })
        })
        .collect();
    for (sec, &alloc) in sections.iter_mut().zip(alloc_flags.iter()) {
        if !alloc {
            continue;
        }
        for ph in elf.program_headers.iter() {
            if ph.p_type != goblin::elf::program_header::PT_LOAD {
                continue;
            }
            let ps = ph.p_vaddr;
            let pe = ph.p_vaddr.saturating_add(ph.p_memsz);
            if sec.vaddr >= ps && sec.vaddr < pe {
                sec.readable = ph.p_flags & 0x4 != 0;
                sec.writable = ph.p_flags & 0x2 != 0;
                sec.is_executable = ph.p_flags & 0x1 != 0;
                break;
            }
        }
    }

    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_ARM => "arm",
        _ => "unknown",
    };

    let is_func = |t: u8| t == goblin::elf::sym::STT_FUNC || t == 10;
    let sym_addr = |v: u64, t: u8| {
        if arch == "arm" && is_func(t) {
            v & !1
        } else {
            v
        }
    };

    let mut symbols: Vec<Symbol> = elf
        .syms
        .iter()
        .filter_map(|s| {
            if s.st_shndx == 0
                || matches!(
                    s.st_type(),
                    goblin::elf::sym::STT_SECTION | goblin::elf::sym::STT_FILE
                )
            {
                return None;
            }
            let name = elf.strtab.get_at(s.st_name)?.to_string();
            if name.is_empty() {
                return None;
            }
            Some(Symbol {
                name,
                addr: sym_addr(s.st_value, s.st_type()) + pie_base,
                size: s.st_size,
                is_function: is_func(s.st_type()),
            })
        })
        .collect();
    if symbols.is_empty() {
        for s in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(s.st_name) {
                if name.is_empty() || s.st_value == 0 || s.st_shndx == 0 {
                    continue;
                }
                symbols.push(Symbol {
                    name: name.to_string(),
                    addr: sym_addr(s.st_value, s.st_type()) + pie_base,
                    size: s.st_size,
                    is_function: is_func(s.st_type()),
                });
            }
        }
    }

    let plt_sec = sections
        .iter()
        .find(|s| s.name == ".plt.sec")
        .or_else(|| sections.iter().find(|s| s.name == ".plt"));
    let plt_va = plt_sec.map(|s| s.vaddr);
    let jump_slot_type: u32 = match arch {
        "x86_64" | "x86" => 7,
        "aarch64" => 1026,
        "arm" => 22,
        _ => u32::MAX,
    };
    let mut import_addrs: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    if let (Some(plt), Some(ps)) = (plt_va, plt_sec) {
        let header: u64 = if ps.name == ".plt.sec" {
            0
        } else {
            match arch {
                "arm" => 20,
                "aarch64" => 32,
                _ => 16,
            }
        };
        let n = elf
            .pltrelocs
            .iter()
            .filter(|r| r.r_type == jump_slot_type)
            .count()
            .max(1) as u64;
        let entry_size = (ps.size.saturating_sub(header) / n).max(1);
        let mut i: u64 = 0;
        for rel in elf.pltrelocs.iter() {
            if rel.r_type != jump_slot_type {
                continue;
            }
            if let Some(sym) = elf.dynsyms.get(rel.r_sym)
                && let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    import_addrs
                        .insert(name.to_string(), plt.wrapping_add(header + i * entry_size));
                }
            i += 1;
        }
    }

    let libraries: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();
    let imports = elf
        .dynsyms
        .iter()
        .filter_map(|s| {
            let name = elf.dynstrtab.get_at(s.st_name)?.to_string();
            if name.is_empty() || s.st_shndx != 0 {
                return None;
            }
            let lib = if libraries.len() == 1 {
                libraries[0].clone()
            } else {
                String::new()
            };
            let addr = import_addrs.get(&name).copied().unwrap_or(s.st_value + pie_base);
            Some(Import {
                name,
                library: lib,
                offset: addr,
            })
        })
        .collect();

    let exports = elf
        .dynsyms
        .iter()
        .filter_map(|s| {
            let name = elf.dynstrtab.get_at(s.st_name)?.to_string();
            if name.is_empty() || s.st_value == 0 || s.st_shndx == 0 {
                return None;
            }
            Some(Export {
                name,
                offset: s.st_value + pie_base,
                ordinal: 0,
                forwarder: None,
            })
        })
        .collect();

    let strings = extract_all_strings(&data[..], &sections, 4);

    let mut relocations = elf_relocations(elf, arch);
    if pie_base != 0 {
        for r in &mut relocations {
            r.va += pie_base;
        }
    }

    let mut raw_end: usize = 0;
    for s in elf.section_headers.iter() {
        if s.sh_type == 8 {
            continue;
        }
        let e = (s.sh_offset as usize).saturating_add(s.sh_size as usize);
        if e > raw_end && e <= data.len() {
            raw_end = e;
        }
    }
    let sh_end = (elf.header.e_shoff as usize).saturating_add(
        (elf.header.e_shentsize as usize).saturating_mul(elf.header.e_shnum as usize),
    );
    if sh_end > raw_end && sh_end <= data.len() {
        raw_end = sh_end;
    }
    let ph_end = (elf.header.e_phoff as usize).saturating_add(
        (elf.header.e_phentsize as usize).saturating_mul(elf.header.e_phnum as usize),
    );
    if ph_end > raw_end && ph_end <= data.len() {
        raw_end = ph_end;
    }
    for ph in elf.program_headers.iter() {
        if ph.p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        let e = (ph.p_offset as usize).saturating_add(ph.p_filesz as usize);
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
        format: "ELF".to_string(),
        arch: arch.to_string(),
        entry_point: elf.entry + pie_base,
        sections,
        symbols,
        imports,
        exports,
        strings,
        data: std::sync::Arc::clone(data),
        image_base: pie_base,
        is_dll: elf.header.e_type == goblin::elf::header::ET_DYN && elf.interpreter.is_none(),
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay,
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        has_rich: false,
        libraries,
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations,
    })
}

fn reloc_width(arch: &str, typ: u32) -> u8 {
    match (arch, typ) {
        ("x86_64", 1 | 6 | 7 | 8 | 16 | 17 | 18 | 37) => 8,
        ("x86_64", 2 | 4 | 10 | 11) => 4,
        ("x86", 1 | 2 | 6 | 7 | 8 | 42) => 4,
        ("aarch64", 257 | 1025 | 1026 | 1027 | 1032) => 8,
        ("aarch64", 258) => 4,
        ("arm", 2 | 21 | 22 | 23 | 160) => 4,
        _ => 0,
    }
}

fn elf_relocations(elf: &goblin::elf::Elf, arch: &str) -> Vec<crate::parser::model::Relocation> {
    use crate::parser::model::Relocation;
    const CAP: usize = 262_144;
    let mut out: Vec<Relocation> = Vec::new();
    let mut seen: std::collections::HashSet<(u64, u32)> = std::collections::HashSet::new();
    let sym_name = |idx: usize| -> Option<String> {
        let st_name = elf.dynsyms.get(idx).map(|s| s.st_name).unwrap_or(0);
        elf.dynstrtab
            .get_at(st_name)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };
    let mut push = |rel: &goblin::elf::reloc::Reloc, artificial: bool| {
        if out.len() >= CAP || !seen.insert((rel.r_offset, rel.r_type)) {
            return;
        }
        out.push(Relocation {
            va: rel.r_offset,
            size: reloc_width(arch, rel.r_type),
            rel_type: rel.r_type,
            symbol: sym_name(rel.r_sym),
            addend: rel.r_addend.unwrap_or(0),
            is_artificial: artificial,
        });
    };
    for rel in elf.pltrelocs.iter() {
        push(&rel, true);
    }
    for rel in elf.dynrelas.iter() {
        push(&rel, false);
    }
    for (_, sec) in elf.shdr_relocs.iter() {
        for rel in sec.iter() {
            push(&rel, false);
        }
    }
    out.sort_by_key(|r| r.va);
    out
}
