use crate::parser::{ParsedBinary, Symbol};
use rustc_hash::FxHashSet as HashSet;

pub(crate) fn pdb_sections(binary: &ParsedBinary) -> Vec<(u16, u64, u64)> {
    binary
        .sections
        .iter()
        .enumerate()
        .map(|(i, s)| (i as u16 + 1, s.vaddr, s.size))
        .collect()
}

pub(crate) fn pdb_offset_to_va(
    sections: &[(u16, u64, u64)],
    off: pdb::PdbInternalSectionOffset,
) -> Option<u64> {
    let (idx, vaddr, size) = sections.iter().find(|(i, _, _)| *i == off.section)?;
    if off.offset as u64 >= *size {
        return None;
    }
    (*idx != 0).then(|| vaddr.wrapping_add(off.offset as u64))
}













pub fn find_pdb_path(
    binary: &ParsedBinary,
    source_path: Option<&str>,
) -> Option<std::path::PathBuf> {
    let mut probe = DebugSymbolsAnalyzer::new();
    probe.parse_pdb_reference(binary);
    let mut candidates: Vec<std::path::PathBuf> = probe
        .source_files
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    if let Some(src) = source_path {
        let sp = std::path::Path::new(src);
        if let Some(dir) = sp.parent() {
            let rsds_names: Vec<std::path::PathBuf> = candidates
                .iter()
                .filter_map(|c| std::path::Path::new(c).file_name())
                .map(|n| dir.join(n))
                .collect();
            candidates.extend(rsds_names);
            if let Some(stem) = sp.file_stem() {
                candidates.push(dir.join(format!("{}.pdb", stem.to_string_lossy())));
            }
            if let Ok(rd) = std::fs::read_dir(dir) {
                let mut pdbs: Vec<std::path::PathBuf> = rd
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| {
                        p.extension()
                            .is_some_and(|x| x.eq_ignore_ascii_case("pdb"))
                    })
                    .collect();
                if pdbs.len() == 1 {
                    candidates.push(pdbs.remove(0));
                }
            }
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn read_pdb_names(path: &std::path::Path, sections: &[(u16, u64, u64)]) -> rustc_hash::FxHashMap<u64, String> {
    use pdb::FallibleIterator;
    let mut out: rustc_hash::FxHashMap<u64, String> = rustc_hash::FxHashMap::default();
    let Ok(file) = std::fs::File::open(path) else {
        return out;
    };
    let Ok(mut pdb) = pdb::PDB::open(file) else {
        return out;
    };
    let Ok(dbi) = pdb.debug_information() else {
        return out;
    };
    let Ok(module_iter) = dbi.modules() else {
        return out;
    };
    let mut modules = module_iter;
    while let Ok(Some(module)) = modules.next() {
        let Ok(Some(info)) = pdb.module_info(&module) else {
            continue;
        };
        let Ok(mut symbols) = info.symbols() else {
            continue;
        };
        while let Ok(Some(sym)) = symbols.next() {
            let Ok(data) = sym.parse() else {
                continue;
            };
            let (off, name, is_code) = match data {
                pdb::SymbolData::Public(p) => (p.offset, p.name.to_string(), p.function && p.code),
                pdb::SymbolData::Procedure(p) => (p.offset, p.name.to_string(), true),
                _ => continue,
            };
            if !is_code || name.is_empty() {
                continue;
            }
            let Some(va) = pdb_offset_to_va(sections, off) else {
                continue;
            };
            out.entry(va).or_insert_with(|| name.to_string());
        }
    }
    out
}




pub fn load_pdb_function_names(
    binary: &ParsedBinary,
    source_path: Option<&str>,
) -> rustc_hash::FxHashMap<u64, String> {
    if !(binary.format.starts_with("PE") || binary.format == "COFF") {
        return Default::default();
    }
    let Some(path) = find_pdb_path(binary, source_path) else {
        return Default::default();
    };
    let sections = pdb_sections(binary);
    
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let names = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_pdb_names(&path, &sections)
    }))
    .unwrap_or_default();
    std::panic::set_hook(prev_hook);
    names
}

#[derive(Debug, Clone)]
pub struct DebugSymbolsAnalyzer {
    pub symbols: Vec<Symbol>,
    pub source_files: Vec<String>,
    pub line_numbers: Vec<LineNumber>,
}

#[derive(Debug, Clone)]
pub struct LineNumber {
    pub address: u64,
    #[allow(dead_code)]
    pub line: u32,
}

impl DebugSymbolsAnalyzer {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            source_files: Vec::new(),
            line_numbers: Vec::new(),
        }
    }

    pub fn analyze(&mut self, binary: &ParsedBinary) {
        self.analyze_with_source(binary, None);
    }

    pub fn analyze_with_source(&mut self, binary: &ParsedBinary, source_path: Option<&str>) {
        if binary.format.starts_with("PE") || binary.format == "COFF" {
            self.parse_coff_symbols(binary);
            self.parse_pdb_reference(binary);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.load_pdb_if_present(binary, source_path);
            }));
        } else if binary.format == "ELF" {
            self.parse_dwarf(binary);
        }
        self.source_files.sort();
        self.source_files.dedup();
        self.line_numbers.sort_by_key(|l| l.address);
    }

    fn load_pdb_if_present(&mut self, binary: &ParsedBinary, source_path: Option<&str>) {
        let Some(path) = find_pdb_path(binary, source_path) else {
            return;
        };
        let Ok(file) = std::fs::File::open(&path) else {
            return;
        };
        let Ok(mut pdb) = pdb::PDB::open(file) else {
            return;
        };
        let Ok(dbi) = pdb.debug_information() else {
            return;
        };
        let Ok(module_iter) = dbi.modules() else {
            return;
        };
        let Ok(string_table) = pdb.string_table() else {
            return;
        };
        let _image_base = binary.image_base;
        let sections = pdb_sections(binary);
        let to_va = |off: pdb::PdbInternalSectionOffset| -> Option<u64> {
            pdb_offset_to_va(&sections, off)
        };
        let mut seen = rustc_hash::FxHashSet::default();
        use pdb::FallibleIterator;
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut modules = module_iter;
        while let Ok(Some(module)) = modules.next() {
            let Ok(Some(info)) = pdb.module_info(&module) else {
                continue;
            };
            if let Ok(lp) = info.line_program() {
                let mut seen_files: rustc_hash::FxHashSet<pdb::FileIndex> =
                    rustc_hash::FxHashSet::default();
                let lines_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    lp.lines().collect::<Vec<pdb::LineInfo>>()
                }));
                if let Ok(Ok(lines)) = lines_result {
                    for l in lines {
                        if self.line_numbers.len() >= 8_192 {
                            break;
                        }
                        if l.line_start == 0 {
                            continue;
                        }
                        let Some(va) = to_va(l.offset) else {
                            continue;
                        };
                        self.line_numbers.push(LineNumber {
                            address: va,
                            line: l.line_start,
                        });
                        seen_files.insert(l.file_index);
                    }
                }
                let files_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    lp.files().collect::<Vec<pdb::FileInfo>>()
                }));
                if let Ok(Ok(files)) = files_result {
                    for f in files {
                        if let Ok(name) = string_table.get(f.name) {
                            self.source_files.push(name.to_string().into_owned());
                        }
                    }
                }
                let _ = seen_files;
            }
            if let Ok(symbols) = info.symbols()
                && let Ok(syms) = symbols.collect::<Vec<pdb::Symbol>>() {
                    for sym in syms {
                        let Ok(pdb::SymbolData::Public(public)) = sym.parse() else {
                            continue;
                        };
                        if !public.function || !public.code {
                            continue;
                        }
                        let Some(va) = to_va(public.offset) else {
                            continue;
                        };
                        let name = public.name.to_string().into_owned();
                        if seen.insert((va, name.clone())) {
                            self.symbols.push(crate::parser::Symbol {
                                name,
                                addr: va,
                                size: 0,
                                is_function: true,
                            });
                        }
                    }
                }
            if self.line_numbers.len() >= 8_192 {
                break;
            }
        }
        std::panic::set_hook(prev_hook);
    }

    fn parse_coff_symbols(&mut self, binary: &ParsedBinary) {
        let mut seen: HashSet<(u64, &str)> =
            HashSet::with_capacity_and_hasher(binary.symbols.len(), rustc_hash::FxBuildHasher);
        for sym in &binary.symbols {
            if seen.insert((sym.addr, sym.name.as_str())) {
                self.symbols.push(sym.clone());
            }
        }
    }

    fn parse_pdb_reference(&mut self, binary: &ParsedBinary) {
        let data = &binary.data;

        let mut pos = 0usize;
        while pos + 28 < data.len() {
            if data[pos] != b'R' {
                let rel = data[pos + 1..].iter().position(|&b| b == b'R');
                match rel {
                    Some(r) => {
                        pos += 1 + r;
                        continue;
                    }
                    None => break,
                }
            }
            if &data[pos..pos + 4] == b"RSDS" {
                let path_start = pos + 24;
                let mut end = path_start;
                while end < data.len() && data[end] != 0 && end - path_start < 512 {
                    end += 1;
                }
                if end > path_start
                    && let Ok(p) = std::str::from_utf8(&data[path_start..end]) {
                        let p = p.trim();
                        if !p.is_empty()
                            && p.to_ascii_lowercase().ends_with(".pdb")
                            && !self.source_files.contains(&p.to_string())
                        {
                            self.source_files.push(p.to_string());
                        }
                    }
                pos = end.saturating_add(1);
                continue;
            }
            pos += 1;
            if pos > data.len() {
                break;
            }
        }
        if !self.source_files.is_empty() {
            return;
        }

        let pdb_marker = b".pdb";
        if let Some(pos) = data.windows(pdb_marker.len()).position(|w| w == pdb_marker) {
            let start = pos.saturating_sub(200);
            let end = (pos + 200).min(data.len());
            let context = &data[start..end];

            if let Some(pdb_path) = extract_pdb_path(context) {
                self.source_files.push(pdb_path);
            }
        }
    }

    fn parse_dwarf(&mut self, binary: &ParsedBinary) {
        for section in &binary.sections {
            if section.name == ".debug_info" || section.name == ".debug_line" {
                self.parse_dwarf_section(binary, section);
            }
        }
    }

    fn parse_dwarf_section(&mut self, binary: &ParsedBinary, section: &crate::parser::Section) {
        let offset = section.offset as usize;
        let size = section.size as usize;
        let end = offset.saturating_add(size);

        if offset >= binary.data.len() || end > binary.data.len() {
            return;
        }

        let data = &binary.data[offset..end];

        if section.name == ".debug_line" {
            self.parse_debug_line(data);
        }
    }

    fn parse_debug_line(&mut self, data: &[u8]) {
        let mut offset = 0usize;
        while offset + 4 <= data.len() {
            let unit_length = read_u32(data, offset);
            if unit_length == 0 || unit_length == 0xFFFF_FFFF {
                break;
            }
            offset += 4;
            let unit_end = offset.saturating_add(unit_length as usize);
            if unit_end > data.len() {
                break;
            }
            self.parse_line_unit(&data[offset..unit_end]);
            offset = unit_end;
        }
    }

    fn parse_line_unit(&mut self, data: &[u8]) {
        if data.len() < 6 {
            return;
        }
        let version = read_u16(data, 0);
        if !(2..=5).contains(&version) {
            return;
        }
        let mut pos = 2usize;
        let header_length = if version <= 4 {
            if pos + 4 > data.len() {
                return;
            }
            let h = read_u32(data, pos) as usize;
            pos += 4;
            h
        } else {
            if pos + 6 > data.len() {
                return;
            }
            pos += 2;
            let h = read_u32(data, pos) as usize;
            pos += 4;
            h
        };
        let header_end = pos.saturating_add(header_length).min(data.len());
        if pos + 6 > data.len() {
            return;
        }
        let min_insn_len = data[pos].max(1);
        let _max_ops = data[pos + 1];
        let default_is_stmt = data[pos + 2] != 0;
        let line_base = data[pos + 3] as i8;
        let line_range = data[pos + 4].max(1);
        let opcode_base = data[pos + 5].max(1);
        pos += 6;
        let std_len = (opcode_base as usize).saturating_sub(1);
        if pos + std_len > data.len() {
            return;
        }
        pos += std_len;
        if version <= 4 {
            while pos < header_end && pos < data.len() {
                if data[pos] == 0 {
                    pos += 1;
                    break;
                }
                while pos < data.len() && data[pos] != 0 {
                    pos += 1;
                }
                pos += 1;
            }
            while pos < header_end && pos < data.len() {
                if data[pos] == 0 {
                    pos += 1;
                    break;
                }
                let start = pos;
                while pos < data.len() && data[pos] != 0 {
                    pos += 1;
                }
                let name = String::from_utf8_lossy(&data[start..pos.min(data.len())]).to_string();
                pos += 1;
                let (dir, n1) = read_uleb(&data[pos.min(data.len())..]);
                pos += n1;
                let (_, n2) = read_uleb(&data[pos.min(data.len())..]);
                pos += n2;
                let (_, n3) = read_uleb(&data[pos.min(data.len())..]);
                pos += n3;
                if !name.is_empty() {
                    self.source_files.push(format!(
                        "{}{}",
                        if dir > 0 {
                            format!("[dir{}]/", dir)
                        } else {
                            String::new()
                        },
                        name
                    ));
                }
            }
        } else {
            pos = header_end;
        }
        let files: Vec<String> = self
            .source_files
            .iter()
            .rev()
            .take(64)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let mut address: u64 = 0;
        let mut file_idx: usize = 1;
        let mut line: u32 = 1;
        let mut column: u32 = 0;
        let mut is_stmt = default_is_stmt;
        let mut _basic_block = false;
        let mut p = pos;
        let mut emitted = 0usize;
        while p < data.len() && emitted < 4096 {
            let op = data[p];
            p += 1;
            if op >= opcode_base {
                let adj = (op - opcode_base) as u32;
                let addr_adv = (adj / line_range as u32) as u64 * min_insn_len as u64;
                let line_adv = (adj % line_range as u32) as i32 + line_base as i32;
                address = address.wrapping_add(addr_adv);
                line = line.saturating_add_signed(line_adv);
                _basic_block = false;
                self.push_line(address, &files, file_idx, line, column, is_stmt);
                emitted += 1;
            } else if op == 0 {
                let (len, n) = read_uleb(&data[p.min(data.len())..]);
                p += n;
                if len == 0 || p >= data.len() {
                    break;
                }
                let sub = data[p];
                p += 1;
                match sub {
                    1 => {
                        address = 0;
                        file_idx = 1;
                        line = 1;
                        column = 0;
                        is_stmt = default_is_stmt;
                        _basic_block = false;
                    }
                    2 => {
                        if p + 8 <= data.len() {
                            address = u64::from_le_bytes(data[p..p + 8].try_into().unwrap());
                            p += 8;
                        } else if p + 4 <= data.len() {
                            address = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as u64;
                            p += 4;
                        } else {
                            break;
                        }
                    }
                    3 => {
                        while p < data.len() && data[p] != 0 {
                            p += 1;
                        }
                        p += 1;
                        for _ in 0..3 {
                            let (_, n) = read_uleb(&data[p.min(data.len())..]);
                            p += n;
                        }
                    }
                    _ => {
                        let skip = (len as usize).saturating_sub(1);
                        p = p.saturating_add(skip).min(data.len());
                    }
                }
            } else {
                match op {
                    1 => {
                        self.push_line(address, &files, file_idx, line, column, is_stmt);
                        emitted += 1;
                        _basic_block = false;
                    }
                    2 => {
                        let (v, n) = read_uleb(&data[p.min(data.len())..]);
                        p += n;
                        address = address.wrapping_add(v * min_insn_len as u64);
                    }
                    3 => {
                        let (v, n) = read_sleb(&data[p.min(data.len())..]);
                        p += n;
                        line = line.saturating_add_signed(v as i32);
                    }
                    4 => {
                        let (v, n) = read_uleb(&data[p.min(data.len())..]);
                        p += n;
                        file_idx = v.max(1) as usize;
                    }
                    5 => {
                        let (v, n) = read_uleb(&data[p.min(data.len())..]);
                        p += n;
                        column = v as u32;
                    }
                    6 => is_stmt = !is_stmt,
                    7 => _basic_block = true,
                    8 => {
                        let adj = (255 - opcode_base) as u64;
                        address =
                            address.wrapping_add((adj / line_range as u64) * min_insn_len as u64);
                    }
                    9 => {
                        if p + 2 > data.len() {
                            break;
                        }
                        let v = u16::from_le_bytes([data[p], data[p + 1]]) as u64;
                        p += 2;
                        address = address.wrapping_add(v);
                    }
                    _ => {
                        break;
                    }
                }
            }
        }
    }

    fn push_line(
        &mut self,
        address: u64,
        _files: &[String],
        _file_idx: usize,
        line: u32,
        _column: u32,
        _is_stmt: bool,
    ) {
        if address == 0 || line == 0 {
            return;
        }
        if self.line_numbers.len() >= 8192 {
            return;
        }
        if self.line_numbers.last().map(|l| l.address) == Some(address) {
            return;
        }
        self.line_numbers.push(LineNumber { address, line });
    }

    pub fn get_source_files(&self) -> &[String] {
        &self.source_files
    }
}

impl Default for DebugSymbolsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_pdb_path(data: &[u8]) -> Option<String> {
    let mut path = String::new();
    let mut in_path = false;

    for &byte in data {
        if byte == 0 {
            if in_path && !path.is_empty() {
                return Some(path);
            }
            path.clear();
            in_path = false;
        } else if (0x20..0x7F).contains(&byte) {
            if byte == b'.' || byte == b'\\' || byte == b'/' || byte.is_ascii_alphanumeric() {
                path.push(byte as char);
                if path.ends_with(".pdb") {
                    in_path = true;
                }
            } else {
                path.clear();
            }
        } else {
            path.clear();
        }
    }

    if in_path && !path.is_empty() {
        return Some(path);
    }

    None
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_uleb(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate().take(10) {
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return (result, i + 1);
        }
        shift += 7;
    }
    (result, data.len().clamp(1, 10))
}

fn read_sleb(data: &[u8]) -> (i64, usize) {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    for (i, &b) in data.iter().enumerate().take(10) {
        consumed = i + 1;
        result |= ((b & 0x7F) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= !0 << shift;
            }
            break;
        }
    }
    (result, consumed.max(1))
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}
