use crate::parser::ParsedBinary;
use rustc_hash::FxHashMap as HashMap;

#[derive(Debug, Clone)]
pub struct PEResource {
    pub resource_type: ResourceType,
    #[allow(dead_code)]
    pub id: u32,
    #[allow(dead_code)]
    pub language: u16,
    #[allow(dead_code)]
    pub offset: u64,
    #[allow(dead_code)]
    pub size: u32,
    #[allow(dead_code)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Cursor,
    Bitmap,
    Icon,
    Menu,
    Dialog,
    String,
    FontDir,
    Font,
    Accelerator,
    RCData,
    MessageTable,
    GroupCursor,
    GroupIcon,
    Version,
    DlgInclude,
    PlugPlay,
    VXD,
    AniCursor,
    AniIcon,
    HTML,
    Manifest,
    Unknown(u32),
}

impl ResourceType {
    pub fn from_id(id: u32) -> Self {
        match id {
            1 => ResourceType::Cursor,
            2 => ResourceType::Bitmap,
            3 => ResourceType::Icon,
            4 => ResourceType::Menu,
            5 => ResourceType::Dialog,
            6 => ResourceType::String,
            7 => ResourceType::FontDir,
            8 => ResourceType::Font,
            9 => ResourceType::Accelerator,
            10 => ResourceType::RCData,
            11 => ResourceType::MessageTable,
            12 => ResourceType::GroupCursor,
            14 => ResourceType::GroupIcon,
            16 => ResourceType::Version,
            17 => ResourceType::DlgInclude,
            18 => ResourceType::PlugPlay,
            19 => ResourceType::VXD,
            20 => ResourceType::AniCursor,
            21 => ResourceType::AniIcon,
            23 => ResourceType::HTML,
            24 => ResourceType::Manifest,
            _ => ResourceType::Unknown(id),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::Cursor => "Cursor",
            ResourceType::Bitmap => "Bitmap",
            ResourceType::Icon => "Icon",
            ResourceType::Menu => "Menu",
            ResourceType::Dialog => "Dialog",
            ResourceType::String => "String",
            ResourceType::FontDir => "FontDir",
            ResourceType::Font => "Font",
            ResourceType::Accelerator => "Accelerator",
            ResourceType::RCData => "RCData",
            ResourceType::MessageTable => "MessageTable",
            ResourceType::GroupCursor => "GroupCursor",
            ResourceType::GroupIcon => "GroupIcon",
            ResourceType::Version => "Version",
            ResourceType::DlgInclude => "DlgInclude",
            ResourceType::PlugPlay => "PlugPlay",
            ResourceType::VXD => "VXD",
            ResourceType::AniCursor => "AniCursor",
            ResourceType::AniIcon => "AniIcon",
            ResourceType::HTML => "HTML",
            ResourceType::Manifest => "Manifest",
            ResourceType::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PEResourceAnalyzer {
    pub resources: Vec<PEResource>,
    pub version_info: Option<VersionInfo>,
    pub version_strings: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub file_version: String,
    pub product_version: String,
    pub company_name: String,
    pub file_description: String,
    pub product_name: String,
    pub original_filename: String,
    pub internal_name: String,
    pub legal_copyright: String,
}

impl VersionInfo {
    fn empty() -> Self {
        VersionInfo {
            file_version: String::new(),
            product_version: String::new(),
            company_name: String::new(),
            file_description: String::new(),
            product_name: String::new(),
            original_filename: String::new(),
            internal_name: String::new(),
            legal_copyright: String::new(),
        }
    }
}

impl PEResourceAnalyzer {
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
            version_info: None,
            version_strings: HashMap::default(),
        }
    }

    pub fn analyze(&mut self, binary: &ParsedBinary) {
        if !binary.format.starts_with("PE") {
            return;
        }
        self.parse_resources(binary);
        self.extract_version_info(binary);
    }

    fn parse_resources(&mut self, binary: &ParsedBinary) {
        let data = &binary.data;
        for section in &binary.sections {
            if section.name == ".rsrc" {
                let dir_off = section.offset as usize;
                if dir_off + 16 > data.len() {
                    break;
                }
                let depth = 0;
                self.walk_directory(binary, dir_off, None, depth, 0, 0, section.offset);
                break;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_directory(
        &mut self,
        binary: &ParsedBinary,
        dir_offset: usize,
        context_type: Option<ResourceType>,
        depth: usize,
        type_id: u32,
        name_id: u32,
        rsrc_file_offset: u64,
    ) {
        if depth > 4 {
            return;
        }
        let data = &binary.data;
        if dir_offset + 16 > data.len() {
            return;
        }
        let num_named = read_u16(data, dir_offset + 12) as usize;
        let num_id = read_u16(data, dir_offset + 14) as usize;
        let total_entries = num_named + num_id;
        let entries_offset = dir_offset + 16;

        for i in 0..total_entries {
            let entry_offset = entries_offset + i * 8;
            if entry_offset + 8 > data.len() {
                break;
            }
            let name_or_id = read_u32(data, entry_offset);
            let data_or_dir = read_u32(data, entry_offset + 4);
            let is_directory = data_or_dir & 0x8000_0000 != 0;
            let offset_val = (data_or_dir & 0x7FFF_FFFF) as usize;

            let entry_name: Option<String> = if name_or_id & 0x8000_0000 != 0 {
                let str_off = rsrc_file_offset as usize + (name_or_id & 0x7FFF_FFFF) as usize;
                read_utf16_cstr(data, str_off, 64)
            } else {
                None
            };

            let child_type = match context_type {
                None => Some(ResourceType::from_id(name_or_id & 0x7FFF_FFFF)),
                Some(t) => Some(t),
            };
            let is_named = name_or_id & 0x8000_0000 != 0;
            let numeric = name_or_id & 0x7FFF_FFFF;
            let (next_type, next_name) = match depth {
                0 => (if is_named { type_id } else { numeric }, name_id),
                1 => (type_id, if is_named { 0 } else { numeric }),
                _ => (type_id, name_id),
            };

            if is_directory {
                let sub_off = rsrc_file_offset as usize + offset_val;
                if sub_off > data.len() {
                    continue;
                }
                self.walk_directory(
                    binary,
                    sub_off,
                    child_type,
                    depth + 1,
                    next_type,
                    next_name,
                    rsrc_file_offset,
                );
            } else if depth == 2 {
                let entry_off = rsrc_file_offset as usize + offset_val;
                if entry_off + 16 > data.len() {
                    continue;
                }
                let data_rva = read_u32(data, entry_off);
                let size = read_u32(data, entry_off + 4);
                let vaddr = binary.image_base.wrapping_add(data_rva as u64);

                let res_type = context_type.unwrap_or_else(|| ResourceType::from_id(type_id));
                self.resources.push(PEResource {
                    resource_type: res_type,
                    id: name_id,
                    language: (name_or_id & 0xFFFF) as u16,
                    offset: vaddr,
                    size,
                    name: entry_name,
                });
            } else {
                let res_type = context_type.unwrap_or_else(|| ResourceType::from_id(type_id));
                self.resources.push(PEResource {
                    resource_type: res_type,
                    id: name_or_id,
                    language: 0,
                    offset: 0,
                    size: 0,
                    name: entry_name,
                });
            }
        }
    }

    fn extract_version_info(&mut self, binary: &ParsedBinary) {
        let data = &binary.data;
        let needle: Vec<u8> = "VS_VERSION_INFO"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut strings: HashMap<String, String> = HashMap::default();

        for section in &binary.sections {
            if section.name != ".rsrc" {
                continue;
            }
            let start = section.offset as usize;
            let end = start.saturating_add(section.size as usize).min(data.len());
            let window = &data[start..end];
            let mut pos = 0;
            while pos + needle.len() <= window.len() {
                if &window[pos..pos + needle.len()] == needle.as_slice() {
                    self.walk_version_block(window, start + pos, &mut strings, 0);
                    break;
                }
                pos += 2;
            }
            if !strings.is_empty() {
                break;
            }
        }

        if strings.is_empty() {
            return;
        }

        self.version_strings = strings.clone();
        let mut info = VersionInfo::empty();
        let pick = |key: &str| -> String { strings.get(key).cloned().unwrap_or_default() };
        info.file_version = pick("FileVersion");
        info.product_version = pick("ProductVersion");
        info.company_name = pick("CompanyName");
        info.file_description = pick("FileDescription");
        info.product_name = pick("ProductName");
        info.original_filename = pick("OriginalFilename");
        info.internal_name = pick("InternalName");
        info.legal_copyright = pick("LegalCopyright");
        self.version_info = Some(info);
    }

    fn walk_version_block(
        &self,
        data: &[u8],
        offset: usize,
        strings: &mut HashMap<String, String>,
        depth: usize,
    ) {
        if depth > 8 || offset + 6 > data.len() {
            return;
        }
        let len = read_u16(data, offset) as usize;
        if len < 6 || offset + len > data.len() {
            return;
        }
        let value_len = read_u16(data, offset + 2) as usize;
        let _value_type = read_u16(data, offset + 4);

        let key = read_utf16_cstr(data, offset + 6, 128).unwrap_or_default();
        if key.is_empty() {
            return;
        }
        let key_utf16_bytes = key.encode_utf16().count() * 2 + 2;
        let mut value_off = offset + 6 + key_utf16_bytes;
        value_off = (value_off + 3) & !3;

        let is_container = matches!(
            key.as_str(),
            "VS_VERSION_INFO" | "StringFileInfo" | "VarFileInfo" | "Var"
        ) || (key.len() == 8 && key.chars().all(|c| c.is_ascii_hexdigit()));

        if !is_container {
            let vbytes = value_len.saturating_mul(2);
            let v = if vbytes > 0 && value_off + vbytes <= data.len() {
                decode_utf16_lossy(&data[value_off..value_off + vbytes])
            } else {
                read_utf16_cstr(data, value_off, 512).unwrap_or_default()
            };
            if !v.is_empty() {
                strings.insert(key, v);
            }
            return;
        }

        let mut child_off = value_off;
        if value_len > 0 {
            child_off = (child_off + value_len + 3) & !3;
        }
        let block_end = offset + len;
        while child_off + 6 <= block_end && child_off + 6 <= data.len() {
            let child_len = read_u16(data, child_off) as usize;
            if child_len == 0 || child_off + child_len > block_end {
                break;
            }
            self.walk_version_block(data, child_off, strings, depth + 1);
            child_off += (child_len + 3) & !3;
        }
    }

    pub fn get_resources_by_type(&self) -> HashMap<ResourceType, Vec<&PEResource>> {
        let mut map = HashMap::default();
        for res in &self.resources {
            map.entry(res.resource_type)
                .or_insert_with(Vec::new)
                .push(res);
        }
        map
    }

    pub fn get_resource_count(&self) -> usize {
        self.resources.len()
    }
}

impl Default for PEResourceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_utf16_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn read_utf16_cstr(data: &[u8], offset: usize, max_units: usize) -> Option<String> {
    if offset + 2 > data.len() {
        return None;
    }
    let mut units = Vec::new();
    let mut i = offset;
    while units.len() < max_units && i + 1 < data.len() {
        let lo = data[i] as u16;
        let hi = data[i + 1] as u16;
        let cu = lo | (hi << 8);
        if cu == 0 {
            break;
        }
        units.push(cu);
        i += 2;
    }
    let s = String::from_utf16(&units).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
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

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}
