#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub offset: u64,
    pub is_executable: bool,
    pub readable: bool,
    pub writable: bool,
    pub initialized: bool,
}

impl Section {
    pub fn perms(&self) -> String {
        format!(
            "{}{}{}",
            if self.readable { "R" } else { "-" },
            if self.writable { "W" } else { "-" },
            if self.is_executable { "X" } else { "-" }
        )
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub is_function: bool,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub name: String,
    pub library: String,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub offset: u64,
    pub ordinal: u32,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub va: u64,
    pub size: u8,
    pub rel_type: u32,
    pub symbol: Option<String>,
    pub addend: i64,
    pub is_artificial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf32Le,
    Pascal,
}

#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub vaddr: u64,
    pub content: String,
    pub encoding: StringEncoding,
    pub score: f64,
}

pub fn string_label(vaddr: u64) -> String {
    format!("s_{:x}", vaddr)
}

#[derive(Debug, Clone)]
pub struct ParsedBinary {
    pub format: String,
    pub arch: String,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub strings: Vec<ExtractedString>,
    pub data: std::sync::Arc<Vec<u8>>,
    pub image_base: u64,
    pub is_dll: bool,
    pub pe_characteristics: u16,
    pub dll_characteristics: u16,
    pub overlay: Option<(u64, u64)>,
    pub tls_callbacks: Vec<u64>,
    pub delay_imports: Vec<Import>,
    pub has_rich: bool,
    pub libraries: Vec<String>,
    pub rpaths: Vec<String>,
    pub macho_uuid: Option<String>,
    pub relocations: Vec<Relocation>,
}

impl ParsedBinary {
    pub fn all_imports(&self) -> impl Iterator<Item = &Import> {
        self.imports.iter().chain(self.delay_imports.iter())
    }
}
