use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

pub const ARCHIVE_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Arch {
    X86,
    X64,
}

impl Arch {
    pub fn pointer_size(self) -> usize {
        match self {
            Arch::X86 => 4,
            Arch::X64 => 8,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "x86" | "x86_32" | "i386" | "i686" | "32" | "x86-32" => Some(Arch::X86),
            "x64" | "x86_64" | "amd64" | "64" | "x86-64" => Some(Arch::X64),
            _ => None,
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X64 => "x64",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRef {
    Named(String),
    Pointer(Box<TypeRef>),
    Array(Box<TypeRef>, usize),
}

impl TypeRef {
    pub fn named(name: &str) -> Self {
        TypeRef::Named(name.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveParam {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFunction {
    pub name: String,
    pub module: String,
    pub ret: String,
    pub params: Vec<ArchiveParam>,
    pub cc: String,
    pub varargs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedField {
    pub name: String,
    pub ty: String,
    pub offset: usize,
    pub size: usize,
    pub bit_offset: Option<u8>,
    pub bit_width: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Primitive {
        size: usize,
        signed: bool,
        float: bool,
        spelling: String,
    },
    Pointer {
        target: String,
    },
    Array {
        element: String,
        count: usize,
    },
    Aggregate {
        fields: Vec<ResolvedField>,
        pack: Option<usize>,
        is_union: bool,
        explicit_size: Option<usize>,
    },
    Enum {
        underlying: String,
        variants: Vec<(String, i64)>,
    },
    Alias {
        target: String,
    },
    Function {
        ret: String,
        params: Vec<ArchiveParam>,
        cc: String,
        varargs: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedType {
    pub name: String,
    pub kind: TypeKind,
    pub size: usize,
    pub align: usize,
    pub arch: Arch,
}

impl ResolvedType {
    pub fn is_aggregate(&self) -> bool {
        matches!(self.kind, TypeKind::Aggregate { .. })
    }

    pub fn fields(&self) -> &[ResolvedField] {
        match &self.kind {
            TypeKind::Aggregate { fields, .. } => fields,
            _ => &[],
        }
    }

    pub fn is_union(&self) -> bool {
        matches!(self.kind, TypeKind::Aggregate { is_union: true, .. })
    }

    pub fn field_at(&self, offset: usize) -> Option<&ResolvedField> {
        self.fields().iter().find(|f| f.offset == offset)
    }
}

#[derive(Debug, Clone)]
pub struct TypeArchive {
    name: String,
    version: String,
    arch: Arch,
    types: BTreeMap<String, ResolvedType>,
    functions: BTreeMap<String, ArchiveFunction>,
    by_plain_name: BTreeMap<String, String>,
    unknown: BTreeSet<String>,
    laid_out: BTreeSet<String>,
}

impl TypeArchive {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn type_names(&self) -> impl Iterator<Item = &str> {
        self.types.keys().map(|s| s.as_str())
    }

    pub fn get(&self, name: &str) -> Option<&ResolvedType> {
        self.types.get(name)
    }

    pub fn unknown_types(&self) -> &BTreeSet<String> {
        &self.unknown
    }

    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    pub fn functions(&self) -> impl Iterator<Item = (&str, &ArchiveFunction)> {
        self.functions.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn chase_alias(&self, name: &str) -> Option<&ResolvedType> {
        let mut cur = name;
        for _ in 0..16 {
            let ty = self.types.get(cur)?;
            match &ty.kind {
                TypeKind::Alias { target } => cur = target,
                _ => return Some(ty),
            }
        }
        None
    }

    pub fn pointee(&self, name: &str) -> Option<String> {
        match &self.chase_alias(name)?.kind {
            TypeKind::Pointer { target } => Some(target.clone()),
            _ => None,
        }
    }

    pub fn pointee_aggregate(&self, name: &str) -> Option<&ResolvedType> {
        let target = self.pointee(name)?;
        let ty = self.chase_alias(&target)?;
        ty.is_aggregate().then_some(ty)
    }

    pub fn size_of(&self, name: &str) -> Option<usize> {
        self.types.get(name).map(|t| t.size)
    }

    pub fn render(&self, name: &str) -> String {
        self.render_depth(name, 0)
    }

    fn render_depth(&self, name: &str, depth: usize) -> String {
        if depth > 12 {
            return "void *".into();
        }
        match self.types.get(name) {
            Some(ResolvedType {
                kind: TypeKind::Pointer { target },
                ..
            }) => format!("{} *", self.render_depth(target, depth + 1)),
            Some(ResolvedType {
                kind: TypeKind::Array { element, count },
                ..
            }) => format!("{}[{}]", self.render_depth(element, depth + 1), count),
            Some(t) => match &t.kind {
                TypeKind::Primitive { spelling, .. } => spelling.clone(),
                _ => name.to_string(),
            },
            None => name.to_string(),
        }
    }

    pub fn type_ref(&self, name: &str) -> TypeRef {
        match self.types.get(name) {
            Some(ResolvedType {
                kind: TypeKind::Pointer { target },
                ..
            }) => TypeRef::Pointer(Box::new(self.type_ref(target))),
            Some(ResolvedType {
                kind: TypeKind::Array { element, count },
                ..
            }) => TypeRef::Array(Box::new(self.type_ref(element)), *count),
            _ => TypeRef::Named(name.to_string()),
        }
    }

    pub fn function(&self, module: &str, name: &str) -> Option<&ArchiveFunction> {
        let module = normalize_module(module);
        let symbol = normalize_symbol(name);
        for key in [
            format!("{}!{}", module, symbol.to_ascii_lowercase()),
            format!("{}!{}", module, name.to_ascii_lowercase()),
            format!("*!{}", symbol.to_ascii_lowercase()),
        ] {
            if let Some(f) = self.functions.get(&key) {
                return Some(f);
            }
        }
        None
    }

    pub fn function_any_module(&self, name: &str) -> Option<&ArchiveFunction> {
        let symbol = normalize_symbol(name).to_ascii_lowercase();
        if let Some(key) = self.by_plain_name.get(&symbol) {
            return self.functions.get(key);
        }
        self.functions.get(&format!("*!{}", symbol))
    }
}

fn normalize_module(module: &str) -> String {
    let m = module.trim().to_ascii_lowercase();
    m.trim_end_matches(".dll")
        .trim_end_matches(".drv")
        .trim_end_matches(".exe")
        .to_string()
}

pub fn normalize_symbol(name: &str) -> String {
    let mut s = name.trim();
    if let Some(i) = s.find('!') {
        s = &s[i + 1..];
    }
    loop {
        let before = s.len();
        for prefix in ["__imp_", "_imp__", "__imp__", "_", "@", "?"] {
            if let Some(rest) = s.strip_prefix(prefix) {
                s = rest;
                break;
            }
        }
        if s.len() == before {
            break;
        }
    }
    loop {
        let before = s.len();
        if let Some(at) = s.rfind('@')
            && at + 1 < s.len()
            && s[at + 1..].chars().all(|c| c.is_ascii_digit())
        {
            s = &s[..at];
        }
        if s.len() == before {
            break;
        }
    }
    s.to_string()
}

#[derive(Debug, Clone)]
pub struct TypeArchiveSet {
    arch: Arch,
    archives: Vec<TypeArchive>,
}

impl TypeArchiveSet {
    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn archives(&self) -> &[TypeArchive] {
        &self.archives
    }

    pub fn archive(&self, name: &str) -> Option<&TypeArchive> {
        self.archives
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name.trim()))
    }

    pub fn type_count(&self) -> usize {
        self.archives.iter().map(|a| a.types.len()).sum()
    }

    pub fn function_count(&self) -> usize {
        self.archives.iter().map(|a| a.functions.len()).sum()
    }

    pub fn get(&self, name: &str) -> Option<&ResolvedType> {
        self.archives.iter().find_map(|a| a.get(name))
    }

    pub fn function(&self, module: &str, name: &str) -> Option<&ArchiveFunction> {
        self.archives.iter().find_map(|a| a.function(module, name))
    }

    pub fn function_any_module(&self, name: &str) -> Option<&ArchiveFunction> {
        self.archives
            .iter()
            .find_map(|a| a.function_any_module(name))
    }

    pub fn render(&self, name: &str) -> Option<String> {
        self.archives
            .iter()
            .find(|a| a.get(name).is_some())
            .map(|a| a.render(name))
    }

    pub fn pointee(&self, name: &str) -> Option<String> {
        self.archives.iter().find_map(|a| a.pointee(name))
    }

    pub fn size_of(&self, name: &str) -> Option<usize> {
        self.archives.iter().find_map(|a| a.size_of(name))
    }

    pub fn pointee_aggregate(&self, name: &str) -> Option<&ResolvedType> {
        self.archives
            .iter()
            .find_map(|a| a.pointee_aggregate(name))
    }

    pub fn unknown_types(&self) -> BTreeSet<String> {
        self.archives
            .iter()
            .flat_map(|a| a.unknown.iter().cloned())
            .collect()
    }
}

const WIN32_FILES: &[&str] = &[
    include_str!("../../data/types/win32/typedefs.json"),
    include_str!("../../data/types/win32/structs.json"),
    include_str!("../../data/types/win32/enums.json"),
    include_str!("../../data/types/win32/api-kernel32.json"),
    include_str!("../../data/types/win32/api-kernelbase.json"),
    include_str!("../../data/types/win32/api-ntdll.json"),
    include_str!("../../data/types/win32/api-user32.json"),
    include_str!("../../data/types/win32/api-advapi32.json"),
];

const CRT_FILES: &[&str] = &[
    include_str!("../../data/types/crt/typedefs.json"),
    include_str!("../../data/types/crt/structs.json"),
    include_str!("../../data/types/crt/api-ucrt.json"),
];

const LIBC_FILES: &[&str] = &[
    include_str!("../../data/types/libc/typedefs.json"),
    include_str!("../../data/types/libc/structs.json"),
];

fn source_files() -> [(&'static str, &'static [&'static str]); 3] {
    [
        ("win32", WIN32_FILES),
        ("crt", CRT_FILES),
        ("libc", LIBC_FILES),
    ]
}

pub fn embedded_archive(name: &str, arch: Arch) -> Result<TypeArchive, String> {
    let lower = name.trim().to_ascii_lowercase();
    let (canonical, files) = match lower.as_str() {
        "win32" => ("win32", WIN32_FILES),
        "crt" => ("crt", CRT_FILES),
        "libc" => ("libc", LIBC_FILES),
        other => {
            return Err(format!(
                "Unknown archive '{}' (want one of: win32, crt, libc)",
                other
            ));
        }
    };
    TypeArchive::from_documents(canonical, arch, files)
}

pub fn parse_archive(name: &str, arch: Arch, docs: &[&str]) -> Result<TypeArchive, String> {
    TypeArchive::from_documents(name, arch, docs)
}

impl TypeArchiveSet {
    pub fn embedded(arch: Arch) -> Result<Self, String> {
        let mut archives = Vec::new();
        for (name, docs) in source_files() {
            archives.push(TypeArchive::from_documents(name, arch, docs)?);
        }
        Ok(Self { arch, archives })
    }

    pub fn from_arch_name(name: &str) -> Result<Self, String> {
        let arch = Arch::from_name(name)
            .ok_or_else(|| format!("Unsupported archive architecture '{}'", name))?;
        Self::embedded(arch)
    }
}

static ARCHIVE_X64: OnceLock<Option<Arc<TypeArchiveSet>>> = OnceLock::new();
static ARCHIVE_X86: OnceLock<Option<Arc<TypeArchiveSet>>> = OnceLock::new();

pub fn embedded_archives(pointer_size: usize) -> Option<&'static Arc<TypeArchiveSet>> {
    let (slot, arch) = if pointer_size <= 4 {
        (&ARCHIVE_X86, Arch::X86)
    } else {
        (&ARCHIVE_X64, Arch::X64)
    };
    slot.get_or_init(|| TypeArchiveSet::embedded(arch).ok().map(Arc::new))
        .as_ref()
}

struct RawArchive {
    name: String,
    version: String,
    arch: Arch,
    raw_types: BTreeMap<String, Value>,
    functions: BTreeMap<String, ArchiveFunction>,
}

impl TypeArchive {
    fn from_documents(name: &str, arch: Arch, docs: &[&str]) -> Result<Self, String> {
        let mut raw = RawArchive {
            name: name.to_string(),
            version: String::new(),
            arch,
            raw_types: BTreeMap::new(),
            functions: BTreeMap::new(),
        };
        for text in docs {
            let doc: Value =
                serde_json::from_str(text).map_err(|e| format!("{name}: invalid JSON: {e}"))?;
            raw.absorb(&doc)?;
        }
        raw.finish()
    }
}

impl RawArchive {
    fn absorb(&mut self, doc: &Value) -> Result<(), String> {
        let schema = doc
            .get("schema")
            .and_then(Value::as_u64)
            .unwrap_or(ARCHIVE_SCHEMA as u64);
        if schema != ARCHIVE_SCHEMA as u64 {
            return Err(format!(
                "archive '{}' uses schema {} (this build supports {})",
                self.name, schema, ARCHIVE_SCHEMA
            ));
        }
        if let Some(version) = doc.get("version").and_then(Value::as_str)
            && self.version.is_empty()
        {
            self.version = version.to_string();
        }
        if let Some(arch) = doc.get("arch").and_then(Value::as_str)
            && Arch::from_name(arch) != Some(self.arch)
        {
            return Ok(());
        }
        if let Some(Value::Object(variants)) = doc.get("variants")
            && let Some(section) = variants.get(self.arch.tag())
            && let Some(obj) = section.as_object()
        {
            for (k, v) in obj {
                if matches!(k.as_str(), "typedefs" | "structs" | "unions" | "enums") {
                    self.absorb_type_section(k, v)?;
                }
            }
        }
        for section in ["typedefs", "structs", "unions", "enums"] {
            if let Some(v) = doc.get(section) {
                self.absorb_type_section(section, v)?;
            }
        }
        if let Some(funcs) = doc.get("functions") {
            self.absorb_functions(doc, funcs)?;
        }
        Ok(())
    }

    fn absorb_type_section(&mut self, section: &str, value: &Value) -> Result<(), String> {
        let obj = value
            .as_object()
            .ok_or_else(|| format!("{}: '{}' must be an object", self.name, section))?;
        for (name, def) in obj {
            if name.trim().is_empty() {
                return Err(format!("{}: empty type name in '{}'", self.name, section));
            }
            let mut merged = def.clone();
            if let Some(map) = merged.as_object_mut() {
                map.insert("__section".into(), Value::String(section.to_string()));
            }
            self.raw_types.insert(name.clone(), merged);
        }
        Ok(())
    }

    fn absorb_functions(&mut self, doc: &Value, value: &Value) -> Result<(), String> {
        let obj = value
            .as_object()
            .ok_or_else(|| format!("{}: 'functions' must be an object", self.name))?;
        let default_module = doc
            .get("module")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        for (name, def) in obj {
            let module = def
                .get("module")
                .and_then(Value::as_str)
                .unwrap_or(default_module.as_str())
                .to_string();
            let ret = def
                .get("ret")
                .and_then(Value::as_str)
                .unwrap_or("void")
                .to_string();
            let cc = def
                .get("cc")
                .and_then(Value::as_str)
                .unwrap_or("stdcall")
                .to_string();
            let varargs = def.get("varargs").and_then(Value::as_bool).unwrap_or(false);
            let mut params = Vec::new();
            if let Some(list) = def.get("params").and_then(Value::as_array) {
                for p in list {
                    let pname = p
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let pty = p
                        .get("type")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            format!(
                                "{}: function '{}' has a parameter without a type",
                                self.name, name
                            )
                        })?
                        .to_string();
                    params.push(ArchiveParam { name: pname, ty: pty });
                }
            }
            let func = ArchiveFunction {
                name: name.clone(),
                module: module.clone(),
                ret,
                params,
                cc,
                varargs,
            };
            let key = format!(
                "{}!{}",
                normalize_module(&module),
                normalize_symbol(name).to_ascii_lowercase()
            );
            self.functions.insert(key, func);
        }
        Ok(())
    }

    fn finish(mut self) -> Result<TypeArchive, String> {
        let version = if self.version.is_empty() {
            "unspecified".to_string()
        } else {
            self.version.clone()
        };
        let mut archive = TypeArchive {
            name: self.name.clone(),
            version,
            arch: self.arch,
            types: BTreeMap::new(),
            functions: BTreeMap::new(),
            by_plain_name: BTreeMap::new(),
            unknown: BTreeSet::new(),
            laid_out: BTreeSet::new(),
        };
        let raw_types = std::mem::take(&mut self.raw_types);
        let mut resolving: Vec<String> = Vec::new();
        for name in raw_types.keys() {
            archive.need_layout(name, &raw_types, &mut resolving)?;
        }
        let mut functions: BTreeMap<String, ArchiveFunction> = BTreeMap::new();
        for (key, func) in &self.functions {
            let ret = archive.resolve_type_expr(&func.ret, &raw_types, &mut Vec::new())?;
            let mut params = Vec::new();
            let mut ok = true;
            for p in &func.params {
                match archive.resolve_type_expr(&p.ty, &raw_types, &mut Vec::new()) {
                    Ok(ty) => params.push(ArchiveParam {
                        name: p.name.clone(),
                        ty,
                    }),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            functions.insert(
                key.clone(),
                ArchiveFunction {
                    name: func.name.clone(),
                    module: func.module.clone(),
                    ret,
                    params,
                    cc: func.cc.clone(),
                    varargs: func.varargs,
                },
            );
        }
        let mut by_module: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, f) in &functions {
            let module = normalize_module(&f.module);
            by_module
                .entry(format!("{}!{}", module, key.rsplit('!').next().unwrap_or(key)))
                .or_default()
                .push(key.clone());
        }
        for (_, keys) in by_module {
            if keys.len() == 1
                && let Some(key) = keys.first()
                && let Some(f) = functions.get(key)
            {
                archive
                    .by_plain_name
                    .entry(normalize_symbol(&f.name).to_ascii_lowercase())
                    .or_insert_with(|| key.clone());
            }
        }
        archive.functions = functions;
        Ok(archive)
    }
}

fn section_of(def: &Value) -> &str {
    def.get("__section").and_then(Value::as_str).unwrap_or("")
}

fn alias_text(def: &Value) -> Option<&str> {
    def.get("to").and_then(Value::as_str).or_else(|| def.as_str())
}

fn primitive_of(text: &str, pointer_size: usize) -> Option<(usize, bool, bool, String)> {
    let t = text.trim();
    let key = t
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let prim = |size: usize, signed: bool, float: bool| Some((size, signed, float, t.to_string()));
    match key.as_str() {
        "void" => prim(0, false, false),
        "char" | "signed char" => prim(1, true, false),
        "unsigned char" | "uchar" | "uint8_t" | "uint8" => prim(1, false, false),
        "int8_t" | "int8" => prim(1, true, false),
        "short" | "short int" | "signed short" | "signed short int" | "int16_t" | "int16" => {
            prim(2, true, false)
        }
        "unsigned short" | "unsigned short int" | "ushort" | "uint16_t" | "uint16" => {
            prim(2, false, false)
        }
        "wchar_t" | "char16_t" => prim(2, false, false),
        "int" | "signed" | "signed int" | "int32_t" | "int32" => prim(4, true, false),
        "unsigned int" | "unsigned" | "uint" | "uint32_t" | "uint32" => prim(4, false, false),
        "long" | "long int" | "signed long" | "signed long int" => prim(4, true, false),
        "unsigned long" | "unsigned long int" | "ulong" | "long unsigned int" => {
            prim(4, false, false)
        }
        "char32_t" => prim(4, false, false),
        "long long" | "long long int" | "signed long long" | "__int64" | "int64_t" | "int64" => {
            prim(8, true, false)
        }
        "unsigned long long"
        | "unsigned long long int"
        | "unsigned __int64"
        | "uint64_t"
        | "uint64" => prim(8, false, false),
        "float" => prim(4, false, true),
        "double" | "long double" => prim(8, false, true),
        "bool" | "_bool" => prim(1, false, false),
        "uintptr_t" | "size_t" | "ulong_ptr" | "dword_ptr" | "uint_ptr" => {
            prim(pointer_size, false, false)
        }
        "intptr_t" | "ssize_t" | "ptrdiff_t" | "long_ptr" | "int_ptr" => {
            prim(pointer_size, true, false)
        }
        _ => None,
    }
}

fn function_pointer_target(s: &str) -> bool {
    let Some(open) = s.find('(') else {
        return false;
    };
    let Some(rel_close) = s[open..].find(')') else {
        return false;
    };
    let close = open + rel_close;
    let inner = &s[open + 1..close];
    inner.contains('*') && s[close + 1..].trim_start().starts_with('(')
}

pub fn parse_type_expr(text: &str) -> TypeRef {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut s = collapsed.trim();
    if s.is_empty() {
        return TypeRef::named("void");
    }
    if function_pointer_target(s) {
        return TypeRef::named("void *");
    }
    loop {
        let before = s.len();
        for q in ["const ", "volatile "] {
            if let Some(rest) = s.strip_prefix(q) {
                s = rest.trim_start();
            }
        }
        for q in [" const", " volatile"] {
            if let Some(rest) = s.strip_suffix(q) {
                s = rest.trim_end();
            }
        }
        if s.len() == before {
            break;
        }
    }
    let mut dims: Vec<usize> = Vec::new();
    while s.ends_with(']')
        && let Some(open) = s.rfind('[')
    {
        match s[open + 1..s.len() - 1].trim().parse::<usize>() {
            Ok(n) => dims.push(n.max(1)),
            Err(_) => break,
        }
        s = s[..open].trim_end();
    }
    let mut ptrs = 0usize;
    while let Some(rest) = s.strip_suffix('*') {
        s = rest.trim_end();
        ptrs += 1;
    }
    if s.is_empty() {
        return TypeRef::named("void");
    }
    let mut ty = TypeRef::named(s);
    for _ in 0..ptrs {
        ty = TypeRef::Pointer(Box::new(ty));
    }
    for count in dims {
        ty = TypeRef::Array(Box::new(ty), count);
    }
    ty
}

impl TypeArchive {
    fn resolve_type_expr(
        &mut self,
        text: &str,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        let tref = parse_type_expr(text);
        self.resolve_ref(&tref, raw, resolving)
    }

    fn resolve_ref(
        &mut self,
        tref: &TypeRef,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        match tref {
            TypeRef::Named(name) => self.need_layout(name, raw, resolving),
            TypeRef::Pointer(inner) => {
                let target = self.need_name_ref(inner, raw, resolving)?;
                Ok(self.intern_pointer(&target))
            }
            TypeRef::Array(inner, count) => {
                let element = self.resolve_ref(inner, raw, resolving)?;
                Ok(self.intern_array(&element, *count))
            }
        }
    }

    fn need_name_ref(
        &mut self,
        tref: &TypeRef,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        match tref {
            TypeRef::Named(name) => self.need_name(name, raw),
            TypeRef::Pointer(inner) => {
                let target = self.need_name_ref(inner, raw, resolving)?;
                Ok(self.intern_pointer(&target))
            }
            TypeRef::Array(..) => self.resolve_ref(tref, raw, resolving),
        }
    }

    fn need_name(&mut self, name: &str, raw: &BTreeMap<String, Value>) -> Result<String, String> {
        if let Some(canonical) = lookup_exact(raw, name) {
            return Ok(canonical);
        }
        if self.types.contains_key(name) {
            return Ok(name.to_string());
        }
        if let Some(p) = primitive_of(name, self.arch.pointer_size()) {
            return Ok(self.intern_primitive(p));
        }
        if let Some(canonical) = lookup_loose(raw, name) {
            return Ok(canonical);
        }
        self.unknown.insert(name.to_string());
        Ok(name.to_string())
    }

    fn intern_pointer(&mut self, target: &str) -> String {
        let key = format!("{} *", target.trim());
        if !self.types.contains_key(&key) {
            let size = self.arch.pointer_size();
            self.types.insert(
                key.clone(),
                ResolvedType {
                    name: key.clone(),
                    kind: TypeKind::Pointer {
                        target: target.trim().to_string(),
                    },
                    size,
                    align: size,
                    arch: self.arch,
                },
            );
        }
        key
    }

    fn intern_array(&mut self, element: &str, count: usize) -> String {
        let key = format!("{}[{}]", element, count);
        if !self.types.contains_key(&key) {
            let (esize, ealign) = self
                .types
                .get(element)
                .map(|t| (t.size, t.align))
                .unwrap_or((1, 1));
            self.types.insert(
                key.clone(),
                ResolvedType {
                    name: key.clone(),
                    kind: TypeKind::Array {
                        element: element.to_string(),
                        count,
                    },
                    size: esize.saturating_mul(count),
                    align: ealign.max(1),
                    arch: self.arch,
                },
            );
        }
        key
    }

    fn intern_primitive(&mut self, p: (usize, bool, bool, String)) -> String {
        let (size, signed, float, spelling) = p;
        let key = spelling.to_ascii_lowercase();
        if !self.types.contains_key(&key) {
            self.types.insert(
                key.clone(),
                ResolvedType {
                    name: key.clone(),
                    kind: TypeKind::Primitive {
                        size,
                        signed,
                        float,
                        spelling,
                    },
                    size,
                    align: size.max(1),
                    arch: self.arch,
                },
            );
        }
        key
    }

    fn need_layout(
        &mut self,
        name: &str,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        if self.laid_out.contains(name) {
            return Ok(name.to_string());
        }
        let exact = lookup_exact_value(raw, name);
        let Some((canonical, def)) = exact else {
            if let Some(p) = primitive_of(name, self.arch.pointer_size()) {
                let key = self.intern_primitive(p);
                self.laid_out.insert(key.clone());
                return Ok(key);
            }
            if let Some(canonical) = lookup_loose(raw, name)
                && let Some(def) = raw.get(&canonical)
            {
                return self.layout_raw(&canonical, def, raw, resolving).inspect(|id| {
                    let _ = id;
                });
            }
            self.unknown.insert(name.to_string());
            self.laid_out.insert(name.to_string());
            return Ok(name.to_string());
        };
        self.layout_raw(&canonical, def, raw, resolving)
    }

    fn layout_raw(
        &mut self,
        canonical: &str,
        def: &Value,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        if self.laid_out.contains(canonical) {
            return Ok(canonical.to_string());
        }
        if resolving.iter().any(|n| n == canonical) {
            return Err(format!(
                "{}: type '{}' embeds itself by value (cycle: {} -> {})",
                self.name,
                canonical,
                resolving.join(" -> "),
                canonical
            ));
        }
        resolving.push(canonical.to_string());
        let resolved = self.build_type(canonical, def, raw, resolving);
        resolving.pop();
        let resolved = resolved?;
        self.laid_out.insert(resolved.clone());
        Ok(resolved)
    }

    fn build_type(
        &mut self,
        canonical: &str,
        def: &Value,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        let section = section_of(def).to_string();
        if let Some(text) = alias_text(def) {
            return self.build_alias(canonical, text, raw, resolving);
        }
        let obj = def.as_object().ok_or_else(|| {
            format!(
                "{}: type '{}' must be a string, a {{\"to\": ...}} alias or an object",
                self.name, canonical
            )
        })?;
        if let Some(to) = obj.get("to").and_then(Value::as_str) {
            return self.build_alias(canonical, to, raw, resolving);
        }
        let is_union =
            section == "unions" || obj.get("union").and_then(Value::as_bool) == Some(true);
        let arch_variants = obj
            .get("variants")
            .and_then(Value::as_object)
            .is_some_and(|v| v.contains_key("x86") || v.contains_key("x64"));
        let aggregate = section == "structs"
            || section == "unions"
            || obj.contains_key("fields")
            || arch_variants;
        if obj.contains_key("variants") && !aggregate {
            return self.build_enum(canonical, obj, raw, resolving);
        }
        if obj.contains_key("params") && !aggregate {
            return self.build_function_type(canonical, obj, raw, resolving);
        }
        if !aggregate {
            return self.build_enum(canonical, obj, raw, resolving);
        }
        let pack = obj
            .get("pack")
            .and_then(Value::as_u64)
            .map(|p| (p as usize).clamp(1, 32));
        let explicit_size = obj
            .get("size")
            .and_then(Value::as_u64)
            .map(|s| s as usize)
            .or_else(|| variant_size_for(obj, self.arch));
        let field_defs = field_defs_for(obj, self.arch)?;
        let mut fields: Vec<ResolvedField> = Vec::new();
        let mut offset = 0usize;
        let mut align = 1usize;
        let mut open_bits: Option<(usize, usize, usize)> = None;
        for fd in &field_defs {
            let fname = fd
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if fname.is_empty() {
                return Err(format!("{}: '{}' has a field without a name", self.name, canonical));
            }
            let fty_text = fd
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{}: field '{}.{}' has no type", self.name, canonical, fname))?;
            let fty = self.resolve_type_expr(fty_text, raw, resolving)?;
            let (fsize, falign) = self
                .types
                .get(&fty)
                .map(|t| (t.size, t.align))
                .unwrap_or((0, 1));
            let bit_width = fd.get("bit_width").and_then(Value::as_u64).map(|w| w as u8);
            if let Some(width) = bit_width {
                let storage_bits = fsize.saturating_mul(8);
                if storage_bits == 0 || width == 0 || width as usize > storage_bits {
                    return Err(format!(
                        "{}: bitfield '{}.{}' width {} does not fit in {} bits",
                        self.name, canonical, fname, width, storage_bits
                    ));
                }
                let (unit_off, used) = match open_bits {
                    Some((o, u, s)) if u + width as usize <= storage_bits && s == fsize => (o, u),
                    _ => {
                        let a = pack.map_or(falign.max(1), |p| falign.min(p).max(1));
                        let explicit = fd.get("offset").and_then(Value::as_u64).map(|o| o as usize);
                        let o = match explicit {
                            Some(o) if !is_union => o,
                            _ if is_union => 0,
                            _ => round_up(offset, a),
                        };
                        align = align.max(a);
                        (o, 0usize)
                    }
                };
                fields.push(ResolvedField {
                    name: fname,
                    ty: fty.clone(),
                    offset: unit_off,
                    size: fsize,
                    bit_offset: Some(used as u8),
                    bit_width: Some(width),
                });
                open_bits = Some((unit_off, used + width as usize, fsize));
                if !is_union {
                    offset = unit_off + fsize;
                }
                continue;
            }
            open_bits = None;
            let a = pack.map_or(falign.max(1), |p| falign.min(p).max(1));
            let explicit = fd.get("offset").and_then(Value::as_u64).map(|o| o as usize);
            let o = if is_union {
                explicit.unwrap_or(0)
            } else {
                match explicit {
                    Some(o) => {
                        if o < offset {
                            return Err(format!(
                                "{}: field '{}.{}' at offset {} overlaps the previous field ending at {}",
                                self.name, canonical, fname, o, offset
                            ));
                        }
                        o
                    }
                    None => round_up(offset, a),
                }
            };
            align = align.max(a);
            fields.push(ResolvedField {
                name: fname,
                ty: fty,
                offset: o,
                size: fsize,
                bit_offset: None,
                bit_width: None,
            });
            if !is_union {
                offset = o + fsize;
            }
        }
        let raw_end = fields
            .iter()
            .map(|f| f.offset.saturating_add(f.size))
            .max()
            .unwrap_or(0);
        let eff_align = pack.map_or(align, |p| align.min(p)).max(1);
        let size = match explicit_size {
            Some(s) => {
                if s < raw_end {
                    return Err(format!(
                        "{}: '{}' declares size {} but its fields need {} bytes",
                        self.name, canonical, s, raw_end
                    ));
                }
                s
            }
            None => round_up(raw_end, eff_align),
        };
        validate_fields(&self.name, canonical, &fields, size, is_union)?;
        self.types.insert(
            canonical.to_string(),
            ResolvedType {
                name: canonical.to_string(),
                kind: TypeKind::Aggregate {
                    fields,
                    pack,
                    is_union,
                    explicit_size,
                },
                size,
                align: eff_align,
                arch: self.arch,
            },
        );
        Ok(canonical.to_string())
    }

    fn build_alias(
        &mut self,
        canonical: &str,
        text: &str,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        let target = self.resolve_type_expr(text, raw, resolving)?;
        let (size, align) = self
            .types
            .get(&target)
            .map(|t| (t.size, t.align))
            .unwrap_or((0, 1));
        self.types.insert(
            canonical.to_string(),
            ResolvedType {
                name: canonical.to_string(),
                kind: TypeKind::Alias { target },
                size,
                align,
                arch: self.arch,
            },
        );
        Ok(canonical.to_string())
    }

    fn build_enum(
        &mut self,
        canonical: &str,
        obj: &serde_json::Map<String, Value>,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        let underlying_text = obj
            .get("underlying")
            .and_then(Value::as_str)
            .unwrap_or("int");
        let underlying = self.resolve_type_expr(underlying_text, raw, resolving)?;
        let mut variants: Vec<(String, i64)> = Vec::new();
        match obj.get("variants") {
            Some(Value::Object(map)) => {
                for (vname, vval) in map {
                    variants.push((vname.clone(), value_as_i64(vval).unwrap_or(0)));
                }
            }
            Some(Value::Array(list)) => {
                let mut next = 0i64;
                for v in list {
                    let vname = v
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let vval = v.get("value").and_then(value_as_i64).unwrap_or(next);
                    next = vval.saturating_add(1);
                    variants.push((vname, vval));
                }
            }
            _ => {}
        }
        variants.sort_by_key(|(_, v)| *v);
        let (size, align) = self
            .types
            .get(&underlying)
            .map(|t| (t.size, t.align))
            .unwrap_or((4, 4));
        self.types.insert(
            canonical.to_string(),
            ResolvedType {
                name: canonical.to_string(),
                kind: TypeKind::Enum {
                    underlying,
                    variants,
                },
                size,
                align,
                arch: self.arch,
            },
        );
        Ok(canonical.to_string())
    }

    fn build_function_type(
        &mut self,
        canonical: &str,
        obj: &serde_json::Map<String, Value>,
        raw: &BTreeMap<String, Value>,
        resolving: &mut Vec<String>,
    ) -> Result<String, String> {
        let ret = obj.get("ret").and_then(Value::as_str).unwrap_or("void");
        let ret = self.resolve_type_expr(ret, raw, resolving)?;
        let cc = obj
            .get("cc")
            .and_then(Value::as_str)
            .unwrap_or("stdcall")
            .to_string();
        let varargs = obj.get("varargs").and_then(Value::as_bool).unwrap_or(false);
        let mut params = Vec::new();
        for p in obj
            .get("params")
            .and_then(Value::as_array)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
        {
            let pname = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let pty = p.get("type").and_then(Value::as_str).unwrap_or("void");
            let pty = self.resolve_type_expr(pty, raw, resolving)?;
            params.push(ArchiveParam {
                name: pname,
                ty: pty,
            });
        }
        self.types.insert(
            canonical.to_string(),
            ResolvedType {
                name: canonical.to_string(),
                kind: TypeKind::Function {
                    ret,
                    params,
                    cc,
                    varargs,
                },
                size: 0,
                align: 1,
                arch: self.arch,
            },
        );
        Ok(canonical.to_string())
    }
}

fn field_defs_for(obj: &serde_json::Map<String, Value>, arch: Arch) -> Result<Vec<Value>, String> {
    if let Some(Value::Object(variants)) = obj.get("variants")
        && let Some(section) = variants.get(arch.tag())
        && let Some(fields) = section.get("fields")
    {
        return fields
            .as_array()
            .cloned()
            .ok_or_else(|| "variant 'fields' must be an array".to_string());
    }
    Ok(obj
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

fn variant_size_for(obj: &serde_json::Map<String, Value>, arch: Arch) -> Option<usize> {
    let variants = obj.get("variants")?;
    let section = variants.get(arch.tag())?;
    section.get("size")?.as_u64().map(|s| s as usize)
}

fn value_as_i64(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(n) = v.as_u64() {
        return Some(n as i64);
    }
    if let Some(s) = v.as_str() {
        let t = s.trim();
        if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16).ok().map(|n| n as i64);
        }
        if let Some(neg) = t.strip_prefix("-0x").or_else(|| t.strip_prefix("-0X")) {
            return u64::from_str_radix(neg, 16).ok().map(|n| -(n as i64));
        }
        return t.parse::<i64>().ok();
    }
    None
}

fn validate_fields(
    archive: &str,
    name: &str,
    fields: &[ResolvedField],
    size: usize,
    is_union: bool,
) -> Result<(), String> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for f in fields {
        if !seen.insert(f.name.as_str()) {
            return Err(format!("{}: duplicate field '{}.{}'", archive, name, f.name));
        }
        let end = f.offset.saturating_add(f.size);
        if end > size {
            return Err(format!(
                "{}: field '{}.{}' ends at {} beyond the {}-byte layout",
                archive, name, f.name, end, size
            ));
        }
    }
    if !is_union {
        let mut spans: Vec<(usize, usize, &str)> = fields
            .iter()
            .filter(|f| f.bit_width.is_none())
            .map(|f| (f.offset, f.offset + f.size, f.name.as_str()))
            .collect();
        spans.sort_unstable();
        for w in spans.windows(2) {
            if w[0].1 > w[1].0 {
                return Err(format!(
                    "{}: fields '{}.{}' and '{}.{}' overlap ({} > {})",
                    archive, name, w[0].2, name, w[1].2, w[0].1, w[1].0
                ));
            }
        }
    }
    Ok(())
}

fn lookup_exact_value<'a>(
    raw: &'a BTreeMap<String, Value>,
    name: &str,
) -> Option<(String, &'a Value)> {
    raw.get(name).map(|v| (name.to_string(), v))
}

fn lookup_exact(raw: &BTreeMap<String, Value>, name: &str) -> Option<String> {
    raw.contains_key(name).then(|| name.to_string())
}

fn lookup_loose(raw: &BTreeMap<String, Value>, name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    raw.keys()
        .find(|k| k.to_ascii_lowercase() == lower)
        .cloned()
}

fn round_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    match value % align {
        0 => value,
        rem => value.saturating_add(align - rem),
    }
}
