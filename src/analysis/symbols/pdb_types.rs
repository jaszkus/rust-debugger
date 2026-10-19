use pdb::{FallibleIterator, TypeData, TypeIndex};
use rustc_hash::FxHashMap;

use super::debug_types::{DebugField, DebugFunction, DebugParam, DebugStruct, DebugTypes};
use crate::type_system::manager::DataTypeManager;
use crate::type_system::types::TypeId;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PdbImportStats {
    pub structs: usize,
    pub unions: usize,
    pub enums: usize,
    pub typedefs: usize,
    pub skipped: usize,
}




pub fn import_pdb_types_from_binary(
    binary: &crate::parser::ParsedBinary,
    source_path: Option<&str>,
    tm: &mut DataTypeManager,
) -> Option<PdbImportStats> {
    if !(binary.format.starts_with("PE") || binary.format == "COFF") {
        return None;
    }
    let path = crate::analysis::symbols::debug_symbols::find_pdb_path(binary, source_path)?;
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        import_pdb_types(&path, tm)
    }))
    .ok()
    .and_then(|r| r.ok());
    std::panic::set_hook(prev_hook);
    result
}

pub fn import_pdb_types(
    pdb_path: &std::path::Path,
    tm: &mut DataTypeManager,
) -> Result<PdbImportStats, String> {    let file = std::fs::File::open(pdb_path).map_err(|e| format!("open: {}", e))?;
    let mut pdb = pdb::PDB::open(file).map_err(|e| format!("open pdb: {}", e))?;
    let tpi = pdb.type_information().map_err(|e| format!("tpi: {}", e))?;
    let mut finder = tpi.finder();
    let mut iter = tpi.iter();
    let mut named: Vec<(TypeIndex, TypeData<'_>)> = Vec::new();

    while let Some(ty) = iter.next().map_err(|e| format!("tpi iter: {}", e))? {
        finder.update(&iter);
        let Ok(data) = ty.parse() else {
            continue;
        };
        match data {
            TypeData::Class(c) => {
                if !c.properties.forward_reference() {
                    named.push((ty.index(), TypeData::Class(c)));
                }
            }
            TypeData::Union(u) => {
                if !u.properties.forward_reference() {
                    named.push((ty.index(), TypeData::Union(u)));
                }
            }
            TypeData::Enumeration(e) if !e.properties.forward_reference() => {
                named.push((ty.index(), TypeData::Enumeration(e)));
            }
            _ => {}
        }
    }

    let mut memo: FxHashMap<TypeIndex, Option<TypeId>> = FxHashMap::default();
    let mut stats_out = PdbImportStats::default();
    for (_idx, data) in &named {
        match data {
            TypeData::Class(c) => {
                let is_struct = true;
                let name = c.name.to_string();
                let id = match tm.find_by_name(&name) {
                    Some(existing) => existing,
                    None => {
                        let r = if is_struct {
                            tm.create_struct(&name)
                        } else {
                            tm.create_union(&name)
                        };
                        match r {
                            Ok(i) => i,
                            Err(_) => {
                                stats_out.skipped += 1;
                                continue;
                            }
                        }
                    }
                };
                let mut added = 0usize;
                if let Some(fields) = c.fields {
                    add_fields(tm, &finder, &mut memo, id, fields, &mut stats_out.skipped);
                    added += 1;
                }
                if is_struct {
                    stats_out.structs += 1;
                } else {
                    stats_out.unions += 1;
                }
                let _ = added;
            }
            TypeData::Union(u) => {
                let name = u.name.to_string();
                let id = match tm.find_by_name(&name) {
                    Some(existing) => existing,
                    None => match tm.create_union(&name) {
                        Ok(i) => i,
                        Err(_) => {
                            stats_out.skipped += 1;
                            continue;
                        }
                    },
                };
                add_fields(tm, &finder, &mut memo, id, u.fields, &mut stats_out.skipped);
                stats_out.unions += 1;
            }
            TypeData::Enumeration(e) => {
                let name = e.name.to_string();
                let id = match tm.find_by_name(&name) {
                    Some(existing) => existing,
                    None => {
                        let underlying = resolve_pdb(tm, &finder, &mut memo, e.underlying_type)
                            .unwrap_or(TypeId::MAX);
                        match tm.create_enum(&name, underlying) {
                            Ok(i) => i,
                            Err(_) => {
                                stats_out.skipped += 1;
                                continue;
                            }
                        }
                    }
                };
                if let Ok(item) = finder.find(e.fields)
                    && let Ok(TypeData::FieldList(fl)) = item.parse() {
                        for f in &fl.fields {
                            if let TypeData::Enumerate(en) = f {
                                let vname = en.name.to_string().into_owned();
                                let _ = tm.add_enum_variant(id, &vname, variant_i64(&en.value));
                            }
                        }
                        let mut cont = fl.continuation;
                        while let Some(ci) = cont {
                            let Ok(item) = finder.find(ci) else { break };
                            let Ok(TypeData::FieldList(next)) = item.parse() else {
                                break;
                            };
                            for f in &next.fields {
                                if let TypeData::Enumerate(en) = f {
                                    let vname = en.name.to_string().into_owned();
                                    let _ = tm.add_enum_variant(id, &vname, variant_i64(&en.value));
                                }
                            }
                            cont = next.continuation;
                        }
                    }
                stats_out.enums += 1;
            }
            _ => {}
        }
    }

    Ok(stats_out)
}

fn add_fields(
    tm: &mut DataTypeManager,
    finder: &pdb::ItemFinder<'_, TypeIndex>,
    memo: &mut FxHashMap<TypeIndex, Option<TypeId>>,
    id: TypeId,
    fields: TypeIndex,
    skipped: &mut usize,
) {
    let Ok(item) = finder.find(fields) else {
        *skipped += 1;
        return;
    };
    let Ok(TypeData::FieldList(fl)) = item.parse() else {
        *skipped += 1;
        return;
    };
    for f in &fl.fields {
        match f {
            TypeData::Member(m) => {
                let Some(mt) = resolve_pdb(tm, finder, memo, m.field_type) else {
                    *skipped += 1;
                    continue;
                };
                if tm
                    .add_field(
                        id,
                        m.name.to_string().into_owned().as_str(),
                        mt,
                        Some(m.offset as usize),
                        "",
                    )
                    .is_err()
                {
                    *skipped += 1;
                }
            }
            TypeData::Bitfield(b) => {
                let _ = b;
                *skipped += 1;
            }
            _ => {}
        }
    }
    let mut cont = fl.continuation;
    while let Some(ci) = cont {
        let Ok(item) = finder.find(ci) else { break };
        let Ok(TypeData::FieldList(next)) = item.parse() else {
            break;
        };
        for f in &next.fields {
            if let TypeData::Member(m) = f {
                let Some(mt) = resolve_pdb(tm, finder, memo, m.field_type) else {
                    *skipped += 1;
                    continue;
                };
                let _ = tm.add_field(
                    id,
                    m.name.to_string().into_owned().as_str(),
                    mt,
                    Some(m.offset as usize),
                    "",
                );
            }
        }
        cont = next.continuation;
    }
}

fn resolve_pdb(
    tm: &mut DataTypeManager,
    finder: &pdb::ItemFinder<'_, TypeIndex>,
    memo: &mut FxHashMap<TypeIndex, Option<TypeId>>,
    idx: TypeIndex,
) -> Option<TypeId> {
    if let Some(v) = memo.get(&idx) {
        return *v;
    }
    memo.insert(idx, None);
    let Ok(item) = finder.find(idx) else {
        return None;
    };
    let Ok(parsed) = item.parse() else {
        return None;
    };
    let id = match parsed {
        TypeData::Primitive(p) => primitive_id(tm, p),
        TypeData::Class(c) => {
            let name = c.name.to_string();
            tm.find_by_name(&name)
                .or_else(|| tm.create_struct(&name).ok())
        }
        TypeData::Union(u) => {
            let name = u.name.to_string();
            tm.find_by_name(&name)
                .or_else(|| tm.create_union(&name).ok())
        }
        TypeData::Enumeration(e) => {
            let name = e.name.to_string();
            tm.find_by_name(&name)
        }
        TypeData::Pointer(p) => {
            let t = resolve_pdb(tm, finder, memo, p.underlying_type)
                .or_else(|| tm.find_by_name("void"))?;
            tm.create_pointer(t).ok()
        }
        TypeData::Array(a) => {
            let e = resolve_pdb(tm, finder, memo, a.element_type)?;
            let elem_size = tm.size_of(e).unwrap_or(1).max(1) as u32;
            let total = a.dimensions.last().copied().unwrap_or(0) as usize;
            let count = (total / elem_size as usize).max(1);
            tm.create_array(e, count).ok()
        }
        TypeData::Modifier(m) => resolve_pdb(tm, finder, memo, m.underlying_type),
        _ => None,
    };
    memo.insert(idx, id);
    id
}

fn primitive_id(tm: &DataTypeManager, p: pdb::PrimitiveType) -> Option<TypeId> {
    use pdb::PrimitiveKind;
    let name = match p.kind {
        PrimitiveKind::Void => "void",
        PrimitiveKind::Char => "char",
        PrimitiveKind::UChar => "uchar",
        PrimitiveKind::I8 => "char",
        PrimitiveKind::U8 => "uchar",
        PrimitiveKind::I16 | PrimitiveKind::Short => "short",
        PrimitiveKind::U16 | PrimitiveKind::UShort => "ushort",
        PrimitiveKind::I32 | PrimitiveKind::Long => "long",
        PrimitiveKind::U32 | PrimitiveKind::ULong => "ulong",
        PrimitiveKind::I64 | PrimitiveKind::Quad => "longlong",
        PrimitiveKind::U64 | PrimitiveKind::UQuad => "ulonglong",
        PrimitiveKind::F16 => "ushort",
        PrimitiveKind::F32 => "float",
        PrimitiveKind::F64 => "double",
        PrimitiveKind::Bool8 | PrimitiveKind::Bool32 => "bool",
        _ => return None,
    };
    tm.find_by_name(name)
}

fn variant_i64(v: &pdb::Variant) -> i64 {
    match v {
        pdb::Variant::U8(v) => *v as i64,
        pdb::Variant::U16(v) => *v as i64,
        pdb::Variant::U32(v) => *v as i64,
        pdb::Variant::U64(v) => *v as i64,
        pdb::Variant::I8(v) => *v as i64,
        pdb::Variant::I16(v) => *v as i64,
        pdb::Variant::I32(v) => *v as i64,
        pdb::Variant::I64(v) => *v,
    }
}







pub fn debug_types_from_pdb(
    binary: &crate::parser::ParsedBinary,
    source_path: Option<&str>,
) -> Option<DebugTypes> {
    if !(binary.format.starts_with("PE") || binary.format == "COFF") {
        return None;
    }
    let path = crate::analysis::symbols::debug_symbols::find_pdb_path(binary, source_path)?;
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        load_pdb_debug_types(&path, binary)
    }))
    .ok()
    .flatten();
    std::panic::set_hook(prev_hook);
    result
}

fn load_pdb_debug_types(
    path: &std::path::Path,
    binary: &crate::parser::ParsedBinary,
) -> Option<DebugTypes> {
    let file = std::fs::File::open(path).ok()?;
    let mut pdb = pdb::PDB::open(file).ok()?;
    let ptr_size = if binary.arch.contains("64") { 8 } else { 4 };

    
    
    let mut struct_specs: Vec<(String, usize, Option<TypeIndex>)> = Vec::new();
    {
        let tpi = pdb.type_information().ok()?;
        let mut finder = tpi.finder();
        let mut iter = tpi.iter();
        while let Ok(Some(ty)) = iter.next() {
            finder.update(&iter);
            let Ok(data) = ty.parse() else {
                continue;
            };
            match data {
                TypeData::Class(c) if !c.properties.forward_reference() => {
                    let name = c.name.to_string().into_owned();
                    if name.is_empty() || name.starts_with('<') {
                        continue;
                    }
                    struct_specs.push((name, c.size as usize, c.fields));
                }
                TypeData::Union(u) if !u.properties.forward_reference() => {
                    let name = u.name.to_string().into_owned();
                    if name.is_empty() || name.starts_with('<') {
                        continue;
                    }
                    struct_specs.push((name, u.size as usize, Some(u.fields)));
                }
                _ => {}
            }
        }
    }
    struct_specs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
    struct_specs.dedup_by(|a, b| a.0 == b.0);

    
    
    let sections = crate::analysis::symbols::debug_symbols::pdb_sections(binary);
    let mut symbols: Vec<(u64, String, TypeIndex, Vec<String>)> = Vec::new();
    {
        let dbi = pdb.debug_information().ok()?;
        let mut modules = dbi.modules().ok()?;
        while let Ok(Some(module)) = modules.next() {
            let Ok(Some(info)) = pdb.module_info(&module) else {
                continue;
            };
            let Ok(mut syms) = info.symbols() else {
                continue;
            };
            let mut current: Option<usize> = None;
            while let Ok(Some(sym)) = syms.next() {
                let Ok(data) = sym.parse() else {
                    continue;
                };
                match data {
                    pdb::SymbolData::Procedure(proc) => {
                        if proc.type_index.0 == 0 {
                            current = None;
                            continue;
                        }
                        let Some(va) = crate::analysis::symbols::debug_symbols::pdb_offset_to_va(
                            &sections,
                            proc.offset,
                        ) else {
                            current = None;
                            continue;
                        };
                        let name = proc.name.to_string().into_owned();
                        if name.is_empty() {
                            current = None;
                            continue;
                        }
                        symbols.push((va, name, proc.type_index, Vec::new()));
                        current = Some(symbols.len() - 1);
                    }
                    pdb::SymbolData::Local(local) if local.flags.isparam => {
                        if let Some(i) = current {
                            let name = local.name.to_string().into_owned();
                            if !name.is_empty() {
                                symbols[i].3.push(name);
                            }
                        }
                    }
                    pdb::SymbolData::ProcedureEnd => current = None,
                    _ => {}
                }
            }
        }
    }
    if symbols.is_empty() && struct_specs.is_empty() {
        return None;
    }

    
    
    if let Ok(globals) = pdb.global_symbols() {
        let mut iter = globals.iter();
        while let Ok(Some(sym)) = iter.next() {
            let Ok(pdb::SymbolData::Procedure(proc)) = sym.parse() else {
                continue;
            };
            if proc.type_index.0 == 0 {
                continue;
            }
            let Some(va) =
                crate::analysis::symbols::debug_symbols::pdb_offset_to_va(&sections, proc.offset)
            else {
                continue;
            };
            let name = proc.name.to_string().into_owned();
            if !name.is_empty() {
                symbols.push((va, name, proc.type_index, Vec::new()));
            }
        }
    }

    let mut out = DebugTypes::default();

    
    
    if !struct_specs.is_empty() {
        let tpi = pdb.type_information().ok()?;
        let mut finder = tpi.finder();
        let mut iter = tpi.iter();
        while let Ok(Some(ty)) = iter.next() {
            finder.update(&iter);
            let _ = ty;
        }
        let mut memo: FxHashMap<TypeIndex, Option<CType>> = FxHashMap::default();
        for (name, size, fields) in struct_specs {
            let mut fs = Vec::new();
            if let Some(fields) = fields {
                fs = collect_debug_fields(&finder, &mut memo, fields, ptr_size);
            }
            if fs.is_empty() {
                continue;
            }
            fs.sort_by_key(|f| f.offset);
            fs.dedup_by(|a, b| a.offset == b.offset && a.name == b.name);
            let real_size = if size == 0 {
                fs.iter().map(|f| f.offset + f.size).max().unwrap_or(0)
            } else {
                size
            };
            out.structs.push(DebugStruct {
                name,
                size: real_size,
                fields: fs,
            });
        }
    }

    
    if !symbols.is_empty() {
        let tpi = pdb.type_information().ok()?;
        let mut finder = tpi.finder();
        let mut iter = tpi.iter();
        while let Ok(Some(ty)) = iter.next() {
            finder.update(&iter);
            let _ = ty;
        }
        let mut memo: FxHashMap<TypeIndex, Option<CType>> = FxHashMap::default();
        for (va, name, type_index, param_names) in symbols {
            let Some(proc) = resolve_procedure(&finder, type_index) else {
                continue;
            };
            let ret = proc
                .return_type
                .and_then(|t| resolve_c(&finder, &mut memo, t, ptr_size, 0))
                .map(|t| t.name)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "void".into());
            let args = finder
                .find(proc.argument_list)
                .ok()
                .and_then(|item| item.parse().ok())
                .and_then(|data| match data {
                    TypeData::ArgumentList(a) => Some(a.arguments),
                    _ => None,
                })
                .unwrap_or_default();
            let mut params = Vec::with_capacity(args.len());
            for (i, arg) in args.into_iter().enumerate() {
                let ct = resolve_c(&finder, &mut memo, arg, ptr_size, 0);
                let (type_name, struct_name) = match ct {
                    Some(t) => (t.name, t.struct_name),
                    None => ("void *".into(), None),
                };
                let pname = param_names
                    .get(i)
                    .filter(|n| !n.is_empty())
                    .cloned()
                    .unwrap_or_else(|| format!("param_{}", i + 1));
                params.push(DebugParam {
                    name: pname,
                    type_name,
                    struct_name,
                });
            }
            let func = DebugFunction {
                name,
                ret,
                params,
            };
            match out.functions.get(&va) {
                Some(existing) if existing.params.len() >= func.params.len() => {}
                _ => {
                    out.functions.insert(va, func);
                }
            }
        }
    }

    (!out.is_empty()).then_some(out)
}

#[derive(Debug, Clone)]
struct CType {
    name: String,
    size: usize,
    struct_name: Option<String>,
}

fn resolve_procedure(
    finder: &pdb::ItemFinder<'_, TypeIndex>,
    index: TypeIndex,
) -> Option<pdb::ProcedureType> {
    let item = finder.find(index).ok()?;
    match item.parse().ok()? {
        TypeData::Procedure(p) => Some(p),
        _ => None,
    }
}

fn collect_debug_fields(
    finder: &pdb::ItemFinder<'_, TypeIndex>,
    memo: &mut FxHashMap<TypeIndex, Option<CType>>,
    fields: TypeIndex,
    ptr_size: usize,
) -> Vec<DebugField> {
    let mut out = Vec::new();
    let mut next = Some(fields);
    while let Some(idx) = next {
        let Ok(item) = finder.find(idx) else {
            break;
        };
        let Ok(TypeData::FieldList(fl)) = item.parse() else {
            break;
        };
        for f in &fl.fields {
            if let TypeData::Member(m) = f {
                let name = m.name.to_string().into_owned();
                if name.is_empty() {
                    continue;
                }
                let Some(ct) = resolve_c(finder, memo, m.field_type, ptr_size, 0) else {
                    continue;
                };
                out.push(DebugField {
                    name,
                    offset: m.offset as usize,
                    type_name: ct.name,
                    size: ct.size,
                });
            }
        }
        next = fl.continuation;
    }
    out
}

fn resolve_c(
    finder: &pdb::ItemFinder<'_, TypeIndex>,
    memo: &mut FxHashMap<TypeIndex, Option<CType>>,
    index: TypeIndex,
    ptr_size: usize,
    depth: usize,
) -> Option<CType> {
    if depth > 16 {
        return None;
    }
    if let Some(cached) = memo.get(&index) {
        return cached.clone();
    }
    memo.insert(index, None);
    let item = finder.find(index).ok()?;
    let parsed = item.parse().ok()?;
    let result = match parsed {
        TypeData::Primitive(p) => {
            let (name, mut size) = primitive_name_size(p.kind)?;
            let mut name = name.to_string();
            if p.indirection.is_some() {
                if !name.ends_with('*') {
                    name.push_str(" *");
                }
                size = ptr_size;
            }
            Some(CType {
                name,
                size,
                struct_name: None,
            })
        }
        TypeData::Class(c) => {
            let name = c.name.to_string().into_owned();
            let name = if name.is_empty() {
                "void".to_string()
            } else {
                name
            };
            Some(CType {
                name: name.clone(),
                size: c.size as usize,
                struct_name: (!name.is_empty() && name != "void").then_some(name),
            })
        }
        TypeData::Union(u) => {
            let name = u.name.to_string().into_owned();
            let name = if name.is_empty() {
                "void".to_string()
            } else {
                name
            };
            Some(CType {
                name: name.clone(),
                size: u.size as usize,
                struct_name: (!name.is_empty() && name != "void").then_some(name),
            })
        }
        TypeData::Enumeration(e) => {
            let name = e.name.to_string().into_owned();
            let size = resolve_c(finder, memo, e.underlying_type, ptr_size, depth + 1)
                .map(|t| t.size)
                .unwrap_or(4);
            Some(CType {
                name: if name.is_empty() {
                    "int".into()
                } else {
                    name
                },
                size,
                struct_name: None,
            })
        }
        TypeData::Pointer(p) => {
            let inner = resolve_c(finder, memo, p.underlying_type, ptr_size, depth + 1)?;
            Some(CType {
                name: format!("{} *", inner.name),
                size: ptr_size,
                struct_name: inner.struct_name,
            })
        }
        TypeData::Modifier(m) => {
            let inner = resolve_c(finder, memo, m.underlying_type, ptr_size, depth + 1)?;
            let mut prefix = String::new();
            if m.constant {
                prefix.push_str("const ");
            }
            if m.volatile {
                prefix.push_str("volatile ");
            }
            Some(CType {
                name: format!("{}{}", prefix, inner.name),
                ..inner
            })
        }
        TypeData::Array(a) => {
            let elem = resolve_c(finder, memo, a.element_type, ptr_size, depth + 1)?;
            let elem_size = elem.size.max(1) as u32;
            let total = a.dimensions.last().copied().unwrap_or(0);
            let count = (total / elem_size).max(1) as usize;
            Some(CType {
                name: format!("{}[{}]", elem.name, count),
                size: elem_size as usize * count,
                struct_name: None,
            })
        }
        TypeData::Bitfield(b) => resolve_c(finder, memo, b.underlying_type, ptr_size, depth + 1),
        TypeData::Procedure(_) => Some(CType {
            name: "void *".into(),
            size: ptr_size,
            struct_name: None,
        }),
        _ => None,
    };
    memo.insert(index, result.clone());
    result
}

fn primitive_name_size(kind: pdb::PrimitiveKind) -> Option<(&'static str, usize)> {
    use pdb::PrimitiveKind::*;
    Some(match kind {
        NoType | Void => ("void", 0),
        Char | RChar | I8 => ("int8_t", 1),
        UChar | U8 => ("uint8_t", 1),
        WChar | RChar16 => ("wchar_t", 2),
        Short | I16 => ("int16_t", 2),
        UShort | U16 => ("uint16_t", 2),
        Long | I32 => ("int32_t", 4),
        ULong | U32 => ("uint32_t", 4),
        Quad | I64 => ("int64_t", 8),
        UQuad | U64 => ("uint64_t", 8),
        Octa | I128 => ("__int128", 16),
        UOcta | U128 => ("unsigned __int128", 16),
        F16 => ("_Float16", 2),
        F32 | F32PP => ("float", 4),
        F48 => ("long double", 6),
        F64 => ("double", 8),
        F80 => ("long double", 10),
        F128 => ("__float128", 16),
        Complex32 => ("_Complex float", 8),
        Complex64 => ("_Complex double", 16),
        Complex80 => ("_Complex long double", 20),
        Complex128 => ("_Complex __float128", 32),
        Bool8 => ("bool", 1),
        Bool16 => ("bool", 2),
        Bool32 => ("bool", 4),
        Bool64 => ("bool", 8),
        HRESULT => ("HRESULT", 4),
        _ => return None,
    })
}
