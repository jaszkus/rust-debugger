use pdb::{FallibleIterator, TypeData, TypeIndex};
use rustc_hash::FxHashMap;

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
