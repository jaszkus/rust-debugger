use gimli::{AttributeValue, Dwarf, EndianSlice, RunTimeEndian, Unit};
use rustc_hash::FxHashMap;

use crate::parser::ParsedBinary;
use crate::type_system::manager::DataTypeManager;
use crate::type_system::types::TypeId;

type R<'a> = EndianSlice<'a, RunTimeEndian>;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DwarfImportStats {
    pub structs: usize,
    pub unions: usize,
    pub enums: usize,
    pub typedefs: usize,
    pub arrays: usize,
    pub pointers: usize,
    pub functions_named: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone)]
struct Member {
    name: String,
    offset: u64,
    ty: Key,
}

type Key = (usize, usize);

#[derive(Debug)]
enum DieKind {
    Base {
        name: String,
        size: u64,
    },
    Typedef {
        name: String,
        target: Key,
    },
    Pointer {
        target: Key,
    },
    Array {
        elem: Key,
        count: u64,
    },
    Composite {
        name: String,
        is_struct: bool,
        members: Vec<Member>,
    },
    Enum {
        name: String,
        variants: Vec<(String, i64)>,
    },
}

#[derive(Debug)]
struct DieType {
    kind: DieKind,
    shell: Option<TypeId>,
}

#[derive(Debug, Clone, Copy)]
enum Parent {
    Composite(Key),
    Enum(Key),
    Array(Key),
}

fn load_dwarf<'a>(bin: &'a ParsedBinary) -> Option<Dwarf<R<'a>>> {
    let find = |name: &str| -> &'a [u8] {
        bin.sections
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| {
                let off = s.offset as usize;
                let end = off.saturating_add(s.size as usize).min(bin.data.len());
                if off < end && end <= bin.data.len() {
                    Some(&bin.data[off..end])
                } else {
                    None
                }
            })
            .unwrap_or(&[])
    };
    Dwarf::load(|section| -> Result<_, gimli::Error> {
        Ok(EndianSlice::new(
            find(section.name()),
            RunTimeEndian::Little,
        ))
    })
    .ok()
}

pub fn import_dwarf_types(bin: &ParsedBinary, tm: &mut DataTypeManager) -> DwarfImportStats {
    let mut stats = DwarfImportStats::default();
    let Some(dwarf) = load_dwarf(bin) else {
        return stats;
    };

    let mut types: FxHashMap<Key, DieType> = FxHashMap::default();
    let mut named_funcs: Vec<(u64, String)> = Vec::new();
    let mut skipped = 0usize;

    let mut units = dwarf.units();
    let mut unit_idx = 0usize;
    while let Some(header) = units.next().ok().and_then(|h| h) {
        if let Ok(unit) = dwarf.unit(header) {
            collect_unit(
                &dwarf,
                &unit,
                unit_idx,
                &mut types,
                &mut named_funcs,
                &mut skipped,
            );
        }
        unit_idx += 1;
    }
    let keys: Vec<Key> = types.keys().copied().collect();

    for key in &keys {
        let (name, is_enum) = match &types[key].kind {
            DieKind::Composite { name, .. } => (name.clone(), false),
            DieKind::Enum { name, .. } => (name.clone(), true),
            _ => continue,
        };
        if tm.find_by_name(&name).is_some() {
            continue;
        }
        let shell = if is_enum {
            prim(tm, "uint").and_then(|u| tm.create_enum(&name, u).ok())
        } else if matches!(
            &types[key].kind,
            DieKind::Composite {
                is_struct: true,
                ..
            }
        ) {
            tm.create_struct(&name).ok()
        } else {
            tm.create_union(&name).ok()
        };
        types.get_mut(key).unwrap().shell = shell;
    }

    let mut memo: FxHashMap<Key, Option<TypeId>> = FxHashMap::default();
    for key in &keys {
        if let DieKind::Composite { members, .. } = &types[key].kind {
            let Some(shell) = types[key].shell else {
                continue;
            };
            let members: Vec<Member> = members.to_vec();
            for m in &members {
                let Some(mt) = resolve(&types, m.ty, tm, &mut memo) else {
                    skipped += 1;
                    continue;
                };
                if tm
                    .add_field(shell, &m.name, mt, Some(m.offset as usize), "")
                    .is_err()
                {
                    skipped += 1;
                }
            }
        }
    }

    for key in &keys {
        match &types[key].kind {
            DieKind::Enum { variants, .. } => {
                if let Some(shell) = types[key].shell {
                    for (vname, vval) in variants {
                        let _ = tm.add_enum_variant(shell, vname, *vval);
                    }
                }
            }
            DieKind::Composite { .. } => {}
            _ => {
                resolve(&types, *key, tm, &mut memo);
            }
        }
    }

    for t in types.values() {
        match &t.kind {
            DieKind::Composite {
                is_struct: true, ..
            } => stats.structs += 1,
            DieKind::Composite {
                is_struct: false, ..
            } => stats.unions += 1,
            DieKind::Enum { .. } => stats.enums += 1,
            DieKind::Typedef { .. } => stats.typedefs += 1,
            DieKind::Array { .. } => stats.arrays += 1,
            DieKind::Pointer { .. } => stats.pointers += 1,
            DieKind::Base { .. } => {}
        }
    }
    for (addr, name) in &named_funcs {
        if bin
            .symbols
            .iter()
            .any(|s| s.addr == *addr && s.name == *name)
        {
            continue;
        }
        stats.functions_named += 1;
    }
    stats.functions_named = named_funcs.len();
    stats.skipped = skipped;
    stats
}

pub fn dwarf_function_names(bin: &ParsedBinary) -> Vec<(u64, String)> {
    let Some(dwarf) = load_dwarf(bin) else {
        return Vec::new();
    };
    let mut out: Vec<(u64, String)> = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().ok().and_then(|h| h) {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().ok().and_then(|x| x) {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            if let (Some(addr), Some(name)) = (
                attr_u64(entry, gimli::DW_AT_low_pc),
                attr_str(&dwarf, &unit, entry, gimli::DW_AT_name),
            )
                && addr != 0 && !out.iter().any(|(a, _)| *a == addr) {
                    out.push((addr, name));
                }
        }
    }
    out.sort_by_key(|(a, _)| *a);
    out
}

fn resolve(
    types: &FxHashMap<Key, DieType>,
    key: Key,
    tm: &mut DataTypeManager,
    memo: &mut FxHashMap<Key, Option<TypeId>>,
) -> Option<TypeId> {
    if let Some(v) = memo.get(&key) {
        return *v;
    }
    memo.insert(key, None);
    let info = types.get(&key)?;
    let id = match &info.kind {
        DieKind::Base { name, size } => base_type(tm, name, *size),
        DieKind::Typedef { name, target } => {
            if let Some(existing) = tm.find_by_name(name) {
                Some(existing)
            } else {
                resolve(types, *target, tm, memo).and_then(|t| tm.create_typedef(name, t).ok())
            }
        }
        DieKind::Pointer { target } => {
            let t = resolve(types, *target, tm, memo).or_else(|| prim(tm, "void"));
            t.and_then(|t| tm.create_pointer(t).ok())
        }
        DieKind::Array { elem, count } => resolve(types, *elem, tm, memo)
            .and_then(|e| tm.create_array(e, (*count).max(1) as usize).ok()),
        DieKind::Composite { .. } | DieKind::Enum { .. } => info.shell,
    };
    memo.insert(key, id);
    id
}

fn base_type(tm: &mut DataTypeManager, name: &str, size: u64) -> Option<TypeId> {
    let canonical = match name {
        "char" | "signed char" => "char",
        "unsigned char" | "boolean" => "uchar",
        "short int" | "short" => "short",
        "short unsigned int" | "unsigned short" => "ushort",
        "int" | "long int" => "int",
        "unsigned int" => "uint",
        "long unsigned int" | "unsigned long" => "ulong",
        "long long int" => "longlong",
        "long long unsigned int" | "unsigned long long" => "ulonglong",
        "_Bool" | "bool" => "bool",
        "float" => "float",
        "double" | "long double" => "double",
        "void" => "void",
        other => other,
    };
    tm.find_by_name(canonical).or_else(|| match size {
        1 => tm.find_by_name("uchar"),
        2 => tm.find_by_name("ushort"),
        4 => tm.find_by_name("uint"),
        8 => tm.find_by_name("ulonglong"),
        _ => None,
    })
}

fn prim(tm: &DataTypeManager, name: &str) -> Option<TypeId> {
    tm.find_by_name(name)
}

fn collect_unit(
    dwarf: &Dwarf<R<'_>>,
    unit: &Unit<R<'_>>,
    unit_idx: usize,
    types: &mut FxHashMap<Key, DieType>,
    named_funcs: &mut Vec<(u64, String)>,
    skipped: &mut usize,
) {
    let mut stack: Vec<(isize, Parent)> = Vec::new();
    let mut entries = unit.entries();
    while let Some(entry) = entries.next_dfs().ok().and_then(|x| x) {
        let depth = entry.depth();
        while stack.last().is_some_and(|(d, _)| *d >= depth) {
            stack.pop();
        }
        let key: Key = (unit_idx, entry.offset().0);
        match entry.tag() {
            gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                let name = attr_str(dwarf, unit, entry, gimli::DW_AT_name)
                    .unwrap_or_else(|| format!("__anon_{:x}", entry.offset().0));
                types.insert(
                    key,
                    DieType {
                        kind: DieKind::Composite {
                            name,
                            is_struct: entry.tag() == gimli::DW_TAG_structure_type,
                            members: Vec::new(),
                        },
                        shell: None,
                    },
                );
                stack.push((depth, Parent::Composite(key)));
            }
            gimli::DW_TAG_enumeration_type => {
                let name = attr_str(dwarf, unit, entry, gimli::DW_AT_name)
                    .unwrap_or_else(|| format!("__anon_enum_{:x}", entry.offset().0));
                types.insert(
                    key,
                    DieType {
                        kind: DieKind::Enum {
                            name,
                            variants: Vec::new(),
                        },
                        shell: None,
                    },
                );
                stack.push((depth, Parent::Enum(key)));
            }
            gimli::DW_TAG_enumerator => {
                if let Some((_, Parent::Enum(ek))) = stack.last() {
                    let ek = *ek;
                    if let (Some(n), Some(v)) = (
                        attr_str(dwarf, unit, entry, gimli::DW_AT_name),
                        attr_i64(entry, gimli::DW_AT_const_value),
                    )
                        && let Some(t) = types.get_mut(&ek)
                            && let DieKind::Enum { variants, .. } = &mut t.kind {
                                variants.push((n, v));
                            }
                }
            }
            gimli::DW_TAG_member => {
                if let Some((_, Parent::Composite(ck))) = stack.last() {
                    let ck = *ck;
                    if attr_u64(entry, gimli::DW_AT_bit_size).is_some() {
                        *skipped += 1;
                        continue;
                    }
                    let (Some(name), Some(ty)) = (
                        attr_str(dwarf, unit, entry, gimli::DW_AT_name),
                        type_ref(entry, unit_idx),
                    ) else {
                        *skipped += 1;
                        continue;
                    };
                    let off = attr_u64(entry, gimli::DW_AT_data_member_location).unwrap_or(0);
                    if let Some(t) = types.get_mut(&ck)
                        && let DieKind::Composite { members, .. } = &mut t.kind {
                            members.push(Member {
                                name,
                                offset: off,
                                ty,
                            });
                        }
                }
            }
            gimli::DW_TAG_array_type => match type_ref(entry, unit_idx) {
                Some(elem) => {
                    types.insert(
                        key,
                        DieType {
                            kind: DieKind::Array { elem, count: 0 },
                            shell: None,
                        },
                    );
                    stack.push((depth, Parent::Array(key)));
                }
                None => *skipped += 1,
            },
            gimli::DW_TAG_subrange_type => {
                if let Some((_, Parent::Array(ak))) = stack.last() {
                    let ak = *ak;
                    let count = attr_u64(entry, gimli::DW_AT_count)
                        .or_else(|| {
                            attr_u64(entry, gimli::DW_AT_upper_bound).map(|ub| ub.wrapping_add(1))
                        })
                        .unwrap_or(0);
                    if let Some(t) = types.get_mut(&ak)
                        && let DieKind::Array { count: c, .. } = &mut t.kind {
                            *c = count;
                        }
                }
            }
            gimli::DW_TAG_typedef => {
                let (Some(name), Some(target)) = (
                    attr_str(dwarf, unit, entry, gimli::DW_AT_name),
                    type_ref(entry, unit_idx),
                ) else {
                    *skipped += 1;
                    continue;
                };
                types.insert(
                    key,
                    DieType {
                        kind: DieKind::Typedef { name, target },
                        shell: None,
                    },
                );
            }
            gimli::DW_TAG_base_type => {
                let Some(name) = attr_str(dwarf, unit, entry, gimli::DW_AT_name) else {
                    *skipped += 1;
                    continue;
                };
                let size = attr_u64(entry, gimli::DW_AT_byte_size).unwrap_or(4);
                types.insert(
                    key,
                    DieType {
                        kind: DieKind::Base { name, size },
                        shell: None,
                    },
                );
            }
            gimli::DW_TAG_pointer_type => {
                if let Some(target) = type_ref(entry, unit_idx) {
                    types.insert(
                        key,
                        DieType {
                            kind: DieKind::Pointer { target },
                            shell: None,
                        },
                    );
                }
            }
            gimli::DW_TAG_subprogram => {
                if let (Some(addr), Some(name)) = (
                    attr_u64(entry, gimli::DW_AT_low_pc),
                    attr_str(dwarf, unit, entry, gimli::DW_AT_name),
                )
                    && addr != 0 {
                        named_funcs.push((addr, name));
                    }
            }
            _ => {}
        }
    }
}

fn type_ref(entry: &gimli::DebuggingInformationEntry<R>, unit_idx: usize) -> Option<Key> {
    match entry.attr_value(gimli::DW_AT_type)? {
        AttributeValue::UnitRef(o) => Some((unit_idx, o.0)),
        _ => None,
    }
}

fn attr_str(
    dwarf: &Dwarf<R<'_>>,
    unit: &Unit<R<'_>>,
    entry: &gimli::DebuggingInformationEntry<R>,
    at: gimli::constants::DwAt,
) -> Option<String> {
    let v = entry.attr_value(at)?;
    dwarf
        .attr_string(unit, v)
        .ok()
        .map(|s| s.to_string_lossy().into_owned())
}

fn attr_u64(
    entry: &gimli::DebuggingInformationEntry<R>,
    at: gimli::constants::DwAt,
) -> Option<u64> {
    match entry.attr_value(at)? {
        AttributeValue::Addr(v) | AttributeValue::Udata(v) | AttributeValue::Data8(v) => Some(v),
        AttributeValue::Data4(v) => Some(v as u64),
        AttributeValue::Data2(v) => Some(v as u64),
        AttributeValue::Data1(v) => Some(v as u64),

        _ => None,
    }
}
fn attr_i64(
    entry: &gimli::DebuggingInformationEntry<R>,
    at: gimli::constants::DwAt,
) -> Option<i64> {
    match entry.attr_value(at)? {
        AttributeValue::Sdata(v) => Some(v),
        AttributeValue::Addr(v) | AttributeValue::Udata(v) | AttributeValue::Data8(v) => {
            Some(v as i64)
        }
        AttributeValue::Data4(v) => Some(v as i64),
        AttributeValue::Data2(v) => Some(v as i64),
        AttributeValue::Data1(v) => Some(v as i64),
        _ => None,
    }
}
