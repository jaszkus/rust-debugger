use crate::analysis::pcode::{PInstr, POp, PVar, CALL_CLOBBERED};
use rustc_hash::FxHashMap as HashMap;

pub struct TypeReconstructor {
    types: HashMap<u64, ReconstructedType>,
    pointer_types: HashMap<u64, u64>,
    next_id: u64,
    struct_index: HashMap<u64, u64>,
    base_to_struct: HashMap<u64, u64>,
}

#[derive(Debug, Clone)]
pub struct ReconstructedType {
    pub name: String,
    pub size: usize,
    pub kind: TypeKind,
    pub fields: Vec<TypeField>,
}

#[derive(Debug, Clone)]
pub enum TypeKind {
    Primitive(PrimitiveType),
    Struct,
    Array { element_type: u64, count: usize },
    Pointer { target_type: u64 },
    Enum { variants: Vec<(i64, String)> },
}

#[derive(Debug, Clone, Copy)]
pub enum PrimitiveType {
    Bool,
    Char,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    Float,
    Double,
    Void,
}

#[derive(Debug, Clone)]
pub struct TypeField {
    pub name: String,
    pub offset: i64,
    pub size: usize,
    pub type_id: u64,
    pub access_count: usize,
}

impl TypeReconstructor {
    pub fn new() -> Self {
        let mut reconstructor = Self {
            types: HashMap::default(),
            pointer_types: HashMap::default(),
            next_id: 100,
            struct_index: HashMap::default(),
            base_to_struct: HashMap::default(),
        };
        reconstructor.init_primitive_types();
        reconstructor
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn init_primitive_types(&mut self) {
        let primitives = vec![
            (1, "bool", TypeKind::Primitive(PrimitiveType::Bool), 1),
            (2, "char", TypeKind::Primitive(PrimitiveType::Char), 1),
            (3, "uchar", TypeKind::Primitive(PrimitiveType::UChar), 1),
            (4, "short", TypeKind::Primitive(PrimitiveType::Short), 2),
            (5, "ushort", TypeKind::Primitive(PrimitiveType::UShort), 2),
            (6, "int", TypeKind::Primitive(PrimitiveType::Int), 4),
            (7, "uint", TypeKind::Primitive(PrimitiveType::UInt), 4),
            (8, "long", TypeKind::Primitive(PrimitiveType::Long), 8),
            (9, "ulong", TypeKind::Primitive(PrimitiveType::ULong), 8),
            (
                10,
                "longlong",
                TypeKind::Primitive(PrimitiveType::LongLong),
                8,
            ),
            (
                11,
                "ulonglong",
                TypeKind::Primitive(PrimitiveType::ULongLong),
                8,
            ),
            (12, "float", TypeKind::Primitive(PrimitiveType::Float), 4),
            (13, "double", TypeKind::Primitive(PrimitiveType::Double), 8),
            (14, "void", TypeKind::Primitive(PrimitiveType::Void), 0),
        ];

        for (id, name, kind, size) in primitives {
            self.types.insert(
                id,
                ReconstructedType {
                    name: name.to_string(),
                    size,
                    kind,
                    fields: Vec::new(),
                },
            );
        }
    }

    pub fn analyze_function(&mut self, pinstrs: &[PInstr], entry: u64, end: u64) {
        let mut struct_accesses: HashMap<u64, Vec<StructAccess>> = HashMap::default();
        let mut base_names: HashMap<u64, String> = HashMap::default();
        let mut prov: HashMap<&'static str, (u64, i64)> = HashMap::default();
        let mut pointer_fields: Vec<(u64, i64)> = Vec::new();

        for pi in pinstrs {
            if pi.address < entry || pi.address >= end {
                continue;
            }
            self.analyze_instruction(
                pi,
                &mut struct_accesses,
                &mut base_names,
                &mut prov,
                &mut pointer_fields,
            );
        }

        for (base_key, accesses) in struct_accesses {
            if accesses.len() >= 2 {
                let name = base_names
                    .get(&base_key)
                    .cloned()
                    .unwrap_or_else(|| format!("base_{:x}", base_key));
                self.reconstruct_struct(&base_key, &name, &accesses);
            }
        }

        for (base_key, off) in pointer_fields {
            if let Some(&tsid) = self.base_to_struct.get(&base_key) {
                let ptr_id = self.create_pointer_type(tsid);
                if let Some(ReconstructedType { fields, .. }) = self.types.get_mut(&tsid)
                    && let Some(f) = fields.iter_mut().find(|f| f.offset == off) {
                        f.type_id = ptr_id;
                    }
            }
        }
    }

    fn analyze_instruction(
        &self,
        pi: &PInstr,
        struct_accesses: &mut HashMap<u64, Vec<StructAccess>>,
        base_names: &mut HashMap<u64, String>,
        prov: &mut HashMap<&'static str, (u64, i64)>,
        pointer_fields: &mut Vec<(u64, i64)>,
    ) {
        for op in &pi.ops {
            match op {
                POp::Load { dst, addr, size } => {
                    if let Some((base, off)) = direct_mem(addr, base_names)
                        && let PVar::Reg(r) = dst {
                            prov.insert(r, (base, off));
                        }
                    if let Some((base_key, offset, ptr_field)) = resolve_mem(addr, prov, base_names)
                    {
                        if let Some(pf) = ptr_field {
                            pointer_fields.push(pf);
                        }
                        struct_accesses
                            .entry(base_key)
                            .or_default()
                            .push(StructAccess {
                                offset,
                                size: *size as usize,
                                is_write: false,
                                address: pi.address,
                            });
                    }
                }
                POp::Store { addr, size, .. } => {
                    if let Some((base_key, offset, ptr_field)) = resolve_mem(addr, prov, base_names)
                    {
                        if let Some(pf) = ptr_field {
                            pointer_fields.push(pf);
                        }
                        struct_accesses
                            .entry(base_key)
                            .or_default()
                            .push(StructAccess {
                                offset,
                                size: *size as usize,
                                is_write: true,
                                address: pi.address,
                            });
                    }
                }
                POp::Copy { dst, src, .. } => {
                    if let (PVar::Reg(d), PVar::Reg(s)) = (dst, src)
                        && let Some(p) = prov.get(*s).cloned() {
                            prov.insert(d, p);
                        }
                    if let (PVar::Reg(d), PVar::Mem(..)) = (dst, src)
                        && let Some((base, off)) = direct_mem(src, base_names) {
                            prov.insert(d, (base, off));
                        }
                }
                POp::Call { .. } => {
                    for r in CALL_CLOBBERED {
                        prov.remove(*r);
                    }
                }
                _ => {}
            }
        }
    }

    fn reconstruct_struct(&mut self, base_key: &u64, base_name: &str, accesses: &[StructAccess]) {
        let mut field_map: HashMap<i64, (usize, usize, bool)> = HashMap::default();
        for access in accesses {
            let e = field_map
                .entry(access.offset)
                .or_insert((access.size, 0, access.is_write));
            e.0 = e.0.max(access.size);
            e.1 += 1;
            e.2 |= access.is_write;
        }

        let mut fields: Vec<TypeField> = field_map
            .iter()
            .map(|(&offset, &(size, count, _))| TypeField {
                name: format!("field_{:x}", offset),
                offset,
                size,
                type_id: self.guess_type_from_size(size),
                access_count: count,
            })
            .collect();
        fields.sort_by_key(|f| f.offset);

        let max_offset = fields
            .iter()
            .map(|f| f.offset + f.size as i64)
            .max()
            .unwrap_or(0);

        let fp = struct_fp(max_offset, &fields);

        let struct_id = if let Some(&id) = self.struct_index.get(&fp) {
            if let Some(existing) = self.types.get_mut(&id) {
                if max_offset as usize > existing.size {
                    existing.size = max_offset as usize;
                }
                for f in &fields {
                    if !existing.fields.iter().any(|x| x.offset == f.offset) {
                        existing.fields.push(f.clone());
                    }
                }
                existing.fields.sort_by_key(|f| f.offset);
            }
            id
        } else {
            let id = self.alloc_id();
            let struct_name = format!("struct_{}", sanitize(base_name));
            self.types.insert(
                id,
                ReconstructedType {
                    name: struct_name,
                    size: max_offset as usize,
                    kind: TypeKind::Struct,
                    fields: fields.clone(),
                },
            );
            self.struct_index.insert(fp, id);
            self.base_to_struct.insert(*base_key, id);
            id
        };

        if !self.pointer_types.contains_key(&struct_id) {
            let ptr_id = self.alloc_id();
            let target_name = self
                .types
                .get(&struct_id)
                .map(|t| t.name.clone())
                .unwrap_or_else(|| "void".into());
            self.types.insert(
                ptr_id,
                ReconstructedType {
                    name: format!("{}*", target_name),
                    size: 8,
                    kind: TypeKind::Pointer {
                        target_type: struct_id,
                    },
                    fields: Vec::new(),
                },
            );
            self.pointer_types.insert(struct_id, ptr_id);
        }
    }

    fn guess_type_from_size(&self, size: usize) -> u64 {
        match size {
            1 => 2,
            2 => 4,
            4 => 6,
            8 => 8,
            _ => 6,
        }
    }

    #[allow(dead_code)]
    pub fn get_type(&self, id: u64) -> Option<&ReconstructedType> {
        self.types.get(&id)
    }

    pub fn get_all_types(&self) -> &HashMap<u64, ReconstructedType> {
        &self.types
    }

    pub fn create_pointer_type(&mut self, target_type: u64) -> u64 {
        if let Some(&ptr_id) = self.pointer_types.get(&target_type) {
            return ptr_id;
        }
        let ptr_id = self.alloc_id();
        let target_name = self
            .types
            .get(&target_type)
            .map(|t| t.name.clone())
            .unwrap_or_else(|| "void".to_string());

        self.types.insert(
            ptr_id,
            ReconstructedType {
                name: format!("{}*", target_name),
                size: 8,
                kind: TypeKind::Pointer { target_type },
                fields: Vec::new(),
            },
        );

        self.pointer_types.insert(target_type, ptr_id);
        ptr_id
    }

    #[allow(dead_code)]
    pub fn create_array_type(&mut self, element_type: u64, count: usize) -> u64 {
        let array_id = self.alloc_id();
        let element_size = self.types.get(&element_type).map(|t| t.size).unwrap_or(1);
        let element_name = self
            .types
            .get(&element_type)
            .map(|t| t.name.clone())
            .unwrap_or_else(|| "void".to_string());

        self.types.insert(
            array_id,
            ReconstructedType {
                name: format!("{}[{}]", element_name, count),
                size: element_size.saturating_mul(count),
                kind: TypeKind::Array {
                    element_type,
                    count,
                },
                fields: Vec::new(),
            },
        );

        array_id
    }
}

impl Default for TypeReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

fn base_key_of(reg: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in reg.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h & 0x00ff_ffff_ffff_ffff
}

fn base_key_addr(a: u64) -> u64 {
    0x0100_0000_0000_0000 | a
}

fn direct_mem(v: &PVar, base_names: &mut HashMap<u64, String>) -> Option<(u64, i64)> {
    match v {
        PVar::Mem(base, disp) => match &**base {
            PVar::Reg(r) if *r != "rsp" && *r != "rbp" => {
                let key = base_key_of(r);
                base_names.entry(key).or_insert_with(|| r.to_string());
                Some((key, *disp))
            }
            _ => None,
        },
        PVar::Scaled { base, disp, .. } => match &**base {
            PVar::Reg(r) if *r != "rsp" && *r != "rbp" => {
                let key = base_key_of(r);
                base_names.entry(key).or_insert_with(|| r.to_string());
                Some((key, *disp))
            }
            _ => None,
        },
        PVar::StackSlot { .. } | PVar::Addr(_) => None,
        _ => None,
    }
}

type ResolvedMem = (u64, i64, Option<(u64, i64)>);

fn resolve_mem(
    v: &PVar,
    prov: &HashMap<&'static str, (u64, i64)>,
    base_names: &mut HashMap<u64, String>,
) -> Option<ResolvedMem> {
    match v {
        PVar::Mem(base, disp) => match &**base {
            PVar::Reg(r) => {
                if *r == "rsp" || *r == "rbp" {
                    return None;
                }
                let start_key = base_key_of(r);
                base_names.entry(start_key).or_insert_with(|| r.to_string());
                match prov.get(r) {
                    Some((base, off)) => {
                        let mut acc = disp.wrapping_add(*off);
                        let pointer_field = Some((*base, *off));
                        let mut cur_key = *base;
                        for _ in 0..8 {
                            match base_names.get(&cur_key).and_then(|n| prov.get(n.as_str())) {
                                Some((b2, o2)) => {
                                    acc = acc.wrapping_add(*o2);
                                    cur_key = *b2;
                                }
                                None => break,
                            }
                        }
                        Some((cur_key, acc, pointer_field))
                    }
                    None => Some((start_key, *disp, None)),
                }
            }
            PVar::Const(addr) => Some((base_key_addr(*addr as u64), *disp, None)),
            PVar::Addr(a) => Some((base_key_addr(*a), *disp, None)),
            _ => None,
        },
        PVar::Scaled { base, disp, .. } => match &**base {
            PVar::Reg(r) if *r != "rsp" && *r != "rbp" => {
                let key = base_key_of(r);
                base_names.entry(key).or_insert_with(|| r.to_string());
                Some((key, *disp, None))
            }
            PVar::Addr(a) => Some((base_key_addr(*a), *disp, None)),
            _ => None,
        },
        PVar::Addr(a) => Some((base_key_addr(*a), 0, None)),
        _ => None,
    }
}

fn sanitize(s: &str) -> String {
    s.replace([' ', '.', ','], "_")
}

fn struct_fp(max_offset: i64, fields: &[TypeField]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in max_offset.to_le_bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    for f in fields {
        for b in f.offset.to_le_bytes() {
            h = (h ^ b as u64).wrapping_mul(0x100000001b3);
        }
        for b in (f.size as u64).to_le_bytes() {
            h = (h ^ b as u64).wrapping_mul(0x100000001b3);
        }
        for b in f.type_id.to_le_bytes() {
            h = (h ^ b as u64).wrapping_mul(0x100000001b3);
        }
    }
    h
}

#[derive(Debug, Clone)]
struct StructAccess {
    offset: i64,
    size: usize,
    is_write: bool,
    #[allow(dead_code)]
    address: u64,
}
