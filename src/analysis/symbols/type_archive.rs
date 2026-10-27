use crate::type_system::{Arch, TypeArchiveSet, embedded_archives, normalize_symbol};
use rustc_hash::FxHashMap as HashMap;
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldShape {
    pub offset: usize,
    pub size: usize,
    pub name: String,
    pub bitfield: bool,
    pub pointee: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructShape {
    pub name: String,
    pub size: usize,
    pub is_union: bool,
    pub fields: Vec<FieldShape>,
}

impl StructShape {
    pub fn field_at(&self, offset: usize, size: usize) -> Option<&FieldShape> {
        self.fields
            .iter()
            .find(|f| f.offset == offset && (f.bitfield || f.size == size))
    }

    pub fn pointee_of(&self, offset: usize, size: usize) -> Option<&str> {
        self.field_at(offset, size)?.pointee.as_deref()
    }

    pub fn offsets(&self) -> impl Iterator<Item = usize> + '_ {
        self.fields.iter().map(|f| f.offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSignature {
    pub name: String,
    pub module: String,
    pub ret: String,
    pub params: Vec<(String, String)>,
    pub cc: String,
    pub varargs: bool,
    pub param_shapes: Vec<Option<StructShape>>,
    pub param_pointer_types: Vec<Option<String>>,
    pub param_pointee_sizes: Vec<Option<usize>>,
    pub ret_shape: Option<StructShape>,
}

impl ArchiveSignature {
    pub fn param_count(&self) -> usize {
        self.params.len()
    }

    pub fn param_is_pointer(&self, index: usize) -> bool {
        self.params
            .get(index)
            .is_some_and(|(ty, _)| ty.trim_end().ends_with('*'))
    }
}

pub fn arch_for_pointer_size(pointer_size: usize) -> Arch {
    if pointer_size >= 8 {
        Arch::X64
    } else {
        Arch::X86
    }
}

pub struct ArchiveIndex {
    set: Arc<TypeArchiveSet>,
    signatures: HashMap<String, Arc<ArchiveSignature>>,
    shapes: HashMap<String, Option<StructShape>>,
    candidates: Vec<Arc<StructShape>>,
    peb: Option<StructShape>,
    teb: Option<StructShape>,
}

impl std::fmt::Debug for ArchiveIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveIndex")
            .field("arch", &self.set.arch())
            .field("types", &self.set.type_count())
            .field("functions", &self.signatures.len())
            .field("candidates", &self.candidates.len())
            .finish()
    }
}

const MAX_MATCHED_FIELDS: usize = 48;

impl ArchiveIndex {
    fn build(set: Arc<TypeArchiveSet>) -> Self {
        let mut signatures: HashMap<String, Arc<ArchiveSignature>> = HashMap::default();
        let mut shapes: HashMap<String, Option<StructShape>> = HashMap::default();
        let mut names: Vec<(String, String)> = Vec::new();
        for archive in set.archives() {
            for (_, func) in archive.functions() {
                names.push((func.name.clone(), func.module.clone()));
            }
        }
        names.sort();
        names.dedup();
        for (name, module) in names {
            let key = normalize_symbol(&name).to_ascii_lowercase();
            if signatures.contains_key(&key) {
                continue;
            }
            if let Some(sig) = build_signature(&set, &name, &module, &mut shapes) {
                signatures.insert(key, Arc::new(sig));
            }
        }
        let mut candidates: Vec<Arc<StructShape>> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut type_names: Vec<String> = Vec::new();
        for archive in set.archives() {
            type_names.extend(archive.type_names().map(|s| s.to_string()));
        }
        type_names.sort();
        type_names.dedup();
        for name in type_names {
            let Some(ty) = set.get(&name) else { continue };
            if !ty.is_aggregate() || ty.is_union() || ty.fields().is_empty() {
                continue;
            }
            if ty.fields().len() > MAX_MATCHED_FIELDS || !seen.insert(name.clone()) {
                continue;
            }
            if let Some(shape) = shape_of_aggregate(&set, &name) {
                candidates.push(Arc::new(shape));
            }
        }
        candidates.sort_by(|a, b| {
            a.fields
                .len()
                .cmp(&b.fields.len())
                .then_with(|| a.name.cmp(&b.name))
        });
        let peb = shape_of(&set, "PEB *");
        let teb = shape_of(&set, "TEB *");
        Self {
            set,
            signatures,
            shapes,
            candidates,
            peb,
            teb,
        }
    }

    pub fn arch(&self) -> Arch {
        self.set.arch()
    }

    pub fn set(&self) -> &TypeArchiveSet {
        &self.set
    }

    pub fn signature(&self, name: &str) -> Option<&Arc<ArchiveSignature>> {
        self.signatures
            .get(&normalize_symbol(name).to_ascii_lowercase())
    }

    pub fn struct_shape(&self, type_name: &str) -> Option<StructShape> {
        if let Some(hit) = self.shapes.get(type_name) {
            return hit.clone();
        }
        shape_of(&self.set, type_name)
    }

    pub fn aggregate_named(&self, name: &str) -> Option<StructShape> {
        shape_of_aggregate(&self.set, name)
    }

    pub fn candidates(&self) -> &[Arc<StructShape>] {
        &self.candidates
    }

    pub fn peb_shape(&self) -> Option<&StructShape> {
        self.peb.as_ref()
    }

    pub fn teb_shape(&self) -> Option<&StructShape> {
        self.teb.as_ref()
    }

    pub fn windows_struct(&self, name: &str) -> Option<StructShape> {
        self.struct_shape(&format!("{} *", name))
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn match_layout(&self, accesses: &[(usize, usize)]) -> Option<&Arc<StructShape>> {
        if accesses.len() < 3 {
            return None;
        }
        let mut offsets: Vec<usize> = accesses.iter().map(|(o, _)| *o).collect();
        offsets.sort_unstable();
        offsets.dedup();
        if offsets.len() < 3 {
            return None;
        }
        let mut best: Option<&Arc<StructShape>> = None;
        let mut best_fields = usize::MAX;
        let mut ambiguous = false;
        for cand in &self.candidates {
            if cand.fields.len() < offsets.len() || cand.fields.len() > offsets.len() * 2 + 3 {
                continue;
            }
            if !accesses
                .iter()
                .all(|(o, s)| cand.field_at(*o, *s).is_some())
            {
                continue;
            }
            if cand.fields.len() < best_fields {
                best_fields = cand.fields.len();
                best = Some(cand);
                ambiguous = false;
            } else if cand.fields.len() == best_fields {
                ambiguous = true;
            }
        }
        if ambiguous { None } else { best }
    }
}

fn shape_of_aggregate(set: &TypeArchiveSet, name: &str) -> Option<StructShape> {
    let agg = set.get(name)?;
    if !agg.is_aggregate() {
        return None;
    }
    Some(StructShape {
        name: agg.name.clone(),
        size: agg.size,
        is_union: agg.is_union(),
        fields: agg
            .fields()
            .iter()
            .map(|f| FieldShape {
                offset: f.offset,
                size: f.size,
                name: f.name.clone(),
                bitfield: f.bit_width.is_some(),
                pointee: set.pointee_aggregate(&f.ty).map(|a| a.name.clone()),
            })
            .collect(),
    })
}

fn shape_of(set: &TypeArchiveSet, ty: &str) -> Option<StructShape> {
    let target = set.pointee_aggregate(ty)?;
    shape_of_aggregate(set, &target.name)
}

fn cached_shape(
    set: &TypeArchiveSet,
    ty: &str,
    cache: &mut HashMap<String, Option<StructShape>>,
) -> Option<StructShape> {
    if let Some(hit) = cache.get(ty) {
        return hit.clone();
    }
    let shape = shape_of(set, ty);
    cache.insert(ty.to_string(), shape.clone());
    shape
}

fn build_signature(
    set: &TypeArchiveSet,
    name: &str,
    module: &str,
    cache: &mut HashMap<String, Option<StructShape>>,
) -> Option<ArchiveSignature> {
    let func = set
        .function(module, name)
        .or_else(|| set.function_any_module(name))?;
    let params = func
        .params
        .iter()
        .map(|p| {
            (
                set.render(&p.ty).unwrap_or_else(|| p.ty.clone()),
                p.name.clone(),
            )
        })
        .collect::<Vec<_>>();
    Some(ArchiveSignature {
        name: func.name.clone(),
        module: func.module.clone(),
        ret: set.render(&func.ret).unwrap_or_else(|| func.ret.clone()),
        params: params.clone(),
        cc: func.cc.clone(),
        varargs: func.varargs,
        param_shapes: func
            .params
            .iter()
            .map(|p| cached_shape(set, &p.ty, cache))
            .collect(),
        param_pointer_types: params
            .iter()
            .map(|(ty, _)| {
                let tref = crate::type_system::parse_type_expr(ty);
                match &tref {
                    crate::type_system::TypeRef::Pointer(_) => Some(ty.clone()),
                    _ => None,
                }
            })
            .collect(),
        param_pointee_sizes: func
            .params
            .iter()
            .map(|p| match set.pointee(&p.ty) {
                Some(target) => set.size_of(&target).filter(|s| *s > 0),
                None => None,
            })
            .collect(),
        ret_shape: cached_shape(set, &func.ret, cache),
    })
}

static INDEX_X64: OnceLock<Option<ArchiveIndex>> = OnceLock::new();
static INDEX_X86: OnceLock<Option<ArchiveIndex>> = OnceLock::new();

pub fn index(pointer_size: usize) -> Option<&'static ArchiveIndex> {
    let (slot, arch) = if pointer_size <= 4 {
        (&INDEX_X86, Arch::X86)
    } else {
        (&INDEX_X64, Arch::X64)
    };
    slot.get_or_init(|| {
        let set = embedded_archives(arch.pointer_size())?;
        Some(ArchiveIndex::build(set.clone()))
    })
    .as_ref()
}
