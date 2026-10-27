use super::archive::{Arch, ResolvedType, TypeArchive, TypeKind, embedded_archive};
use super::manager::DataTypeManager;
use super::types::{
    TypeId, ID_CHAR, ID_DOUBLE, ID_FLOAT, ID_INT, ID_LONGLONG, ID_SHORT, ID_UCHAR, ID_UINT,
    ID_ULONGLONG, ID_USHORT, ID_VOID,
};
use rustc_hash::FxHashMap as HashMap;

impl DataTypeManager {
    pub const ARCHIVES: &'static [&'static str] = &["win32", "crt", "libc"];

    pub fn list_archives() -> &'static [&'static str] {
        Self::ARCHIVES
    }

    pub fn seed_archive(&mut self, archive: &str) -> Result<usize, String> {
        let name = archive.trim().to_ascii_lowercase();
        match name.as_str() {
            "win32" | "crt" | "libc" => self.seed_named_archive(&name),
            "all" => {
                let mut added = 0usize;
                for a in Self::ARCHIVES {
                    added += self.seed_named_archive(a)?;
                }
                Ok(added)
            }
            other => Err(format!(
                "Unknown archive '{}' (want one of: win32, crt, libc, all)",
                other
            )),
        }
    }

    fn seed_named_archive(&mut self, name: &str) -> Result<usize, String> {
        let arch = if self.pointer_size >= 8 {
            Arch::X64
        } else {
            Arch::X86
        };
        let archive = embedded_archive(name, arch)?;
        self.materialise_archive(&archive)
    }

    pub fn materialise_archive(&mut self, archive: &TypeArchive) -> Result<usize, String> {
        let mut ids: HashMap<String, TypeId> = HashMap::default();
        let mut created: Vec<String> = Vec::new();
        let names: Vec<String> = archive.type_names().map(|s| s.to_string()).collect();
        for name in &names {
            let Some(ty) = archive.get(name) else {
                continue;
            };
            if matches!(
                ty.kind,
                TypeKind::Primitive { .. }
                    | TypeKind::Pointer { .. }
                    | TypeKind::Array { .. }
                    | TypeKind::Function { .. }
            ) {
                continue;
            }
            if let Some(existing) = self.find_by_name(name) {
                ids.insert(name.clone(), existing);
                continue;
            }
            let made = match &ty.kind {
                TypeKind::Aggregate { is_union, .. } => {
                    if *is_union {
                        self.create_union(name)
                    } else {
                        self.create_struct(name)
                    }
                }
                TypeKind::Enum { .. } => self.create_enum(name, ID_INT),
                TypeKind::Alias { .. } => self.create_typedef(name, ID_VOID),
                TypeKind::Primitive { .. }
                | TypeKind::Pointer { .. }
                | TypeKind::Array { .. }
                | TypeKind::Function { .. } => continue,
            };
            if let Ok(id) = made {
                ids.insert(name.clone(), id);
                created.push(name.clone());
            }
        }
        for name in &created {
            let Some(id) = ids.get(name).copied() else {
                continue;
            };
            let Some(ty) = archive.get(name) else {
                continue;
            };
            self.fill_archive_type(archive, ty, id, &mut ids)?;
        }
        Ok(created.len())
    }

    fn fill_archive_type(
        &mut self,
        archive: &TypeArchive,
        ty: &ResolvedType,
        id: TypeId,
        ids: &mut HashMap<String, TypeId>,
    ) -> Result<(), String> {
        match &ty.kind {
            TypeKind::Aggregate {
                fields,
                pack,
                is_union,
                explicit_size,
            } => {
                if let Some(p) = pack
                    && *p < 8
                {
                    let _ = self.set_packed(id, true);
                }
                for f in fields {
                    let storage = self.archive_type_id(archive, &f.ty, ids)?;
                    let res = match f.bit_width {
                        Some(w) => self.add_bitfield(
                            id,
                            &f.name,
                            storage,
                            f.offset,
                            f.bit_offset.unwrap_or(0),
                            w,
                        ),
                        None => self.add_field(id, &f.name, storage, Some(f.offset), ""),
                    };
                    if let Err(e) = res {
                        return Err(format!("{}.{}: {}", ty.name, f.name, e));
                    }
                }
                let _ = is_union;
                let _ = explicit_size;
            }
            TypeKind::Enum {
                underlying,
                variants,
            } => {
                if let Ok(u) = self.archive_type_id(archive, underlying, ids)
                    && let Some(super::types::DataType::Enum { underlying: slot, .. }) =
                        self.types.get_mut(&id)
                {
                    *slot = u;
                }
                for (vname, value) in variants {
                    let _ = self.add_enum_variant(id, vname, *value);
                }
            }
            TypeKind::Alias { target } => {
                let t = self.archive_type_id(archive, target, ids)?;
                if let Some(super::types::DataType::Typedef { target: slot, .. }) =
                    self.types.get_mut(&id)
                {
                    *slot = t;
                }
            }
            TypeKind::Function { .. } => {}
            TypeKind::Primitive { .. } | TypeKind::Pointer { .. } | TypeKind::Array { .. } => {}
        }
        Ok(())
    }

    fn archive_type_id(
        &mut self,
        archive: &TypeArchive,
        name: &str,
        ids: &mut HashMap<String, TypeId>,
    ) -> Result<TypeId, String> {
        if let Some(&id) = ids.get(name) {
            return Ok(id);
        }
        let Some(ty) = archive.get(name) else {
            return Err(format!("archive type '{}' is not resolved", name));
        };
        let id = match &ty.kind {
            TypeKind::Primitive {
                size,
                signed,
                float,
                ..
            } => primitive_id(*size, *signed, *float),
            TypeKind::Pointer { target } => {
                let t = self.archive_type_id(archive, target, ids)?;
                self.create_pointer(t)?
            }
            TypeKind::Array { element, count } => {
                let t = self.archive_type_id(archive, element, ids)?;
                self.create_array(t, *count)?
            }
            _ => return Err(format!("archive type '{}' has no id", name)),
        };
        ids.insert(name.to_string(), id);
        Ok(id)
    }
}

fn primitive_id(size: usize, signed: bool, float: bool) -> TypeId {
    if float {
        return if size >= 8 { ID_DOUBLE } else { ID_FLOAT };
    }
    match (size, signed) {
        (0, _) => ID_VOID,
        (1, true) => ID_CHAR,
        (1, false) => ID_UCHAR,
        (2, true) => ID_SHORT,
        (2, false) => ID_USHORT,
        (4, true) => ID_INT,
        (4, false) => ID_UINT,
        (_, true) => ID_LONGLONG,
        (_, false) => ID_ULONGLONG,
    }
}
