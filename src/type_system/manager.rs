use super::types::{
    CallingConvention, DataType, StructField, TypeId, FIRST_USER_TYPE_ID, ID_BOOL, ID_CHAR,
    ID_DOUBLE, ID_FLOAT, ID_INT, ID_LONG, ID_LONGLONG, ID_POINTER, ID_SHORT, ID_STRING, ID_UCHAR,
    ID_UINT, ID_ULONG, ID_ULONGLONG, ID_USHORT, ID_VOID,
};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

const MAX_LAYOUT_DEPTH: usize = 64;
const MAX_TYPE_EXPR_LEN: usize = 512;

const PRIMITIVES: &[(TypeId, &str, usize)] = &[
    (ID_VOID, "void", 0),
    (ID_BOOL, "bool", 1),
    (ID_CHAR, "char", 1),
    (ID_UCHAR, "uchar", 1),
    (ID_SHORT, "short", 2),
    (ID_USHORT, "ushort", 2),
    (ID_INT, "int", 4),
    (ID_UINT, "uint", 4),
    (ID_LONG, "long", 8),
    (ID_ULONG, "ulong", 8),
    (ID_LONGLONG, "longlong", 8),
    (ID_ULONGLONG, "ulonglong", 8),
    (ID_FLOAT, "float", 4),
    (ID_DOUBLE, "double", 8),
    (ID_POINTER, "pointer", 8),
    (ID_STRING, "string", 0),
];

#[derive(Debug, Clone)]
pub struct DataTypeManager {
    pub(crate) next_id: TypeId,
    pub(crate) types: HashMap<TypeId, DataType>,
    pub(crate) by_name: HashMap<String, TypeId>,
    pub(crate) pointer_size: usize,
}

impl Default for DataTypeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DataTypeManager {
    pub fn new() -> Self {
        let mut m = Self {
            next_id: FIRST_USER_TYPE_ID,
            types: HashMap::with_capacity(128),
            by_name: HashMap::with_capacity(128),
            pointer_size: 8,
        };
        m.seed_primitives();
        m
    }

    pub fn set_arch(&mut self, arch: &str) {
        let ptr_size = match arch.trim().to_ascii_lowercase().as_str() {
            "x86" | "i386" | "i686" | "x86_32" | "arm" | "arm32" | "armv7" | "thumb" => 4,
            _ => 8,
        };
        let _ = self.set_pointer_size(ptr_size);
    }

    pub fn set_pointer_size(&mut self, ptr_size: usize) -> Result<(), String> {
        if ptr_size != 4 && ptr_size != 8 {
            return Err(format!(
                "Unsupported pointer size {} (want 4 or 8)",
                ptr_size
            ));
        }
        self.pointer_size = ptr_size;
        let long_size = if ptr_size == 4 { 4 } else { 8 };
        for (id, new_size) in [
            (ID_POINTER, ptr_size),
            (ID_LONG, long_size),
            (ID_ULONG, long_size),
        ] {
            if let Some(DataType::Primitive { size, .. }) = self.types.get_mut(&id) {
                *size = new_size;
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    fn seed_primitives(&mut self) {
        for &(id, name, size) in PRIMITIVES {
            let dt = if id == ID_STRING {
                DataType::String
            } else {
                DataType::Primitive {
                    name: name.to_string(),
                    size,
                }
            };
            self.types.insert(id, dt);
            self.by_name.insert(name.to_string(), id);
        }
    }

    fn alloc_id(&mut self) -> Result<TypeId, String> {
        let id = self.next_id.max(FIRST_USER_TYPE_ID);
        self.next_id = id
            .checked_add(1)
            .ok_or_else(|| "Data type id space exhausted".to_string())?;
        Ok(id)
    }

    fn validate_name(name: &str) -> Result<(), String> {
        if name.trim().is_empty() {
            return Err("Data type name must not be empty".into());
        }
        if name.ends_with('*') || name.ends_with(']') {
            return Err(format!(
                "Data type name '{}' must not end with '*' or ']' (reserved for pointer/array types)",
                name
            ));
        }
        Ok(())
    }

    fn require_type(&self, id: TypeId, what: &str) -> Result<(), String> {
        if self.types.contains_key(&id) {
            Ok(())
        } else {
            Err(format!("{} type {} does not exist", what, id))
        }
    }

    fn insert(&mut self, name: &str, dt: DataType) -> Result<TypeId, String> {
        Self::validate_name(name)?;
        if self.by_name.contains_key(name) {
            return Err(format!("Data type '{}' already exists", name));
        }
        let id = self.alloc_id()?;
        self.types.insert(id, dt);
        self.by_name.insert(name.to_string(), id);
        Ok(id)
    }

    fn intern_derived(&mut self, name: String, dt: DataType) -> Result<TypeId, String> {
        if let Some(&existing) = self.by_name.get(&name) {
            return Ok(existing);
        }
        let id = self.alloc_id()?;
        self.types.insert(id, dt);
        self.by_name.insert(name, id);
        Ok(id)
    }

    pub(crate) fn unique_name(&self, base: &str) -> String {
        if !self.by_name.contains_key(base) {
            return base.to_string();
        }
        (1u32..)
            .map(|n| format!("{}_{}", base, n))
            .find(|candidate| !self.by_name.contains_key(candidate.as_str()))
            .unwrap_or_else(|| base.to_string())
    }

    pub fn get(&self, id: TypeId) -> Option<&DataType> {
        self.types.get(&id)
    }

    pub fn find_by_name(&self, name: &str) -> Option<TypeId> {
        self.by_name.get(name).copied()
    }

    pub fn resolve_type_name(&mut self, name: &str) -> Result<TypeId, String> {
        if let Some(&id) = self.by_name.get(name) {
            return Ok(id);
        }
        let t = name.split_whitespace().collect::<Vec<_>>().join(" ");
        if t.is_empty() {
            return Err("Empty type name".into());
        }
        if t.len() > MAX_TYPE_EXPR_LEN {
            return Err(format!("Type expression too long ({} bytes)", t.len()));
        }
        if t != name {
            if let Some(&id) = self.by_name.get(t.as_str()) {
                return Ok(id);
            }
        }

        let stripped = strip_qualifiers(&t);
        if stripped.len() != t.len() {
            return self.resolve_type_name(stripped);
        }

        if t.ends_with('*') {
            let mut base = t.as_str();
            let mut depth = 0usize;
            while let Some(rest) = base.strip_suffix('*') {
                base = rest.trim_end();
                depth += 1;
            }
            let mut id = self.resolve_type_name(base)?;
            for _ in 0..depth {
                id = self.create_pointer(id)?;
            }
            return Ok(id);
        }

        if t.ends_with(']') {
            if let Some(open) = t.find('[') {
                if let Some(rel_close) = t[open..].find(']') {
                    let close = open + rel_close;
                    let count: usize = t[open + 1..close]
                        .trim()
                        .parse()
                        .map_err(|_| format!("Invalid array count in '{}'", t))?;
                    let element_name = format!("{}{}", t[..open].trim_end(), &t[close + 1..]);
                    let eid = self.resolve_type_name(&element_name)?;
                    return self.create_array(eid, count.max(1));
                }
            }
        }

        let lower = t.to_ascii_lowercase();
        if let Some(canonical) = alias_target(&lower, self.pointer_size) {
            return self
                .find_by_name(canonical)
                .ok_or_else(|| format!("Alias '{}' maps to unknown type '{}'", t, canonical));
        }
        if let Some(&id) = self.by_name.get(&lower) {
            return Ok(id);
        }
        Err(format!("Unknown data type: '{}'", name))
    }

    pub fn all(&self) -> Vec<(TypeId, &DataType)> {
        let mut v: Vec<(TypeId, &DataType)> = self.types.iter().map(|(k, v)| (*k, v)).collect();
        v.sort_unstable_by_key(|(k, _)| *k);
        v
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    pub fn create_struct(&mut self, name: &str) -> Result<TypeId, String> {
        self.insert(
            name,
            DataType::Struct {
                name: name.to_string(),
                fields: Vec::new(),
                packed: false,
            },
        )
    }

    pub fn create_union(&mut self, name: &str) -> Result<TypeId, String> {
        self.insert(
            name,
            DataType::Union {
                name: name.to_string(),
                fields: Vec::new(),
            },
        )
    }

    pub fn create_enum(&mut self, name: &str, underlying: TypeId) -> Result<TypeId, String> {
        self.require_type(underlying, "Enum underlying")?;
        self.insert(
            name,
            DataType::Enum {
                name: name.to_string(),
                underlying,
                variants: Vec::new(),
            },
        )
    }

    pub fn create_typedef(&mut self, name: &str, target: TypeId) -> Result<TypeId, String> {
        self.require_type(target, "Typedef target")?;
        self.insert(
            name,
            DataType::Typedef {
                name: name.to_string(),
                target,
            },
        )
    }

    pub fn create_pointer(&mut self, target: TypeId) -> Result<TypeId, String> {
        self.require_type(target, "Pointer target")?;
        let name = format!("{}*", self.type_name(target));
        self.intern_derived(name, DataType::Pointer { target })
    }

    pub fn create_array(&mut self, element: TypeId, count: usize) -> Result<TypeId, String> {
        self.require_type(element, "Array element")?;
        let name = format!("{}[{}]", self.type_name(element), count);
        self.intern_derived(name, DataType::Array { element, count })
    }

    pub fn create_function_sig(
        &mut self,
        name: &str,
        ret: TypeId,
        params: Vec<(TypeId, String)>,
        calling_convention: &str,
        varargs: bool,
    ) -> Result<TypeId, String> {
        self.require_type(ret, "Return")?;
        for (t, _) in &params {
            self.require_type(*t, "Parameter")?;
        }
        let cc = CallingConvention::normalize(calling_convention)
            .as_str()
            .to_string();
        self.insert(
            name,
            DataType::FunctionSig {
                name: name.to_string(),
                ret,
                params,
                calling_convention: cc,
                varargs,
            },
        )
    }

    pub fn rename(&mut self, id: TypeId, new_name: &str) -> Result<(), String> {
        Self::validate_name(new_name)?;
        if let Some(&owner) = self.by_name.get(new_name) {
            if owner != id {
                return Err(format!("Data type '{}' already exists", new_name));
            }
        }
        let slot = self
            .types
            .get_mut(&id)
            .and_then(|dt| dt.name_mut())
            .ok_or("Cannot rename this data type")?;
        if slot.as_str() == new_name {
            return Ok(());
        }
        let old = std::mem::replace(slot, new_name.to_string());
        if self.by_name.get(&old) == Some(&id) {
            self.by_name.remove(&old);
        }
        self.by_name.insert(new_name.to_string(), id);
        self.rekey_derived();
        Ok(())
    }

    fn rekey_derived(&mut self) {
        let types = &self.types;
        self.by_name
            .retain(|_, tid| !types.get(&*tid).is_some_and(|dt| dt.is_derived()));
        let mut derived: Vec<TypeId> = self
            .types
            .iter()
            .filter(|(_, dt)| dt.is_derived())
            .map(|(id, _)| *id)
            .collect();
        derived.sort_unstable();
        for id in derived {
            let name = self.type_name(id);
            self.by_name.entry(name).or_insert(id);
        }
    }

    fn dependents_closure(&self, id: TypeId) -> HashSet<TypeId> {
        let mut doomed: HashSet<TypeId> = HashSet::from([id]);
        loop {
            let more: Vec<TypeId> = self
                .types
                .iter()
                .filter(|&(k, dt)| {
                    dt.is_derived() && !doomed.contains(k) && dt.any_ref(|r| doomed.contains(&r))
                })
                .map(|(k, _)| *k)
                .collect();
            if more.is_empty() {
                return doomed;
            }
            doomed.extend(more);
        }
    }

    #[allow(dead_code)]
    pub fn is_used_at(&self, id: TypeId, used: &HashMap<u64, TypeId>) -> bool {
        let doomed = self.dependents_closure(id);
        used.values().any(|t| doomed.contains(t))
    }

    #[allow(dead_code)]
    pub fn delete_with_usages(
        &mut self,
        id: TypeId,
        used: &HashMap<u64, TypeId>,
    ) -> Result<(), String> {
        if self.is_used_at(id, used) {
            return Err("Type is still applied at an address (data_types_at)".into());
        }
        self.delete(id)
    }

    pub fn delete(&mut self, id: TypeId) -> Result<(), String> {
        if id < FIRST_USER_TYPE_ID {
            return Err("Cannot delete a built-in type".into());
        }
        if !self.types.contains_key(&id) {
            return Err(format!("No such data type: {}", id));
        }
        let doomed = self.dependents_closure(id);
        let referenced = self
            .types
            .iter()
            .any(|(k, dt)| !doomed.contains(k) && dt.any_ref(|r| doomed.contains(&r)));
        if referenced {
            return Err("Type is still referenced by another type".into());
        }
        let names: Vec<(String, TypeId)> = doomed.iter().map(|&d| (self.type_name(d), d)).collect();
        for (name, d) in names {
            if self.by_name.get(&name) == Some(&d) {
                self.by_name.remove(&name);
            }
            self.types.remove(&d);
        }
        Ok(())
    }

    pub(crate) fn embeds(&self, haystack: TypeId, needle: TypeId) -> bool {
        let mut seen: HashSet<TypeId> = HashSet::new();
        let mut stack = vec![haystack];
        while let Some(cur) = stack.pop() {
            if cur == needle {
                return true;
            }
            if !seen.insert(cur) {
                continue;
            }
            match self.types.get(&cur) {
                Some(DataType::Array { element, .. }) => stack.push(*element),
                Some(DataType::Typedef { target, .. }) => stack.push(*target),
                Some(DataType::Enum { underlying, .. }) => stack.push(*underlying),
                Some(DataType::Struct { fields, .. }) | Some(DataType::Union { fields, .. }) => {
                    stack.extend(fields.iter().map(|f| f.type_id));
                }
                _ => {}
            }
        }
        false
    }

    fn push_member(&mut self, id: TypeId, field: StructField) -> Result<StructField, String> {
        let (fields, sorted) = match self.types.get_mut(&id) {
            Some(DataType::Struct { fields, .. }) => (fields, true),
            Some(DataType::Union { fields, .. }) => (fields, false),
            _ => return Err("Not a struct or union".into()),
        };
        if fields.iter().any(|f| f.name == field.name) {
            return Err(format!("Field '{}' already exists", field.name));
        }
        if sorted {
            let pos = fields.partition_point(|f| f.offset <= field.offset);
            fields.insert(pos, field.clone());
        } else {
            fields.push(field.clone());
        }
        Ok(field)
    }

    pub fn add_field(
        &mut self,
        id: TypeId,
        name: &str,
        type_id: TypeId,
        offset: Option<usize>,
        comment: &str,
    ) -> Result<StructField, String> {
        if !matches!(
            self.types.get(&id),
            Some(DataType::Struct { .. }) | Some(DataType::Union { .. })
        ) {
            return Err("Not a struct or union".into());
        }
        if !self.types.contains_key(&type_id) {
            return Err("Field type does not exist".into());
        }
        if self.embeds(type_id, id) {
            return Err(format!(
                "Field '{}' would make '{}' contain itself by value",
                name,
                self.type_name(id)
            ));
        }
        let off = match offset {
            Some(o) => o,
            None => match self.types.get(&id) {
                Some(DataType::Struct { fields, .. }) => fields
                    .iter()
                    .map(|f| {
                        f.offset
                            .saturating_add(self.size_of(f.type_id).unwrap_or(1))
                    })
                    .max()
                    .unwrap_or(0),
                _ => 0,
            },
        };
        self.push_member(
            id,
            StructField {
                name: name.to_string(),
                offset: off,
                type_id,
                comment: comment.to_string(),
                bit_offset: None,
                bit_width: None,
            },
        )
    }

    pub fn add_bitfield(
        &mut self,
        id: TypeId,
        name: &str,
        storage_type: TypeId,
        byte_offset: usize,
        bit_offset: u8,
        bit_width: u8,
    ) -> Result<StructField, String> {
        let storage_bits = self.size_of(storage_type).unwrap_or(0).saturating_mul(8);
        if storage_bits == 0 {
            return Err("Bitfield storage type must have a known size".into());
        }
        if bit_width == 0 || bit_width as usize > storage_bits {
            return Err(format!(
                "Bit width {} doesn't fit in {}-bit storage",
                bit_width, storage_bits
            ));
        }
        if bit_offset as usize + bit_width as usize > storage_bits {
            return Err(format!(
                "Bits {}..{} exceed {}-bit storage",
                bit_offset,
                bit_offset as usize + bit_width as usize,
                storage_bits
            ));
        }
        self.push_member(
            id,
            StructField {
                name: name.to_string(),
                offset: byte_offset,
                type_id: storage_type,
                comment: String::new(),
                bit_offset: Some(bit_offset),
                bit_width: Some(bit_width),
            },
        )
    }

    pub fn remove_field(&mut self, id: TypeId, name: &str) -> Result<(), String> {
        let fields = match self.types.get_mut(&id) {
            Some(DataType::Struct { fields, .. }) | Some(DataType::Union { fields, .. }) => fields,
            _ => return Err("Not a struct or union".into()),
        };
        let before = fields.len();
        fields.retain(|f| f.name != name);
        if fields.len() == before {
            return Err(format!("No such field: {}", name));
        }
        Ok(())
    }

    pub fn set_packed(&mut self, id: TypeId, packed: bool) -> Result<(), String> {
        match self.types.get_mut(&id) {
            Some(DataType::Struct { packed: p, .. }) => {
                *p = packed;
                Ok(())
            }
            _ => Err("Not a struct".into()),
        }
    }

    pub fn add_enum_variant(&mut self, id: TypeId, name: &str, value: i64) -> Result<(), String> {
        match self.types.get_mut(&id) {
            Some(DataType::Enum { variants, .. }) => {
                if variants.iter().any(|(n, _)| n == name) {
                    return Err(format!("Variant '{}' already exists", name));
                }
                let pos = variants.partition_point(|(_, v)| *v <= value);
                variants.insert(pos, (name.to_string(), value));
                Ok(())
            }
            _ => Err("Not an enum".into()),
        }
    }

    fn write_type_name(&self, id: TypeId, out: &mut String) {
        match self.types.get(&id) {
            Some(DataType::Pointer { target }) => {
                self.write_type_name(*target, out);
                out.push('*');
            }
            Some(DataType::Array { element, count }) => {
                self.write_type_name(*element, out);
                let _ = write!(out, "[{}]", count);
            }
            Some(dt) => out.push_str(dt.own_name().unwrap_or("")),
            None => {
                let _ = write!(out, "unknown_{}", id);
            }
        }
    }

    pub fn type_name(&self, id: TypeId) -> String {
        let mut s = String::new();
        self.write_type_name(id, &mut s);
        s
    }

    pub fn size_of(&self, id: TypeId) -> Option<usize> {
        self.layout_of(id, 0).0
    }

    pub fn align_of(&self, id: TypeId) -> usize {
        self.layout_of(id, 0).1
    }

    fn layout_of(&self, id: TypeId, depth: usize) -> (Option<usize>, usize) {
        if depth > MAX_LAYOUT_DEPTH {
            return (None, 1);
        }
        let d = depth + 1;
        match self.types.get(&id) {
            Some(DataType::Primitive { size, .. }) => (Some(*size), (*size).max(1)),
            Some(DataType::Pointer { .. }) => (Some(self.pointer_size), self.pointer_size.max(1)),
            Some(DataType::Array { element, count }) => {
                let (size, align) = self.layout_of(*element, d);
                (size.map(|s| s.saturating_mul(*count)), align)
            }
            Some(DataType::Struct { fields, packed, .. }) => {
                let mut end = 0usize;
                let mut align = 1usize;
                for f in fields {
                    let (fsz, falign) = self.layout_of(f.type_id, d);
                    end = end.max(f.offset.saturating_add(fsz.unwrap_or(1)));
                    align = align.max(falign);
                }
                if *packed {
                    return (Some(end), 1);
                }
                (Some(round_up(end, align)), align)
            }
            Some(DataType::Union { fields, .. }) => {
                let mut size: Option<usize> = None;
                let mut align = 1usize;
                for f in fields {
                    let (fsz, falign) = self.layout_of(f.type_id, d);
                    size = Some(size.unwrap_or(0).max(fsz.unwrap_or(1)));
                    align = align.max(falign);
                }
                match size {
                    None => (None, 1),
                    Some(s) => (Some(round_up(s.max(1), align)), align),
                }
            }
            Some(DataType::Enum { underlying, .. }) => self.layout_of(*underlying, d),
            Some(DataType::Typedef { target, .. }) => self.layout_of(*target, d),
            Some(DataType::String) | Some(DataType::FunctionSig { .. }) | None => (None, 1),
        }
    }

    fn c_declare(&self, ty: TypeId, name: &str) -> String {
        let mut dims = String::new();
        let mut cur = ty;
        while let Some(DataType::Array { element, count }) = self.types.get(&cur) {
            let _ = write!(dims, "[{}]", count);
            cur = *element;
        }
        let base = self.type_name(cur);
        if name.is_empty() {
            format!("{}{}", base, dims)
        } else {
            format!("{} {}{}", base, name, dims)
        }
    }

    fn write_members(&self, out: &mut String, fields: &[StructField], pad: &str) {
        for f in fields {
            match f.bit_width {
                Some(w) => {
                    let _ = write!(
                        out,
                        "{}{} {} : {};",
                        pad,
                        self.type_name(f.type_id),
                        f.name,
                        w
                    );
                }
                None => {
                    let _ = write!(out, "{}{};", pad, self.c_declare(f.type_id, &f.name));
                }
            }
            if !f.comment.is_empty() {
                let _ = write!(out, " // {}", f.comment.replace('\n', " "));
            }
            out.push('\n');
        }
    }

    pub fn to_c_decl(&self, id: TypeId, indent: usize) -> String {
        let pad = " ".repeat(indent);
        match self.types.get(&id) {
            Some(DataType::Struct {
                name,
                fields,
                packed,
            }) => {
                if fields.is_empty() {
                    return format!("struct {};", name);
                }
                let mut s = String::with_capacity(32 + fields.len() * 32);
                let _ = writeln!(s, "struct {} {{", name);
                self.write_members(&mut s, fields, &pad);
                let _ = write!(
                    s,
                    "{}}}{};",
                    pad,
                    if *packed {
                        " __attribute__((packed))"
                    } else {
                        ""
                    }
                );
                s
            }
            Some(DataType::Union { name, fields }) => {
                if fields.is_empty() {
                    return format!("union {};", name);
                }
                let mut s = String::with_capacity(32 + fields.len() * 32);
                let _ = writeln!(s, "union {} {{", name);
                self.write_members(&mut s, fields, &pad);
                let _ = write!(s, "{}}};", pad);
                s
            }
            Some(DataType::Enum { name, variants, .. }) => {
                let mut s = String::with_capacity(32 + variants.len() * 24);
                let _ = writeln!(s, "enum {} {{", name);
                for (vname, v) in variants {
                    let _ = writeln!(s, "{}{} = {},", pad, vname, v);
                }
                let _ = write!(s, "{}}};", pad);
                s
            }
            Some(DataType::Typedef { name, target }) => {
                format!("typedef {};", self.c_declare(*target, name))
            }
            Some(DataType::FunctionSig {
                name,
                ret,
                params,
                calling_convention,
                varargs,
            }) => {
                let mut args: Vec<String> =
                    params.iter().map(|(t, n)| self.c_declare(*t, n)).collect();
                if *varargs {
                    args.push("...".to_string());
                }
                format!(
                    "{} {}({}) // calling convention: {}",
                    self.type_name(*ret),
                    name,
                    args.join(", "),
                    calling_convention
                )
            }
            _ => self.type_name(id),
        }
    }
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

fn strip_qualifiers(mut s: &str) -> &str {
    loop {
        let before = s.len();
        for q in [
            "const ",
            "volatile ",
            "struct ",
            "union ",
            "enum ",
            "class ",
        ] {
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
            return s;
        }
    }
}

fn alias_target(lower: &str, ptr_size: usize) -> Option<&'static str> {
    let wide = ptr_size >= 8;
    Some(match lower {
        "boolean" | "_bool" => "bool",
        "int8" | "int8_t" | "i8" | "sbyte" | "signed char" => "char",
        "byte" | "uint8" | "uint8_t" | "u8" | "unsigned char" => "uchar",
        "int16" | "int16_t" | "i16" | "short int" | "signed short" | "signed short int" => "short",
        "word" | "uint16" | "uint16_t" | "u16" | "unsigned short" | "unsigned short int"
        | "char16_t" | "wchar" | "wchar_t" => "ushort",
        "int32" | "int32_t" | "i32" | "signed" | "signed int" => "int",
        "dword" | "uint32" | "uint32_t" | "u32" | "unsigned" | "unsigned int" | "char32_t" => {
            "uint"
        }
        "long int" | "signed long" | "signed long int" => "long",
        "unsigned long" | "unsigned long int" | "long unsigned int" => "ulong",
        "int64" | "int64_t" | "i64" | "long long" | "long long int" | "signed long long" => {
            "longlong"
        }
        "qword"
        | "uint64"
        | "uint64_t"
        | "u64"
        | "unsigned long long"
        | "unsigned long long int" => "ulonglong",
        "intptr" | "intptr_t" | "ssize_t" | "ptrdiff_t" => {
            if wide {
                "longlong"
            } else {
                "int"
            }
        }
        "uintptr" | "uintptr_t" | "size_t" => {
            if wide {
                "ulonglong"
            } else {
                "uint"
            }
        }
        "float32" => "float",
        "float64" => "double",
        "unicode" => "string",
        _ => return None,
    })
}
