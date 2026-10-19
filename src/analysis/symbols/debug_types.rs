use rustc_hash::FxHashMap as HashMap;

use crate::parser::ParsedBinary;









#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugTypes {
    pub structs: Vec<DebugStruct>,
    pub functions: HashMap<u64, DebugFunction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugStruct {
    pub name: String,
    pub size: usize,
    pub fields: Vec<DebugField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugField {
    pub name: String,
    pub offset: usize,
    pub type_name: String,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugFunction {
    pub name: String,
    pub ret: String,
    pub params: Vec<DebugParam>,
    pub locals: Vec<DebugLocal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugBase {
    
    Cfa,
    
    Rbp,
    
    Rsp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugLocal {
    pub name: String,
    pub type_name: String,
    pub struct_name: Option<String>,
    pub base: DebugBase,
    pub offset: i64,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugParam {
    pub name: String,
    pub type_name: String,
    
    
    
    pub struct_name: Option<String>,
}

impl DebugTypes {
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty() && self.functions.is_empty()
    }

    pub fn load(binary: &ParsedBinary, source_path: Option<&str>) -> Option<Self> {
        let mut out = Self::default();
        if (binary.format.starts_with("PE") || binary.format == "COFF")
            && let Some(pdb) = super::pdb_types::debug_types_from_pdb(binary, source_path)
        {
            out.merge(pdb);
        }
        if binary.format == "ELF"
            && let Some(dwarf) = super::dwarf_types::debug_types_from_dwarf(binary)
        {
            out.merge(dwarf);
        }
        (!out.is_empty()).then_some(out)
    }

    fn merge(&mut self, mut other: Self) {
        self.structs.append(&mut other.structs);
        self.structs.sort_by(|a, b| a.name.cmp(&b.name));
        self.structs.dedup_by(|a, b| a.name == b.name);
        for (addr, func) in other.functions {
            self.functions.entry(addr).or_insert(func);
        }
    }

    pub fn function(&self, addr: u64) -> Option<&DebugFunction> {
        self.functions.get(&addr)
    }

    pub fn struct_named(&self, name: &str) -> Option<&DebugStruct> {
        self.structs.iter().find(|s| s.name == name)
    }

    
    
    
    
    
    
    
    pub fn struct_for_offsets(
        &self,
        offsets: &[i64],
        preferred: Option<&str>,
    ) -> Option<&DebugStruct> {
        if offsets.is_empty() {
            return None;
        }
        if let Some(name) = preferred
            && let Some(s) = self.struct_named(name)
            && s.covers(offsets)
        {
            return Some(s);
        }
        let mut candidates: Vec<&DebugStruct> = self
            .structs
            .iter()
            .filter(|s| s.covers(offsets))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by(|a, b| {
            a.fields
                .len()
                .cmp(&b.fields.len())
                .then_with(|| a.name.cmp(&b.name))
        });
        if candidates.len() == 1 {
            return candidates.first().copied();
        }
        
        
        
        let first_names: Vec<&str> = offsets
            .iter()
            .map(|o| candidates[0].field_name(*o))
            .collect();
        let agree = candidates.iter().all(|s| {
            offsets
                .iter()
                .zip(&first_names)
                .all(|(o, n)| s.field_name(*o) == *n)
        });
        agree.then(|| candidates[0])
    }
}

impl DebugStruct {
    pub fn field_at(&self, offset: i64) -> Option<&DebugField> {
        self.fields
            .iter()
            .find(|f| f.offset as i64 == offset)
    }

    pub fn field_name(&self, offset: i64) -> &str {
        self.field_at(offset).map(|f| f.name.as_str()).unwrap_or("")
    }

    fn covers(&self, offsets: &[i64]) -> bool {
        !self.fields.is_empty() && offsets.iter().all(|o| self.field_at(*o).is_some())
    }
}
