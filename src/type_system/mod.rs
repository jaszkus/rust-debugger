pub mod archive;
pub mod archives;
pub mod codec;
pub mod manager;
pub mod types;

#[cfg(test)]
mod tests;

pub use archive::{
    Arch, ArchiveFunction, ArchiveParam, ResolvedField, ResolvedType, TypeArchive, TypeArchiveSet,
    TypeKind, TypeRef, embedded_archive, embedded_archives, normalize_symbol, parse_archive,
    parse_type_expr,
};
pub use manager::DataTypeManager;
pub use types::*;
