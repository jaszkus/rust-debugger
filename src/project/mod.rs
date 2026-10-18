pub mod analysis_codec;
pub mod binary_codec;
#[cfg(test)]
mod compat_tests;
pub mod snapshot;

#[allow(unused_imports)]
pub use snapshot::{apply_annotations, db_path_for, load_project_db, save_project_db};
pub use snapshot::{resolve_db_path, Annotations};

const MAGIC: &[u8; 4] = b"RDDB";
pub(crate) const MAGIC_ZSTD: &[u8; 4] = b"RZ\x01\xa7";
const VERSION: u32 = 5;

pub(crate) fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
