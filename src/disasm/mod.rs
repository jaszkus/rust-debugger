pub mod arm64;
pub mod operand_enum;
pub mod types;
pub mod x86;

pub use types::{DisasmInstruction, DisasmResult, InsnBytes};
pub(crate) use x86::intern_mnemonic;
pub use x86::{
    disassemble_binary, disassemble_region, peek_mnemonic, rebuild_after_patch,
    rebuild_after_patch_with_affected,
};
