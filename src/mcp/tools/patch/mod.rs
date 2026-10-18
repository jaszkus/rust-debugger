pub mod branches;
pub mod bytes;
pub mod common;
pub mod history;

pub use branches::{
    patch_call_to_nop, patch_function_to_ret, patch_jcc_invert, patch_jcc_to_jmp, patch_jcc_to_nop,
    patch_jmp_to_address, patch_nop_instruction, patch_return_value,
};
pub use bytes::{
    copy_bytes, fill_bytes, fill_pattern, nop_range, patch_bytes, patch_int, patch_string,
    patch_wide_string, search_and_replace_bytes,
};
pub use common::apply_patch_internal;
pub use history::{
    clear_patch_history, diff_with_file, export_patches, get_patch_diff, import_patches,
    list_patches, revert_all_patches, save_patched_binary, undo_last_patch, undo_patch_at,
};
