pub mod analyze;
pub mod common;
pub mod funcs;
pub mod labels;
pub mod lists;
pub mod memory;
pub mod misc;
pub mod program;
pub mod search;
pub mod xrefs;

pub use analyze::{
    analyze_call_graph, analyze_control_flow, find_code_gaps, find_next_undefined_function,
};
pub use funcs::{diff_functions, get_function_signature};
pub use labels::{
    batch_set_comments, create_label, delete_label, get_function_labels, label_strings,
    list_function_tags, list_labels, tag_function, untag_function,
};
pub use lists::{
    list_calling_conventions, list_classes, list_data_items, list_globals, list_namespaces,
    list_valid_data_types,
};
pub use memory::{get_assembly_context, inspect_memory_content, read_memory};
pub use misc::{check_connection, debugger_stack_trace, get_version, health};
pub use program::{get_current_program_info, reanalyze, save_program};
pub use search::{
    force_decompile, search_byte_patterns, search_functions_enhanced, search_instructions,
};
pub use xrefs::{
    add_memory_reference, get_bulk_xrefs, get_function_xrefs, list_memory_references,
    remove_reference,
};
