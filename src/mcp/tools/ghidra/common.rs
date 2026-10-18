use std::sync::{Arc, Mutex};

use crate::gui::AppState;

pub(crate) use crate::mcp::tools::common::{arg_addr, arg_int, arg_str, arg_str_opt};

pub(crate) fn lock(
    state: &Arc<Mutex<AppState>>,
) -> Result<std::sync::MutexGuard<'_, AppState>, String> {
    state.lock().map_err(|_| "lock poisoned".to_string())
}

pub(crate) fn no_binary() -> String {
    "No binary loaded".to_string()
}

pub(crate) fn addr_str(a: u64) -> String {
    format!("{:#x}", a)
}

pub(crate) fn section_name_for(bin: &crate::parser::ParsedBinary, addr: u64) -> String {
    for s in &bin.sections {
        if addr >= s.vaddr && addr < s.vaddr + s.size {
            return s.name.clone();
        }
    }
    "".to_string()
}

pub(crate) fn paginate<T: Clone>(items: &[T], offset: usize, limit: usize) -> Vec<T> {
    let start = offset.min(items.len());
    let end = (start + limit).min(items.len());
    items[start..end].to_vec()
}
