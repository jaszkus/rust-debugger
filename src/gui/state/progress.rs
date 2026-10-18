use super::*;

#[derive(Debug)]
pub struct LoadProgress {
    pub phase: String,
    pub done: bool,
    pub result: Option<Result<LoadedProgram, String>>,
    pub started_at: std::time::Instant,
}

#[derive(Debug)]
pub struct LoadedProgram {
    pub path: String,
    pub bin: crate::parser::ParsedBinary,
    pub disasm: crate::disasm::DisasmResult,
    pub analysis: Option<crate::analysis::AnalysisResult>,
    pub annotations: Option<crate::project::Annotations>,
    pub project_name: Option<String>,
}

impl LoadProgress {
    pub fn new() -> Self {
        Self {
            phase: "reading file".into(),
            done: false,
            result: None,
            started_at: std::time::Instant::now(),
        }
    }
}

impl Default for LoadProgress {
    fn default() -> Self {
        Self::new()
    }
}

pub fn invalidate_analysis_caches(state: &mut AppState) {
    state.analysis_version = state.analysis_version.wrapping_add(1);
    state.disasm_cache = None;
    state.strings_cache = (u64::MAX, String::new(), Vec::new());
    state.funcs_cache = (u64::MAX, String::new(), 0, Vec::new());
    state.decomp_cache = (u64::MAX, u64::MAX, Vec::new());
    state.cfg_layout_cache = (u64::MAX, u64::MAX, Vec::new(), Vec::new(), 0.0, 0.0);
}

pub fn drop_analysis(state: &mut AppState) {
    state.analysis = None;
    invalidate_analysis_caches(state);
}

pub fn rebuild_disasm_cache(state: &mut AppState) {
    if state.disasm_cache.is_some() {
        return;
    }
    let mut cache = DisasmCache::default();
    if let Some(ref analysis) = state.analysis {
        cache.func_lookup = analysis
            .functions
            .iter()
            .map(|f| (f.entry, f.name.clone()))
            .collect();
        cache.xref_to_func = analysis
            .xrefs
            .by_to
            .iter()
            .map(|(k, v)| (*k, v.len()))
            .collect();
        cache.sorted_func_entries = {
            let mut v: Vec<u64> = cache.func_lookup.keys().copied().collect();
            v.sort_unstable();
            v
        };
        cache.sorted_xref_addrs = {
            let mut v: Vec<u64> = cache
                .xref_to_func
                .iter()
                .filter(|(a, c)| **c > 0 && !cache.func_lookup.contains_key(*a))
                .map(|(a, _)| *a)
                .collect();
            v.sort_unstable();
            v
        };
    }
    if let Some(ref bin) = state.binary {
        cache.string_at = bin
            .strings
            .iter()
            .map(|s| (s.vaddr, s.content.clone()))
            .collect();
        cache.string_ranges = bin
            .strings
            .iter()
            .map(|s| {
                let len = match s.encoding {
                    crate::parser::StringEncoding::Ascii => s.content.len() as u64 + 1,
                    crate::parser::StringEncoding::Utf16Le => s.content.len() as u64 * 2 + 2,
                    crate::parser::StringEncoding::Utf32Le => s.content.len() as u64 * 4 + 4,
                    crate::parser::StringEncoding::Pascal => s.content.len() as u64 + 2,
                };
                (s.vaddr, s.vaddr.saturating_add(len))
            })
            .collect();
        cache.string_ranges.sort_by_key(|r| r.0);
    }
    state.disasm_cache = Some(cache);
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn poll_analysis(state: &mut AppState) {
    crate::gui::app::poll_analysis_install(state);
}

#[derive(Debug, Default)]
pub struct AnalysisProgress {
    pub phase: String,
    pub message: String,
    pub current: usize,
    pub total: usize,
    pub done: bool,
    pub started_at: Option<std::time::Instant>,
    pub result: Option<crate::analysis::AnalysisResult>,
    pub cancel: bool,
    pub log: Vec<String>,
}
