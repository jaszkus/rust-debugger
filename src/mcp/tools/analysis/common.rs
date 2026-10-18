pub(crate) use crate::mcp::tools::common::{arg_addr, arg_int, arg_str, arg_str_opt};

pub(crate) fn function_containing(
    analysis: &crate::analysis::AnalysisResult,
    addr: u64,
) -> Option<&crate::analysis::DetectedFunction> {
    analysis
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
}

pub(crate) fn not_in_function(addr: u64) -> String {
    format!(
        "Function not found: {:#x} is not inside any known function",
        addr
    )
}

pub(crate) fn is_mapped(bin: &crate::parser::ParsedBinary, addr: u64) -> bool {
    bin.format == "RAW"
        || bin
            .sections
            .iter()
            .any(|sec| addr >= sec.vaddr && addr < sec.vaddr.saturating_add(sec.size))
}

pub(crate) fn extract_hex_token(s: &str) -> Option<&str> {
    let start = s.find("0x").or_else(|| s.find("0X"))?;
    let rest = &s[start..];
    let mut end = rest.len();
    for (i, c) in rest.char_indices() {
        if i < 2 {
            continue;
        }
        if !c.is_ascii_hexdigit() {
            end = i;
            break;
        }
    }
    Some(&rest[..end])
}
