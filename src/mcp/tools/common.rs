use serde_json::Value;

use super::parse_addr;
use crate::parser::ParsedBinary;

pub fn arg_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Missing required argument: {}", key))
}

pub fn arg_str_opt(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn arg_addr(args: &Value, key: &str) -> Result<u64, String> {
    let s = arg_str(args, key)?;
    parse_addr(&s).ok_or_else(|| format!("Invalid address: {}", s))
}

pub fn arg_int(args: &Value, key: &str, default: i64) -> i64 {
    args.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
}

pub fn arg_bool(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

pub fn parse_hex_pattern(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err("Hex pattern must have even number of digits".into());
    }
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn vaddr_to_offset(bin: &ParsedBinary, vaddr: u64) -> Option<usize> {
    for sec in &bin.sections {
        let sec_end = sec.vaddr.checked_add(sec.size)?;
        if vaddr >= sec.vaddr && vaddr < sec_end {
            return sec
                .offset
                .checked_add(vaddr - sec.vaddr)
                .map(|o| o as usize);
        }
    }
    if bin.format == "RAW" {
        return vaddr.checked_sub(bin.image_base).map(|o| o as usize);
    }
    None
}
