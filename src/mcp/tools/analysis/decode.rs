use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::parse_addr;

pub fn disassemble_range(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let start = arg_addr(args, "address")?;
    let count = arg_int(args, "count", 32).clamp(1, 4096) as usize;
    let end_addr = args
        .get("end_address")
        .and_then(|v| v.as_str())
        .and_then(parse_addr);

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let d = s.disasm.as_ref().ok_or("No disassembly loaded")?;

    if let Some(bin) = s.binary.as_ref()
        && !is_mapped(bin, start) {
            return Err(format!("Address {:#x} not in any section", start));
        }

    let begin = d.instructions.partition_point(|i| i.address < start);
    if begin >= d.instructions.len() {
        return Err(format!("No instructions at or after {:#x}", start));
    }
    let first = d.instructions[begin].address;

    let mut lines: Vec<Value> = Vec::new();
    for insn in d.instructions.iter().skip(begin) {
        if let Some(e) = end_addr
            && insn.address >= e {
                break;
            }
        if lines.len() >= count {
            break;
        }
        lines.push(crate::mcp::tools::format::instruction(insn));
    }

    let mut out = json!({
        "start": format!("{:#x}", start),
        "first_address": format!("{:#x}", first),
        "instruction_count": lines.len(),
        "lines": lines,
    });
    if first != start {
        crate::mcp::tools::schemas::push_warning(&mut out, format!(
            "no decoded instruction starts at {:#x}; the listing begins at the next one, {:#x} ({} bytes later: data, padding, or the middle of an instruction)",
            start, first, first - start
        ));
    }
    Ok(out)
}

pub fn disassemble_bytes(args: &Value, _state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let hex_str = crate::mcp::tools::schemas::arg_str_alias(args, &["bytes", "hex"])?;
    let base = match crate::mcp::tools::schemas::arg_opt_alias(args, &["base_address", "base"]) {
        Some(b) => parse_addr(&b).ok_or_else(|| format!("Invalid address: {}", b))?,
        None => 0,
    };
    let arch = {
        let a = arg_str_opt(args, "arch");
        if a.is_empty() {
            "x86_64".to_string()
        } else {
            a
        }
    };

    let clean: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err("Hex must have even number of digits".into());
    }
    let bytes: Vec<u8> = (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        return Err("Empty bytes".into());
    }

    let insns = crate::disasm::disassemble_region(&bytes, base, &arch)?;
    let lines: Vec<Value> = insns
        .iter()
        .map(crate::mcp::tools::format::instruction)
        .collect();

    Ok(json!({
        "arch": arch,
        "base_address": format!("{:#x}", base),
        "input_bytes": clean,
        "instruction_count": lines.len(),
        "lines": lines,
    }))
}
