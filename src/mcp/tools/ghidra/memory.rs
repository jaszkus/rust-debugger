use serde_json::{json, Value};

use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::common::vaddr_to_offset;
use crate::mcp::tools::data::get_bytes;

pub fn inspect_memory_content(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    let addr = arg_addr(args, "address")?;
    let size = arg_int(args, "size", 32).max(1) as usize;
    let offset = vaddr_to_offset(bin, addr).ok_or("Address out of range")?;
    if offset >= bin.data.len() {
        return Err("Address out of range".into());
    }
    let n = size.min(bin.data.len() - offset);
    let bytes = &bin.data[offset..offset + n];
    let mut ascii = String::new();
    for b in bytes {
        ascii.push(if b.is_ascii_graphic() || *b == b' ' {
            *b as char
        } else {
            '.'
        });
    }
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let mut kind = "data";
    if bytes.len() >= 4 {
        let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if u64::from(v) >= bin.image_base
            && u64::from(v) < bin.image_base.wrapping_add(bin.data.len() as u64)
        {
            kind = "pointer";
        }
    }
    if bytes
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0)
        && bytes.contains(&0)
    {
        kind = "string";
    }
    let sec = section_name_for(bin, addr);
    Ok(json!({
        "address": addr_str(addr),
        "section": sec,
        "hex": hex,
        "ascii": ascii,
        "guessed_type": kind
    }))
}

pub fn read_memory(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    get_bytes(args, state)
}

pub fn get_assembly_context(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    let addr = arg_addr(args, "address")?;
    let before = arg_int(args, "before", 8).max(0) as usize;
    let after = arg_int(args, "after", 8).max(0) as usize;

    let mut aligned = false;
    let base = match s.disasm.as_ref() {
        Some(d) => {
            let idx = d
                .instructions
                .partition_point(|i| i.address <= addr.saturating_sub(before as u64));
            if idx > 0 {
                aligned = true;
                d.instructions[idx - 1].address
            } else {
                addr.saturating_sub(before as u64)
            }
        }
        None => addr.saturating_sub(before as u64),
    };
    let end_addr = addr.saturating_add(after as u64);
    let size = end_addr.saturating_sub(base).min(64 * 1024) as usize;
    let offset = vaddr_to_offset(bin, base).ok_or("Address out of range")?;
    if offset >= bin.data.len() {
        return Err("Address out of range".into());
    }
    let n = size.min(bin.data.len() - offset);
    let bytes = &bin.data[offset..offset + n];
    let disasm = crate::disasm::disassemble_region(bytes, base, &bin.arch).unwrap_or_default();
    let rows: Vec<Value> = disasm
        .iter()
        .map(|i| {
            json!({
                "address": addr_str(i.address),
                "mnemonic": i.mnemonic,
                "operands": i.ops().as_ref(),
                "bytes": i.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
                "is_target": i.address == addr,
            })
        })
        .collect();
    Ok(json!({
        "target": addr_str(addr),
        "window_start_aligned_to_instruction": aligned,
        "instructions": rows
    }))
}
