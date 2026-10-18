use serde_json::{json, Value};

use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::common::vaddr_to_offset;

pub fn diff_functions(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let addr1 = arg_addr(args, "address_a")?;
    let addr2 = arg_addr(args, "address_b")?;
    let f1 = a
        .functions
        .iter()
        .find(|f| addr1 >= f.entry && addr1 < f.end)
        .ok_or("address_a not in any function")?;
    let f2 = a
        .functions
        .iter()
        .find(|f| addr2 >= f.entry && addr2 < f.end)
        .ok_or("address_b not in any function")?;
    let d = s.disasm.as_ref().ok_or("No disassembly loaded")?;
    let seq1: Vec<String> = d
        .instructions
        .iter()
        .filter(|i| i.address >= f1.entry && i.address < f1.end)
        .map(|i| i.mnemonic.to_string())
        .collect();
    let seq2: Vec<String> = d
        .instructions
        .iter()
        .filter(|i| i.address >= f2.entry && i.address < f2.end)
        .map(|i| i.mnemonic.to_string())
        .collect();
    let mut common = 0usize;
    let n = seq1.len().min(seq2.len());
    for i in 0..n {
        if seq1[i] == seq2[i] {
            common += 1;
        }
    }
    Ok(json!({
        "function_a": addr_str(f1.entry),
        "function_b": addr_str(f2.entry),
        "name_a": f1.name,
        "name_b": f2.name,
        "size_a": f1.end.saturating_sub(f1.entry),
        "size_b": f2.end.saturating_sub(f2.entry),
        "insn_count_a": seq1.len(),
        "insn_count_b": seq2.len(),
        "identical_prefix": common,
        "similarity": if n > 0 { common as f64 / n as f64 } else { 0.0 }
    }))
}

pub fn get_function_signature(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = lock(state)?;
    let a = s
        .analysis
        .as_ref()
        .ok_or("No analysis loaded - run the run_analysis tool first")?;
    let addr = arg_addr(args, "address")?;
    let f = a
        .functions
        .iter()
        .find(|f| addr >= f.entry && addr < f.end)
        .ok_or("Address not in any function")?;
    let len = arg_int(args, "bytes", 16).max(1) as usize;
    let bin = s.binary.as_ref().ok_or_else(no_binary)?;
    let offset = vaddr_to_offset(bin, f.entry).ok_or("Function entry outside mapped memory")?;
    let n = len.min(bin.data.len().saturating_sub(offset));
    let sig: String = bin.data[offset..offset + n]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in sig.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(json!({
        "function": addr_str(f.entry),
        "name": f.name,
        "bytes": sig,
        "fnv1a": format!("{:016x}", hash)
    }))
}
