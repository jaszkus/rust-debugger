use serde_json::{json, Value};
use std::sync::Arc;

use crate::gui::{AppState, PatchRecord};
pub(crate) use crate::mcp::tools::common::{arg_addr, arg_bool, arg_int, arg_str, arg_str_opt};
pub use crate::mcp::tools::common::{parse_hex_pattern, vaddr_to_offset};

pub(crate) fn offset_to_vaddr(bin: &crate::parser::ParsedBinary, offset: usize) -> u64 {
    for sec in &bin.sections {
        let so = sec.offset as usize;
        let se = so.saturating_add(sec.size as usize);
        if offset >= so && offset < se {
            return sec.vaddr.wrapping_add(offset as u64 - sec.offset);
        }
    }
    0
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn apply_patch_internal(
    state_lock: &mut std::sync::MutexGuard<'_, AppState>,
    vaddr: u64,
    new_bytes: &[u8],
    description: &str,
    invalidate_analysis: bool,
) -> Result<(u64, Vec<u8>, usize), String> {
    apply_patch_internal_impl(
        state_lock,
        vaddr,
        new_bytes,
        description,
        invalidate_analysis,
        true,
    )
}

pub fn apply_patch_internal_impl(
    state_lock: &mut std::sync::MutexGuard<'_, AppState>,
    vaddr: u64,
    new_bytes: &[u8],
    description: &str,
    invalidate_analysis: bool,
    re_disasm: bool,
) -> Result<(u64, Vec<u8>, usize), String> {
    if new_bytes.is_empty() {
        return Err("Empty patch".into());
    }
    let bin = state_lock.binary.as_mut().ok_or("No binary loaded")?;
    let off = vaddr_to_offset(bin, vaddr).ok_or("Address not in any section")?;
    let end = off
        .checked_add(new_bytes.len())
        .ok_or("Patch offset overflow")?;
    if end > bin.data.len() {
        return Err(format!(
            "Patch goes past end of data ({} bytes at offset {:#x}, file size {:#x})",
            new_bytes.len(),
            off,
            bin.data.len()
        ));
    }
    let original: Vec<u8> = bin.data[off..end].to_vec();
    Arc::make_mut(&mut bin.data)[off..end].copy_from_slice(new_bytes);

    state_lock.patch_seq += 1;
    let id = state_lock.patch_seq;
    state_lock.patches.push(PatchRecord {
        id,
        offset: off,
        vaddr,
        original: original.clone(),
        new: new_bytes.to_vec(),
        description: description.to_string(),
        timestamp: now_secs(),
    });

    if re_disasm {
        let ranges = [(off, new_bytes.len())];
        if let (Some(bin), Some(old)) = (state_lock.binary.as_ref(), state_lock.disasm.as_ref()) {
            state_lock.disasm = Some(crate::disasm::rebuild_after_patch(bin, old, &ranges));
        } else if let Some(bin) = state_lock.binary.as_ref()
            && let Ok(disasm) = crate::disasm::disassemble_binary(bin) {
                state_lock.disasm = Some(disasm);
            }
    }
    if invalidate_analysis {
        crate::gui::drop_analysis(state_lock);
    }
    state_lock.status_msg = format!(
        "Patched {} bytes at {:#x} ({})",
        new_bytes.len(),
        vaddr,
        description
    );

    Ok((id, original, off))
}

pub(crate) fn apply_offset_patch(
    state_lock: &mut std::sync::MutexGuard<'_, AppState>,
    offset: usize,
    new_bytes: &[u8],
    description: &str,
) -> Result<u64, String> {
    let bin = state_lock.binary.as_mut().ok_or("No binary loaded")?;
    let end = offset
        .checked_add(new_bytes.len())
        .ok_or("Patch offset overflow")?;
    if end > bin.data.len() {
        return Err("Patch goes past end of data".into());
    }
    let original: Vec<u8> = bin.data[offset..end].to_vec();
    Arc::make_mut(&mut bin.data)[offset..end].copy_from_slice(new_bytes);
    let vaddr = offset_to_vaddr(bin, offset);

    state_lock.patch_seq += 1;
    let id = state_lock.patch_seq;
    state_lock.patches.push(PatchRecord {
        id,
        offset,
        vaddr,
        original,
        new: new_bytes.to_vec(),
        description: description.to_string(),
        timestamp: now_secs(),
    });
    Ok(id)
}

pub(crate) fn record_to_json(p: &PatchRecord) -> Value {
    json!({
        "id": p.id,
        "offset": p.offset,
        "address": format!("{:#x}", p.vaddr),
        "size": p.new.len(),
        "original_bytes": hex(&p.original),
        "new_bytes": hex(&p.new),
        "description": p.description,
        "timestamp": p.timestamp,
    })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

pub(crate) fn read_byte(state_lock: &AppState, vaddr: u64) -> Result<u8, String> {
    let bin = state_lock.binary.as_ref().ok_or("No binary loaded")?;
    let off = vaddr_to_offset(bin, vaddr).ok_or("Address not in any section")?;
    bin.data
        .get(off)
        .copied()
        .ok_or_else(|| "Out of bounds".to_string())
}

pub(crate) fn read_bytes_at(
    state_lock: &AppState,
    vaddr: u64,
    n: usize,
) -> Result<Vec<u8>, String> {
    let bin = state_lock.binary.as_ref().ok_or("No binary loaded")?;
    let off = vaddr_to_offset(bin, vaddr).ok_or("Address not in any section")?;
    let end = off + n;
    if end > bin.data.len() {
        return Err("Out of bounds".into());
    }
    Ok(bin.data[off..end].to_vec())
}
