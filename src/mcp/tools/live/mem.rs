use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;
use crate::mcp::tools::schemas::arg_query;

pub fn read_proc_mem_blocking(
    state: &Arc<Mutex<AppState>>,
    address: u64,
    size: usize,
) -> Result<Vec<u8>, String> {
    let (id, sig) = {
        let mut s = try_state(state)?;
        if !s.debug_state.is_attached {
            return Err("No debugger attached. Call debugger_start first.".into());
        }
        s.debug_state.mem_request_seq += 1;
        let id = s.debug_state.mem_request_seq;
        s.debug_state.mem_read_result = None;
        s.debug_state.mem_read_request =
            Some(crate::debugger::MemReadRequest { id, address, size });
        let sig = s.debug_state.signal.clone();
        (id, sig)
    };
    if let Ok(s) = state.try_lock() {
        s.debug_state.signal.notify();
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        sig.wait(std::time::Duration::from_millis(10));
        let mut s = match state.try_lock() {
            Ok(g) => g,
            Err(_) => {
                if std::time::Instant::now() >= deadline {
                    return Err(
                        "Service unavailable (503): state busy reading process memory".into(),
                    );
                }
                continue;
            }
        };
        if let Some(res) = &s.debug_state.mem_read_result {
            if res.id == id {
                let res = s.debug_state.mem_read_result.take().unwrap();
                return res.data;
            }
        }
        drop(s);
        if std::time::Instant::now() >= deadline {
            return Err("Timed out reading process memory".into());
        }
    }
}

pub fn disassemble_process_memory(
    args: &Value,
    state: &Arc<Mutex<AppState>>,
) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let count = arg_int(args, "count", 32).clamp(1, 1024) as usize;
    let arch = args
        .get("arch")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "x86_64".into());
    let buf = read_proc_mem_blocking(state, addr, count * 16)?;
    if buf.is_empty() {
        return Err("Failed to read any bytes from the address".into());
    }
    let insns = crate::disasm::disassemble_region(&buf, addr, &arch)?;
    let lines: Vec<Value> = insns
        .iter()
        .take(count)
        .map(|i| {
            let asm = if i.ops().is_empty() {
                i.mnemonic.to_string()
            } else {
                format!("{} {}", i.mnemonic, i.operands)
            };
            json!({
                "address": format!("{:#x}", i.address),
                "asm": asm,
                "bytes": i.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
            })
        })
        .collect();

    Ok(json!({
        "address": format!("{:#x}", addr),
        "instruction_count": lines.len(),
        "lines": lines,
    }))
}

pub fn search_process_memory(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let pattern = arg_query(args)?;
    let limit = arg_int(args, "limit", 100).clamp(1, 100_000) as usize;
    let only_executable = args
        .get("only_executable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let only_writable = args
        .get("only_writable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let module_filter = args.get("module").and_then(|v| v.as_str()).unwrap_or("");
    let start_at = args
        .get("start")
        .and_then(|v| v.as_str())
        .and_then(|s| arg_addr(&json!({"address": s}), "address").ok());
    let end_at = args
        .get("end")
        .and_then(|v| v.as_str())
        .and_then(|s| arg_addr(&json!({"address": s}), "address").ok());
    let max_bytes = (arg_int(args, "max_mb", 256).clamp(1, 1024) as u64) << 20;

    let mut needles: Vec<(Vec<Option<u8>>, &'static str)> = Vec::new();
    if let Some(rest) = pattern.strip_prefix("s:") {
        let ascii: Vec<Option<u8>> = rest.as_bytes().iter().map(|&b| Some(b)).collect();
        let mut utf16: Vec<Option<u8>> = Vec::with_capacity(ascii.len() * 2);
        for b in rest.encode_utf16().flat_map(|u| u.to_le_bytes()) {
            utf16.push(Some(b));
        }
        if !ascii.iter().any(|b| b.is_some()) {
            return Err("Empty pattern".into());
        }
        needles.push((ascii, "ascii"));
        needles.push((utf16, "utf16le"));
    } else {
        needles.push((crate::mcp::tools::search::parse_pattern(&pattern)?, "hex"));
    }
    if needles.is_empty() || needles.iter().all(|(n, _)| n.is_empty()) {
        return Err("Empty pattern".into());
    }
    struct NeedlePlan {
        bytes: Vec<Option<u8>>,
        anchor: (usize, u8),
        encoding: &'static str,
    }
    let plans: Vec<NeedlePlan> = needles
        .into_iter()
        .filter(|(n, _)| !n.is_empty())
        .map(|(bytes, encoding)| {
            let anchor = bytes
                .iter()
                .position(|b| b.is_some())
                .map(|i| (i, bytes[i].unwrap()))
                .ok_or_else(|| "Pattern contains no concrete bytes".to_string());
            match anchor {
                Ok(a) => Ok(NeedlePlan {
                    bytes,
                    anchor: a,
                    encoding,
                }),
                Err(e) => Err(e),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let matches_at = |data: &[u8], i: usize, plan: &NeedlePlan| -> bool {
        for (k, want) in plan.bytes.iter().enumerate() {
            if let Some(w) = want {
                if data[i + k] != *w {
                    return false;
                }
            }
        }
        true
    };

    let t0 = std::time::Instant::now();

    let regions: Vec<crate::debugger::MemoryRegion> = wait_for(
        state,
        |s| {
            s.debug_state.mem_request_seq += 1;
            let id = s.debug_state.mem_request_seq;
            s.debug_state.mem_regions_result = None;
            s.debug_state.mem_regions_request = Some(id);
            Ok(id)
        },
        |s, id| {
            if let Some((rid, _)) = &s.debug_state.mem_regions_result {
                if *rid == id {
                    let (_, r) = s.debug_state.mem_regions_result.take().unwrap();
                    return Some(r);
                }
            }
            None
        },
        3000,
    )?;

    let mut module_span: Option<(u64, u64)> = None;
    if !module_filter.is_empty() {
        let mods: Vec<crate::debugger::ModuleInfo> = wait_for(
            state,
            |s| {
                s.debug_state.mem_request_seq += 1;
                let id = s.debug_state.mem_request_seq;
                s.debug_state.modules_result = None;
                s.debug_state.modules_request = Some(id);
                Ok(id)
            },
            |s, id| {
                if let Some((rid, _)) = &s.debug_state.modules_result {
                    if *rid == id {
                        let (_, r) = s.debug_state.modules_result.take().unwrap();
                        return Some(r);
                    }
                }
                None
            },
            3000,
        )?;
        let mf = module_filter.to_ascii_lowercase();
        module_span = mods
            .iter()
            .find(|m| m.name.to_ascii_lowercase().contains(&mf))
            .map(|m| (m.base, m.base + m.size));
        if module_span.is_none() {
            return Err(format!(
                "Module '{}' not found in target process (try list_modules)",
                module_filter
            ));
        }
    }

    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    const MEM_COMMIT: u32 = 0x1000;
    const CHUNK: usize = 1 << 20;

    let mut hits: Vec<Value> = Vec::new();
    let mut scanned: u64 = 0;
    let mut regions_scanned = 0usize;
    let mut regions_skipped = 0usize;
    let mut budget_exhausted = false;

    'regions: for r in &regions {
        if hits.len() >= limit {
            break;
        }
        if scanned >= max_bytes {
            budget_exhausted = true;
            break;
        }
        if r.state != MEM_COMMIT
            || r.protection & 0xff == PAGE_NOACCESS
            || r.protection & PAGE_GUARD != 0
        {
            regions_skipped += 1;
            continue;
        }
        let exec = matches!(r.protection & 0xf0, 0x10 | 0x20 | 0x40 | 0x80);
        let writ = matches!(r.protection & 0x0f, 0x04 | 0x08)
            || matches!(r.protection & 0xf0, 0x40 | 0x80);
        if (only_executable && !exec) || (only_writable && !writ) {
            regions_skipped += 1;
            continue;
        }
        let (mut lo, mut hi) = (r.base, r.base.saturating_add(r.size));
        if let Some((mb, me)) = module_span {
            lo = lo.max(mb);
            hi = hi.min(me);
        }
        if let (Some(s), Some(e)) = (start_at, end_at) {
            lo = lo.max(s);
            hi = hi.min(e);
        } else if let Some(s) = start_at {
            lo = lo.max(s);
        } else if let Some(e) = end_at {
            hi = hi.min(e);
        }
        if lo >= hi {
            continue;
        }
        let remaining_budget = max_bytes - scanned;
        let span = (hi - lo).min(remaining_budget);
        budget_exhausted |= (hi - lo) > remaining_budget;

        let mut off = 0u64;
        while off < span {
            let want = (span - off).min(CHUNK as u64) as usize;
            let data = match read_proc_mem_blocking(state, lo + off, want) {
                Ok(d) if !d.is_empty() => d,
                _ => {
                    break;
                }
            };
            let n = data.len();
            if n == 0 {
                break;
            }
            for plan in &plans {
                let plen = plan.bytes.len();
                let mut i = 0usize;
                while i + plen <= n {
                    if data[i + plan.anchor.0] == plan.anchor.1 && matches_at(&data, i, plan) {
                        hits.push(json!({
                            "address": format!("{:#x}", lo + off + i as u64),
                            "region_base": format!("{:#x}", r.base),
                            "protection": fmt_protection(r.protection),
                            "encoding": plan.encoding,
                        }));
                        if hits.len() >= limit {
                            break 'regions;
                        }
                        i += plen;
                    } else {
                        i += 1;
                    }
                }
            }
            scanned += n as u64;
            off += n as u64;
            if hits.len() >= limit {
                break;
            }
            if off < span {
                let max_needle = plans.iter().map(|p| p.bytes.len()).max().unwrap_or(1);
                let overlap = (max_needle - 1) as u64;
                off = off.saturating_sub(overlap.min(off));
            }
        }
        regions_scanned += 1;
        if hits.len() >= limit {
            break 'regions;
        }
    }
    Ok(json!({
        "matches": hits.len(),
        "items": hits,
        "truncated": hits.len() >= limit,
        "scanned_bytes": scanned,
        "regions_scanned": regions_scanned,
        "regions_skipped": regions_skipped,
        "budget_exhausted": budget_exhausted,
        "elapsed_ms": t0.elapsed().as_millis() as u64,
        "hint": if budget_exhausted {
            "Scan budget reached before covering every region. Narrow the search with module=, start=/end=, or raise max_mb."
        } else { "" },
    }))
}

pub fn dump_process_region(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let size = arg_int(args, "size", 0).clamp(1, 64 << 20) as usize;
    let path = arg_str(args, "path")?;

    let buf = match read_proc_mem_blocking(state, addr, size) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            let mut out = vec![0u8; size];
            let mut pos = 0usize;
            let mut chunk = 64 * 1024usize;
            while pos < size {
                let want = chunk.min(size - pos);
                match read_proc_mem_blocking(state, addr + pos as u64, want) {
                    Ok(b) if !b.is_empty() => {
                        let n = b.len().min(want);
                        out[pos..pos + n].copy_from_slice(&b[..n]);
                        pos += n.max(1);
                        chunk = (chunk * 2).min(64 * 1024);
                    }
                    _ => {
                        if chunk > 4096 {
                            chunk /= 2;
                            continue;
                        }
                        pos += 4096;
                    }
                }
            }
            out
        }
    };

    std::fs::write(&path, &buf).map_err(|e| format!("write failed: {}", e))?;
    Ok(json!({
        "address": format!("{:#x}", addr),
        "size_written": buf.len(),
        "path": path,
    }))
}
