use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::arg_int;
use crate::gui::AppState;

pub(crate) fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut lanes = [[0u64; 256]; 4];
    let (chunks, remainder) = data.as_chunks::<4>();
    for c in chunks {
        lanes[0][c[0] as usize] += 1;
        lanes[1][c[1] as usize] += 1;
        lanes[2][c[2] as usize] += 1;
        lanes[3][c[3] as usize] += 1;
    }
    for &b in remainder {
        lanes[0][b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for (i, &lane0) in lanes[0].iter().enumerate() {
        let f = lane0 + lanes[1][i] + lanes[2][i] + lanes[3][i];
        if f > 0 {
            let p = f as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

pub(crate) fn entropy_verdict(h: f64) -> &'static str {
    if h > 7.5 {
        "packed_or_encrypted"
    } else if h > 6.8 {
        "compressed_or_high_random"
    } else if h > 5.0 {
        "code_or_dense_data"
    } else if h > 1.5 {
        "structured_data"
    } else {
        "padding_or_zeros"
    }
}

pub(crate) fn section_entropy_value(
    bin: &crate::parser::ParsedBinary,
    sec: &crate::parser::Section,
) -> f64 {
    if !sec.initialized {
        return 0.0;
    }
    let so = sec.offset as usize;
    let se = so.saturating_add(sec.size as usize).min(bin.data.len());
    if se > so {
        entropy(&bin.data[so..se])
    } else {
        0.0
    }
}

pub fn section_entropy(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let bin = {
        let s = super::lock::lock_state(state)?;
        s.binary.clone().ok_or("No binary loaded")?
    };
    let bin = &bin;
    let mut rows: Vec<Value> = Vec::with_capacity(bin.sections.len());
    for sec in &bin.sections {
        let h = section_entropy_value(bin, sec);
        let verdict = entropy_verdict(h);
        rows.push(json!({
            "name": sec.name,
            "vaddr": format!("{:#x}", sec.vaddr),
            "size": sec.size,
            "executable": sec.is_executable,
            "entropy": (h * 100.0).round() / 100.0,
            "verdict": verdict,
        }));
    }
    Ok(json!({
        "section_count": rows.len(),
        "sections": rows,
    }))
}

pub fn find_pe_headers(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 32).clamp(1, 1024) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let data = &bin.data;

    let mut hits: Vec<Value> = Vec::new();
    let mut i = 0usize;
    while i + 0x40 <= data.len() {
        if data[i] == 0x4D && data[i + 1] == 0x5A {
            let e_lfanew = u32::from_le_bytes([
                data[i + 0x3C],
                data[i + 0x3D],
                data[i + 0x3E],
                data[i + 0x3F],
            ]) as usize;
            let pe_off = i.checked_add(e_lfanew);
            if let Some(po) = pe_off
                && po + 24 <= data.len()
                    && data[po] == b'P'
                    && data[po + 1] == b'E'
                    && data[po + 2] == 0
                    && data[po + 3] == 0
                {
                    let machine = u16::from_le_bytes([data[po + 4], data[po + 5]]);
                    let n_sections = u16::from_le_bytes([data[po + 6], data[po + 7]]);
                    let opt_size = u16::from_le_bytes([data[po + 20], data[po + 21]]) as usize;
                    let opt_off = po + 24;
                    let (magic, entry_rva, image_base) =
                        if opt_off + 32 <= data.len() && opt_size >= 28 {
                            let mg = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
                            let er = u32::from_le_bytes([
                                data[opt_off + 16],
                                data[opt_off + 17],
                                data[opt_off + 18],
                                data[opt_off + 19],
                            ]);
                            let ib = if mg == 0x20b && opt_off + 32 <= data.len() {
                                u64::from_le_bytes([
                                    data[opt_off + 24],
                                    data[opt_off + 25],
                                    data[opt_off + 26],
                                    data[opt_off + 27],
                                    data[opt_off + 28],
                                    data[opt_off + 29],
                                    data[opt_off + 30],
                                    data[opt_off + 31],
                                ])
                            } else if mg == 0x10b && opt_off + 32 <= data.len() {
                                u32::from_le_bytes([
                                    data[opt_off + 28],
                                    data[opt_off + 29],
                                    data[opt_off + 30],
                                    data[opt_off + 31],
                                ]) as u64
                            } else {
                                0
                            };
                            (mg, er, ib)
                        } else {
                            (0, 0, 0)
                        };
                    let machine_str = match machine {
                        0x14C => "x86",
                        0x8664 => "x86_64",
                        0xAA64 => "aarch64",
                        0x1C0 => "arm",
                        _ => "?",
                    };
                    let pe32_str = match magic {
                        0x10b => "PE32",
                        0x20b => "PE32+",
                        _ => "?",
                    };
                    let vaddr = bin.sections.iter().find_map(|sec| {
                        let so = sec.offset as usize;
                        let se = so + sec.size as usize;
                        if i >= so && i < se {
                            Some(sec.vaddr + (i as u64 - sec.offset))
                        } else {
                            None
                        }
                    });
                    let mut row = serde_json::Map::new();
                    row.insert("file_offset".into(), Value::from(i));
                    if let Some(v) = vaddr {
                        row.insert("address".into(), Value::String(format!("{:#x}", v)));
                    }
                    row.insert("machine".into(), Value::String(machine_str.to_string()));
                    row.insert(
                        "optional_header".into(),
                        Value::String(pe32_str.to_string()),
                    );
                    row.insert("section_count".into(), Value::from(n_sections));
                    row.insert(
                        "entry_rva".into(),
                        Value::String(format!("{:#x}", entry_rva)),
                    );
                    if image_base != 0 {
                        row.insert(
                            "image_base".into(),
                            Value::String(format!("{:#x}", image_base)),
                        );
                    }
                    hits.push(Value::Object(row));
                    if hits.len() >= limit {
                        break;
                    }
                    i += 64;
                    continue;
                }
        }
        i += 1;
    }
    Ok(json!({
        "matches": hits.len(),
        "items": hits,
    }))
}

pub fn find_xor_loops(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let limit = arg_int(args, "limit", 50).clamp(1, 1000) as usize;
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let dis = s.disasm.as_ref().ok_or("No disassembly loaded")?;
    let insns = &dis.instructions;

    let mut hits: Vec<Value> = Vec::new();

    for i in 0..insns.len() {
        let a = &insns[i];
        if a.mnem() != "xor" {
            continue;
        }
        let a_ops = a.ops();
        let dst = a_ops.split(',').next().unwrap_or("").trim();
        let touches_mem = dst.starts_with('[')
            || dst.starts_with("byte")
            || dst.starts_with("word")
            || dst.starts_with("dword")
            || dst.starts_with("qword");
        if !touches_mem {
            continue;
        }
        let end = (i + 12).min(insns.len());
        let mut saw_inc = false;
        let mut backward_branch = None;
        for j in (i + 1)..end {
            let b = &insns[j];
            if b.mnem() == "inc" || (b.mnem() == "add" && b.ops().contains(", 1")) {
                saw_inc = true;
            }
            if matches!(
                b.mnemonic,
                "jne" | "jnz" | "jl" | "jb" | "jbe" | "jge" | "ja" | "jmp"
            )
                && let Some(target_str) = b.ops().split_whitespace().next()
                    && let Some(t) = target_str
                        .strip_prefix("0x")
                        .and_then(|h| u64::from_str_radix(h, 16).ok())
                        && t <= a.address && t >= a.address.saturating_sub(0x40) {
                            backward_branch = Some((b.address, t));
                            break;
                        }
        }
        if saw_inc
            && let Some((br_at, br_to)) = backward_branch {
                hits.push(json!({
                    "address": format!("{:#x}", a.address),
                    "asm": format!("{} {}", a.mnemonic, a.operands),
                    "loop_branch": format!("{:#x}", br_at),
                    "loop_back_to": format!("{:#x}", br_to),
                }));
                if hits.len() >= limit {
                    break;
                }
            }
    }

    Ok(json!({
        "matches": hits.len(),
        "items": hits,
    }))
}

pub fn find_aes_rcon_table(_args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let data = &bin.data;
    let needle: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    let mut hits: Vec<Value> = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= data.len() {
        if data[i..i + needle.len()] == needle {
            let vaddr = bin.sections.iter().find_map(|sec| {
                let so = sec.offset as usize;
                let se = so + sec.size as usize;
                if i >= so && i < se {
                    Some(sec.vaddr + (i as u64 - sec.offset))
                } else {
                    None
                }
            });
            let mut row = serde_json::Map::new();
            row.insert("file_offset".into(), Value::from(i));
            if let Some(v) = vaddr {
                row.insert("address".into(), Value::String(format!("{:#x}", v)));
            }
            hits.push(Value::Object(row));
            i += needle.len();
        } else {
            i += 1;
        }
    }
    Ok(json!({
        "matches": hits.len(),
        "items": hits,
    }))
}
