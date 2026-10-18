use crate::disasm::{DisasmInstruction, DisasmResult};
use crate::parser::ParsedBinary;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CallKind {
    DirectCall,
    DirectJump,
    ThunkedCall,
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub address: u64,
    pub kind: CallKind,
    pub bytes: Vec<u8>,
    pub asm: String,
    pub thunk_address: Option<u64>,
}

pub fn resolve_iat_slot(bin: &ParsedBinary, query: &str) -> Option<u64> {
    let (lib_filter, name) = if let Some(bang) = query.find('!') {
        (
            Some(query[..bang].to_string()),
            query[bang + 1..].to_string(),
        )
    } else {
        (None, query.to_string())
    };
    let lib_filter_lower = lib_filter.as_ref().map(|s| s.to_lowercase());
    for imp in &bin.imports {
        if let Some(lib) = &lib_filter_lower {
            if imp.library.to_lowercase() != *lib {
                continue;
            }
        }
        if imp.name == name {
            return Some(imp.offset);
        }
    }
    None
}

fn scan_direct(disasm: &DisasmResult, iat_slot: u64) -> (Vec<u64>, Vec<CallSite>, Vec<CallSite>) {
    let mut thunks: Vec<u64> = Vec::new();
    let mut calls: Vec<CallSite> = Vec::new();
    let mut jumps: Vec<CallSite> = Vec::new();

    for insn in disasm.instructions.iter() {
        if insn.bytes.len() < 6 {
            continue;
        }
        let b = &insn.bytes;
        if b[0] != 0xFF {
            continue;
        }
        let modrm = b[1];
        let target_abs: Option<u64> = if modrm == 0x15 || modrm == 0x25 {
            let disp = u32::from_le_bytes([b[2], b[3], b[4], b[5]]);
            if disasm.arch == "x86_64" {
                let next_ip = insn.address.wrapping_add(insn.bytes.len() as u64);
                Some(next_ip.wrapping_add(disp as i32 as i64 as u64))
            } else {
                Some(disp as u64)
            }
        } else {
            None
        };

        if let Some(t) = target_abs {
            if t == iat_slot {
                let asm = format!("{} {}", insn.mnemonic, insn.operands);
                let site = CallSite {
                    address: insn.address,
                    kind: if modrm == 0x15 {
                        CallKind::DirectCall
                    } else {
                        CallKind::DirectJump
                    },
                    bytes: insn.bytes.to_vec(),
                    asm,
                    thunk_address: None,
                };
                if modrm == 0x25 {
                    thunks.push(insn.address);
                    jumps.push(site);
                } else {
                    calls.push(site);
                }
            }
        }
    }

    (thunks, calls, jumps)
}

fn scan_thunked_calls(disasm: &DisasmResult, thunk_addrs: &[u64]) -> Vec<CallSite> {
    let mut out: Vec<CallSite> = Vec::new();
    if thunk_addrs.is_empty() {
        return out;
    }
    let thunk_set: rustc_hash::FxHashSet<u64> = thunk_addrs.iter().copied().collect();
    for insn in disasm.instructions.iter() {
        if insn.bytes.len() != 5 || insn.bytes[0] != 0xE8 {
            continue;
        }
        let rel = i32::from_le_bytes([insn.bytes[1], insn.bytes[2], insn.bytes[3], insn.bytes[4]]);
        let next_ip = insn.address.wrapping_add(5);
        let target = next_ip.wrapping_add(rel as i64 as u64);
        if thunk_set.contains(&target) {
            out.push(CallSite {
                address: insn.address,
                kind: CallKind::ThunkedCall,
                bytes: insn.bytes.to_vec(),
                asm: format!("{} {}", insn.mnemonic, insn.operands),
                thunk_address: Some(target),
            });
        }
    }
    out
}

pub fn find_callsites(
    bin: &ParsedBinary,
    disasm: &DisasmResult,
    import_name: &str,
) -> Vec<CallSite> {
    let Some(iat_slot) = resolve_iat_slot(bin, import_name) else {
        return Vec::new();
    };

    let (thunks_d, direct_calls_d, direct_jumps_d) = scan_direct(disasm, iat_slot);
    let (thunks_r, mut direct_calls, mut direct_jumps) = scan_direct_raw(bin, iat_slot);

    direct_calls.extend(direct_calls_d);
    direct_jumps.extend(direct_jumps_d);

    let mut thunk_set: rustc_hash::FxHashSet<u64> = thunks_d.iter().copied().collect();
    let mut thunk_addrs: Vec<u64> = thunks_d;
    for t in thunks_r {
        if thunk_set.insert(t) {
            thunk_addrs.push(t);
        }
    }

    let mut indirect = scan_thunked_calls(disasm, &thunk_addrs);
    indirect.extend(scan_thunked_calls_raw(bin, &thunk_addrs));

    let mut out = Vec::new();
    out.append(&mut direct_calls);
    out.append(&mut direct_jumps);
    out.append(&mut indirect);
    out.sort_by_key(|s| (s.address, s.kind.clone()));
    out.dedup_by(|a, b| a.address == b.address && a.kind == b.kind);
    out
}

fn scan_direct_raw(bin: &ParsedBinary, iat_slot: u64) -> (Vec<u64>, Vec<CallSite>, Vec<CallSite>) {
    let mut thunks: Vec<u64> = Vec::new();
    let mut calls: Vec<CallSite> = Vec::new();
    let mut jumps: Vec<CallSite> = Vec::new();
    let is_x64 = bin.arch == "x86_64";

    for sec in &bin.sections {
        if !sec.is_executable {
            continue;
        }
        let start = sec.offset as usize;
        let end = start.saturating_add(sec.size as usize).min(bin.data.len());
        if end <= start + 6 {
            continue;
        }
        let bytes = &bin.data[start..end];
        let mut i = 0usize;
        while i + 6 <= bytes.len() {
            if bytes[i] == 0xFF && (bytes[i + 1] == 0x15 || bytes[i + 1] == 0x25) {
                let disp =
                    u32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
                let va = sec.vaddr + i as u64;
                let target = if is_x64 {
                    let next_ip = va.wrapping_add(6);
                    next_ip.wrapping_add(disp as i32 as i64 as u64)
                } else {
                    disp as u64
                };
                if target == iat_slot {
                    let modrm = bytes[i + 1];
                    let mnem = if modrm == 0x15 { "call" } else { "jmp" };
                    let site = CallSite {
                        address: va,
                        kind: if modrm == 0x15 {
                            CallKind::DirectCall
                        } else {
                            CallKind::DirectJump
                        },
                        bytes: bytes[i..i + 6].to_vec(),
                        asm: format!("{} dword ptr [{:#x}]", mnem, iat_slot),
                        thunk_address: None,
                    };
                    if modrm == 0x25 {
                        thunks.push(va);
                        jumps.push(site);
                    } else {
                        calls.push(site);
                    }
                }
            }
            i += 1;
        }
    }

    (thunks, calls, jumps)
}

fn scan_thunked_calls_raw(bin: &ParsedBinary, thunk_addrs: &[u64]) -> Vec<CallSite> {
    let mut out: Vec<CallSite> = Vec::new();
    if thunk_addrs.is_empty() {
        return out;
    }
    let thunk_set: rustc_hash::FxHashSet<u64> = thunk_addrs.iter().copied().collect();
    for sec in &bin.sections {
        if !sec.is_executable {
            continue;
        }
        let start = sec.offset as usize;
        let end = start.saturating_add(sec.size as usize).min(bin.data.len());
        if end <= start + 5 {
            continue;
        }
        let bytes = &bin.data[start..end];
        let mut i = 0usize;
        while i + 5 <= bytes.len() {
            if bytes[i] == 0xE8 {
                let rel =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                let va = sec.vaddr + i as u64;
                let target = va.wrapping_add(5).wrapping_add(rel as i64 as u64);
                if thunk_set.contains(&target) {
                    out.push(CallSite {
                        address: va,
                        kind: CallKind::ThunkedCall,
                        bytes: bytes[i..i + 5].to_vec(),
                        asm: format!("call {:#x}", target),
                        thunk_address: Some(target),
                    });
                }
            }
            i += 1;
        }
    }
    out
}

#[allow(dead_code)]
pub fn find_callsites_at_slot(disasm: &DisasmResult, iat_slot: u64) -> Vec<CallSite> {
    let (thunks, mut direct_calls, mut direct_jumps) = scan_direct(disasm, iat_slot);
    let mut indirect = scan_thunked_calls(disasm, &thunks);
    let mut out = Vec::new();
    out.append(&mut direct_calls);
    out.append(&mut direct_jumps);
    out.append(&mut indirect);
    out.sort_by_key(|s| s.address);
    out
}

#[allow(dead_code)]
pub fn instruction_at(disasm: &DisasmResult, address: u64) -> Option<&DisasmInstruction> {
    disasm.instructions.iter().find(|i| i.address == address)
}
