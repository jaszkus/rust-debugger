use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use super::common::*;
use crate::gui::AppState;

pub fn patch_nop_instruction(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let count = arg_int(args, "count", 1).clamp(1, 4096) as usize;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;

    let total: usize = {
        let d = s.disasm.as_ref().ok_or("No disassembly available")?;
        let start = d
            .instructions
            .iter()
            .position(|i| i.address == addr)
            .ok_or_else(|| format!("No instruction starts at {:#x}", addr))?;
        if start + count > d.instructions.len() {
            return Err(format!(
                "Only {} instructions available from {:#x}",
                d.instructions.len() - start,
                addr
            ));
        }
        let mut total = 0usize;
        let mut expect = addr;
        for i in &d.instructions[start..start + count] {
            if i.address != expect {
                return Err(format!(
                    "Instructions from {:#x} are not contiguous (gap at {:#x}); NOP them individually",
                    addr, i.address
                ));
            }
            expect = expect.wrapping_add(i.bytes.len() as u64);
            total += i.bytes.len();
        }
        total
    };

    let nops = vec![0x90u8; total];
    let (id, original, off) = apply_patch_internal(
        &mut s,
        addr,
        &nops,
        &format!("patch_nop_instruction(x{})", count),
        invalidate,
    )?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "instructions_nopped": count,
        "size": total,
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn patch_call_to_nop(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let size = {
        let d = s.disasm.as_ref().ok_or("No disassembly available")?;
        let insn = d
            .instructions
            .iter()
            .find(|i| i.address == addr)
            .ok_or_else(|| format!("No instruction starts at {:#x}", addr))?;
        if insn.mnemonic.to_lowercase() != "call" {
            return Err(format!(
                "Instruction at {:#x} is '{}', not a call",
                addr, insn.mnemonic
            ));
        }
        insn.bytes.len()
    };
    let nops = vec![0x90u8; size];
    let (id, original, off) =
        apply_patch_internal(&mut s, addr, &nops, "patch_call_to_nop", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": size,
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn patch_jcc_to_nop(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let size = {
        let d = s.disasm.as_ref().ok_or("No disassembly available")?;
        let insn = d
            .instructions
            .iter()
            .find(|i| i.address == addr)
            .ok_or_else(|| format!("No instruction starts at {:#x}", addr))?;
        let m = insn.mnemonic.to_lowercase();
        if !is_jcc_mnemonic(&m) {
            return Err(format!(
                "Instruction at {:#x} is '{}', not a conditional jump",
                addr, insn.mnemonic
            ));
        }
        insn.bytes.len()
    };
    let nops = vec![0x90u8; size];
    let (id, original, off) =
        apply_patch_internal(&mut s, addr, &nops, "patch_jcc_to_nop", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "size": size,
        "original_bytes": hex(&original),
        "ok": true
    }))
}

fn is_jcc_mnemonic(m: &str) -> bool {
    matches!(
        m,
        "je" | "jz"
            | "jne"
            | "jnz"
            | "jb"
            | "jc"
            | "jnae"
            | "jnb"
            | "jnc"
            | "jae"
            | "jbe"
            | "jna"
            | "ja"
            | "jnbe"
            | "jl"
            | "jnge"
            | "jge"
            | "jnl"
            | "jle"
            | "jng"
            | "jg"
            | "jnle"
            | "js"
            | "jns"
            | "jo"
            | "jno"
            | "jp"
            | "jpe"
            | "jnp"
            | "jpo"
            | "jcxz"
            | "jecxz"
            | "jrcxz"
    )
}

pub fn patch_jcc_invert(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let first = read_byte(&s, addr)?;
    let (new_bytes, label): (Vec<u8>, String) = if (0x70..=0x7F).contains(&first) {
        let new = first ^ 0x01;
        (vec![new], format!("Jcc short {:02x}->{:02x}", first, new))
    } else if first == 0x0F {
        let second = read_byte(&s, addr + 1)?;
        if (0x80..=0x8F).contains(&second) {
            let new_second = second ^ 0x01;
            (
                vec![0x0F, new_second],
                format!("Jcc near 0F {:02x}->{:02x}", second, new_second),
            )
        } else {
            return Err(format!(
                "Byte at {:#x} is 0F {:02x}, not a near Jcc",
                addr, second
            ));
        }
    } else {
        return Err(format!(
            "First byte at {:#x} is 0x{:02x}, not a recognized Jcc opcode",
            addr, first
        ));
    };

    let (id, original, off) =
        apply_patch_internal(&mut s, addr, &new_bytes, "patch_jcc_invert", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "transform": label,
        "original_bytes": hex(&original),
        "new_bytes": hex(&new_bytes),
        "ok": true
    }))
}

pub fn patch_jcc_to_jmp(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let first = read_byte(&s, addr)?;

    let (new_bytes, label): (Vec<u8>, String) = if (0x70..=0x7F).contains(&first) {
        let disp = read_byte(&s, addr + 1)?;
        (vec![0xEB, disp], format!("Jcc short {:02x} -> EB", first))
    } else if first == 0x0F {
        let second = read_byte(&s, addr + 1)?;
        if (0x80..=0x8F).contains(&second) {
            let rel32 = read_bytes_at(&s, addr + 2, 4)?;
            let mut buf = vec![0x90, 0xE9];
            buf.extend_from_slice(&rel32);
            (
                buf,
                format!("Jcc near 0F {:02x} -> 90 E9 (jmp rel32)", second),
            )
        } else {
            return Err(format!(
                "Byte at {:#x} is 0F {:02x}, not a near Jcc",
                addr, second
            ));
        }
    } else {
        return Err(format!(
            "First byte at {:#x} is 0x{:02x}, not a recognized Jcc opcode",
            addr, first
        ));
    };

    let (id, original, off) =
        apply_patch_internal(&mut s, addr, &new_bytes, "patch_jcc_to_jmp", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "transform": label,
        "original_bytes": hex(&original),
        "new_bytes": hex(&new_bytes),
        "ok": true
    }))
}

pub fn patch_function_to_ret(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) =
        apply_patch_internal(&mut s, addr, &[0xC3], "patch_function_to_ret", invalidate)?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "original_bytes": hex(&original),
        "new_bytes": "c3",
        "note": "Wrote 0xC3 (ret near) at function entry",
        "ok": true
    }))
}

pub fn patch_return_value(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let value_raw = args
        .get("value")
        .ok_or("Missing required argument: value")?;
    let value: i64 = if let Some(s) = value_raw.as_str() {
        let t = s.trim();
        if let Some(stripped) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            i64::from_str_radix(stripped, 16).map_err(|e| e.to_string())?
        } else {
            t.parse::<i64>().map_err(|e| e.to_string())?
        }
    } else if let Some(n) = value_raw.as_i64() {
        n
    } else {
        return Err("'value' must be number or string".into());
    };

    let payload: Vec<u8> = if value == 0 {
        vec![0x31, 0xC0, 0xC3]
    } else if value >= i32::MIN as i64 && value <= u32::MAX as i64 {
        let imm = (value as u32).to_le_bytes();
        let mut v = vec![0xB8];
        v.extend_from_slice(&imm);
        v.push(0xC3);
        v
    } else {
        return Err(format!(
            "Value {} doesn't fit in 32 bits; for 64-bit returns use mov rax,imm64 manually",
            value
        ));
    };

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) = apply_patch_internal(
        &mut s,
        addr,
        &payload,
        &format!("patch_return_value({})", value),
        invalidate,
    )?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "value": value,
        "size": payload.len(),
        "new_bytes": hex(&payload),
        "original_bytes": hex(&original),
        "ok": true
    }))
}

pub fn patch_jmp_to_address(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    let addr = arg_addr(args, "address")?;
    let target = arg_addr(args, "target")?;
    let invalidate = arg_bool(args, "invalidate_analysis", true);

    let next = addr.wrapping_add(5);
    let rel: i64 = (target as i64) - (next as i64);
    if !(i32::MIN as i64..=i32::MAX as i64).contains(&rel) {
        return Err(format!(
            "Target {:#x} is too far from {:#x} for a 32-bit relative jump (rel = {})",
            target, addr, rel
        ));
    }
    let rel_bytes = (rel as i32 as u32).to_le_bytes();
    let mut payload = vec![0xE9];
    payload.extend_from_slice(&rel_bytes);

    let mut s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let (id, original, off) = apply_patch_internal(
        &mut s,
        addr,
        &payload,
        &format!("patch_jmp_to_address({:#x})", target),
        invalidate,
    )?;
    Ok(json!({
        "patch_id": id,
        "offset": off,
        "address": format!("{:#x}", addr),
        "target": format!("{:#x}", target),
        "rel32": rel,
        "size": payload.len(),
        "new_bytes": hex(&payload),
        "original_bytes": hex(&original),
        "ok": true
    }))
}
