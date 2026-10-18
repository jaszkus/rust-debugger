use super::operands::{reg_code, reg_size_of, Ctx, OpSize, Operand};

pub(crate) fn is_64(ctx: &Ctx) -> bool {
    ctx.is_64()
}

fn rex_bit(code: u8) -> u8 {
    (code >= 8) as u8
}

pub(crate) fn emit_rex(out: &mut Vec<u8>, w: bool, r: u8, x: u8, b: u8, is_64_mode: bool) {
    if is_64_mode && (w || r != 0 || x != 0 || b != 0) {
        out.push(0x40 | ((w as u8) << 3) | ((r & 1) << 2) | ((x & 1) << 1) | (b & 1));
    }
}

pub(crate) fn emit_rex_byte(
    out: &mut Vec<u8>,
    w: bool,
    r: u8,
    x: u8,
    b: u8,
    is_64_mode: bool,
    codes: &[u8],
) {
    let before = out.len();
    emit_rex(out, w, r, x, b, is_64_mode);
    if is_64_mode && out.len() == before && codes.iter().any(|c| (4..8).contains(c)) {
        out.push(0x40);
    }
}

fn reg_of(op: &Operand) -> Result<(u8, OpSize), String> {
    match op {
        Operand::Reg { name, size } => {
            let c = reg_code(name).ok_or_else(|| format!("bad register {}", name))?;
            Ok((c, *size))
        }
        _ => Err("expected a register".into()),
    }
}

pub(crate) fn reg_field_of(op: &Operand) -> Result<(u8, u8), String> {
    let (c, _) = reg_of(op)?;
    Ok((c & 7, rex_bit(c)))
}

pub(crate) fn reg_operand_size(op: &Operand) -> Result<OpSize, String> {
    reg_of(op).map(|(_, s)| s)
}

fn rm_size(op: &Operand, mnemonic: &str) -> Result<OpSize, String> {
    match op {
        Operand::Reg { size, .. } => Ok(*size),
        Operand::Mem { size, has_hint, .. } => {
            if *has_hint {
                Ok(*size)
            } else {
                Err(format!(
                    "size hint required (byte/word/dword/qword ptr) for {} with a memory operand",
                    mnemonic
                ))
            }
        }
        _ => Err(format!("unsupported {} form", mnemonic)),
    }
}

fn check_hint(mem: &Operand, size: OpSize, mnemonic: &str) -> Result<(), String> {
    if let Operand::Mem {
        size: msz,
        has_hint: true,
        ..
    } = mem
        && *msz != size {
            return Err(format!(
                "{} operand size mismatch ({:?} vs {:?})",
                mnemonic, size, msz
            ));
        }
    Ok(())
}

pub(crate) fn sz_flags(sz: OpSize, ctx: &Ctx) -> (bool, bool) {
    match sz {
        OpSize::Byte => (false, false),
        OpSize::Word => (false, true),
        OpSize::Dword => (false, false),
        OpSize::Qword => (is_64(ctx), false),
    }
}

fn validate_mode(ctx: &Ctx, ops: &[Operand]) -> Result<(), String> {
    let is64 = is_64(ctx);
    let bits = if is64 { 64 } else { 32 };
    for op in ops {
        match op {
            Operand::Reg { name, size } if !is64 => {
                let code = reg_code(name).unwrap_or(0);
                if code >= 8 || *size == OpSize::Qword || (*size == OpSize::Byte && code >= 4) {
                    return Err(format!("register {} requires 64-bit mode", name));
                }
            }
            Operand::Mem {
                base,
                index,
                size,
                has_hint,
                ..
            } => {
                if *has_hint && *size == OpSize::Qword && !is64 {
                    return Err("qword operands require 64-bit mode".into());
                }
                for r in base.iter().chain(index.iter()) {
                    if r.as_str() == "rip" {
                        if !is64 {
                            return Err("rip-relative addressing requires 64-bit mode".into());
                        }
                        continue;
                    }
                    let want = if is64 { OpSize::Qword } else { OpSize::Dword };
                    if reg_size_of(r) != want {
                        return Err(format!(
                            "address register {} must be a {}-bit register",
                            r, bits
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn imm_fits(v: i64, size: OpSize) -> bool {
    match size {
        OpSize::Byte => (-128..=255).contains(&v),
        OpSize::Word => (-32768..=65535).contains(&v),
        OpSize::Dword => v >= i32::MIN as i64 && v <= u32::MAX as i64,
        OpSize::Qword => v >= i32::MIN as i64 && v <= i32::MAX as i64,
    }
}

fn check_imm(v: i64, size: OpSize) -> Result<(), String> {
    if imm_fits(v, size) {
        return Ok(());
    }
    let what = match size {
        OpSize::Byte => "a byte",
        OpSize::Word => "a word",
        OpSize::Dword => "a dword",
        OpSize::Qword => "a sign-extended imm32",
    };
    Err(format!("immediate {} does not fit in {}", v, what))
}

fn push_imm(out: &mut Vec<u8>, v: i64, size: OpSize) {
    match size {
        OpSize::Byte => out.push(v as u8),
        OpSize::Word => out.extend_from_slice(&(v as i16).to_le_bytes()),
        _ => out.extend_from_slice(&(v as i32).to_le_bytes()),
    }
}

fn disp32(ctx: &Ctx, disp: i64) -> Result<i32, String> {
    if disp >= i32::MIN as i64 && disp <= i32::MAX as i64 {
        return Ok(disp as i32);
    }
    if !is_64(ctx) && disp >= 0 && disp <= u32::MAX as i64 {
        return Ok(disp as u32 as i32);
    }
    Err(format!("displacement {} does not fit in 32 bits", disp))
}

fn disp_mod(disp: i32, needs_disp: bool) -> (u8, Vec<u8>) {
    if disp == 0 && !needs_disp {
        (0x00, Vec::new())
    } else if (-128..=127).contains(&disp) {
        (0x40, vec![disp as i8 as u8])
    } else {
        (0x80, disp.to_le_bytes().to_vec())
    }
}

fn push_rm_tail(out: &mut Vec<u8>, modrm: u8, sib: Option<u8>, disp: &[u8]) {
    out.push(modrm);
    if let Some(s) = sib {
        out.push(s);
    }
    out.extend_from_slice(disp);
}

type EncodedMem = (u8, Option<u8>, Vec<u8>, u8, u8);

pub(crate) fn encode_mem(ctx: &Ctx, m: &Operand, reg_field: u8) -> Result<EncodedMem, String> {
    let Operand::Mem {
        base,
        index,
        scale,
        disp,
        ..
    } = m
    else {
        return Err("not a memory operand".into());
    };
    let disp32 = disp32(ctx, *disp)?;
    let reg_bits = (reg_field & 7) << 3;

    if base.as_deref() == Some("rip") {
        if index.is_some() {
            return Err("rip-relative addressing cannot have an index register".into());
        }
        return Ok((reg_bits | 0x05, None, disp32.to_le_bytes().to_vec(), 0, 0));
    }

    let idx = match index.as_deref() {
        Some(r) => {
            let c = reg_code(r).ok_or_else(|| format!("bad index register {}", r))?;
            if c == 4 {
                return Err("rsp/esp cannot be used as an index register".into());
            }
            Some(c)
        }
        None => None,
    };
    let scale_bits = match *scale {
        1 => 0u8,
        2 => 1,
        4 => 2,
        8 => 3,
        other => return Err(format!("invalid scale {} (use 1, 2, 4 or 8)", other)),
    };
    let rex_x = idx.map(rex_bit).unwrap_or(0);

    let Some(base_name) = base.as_deref() else {
        return Ok(match idx {
            None => (
                reg_bits | 0x04,
                Some(0x25),
                disp32.to_le_bytes().to_vec(),
                0,
                0,
            ),
            Some(i) => (
                reg_bits | 0x04,
                Some((scale_bits << 6) | ((i & 7) << 3) | 0x05),
                disp32.to_le_bytes().to_vec(),
                0,
                rex_x,
            ),
        });
    };

    let b = reg_code(base_name).ok_or("unsupported base register in memory operand")?;
    let rex_b = rex_bit(b);
    let (md, disp_bytes) = disp_mod(disp32, (b & 7) == 5);

    let (modrm, sib) = if let Some(i) = idx {
        (
            md | reg_bits | 0x04,
            Some((scale_bits << 6) | ((i & 7) << 3) | (b & 7)),
        )
    } else if (b & 7) == 4 {
        (md | reg_bits | 0x04, Some(0x20 | (b & 7)))
    } else {
        (md | reg_bits | (b & 7), None)
    };
    Ok((modrm, sib, disp_bytes, rex_b, rex_x))
}

fn emit_reg_reg(
    ctx: &Ctx,
    opcode: &[u8],
    reg: &Operand,
    rm: &Operand,
    size: OpSize,
    byte_codes: &[u8],
) -> Result<Vec<u8>, String> {
    let (w, o66) = sz_flags(size, ctx);
    let (reg3, rex_r) = reg_field_of(reg)?;
    let (rm3, rex_b) = reg_field_of(rm)?;
    let mut out = Vec::with_capacity(5);
    if o66 {
        out.push(0x66);
    }
    emit_rex_byte(&mut out, w, rex_r, 0, rex_b, is_64(ctx), byte_codes);
    out.extend_from_slice(opcode);
    out.push(0xC0 | (reg3 << 3) | rm3);
    Ok(out)
}

fn emit_reg_mem(
    ctx: &Ctx,
    opcode: &[u8],
    reg: &Operand,
    mem: &Operand,
    size: OpSize,
) -> Result<Vec<u8>, String> {
    let (w, o66) = sz_flags(size, ctx);
    let (reg3, rex_r) = reg_field_of(reg)?;
    let (modrm, sib, disp, rex_b, rex_x) = encode_mem(ctx, mem, reg3)?;
    let mut out = Vec::with_capacity(10);
    if o66 {
        out.push(0x66);
    }
    let arr = [reg3 | (rex_r << 3)];
    let codes: &[u8] = if size == OpSize::Byte { &arr } else { &[] };
    emit_rex_byte(&mut out, w, rex_r, rex_x, rex_b, is_64(ctx), codes);
    out.extend_from_slice(opcode);
    push_rm_tail(&mut out, modrm, sib, &disp);
    Ok(out)
}

fn emit_rm_ext(
    ctx: &Ctx,
    dst: &Operand,
    size: OpSize,
    opcode: &[u8],
    ext: u8,
) -> Result<Vec<u8>, String> {
    let (w, o66) = sz_flags(size, ctx);
    let mut out = Vec::with_capacity(12);
    if o66 {
        out.push(0x66);
    }
    match dst {
        Operand::Reg { .. } => {
            let (c, _) = reg_of(dst)?;
            let arr = [c];
            let codes: &[u8] = if size == OpSize::Byte { &arr } else { &[] };
            emit_rex_byte(&mut out, w, 0, 0, rex_bit(c), is_64(ctx), codes);
            out.extend_from_slice(opcode);
            out.push(0xC0 | (ext << 3) | (c & 7));
        }
        Operand::Mem { .. } => {
            let (modrm, sib, disp, rex_b, rex_x) = encode_mem(ctx, dst, ext)?;
            emit_rex(&mut out, w, 0, rex_x, rex_b, is_64(ctx));
            out.extend_from_slice(opcode);
            push_rm_tail(&mut out, modrm, sib, &disp);
        }
        _ => return Err("expected a register or memory operand".into()),
    }
    Ok(out)
}

fn stack_native(ctx: &Ctx) -> OpSize {
    if is_64(ctx) {
        OpSize::Qword
    } else {
        OpSize::Dword
    }
}

fn stack_reg(ctx: &Ctx, mnemonic: &str, op: &Operand, base_opcode: u8) -> Result<Vec<u8>, String> {
    let Operand::Reg { name, size } = op else {
        return Err("expected a register".into());
    };
    let c = reg_code(name).ok_or_else(|| format!("bad register {}", name))?;
    if *size != stack_native(ctx) && *size != OpSize::Word {
        return Err(format!(
            "{} {} is not encodable in {}-bit mode",
            mnemonic,
            name,
            if is_64(ctx) { 64 } else { 32 }
        ));
    }
    let mut out = Vec::with_capacity(3);
    if *size == OpSize::Word {
        out.push(0x66);
    }
    emit_rex(&mut out, false, 0, 0, rex_bit(c), is_64(ctx));
    out.push(base_opcode + (c & 7));
    Ok(out)
}

fn stack_mem(
    ctx: &Ctx,
    mnemonic: &str,
    op: &Operand,
    opcode: u8,
    ext: u8,
) -> Result<Vec<u8>, String> {
    let Operand::Mem { size, has_hint, .. } = op else {
        return Err("expected a memory operand".into());
    };
    if *has_hint && *size != stack_native(ctx) && *size != OpSize::Word {
        return Err(format!(
            "{} memory operand must be {}-bit or 16-bit",
            mnemonic,
            if is_64(ctx) { 64 } else { 32 }
        ));
    }
    let osize = if *has_hint && *size == OpSize::Word {
        OpSize::Word
    } else {
        OpSize::Dword
    };
    emit_rm_ext(ctx, op, osize, &[opcode], ext)
}

pub(crate) fn push_operand_bytes(ctx: &Ctx, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 1 {
        return Err("push takes one operand".into());
    }
    match &ops[0] {
        Operand::Reg { .. } => stack_reg(ctx, "push", &ops[0], 0x50),
        Operand::Imm(v) => {
            check_imm(*v, stack_native(ctx))?;
            if *v >= -128 && *v <= 127 {
                Ok(vec![0x6A, *v as u8])
            } else {
                let mut out = Vec::with_capacity(5);
                out.push(0x68);
                push_imm(&mut out, *v, OpSize::Dword);
                Ok(out)
            }
        }
        Operand::Mem { .. } => stack_mem(ctx, "push", &ops[0], 0xFF, 6),
    }
}

pub(crate) fn pop_operand_bytes(ctx: &Ctx, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 1 {
        return Err("pop takes one operand".into());
    }
    match &ops[0] {
        Operand::Reg { .. } => stack_reg(ctx, "pop", &ops[0], 0x58),
        Operand::Mem { .. } => stack_mem(ctx, "pop", &ops[0], 0x8F, 0),
        _ => Err("pop supports registers and memory only".into()),
    }
}

fn mov_reg_imm(ctx: &Ctx, dst: &Operand, v: i64) -> Result<Vec<u8>, String> {
    let (c, sz) = reg_of(dst)?;
    let mut out = Vec::with_capacity(10);
    match sz {
        OpSize::Byte => {
            check_imm(v, OpSize::Byte)?;
            emit_rex_byte(&mut out, false, 0, 0, rex_bit(c), is_64(ctx), &[c]);
            out.push(0xB0 + (c & 7));
            out.push(v as u8);
        }
        OpSize::Word => {
            check_imm(v, OpSize::Word)?;
            out.push(0x66);
            emit_rex(&mut out, false, 0, 0, rex_bit(c), is_64(ctx));
            out.push(0xB8 + (c & 7));
            push_imm(&mut out, v, OpSize::Word);
        }
        OpSize::Dword => {
            check_imm(v, OpSize::Dword)?;
            emit_rex(&mut out, false, 0, 0, rex_bit(c), is_64(ctx));
            out.push(0xB8 + (c & 7));
            push_imm(&mut out, v, OpSize::Dword);
        }
        OpSize::Qword => {
            emit_rex(&mut out, true, 0, 0, rex_bit(c), is_64(ctx));
            out.push(0xB8 + (c & 7));
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    Ok(out)
}

pub(crate) fn mov_bytes(ctx: &Ctx, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 2 {
        return Err("mov takes two operands".into());
    }
    let (dst, src) = (&ops[0], &ops[1]);
    match (dst, src) {
        (Operand::Reg { .. }, Operand::Imm(v)) => mov_reg_imm(ctx, dst, *v),
        (Operand::Reg { .. }, Operand::Mem { .. }) => {
            let sz = reg_operand_size(dst)?;
            check_hint(src, sz, "mov")?;
            emit_reg_mem(
                ctx,
                &[if sz == OpSize::Byte { 0x8A } else { 0x8B }],
                dst,
                src,
                sz,
            )
        }
        (Operand::Mem { .. }, Operand::Reg { .. }) => {
            let sz = reg_operand_size(src)?;
            check_hint(dst, sz, "mov")?;
            emit_reg_mem(
                ctx,
                &[if sz == OpSize::Byte { 0x88 } else { 0x89 }],
                src,
                dst,
                sz,
            )
        }
        (Operand::Reg { .. }, Operand::Reg { .. }) => {
            let (dc, dsz) = reg_of(dst)?;
            let (sc, ssz) = reg_of(src)?;
            if dsz != ssz {
                return Err(format!(
                    "mov operand size mismatch ({:?} vs {:?})",
                    dsz, ssz
                ));
            }
            let arr = [dc, sc];
            let codes: &[u8] = if dsz == OpSize::Byte { &arr } else { &[] };
            emit_reg_reg(
                ctx,
                &[if dsz == OpSize::Byte { 0x8A } else { 0x8B }],
                dst,
                src,
                dsz,
                codes,
            )
        }
        (Operand::Mem { size, has_hint, .. }, Operand::Imm(v)) => {
            if !*has_hint {
                return Err(
                    "size hint required (byte/word/dword/qword ptr) for mov [mem], imm".into(),
                );
            }
            check_imm(*v, *size)?;
            let mut out = emit_rm_ext(
                ctx,
                dst,
                *size,
                &[if *size == OpSize::Byte { 0xC6 } else { 0xC7 }],
                0,
            )?;
            push_imm(&mut out, *v, *size);
            Ok(out)
        }
        _ => Err("unsupported mov form".into()),
    }
}

pub(crate) fn alu_opcode_rm_byte(mnemonic: &str) -> Option<u8> {
    match mnemonic {
        "add" => Some(0x00),
        "or" => Some(0x08),
        "and" => Some(0x20),
        "sub" => Some(0x28),
        "xor" => Some(0x30),
        "cmp" => Some(0x38),
        _ => None,
    }
}

pub(crate) fn alu_opcode_rm(mnemonic: &str) -> Option<u8> {
    match mnemonic {
        "add" => Some(0x01),
        "or" => Some(0x09),
        "and" => Some(0x21),
        "sub" => Some(0x29),
        "xor" => Some(0x31),
        "cmp" => Some(0x39),
        _ => None,
    }
}

fn alu_imm(ctx: &Ctx, ext: u8, dst: &Operand, v: i64, mnemonic: &str) -> Result<Vec<u8>, String> {
    let size = rm_size(dst, mnemonic)?;
    check_imm(v, size)?;
    let mut v = v;
    match size {
        OpSize::Word if v > i16::MAX as i64 => v -= 0x1_0000,
        OpSize::Dword if v > i32::MAX as i64 => v -= 0x1_0000_0000,
        _ => {}
    }
    let (opcode, imm_size) = if size == OpSize::Byte {
        (0x80u8, OpSize::Byte)
    } else if (-128..=127).contains(&v) {
        (0x83, OpSize::Byte)
    } else {
        (0x81, size)
    };
    let mut out = emit_rm_ext(ctx, dst, size, &[opcode], ext)?;
    push_imm(&mut out, v, imm_size);
    Ok(out)
}

pub(crate) fn alu_bytes(ctx: &Ctx, mnemonic: &str, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 2 {
        return Err(format!("{} takes two operands", mnemonic));
    }
    let ext: u8 = match mnemonic {
        "add" => 0,
        "or" => 1,
        "and" => 4,
        "sub" => 5,
        "xor" => 6,
        "cmp" => 7,
        _ => return Err(format!("{} not supported", mnemonic)),
    };
    let op_rm = alu_opcode_rm(mnemonic).ok_or("bad alu")?;
    let op_rm8 = alu_opcode_rm_byte(mnemonic).ok_or("bad alu")?;
    let (dst, src) = (&ops[0], &ops[1]);

    match (dst, src) {
        (Operand::Reg { .. }, Operand::Reg { .. }) => {
            let (dc, dsz) = reg_of(dst)?;
            let (sc, ssz) = reg_of(src)?;
            if dsz != ssz {
                return Err(format!(
                    "{} operand size mismatch ({:?} vs {:?})",
                    mnemonic, dsz, ssz
                ));
            }
            let arr = [dc, sc];
            let codes: &[u8] = if dsz == OpSize::Byte { &arr } else { &[] };
            let opcode = if dsz == OpSize::Byte { op_rm8 } else { op_rm };
            emit_reg_reg(ctx, &[opcode], src, dst, dsz, codes)
        }
        (Operand::Reg { .. }, Operand::Mem { .. }) => {
            let sz = reg_operand_size(dst)?;
            check_hint(src, sz, mnemonic)?;
            let opcode = (if sz == OpSize::Byte { op_rm8 } else { op_rm }) + 2;
            emit_reg_mem(ctx, &[opcode], dst, src, sz)
        }
        (Operand::Mem { .. }, Operand::Reg { .. }) => {
            let sz = reg_operand_size(src)?;
            check_hint(dst, sz, mnemonic)?;
            let opcode = if sz == OpSize::Byte { op_rm8 } else { op_rm };
            emit_reg_mem(ctx, &[opcode], src, dst, sz)
        }
        (_, Operand::Imm(v)) => alu_imm(ctx, ext, dst, *v, mnemonic),
        _ => Err(format!("unsupported {} form", mnemonic)),
    }
}

fn test_rm_reg(ctx: &Ctx, mem: &Operand, reg: &Operand) -> Result<Vec<u8>, String> {
    let sz = reg_operand_size(reg)?;
    check_hint(mem, sz, "test")?;
    emit_reg_mem(
        ctx,
        &[if sz == OpSize::Byte { 0x84 } else { 0x85 }],
        reg,
        mem,
        sz,
    )
}

pub(crate) fn test_bytes(ctx: &Ctx, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 2 {
        return Err("test takes two operands".into());
    }
    let (dst, src) = (&ops[0], &ops[1]);
    match (dst, src) {
        (Operand::Reg { .. }, Operand::Reg { .. }) => {
            let (dc, dsz) = reg_of(dst)?;
            let (sc, ssz) = reg_of(src)?;
            if dsz != ssz {
                return Err(format!(
                    "test operand size mismatch ({:?} vs {:?})",
                    dsz, ssz
                ));
            }
            let arr = [dc, sc];
            let codes: &[u8] = if dsz == OpSize::Byte { &arr } else { &[] };
            emit_reg_reg(
                ctx,
                &[if dsz == OpSize::Byte { 0x84 } else { 0x85 }],
                src,
                dst,
                dsz,
                codes,
            )
        }
        (Operand::Mem { .. }, Operand::Reg { .. }) => test_rm_reg(ctx, dst, src),
        (Operand::Reg { .. }, Operand::Mem { .. }) => test_rm_reg(ctx, src, dst),
        (_, Operand::Imm(v)) => {
            let size = rm_size(dst, "test")?;
            check_imm(*v, size)?;
            let mut out = emit_rm_ext(
                ctx,
                dst,
                size,
                &[if size == OpSize::Byte { 0xF6 } else { 0xF7 }],
                0,
            )?;
            push_imm(&mut out, *v, size);
            Ok(out)
        }
        _ => Err("unsupported test form".into()),
    }
}

pub(crate) fn lea_bytes(ctx: &Ctx, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 2 {
        return Err("lea takes two operands".into());
    }
    let (dst, src) = (&ops[0], &ops[1]);
    if !matches!(dst, Operand::Reg { .. }) {
        return Err("lea destination must be a register".into());
    }
    let sz = reg_operand_size(dst)?;
    if sz == OpSize::Byte {
        return Err("lea destination must be a 16/32/64-bit register".into());
    }
    emit_reg_mem(ctx, &[0x8D], dst, src, sz)
}

pub(crate) fn movx_bytes(ctx: &Ctx, mnemonic: &str, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 2 {
        return Err(format!("{} takes two operands", mnemonic));
    }
    let (dst, src) = (&ops[0], &ops[1]);
    let dsz = reg_operand_size(dst)?;

    if mnemonic == "movsxd" {
        if !is_64(ctx) {
            return Err("movsxd requires 64-bit mode".into());
        }
        if dsz != OpSize::Qword {
            return Err("movsxd destination must be a 64-bit register".into());
        }
        let ssz = match src {
            Operand::Reg { size, .. } => *size,
            Operand::Mem { size, has_hint, .. } => {
                if *has_hint {
                    *size
                } else {
                    OpSize::Dword
                }
            }
            _ => return Err("bad movsxd source".into()),
        };
        if ssz != OpSize::Dword {
            return Err("movsxd source must be 32-bit".into());
        }
        return match src {
            Operand::Reg { .. } => emit_reg_reg(ctx, &[0x63], dst, src, OpSize::Qword, &[]),
            _ => emit_reg_mem(ctx, &[0x63], dst, src, OpSize::Qword),
        };
    }

    if dsz == OpSize::Byte {
        return Err(format!(
            "{} destination must be a 16/32/64-bit register",
            mnemonic
        ));
    }
    let signed = mnemonic == "movsx";
    let ssz = match src {
        Operand::Reg { size, .. } => *size,
        Operand::Mem { size, has_hint, .. } => {
            if !*has_hint {
                return Err(format!(
                    "size hint required (byte ptr / word ptr) for {} [mem]",
                    mnemonic
                ));
            }
            *size
        }
        _ => return Err(format!("bad {} source", mnemonic)),
    };
    let opcode = match (signed, ssz) {
        (false, OpSize::Byte) => 0xB6u8,
        (false, OpSize::Word) => 0xB7,
        (true, OpSize::Byte) => 0xBE,
        (true, OpSize::Word) => 0xBF,
        _ => {
            return Err(format!(
                "{} source must be 8 or 16-bit (use movsxd for 32-bit)",
                mnemonic
            ))
        }
    };
    if dsz == OpSize::Word && ssz == OpSize::Word {
        return Err(format!("{} word -> word is not encodable", mnemonic));
    }
    match src {
        Operand::Reg { .. } => {
            let (sc, _) = reg_of(src)?;
            let arr = [sc];
            let codes: &[u8] = if ssz == OpSize::Byte { &arr } else { &[] };
            emit_reg_reg(ctx, &[0x0F, opcode], dst, src, dsz, codes)
        }
        _ => emit_reg_mem(ctx, &[0x0F, opcode], dst, src, dsz),
    }
}

pub(crate) fn cmov_bytes(ctx: &Ctx, mnemonic: &str, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 2 {
        return Err("cmovcc takes two operands".into());
    }
    let cc = cc_code(&mnemonic[4..]).ok_or_else(|| format!("{} not supported", mnemonic))?;
    let (dst, src) = (&ops[0], &ops[1]);
    let dsz = reg_operand_size(dst)?;
    if dsz == OpSize::Byte {
        return Err(format!(
            "{} destination must be a 16/32/64-bit register",
            mnemonic
        ));
    }
    let opcode = [0x0F, 0x40 + cc];
    match src {
        Operand::Reg { .. } => {
            let ssz = reg_operand_size(src)?;
            if ssz != dsz {
                return Err(format!(
                    "{} operand size mismatch ({:?} vs {:?})",
                    mnemonic, dsz, ssz
                ));
            }
            emit_reg_reg(ctx, &opcode, dst, src, dsz, &[])
        }
        Operand::Mem { .. } => {
            check_hint(src, dsz, mnemonic)?;
            emit_reg_mem(ctx, &opcode, dst, src, dsz)
        }
        _ => Err(format!("unsupported {} form", mnemonic)),
    }
}

pub(crate) fn cc_code(cc: &str) -> Option<u8> {
    Some(match cc {
        "o" => 0,
        "no" => 1,
        "b" | "c" | "nae" => 2,
        "ae" | "nb" | "nc" => 3,
        "e" | "z" => 4,
        "ne" | "nz" => 5,
        "be" | "na" => 6,
        "a" | "nbe" => 7,
        "s" => 8,
        "ns" => 9,
        "p" | "pe" => 10,
        "np" | "po" => 11,
        "l" | "nge" => 12,
        "ge" | "nl" => 13,
        "le" | "ng" => 14,
        "g" | "nle" => 15,
        _ => return None,
    })
}

pub(crate) fn rel_branch_bytes(
    ctx: &Ctx,
    opcode_short: u8,
    opcode_near: u16,
    ops: &[Operand],
) -> Result<Vec<u8>, String> {
    if ops.len() != 1 {
        return Err("branch takes one operand".into());
    }
    let target = match &ops[0] {
        Operand::Imm(v) => *v as u64,
        _ => return Err("branch target must be an address".into()),
    };
    let from = ctx.addr;
    let is_call = opcode_short == 0xE8;
    let rel = |len: i128| target as i128 - (from as i128 + len);
    let rel_short = rel(2);
    let mut out = Vec::with_capacity(6);
    if !is_call && (-128..=127).contains(&rel_short) {
        out.push(opcode_short);
        out.push(rel_short as i8 as u8);
        return Ok(out);
    }
    let len: i128 = if opcode_near > 0xFF { 6 } else { 5 };
    let r = rel(len);
    if r < i32::MIN as i128 || r > i32::MAX as i128 {
        return Err(format!(
            "branch target {:#x} is out of rel32 range from {:#x}",
            target, from
        ));
    }
    if opcode_near > 0xFF {
        out.push((opcode_near >> 8) as u8);
        out.push((opcode_near & 0xFF) as u8);
    } else {
        out.push(opcode_near as u8);
    }
    out.extend_from_slice(&(r as i32).to_le_bytes());
    Ok(out)
}

fn indirect_branch(ctx: &Ctx, mnemonic: &str, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 1 {
        return Err(format!("{} takes one operand", mnemonic));
    }
    let ext = if mnemonic == "call" { 2u8 } else { 4u8 };
    let native = stack_native(ctx);
    let size = match &ops[0] {
        Operand::Reg { size, .. } => *size,
        Operand::Mem { size, has_hint, .. } => {
            if *has_hint {
                *size
            } else {
                native
            }
        }
        _ => {
            return Err(format!(
                "{} target must be a register or memory operand",
                mnemonic
            ))
        }
    };
    if size != native {
        return Err(format!(
            "{} target must be a {}-bit operand",
            mnemonic,
            if is_64(ctx) { 64 } else { 32 }
        ));
    }
    emit_rm_ext(ctx, &ops[0], OpSize::Dword, &[0xFF], ext)
}

pub(crate) fn setcc_bytes(ctx: &Ctx, mnemonic: &str, ops: &[Operand]) -> Result<Vec<u8>, String> {
    if ops.len() != 1 {
        return Err("setcc takes one operand".into());
    }
    let cc = cc_code(&mnemonic[3..]).ok_or_else(|| format!("{} not supported", mnemonic))?;
    let size = rm_size(&ops[0], mnemonic)?;
    if size != OpSize::Byte {
        return Err(format!("{} operand must be 8-bit", mnemonic));
    }
    emit_rm_ext(ctx, &ops[0], OpSize::Byte, &[0x0F, 0x90 + cc], 0)
}

fn ret_bytes(ops: &[Operand]) -> Result<Vec<u8>, String> {
    match ops {
        [] => Ok(vec![0xC3]),
        [Operand::Imm(v)] => {
            if *v < 0 || *v > 0xFFFF {
                return Err(format!("ret operand {} out of range 0..65535", v));
            }
            Ok(vec![0xC2, (*v & 0xFF) as u8, ((*v >> 8) & 0xFF) as u8])
        }
        _ => Err("ret takes no operand or one 16-bit immediate".into()),
    }
}

fn simple_opcode(mnemonic: &str) -> Option<&'static [u8]> {
    let bytes: &'static [u8] = match mnemonic {
        "leave" => &[0xC9],
        "int3" | "break" => &[0xCC],
        "hlt" => &[0xF4],
        "syscall" => &[0x0F, 0x05],
        "cpuid" => &[0x0F, 0xA2],
        "ud2" => &[0x0F, 0x0B],
        "pause" => &[0xF3, 0x90],
        "cwde" => &[0x98],
        "cdq" => &[0x99],
        "cdqe" => &[0x48, 0x98],
        "cqo" => &[0x48, 0x99],
        _ => return None,
    };
    Some(bytes)
}

pub(crate) fn unary_group(
    ctx: &Ctx,
    ext: u8,
    byte_opcode: u8,
    full_opcode: u8,
    mnemonic: &str,
    ops: &[Operand],
) -> Result<Vec<u8>, String> {
    if ops.len() != 1 {
        return Err(format!("{} takes one operand", mnemonic));
    }
    let size = rm_size(&ops[0], mnemonic)?;
    let opcode = if size == OpSize::Byte {
        byte_opcode
    } else {
        full_opcode
    };
    emit_rm_ext(ctx, &ops[0], size, &[opcode], ext)
}

pub(crate) fn nop_bytes(ctx: &Ctx, ops: &[Operand]) -> Result<Vec<u8>, String> {
    match ops.first() {
        None => Ok(vec![0x90]),
        Some(Operand::Reg { name, .. }) => match name.as_str() {
            "ax" | "eax" | "rax" => Ok(vec![0x90]),
            _ => Err(
                "nop register form only supports ax/eax/rax (use memory form for multi-byte NOPs)"
                    .into(),
            ),
        },
        Some(op @ Operand::Mem { size, has_hint, .. }) => {
            if !*has_hint {
                return Err("size hint required (byte/word/dword/qword ptr) for nop [mem]".into());
            }
            let mut out = Vec::new();
            if matches!(size, OpSize::Word) {
                out.push(0x66);
            }
            let (mut modrm, sib, mut disp, rex_b, rex_x) = encode_mem(ctx, op, 0)?;
            if disp.is_empty()
                && let Operand::Mem {
                    base,
                    index,
                    disp: d,
                    ..
                } = op
                    && index.is_none()
                        && *d == 0
                        && base
                            .as_deref()
                            .and_then(reg_code)
                            .map(|c| c & 7 == 4)
                            .unwrap_or(false)
                    {
                        modrm = (modrm & 0x3F) | 0x40;
                        disp = vec![0x00];
                    }
            emit_rex(&mut out, false, 0, rex_x, rex_b, is_64(ctx));
            out.push(0x0F);
            out.push(0x1F);
            push_rm_tail(&mut out, modrm, sib, &disp);
            Ok(out)
        }
        Some(_) => Err("nop takes no immediate operand".into()),
    }
}

pub(crate) fn encode(ctx: &Ctx, mnemonic: &str, ops: &[Operand]) -> Result<Vec<u8>, String> {
    validate_mode(ctx, ops)?;

    if let Some(bytes) = simple_opcode(mnemonic) {
        if !ops.is_empty() {
            return Err(format!("{} takes no operands", mnemonic));
        }
        if matches!(mnemonic, "cqo" | "cdqe") && !is_64(ctx) {
            return Err(format!("{} requires 64-bit mode", mnemonic));
        }
        return Ok(bytes.to_vec());
    }

    match mnemonic {
        "nop" => nop_bytes(ctx, ops),
        "ret" | "retn" => ret_bytes(ops),
        "retn16" | "ret16" => Ok(vec![0xC2, 0x00, 0x00]),
        "int" => {
            if ops.len() != 1 {
                return Err("int takes one operand".into());
            }
            if let Operand::Imm(v) = ops[0] {
                if !(0..=255).contains(&v) {
                    return Err(format!("int vector {} out of range 0..255", v));
                }
                if v == 3 {
                    return Ok(vec![0xCC]);
                }
                Ok(vec![0xCD, v as u8])
            } else {
                Err("int operand must be immediate".into())
            }
        }
        "push" => push_operand_bytes(ctx, ops),
        "pop" => pop_operand_bytes(ctx, ops),
        "mov" | "movabs" => mov_bytes(ctx, ops),
        "movzx" | "movsx" | "movsxd" => movx_bytes(ctx, mnemonic, ops),
        "lea" => lea_bytes(ctx, ops),
        "add" | "or" | "and" | "sub" | "xor" | "cmp" => alu_bytes(ctx, mnemonic, ops),
        "test" => test_bytes(ctx, ops),
        "inc" => unary_group(ctx, 0, 0xFE, 0xFF, mnemonic, ops),
        "dec" => unary_group(ctx, 1, 0xFE, 0xFF, mnemonic, ops),
        "not" => unary_group(ctx, 2, 0xF6, 0xF7, mnemonic, ops),
        "neg" => unary_group(ctx, 3, 0xF6, 0xF7, mnemonic, ops),
        "call" | "jmp" => {
            if matches!(
                ops.first(),
                Some(Operand::Reg { .. }) | Some(Operand::Mem { .. })
            ) {
                indirect_branch(ctx, mnemonic, ops)
            } else if mnemonic == "call" {
                rel_branch_bytes(ctx, 0xE8, 0x00E8, ops)
            } else {
                rel_branch_bytes(ctx, 0xEB, 0x00E9, ops)
            }
        }
        m if m.starts_with('j') => {
            let cc = cc_code(&m[1..]).ok_or_else(|| format!("{} not supported", m))?;
            rel_branch_bytes(ctx, 0x70 + cc, 0x0F80 + cc as u16, ops)
        }
        m if m.starts_with("set") => setcc_bytes(ctx, m, ops),
        m if m.starts_with("cmov") => cmov_bytes(ctx, m, ops),
        _ => Err(format!(
            "mnemonic '{}' not supported by the built-in assembler",
            mnemonic
        )),
    }
}
