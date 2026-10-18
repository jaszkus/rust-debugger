use super::{POp, PVar, StackBase};
use crate::analysis::operands::{canonical_reg, parse_operand, split_operands, Operand};
use crate::disasm::DisasmInstruction;

pub(crate) use crate::analysis::operands::parse_insn_operands;

pub(crate) fn operand_has_segment(op: &str, segment: &str) -> bool {
    if op.len() < segment.len() + 1 {
        return false;
    }
    let b = op.as_bytes();
    let s = segment.as_bytes();
    b.windows(s.len() + 1).any(|w| {
        w[..s.len()]
            .iter()
            .zip(s.iter())
            .all(|(a, c)| a.to_ascii_lowercase() == *c)
            && w[s.len()] == b':'
    })
}

#[allow(dead_code)]
pub(crate) fn has_segment(ops: &str, seg: &[u8; 3]) -> bool {
    match std::str::from_utf8(&seg[..2]) {
        Ok(name) => operand_has_segment(ops, name),
        Err(_) => false,
    }
}

#[inline]
pub(crate) fn next_tmp(ctr: &mut u32) -> u32 {
    let v = *ctr;
    *ctr = ctr.wrapping_add(1);
    v
}

pub(crate) fn subreg_part(r: &str) -> Option<(&'static str, u32, u32)> {
    let (off, w) = match r {
        "al" | "bl" | "cl" | "dl" | "sil" | "dil" | "bpl" | "spl" | "r8b" | "r9b" | "r10b"
        | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => (0, 1),
        "ah" | "bh" | "ch" | "dh" => (8, 1),
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp" | "r8w" | "r9w" | "r10w" | "r11w"
        | "r12w" | "r13w" | "r14w" | "r15w" => (0, 2),
        _ => return None,
    };
    Some((canonical_reg(r), off, w))
}

pub(crate) fn width_mask(w: u32) -> u64 {
    if w >= 8 {
        u64::MAX
    } else {
        (1u64 << (w * 8)) - 1
    }
}

fn extract_field(ops: &mut Vec<POp>, base: PVar, off: u32, w: u32, tmp: &mut u32) -> PVar {
    let masked = PVar::Tmp(next_tmp(tmp));
    ops.push(POp::IntAnd {
        dst: masked.clone(),
        a: base,
        b: PVar::Const(width_mask(w).wrapping_shl(off) as i64),
        size: 8,
    });
    if off == 0 {
        return masked;
    }
    let shifted = PVar::Tmp(next_tmp(tmp));
    ops.push(POp::IntShr {
        dst: shifted.clone(),
        a: masked,
        b: PVar::Const(off as i64),
        size: 8,
    });
    shifted
}

pub(crate) fn field_read(
    op: &Operand,
    insn: &DisasmInstruction,
    ops: &mut Vec<POp>,
    tmp: &mut u32,
) -> PVar {
    if let Operand::Reg(r) = op
        && let Some((base, off, w)) = subreg_part(r) {
            return extract_field(ops, PVar::Reg(base), off, w, tmp);
        }
    to_pvar(op, insn)
}

pub(crate) fn rmw_store(
    ops: &mut Vec<POp>,
    base: PVar,
    off_bits: u32,
    width: u32,
    narrow: PVar,
    tmp: &mut u32,
) {
    let m = width_mask(width);
    let t_n = PVar::Tmp(next_tmp(tmp));
    ops.push(POp::IntAnd {
        dst: t_n.clone(),
        a: narrow,
        b: PVar::Const(m as i64),
        size: 8,
    });
    let t_n = if off_bits == 0 {
        t_n
    } else {
        let t = PVar::Tmp(next_tmp(tmp));
        ops.push(POp::IntLeft {
            dst: t.clone(),
            a: t_n,
            b: PVar::Const(off_bits as i64),
            size: 8,
        });
        t
    };
    let shifted = m.wrapping_shl(off_bits);
    let t_k = PVar::Tmp(next_tmp(tmp));
    ops.push(POp::IntAnd {
        dst: t_k.clone(),
        a: base.clone(),
        b: PVar::Const(!(shifted as i64)),
        size: 8,
    });
    ops.push(POp::IntOr {
        dst: base,
        a: t_k,
        b: t_n,
        size: 8,
    });
}

pub(crate) fn mem_binop<F>(
    op: &Operand,
    b: PVar,
    ops: &mut Vec<POp>,
    insn: &DisasmInstruction,
    tmp: &mut u32,
    ctor: F,
) where
    F: FnOnce(PVar, PVar, PVar, u32) -> POp,
{
    let dst = to_pvar(op, insn);
    match op {
        Operand::Mem { .. } => {
            let size = mem_size(op);
            let t = PVar::Tmp(next_tmp(tmp));
            ops.push(POp::Load {
                dst: t.clone(),
                addr: dst.clone(),
                size,
            });
            ops.push(ctor(t.clone(), t.clone(), b, size));
            ops.push(POp::Store {
                addr: dst,
                src: t,
                size,
            });
        }
        Operand::Reg(r) => match subreg_part(r) {
            Some((base, off, w)) => {
                let base_pv = PVar::Reg(base);
                let current = extract_field(ops, base_pv.clone(), off, w, tmp);
                let t_r = PVar::Tmp(next_tmp(tmp));
                ops.push(ctor(t_r.clone(), current, b, w));
                rmw_store(ops, base_pv, off, w, t_r, tmp);
            }
            None => {
                let size = reg_size(r);
                ops.push(ctor(dst.clone(), dst, b, size));
            }
        },
        _ => {
            let size = op_size(op, op);
            ops.push(ctor(dst.clone(), dst, b, size));
        }
    }
}

pub(crate) fn binop<F>(
    insn: &DisasmInstruction,
    parsed: &[Operand],
    ops: &mut Vec<POp>,
    tmp: &mut u32,
    ctor: F,
) where
    F: FnOnce(PVar, PVar, PVar, u32) -> POp,
{
    if let [dst, src] = parsed {
        let b = field_read(src, insn, ops, tmp);
        mem_binop(dst, b, ops, insn, tmp, ctor);
    }
}

pub(crate) fn mem_size(op: &Operand) -> u32 {
    if let Operand::Mem { size, .. } = op
        && *size > 0 {
            return *size;
        }
    8
}

pub(crate) fn src_width(op: &Operand) -> u32 {
    match op {
        Operand::Reg(r) => reg_size(r),
        Operand::Mem { size, .. } if *size > 0 => *size,
        _ => 8,
    }
}

pub(crate) fn op_size(dst: &Operand, _src: &Operand) -> u32 {
    src_width(dst)
}

pub(crate) fn reg_size_of(op: &Operand) -> Option<u32> {
    match op {
        Operand::Reg(r) => Some(reg_size(r)),
        _ => None,
    }
}

pub fn reg_size(r: &str) -> u32 {
    match r {
        "al" | "bl" | "cl" | "dl" | "sil" | "dil" | "bpl" | "spl" | "ah" | "bh" | "ch" | "dh"
        | "r8b" | "r9b" | "r10b" | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => 1,
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp" | "r8w" | "r9w" | "r10w" | "r11w"
        | "r12w" | "r13w" | "r14w" | "r15w" => 2,
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" | "r8d" | "r9d" | "r10d"
        | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => 4,
        _ if r.bytes().any(|b| b.is_ascii_uppercase()) => reg_size(&r.to_ascii_lowercase()),
        _ => 8,
    }
}

pub(crate) fn to_pvar(op: &Operand, insn: &DisasmInstruction) -> PVar {
    match op {
        Operand::Reg(r) => PVar::Reg(canonical_reg(r)),
        Operand::Imm(v) => PVar::Const(*v),
        Operand::Addr(a) => PVar::Addr(*a),
        Operand::Mem {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            if *base == Some("rip") {
                let next_ip = insn.address.wrapping_add(insn.bytes.len() as u64);
                return PVar::Addr(next_ip.wrapping_add(*disp as u64));
            }
            let base = (*base).map(canonical_reg);
            let index = (*index).map(canonical_reg);
            match (base, index) {
                (Some(b), Some(i)) => PVar::Scaled {
                    base: Box::new(PVar::Reg(b)),
                    index: Box::new(PVar::Reg(i)),
                    scale: *scale,
                    disp: *disp,
                },
                (Some("rbp"), None) => PVar::StackSlot {
                    base: StackBase::Rbp,
                    off: *disp,
                },
                (Some("rsp"), None) => PVar::StackSlot {
                    base: StackBase::Rsp,
                    off: *disp,
                },
                (Some(b), None) => PVar::Mem(Box::new(PVar::Reg(b)), *disp),
                (None, Some(i)) if *scale != 1 => PVar::Scaled {
                    base: Box::new(PVar::Const(0)),
                    index: Box::new(PVar::Reg(i)),
                    scale: *scale,
                    disp: *disp,
                },
                (None, Some(i)) => PVar::Mem(Box::new(PVar::Reg(i)), *disp),
                (None, None) => PVar::Addr(*disp as u64),
            }
        }
        Operand::Unknown(s) => PVar::Reg(canonical_reg(s)),
    }
}

pub(crate) fn is_setcc(m: &str) -> bool {
    matches!(
        m,
        "sete"
            | "setz"
            | "setne"
            | "setnz"
            | "setl"
            | "setnge"
            | "setle"
            | "setng"
            | "setg"
            | "setnle"
            | "setge"
            | "setnl"
            | "setb"
            | "setnae"
            | "setc"
            | "setbe"
            | "setna"
            | "seta"
            | "setnbe"
            | "setae"
            | "setnb"
            | "setnc"
            | "sets"
            | "setns"
            | "seto"
            | "setno"
            | "setp"
            | "setpe"
            | "setnp"
            | "setpo"
    )
}

pub(crate) fn setcc_cond(m: &str) -> &'static str {
    match m {
        "sete" | "setz" => "ZF",
        "setne" | "setnz" => "!ZF",
        "setl" | "setnge" => "(SF != OF)",
        "setle" | "setng" => "(SF != OF) || ZF",
        "setg" | "setnle" => "(SF == OF) && !ZF",
        "setge" | "setnl" => "(SF == OF)",
        "setb" | "setnae" | "setc" => "CF",
        "setbe" | "setna" => "CF || ZF",
        "seta" | "setnbe" => "!CF && !ZF",
        "setae" | "setnb" | "setnc" => "!CF",
        "sets" => "SF",
        "setns" => "!SF",
        "seto" => "OF",
        "setno" => "!OF",
        "setp" | "setpe" => "PF",
        "setnp" | "setpo" => "!PF",
        _ => "cond",
    }
}

#[allow(dead_code)]
pub(crate) fn parse_seg_disp(d: &str) -> u64 {
    let d = d.trim();
    if let Some(h) = d.strip_prefix("0x").or_else(|| d.strip_prefix("0X")) {
        u64::from_str_radix(h.trim(), 16).unwrap_or(0)
    } else if d.starts_with('-') {
        d.parse::<i64>().map(|v| v as u64).unwrap_or(0)
    } else {
        d.parse::<u64>()
            .unwrap_or_else(|_| u64::from_str_radix(d, 16).unwrap_or(0))
    }
}

pub(crate) fn lift_segment(
    insn: &DisasmInstruction,
    segment: &'static str,
    tmp: &mut u32,
) -> Option<POp> {
    let ops_cow = insn.ops();
    let operands = split_operands(&ops_cow);
    let idx = operands
        .iter()
        .position(|s| operand_has_segment(s, segment))?;
    let parsed: Vec<Operand> = operands.iter().map(|s| parse_operand(s)).collect();
    let addr = to_pvar(&parsed[idx], insn);
    let size = op_size(&parsed[idx], &parsed[idx]);
    let m = insn.mnemonic;
    if (m == "mov" || m == "movzx" || m == "movsx") && parsed.len() == 2 {
        return Some(if idx == 1 {
            POp::SegmentOp {
                dst: to_pvar(&parsed[0], insn),
                segment: segment.to_string(),
                addr,
                size,
                is_store: false,
            }
        } else {
            POp::SegmentOp {
                dst: to_pvar(&parsed[1], insn),
                segment: segment.to_string(),
                addr,
                size,
                is_store: true,
            }
        });
    }
    Some(POp::SegmentOp {
        dst: PVar::Tmp(next_tmp(tmp)),
        segment: segment.to_string(),
        addr,
        size,
        is_store: false,
    })
}
