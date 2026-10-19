pub mod operands;

pub use operands::reg_size;
use operands::*;

use crate::analysis::operands::{canonical_reg, Operand};
use crate::disasm::DisasmInstruction;

pub const CALL_CLOBBERED: &[&str] = &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

#[derive(Debug, Clone)]
pub enum POp {
    Copy {
        dst: PVar,
        src: PVar,
        size: u32,
    },
    IntAdd {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntSub {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntMul {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntDiv {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntSDiv {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntAnd {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntOr {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntXor {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntLeft {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntShr {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    IntSar {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    Zext {
        dst: PVar,
        src: PVar,
        from_size: u32,
        to_size: u32,
    },
    Sext {
        dst: PVar,
        src: PVar,
        from_size: u32,
        to_size: u32,
    },
    Load {
        dst: PVar,
        addr: PVar,
        size: u32,
    },
    Store {
        addr: PVar,
        src: PVar,
        size: u32,
    },
    Branch {
        target: u64,
    },
    CBranch {
        target: u64,
        cond: String,
    },
    BranchInd {
        target: PVar,
    },
    Call {
        target: u64,
    },
    CallInd {
        target: PVar,
    },
    Return,
    ReturnPop {
        pop_imm: u16,
    },
    Nop,
    Cmp {
        a: PVar,
        b: PVar,
        size: u32,
    },
    Test {
        a: PVar,
        b: PVar,
        size: u32,
    },
    Push {
        src: PVar,
        size: u32,
    },
    Pop {
        dst: PVar,
        size: u32,
    },
    LeaAddr {
        dst: PVar,
        addr: u64,
    },
    AddrOf {
        dst: PVar,
        base: Option<Box<PVar>>,
        index: Option<Box<PVar>>,
        scale: u32,
        disp: i64,
    },
    SetCC {
        dst: PVar,
        cond: String,
        size: u32,
    },
    
    CondCopy {
        dst: PVar,
        src: PVar,
        cond: String,
        size: u32,
    },
    
    BitTest {
        a: PVar,
        b: PVar,
        size: u32,
    },
    
    BitModify {
        dst: PVar,
        bit: PVar,
        kind: String,
        size: u32,
    },
    
    Cmpxchg {
        addr: PVar,
        src: PVar,
        size: u32,
    },
    
    
    Opaque(String),
    FloatBinop {
        kind: String,
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
    },
    Cvt {
        kind: String,
        dst: PVar,
        src: PVar,
    },
    FloatCmp {
        a: PVar,
        b: PVar,
        size: u32,
    },
    SegmentOp {
        dst: PVar,
        segment: String,
        addr: PVar,
        size: u32,
        is_store: bool,
    },
    CallOther {
        name: String,
    },
    Rotate {
        dst: PVar,
        a: PVar,
        b: PVar,
        size: u32,
        left: bool,
    },
    Bswap {
        dst: PVar,
        src: PVar,
        size: u32,
    },
    Unimplemented(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PVar {
    Reg(&'static str),
    Const(i64),
    StackSlot {
        base: StackBase,
        off: i64,
    },
    Mem(Box<PVar>, i64),
    Scaled {
        base: Box<PVar>,
        index: Box<PVar>,
        scale: u32,
        disp: i64,
    },
    Addr(u64),
    Tmp(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackBase {
    Rbp,
    Rsp,
}

#[derive(Debug, Clone)]
pub struct PInstr {
    pub address: u64,
    pub mnemonic: String,
    pub ops: Vec<POp>,
}

pub fn lift_instruction(insn: &DisasmInstruction) -> PInstr {
    let mut ctr = 0u32;
    lift_instruction_inner(insn, &mut ctr)
}

#[inline]
fn finish(insn: &DisasmInstruction, ops: Vec<POp>) -> PInstr {
    PInstr {
        address: insn.address,
        mnemonic: insn.mnemonic.to_string(),
        ops,
    }
}

fn read_operand(
    op: &Operand,
    insn: &DisasmInstruction,
    ops: &mut Vec<POp>,
    ctr: &mut u32,
) -> PVar {
    if matches!(op, Operand::Mem { .. }) {
        let t = PVar::Tmp(next_tmp(ctr));
        ops.push(POp::Load {
            dst: t.clone(),
            addr: to_pvar(op, insn),
            size: src_width(op),
        });
        t
    } else {
        field_read(op, insn, ops, ctr)
    }
}

fn write_operand(
    op: &Operand,
    value: PVar,
    insn: &DisasmInstruction,
    ops: &mut Vec<POp>,
    ctr: &mut u32,
) {
    match op {
        Operand::Reg(r) => {
            if let Some((base, off, w)) = subreg_part(r) {
                rmw_store(ops, PVar::Reg(base), off, w, value, ctr);
            } else {
                ops.push(POp::Copy {
                    dst: to_pvar(op, insn),
                    src: value,
                    size: op_size(op, op),
                });
            }
        }
        Operand::Mem { .. } => ops.push(POp::Store {
            addr: to_pvar(op, insn),
            src: value,
            size: src_width(op),
        }),
        _ => {}
    }
}

fn lift_rax_op(
    insn: &DisasmInstruction,
    m: &str,
    src: &Operand,
    ops: &mut Vec<POp>,
    ctr: &mut u32,
) {
    let dst = PVar::Reg("rax");
    let a = dst.clone();
    let b = field_read(src, insn, ops, ctr);
    let size = src_width(src);
    ops.push(match m {
        "div" => POp::IntDiv { dst, a, b, size },
        "idiv" => POp::IntSDiv { dst, a, b, size },
        _ => POp::IntMul { dst, a, b, size },
    });
}

fn lift_instruction_inner(insn: &DisasmInstruction, ctr: &mut u32) -> PInstr {
    let ops_text = insn.ops();
    let segment = if operand_has_segment(&ops_text, "fs") {
        Some("fs")
    } else if operand_has_segment(&ops_text, "gs") {
        Some("gs")
    } else {
        None
    };
    if let Some(segment) = segment
        && let Some(seg_op) = lift_segment(insn, segment, ctr) {
            return finish(insn, vec![seg_op]);
        }
    let parsed: Vec<Operand> = parse_insn_operands(insn);
    let mut ops = Vec::new();

    let m = insn.mnemonic;
    match m {
        "mov" => {
            if let [dst, src] = parsed.as_slice() {
                if let Operand::Reg(r) = dst
                    && let Some((base, off, w)) = subreg_part(r) {
                        let value = if matches!(src, Operand::Mem { .. }) {
                            let t = PVar::Tmp(next_tmp(ctr));
                            ops.push(POp::Load {
                                dst: t.clone(),
                                addr: to_pvar(src, insn),
                                size: w,
                            });
                            t
                        } else {
                            field_read(src, insn, &mut ops, ctr)
                        };
                        rmw_store(&mut ops, PVar::Reg(base), off, w, value, ctr);
                        return finish(insn, ops);
                    }
                if matches!(src, Operand::Mem { .. }) {
                    ops.push(POp::Load {
                        dst: to_pvar(dst, insn),
                        addr: to_pvar(src, insn),
                        size: op_size(dst, src),
                    });
                } else if matches!(dst, Operand::Mem { .. }) {
                    ops.push(POp::Store {
                        addr: to_pvar(dst, insn),
                        src: to_pvar(src, insn),
                        size: op_size(dst, src),
                    });
                } else {
                    ops.push(POp::Copy {
                        dst: to_pvar(dst, insn),
                        src: to_pvar(src, insn),
                        size: op_size(dst, src),
                    });
                }
            }
        }
        "movzx" | "movsx" | "movsxd" => {
            if let [d, s] = parsed.as_slice() {
                let dst = to_pvar(d, insn);
                let to_size = op_size(d, d);
                let from_size = src_width(s);
                let src = if matches!(s, Operand::Mem { .. }) {
                    let t = PVar::Tmp(next_tmp(ctr));
                    ops.push(POp::Load {
                        dst: t.clone(),
                        addr: to_pvar(s, insn),
                        size: from_size,
                    });
                    t
                } else {
                    to_pvar(s, insn)
                };
                ops.push(if m == "movzx" {
                    POp::Zext {
                        dst,
                        src,
                        from_size,
                        to_size,
                    }
                } else {
                    POp::Sext {
                        dst,
                        src,
                        from_size,
                        to_size,
                    }
                });
            }
        }
        "lea" => {
            if let [d, s] = parsed.as_slice() {
                let narrow = match d {
                    Operand::Reg(r) => subreg_part(r),
                    _ => None,
                };
                let (dst, narrow_back) = match narrow {
                    Some((base, off, w)) => {
                        (PVar::Tmp(next_tmp(ctr)), Some((PVar::Reg(base), off, w)))
                    }
                    None => (to_pvar(d, insn), None),
                };
                match s {
                    Operand::Addr(a) => ops.push(POp::LeaAddr {
                        dst: dst.clone(),
                        addr: *a,
                    }),
                    Operand::Mem {
                        base,
                        index,
                        scale,
                        disp,
                        ..
                    } => {
                        if *base == Some("rip") && index.is_none() {
                            let next_ip = insn.address.wrapping_add(insn.bytes.len() as u64);
                            ops.push(POp::LeaAddr {
                                dst: dst.clone(),
                                addr: next_ip.wrapping_add(*disp as u64),
                            });
                        } else {
                            ops.push(POp::AddrOf {
                                dst: dst.clone(),
                                base: (*base).map(|b| Box::new(PVar::Reg(canonical_reg(b)))),
                                index: (*index).map(|i| Box::new(PVar::Reg(canonical_reg(i)))),
                                scale: *scale,
                                disp: *disp,
                            });
                        }
                    }
                    other => ops.push(POp::Copy {
                        dst: dst.clone(),
                        src: to_pvar(other, insn),
                        size: 8,
                    }),
                }
                if let Some((base, off, w)) = narrow_back {
                    rmw_store(&mut ops, base, off, w, dst, ctr);
                }
            }
        }
        "add" | "adc" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
            POp::IntAdd { dst, a, b, size }
        }),
        "sub" | "sbb" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
            POp::IntSub { dst, a, b, size }
        }),
        "and" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
            POp::IntAnd { dst, a, b, size }
        }),
        "or" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| POp::IntOr {
            dst,
            a,
            b,
            size,
        }),
        "xor" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
            POp::IntXor { dst, a, b, size }
        }),
        "shl" | "sal" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
            POp::IntLeft { dst, a, b, size }
        }),
        "shr" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
            POp::IntShr { dst, a, b, size }
        }),
        "sar" => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
            POp::IntSar { dst, a, b, size }
        }),
        "imul" => match parsed.as_slice() {
            [_, _] => binop(insn, &parsed, &mut ops, ctr, |dst, a, b, size| {
                POp::IntMul { dst, a, b, size }
            }),
            [d, s1, s2] => {
                let narrow = match d {
                    Operand::Reg(r) => subreg_part(r),
                    _ => None,
                };
                let a = field_read(s1, insn, &mut ops, ctr);
                let b = field_read(s2, insn, &mut ops, ctr);
                match narrow {
                    Some((base, off, w)) => {
                        let t_r = PVar::Tmp(next_tmp(ctr));
                        ops.push(POp::IntMul {
                            dst: t_r.clone(),
                            a,
                            b,
                            size: w,
                        });
                        rmw_store(&mut ops, PVar::Reg(base), off, w, t_r, ctr);
                    }
                    None => {
                        let size = reg_size_of(d).unwrap_or(8);
                        ops.push(POp::IntMul {
                            dst: to_pvar(d, insn),
                            a,
                            b,
                            size,
                        });
                    }
                }
            }
            [s] => lift_rax_op(insn, m, s, &mut ops, ctr),
            _ => {}
        },
        "mul" | "div" | "idiv" => {
            if let [s] = parsed.as_slice() {
                lift_rax_op(insn, m, s, &mut ops, ctr);
            }
        }
        "not" => {
            if let [op] = parsed.as_slice() {
                mem_binop(
                    op,
                    PVar::Const(-1),
                    &mut ops,
                    insn,
                    ctr,
                    |dst, a, b, size| POp::IntXor { dst, a, b, size },
                );
            }
        }
        "neg" => {
            if let [op] = parsed.as_slice() {
                mem_binop(
                    op,
                    PVar::Const(0),
                    &mut ops,
                    insn,
                    ctr,
                    |dst, a, _zero, size| POp::IntSub {
                        dst,
                        a: PVar::Const(0),
                        b: a,
                        size,
                    },
                );
            }
        }
        "inc" => {
            if let [op] = parsed.as_slice() {
                mem_binop(
                    op,
                    PVar::Const(1),
                    &mut ops,
                    insn,
                    ctr,
                    |dst, a, b, size| POp::IntAdd { dst, a, b, size },
                );
            }
        }
        "dec" => {
            if let [op] = parsed.as_slice() {
                mem_binop(
                    op,
                    PVar::Const(1),
                    &mut ops,
                    insn,
                    ctr,
                    |dst, a, b, size| POp::IntSub { dst, a, b, size },
                );
            }
        }
        "cdqe" => ops.push(POp::Sext {
            dst: PVar::Reg("rax"),
            src: PVar::Reg("rax"),
            from_size: 4,
            to_size: 8,
        }),
        "cqo" => ops.push(POp::IntSar {
            dst: PVar::Reg("rdx"),
            a: PVar::Reg("rax"),
            b: PVar::Const(63),
            size: 8,
        }),
        "cdq" => ops.push(POp::IntSar {
            dst: PVar::Reg("rdx"),
            a: PVar::Reg("rax"),
            b: PVar::Const(31),
            size: 4,
        }),
        "xchg" => {
            if let [pa, pb] = parsed.as_slice() {
                let a_val = read_operand(pa, insn, &mut ops, ctr);
                let b_val = read_operand(pb, insn, &mut ops, ctr);
                write_operand(pa, b_val, insn, &mut ops, ctr);
                write_operand(pb, a_val, insn, &mut ops, ctr);
            }
        }
        "push" => {
            if let [op] = parsed.as_slice() {
                ops.push(POp::Push {
                    src: to_pvar(op, insn),
                    size: src_width(op),
                });
            }
        }
        "pop" => {
            if let [op] = parsed.as_slice() {
                ops.push(POp::Pop {
                    dst: to_pvar(op, insn),
                    size: op_size(op, op),
                });
            }
        }
        "cmp" | "test" => {
            if let [pa, pb] = parsed.as_slice() {
                let a = to_pvar(pa, insn);
                let b = to_pvar(pb, insn);
                let size = op_size(pa, pb);
                ops.push(if m == "cmp" {
                    POp::Cmp { a, b, size }
                } else {
                    POp::Test { a, b, size }
                });
            }
        }
        "call" => {
            if let Some(op) = parsed.first() {
                ops.push(match op {
                    Operand::Addr(a) => POp::Call { target: *a },
                    Operand::Imm(v) => POp::Call { target: *v as u64 },
                    _ => POp::CallInd {
                        target: to_pvar(op, insn),
                    },
                });
            }
        }
        "jmp" => {
            if let Some(op) = parsed.first() {
                ops.push(match op {
                    Operand::Addr(a) => POp::Branch { target: *a },
                    Operand::Imm(v) => POp::Branch { target: *v as u64 },
                    _ => POp::BranchInd {
                        target: to_pvar(op, insn),
                    },
                });
            }
        }
        "ret" | "retn" => {
            let pop: u16 = match parsed.first() {
                Some(Operand::Imm(v)) => (*v as u64 & 0xFFFF) as u16,
                Some(Operand::Addr(a)) => (*a & 0xFFFF) as u16,
                _ => 0,
            };
            ops.push(if pop == 0 {
                POp::Return
            } else {
                POp::ReturnPop { pop_imm: pop }
            });
        }
        "nop" => ops.push(POp::Nop),
        "bt" | "bts" | "btr" | "btc" => {
            if let [d, bit] = parsed.as_slice() {
                let a = to_pvar(d, insn);
                let b = field_read(bit, insn, &mut ops, ctr);
                let size = op_size(d, bit);
                ops.push(POp::BitTest {
                    a: a.clone(),
                    b: b.clone(),
                    size,
                });
                if m != "bt" {
                    let kind = match m {
                        "bts" => "set",
                        "btr" => "reset",
                        _ => "complement",
                    };
                    ops.push(POp::BitModify {
                        dst: a,
                        bit: b,
                        kind: kind.into(),
                        size,
                    });
                }
            }
        }
        "cmpxchg" | "lock cmpxchg" => {
            if let [d, s] = parsed.as_slice()
                && matches!(d, Operand::Mem { .. })
            {
                let addr = to_pvar(d, insn);
                let size = op_size(d, s);
                
                
                ops.push(POp::Cmp {
                    a: PVar::Reg("rax"),
                    b: addr.clone(),
                    size,
                });
                let src = field_read(s, insn, &mut ops, ctr);
                ops.push(POp::Cmpxchg { addr, src, size });
            }
        }
        _ if m.starts_with("cmov") => {
            if let [d, s] = parsed.as_slice() {
                let src = field_read(s, insn, &mut ops, ctr);
                ops.push(POp::CondCopy {
                    dst: to_pvar(d, insn),
                    src,
                    cond: m[4..].to_string(),
                    size: op_size(d, s),
                });
            }
        }
        "ud2" => ops.push(POp::Opaque("ud2".into())),
        "cpuid" => ops.push(POp::Opaque("cpuid".into())),
        "xgetbv" => ops.push(POp::Opaque("xgetbv".into())),
        "pause" => ops.push(POp::Nop),
        "lfence" | "mfence" | "sfence" => ops.push(POp::Nop),
        _ if m.starts_with("prefetch") => ops.push(POp::Nop),
        _ if m.starts_with("lock ") => {
            ops.push(POp::Opaque(format!("{} {}", m, ops_text)));
        }
        _ if is_setcc(m) => {
            if let [op] = parsed.as_slice() {
                ops.push(POp::SetCC {
                    dst: to_pvar(op, insn),
                    cond: setcc_cond(m).to_string(),
                    size: op_size(op, op),
                });
            }
        }
        _ if m.starts_with('j') && m != "jmp" => {
            let target = match parsed.first() {
                Some(Operand::Addr(a)) => Some(*a),
                Some(Operand::Imm(v)) => Some(*v as u64),
                _ => None,
            };
            if let Some(target) = target {
                ops.push(POp::CBranch {
                    target,
                    cond: m.to_string(),
                });
            }
        }
        "movss" | "movsd" | "movaps" | "movapd" | "movups" | "movupd" | "movdqa" | "movdqu"
        | "movlps" | "movhps" | "movlpd" | "movhpd" | "movq" | "movd" => {
            if let [dst, src] = parsed.as_slice() {
                let size = match m {
                    "movss" | "movd" => 4,
                    "movsd" | "movq" | "movlps" | "movhps" | "movlpd" | "movhpd" => 8,
                    _ => 16,
                };
                if matches!(src, Operand::Mem { .. }) {
                    ops.push(POp::Load {
                        dst: to_pvar(dst, insn),
                        addr: to_pvar(src, insn),
                        size,
                    });
                } else if matches!(dst, Operand::Mem { .. }) {
                    ops.push(POp::Store {
                        addr: to_pvar(dst, insn),
                        src: to_pvar(src, insn),
                        size,
                    });
                } else {
                    ops.push(POp::Copy {
                        dst: to_pvar(dst, insn),
                        src: to_pvar(src, insn),
                        size,
                    });
                }
            }
        }
        "addss" | "addsd" | "addps" | "addpd" | "subss" | "subsd" | "subps" | "subpd" | "mulss"
        | "mulsd" | "mulps" | "mulpd" | "divss" | "divsd" | "divps" | "divpd" | "xorps"
        | "xorpd" | "pxor" | "andps" | "andpd" | "orps" | "orpd" => {
            if let [pd, ps] = parsed.as_slice() {
                let (kind, size) = match m {
                    "xorps" | "xorpd" | "pxor" => ("xor".to_string(), 16),
                    "andps" | "andpd" => ("and".to_string(), 16),
                    "orps" | "orpd" => ("or".to_string(), 16),
                    _ => (
                        m[..3].to_string(),
                        if m.ends_with("sd") {
                            8
                        } else if m.ends_with("ss") {
                            4
                        } else {
                            16
                        },
                    ),
                };
                let dst = to_pvar(pd, insn);
                let a = dst.clone();
                let b = to_pvar(ps, insn);
                ops.push(match kind.as_str() {
                    "xor" => POp::IntXor { dst, a, b, size },
                    "and" => POp::IntAnd { dst, a, b, size },
                    "or" => POp::IntOr { dst, a, b, size },
                    _ => POp::FloatBinop {
                        kind,
                        dst,
                        a,
                        b,
                        size,
                    },
                });
            }
        }
        "cvttss2si" | "cvttsd2si" | "cvtsi2ss" | "cvtsi2sd" | "cvtss2sd" | "cvtsd2ss"
        | "cvtdq2pd" | "cvtps2pd" | "cvtpd2ps" => {
            if let [dst, src] = parsed.as_slice() {
                let kind = match m {
                    "cvttss2si" | "cvttsd2si" => "f2i",
                    "cvtsi2ss" | "cvtsi2sd" => "i2f",
                    _ => "f2f",
                };
                ops.push(POp::Cvt {
                    kind: kind.to_string(),
                    dst: to_pvar(dst, insn),
                    src: to_pvar(src, insn),
                });
            }
        }
        "lahf" | "sahf" => ops.push(POp::Nop),
        "bswap" => {
            if let [op] = parsed.as_slice() {
                let dst = to_pvar(op, insn);
                let src = dst.clone();
                ops.push(POp::Bswap {
                    dst,
                    src,
                    size: op_size(op, op),
                });
            }
        }
        "rol" | "rcl" | "ror" | "rcr" => {
            if let [d, s] = parsed.as_slice() {
                let dst = to_pvar(d, insn);
                let a = dst.clone();
                ops.push(POp::Rotate {
                    dst,
                    a,
                    b: to_pvar(s, insn),
                    size: op_size(d, d),
                    left: matches!(m, "rol" | "rcl"),
                });
            }
        }
        "syscall" | "sysenter" => ops.push(POp::CallOther {
            name: m.to_string(),
        }),
        "int" | "int3" => {
            let imm = ops_text.trim();
            ops.push(if m == "int3" || imm == "3" {
                POp::Nop
            } else {
                POp::CallOther {
                    name: format!("int {}", imm),
                }
            });
        }
        "comiss" | "comisd" | "ucomiss" | "ucomisd" | "vcomiss" | "vcomisd" | "vucomiss"
        | "vucomisd" => {
            if let [pa, pb] = parsed.as_slice() {
                ops.push(POp::FloatCmp {
                    a: to_pvar(pa, insn),
                    b: to_pvar(pb, insn),
                    size: if m.ends_with("sd") { 8 } else { 4 },
                });
            }
        }
        _ => ops.push(POp::Unimplemented(format!("{} {}", m, ops_text))),
    }

    finish(insn, ops)
}

#[allow(dead_code)]
pub fn lift_all(insns: &[DisasmInstruction]) -> Vec<PInstr> {
    let mut ctr = 0u32;
    insns
        .iter()
        .map(|i| lift_instruction_inner(i, &mut ctr))
        .collect()
}

pub fn lift_func(insns: &[DisasmInstruction], entry: u64, end: u64) -> Vec<PInstr> {
    let s = insns.partition_point(|i| i.address < entry);
    let e = insns.partition_point(|i| i.address < end);
    if s > e {
        return Vec::new();
    }
    let mut ctr = 0u32;
    insns[s..e]
        .iter()
        .map(|i| lift_instruction_inner(i, &mut ctr))
        .collect()
}
