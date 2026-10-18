use crate::analysis::decompiler::pcode::{PInstr, POp, PVar};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct StackVar {
    pub offset: i64,
    pub size: u32,
    pub access_count: u32,
    pub kind: VarKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum VarKind {
    Local,
    Parameter,
    SavedReg,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub func_entry: u64,
    pub variables: Vec<StackVar>,
    pub frame_size: i64,
}

pub fn analyze_stack(
    pinstrs: &[PInstr],
    func_entry: u64,
    func_end: u64,
    has_frame: bool,
    frame_size: i64,
) -> StackFrame {
    let mut accesses: BTreeMap<i64, (u32, u32)> = BTreeMap::new();

    for pi in pinstrs {
        if pi.address < func_entry || pi.address >= func_end {
            continue;
        }

        for op in &pi.ops {
            collect_stack_accesses(op, &mut accesses);
        }
    }

    let mut prologue_saved: usize = 0;
    for pi in pinstrs
        .iter()
        .filter(|p| p.address >= func_entry && p.address < func_end)
        .take(8)
    {
        for op in &pi.ops {
            if let POp::Push { src, .. } = op {
                if let PVar::Reg(r) = src
                    && is_callee_saved_reg(r) {
                        prologue_saved += 1;
                    }
            } else {
                break;
            }
        }
    }
    let _ = prologue_saved;

    let mut variables = Vec::new();
    for (offset, (count, size)) in &accesses {
        let kind = if has_frame {
            if *offset < 0 {
                VarKind::Local
            } else if *offset == 0 {
                VarKind::SavedReg
            } else if *offset == 8 {
                VarKind::Unknown
            } else {
                VarKind::Parameter
            }
        } else {
            if *offset >= 0 && *offset < frame_size.saturating_sub(8) {
                VarKind::Local
            } else if *offset >= 0 && *offset < frame_size {
                VarKind::SavedReg
            } else if *offset >= frame_size {
                VarKind::Parameter
            } else {
                VarKind::Unknown
            }
        };

        let name = match kind {
            VarKind::Local => format!("local_{:X}", offset.unsigned_abs()),
            VarKind::Parameter => format!("arg_{:X}", offset),
            VarKind::SavedReg => "saved_reg".to_string(),
            VarKind::Unknown => format!("var_{}", offset),
        };

        variables.push(StackVar {
            offset: *offset,
            size: *size,
            access_count: *count,
            kind,
            name,
        });
    }

    StackFrame {
        func_entry,
        variables,
        frame_size,
    }
}

fn collect_stack_accesses(op: &POp, accesses: &mut BTreeMap<i64, (u32, u32)>) {
    let visit = |v: &PVar, sz: u32, acc: &mut BTreeMap<i64, (u32, u32)>| {
        if let PVar::StackSlot { off, .. } = v {
            let entry = acc.entry(*off).or_insert((0, sz.max(1)));
            entry.0 += 1;
            if sz > entry.1 {
                entry.1 = sz;
            }
        }
    };

    match op {
        POp::Copy { dst, src, size } => {
            visit(dst, *size, accesses);
            visit(src, *size, accesses);
        }
        POp::Load { dst, addr, size } => {
            visit(dst, *size, accesses);
            visit(addr, *size, accesses);
        }
        POp::Store { addr, src, size } => {
            visit(addr, *size, accesses);
            visit(src, *size, accesses);
        }
        POp::Zext {
            dst,
            src,
            from_size,
            ..
        } => {
            visit(dst, *from_size, accesses);
            visit(src, *from_size, accesses);
        }
        POp::Sext {
            dst,
            src,
            from_size,
            ..
        } => {
            visit(dst, *from_size, accesses);
            visit(src, *from_size, accesses);
        }
        POp::IntAdd { dst, a, b, size }
        | POp::IntSub { dst, a, b, size }
        | POp::IntMul { dst, a, b, size }
        | POp::IntDiv { dst, a, b, size }
        | POp::IntSDiv { dst, a, b, size }
        | POp::IntAnd { dst, a, b, size }
        | POp::IntOr { dst, a, b, size }
        | POp::IntXor { dst, a, b, size }
        | POp::IntLeft { dst, a, b, size }
        | POp::IntShr { dst, a, b, size }
        | POp::IntSar { dst, a, b, size } => {
            visit(dst, *size, accesses);
            visit(a, *size, accesses);
            visit(b, *size, accesses);
        }
        POp::Cmp { a, b, size } | POp::Test { a, b, size } => {
            visit(a, *size, accesses);
            visit(b, *size, accesses);
        }
        POp::Push { src, size } => visit(src, *size, accesses),
        POp::Pop { dst, size } => visit(dst, *size, accesses),
        POp::AddrOf {
            dst, base, index, ..
        } => {
            visit(dst, 8, accesses);
            if let Some(b) = base {
                visit(b, 8, accesses);
            }
            if let Some(i) = index {
                visit(i, 8, accesses);
            }
        }
        POp::SetCC { dst, size, .. } => visit(dst, *size, accesses),
        POp::Branch { .. }
        | POp::CBranch { .. }
        | POp::Call { .. }
        | POp::Return
        | POp::ReturnPop { .. }
        | POp::Nop
        | POp::LeaAddr { .. }
        | POp::CallOther { .. }
        | POp::Unimplemented(_) => {}
        POp::BranchInd { target } | POp::CallInd { target } => {
            visit(target, 8, accesses);
        }
        POp::FloatBinop {
            dst, a, b, size, ..
        } => {
            visit(dst, *size, accesses);
            visit(a, *size, accesses);
            visit(b, *size, accesses);
        }
        POp::Cvt { dst, src, .. } => {
            visit(dst, 8, accesses);
            visit(src, 8, accesses);
        }
        POp::FloatCmp { a, b, size } => {
            visit(a, *size, accesses);
            visit(b, *size, accesses);
        }
        POp::SegmentOp {
            dst, addr, size, ..
        } => {
            visit(dst, *size, accesses);
            visit(addr, *size, accesses);
        }
        POp::Rotate {
            dst, a, b, size, ..
        } => {
            visit(dst, *size, accesses);
            visit(a, *size, accesses);
            visit(b, *size, accesses);
        }
        POp::Bswap { dst, src, size } => {
            visit(dst, *size, accesses);
            visit(src, *size, accesses);
        }
    }
}

fn is_callee_saved_reg(r: &str) -> bool {
    matches!(
        r.to_lowercase().as_str(),
        "rbx"
            | "rbp"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
            | "rdi"
            | "rsi"
            | "ebx"
            | "ebp"
            | "esi"
            | "edi"
    )
}
