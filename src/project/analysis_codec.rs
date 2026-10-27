use super::binary_codec::{
    R, T_EDGE_F, T_EDGE_FT, T_EDGE_JMP, T_EDGE_T, T_FUNC_ADDRESS, T_FUNC_AFTER_RET, T_FUNC_CALL,
    T_FUNC_DATA_PTR, T_FUNC_ENTRY, T_FUNC_PROLOGUE, T_FUNC_SYMBOL, T_FUNC_UNWIND, T_FUNC_USER, T_LINE_ASSIGN,
    T_LINE_BRANCH, T_LINE_CALL, T_LINE_CLOSE, T_LINE_COMMENT, T_LINE_DECL, T_LINE_LABEL,
    T_LINE_OPEN, T_LINE_RET, T_LINE_SIG, T_PRIM_BOOL, T_PRIM_CHAR, T_PRIM_DOUBLE, T_PRIM_FLOAT,
    T_PRIM_INT, T_PRIM_LLONG, T_PRIM_LONG, T_PRIM_SHORT, T_PRIM_UCHAR, T_PRIM_UINT, T_PRIM_ULLONG,
    T_PRIM_ULONG, T_PRIM_USHORT, T_PRIM_VOID, T_RT_ARRAY, T_RT_ENUM, T_RT_POINTER, T_RT_PRIM,
    T_RT_STRUCT, T_STUB_IMPORT, T_STUB_TAIL, T_VAR_LOCAL, T_VAR_PARAM, T_VAR_SAVED, T_VAR_UNKNOWN,
    T_XREF_ADDR, T_XREF_CALL, T_XREF_CALLIND, T_XREF_JMPIND, T_XREF_JUMP, T_XREF_READ,
    T_XREF_STRING, T_XREF_TAIL, T_XREF_THUNK, T_XREF_WRITE, W,
};
use crate::analysis::cfg::{BasicBlock, Edge};
use crate::analysis::decompiler::PseudoLine;
use crate::analysis::stack::StackVar;
use crate::analysis::type_reconstruction::{PrimitiveType, ReconstructedType, TypeField, TypeKind};
use crate::analysis::xref::XRef;
use crate::analysis::*;
use crate::disasm::DisasmInstruction;

pub(crate) fn write_insn(w: &mut W, i: &DisasmInstruction) {
    w.u64(i.address);
    w.bytes(&i.bytes);
    w.str(i.mnemonic);
    w.str(&i.ops());
}

pub(crate) fn read_insn(r: &mut R) -> Result<DisasmInstruction, String> {
    let address = r.u64()?;
    let bytes = r.bytes()?;
    let mnemonic = r.str()?;
    let operands = r.str()?;
    let operands = crate::disasm::operand_enum::OperandList::pack_text(&operands)
        .unwrap_or_else(|| crate::disasm::operand_enum::intern_text(&operands).into());
    Ok(DisasmInstruction {
        address,
        bytes: crate::disasm::InsnBytes::from_slice(&bytes),
        mnemonic: crate::disasm::intern_mnemonic(&mnemonic),
        operands,
    })
}

pub(crate) fn write_analysis(w: &mut W, a: &AnalysisResult) {
    w.u32(a.functions.len() as u32);
    for f in &a.functions {
        w.u64(f.entry);
        w.u64(f.end);
        w.str(&f.name);
        w.u8(f.has_frame as u8);
        w.i64(f.stack_size);
        w.u8(match f.source {
            FuncSource::EntryPoint => T_FUNC_ENTRY,
            FuncSource::SymbolTable => T_FUNC_SYMBOL,
            FuncSource::CallTarget => T_FUNC_CALL,
            FuncSource::Prologue => T_FUNC_PROLOGUE,
            FuncSource::AfterReturn => T_FUNC_AFTER_RET,
            FuncSource::UnwindInfo => T_FUNC_UNWIND,
            FuncSource::UserDefined => T_FUNC_USER,
            FuncSource::DataPointer => T_FUNC_DATA_PTR,
            FuncSource::AddressTaken => T_FUNC_ADDRESS,
        });
        w.u8(f.is_thunk as u8);
        w.opt_u64(f.thunk_target);
    }
    w.u32(a.xrefs.all.len() as u32);
    for x in &a.xrefs.all {
        w.u64(x.from);
        w.u64(x.to);
        w.u8(match x.kind {
            XRefKind::Call => T_XREF_CALL,
            XRefKind::Jump => T_XREF_JUMP,
            XRefKind::DataRead => T_XREF_READ,
            XRefKind::DataWrite => T_XREF_WRITE,
            XRefKind::DataAddr => T_XREF_ADDR,
            XRefKind::StringRef => T_XREF_STRING,
            XRefKind::CallIndirect => T_XREF_CALLIND,
            XRefKind::JumpIndirect => T_XREF_JMPIND,
            XRefKind::TailCall => T_XREF_TAIL,
            XRefKind::Thunk => T_XREF_THUNK,
        });
        w.str(x.note.as_deref().unwrap_or(""));
        w.u8(x.is_primary as u8);
        w.i32(x.op_index);
    }
    let write_idx_map = |w: &mut W, m: &rustc_hash::FxHashMap<u64, Vec<usize>>| {
        w.u32(m.len() as u32);
        let mut keys: Vec<u64> = m.keys().copied().collect();
        keys.sort_unstable();
        for k in keys {
            let v = &m[&k];
            w.u64(k);
            w.u32(v.len() as u32);
            for &i in v {
                w.u32(i as u32);
            }
        }
    };
    write_idx_map(w, &a.xrefs.by_to);
    write_idx_map(w, &a.xrefs.by_from);
    w.u32(a.cfgs.len() as u32);
    let mut cfg_keys: Vec<u64> = a.cfgs.keys().copied().collect();
    cfg_keys.sort_unstable();
    for key in &cfg_keys {
        let cfg = &a.cfgs[key];
        w.u64(*key);
        w.u64(cfg.func_entry);
        w.u32(cfg.blocks.len() as u32);
        for b in &cfg.blocks {
            w.u32(b.id as u32);
            w.u64(b.start);
            w.u64(b.end);
            w.u32(b.instr_indices.len() as u32);
            w.u32(b.instr_indices.start as u32);
            w.u32(b.instr_indices.end as u32);
            w.u32(b.successors.len() as u32);
            for e in &b.successors {
                w.u64(e.target as u64);
                w.u8(match e.kind {
                    EdgeKind::Fallthrough => T_EDGE_FT,
                    EdgeKind::Jump => T_EDGE_JMP,
                    EdgeKind::BranchTrue => T_EDGE_T,
                    EdgeKind::BranchFalse => T_EDGE_F,
                });
            }
            w.u32(b.predecessors.len() as u32);
            for &p in &b.predecessors {
                w.u64(p as u64);
            }
        }
        w.u32(cfg.block_at.len() as u32);
        let mut ba_keys: Vec<u64> = cfg.block_at.keys().copied().collect();
        ba_keys.sort_unstable();
        for k in ba_keys {
            w.u64(k);
            w.u32(cfg.block_at[&k] as u32);
        }
    }
    w.u32(a.stack_frames.len() as u32);
    let mut sf_keys: Vec<u64> = a.stack_frames.keys().copied().collect();
    sf_keys.sort_unstable();
    for key in &sf_keys {
        let sf = &a.stack_frames[key];
        w.u64(*key);
        w.u64(sf.func_entry);
        w.i64(sf.frame_size);
        w.u32(sf.variables.len() as u32);
        for v in &sf.variables {
            w.i64(v.offset);
            w.u32(v.size);
            w.u32(v.access_count);
            w.u8(match v.kind {
                VarKind::Local => T_VAR_LOCAL,
                VarKind::Parameter => T_VAR_PARAM,
                VarKind::SavedReg => T_VAR_SAVED,
                VarKind::Unknown => T_VAR_UNKNOWN,
            });
            w.str(&v.name);
        }
    }
    w.u32(a.pseudocode.len() as u32);
    let mut pc_keys: Vec<u64> = a.pseudocode.keys().copied().collect();
    pc_keys.sort_unstable();
    for key in &pc_keys {
        let pc = &a.pseudocode[key];
        w.u64(*key);
        w.u64(pc.func_entry);
        w.str(&pc.func_name);
        w.u32(pc.lines.len() as u32);
        for l in &pc.lines {
            w.u32(l.indent);
            w.str(&l.text);
            w.u8(match l.kind {
                LineKind::Signature => T_LINE_SIG,
                LineKind::Declaration => T_LINE_DECL,
                LineKind::Assignment => T_LINE_ASSIGN,
                LineKind::Call => T_LINE_CALL,
                LineKind::Return => T_LINE_RET,
                LineKind::Branch => T_LINE_BRANCH,
                LineKind::Label => T_LINE_LABEL,
                LineKind::Comment => T_LINE_COMMENT,
                LineKind::OpenBrace => T_LINE_OPEN,
                LineKind::CloseBrace => T_LINE_CLOSE,
            });
            w.opt_u64(l.source_addr);
        }
    }
    w.u32(a.callers.len() as u32);
    let mut caller_keys: Vec<u64> = a.callers.keys().copied().collect();
    caller_keys.sort_unstable();
    for k in caller_keys {
        w.u64(k);
        w.vec_u64(&a.callers[&k]);
    }
    w.u32(a.callees.len() as u32);
    let mut callee_keys: Vec<u64> = a.callees.keys().copied().collect();
    callee_keys.sort_unstable();
    for k in callee_keys {
        w.u64(k);
        w.vec_u64(&a.callees[&k]);
    }
    w.u32(a.stubs.len() as u32);
    let mut stub_keys: Vec<u64> = a.stubs.keys().copied().collect();
    stub_keys.sort_unstable();
    for key in &stub_keys {
        let s = &a.stubs[key];
        w.u64(*key);
        w.u64(s.func_entry);
        w.u8(match s.kind {
            StubKind::ImportThunk => T_STUB_IMPORT,
            StubKind::TailCall => T_STUB_TAIL,
        });
        w.str(&s.target_name);
        w.opt_u64(s.target_addr);
    }
    w.u32(a.switches.len() as u32);
    for s in &a.switches {
        w.u64(s.jump_addr);
        w.u64(s.table_addr);
        w.u32(s.case_count);
        w.vec_u64(&s.case_targets);
    }
    w.u32(a.noreturn_functions.len() as u32);
    let mut nr: Vec<u64> = a.noreturn_functions.iter().copied().collect();
    nr.sort_unstable();
    for x in nr {
        w.u64(x);
    }
    w.u32(a.function_signatures.len() as u32);
    let mut sig_keys: Vec<u64> = a.function_signatures.keys().copied().collect();
    sig_keys.sort_unstable();
    for key in &sig_keys {
        let s = &a.function_signatures[key];
        w.u64(*key);
        w.u64(s.hash);
        w.str(&s.name);
        w.str(&s.library);
        w.u32(s.size as u32);
        w.u64(s.specific);
        w.u64(s.score.to_bits());
    }
    w.u32(a.reconstructed_types.len() as u32);
    let mut rt_keys: Vec<u64> = a.reconstructed_types.keys().copied().collect();
    rt_keys.sort_unstable();
    for key in &rt_keys {
        let t = &a.reconstructed_types[key];
        w.u64(*key);
        w.str(&t.name);
        w.u64(t.size as u64);
        w.u8(match t.kind {
            TypeKind::Primitive(_) => T_RT_PRIM,
            TypeKind::Struct => T_RT_STRUCT,
            TypeKind::Array { .. } => T_RT_ARRAY,
            TypeKind::Pointer { .. } => T_RT_POINTER,
            TypeKind::Enum { .. } => T_RT_ENUM,
        });
        match &t.kind {
            TypeKind::Primitive(p) => w.u8(match p {
                PrimitiveType::Bool => T_PRIM_BOOL,
                PrimitiveType::Char => T_PRIM_CHAR,
                PrimitiveType::UChar => T_PRIM_UCHAR,
                PrimitiveType::Short => T_PRIM_SHORT,
                PrimitiveType::UShort => T_PRIM_USHORT,
                PrimitiveType::Int => T_PRIM_INT,
                PrimitiveType::UInt => T_PRIM_UINT,
                PrimitiveType::Long => T_PRIM_LONG,
                PrimitiveType::ULong => T_PRIM_ULONG,
                PrimitiveType::LongLong => T_PRIM_LLONG,
                PrimitiveType::ULongLong => T_PRIM_ULLONG,
                PrimitiveType::Float => T_PRIM_FLOAT,
                PrimitiveType::Double => T_PRIM_DOUBLE,
                PrimitiveType::Void => T_PRIM_VOID,
            }),
            TypeKind::Array {
                element_type,
                count,
            } => {
                w.u64(*element_type);
                w.u64(*count as u64);
            }
            TypeKind::Pointer { target_type } => w.u64(*target_type),
            TypeKind::Enum { variants } => {
                w.u32(variants.len() as u32);
                for (v, n) in variants {
                    w.i64(*v);
                    w.str(n);
                }
            }
            TypeKind::Struct => {}
        }
        w.u32(t.fields.len() as u32);
        for f in &t.fields {
            w.str(&f.name);
            w.i64(f.offset);
            w.u64(f.size as u64);
            w.u64(f.type_id);
            w.u64(f.access_count as u64);
        }
    }
    match &a.debug_types {
        Some(dt) => {
            w.u8(1);
            write_debug_types(w, dt);
        }
        None => w.u8(0),
    }
    w.u8(a.is_win64 as u8);
}

fn write_debug_types(w: &mut W, d: &crate::analysis::symbols::debug_types::DebugTypes) {
    w.u32(d.structs.len() as u32);
    for s in &d.structs {
        w.str(&s.name);
        w.u64(s.size as u64);
        w.u32(s.fields.len() as u32);
        for f in &s.fields {
            w.str(&f.name);
            w.u64(f.offset as u64);
            w.str(&f.type_name);
            w.u64(f.size as u64);
            match f.bitfield {
                Some((off, width)) => {
                    w.u8(1);
                    w.u8(off);
                    w.u8(width);
                }
                None => w.u8(0),
            }
        }
    }
    w.u32(d.functions.len() as u32);
    let mut keys: Vec<u64> = d.functions.keys().copied().collect();
    keys.sort_unstable();
    for key in keys {
        let f = &d.functions[&key];
        w.u64(key);
        w.str(&f.name);
        w.str(&f.ret);
        w.u32(f.params.len() as u32);
        for p in &f.params {
            w.str(&p.name);
            w.str(&p.type_name);
            match &p.struct_name {
                Some(name) => {
                    w.u8(1);
                    w.str(name);
                }
                None => w.u8(0),
            }
        }
        w.u32(f.locals.len() as u32);
        for l in &f.locals {
            w.str(&l.name);
            w.str(&l.type_name);
            match &l.struct_name {
                Some(name) => {
                    w.u8(1);
                    w.str(name);
                }
                None => w.u8(0),
            }
            w.u8(match l.base {
                crate::analysis::symbols::debug_types::DebugBase::Cfa => 0,
                crate::analysis::symbols::debug_types::DebugBase::Rbp => 1,
                crate::analysis::symbols::debug_types::DebugBase::Rsp => 2,
            });
            w.i64(l.offset);
            w.u64(l.size as u64);
        }
    }
    w.u32(d.enums.len() as u32);
    for e in &d.enums {
        w.str(&e.name);
        w.u64(e.size as u64);
        w.u32(e.variants.len() as u32);
        for (name, value) in &e.variants {
            w.str(name);
            w.i64(*value);
        }
    }
}

fn read_debug_types(
    r: &mut R,
    db_ver: u32,
) -> Result<crate::analysis::symbols::debug_types::DebugTypes, String> {
    use crate::analysis::symbols::debug_types::{
        DebugEnum, DebugField, DebugFunction, DebugParam, DebugStruct, DebugTypes,
    };
    let n = r.u32()? as usize;
    let mut structs = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        let name = r.str()?;
        let size = r.u64()? as usize;
        let fn_ = r.u32()? as usize;
        let mut fields = Vec::with_capacity(fn_.min(1 << 20));
        for _ in 0..fn_ {
            fields.push(DebugField {
                name: r.str()?,
                offset: r.u64()? as usize,
                type_name: r.str()?,
                size: r.u64()? as usize,
                bitfield: if db_ver >= 9 {
                    match r.u8()? {
                        0 => None,
                        1 => Some((r.u8()?, r.u8()?)),
                        other => {
                            return Err(format!(
                                "corrupt project DB (bitfield tag {other})"
                            ));
                        }
                    }
                } else {
                    None
                },
            });
        }
        structs.push(DebugStruct { name, size, fields });
    }
    let n = r.u32()? as usize;
    let mut functions = rustc_hash::FxHashMap::with_capacity_and_hasher(
        n.min(1 << 20),
        rustc_hash::FxBuildHasher,
    );
    for _ in 0..n {
        let addr = r.u64()?;
        let name = r.str()?;
        let ret = r.str()?;
        let pn = r.u32()? as usize;
        let mut params = Vec::with_capacity(pn.min(1 << 20));
        for _ in 0..pn {
            let name = r.str()?;
            let type_name = r.str()?;
            let struct_name = match r.u8()? {
                0 => None,
                1 => Some(r.str()?),
                other => return Err(format!("corrupt project DB (param struct tag {other})")),
            };
            params.push(DebugParam {
                name,
                type_name,
                struct_name,
            });
        }
        let locals = if db_ver >= 7 {
            let ln = r.u32()? as usize;
            let mut locals = Vec::with_capacity(ln.min(1 << 20));
            for _ in 0..ln {
                let name = r.str()?;
                let type_name = r.str()?;
                let struct_name = match r.u8()? {
                    0 => None,
                    1 => Some(r.str()?),
                    other => {
                        return Err(format!("corrupt project DB (local struct tag {other})"))
                    }
                };
                let base = match r.u8()? {
                    0 => crate::analysis::symbols::debug_types::DebugBase::Cfa,
                    1 => crate::analysis::symbols::debug_types::DebugBase::Rbp,
                    2 => crate::analysis::symbols::debug_types::DebugBase::Rsp,
                    other => {
                        return Err(format!("corrupt project DB (local base tag {other})"))
                    }
                };
                let offset = r.i64()?;
                let size = r.u64()? as usize;
                locals.push(crate::analysis::symbols::debug_types::DebugLocal {
                    name,
                    type_name,
                    struct_name,
                    base,
                    offset,
                    size,
                });
            }
            locals
        } else {
            Vec::new()
        };
        functions.insert(
            addr,
            DebugFunction {
                name,
                ret,
                params,
                locals,
            },
        );
    }
    let enums = if db_ver >= 9 {
        let n = r.u32()? as usize;
        let mut enums = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            let name = r.str()?;
            let size = r.u64()? as usize;
            let vn = r.u32()? as usize;
            let mut variants = Vec::with_capacity(vn.min(1 << 20));
            for _ in 0..vn {
                variants.push((r.str()?, r.i64()?));
            }
            enums.push(DebugEnum {
                name,
                size,
                variants,
            });
        }
        enums
    } else {
        Vec::new()
    };
    Ok(DebugTypes {
        structs,
        enums,
        functions,
    })
}

pub(crate) fn read_analysis(r: &mut R, db_ver: u32) -> Result<AnalysisResult, String> {
    let mut a = AnalysisResult::default();

    let n = r.u32()? as usize;
    let mut functions = Vec::with_capacity(n.min(1 << 21));
    for _ in 0..n {
        let entry = r.u64()?;
        let end = r.u64()?;
        let name = r.str()?;
        let has_frame = r.u8()? != 0;
        let stack_size = r.i64()?;
        let source = match r.u8()? {
            T_FUNC_ENTRY => FuncSource::EntryPoint,
            T_FUNC_SYMBOL => FuncSource::SymbolTable,
            T_FUNC_CALL => FuncSource::CallTarget,
            T_FUNC_PROLOGUE => FuncSource::Prologue,
            T_FUNC_AFTER_RET => FuncSource::AfterReturn,
            T_FUNC_UNWIND => FuncSource::UnwindInfo,
            T_FUNC_USER => FuncSource::UserDefined,
            T_FUNC_DATA_PTR => FuncSource::DataPointer,
            T_FUNC_ADDRESS => FuncSource::AddressTaken,
            other => {
                return Err(format!(
                    "corrupt project DB (function source tag {})",
                    other
                ));
            }
        };
        let (is_thunk, thunk_target) = if db_ver >= 4 {
            (r.u8()? != 0, r.opt_u64()?)
        } else {
            (false, None)
        };
        functions.push(DetectedFunction {
            entry,
            end,
            name,
            has_frame,
            stack_size,
            source,
            is_thunk,
            thunk_target,
        });
    }
    a.functions = functions;

    let n = r.u32()? as usize;
    let mut all = Vec::with_capacity(n.min(1 << 23));
    for _ in 0..n {
        let from = r.u64()?;
        let to = r.u64()?;
        let kind = match r.u8()? {
            T_XREF_CALL => XRefKind::Call,
            T_XREF_JUMP => XRefKind::Jump,
            T_XREF_READ => XRefKind::DataRead,
            T_XREF_WRITE => XRefKind::DataWrite,
            T_XREF_ADDR => XRefKind::DataAddr,
            T_XREF_STRING => XRefKind::StringRef,
            T_XREF_CALLIND => XRefKind::CallIndirect,
            T_XREF_JMPIND => XRefKind::JumpIndirect,
            T_XREF_TAIL => XRefKind::TailCall,
            T_XREF_THUNK => XRefKind::Thunk,
            other => return Err(format!("corrupt project DB (xref tag {})", other)),
        };
        let note = r.str()?;
        let (is_primary, op_index) = if db_ver >= 2 {
            (r.u8()? != 0, r.i32()?)
        } else {
            (true, 0)
        };
        let note = if note.is_empty() {
            None
        } else {
            Some(std::sync::Arc::from(note.as_str()))
        };
        all.push(XRef {
            from,
            to,
            kind,
            note,
            is_primary,
            op_index,
        });
    }
    let read_idx_map = |r: &mut R| -> Result<rustc_hash::FxHashMap<u64, Vec<usize>>, String> {
        let n = r.u32()? as usize;
        let mut m = rustc_hash::FxHashMap::with_capacity_and_hasher(
            n.min(1 << 24),
            rustc_hash::FxBuildHasher,
        );
        for _ in 0..n {
            let k = r.u64()?;
            let c = r.u32()? as usize;
            let mut v = Vec::with_capacity(c.min(1 << 24));
            for _ in 0..c {
                v.push(r.u32()? as usize);
            }
            m.insert(k, v);
        }
        Ok(m)
    };
    let by_to = read_idx_map(r)?;
    let by_from = read_idx_map(r)?;
    a.xrefs = XRefDB::from_parts(all, by_to, by_from);

    let n = r.u32()? as usize;
    let mut cfgs =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 22), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let key = r.u64()?;
        let func_entry = r.u64()?;
        let bn = r.u32()? as usize;
        let mut blocks = Vec::with_capacity(bn.min(1 << 21));
        for _ in 0..bn {
            let id = r.u32()? as usize;
            let start = r.u64()?;
            let end = r.u64()?;
            let ic = r.u32()? as usize;
            let instr_indices = if db_ver >= 5 {
                let rs = r.u32()? as usize;
                let re = r.u32()? as usize;
                rs..re
            } else {
                let mut lo = usize::MAX;
                let mut hi = 0usize;
                for _ in 0..ic {
                    let idx = r.u64()? as usize;
                    lo = lo.min(idx);
                    hi = hi.max(idx + 1);
                }
                if ic == 0 {
                    0..0
                } else {
                    lo..hi
                }
            };
            let sc = r.u32()? as usize;
            let mut successors = Vec::with_capacity(sc.min(1 << 20));
            for _ in 0..sc {
                let target = r.u64()? as usize;
                let edge_tag = r.u8()?;
                let kind = match edge_tag {
                    T_EDGE_FT => EdgeKind::Fallthrough,
                    T_EDGE_JMP => EdgeKind::Jump,
                    T_EDGE_T => EdgeKind::BranchTrue,
                    T_EDGE_F => EdgeKind::BranchFalse,
                    other => {
                        return Err(format!("corrupt project DB (edge tag {})", other));
                    }
                };
                successors.push(Edge { target, kind });
            }
            let pc = r.u32()? as usize;
            let mut predecessors = Vec::with_capacity(pc.min(1 << 20));
            for _ in 0..pc {
                predecessors.push(r.u64()? as usize);
            }
            blocks.push(BasicBlock {
                id,
                start,
                end,
                instr_indices,
                successors,
                predecessors,
            });
        }
        let bcn = r.u32()? as usize;
        let mut block_at = rustc_hash::FxHashMap::with_capacity_and_hasher(
            bcn.min(1 << 20),
            rustc_hash::FxBuildHasher,
        );
        for _ in 0..bcn {
            let k = r.u64()?;
            let v = r.u32()? as usize;
            block_at.insert(k, v);
        }
        cfgs.insert(
            key,
            CFG {
                func_entry,
                blocks,
                block_at,
            },
        );
    }
    a.cfgs = cfgs;

    let n = r.u32()? as usize;
    let mut stack_frames =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 22), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let key = r.u64()?;
        let func_entry = r.u64()?;
        let frame_size = r.i64()?;
        let vn = r.u32()? as usize;
        let mut variables = Vec::with_capacity(vn.min(1 << 20));
        for _ in 0..vn {
            variables.push(StackVar {
                offset: r.i64()?,
                size: r.u32()?,
                access_count: r.u32()?,
                kind: match r.u8()? {
                    T_VAR_LOCAL => VarKind::Local,
                    T_VAR_PARAM => VarKind::Parameter,
                    T_VAR_SAVED => VarKind::SavedReg,
                    T_VAR_UNKNOWN => VarKind::Unknown,
                    other => return Err(format!("corrupt project DB (var tag {})", other)),
                },
                name: r.str()?,
            });
        }
        stack_frames.insert(
            key,
            StackFrame {
                func_entry,
                variables,
                frame_size,
            },
        );
    }
    a.stack_frames = stack_frames;

    let n = r.u32()? as usize;
    let mut pseudocode =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 20), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let key = r.u64()?;
        let func_entry = r.u64()?;
        let func_name = r.str()?;
        let ln = r.u32()? as usize;
        let mut lines = Vec::with_capacity(ln.min(1 << 22));
        for _ in 0..ln {
            lines.push(PseudoLine {
                indent: r.u32()?,
                text: r.str()?,
                kind: match r.u8()? {
                    T_LINE_SIG => LineKind::Signature,
                    T_LINE_DECL => LineKind::Declaration,
                    T_LINE_ASSIGN => LineKind::Assignment,
                    T_LINE_CALL => LineKind::Call,
                    T_LINE_RET => LineKind::Return,
                    T_LINE_BRANCH => LineKind::Branch,
                    T_LINE_LABEL => LineKind::Label,
                    T_LINE_COMMENT => LineKind::Comment,
                    T_LINE_OPEN => LineKind::OpenBrace,
                    T_LINE_CLOSE => LineKind::CloseBrace,
                    other => return Err(format!("corrupt project DB (line tag {})", other)),
                },
                source_addr: r.opt_u64()?,
            });
        }
        pseudocode.insert(
            key,
            Pseudocode {
                func_entry,
                func_name,
                lines,
            },
        );
    }
    a.pseudocode = rustc_hash::FxHashMap::default();

    let n = r.u32()? as usize;
    let mut callers =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 22), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let k = r.u64()?;
        let v = r.vec_u64()?;
        callers.insert(k, v);
    }
    a.callers = callers;
    let n = r.u32()? as usize;
    let mut callees =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 22), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let k = r.u64()?;
        let v = r.vec_u64()?;
        callees.insert(k, v);
    }
    a.callees = callees;

    let n = r.u32()? as usize;
    let mut stubs =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 20), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let key = r.u64()?;
        let func_entry = r.u64()?;
        let kind = match r.u8()? {
            T_STUB_IMPORT => StubKind::ImportThunk,
            T_STUB_TAIL => StubKind::TailCall,
            other => return Err(format!("corrupt project DB (stub tag {})", other)),
        };
        let target_name = r.str()?;
        let target_addr = if db_ver >= 2 { r.opt_u64()? } else { None };
        stubs.insert(
            key,
            StubInfo {
                func_entry,
                kind,
                target_name,
                target_addr,
                jump_addr: func_entry,
            },
        );
    }
    a.stubs = stubs;

    let n = r.u32()? as usize;
    let mut switches = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        switches.push(SwitchTable {
            jump_addr: r.u64()?,
            table_addr: r.u64()?,
            case_count: r.u32()?,
            case_targets: r.vec_u64()?,
        });
    }
    a.switches = switches;

    let n = r.u32()? as usize;
    let mut noreturn_functions =
        rustc_hash::FxHashSet::with_capacity_and_hasher(n.min(1 << 20), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        noreturn_functions.insert(r.u64()?);
    }
    a.noreturn_functions = noreturn_functions;

    let n = r.u32()? as usize;
    let mut function_signatures =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 20), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let key = r.u64()?;
        let hash = r.u64()?;
        let name = r.str()?;
        let library = r.str()?;
        let size = r.u32()? as usize;
        let (specific, score) = if db_ver >= 2 {
            (r.u64()?, f64::from_bits(r.u64()?))
        } else {
            (hash, 0.0)
        };
        function_signatures.insert(
            key,
            function_id::FunctionSignature {
                hash,
                name,
                library,
                size,
                specific,
                score,
            },
        );
    }
    a.function_signatures = function_signatures;

    let n = r.u32()? as usize;
    let mut reconstructed_types =
        rustc_hash::FxHashMap::with_capacity_and_hasher(n.min(1 << 20), rustc_hash::FxBuildHasher);
    for _ in 0..n {
        let key = r.u64()?;
        let name = r.str()?;
        let size = r.u64()? as usize;
        let kind = match r.u8()? {
            T_RT_PRIM => TypeKind::Primitive(match r.u8()? {
                T_PRIM_BOOL => PrimitiveType::Bool,
                T_PRIM_CHAR => PrimitiveType::Char,
                T_PRIM_UCHAR => PrimitiveType::UChar,
                T_PRIM_SHORT => PrimitiveType::Short,
                T_PRIM_USHORT => PrimitiveType::UShort,
                T_PRIM_INT => PrimitiveType::Int,
                T_PRIM_UINT => PrimitiveType::UInt,
                T_PRIM_LONG => PrimitiveType::Long,
                T_PRIM_ULONG => PrimitiveType::ULong,
                T_PRIM_LLONG => PrimitiveType::LongLong,
                T_PRIM_ULLONG => PrimitiveType::ULongLong,
                T_PRIM_FLOAT => PrimitiveType::Float,
                T_PRIM_DOUBLE => PrimitiveType::Double,
                T_PRIM_VOID => PrimitiveType::Void,
                other => return Err(format!("corrupt project DB (prim tag {})", other)),
            }),
            T_RT_STRUCT => TypeKind::Struct,
            T_RT_ARRAY => TypeKind::Array {
                element_type: r.u64()?,
                count: r.u64()? as usize,
            },
            T_RT_POINTER => TypeKind::Pointer {
                target_type: r.u64()?,
            },
            T_RT_ENUM => {
                let vn = r.u32()? as usize;
                let mut variants = Vec::with_capacity(vn.min(1 << 20));
                for _ in 0..vn {
                    let v = r.i64()?;
                    let n = r.str()?;
                    variants.push((v, n));
                }
                TypeKind::Enum { variants }
            }
            other => return Err(format!("corrupt project DB (rtype tag {})", other)),
        };
        let fn_ = r.u32()? as usize;
        let mut fields = Vec::with_capacity(fn_.min(1 << 20));
        for _ in 0..fn_ {
            fields.push(TypeField {
                name: r.str()?,
                offset: r.i64()?,
                size: r.u64()? as usize,
                type_id: r.u64()?,
                access_count: r.u64()? as usize,
            });
        }
        reconstructed_types.insert(
            key,
            ReconstructedType {
                name,
                size,
                kind,
                fields,
            },
        );
    }
    a.reconstructed_types = reconstructed_types;

    a.debug_types = if db_ver >= 6 {
        match r.u8()? {
            0 => None,
            1 => Some(std::sync::Arc::new(read_debug_types(r, db_ver)?)),
            other => return Err(format!("corrupt project DB (debug types tag {other})")),
        }
    } else {
        None
    };
    a.is_win64 = db_ver >= 8 && r.u8()? != 0;

    a.pe_resources = None;
    a.debug_symbols = None;

    Ok(a)
}

pub(crate) fn write_types(w: &mut W, m: &crate::type_system::DataTypeManager) {
    let json = m.to_json().to_string();
    let compressed =
        zstd::bulk::compress(json.as_bytes(), 3).unwrap_or_else(|_| json.as_bytes().to_vec());
    w.bytes(&compressed);
}

pub(crate) fn read_types(
    r: &mut R,
    db_ver: u32,
) -> Result<crate::type_system::DataTypeManager, String> {
    let json = if db_ver >= 5 {
        let blob = r.bytes()?;
        let raw = zstd::bulk::decompress(&blob, 1 << 30)
            .map_err(|_| "corrupt project DB (types zstd)".to_string())?;
        String::from_utf8(raw).map_err(|_| "corrupt project DB (types utf8)".to_string())?
    } else {
        r.str()?
    };
    let doc: serde_json::Value =
        serde_json::from_str(&json).map_err(|_| "corrupt project DB (types json)".to_string())?;
    let mut m = crate::type_system::DataTypeManager::new();
    m.from_json(&doc)
        .map_err(|e| format!("corrupt project DB (types): {}", e))?;
    Ok(m)
}
