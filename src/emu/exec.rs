use super::alu::*;
use super::config::*;
use super::mem::*;
use super::regs::*;
use crate::analysis::pcode::{lift_instruction, POp};
use crate::disasm::DisasmInstruction;
use crate::parser::ParsedBinary;
use rustc_hash::FxHashMap as HashMap;
use std::cell::Cell;
use std::rc::Rc;

macro_rules! ev {
    ($slf:expr, $v:expr) => {
        match $slf.eval($v) {
            Ok(val__) => val__,
            Err(reason__) => return OpFlow::Halt(reason__),
        }
    };
}

pub struct Emulator<'a> {
    pub(crate) insns: &'a [DisasmInstruction],
    pub(crate) by_addr: HashMap<u64, usize>,
    pub(crate) lifted: HashMap<u64, Rc<crate::analysis::pcode::PInstr>>,
    pub(crate) imports: HashMap<u64, String>,
    pub(crate) regions: Vec<(u64, u64, u8)>,
    pub(crate) regs: [u64; N_REGS],
    pub(crate) ext_regs: HashMap<String, u64>,
    pub(crate) rsp: u64,
    pub(crate) tmps: Vec<u64>,
    pub(crate) flags: Flags,
    pub(crate) mem: HashMap<u64, Page>,
    pub(crate) cfg: EmuConfig,
    pub(crate) call_stack: Vec<u64>,
    pub(crate) steps: usize,
    pub(crate) writes: Vec<MemWrite>,
    pub(crate) dropped_writes: usize,
    pub(crate) stack_writes: usize,
    pub(crate) trace: [u64; TRACE_CAP],
    pub(crate) trace_count: usize,
    pub(crate) region_cache: Cell<Option<usize>>,
    pub(crate) mapped_memo: HashMap<u64, bool>,
}

impl<'a> Emulator<'a> {
    pub fn with_config(
        bin: &'a ParsedBinary,
        insns: &'a [DisasmInstruction],
        cfg: EmuConfig,
    ) -> Self {
        let mut by_addr = HashMap::with_capacity_and_hasher(insns.len(), rustc_hash::FxBuildHasher);
        for (i, ins) in insns.iter().enumerate() {
            by_addr.entry(ins.address).or_insert(i);
        }
        let mut imports = HashMap::default();
        for imp in &bin.imports {
            if imp.offset != 0 {
                let name = if imp.library.is_empty() {
                    imp.name.clone()
                } else {
                    format!("{}!{}", imp.library, imp.name)
                };
                imports.entry(imp.offset).or_insert(name);
            }
        }
        let mut regions: Vec<(u64, u64, u8)> = bin
            .sections
            .iter()
            .filter(|s| s.size > 0)
            .map(|s| {
                let rwx = (if s.readable { 4 } else { 0 })
                    | (if s.writable { 2 } else { 0 })
                    | (if s.is_executable { 1 } else { 0 });
                (s.vaddr, s.size, rwx)
            })
            .collect();
        regions.sort();
        let mut mem: HashMap<u64, Page> = HashMap::default();
        let mut preloaded: u64 = 0;
        const PRELOAD_CAP: u64 = 32 << 20;
        let mut secs: Vec<_> = bin
            .sections
            .iter()
            .filter(|s| s.initialized && s.is_executable)
            .collect();
        secs.sort_by_key(|s| s.offset);
        for s in secs {
            if preloaded >= PRELOAD_CAP {
                break;
            }
            let size = s.size.min(PRELOAD_CAP - preloaded);
            let start = s.offset as usize;
            let end = start.saturating_add(size as usize).min(bin.data.len());
            if start >= bin.data.len() || end <= start {
                continue;
            }
            copy_into_pages(&mut mem, s.vaddr, &bin.data[start..end]);
            preloaded += (end - start) as u64;
        }
        let rsp = cfg.stack_top;
        Self {
            insns,
            by_addr,
            lifted: HashMap::default(),
            imports,
            regions,
            regs: [0u64; N_REGS],
            ext_regs: HashMap::default(),
            rsp,
            tmps: Vec::new(),
            flags: Flags::default(),
            mem,
            cfg,
            call_stack: Vec::new(),
            steps: 0,
            writes: Vec::new(),
            dropped_writes: 0,
            stack_writes: 0,
            trace: [0u64; TRACE_CAP],
            trace_count: 0,
            region_cache: Cell::new(None),
            mapped_memo: HashMap::default(),
        }
    }

    pub fn run_function(
        &mut self,
        entry: u64,
        end: u64,
        _has_frame: bool,
        args: &[u64],
    ) -> EmuResult {
        self.regs = [0u64; N_REGS];
        self.ext_regs.clear();
        self.tmps.clear();
        self.flags = Flags::default();
        self.call_stack.clear();
        self.steps = 0;
        self.writes.clear();
        self.dropped_writes = 0;
        self.stack_writes = 0;
        self.trace = [0u64; TRACE_CAP];
        self.trace_count = 0;
        let slots = [R_RDI, R_RSI, R_RDX, R_RCX, R_R8, R_R9];
        for (i, s) in slots.iter().enumerate() {
            self.regs[*s] = args.get(i).copied().unwrap_or(0);
        }
        self.rsp = self.cfg.stack_top;
        self.regs[R_RBP] = self.cfg.stack_top;

        let mut rip = entry;
        let mut seq_idx: Option<usize> = None;
        let reason = loop {
            if self.steps >= self.cfg.max_steps {
                break EndReason::MaxSteps;
            }
            if (rip < entry || rip >= end)
                && !(self.cfg.follow_tailcalls && self.is_mapped_code(rip))
            {
                break EndReason::LeftFunction(rip);
            }
            let idx = match seq_idx.take() {
                Some(i) => i,
                None => match self.by_addr.get(&rip) {
                    Some(&i) => i,
                    None => break EndReason::UnmappedRip(rip),
                },
            };
            let ins = &self.insns[idx];
            let next_fall = rip.wrapping_add(ins.bytes.len() as u64);
            let pin = if let Some(p) = self.lifted.get(&rip) {
                Rc::clone(p)
            } else {
                if self.lifted.len() >= LIFTED_CAP {
                    self.lifted.clear();
                }
                let p = Rc::new(lift_instruction(ins));
                self.lifted.insert(rip, Rc::clone(&p));
                p
            };
            let float_single = pin.mnemonic.as_str().ends_with("ss");
            self.steps += 1;
            self.trace[self.trace_count % TRACE_CAP] = rip;
            self.trace_count = self.trace_count.wrapping_add(1);
            match self.exec_ops(&pin, next_fall, float_single) {
                OpFlow::Continue => {
                    if next_fall != rip {
                        if let Some(n) = self.insns.get(idx + 1) {
                            if n.address == next_fall {
                                seq_idx = Some(idx + 1);
                            }
                        }
                    }
                    rip = next_fall;
                }
                OpFlow::Jump(t) => rip = t,
                OpFlow::Halt(r) => break r,
            }
        };
        let n = self.trace_count.min(TRACE_CAP);
        let mut tail = Vec::with_capacity(n);
        if self.trace_count <= TRACE_CAP {
            tail.extend_from_slice(&self.trace[..n]);
        } else {
            let start = self.trace_count % TRACE_CAP;
            tail.extend_from_slice(&self.trace[start..]);
            tail.extend_from_slice(&self.trace[..start]);
        }
        EmuResult {
            reason,
            rax: self.regs[R_RAX],
            steps: self.steps,
            writes: std::mem::take(&mut self.writes),
            dropped_writes: self.dropped_writes,
            stack_writes: self.stack_writes,
            trace_tail: tail,
        }
    }

    fn exec_ops(
        &mut self,
        pin: &crate::analysis::pcode::PInstr,
        next_fall: u64,
        float_single: bool,
    ) -> OpFlow {
        for op in &pin.ops {
            match self.exec_op(op, next_fall, float_single) {
                OpFlow::Continue => {}
                other => return other,
            }
        }
        OpFlow::Continue
    }

    fn exec_op(&mut self, op: &POp, next_fall: u64, float_single: bool) -> OpFlow {
        match op {
            POp::Nop => OpFlow::Continue,
            POp::Copy { dst, src, size } => {
                let v = ev!(self, src);
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntAdd { dst, a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let (v, cf, of) = add_with_flags(x, y, *size);
                self.set_arith_flags(v, *size, cf, of);
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntSub { dst, a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let (v, cf, of) = sub_with_flags(x, y, *size);
                self.set_arith_flags(v, *size, cf, of);
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntMul { dst, a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let (x, y) = (mask(x, *size), mask(y, *size));
                let full = (x as u128).wrapping_mul(y as u128);
                let v = mask(full as u64, *size);
                let bits = (*size * 8).min(64);
                let max: u128 = if bits >= 64 {
                    u64::MAX as u128
                } else {
                    (1u128 << bits) - 1
                };
                let overflow = full > max;
                self.set_arith_flags(v, *size, overflow, overflow);
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntDiv { dst, a, b, size } | POp::IntSDiv { dst, a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let s = *size;
                let v = if matches!(op, POp::IntDiv { .. }) {
                    if mask(y, s) == 0 {
                        return OpFlow::Halt(EndReason::DivByZero);
                    }
                    mask(x, s) / mask(y, s)
                } else {
                    let xs = sext(mask(x, s), s) as i128;
                    let ys = sext(mask(y, s), s) as i128;
                    if ys == 0 {
                        return OpFlow::Halt(EndReason::DivByZero);
                    }
                    mask(xs.wrapping_div(ys) as u64, s)
                };
                self.assign(dst, v, s);
                OpFlow::Continue
            }
            POp::IntAnd { dst, a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let v = mask(x & y, *size);
                self.set_logic_flags(v, *size);
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntOr { dst, a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let v = mask(x | y, *size);
                self.set_logic_flags(v, *size);
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntXor { dst, a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let v = mask(x ^ y, *size);
                self.set_logic_flags(v, *size);
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntLeft { dst, a, b, size } => {
                let (v, cf, of, touched) =
                    shift_op(ev!(self, a), ev!(self, b), *size, ShiftKind::Left);
                if touched {
                    self.set_arith_flags(v, *size, cf, of);
                }
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntShr { dst, a, b, size } => {
                let (v, cf, of, touched) =
                    shift_op(ev!(self, a), ev!(self, b), *size, ShiftKind::Right);
                if touched {
                    self.set_arith_flags(v, *size, cf, of);
                }
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::IntSar { dst, a, b, size } => {
                let (v, cf, of, touched) =
                    shift_op(ev!(self, a), ev!(self, b), *size, ShiftKind::Sar);
                if touched {
                    self.set_arith_flags(v, *size, cf, of);
                }
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::Zext {
                dst, src, to_size, ..
            } => {
                let v = mask(ev!(self, src), *to_size);
                self.assign(dst, v, *to_size);
                OpFlow::Continue
            }
            POp::Sext {
                dst,
                src,
                from_size,
                to_size,
            } => {
                let v = mask(sext(ev!(self, src), *from_size) as u64, *to_size);
                self.assign(dst, v, *to_size);
                OpFlow::Continue
            }
            POp::Load { dst, addr, size } => {
                let Some(a) = self.eval_addr_opt(addr) else {
                    return OpFlow::Halt(EndReason::Unmodeled("tmp-addr load".into()));
                };
                match self.read_mem(a, *size) {
                    Ok(v) => {
                        self.assign(dst, v, *size);
                        OpFlow::Continue
                    }
                    Err(r) => OpFlow::Halt(r),
                }
            }
            POp::Store { addr, src, size } => {
                let Some(a) = self.eval_addr_opt(addr) else {
                    return OpFlow::Halt(EndReason::Unmodeled("tmp-addr store".into()));
                };
                let v = mask(ev!(self, src), *size);
                if let Err(r) = self.write_mem(a, v, *size) {
                    return OpFlow::Halt(r);
                }
                OpFlow::Continue
            }
            POp::Branch { target } => OpFlow::Jump(*target),
            POp::CBranch { target, cond } => {
                let Some(taken) = eval_cond(cond, &self.flags, self.regs[R_RCX]) else {
                    return OpFlow::Halt(EndReason::Unmodeled(format!("cond {cond}")));
                };
                if taken {
                    OpFlow::Jump(*target)
                } else {
                    OpFlow::Continue
                }
            }
            POp::BranchInd { target } => {
                let t = ev!(self, target);
                if self.is_mapped_code(t) {
                    OpFlow::Jump(t)
                } else {
                    OpFlow::Halt(EndReason::IndirectUnknown(t))
                }
            }
            POp::Call { target } => self.do_call(*target, next_fall),
            POp::CallInd { target } => {
                let t = ev!(self, target);
                if let Some(name) = self.imports.get(&t).cloned() {
                    return OpFlow::Halt(EndReason::CallToImport(name));
                }
                if self.is_mapped_code(t) {
                    return self.do_call(t, next_fall);
                }
                if let Ok(p) = self.read_mem(t, 8) {
                    if self.is_mapped_code(p) {
                        return self.do_call(p, next_fall);
                    }
                    if let Some(name) = self.imports.get(&p).cloned() {
                        return OpFlow::Halt(EndReason::CallToImport(name));
                    }
                }
                OpFlow::Halt(EndReason::IndirectUnknown(t))
            }
            POp::Return => {
                if self.call_stack.pop().is_none() {
                    return OpFlow::Halt(EndReason::Returned);
                }
                let rsp = self.rsp;
                if !self.in_stack(rsp, 8) {
                    return OpFlow::Halt(EndReason::StackUnderflow(rsp));
                }
                match self.read_mem(rsp, 8) {
                    Ok(ret_mem) => {
                        self.rsp = rsp.wrapping_add(8);
                        OpFlow::Jump(ret_mem)
                    }
                    Err(r) => OpFlow::Halt(r),
                }
            }
            POp::ReturnPop { pop_imm } => {
                if self.call_stack.pop().is_none() {
                    return OpFlow::Halt(EndReason::Returned);
                }
                let rsp = self.rsp;
                if !self.in_stack(rsp, 8) {
                    return OpFlow::Halt(EndReason::StackUnderflow(rsp));
                }
                match self.read_mem(rsp, 8) {
                    Ok(ret_mem) => {
                        self.rsp = rsp.wrapping_add(8).wrapping_add(*pop_imm as u64);
                        OpFlow::Jump(ret_mem)
                    }
                    Err(r) => OpFlow::Halt(r),
                }
            }
            POp::Cmp { a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let (v, cf, of) = sub_with_flags(x, y, *size);
                self.set_arith_flags(v, *size, cf, of);
                OpFlow::Continue
            }
            POp::Test { a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let v = mask(x & y, *size);
                self.set_logic_flags(v, *size);
                OpFlow::Continue
            }
            POp::Push { src, size } => {
                let v = mask(ev!(self, src), *size);
                let rsp2 = self.rsp.wrapping_sub(*size as u64);
                if !self.in_stack(rsp2, *size) {
                    return OpFlow::Halt(EndReason::StackOverflow(rsp2));
                }
                self.paged_store(rsp2, v, *size);
                self.stack_writes += 1;
                self.rsp = rsp2;
                OpFlow::Continue
            }
            POp::Pop { dst, size } => {
                let rsp = self.rsp;
                if !self.in_stack(rsp, *size) {
                    return OpFlow::Halt(EndReason::StackUnderflow(rsp));
                }
                let (v, _) = self.paged_load(rsp, *size);
                self.rsp = rsp.wrapping_add(*size as u64);
                self.assign(dst, mask(v, *size), *size);
                OpFlow::Continue
            }
            POp::LeaAddr { dst, addr } => {
                self.assign(dst, *addr, 8);
                OpFlow::Continue
            }
            POp::AddrOf {
                dst,
                base,
                index,
                scale,
                disp,
            } => {
                let mut v = *disp as u64;
                if let Some(b) = base {
                    let x = ev!(self, b);
                    v = v.wrapping_add(x);
                }
                if let Some(idx) = index {
                    let x = ev!(self, idx);
                    v = v.wrapping_add(x.wrapping_mul(*scale as u64));
                }
                self.assign(dst, v, 8);
                OpFlow::Continue
            }
            POp::SetCC { dst, cond, size } => {
                let Some(taken) = eval_cond(cond, &self.flags, self.regs[R_RCX]) else {
                    return OpFlow::Halt(EndReason::Unmodeled(format!("cond {cond}")));
                };
                let v = if taken { 1 } else { 0 };
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::FloatBinop {
                kind,
                dst,
                a,
                b,
                size,
            } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let v = match (kind.as_str(), *size) {
                    ("add", 4) => {
                        f32::to_bits(f32::from_bits(x as u32) + f32::from_bits(y as u32)) as u64
                    }
                    ("add", _) => f64::to_bits(f64::from_bits(x) + f64::from_bits(y)),
                    ("sub", 4) => {
                        f32::to_bits(f32::from_bits(x as u32) - f32::from_bits(y as u32)) as u64
                    }
                    ("sub", _) => f64::to_bits(f64::from_bits(x) - f64::from_bits(y)),
                    ("mul", 4) => {
                        f32::to_bits(f32::from_bits(x as u32) * f32::from_bits(y as u32)) as u64
                    }
                    ("mul", _) => f64::to_bits(f64::from_bits(x) * f64::from_bits(y)),
                    ("div", 4) => {
                        f32::to_bits(f32::from_bits(x as u32) / f32::from_bits(y as u32)) as u64
                    }
                    ("div", _) => f64::to_bits(f64::from_bits(x) / f64::from_bits(y)),
                    _ => return OpFlow::Halt(EndReason::Unmodeled(format!("float {}", kind))),
                };
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::Cvt { kind, dst, src } => {
                let x = ev!(self, src);
                let v = match kind.as_str() {
                    "f2i" => {
                        let w = self.reg_width(dst);
                        let f = if float_single {
                            f32::from_bits(x as u32) as f64
                        } else {
                            f64::from_bits(x)
                        };
                        f2i_trunc(f, w)
                    }
                    "i2f" => {
                        if float_single {
                            f32::to_bits(sext(x, self.reg_width(src)) as f32) as u64
                        } else {
                            f64::to_bits(sext(x, self.reg_width(src)) as f64)
                        }
                    }
                    _ => x,
                };
                let w = self.reg_width(dst);
                self.assign(dst, v, w);
                OpFlow::Continue
            }
            POp::FloatCmp { a, b, size } => {
                let x = ev!(self, a);
                let y = ev!(self, b);
                let (less, eq, unordered) = if *size == 4 {
                    let (f, g) = (f32::from_bits(x as u32), f32::from_bits(y as u32));
                    (f < g, f == g, f.is_nan() || g.is_nan())
                } else {
                    let (f, g) = (f64::from_bits(x), f64::from_bits(y));
                    (f < g, f == g, f.is_nan() || g.is_nan())
                };
                if unordered {
                    self.flags.set(Flags::ZF, true);
                    self.flags.set(Flags::PF, true);
                    self.flags.set(Flags::CF, true);
                } else {
                    self.flags.set(Flags::ZF, eq);
                    self.flags.set(Flags::CF, less);
                    self.flags.set(Flags::PF, false);
                }
                self.flags.set(Flags::SF, !eq && less);
                self.flags.set(Flags::OF, false);
                OpFlow::Continue
            }
            POp::SegmentOp {
                dst,
                segment,
                addr,
                size,
                is_store,
            } => {
                if *is_store {
                    return OpFlow::Continue;
                }
                let Some(a) = self.eval_addr_opt(addr) else {
                    return OpFlow::Halt(EndReason::Unmodeled("tmp-addr segment".into()));
                };
                if segment == "fs" && a == 0x28 {
                    self.assign(dst, self.cfg.canary, *size);
                    OpFlow::Continue
                } else {
                    let v = self.read_mem(a, *size).unwrap_or(0);
                    self.assign(dst, v, *size);
                    OpFlow::Continue
                }
            }
            POp::CallOther { name } => OpFlow::Halt(EndReason::Trap(name.clone())),
            POp::Rotate {
                dst,
                a,
                b,
                size,
                left,
            } => {
                let sh = (ev!(self, b) % (*size as u64 * 8).max(1)) as u32;
                let x = mask(ev!(self, a), *size);
                let w = *size * 8;
                let v = if w == 0 {
                    x
                } else if *left {
                    mask((x << sh) | (x >> ((w - sh) % w)), *size)
                } else {
                    mask((x >> sh) | (x << ((w - sh) % w)), *size)
                };
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::Bswap { dst, src, size } => {
                let x = mask(ev!(self, src), *size);
                let mut v = 0u64;
                for i in 0..*size as u64 {
                    v |= ((x >> (8 * i)) & 0xFF) << (8 * (*size as u64 - 1 - i));
                }
                self.assign(dst, v, *size);
                OpFlow::Continue
            }
            POp::Unimplemented(text) => OpFlow::Halt(EndReason::Unmodeled(text.clone())),
        }
    }

    fn do_call(&mut self, target: u64, next_fall: u64) -> OpFlow {
        if let Some(name) = self.imports.get(&target).cloned() {
            return OpFlow::Halt(EndReason::CallToImport(name));
        }
        if !self.is_mapped_code(target) {
            return OpFlow::Halt(EndReason::UnmappedCall(target));
        }
        if self.call_stack.len() >= self.cfg.max_call_depth {
            return OpFlow::Halt(EndReason::UnmappedCall(target));
        }
        let ret = next_fall;
        self.call_stack.push(ret);
        let rsp2 = self.rsp.wrapping_sub(8);
        if !self.in_stack(rsp2, 8) {
            self.call_stack.pop();
            return OpFlow::Halt(EndReason::StackOverflow(rsp2));
        }
        self.paged_store(rsp2, ret, 8);
        self.stack_writes += 1;
        self.rsp = rsp2;
        OpFlow::Jump(target)
    }
}
