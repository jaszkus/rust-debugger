use rustc_hash::FxHashMap as HashMap;

use super::alu::{int_min, mask, sign_bit};
use super::config::{EndReason, MemWrite};
use super::exec::Emulator;
use super::regs::{reg_part, Flags, RSP_SENTINEL, R_RBP};
use crate::analysis::pcode::PVar;

pub(crate) const PAGE_SHIFT: u32 = 12;
pub(crate) const PAGE_SIZE: usize = 4096;
pub(crate) const PAGE_MASK: u64 = (PAGE_SIZE as u64) - 1;
pub(crate) const LIFTED_CAP: usize = 4096;
pub(crate) const TRACE_CAP: usize = 64;
pub(crate) const MAPPED_MEMO_CAP: usize = 8192;

pub(crate) type Page = Box<[u8; PAGE_SIZE]>;

#[inline]
pub(crate) fn page_of(addr: u64) -> u64 {
    addr >> PAGE_SHIFT
}

#[inline]
pub(crate) fn new_page() -> Page {
    Box::new([0u8; PAGE_SIZE])
}

pub(crate) fn copy_into_pages(mem: &mut HashMap<u64, Page>, vaddr: u64, data: &[u8]) {
    let mut addr = vaddr;
    let mut rest = data;
    while !rest.is_empty() {
        let off = (addr & PAGE_MASK) as usize;
        let n = (PAGE_SIZE - off).min(rest.len());
        let (head, tail) = rest.split_at(n);
        mem.entry(page_of(addr)).or_insert_with(new_page)[off..off + n].copy_from_slice(head);
        addr = addr.wrapping_add(n as u64);
        rest = tail;
    }
}

#[inline]
pub(crate) fn f2i_trunc(f: f64, size: u32) -> u64 {
    let bits = (size.max(1) * 8).min(64);
    let hi = (1u64 << (bits - 1)) as f64;
    let t = f.trunc();
    if t >= -hi && t < hi {
        mask(t as i64 as u64, size)
    } else {
        int_min(size)
    }
}

impl<'a> Emulator<'a> {
    #[inline]
    pub(crate) fn find_region(&self, addr: u64) -> Option<usize> {
        if let Some(i) = self.region_cache.get()
            && let Some(&(base, size, _)) = self.regions.get(i)
                && addr >= base && addr < base.wrapping_add(size) {
                    return Some(i);
                }
        let n = self.regions.partition_point(|(base, _, _)| *base <= addr);
        let idx = n.checked_sub(1).filter(|&i| {
            let (base, size, _) = self.regions[i];
            addr < base.wrapping_add(size)
        });
        self.region_cache.set(idx);
        idx
    }

    pub(crate) fn is_mapped_code(&mut self, addr: u64) -> bool {
        if let Some(&hit) = self.mapped_memo.get(&addr) {
            return hit;
        }
        let hit = match self.find_region(addr) {
            Some(i) => (self.regions[i].2 & 1) != 0,
            None => false,
        };
        if self.mapped_memo.len() < MAPPED_MEMO_CAP {
            self.mapped_memo.insert(addr, hit);
        }
        hit
    }

    #[inline]
    pub(crate) fn region_allows(&self, addr: u64, size: u32, perm: u8) -> bool {
        if size == 0 {
            return true;
        }
        if self.in_stack(addr, size) {
            return true;
        }
        let end = addr.saturating_add(size as u64);
        match self.find_region(addr) {
            Some(i) => {
                let (base, sz, rwx) = self.regions[i];
                (rwx & perm) != 0 && end <= base.wrapping_add(sz)
            }
            None => false,
        }
    }

    pub(crate) fn is_readable(&self, addr: u64, size: u32) -> bool {
        self.region_allows(addr, size, 4)
    }

    pub(crate) fn is_writable(&self, addr: u64, size: u32) -> bool {
        self.region_allows(addr, size, 2)
    }

    pub(crate) fn in_stack(&self, addr: u64, size: u32) -> bool {
        let lo = self.cfg.stack_top.saturating_sub(self.cfg.stack_size);
        addr >= lo && addr.saturating_add(size as u64) <= self.cfg.stack_top
    }

    pub(crate) fn eval(&self, v: &PVar) -> Result<u64, EndReason> {
        match v {
            PVar::Reg(r) => Ok(self.reg_value(r)),
            PVar::Const(c) => Ok(*c as u64),
            PVar::StackSlot { base, off } => {
                let b = match base {
                    crate::analysis::pcode::StackBase::Rbp => self.regs[R_RBP],
                    crate::analysis::pcode::StackBase::Rsp => self.rsp,
                };
                Ok(b.wrapping_add(*off as u64))
            }
            PVar::Mem(_, _) | PVar::Scaled { .. } => {
                let Some(a) = self.eval_addr_opt(v) else {
                    return Err(EndReason::Unmodeled("tmp-addr load".into()));
                };
                self.read_mem(a, 8)
            }
            PVar::Addr(a) => Ok(*a),
            PVar::Tmp(id) => Ok(self.tmp_get(*id)),
        }
    }

    pub(crate) fn eval_addr_opt(&self, v: &PVar) -> Option<u64> {
        match v {
            PVar::Reg(r) => Some(self.reg_value(r)),
            PVar::Const(c) => Some(*c as u64),
            PVar::StackSlot { base, off } => {
                let b = match base {
                    crate::analysis::pcode::StackBase::Rbp => self.regs[R_RBP],
                    crate::analysis::pcode::StackBase::Rsp => self.rsp,
                };
                Some(b.wrapping_add(*off as u64))
            }
            PVar::Mem(b, d) => {
                let base = match b.as_ref() {
                    PVar::Reg(r) => self.reg_value(r),
                    PVar::Const(c) => *c as u64,
                    PVar::Addr(a) => *a,
                    _ => return None,
                };
                Some(base.wrapping_add(*d as u64))
            }
            PVar::Scaled {
                base,
                index,
                scale,
                disp,
            } => {
                let b = self.eval_addr_opt(base)?;
                let i = self.eval_addr_opt(index)?;
                Some(
                    b.wrapping_add(i.wrapping_mul(*scale as u64))
                        .wrapping_add(*disp as u64),
                )
            }
            PVar::Addr(a) => Some(*a),
            PVar::Tmp(_) => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn eval_addr(&self, v: &PVar) -> u64 {
        self.eval_addr_opt(v).unwrap_or(0)
    }

    #[inline]
    pub(crate) fn reg_value(&self, name: &str) -> u64 {
        match reg_part(name) {
            Some((slot, off, sz, _, _)) => {
                let cur = if slot == RSP_SENTINEL {
                    self.rsp
                } else {
                    self.regs[slot]
                };
                let mb = if sz >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (sz * 8)) - 1
                };
                (cur >> (off * 8)) & mb
            }
            None => self.ext_regs.get(name).copied().unwrap_or(0),
        }
    }

    #[inline]
    pub(crate) fn tmp_get(&self, id: u32) -> u64 {
        self.tmps.get(id as usize).copied().unwrap_or(0)
    }

    #[inline]
    pub(crate) fn tmp_set(&mut self, id: u32, v: u64) {
        let i = id as usize;
        if i >= self.tmps.len() {
            self.tmps.resize(i + 1, 0);
        }
        self.tmps[i] = v;
    }

    pub(crate) fn assign(&mut self, dst: &PVar, mut v: u64, size: u32) {
        match dst {
            PVar::Reg(r) => {
                let Some((slot, off, sz, zero_ext, is_lane)) = reg_part(r) else {
                    let val = mask(v, size.max(1));
                    let name: &str = r;
                    if let Some(slot) = self.ext_regs.get_mut(name) {
                        *slot = val;
                    } else {
                        self.ext_regs.insert(name.to_string(), val);
                    }
                    return;
                };
                if slot == RSP_SENTINEL {
                    let fw = sz.max(size);
                    v = mask(v, fw);
                    let mask_bits = if fw >= 8 {
                        u64::MAX
                    } else {
                        (1u64 << (fw * 8)) - 1
                    };
                    let mut nv =
                        (self.rsp & !(mask_bits << (off * 8))) | ((v & mask_bits) << (off * 8));
                    if zero_ext {
                        nv &= 0xFFFF_FFFF;
                    }
                    self.rsp = nv;
                    return;
                }
                let fw = if is_lane {
                    sz.min(size).max(1)
                } else {
                    sz.max(size)
                };
                v = mask(v, fw);
                let cur = self.regs[slot];
                let mask_bits = if fw >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (fw * 8)) - 1
                };
                let mut nv = (cur & !(mask_bits << (off * 8))) | ((v & mask_bits) << (off * 8));
                if zero_ext {
                    nv &= 0xFFFF_FFFF;
                }
                self.regs[slot] = nv;
            }
            PVar::Tmp(id) => {
                self.tmp_set(*id, mask(v, size.max(1)));
            }
            _ => {
                debug_assert!(false, "assign to unmodeled dst");
            }
        }
    }

    pub(crate) fn reg_width(&self, v: &PVar) -> u32 {
        match v {
            PVar::Reg(r) => reg_part(r).map(|(_, _, sz, _, _)| sz.max(1)).unwrap_or(8),
            _ => 8,
        }
    }

    #[inline]
    pub(crate) fn paged_load(&self, addr: u64, size: u32) -> (u64, bool) {
        let sz = (size as usize).min(8);
        let off = (addr & PAGE_MASK) as usize;
        if off + sz <= PAGE_SIZE {
            match self.mem.get(&page_of(addr)) {
                Some(p) => {
                    let mut buf = [0u8; 8];
                    buf[..sz].copy_from_slice(&p[off..off + sz]);
                    (u64::from_le_bytes(buf), false)
                }
                None => (0, true),
            }
        } else {
            let mut v = 0u64;
            let mut missing = false;
            for i in 0..sz {
                let a = addr.wrapping_add(i as u64);
                match self.mem.get(&page_of(a)) {
                    Some(p) => v |= (p[(a & PAGE_MASK) as usize] as u64) << (8 * i),
                    None => missing = true,
                }
            }
            (v, missing)
        }
    }

    #[inline]
    pub(crate) fn paged_store(&mut self, addr: u64, v: u64, size: u32) {
        let sz = (size as usize).min(8);
        let bytes = v.to_le_bytes();
        let off = (addr & PAGE_MASK) as usize;
        if off + sz <= PAGE_SIZE {
            let p = self.mem.entry(page_of(addr)).or_insert_with(new_page);
            p[off..off + sz].copy_from_slice(&bytes[..sz]);
        } else {
            for (i, &byte) in bytes.iter().enumerate().take(sz) {
                let a = addr.wrapping_add(i as u64);
                let o = (a & PAGE_MASK) as usize;
                self.mem.entry(page_of(a)).or_insert_with(new_page)[o] = byte;
            }
        }
    }

    pub(crate) fn read_mem(&self, addr: u64, size: u32) -> Result<u64, EndReason> {
        if size == 0 {
            return Ok(0);
        }
        if self.in_stack(addr, size) {
            return Ok(self.paged_load(addr, size).0);
        }
        if !self.is_readable(addr, size) {
            return Err(EndReason::OobRead(addr));
        }
        let (v, missing) = self.paged_load(addr, size);
        if missing && self.cfg.strict_uninit {
            return Err(EndReason::UninitRead(addr));
        }
        Ok(v)
    }

    pub(crate) fn write_mem(&mut self, addr: u64, v: u64, size: u32) -> Result<(), EndReason> {
        if size == 0 {
            return Ok(());
        }
        if self.in_stack(addr, size) {
            self.paged_store(addr, v, size);
            self.stack_writes += 1;
            return Ok(());
        }
        if !self.is_writable(addr, size) {
            return Err(EndReason::OobWrite(addr));
        }
        let old = self.paged_load(addr, size).0;
        self.paged_store(addr, v, size);
        if self.writes.len() < self.cfg.max_writes {
            self.writes.push(MemWrite {
                addr,
                size,
                old,
                new: mask(v, size),
            });
        } else {
            self.dropped_writes += 1;
        }
        Ok(())
    }

    pub(crate) fn set_arith_flags(&mut self, v: u64, size: u32, cf: bool, of: bool) {
        let v = mask(v, size);
        self.flags.set(Flags::ZF, v == 0);
        self.flags.set(Flags::SF, sign_bit(v, size));
        self.flags.set(Flags::CF, cf);
        self.flags.set(Flags::OF, of);
        self.flags
            .set(Flags::PF, (v as u8).count_ones().is_multiple_of(2));
    }

    pub(crate) fn set_logic_flags(&mut self, v: u64, size: u32) {
        self.set_arith_flags(v, size, false, false);
    }
}
