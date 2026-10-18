use super::config::EndReason;
use super::regs::Flags;

pub(crate) enum OpFlow {
    Continue,
    Jump(u64),
    Halt(EndReason),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ShiftKind {
    Left,
    Right,
    Sar,
}

#[inline]
pub(crate) fn shift_op(x: u64, count: u64, size: u32, kind: ShiftKind) -> (u64, bool, bool, bool) {
    if size == 0 {
        return (0, false, false, false);
    }
    let count_mask = if size <= 4 { 31u64 } else { 63u64 };
    let sh = (count & count_mask) as u32;
    let x = mask(x, size);
    if sh == 0 {
        return (x, false, false, false);
    }
    match kind {
        ShiftKind::Left => {
            let v = mask(x.wrapping_shl(sh), size);
            let width = (size * 8).min(64);
            let cf = if sh <= width {
                ((x >> (width - sh)) & 1) != 0
            } else {
                false
            };
            let of = if sh == 1 {
                sign_bit(v, size) != sign_bit(x, size)
            } else {
                false
            };
            (v, cf, of, true)
        }
        ShiftKind::Right => {
            let v = mask(x.wrapping_shr(sh), size);
            let cf = if sh <= 64 {
                ((x >> (sh - 1)) & 1) != 0
            } else {
                false
            };
            let of = if sh == 1 { sign_bit(x, size) } else { false };
            (v, cf, of, true)
        }
        ShiftKind::Sar => {
            let sx = sext(x, size);
            let v = mask(sx.wrapping_shr(sh) as u64, size);
            let cf = if sh <= 64 {
                ((x >> (sh - 1)) & 1) != 0
            } else {
                false
            };
            (v, cf, false, true)
        }
    }
}

#[inline]
pub(crate) fn mask(v: u64, size: u32) -> u64 {
    match size {
        0 => 0,
        1 => v & 0xFF,
        2 => v & 0xFFFF,
        4 => v & 0xFFFF_FFFF,
        8 => v,
        _ => {
            debug_assert!(false, "bad pcode size");
            v
        }
    }
}

#[inline]
pub(crate) fn int_min(size: u32) -> u64 {
    match size {
        0 => 0,
        1 => 0x80,
        2 => 0x8000,
        4 => 0x8000_0000,
        _ => 0x8000_0000_0000_0000,
    }
}

#[inline]
pub(crate) fn sign_bit(v: u64, size: u32) -> bool {
    match size {
        1 => v & 0x80 != 0,
        2 => v & 0x8000 != 0,
        4 => v & 0x8000_0000 != 0,
        _ => v & 0x8000_0000_0000_0000 != 0,
    }
}

#[inline]
pub(crate) fn sext(v: u64, size: u32) -> i64 {
    match size {
        1 => (v as u8) as i8 as i64,
        2 => (v as u16) as i16 as i64,
        4 => (v as u32) as i32 as i64,
        _ => v as i64,
    }
}

pub(crate) fn add_with_flags(x: u64, y: u64, size: u32) -> (u64, bool, bool) {
    let (x, y) = (mask(x, size), mask(y, size));
    let bits = (size * 8).min(64);
    let max: u128 = if bits >= 64 {
        u64::MAX as u128
    } else {
        (1u128 << bits) - 1
    };
    let full = (x as u128) + (y as u128);
    let v = mask(full as u64, size);
    let cf = full > max;
    let sx = sext(x, size);
    let sy = sext(y, size);
    let of = sx.checked_add(sy).is_none_or(|r| sext(v, size) != r);
    (v, cf, of)
}

pub(crate) fn sub_with_flags(x: u64, y: u64, size: u32) -> (u64, bool, bool) {
    let (x, y) = (mask(x, size), mask(y, size));
    let v = mask(x.wrapping_sub(y), size);
    let cf = x < y;
    let sx = sext(x, size);
    let sy = sext(y, size);
    let of = sx.checked_sub(sy).is_none_or(|r| sext(v, size) != r);
    (v, cf, of)
}

pub(crate) fn cond_nospace_eq(cond: &str, pat: &str) -> bool {
    let mut pi = pat.bytes();
    for b in cond.bytes() {
        if b == b' ' || b == b'\t' {
            continue;
        }
        match pi.next() {
            Some(p) => {
                if !p.eq_ignore_ascii_case(&b) {
                    return false;
                }
            }
            None => return false,
        }
    }
    pi.next().is_none()
}

pub(crate) fn eval_cond(cond: &str, f: &Flags, rcx: u64) -> Option<bool> {
    if cond.eq_ignore_ascii_case("je") || cond.eq_ignore_ascii_case("jz") {
        return Some(f.zf());
    }
    if cond.eq_ignore_ascii_case("jne") || cond.eq_ignore_ascii_case("jnz") {
        return Some(!f.zf());
    }
    if cond.eq_ignore_ascii_case("jl") || cond.eq_ignore_ascii_case("jnge") {
        return Some(f.sf() != f.of());
    }
    if cond.eq_ignore_ascii_case("jle") || cond.eq_ignore_ascii_case("jng") {
        return Some(f.zf() || f.sf() != f.of());
    }
    if cond.eq_ignore_ascii_case("jg") || cond.eq_ignore_ascii_case("jnle") {
        return Some(!f.zf() && f.sf() == f.of());
    }
    if cond.eq_ignore_ascii_case("jge") || cond.eq_ignore_ascii_case("jnl") {
        return Some(f.sf() == f.of());
    }
    if cond.eq_ignore_ascii_case("jb")
        || cond.eq_ignore_ascii_case("jnae")
        || cond.eq_ignore_ascii_case("jc")
    {
        return Some(f.cf());
    }
    if cond.eq_ignore_ascii_case("jbe") || cond.eq_ignore_ascii_case("jna") {
        return Some(f.cf() || f.zf());
    }
    if cond.eq_ignore_ascii_case("ja") || cond.eq_ignore_ascii_case("jnbe") {
        return Some(!f.cf() && !f.zf());
    }
    if cond.eq_ignore_ascii_case("jae")
        || cond.eq_ignore_ascii_case("jnb")
        || cond.eq_ignore_ascii_case("jnc")
    {
        return Some(!f.cf());
    }
    if cond.eq_ignore_ascii_case("js") {
        return Some(f.sf());
    }
    if cond.eq_ignore_ascii_case("jns") {
        return Some(!f.sf());
    }
    if cond.eq_ignore_ascii_case("jo") {
        return Some(f.of());
    }
    if cond.eq_ignore_ascii_case("jno") {
        return Some(!f.of());
    }
    if cond.eq_ignore_ascii_case("jp") || cond.eq_ignore_ascii_case("jpe") {
        return Some(f.pf());
    }
    if cond.eq_ignore_ascii_case("jnp") || cond.eq_ignore_ascii_case("jpo") {
        return Some(!f.pf());
    }
    if cond.eq_ignore_ascii_case("jcxz") {
        return Some(rcx & 0xFFFF == 0);
    }
    if cond.eq_ignore_ascii_case("jecxz") {
        return Some(rcx & 0xFFFF_FFFF == 0);
    }
    if cond.eq_ignore_ascii_case("jrcxz") {
        return Some(rcx == 0);
    }
    if cond.eq_ignore_ascii_case("zf") {
        return Some(f.zf());
    }
    if cond.eq_ignore_ascii_case("!zf") {
        return Some(!f.zf());
    }
    if cond.eq_ignore_ascii_case("cf") {
        return Some(f.cf());
    }
    if cond.eq_ignore_ascii_case("!cf") {
        return Some(!f.cf());
    }
    if cond.eq_ignore_ascii_case("sf") {
        return Some(f.sf());
    }
    if cond.eq_ignore_ascii_case("!sf") {
        return Some(!f.sf());
    }
    if cond.eq_ignore_ascii_case("of") {
        return Some(f.of());
    }
    if cond.eq_ignore_ascii_case("pf") {
        return Some(f.pf());
    }
    if cond.eq_ignore_ascii_case("!pf") {
        return Some(!f.pf());
    }
    if cond_nospace_eq(cond, "(SF!=OF)") {
        return Some(f.sf() != f.of());
    }
    if cond_nospace_eq(cond, "(SF!=OF)||ZF") {
        return Some(f.sf() != f.of() || f.zf());
    }
    if cond_nospace_eq(cond, "(SF==OF)&&!ZF") {
        return Some(f.sf() == f.of() && !f.zf());
    }
    if cond_nospace_eq(cond, "(SF==OF)") {
        return Some(f.sf() == f.of());
    }
    if cond_nospace_eq(cond, "CF||ZF") {
        return Some(f.cf() || f.zf());
    }
    if cond_nospace_eq(cond, "!CF&&!ZF") {
        return Some(!f.cf() && !f.zf());
    }
    None
}
