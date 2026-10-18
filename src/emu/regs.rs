#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Flags(u8);

impl Flags {
    pub(crate) const ZF: u8 = 1 << 0;
    pub(crate) const SF: u8 = 1 << 1;
    pub(crate) const CF: u8 = 1 << 2;
    pub(crate) const OF: u8 = 1 << 3;
    pub(crate) const PF: u8 = 1 << 4;

    #[inline]
    pub(crate) fn zf(&self) -> bool {
        self.0 & Self::ZF != 0
    }
    #[inline]
    pub(crate) fn sf(&self) -> bool {
        self.0 & Self::SF != 0
    }
    #[inline]
    pub(crate) fn cf(&self) -> bool {
        self.0 & Self::CF != 0
    }
    #[inline]
    pub(crate) fn of(&self) -> bool {
        self.0 & Self::OF != 0
    }
    #[inline]
    pub(crate) fn pf(&self) -> bool {
        self.0 & Self::PF != 0
    }
    #[inline]
    pub(crate) fn set(&mut self, mask: u8, v: bool) {
        if v {
            self.0 |= mask;
        } else {
            self.0 &= !mask;
        }
    }
}

pub(crate) const R_RAX: usize = 0;
pub(crate) const R_RBX: usize = 1;
pub(crate) const R_RCX: usize = 2;
pub(crate) const R_RDX: usize = 3;
pub(crate) const R_RSI: usize = 4;
pub(crate) const R_RDI: usize = 5;
pub(crate) const R_RBP: usize = 6;
pub(crate) const R_R8: usize = 7;
pub(crate) const R_R9: usize = 8;
pub(crate) const R_R10: usize = 9;
pub(crate) const R_R11: usize = 10;
pub(crate) const R_R12: usize = 11;
pub(crate) const R_R13: usize = 12;
pub(crate) const R_R14: usize = 13;
pub(crate) const R_R15: usize = 14;
pub(crate) const R_XMM_BASE: usize = 16;
pub(crate) const N_REGS: usize = 32;
pub(crate) const RSP_SENTINEL: usize = usize::MAX;

pub(crate) type RegPart = (usize, u64, u32, bool, bool);

#[inline]
pub(crate) fn pack_reg_name(b: &[u8]) -> u64 {
    debug_assert!(b.len() <= 4);
    let mut key = (b.len() as u64) << 32;
    for (i, &c) in b.iter().enumerate() {
        key |= (c.to_ascii_lowercase() as u64) << (8 * i);
    }
    key
}

#[inline]
pub(crate) fn gpr_part(key: u64) -> Option<RegPart> {
    match key {
        0x0200006861 => Some((R_RAX, 1, 1, false, false)),
        0x0200006C61 => Some((R_RAX, 0, 1, false, false)),
        0x0200007861 => Some((R_RAX, 0, 2, false, false)),
        0x0200006862 => Some((R_RBX, 1, 1, false, false)),
        0x0200006C62 => Some((R_RBX, 0, 1, false, false)),
        0x0200007062 => Some((R_RBP, 0, 2, false, false)),
        0x0200007862 => Some((R_RBX, 0, 2, false, false)),
        0x0200006863 => Some((R_RCX, 1, 1, false, false)),
        0x0200006C63 => Some((R_RCX, 0, 1, false, false)),
        0x0200007863 => Some((R_RCX, 0, 2, false, false)),
        0x0200006864 => Some((R_RDX, 1, 1, false, false)),
        0x0200006964 => Some((R_RDI, 0, 2, false, false)),
        0x0200006C64 => Some((R_RDX, 0, 1, false, false)),
        0x0200007864 => Some((R_RDX, 0, 2, false, false)),
        0x0200003872 => Some((R_R8, 0, 8, false, false)),
        0x0200003972 => Some((R_R9, 0, 8, false, false)),
        0x0200006973 => Some((R_RSI, 0, 2, false, false)),
        0x0200007073 => Some((RSP_SENTINEL, 0, 2, false, false)),
        0x03006C7062 => Some((R_RBP, 0, 1, false, false)),
        0x03006C6964 => Some((R_RDI, 0, 1, false, false)),
        0x0300786165 => Some((R_RAX, 0, 4, true, false)),
        0x0300706265 => Some((R_RBP, 0, 4, true, false)),
        0x0300786265 => Some((R_RBX, 0, 4, true, false)),
        0x0300786365 => Some((R_RCX, 0, 4, true, false)),
        0x0300696465 => Some((R_RDI, 0, 4, true, false)),
        0x0300786465 => Some((R_RDX, 0, 4, true, false)),
        0x0300697365 => Some((R_RSI, 0, 4, true, false)),
        0x0300707365 => Some((RSP_SENTINEL, 0, 4, true, false)),
        0x0300303172 => Some((R_R10, 0, 8, false, false)),
        0x0300313172 => Some((R_R11, 0, 8, false, false)),
        0x0300323172 => Some((R_R12, 0, 8, false, false)),
        0x0300333172 => Some((R_R13, 0, 8, false, false)),
        0x0300343172 => Some((R_R14, 0, 8, false, false)),
        0x0300353172 => Some((R_R15, 0, 8, false, false)),
        0x0300623872 => Some((R_R8, 0, 1, false, false)),
        0x0300643872 => Some((R_R8, 0, 4, true, false)),
        0x0300773872 => Some((R_R8, 0, 2, false, false)),
        0x0300623972 => Some((R_R9, 0, 1, false, false)),
        0x0300643972 => Some((R_R9, 0, 4, true, false)),
        0x0300773972 => Some((R_R9, 0, 2, false, false)),
        0x0300786172 => Some((R_RAX, 0, 8, false, false)),
        0x0300706272 => Some((R_RBP, 0, 8, false, false)),
        0x0300786272 => Some((R_RBX, 0, 8, false, false)),
        0x0300786372 => Some((R_RCX, 0, 8, false, false)),
        0x0300696472 => Some((R_RDI, 0, 8, false, false)),
        0x0300786472 => Some((R_RDX, 0, 8, false, false)),
        0x0300697372 => Some((R_RSI, 0, 8, false, false)),
        0x0300707372 => Some((RSP_SENTINEL, 0, 8, false, false)),
        0x03006C6973 => Some((R_RSI, 0, 1, false, false)),
        0x03006C7073 => Some((RSP_SENTINEL, 0, 1, false, false)),
        0x0462303172 => Some((R_R10, 0, 1, false, false)),
        0x0464303172 => Some((R_R10, 0, 4, true, false)),
        0x0477303172 => Some((R_R10, 0, 2, false, false)),
        0x0462313172 => Some((R_R11, 0, 1, false, false)),
        0x0464313172 => Some((R_R11, 0, 4, true, false)),
        0x0477313172 => Some((R_R11, 0, 2, false, false)),
        0x0462323172 => Some((R_R12, 0, 1, false, false)),
        0x0464323172 => Some((R_R12, 0, 4, true, false)),
        0x0477323172 => Some((R_R12, 0, 2, false, false)),
        0x0462333172 => Some((R_R13, 0, 1, false, false)),
        0x0464333172 => Some((R_R13, 0, 4, true, false)),
        0x0477333172 => Some((R_R13, 0, 2, false, false)),
        0x0462343172 => Some((R_R14, 0, 1, false, false)),
        0x0464343172 => Some((R_R14, 0, 4, true, false)),
        0x0477343172 => Some((R_R14, 0, 2, false, false)),
        0x0462353172 => Some((R_R15, 0, 1, false, false)),
        0x0464353172 => Some((R_R15, 0, 4, true, false)),
        0x0477353172 => Some((R_R15, 0, 2, false, false)),
        _ => None,
    }
}

#[inline]
pub(crate) fn reg_part(name: &str) -> Option<RegPart> {
    let b = name.as_bytes();
    if b.len() <= 4 {
        if let Some(r) = gpr_part(pack_reg_name(b)) {
            return Some(r);
        }
    }
    if b.len() >= 4 {
        let vec_prefix = (b[0] == b'x'
            || b[0] == b'X'
            || b[0] == b'y'
            || b[0] == b'Y'
            || b[0] == b'Z'
            || b[0] == b'z')
            && (b[1] == b'm' || b[1] == b'M')
            && (b[2] == b'm' || b[2] == b'M');
        if vec_prefix {
            let mut n: usize = 0;
            let mut digits = 0usize;
            for &d in &b[3..] {
                if !d.is_ascii_digit() {
                    return None;
                }
                n = n * 10 + (d - b'0') as usize;
                digits += 1;
            }
            if digits > 0 && n < 16 {
                return Some((R_XMM_BASE + n, 0, 8, false, true));
            }
            return None;
        }
    }
    None
}
