pub mod alu;
pub mod config;
pub mod exec;
pub mod mem;
pub mod regs;

pub use config::{EmuConfig, EmuResult, EndReason, MemWrite};
pub use exec::Emulator;

#[cfg(test)]
pub(crate) use alu::*;
#[cfg(test)]
pub(crate) use mem::*;
#[cfg(test)]
pub(crate) use regs::*;
#[cfg(test)]
use rustc_hash::FxHashMap as HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_truncates() {
        assert_eq!(mask(0x1FF, 1), 0xFF);
        assert_eq!(mask(0x1_FFFF, 2), 0xFFFF);
        assert_eq!(mask(u64::MAX, 4), 0xFFFF_FFFF);
        assert_eq!(mask(u64::MAX, 8), u64::MAX);
    }

    #[test]
    fn add_flags_carry_overflow() {
        let (v, cf, of) = add_with_flags(0xFF, 0x01, 1);
        assert_eq!(v, 0);
        assert!(cf);
        assert!(!of);
        let (_, _, of2) = add_with_flags(0x7F, 0x01, 1);
        assert!(of2);
    }

    #[test]
    fn sub_flags_borrow() {
        let (v, cf, _) = sub_with_flags(0, 1, 8);
        assert_eq!(v, u64::MAX);
        assert!(cf);
    }

    #[test]
    fn cond_unknown_is_none() {
        let f = Flags::default();
        assert_eq!(eval_cond("jz", &f, 0), Some(false));
        assert_eq!(eval_cond("cond", &f, 0), None);
        assert_eq!(eval_cond("bogus-cc", &f, 0), None);
    }

    #[test]
    fn int_min_widths() {
        assert_eq!(int_min(1), 0x80);
        assert_eq!(int_min(4), 0x8000_0000);
        assert_eq!(int_min(8), 0x8000_0000_0000_0000);
    }

    const REG_EXPECT: &[(&str, RegPart)] = &[
        ("rax", (R_RAX, 0, 8, false, false)),
        ("rcx", (R_RCX, 0, 8, false, false)),
        ("rdx", (R_RDX, 0, 8, false, false)),
        ("rsi", (R_RSI, 0, 8, false, false)),
        ("rdi", (R_RDI, 0, 8, false, false)),
        ("rsp", (RSP_SENTINEL, 0, 8, false, false)),
        ("rbp", (R_RBP, 0, 8, false, false)),
        ("rbx", (R_RBX, 0, 8, false, false)),
        ("r8", (R_R8, 0, 8, false, false)),
        ("r9", (R_R9, 0, 8, false, false)),
        ("r10", (R_R10, 0, 8, false, false)),
        ("r11", (R_R11, 0, 8, false, false)),
        ("r12", (R_R12, 0, 8, false, false)),
        ("r13", (R_R13, 0, 8, false, false)),
        ("r14", (R_R14, 0, 8, false, false)),
        ("r15", (R_R15, 0, 8, false, false)),
        ("eax", (R_RAX, 0, 4, true, false)),
        ("ebx", (R_RBX, 0, 4, true, false)),
        ("ecx", (R_RCX, 0, 4, true, false)),
        ("edx", (R_RDX, 0, 4, true, false)),
        ("esi", (R_RSI, 0, 4, true, false)),
        ("edi", (R_RDI, 0, 4, true, false)),
        ("ebp", (R_RBP, 0, 4, true, false)),
        ("esp", (RSP_SENTINEL, 0, 4, true, false)),
        ("r8d", (R_R8, 0, 4, true, false)),
        ("r9d", (R_R9, 0, 4, true, false)),
        ("r10d", (R_R10, 0, 4, true, false)),
        ("r11d", (R_R11, 0, 4, true, false)),
        ("r12d", (R_R12, 0, 4, true, false)),
        ("r13d", (R_R13, 0, 4, true, false)),
        ("r14d", (R_R14, 0, 4, true, false)),
        ("r15d", (R_R15, 0, 4, true, false)),
        ("ax", (R_RAX, 0, 2, false, false)),
        ("bx", (R_RBX, 0, 2, false, false)),
        ("cx", (R_RCX, 0, 2, false, false)),
        ("dx", (R_RDX, 0, 2, false, false)),
        ("si", (R_RSI, 0, 2, false, false)),
        ("di", (R_RDI, 0, 2, false, false)),
        ("bp", (R_RBP, 0, 2, false, false)),
        ("sp", (RSP_SENTINEL, 0, 2, false, false)),
        ("r8w", (R_R8, 0, 2, false, false)),
        ("r9w", (R_R9, 0, 2, false, false)),
        ("r10w", (R_R10, 0, 2, false, false)),
        ("r11w", (R_R11, 0, 2, false, false)),
        ("r12w", (R_R12, 0, 2, false, false)),
        ("r13w", (R_R13, 0, 2, false, false)),
        ("r14w", (R_R14, 0, 2, false, false)),
        ("r15w", (R_R15, 0, 2, false, false)),
        ("al", (R_RAX, 0, 1, false, false)),
        ("bl", (R_RBX, 0, 1, false, false)),
        ("cl", (R_RCX, 0, 1, false, false)),
        ("dl", (R_RDX, 0, 1, false, false)),
        ("sil", (R_RSI, 0, 1, false, false)),
        ("dil", (R_RDI, 0, 1, false, false)),
        ("bpl", (R_RBP, 0, 1, false, false)),
        ("spl", (RSP_SENTINEL, 0, 1, false, false)),
        ("r8b", (R_R8, 0, 1, false, false)),
        ("r9b", (R_R9, 0, 1, false, false)),
        ("r10b", (R_R10, 0, 1, false, false)),
        ("r11b", (R_R11, 0, 1, false, false)),
        ("r12b", (R_R12, 0, 1, false, false)),
        ("r13b", (R_R13, 0, 1, false, false)),
        ("r14b", (R_R14, 0, 1, false, false)),
        ("r15b", (R_R15, 0, 1, false, false)),
        ("ah", (R_RAX, 1, 1, false, false)),
        ("bh", (R_RBX, 1, 1, false, false)),
        ("ch", (R_RCX, 1, 1, false, false)),
        ("dh", (R_RDX, 1, 1, false, false)),
    ];

    #[test]
    fn reg_part_matches_legacy_table() {
        for &(name, want) in REG_EXPECT {
            assert_eq!(reg_part(name), Some(want), "{name}");
            assert_eq!(
                reg_part(&name.to_ascii_uppercase()),
                Some(want),
                "{name} upper"
            );
        }
    }

    #[test]
    fn reg_part_vectors_and_unknowns() {
        assert_eq!(reg_part("xmm0"), Some((R_XMM_BASE, 0, 8, false, true)));
        assert_eq!(
            reg_part("XMM15"),
            Some((R_XMM_BASE + 15, 0, 8, false, true))
        );
        assert_eq!(reg_part("ymm3"), Some((R_XMM_BASE + 3, 0, 8, false, true)));
        assert_eq!(reg_part("zmm9"), Some((R_XMM_BASE + 9, 0, 8, false, true)));
        assert_eq!(reg_part("xmm16"), None);
        assert_eq!(reg_part("xmm"), None);
        assert_eq!(reg_part("xmmx"), None);
        assert_eq!(reg_part("rip"), None);
        assert_eq!(reg_part("r8l"), None);
        assert_eq!(reg_part("ax\0"), None);
        assert_eq!(reg_part(""), None);
    }

    #[test]
    fn cvtt_out_of_range_is_int_min() {
        assert_eq!(f2i_trunc(3.9, 4), 3);
        assert_eq!(f2i_trunc(-3.9, 4), (-3i64) as u64 & 0xFFFF_FFFF);
        assert_eq!(f2i_trunc(2147483647.0, 4), 0x7FFF_FFFF);
        assert_eq!(f2i_trunc(-2147483648.0, 4), 0x8000_0000);
        assert_eq!(f2i_trunc(3_000_000_000.0, 4), 0x8000_0000);
        assert_eq!(f2i_trunc(f64::NAN, 4), 0x8000_0000);
        assert_eq!(f2i_trunc(-1.0, 8), u64::MAX);
        assert_eq!(f2i_trunc(1e19, 8), 0x8000_0000_0000_0000);
        assert_eq!(
            f2i_trunc(-9.223_372_036_854_776e18, 8),
            0x8000_0000_0000_0000
        );
        assert_eq!(f2i_trunc(f64::INFINITY, 8), 0x8000_0000_0000_0000);
        assert_eq!(f2i_trunc(f64::NEG_INFINITY, 4), 0x8000_0000);
    }

    #[test]
    fn copy_into_pages_spans_boundaries() {
        let mut mem: HashMap<u64, Page> = HashMap::default();
        let data: Vec<u8> = (0..PAGE_SIZE + 100).map(|i| (i % 251) as u8).collect();
        let base = 0x40_0000u64 + PAGE_SIZE as u64 - 10;
        copy_into_pages(&mut mem, base, &data);
        assert_eq!(mem.len(), 3);
        for (i, &b) in data.iter().enumerate() {
            let a = base + i as u64;
            let p = mem.get(&page_of(a)).expect("page present");
            assert_eq!(p[(a & PAGE_MASK) as usize], b, "byte {i}");
        }
        let mut empty: HashMap<u64, Page> = HashMap::default();
        copy_into_pages(&mut empty, 0x1000, &[]);
        assert!(empty.is_empty());
    }
}
