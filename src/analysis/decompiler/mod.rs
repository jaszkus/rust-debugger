pub mod expr;
pub mod lifting;
pub mod pcode;
pub mod printing;
pub mod structure;

pub use lifting::{decompile, LiftInput};
pub use printing::render_pseudocode;

#[allow(unused_imports)]
pub(crate) use printing::{binop_render, mentions_reg, pval_str, track, PVal, TypeHints};

#[allow(unused_imports)]
use crate::disasm::DisasmInstruction;
#[allow(unused_imports)]
use pcode::{PInstr, POp, PVar, CALL_CLOBBERED};
#[allow(unused_imports)]
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Pseudocode {
    pub func_entry: u64,
    pub func_name: String,
    pub lines: Vec<PseudoLine>,
}

#[derive(Debug, Clone)]
pub struct PseudoLine {
    pub indent: u32,
    pub text: String,
    pub kind: LineKind,
    pub source_addr: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LineKind {
    Signature,
    Declaration,
    Assignment,
    Call,
    Return,
    Branch,
    Label,
    Comment,
    OpenBrace,
    CloseBrace,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Lattice {
    Top,
    Const(i64),
    Var(&'static str),
}

#[inline]
pub(crate) fn imap_get(imap: &[DisasmInstruction], addr: u64) -> Option<&DisasmInstruction> {
    let idx = imap.partition_point(|i| i.address < addr);
    imap.get(idx).filter(|i| i.address == addr)
}

pub const MAX_DECOMP_BLOCKS: usize = 5_000;
pub const MAX_DECOMP_LINES: usize = 200_000;
pub const MAX_DECOMP_BYTES: usize = 16 * 1024 * 1024;
pub const BIG_STACK_BLOCKS: usize = 200;
pub const BIG_STACK_SIZE: usize = 256 << 20;
pub(crate) const MAX_TRACKED_EXPR: usize = 4096;

thread_local! {
    pub(crate) static EXPR_OVERFLOWS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod oom_tests {
    use super::*;

    #[test]
    fn self_doubling_chain_stays_bounded() {
        let hints = TypeHints::default();
        let mut rv: HashMap<&'static str, PVal> = HashMap::default();
        let rax = PVar::Reg("rax");
        let mut max_line = 0usize;
        for _ in 0..64 {
            let (text, _) = binop_render(&mut rv, &rax, &rax, &rax, "+", &hints).unwrap();
            max_line = max_line.max(text.len());
        }
        assert!(max_line < 4 * MAX_TRACKED_EXPR, "max_line={}", max_line);
        assert!(matches!(
            rv.get("rax"),
            Some(PVal::Opaque(_)) | Some(PVal::X(_))
        ));
    }

    #[test]
    fn overwritten_reg_invalidates_dependents() {
        let mut rv: HashMap<&'static str, PVal> = HashMap::default();
        let rax = PVar::Reg("rax");
        let rcx = PVar::Reg("rcx");
        track(&mut rv, &rcx, PVal::E("rax".into()));
        track(&mut rv, &rax, PVal::C(5));
        assert!(matches!(rv.get("rcx"), Some(PVal::Opaque("rcx"))));
        assert_eq!(pval_str(rv.get("rax").unwrap()), "5");
        assert!(!mentions_reg(&PVal::E("r10".into()), "r1"));
        assert!(mentions_reg(&PVal::E("rax + rbx".into()), "rbx"));
        assert!(!mentions_reg(&PVal::E("rax + rbx".into()), "rcx"));
    }
}
