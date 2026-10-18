use rustc_hash::FxHashSet;
use std::cell::RefCell;
use std::sync::{Mutex, OnceLock};

thread_local! {
    static LOCAL_NAMES: RefCell<FxHashSet<&'static str>> = RefCell::new(FxHashSet::default());
}

fn intern_global(s: &str) -> &'static str {
    static GLOBAL: OnceLock<Mutex<FxHashSet<&'static str>>> = OnceLock::new();
    let set = GLOBAL.get_or_init(|| Mutex::new(FxHashSet::default()));
    let mut guard = match set.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(v) = guard.get(s) {
        return v;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    guard.insert(leaked);
    leaked
}

fn intern_static(s: &str) -> &'static str {
    LOCAL_NAMES.with(|local| {
        if let Some(v) = local.borrow().get(s) {
            return *v;
        }
        let v = intern_global(s);
        local.borrow_mut().insert(v);
        v
    })
}

pub(crate) fn intern_static_lower(s: &str) -> &'static str {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        intern_static(&s.to_ascii_lowercase())
    } else {
        intern_static(s)
    }
}

pub const ADDR_THRESHOLD: u64 = 0x10000;

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Reg(&'static str),
    Imm(i64),
    Mem {
        base: Option<&'static str>,
        index: Option<&'static str>,
        scale: u32,
        disp: i64,
        size: u32,
    },
    Addr(u64),
    Unknown(String),
}

#[inline]
fn strip_hex_prefix(s: &str) -> Option<&str> {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
}

#[inline]
fn classify_unsigned(v: u64) -> Operand {
    if v > ADDR_THRESHOLD && v <= i64::MAX as u64 {
        Operand::Addr(v)
    } else {
        Operand::Imm(v as i64)
    }
}

fn ptr_prefix_size(s: &str) -> u32 {
    if s.starts_with("byte") {
        1
    } else if s.starts_with("word") {
        2
    } else if s.starts_with("dword") {
        4
    } else if s.starts_with("qword") {
        8
    } else {
        0
    }
}

pub fn parse_operand(s: &str) -> Operand {
    let s = s.trim();
    if s.is_empty() {
        return Operand::Unknown(String::new());
    }

    if let (Some(open), Some(close)) = (s.find('['), s.rfind(']'))
        && open < close {
            let mut mem = parse_memory(&s[open + 1..close]);
            if let Operand::Mem { size, .. } = &mut mem {
                *size = ptr_prefix_size(s);
            }
            return mem;
        }

    if let Some(hex) = strip_hex_prefix(s)
        && let Ok(v) = u64::from_str_radix(hex, 16) {
            return classify_unsigned(v);
        }
    if let Ok(v) = s.parse::<i64>() {
        return Operand::Imm(v);
    }
    if let Some(hex) = s.strip_prefix('-').and_then(strip_hex_prefix)
        && let Ok(v) = u64::from_str_radix(hex, 16) {
            return Operand::Imm((v as i64).wrapping_neg());
        }

    if is_register(s) {
        return Operand::Reg(intern_static_lower(s));
    }

    Operand::Unknown(s.to_string())
}

fn parse_disp(part: &str) -> i64 {
    match strip_hex_prefix(part) {
        Some(h) => u64::from_str_radix(h.trim(), 16)
            .map(|v| v as i64)
            .unwrap_or(0),
        None => part.parse::<i64>().unwrap_or(0),
    }
}

fn parse_memory(s: &str) -> Operand {
    let mut base: Option<&'static str> = None;
    let mut index: Option<&'static str> = None;
    let mut scale: u32 = 1;
    let mut disp: i64 = 0;

    let mut apply = |sign: char, raw: &str| {
        let part = raw.trim();
        if part.is_empty() {
            return;
        }
        if let Some((lhs, rhs)) = part.split_once('*') {
            let (lhs, rhs) = (lhs.trim(), rhs.trim());
            if is_register(lhs) {
                index = Some(intern_static_lower(lhs));
                scale = rhs.parse().unwrap_or(1);
            } else if is_register(rhs) {
                index = Some(intern_static_lower(rhs));
                scale = lhs.parse().unwrap_or(1);
            }
        } else if is_register(part) {
            let reg = intern_static_lower(part);
            if base.is_none() {
                base = Some(reg);
            } else {
                index = Some(reg);
            }
        } else {
            let val = parse_disp(part);
            disp = if sign == '-' {
                disp.wrapping_sub(val)
            } else {
                disp.wrapping_add(val)
            };
        }
    };

    let mut sign = '+';
    let mut start = 0usize;
    for (i, b) in s.bytes().enumerate() {
        if b == b'+' || b == b'-' {
            apply(sign, &s[start..i]);
            sign = b as char;
            start = i + 1;
        }
    }
    apply(sign, &s[start..]);

    Operand::Mem {
        base,
        index,
        scale,
        disp,
        size: 0,
    }
}

pub fn is_register(s: &str) -> bool {
    let mut buf = [0u8; 8];
    let s = if !s.bytes().any(|b| b.is_ascii_uppercase()) {
        s
    } else if s.len() <= buf.len() {
        for (d, c) in buf[..s.len()].iter_mut().zip(s.bytes()) {
            *d = c.to_ascii_lowercase();
        }
        std::str::from_utf8(&buf[..s.len()]).unwrap_or("")
    } else {
        return false;
    };
    matches!(
        s,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "rip"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "eip"
            | "r8d"
            | "r9d"
            | "r10d"
            | "r11d"
            | "r12d"
            | "r13d"
            | "r14d"
            | "r15d"
            | "ax"
            | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "bp"
            | "sp"
            | "al"
            | "bl"
            | "cl"
            | "dl"
            | "sil"
            | "dil"
            | "bpl"
            | "spl"
            | "ah"
            | "bh"
            | "ch"
            | "dh"
            | "r8w"
            | "r9w"
            | "r10w"
            | "r11w"
            | "r12w"
            | "r13w"
            | "r14w"
            | "r15w"
            | "r8b"
            | "r9b"
            | "r10b"
            | "r11b"
            | "r12b"
            | "r13b"
            | "r14b"
            | "r15b"
    )
}

#[inline]
pub fn canonical_reg(r: &str) -> &'static str {
    match r {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "rip" | "eip" => "rip",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        _ => intern_static_lower(r),
    }
}

pub fn split_operands_slices<'a>(s: &'a str) -> smallvec_like::OperandSlices<'a> {
    let mut out = smallvec_like::OperandSlices::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ',' if depth == 0 => {
                let piece = s[start..i].trim();
                if !piece.is_empty() {
                    out.push(piece);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = s[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

pub mod smallvec_like {
    pub struct OperandSlices<'a> {
        inline: [&'a str; 4],
        len: usize,
        spill: Vec<&'a str>,
    }

    impl<'a> Default for OperandSlices<'a> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<'a> OperandSlices<'a> {
        #[inline]
        pub fn new() -> Self {
            Self {
                inline: [""; 4],
                len: 0,
                spill: Vec::new(),
            }
        }

        #[inline]
        pub fn push(&mut self, s: &'a str) {
            if self.len < 4 {
                self.inline[self.len] = s;
                self.len += 1;
            } else {
                self.spill.push(s);
            }
        }

        #[inline]
        pub fn iter(&self) -> impl Iterator<Item = &'a str> + '_ {
            self.inline[..self.len]
                .iter()
                .copied()
                .chain(self.spill.iter().copied())
        }
    }
}

pub fn split_operands(s: &str) -> Vec<String> {
    split_operands_slices(s)
        .iter()
        .map(|p| p.to_string())
        .collect()
}

pub fn parse_insn_operands(insn: &crate::disasm::DisasmInstruction) -> Vec<Operand> {
    match &insn.operands {
        crate::disasm::operand_enum::OperandList::Packed(p) => {
            p.to_list().iter().map(packed_operand_to_analysis).collect()
        }
        crate::disasm::operand_enum::OperandList::Text(t) => {
            let slices = split_operands_slices(t);
            slices.iter().map(parse_operand).collect()
        }
    }
}

pub(crate) fn packed_operand_to_analysis(op: &crate::disasm::operand_enum::Operand) -> Operand {
    use crate::disasm::operand_enum::{MemBase, OpWidth};
    match op {
        crate::disasm::operand_enum::Operand::Imm(v) => {
            if *v > 0 && (*v as u64) > ADDR_THRESHOLD {
                Operand::Addr(*v as u64)
            } else {
                Operand::Imm(*v)
            }
        }
        crate::disasm::operand_enum::Operand::Reg { code, width } => Operand::Reg(
            intern_static_lower(&crate::disasm::operand_enum::reg_to_text(*code, *width)),
        ),
        crate::disasm::operand_enum::Operand::Mem(m) => {
            let size = match m.width {
                Some(OpWidth::B1) => 1,
                Some(OpWidth::B2) => 2,
                Some(OpWidth::B4) => 4,
                Some(OpWidth::B8) => 8,
                None => 0,
            };
            let base = m.base.map(|b| match b {
                MemBase::Rip => "rip",
                MemBase::Reg(code, width) => {
                    intern_static_lower(&crate::disasm::operand_enum::reg_to_text(code, width))
                }
            });
            let index = m.index.map(|(code, width)| {
                intern_static_lower(&crate::disasm::operand_enum::reg_to_text(code, width))
            });
            Operand::Mem {
                base,
                index,
                scale: m.scale,
                disp: m.disp,
                size,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(
        base: Option<&'static str>,
        index: Option<&'static str>,
        scale: u32,
        disp: i64,
        size: u32,
    ) -> Operand {
        Operand::Mem {
            base,
            index,
            scale,
            disp,
            size,
        }
    }

    #[test]
    fn memory_operands() {
        assert_eq!(
            parse_operand("qword ptr [rbp-0x8]"),
            mem(Some("rbp"), None, 1, -8, 8)
        );
        assert_eq!(
            parse_operand("[rax+rbx*4+0x10]"),
            mem(Some("rax"), Some("rbx"), 4, 16, 0)
        );
        assert_eq!(
            parse_operand("dword ptr [rip+0x2fe2]"),
            mem(Some("rip"), None, 1, 0x2fe2, 4)
        );
        assert_eq!(
            parse_operand("byte ptr [ RAX + 4 * RCX - 1 ]"),
            mem(Some("rax"), Some("rcx"), 4, -1, 1)
        );
        assert_eq!(parse_operand("[0x601040]"), mem(None, None, 1, 0x601040, 0));
    }

    #[test]
    fn immediates_registers_and_addresses() {
        assert_eq!(parse_operand("0x401000"), Operand::Addr(0x401000));
        assert_eq!(parse_operand("0x10"), Operand::Imm(16));
        assert_eq!(parse_operand("0xfffffffffffffff0"), Operand::Imm(-16));
        assert_eq!(parse_operand("-0x10"), Operand::Imm(-16));
        assert_eq!(parse_operand("-5"), Operand::Imm(-5));
        assert_eq!(parse_operand("RAX"), Operand::Reg("rax"));
        assert!(matches!(parse_operand(""), Operand::Unknown(_)));
    }

    #[test]
    fn malformed_brackets_do_not_panic() {
        assert!(matches!(parse_operand("]ptr["), Operand::Unknown(_)));
        assert!(matches!(parse_operand("]["), Operand::Unknown(_)));
        let _ = parse_operand("dword ptr [");
        let _ = parse_operand("[]");
    }

    #[test]
    fn splitting_respects_brackets() {
        assert_eq!(
            split_operands("qword ptr [rax+rbx*4], rcx"),
            vec!["qword ptr [rax+rbx*4]".to_string(), "rcx".to_string()]
        );
        assert!(split_operands("").is_empty());
        assert_eq!(split_operands("a, b, c, d, e, f").len(), 6);
    }
}
