use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpWidth {
    B1,
    B2,
    B4,
    B8,
}

impl OpWidth {
    #[inline]
    pub(crate) fn to_str(self) -> &'static str {
        match self {
            OpWidth::B1 => "byte",
            OpWidth::B2 => "word",
            OpWidth::B4 => "dword",
            OpWidth::B8 => "qword",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemBase {
    Reg(u8, OpWidth),
    Rip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemOperand {
    pub base: Option<MemBase>,
    pub index: Option<(u8, OpWidth)>,
    pub scale: u32,
    pub disp: i64,
    pub width: Option<OpWidth>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    Imm(i64),
    Reg { code: u8, width: OpWidth },
    Mem(MemOperand),
}

fn gpr_code(name: &str) -> Option<(u8, OpWidth)> {
    let (code, width) = match name {
        "al" => (0, OpWidth::B1),
        "cl" => (1, OpWidth::B1),
        "dl" => (2, OpWidth::B1),
        "bl" => (3, OpWidth::B1),
        "spl" => (4, OpWidth::B1),
        "bpl" => (5, OpWidth::B1),
        "sil" => (6, OpWidth::B1),
        "dil" => (7, OpWidth::B1),
        "ax" => (0, OpWidth::B2),
        "cx" => (1, OpWidth::B2),
        "dx" => (2, OpWidth::B2),
        "bx" => (3, OpWidth::B2),
        "sp" => (4, OpWidth::B2),
        "bp" => (5, OpWidth::B2),
        "si" => (6, OpWidth::B2),
        "di" => (7, OpWidth::B2),
        "eax" => (0, OpWidth::B4),
        "ecx" => (1, OpWidth::B4),
        "edx" => (2, OpWidth::B4),
        "ebx" => (3, OpWidth::B4),
        "esp" => (4, OpWidth::B4),
        "ebp" => (5, OpWidth::B4),
        "esi" => (6, OpWidth::B4),
        "edi" => (7, OpWidth::B4),
        "rax" => (0, OpWidth::B8),
        "rcx" => (1, OpWidth::B8),
        "rdx" => (2, OpWidth::B8),
        "rbx" => (3, OpWidth::B8),
        "rsp" => (4, OpWidth::B8),
        "rbp" => (5, OpWidth::B8),
        "rsi" => (6, OpWidth::B8),
        "rdi" => (7, OpWidth::B8),
        _ => {
            let rest = &name[1..];
            let (num, width) = if let Some(n) = rest.strip_suffix('b') {
                (n, OpWidth::B1)
            } else if let Some(n) = rest.strip_suffix('w') {
                (n, OpWidth::B2)
            } else if let Some(n) = rest.strip_suffix('d') {
                (n, OpWidth::B4)
            } else {
                (rest, OpWidth::B8)
            };
            if let Ok(num) = num.parse::<u8>() {
                if (8..16).contains(&num) {
                    return Some((num, width));
                }
            }
            return None;
        }
    };
    Some((code, width))
}

fn gpr_name(code: u8, width: OpWidth) -> String {
    const NAMES: [&str; 4] = ["al", "ax", "eax", "rax"];
    if code < 8 {
        match width {
            OpWidth::B1 => {
                ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"][code as usize].to_string()
            }
            _ => {
                let row = match width {
                    OpWidth::B2 => ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"],
                    OpWidth::B4 => ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"],
                    OpWidth::B8 => ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"],
                    OpWidth::B1 => unreachable!(),
                };
                row[code as usize].to_string()
            }
        }
    } else {
        let _ = NAMES;
        let suffix = match width {
            OpWidth::B1 => "b",
            OpWidth::B2 => "w",
            OpWidth::B4 => "d",
            OpWidth::B8 => "",
        };
        format!("r{}{}", code, suffix)
    }
}

fn parse_scalar(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok().map(|v| v as i64);
    }
    if let Some(h) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        return u64::from_str_radix(h, 16)
            .ok()
            .map(|v| (v as i64).wrapping_neg());
    }
    if let Ok(v) = s.parse::<i64>() {
        return Some(v);
    }
    s.parse::<u64>().ok().map(|v| v as i64)
}

fn fmt_scalar(f: &mut std::fmt::Formatter<'_>, v: u64) -> std::fmt::Result {
    if v <= 9 {
        write!(f, "{}", v)
    } else {
        write!(f, "{:#x}", v)
    }
}

fn split_size_hint(s: &str) -> Option<(OpWidth, &str)> {
    let mut it = s.splitn(3, char::is_whitespace);
    let size = it.next()?.to_ascii_lowercase();
    let width = match size.as_str() {
        "byte" => OpWidth::B1,
        "word" => OpWidth::B2,
        "dword" => OpWidth::B4,
        "qword" => OpWidth::B8,
        _ => return None,
    };
    let kw = it.next()?.to_ascii_lowercase();
    if kw != "ptr" {
        return None;
    }
    let rest = it.next()?;
    Some((width, rest))
}

pub(crate) fn parse(text: &str) -> Option<Operand> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let (hint, rest) = match split_size_hint(text) {
        Some((w, r)) => (Some(w), r.trim()),
        None => (None, text),
    };

    if rest.starts_with('[') {
        if !rest.ends_with(']') {
            return None;
        }
        return parse_mem(&rest[1..rest.len() - 1], hint);
    }
    if hint.is_some() {
        return None;
    }

    if let Some((code, width)) = gpr_code(text) {
        return Some(Operand::Reg { code, width });
    }
    parse_scalar(text).map(Operand::Imm)
}

pub(crate) fn parse_operands_text(text: &str) -> Option<Vec<Operand>> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in text.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(parse(&cur)?);
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(parse(&cur)?);
    }
    Some(out)
}

fn parse_mem(inner: &str, hint: Option<OpWidth>) -> Option<Operand> {
    let mut base: Option<MemBase> = None;
    let mut index: Option<(u8, OpWidth)> = None;
    let mut scale: u32 = 1;
    let mut disp: i64 = 0;

    let mut cur = String::new();
    let mut sign = 1i64;
    let mut parts: Vec<(i64, String)> = Vec::new();
    for c in inner.chars() {
        match c {
            '+' | '-' => {
                if !cur.is_empty() {
                    parts.push((sign, std::mem::take(&mut cur)));
                }
                sign = if c == '-' { -1 } else { 1 };
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        parts.push((sign, cur));
    }

    for (sgn, part) in parts {
        if part == "rip" {
            if base.is_some() {
                return None;
            }
            base = Some(MemBase::Rip);
        } else if let Some(star) = part.find('*') {
            if index.is_some() {
                return None;
            }
            let (code, width) = gpr_code(&part[..star])?;
            let mult: u32 = part[star + 1..].parse().ok()?;
            index = Some((code, width));
            scale = mult;
        } else if let Some((code, width)) = gpr_code(&part) {
            if base.is_none() {
                base = Some(MemBase::Reg(code, width));
            } else if index.is_none() {
                index = Some((code, width));
            } else {
                return None;
            }
        } else {
            let v = parse_scalar(&part)?;
            disp = disp.wrapping_add(sgn.wrapping_mul(v));
        }
    }

    Some(Operand::Mem(MemOperand {
        base,
        index,
        scale,
        disp,
        width: hint,
    }))
}

pub(crate) fn reg_to_text(code: u8, width: OpWidth) -> String {
    gpr_name(code, width)
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operand::Imm(v) => fmt_scalar(f, *v as u64),
            Operand::Reg { code, width } => f.write_str(&gpr_name(*code, *width)),
            Operand::Mem(m) => {
                if let Some(w) = m.width {
                    write!(f, "{} ptr ", w.to_str())?;
                }
                f.write_str("[")?;
                match m.base {
                    Some(MemBase::Rip) => {
                        if m.disp != 0 {
                            if m.disp < 0 {
                                f.write_str("rip-")?;
                                fmt_scalar(f, m.disp.unsigned_abs())?;
                            } else {
                                f.write_str("rip+")?;
                                fmt_scalar(f, m.disp as u64)?;
                            }
                        } else {
                            f.write_str("rip")?;
                        }
                    }
                    Some(MemBase::Reg(code, width)) => f.write_str(&gpr_name(code, width))?,
                    None => {}
                }
                if let Some((code, width)) = m.index {
                    if m.base.is_some() {
                        f.write_str("+")?;
                    }
                    f.write_str(&gpr_name(code, width))?;
                    if m.scale != 1 {
                        write!(f, "*{}", m.scale)?;
                    }
                }
                if m.base.is_none() && m.index.is_none() {
                    fmt_scalar(f, m.disp as u64)?;
                } else if m.base != Some(MemBase::Rip) && m.disp != 0 {
                    if m.disp < 0 {
                        f.write_str("-")?;
                        fmt_scalar(f, m.disp.unsigned_abs())?;
                    } else {
                        f.write_str("+")?;
                        fmt_scalar(f, m.disp as u64)?;
                    }
                }
                f.write_str("]")
            }
        }
    }
}

pub(crate) fn intern_text(s: &str) -> Arc<str> {
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex;
    static CACHE: std::sync::OnceLock<Mutex<StdHashMap<String, Arc<str>>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(StdHashMap::new()));
    let mut guard = match cache.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(v) = guard.get(s) {
        return v.clone();
    }
    let a: Arc<str> = Arc::from(s);
    guard.insert(s.to_string(), a.clone());
    a
}

pub(crate) fn intern_text_local(s: &str) -> Arc<str> {
    use std::cell::RefCell;
    const MAX_LEN: usize = 48;
    const MAX_ENTRIES: usize = 1 << 15;
    thread_local! {
        static TABLE: RefCell<rustc_hash::FxHashSet<Arc<str>>> =
            RefCell::new(rustc_hash::FxHashSet::default());
    }
    if s.len() > MAX_LEN {
        return Arc::from(s);
    }
    TABLE.with(|table| {
        let mut table = table.borrow_mut();
        if let Some(hit) = table.get(s) {
            return hit.clone();
        }
        if table.len() >= MAX_ENTRIES {
            table.clear();
        }
        let a: Arc<str> = Arc::from(s);
        table.insert(a.clone());
        a
    })
}

#[cfg(test)]
mod intern_local_tests {
    use super::*;

    #[test]
    fn repeated_text_shares_one_allocation() {
        let a = intern_text_local("xmm0,xmm1");
        let b = intern_text_local("xmm0,xmm1");
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(&*a, "xmm0,xmm1");
        assert!(Arc::ptr_eq(&intern_text_local(""), &intern_text_local("")));
    }

    #[test]
    fn long_text_is_not_retained_but_stays_correct() {
        let long = "x".repeat(200);
        let a = intern_text_local(&long);
        let b = intern_text_local(&long);
        assert_eq!(&*a, long.as_str());
        assert_eq!(&*a, &*b);
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn table_reset_keeps_text_correct() {
        for i in 0..(2 * (1usize << 15) + 10) {
            let t = format!("v{i}");
            assert_eq!(&*intern_text_local(&t), t.as_str());
        }
        assert_eq!(&*intern_text_local("v1"), "v1");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackedOp {
    Imm(i64),
    Reg {
        code: u8,
        width: OpWidth,
    },
    Mem {
        base: Option<MemBase>,
        index: Option<(u8, OpWidth)>,
        scale: u32,
        disp: i32,
        width: Option<OpWidth>,
    },
}

impl PackedOp {
    pub(crate) fn from_operand(op: &Operand) -> Option<PackedOp> {
        match *op {
            Operand::Imm(v) => Some(PackedOp::Imm(v)),
            Operand::Reg { code, width } => Some(PackedOp::Reg { code, width }),
            Operand::Mem(MemOperand {
                base,
                index,
                scale,
                disp,
                width,
            }) => {
                let disp = i32::try_from(disp).ok()?;
                Some(PackedOp::Mem {
                    base,
                    index,
                    scale,
                    disp,
                    width,
                })
            }
        }
    }

    pub(crate) fn to_operand(self) -> Operand {
        match self {
            PackedOp::Imm(v) => Operand::Imm(v),
            PackedOp::Reg { code, width } => Operand::Reg { code, width },
            PackedOp::Mem {
                base,
                index,
                scale,
                disp,
                width,
            } => Operand::Mem(MemOperand {
                base,
                index,
                scale,
                disp: disp as i64,
                width,
            }),
        }
    }

    pub(crate) fn to_text(self) -> String {
        self.to_operand().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperandList {
    Packed(PackedOps),
    Text(Arc<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedOps {
    pub(crate) a: Option<PackedOp>,
    pub(crate) b: Option<PackedOp>,
}

impl PackedOps {
    pub(crate) fn from_list(ops: &[Operand]) -> Option<PackedOps> {
        if ops.is_empty() || ops.len() > 2 {
            return None;
        }
        Some(match ops.len() {
            1 => PackedOps {
                a: Some(PackedOp::from_operand(&ops[0])?),
                b: None,
            },
            _ => PackedOps {
                a: Some(PackedOp::from_operand(&ops[0])?),
                b: Some(PackedOp::from_operand(&ops[1])?),
            },
        })
    }

    pub(crate) fn to_list(self) -> Vec<Operand> {
        let mut out = Vec::with_capacity(2);
        if let Some(a) = self.a {
            out.push(a.to_operand());
        }
        if let Some(b) = self.b {
            out.push(b.to_operand());
        }
        out
    }

    pub(crate) fn to_text(self) -> String {
        let mut out = String::with_capacity(24);
        if let Some(a) = self.a {
            out.push_str(&a.to_text());
        }
        if let Some(b) = self.b {
            out.push(',');
            out.push_str(&b.to_text());
        }
        out
    }
}

impl OperandList {
    pub(crate) fn text(&self) -> std::borrow::Cow<'_, str> {
        match self {
            OperandList::Text(t) => std::borrow::Cow::Borrowed(t.as_ref()),
            OperandList::Packed(p) => std::borrow::Cow::Owned(p.to_text()),
        }
    }

    pub(crate) fn pack_text(s: &str) -> Option<OperandList> {
        let ops = parse_operands_text(s)?;
        let packed = PackedOps::from_list(&ops)?;
        debug_assert_eq!(packed.to_text(), s, "packed round-trip broke on '{}'", s);
        Some(OperandList::Packed(packed))
    }
}

impl std::fmt::Display for OperandList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

impl From<&str> for OperandList {
    fn from(s: &str) -> Self {
        OperandList::Text(Arc::from(s))
    }
}

impl From<String> for OperandList {
    fn from(s: String) -> Self {
        OperandList::Text(Arc::from(s.as_str()))
    }
}

impl From<Arc<str>> for OperandList {
    fn from(s: Arc<str>) -> Self {
        OperandList::Text(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(line: &str, arch: &str, addr: u64) {
        let bytes = crate::asm::assemble(arch, addr, line)
            .unwrap_or_else(|e| panic!("assemble '{}' ({}): {}", line, arch, e));
        let insns = crate::disasm::disassemble_region(&bytes, addr, arch)
            .unwrap_or_else(|e| panic!("disassemble '{}': {}", line, e));
        assert_eq!(
            insns.len(),
            1,
            "'{}' decoded to {} insns",
            line,
            insns.len()
        );
        let text = insns[0].ops();
        let text = text.as_ref();
        let ops = parse_operands_text(text)
            .unwrap_or_else(|| panic!("parse failed on formatter output '{}'", text));
        let joined = ops
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(joined, text, "round-trip mismatch for '{}'", line);
        if let Some(packed) = PackedOps::from_list(&ops) {
            assert_eq!(
                packed.to_text(),
                text,
                "packed round-trip mismatch for '{}'",
                line
            );
        }
    }

    #[test]
    fn roundtrips_through_real_decoder_x64() {
        let a = "x86_64";
        let base = 0x1000;
        for line in [
            "mov rax, rbx",
            "mov rax, 0x1234",
            "mov eax, 0xffffffff",
            "mov r8, r15",
            "mov r12d, r13d",
            "mov r9b, r10b",
            "mov byte ptr [rax], 0x5",
            "mov qword ptr [rax + 0x8], rdx",
            "mov rax, qword ptr [rip + 0x10]",
            "mov rax, qword ptr [rip]",
            "cmp byte ptr [rcx], 0x7",
            "mov eax, dword ptr [rbp-0x18]",
            "lea rdx, [rcx + rax*4 - 0x10]",
            "add dword ptr [rbx + rax*2], esi",
            "mov ecx, dword ptr [0x1234]",
            "jmp 0x1010",
            "call 0x1015",
            "push rbp",
            "pop rax",
            "nop dword ptr [rax]",
            "mov eax, dword ptr [rsp + 0x24]",
        ] {
            rt(line, a, base);
        }
    }

    #[test]
    fn roundtrips_through_real_decoder_x86() {
        let a = "x86";
        let base = 0x1000;
        for line in [
            "mov eax, ebx",
            "mov ax, 0x1234",
            "mov dword ptr [eax + 0x4], ecx",
            "mov byte ptr [ebx], 0x9",
            "mov eax, dword ptr [ebp + 0x8]",
            "lea edx, [eax + ecx*2]",
            "push ebp",
            "pop edi",
        ] {
            rt(line, a, base);
        }
    }

    #[test]
    fn parses_all_register_widths() {
        for code in 0u8..16 {
            for width in [OpWidth::B1, OpWidth::B2, OpWidth::B4, OpWidth::B8] {
                let name = reg_to_text(code, width);
                match parse(&name) {
                    Some(Operand::Reg { code: c, width: w }) => {
                        assert_eq!((c, w), (code, width), "reg '{}'", name);
                    }
                    other => panic!("'{}' parsed as {:?}", name, other),
                }
                assert_eq!(reg_to_text(code, width), name);
            }
        }
        assert_eq!(reg_to_text(4, OpWidth::B1), "spl");
        assert_eq!(reg_to_text(12, OpWidth::B1), "r12b");
    }

    #[test]
    fn parses_hintless_memory() {
        match parse("[rax+0x10]") {
            Some(Operand::Mem(m)) => {
                assert_eq!(m.base, Some(MemBase::Reg(0, OpWidth::B8)));
                assert_eq!(m.width, None);
                assert_eq!(m.disp, 0x10);
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn rejects_unknown_operands() {
        for t in [
            "xmm0",
            "st0",
            "zmm3",
            "ah",
            "byte ptr rax",
            "[fs:0x30]",
            "",
            "xmmword ptr [rax]",
        ] {
            assert!(parse(t).is_none(), "'{}' should not parse", t);
        }
    }

    #[test]
    fn imm_wraps_through_u64_bits() {
        assert_eq!(parse("0xffffffffffffffff"), Some(Operand::Imm(-1)));
        assert_eq!(parse("0xffffffff"), Some(Operand::Imm(0xffffffff)));
        assert_eq!(Operand::Imm(-1).to_string(), "0xffffffffffffffff");
    }
}
