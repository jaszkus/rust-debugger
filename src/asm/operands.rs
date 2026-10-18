#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpSize {
    Byte,
    Word,
    Dword,
    Qword,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Operand {
    Reg {
        name: String,
        size: OpSize,
    },
    Imm(i64),
    Mem {
        base: Option<String>,
        index: Option<String>,
        scale: u32,
        disp: i64,
        size: OpSize,
        has_hint: bool,
    },
}

pub(crate) struct Ctx<'a> {
    pub(crate) arch: &'a str,
    pub(crate) addr: u64,
}

const ARCH_64: [&str; 4] = ["x86_64", "x86-64", "x64", "amd64"];

impl<'a> Ctx<'a> {
    pub(crate) fn is_64(&self) -> bool {
        ARCH_64.iter().any(|a| self.arch.eq_ignore_ascii_case(a))
    }
}

pub(crate) fn parse_operands(s: &str) -> Result<Vec<Operand>, String> {
    let mut out = Vec::new();
    let s = s.trim();
    if s.is_empty() {
        return Ok(out);
    }
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err(format!("unbalanced ']' in operands '{}'", s));
                }
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(parse_operand(cur.trim())?);
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if depth != 0 {
        return Err(format!("unbalanced '[' in operands '{}'", s));
    }
    if !cur.trim().is_empty() || s.ends_with(',') {
        out.push(parse_operand(cur.trim())?);
    }
    Ok(out)
}

fn parse_size_prefix(prefix: &str) -> Result<OpSize, String> {
    let lower = prefix.to_ascii_lowercase();
    let word = lower
        .strip_suffix("ptr")
        .map(str::trim_end)
        .unwrap_or(lower.as_str());
    match word {
        "byte" => Ok(OpSize::Byte),
        "word" => Ok(OpSize::Word),
        "dword" => Ok(OpSize::Dword),
        "qword" => Ok(OpSize::Qword),
        _ => Err(format!("unknown operand size prefix '{}'", prefix)),
    }
}

pub(crate) fn parse_operand(s: &str) -> Result<Operand, String> {
    let s = s.trim();

    if let Some(b) = s.find('[') {
        let e = match s.rfind(']') {
            Some(e) if e > b => e,
            _ => return Err(format!("unterminated memory operand '{}'", s)),
        };
        if !s[e + 1..].trim().is_empty() {
            return Err(format!("unexpected text after memory operand in '{}'", s));
        }
        let prefix = s[..b].trim();
        let mut m = parse_mem(&s[b + 1..e])?;
        if !prefix.is_empty() {
            let hint = parse_size_prefix(prefix)?;
            if let Operand::Mem { size, has_hint, .. } = &mut m {
                *size = hint;
                *has_hint = true;
            }
        }
        return Ok(m);
    }

    let first = s
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(first.as_str(), "byte" | "word" | "dword" | "qword") {
        return Err(format!("size hint without memory operand in '{}'", s));
    }

    if let Some(r) = parse_reg(s) {
        let size = reg_size_of(&r);
        return Ok(Operand::Reg { name: r, size });
    }
    if let Some(v) = parse_int(s) {
        return Ok(Operand::Imm(v));
    }
    Err(format!(
        "cannot parse operand '{}' (symbols/labels are not supported)",
        s
    ))
}

pub(crate) fn parse_mem(inner: &str) -> Result<Operand, String> {
    let clean: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return Err("empty memory operand".into());
    }
    if clean.ends_with(['+', '-']) {
        return Err(format!(
            "dangling operator in memory operand '[{}]'",
            inner.trim()
        ));
    }

    let mut terms: Vec<(bool, String)> = Vec::new();
    let mut cur = String::new();
    let mut neg = false;
    for c in clean.chars() {
        if c == '+' || c == '-' {
            if !cur.is_empty() {
                terms.push((neg, std::mem::take(&mut cur)));
            }
            neg = c == '-';
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        terms.push((neg, cur));
    }

    let mut base: Option<String> = None;
    let mut index: Option<String> = None;
    let mut scale: u32 = 1;
    let mut disp: i64 = 0;

    for (neg, term) in terms {
        if term == "rip" {
            if neg || base.is_some() {
                return Err("invalid use of rip in memory operand".into());
            }
            base = Some("rip".into());
        } else if let Some((l, r)) = term.split_once('*') {
            if neg {
                return Err(format!("index register cannot be subtracted in '{}'", term));
            }
            let (reg, mult) = if let Some(reg) = parse_reg(l) {
                (reg, r)
            } else if let Some(reg) = parse_reg(r) {
                (reg, l)
            } else {
                return Err(format!("bad scaled index '{}'", term));
            };
            let m = parse_int(mult).ok_or_else(|| format!("bad scale '{}'", mult))?;
            if !matches!(m, 1 | 2 | 4 | 8) {
                return Err(format!("invalid scale {} (use 1, 2, 4 or 8)", m));
            }
            if index.is_some() {
                return Err("multiple index registers in memory operand".into());
            }
            index = Some(reg);
            scale = m as u32;
        } else if let Some(reg) = parse_reg(&term) {
            if neg {
                return Err(format!("register {} cannot be subtracted", term));
            }
            if base.is_none() {
                base = Some(reg);
            } else if index.is_none() {
                index = Some(reg);
            } else {
                return Err("too many registers in memory operand".into());
            }
        } else if let Some(v) = parse_int(&term) {
            let signed = if neg {
                v.checked_neg().ok_or("displacement overflow")?
            } else {
                v
            };
            disp = disp.checked_add(signed).ok_or("displacement overflow")?;
        } else {
            return Err(format!("cannot parse memory term '{}'", term));
        }
    }

    Ok(Operand::Mem {
        base,
        index,
        scale,
        disp,
        size: OpSize::Qword,
        has_hint: false,
    })
}

pub(crate) fn parse_reg(s: &str) -> Option<String> {
    let r = s.trim().to_ascii_lowercase();
    if reg_code(&r).is_some() {
        Some(r)
    } else {
        None
    }
}

pub(crate) fn reg_code(r: &str) -> Option<u8> {
    let code = match r {
        "al" | "ax" | "eax" | "rax" => 0,
        "cl" | "cx" | "ecx" | "rcx" => 1,
        "dl" | "dx" | "edx" | "rdx" => 2,
        "bl" | "bx" | "ebx" | "rbx" => 3,
        "spl" | "sp" | "esp" | "rsp" => 4,
        "bpl" | "bp" | "ebp" | "rbp" => 5,
        "sil" | "si" | "esi" | "rsi" => 6,
        "dil" | "di" | "edi" | "rdi" => 7,
        "r8b" | "r8w" | "r8d" | "r8" => 8,
        "r9b" | "r9w" | "r9d" | "r9" => 9,
        "r10b" | "r10w" | "r10d" | "r10" => 10,
        "r11b" | "r11w" | "r11d" | "r11" => 11,
        "r12b" | "r12w" | "r12d" | "r12" => 12,
        "r13b" | "r13w" | "r13d" | "r13" => 13,
        "r14b" | "r14w" | "r14d" | "r14" => 14,
        "r15b" | "r15w" | "r15d" | "r15" => 15,
        _ => return None,
    };
    Some(code)
}

pub(crate) fn reg_size_of(r: &str) -> OpSize {
    match r {
        "al" | "bl" | "cl" | "dl" | "spl" | "bpl" | "sil" | "dil" | "r8b" | "r9b" | "r10b"
        | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => OpSize::Byte,
        "ax" | "bx" | "cx" | "dx" | "sp" | "bp" | "si" | "di" | "r8w" | "r9w" | "r10w" | "r11w"
        | "r12w" | "r13w" | "r14w" | "r15w" => OpSize::Word,
        "eax" | "ebx" | "ecx" | "edx" | "esp" | "ebp" | "esi" | "edi" | "r8d" | "r9d" | "r10d"
        | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => OpSize::Dword,
        _ => OpSize::Qword,
    }
}

pub(crate) fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    if body.is_empty() || body.starts_with('+') {
        return None;
    }
    let digits = body.replace('_', "");
    let mag: u128 = if let Some(h) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        u128::from_str_radix(h, 16).ok()?
    } else if let Some(b) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        u128::from_str_radix(b, 2).ok()?
    } else {
        digits.parse::<u128>().ok()?
    };
    if neg {
        if mag > (1u128 << 63) {
            return None;
        }
        Some((-(mag as i128)) as i64)
    } else {
        if mag > u64::MAX as u128 {
            return None;
        }
        Some(mag as u64 as i64)
    }
}
