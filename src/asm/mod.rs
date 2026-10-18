pub mod encode;
pub mod operands;

#[cfg(test)]
mod tests;

use encode::encode;
use operands::{parse_operands, Ctx};

pub fn assemble(arch: &str, addr: u64, line: &str) -> Result<Vec<u8>, String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("Empty assembly line".into());
    }
    let (mnemonic, ops) = match line.find(char::is_whitespace) {
        Some(i) => (&line[..i], line[i..].trim()),
        None => (line, ""),
    };
    let operands = parse_operands(ops)?;
    let ctx = Ctx { arch, addr };
    encode(&ctx, &mnemonic.to_ascii_lowercase(), &operands)
}

pub fn assemble_snippet(
    arch: &str,
    addr: u64,
    snippet: &str,
) -> Result<(Vec<u8>, Vec<String>), String> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut cur = addr;
    for raw_line in snippet.lines() {
        for part in raw_line.split(';') {
            let line = part.trim();
            if line.is_empty() {
                continue;
            }
            match assemble(arch, cur, line) {
                Ok(bytes) => {
                    cur += bytes.len() as u64;
                    out.extend(bytes);
                }
                Err(e) => errors.push(format!("{}: {}", line, e)),
            }
        }
    }
    Ok((out, errors))
}

pub fn supported_mnemonics() -> Vec<&'static str> {
    vec![
        "nop", "ret", "retn", "leave", "int3", "break", "int", "hlt", "syscall", "cpuid", "ud2",
        "pause", "cwde", "cdq", "cdqe", "cqo", "push", "pop", "mov", "movabs", "movzx", "movsx",
        "movsxd", "lea", "add", "or", "and", "sub", "xor", "cmp", "test", "inc", "dec", "not",
        "neg", "call", "jmp", "jo", "jno", "jb", "jc", "jnae", "jae", "jnb", "jnc", "je", "jz",
        "jne", "jnz", "jbe", "jna", "ja", "jnbe", "js", "jns", "jp", "jpe", "jnp", "jpo", "jl",
        "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle", "seto", "setno", "setb", "setc",
        "setnae", "setae", "setnb", "setnc", "sete", "setz", "setne", "setnz", "setbe", "setna",
        "seta", "setnbe", "sets", "setns", "setp", "setpe", "setnp", "setpo", "setl", "setnge",
        "setge", "setnl", "setle", "setng", "setg", "setnle", "cmovo", "cmovno", "cmovb", "cmovc",
        "cmovnae", "cmovae", "cmovnb", "cmovnc", "cmove", "cmovz", "cmovne", "cmovnz", "cmovbe",
        "cmovna", "cmova", "cmovnbe", "cmovs", "cmovns", "cmovp", "cmovpe", "cmovnp", "cmovpo",
        "cmovl", "cmovnge", "cmovge", "cmovnl", "cmovle", "cmovng", "cmovg", "cmovnle",
    ]
}
