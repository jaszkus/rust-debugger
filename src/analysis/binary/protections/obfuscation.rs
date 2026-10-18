use super::{Category, Finding, Severity, Source};
use crate::disasm::DisasmResult;

pub fn detect_obfuscation(disasm: &DisasmResult) -> Vec<Finding> {
    let mut out = Vec::new();
    let total = disasm.instructions.len() as u64;
    if total == 0 {
        return out;
    }

    let mut indirect_jmp = 0u64;
    let mut indirect_call = 0u64;
    let mut jmp_short_one = 0u64;
    let mut prefix_chains = 0u64;
    let mut never_taken_jcc_at_top = 0u64;

    for insn in disasm.instructions.iter() {
        match insn.mnemonic {
            "jmp" => {
                if insn.ops().starts_with('[')
                    || insn.ops().starts_with("qword")
                    || insn.ops().starts_with("dword")
                    || is_register(&insn.ops())
                {
                    indirect_jmp += 1;
                }
                if insn.bytes.len() == 2 && insn.bytes[0] == 0xEB && insn.bytes[1] == 0x00 {
                    jmp_short_one += 1;
                }
            }
            "call" => {
                if insn.ops().starts_with('[')
                    || insn.ops().starts_with("qword")
                    || insn.ops().starts_with("dword")
                    || is_register(&insn.ops())
                {
                    indirect_call += 1;
                }
            }
            "rep" | "repne" | "repe" | "repnz" | "repz" => prefix_chains += 1,
            _ => {}
        }
        if insn.bytes.len() >= 5 {
            let mut pfx = 0;
            for &b in insn.bytes.iter() {
                if matches!(
                    b,
                    0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
                ) {
                    pfx += 1;
                } else {
                    break;
                }
            }
            if pfx >= 4 {
                prefix_chains += 1;
            }
        }
    }

    let insns = &disasm.instructions;
    for w in insns.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        let a_ops = a.ops();
        if a.mnem() == "xor" && a_ops.split(',').count() == 2 {
            let parts: Vec<_> = a_ops.split(',').map(|s| s.trim()).collect();
            if parts.len() == 2 && parts[0] == parts[1] && b.mnem() == "jne" {
                never_taken_jcc_at_top += 1;
            }
        }
    }

    if indirect_jmp * 100 > total * 5 {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::Medium,
            id: "many_indirect_jmps",
            description: format!(
                "{} indirect jumps ({:.1}% of all insns) — possible control-flow flattening or VM",
                indirect_jmp,
                indirect_jmp as f64 * 100.0 / total as f64
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.7,
        });
    }
    if indirect_call * 100 > total * 5 {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::Medium,
            id: "many_indirect_calls",
            description: format!(
                "{} indirect calls ({:.1}% of all insns)",
                indirect_call,
                indirect_call as f64 * 100.0 / total as f64
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.7,
        });
    }
    if jmp_short_one > 50 {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::High,
            id: "junk_jmp_short_zero",
            description: format!(
                "{} `jmp $+2` instructions — junk-insertion obfuscation",
                jmp_short_one
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.85,
        });
    }
    if prefix_chains > 50 {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::Medium,
            id: "prefix_chain",
            description: format!("{} instructions with unusual prefix chains", prefix_chains),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.7,
        });
    }
    if never_taken_jcc_at_top > 10 {
        out.push(Finding {
            category: Category::Obfuscation,
            severity: Severity::Medium,
            id: "opaque_predicate",
            description: format!(
                "{} `xor reg,reg; jne …` pairs — opaque (always-false) predicates",
                never_taken_jcc_at_top
            ),
            address: None,
            evidence: None,
            source: Source::Heuristic,
            confidence: 0.7,
        });
    }

    out
}

fn is_register(op: &str) -> bool {
    let t = op.trim();
    matches!(
        t,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rsp"
            | "rbp"
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
            | "esp"
            | "ebp"
    )
}
