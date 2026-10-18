use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashSet as HashSet;

pub struct NoReturnAnalyzer {
    noreturn_functions: HashSet<u64>,
    noreturn_imports: HashSet<String>,
}

impl NoReturnAnalyzer {
    pub fn new() -> Self {
        let mut noreturn_imports = HashSet::default();
        for name in [
            "ExitProcess",
            "ExitThread",
            "FatalExit",
            "FatalAppExitW",
            "TerminateProcess",
            "RtlExitUserProcess",
            "NtTerminateProcess",
            "ZwTerminateProcess",
            "RtlAssert",
            "__debugbreak",
            "abort",
            "exit",
            "_exit",
            "_Exit",
            "quick_exit",
            "_cexit",
            "_c_exit",
            "_exit_callback",
            "longjmp",
            "_longjmp",
            "__assert_fail",
            "__assert_rtn",
            "_assert",
            "_wassert",
            "__stack_chk_fail",
            "__stack_chk_guard",
            "__chk_fail",
            "__fortify_fail",
            "__ubsan_handle_abort",
            "__cxa_throw",
            "__cxa_rethrow",
            "__cxa_call_terminate",
            "__cxa_pure_virtual",
            "__cxa_deleted_virtual",
            "panic_abort",
            "panic_bounds_check",
            "panic_nounwind",
            "std::rt::lang_start_internal",
            "rust_oom",
            "rust_begin_unwind",
            "runtime.throw",
            "runtime.fatalpanic",
            "runtime.exit",
            "runtime.goexit",
            "Goexit",
            "__libc_fatal",
            "__libc_message",
            "__pthread_exit",
            "pthread_exit",
            "_Unwind_Resume",
            "__gcc_personality_v0",
            "ud2_trap",
            "__builtin_trap",
            "unreachable_trap",
        ] {
            noreturn_imports.insert(name.to_string());
        }

        Self {
            noreturn_functions: HashSet::default(),
            noreturn_imports,
        }
    }

    pub fn analyze(
        &mut self,
        insns: &[DisasmInstruction],
        imports: &[crate::parser::Import],
        functions: &[super::function::DetectedFunction],
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) {
        for imp in imports {
            if is_callfixup_name(&imp.name) {
                continue;
            }
            if self.noreturn_imports.contains(&imp.name) && imp.offset != 0 {
                self.noreturn_functions.insert(imp.offset);
            }
        }

        for _ in 0..16 {
            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                return;
            }
            let noreturn = &self.noreturn_functions;
            let found: Vec<u64> = if functions.len() >= crate::util::parallel::PAR_FUNCS {
                use rayon::prelude::*;
                crate::util::parallel::install(|| {
                    functions
                        .par_iter()
                        .filter(|f| !noreturn.contains(&f.entry))
                        .filter(|f| evidence_score(insns, f, noreturn) >= NORETURN_THRESHOLD)
                        .map(|f| f.entry)
                        .collect()
                })
            } else {
                let mut v = Vec::new();
                for (fi, f) in functions.iter().enumerate() {
                    if fi % 256 == 0
                        && cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                    {
                        return;
                    }
                    if self.noreturn_functions.contains(&f.entry) {
                        continue;
                    }
                    if evidence_score(insns, f, &self.noreturn_functions) >= NORETURN_THRESHOLD {
                        v.push(f.entry);
                    }
                }
                v
            };
            if found.is_empty() {
                break;
            }
            let mut changed = false;
            for e in found {
                changed |= self.noreturn_functions.insert(e);
            }
            if !changed {
                break;
            }
        }
    }

    #[allow(dead_code)]
    pub fn is_noreturn(&self, addr: u64) -> bool {
        self.noreturn_functions.contains(&addr)
    }

    #[allow(dead_code)]
    pub fn is_noreturn_call_at(&self, insn: &DisasmInstruction) -> bool {
        if insn.mnem() == "call" {
            if let Some(target) = parse_call_target(&insn.ops()) {
                if self.noreturn_functions.contains(&target) {
                    return true;
                }
            }
            if let Some(slot) = resolve_mem_target(insn) {
                return self.noreturn_functions.contains(&slot);
            }
            return false;
        }
        is_trap(insn)
    }

    pub fn get_noreturn_functions(&self) -> &HashSet<u64> {
        &self.noreturn_functions
    }
}

impl Default for NoReturnAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_call_target(operands: &str) -> Option<u64> {
    let s = operands.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    u64::from_str_radix(s, 16).ok()
}

const NORETURN_THRESHOLD: u32 = 3;

fn is_callfixup_name(name: &str) -> bool {
    matches!(
        name.trim_start_matches('_').to_ascii_lowercase().as_str(),
        "chkstk" | "chkstk_ms" | "alloca_probe" | "security_check_cookie" | "security_init_cookie"
    )
}

fn evidence_score(
    insns: &[DisasmInstruction],
    f: &super::function::DetectedFunction,
    noreturn: &HashSet<u64>,
) -> u32 {
    let start = insns.partition_point(|x| x.address < f.entry);
    let end = insns.partition_point(|x| x.address < f.end);
    if start >= end {
        return 0;
    }
    let mut score = 0u32;
    if ends_with_noreturn_transfer(insns, f, noreturn) {
        score += 2;
    } else {
        for ins in insns[start..end].iter() {
            if is_noreturn_transfer(ins, noreturn) {
                let call_end = ins.address.saturating_add(ins.bytes.len() as u64);
                let ts = insns.partition_point(|x| x.address < call_end);
                let te = insns.partition_point(|x| x.address < f.end);
                let tail_pad = insns[ts.min(te)..te].iter().take(64).all(is_padding);
                if tail_pad {
                    score += 1;
                    break;
                }
            }
        }
    }
    if has_int3_after_noreturn_call(&insns[start..end], noreturn) {
        score += 1;
    }
    if !insns[start..end]
        .iter()
        .any(|x| x.mnem() == "ret" || x.mnem() == "retn")
    {
        score += 1;
    }
    score
}

fn has_int3_after_noreturn_call(body: &[DisasmInstruction], noreturn: &HashSet<u64>) -> bool {
    for (i, ins) in body.iter().enumerate() {
        if !is_noreturn_transfer(ins, noreturn) {
            continue;
        }
        let mut seen_cc = false;
        for next in body.iter().skip(i + 1).take(4) {
            if next.mnem() == "int3" || next.bytes.iter().all(|&b| b == 0xCC) {
                seen_cc = true;
                break;
            }
            if next.mnem() == "jmp" || next.mnem() == "call" {
                continue;
            }
            break;
        }
        if seen_cc {
            return true;
        }
    }
    false
}

fn is_padding(ins: &DisasmInstruction) -> bool {
    ins.mnem() == "nop"
        || ins.mnem() == "int3"
        || ins.bytes.iter().all(|&b| b == 0x00)
        || ins.bytes.iter().all(|&b| b == 0xCC)
}

fn is_trap(ins: &DisasmInstruction) -> bool {
    matches!(ins.mnemonic, "ud2" | "ud1" | "hlt")
        || (ins.mnem() == "int" && ins.ops().trim() == "0x29")
}

fn is_noreturn_transfer(ins: &DisasmInstruction, noreturn: &HashSet<u64>) -> bool {
    if is_trap(ins) {
        return true;
    }
    if ins.mnem() == "call" || ins.mnem() == "jmp" {
        if parse_call_target(&ins.ops()).is_some_and(|t| noreturn.contains(&t)) {
            return true;
        }
        if resolve_mem_target(ins).is_some_and(|t| noreturn.contains(&t)) {
            return true;
        }
    }
    false
}

fn resolve_mem_target(ins: &DisasmInstruction) -> Option<u64> {
    let ops_owned = ins.ops();
    let ops = ops_owned.trim();
    if !ops.contains('[') {
        return None;
    }
    let open = ops.find('[')?;
    let close = ops.rfind(']')?;
    if close <= open {
        return None;
    }
    let inner = ops[open + 1..close].replace(' ', "");
    let lower = inner.to_lowercase();
    if let Some(rest) = lower.strip_prefix("rip+") {
        let disp = u64::from_str_radix(rest.trim_start_matches("0x"), 16).ok()?;
        let next_ip = ins.address.wrapping_add(ins.bytes.len() as u64);
        return Some(next_ip.wrapping_add(disp));
    }
    if let Some(rest) = lower.strip_prefix("rip-") {
        let disp = u64::from_str_radix(rest.trim_start_matches("0x"), 16).ok()?;
        let next_ip = ins.address.wrapping_add(ins.bytes.len() as u64);
        return Some(next_ip.wrapping_sub(disp));
    }
    let h = lower.strip_prefix("0x")?;
    if h.chars()
        .any(|c| c.is_ascii_alphabetic() && !('a'..='f').contains(&c))
    {
        return None;
    }
    u64::from_str_radix(h, 16).ok()
}

fn ends_with_noreturn_transfer(
    insns: &[DisasmInstruction],
    f: &super::function::DetectedFunction,
    noreturn: &HashSet<u64>,
) -> bool {
    let start = insns.partition_point(|x| x.address < f.entry);
    let end = insns.partition_point(|x| x.address < f.end);
    let mut last: Option<&DisasmInstruction> = None;
    for ins in &insns[start..end] {
        let padding = ins.mnem() == "nop"
            || ins.mnem() == "int3"
            || ins.bytes.iter().all(|&b| b == 0x00)
            || ins.bytes.iter().all(|&b| b == 0xCC);
        if !padding {
            last = Some(ins);
        }
    }
    match last {
        Some(ins) if is_trap(ins) => true,
        Some(ins) if ins.mnem() == "call" || ins.mnem() == "jmp" => {
            parse_call_target(&ins.ops()).is_some_and(|t| noreturn.contains(&t))
        }
        _ => false,
    }
}
