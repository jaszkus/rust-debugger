use crate::disasm::DisasmInstruction;
use rustc_hash::FxHashMap as HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RegValue {
    Known(u64),
    Unknown,
    #[allow(dead_code)]
    StackOffset(i64),
}

pub struct ConstantPropagator {
    registers: HashMap<String, RegValue>,
    memory: HashMap<u64, RegValue>,
}

impl ConstantPropagator {
    pub fn new() -> Self {
        Self {
            registers: HashMap::default(),
            memory: HashMap::default(),
        }
    }

    pub fn propagate(&mut self, insns: &[DisasmInstruction], entry: u64, end: u64) {
        let lo = insns.partition_point(|i| i.address < entry);
        let hi = insns.partition_point(|i| i.address < end);
        self.propagate_slice(&insns[lo..hi]);
    }

    pub fn propagate_slice(&mut self, insns: &[DisasmInstruction]) {
        self.registers.clear();
        self.memory.clear();

        for insn in insns {
            self.process_instruction(insn);
        }
    }

    fn process_instruction(&mut self, insn: &DisasmInstruction) {
        match insn.mnemonic {
            "mov" => self.handle_mov(insn),
            "lea" => self.handle_lea(insn),
            "xor" => self.handle_xor(insn),
            "push" => self.handle_push(insn),
            "pop" => self.handle_pop(insn),
            "add" => self.handle_add(insn),
            "sub" => self.handle_sub(insn),
            "call" => self.handle_call(insn),
            _ => {}
        }
    }

    fn handle_mov(&mut self, insn: &DisasmInstruction) {
        let ops_cow = insn.ops();
        let parts: Vec<&str> = ops_cow.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return;
        }

        let dst = parts[0];
        let src = parts[1];

        if is_register(dst) {
            if let Some(val) = self.parse_value(src) {
                self.registers.insert(dst.to_string(), val);
            } else {
                self.registers.insert(dst.to_string(), RegValue::Unknown);
            }
        } else if dst.starts_with('[') {
            if let Some(addr) = self.resolve_address(dst, insn.address, insn.bytes.len()) {
                if let Some(val) = self.parse_value(src) {
                    self.memory.insert(addr, val);
                }
            }
        }
    }

    fn handle_lea(&mut self, insn: &DisasmInstruction) {
        let ops_cow = insn.ops();
        let parts: Vec<&str> = ops_cow.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return;
        }

        let dst = parts[0];
        let src = parts[1];

        if is_register(dst) {
            if let Some(addr) = self.resolve_address(src, insn.address, insn.bytes.len()) {
                self.registers
                    .insert(dst.to_string(), RegValue::Known(addr));
            } else {
                self.registers.insert(dst.to_string(), RegValue::Unknown);
            }
        }
    }

    fn handle_xor(&mut self, insn: &DisasmInstruction) {
        let ops_cow = insn.ops();
        let parts: Vec<&str> = ops_cow.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return;
        }

        if parts[0] == parts[1] {
            self.registers
                .insert(parts[0].to_string(), RegValue::Known(0));
        }
    }

    fn handle_push(&mut self, _insn: &DisasmInstruction) {
        let rsp = self
            .registers
            .get("rsp")
            .copied()
            .unwrap_or(RegValue::Unknown);
        if let RegValue::Known(val) = rsp {
            self.registers
                .insert("rsp".to_string(), RegValue::Known(val - 8));
        }
    }

    fn handle_pop(&mut self, insn: &DisasmInstruction) {
        let rsp = self
            .registers
            .get("rsp")
            .copied()
            .unwrap_or(RegValue::Unknown);
        if let RegValue::Known(val) = rsp {
            self.registers
                .insert("rsp".to_string(), RegValue::Known(val + 8));
        }

        let reg_cow = insn.ops();
        let reg = reg_cow.trim();
        if is_register(reg) {
            self.registers.insert(reg.to_string(), RegValue::Unknown);
        }
    }

    fn handle_add(&mut self, insn: &DisasmInstruction) {
        let ops_cow = insn.ops();
        let parts: Vec<&str> = ops_cow.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return;
        }

        let dst = parts[0];
        if !is_register(dst) {
            return;
        }

        if let Some(RegValue::Known(dst_val)) = self.registers.get(dst).copied() {
            if let Some(RegValue::Known(src_val)) = self.parse_value(parts[1]) {
                self.registers.insert(
                    dst.to_string(),
                    RegValue::Known(dst_val.wrapping_add(src_val)),
                );
            } else {
                self.registers.insert(dst.to_string(), RegValue::Unknown);
            }
        }
    }

    fn handle_sub(&mut self, insn: &DisasmInstruction) {
        let ops_cow = insn.ops();
        let parts: Vec<&str> = ops_cow.split(',').map(|s| s.trim()).collect();
        if parts.len() != 2 {
            return;
        }

        let dst = parts[0];
        if !is_register(dst) {
            return;
        }

        if let Some(RegValue::Known(dst_val)) = self.registers.get(dst).copied() {
            if let Some(RegValue::Known(src_val)) = self.parse_value(parts[1]) {
                self.registers.insert(
                    dst.to_string(),
                    RegValue::Known(dst_val.wrapping_sub(src_val)),
                );
            } else {
                self.registers.insert(dst.to_string(), RegValue::Unknown);
            }
        }
    }

    fn handle_call(&mut self, insn: &DisasmInstruction) {
        let ops = insn.ops().to_ascii_lowercase();
        if ops.contains("chkstk")
            || ops.contains("security_check_cookie")
            || ops.contains("security_cookie")
        {
            return;
        }
        for reg in &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
            self.registers.insert(reg.to_string(), RegValue::Unknown);
        }
    }

    fn parse_value(&self, s: &str) -> Option<RegValue> {
        let s = s.trim();

        if let Some(hex) = s.strip_prefix("0x") {
            if let Ok(val) = u64::from_str_radix(hex, 16) {
                return Some(RegValue::Known(val));
            }
        } else if let Ok(val) = s.parse::<u64>() {
            return Some(RegValue::Known(val));
        }

        if is_register(s) {
            return self.registers.get(s).copied();
        }

        None
    }

    fn resolve_address(&self, s: &str, insn_addr: u64, insn_len: usize) -> Option<u64> {
        let s = s.trim();
        if !s.starts_with('[') || !s.ends_with(']') {
            return None;
        }

        let inner = s[1..s.len() - 1].trim();
        let lower = inner.to_ascii_lowercase();

        if lower.starts_with("rip") {
            let rest = inner[3..].trim();
            if rest.is_empty() {
                return Some(insn_addr.wrapping_add(insn_len as u64));
            }
            let (neg, num) = if let Some(r) = rest.strip_prefix('+') {
                (false, r.trim())
            } else {
                let r = rest.strip_prefix('-')?;
                (true, r.trim())
            };
            let disp = if let Some(h) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
                u64::from_str_radix(h, 16).ok()?
            } else {
                num.parse::<i64>().ok()? as u64
            };
            let next_rip = insn_addr.wrapping_add(insn_len as u64);
            return Some(if neg {
                next_rip.wrapping_sub(disp)
            } else {
                next_rip.wrapping_add(disp)
            });
        }

        if let Some(hex) = inner
            .strip_prefix("0x")
            .or_else(|| inner.strip_prefix("0X"))
        {
            let hex = hex.trim();
            if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(addr) = u64::from_str_radix(hex, 16) {
                    return Some(addr);
                }
            }
        }

        None
    }

    pub fn get_register_value(&self, reg: &str) -> Option<RegValue> {
        self.registers.get(reg).copied()
    }

    #[allow(dead_code)]
    pub fn get_memory_value(&self, addr: u64) -> Option<RegValue> {
        self.memory.get(&addr).copied()
    }
}

impl Default for ConstantPropagator {
    fn default() -> Self {
        Self::new()
    }
}

fn is_register(s: &str) -> bool {
    matches!(
        s,
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
