use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u32,
}

impl Registers {
    pub fn new() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            eflags: 0,
        }
    }
}

impl Default for Registers {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub address: u64,
    pub enabled: bool,
    pub original_byte: u8,
    pub name: String,
    pub kind: BpKind,
    pub len: u8,
    pub planted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum BpOrigin {
    Logical,
    Planted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpKind {
    SwExec,
    HwExec,
    Read,
    Write,
    Access,
}

impl BpKind {
    #[allow(dead_code)]
    pub const FLAG_SW_EXECUTE: u32 = 0x01;
    #[allow(dead_code)]
    pub const FLAG_HW_EXECUTE: u32 = 0x02;
    #[allow(dead_code)]
    pub const FLAG_READ: u32 = 0x04;
    #[allow(dead_code)]
    pub const FLAG_WRITE: u32 = 0x08;
    #[allow(dead_code)]
    pub const FLAG_ACCESS: u32 = Self::FLAG_READ | Self::FLAG_WRITE;

    #[allow(dead_code)]
    pub fn try_parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sw" | "swexec" | "sw_exec" | "soft" | "int3" => Ok(BpKind::SwExec),
            "hw" | "hwexec" | "hwx" | "execute" | "x" => Ok(BpKind::HwExec),
            "read" | "r" => Ok(BpKind::Read),
            "write" | "w" => Ok(BpKind::Write),
            "access" | "rw" | "readwrite" => Ok(BpKind::Access),
            other => Err(format!("Unknown breakpoint kind '{}', retry", other)),
        }
    }
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Self {
        Self::try_parse(s).unwrap_or(BpKind::SwExec)
    }
    #[allow(dead_code)]
    pub fn to_flags(self) -> u32 {
        match self {
            BpKind::SwExec => Self::FLAG_SW_EXECUTE,
            BpKind::HwExec => Self::FLAG_HW_EXECUTE,
            BpKind::Read => Self::FLAG_READ,
            BpKind::Write => Self::FLAG_WRITE,
            BpKind::Access => Self::FLAG_ACCESS,
        }
    }
    #[allow(dead_code)]
    pub fn from_flags(flags: u32) -> Result<Self, String> {
        if flags & Self::FLAG_HW_EXECUTE != 0 {
            return Ok(BpKind::HwExec);
        }
        if flags & Self::FLAG_ACCESS == Self::FLAG_ACCESS {
            return Ok(BpKind::Access);
        }
        if flags & Self::FLAG_READ != 0 {
            return Ok(BpKind::Read);
        }
        if flags & Self::FLAG_WRITE != 0 {
            return Ok(BpKind::Write);
        }
        if flags & Self::FLAG_SW_EXECUTE != 0 {
            return Ok(BpKind::SwExec);
        }
        Err(format!("Unknown breakpoint flags {:#x}, retry", flags))
    }
    pub fn as_str(self) -> &'static str {
        match self {
            BpKind::SwExec => "sw_exec",
            BpKind::HwExec => "hw_exec",
            BpKind::Read => "read",
            BpKind::Write => "write",
            BpKind::Access => "access",
        }
    }
}

impl Breakpoint {
    #[allow(dead_code)]
    pub fn sw(address: u64, original_byte: u8, name: String) -> Self {
        Self {
            address,
            enabled: true,
            original_byte,
            name,
            kind: BpKind::SwExec,
            len: 1,
            planted: original_byte != 0,
        }
    }
    #[allow(dead_code)]
    pub fn original_opt(&self) -> Option<u8> {
        if self.original_byte == 0 {
            None
        } else {
            Some(self.original_byte)
        }
    }
    #[allow(dead_code)]
    pub fn origin(&self) -> BpOrigin {
        if self.planted && self.original_byte != 0 {
            BpOrigin::Planted
        } else {
            BpOrigin::Logical
        }
    }
    pub fn mark_planted(&mut self, orig: u8) {
        self.original_byte = orig;
        self.planted = true;
        self.enabled = true;
    }
    #[allow(dead_code)]
    pub fn mark_logical(&mut self) {
        self.planted = false;
        self.enabled = false;
    }
}

impl std::fmt::Display for BpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Display for Breakpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at {:#x} [{}]",
            self.name,
            self.address,
            if self.enabled { "enabled" } else { "disabled" }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepOverTemp {
    pub addr: u64,
    pub token: u64,
}

impl std::fmt::Display for StepOverTemp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "step_over {:#x} (token {})", self.addr, self.token)
    }
}

pub fn lock_state<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| {
        eprintln!("[debugger] state lock poisoned, recovering inner guard");
        p.into_inner()
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExceptionAction {
    Forward,
    Swallow,
    Pause,
}

#[allow(dead_code)]
pub fn policy_for(state: &DebugState, code: u32) -> Option<ExceptionAction> {
    let map: std::collections::HashMap<u32, ExceptionAction> =
        state.exception_policy.iter().copied().collect();
    map.get(&code).copied()
}

#[allow(dead_code)]
pub fn set_policy(state: &mut DebugState, code: u32, action: ExceptionAction) {
    if let Some(slot) = state.exception_policy.iter_mut().find(|(c, _)| *c == code) {
        slot.1 = action;
    } else {
        state.exception_policy.push((code, action));
    }
}

#[derive(Debug, Clone)]
pub struct DebugState {
    pub is_running: bool,
    pub is_attached: bool,
    pub process_id: u32,
    pub thread_id: u32,
    pub active_tid: u32,
    pub registers: Registers,
    pub breakpoints: Vec<Breakpoint>,
    pub stack_data: Vec<u8>,
    pub current_rip: u64,
    pub step_into: bool,
    pub step_over: bool,
    pub continue_exec: bool,
    pub break_exec: bool,
    pub stop: bool,
    pub start_debug: bool,
    pub events: Vec<String>,
    pub mem_read_request: Option<MemReadRequest>,
    pub mem_read_result: Option<MemReadResult>,
    pub mem_write_request: Option<MemWriteRequest>,
    pub mem_write_result: Option<MemWriteResult>,
    pub mem_request_seq: u64,
    pub mem_regions_request: Option<u64>,
    pub mem_regions_result: Option<(u64, Result<Vec<MemoryRegion>, String>)>,
    pub modules_request: Option<u64>,
    pub modules_result: Option<(u64, Result<Vec<ModuleInfo>, String>)>,
    pub threads_request: Option<u64>,
    pub threads_result: Option<(u64, Result<Vec<u32>, String>)>,
    pub hw_bp_request: Option<HwBpRequest>,
    pub hw_bp_result: Option<(u64, Result<(), String>)>,
    pub arm_int3_request: Option<(u64, u64)>,
    pub arm_int3_result: Option<(u64, Result<u8, String>)>,
    pub attach_request: Option<(u64, u32)>,
    pub attach_result: Option<(u64, Result<(), String>)>,
    pub detach_request: Option<u64>,
    pub detach_result: Option<(u64, Result<(), String>)>,
    pub forward_exceptions: bool,
    pub auto_continue_after_bp: bool,
    pub stop_at_entry: bool,
    pub stealth_patches: bool,
    pub exception_policy: Vec<(u32, ExceptionAction)>,
    pub trace_active: bool,
    pub trace_buffer: Vec<TraceEntry>,
    pub trace_max: usize,
    pub step_over_temp: Option<StepOverTemp>,
    pub step_over_plants: std::collections::HashMap<u64, StepOverTemp>,
    pub step_over_seq: u64,
    pub trace_snap: u64,
    pub signal: Arc<DebugSignal>,
}

#[derive(Debug, Default)]
pub struct DebugSignal {
    pub mutex: std::sync::Mutex<u64>,
    pub condvar: std::sync::Condvar,
}

impl DebugSignal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            mutex: std::sync::Mutex::new(0),
            condvar: std::sync::Condvar::new(),
        })
    }

    pub fn notify(&self) {
        {
            let mut g = self.mutex.lock().unwrap_or_else(|p| p.into_inner());
            *g = g.wrapping_add(1);
        }
        self.condvar.notify_all();
    }

    pub fn wait_flag(&self, timeout: std::time::Duration) -> bool {
        let g = self.mutex.lock().unwrap_or_else(|p| {
            eprintln!("[debugger] signal lock poisoned, recovering");
            p.into_inner()
        });
        let start = *g;
        match self
            .condvar
            .wait_timeout_while(g, timeout, |gen| *gen == start)
        {
            Ok((_, res)) => !res.timed_out(),
            Err(_) => false,
        }
    }

    pub fn wait_timeout(&self, timeout: std::time::Duration) -> bool {
        self.wait_flag(timeout)
    }

    pub fn wait(&self, timeout: std::time::Duration) -> bool {
        self.wait_flag(timeout)
    }
}

#[derive(Debug, Clone)]
pub enum HwBpRequest {
    Set {
        id: u64,
        slot: u8,
        address: u64,
        kind: HwBpKind,
        len: HwBpLen,
    },
    Clear {
        id: u64,
        slot: u8,
    },
}

#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub rip: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsp: u64,
    pub ts: u64,
    #[allow(dead_code)]
    pub snap: u64,
    #[allow(dead_code)]
    pub instant: Option<std::time::Instant>,
}

impl TraceEntry {
    pub fn now(rip: u64, rax: u64, rcx: u64, rdx: u64, rsp: u64, snap: u64) -> Self {
        Self {
            rip,
            rax,
            rcx,
            rdx,
            rsp,
            ts: now_micros_instant(),
            snap,
            instant: Some(std::time::Instant::now()),
        }
    }
}

pub fn now_micros_instant() -> u64 {
    use std::sync::OnceLock;
    static ANCHOR_WALL: OnceLock<u64> = OnceLock::new();
    static ANCHOR_MONO: OnceLock<std::time::Instant> = OnceLock::new();
    let wall0 = *ANCHOR_WALL.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    });
    let mono0 = *ANCHOR_MONO.get_or_init(std::time::Instant::now);
    wall0.wrapping_add(mono0.elapsed().as_micros() as u64)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ThreadInfo {
    pub tid: u32,
    pub state: String,
    pub rip: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StackFrameInfo {
    pub level: u32,
    pub pc: u64,
    pub func: String,
}

#[derive(Debug, Clone)]
pub struct MemReadRequest {
    pub id: u64,
    pub address: u64,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct MemReadResult {
    pub id: u64,
    pub address: u64,
    pub data: Result<Vec<u8>, String>,
}

#[derive(Debug, Clone)]
pub struct MemWriteRequest {
    pub id: u64,
    pub address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MemWriteResult {
    pub id: u64,
    pub address: u64,
    pub written: Result<usize, String>,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub protection: u32,
    pub state: u32,
    pub kind: u32,
    pub mapped_file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBpKind {
    Execute,
    Write,
    ReadWrite,
    Read,
}

#[derive(Debug, Clone, Copy)]
pub enum HwBpLen {
    One,
    Two,
    Four,
    Eight,
}

impl DebugState {
    pub fn new() -> Self {
        Self {
            is_running: false,
            is_attached: false,
            process_id: 0,
            thread_id: 0,
            active_tid: 0,
            registers: Registers::new(),
            breakpoints: Vec::new(),
            stack_data: Vec::new(),
            current_rip: 0,
            step_into: false,
            step_over: false,
            continue_exec: false,
            break_exec: false,
            stop: false,
            start_debug: false,
            events: Vec::new(),
            mem_read_request: None,
            mem_read_result: None,
            mem_write_request: None,
            mem_write_result: None,
            mem_request_seq: 0,
            mem_regions_request: None,
            mem_regions_result: None,
            modules_request: None,
            modules_result: None,
            threads_request: None,
            threads_result: None,
            hw_bp_request: None,
            hw_bp_result: None,
            arm_int3_request: None,
            arm_int3_result: None,
            attach_request: None,
            attach_result: None,
            detach_request: None,
            detach_result: None,
            forward_exceptions: true,
            auto_continue_after_bp: false,
            stop_at_entry: true,
            stealth_patches: true,
            exception_policy: Vec::new(),
            trace_active: false,
            trace_buffer: Vec::new(),
            trace_max: 4096,
            step_over_temp: None,
            step_over_plants: std::collections::HashMap::new(),
            step_over_seq: 0,
            trace_snap: 0,
            signal: DebugSignal::new(),
        }
    }

    pub fn next_step_over(&mut self, addr: u64) -> StepOverTemp {
        self.step_over_seq = self.step_over_seq.wrapping_add(1);
        let spec = StepOverTemp {
            addr,
            token: self.step_over_seq,
        };
        self.step_over_temp = Some(spec);
        self.step_over_plants.insert(spec.token, spec);
        spec
    }

    #[allow(dead_code)]
    pub fn take_step_over(&mut self, token: u64) -> Option<StepOverTemp> {
        let spec = self.step_over_plants.remove(&token)?;
        if self.step_over_temp.map(|s| s.token) == Some(token) {
            self.step_over_temp = None;
        }
        Some(spec)
    }

    #[allow(dead_code)]
    pub fn consume_step_over_at(&mut self, addr: u64) -> Option<StepOverTemp> {
        let tok = self
            .step_over_plants
            .iter()
            .find(|(_, s)| s.addr == addr)
            .map(|(t, _)| *t)?;
        self.take_step_over(tok)
    }

    pub fn next_trace_snap(&mut self) -> u64 {
        self.trace_snap = self.trace_snap.wrapping_add(1);
        self.trace_snap
    }

    #[allow(dead_code)]
    pub fn result_is_fresh(&self, id: u64) -> bool {
        id != 0 && id >= self.mem_request_seq.saturating_sub(16)
    }

    #[allow(dead_code)]
    pub fn request_mem_read(&mut self, id: u64, address: u64, size: usize) -> Result<(), String> {
        if self.mem_read_request.is_some() {
            return Err("mem_read slot busy, retry".into());
        }
        if self.mem_read_result.is_some() {
            return Err("mem_read result busy (unconsumed), retry".into());
        }
        if id != 0 && id < self.mem_request_seq {
            return Err("mem_read stale seq, retry with fresh id".into());
        }
        self.mem_request_seq = self.mem_request_seq.max(id);
        self.mem_read_request = Some(MemReadRequest { id, address, size });
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_mem_write(
        &mut self,
        id: u64,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        if self.mem_write_request.is_some() {
            return Err("mem_write slot busy, retry".into());
        }
        if self.mem_write_result.is_some() {
            return Err("mem_write result busy (unconsumed), retry".into());
        }
        if id != 0 && id < self.mem_request_seq {
            return Err("mem_write stale seq, retry with fresh id".into());
        }
        self.mem_request_seq = self.mem_request_seq.max(id);
        self.mem_write_request = Some(MemWriteRequest { id, address, bytes });
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_mem_regions(&mut self, id: u64) -> Result<(), String> {
        if self.mem_regions_request.is_some() {
            return Err("mem_regions slot busy, retry".into());
        }
        if self.mem_regions_result.is_some() {
            return Err("mem_regions result busy (unconsumed), retry".into());
        }
        if id != 0 && id < self.mem_request_seq {
            return Err("mem_regions stale seq, retry with fresh id".into());
        }
        self.mem_request_seq = self.mem_request_seq.max(id);
        self.mem_regions_request = Some(id);
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_modules(&mut self, id: u64) -> Result<(), String> {
        if self.modules_request.is_some() {
            return Err("modules slot busy, retry".into());
        }
        if self.modules_result.is_some() {
            return Err("modules result busy (unconsumed), retry".into());
        }
        if id != 0 && id < self.mem_request_seq {
            return Err("modules stale seq, retry with fresh id".into());
        }
        self.mem_request_seq = self.mem_request_seq.max(id);
        self.modules_request = Some(id);
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_threads(&mut self, id: u64) -> Result<(), String> {
        if self.threads_request.is_some() {
            return Err("threads slot busy, retry".into());
        }
        if self.threads_result.is_some() {
            return Err("threads result busy (unconsumed), retry".into());
        }
        if id != 0 && id < self.mem_request_seq {
            return Err("threads stale seq, retry with fresh id".into());
        }
        self.mem_request_seq = self.mem_request_seq.max(id);
        self.threads_request = Some(id);
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_hw_bp(&mut self, req: HwBpRequest) -> Result<(), String> {
        if self.hw_bp_request.is_some() {
            return Err("hw_bp slot busy, retry".into());
        }
        if self.hw_bp_result.is_some() {
            return Err("hw_bp result busy (unconsumed), retry".into());
        }
        self.hw_bp_request = Some(req);
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_arm_int3(&mut self, id: u64, address: u64) -> Result<(), String> {
        if self.arm_int3_request.is_some() {
            return Err("arm_int3 slot busy, retry".into());
        }
        if self.arm_int3_result.is_some() {
            return Err("arm_int3 result busy (unconsumed), retry".into());
        }
        self.arm_int3_request = Some((id, address));
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_attach(&mut self, id: u64, pid: u32) -> Result<(), String> {
        if self.attach_request.is_some() {
            return Err("attach slot busy, retry".into());
        }
        if self.attach_result.is_some() {
            return Err("attach result busy (unconsumed), retry".into());
        }
        self.attach_request = Some((id, pid));
        Ok(())
    }
    #[allow(dead_code)]
    pub fn request_detach(&mut self, id: u64) -> Result<(), String> {
        if self.detach_request.is_some() {
            return Err("detach slot busy, retry".into());
        }
        if self.detach_result.is_some() {
            return Err("detach result busy (unconsumed), retry".into());
        }
        self.detach_request = Some(id);
        Ok(())
    }
}

impl Default for DebugState {
    fn default() -> Self {
        Self::new()
    }
}
