pub struct EmuConfig {
    pub max_steps: usize,
    pub max_call_depth: usize,
    pub stack_top: u64,
    pub stack_size: u64,
    pub canary: u64,
    pub max_writes: usize,
    pub strict_uninit: bool,
    pub follow_tailcalls: bool,
}

impl Default for EmuConfig {
    fn default() -> Self {
        Self {
            max_steps: 200_000,
            max_call_depth: 32,
            stack_top: 0x7fff_ff00_0000,
            stack_size: 8 << 20,
            canary: 0xA5A5_A5A5_A5A5_A5A5,
            max_writes: 4096,
            strict_uninit: false,
            follow_tailcalls: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EndReason {
    Returned,
    MaxSteps,
    UnmappedRip(u64),
    IndirectUnknown(u64),
    CallToImport(String),
    UnmappedCall(u64),
    OobRead(u64),
    UninitRead(u64),
    OobWrite(u64),
    StackOverflow(u64),
    StackUnderflow(u64),
    DivByZero,
    Trap(String),
    Unmodeled(String),
    LeftFunction(u64),
}

#[derive(Debug, Clone)]
pub struct MemWrite {
    pub addr: u64,
    pub size: u32,
    pub old: u64,
    pub new: u64,
}

#[derive(Debug, Clone)]
pub struct EmuResult {
    pub reason: EndReason,
    pub rax: u64,
    pub steps: usize,
    pub writes: Vec<MemWrite>,
    pub dropped_writes: usize,
    pub stack_writes: usize,
    pub trace_tail: Vec<u64>,
}
