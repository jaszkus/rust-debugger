pub mod state;
pub mod thread;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::ptrace;

#[cfg(target_os = "windows")]
pub use windows::win_impl as win_debugger;

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
#[path = "win_stub.rs"]
pub mod win_debugger;

#[allow(unused_imports)]
pub use state::{
    lock_state, now_micros_instant, policy_for, set_policy, BpKind, Breakpoint, DebugSignal,
    DebugState, ExceptionAction, HwBpKind, HwBpLen, HwBpRequest, MemReadRequest, MemReadResult,
    MemWriteRequest, MemWriteResult, MemoryRegion, ModuleInfo, Registers, StackFrameInfo,
    StepOverTemp, ThreadInfo, TraceEntry,
};
