use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
pub use super::linux::thread::spawn_debug_thread;
#[cfg(target_os = "windows")]
pub use super::windows::thread::spawn_debug_thread;

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) fn lock_app<'a>(
    state: &'a Arc<Mutex<crate::gui::AppState>>,
) -> std::sync::MutexGuard<'a, crate::gui::AppState> {
    crate::debugger::lock_state(state)
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) fn step_over_target(
    disasm: &Option<crate::disasm::DisasmResult>,
    rip: u64,
) -> Option<u64> {
    let dis = disasm.as_ref()?;
    let insns = &dis.instructions;
    let idx = insns.partition_point(|i| i.address < rip);
    let insn = insns.get(idx).filter(|i| i.address == rip)?;
    if insn.mnem() != "call" {
        return None;
    }
    let len = insn.bytes_slice().len() as u64;
    if len == 0 {
        return None;
    }
    Some(rip.wrapping_add(len))
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) fn step_over_tmp_bp(next: u64) -> crate::debugger::Breakpoint {
    crate::debugger::Breakpoint {
        address: next,
        enabled: true,
        original_byte: 0,
        name: "step_over_temp".into(),
        kind: crate::debugger::BpKind::SwExec,
        len: 1,
        planted: false,
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) fn cleanup_step_over(
    d: &mut crate::debugger::DebugState,
    pending_rearm_addr: Option<u64>,
) -> bool {
    let temp = match d
        .step_over_temp
        .or_else(|| d.step_over_plants.values().copied().max_by_key(|s| s.token))
    {
        Some(t) => t,
        None => return false,
    };
    let rip = d.current_rip;
    if !d.is_running && (rip == temp.addr || rip == temp.addr.wrapping_add(1)) {
        d.breakpoints.retain(|b| b.address != temp.addr);
        if d.step_over_temp.map(|s| s.token) == Some(temp.token) {
            d.step_over_temp = None;
        }
        d.step_over_plants.remove(&temp.token);
        d.step_over_plants.retain(|_, s| s.addr != temp.addr);
        if d.step_over_temp.map(|s| s.addr) == Some(temp.addr) {
            d.step_over_temp = None;
        }
        if pending_rearm_addr == Some(temp.addr) {
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) fn merge_pump_tail(
    d: &mut crate::debugger::DebugState,
    local_events: &[String],
    orig_events: usize,
    local_trace: &[crate::debugger::TraceEntry],
    orig_trace: usize,
) {
    if local_events.len() > orig_events {
        d.events.extend(local_events[orig_events..].iter().cloned());
    }
    if d.events.len() > 1024 {
        let n = d.events.len();
        d.events.drain(..n - 1024);
    }
    if local_trace.len() > orig_trace {
        d.trace_buffer
            .extend(local_trace[orig_trace..].iter().cloned());
    }
    if d.trace_buffer.len() > d.trace_max {
        let n = d.trace_buffer.len();
        let m = d.trace_max;
        d.trace_buffer.drain(..n - m);
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) struct PumpErr {
    count: u64,
    last: std::time::Instant,
}
#[cfg(any(target_os = "windows", target_os = "linux"))]
impl PumpErr {
    pub(crate) fn new() -> Self {
        Self {
            count: 0,
            last: std::time::Instant::now() - std::time::Duration::from_secs(3600),
        }
    }
    pub(crate) fn note(&mut self) -> (u64, bool) {
        self.count += 1;
        let n = self.count;
        let shift = ((n.saturating_sub(1)) / 5).min(5);
        let backoff = (1u64 << shift).min(30);
        let due = n == 1 || self.last.elapsed().as_secs() >= backoff;
        if due {
            self.last = std::time::Instant::now();
        }
        (n, due)
    }
    pub(crate) fn reset(&mut self) {
        self.count = 0;
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn spawn_debug_thread(_state: Arc<Mutex<crate::gui::AppState>>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("rust-debugger-debug-loop-stub".into())
        .spawn(|| {})
        .expect("Failed to spawn debug-thread stub")
}
