pub mod memory;

use crate::debugger::{now_micros_instant, Breakpoint, DebugState, Registers};

#[cfg(target_os = "linux")]
const PTRACE_O_TRACECLONE: u64 = 0x0000_0008;
#[cfg(target_os = "linux")]
const PTRACE_O_TRACEFORK: u64 = 0x0000_0002;
#[cfg(target_os = "linux")]
const PTRACE_O_TRACEEXEC: u64 = 0x0000_0010;
#[cfg(target_os = "linux")]
const PTRACE_O_TRACEEXIT: u64 = 0x0000_0040;
#[cfg(target_os = "linux")]
const PTRACE_SETOPTIONS: u32 = 0x4200;

pub(super) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub struct PtraceDebugger {
    pub is_active: bool,
    pub process_id: u32,
    pub pending_rearm: Option<(u64, u8)>,
    pub pending_queue: Vec<(u64, u8)>,
    pub(super) pending_signal: i32,
    pub pending_signals: Vec<i32>,
    pub at_initial_stop: bool,
    pub(super) entry_bp: Option<(u64, u8)>,
    pub(super) maps_cache: std::cell::RefCell<(std::time::Instant, std::rc::Rc<Vec<String>>)>,
    pub(super) task_cache: std::cell::RefCell<(std::time::Instant, Vec<u32>)>,
}

impl Default for PtraceDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl PtraceDebugger {
    pub fn new() -> Self {
        let ancient = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        Self {
            is_active: false,
            process_id: 0,
            pending_rearm: None,
            pending_queue: Vec::new(),
            pending_signal: 0,
            pending_signals: Vec::new(),
            at_initial_stop: false,
            entry_bp: None,
            maps_cache: std::cell::RefCell::new((ancient, std::rc::Rc::new(Vec::new()))),
            task_cache: std::cell::RefCell::new((ancient, Vec::new())),
        }
    }

    fn set_trace_options(&self, pid: libc::pid_t) {
        let flags =
            (PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT)
                as *mut libc::c_void;
        unsafe {
            libc::ptrace(
                PTRACE_SETOPTIONS,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                flags,
            );
        }
    }

    pub fn launch_process(&mut self, path: &str) -> Result<(), String> {
        if self.is_active {
            return Err("Debugger already active".into());
        }
        let canon = std::fs::canonicalize(path)
            .map_err(|e| format!("Cannot resolve target '{}': {}", path, e))?;
        let cpath = std::ffi::CString::new(canon.to_string_lossy().as_bytes().to_vec())
            .map_err(|_| "Target path contains NUL".to_string())?;
        let argv0 = cpath.clone();

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork failed: errno {}", errno()));
        }
        if pid == 0 {
            unsafe {
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                ) != 0
                {
                    libc::_exit(126);
                }
                libc::raise(libc::SIGSTOP);
                let argv = [argv0.as_ptr(), std::ptr::null()];
                libc::execv(cpath.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
        }

        self.process_id = pid as u32;
        let mut status = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut saw_stop = false;
        let mut saw_exec = false;
        while std::time::Instant::now() < deadline {
            let w = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
            if w != pid {
                if errno() == libc::EINTR {
                    continue;
                }
                break;
            }
            if libc::WIFEXITED(status) {
                let code = libc::WEXITSTATUS(status);
                self.process_id = 0;
                return Err(if code == 127 {
                    format!("exec failed for '{}' (missing loader? noexec mount?)", path)
                } else if code == 126 {
                    "PTRACE_TRACEME refused (Yama ptrace_scope?)".into()
                } else {
                    format!("Target exited immediately with code {}", code)
                });
            }
            if libc::WIFSIGNALED(status) {
                self.process_id = 0;
                return Err(format!(
                    "Target killed by signal {} on launch",
                    libc::WTERMSIG(status)
                ));
            }
            if libc::WIFSTOPPED(status) {
                let sig = libc::WSTOPSIG(status);
                if !saw_stop && sig == libc::SIGSTOP {
                    saw_stop = true;
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_CONT,
                            pid,
                            std::ptr::null_mut::<libc::c_void>(),
                            sig as *mut libc::c_void,
                        );
                    }
                    continue;
                }
                if sig == libc::SIGTRAP {
                    saw_exec = true;
                    break;
                }
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_CONT,
                        pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        sig as *mut libc::c_void,
                    );
                }
            }
        }
        if !saw_exec {
            self.terminate();
            return Err("Launch handshake timed out (no exec trap)".into());
        }
        self.set_trace_options(pid);
        self.is_active = true;
        self.at_initial_stop = true;
        self.pending_signal = 0;
        self.pending_signals.clear();
        self.pending_rearm = None;
        self.pending_queue.clear();
        self.entry_bp = None;
        self.invalidate_maps();
        self.invalidate_tasks();
        Ok(())
    }

    pub fn attach_process(&mut self, pid: u32) -> Result<(), String> {
        if self.is_active {
            return Err("Debugger already active".into());
        }
        let r = unsafe {
            libc::ptrace(
                libc::PTRACE_ATTACH,
                pid as libc::pid_t,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if r != 0 {
            return Err(format!(
                "PTRACE_ATTACH({}) failed: errno {} (Yama ptrace_scope=1 only allows tracing children; run as the same user or root)",
                pid,
                errno()
            ));
        }
        let mut status = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let w = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WUNTRACED) };
            if w == pid as libc::pid_t && libc::WIFSTOPPED(status) {
                break;
            }
            if std::time::Instant::now() > deadline {
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        pid as libc::pid_t,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    );
                }
                return Err("Attach handshake timed out".into());
            }
            if w < 0 && errno() != libc::EINTR {
                return Err(format!("waitpid during attach: errno {}", errno()));
            }
        }
        self.is_active = true;
        self.process_id = pid;
        self.at_initial_stop = true;
        self.pending_signal = 0;
        self.pending_signals.clear();
        self.pending_rearm = None;
        self.pending_queue.clear();
        self.entry_bp = None;
        self.invalidate_maps();
        self.invalidate_tasks();
        self.set_trace_options(pid as libc::pid_t);
        Ok(())
    }

    pub fn detach_process(&mut self, breakpoints: &[Breakpoint]) -> Result<(), String> {
        if !self.is_active {
            return Ok(());
        }
        for bp in breakpoints.iter().filter(|b| b.enabled) {
            let _ = self.remove_breakpoint(bp);
        }
        self.pending_rearm = None;
        self.pending_queue.clear();
        self.pending_signal = 0;
        self.pending_signals.clear();
        self.entry_bp = None;
        self.invalidate_maps();
        self.invalidate_tasks();
        let pid = self.process_id as libc::pid_t;
        let r = unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        self.is_active = false;
        self.process_id = 0;
        self.pending_rearm = None;
        self.pending_queue.clear();
        self.pending_signal = 0;
        self.pending_signals.clear();
        self.entry_bp = None;
        if r != 0 {
            return Err(format!("PTRACE_DETACH failed: errno {}", errno()));
        }
        Ok(())
    }

    pub fn terminate(&mut self) {
        if self.process_id != 0 {
            unsafe {
                libc::kill(self.process_id as libc::pid_t, libc::SIGKILL);
                let mut status = 0;
                for _ in 0..8 {
                    let w =
                        libc::waitpid(self.process_id as libc::pid_t, &mut status, libc::WNOHANG);
                    if w == self.process_id as libc::pid_t || (w < 0 && errno() == libc::ECHILD) {
                        break;
                    }
                }
            }
        }
        self.is_active = false;
        self.process_id = 0;
        self.pending_rearm = None;
        self.pending_queue.clear();
        self.pending_signal = 0;
        self.pending_signals.clear();
        self.entry_bp = None;
    }

    pub fn is_process_alive(&self) -> bool {
        if self.process_id == 0 {
            return false;
        }
        let pid = self.process_id as libc::pid_t;
        unsafe {
            let mut status = 0;
            let w = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if w == pid {
                return false;
            }
            *libc::__errno_location() = 0;
            if libc::kill(pid, 0) == 0 {
                if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", self.process_id))
                    && let Some(rparen) = stat.rfind(')')
                    && stat[rparen..].split_whitespace().nth(1) == Some("Z")
                {
                    return false;
                }
                return true;
            }
            match errno() {
                e if e == libc::ESRCH => false,
                e if e == libc::EPERM => true,
                _ => false,
            }
        }
    }

    pub(super) fn cont_raw(&mut self, sig: i32) -> Result<(), String> {
        let r = unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                self.process_id as libc::pid_t,
                std::ptr::null_mut::<libc::c_void>(),
                sig as *mut libc::c_void,
            )
        };
        if r != 0 {
            return Err(format!("PTRACE_CONT failed: errno {}", errno()));
        }
        Ok(())
    }

    pub fn continue_execution(&mut self) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        if let Some((addr, orig)) = self.pending_rearm.take() {
            self.step_over_planted(addr, orig)?;
        }
        while let Some((addr, orig)) = self.pending_queue.pop() {
            self.step_over_planted(addr, orig)?;
        }
        let sig = if self.pending_signal != 0 {
            let s = self.pending_signal;
            self.pending_signal = 0;
            s
        } else if !self.pending_signals.is_empty() {
            self.pending_signals.remove(0)
        } else {
            0
        };
        self.at_initial_stop = false;
        self.cont_raw(sig)
    }

    pub fn resume_paused(&mut self) -> Result<(), String> {
        self.continue_execution()
    }

    pub fn interrupt(&self) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let r = unsafe { libc::kill(self.process_id as libc::pid_t, libc::SIGSTOP) };
        if r != 0 {
            return Err(format!("SIGSTOP failed: errno {}", errno()));
        }
        Ok(())
    }

    pub fn set_single_step(&self) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let mut regs = self.get_regs_raw()?;
        regs.eflags |= 0x100;
        self.set_regs_raw(&regs)
    }

    pub(super) fn get_regs_raw(&self) -> Result<libc::user_regs_struct, String> {
        self.get_regs_raw_tid(self.process_id as libc::pid_t)
    }

    pub(super) fn get_regs_raw_tid(
        &self,
        tid: libc::pid_t,
    ) -> Result<libc::user_regs_struct, String> {
        let mut regs: libc::user_regs_struct =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        let r = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                tid,
                std::ptr::null_mut::<libc::c_void>(),
                &mut regs as *mut _ as *mut libc::c_void,
            )
        };
        if r != 0 {
            return Err(format!(
                "PTRACE_GETREGS(tid {}) failed: errno {}",
                tid,
                errno()
            ));
        }
        Ok(regs)
    }

    pub(super) fn set_regs_raw(&self, regs: &libc::user_regs_struct) -> Result<(), String> {
        self.set_regs_raw_tid(self.process_id as libc::pid_t, regs)
    }

    pub(super) fn set_regs_raw_tid(
        &self,
        tid: libc::pid_t,
        regs: &libc::user_regs_struct,
    ) -> Result<(), String> {
        let r = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGS,
                tid,
                std::ptr::null_mut::<libc::c_void>(),
                regs as *const _ as *mut libc::c_void,
            )
        };
        if r != 0 {
            return Err(format!(
                "PTRACE_SETREGS(tid {}) failed: errno {}",
                tid,
                errno()
            ));
        }
        Ok(())
    }

    pub fn get_registers(&self, state: &mut DebugState) -> Result<(), String> {
        let tid = if state.active_tid != 0 {
            state.active_tid as libc::pid_t
        } else {
            self.process_id as libc::pid_t
        };
        self.get_registers_for(tid, state)
    }

    pub fn get_registers_for(
        &self,
        tid: libc::pid_t,
        state: &mut DebugState,
    ) -> Result<(), String> {
        let r = self.get_regs_raw_tid(tid)?;
        state.registers = Registers {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rbp: r.rbp,
            rsp: r.rsp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            eflags: r.eflags as u32,
        };
        state.current_rip = r.rip;
        state.stack_data = self.read_memory(r.rsp, 0x400).unwrap_or_default();
        Ok(())
    }

    fn append_trace(&self, state: &mut DebugState) {
        if state.trace_buffer.len() < state.trace_max {
            let snap = state.next_trace_snap();
            state.trace_buffer.push(crate::debugger::TraceEntry::now(
                state.registers.rip,
                state.registers.rax,
                state.registers.rcx,
                state.registers.rdx,
                state.registers.rsp,
                snap,
            ));
            if let Some(last) = state.trace_buffer.last_mut() {
                last.ts = now_micros_instant();
            }
        }
    }

    fn wait_one(&self, main: libc::pid_t, status: &mut i32) -> Option<libc::pid_t> {
        let mut st = 0;
        let w = unsafe {
            libc::waitpid(
                main,
                &mut st,
                libc::WNOHANG | libc::__WALL | libc::WUNTRACED | libc::WCONTINUED,
            )
        };
        if w > 0 {
            *status = st;
            return Some(w);
        }
        let mut st2 = 0;
        let w2 = unsafe {
            libc::waitpid(
                -1,
                &mut st2,
                libc::WNOHANG | libc::__WALL | libc::WUNTRACED | libc::WCONTINUED,
            )
        };
        if w2 > 0 {
            *status = st2;
            return Some(w2);
        }
        None
    }

    pub fn process_debug_event(&mut self, state: &mut DebugState) -> Result<bool, String> {
        if !self.is_active {
            return Ok(false);
        }
        let main_pid = self.process_id as libc::pid_t;
        self.invalidate_tasks();
        let known: Vec<u32> = self.cached_threads();
        let mut status = 0;
        loop {
            let w = match self.wait_one(main_pid, &mut status) {
                Some(tid) => tid,
                None => {
                    if !self.is_process_alive() {
                        self.is_active = false;
                        return Ok(false);
                    }
                    break;
                }
            };
            let tid = w;
            let is_main = w as u32 == self.process_id;
            let is_known_thread = state.thread_id == w as u32
                || state.active_tid == w as u32
                || known.contains(&(w as u32));
            if !is_main && !is_known_thread {
                if !is_main && !self.is_process_alive() {
                    self.is_active = false;
                    return Ok(false);
                }
                let alive_main = unsafe { libc::kill(self.process_id as libc::pid_t, 0) == 0 };
                if !alive_main && is_known_thread {
                } else if !is_known_thread {
                    continue;
                }
            }
            if libc::WIFEXITED(status) {
                let code = libc::WEXITSTATUS(status);
                state.events.push(format!("Target exited (code {})", code));
                state.is_attached = false;
                state.is_running = false;
                state.process_id = 0;
                self.is_active = false;
                self.process_id = 0;
                return Ok(false);
            }
            if libc::WIFSIGNALED(status) {
                let sig = libc::WTERMSIG(status);
                state
                    .events
                    .push(format!("Target killed by signal {}", sig));
                state.is_attached = false;
                state.is_running = false;
                state.process_id = 0;
                self.is_active = false;
                self.process_id = 0;
                return Ok(false);
            }
            if libc::WIFCONTINUED(status) {
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            let sig = libc::WSTOPSIG(status);
            let _ = self.get_registers_for(tid, state);
            state.thread_id = tid as u32;
            if state.active_tid == 0 {
                state.active_tid = tid as u32;
            }

            if sig == libc::SIGTRAP {
                clear_tf_tid(self, tid);
                let rip = state.registers.rip;
                if let Some((entry, orig)) = self.entry_bp.take() {
                    if rip.wrapping_sub(1) == entry {
                        let mut regs = self.get_regs_raw_tid(tid)?;
                        regs.rip = entry;
                        let _ = self.set_regs_raw_tid(tid, &regs);
                        state.registers.rip = entry;
                        state.current_rip = entry;
                        let aligned = entry & !7u64;
                        let off = (entry - aligned) as usize;
                        if let Ok(word) = self.peek_word(aligned) {
                            let mut bytes = word.to_ne_bytes();
                            if bytes[off] == 0xCC {
                                bytes[off] = orig;
                                let _ = self.poke_word(aligned, u64::from_ne_bytes(bytes));
                            }
                        }
                        let _ = self.get_registers_for(tid, state);
                        state.events.push(format!("Stopped at entry {:#x}", entry));
                        state.is_running = false;
                        state.thread_id = tid as u32;
                        if state.active_tid == 0 {
                            state.active_tid = tid as u32;
                        }
                        continue;
                    }
                    self.entry_bp = Some((entry, orig));
                }
                let bp_addr = rip.wrapping_sub(1);
                let ours = state
                    .breakpoints
                    .iter()
                    .find(|b| b.enabled && b.address == bp_addr);
                let confirmed = ours.is_some()
                    && self
                        .read_memory(bp_addr, 1)
                        .is_ok_and(|b| b.first() == Some(&0xCC));
                if confirmed {
                    let mut regs = self.get_regs_raw_tid(tid)?;
                    regs.rip = bp_addr;
                    let _ = self.set_regs_raw_tid(tid, &regs);
                    state.registers.rip = bp_addr;
                    state.current_rip = bp_addr;
                    let orig = ours.map(|b| b.original_byte).unwrap_or(0xCC);
                    let aligned = bp_addr & !7u64;
                    let off = (bp_addr - aligned) as usize;
                    if let Ok(word) = self.peek_word(aligned) {
                        let mut bytes = word.to_ne_bytes();
                        if bytes[off] == 0xCC {
                            bytes[off] = orig;
                            let _ = self.poke_word(aligned, u64::from_ne_bytes(bytes));
                        }
                    }
                    if let Some(prev) = self.pending_rearm.take() {
                        self.pending_queue.push(prev);
                    }
                    self.pending_rearm = Some((bp_addr, orig));
                    state
                        .events
                        .push(format!("Breakpoint hit at {:#x}", bp_addr));
                    if state.trace_active {
                        self.append_trace(state);
                    }
                    state.is_running = false;
                } else if state.trace_active {
                    self.append_trace(state);
                    let _ = self.set_single_step();
                    let _ = self.cont_raw(0);
                    state.is_running = true;
                    continue;
                } else {
                    state
                        .events
                        .push(format!("Stopped (SIGTRAP) at {:#x}", rip));
                    state.is_running = false;
                }
            } else if sig == libc::SIGSTOP {
                state
                    .events
                    .push(format!("Stopped (SIGSTOP) at {:#x}", state.registers.rip));
                state.is_running = false;
            } else {
                let signame = signal_name(sig);
                state.events.push(format!(
                    "Target stopped by {} at {:#x}",
                    signame, state.registers.rip
                ));
                if state.forward_exceptions {
                    self.pending_signal = sig;
                    self.pending_signals.push(sig);
                }
                state.is_running = false;
            }
            state.thread_id = tid as u32;
            if state.active_tid == 0 {
                state.active_tid = tid as u32;
            }
        }
        Ok(self.is_active)
    }
}

#[allow(dead_code)]
fn clear_tf(dbg: &PtraceDebugger) {
    if let Ok(mut regs) = dbg.get_regs_raw()
        && regs.eflags & 0x100 != 0
    {
        regs.eflags &= !0x100;
        let _ = dbg.set_regs_raw(&regs);
    }
}

fn clear_tf_tid(dbg: &PtraceDebugger, tid: libc::pid_t) {
    if let Ok(mut regs) = dbg.get_regs_raw_tid(tid)
        && regs.eflags & 0x100 != 0
    {
        regs.eflags &= !0x100;
        let _ = dbg.set_regs_raw_tid(tid, &regs);
    }
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGILL => "SIGILL",
        libc::SIGABRT => "SIGABRT",
        libc::SIGFPE => "SIGFPE",
        libc::SIGBUS => "SIGBUS",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGTERM => "SIGTERM",
        libc::SIGINT => "SIGINT",
        _ => "signal",
    }
}
