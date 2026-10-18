pub mod memory;

use crate::debugger::state::*;
use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::*;

#[repr(C, align(16))]
pub(super) struct CONTEXT64 {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    pub(super) dr0: u64,
    pub(super) dr1: u64,
    pub(super) dr2: u64,
    pub(super) dr3: u64,
    dr6: u64,
    pub(super) dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    _flt_save: [u8; 512],
    _vector_register: [u8; 416],
    debug_control: u64,
    last_branch_to_rip: u64,
    last_branch_from_rip: u64,
    last_exception_to_rip: u64,
    last_exception_from_rip: u64,
}

pub(super) const CONTEXT_AMD64: u32 = 0x00100000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x01;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x02;
pub(super) const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | (CONTEXT_AMD64 | 0x08);
pub(super) const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;

unsafe extern "system" {
    pub(super) fn GetThreadContext(hthread: HANDLE, lpcontext: *mut CONTEXT64) -> BOOL;
    pub(super) fn SetThreadContext(hthread: HANDLE, lpcontext: *const CONTEXT64) -> BOOL;
}

pub struct WinDebugger {
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
    pub is_active: bool,
    pub paused_thread: Option<u32>,
    pub pending_rearm: Option<(u64, u8)>,
    pub pending_queue: Vec<(u64, u8)>,
    pub thread_handles: std::collections::HashMap<u32, HANDLE>,
    pub awaiting_initial_break: bool,
}

pub(super) fn new_context(flags: u32) -> CONTEXT64 {
    let mut ctx: CONTEXT64 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    ctx.context_flags = flags;
    ctx
}

const _: () = assert!(std::mem::align_of::<CONTEXT64>() == 16);
const _: () = assert!(std::mem::size_of::<CONTEXT64>() == 1232);
const _: () = assert!(std::mem::offset_of!(CONTEXT64, context_flags) == 48);
const _: () = assert!(std::mem::offset_of!(CONTEXT64, dr0) == 72);
const _: () = assert!(std::mem::offset_of!(CONTEXT64, dr7) == 112);
const _: () = assert!(std::mem::offset_of!(CONTEXT64, rip) == 248);

impl WinDebugger {
    pub fn new() -> Self {
        Self {
            process_handle: HANDLE::default(),
            thread_handle: HANDLE::default(),
            process_id: 0,
            thread_id: 0,
            is_active: false,
            paused_thread: None,
            pending_rearm: None,
            pending_queue: Vec::new(),
            thread_handles: std::collections::HashMap::new(),
            awaiting_initial_break: false,
        }
    }

    pub fn launch_process(&mut self, path: &str) -> Result<(), String> {
        self.terminate();

        let wide_path: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut si: STARTUPINFOW = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };

        let result = unsafe {
            CreateProcessW(
                None,
                windows::core::PWSTR(wide_path.as_ptr() as *mut _),
                None,
                None,
                false,
                DEBUG_PROCESS | CREATE_NEW_CONSOLE,
                None,
                None,
                &si,
                &mut pi,
            )
        };

        match result {
            Ok(_) => {
                self.process_handle = pi.hProcess;
                self.thread_handle = pi.hThread;
                self.process_id = pi.dwProcessId;
                self.thread_id = pi.dwThreadId;
                self.is_active = true;
                self.awaiting_initial_break = true;
                Ok(())
            }
            Err(e) => Err(format!("CreateProcess failed: {}", e)),
        }
    }

    pub fn attach_process(&mut self, pid: u32) -> Result<(), String> {
        self.terminate();
        let process_handle = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, false, pid)
                .map_err(|e| format!("OpenProcess({}): {}", pid, e))?
        };
        if let Err(e) = unsafe { DebugActiveProcess(pid) } {
            unsafe {
                let _ = CloseHandle(process_handle);
            }
            return Err(format!("DebugActiveProcess({}): {}", pid, e));
        }
        unsafe {
            let _ = DebugSetProcessKillOnExit(false);
        }
        self.process_handle = process_handle;
        self.process_id = pid;
        let first_tid = self.first_thread_of(pid);
        let thread_handle = match first_tid {
            Some(tid) => unsafe {
                OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    false,
                    tid,
                )
                .unwrap_or(HANDLE::default())
            },
            None => HANDLE::default(),
        };
        self.thread_handle = thread_handle;
        self.thread_id = 0;
        self.is_active = true;
        self.awaiting_initial_break = true;
        Ok(())
    }

    pub fn detach_process(
        &mut self,
        breakpoints: &[crate::debugger::Breakpoint],
    ) -> Result<(), String> {
        if !self.is_active {
            return Ok(());
        }
        for bp in breakpoints.iter().filter(|b| b.enabled) {
            let _ = self.write_memory(bp.address, &[bp.original_byte]);
        }
        self.pending_rearm = None;
        self.pending_queue.clear();
        for (_, h) in self.thread_handles.drain() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
        self.paused_thread = None;
        unsafe {
            for _ in 0..16 {
                let tid = self.paused_thread.take().unwrap_or(self.thread_id);
                if ContinueDebugEvent(self.process_id, tid, NTSTATUS(0x00010002)).is_err() {
                    break;
                }
            }
            let _ = DebugActiveProcessStop(self.process_id);
            let _ = CloseHandle(self.process_handle);
            if !self.thread_handle.is_invalid() {
                let _ = CloseHandle(self.thread_handle);
            }
        }
        self.process_handle = HANDLE::default();
        self.thread_handle = HANDLE::default();
        self.is_active = false;
        Ok(())
    }

    pub fn get_registers(&self, state: &mut DebugState) -> Result<(), String> {
        let mut context: CONTEXT64 = new_context(CONTEXT_FULL);

        let result = unsafe { GetThreadContext(self.thread_handle, &mut context) };
        if result == BOOL(0) {
            return Err("GetThreadContext failed".into());
        }

        state.registers.rax = context.rax;
        state.registers.rbx = context.rbx;
        state.registers.rcx = context.rcx;
        state.registers.rdx = context.rdx;
        state.registers.rsi = context.rsi;
        state.registers.rdi = context.rdi;
        state.registers.rbp = context.rbp;
        state.registers.rsp = context.rsp;
        state.registers.r8 = context.r8;
        state.registers.r9 = context.r9;
        state.registers.r10 = context.r10;
        state.registers.r11 = context.r11;
        state.registers.r12 = context.r12;
        state.registers.r13 = context.r13;
        state.registers.r14 = context.r14;
        state.registers.r15 = context.r15;
        state.registers.rip = context.rip;
        state.registers.eflags = context.eflags;
        state.current_rip = context.rip;
        Ok(())
    }

    pub fn set_single_step(&self) -> Result<(), String> {
        let mut context: CONTEXT64 = new_context(CONTEXT_FULL);

        let prev_suspend = unsafe { SuspendThread(self.thread_handle) };
        let result = unsafe { GetThreadContext(self.thread_handle, &mut context) };
        if result == BOOL(0) {
            if prev_suspend != u32::MAX {
                unsafe {
                    ResumeThread(self.thread_handle);
                }
            }
            return Err("GetThreadContext failed".into());
        }

        context.eflags |= 0x100;

        let result = unsafe { SetThreadContext(self.thread_handle, &context) };
        if prev_suspend != u32::MAX {
            unsafe {
                ResumeThread(self.thread_handle);
            }
        }
        if result == BOOL(0) {
            return Err("SetThreadContext failed".into());
        }
        Ok(())
    }

    pub fn set_rip(&self, rip: u64) -> Result<(), String> {
        let mut context: CONTEXT64 = new_context(CONTEXT_FULL);
        let result = unsafe { GetThreadContext(self.thread_handle, &mut context) };
        if result == BOOL(0) {
            return Err("GetThreadContext failed".into());
        }
        context.rip = rip;
        let result = unsafe { SetThreadContext(self.thread_handle, &context) };
        if result == BOOL(0) {
            return Err("SetThreadContext failed".into());
        }
        Ok(())
    }

    pub fn continue_execution(&mut self) -> Result<(), String> {
        let tid = self.paused_thread.take().unwrap_or(self.thread_id);
        if self.pending_rearm.is_some() {
            let _ = self.set_single_step();
        }
        unsafe {
            ContinueDebugEvent(self.process_id, tid, NTSTATUS(0x00010002))
                .map_err(|e| format!("ContinueDebugEvent: {}", e))?;
        }
        Ok(())
    }

    pub fn interrupt(&self) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        unsafe {
            DebugBreakProcess(self.process_handle)
                .map_err(|e| format!("DebugBreakProcess: {}", e))?;
        }
        Ok(())
    }

    pub fn resume_paused(&mut self) -> Result<(), String> {
        let tid = self.paused_thread.take().unwrap_or(self.thread_id);
        if self.pending_rearm.is_some() {
            let _ = self.set_single_step();
        }
        unsafe {
            ContinueDebugEvent(self.process_id, tid, NTSTATUS(0x00010002))
                .map_err(|e| format!("ContinueDebugEvent: {}", e))?;
        }
        Ok(())
    }

    fn continue_not_handled(&mut self) -> Result<(), String> {
        let tid = self.paused_thread.take().unwrap_or(self.thread_id);
        unsafe {
            ContinueDebugEvent(self.process_id, tid, NTSTATUS(0x80010001u32 as i32))
                .map_err(|e| format!("ContinueDebugEvent: {}", e))?;
        }
        Ok(())
    }

    pub fn is_process_alive(&self) -> bool {
        if !self.is_active || self.process_handle.is_invalid() {
            return false;
        }
        unsafe { WaitForSingleObject(self.process_handle, 0) != WAIT_OBJECT_0 }
    }

    pub fn wait_for_event(&self, timeout_ms: u32) -> Result<Option<DEBUG_EVENT>, String> {
        let mut event: DEBUG_EVENT = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        let result = unsafe { WaitForDebugEvent(&mut event, timeout_ms) };
        match result {
            Ok(_) => Ok(Some(event)),
            Err(e) if e.code().0 == 0x80070102u32 as i32 => Ok(None),
            Err(e) if e.code().0 == 0x80070079u32 as i32 => Ok(None),
            Err(e) => Err(format!("WaitForDebugEvent failed: {}", e)),
        }
    }

    pub fn process_debug_event(&mut self, state: &mut DebugState) -> Result<bool, String> {
        if let Some(event) = self.wait_for_event(10)? {
            self.thread_id = event.dwThreadId;
            if state.events.len() > 1024 {
                state.events.drain(..state.events.len() - 1024);
            }

            match event.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    let exc = unsafe { event.u.Exception };
                    let code = exc.ExceptionRecord.ExceptionCode;
                    let exc_addr = exc.ExceptionRecord.ExceptionAddress as u64;
                    let first_chance = exc.dwFirstChance != 0;

                    let is_bp = code == EXCEPTION_BREAKPOINT || code == NTSTATUS(0x4000_001F_i32);
                    let is_ss = code == EXCEPTION_SINGLE_STEP || code == NTSTATUS(0x4000_001E_i32);
                    if is_bp {
                        self.paused_thread = Some(event.dwThreadId);
                        let bp_hit = state
                            .breakpoints
                            .iter()
                            .find(|b| {
                                b.enabled
                                    && (b.address == exc_addr
                                        || b.address == exc_addr.wrapping_sub(1))
                            })
                            .cloned();
                        let _bp_addr = bp_hit
                            .as_ref()
                            .map(|b| b.address)
                            .unwrap_or_else(|| exc_addr.wrapping_sub(1));
                        if self.awaiting_initial_break && bp_hit.is_none() {
                            self.awaiting_initial_break = false;
                            let _ = self.get_registers(state);
                            let mut armed_ep: Option<u64> = None;
                            if state.stealth_patches {
                                match self.apply_stealth_patches() {
                                    Ok(n) => state
                                        .events
                                        .push(format!("Stealth patches applied ({} fields)", n)),
                                    Err(e) => {
                                        state.events.push(format!("Stealth patch skipped: {}", e))
                                    }
                                }
                            }
                            if state.stop_at_entry {
                                match self.arm_entry_breakpoint(state) {
                                    Ok(Some(ep)) => {
                                        armed_ep = Some(ep);
                                        state.events.push(format!(
                                            "Entry breakpoint armed at {:#x} - target will pause before first instruction", ep));
                                    }
                                    Ok(None) => {
                                        state
                                            .events
                                            .push("Entry point not resolved - free-running".into());
                                    }
                                    Err(e) => state
                                        .events
                                        .push(format!("Entry BP failed ({}), free-running", e)),
                                }
                            } else {
                                state.events.push(format!(
                                    "Initial break at {:#x} - stealth done, resuming",
                                    exc_addr
                                ));
                            }
                            let _ = armed_ep;
                            match self.resume_paused() {
                                Ok(_) => {
                                    state.is_running = true;
                                }
                                Err(e) => state
                                    .events
                                    .push(format!("Initial-break resume failed: {}", e)),
                            }
                            return Ok(true);
                        }
                        if let Some(bp) = bp_hit {
                            let _ = self.write_memory(bp.address, &[bp.original_byte]);
                            let _ = self.set_rip(bp.address);
                            self.pending_rearm = Some((bp.address, bp.original_byte));
                            state
                                .events
                                .push(format!("Breakpoint '{}' hit at {:#x}", bp, bp.address));
                        } else {
                            state.events.push(format!("Breakpoint at {:#x}", exc_addr));
                        }
                        let _ = self.get_registers(state);
                        let _ = self.read_stack(state, 32);
                        state.is_running = false;
                        if state.trace_active {
                            self.append_trace(state);
                            let _ = self.set_single_step();
                            self.continue_execution()?;
                            state.is_running = true;
                        } else if state.auto_continue_after_bp {
                            let _ = self.set_single_step();
                            self.continue_execution()?;
                            state.is_running = true;
                        }
                        return Ok(true);
                    } else if is_ss {
                        self.paused_thread = Some(event.dwThreadId);
                        if let Some((addr, _orig)) = self.pending_rearm.take() {
                            if state
                                .breakpoints
                                .iter()
                                .any(|b| b.enabled && b.address == addr)
                            {
                                let _ = self.write_memory(addr, &[0xCC]);
                            }
                            if state.trace_active || state.auto_continue_after_bp {
                                if state.trace_active {
                                    self.append_trace(state);
                                    let _ = self.set_single_step();
                                }
                                self.continue_execution()?;
                                state.is_running = true;
                                return Ok(true);
                            }
                            let _ = self.get_registers(state);
                            let _ = self.read_stack(state, 32);
                            state.is_running = false;
                            return Ok(true);
                        }
                        state.events.push(format!("Single step at {:#x}", exc_addr));
                        let _ = self.get_registers(state);
                        if state.trace_active && state.trace_buffer.len() < state.trace_max {
                            self.append_trace(state);
                            let _ = self.set_single_step();
                            self.continue_execution()?;
                            state.is_running = true;
                        } else {
                            self.read_stack(state, 32)?;
                            state.is_running = false;
                            if state.auto_continue_after_bp {
                                self.continue_execution()?;
                                state.is_running = true;
                            }
                        }
                        return Ok(true);
                    } else {
                        state.events.push(format!(
                            "Exception {:08X} at {:#x} (first_chance={})",
                            code.0, exc_addr, first_chance
                        ));
                        match crate::debugger::policy_for(state, code.0 as u32) {
                            Some(ExceptionAction::Pause) => {
                                self.paused_thread = Some(event.dwThreadId);
                                let _ = self.get_registers(state);
                                let _ = self.read_stack(state, 32);
                                state.is_running = false;
                                return Ok(true);
                            }
                            Some(ExceptionAction::Swallow) => {
                                self.continue_execution()?;
                            }
                            Some(ExceptionAction::Forward) => {
                                self.continue_not_handled()?;
                            }
                            None => {
                                if state.forward_exceptions {
                                    self.continue_not_handled()?;
                                } else {
                                    self.continue_execution()?;
                                }
                            }
                        }
                        return Ok(true);
                    }
                }
                CREATE_PROCESS_DEBUG_EVENT => {
                    state.events.push("Process created".to_string());
                    let info = unsafe { event.u.CreateProcessInfo };
                    unsafe {
                        if !info.hFile.is_invalid() {
                            let _ = CloseHandle(info.hFile);
                        }
                    }
                    if self.thread_handle.is_invalid() {
                        let h = unsafe {
                            OpenThread(
                                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                false,
                                event.dwThreadId,
                            )
                        };
                        if let Ok(h) = h {
                            self.thread_handle = h;
                        }
                    }
                    self.thread_id = event.dwThreadId;
                    self.continue_execution()?;
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    state.events.push("Process exited".to_string());
                    self.is_active = false;
                    state.is_running = false;
                    state.is_attached = false;
                    state.process_id = 0;
                    state.thread_id = 0;
                    state.active_tid = 0;
                    let _ = self.continue_execution();
                    unsafe {
                        if !self.process_handle.is_invalid() {
                            let _ = CloseHandle(self.process_handle);
                        }
                        if !self.thread_handle.is_invalid() {
                            let _ = CloseHandle(self.thread_handle);
                        }
                    }
                    self.process_handle = HANDLE::default();
                    self.thread_handle = HANDLE::default();
                    self.paused_thread = None;
                    self.pending_rearm = None;
                    self.pending_queue.clear();
                    for (_, h) in self.thread_handles.drain() {
                        unsafe {
                            let _ = CloseHandle(h);
                        }
                    }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let info = unsafe { event.u.LoadDll };
                    state
                        .events
                        .push(format!("DLL loaded at {:#x}", info.lpBaseOfDll as u64));
                    unsafe {
                        if !info.hFile.is_invalid() {
                            let _ = CloseHandle(info.hFile);
                        }
                    }
                    self.continue_execution()?;
                }
                UNLOAD_DLL_DEBUG_EVENT => {
                    let info = unsafe { event.u.UnloadDll };
                    state
                        .events
                        .push(format!("DLL unloaded at {:#x}", info.lpBaseOfDll as u64));
                    self.continue_execution()?;
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    state
                        .events
                        .push(format!("Thread created: {}", event.dwThreadId));
                    self.continue_execution()?;
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    state
                        .events
                        .push(format!("Thread exited: {}", event.dwThreadId));
                    self.continue_execution()?;
                }
                OUTPUT_DEBUG_STRING_EVENT => {
                    state.events.push("OutputDebugString".to_string());
                    self.continue_execution()?;
                }
                _ => {
                    self.continue_execution()?;
                }
            }
        }
        Ok(false)
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
        }
    }

    pub fn terminate(&mut self) {
        if self.is_active {
            unsafe {
                let _ = TerminateProcess(self.process_handle, 0);
                for _ in 0..16 {
                    let tid = self.paused_thread.take().unwrap_or(self.thread_id);
                    if ContinueDebugEvent(self.process_id, tid, NTSTATUS(0x00010002)).is_err() {
                        break;
                    }
                }
            }
            self.is_active = false;
        }
        unsafe {
            if !self.process_handle.is_invalid() {
                let _ = CloseHandle(self.process_handle);
            }
            if !self.thread_handle.is_invalid() {
                let _ = CloseHandle(self.thread_handle);
            }
        }
        self.process_handle = HANDLE::default();
        self.thread_handle = HANDLE::default();
        self.paused_thread = None;
        self.pending_rearm = None;
        self.pending_queue.clear();
        for (_, h) in self.thread_handles.drain() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
        self.awaiting_initial_break = false;
    }
}

impl Default for WinDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WinDebugger {
    fn drop(&mut self) {
        self.terminate();
    }
}
