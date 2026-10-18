use super::*;

pub struct WinDebugger {
    pub is_active: bool,
    pub process_id: u32,
    pub thread_id: u32,
    pub paused_thread: Option<u32>,
    pub pending_rearm: Option<(u64, u8)>,
    pub awaiting_initial_break: bool,
}

impl WinDebugger {
    pub fn new() -> Self {
        Self {
            is_active: false,
            process_id: 0,
            thread_id: 0,
            paused_thread: None,
            pending_rearm: None,
            awaiting_initial_break: false,
        }
    }
    pub fn launch_process(&mut self, _path: &str) -> Result<(), String> {
        Err("Debugger only supported on Windows".into())
    }
    pub fn attach_process(&mut self, _pid: u32) -> Result<(), String> {
        Err("Debugger only supported on Windows".into())
    }
    pub fn detach_process(&mut self, _breakpoints: &[Breakpoint]) -> Result<(), String> {
        Ok(())
    }
    pub fn process_debug_event(&mut self, _state: &mut DebugState) -> Result<bool, String> {
        Ok(false)
    }
    pub fn set_single_step(&self) -> Result<(), String> {
        Ok(())
    }
    pub fn set_rip(&self, _rip: u64) -> Result<(), String> {
        Ok(())
    }
    pub fn interrupt(&self) -> Result<(), String> {
        Err("Debugger only supported on Windows".into())
    }
    pub fn continue_execution(&mut self) -> Result<(), String> {
        Ok(())
    }
    pub fn resume_paused(&mut self) -> Result<(), String> {
        Ok(())
    }
    pub fn set_breakpoint(&self, _bp: &mut Breakpoint) -> Result<(), String> {
        Ok(())
    }
    pub fn remove_breakpoint(&self, _bp: &Breakpoint) -> Result<(), String> {
        Ok(())
    }
    pub fn get_registers(&self, _state: &mut DebugState) -> Result<(), String> {
        Ok(())
    }
    pub fn read_stack(&self, _state: &mut DebugState, _count: usize) -> Result<(), String> {
        Ok(())
    }
    pub fn read_memory(&self, _addr: u64, _size: usize) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    pub fn write_memory(&self, _addr: u64, _data: &[u8]) -> Result<(), String> {
        Ok(())
    }
    pub fn list_memory_regions(&self) -> Result<Vec<super::MemoryRegion>, String> {
        Ok(Vec::new())
    }
    pub fn list_modules(&self) -> Result<Vec<super::ModuleInfo>, String> {
        Ok(Vec::new())
    }
    pub fn list_threads(&self) -> Result<Vec<u32>, String> {
        Ok(Vec::new())
    }
    pub fn set_hardware_breakpoint(
        &self,
        slot: u8,
        _a: u64,
        _k: super::HwBpKind,
        _l: super::HwBpLen,
    ) -> Result<(), String> {
        if slot > 3 {
            return Err("HW BP slot must be 0..=3".into());
        }
        Ok(())
    }
    pub fn clear_hardware_breakpoint(&self, slot: u8) -> Result<(), String> {
        if slot > 3 {
            return Err("HW BP slot must be 0..=3".into());
        }
        Ok(())
    }
    pub fn is_process_alive(&self) -> bool {
        false
    }
    pub fn apply_stealth_patches(&self) -> Result<usize, String> {
        Err("Debugger only supported on Windows".into())
    }
    pub fn arm_entry_breakpoint(&mut self, _state: &mut DebugState) -> Result<Option<u64>, String> {
        Err("Debugger only supported on Windows".into())
    }
    pub fn terminate(&mut self) {
        self.is_active = false;
        self.process_id = 0;
        self.thread_id = 0;
        self.paused_thread = None;
        self.pending_rearm = None;
        self.awaiting_initial_break = false;
    }
}
