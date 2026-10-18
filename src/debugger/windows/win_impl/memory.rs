use super::{
    new_context, GetThreadContext, SetThreadContext, WinDebugger, CONTEXT64,
    CONTEXT_DEBUG_REGISTERS, CONTEXT_FULL,
};
use crate::debugger::state::*;
use std::mem;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

impl WinDebugger {
    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;

        let result = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )
        };

        match result {
            Ok(_) => {
                buffer.truncate(bytes_read);
                Ok(buffer)
            }
            Err(e) => Err(format!("ReadProcessMemory failed: {}", e)),
        }
    }

    pub fn write_memory(&self, address: u64, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        let end = address
            .checked_add(data.len() as u64)
            .ok_or_else(|| "write_memory: address range overflow".to_string())?;
        let mut saved: Vec<(
            u64,
            usize,
            windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
        )> = Vec::new();
        let mut cur = address;
        while cur < end {
            let mut mbi: MEMORY_BASIC_INFORMATION =
                unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
            let n = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    Some(cur as *const _),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 {
                for (b, s, old) in saved.iter() {
                    let mut tmp = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
                    unsafe {
                        let _ = VirtualProtectEx(
                            self.process_handle,
                            *b as *const _,
                            *s,
                            *old,
                            &mut tmp,
                        );
                    }
                }
                return Err(format!("VirtualQueryEx failed at {:#x}", cur));
            }
            let rbase = mbi.BaseAddress as u64;
            let rsize = mbi.RegionSize as u64;
            let rend = rbase.saturating_add(rsize);
            let chunk_end = rend.min(end);
            let chunk_base = cur.max(rbase);
            let chunk_len = chunk_end.saturating_sub(chunk_base) as usize;
            if chunk_len == 0 {
                break;
            }
            let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
            let ok = unsafe {
                VirtualProtectEx(
                    self.process_handle,
                    chunk_base as *const _,
                    chunk_len.max(1),
                    windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
                    &mut old,
                )
            };
            if ok.is_err() {
                let msg = format!("VirtualProtectEx failed at {:#x}", chunk_base);
                let is_access_denied =
                    format!("{:?}", ok).contains("ACCESS_DENIED") || msg.contains("5");
                if !is_access_denied {
                    for (b, s, o) in saved.iter() {
                        let mut tmp = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
                        unsafe {
                            let _ = VirtualProtectEx(
                                self.process_handle,
                                *b as *const _,
                                *s,
                                *o,
                                &mut tmp,
                            );
                        }
                    }
                    return Err(msg);
                }
            } else {
                saved.push((chunk_base, chunk_len.max(1), old));
            }
            cur = chunk_end;
            if cur <= chunk_base {
                break;
            }
        }
        let mut bytes_written = 0usize;
        let wres = unsafe {
            WriteProcessMemory(
                self.process_handle,
                address as *const _,
                data.as_ptr() as *const _,
                data.len(),
                Some(&mut bytes_written),
            )
        };
        for (b, s, old) in saved.iter() {
            let mut tmp = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
            unsafe {
                let _ = VirtualProtectEx(self.process_handle, *b as *const _, *s, *old, &mut tmp);
            }
        }
        match wres {
            Ok(_) => {}
            Err(e) => {
                let s = format!("{}", e);
                if s.contains("ACCESS_DENIED") || s.contains("0x80070005") || s.contains("(5)") {
                    return Err(format!(
                        "WriteProcessMemory ACCESS_DENIED at {:#x} (retry when suspended): {}",
                        address, e
                    ));
                }
                return Err(format!("WriteProcessMemory failed: {}", e));
            }
        }
        if bytes_written != data.len() {
            return Err(format!(
                "WriteProcessMemory wrote {} of {} bytes",
                bytes_written,
                data.len()
            ));
        }
        unsafe {
            let _ =
                FlushInstructionCache(self.process_handle, Some(address as *const _), data.len());
        }
        Ok(())
    }

    pub(super) fn validate_exec(&self, address: u64) -> Result<(), String> {
        let mut mbi: MEMORY_BASIC_INFORMATION =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        let n = unsafe {
            VirtualQueryEx(
                self.process_handle,
                Some(address as *const _),
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 {
            return Err(format!("No memory region at {:#x}", address));
        }
        if mbi.Protect.0 & 0xF0 == 0 {
            return Err(format!(
                "Not executable at {:#x} (protect {:#x}), retry",
                address, mbi.Protect.0
            ));
        }
        Ok(())
    }

    pub fn set_breakpoint(&self, bp: &mut Breakpoint) -> Result<(), String> {
        self.validate_exec(bp.address)?;
        let original = self.read_memory(bp.address, 1)?;
        if original.is_empty() {
            return Err(format!("Cannot read byte at {:#x}", bp.address));
        }
        if original[0] == 0xCC {
            return Err(format!("INT3 slot busy at {:#x}, retry", bp.address));
        }
        bp.original_byte = original[0];
        self.write_memory(bp.address, &[0xCC])?;
        bp.enabled = true;
        Ok(())
    }

    pub fn remove_breakpoint(&self, bp: &Breakpoint) -> Result<(), String> {
        match self.read_memory(bp.address, 1) {
            Ok(cur) if cur.first() == Some(&0xCC) => {}
            _ => return Ok(()),
        }
        self.write_memory(bp.address, &[bp.original_byte])?;
        Ok(())
    }

    fn get_peb_address(&self) -> Result<u64, String> {
        use windows::core::{w, PCSTR};
        unsafe {
            let ntdll = GetModuleHandleW(w!("ntdll.dll"))
                .map_err(|e| format!("GetModuleHandleW(ntdll): {}", e))?;
            let proc_addr =
                GetProcAddress(ntdll, PCSTR(c"NtQueryInformationProcess".as_ptr().cast()))
                    .ok_or("NtQueryInformationProcess not found")?;
            type NtQIP = unsafe extern "system" fn(
                HANDLE,
                u32,
                *mut core::ffi::c_void,
                u32,
                *mut u32,
            ) -> i32;
            let ntqip: NtQIP = std::mem::transmute(proc_addr);
            let mut pbi = [0u8; 48];
            let mut ret_len: u32 = 0;
            let status = ntqip(
                self.process_handle,
                0,
                pbi.as_mut_ptr() as *mut _,
                pbi.len() as u32,
                &mut ret_len,
            );
            if status != 0 {
                return Err(format!("NtQueryInformationProcess status {:#x}", status));
            }
            Ok(u64::from_le_bytes(pbi[8..16].try_into().unwrap()))
        }
    }

    pub fn apply_stealth_patches(&self) -> Result<usize, String> {
        let peb = self.get_peb_address()?;
        let mut patched = 0usize;

        self.write_memory(peb + 0x02, &[0])?;
        patched += 1;

        self.write_memory(peb + 0xBC, &[0, 0, 0, 0])?;
        patched += 1;

        let heap_b = self.read_memory(peb + 0x30, 8)?;
        if heap_b.len() == 8 {
            let heap = u64::from_le_bytes(heap_b.try_into().unwrap());
            if heap != 0 {
                for off in [0x70u64, 0x74u64] {
                    if let Ok(cur) = self.read_memory(heap + off, 4)
                        && cur.len() == 4 {
                            let v = u32::from_le_bytes(cur.try_into().unwrap());
                            if v != 0 && v < 0x10000 {
                                let _ = self.write_memory(heap + off, &[0, 0, 0, 0]);
                                patched += 1;
                            }
                        }
                }
            }
        }
        Ok(patched)
    }

    pub fn arm_entry_breakpoint(&mut self, state: &mut DebugState) -> Result<Option<u64>, String> {
        let modules = self.list_modules()?;
        let mut main_base: Option<u64> = None;
        for m in &modules {
            if let Ok(hdr) = self.read_memory(m.base, 2)
                && hdr.as_slice() == b"MZ" {
                    main_base = Some(m.base);
                    break;
                }
        }
        let base = main_base.ok_or("No MZ module found in target")?;

        let lfanew_b = self.read_memory(base + 0x3C, 4)?;
        if lfanew_b.len() < 4 {
            return Err("Cannot read e_lfanew".into());
        }
        let pe_base = base + u32::from_le_bytes(lfanew_b.try_into().unwrap()) as u64;
        let sig = self.read_memory(pe_base, 4)?;
        if sig.as_slice() != b"PE\0\0" {
            return Err("Invalid PE signature at e_lfanew".into());
        }
        let ep_b = self.read_memory(pe_base + 0x28, 4)?;
        if ep_b.len() < 4 {
            return Err("Cannot read AddressOfEntryPoint".into());
        }
        let ep_rva = u32::from_le_bytes(ep_b.try_into().unwrap());
        let entry_va = base + ep_rva as u64;

        if state.breakpoints.iter().any(|b| b.address == entry_va) {
            return Ok(Some(entry_va));
        }
        let orig_b = self.read_memory(entry_va, 1)?;
        let original = *orig_b.first().ok_or("Entry point unreadable")?;
        self.write_memory(entry_va, &[0xCC])?;
        state.breakpoints.push(Breakpoint {
            address: entry_va,
            enabled: true,
            original_byte: original,
            name: "entry".into(),
            kind: crate::debugger::BpKind::SwExec,
            len: 1,
            planted: true,
        });
        Ok(Some(entry_va))
    }

    pub fn read_stack(&self, state: &mut DebugState, count: usize) -> Result<(), String> {
        let rsp = state.registers.rsp;
        if rsp == 0 {
            return Ok(());
        }
        match self.read_memory(rsp, count * 8) {
            Ok(data) => {
                state.stack_data = data;
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }

    pub fn list_memory_regions(&self) -> Result<Vec<crate::debugger::MemoryRegion>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let mut out: Vec<crate::debugger::MemoryRegion> = Vec::new();
        let mut addr: u64 = 0;
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION =
                unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
            let n = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    Some(addr as *const _),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 {
                break;
            }
            if mbi.State.0 & MEM_COMMIT.0 != 0 {
                let mut mapped_file = None;
                if mbi.Type.0 & (MEM_IMAGE.0 | MEM_MAPPED.0) != 0 {
                    let mut buf = [0u16; 260];
                    let chars = unsafe {
                        windows::Win32::System::ProcessStatus::K32GetMappedFileNameW(
                            self.process_handle,
                            mbi.BaseAddress,
                            &mut buf,
                        )
                    };
                    if chars > 0 {
                        mapped_file = Some(String::from_utf16_lossy(&buf[..chars as usize]));
                    }
                }
                out.push(crate::debugger::MemoryRegion {
                    base: mbi.BaseAddress as u64,
                    size: mbi.RegionSize as u64,
                    protection: mbi.Protect.0,
                    state: mbi.State.0,
                    kind: mbi.Type.0,
                    mapped_file,
                });
            }
            let next = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
            if next == addr {
                break;
            }
            addr = next;
            if out.len() > 65536 {
                break;
            }
        }
        Ok(out)
    }

    pub fn list_modules(&self) -> Result<Vec<crate::debugger::ModuleInfo>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let snap = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.process_id)
                .map_err(|e| format!("CreateToolhelp32Snapshot: {}", e))?
        };
        let mut out = Vec::new();
        let mut me: MODULEENTRY32W = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        me.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        let mut ok = unsafe { Module32FirstW(snap, &mut me) };
        while ok.is_ok() {
            let name = String::from_utf16_lossy(
                &me.szModule[..me.szModule.iter().position(|&c| c == 0).unwrap_or(0)],
            );
            let path = String::from_utf16_lossy(
                &me.szExePath[..me.szExePath.iter().position(|&c| c == 0).unwrap_or(0)],
            );
            out.push(crate::debugger::ModuleInfo {
                base: me.modBaseAddr as u64,
                size: me.modBaseSize as u64,
                name,
                path,
            });
            ok = unsafe { Module32NextW(snap, &mut me) };
        }
        unsafe {
            let _ = CloseHandle(snap);
        }
        Ok(out)
    }

    pub fn list_threads(&self) -> Result<Vec<u32>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let snap = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| format!("CreateToolhelp32Snapshot: {}", e))?
        };
        let mut out = Vec::new();
        let mut te: THREADENTRY32 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        te.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        let mut ok = unsafe { Thread32First(snap, &mut te) };
        while ok.is_ok() {
            if te.th32OwnerProcessID == self.process_id {
                out.push(te.th32ThreadID);
            }
            ok = unsafe { Thread32Next(snap, &mut te) };
        }
        unsafe {
            let _ = CloseHandle(snap);
        }
        Ok(out)
    }

    pub(super) fn first_thread_of(&self, pid: u32) -> Option<u32> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).ok()? };
        let mut te: THREADENTRY32 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        te.dwSize = mem::size_of::<THREADENTRY32>() as u32;
        let mut ok = unsafe { Thread32First(snap, &mut te) };
        let mut found = None;
        while ok.is_ok() {
            if te.th32OwnerProcessID == pid {
                found = Some(te.th32ThreadID);
                break;
            }
            ok = unsafe { Thread32Next(snap, &mut te) };
        }
        unsafe {
            let _ = CloseHandle(snap);
        }
        found
    }

    pub fn set_hardware_breakpoint(
        &self,
        slot: u8,
        address: u64,
        kind: crate::debugger::HwBpKind,
        len: crate::debugger::HwBpLen,
    ) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        if slot > 3 {
            return Err("HW BP slot must be 0..=3".into());
        }
        let mut ctx: CONTEXT64 = new_context(CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS);
        let prev_suspend = unsafe { SuspendThread(self.thread_handle) };
        let r = unsafe { GetThreadContext(self.thread_handle, &mut ctx) };
        if !r.as_bool() {
            if prev_suspend != u32::MAX {
                unsafe {
                    ResumeThread(self.thread_handle);
                }
            }
            return Err("GetThreadContext failed".into());
        }
        if (ctx.dr7 >> (slot as u64 * 2)) & 0b11 != 0 {
            if prev_suspend != u32::MAX {
                unsafe {
                    ResumeThread(self.thread_handle);
                }
            }
            return Err(format!("HW BP slot {} busy, retry with another slot", slot));
        }
        match slot {
            0 => ctx.dr0 = address,
            1 => ctx.dr1 = address,
            2 => ctx.dr2 = address,
            _ => ctx.dr3 = address,
        }
        let rw_bits: u64 = match kind {
            crate::debugger::HwBpKind::Execute => 0b00,
            crate::debugger::HwBpKind::Write => 0b01,
            crate::debugger::HwBpKind::Read | crate::debugger::HwBpKind::ReadWrite => 0b11,
        };
        let len_bits: u64 = match len {
            crate::debugger::HwBpLen::One => 0b00,
            crate::debugger::HwBpLen::Two => 0b01,
            crate::debugger::HwBpLen::Four => 0b11,
            crate::debugger::HwBpLen::Eight => 0b10,
        };
        let slot_u = slot as u64;
        let local_enable = 1u64 << (slot_u * 2);
        let rw_shift = 16 + slot_u * 4;
        let len_shift = 18 + slot_u * 4;
        let mask = (0b11u64 << rw_shift) | (0b11u64 << len_shift) | (0b11u64 << (slot_u * 2));
        ctx.dr7 =
            (ctx.dr7 & !mask) | local_enable | (rw_bits << rw_shift) | (len_bits << len_shift);
        let r = unsafe { SetThreadContext(self.thread_handle, &ctx) };
        if prev_suspend != u32::MAX {
            unsafe {
                ResumeThread(self.thread_handle);
            }
        }
        if !r.as_bool() {
            return Err("SetThreadContext failed".into());
        }
        Ok(())
    }

    pub fn clear_hardware_breakpoint(&self, slot: u8) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        if slot > 3 {
            return Err("HW BP slot must be 0..=3".into());
        }
        let mut ctx: CONTEXT64 = new_context(CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS);
        let prev_suspend = unsafe { SuspendThread(self.thread_handle) };
        let r = unsafe { GetThreadContext(self.thread_handle, &mut ctx) };
        if !r.as_bool() {
            if prev_suspend != u32::MAX {
                unsafe {
                    ResumeThread(self.thread_handle);
                }
            }
            return Err("GetThreadContext failed".into());
        }
        let slot_u = slot as u64;
        let rw_shift = 16 + slot_u * 4;
        let len_shift = 18 + slot_u * 4;
        let mask = (0b11u64 << rw_shift) | (0b11u64 << len_shift) | (0b11u64 << (slot_u * 2));
        ctx.dr7 &= !mask;
        match slot {
            0 => ctx.dr0 = 0,
            1 => ctx.dr1 = 0,
            2 => ctx.dr2 = 0,
            _ => ctx.dr3 = 0,
        }
        let r = unsafe { SetThreadContext(self.thread_handle, &ctx) };
        if prev_suspend != u32::MAX {
            unsafe {
                ResumeThread(self.thread_handle);
            }
        }
        if !r.as_bool() {
            return Err("SetThreadContext failed".into());
        }
        Ok(())
    }
}
