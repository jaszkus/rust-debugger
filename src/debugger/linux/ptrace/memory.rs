use super::{errno, PtraceDebugger};
use crate::debugger::{Breakpoint, DebugState, HwBpKind, HwBpLen, MemoryRegion, ModuleInfo};

impl PtraceDebugger {
    pub fn setup_entry_break(&mut self, path: &str) -> Result<u64, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let data = std::fs::read(path)
            .map_err(|e| format!("Cannot read target for entry parse: {}", e))?;
        if data.len() < 0x40 || &data[0..4] != b"\x7fELF" {
            return Err("Target is not an ELF image".into());
        }
        let is64 = data[4] == 2;
        let e_type = u16::from_le_bytes(data[0x10..0x12].try_into().unwrap());
        const ET_EXEC: u16 = 2;
        const ET_DYN: u16 = 3;
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(format!(
                "Unsupported ELF e_type {} (need ET_EXEC/ET_DYN)",
                e_type
            ));
        }
        let entry_off: u64 = if is64 {
            u64::from_le_bytes(data[0x18..0x20].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[0x18..0x1C].try_into().unwrap()) as u64
        };
        let canon = std::fs::canonicalize(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string());
        let mut base: Option<u64> = None;
        for line in self.maps_lines()?.iter() {
            let mut parts = line.split_whitespace();
            let range = parts.next().unwrap_or("");
            let mapped = parts.nth(4).unwrap_or("");
            if mapped != canon {
                continue;
            }
            if let Some(s0) = range.split('-').next()
                && let Ok(start) = u64::from_str_radix(s0, 16)
            {
                base = Some(base.map_or(start, |b: u64| b.min(start)));
            }
        }
        let entry = if e_type == ET_EXEC {
            entry_off
        } else {
            let base = base.ok_or("Main image not yet mapped (static HBRK?)")?;
            base.checked_add(entry_off)
                .ok_or_else(|| "Entry address overflow (base + e_entry), retry".to_string())?
        };
        self.validate_exec(entry)?;
        let orig = self.plant_int3(entry)?;
        self.entry_bp = Some((entry, orig));
        Ok(entry)
    }

    pub(super) fn peek_word(&self, addr: u64) -> Result<u64, String> {
        unsafe {
            *libc::__errno_location() = 0;
            let v = libc::ptrace(
                libc::PTRACE_PEEKDATA,
                self.process_id as libc::pid_t,
                addr as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            );
            if v == -1 && errno() != 0 {
                return Err(format!("PEEKDATA {:#x}: errno {}", addr, errno()));
            }
            Ok(v as u64)
        }
    }

    pub(super) fn poke_word(&self, addr: u64, val: u64) -> Result<(), String> {
        let r = unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                self.process_id as libc::pid_t,
                addr as *mut libc::c_void,
                val as *mut libc::c_void,
            )
        };
        if r != 0 {
            return Err(format!("POKEDATA {:#x}: errno {}", addr, errno()));
        }
        Ok(())
    }

    pub fn read_memory(&self, addr: u64, size: usize) -> Result<Vec<u8>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        if size == 0 || size > (1 << 24) {
            return Err("Read size out of range".into());
        }
        addr.checked_add(size as u64)
            .ok_or_else(|| "read_memory: address range overflow".to_string())?;
        if let Ok(buf) = self.read_via_vm(addr, size) {
            return Ok(buf);
        }
        if let Ok(buf) = self.read_via_proc_mem(addr, size) {
            return Ok(buf);
        }
        let mut out = Vec::with_capacity(size);
        let mut cur = addr;
        let end = addr.saturating_add(size as u64);
        while cur < end {
            let aligned = cur & !7u64;
            match self.peek_word(aligned) {
                Ok(word) => {
                    let bytes = word.to_ne_bytes();
                    let off = (cur - aligned) as usize;
                    let take = ((end - cur) as usize).min(8 - off);
                    out.extend_from_slice(&bytes[off..off + take]);
                    cur += take as u64;
                }
                Err(e) => {
                    if e.contains("ESRCH") || e.contains("errno 3") {
                        return Err(format!("{} (target running? interrupt() then retry)", e));
                    }
                    return Err(e);
                }
            }
        }
        Ok(out)
    }

    fn read_via_vm(&self, addr: u64, size: usize) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; size];
        let local = libc::iovec {
            iov_base: out.as_mut_ptr() as *mut libc::c_void,
            iov_len: size,
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: size,
        };
        let n = unsafe {
            libc::process_vm_readv(
                self.process_id as libc::pid_t,
                &local as *const _ as *const libc::iovec,
                1,
                &remote as *const _ as *const libc::iovec,
                1,
                0,
            )
        };
        if n < 0 {
            return Err(format!("process_vm_readv errno {}", errno()));
        }
        if n as usize != size {
            return Err("process_vm_readv short read".into());
        }
        Ok(out)
    }

    fn read_via_proc_mem(&self, addr: u64, size: usize) -> Result<Vec<u8>, String> {
        use std::io::{Read, Seek, SeekFrom};
        let path = format!("/proc/{}/mem", self.process_id);
        let mut f = std::fs::File::open(&path).map_err(|e| format!("open {}: {}", path, e))?;
        f.seek(SeekFrom::Start(addr))
            .map_err(|e| format!("seek {:#x}: {}", addr, e))?;
        let mut buf = vec![0u8; size];
        f.read_exact(&mut buf)
            .map_err(|e| format!("read {:#x}: {}", addr, e))?;
        Ok(buf)
    }

    pub fn write_memory(&self, addr: u64, data: &[u8]) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        if data.is_empty() || data.len() > (1 << 24) {
            return Err("Write size out of range".into());
        }
        addr.checked_add(data.len() as u64)
            .ok_or_else(|| "write_memory: address range overflow".to_string())?;
        if self.write_via_proc_mem(addr, data).is_ok() {
            return Ok(());
        }
        let mut cur = addr;
        let mut i = 0usize;
        while i < data.len() {
            let aligned = cur & !7u64;
            let off = (cur - aligned) as usize;
            let take = (data.len() - i).min(8 - off);
            let mut bytes = self.peek_word(aligned)?.to_ne_bytes();
            bytes[off..off + take].copy_from_slice(&data[i..i + take]);
            self.poke_word(aligned, u64::from_ne_bytes(bytes))?;
            cur += take as u64;
            i += take;
        }
        Ok(())
    }

    fn write_via_proc_mem(&self, addr: u64, data: &[u8]) -> Result<(), String> {
        use std::io::{Seek, SeekFrom, Write};
        let path = format!("/proc/{}/mem", self.process_id);
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("open {} for write: {}", path, e))?;
        f.seek(SeekFrom::Start(addr))
            .map_err(|e| format!("seek {:#x}: {}", addr, e))?;
        f.write_all(data)
            .map_err(|e| format!("write {:#x}: {}", addr, e))?;
        Ok(())
    }

    pub(super) fn validate_exec(&self, addr: u64) -> Result<(), String> {
        for line in self.maps_lines()?.iter() {
            let mut parts = line.split_whitespace();
            let range = parts.next().unwrap_or("");
            let perms = parts.next().unwrap_or("---");
            let mut dash = range.split('-');
            let (Some(s0), Some(s1)) = (dash.next(), dash.next()) else {
                continue;
            };
            let (Ok(start), Ok(end)) = (u64::from_str_radix(s0, 16), u64::from_str_radix(s1, 16))
            else {
                continue;
            };
            if addr >= start && addr < end {
                if perms.as_bytes().get(2) == Some(&b'x') {
                    return Ok(());
                } else {
                    return Err(format!(
                        "Not executable at {:#x} (perms {}), retry",
                        addr, perms
                    ));
                }
            }
        }
        Err(format!("No mapping for {:#x}", addr))
    }

    pub(super) fn plant_int3(&self, addr: u64) -> Result<u8, String> {
        self.validate_exec(addr)?;
        let aligned = addr & !7u64;
        let off = (addr - aligned) as usize;
        let mut bytes = self.peek_word(aligned)?.to_ne_bytes();
        let orig = bytes[off];
        if orig == 0xCC {
            return Err(format!("INT3 slot busy at {:#x}, retry", addr));
        }
        bytes[off] = 0xCC;
        self.poke_word(aligned, u64::from_ne_bytes(bytes))?;
        Ok(orig)
    }

    pub fn set_breakpoint(&self, bp: &mut Breakpoint) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let orig = self.plant_int3(bp.address)?;
        bp.mark_planted(orig);
        Ok(())
    }

    pub fn remove_breakpoint(&self, bp: &Breakpoint) -> Result<(), String> {
        if !self.is_active {
            return Ok(());
        }
        let aligned = bp.address & !7u64;
        let off = (bp.address - aligned) as usize;
        if let Ok(word) = self.peek_word(aligned) {
            let mut bytes = word.to_ne_bytes();
            if bytes[off] == 0xCC {
                bytes[off] = bp.original_byte;
                let _ = self.poke_word(aligned, u64::from_ne_bytes(bytes));
            }
        }
        Ok(())
    }

    pub(super) fn step_over_planted(&mut self, addr: u64, orig: u8) -> Result<(), String> {
        let aligned = addr & !7u64;
        let off = (addr - aligned) as usize;
        let mut bytes = self.peek_word(aligned)?.to_ne_bytes();
        bytes[off] = orig;
        self.poke_word(aligned, u64::from_ne_bytes(bytes))?;
        self.set_single_step()?;
        self.cont_raw(0)?;
        let main = self.process_id as libc::pid_t;
        let mut status = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let w = unsafe { libc::waitpid(main, &mut status, libc::WUNTRACED | libc::__WALL) };
            if w == main && libc::WIFSTOPPED(status) {
                break;
            }
            if w == main && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                self.is_active = false;
                return Err("Target died during single-step".into());
            }
            if std::time::Instant::now() > deadline {
                return Err("Single-step timed out".into());
            }
            if w < 0 && errno() != libc::EINTR {
                return Err(format!("waitpid during step: errno {}", errno()));
            }
        }
        self.plant_int3(addr).map(|_| ())
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) const U_DEBUGREG: u64 = 848;
    #[cfg(not(target_arch = "x86_64"))]
    pub(super) const U_DEBUGREG: u64 = 848;
    #[allow(dead_code)]
    const U_DEBUGREG_LAYOUT_CHECK: () =
        assert!(Self::U_DEBUGREG == 848, "u_debugreg offset changed?");

    pub(super) fn poke_user_tid(&self, tid: libc::pid_t, off: u64, val: u64) -> Result<(), String> {
        let r = unsafe {
            libc::ptrace(
                libc::PTRACE_POKEUSER,
                tid,
                off as *mut libc::c_void,
                val as *mut libc::c_void,
            )
        };
        if r != 0 {
            return Err(format!(
                "POKEUSER tid {} {:#x}: errno {}",
                tid,
                off,
                errno()
            ));
        }
        Ok(())
    }

    pub(super) fn peek_user_tid(&self, tid: libc::pid_t, off: u64) -> Result<u64, String> {
        unsafe {
            *libc::__errno_location() = 0;
            let v = libc::ptrace(
                libc::PTRACE_PEEKUSER,
                tid,
                off as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            );
            if v == -1 && errno() != 0 {
                return Err(format!(
                    "PEEKUSER tid {} {:#x}: errno {}",
                    tid,
                    off,
                    errno()
                ));
            }
            Ok(v as u64)
        }
    }

    #[allow(dead_code)]
    pub(super) fn poke_user(&self, off: u64, val: u64) -> Result<(), String> {
        self.poke_user_tid(self.process_id as libc::pid_t, off, val)
    }

    pub(super) fn peek_user(&self, off: u64) -> Result<u64, String> {
        self.peek_user_tid(self.process_id as libc::pid_t, off)
    }

    pub fn set_hardware_breakpoint(
        &self,
        slot: u8,
        address: u64,
        kind: HwBpKind,
        len: HwBpLen,
    ) -> Result<(), String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        if slot > 3 {
            return Err("HW BP slot must be 0..=3".into());
        }
        let s = slot as u64;
        let dr7_cur = self.peek_user(Self::U_DEBUGREG + 7 * 8)?;
        if (dr7_cur >> (s * 2)) & 0b11 != 0 {
            return Err(format!("HW BP slot {} busy, retry with another slot", slot));
        }
        let rw: u64 = match kind {
            HwBpKind::Execute => 0b00,
            HwBpKind::Write => 0b01,
            HwBpKind::Read | HwBpKind::ReadWrite => 0b11,
        };
        let ln: u64 = match len {
            HwBpLen::One => 0b00,
            HwBpLen::Two => 0b01,
            HwBpLen::Four => 0b11,
            HwBpLen::Eight => 0b10,
        };
        let s = slot as u64;
        let tids = self
            .list_threads()
            .unwrap_or_else(|_| vec![self.process_id]);
        let mut armed = 0usize;
        let mut last_err = String::new();
        for tid in tids {
            let t = tid as libc::pid_t;
            if self.peek_user_tid(t, Self::U_DEBUGREG + 7 * 8).is_err() {
                last_err = format!("tid {} gone", tid);
                continue;
            }
            if self
                .poke_user_tid(t, Self::U_DEBUGREG + s * 8, address)
                .is_err()
            {
                last_err = format!("POKEUSER tid {}", tid);
                continue;
            }
            match self.peek_user_tid(t, Self::U_DEBUGREG + 7 * 8) {
                Ok(cur) => {
                    let mut dr7 = cur;
                    dr7 |= 1 << (s * 2);
                    dr7 |= rw << (16 + s * 4);
                    dr7 |= ln << (18 + s * 4);
                    if self.poke_user_tid(t, Self::U_DEBUGREG + 7 * 8, dr7).is_ok() {
                        armed += 1;
                    } else {
                        last_err = format!("DR7 tid {}", tid);
                    }
                }
                Err(e) => last_err = e,
            }
        }
        if armed == 0 {
            return Err(if last_err.is_empty() {
                "HW BP arm failed on all TIDs".into()
            } else {
                format!("HW BP arm failed: {}", last_err)
            });
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
        let s = slot as u64;
        let tids = self
            .list_threads()
            .unwrap_or_else(|_| vec![self.process_id]);
        for tid in tids {
            let t = tid as libc::pid_t;
            let cur = match self.peek_user_tid(t, Self::U_DEBUGREG + 7 * 8) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut dr7 = cur;
            dr7 &= !((0b11u64 << (s * 2)) | (0b11u64 << (16 + s * 4)) | (0b11u64 << (18 + s * 4)));
            let _ = self.poke_user_tid(t, Self::U_DEBUGREG + 7 * 8, dr7);
            let _ = self.poke_user_tid(t, Self::U_DEBUGREG + s * 8, 0);
        }
        Ok(())
    }

    pub(super) fn maps_lines(&self) -> Result<std::rc::Rc<Vec<String>>, String> {
        if let Ok(cache) = self.maps_cache.try_borrow()
            && !cache.1.is_empty()
            && cache.0.elapsed() < std::time::Duration::from_millis(250)
        {
            return Ok(cache.1.clone());
        }
        let text = std::fs::read_to_string(format!("/proc/{}/maps", self.process_id))
            .map_err(|e| format!("Cannot read target maps: {}", e))?;
        let lines = std::rc::Rc::new(text.lines().map(|l| l.to_string()).collect::<Vec<String>>());
        if let Ok(mut cache) = self.maps_cache.try_borrow_mut() {
            *cache = (std::time::Instant::now(), lines.clone());
        }
        Ok(lines)
    }

    pub(super) fn invalidate_maps(&self) {
        if let Ok(mut cache) = self.maps_cache.try_borrow_mut() {
            cache.1 = std::rc::Rc::new(Vec::new());
        }
    }

    pub(super) fn invalidate_tasks(&self) {
        if let Ok(mut cache) = self.task_cache.try_borrow_mut() {
            cache.1.clear();
        }
    }

    pub(super) fn cached_threads(&self) -> Vec<u32> {
        if let Ok(cache) = self.task_cache.try_borrow()
            && !cache.1.is_empty()
            && cache.0.elapsed() < std::time::Duration::from_millis(100)
        {
            return cache.1.clone();
        }
        let tids = self.read_task_dir();
        if let Ok(mut cache) = self.task_cache.try_borrow_mut() {
            *cache = (std::time::Instant::now(), tids.clone());
        }
        tids
    }

    fn read_task_dir(&self) -> Vec<u32> {
        let mut tids = Vec::new();
        if let Ok(dir) = std::fs::read_dir(format!("/proc/{}/task", self.process_id)) {
            for entry in dir.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && let Ok(tid) = name.parse::<u32>()
                {
                    tids.push(tid);
                }
            }
            tids.sort_unstable();
        }
        tids
    }

    pub fn list_memory_regions(&self) -> Result<Vec<MemoryRegion>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let mut out = Vec::new();
        for line in self.maps_lines()?.iter() {
            let mut parts = line.split_whitespace();
            let range = parts.next().unwrap_or("");
            let perms = parts.next().unwrap_or("---");
            let mut dash = range.split('-');
            let (Some(s0), Some(s1)) = (dash.next(), dash.next()) else {
                continue;
            };
            let (Ok(start), Ok(end)) = (u64::from_str_radix(s0, 16), u64::from_str_radix(s1, 16))
            else {
                continue;
            };
            let mut prot = 0u32;
            let b = perms.as_bytes();
            if b.first() == Some(&b'r') {
                prot |= 4;
            }
            if b.get(1) == Some(&b'w') {
                prot |= 2;
            }
            if b.get(2) == Some(&b'x') {
                prot |= 1;
            }
            let mapped_file = parts.nth(3).map(|s| s.to_string());
            out.push(MemoryRegion {
                base: start,
                size: end.saturating_sub(start),
                protection: prot,
                state: 0x1000,
                kind: 0,
                mapped_file,
            });
        }
        Ok(out)
    }

    pub fn list_modules(&self) -> Result<Vec<ModuleInfo>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let mut mods: std::collections::HashMap<String, (u64, u64)> =
            std::collections::HashMap::new();
        let mut order: Vec<String> = Vec::new();
        for line in self.maps_lines()?.iter() {
            let mut parts = line.split_whitespace();
            let range = parts.next().unwrap_or("");
            let path = match parts.nth(4) {
                Some(p) if p.starts_with('/') || p.starts_with('[') => p,
                _ => continue,
            };
            if path.starts_with('[') {
                continue;
            }
            let mut dash = range.split('-');
            let (Some(s0), Some(s1)) = (dash.next(), dash.next()) else {
                continue;
            };
            let (Ok(start), Ok(end)) = (u64::from_str_radix(s0, 16), u64::from_str_radix(s1, 16))
            else {
                continue;
            };
            mods.entry(path.to_string())
                .and_modify(|(b, e)| {
                    *b = (*b).min(start);
                    *e = (*e).max(end);
                })
                .or_insert_with(|| {
                    order.push(path.to_string());
                    (start, end)
                });
        }
        let mut out = Vec::new();
        for path in order {
            if let Some((base, end)) = mods.get(&path) {
                let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                out.push(ModuleInfo {
                    base: *base,
                    size: end.saturating_sub(*base),
                    name,
                    path: path.clone(),
                });
            }
        }
        Ok(out)
    }

    pub fn list_threads(&self) -> Result<Vec<u32>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let tids = self.cached_threads();
        if tids.is_empty() {
            return Err("Cannot list target threads (task gone?)".into());
        }
        Ok(tids)
    }

    #[allow(dead_code)]
    pub fn list_threads_uncached(&self) -> Result<Vec<u32>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        let tids = self.read_task_dir();
        if tids.is_empty() {
            return Err("Cannot list target threads (task gone?)".into());
        }
        Ok(tids)
    }

    #[allow(dead_code)]
    pub fn apply_stealth_patches(&self) -> Result<usize, String> {
        Ok(0)
    }

    #[allow(dead_code)]
    pub fn arm_entry_breakpoint(&mut self, _state: &mut DebugState) -> Result<Option<u64>, String> {
        if !self.is_active {
            return Err("Debugger not active".into());
        }
        Ok(None)
    }
}
