use crate::debugger::thread::{
    cleanup_step_over, lock_app, merge_pump_tail, step_over_target, step_over_tmp_bp, PumpErr,
};
use std::sync::{Arc, Mutex};
use std::thread;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::time::Duration;

#[cfg(target_os = "linux")]
pub fn spawn_debug_thread(state: Arc<Mutex<crate::gui::AppState>>) -> thread::JoinHandle<()> {
    use crate::debugger::{ptrace::PtraceDebugger, HwBpRequest, MemReadResult, MemWriteResult};

    thread::Builder::new()
        .name("rust-debugger-debug-loop".into())
        .spawn(move || {
            use crate::debugger::DebugSignal;
            let mut dbg = PtraceDebugger::new();
            let mut pump_err = PumpErr::new();

            loop {
                let signal: Arc<DebugSignal> = lock_app(&state).debug_state.signal.clone();
                {
                    let mut s = lock_app(&state);
                    if s.debug_state.start_debug {
                        s.debug_state.start_debug = false;
                        if !s.file_path.is_empty() {
                            s.debug_state.events.clear();
                            s.debug_state.current_rip = 0;
                            s.debug_state.thread_id = 0;
                            s.debug_state.active_tid = 0;
                            s.debug_state.trace_buffer.clear();
                            s.debug_state.mem_read_request = None;
                            s.debug_state.mem_read_result = None;
                            s.debug_state.mem_write_request = None;
                            s.debug_state.mem_write_result = None;
                            s.debug_state.mem_regions_request = None;
                            s.debug_state.mem_regions_result = None;
                            s.debug_state.modules_request = None;
                            s.debug_state.modules_result = None;
                            s.debug_state.threads_request = None;
                            s.debug_state.threads_result = None;
                            s.debug_state.hw_bp_request = None;
                            s.debug_state.hw_bp_result = None;
                            s.debug_state.arm_int3_request = None;
                            s.debug_state.arm_int3_result = None;

                            let path = s.file_path.clone();
                            drop(s);
                            let r = dbg.launch_process(&path);
                            {
                                let mut s2 = lock_app(&state);
                                match r {
                                    Ok(_) => {
                                        for bp in s2.debug_state.breakpoints.iter_mut() {
                                            if bp.enabled {
                                                let _ = dbg.set_breakpoint(bp);
                                            }
                                        }
                                        let _ = dbg.get_registers(&mut s2.debug_state);
                                        if s2.debug_state.stop_at_entry {
                                            match dbg.setup_entry_break(&path) {
                                                Ok(entry) => {
                                                    s2.debug_state.events.push(format!(
                                                        "Entry breakpoint at {:#x}, running loader...",
                                                        entry
                                                    ));
                                                    let _ = dbg.continue_execution();
                                                    s2.debug_state.is_running = true;
                                                    s2.status_msg = format!(
                                                        "Running loader: {} (PID: {})",
                                                        path, dbg.process_id
                                                    );
                                                }
                                                Err(e) => {
                                                    s2.debug_state.events.push(format!(
                                                        "Entry break failed: {} (parked in loader)", e
                                                    ));
                                                }
                                            }
                                        }
                                        if !s2.debug_state.is_running {
                                            s2.status_msg = format!(
                                                "Debugging: {} (PID: {})",
                                                path, dbg.process_id
                                            );
                                        }
                                        s2.debug_state.is_attached = true;
                                        s2.debug_state.process_id = dbg.process_id;
                                        s2.debug_state.thread_id = dbg.process_id;
                                        s2.debug_state.active_tid = dbg.process_id;
                                        s2.debug_state.events.push(format!(
                                            "Launched {} (PID {}), stopped at entry",
                                            path, dbg.process_id
                                        ));
                                    }
                                    Err(e) => {
                                        s2.status_msg = format!("Debug error: {}", e);
                                        s2.debug_state.events.push(format!("Launch failed: {}", e));
                                    }
                                }
                            }
                            signal.wait_timeout(Duration::from_millis(2));
                            continue;
                        }
                    }

                    if s.debug_state.step_into {
                        s.debug_state.step_into = false;
                        if dbg.is_active {
                            let _ = dbg.set_single_step();
                            let _ = dbg.resume_paused();
                            s.debug_state.is_running = true;
                            s.status_msg = "Stepping...".into();
                        }
                    }
                    if s.debug_state.step_over {
                        s.debug_state.step_over = false;
                        if dbg.is_active {
                            let rip = if s.debug_state.current_rip != 0 {
                                s.debug_state.current_rip
                            } else {
                                s.debug_state.registers.rip
                            };
                            match step_over_target(&s.disasm, rip) {
                                Some(next) => {
                                    let already = s.debug_state.breakpoints.iter().any(|b| b.enabled && b.address == next);
                                    if already {
                                        s.debug_state.next_step_over(next);
                                        let _ = dbg.resume_paused();
                                        s.debug_state.is_running = true;
                                        s.status_msg = format!("Step over call at {:#x} (existing BP at {:#x})...", rip, next);
                                    } else {
                                        let readable = dbg.read_memory(next, 1)
                                            .map(|b| !b.is_empty() && b[0] != 0xCC)
                                            .unwrap_or(false);
                                        if !readable {
                                            let _ = dbg.set_single_step();
                                            let _ = dbg.resume_paused();
                                            s.debug_state.is_running = true;
                                            s.status_msg = format!("Step-over target {:#x} unreadable/busy, stepped into", next);
                                        } else {
                                            let mut tmp = step_over_tmp_bp(next);
                                            match dbg.set_breakpoint(&mut tmp) {
                                                Ok(()) => {
                                                    tmp.name = "step_over_temp".into();
                                                    s.debug_state.breakpoints.push(tmp);
                                                    s.debug_state.next_step_over(next);
                                                    let _ = dbg.resume_paused();
                                                    s.debug_state.is_running = true;
                                                    s.status_msg = format!("Step over call at {:#x}...", rip);
                                                }
                                                Err(e) => {
                                                    let _ = dbg.set_single_step();
                                                    let _ = dbg.resume_paused();
                                                    s.debug_state.is_running = true;
                                                    s.status_msg = format!("Step-over plant failed ({}), stepped into", e);
                                                }
                                            }
                                        }
                                    }
                                }
                                None => {
                                    let _ = dbg.set_single_step();
                                    let _ = dbg.resume_paused();
                                    s.debug_state.is_running = true;
                                    s.status_msg = "Stepping...".into();
                                }
                            }
                        }
                    }
                    if s.debug_state.continue_exec {
                        s.debug_state.continue_exec = false;
                        if dbg.is_active {
                            let _ = dbg.resume_paused();
                            s.debug_state.is_running = true;
                            s.status_msg = "Running...".into();
                        }
                    }
                    if s.debug_state.break_exec {
                        s.debug_state.break_exec = false;
                        if dbg.is_active {
                            match dbg.interrupt() {
                                Ok(_) => s.status_msg = "Break requested...".into(),
                                Err(e) => s.status_msg = format!("Break failed: {}", e),
                            }
                        }
                    }
                    if s.debug_state.stop {
                        s.debug_state.stop = false;
                        dbg.terminate();
                        s.debug_state.is_running = false;
                        s.debug_state.is_attached = false;
                        s.debug_state.process_id = 0;
                        s.status_msg = "Debugger stopped.".into();
                    }

                    if let Some(req) = s.debug_state.mem_read_request.take() {
                        let result = if dbg.is_active {
                            dbg.read_memory(req.address, req.size)
                        } else {
                            Err("Debugger not active".into())
                        };
                        s.debug_state.mem_read_result = Some(MemReadResult {
                            id: req.id,
                            address: req.address,
                            data: result,
                        });
                    }
                    if let Some(req) = s.debug_state.mem_write_request.take() {
                        let result = if dbg.is_active {
                            dbg.write_memory(req.address, &req.bytes).map(|_| req.bytes.len())
                        } else {
                            Err("Debugger not active".into())
                        };
                        s.debug_state.mem_write_result = Some(MemWriteResult {
                            id: req.id,
                            address: req.address,
                            written: result,
                        });
                    }
                    if let Some(id) = s.debug_state.mem_regions_request.take() {
                        let r = if dbg.is_active {
                            dbg.list_memory_regions()
                        } else {
                            Err("Debugger not active".into())
                        };
                        s.debug_state.mem_regions_result = Some((id, r));
                    }
                    if let Some(id) = s.debug_state.modules_request.take() {
                        let r = if dbg.is_active {
                            dbg.list_modules()
                        } else {
                            Err("Debugger not active".into())
                        };
                        s.debug_state.modules_result = Some((id, r));
                    }
                    if let Some(id) = s.debug_state.threads_request.take() {
                        let r = if dbg.is_active {
                            dbg.list_threads()
                        } else {
                            Err("Debugger not active".into())
                        };
                        s.debug_state.threads_result = Some((id, r));
                    }
                    if let Some(req) = s.debug_state.hw_bp_request.take() {
                        match req {
                            HwBpRequest::Set { id, slot, address, kind, len } => {
                                let r = if dbg.is_active {
                                    dbg.set_hardware_breakpoint(slot, address, kind, len)
                                } else {
                                    Err("Debugger not active".into())
                                };
                                s.debug_state.hw_bp_result = Some((id, r));
                            }
                            HwBpRequest::Clear { id, slot } => {
                                let r = if dbg.is_active {
                                    dbg.clear_hardware_breakpoint(slot)
                                } else {
                                    Err("Debugger not active".into())
                                };
                                s.debug_state.hw_bp_result = Some((id, r));
                            }
                        }
                    }
                    if let Some((id, address)) = s.debug_state.arm_int3_request.take() {
                        let r = if dbg.is_active {
                            let known = s.debug_state.breakpoints.iter()
                                .find(|b| b.address == address)
                                .map(|b| b.original_byte)
                                .filter(|o| *o != 0);
                            match dbg.read_memory(address, 1) {
                                Ok(cur) if cur.first() == Some(&0xCC) => match known {
                                    Some(orig) => Ok(orig),
                                    None => Err("INT3 already planted here by an unknown owner".into()),
                                },
                                Ok(cur) if !cur.is_empty() => {
                                    let fresh = cur[0];
                                    dbg.write_memory(address, &[0xCC]).map(|_| fresh)
                                }
                                Ok(_) => Err("read_memory returned empty".into()),
                                Err(e) => Err(e),
                            }
                        } else {
                            Err("Debugger not active".into())
                        };
                        s.debug_state.arm_int3_result = Some((id, r));
                    }

                    if let Some((id, pid)) = s.debug_state.attach_request.take() {
                        s.debug_state.events.clear();
                        s.debug_state.current_rip = 0;
                        s.debug_state.thread_id = 0;
                        s.debug_state.active_tid = 0;
                        s.debug_state.trace_buffer.clear();
                        s.debug_state.mem_read_request = None;
                        s.debug_state.mem_read_result = None;
                        s.debug_state.mem_write_request = None;
                        s.debug_state.mem_write_result = None;
                        s.debug_state.mem_regions_request = None;
                        s.debug_state.mem_regions_result = None;
                        s.debug_state.modules_request = None;
                        s.debug_state.modules_result = None;
                        s.debug_state.threads_request = None;
                        s.debug_state.threads_result = None;
                        s.debug_state.hw_bp_request = None;
                        s.debug_state.hw_bp_result = None;
                        s.debug_state.arm_int3_request = None;
                        s.debug_state.arm_int3_result = None;
                        s.debug_state.step_over_temp = None;
                        s.debug_state.step_over_plants.clear();
                        drop(s);
                        let r = dbg.attach_process(pid);
                        {
                            let mut s2 = lock_app(&state);
                            match &r {
                                Ok(_) => {
                                    let _ = dbg.get_registers(&mut s2.debug_state);
                                    s2.debug_state.is_running = false;
                                    s2.debug_state.is_attached = true;
                                    s2.debug_state.process_id = pid;
                                    s2.status_msg = format!("Attached to PID {}", pid);
                                }
                                Err(e) => {
                                    s2.status_msg = format!("Attach error: {}", e);
                                }
                            }
                            s2.debug_state.attach_result = Some((id, r));
                        }
                        signal.wait_timeout(Duration::from_millis(2));
                        continue;
                    }
                    if let Some(id) = s.debug_state.detach_request.take() {
                        for bp in s.debug_state.breakpoints.clone() {
                            let _ = dbg.remove_breakpoint(&bp);
                        }
                        let bps = s.debug_state.breakpoints.clone();
                        let r = dbg.detach_process(&bps);
                        s.debug_state.is_running = false;
                        s.debug_state.is_attached = false;
                        s.debug_state.process_id = 0;
                        s.debug_state.thread_id = 0;
                        s.debug_state.active_tid = 0;
                        s.debug_state.step_over_temp = None;
                        s.debug_state.step_over_plants.clear();
                        s.debug_state.mem_read_request = None;
                        s.debug_state.mem_write_request = None;
                        s.debug_state.mem_regions_request = None;
                        s.debug_state.modules_request = None;
                        s.debug_state.threads_request = None;
                        s.debug_state.hw_bp_request = None;
                        s.debug_state.arm_int3_request = None;
                        s.debug_state.attach_request = None;
                        s.status_msg = "Detached".into();
                        s.debug_state.detach_result = Some((id, r));
                    }

                }

                if dbg.is_active {
                    let snapshot = {
                        let s = lock_app(&state);
                        (
                            s.debug_state.clone(),
                            s.debug_state.events.len(),
                            s.debug_state.trace_buffer.len(),
                        )
                    };
                    {
                        let (mut local, orig_events, orig_trace) = snapshot;
                        match dbg.process_debug_event(&mut local) {
                            Ok(alive) => {
                                pump_err.reset();
                                if !alive {
                                    local.events.push("Target process exited.".into());
                                }
                                let mut s = lock_app(&state);
                                let target_gone = !local.is_attached;
                                {
                                    let d = &mut s.debug_state;
                                    d.is_running = local.is_running;
                                    d.current_rip = local.current_rip;
                                    d.is_attached = local.is_attached;
                                    if target_gone {
                                        d.process_id = 0;
                                        d.thread_id = 0;
                                        d.active_tid = 0;
                                        d.current_rip = 0;
                                    }
                                    d.registers = local.registers.clone();
                                    d.stack_data = local.stack_data.clone();
                                    for b in &d.breakpoints {
                                        if !local.breakpoints.iter().any(|x| x.address == b.address) {
                                            local.breakpoints.push(b.clone());
                                        }
                                    }
                                    d.breakpoints = local.breakpoints;
                                    merge_pump_tail(d, &local.events, orig_events, &local.trace_buffer, orig_trace);
                                    let had_temp = d.step_over_temp.or_else(|| {
                                        d.step_over_plants.values().copied().max_by_key(|s| s.token)
                                    });
                                    let rearm = dbg.pending_rearm.map(|(a, _)| a);
                                    let parked = !d.is_running
                                        && had_temp.map(|t| d.current_rip == t.addr || d.current_rip == t.addr.wrapping_add(1)).unwrap_or(false);
                                    if cleanup_step_over(d, rearm) || (parked && had_temp.is_some()) {
                                        if let Some(t) = had_temp {
                                            if rearm == Some(t.addr) {
                                                dbg.pending_rearm = None;
                                            }
                                            dbg.pending_queue.retain(|(a, _)| *a != t.addr);
                                            d.events.push(format!("Stepped over call, stopped at {:#x}", d.current_rip));
                                            s.status_msg = format!("Stepped over -> {:#x}", d.current_rip);
                                        } else if rearm.is_some() && parked {
                                            dbg.pending_rearm = None;
                                        }
                                    }
                                }
                                if target_gone {
                                    s.status_msg = "Target process exited.".into();
                                }
                                s.debug_state.signal.notify();
                            }
                            Err(e) => {
                                if !dbg.is_process_alive() {
                                    dbg.terminate();
                                    let mut s = lock_app(&state);
                                    s.debug_state.is_attached = false;
                                    s.debug_state.is_running = false;
                                    s.debug_state.process_id = 0;
                                    s.debug_state.events.push(
                                        "Target died - debug session cleaned up".into());
                                    s.debug_state.signal.notify();
                                } else {
                                    let (n, due) = pump_err.note();
                                    if due {
                                        let mut s = lock_app(&state);
                                        s.debug_state.events.push(format!("Debug loop ({}): {}", n, e));
                                        s.debug_state.signal.notify();
                                    }
                                }
                            }
                        }
                    }
                }

                signal.wait_timeout(Duration::from_millis(10));
            }
        })
        .expect("Failed to spawn debug thread")
}
