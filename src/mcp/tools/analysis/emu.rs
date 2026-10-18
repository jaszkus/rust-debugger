use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

use super::common::*;

pub fn emu_run_function(args: &Value, state: &Arc<Mutex<AppState>>) -> Result<Value, String> {
    use crate::emu::{EmuConfig, Emulator};

    let addr = arg_addr(args, "address")?;
    let arg_vec: Vec<u64> = args
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|x| x.as_u64().unwrap_or(0)).collect())
        .unwrap_or_default();
    let max_steps = args
        .get("max_steps")
        .and_then(|v| v.as_u64())
        .unwrap_or(200_000) as usize;

    let s = state.lock().map_err(|_| "lock poisoned".to_string())?;
    let bin = s.binary.as_ref().ok_or("No binary loaded")?;
    let disasm = s.disasm.as_ref().ok_or("No disassembly loaded")?;
    let (entry, end, has_frame, name) = match &s.analysis {
        Some(a) => a
            .functions
            .iter()
            .find(|f| addr >= f.entry && addr < f.end)
            .map(|f| (f.entry, f.end, f.has_frame, f.name.clone()))
            .ok_or("Address not in any function (run analysis first)")?,
        None => (
            addr,
            addr.saturating_add(0x1000),
            false,
            format!("sub_{:X}", addr),
        ),
    };
    let cfg = EmuConfig {
        max_steps: max_steps.clamp(1, 10_000_000),
        ..EmuConfig::default()
    };
    let mut emu = Emulator::with_config(bin, &disasm.instructions, cfg);
    let r = emu.run_function(entry, end, has_frame, &arg_vec);
    let reason = match &r.reason {
        crate::emu::EndReason::Returned => "returned".to_string(),
        crate::emu::EndReason::MaxSteps => "max_steps".to_string(),
        crate::emu::EndReason::UnmappedRip(a) => format!("unmapped_rip({:#x})", a),
        crate::emu::EndReason::IndirectUnknown(a) => format!("indirect_unknown({:#x})", a),
        crate::emu::EndReason::CallToImport(n) => format!("call_to_import({})", n),
        crate::emu::EndReason::UnmappedCall(a) => format!("unmapped_call({:#x})", a),
        crate::emu::EndReason::OobRead(a) => format!("oob_read({:#x})", a),
        crate::emu::EndReason::UninitRead(a) => format!("uninit_read({:#x})", a),
        crate::emu::EndReason::OobWrite(a) => format!("oob_write({:#x})", a),
        crate::emu::EndReason::StackOverflow(a) => format!("stack_overflow({:#x})", a),
        crate::emu::EndReason::StackUnderflow(a) => format!("stack_underflow({:#x})", a),
        crate::emu::EndReason::DivByZero => "div_by_zero".to_string(),
        crate::emu::EndReason::Trap(n) => format!("trap({})", n),
        crate::emu::EndReason::Unmodeled(t) => format!("unmodeled({})", t),
        crate::emu::EndReason::LeftFunction(a) => format!("left_function({:#x})", a),
    };
    Ok(json!({
        "function": name,
        "entry": format!("{:#x}", entry),
        "rax": format!("{:#x}", r.rax),
        "rax_signed": r.rax as i64,
        "reason": reason,
        "steps": r.steps,
        "writes": r.writes.iter().take(64).map(|w| json!({
            "address": format!("{:#x}", w.addr),
            "size": w.size,
            "old": format!("{:#x}", w.old),
            "new": format!("{:#x}", w.new),
        })).collect::<Vec<_>>(),
        "write_count": r.writes.len(),
        "dropped_writes": r.dropped_writes,
        "stack_writes": r.stack_writes,
        "trace_tail": r.trace_tail.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>(),
    }))
}
