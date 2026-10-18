use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use crate::gui::AppState;

pub const MCP_LOCK_TIMEOUT: Duration = Duration::from_millis(3000);

pub fn lock_state_timeout<'a>(
    state: &'a Arc<Mutex<AppState>>,
    timeout: Duration,
) -> Result<MutexGuard<'a, AppState>, String> {
    let start = Instant::now();
    let mut backoff = Duration::from_micros(100);
    loop {
        match state.try_lock() {
            Ok(g) => return Ok(g),
            Err(TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
            Err(TryLockError::WouldBlock) => {}
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "Service unavailable (503): state busy for {} ms, retry",
                timeout.as_millis()
            ));
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(5));
    }
}

pub fn lock_state<'a>(state: &'a Arc<Mutex<AppState>>) -> Result<MutexGuard<'a, AppState>, String> {
    lock_state_timeout(state, MCP_LOCK_TIMEOUT)
}
