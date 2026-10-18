use super::*;

pub(crate) fn recents_path() -> std::path::PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let dir = std::path::Path::new(&appdata).join("rust-debugger");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("recent_projects.txt")
    } else {
        std::path::PathBuf::from("recent_projects.txt")
    }
}

pub(crate) fn load_recents() -> Vec<String> {
    std::fs::read_to_string(recents_path())
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn save_recents(list: &[String]) {
    let path = recents_path();
    let content = list.join("\n");
    let _ = std::fs::write(path, content);
}

pub fn touch_recent(state: &mut AppState, path: &str) {
    if path.is_empty() {
        return;
    }
    state.recent_projects.retain(|p| p != path);
    state.recent_projects.insert(0, path.to_string());
    if state.recent_projects.len() > 12 {
        state.recent_projects.truncate(12);
    }
    save_recents(&state.recent_projects);
}

pub(crate) fn db_fingerprint(state: &AppState) -> u64 {
    fn mix(h: &mut u64, v: u64) {
        *h ^= v;
        *h = h.wrapping_mul(0x100000001b3);
    }
    fn mix_bytes(h: &mut u64, bytes: &[u8]) {
        mix(h, bytes.len() as u64);
        for &b in bytes {
            mix(h, b as u64);
        }
    }
    fn mix_str(h: &mut u64, s: &str) {
        mix_bytes(h, s.as_bytes());
    }
    let mut h: u64 = 0xcbf29ce484222325;
    mix(&mut h, state.analysis_version);
    mix(&mut h, state.patch_seq);
    mix(&mut h, state.comments.len() as u64);
    for (k, v) in &state.comments {
        mix(&mut h, *k);
        mix_str(&mut h, v);
    }
    mix(&mut h, state.comments_ex.len() as u64);
    for ((k, kind), v) in &state.comments_ex {
        mix(&mut h, *k);
        mix(&mut h, kind.tag() as u64);
        mix_str(&mut h, v);
    }
    mix(&mut h, state.user_func_names.len() as u64);
    for (k, v) in &state.user_func_names {
        mix(&mut h, *k);
        mix_str(&mut h, v);
    }
    mix(&mut h, state.bookmarks.len() as u64);
    for b in &state.bookmarks {
        mix(&mut h, b.addr);
        mix(&mut h, b.kind as u64);
        mix_str(&mut h, &b.note);
    }
    mix(&mut h, state.user_labels.len() as u64);
    for (k, v) in &state.user_labels {
        mix(&mut h, *k);
        mix_str(&mut h, v);
    }
    mix(&mut h, state.function_tags.len() as u64);
    for (k, tags) in &state.function_tags {
        mix(&mut h, *k);
        for t in tags {
            mix_str(&mut h, t);
        }
    }
    mix(&mut h, state.user_xrefs.len() as u64);
    mix(&mut h, state.data_types_at.len() as u64);
    mix(&mut h, state.types.len() as u64);
    h
}

pub(crate) fn autosave_check(state: &mut AppState) {
    if state.binary.is_none() || state.file_path.is_empty() {
        return;
    }
    let saved_fp_now = state.db_saved_fp;
    if !state.program.is_changed() && saved_fp_now != 0 {
        return;
    }
    if let Some(p) = state.analysis_progress.as_ref() {
        let running = match p.try_lock() {
            Ok(g) => !g.done,
            Err(std::sync::TryLockError::Poisoned(p)) => !p.into_inner().done,
            Err(std::sync::TryLockError::WouldBlock) => true,
        };
        if running {
            return;
        }
    }
    match save_state_of(state) {
        SaveState::Saving {
            saved_fp: _,
            pending_fp,
        } => {
            let verdict = state.db_save_rx.as_ref().map(|rx| rx.try_recv());
            match verdict {
                Some(Ok(true)) => {
                    state.db_saved_fp = pending_fp;
                    state.program.mark_saved();
                    state.db_save_rx = None;
                }
                Some(Ok(false)) | Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => {
                    state.db_save_rx = None;
                    state.db_last_save_attempt =
                        std::time::Instant::now().checked_sub(std::time::Duration::from_secs(50));
                }
                Some(Err(std::sync::mpsc::TryRecvError::Empty)) => {}
                None => {}
            }
        }
        SaveState::Idle { .. } => {}
    }
    let now = std::time::Instant::now();
    let modif = state.program.modification_number;
    let fp = if modif == state.db_fp_modif && state.db_fp_value != 0 {
        state.db_fp_value
    } else {
        if let Some(t) = state.db_fp_checked
            && now.duration_since(t).as_millis() < 1000 {
                return;
            }
        let fp = db_fingerprint(state);
        state.db_fp_modif = modif;
        state.db_fp_value = fp;
        state.db_fp_checked = Some(now);
        fp
    };
    if fp == state.db_saved_fp && state.db_saved_fp != 0 {
        state.program.mark_saved();
        return;
    }
    if matches!(save_state_of(state), SaveState::Saving { .. }) {
        return;
    }
    let due = state
        .db_last_save_attempt
        .map(|t| now.duration_since(t).as_secs() >= 60)
        .unwrap_or(true);
    if !due {
        return;
    }
    state.db_last_save_attempt = Some(now);
    state.db_pending_fp = fp;
    let program = state.program.clone();
    let db = crate::project::resolve_db_path(&state.file_path);
    let (tx, rx) = std::sync::mpsc::channel();
    state.db_save_rx = Some(rx);
    std::thread::spawn(move || {
        let ok = crate::project::save_project_db(&program, &db).is_ok();
        let _ = tx.send(ok);
    });
}

#[allow(dead_code)]
pub fn clip_len(n: usize) -> i32 {
    n.min(i32::MAX as usize) as i32
}

pub const ARCH_OPTIONS: &[&str] = &["x86_64", "x86", "aarch64", "arm"];
pub const ARCH_OPTION_LABELS: &[&str] = &[
    "x86_64 (64-bit)",
    "x86 (32-bit)",
    "aarch64 (ARM64)",
    "arm (32-bit, incl. Thumb mode)",
];

pub fn clamp_arch_idx(idx: usize) -> usize {
    idx.min(ARCH_OPTIONS.len().saturating_sub(1))
}
