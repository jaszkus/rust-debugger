use crate::debugger::thread::spawn_debug_thread;
use crate::gui::AppState;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const DEFAULT_PORT: u16 = 7777;
const EXIT_FAILURE: i32 = 1;
const EXIT_USAGE: i32 = 2;

const HELP: &str = "\
rust-debugger — IDA/Ghidra-style binary analysis tool

Usage:
  rust-debugger [file]                         launch the GUI (optionally preloading a file)
  rust-debugger --serve [port] [file]          headless MCP server (alias --headless)
        --port <n>                             same as the positional port
                                               (default 7777, 0 = pick a free port)
  rust-debugger --analyze <file> [--fresh]     batch: parse + disasm + analyze, print a JSON
                                               summary (RDDB-cached; --fresh ignores the cache)
  rust-debugger --bench <file> [--parse-only]  time the parse / disasm / analysis phases
  rust-debugger --version | -v                 print version
  rust-debugger --help | -h                    print this help

Environment:
  RD_MAX_DECOMP    --analyze sets it to 0 unless it is already set

Exit codes: 0 ok, 1 runtime failure, 2 usage error
";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Version,
    Help,
    Serve { port: u16, file: Option<String> },
    Analyze { file: String, fresh: bool },
    Bench { file: String, parse_only: bool },
    Gui { file: Option<String> },
}

#[derive(Debug, PartialEq, Eq)]
struct Parsed {
    command: Command,
    warnings: Vec<String>,
}

fn is_flag(a: &str) -> bool {
    a.len() > 1 && a.starts_with('-')
}

fn first_positional(args: &[String], from: usize) -> Option<String> {
    args.iter().skip(from).find(|a| !is_flag(a)).cloned()
}

fn find_flag(args: &[String], names: &[&str]) -> Option<usize> {
    args.iter().position(|a| names.contains(&a.as_str()))
}

fn parse_port(s: &str) -> Result<u16, String> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(p) = s.parse::<u16>() {
            return Ok(p);
        }
    }
    Err(format!(
        "Bad port '{}' (want 0..=65535, 0 = pick a free port, default {})",
        s, DEFAULT_PORT
    ))
}

fn parse_serve_args(rest: &[String]) -> Result<(u16, Option<String>), String> {
    let mut port: Option<u16> = None;
    let mut file: Option<String> = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--port" {
            let v = it.next().ok_or("--port requires a value")?;
            port = Some(parse_port(v)?);
        } else if let Some(v) = a.strip_prefix("--port=") {
            port = Some(parse_port(v)?);
        } else if is_flag(a) {
        } else if port.is_none() && a.bytes().all(|b| b.is_ascii_digit()) {
            port = Some(parse_port(a)?);
        } else if file.is_none() {
            file = Some(a.clone());
        }
    }
    Ok((port.unwrap_or(DEFAULT_PORT), file))
}

fn unknown_flag_warnings(args: &[String], known: &[&str]) -> Vec<String> {
    args.iter()
        .filter(|a| is_flag(a))
        .filter(|a| {
            let name = a.split_once('=').map_or(a.as_str(), |(n, _)| n);
            !known.contains(&name)
        })
        .map(|a| format!("ignoring unknown option '{a}'"))
        .collect()
}

fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let done = |command: Command, known: &[&str]| Parsed {
        command,
        warnings: unknown_flag_warnings(args, known),
    };

    if find_flag(args, &["--version", "-v"]).is_some() {
        return Ok(Parsed {
            command: Command::Version,
            warnings: Vec::new(),
        });
    }
    if find_flag(args, &["--help", "-h"]).is_some() {
        return Ok(Parsed {
            command: Command::Help,
            warnings: Vec::new(),
        });
    }

    if let Some(pos) = find_flag(args, &["--serve", "--headless"]) {
        let mut rest = args.to_vec();
        rest.remove(pos);
        let (port, file) = parse_serve_args(&rest)?;
        return Ok(done(
            Command::Serve { port, file },
            &["--serve", "--headless", "--port"],
        ));
    }

    if find_flag(args, &["--analyze"]).is_some() {
        let file = first_positional(args, 0).ok_or("--analyze requires a file path")?;
        let fresh = find_flag(args, &["--fresh"]).is_some();
        return Ok(done(
            Command::Analyze { file, fresh },
            &["--analyze", "--fresh"],
        ));
    }

    if find_flag(args, &["--bench"]).is_some() {
        let mut positional: Vec<&String> = args.iter().filter(|a| !is_flag(a)).collect();
        let mut parse_only = find_flag(args, &["--parse-only", "--parse_only"]).is_some();
        if positional.len() > 1 && positional[0] == "parse" {
            positional.remove(0);
            parse_only = true;
        }
        parse_only |= positional.iter().skip(1).any(|p| *p == "parse");
        let file = positional
            .first()
            .map(|f| f.to_string())
            .ok_or("--bench requires a file path")?;
        return Ok(done(
            Command::Bench { file, parse_only },
            &["--bench", "--parse-only", "--parse_only"],
        ));
    }

    Ok(done(
        Command::Gui {
            file: first_positional(args, 0),
        },
        &[],
    ))
}

fn collect_args() -> Result<Vec<String>, String> {
    std::env::args_os()
        .skip(1)
        .map(|a| {
            a.into_string()
                .map_err(|bad| format!("argument is not valid Unicode: {bad:?}"))
        })
        .collect()
}

fn usage_exit(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!("Try 'rust-debugger --help' for usage.");
    std::process::exit(EXIT_USAGE);
}

fn print_version() {
    println!(
        "rust-debugger {} ({}/{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!(
        "MCP endpoint (default port): POST http://127.0.0.1:{}/mcp (JSON-RPC 2.0)",
        DEFAULT_PORT
    );
}

pub fn run() {
    let args = collect_args().unwrap_or_else(|msg| usage_exit(&msg));
    let parsed = parse_args(&args).unwrap_or_else(|msg| usage_exit(&msg));
    for w in &parsed.warnings {
        eprintln!("warning: {w}");
    }

    let result = match parsed.command {
        Command::Version => {
            print_version();
            Ok(())
        }
        Command::Help => {
            print!("{}", HELP);
            Ok(())
        }
        Command::Serve { port, file } => run_headless(port, file),
        Command::Analyze { file, fresh } => {
            run_batch_analyze(&file, fresh).inspect_err(|e| print_json_failure(e))
        }
        Command::Bench { file, parse_only } => run_bench(&file, parse_only),
        Command::Gui { file } => run_gui(file),
    };

    if let Err(msg) = result {
        eprintln!("error: {msg}");
        std::process::exit(EXIT_FAILURE);
    }
}

fn print_json_failure(msg: &str) {
    let err = serde_json::json!({ "ok": false, "error": msg });
    println!("{err}");
}

fn fmt_dur(d: Duration) -> String {
    if d < Duration::from_secs(1) {
        format!("{:.1} ms", d.as_secs_f64() * 1000.0)
    } else {
        format!("{:.2} s", d.as_secs_f64())
    }
}

fn file_mtime(p: impl AsRef<std::path::Path>) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn cache_is_fresh(bin_mtime: Option<SystemTime>, db_mtime: Option<SystemTime>) -> bool {
    match (bin_mtime, db_mtime) {
        (Some(b), Some(d)) => d >= b,
        _ => false,
    }
}

fn absolute_path_string(path: &str) -> String {
    std::path::absolute(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

fn exec_coverage<T>(
    insns: &[T],
    span: impl Fn(&T) -> (u64, u64),
    sections: impl IntoIterator<Item = (u64, u64)>,
) -> (u64, u64, u64) {
    let (mut gaps, mut uncovered, mut total) = (0u64, 0u64, 0u64);
    for (vaddr, size) in sections {
        let sec_end = vaddr.saturating_add(size);
        total = total.saturating_add(size);
        let mut prev_end = vaddr;
        let mut i = insns.partition_point(|x| span(x).0 < vaddr);
        while let Some(x) = insns.get(i) {
            let (addr, len) = span(x);
            if addr >= sec_end {
                break;
            }
            if addr > prev_end {
                uncovered += addr - prev_end;
                gaps += 1;
            }
            prev_end = prev_end.max(addr.saturating_add(len));
            i += 1;
        }
        if sec_end > prev_end {
            uncovered += sec_end - prev_end;
            gaps += 1;
        }
    }
    (gaps, uncovered, total)
}

#[allow(clippy::field_reassign_with_default)]
fn run_batch_analyze(path: &str, fresh: bool) -> Result<(), String> {
    let started = Instant::now();

    if std::env::var_os("RD_MAX_DECOMP").is_none() {
        
        
        unsafe { std::env::set_var("RD_MAX_DECOMP", "0") };
    }

    let bin = crate::parser::parse_file(std::path::Path::new(path))
        .map_err(|e| format!("parse failed: {e}"))?;
    let parse_time = started.elapsed();

    let abs_path = absolute_path_string(path);
    let db_path = crate::project::resolve_db_path(path);

    let bin_mtime = file_mtime(path);
    let db_mtime = file_mtime(&db_path);
    let cache_usable = cache_is_fresh(bin_mtime, db_mtime);
    if !fresh && !cache_usable {
        if let (Some(b), Some(d)) = (bin_mtime, db_mtime) {
            if d < b {
                eprintln!("[rddb stale: {db_path} is older than {path}; re-analyzing]");
            }
        }
    }

    let cached = if fresh || !cache_usable {
        None
    } else {
        crate::project::load_project_db(&db_path).filter(|s| s.source_path == abs_path.as_str())
    };

    let (cache_hit, functions, xrefs, findings) = match cached {
        Some(snap) => {
            eprintln!("[rddb cache hit: {}]", db_path);
            let findings = crate::analysis::detect::detect_all(&bin, &snap.disasm)
                .findings
                .len();
            (
                true,
                snap.analysis.functions.len(),
                snap.analysis.xrefs.all.len(),
                findings,
            )
        }
        None => {
            let disasm = crate::disasm::disassemble_binary(&bin)
                .map_err(|e| format!("disasm failed: {e}"))?;
            let never_cancel = AtomicBool::new(false);
            let empty_fid = crate::analysis::function_id::FunctionIDMatcher::new();
            let result = crate::analysis::auto_analyze_with_progress(
                &disasm,
                &bin,
                &rustc_hash::FxHashMap::default(),
                &empty_fid,
                &never_cancel,
                &|_, _, _, _| {},
            );

            let functions = result.functions.len();
            let xrefs = result.xrefs.all.len();
            let findings = crate::analysis::detect::detect_all(&bin, &disasm)
                .findings
                .len();

            let mut program = crate::gui::ProgramData::default();
            program.file_path = abs_path.clone();
            program.disasm = Some(disasm);
            program.analysis = Some(Arc::new(result));
            match crate::project::save_project_db(&program, &db_path) {
                Ok(()) => eprintln!("[rddb cached: {}]", db_path),
                Err(e) => eprintln!("[rddb save skipped: {}]", e),
            }
            (false, functions, xrefs, findings)
        }
    };

    let out = serde_json::json!({
        "ok": true,
        "file": path,
        "size": bin.data.len(),
        "cache": if cache_hit { "hit" } else { "miss" },
        "db": db_path,
        "format": bin.format,
        "arch": bin.arch,
        "entry": format!("{:#x}", bin.entry_point),
        "sections": bin.sections.len(),
        "imports": bin.imports.len(),
        "exports": bin.exports.len(),
        "strings": bin.strings.len(),
        "functions": functions,
        "xrefs": xrefs,
        "findings": findings,
        "tls_callbacks": bin.tls_callbacks.len(),
        "delay_imports": bin.delay_imports.len(),
        "has_rich": bin.has_rich,
        "libraries": bin.libraries,
        "parse_ms": parse_time.as_millis() as u64,
        "elapsed_ms": started.elapsed().as_millis() as u64,
    });
    println!("{out:#}");
    Ok(())
}

fn run_bench(path: &str, parse_only: bool) -> Result<(), String> {
    let t0 = Instant::now();
    let bin = crate::parser::parse_file(std::path::Path::new(path))
        .map_err(|e| format!("parse failed: {e}"))?;
    println!(
        "parse:        {:>9}  ({} | {} | entry={:#X}, {} sections, {} symbols)",
        fmt_dur(t0.elapsed()),
        bin.format,
        bin.arch,
        bin.entry_point,
        bin.sections.len(),
        bin.symbols.len()
    );
    println!("strings:      {} (score-filtered)", bin.strings.len());
    let t_raw = Instant::now();
    let raw = crate::parser::extract_strings(&bin.data[..], 4).len();
    println!(
        "strings raw:  {} (unfiltered, {})",
        raw,
        fmt_dur(t_raw.elapsed())
    );
    if parse_only {
        return Ok(());
    }

    let t1 = Instant::now();
    let d = crate::disasm::disassemble_binary(&bin).map_err(|e| format!("disasm failed: {e}"))?;
    println!(
        "disasm:       {:>9}  ({} instructions)",
        fmt_dur(t1.elapsed()),
        d.instructions.len()
    );

    let (gaps, uncovered, total) = exec_coverage(
        &d.instructions,
        |i| (i.address, i.bytes.len() as u64),
        bin.sections
            .iter()
            .filter(|s| s.is_executable)
            .map(|s| (s.vaddr, s.size)),
    );
    let covered_pct = if total > 0 {
        100.0 * (total - uncovered.min(total)) as f64 / total as f64
    } else {
        100.0
    };
    println!(
        "coverage:     {} gaps, {} uncovered bytes in exec sections ({:.2}% covered)",
        gaps, uncovered, covered_pct
    );

    let t2 = Instant::now();
    let funcs =
        crate::analysis::function::detect_functions(&d.instructions, bin.entry_point, &bin.symbols);
    println!(
        "func discover:{:>9}  ({} functions)",
        fmt_dur(t2.elapsed()),
        funcs.len()
    );

    let t3 = Instant::now();
    let never_cancel = AtomicBool::new(false);
    let empty_fid = crate::analysis::function_id::FunctionIDMatcher::new();
    let result = crate::analysis::auto_analyze_with_progress(
        &d,
        &bin,
        &rustc_hash::FxHashMap::default(),
        &empty_fid,
        &never_cancel,
        &|phase, msg, cur, total| {
            println!(
                "  [{:>6.1}s] phase {}/{}: {} — {}",
                t3.elapsed().as_secs_f32(),
                cur,
                total,
                phase,
                msg
            );
        },
    );
    println!(
        "analysis:     {} total ({} functions, {} xrefs)",
        fmt_dur(t3.elapsed()),
        result.functions.len(),
        result.xrefs.all.len()
    );
    Ok(())
}

enum Outcome<R> {
    Done(R, Duration),
    NoProgram,
    Busy,
    Panicked(String),
}

fn spawn_analysis_worker(state: Arc<Mutex<AppState>>) {
    use crate::mcp::tools::lock::lock_state_timeout;

    const POLL_MIN: Duration = Duration::from_millis(50);
    const POLL_MAX: Duration = Duration::from_millis(250);
    const MAX_INSTALL_ATTEMPTS: u32 = 5;

    std::thread::spawn(move || {
        let mut poll = POLL_MIN;
        let mut pending: Option<(_, u32)> = None;

        loop {
            let (outcome, attempts) = match pending.take() {
                Some(p) => p,
                None => {
                    std::thread::sleep(poll);
                    let requested = match lock_state_timeout(&state, Duration::from_millis(200)) {
                        Ok(mut s) => std::mem::take(&mut s.mcp_request_analysis),
                        Err(_) => false,
                    };
                    if !requested {
                        poll = (poll * 2).min(POLL_MAX);
                        continue;
                    }
                    poll = POLL_MIN;
                    eprintln!("[analysis-loop] request flag seen");

                    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let (disasm, bin, user_names, fid_shared) =
                            match lock_state_timeout(&state, Duration::from_secs(5)) {
                                Ok(s) => (
                                    s.disasm.clone(),
                                    s.binary.clone(),
                                    s.user_func_names.clone(),
                                    s.fid_shared(),
                                ),
                                Err(_) => return Outcome::Busy,
                            };
                        let (Some(d), Some(b)) = (disasm, bin) else {
                            return Outcome::NoProgram;
                        };
                        println!("Running analysis...");
                        let started = Instant::now();
                        let never_cancel = AtomicBool::new(false);
                        let r = crate::analysis::auto_analyze_with_progress(
                            &d,
                            &b,
                            &user_names,
                            &fid_shared,
                            &never_cancel,
                            &|p, _, _, _| {
                                println!("  phase: {}", p);
                            },
                        );
                        Outcome::Done(r, started.elapsed())
                    }));
                    let outcome = match run {
                        Ok(o) => o,
                        Err(p) => Outcome::Panicked(panic_message(&*p)),
                    };
                    (outcome, 0)
                }
            };

            let mut s = match lock_state_timeout(&state, Duration::from_secs(30)) {
                Ok(s) => s,
                Err(e) => {
                    if attempts + 1 < MAX_INSTALL_ATTEMPTS {
                        eprintln!("[analysis-loop] cannot install result ({e}); will retry");
                        pending = Some((outcome, attempts + 1));
                        std::thread::sleep(Duration::from_secs(1));
                    } else {
                        eprintln!("[analysis-loop] cannot install result ({e}); giving up");
                    }
                    continue;
                }
            };

            let failure: Option<String> = match outcome {
                Outcome::Done(r, elapsed) => {
                    let (_, _) = s.transact(crate::gui::ProgramEvent::AnalysisReplaced, |s| {
                        s.analysis = Some(Arc::new(r));
                    });
                    crate::gui::state::invalidate_analysis_caches(&mut s);
                    s.analysis_progress = None;
                    s.analysis_error = None;
                    s.analysis_seq = s.analysis_seq.wrapping_add(1);
                    println!("Analysis done in {}", fmt_dur(elapsed));
                    None
                }
                Outcome::NoProgram => {
                    Some("No program loaded; open a file before requesting analysis".to_string())
                }
                Outcome::Busy => {
                    Some("Could not read program state (lock contention); try again".to_string())
                }
                Outcome::Panicked(msg) => Some(format!("Analysis worker panicked: {msg}")),
            };
            if let Some(msg) = failure {
                eprintln!("[analysis-loop] {msg}; seq advanced so waiters wake up");
                s.analysis_progress = None;
                s.analysis_error = Some(msg);
                s.analysis_seq = s.analysis_seq.wrapping_add(1);
            }
        }
    });
}

fn run_headless(port: u16, file: Option<String>) -> Result<(), String> {
    let app_state = Arc::new(Mutex::new(AppState::new()));
    app_state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .attach_mcp_shared(app_state.clone());

    if let Some(path) = file {
        let mut guard = app_state.lock().unwrap_or_else(|p| p.into_inner());
        crate::gui::open_file_into_program_with_auto_analysis(&mut guard, &path, None, true)
            .map_err(|e| format!("Load failed: {e}"))?;
        println!("Loaded {}", path);
    }

    let _debug_join = spawn_debug_thread(app_state.clone());
    spawn_analysis_worker(app_state.clone());

    let srv = crate::mcp::McpServer::start(port, app_state)
        .map_err(|e| format!("MCP server failed to start: {e}"))?;
    println!(
        "MCP server listening on http://127.0.0.1:{}/mcp",
        srv.actual_port
    );
    println!("Press Ctrl+C to stop.");
    loop {
        std::thread::park();
    }
}

fn install_gui_panic_log() {
    let log_path = std::env::temp_dir().join("rust-debugger-gui.log");
    if std::fs::File::create(&log_path).is_err() {
        return;
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log_path)
        {
            let secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let thread = std::thread::current();
            let _ = writeln!(
                f,
                "PANIC [unix {secs}] in thread '{}': {info}",
                thread.name().unwrap_or("<unnamed>")
            );
            let _ = writeln!(f, "{}", std::backtrace::Backtrace::force_capture());
        }
        prev(info);
    }));
}

fn run_gui(initial_file: Option<String>) -> Result<(), String> {
    install_gui_panic_log();
    let mut app_state = AppState::new();

    if let Some(path) = initial_file {
        if let Err(e) = crate::gui::open_file_into_program_with_auto_analysis(
            &mut app_state,
            &path,
            None,
            false,
        ) {
            eprintln!("Load failed: {e}");
        }
    }

    let shared = Arc::new(Mutex::new(app_state));
    shared
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .attach_mcp_shared(shared.clone());
    let _debug_join = spawn_debug_thread(shared.clone());
    start_iced(shared)
}

fn start_iced(shared: Arc<Mutex<AppState>>) -> Result<(), String> {
    let shell = crate::gui::app::Shell::from_shared(shared);
    shell
        .run()
        .map(|_| ())
        .map_err(|e| format!("GUI failed: {e:?}"))
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn cmd(a: &[&str]) -> Command {
        parse_args(&v(a)).expect("should parse").command
    }

    fn warnings(a: &[&str]) -> Vec<String> {
        parse_args(&v(a)).expect("should parse").warnings
    }

    #[test]
    fn serve_defaults_and_port() {
        assert_eq!(parse_serve_args(&v(&[])), Ok((7777, None)));
        assert_eq!(parse_serve_args(&v(&["8080"])), Ok((8080, None)));
        assert_eq!(
            parse_serve_args(&v(&["8080", "a.exe"])),
            Ok((8080, Some("a.exe".into())))
        );
        assert_eq!(parse_serve_args(&v(&["0"])), Ok((0, None)));
        assert_eq!(parse_serve_args(&v(&["65535"])), Ok((65535, None)));
    }

    #[test]
    fn serve_file_without_port() {
        assert_eq!(
            parse_serve_args(&v(&["a.exe"])),
            Ok((7777, Some("a.exe".into())))
        );
        assert_eq!(
            parse_serve_args(&v(&["--x", "a.exe"])),
            Ok((7777, Some("a.exe".into())))
        );
    }

    #[test]
    fn serve_rejects_bad_port() {
        assert!(parse_serve_args(&v(&["65536"])).is_err());
        assert!(parse_serve_args(&v(&["99999999999999999999"])).is_err());
        assert!(parse_serve_args(&v(&[""])).is_err());
    }

    #[test]
    fn positional_skips_flags() {
        let a = v(&["--analyze", "--fresh", "bin.exe"]);
        assert_eq!(first_positional(&a, 1), Some("bin.exe".into()));
        assert_eq!(first_positional(&a, 3), None);
        assert_eq!(first_positional(&v(&["--x"]), 0), None);
    }

    #[test]
    fn single_dash_flags_are_not_files() {
        assert_eq!(
            first_positional(&v(&["-x", "a.exe"]), 0),
            Some("a.exe".into())
        );
        assert_eq!(first_positional(&v(&["-"]), 0), Some("-".into()));
    }

    #[test]
    fn port_forms() {
        assert_eq!(parse_serve_args(&v(&["--port", "9000"])), Ok((9000, None)));
        assert_eq!(
            parse_serve_args(&v(&["--port=9000", "a.exe"])),
            Ok((9000, Some("a.exe".into())))
        );
        assert!(parse_serve_args(&v(&["--port"])).is_err());
        assert!(parse_serve_args(&v(&["--port", "+80"])).is_err());
        assert!(parse_serve_args(&v(&["--port=70000"])).is_err());
    }

    #[test]
    fn gui_is_the_default() {
        assert_eq!(cmd(&[]), Command::Gui { file: None });
        assert_eq!(
            cmd(&["a.exe"]),
            Command::Gui {
                file: Some("a.exe".into())
            }
        );
    }

    #[test]
    fn version_and_help_win_over_everything() {
        assert_eq!(cmd(&["--serve", "-v"]), Command::Version);
        assert_eq!(cmd(&["--version"]), Command::Version);
        assert_eq!(cmd(&["--bench", "a.exe", "--help"]), Command::Help);
        assert_eq!(cmd(&["-h"]), Command::Help);
    }

    #[test]
    fn serve_flag_order_does_not_matter() {
        assert_eq!(
            cmd(&["--serve"]),
            Command::Serve {
                port: 7777,
                file: None
            }
        );
        assert_eq!(
            cmd(&["--headless", "9000", "a.exe"]),
            Command::Serve {
                port: 9000,
                file: Some("a.exe".into())
            }
        );
        assert_eq!(
            cmd(&["a.exe", "--serve"]),
            Command::Serve {
                port: 7777,
                file: Some("a.exe".into())
            }
        );
        assert_eq!(
            cmd(&["--port", "9000", "--serve", "a.exe"]),
            Command::Serve {
                port: 9000,
                file: Some("a.exe".into())
            }
        );
        assert_eq!(
            cmd(&["--serve", "--port=0"]),
            Command::Serve {
                port: 0,
                file: None
            }
        );
        assert!(parse_args(&v(&["--serve", "--port"])).is_err());
        assert!(parse_args(&v(&["--serve", "--port", "70000"])).is_err());
    }

    #[test]
    fn analyze_finds_the_file_anywhere() {
        let want = Command::Analyze {
            file: "a.exe".into(),
            fresh: false,
        };
        assert_eq!(cmd(&["--analyze", "a.exe"]), want);
        assert_eq!(cmd(&["a.exe", "--analyze"]), want);
        assert_eq!(
            cmd(&["--analyze", "--fresh", "a.exe"]),
            Command::Analyze {
                file: "a.exe".into(),
                fresh: true
            }
        );
        assert!(parse_args(&v(&["--analyze", "--fresh"])).is_err());
    }

    #[test]
    fn bench_variants() {
        let plain = Command::Bench {
            file: "f.exe".into(),
            parse_only: false,
        };
        let parse_only = Command::Bench {
            file: "f.exe".into(),
            parse_only: true,
        };
        assert_eq!(cmd(&["--bench", "f.exe"]), plain);
        assert_eq!(cmd(&["--bench", "f.exe", "--parse-only"]), parse_only);
        assert_eq!(cmd(&["--bench", "--parse_only", "f.exe"]), parse_only);
        assert_eq!(cmd(&["--bench", "f.exe", "parse"]), parse_only);
        assert_eq!(cmd(&["--bench", "parse", "f.exe"]), parse_only);
        assert_eq!(
            cmd(&["--bench", "parse"]),
            Command::Bench {
                file: "parse".into(),
                parse_only: false
            }
        );
        assert!(parse_args(&v(&["--bench"])).is_err());
    }

    #[test]
    fn unknown_flags_warn_in_every_mode() {
        assert!(warnings(&["--wat"]).iter().any(|w| w.contains("--wat")));
        assert!(warnings(&["-x", "a.exe"]).iter().any(|w| w.contains("-x")));
        assert!(warnings(&["--analyze", "a.exe", "--fresh"]).is_empty());
        assert!(warnings(&["--serve", "--port=1"]).is_empty());
        assert!(warnings(&["--bench", "a.exe", "--parse-only"]).is_empty());
        assert_eq!(warnings(&["--serve", "--analyze"]).len(), 1);
        assert_eq!(warnings(&["--analyze", "a.exe", "--frsh"]).len(), 1);
    }

    #[test]
    fn coverage_counts_gaps_and_tail() {
        let insns: [(u64, u64); 3] = [(0x1000, 4), (0x1004, 4), (0x1010, 4)];
        let span = |&(a, l): &(u64, u64)| (a, l);
        assert_eq!(exec_coverage(&insns, span, [(0x1000, 0x20)]), (2, 20, 0x20));
    }

    #[test]
    fn coverage_edge_cases() {
        let span = |&(a, l): &(u64, u64)| (a, l);
        let full: [(u64, u64); 1] = [(0x1000, 0x10)];
        assert_eq!(exec_coverage(&full, span, [(0x1000, 0x10)]), (0, 0, 0x10));

        let none: [(u64, u64); 0] = [];
        assert_eq!(
            exec_coverage(&none, span, [(0x1000, 0x10)]),
            (1, 0x10, 0x10)
        );
        assert_eq!(exec_coverage(&none, span, [(0x1000, 0)]), (0, 0, 0));

        let before: [(u64, u64); 1] = [(0x0FF0, 4)];
        assert_eq!(
            exec_coverage(&before, span, [(0x1000, 0x10)]),
            (1, 0x10, 0x10)
        );

        let straddle: [(u64, u64); 1] = [(0x100E, 8)];
        assert_eq!(
            exec_coverage(&straddle, span, [(0x1000, 0x10)]),
            (1, 14, 0x10)
        );
    }

    #[test]
    fn rddb_freshness() {
        let t = |s| UNIX_EPOCH + Duration::from_secs(s);
        assert!(cache_is_fresh(Some(t(10)), Some(t(20))));
        assert!(cache_is_fresh(Some(t(10)), Some(t(10))));
        assert!(!cache_is_fresh(Some(t(20)), Some(t(10))));
        assert!(!cache_is_fresh(None, Some(t(10))));
        assert!(!cache_is_fresh(Some(t(10)), None));
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(fmt_dur(Duration::from_micros(1500)), "1.5 ms");
        assert_eq!(fmt_dur(Duration::from_millis(1500)), "1.50 s");
    }

    #[test]
    fn panic_payloads_are_readable() {
        let p = std::panic::catch_unwind(|| {
            panic!("boom");
        })
        .unwrap_err();
        assert_eq!(panic_message(&*p), "boom");

        let p = std::panic::catch_unwind(|| {
            panic!("code {}", 7);
        })
        .unwrap_err();
        assert_eq!(panic_message(&*p), "code 7");
    }
}
