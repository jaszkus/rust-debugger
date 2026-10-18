#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    rust_debugger::cli::run();
}
