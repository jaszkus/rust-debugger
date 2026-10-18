pub mod analysis;
pub mod asm;
pub mod cli;
pub mod debugger;
pub mod disasm;
pub mod emu;
pub mod gui;
pub mod mcp;
pub mod parser;
pub mod project;
pub mod type_system;
pub mod util;

pub use util::parallel;

#[cfg(test)]
mod tests;
