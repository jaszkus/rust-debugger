pub mod advanced;
pub mod binary;
pub mod decompiler;
pub mod flow;
pub mod operands;
pub mod pipeline;
pub mod symbols;
pub mod type_reconstruction;
pub mod xref;

pub use binary::{detect, golang, pe_resources, rtti};
pub use decompiler::{expr, pcode};
pub use flow::{cfg, constprop, function, function_id, noreturn, stack, unwind};
pub use symbols::{debug_symbols, demangle, dwarf_types, pdb_types};
pub use xref::import_xref;

pub mod types {
    pub use super::operands::*;
}

pub use advanced::{StubInfo, StubKind, SwitchTable};
pub use decompiler::{LineKind, Pseudocode};
pub use flow::cfg::{EdgeKind, CFG};
pub use flow::function::{DetectedFunction, FuncSource};
pub use flow::stack::{StackFrame, VarKind};
pub use pipeline::{
    auto_analyze, auto_analyze_with_progress, decompile_on_demand, decompile_snapshot,
    AnalysisResult, ProgressFn,
};
pub use xref::db::{XRefDB, XRefKind};
