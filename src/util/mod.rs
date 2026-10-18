
pub mod parallel;

pub use parallel::{
    exec_sections, install, join, pool, should_parallelize, should_parallelize_sections,
    split_exec_range, workers,
};
