pub mod golang;
pub mod pe_resources;
pub mod protections;
pub mod rtti;

pub mod detect {
    pub use super::protections::*;
}
