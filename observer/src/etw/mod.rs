pub mod user;
pub mod kernel;
pub mod consumer;
pub mod types;
pub mod errors;
pub mod event_parser;
pub mod utils;
mod manifest_parser;

mod r#trait;
pub use r#trait::TraceSession;

// Re-export specific items to match `etw::UserTrace`, `etw::KernelTrace`, etc.
pub use user::{UserTrace, EventFilter};
pub use kernel::KernelTrace;
pub use types::{Event};

// Create a 'filter' module namespace for clean usage: filter::DoesMatch
pub mod filter {
    pub use super::types::FilterCondition::*;
}