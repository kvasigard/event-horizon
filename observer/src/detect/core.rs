use std::sync::Arc;

/// Standardized context extracted from the ETW Event for syscall detection.
/// Utilizes Arc for zero-copy broadcasting across multiple detector threads.
#[derive(Clone)]
pub struct SyscallEventContext {
    pub process_id: u32,
    pub user_frames: Arc<[u64]>,
}

/// Defines the contract for heuristic analysis plugins.
pub trait Detector: Send + Sync {
    /// Identifies the module in telemetry logs.
    fn name(&self) -> &'static str;

    /// Provisions necessary resources, channels, or background workers prior to event consumption.
    fn initialize(&mut self) -> Result<(), String> {
        Ok(()) 
    }

    /// Evaluates a normalized event against the implemented heuristic.
    fn analyze(&self, context: &SyscallEventContext);
}