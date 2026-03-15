use super::{Detector, SyscallEventContext};
use crate::detect::utils;
use crate::etw::Event;
use std::sync::Arc;

pub struct DetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Registers a new detector heuristic into the engine's pipeline.
    pub fn add_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// Provisions resources and spawns background threads for all registered detectors.
    pub fn start(&mut self) -> Result<(), String> {
        log::info!("Starting Detection Engine...");
        for detector in &mut self.detectors {
            log::debug!("Initializing detector: {}", detector.name());
            detector.initialize()?;
        }
        Ok(())
    }

    /// Ingests raw ETW events, normalizes the stack trace, and broadcasts the context
    /// to all active detectors via zero-copy reference counting.
    pub fn process_etw_event(&self, event: &Event) {
        let mut stack = event.stack_trace();

        if stack.is_empty() {
            return;
        }
        
        utils::filter_kernel_addresses(&mut stack);
        if stack.len() < 3 {
            return; 
        }
        // Convert the heap-allocated Vec into a reference-counted slice.
        // This prevents deep copying of the stack trace when fanning out to multiple worker threads.
        let context = SyscallEventContext {
            process_id: event.pid(),
            user_frames: Arc::from(stack), 
        };

        for detector in &self.detectors {
            detector.analyze(&context);
        }
    }
}