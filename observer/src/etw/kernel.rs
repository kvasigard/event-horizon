#![allow(dead_code)]
use crate::etw::consumer;
use crate::etw::errors::{EtwError, Result};
use crate::etw::r#trait::TraceSession;
use crate::etw::types::EventCallback;

use core::ffi::c_void;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, StartTraceW, TraceSetInformation, WNODE_FLAG_TRACED_GUID,
};

/// The GUID that identifies the NT Kernel Logger session.
/// {9E814AAD-3204-11D2-9A82-006008A86939}
const SYSTEM_TRACE_CONTROL_GUID: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x9E814AAD,
    data2: 0x3204,
    data3: 0x11D2,
    data4: [0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39],
};

/// GUID required for stack walking configuration
const PERFINFO_GUID: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0xce1dbfb4,
    data2: 0x137e,
    data3: 0x4da6,
    data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
};

/// NT Kernel Logger session name required by Windows
const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";

#[repr(C)]
struct STACK_TRACING_EVENT_ID {
    event_guid: windows_sys::core::GUID,
    type_id: u8,
    reserved: [u8; 7],
}

/// Represents a kernel-mode ETW session (NT Kernel Logger).
///
/// Unlike `UserTrace`, a kernel session uses `SystemTraceControlGuid` and
/// sets the wanted kernel event classes via `EnableFlags` in
/// `EVENT_TRACE_PROPERTIES` instead of calling `EnableTraceEx2` per-provider.
pub struct KernelTrace {
    session_handle: Mutex<CONTROLTRACE_HANDLE>,
    /// Kernel-level enable flags (EVENT_TRACE_FLAG_*)
    enable_flags: u32,
    /// Stack-walk event IDs to request from the kernel
    stack_walk_events: Vec<u16>,
    /// Global callbacks that fire on every event from this session
    global_callbacks: Vec<Arc<EventCallback>>,
}

// Safety: The session_handle is behind a Mutex, and CONTROLTRACE_HANDLE
// (a plain u64) has no thread affinity.
unsafe impl Send for KernelTrace {}
unsafe impl Sync for KernelTrace {}

impl KernelTrace {
    pub fn new() -> Self {
        Self {
            session_handle: Mutex::new(CONTROLTRACE_HANDLE { Value: 0 }),
            enable_flags: 0,
            stack_walk_events: Vec::new(),
            global_callbacks: Vec::new(),
        }
    }

    /// Builder: set kernel enable flags (e.g. EVENT_TRACE_FLAG_SYSTEMCALL | EVENT_TRACE_FLAG_PROCESS)
    pub fn enable_flags(mut self, flags: u32) -> Self {
        self.enable_flags = flags;
        self
    }

    /// Builder: request a stack walk for a specific kernel event type
    pub fn enable_stack_walk(mut self, event_type: u32) -> Self {
        self.stack_walk_events.push(event_type as u16);
        self
    }

    /// Builder: add a global callback that runs on every event
    pub fn add_callback(mut self, callback: EventCallback) -> Self {
        self.global_callbacks.push(Arc::new(callback));
        self
    }

    pub fn get_session_name(&self) -> String {
        KERNEL_LOGGER_NAME.to_string()
    }

    pub fn global_callbacks(&self) -> &[Arc<EventCallback>] {
        &self.global_callbacks
    }


    fn do_start_session(&self) -> Result<()> {
        let session_name_wide: Vec<u16> = KERNEL_LOGGER_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let struct_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = session_name_wide.len() * size_of::<u16>();
        let total_size = struct_size + name_bytes;

        let num_u64s = (total_size + 7) / 8;
        let mut buffer = vec![0u64; num_u64s];
        let props_ptr = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {
            (*props_ptr).Wnode.BufferSize = total_size as u32;
            (*props_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props_ptr).Wnode.ClientContext = 1;

            // Kernel sessions MUST use SystemTraceControlGuid
            (*props_ptr).Wnode.Guid = SYSTEM_TRACE_CONTROL_GUID;

            (*props_ptr).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props_ptr).BufferSize = 64;
            (*props_ptr).MinimumBuffers = 4;
            (*props_ptr).MaximumBuffers = 40;
            (*props_ptr).FlushTimer = 1;

            // Kernel event classes are selected via EnableFlags on the properties
            (*props_ptr).EnableFlags = self.enable_flags;

            (*props_ptr).LoggerNameOffset = struct_size as u32;
            (*props_ptr).LogFileNameOffset = 0;

            let name_dest = (buffer.as_mut_ptr() as *mut u8).add(struct_size) as *mut u16;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr(),
                name_dest,
                session_name_wide.len(),
            );

            let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
            let mut result = StartTraceW(&mut handle, session_name_wide.as_ptr(), props_ptr);

            if result == ERROR_ALREADY_EXISTS {
                log::warn!("Kernel trace session already exists. Stopping and retrying...");
                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    session_name_wide.as_ptr(),
                    props_ptr,
                    EVENT_TRACE_CONTROL_STOP,
                );

                // Retry starting the session
                result = StartTraceW(&mut handle, session_name_wide.as_ptr(), props_ptr);
            }

            if result == ERROR_SUCCESS {
                *self.session_handle.lock().unwrap() = handle;

                // Apply stack walking configuration if requested
                if !self.stack_walk_events.is_empty() {
                    for &event_type in &self.stack_walk_events {
                        let mut hook_id_info = STACK_TRACING_EVENT_ID {
                            event_guid: PERFINFO_GUID,
                            type_id: event_type as u8,
                            reserved: [0; 7],
                        };

                        // 3 corresponds to TraceStackTracingInfo
                        let status = TraceSetInformation(
                            handle,
                            3,
                            &mut hook_id_info as *mut _ as *mut c_void,
                            std::mem::size_of::<STACK_TRACING_EVENT_ID>() as u32,
                        );

                        if status != ERROR_SUCCESS {
                            log::warn!(
                                "Failed to set stack tracing for event {}: {}",
                                event_type,
                                status
                            );
                        }
                    }
                }

                Ok(())
            } else {
                Err(EtwError::WindowsError(result))
            }
        }
    }
}

impl TraceSession for KernelTrace {
    fn start_session(&self) -> std::result::Result<(), String> {
        self.do_start_session().map_err(|e| e.to_string())
    }

    fn consume(&self) -> u32 {
        let handle = self.session_handle.lock().unwrap();
        if handle.Value == 0 {
            return 1;
        }
        drop(handle);

        log::debug!("Starting kernel event consumer...");
        consumer::start_kernel_consumption(self)
    }

    fn stop_session(&self) {
        let handle = self.session_handle.lock().unwrap();
        log::debug!("Stopping Kernel ETW session...");
        if handle.Value == 0 {
            return;
        }

        let name_buffer_size = 1024 * std::mem::size_of::<u16>();
        let buf_size =
            (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (name_buffer_size * 2)) as u32;

        let mut buffer = vec![0u8; buf_size as usize];
        let props = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        unsafe {
            let p = &mut *props;
            p.Wnode.BufferSize = buf_size;
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;

            p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            p.LogFileNameOffset =
                (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_buffer_size) as u32;

            let status = ControlTraceW(*handle, std::ptr::null(), props, EVENT_TRACE_CONTROL_STOP);

            if status != ERROR_SUCCESS {
                log::error!("Error stopping kernel ETW session: {}", status);
            } else {
                log::debug!("Kernel ETW session stopped successfully.");
            }
        }
    }
}
