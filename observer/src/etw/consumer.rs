#![allow(dead_code, unused_unsafe, unsafe_op_in_unsafe_fn, unused_variables)]
use crate::etw::kernel::KernelTrace;
use crate::etw::types::{Event, FilterCondition};
use crate::etw::user::UserTrace;
use std::ffi::c_void;
use std::mem::zeroed;
use std::ptr::null;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::core::GUID;

// Constants for ProcessTraceMode
// PROCESS_TRACE_MODE_EVENT_RECORD (0x10000000) | PROCESS_TRACE_MODE_REAL_TIME (0x00000100)
const REAL_TIME_EVENT_RECORD_MODE: u32 = 0x10000100;
const INVALID_PROCESSTRACE_HANDLE_VAL: u64 = 0xFFFFFFFFFFFFFFFF;

fn is_same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// The global static callback for **user-mode** trace sessions.
///
/// # Safety
/// This function is called by the OS. It receives a raw pointer to an EVENT_RECORD.
/// It relies on the `UserContext` field of the record being a valid pointer to our
/// `UserTrace` struct.
unsafe extern "system" fn user_etw_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        log::error!("EventRecord is null!");
        return;
    }

    let context_ptr = unsafe { (*record).UserContext };
    if context_ptr.is_null() {
        log::error!("EventRecord.UserContext is null!");
        return;
    }

    let user_trace = unsafe { &*(context_ptr as *const UserTrace) };
    let event = unsafe { Event::new(record as *const c_void) };
    let event_guid = event.provider_guid();

    // Check provider GUID match
    if let Some(provider_guid) = user_trace.provider_guid_value() {
        if !is_same_guid(&provider_guid, &event_guid) {
            return;
        }
    }

    // Dispatch through filters
    for filter in user_trace.filters() {
        let should_fire = match filter.condition {
            FilterCondition::DoesMatch(id) => event.id() == id,
            FilterCondition::DoesNotMatch(id) => event.id() != id,
        };

        if should_fire {
            // Fire filter-level callbacks
            for callback in &filter.callbacks {
                (callback)(&event);
            }
            // Fire global callbacks
            for callback in user_trace.global_callbacks() {
                (callback)(&event);
            }
        }
    }
}

/// The global static callback for **kernel** trace sessions.
///
/// # Safety
/// Same contract as `user_etw_callback`, but the `UserContext` points to a
/// `KernelTrace` struct.
unsafe extern "system" fn kernel_etw_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        log::error!("EventRecord is null!");
        return;
    }

    let context_ptr = unsafe { (*record).UserContext };
    if context_ptr.is_null() {
        log::error!("EventRecord.UserContext is null!");
        return;
    }

    let kernel_trace = unsafe { &*(context_ptr as *const KernelTrace) };
    let event = unsafe { Event::new(record as *const c_void) };

    // Kernel sessions deliver all enabled event classes; fire every callback.
    for callback in kernel_trace.global_callbacks() {
        (callback)(&event);
    }
}

// ─── Shared open-and-process helper ───

/// Opens a named real-time trace session, processes events using the
/// provided callback, and blocks until the session is stopped.
fn open_and_process(
    session_name: &str,
    context_ptr: *mut c_void,
    callback: unsafe extern "system" fn(*mut EVENT_RECORD),
) -> u32 {
    let mut session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut log_file: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
    log_file.LoggerName = session_name_wide.as_mut_ptr();
    unsafe { log_file.Anonymous1.ProcessTraceMode = REAL_TIME_EVENT_RECORD_MODE };
    unsafe { log_file.Anonymous2.EventRecordCallback = Some(callback) };
    log_file.Context = context_ptr;

    let trace_handle = unsafe { OpenTraceW(&mut log_file) };

    if trace_handle.Value == INVALID_PROCESSTRACE_HANDLE_VAL {
        return unsafe { windows_sys::Win32::Foundation::GetLastError() };
    }

    log::debug!("Starting ProcessTrace");
    let result = unsafe { ProcessTrace(&trace_handle, 1, null(), null()) };

    if result != ERROR_SUCCESS {
        log::error!("ProcessTrace failed with error {}", result);
        return unsafe { windows_sys::Win32::Foundation::GetLastError() };
    } else {
        log::debug!("Closing trace session");
        unsafe { CloseTrace(trace_handle) };
    }

    result
}

/// Starts the blocking consumption loop for a **user-mode** trace session.
pub fn start_user_consumption(trace: &UserTrace) -> u32 {
    unsafe {
        open_and_process(
            &trace.get_session_name(),
            trace as *const UserTrace as *mut c_void,
            user_etw_callback,
        )
    }
}

/// Starts the blocking consumption loop for a **kernel** trace session.
pub fn start_kernel_consumption(trace: &KernelTrace) -> u32 {
    unsafe {
        open_and_process(
            &trace.get_session_name(),
            trace as *const KernelTrace as *mut c_void,
            kernel_etw_callback,
        )
    }
}
