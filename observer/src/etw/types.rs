use std::ffi::c_void;
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::EVENT_RECORD;

// Represents the types of filtering logic supported
#[derive(Clone)]
#[allow(dead_code)]
pub enum FilterCondition {
    DoesMatch(u16),
    DoesNotMatch(u16),
}

// Callback signature definition
pub type EventCallback = fn(event: &Event);

/// Wrapper around the raw EVENT_RECORD pointer passed by Windows.
/// This struct is only valid during the lifetime of the callback.
/// Safe wrapper around the raw EVENT_RECORD pointer.
#[allow(dead_code)]
pub struct Event<'a> {
    // We hold a pointer to the raw record provided by the Windows callback
    raw_record: *const EVENT_RECORD,
    // Marker to tie this struct to the callback's lifetime
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> Event<'a> {
    /// Creates a new Event wrapper.
    /// Safety: `record` must be a valid pointer to an EVENT_RECORD.
    pub unsafe fn new(record: *const c_void) -> Self {
        Self {
            raw_record: record as *const EVENT_RECORD,
            _marker: std::marker::PhantomData,
        }
    }

    /// Accessor for the Process ID (PID)
    pub fn pid(&self) -> u32 {
        unsafe { (*self.raw_record).EventHeader.ProcessId }
    }

    /// Accessor for the Thread ID (TID)
    #[allow(dead_code)]
    pub fn tid(&self) -> u32 {
        unsafe { (*self.raw_record).EventHeader.ThreadId }
    }

    /// Accessor for the Event ID
    pub fn id(&self) -> u16 {
        unsafe { (*self.raw_record).EventHeader.EventDescriptor.Id }
    }

    pub fn provider_guid(&self) -> GUID {
        unsafe { (*self.raw_record).EventHeader.ProviderId }
    }

    /// Returns the raw pointer to the record if needed for advanced parsing (TDH)
    pub fn as_raw(&self) -> *const c_void {
        self.raw_record as *const c_void
    }
}

