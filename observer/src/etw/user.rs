#![allow(dead_code, unused_unsafe, unsafe_op_in_unsafe_fn)]
use crate::etw::consumer;
use crate::etw::errors::{EtwError, Result};
use crate::etw::manifest_parser::ManifestParser;
use crate::etw::r#trait::TraceSession;
use crate::etw::types::{EventCallback, FilterCondition};
use std::mem::{size_of, zeroed};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2,
    PROVIDER_ENUMERATION_INFO, StartTraceW, TdhEnumerateProviders, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::core::GUID;

// ─── Provider-level configuration (previously in provider.rs) ───

/// ETW Log Levels (aligned with Windows definitions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogLevel {
    Critical = 1,
    Error = 2,
    Warning = 3,
    Info = 4,
    Verbose = 5,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Verbose
    }
}

/// Represents a specific Event Filter configuration
#[derive(Clone)]
pub struct EventFilter {
    pub condition: FilterCondition,
    pub callbacks: Vec<EventCallback>,
}

impl EventFilter {
    pub fn new(condition: FilterCondition) -> Self {
        Self {
            condition,
            callbacks: Vec::new(),
        }
    }

    pub fn add_callback(&mut self, callback: EventCallback) {
        self.callbacks.push(callback);
    }
}

/// Internal provider configuration embedded in UserTrace
struct ProviderConfig {
    name: String,
    guid: GUID,
    any_keyword: u64,
    all_keyword: u64,
    level: LogLevel,
    trace_flags: Option<u32>,
    filters: Vec<EventFilter>,
    manifest: Option<ManifestParser>,
}

impl ProviderConfig {
    fn new(guid_str: &str) -> Self {
        Self {
            name: guid_to_name(guid_str),
            guid: crate::etw::utils::string_to_guid(guid_str),
            any_keyword: 0,
            all_keyword: 0,
            level: LogLevel::default(),
            trace_flags: None,
            filters: Vec::new(),
            manifest: None,
        }
    }

    /// Attempts to load and parse the ETW Manifest for this provider.
    #[allow(dead_code)]
    fn load_manifest(&mut self) -> Result<()> {
        let parser = ManifestParser::new(self.guid)?;
        self.manifest = Some(parser);
        Ok(())
    }

    /// Internal helper to build the filter descriptors for EnableTraceEx2
    fn build_filter_descriptors(&self) -> (Vec<EVENT_FILTER_DESCRIPTOR>, Vec<Vec<u8>>) {
        let mut descriptors = Vec::new();
        let mut buffers = Vec::new();

        let event_ids: Vec<u16> = self
            .filters
            .iter()
            .filter_map(|f| {
                if let FilterCondition::DoesMatch(id) = f.condition {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        if !event_ids.is_empty() {
            let mut buffer = Vec::new();
            let filter_in: u8 = 1;
            let reserved: u8 = 0;
            let count: u16 = event_ids.len() as u16;

            buffer.extend_from_slice(&filter_in.to_ne_bytes());
            buffer.extend_from_slice(&reserved.to_ne_bytes());
            buffer.extend_from_slice(&count.to_ne_bytes());
            for id in event_ids {
                buffer.extend_from_slice(&id.to_ne_bytes());
            }

            let descriptor = EVENT_FILTER_DESCRIPTOR {
                Ptr: buffer.as_ptr() as u64,
                Size: buffer.len() as u32,
                Type: EVENT_FILTER_TYPE_EVENT_ID,
            };

            descriptors.push(descriptor);
            buffers.push(buffer);
        }

        (descriptors, buffers)
    }
}

// ─── UserTrace ───

/// Represents a user-mode ETW session with an embedded provider configuration.
pub struct UserTrace {
    session_name: String,
    session_handle: Mutex<CONTROLTRACE_HANDLE>,
    provider: Option<ProviderConfig>,
    /// Global callbacks (added via the builder) that fire on every matched event
    global_callbacks: Vec<Arc<EventCallback>>,
}

// Safety: The session_handle is behind a Mutex, and CONTROLTRACE_HANDLE
// (a plain u64) has no thread affinity.
unsafe impl Send for UserTrace {}
unsafe impl Sync for UserTrace {}

impl UserTrace {
    pub fn new(name: &str) -> Self {
        Self {
            session_name: name.to_string(),
            session_handle: Mutex::new(CONTROLTRACE_HANDLE { Value: 0 }),
            provider: None,
            global_callbacks: Vec::new(),
        }
    }

    /// Builder: set the provider GUID from a string
    pub fn provider_guid(mut self, guid_str: &str) -> Self {
        self.provider = Some(ProviderConfig::new(guid_str));
        self
    }

    /// Builder: set trace flags (e.g. stack-trace property)
    pub fn enable_flags(mut self, flags: u32) -> Self {
        if let Some(ref mut p) = self.provider {
            p.trace_flags = Some(flags);
        }
        self
    }

    /// Builder: add an array of EventFilters
    pub fn add_filters<I>(mut self, filters: I) -> Self
    where
        I: IntoIterator<Item = EventFilter>,
    {
        if let Some(ref mut p) = self.provider {
            for f in filters {
                p.filters.push(f);
            }
        }
        self
    }

    /// Builder: add a global callback that runs on every matching event
    pub fn add_callback(mut self, callback: EventCallback) -> Self {
        self.global_callbacks.push(Arc::new(callback));
        self
    }

    // ── Accessors used by consumer.rs ──

    pub fn get_session_name(&self) -> String {
        self.session_name.clone()
    }

    /// Returns the provider GUID (if configured)
    pub fn provider_guid_value(&self) -> Option<GUID> {
        self.provider.as_ref().map(|p| p.guid)
    }

    /// Returns a reference to the filters list
    pub fn filters(&self) -> &[EventFilter] {
        match &self.provider {
            Some(p) => &p.filters,
            None => &[],
        }
    }

    /// Returns references to the global callbacks
    pub fn global_callbacks(&self) -> &[Arc<EventCallback>] {
        &self.global_callbacks
    }

    // ── Internal helpers ──

    fn enable_provider(&self, handle: CONTROLTRACE_HANDLE) -> Result<()> {
        let provider = match &self.provider {
            Some(p) => p,
            None => return Ok(()),
        };

        let mut params: ENABLE_TRACE_PARAMETERS = unsafe { zeroed() };
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

        if let Some(flags) = provider.trace_flags {
            params.EnableProperty = flags;
        }

        let (descriptors, _buffers) = provider.build_filter_descriptors();
        if !descriptors.is_empty() {
            params.EnableFilterDesc = descriptors.as_ptr() as *mut _;
            params.FilterDescCount = descriptors.len() as u32;
        }

        let result = unsafe {
            EnableTraceEx2(
                handle,
                &provider.guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                provider.level as u8,
                provider.any_keyword,
                provider.all_keyword,
                0,
                &params,
            )
        };

        if result != ERROR_SUCCESS {
            return Err(EtwError::WindowsError(result));
        }

        Ok(())
    }

    fn do_start_session(&self) -> Result<()> {
        let session_name_wide: Vec<u16> = self
            .session_name
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

            let session_guid = uuid::Uuid::new_v4();
            let (d1, d2, d3, d4) = session_guid.to_fields_le();
            (*props_ptr).Wnode.Guid = windows_sys::core::GUID {
                data1: d1,
                data2: d2,
                data3: d3,
                data4: *d4,
            };

            (*props_ptr).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props_ptr).BufferSize = 64;
            (*props_ptr).MinimumBuffers = 2;
            (*props_ptr).MaximumBuffers = 20;
            (*props_ptr).FlushTimer = 1;

            (*props_ptr).LoggerNameOffset = struct_size as u32;
            (*props_ptr).LogFileNameOffset = 0;

            let name_dest = (buffer.as_mut_ptr() as *mut u8).add(struct_size) as *mut u16;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr(),
                name_dest,
                session_name_wide.len(),
            );

            let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
            let result = StartTraceW(&mut handle, session_name_wide.as_ptr(), props_ptr);

            match result {
                ERROR_SUCCESS => {
                    *self.session_handle.lock().unwrap() = handle;
                    Ok(())
                }
                ERROR_ALREADY_EXISTS => {
                    log::warn!("ETW session already exists. Stopping and retrying...");
                    ControlTraceW(
                        CONTROLTRACE_HANDLE { Value: 0 },
                        session_name_wide.as_ptr(),
                        props_ptr,
                        EVENT_TRACE_CONTROL_STOP,
                    );

                    let retry_result =
                        StartTraceW(&mut handle, session_name_wide.as_ptr(), props_ptr);
                    if retry_result == ERROR_SUCCESS {
                        *self.session_handle.lock().unwrap() = handle;
                        Ok(())
                    } else {
                        Err(EtwError::SessionAlreadyExists)
                    }
                }
                err => Err(EtwError::WindowsError(err)),
            }
        }
    }
}

impl TraceSession for UserTrace {
    fn start_session(&self) -> std::result::Result<(), String> {
        self.do_start_session().map_err(|e| e.to_string())?;

        let handle = *self.session_handle.lock().unwrap();
        self.enable_provider(handle).map_err(|e| e.to_string())?;

        Ok(())
    }

    fn consume(&self) -> u32 {
        let handle = self.session_handle.lock().unwrap();
        if handle.Value == 0 {
            return 1;
        }
        drop(handle); // release lock before blocking

        log::debug!("Starting event consumer...");
        consumer::start_user_consumption(self)
    }

    fn stop_session(&self) {
        let handle = self.session_handle.lock().unwrap();
        log::debug!("Stopping ETW session...");
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
                log::error!("Error stopping ETW session: {}", status);
            } else {
                log::debug!("ETW session stopped successfully.");
            }
        }
    }
}

// ─── Helper functions  ───

fn guid_to_name(guid_str: &str) -> String {
    let target_guid = crate::etw::utils::string_to_guid(guid_str);
    let mut buffer_size: u32 = 0;

    unsafe {
        let mut status = TdhEnumerateProviders(std::ptr::null_mut(), &mut buffer_size);

        if status != 122 && status != 0 {
            return guid_str.to_string();
        }

        let mut buffer: Vec<u8> = vec![0u8; buffer_size as usize];
        let p_info = buffer.as_mut_ptr() as *mut PROVIDER_ENUMERATION_INFO;

        status = TdhEnumerateProviders(p_info, &mut buffer_size);

        if status == 0 {
            let info = &*p_info;
            let providers = std::slice::from_raw_parts(
                info.TraceProviderInfoArray.as_ptr(),
                info.NumberOfProviders as usize,
            );

            for provider in providers {
                if crate::etw::utils::guids_equal(&provider.ProviderGuid, &target_guid) {
                    let name_ptr = (p_info as *const u8)
                        .offset(provider.ProviderNameOffset as isize)
                        as *const u16;
                    return utf16_ptr_to_string(name_ptr);
                }
            }
        }
    }

    guid_str.to_string()
}

/// Safely converts a null-terminated PWSTR (UTF-16) to a Rust String
unsafe fn utf16_ptr_to_string(ptr: *const u16) -> String {
    unsafe {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *ptr.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        String::from_utf16_lossy(slice)
    }
}
