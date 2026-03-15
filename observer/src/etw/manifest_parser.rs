#![allow(dead_code, unsafe_op_in_unsafe_fn)]
use crate::etw::errors::{EtwError, Result};
use std::collections::HashMap;
use std::fmt;
use std::ptr::{null_mut};
use std::slice;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_PROPERTY_INFO, EVENT_RECORD, PROVIDER_EVENT_INFO, TRACE_EVENT_INFO,
    TdhEnumerateManifestProviderEvents, TdhGetManifestEventInformation,
};
use windows_sys::core::GUID;

// --- Data Structures ---

/// Represents a single parameter (field) within an event.
#[derive(Clone)]
pub struct EventProperty {
    pub name: String,
    pub in_type: String,  // e.g., "UnicodeString", "Int32"
    pub out_type: String, // e.g., "Pid", "Port", "Null"
    pub is_struct: bool,
    pub count: u16, // Array size (1 if scalar)
}

/// Represents the schema of a specific event.
#[derive(Clone)]
pub struct EventSchema {
    pub id: u16,
    pub version: u8,
    pub name: String,        // Resolved friendly name
    pub task_name: String,   // Raw task name
    pub opcode_name: String, // Raw opcode name
    pub level: u8,
    pub opcode: u8,
    pub keyword: u64,
    pub properties: Vec<EventProperty>,
}

/// Parses and stores the manifest for a specific ETW provider.
/// This allows O(1) lookup of event names and property schemas by Event ID.
pub struct ManifestParser {
    provider_guid: GUID,
    // Map: Event ID -> EventSchema
    events: HashMap<u16, EventSchema>,
}

impl ManifestParser {
    /// Connects to a registered provider and parses its entire manifest.
    pub fn new(provider_guid: GUID) -> Result<Self> {
        let mut parser = ManifestParser {
            provider_guid,
            events: HashMap::new(),
        };
        parser.load_events()?;
        Ok(parser)
    }

    /// Returns the Event name given the event ID.
    pub fn get_event_name(&self, event_id: u16) -> Option<String> {
        self.events.get(&event_id).map(|e| e.name.clone())
    }

    /// Returns the event parameters given the event ID.
    pub fn get_event_properties(&self, event_id: u16) -> Option<&[EventProperty]> {
        self.events.get(&event_id).map(|e| e.properties.as_slice())
    }

    /// Returns the full schema object for advanced usage.
    pub fn get_schema(&self, event_id: u16) -> Option<&EventSchema> {
        self.events.get(&event_id)
    }

    /// Returns a list of all parsed Event IDs.
    pub fn list_event_ids(&self) -> Vec<u16> {
        self.events.keys().cloned().collect()
    }
}

// --- Display / Debug Implementations ---

impl fmt::Debug for ManifestParser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ids: Vec<_> = self.events.keys().collect();
        ids.sort(); // Sort IDs for deterministic output

        writeln!(f, "--- Manifest Summary (Total Events: {}) ---", ids.len())?;

        for id in ids {
            if let Some(schema) = self.events.get(id) {
                write!(f, "{:?}", schema)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for EventSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\n[Event ID: {}] Name: {}", self.id, self.name)?;
        if self.properties.is_empty() {
            writeln!(f, "   (No parameters defined)")?;
        } else {
            for prop in &self.properties {
                write!(f, "{:?}", prop)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for EventProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Cleaning up "Default" or "Null" output types for display if they aren't useful
        let out_display = if self.out_type == "Null" || self.out_type == "Default" {
            " - ".to_string()
        } else {
            self.out_type.clone()
        };

        writeln!(
            f,
            "   -> Parameter: {:<35} [Type: {:<15} | Out: {}]",
            self.name, self.in_type, out_display
        )
    }
}

// --- Internal Parsing Logic ---

impl ManifestParser {
    fn load_events(&mut self) -> Result<()> {
        unsafe {
            let mut buffer_size: u32 = 0;
            // 1. Get size for Provider Info
            let res = TdhEnumerateManifestProviderEvents(
                &self.provider_guid,
                null_mut(),
                &mut buffer_size,
            );

            if res != ERROR_INSUFFICIENT_BUFFER {
                if res == ERROR_SUCCESS {
                    return Ok(());
                }
                return Err(EtwError::WindowsError(res));
            }

            let mut buffer = vec![0u8; buffer_size as usize];
            let provider_info = buffer.as_mut_ptr() as *mut PROVIDER_EVENT_INFO;

            // 2. Get Provider Info
            let res = TdhEnumerateManifestProviderEvents(
                &self.provider_guid,
                provider_info,
                &mut buffer_size,
            );
            if res != ERROR_SUCCESS {
                return Err(EtwError::WindowsError(res));
            }

            let info_ref = &*provider_info;
            let descriptor_ptr = (&(*provider_info).EventDescriptorsArray) as *const _
                as *const windows_sys::Win32::System::Diagnostics::Etw::EVENT_DESCRIPTOR;
            let descriptors =
                slice::from_raw_parts(descriptor_ptr, info_ref.NumberOfEvents as usize);

            // 3. Iterate Descriptors and Parse Schemas
            for desc in descriptors {
                let mut record: EVENT_RECORD = std::mem::zeroed();
                record.EventHeader.ProviderId = self.provider_guid;
                record.EventHeader.EventDescriptor = *desc;

                if let Ok(schema) = Self::parse_single_event(&record) {
                    self.events.insert(desc.Id, schema);
                }
            }
        }
        Ok(())
    }

    unsafe fn parse_single_event(event_record: &EVENT_RECORD) -> Result<EventSchema> {
        let mut buffer_size = 0;
        let provider_guid = &event_record.EventHeader.ProviderId;
        let event_descriptor = &event_record.EventHeader.EventDescriptor;

        // 1. Get required buffer size
        let _ = TdhGetManifestEventInformation(
            provider_guid,
            event_descriptor,
            null_mut(),
            &mut buffer_size,
        );

        let mut buffer = vec![0u8; buffer_size as usize];
        let info_ptr = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;

        // 2. Retrieve actual information
        let res = TdhGetManifestEventInformation(
            provider_guid,
            event_descriptor,
            info_ptr,
            &mut buffer_size,
        );

        if res != ERROR_SUCCESS {
            return Err(EtwError::WindowsError(res));
        }

        let info = &*info_ptr;
        let base_ptr = info_ptr as *const u8;

        // --- String Resolution ---
        let raw_event_msg = ptr_to_string(base_ptr, info.EventMessageOffset);
        let task_name = ptr_to_string(base_ptr, info.TaskNameOffset);
        let opcode_name = ptr_to_string(base_ptr, info.OpcodeNameOffset);

        let event_name = if !raw_event_msg.is_empty() {
            raw_event_msg
        } else if !task_name.is_empty() {
            if !opcode_name.is_empty() {
                format!("{}_{}", task_name, opcode_name)
            } else {
                task_name.clone()
            }
        } else {
            format!("Event_{}", event_record.EventHeader.EventDescriptor.Id)
        };

        // --- Property Parsing ---
        let mut properties = Vec::new();
        if info.PropertyCount > 0 {
            let props_ptr =
                (&(*info_ptr).EventPropertyInfoArray) as *const _ as *const EVENT_PROPERTY_INFO;
            let props_slice = slice::from_raw_parts(props_ptr, info.PropertyCount as usize);

            properties = parse_properties_recursive(props_slice, base_ptr, 0, info.PropertyCount);
        }

        Ok(EventSchema {
            id: event_record.EventHeader.EventDescriptor.Id,
            version: event_record.EventHeader.EventDescriptor.Version,
            name: event_name,
            task_name,
            opcode_name,
            level: event_record.EventHeader.EventDescriptor.Level,
            opcode: event_record.EventHeader.EventDescriptor.Opcode,
            keyword: event_record.EventHeader.EventDescriptor.Keyword,
            properties,
        })
    }
}

// --- Helpers ---

unsafe fn parse_properties_recursive(
    all_props: &[EVENT_PROPERTY_INFO],
    base_ptr: *const u8,
    start_index: u32,
    count: u32,
) -> Vec<EventProperty> {
    let mut result = Vec::new();

    for i in 0..count {
        let index = (start_index + i) as usize;
        if index >= all_props.len() {
            break;
        }

        let prop = &all_props[index];
        let name = ptr_to_string(base_ptr, prop.NameOffset);

        let is_struct = (prop.Flags & 1) != 0;

        if is_struct {
            let members_start = prop.Anonymous1.structType.StructStartIndex;
            let members_count = prop.Anonymous1.structType.NumOfStructMembers;

            let sub_props = parse_properties_recursive(
                all_props,
                base_ptr,
                members_start as u32,
                members_count as u32,
            );

            // Flatten struct names: "Header.Size"
            for mut sub in sub_props {
                sub.name = format!("{}.{}", name, sub.name);
                result.push(sub);
            }
        } else {
            let in_type_code = prop.Anonymous1.nonStructType.InType;
            let out_type_code = prop.Anonymous1.nonStructType.OutType;

            result.push(EventProperty {
                name,
                in_type: map_in_type(in_type_code),
                out_type: map_out_type(out_type_code),
                is_struct: false,
                count: 1,
            });
        }
    }
    result
}

unsafe fn ptr_to_string(base: *const u8, offset: u32) -> String {
    if offset == 0 {
        return String::new();
    }
    let ptr = base.add(offset as usize) as *const u16;
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(slice::from_raw_parts(ptr, len))
        .trim()
        .to_string()
}

fn map_in_type(v: u16) -> String {
    let s = match v {
        0 => "Null",
        1 => "UnicodeString",
        2 => "AnsiString",
        3 => "Int8",
        4 => "UInt8",
        5 => "Int16",
        6 => "UInt16",
        7 => "Int32",
        8 => "UInt32",
        9 => "Int64",
        10 => "UInt64",
        11 => "Float",
        12 => "Double",
        13 => "Boolean",
        14 => "Binary",
        15 => "Guid",
        16 => "Pointer",
        17 => "FileTime",
        18 => "SystemTime",
        19 => "SID",
        20 => "HexInt32",
        21 => "HexInt64",
        // Extended types often supported by TDH but not always in basic docs
        22 => "CountedString",
        23 => "CountedAnsiString",
        24 => "ReversedCountedString",
        25 => "ReversedCountedAnsiString",
        26 => "NonNullTerminatedString",
        27 => "NonNullTerminatedAnsiString",
        28 => "UnicodeChar",
        29 => "AnsiChar",
        30 => "SizeT",
        31 => "HexDump",
        32 => "WbemSID",
        _ => "Unknown",
    };
    s.to_string()
}

fn map_out_type(v: u16) -> String {
    let s = match v {
        0 => "Null",           // No specific output type (uses default for input type)
        1 => "String",         // xs:string
        2 => "DateTime",       // xs:dateTime
        3 => "Byte",           // xs:byte
        4 => "UnsignedByte",   // xs:unsignedByte
        5 => "Short",          // xs:short
        6 => "UnsignedShort",  // xs:unsignedShort
        7 => "Int",            // xs:int
        8 => "UnsignedInt",    // xs:unsignedInt
        9 => "Long",           // xs:long
        10 => "UnsignedLong",  // xs:unsignedLong
        11 => "Float",         // xs:float
        12 => "Double",        // xs:double
        13 => "Boolean",       // xs:boolean
        14 => "Guid",          // xs:GUID
        15 => "HexBinary",     // xs:hexBinary
        16 => "HexInt8",       // win:HexInt8
        17 => "HexInt16",      // win:HexInt16
        18 => "HexInt32",      // win:HexInt32
        19 => "HexInt64",      // win:HexInt64
        20 => "PID",           // win:PID
        21 => "TID",           // win:TID
        22 => "Port",          // win:Port (Network Byte Order)
        23 => "IPv4",          // win:IPv4
        24 => "IPv6",          // win:IPv6
        25 => "SocketAddress", // win:SocketAddress
        26 => "CimDateTime",   // win:CIMDateTime
        27 => "EtwTime",       // win:ETWTIME
        28 => "Xml",           // win:Xml
        29 => "ErrorCode",     // win:ErrorCode
        30 => "Win32Error",    // win:Win32Error
        31 => "NtStatus",      // win:NTSTATUS
        32 => "HResult",       // win:HResult
        33 => "DateTimeCultureInsensitive", // win:DateTimeCultureInsensitive
        34 => "Json",          // win:Json
        35 => "Utf8",          // win:Utf8
        36 => "Pkcs7WithTypeInfo", // win:Pkcs7WithTypeInfo
        _ => "Default",
    };
    s.to_string()
}
// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
    // Microsoft-Windows-Kernel-Process
    // This provider is available on almost all Windows installations.
    const KERNEL_PROCESS_GUID: GUID = GUID {
        data1: 0x22FB2CD6,
        data2: 0x0E7B,
        data3: 0x422B,
        data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
    };

    #[test]
    fn test_load_manifest_success() {
        let parser = ManifestParser::new(KERNEL_PROCESS_GUID);

        // Assert creation
        assert!(
            parser.is_ok(),
            "Should successfully load Kernel-Process manifest"
        );
        let parser = parser.unwrap();

        // Assert content
        let ids = parser.list_event_ids();
        assert!(!ids.is_empty(), "Kernel-Process should have events");

        // Process Start (ID 1) is a standard event in this provider
        assert!(
            ids.contains(&1),
            "Should contain Event ID 1 (Process Start)"
        );
    }

    #[test]
    fn test_event_schema_content() {
        let parser = ManifestParser::new(KERNEL_PROCESS_GUID).unwrap();

        // Get Event ID 1 (ProcessStart)
        let schema = parser.get_schema(1).expect("Event ID 1 should exist");

        // Verify Name resolution
        // Note: The exact string might vary by OS version (e.g., "ProcessStart" vs "Start"),
        // but it shouldn't be empty or generic "Event_1" if symbols are present.
        assert!(!schema.name.is_empty());
        assert!(
            !schema.name.starts_with("Event_"),
            "Should have resolved a friendly name"
        );

        // Verify Properties
        // Process Start usually has "ProcessID", "ImageName", etc.
        let has_pid = schema
            .properties
            .iter()
            .any(|p| p.name.contains("ProcessID") || p.name.contains("ProcessId"));
        assert!(has_pid, "Event ID 1 should have a ProcessID field");
    }

    #[test]
    fn test_debug_formatting() {
        let parser = ManifestParser::new(KERNEL_PROCESS_GUID).unwrap();

        // Format the parser using the Debug trait
        let output = format!("{:?}", parser);

        // Check for key structural elements we implemented
        assert!(output.contains("--- Manifest Summary"));
        assert!(output.contains("[Event ID: 1]"));
        assert!(output.contains("-> Parameter:"));
    }

    #[test]
    fn test_invalid_provider() {
        // Random GUID that shouldn't exist {11111111-2222-3333-4444-555555555555}
        let bad_guid = GUID {
            data1: 0x11111111,
            data2: 0x2222,
            data3: 0x3333,
            data4: [0x44; 8],
        };

        let parser = ManifestParser::new(bad_guid);
        // It might return Ok with empty events, or an error, depending on Windows version/TDH behavior.
        // But if it's Ok, it must be empty.
        if let Ok(p) = parser {
            assert!(
                p.list_event_ids().is_empty(),
                "Random provider should have no events"
            );
        }
    }
}
