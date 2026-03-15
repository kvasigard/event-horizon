#![allow(dead_code, unused_imports, unsafe_op_in_unsafe_fn)]

use crate::etw::types::Event;
use crate::etw::errors::{Result, EtwError};
use std::ffi::{c_void, CStr};
use std::ptr::{null, null_mut};
use std::mem::size_of;
use std::slice;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_RECORD, 
    EVENT_HEADER_FLAG_32_BIT_HEADER,
    EVENT_HEADER_FLAG_64_BIT_HEADER,
    EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
    EVENT_HEADER_EXT_TYPE_STACK_TRACE32,
    EVENT_EXTENDED_ITEM_STACK_TRACE64,
    EVENT_EXTENDED_ITEM_STACK_TRACE32,
    TdhGetEventInformation, 
    TdhGetProperty, 
    TdhGetPropertySize,
    TdhFormatProperty,
    TRACE_EVENT_INFO, 
    PROPERTY_DATA_DESCRIPTOR
};

pub struct EventParser;

impl EventParser {
    pub fn parse_stack_trace(event: &Event) -> Vec<u64> {
        let mut call_stack = Vec::new();
        
        unsafe {
            let record = event.as_raw() as *const EVENT_RECORD;
            let count = (*record).ExtendedDataCount;
            
            if count == 0 || (*record).ExtendedData.is_null() {
                return call_stack;
            }

            let items = slice::from_raw_parts(
                (*record).ExtendedData, 
                count as usize
            );

            for item in items {
                if u32::from(item.ExtType) == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 {
                    // ref: https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64#remarks
                    let stack_trace = item.DataPtr as *const EVENT_EXTENDED_ITEM_STACK_TRACE64;
                    let content_size = item.DataSize as usize;
                    if content_size < 8 { continue; }

                    let stack_length = (content_size - 8) / 8; 
                    let addresses_ptr = (*stack_trace).Address.as_ptr();
                    let addresses = slice::from_raw_parts(addresses_ptr, stack_length);
                    
                    call_stack.extend_from_slice(addresses);
                } 
                else if u32::from(item.ExtType) == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 {
                    let stack_trace = item.DataPtr as *const EVENT_EXTENDED_ITEM_STACK_TRACE32;
                    let content_size = item.DataSize as usize;
                    if content_size < 8 { continue; }

                    let stack_length = (content_size - 8) / 4;
                    
                    let addresses_ptr = (*stack_trace).Address.as_ptr();
                    let addresses = slice::from_raw_parts(addresses_ptr, stack_length);
                    
                    for &addr in addresses {
                        call_stack.push(addr as u64);
                    }
                }
            }
        }

        call_stack
    }

    pub fn get_property_string(event: &Event, property_name: &str) -> Result<String> {
        unsafe {
            // Get the Event Information (Schema)
            // Note: This is still heavy. Ideally, you would use your cached ManifestParser
            // instead of calling TdhGetEventInformation every time, but that requires
            // passing the Manifest into the callback.
            let info_buffer = Self::get_event_info(event)?;
            let info = &*(info_buffer.as_ptr() as *const TRACE_EVENT_INFO);

            let mut property_index = None;
            let properties = slice::from_raw_parts(
                info.EventPropertyInfoArray.as_ptr(),
                info.TopLevelPropertyCount as usize
            );

            // Pre-encode the target name to UTF-16 for comparison
            let target_name_utf16: Vec<u16> = property_name.encode_utf16().collect();

            for (i, prop_info) in properties.iter().enumerate() {
                let name_ptr = (info_buffer.as_ptr() as usize + prop_info.NameOffset as usize) as *const u16;

                // fast_compare_utf16 checks if the pointer matches the target slice
                // and ensures the next char is null terminator
                if Self::fast_compare_utf16(name_ptr, &target_name_utf16) {
                    property_index = Some(i as u32);
                    break;
                }
            }

            let index = property_index.ok_or(EtwError::PropertyNotFound(property_name.parse().unwrap()))?;
            Self::format_property_data(event, info, index)
        }
    }

    // Helper to compare raw pointer w/ slice without allocation
    unsafe fn fast_compare_utf16(ptr: *const u16, target: &[u16]) -> bool {
        let mut i = 0;
        // Compare valid characters
        while i < target.len() {
            if *ptr.add(i) != target[i] {
                return false;
            }
            i += 1;
        }
        // Ensure the string in memory ends here (Null Terminator)
        *ptr.add(i) == 0
    }

    fn get_event_info(event: &Event) -> Result<Vec<u8>> {
        unsafe {
            let record = event.as_raw() as *const EVENT_RECORD;
            let mut buffer_size: u32 = 0;

            let status = TdhGetEventInformation(
                record, 
                0, 
                null(), 
                null_mut(), 
                &mut buffer_size
            );

            if status != ERROR_INSUFFICIENT_BUFFER {
                 return Err(EtwError::WindowsError(status));
            }

            let mut buffer = vec![0u8; buffer_size as usize];
            let info_ptr = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;

            let status = TdhGetEventInformation(
                record, 
                0, 
                null(), 
                info_ptr, 
                &mut buffer_size
            );

            if status != ERROR_SUCCESS {
                return Err(EtwError::WindowsError(status));
            }

            Ok(buffer)
        }
    }

    /// Uses TdhFormatProperty to convert raw bytes into a human-readable string
    /// based on the metadata defined in the event schema.
    unsafe fn format_property_data(
        event: &Event,
        info: &TRACE_EVENT_INFO,
        index: u32
    ) -> Result<String> {
        unsafe {
            let record = event.as_raw() as *const EVENT_RECORD;
            let property_info = *info.EventPropertyInfoArray.as_ptr().add(index as usize);

            let pointer_size = if ((*record).EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16) != 0 {
                4
            } else if ((*record).EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER as u16) != 0 {
                8
            } else {
                size_of::<usize>() as u32
            };

            let mut desc = PROPERTY_DATA_DESCRIPTOR {
                PropertyName: (info as *const _ as usize + property_info.NameOffset as usize) as u64,
                ArrayIndex: u32::MAX,
                Reserved: 0,
            };

            let mut raw_data_size: u32 = 0;
            TdhGetPropertySize(record, 0, null(), 1, &mut desc, &mut raw_data_size);

            let mut raw_data = vec![0u8; raw_data_size as usize];
            TdhGetProperty(record, 0, null(), 1, &mut desc, raw_data_size, raw_data.as_mut_ptr());

            let mut formatted_buffer_size: u32 = 0;
            let mut userdata_consumed: u16 = 0;

            let status = TdhFormatProperty(
                info,
                null(),
                pointer_size,
                property_info.Anonymous1.nonStructType.InType,
                property_info.Anonymous1.nonStructType.OutType,
                raw_data_size as u16,
                raw_data_size as u16,
                raw_data.as_ptr(),
                &mut formatted_buffer_size,
                null_mut(),
                &mut userdata_consumed,
            );

            if status != ERROR_SUCCESS && status != ERROR_INSUFFICIENT_BUFFER {
                return Err(EtwError::WindowsError(status));
            }

            if formatted_buffer_size == 0 {
                return Ok(String::new());
            }

            let mut formatted_buffer = vec![0u16; (formatted_buffer_size / 2) as usize];
            let status = TdhFormatProperty(
                info,
                null(),
                pointer_size,
                property_info.Anonymous1.nonStructType.InType,
                property_info.Anonymous1.nonStructType.OutType,
                raw_data_size as u16,
                raw_data_size as u16,
                raw_data.as_ptr(),
                &mut formatted_buffer_size,
                formatted_buffer.as_mut_ptr(),
                &mut userdata_consumed,
            );

            if status != ERROR_SUCCESS {
                return Err(EtwError::WindowsError(status));
            }

            let len = formatted_buffer.iter().position(|&x| x == 0).unwrap_or(formatted_buffer.len());
            Ok(String::from_utf16_lossy(&formatted_buffer[..len]))
        }
    }
}

impl<'a> Event<'a> {
    pub fn stack_trace(&self) -> Vec<u64> {
        EventParser::parse_stack_trace(self)
    }
    
    // Note: get_property_string function performs a heap allocation to transform the name to UTF-16. 
    //       Use the function inside ETW loop might cause heap fragmentation, so we might want to refactor
    //       this function to avoid heap allocation by requesting UTF-16 strings instead of &str
    pub fn get_property(&self, name: &str) -> Result<String> {
        EventParser::get_property_string(self, name)
    }
}