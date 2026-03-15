use crate::detect::errors::{DetectionError, Result};
use log;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, MAX_PATH};
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQueryEx};
use windows_sys::Win32::System::ProcessStatus::K32GetModuleBaseNameW;

/// Filters a collection of memory addresses to remove those belonging to the kernel space.
pub fn filter_kernel_addresses(addresses: &mut Vec<u64>) {
    // The canonical boundary for the start of kernel space on x64 Windows.
    // Addresses equal to or greater than this constant are considered kernel-mode.
    const KERNEL_RANGE_START: u64 = 0xFFFF_8000_0000_0000;

    // We use retain to modify the vector in-place, which is more efficient than
    // allocating a new vector and copying elements.
    addresses.retain(|&addr| {
        let is_user_space = addr < KERNEL_RANGE_START;

        if !is_user_space {
            log::trace!("Filtering out kernel-space address: {:#X}", addr);
        }

        is_user_space
    });
}

/// Resolves a memory address within a target process to its module name.
///
/// Requires the process handle to have PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access.
pub fn get_module_name_from_address(process_handle: HANDLE, address: u64) -> Result<String> {
    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();

        // VirtualQueryEx requires PROCESS_QUERY_INFORMATION
        let result = VirtualQueryEx(
            process_handle,
            address as *const std::ffi::c_void,
            &mut mbi,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        if result == 0 {
            let err = GetLastError();
            log::debug!(
                "VirtualQueryEx failed for address {:#X}. Error: {}",
                address,
                err
            );
            return Err(DetectionError::WindowsError(err));
        }
        // Prepare a buffer for the UTF-16 string
        let mut buffer = [0u16; MAX_PATH as usize];

        // K32GetModuleBaseNameW requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        let length = K32GetModuleBaseNameW(
            process_handle,
            mbi.AllocationBase as _,
            buffer.as_mut_ptr(),
            MAX_PATH,
        );
        
        
        if length == 0 {
            let err = GetLastError();
            log::debug!(
                "K32GetModuleBaseNameW failed for base {:?}. Error: {}",
                mbi.AllocationBase,
                err
            );
            return Err(DetectionError::WindowsError(err));
        }

        // Convert the wide string buffer into a standard Rust String
        let module_name = OsString::from_wide(&buffer[..length as usize])
            .into_string()
            .map_err(|_| {
                DetectionError::Other("Invalid Unicode sequence in module name".to_string())
            })?;

        Ok(module_name)
    }
}
