use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    SymCleanup, SymFromAddrW, SymInitialize, SymSetOptions, SYMBOL_INFOW, SYMOPT_DEFERRED_LOADS,
    SYMOPT_UNDNAME,
};

/// Initializes the symbol handler for a specific target process.
/// The caller is responsible for ensuring thread safety, as DbgHelp is single-threaded.
pub fn init_remote_symbols(process_handle: HANDLE) -> Result<(), String> {
    unsafe {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        if SymInitialize(process_handle, std::ptr::null(), 1) == 0 {
            return Err("SymInitialize failed for remote process.".to_string());
        }
    }
    Ok(())
}

/// Resolves a virtual address to a symbol name within the context of a specific process.
pub fn resolve_remote_symbol(process_handle: HANDLE, address: u64) -> String {
    unsafe {
        // Allocate buffer appropriately for SYMBOL_INFOW + string length
        let mut buffer = [0u8; std::mem::size_of::<SYMBOL_INFOW>() + (256 * 2)];
        let p_symbol = buffer.as_mut_ptr() as *mut SYMBOL_INFOW;
        (*p_symbol).SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
        (*p_symbol).MaxNameLen = 256;

        let mut displacement = 0u64;
        
        if SymFromAddrW(process_handle, address, &mut displacement, p_symbol) != 0 {
            let name_ptr = (*p_symbol).Name.as_ptr() as *const u16;
            let mut name_len = 0;
            while *name_ptr.add(name_len) != 0 {
                name_len += 1;
            }
            
            let name_slice = std::slice::from_raw_parts(name_ptr, name_len);
            String::from_utf16_lossy(name_slice)
        } else {
            format!("{:#X}", address)
        }
    }
}

/// Cleans up the symbol handler allocations for the target process.
pub fn cleanup_remote_symbols(process_handle: HANDLE) {
    unsafe {
        SymCleanup(process_handle);
    }
}