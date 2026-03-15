#![allow(dead_code)]
use windows_sys::core::GUID;

pub(crate) fn guid_to_string(guid: &windows_sys::core::GUID) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid.data1, guid.data2, guid.data3,
        guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
        guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7]
    )
}

pub(crate) fn string_to_guid(guid_str: &str) -> GUID {
    // Strip braces if present and remove hyphens
    let clean_guid = guid_str.trim_matches(|c| c == '{' || c == '}').replace("-", "");
    
    // Convert hex string to bytes
    let data = u128::from_str_radix(&clean_guid, 16)
        .expect("Invalid GUID format");

    GUID {
        data1: (data >> 96) as u32,
        data2: (data >> 80) as u16,
        data3: (data >> 64) as u16,
        data4: (data as u64).to_be_bytes(),
    }
}

pub(crate) fn guids_equal(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}