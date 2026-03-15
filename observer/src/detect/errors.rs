use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum DetectionError {
    // Changed from windows::core::Error to a raw u32 code
    #[error("Windows API Error Code: {0}")]
    WindowsError(u32),

    #[error("Unable to perform Direct Syscalls detection: {0}")]
    DirectSyscalls(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DetectionError>;
