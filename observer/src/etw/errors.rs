use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum EtwError {
    // Changed from windows::core::Error to a raw u32 code
    #[error("Windows API Error Code: {0}")]
    WindowsError(u32), 
    
    #[error("Failed to parse TDH property")]
    TdhParseError,
    
    #[error("Session already exists")]
    SessionAlreadyExists,

    #[error("{0} property not found")]
    PropertyNotFound(String),
    
    #[error("Unknown error occurred")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, EtwError>;