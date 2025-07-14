use thiserror::{Error};

/// Error type for the minigrep command.
/// 
/// This error type is used to represent errors that can occur during the execution of the minigrep command.
/// Use thiserror to derive error types and implement error trait, with structured error information and context.
#[derive(Error, Debug)]
pub enum GrepError {
    
    /// Invalid path
    #[error("Invalid path: {path}")]
    InvalidPath{
        /// File path is invalid
        path: String,
    },
    
    /// File not found
    #[error("File not found: {path}")]
    FileNotFound{
        /// File path is invalid
        path: String,
    },
    
    /// File read error
    #[error("File read error: {path}")]
    FileReadError{
        /// File path is invalid
        path: String,
    },
    
    /// Permission denied
    #[error("Permission denied: {path}")]
    PermissionDenied{
        /// File path is invalid
        path: String,
    },
    
    /// Io error
    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// Regex error
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}
