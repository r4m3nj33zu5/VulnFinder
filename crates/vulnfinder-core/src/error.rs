use thiserror::Error;

#[derive(Debug, Error)]
pub enum VulnFinderError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("invalid port value: {0}")]
    InvalidPort(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("scan failed: {0}")]
    Scan(String),
}

pub type Result<T> = std::result::Result<T, VulnFinderError>;
