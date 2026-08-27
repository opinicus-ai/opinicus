//! Error type shared by the library crates.

/// Result alias used across the workspace libraries.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that the Agent Firewall libraries return.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The operating system refused an operation or reported a failure.
    #[error("operating system error: {0}")]
    Os(String),

    /// The monitor cannot observe something it needs.
    #[error("monitor error: {0}")]
    Monitor(String),

    /// A policy file is not valid.
    #[error("policy error: {0}")]
    Policy(String),

    /// A recorded trace is not valid.
    #[error("trace error: {0}")]
    Trace(String),

    /// Input or output failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON encoding or decoding failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Any other failure.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Makes an [`Error::Os`] from any message.
    pub fn os(msg: impl Into<String>) -> Self {
        Error::Os(msg.into())
    }

    /// Makes an [`Error::Monitor`] from any message.
    pub fn monitor(msg: impl Into<String>) -> Self {
        Error::Monitor(msg.into())
    }

    /// Makes an [`Error::Policy`] from any message.
    pub fn policy(msg: impl Into<String>) -> Self {
        Error::Policy(msg.into())
    }

    /// Makes an [`Error::Trace`] from any message.
    pub fn trace(msg: impl Into<String>) -> Self {
        Error::Trace(msg.into())
    }

    /// Makes an [`Error::Other`] from any message.
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}
