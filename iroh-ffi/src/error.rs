pub type Result<T> = std::result::Result<T, IrohError>;

/// An Error.
#[derive(Debug, thiserror::Error)]
pub enum IrohError {
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("node creation failed: {0}")]
    NodeCreate(String),
}
