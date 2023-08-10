use std::fmt::Display;

pub type Result<T> = std::result::Result<T, IrohError>;

/// An Error.
#[derive(Debug, thiserror::Error)]
pub enum IrohError {
    #[error("runtime error: {description}")]
    Runtime { description: String },
    #[error("node creation failed: {description}")]
    NodeCreate { description: String },
    #[error("doc error: {description}")]
    Doc { description: String },
    #[error("author error: {description}")]
    Author { description: String },
    #[error("doc ticket error: {description}")]
    DocTicket { description: String },
    #[error("uniffi: {description}")]
    Uniffi { description: String },
}

impl IrohError {
    pub fn runtime(error: impl Display) -> Self {
        IrohError::Runtime {
            description: error.to_string(),
        }
    }

    pub fn node_create(error: impl Display) -> Self {
        IrohError::NodeCreate {
            description: error.to_string(),
        }
    }

    pub fn author(error: impl Display) -> Self {
        IrohError::Author {
            description: error.to_string(),
        }
    }

    pub fn doc(error: impl Display) -> Self {
        IrohError::Doc {
            description: error.to_string(),
        }
    }

    pub fn doc_ticket(error: impl Display) -> Self {
        IrohError::DocTicket {
            description: error.to_string(),
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for IrohError {
    fn from(value: uniffi::UnexpectedUniFFICallbackError) -> Self {
        IrohError::Uniffi {
            description: value.to_string(),
        }
    }
}
