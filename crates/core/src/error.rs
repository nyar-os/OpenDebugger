use std::{
    fmt::{self, Display, Formatter},
    io,
};

use serde::Serialize;

pub type Result<T> = std::result::Result<T, Error>;

/// Capability-level failure codes. The vocabulary is fixed across every Open app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    UnsupportedPlatform,
    NotImplemented,
    DependencyBlocked,
}

impl CapabilityState {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NotImplemented => "not_implemented",
            Self::DependencyBlocked => "dependency_blocked",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "the capability is not available on this platform",
            Self::NotImplemented => "the capability is not implemented yet",
            Self::DependencyBlocked => "the capability is blocked by a missing dependency",
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Message(String),
    Io { path: String, source: io::Error },
}

impl Error {
    pub fn message(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }

    pub fn io(path: impl Into<String>, source: io::Error) -> Self {
        Self::Io { path: path.into(), source }
    }

    pub fn capability(state: CapabilityState, context: impl Display) -> Self {
        Self::Message(format!("{}: {context}", state.code()))
    }

    /// Returns the capability code carried by this error, if any.
    pub fn capability_code(&self) -> Option<&'static str> {
        let text = match self {
            Self::Message(text) => text.as_str(),
            Self::Io { .. } => return None,
        };
        [CapabilityState::UnsupportedPlatform, CapabilityState::NotImplemented, CapabilityState::DependencyBlocked]
            .into_iter()
            .find(|state| text.starts_with(state.code()))
            .map(CapabilityState::code)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(text) => f.write_str(text),
            Self::Io { path, source } => write!(f, "{path}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Message(_) => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}
