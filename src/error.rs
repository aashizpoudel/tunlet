//! Error definitions, protocol wire codes, and exit code mappings.

use std::{fmt, io};

/// Protocol wire error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ErrorCode {
    AuthFailed = 1,
    ProtocolError = 2,
    UnsupportedVersion = 3,
    InvalidPort = 4,
    PortUnavailable = 5,
    NoPortAvailable = 6,
    Replaced = 7,
    ServerBusy = 8,
    RequestUnavailable = 9,
    InternalError = 10,
}

impl ErrorCode {
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::AuthFailed,
            2 => Self::ProtocolError,
            3 => Self::UnsupportedVersion,
            4 => Self::InvalidPort,
            5 => Self::PortUnavailable,
            6 => Self::NoPortAvailable,
            7 => Self::Replaced,
            8 => Self::ServerBusy,
            9 => Self::RequestUnavailable,
            10 => Self::InternalError,
            _ => return None,
        })
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Human-readable error description. Does not expose keys or remote input.
    pub fn message(self) -> &'static str {
        match self {
            Self::AuthFailed => "authentication failed",
            Self::ProtocolError => "protocol error",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::InvalidPort => "requested port is invalid",
            Self::PortUnavailable => "requested port is unavailable or already occupied",
            Self::NoPortAvailable => "no automatic port available in the configured range",
            Self::Replaced => "another process owns this tunnel",
            Self::ServerBusy => "server is at capacity",
            Self::RequestUnavailable => "connection request is no longer available",
            Self::InternalError => "server internal error",
        }
    }

    /// True if the error is fatal and the client must terminate immediately.
    pub fn is_fatal_for_client(self) -> bool {
        !matches!(self, Self::ServerBusy)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// A protocol framing or state-machine violation. Carries the wire error code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub detail: &'static str,
}

impl ProtocolError {
    pub const fn new(detail: &'static str) -> Self {
        Self {
            code: ErrorCode::ProtocolError,
            detail,
        }
    }

    pub const fn with_code(code: ErrorCode, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail)
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug)]
pub enum AppError {
    /// Command-line argument error. Exit status 2.
    Cli(String),
    /// Configuration error. Exit status 2.
    Config(String),
    /// Protocol violation error. Exit status 3.
    Protocol(ProtocolError),
    /// Authentication failure. Exit status 3.
    Auth,
    /// Registration rejected by server. Exit status 3.
    Registration(ErrorCode),
    /// General runtime error. Exit status 1.
    Runtime(String),
    Io(io::Error),
}

impl AppError {
    pub fn protocol(detail: &'static str) -> Self {
        Self::Protocol(ProtocolError::new(detail))
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Cli(_) | Self::Config(_) => 2,
            Self::Protocol(_) | Self::Auth | Self::Registration(_) => 3,
            Self::Runtime(_) | Self::Io(_) => 1,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(message) | Self::Config(message) | Self::Runtime(message) => {
                f.write_str(message)
            }
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
            Self::Auth => f.write_str("authentication failed"),
            Self::Registration(code) => write!(f, "registration failed: {code}"),
            Self::Io(error) => write!(f, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProtocolError> for AppError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
