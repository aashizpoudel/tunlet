//! Wire protocol version 1 framing and message serialization.
//!
//! Integers use big-endian byte order.
//! The parser validates declared lengths before allocating memory.
//! Payloads cannot exceed [`MAX_PAYLOAD`].

use crate::error::{ErrorCode, ProtocolError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAGIC: [u8; 4] = *b"TTUN";
pub const VERSION: u8 = 1;
pub const MAX_PAYLOAD: usize = 1024;
pub const PREAMBLE_LEN: usize = 8;
pub const HEADER_LEN: usize = 3;

pub type InstanceId = [u8; 16];
pub type SessionId = [u8; 16];
pub type RequestId = [u8; 16];
pub type Nonce = [u8; 32];
pub type Mac = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Control = 1,
    Data = 2,
}

impl Kind {
    pub fn from_u8(value: u8) -> std::result::Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::Data),
            _ => Err(ProtocolError::new("invalid connection kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Type {
    ControlHello = 0x01,
    ControlChallenge = 0x02,
    ControlProof = 0x03,
    Registered = 0x04,
    Open = 0x05,
    OpenFailed = 0x06,
    Ping = 0x07,
    Pong = 0x08,
    Goodbye = 0x09,
    GoodbyeAck = 0x0a,
    ServerShutdown = 0x0b,
    DataHello = 0x20,
    DataChallenge = 0x21,
    DataProof = 0x22,
    DataReady = 0x23,
    Error = 0x7f,
}

impl Type {
    pub fn from_u8(value: u8) -> std::result::Result<Self, ProtocolError> {
        Ok(match value {
            0x01 => Self::ControlHello,
            0x02 => Self::ControlChallenge,
            0x03 => Self::ControlProof,
            0x04 => Self::Registered,
            0x05 => Self::Open,
            0x06 => Self::OpenFailed,
            0x07 => Self::Ping,
            0x08 => Self::Pong,
            0x09 => Self::Goodbye,
            0x0a => Self::GoodbyeAck,
            0x0b => Self::ServerShutdown,
            0x20 => Self::DataHello,
            0x21 => Self::DataChallenge,
            0x22 => Self::DataProof,
            0x23 => Self::DataReady,
            0x7f => Self::Error,
            _ => return Err(ProtocolError::new("unknown message type")),
        })
    }

    /// Required payload length for fixed-size message types.
    pub fn payload_len(self) -> usize {
        match self {
            Self::ControlHello => 51,
            Self::ControlChallenge => 80,
            Self::ControlProof => 32,
            Self::Registered => 38,
            Self::Open => 16,
            Self::OpenFailed => 17,
            Self::Ping | Self::Pong => 8,
            Self::Goodbye | Self::GoodbyeAck | Self::ServerShutdown | Self::DataReady => 0,
            Self::DataHello => 64,
            Self::DataChallenge => 64,
            Self::DataProof => 32,
            Self::Error => 2,
        }
    }

    /// Messages permitted on a control connection. `ERROR` is permitted on both kinds.
    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::ControlHello
                | Self::ControlChallenge
                | Self::ControlProof
                | Self::Registered
                | Self::Open
                | Self::OpenFailed
                | Self::Ping
                | Self::Pong
                | Self::Goodbye
                | Self::GoodbyeAck
                | Self::ServerShutdown
                | Self::Error
        )
    }

    /// Messages permitted on a data connection. `ERROR` is permitted on both kinds.
    pub fn is_data(self) -> bool {
        matches!(
            self,
            Self::DataHello | Self::DataChallenge | Self::DataProof | Self::DataReady | Self::Error
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode {
    Fresh = 0,
    Resume = 1,
}

impl Mode {
    pub fn from_u8(value: u8) -> std::result::Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Fresh),
            1 => Ok(Self::Resume),
            _ => Err(ProtocolError::new("invalid registration mode")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OpenFailure {
    TargetConnect = 1,
    SetupTimeout = 2,
    DataAuth = 3,
    LocalCapacity = 4,
}

impl OpenFailure {
    pub fn from_u8(value: u8) -> std::result::Result<Self, ProtocolError> {
        Ok(match value {
            1 => Self::TargetConnect,
            2 => Self::SetupTimeout,
            3 => Self::DataAuth,
            4 => Self::LocalCapacity,
            _ => return Err(ProtocolError::new("invalid OPEN_FAILED reason")),
        })
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::TargetConnect => "client could not connect to its local target",
            Self::SetupTimeout => "client setup timed out",
            Self::DataAuth => "client data connection or authentication failed",
            Self::LocalCapacity => "client is at capacity or shutting down",
        }
    }
}

pub fn encode_preamble(kind: Kind) -> [u8; PREAMBLE_LEN] {
    [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, kind as u8, 0, 0,
    ]
}

/// Validate magic, version, reserved bits, and connection kind.
pub fn decode_preamble(bytes: &[u8; PREAMBLE_LEN]) -> std::result::Result<Kind, ProtocolError> {
    if bytes[..4] != MAGIC {
        return Err(ProtocolError::new("bad magic"));
    }
    if bytes[4] != VERSION {
        return Err(ProtocolError::with_code(
            ErrorCode::UnsupportedVersion,
            "unsupported protocol version",
        ));
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(ProtocolError::new("reserved bits must be zero"));
    }
    Kind::from_u8(bytes[5])
}

/// A decoded frame. The payload length matches the message type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub ty: Type,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(ty: Type, payload: Vec<u8>) -> Self {
        Self { ty, payload }
    }

    pub fn empty(ty: Type) -> Self {
        Self {
            ty,
            payload: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(self.ty as u8);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Reject a frame that is not permitted on this connection kind.
    pub fn require_kind(&self, kind: Kind) -> std::result::Result<(), ProtocolError> {
        let ok = match kind {
            Kind::Control => self.ty.is_control(),
            Kind::Data => self.ty.is_data(),
        };
        if ok {
            Ok(())
        } else {
            Err(ProtocolError::new(
                "message type illegal on this connection",
            ))
        }
    }

    /// Reject a frame that is not expected in the current protocol state.
    pub fn require_type(&self, expected: Type) -> std::result::Result<(), ProtocolError> {
        if self.ty == expected {
            Ok(())
        } else if self.ty == Type::Error {
            Err(ProtocolError::new("peer reported an error"))
        } else {
            Err(ProtocolError::new("unexpected message for this state"))
        }
    }
}

pub async fn write_preamble<W: AsyncWrite + Unpin>(writer: &mut W, kind: Kind) -> Result<()> {
    writer.write_all(&encode_preamble(kind)).await?;
    Ok(())
}

pub async fn read_preamble<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Kind> {
    let mut bytes = [0u8; PREAMBLE_LEN];
    reader.read_exact(&mut bytes).await?;
    Ok(decode_preamble(&bytes)?)
}

/// Read one frame from the reader.
/// Uses exact-length reads to prevent partial frame processing.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let declared = u16::from_be_bytes([header[1], header[2]]) as usize;
    if declared > MAX_PAYLOAD {
        return Err(crate::error::AppError::protocol("payload length too large"));
    }
    // Validate the message type and fixed length before allocating memory.
    let ty = Type::from_u8(header[0])?;
    if declared != ty.payload_len() {
        return Err(crate::error::AppError::protocol(
            "payload length does not match message type",
        ));
    }
    let mut payload = vec![0u8; declared];
    reader.read_exact(&mut payload).await?;
    Ok(Frame { ty, payload })
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(crate::error::AppError::protocol("payload too large"));
    }
    writer.write_all(&frame.encode()).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ty: Type,
    payload: Vec<u8>,
) -> Result<()> {
    write_frame(writer, &Frame::new(ty, payload)).await
}

pub async fn write_error<W: AsyncWrite + Unpin>(writer: &mut W, code: ErrorCode) -> Result<()> {
    write_message(writer, Type::Error, code.as_u16().to_be_bytes().to_vec()).await
}

fn take<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlHello {
    pub instance_id: InstanceId,
    pub client_nonce: Nonce,
    pub mode: Mode,
    pub requested_port: u16,
}

impl ControlHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(51);
        out.extend_from_slice(&self.instance_id);
        out.extend_from_slice(&self.client_nonce);
        out.push(self.mode as u8);
        out.extend_from_slice(&self.requested_port.to_be_bytes());
        out
    }

    pub fn decode(payload: &[u8]) -> std::result::Result<Self, ProtocolError> {
        if payload.len() != 51 {
            return Err(ProtocolError::new("CONTROL_HELLO length"));
        }
        let mode = Mode::from_u8(payload[48])?;
        let requested_port = u16::from_be_bytes([payload[49], payload[50]]);
        // Port 0 specifies automatic allocation for fresh registration only.
        // A resumed session must specify the previous port number.
        match (mode, requested_port) {
            (Mode::Resume, 0) => {
                return Err(ProtocolError::with_code(
                    ErrorCode::InvalidPort,
                    "resume must request a specific port",
                ));
            }
            (_, port) if port != 0 && port < 1024 => {
                return Err(ProtocolError::with_code(
                    ErrorCode::InvalidPort,
                    "requested port must be 1024-65535",
                ));
            }
            _ => {}
        }
        Ok(Self {
            instance_id: take(payload, 0),
            client_nonce: take(payload, 16),
            mode,
            requested_port,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlChallenge {
    pub server_nonce: Nonce,
    pub session_id: SessionId,
    pub server_mac: Mac,
}

impl ControlChallenge {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.server_mac);
        out
    }

    pub fn decode(payload: &[u8]) -> std::result::Result<Self, ProtocolError> {
        if payload.len() != 80 {
            return Err(ProtocolError::new("CONTROL_CHALLENGE length"));
        }
        Ok(Self {
            server_nonce: take(payload, 0),
            session_id: take(payload, 32),
            server_mac: take(payload, 48),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registered {
    pub assigned_port: u16,
    pub max_connections: u32,
    pub ready_mac: Mac,
}

impl Registered {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(38);
        out.extend_from_slice(&self.assigned_port.to_be_bytes());
        out.extend_from_slice(&self.max_connections.to_be_bytes());
        out.extend_from_slice(&self.ready_mac);
        out
    }

    pub fn decode(payload: &[u8]) -> std::result::Result<Self, ProtocolError> {
        if payload.len() != 38 {
            return Err(ProtocolError::new("REGISTERED length"));
        }
        let assigned_port = u16::from_be_bytes([payload[0], payload[1]]);
        if assigned_port < 1024 {
            return Err(ProtocolError::with_code(
                ErrorCode::InvalidPort,
                "assigned port must be 1024-65535",
            ));
        }
        let max_connections = u32::from_be_bytes(take(payload, 2));
        if max_connections == 0 {
            return Err(ProtocolError::new("advertised maximum must be nonzero"));
        }
        Ok(Self {
            assigned_port,
            max_connections,
            ready_mac: take(payload, 6),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenFailed {
    pub request_id: RequestId,
    pub reason: OpenFailure,
}

impl OpenFailed {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.extend_from_slice(&self.request_id);
        out.push(self.reason as u8);
        out
    }

    pub fn decode(payload: &[u8]) -> std::result::Result<Self, ProtocolError> {
        if payload.len() != 17 {
            return Err(ProtocolError::new("OPEN_FAILED length"));
        }
        Ok(Self {
            request_id: take(payload, 0),
            reason: OpenFailure::from_u8(payload[16])?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataHello {
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub client_nonce: Nonce,
}

impl DataHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.client_nonce);
        out
    }

    pub fn decode(payload: &[u8]) -> std::result::Result<Self, ProtocolError> {
        if payload.len() != 64 {
            return Err(ProtocolError::new("DATA_HELLO length"));
        }
        Ok(Self {
            session_id: take(payload, 0),
            request_id: take(payload, 16),
            client_nonce: take(payload, 32),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataChallenge {
    pub server_nonce: Nonce,
    pub server_mac: Mac,
}

impl DataChallenge {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.server_nonce);
        out.extend_from_slice(&self.server_mac);
        out
    }

    pub fn decode(payload: &[u8]) -> std::result::Result<Self, ProtocolError> {
        if payload.len() != 64 {
            return Err(ProtocolError::new("DATA_CHALLENGE length"));
        }
        Ok(Self {
            server_nonce: take(payload, 0),
            server_mac: take(payload, 32),
        })
    }
}

pub fn decode_request_id(payload: &[u8]) -> std::result::Result<RequestId, ProtocolError> {
    if payload.len() != 16 {
        return Err(ProtocolError::new("OPEN length"));
    }
    Ok(take(payload, 0))
}

pub fn decode_sequence(payload: &[u8]) -> std::result::Result<u64, ProtocolError> {
    if payload.len() != 8 {
        return Err(ProtocolError::new("PING/PONG length"));
    }
    Ok(u64::from_be_bytes(take(payload, 0)))
}

pub fn decode_error(payload: &[u8]) -> std::result::Result<ErrorCode, ProtocolError> {
    if payload.len() != 2 {
        return Err(ProtocolError::new("ERROR length"));
    }
    ErrorCode::from_u16(u16::from_be_bytes([payload[0], payload[1]]))
        .ok_or_else(|| ProtocolError::new("unknown error code"))
}
