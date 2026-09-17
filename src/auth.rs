//! Cryptographic authentication and transcript hashing.
//!
//! These functions do not perform network or file operations.
//! The only side effect is reading random bytes from the operating system.

use crate::{
    error::{AppError, Result},
    protocol::{
        ControlHello, DataHello, Kind, Mac, Nonce, PREAMBLE_LEN, SessionId, encode_preamble,
    },
};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// Each label ends with one null byte (0x00).
pub const LABEL_CONTROL_SERVER: &[u8] = b"tunlet/v1/control/server\0";
pub const LABEL_CONTROL_CLIENT: &[u8] = b"tunlet/v1/control/client\0";
pub const LABEL_CONTROL_READY: &[u8] = b"tunlet/v1/control/ready\0";
pub const LABEL_DATA_SERVER: &[u8] = b"tunlet/v1/data/server\0";
pub const LABEL_DATA_CLIENT: &[u8] = b"tunlet/v1/data/client\0";

/// Generate random bytes from the operating system.
///
/// Returns an error if the system entropy source fails.
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|error| {
        AppError::Runtime(format!("operating-system entropy unavailable: {error}"))
    })?;
    Ok(out)
}

pub fn mac(key: &[u8], label: &[u8], transcript: &[u8]) -> Mac {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(label);
    hmac.update(transcript);
    hmac.finalize().into_bytes().into()
}

/// Verify HMAC proofs in constant time.
pub fn verify(key: &[u8], label: &[u8], transcript: &[u8], proof: &[u8]) -> bool {
    let mut hmac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(label);
    hmac.update(transcript);
    hmac.verify_slice(proof).is_ok()
}

/// `T = control_preamble[8] || CONTROL_HELLO_payload[51] || server_nonce[32] || session_id[16]`
pub fn control_transcript(
    hello: &ControlHello,
    server_nonce: &Nonce,
    session_id: &SessionId,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(PREAMBLE_LEN + 51 + 32 + 16);
    transcript.extend_from_slice(&encode_preamble(Kind::Control));
    transcript.extend_from_slice(&hello.encode());
    transcript.extend_from_slice(server_nonce);
    transcript.extend_from_slice(session_id);
    transcript
}

/// Append final assignment parameters to the transcript.
pub fn ready_transcript(transcript: &[u8], assigned_port: u16, max_connections: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(transcript.len() + 6);
    out.extend_from_slice(transcript);
    out.extend_from_slice(&assigned_port.to_be_bytes());
    out.extend_from_slice(&max_connections.to_be_bytes());
    out
}

/// `D = data_preamble[8] || DATA_HELLO_payload[64] || server_nonce[32]`
pub fn data_transcript(hello: &DataHello, server_nonce: &Nonce) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(PREAMBLE_LEN + 64 + 32);
    transcript.extend_from_slice(&encode_preamble(Kind::Data));
    transcript.extend_from_slice(&hello.encode());
    transcript.extend_from_slice(server_nonce);
    transcript
}
