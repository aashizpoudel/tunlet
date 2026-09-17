//! Server data connection handler.
//!
//! Authenticates data connections and transfers sockets to waiting public tasks.

use crate::{
    auth,
    error::{AppError, ErrorCode, Result},
    log_debug,
    protocol::{self, DataChallenge, DataHello, Frame, Type},
    server::registry::{ClaimOutcome, RegistryHandle},
    timing::Timing,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};

/// Process one incoming data connection. The dispatcher already read the preamble.
pub async fn serve(
    socket: TcpStream,
    key: String,
    registry: RegistryHandle,
    timing: Timing,
) -> Result<()> {
    match timeout(timing.handshake, handshake(socket, &key, &registry)).await {
        Err(_) => {
            log_debug!("data handshake timed out");
            Ok(())
        }
        Ok(result) => result,
    }
}

async fn handshake(mut socket: TcpStream, key: &str, registry: &RegistryHandle) -> Result<()> {
    let frame = protocol::read_frame(&mut socket).await?;
    if frame.require_kind(protocol::Kind::Data).is_err()
        || frame.require_type(Type::DataHello).is_err()
    {
        return reject(socket, ErrorCode::ProtocolError).await;
    }
    let hello = match DataHello::decode(&frame.payload) {
        Ok(hello) => hello,
        Err(error) => return reject(socket, error.code).await,
    };

    // Peeking at the request validates existence without consuming the request.
    if !registry.peek(hello.session_id, hello.request_id).await {
        return reject(socket, ErrorCode::RequestUnavailable).await;
    }

    let server_nonce = auth::random::<32>()?;
    let transcript = auth::data_transcript(&hello, &server_nonce);
    let server_mac = auth::mac(key.as_bytes(), auth::LABEL_DATA_SERVER, &transcript);
    protocol::write_frame(
        &mut socket,
        &Frame::new(
            Type::DataChallenge,
            DataChallenge {
                server_nonce,
                server_mac,
            }
            .encode(),
        ),
    )
    .await?;

    let frame = protocol::read_frame(&mut socket).await?;
    if frame.require_kind(protocol::Kind::Data).is_err()
        || frame.require_type(Type::DataProof).is_err()
    {
        return reject(socket, ErrorCode::ProtocolError).await;
    }
    // An invalid proof does not consume the pending request.
    if !auth::verify(
        key.as_bytes(),
        auth::LABEL_DATA_CLIENT,
        &transcript,
        &frame.payload,
    ) {
        return reject(socket, ErrorCode::AuthFailed).await;
    }

    // The registry claims the request and sends the socket to the waiting task.
    match registry
        .claim(hello.session_id, hello.request_id, socket)
        .await
    {
        ClaimOutcome::Delivered => Ok(()),
        ClaimOutcome::Rejected { code, socket } => match socket {
            Some(socket) => reject(socket, code).await,
            None => Err(AppError::Runtime("data connection lost".to_owned())),
        },
    }
}

async fn reject(mut socket: TcpStream, code: ErrorCode) -> Result<()> {
    let _ = protocol::write_error(&mut socket, code).await;
    let _ = socket.shutdown().await;
    log_debug!("data connection rejected: {code}");
    Ok(())
}
