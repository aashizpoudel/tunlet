//! Client data connection handler: dial target, establish data connection, and forward data.

use crate::{
    auth,
    error::{AppError, Result},
    forward, log_debug, net,
    net::Endpoint,
    protocol::{
        self, DataChallenge, DataHello, Frame, Kind, OpenFailed, OpenFailure, RequestId, SessionId,
        Type,
    },
    server::registry::Outbound,
    timing::Timing,
};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc, time::timeout};
use tokio_util::sync::CancellationToken;

pub struct OpenContext {
    pub request_id: RequestId,
    pub session_id: SessionId,
    /// Bound address of the control connection.
    /// Ensures data connections connect to the same server instance.
    pub server_addr: SocketAddr,
    pub target: Endpoint,
    pub key: String,
    pub writer: mpsc::Sender<Outbound>,
    pub timing: Timing,
    pub cancel: CancellationToken,
}

/// Process one OPEN request. Failures affect only this request.
pub async fn handle_open(context: OpenContext) {
    let deadline = Instant::now() + context.timing.request_wait;
    let result = tokio::select! {
        biased;
        () = context.cancel.cancelled() => Err(Failure::Cancelled),
        result = setup(&context, deadline) => result,
    };
    match result {
        Ok((target, data)) => match forward::forward(target, data, &context.cancel).await {
            Ok((to_server, to_target)) => log_debug!(
                "forwarded connection finished: {to_server} bytes up, {to_target} bytes down"
            ),
            Err(error) => log_debug!("forwarded connection ended: {error}"),
        },
        Err(Failure::Cancelled) => {}
        Err(Failure::Reported(reason, message)) => {
            log_debug!("request failed: {message}");
            // Send OpenFailed to notify the server. Late notifications are ignored.
            let _ = context.writer.try_send(Outbound::frame(
                Type::OpenFailed,
                OpenFailed {
                    request_id: context.request_id,
                    reason,
                }
                .encode(),
            ));
        }
    }
}

enum Failure {
    Cancelled,
    Reported(OpenFailure, String),
}

fn remaining(deadline: Instant) -> std::result::Result<Duration, Failure> {
    let now = Instant::now();
    if now >= deadline {
        return Err(Failure::Reported(
            OpenFailure::SetupTimeout,
            "setup budget expired".to_owned(),
        ));
    }
    Ok(deadline - now)
}

async fn setup(
    context: &OpenContext,
    deadline: Instant,
) -> std::result::Result<(TcpStream, TcpStream), Failure> {
    // Dial the local target and server concurrently within the timeout budget.
    let target_budget = context.timing.target_connect.min(remaining(deadline)?);
    let data_budget = remaining(deadline)?;
    let target_dial = net::dial(&context.target, target_budget);
    let data_dial = net::connect_addr(context.server_addr, data_budget);
    let (target, data) = tokio::join!(target_dial, data_dial);

    let target = match target {
        Ok(stream) => stream,
        Err(error) => {
            // Close the data socket if target connection fails.
            drop(data);
            return Err(Failure::Reported(
                OpenFailure::TargetConnect,
                format!("local target {} unavailable: {error}", context.target),
            ));
        }
    };
    let data = match data {
        Ok(stream) => stream,
        Err(error) => {
            drop(target);
            return Err(Failure::Reported(
                OpenFailure::DataAuth,
                format!("data connection failed: {error}"),
            ));
        }
    };

    // Proceed with authentication after the local target connects.
    let budget = remaining(deadline)?;
    match timeout(budget, data_handshake(data, context)).await {
        Ok(Ok(data)) => Ok((target, data)),
        Ok(Err(error)) => Err(Failure::Reported(
            OpenFailure::DataAuth,
            format!("data handshake failed: {error}"),
        )),
        Err(_) => Err(Failure::Reported(
            OpenFailure::SetupTimeout,
            "data handshake timed out".to_owned(),
        )),
    }
}

/// Perform the data handshake using exact unbuffered reads.
/// Application data arriving after DATA_READY remains in the socket buffer.
async fn data_handshake(mut data: TcpStream, context: &OpenContext) -> Result<TcpStream> {
    protocol::write_preamble(&mut data, Kind::Data).await?;
    let client_nonce = auth::random::<32>()?;
    let hello = DataHello {
        session_id: context.session_id,
        request_id: context.request_id,
        client_nonce,
    };
    protocol::write_frame(&mut data, &Frame::new(Type::DataHello, hello.encode())).await?;

    let frame = protocol::read_frame(&mut data).await?;
    frame.require_kind(Kind::Data)?;
    if frame.ty == Type::Error {
        let code = protocol::decode_error(&frame.payload)?;
        let _ = data.shutdown().await;
        return Err(AppError::Runtime(format!("server refused: {code}")));
    }
    frame.require_type(Type::DataChallenge)?;
    let challenge = DataChallenge::decode(&frame.payload)?;
    let transcript = auth::data_transcript(&hello, &challenge.server_nonce);
    if !auth::verify(
        context.key.as_bytes(),
        auth::LABEL_DATA_SERVER,
        &transcript,
        &challenge.server_mac,
    ) {
        return Err(AppError::Auth);
    }
    let proof = auth::mac(context.key.as_bytes(), auth::LABEL_DATA_CLIENT, &transcript);
    protocol::write_frame(&mut data, &Frame::new(Type::DataProof, proof.to_vec())).await?;

    let frame = protocol::read_frame(&mut data).await?;
    frame.require_kind(Kind::Data)?;
    if frame.ty == Type::Error {
        let code = protocol::decode_error(&frame.payload)?;
        return Err(AppError::Runtime(format!("server refused: {code}")));
    }
    frame.require_type(Type::DataReady)?;
    Ok(data)
}
