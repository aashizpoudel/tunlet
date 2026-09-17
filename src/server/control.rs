//! Control connection server handler: handshake, registration, heartbeats, and termination.

use crate::{
    auth,
    error::{AppError, ErrorCode, Result},
    log_debug,
    protocol::{self, ControlChallenge, ControlHello, Frame, OpenFailed, SessionId, Type},
    server::registry::{Outbound, RegisterRequest, RegistryHandle, WRITER_CAPACITY},
    timing::Timing,
};
use std::time::{Duration, Instant};
use tokio::{
    io::AsyncWriteExt,
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::mpsc,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

struct Authenticated {
    hello: ControlHello,
    session_id: SessionId,
    transcript: Vec<u8>,
}

/// Process one control connection.
/// The dispatcher already read and validated the preamble.
pub async fn serve(
    mut socket: TcpStream,
    key: String,
    registry: RegistryHandle,
    timing: Timing,
) -> Result<()> {
    // The whole handshake shares one deadline; trickling bytes do not reset it.
    let authenticated = match timeout(timing.handshake, handshake(&mut socket, &key)).await {
        Err(_) => {
            log_debug!("control handshake timed out");
            return Ok(());
        }
        Ok(Err(error)) => {
            let code = match &error {
                AppError::Auth => ErrorCode::AuthFailed,
                AppError::Protocol(protocol_error) => protocol_error.code,
                _ => ErrorCode::InternalError,
            };
            // Send a fixed error code without secret text, then close the socket.
            let _ = timeout(
                timing.write_timeout,
                protocol::write_error(&mut socket, code),
            )
            .await;
            let _ = socket.shutdown().await;
            log_debug!("control handshake rejected: {error}");
            return Ok(());
        }
        Ok(Ok(authenticated)) => authenticated,
    };

    let (reader, writer_half) = socket.into_split();
    let (writer, outbound) = mpsc::channel::<Outbound>(WRITER_CAPACITY);
    let control_cancel = CancellationToken::new();
    let data_cancel = CancellationToken::new();
    let writer_task = tokio::spawn(writer_loop(
        writer_half,
        outbound,
        timing,
        control_cancel.clone(),
    ));

    let registration = registry
        .register(RegisterRequest {
            session_id: authenticated.session_id,
            instance_id: authenticated.hello.instance_id,
            mode: authenticated.hello.mode,
            requested_port: authenticated.hello.requested_port,
            writer: writer.clone(),
            data_cancel: data_cancel.clone(),
            control_cancel: control_cancel.clone(),
        })
        .await;

    let registration = match registration {
        Ok(registration) => registration,
        Err(code) => {
            let _ = writer.send(Outbound::error(code)).await;
            let _ = writer.send(Outbound::CloseAfterFlush).await;
            drop(writer);
            let _ = writer_task.await;
            log_debug!("registration refused: {code}");
            return Ok(());
        }
    };

    // The REGISTERED message is queued first. OPEN messages cannot precede it.
    let ready_mac = auth::mac(
        key.as_bytes(),
        auth::LABEL_CONTROL_READY,
        &auth::ready_transcript(
            &authenticated.transcript,
            registration.assigned_port,
            registration.max_connections,
        ),
    );
    let registered = protocol::Registered {
        assigned_port: registration.assigned_port,
        max_connections: registration.max_connections,
        ready_mac,
    };
    if writer
        .send(Outbound::frame(Type::Registered, registered.encode()))
        .await
        .is_err()
    {
        registry
            .session_lost(authenticated.session_id, registration.generation)
            .await;
        return Ok(());
    }

    let clean = session_loop(
        reader,
        &writer,
        &registry,
        authenticated.session_id,
        registration.generation,
        timing,
        &control_cancel,
    )
    .await;

    if clean {
        registry
            .goodbye(authenticated.session_id, registration.generation)
            .await;
    } else {
        registry
            .session_lost(authenticated.session_id, registration.generation)
            .await;
    }
    data_cancel.cancel();
    control_cancel.cancel();
    drop(writer);
    let _ = writer_task.await;
    Ok(())
}

async fn handshake(socket: &mut TcpStream, key: &str) -> Result<Authenticated> {
    let frame = protocol::read_frame(socket).await?;
    frame.require_kind(protocol::Kind::Control)?;
    frame.require_type(Type::ControlHello)?;
    let hello = ControlHello::decode(&frame.payload)?;

    let server_nonce = auth::random::<32>()?;
    let session_id = auth::random::<16>()?;
    let transcript = auth::control_transcript(&hello, &server_nonce, &session_id);
    let server_mac = auth::mac(key.as_bytes(), auth::LABEL_CONTROL_SERVER, &transcript);
    let challenge = ControlChallenge {
        server_nonce,
        session_id,
        server_mac,
    };
    protocol::write_frame(
        socket,
        &Frame::new(Type::ControlChallenge, challenge.encode()),
    )
    .await?;

    let frame = protocol::read_frame(socket).await?;
    frame.require_kind(protocol::Kind::Control)?;
    frame.require_type(Type::ControlProof)?;
    if !auth::verify(
        key.as_bytes(),
        auth::LABEL_CONTROL_CLIENT,
        &transcript,
        &frame.payload,
    ) {
        return Err(AppError::Auth);
    }
    Ok(Authenticated {
        hello,
        session_id,
        transcript,
    })
}

/// Writer task for a control connection. Processes a bounded outbound queue.
async fn writer_loop(
    mut half: OwnedWriteHalf,
    mut outbound: mpsc::Receiver<Outbound>,
    timing: Timing,
    control_cancel: CancellationToken,
) {
    while let Some(message) = outbound.recv().await {
        match message {
            Outbound::Frame(frame) => {
                match timeout(
                    timing.write_timeout,
                    protocol::write_frame(&mut half, &frame),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        log_debug!("control write failed: {error}");
                        break;
                    }
                    Err(_) => {
                        log_debug!("control write stalled past its deadline");
                        break;
                    }
                }
            }
            Outbound::CloseAfterFlush => break,
        }
    }
    let _ = half.shutdown().await;
    control_cancel.cancel();
}

/// Process control session messages. Returns true if the client sent GOODBYE.
async fn session_loop(
    reader: OwnedReadHalf,
    writer: &mpsc::Sender<Outbound>,
    registry: &RegistryHandle,
    session_id: SessionId,
    generation: u64,
    timing: Timing,
    control_cancel: &CancellationToken,
) -> bool {
    let (frames, mut incoming) = mpsc::channel::<Result<Frame>>(64);
    let reader_cancel = control_cancel.clone();
    let reader_task = tokio::spawn(read_frames(reader, frames, reader_cancel));

    let mut sequence: u64 = 0;
    let mut outstanding: Option<(u64, Instant)> = None;
    let mut ping = tokio::time::interval_at(
        tokio::time::Instant::now() + timing.heartbeat_interval,
        timing.heartbeat_interval,
    );
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut clean = false;

    loop {
        let pong_deadline = outstanding.map(|(_, deadline)| deadline);
        tokio::select! {
            biased;
            () = control_cancel.cancelled() => break,
            _ = async {
                match pong_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => std::future::pending().await,
                }
            } => {
                log_debug!("heartbeat reply did not arrive in time");
                break;
            }
            _ = ping.tick() => {
                if outstanding.is_some() {
                    // Maximum of one unacknowledged ping at a time.
                    continue;
                }
                sequence = sequence.wrapping_add(1);
                if writer
                    .try_send(Outbound::frame(Type::Ping, sequence.to_be_bytes().to_vec()))
                    .is_err()
                {
                    break;
                }
                outstanding = Some((sequence, Instant::now() + timing.heartbeat_timeout));
            }
            frame = incoming.recv() => {
                let Some(frame) = frame else { break };
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => {
                        log_debug!("control connection ended: {error}");
                        break;
                    }
                };
                match frame.ty {
                    Type::Ping => {
                        let Ok(value) = protocol::decode_sequence(&frame.payload) else { break };
                        if writer
                            .try_send(Outbound::frame(Type::Pong, value.to_be_bytes().to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Type::Pong => {
                        let Ok(value) = protocol::decode_sequence(&frame.payload) else { break };
                        if outstanding.is_some_and(|(expected, _)| expected == value) {
                            outstanding = None;
                        }
                    }
                    Type::OpenFailed => {
                        let Ok(message) = OpenFailed::decode(&frame.payload) else { break };
                        // The registry ignores late reports for expired or claimed requests.
                        registry
                            .open_failed(session_id, message.request_id, message.reason)
                            .await;
                    }
                    Type::Goodbye => {
                        let _ = writer.try_send(Outbound::frame(Type::GoodbyeAck, Vec::new()));
                        let _ = writer.try_send(Outbound::CloseAfterFlush);
                        clean = true;
                        break;
                    }
                    Type::Error => {
                        log_debug!("client reported an error and closed its control connection");
                        break;
                    }
                    _ => {
                        let _ = writer.try_send(Outbound::error(ErrorCode::ProtocolError));
                        let _ = writer.try_send(Outbound::CloseAfterFlush);
                        break;
                    }
                }
            }
        }
    }
    let _ = generation;
    control_cancel.cancel();
    let _ = timeout(Duration::from_secs(1), reader_task).await;
    clean
}

/// Read frames continuously from the socket.
/// Cancellation terminates the reader and closes the connection.
async fn read_frames(
    mut reader: OwnedReadHalf,
    frames: mpsc::Sender<Result<Frame>>,
    cancel: CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            frame = protocol::read_frame(&mut reader) => frame,
        };
        let failed = frame.is_err();
        let checked = frame.and_then(|frame| {
            frame.require_kind(protocol::Kind::Control)?;
            Ok(frame)
        });
        if frames.send(checked).await.is_err() || failed {
            break;
        }
    }
}
