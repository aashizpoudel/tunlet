//! Control connection client handler: connect, authenticate, register, and process session messages.

use crate::{
    auth,
    client::data::{self, OpenContext},
    config::ExposeConfig,
    error::{AppError, ErrorCode, Result},
    log_debug, log_info, net,
    protocol::{
        self, ControlChallenge, ControlHello, Frame, InstanceId, Kind, Mode, OpenFailed,
        OpenFailure, Registered, SessionId, Type,
    },
    server::registry::{Outbound, WRITER_CAPACITY},
    timing::Timing,
};
use std::{
    io::Write,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Semaphore, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Status outcome of a control connection attempt.
pub enum Attempt {
    /// The user initiated an orderly shutdown.
    Clean,
    /// A fatal error occurred; the process must terminate.
    Fatal(AppError),
    /// A recoverable error occurred; retry the connection.
    Retry(String),
}

pub struct ClientState {
    pub instance_id: InstanceId,
    /// Explicit port requested on the command line.
    pub requested_port: Option<u16>,
    /// Port assigned by the server, retained in memory only.
    pub last_assigned: Option<u16>,
    pub ever_registered: bool,
}

struct Session {
    session_id: SessionId,
    server_addr: SocketAddr,
    assigned_port: u16,
    max_connections: u32,
}

pub async fn attempt(
    config: &ExposeConfig,
    state: &mut ClientState,
    timing: Timing,
    cancel: &CancellationToken,
) -> Attempt {
    // Determine the registration mode.
    // A new process uses Mode::Fresh.
    // A reconnecting process uses Mode::Resume with the remembered port.
    let (mode, requested_port) = if state.ever_registered {
        match state.last_assigned {
            Some(port) => (Mode::Resume, port),
            None => (Mode::Fresh, state.requested_port.unwrap_or(0)),
        }
    } else {
        (Mode::Fresh, state.requested_port.unwrap_or(0))
    };

    let connected = tokio::select! {
        biased;
        () = cancel.cancelled() => return Attempt::Clean,
        result = timeout(
            timing.control_attempt,
            connect_and_register(config, state.instance_id, mode, requested_port, timing),
        ) => result,
    };
    let (socket, session) = match connected {
        Err(_) => return Attempt::Retry("control connection attempt timed out".to_owned()),
        Ok(Err(Failure::Fatal(error))) => return Attempt::Fatal(error),
        Ok(Err(Failure::Retry(message))) => return Attempt::Retry(message),
        Ok(Ok(pair)) => pair,
    };

    state.ever_registered = true;
    state.last_assigned = Some(session.assigned_port);

    // Print the assigned port to stdout before processing OPEN messages.
    println!("remote_port={}", session.assigned_port);
    let _ = std::io::stdout().flush();
    log_info!(
        "tunnel ready: {} public port {} forwards to {}",
        config.server,
        session.assigned_port,
        config.target
    );

    run_session(config, socket, session, timing, cancel).await
}

enum Failure {
    Fatal(AppError),
    Retry(String),
}

fn classify(code: ErrorCode) -> Failure {
    if code.is_fatal_for_client() {
        Failure::Fatal(AppError::Registration(code))
    } else {
        Failure::Retry(code.message().to_owned())
    }
}

async fn connect_and_register(
    config: &ExposeConfig,
    instance_id: InstanceId,
    mode: Mode,
    requested_port: u16,
    timing: Timing,
) -> std::result::Result<(TcpStream, Session), Failure> {
    // Re-resolve DNS before each connection attempt.
    let mut socket = net::dial(&config.server, timing.control_attempt)
        .await
        .map_err(|error| Failure::Retry(error.to_string()))?;
    let server_addr = socket
        .peer_addr()
        .map_err(|error| Failure::Retry(error.to_string()))?;

    match register(&mut socket, config, instance_id, mode, requested_port).await {
        Ok(session) => Ok((
            socket,
            Session {
                server_addr,
                ..session
            },
        )),
        Err(failure) => {
            let _ = socket.shutdown().await;
            Err(failure)
        }
    }
}

async fn register(
    socket: &mut TcpStream,
    config: &ExposeConfig,
    instance_id: InstanceId,
    mode: Mode,
    requested_port: u16,
) -> std::result::Result<Session, Failure> {
    let fatal = |error: AppError| Failure::Fatal(error);
    let transport = |error: AppError| match error {
        AppError::Io(inner) => Failure::Retry(inner.to_string()),
        other => Failure::Fatal(other),
    };

    protocol::write_preamble(socket, Kind::Control)
        .await
        .map_err(transport)?;
    let client_nonce = auth::random::<32>().map_err(fatal)?;
    let hello = ControlHello {
        instance_id,
        client_nonce,
        mode,
        requested_port,
    };
    protocol::write_frame(socket, &Frame::new(Type::ControlHello, hello.encode()))
        .await
        .map_err(transport)?;

    let frame = protocol::read_frame(socket).await.map_err(transport)?;
    frame
        .require_kind(Kind::Control)
        .map_err(|error| fatal(error.into()))?;
    if frame.ty == Type::Error {
        let code = protocol::decode_error(&frame.payload).map_err(|e| fatal(e.into()))?;
        return Err(classify(code));
    }
    frame
        .require_type(Type::ControlChallenge)
        .map_err(|error| fatal(error.into()))?;
    let challenge = ControlChallenge::decode(&frame.payload).map_err(|e| fatal(e.into()))?;

    let transcript =
        auth::control_transcript(&hello, &challenge.server_nonce, &challenge.session_id);
    // Verify the server proof. The server must hold the shared key.
    if !auth::verify(
        config.key.as_bytes(),
        auth::LABEL_CONTROL_SERVER,
        &transcript,
        &challenge.server_mac,
    ) {
        return Err(fatal(AppError::Auth));
    }
    let proof = auth::mac(
        config.key.as_bytes(),
        auth::LABEL_CONTROL_CLIENT,
        &transcript,
    );
    protocol::write_frame(socket, &Frame::new(Type::ControlProof, proof.to_vec()))
        .await
        .map_err(transport)?;

    let frame = protocol::read_frame(socket).await.map_err(transport)?;
    frame
        .require_kind(Kind::Control)
        .map_err(|e| fatal(e.into()))?;
    if frame.ty == Type::Error {
        let code = protocol::decode_error(&frame.payload).map_err(|e| fatal(e.into()))?;
        return Err(classify(code));
    }
    frame
        .require_type(Type::Registered)
        .map_err(|e| fatal(e.into()))?;
    let registered = Registered::decode(&frame.payload).map_err(|e| fatal(e.into()))?;

    // Verify the server assignment proof.
    let ready = auth::ready_transcript(
        &transcript,
        registered.assigned_port,
        registered.max_connections,
    );
    if !auth::verify(
        config.key.as_bytes(),
        auth::LABEL_CONTROL_READY,
        &ready,
        &registered.ready_mac,
    ) {
        return Err(fatal(AppError::Auth));
    }
    if requested_port != 0 && registered.assigned_port != requested_port {
        return Err(fatal(AppError::protocol(
            "server assigned a different port than requested",
        )));
    }
    Ok(Session {
        session_id: challenge.session_id,
        server_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        assigned_port: registered.assigned_port,
        max_connections: registered.max_connections,
    })
}

async fn run_session(
    config: &ExposeConfig,
    socket: TcpStream,
    session: Session,
    timing: Timing,
    cancel: &CancellationToken,
) -> Attempt {
    let (reader, write_half) = socket.into_split();
    let (writer, outbound) = mpsc::channel::<Outbound>(WRITER_CAPACITY);
    // Cancels data forwarding tasks for this attempt without terminating the process.
    let session_cancel = CancellationToken::new();
    let writer_task = tokio::spawn(writer_loop(
        write_half,
        outbound,
        timing,
        session_cancel.clone(),
    ));
    let (frames, mut incoming) = mpsc::channel::<Result<Frame>>(64);
    let reader_task = tokio::spawn(read_frames(reader, frames, session_cancel.clone()));
    let permits = Arc::new(Semaphore::new(session.max_connections as usize));

    let mut sequence: u64 = 0;
    let mut outstanding: Option<(u64, Instant)> = None;
    let mut ping = tokio::time::interval_at(
        tokio::time::Instant::now() + timing.heartbeat_interval,
        timing.heartbeat_interval,
    );
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let outcome = loop {
        let pong_deadline = outstanding.map(|(_, deadline)| deadline);
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                break goodbye(&writer, &mut incoming, timing).await;
            }
            () = session_cancel.cancelled() => {
                break Attempt::Retry("control connection closed".to_owned());
            }
            _ = async {
                match pong_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => std::future::pending().await,
                }
            } => {
                break Attempt::Retry("no heartbeat reply from the server".to_owned());
            }
            _ = ping.tick() => {
                if outstanding.is_none() {
                    sequence = sequence.wrapping_add(1);
                    if writer
                        .try_send(Outbound::frame(Type::Ping, sequence.to_be_bytes().to_vec()))
                        .is_err()
                    {
                        break Attempt::Retry("control queue unavailable".to_owned());
                    }
                    outstanding = Some((sequence, Instant::now() + timing.heartbeat_timeout));
                }
            }
            frame = incoming.recv() => {
                let Some(frame) = frame else {
                    break Attempt::Retry("control connection closed".to_owned());
                };
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(AppError::Protocol(error)) => {
                        break Attempt::Fatal(AppError::Protocol(error));
                    }
                    Err(error) => break Attempt::Retry(error.to_string()),
                };
                match frame.ty {
                    Type::Open => {
                        let Ok(request_id) = protocol::decode_request_id(&frame.payload) else {
                            break Attempt::Fatal(AppError::protocol("malformed OPEN"));
                        };
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            let _ = writer.try_send(Outbound::frame(
                                Type::OpenFailed,
                                OpenFailed { request_id, reason: OpenFailure::LocalCapacity }
                                    .encode(),
                            ));
                            continue;
                        };
                        let context = OpenContext {
                            request_id,
                            session_id: session.session_id,
                            server_addr: session.server_addr,
                            target: config.target.clone(),
                            key: config.key.clone(),
                            writer: writer.clone(),
                            timing,
                            cancel: session_cancel.clone(),
                        };
                        // Spawn the data connection task asynchronously.
                        // The control read loop does not block on dialing.
                        tokio::spawn(async move {
                            data::handle_open(context).await;
                            drop(permit);
                        });
                    }
                    Type::Ping => {
                        let Ok(value) = protocol::decode_sequence(&frame.payload) else {
                            break Attempt::Fatal(AppError::protocol("malformed PING"));
                        };
                        if writer
                            .try_send(Outbound::frame(Type::Pong, value.to_be_bytes().to_vec()))
                            .is_err()
                        {
                            break Attempt::Retry("control queue unavailable".to_owned());
                        }
                    }
                    Type::Pong => {
                        let Ok(value) = protocol::decode_sequence(&frame.payload) else {
                            break Attempt::Fatal(AppError::protocol("malformed PONG"));
                        };
                        if outstanding.is_some_and(|(expected, _)| expected == value) {
                            outstanding = None;
                        }
                    }
                    Type::ServerShutdown => {
                        break Attempt::Retry("server is shutting down".to_owned());
                    }
                    Type::Error => {
                        let Ok(code) = protocol::decode_error(&frame.payload) else {
                            break Attempt::Fatal(AppError::protocol("malformed ERROR"));
                        };
                        break match classify(code) {
                            Failure::Fatal(error) => Attempt::Fatal(error),
                            Failure::Retry(message) => Attempt::Retry(message),
                        };
                    }
                    Type::GoodbyeAck => {}
                    _ => {
                        break Attempt::Fatal(AppError::protocol(
                            "unexpected control message from the server",
                        ));
                    }
                }
            }
        }
    };

    // Every data and setup task for this attempt ends with the attempt.
    session_cancel.cancel();
    drop(writer);
    let _ = timeout(Duration::from_secs(1), writer_task).await;
    let _ = timeout(Duration::from_secs(1), reader_task).await;
    outcome
}

/// Send a GOODBYE message for orderly shutdown.
async fn goodbye(
    writer: &mpsc::Sender<Outbound>,
    incoming: &mut mpsc::Receiver<Result<Frame>>,
    timing: Timing,
) -> Attempt {
    if writer
        .try_send(Outbound::frame(Type::Goodbye, Vec::new()))
        .is_err()
    {
        return Attempt::Clean;
    }
    let acknowledged = timeout(timing.shutdown_grace, async {
        while let Some(frame) = incoming.recv().await {
            if matches!(frame, Ok(frame) if frame.ty == Type::GoodbyeAck) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    if acknowledged {
        log_debug!("server acknowledged the goodbye");
    } else {
        log_debug!("goodbye was not acknowledged; the server will reserve the port");
    }
    Attempt::Clean
}

async fn writer_loop(
    mut half: OwnedWriteHalf,
    mut outbound: mpsc::Receiver<Outbound>,
    timing: Timing,
    session_cancel: CancellationToken,
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
    session_cancel.cancel();
}

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
            frame.require_kind(Kind::Control)?;
            Ok(frame)
        });
        if frames.send(checked).await.is_err() || failed {
            break;
        }
    }
}
