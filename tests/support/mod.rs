//! Shared fixtures: loopback servers, readiness signals, and a protocol client
//! that lets tests drive exact handshake sequences.
#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tunlet::{
    auth,
    config::{ExposeConfig, ServerConfig},
    error::ErrorCode,
    logging::Level,
    net::Endpoint,
    protocol::{
        self, ControlChallenge, ControlHello, DataChallenge, DataHello, Frame, InstanceId, Kind,
        Mode, Registered, RequestId, SessionId, Type,
    },
    timing::Timing,
};

pub const KEY: &str = "test-key-lauda-lasoon";
pub const OTHER_KEY: &str = "a-different-key";

/// Default assertion budget. Every await in a test is wrapped so a regression
/// fails instead of hanging.
pub const BUDGET: Duration = Duration::from_secs(10);

/// Keep routine logs out of test output. The binary configures this from the
/// resolved settings; tests set it once, quietly.
pub fn quiet_logs() {
    tunlet::logging::init(Level::Error, true);
}

pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Port numbers already handed to a test in this process. The operating system
/// reuses an ephemeral port as soon as it is released, so without this guard two
/// parallel tests can be given the same number and then assert against each
/// other's listeners.
static CLAIMED: std::sync::Mutex<Option<std::collections::HashSet<u16>>> =
    std::sync::Mutex::new(None);

fn claim(port: u16) -> bool {
    let mut claimed = CLAIMED.lock().expect("port registry");
    claimed
        .get_or_insert_with(std::collections::HashSet::new)
        .insert(port)
}

/// Ask the operating system for a free loopback port, then release it.
/// Production code never binds port 0; only fixtures do.
pub async fn free_port() -> u16 {
    for _ in 0..64 {
        let listener = TcpListener::bind(loopback(0))
            .await
            .expect("bind ephemeral");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        if claim(port) {
            return port;
        }
    }
    panic!("could not find an unused loopback port");
}

/// Hold a port open so a test can assert behavior against an occupied port.
pub async fn occupy_port(port: u16) -> TcpListener {
    TcpListener::bind(loopback(port))
        .await
        .expect("occupy port")
}

pub fn server_config(control_port: u16, allowed: (u16, u16)) -> ServerConfig {
    ServerConfig {
        key: KEY.to_owned(),
        listen: loopback(control_port),
        data_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        allowed_ports: allowed,
        max_connections: 256,
        log_level: Level::Error,
        quiet: true,
    }
}

pub fn expose_config(
    server: SocketAddr,
    remote_port: Option<u16>,
    target: SocketAddr,
) -> ExposeConfig {
    ExposeConfig {
        key: KEY.to_owned(),
        server: Endpoint {
            host: server.ip().to_string(),
            port: server.port(),
        },
        remote_port,
        target: Endpoint {
            host: target.ip().to_string(),
            port: target.port(),
        },
        log_level: Level::Error,
        quiet: true,
    }
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    pub cancel: CancellationToken,
    pub task: JoinHandle<tunlet::error::Result<()>>,
}

impl ServerHandle {
    /// Start a server and wait until its listener is bound.
    pub async fn start(config: ServerConfig, timing: Timing) -> Self {
        quiet_logs();
        let cancel = CancellationToken::new();
        let (ready, listening) = oneshot::channel();
        let task = tokio::spawn(tunlet::server::run(
            config,
            timing,
            cancel.clone(),
            Some(ready),
        ));
        let addr = timeout(BUDGET, listening)
            .await
            .expect("server start timed out")
            .expect("server failed to bind");
        Self { addr, cancel, task }
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = timeout(BUDGET, self.task)
            .await
            .expect("server stop timed out");
    }
}

pub struct ClientHandle {
    pub cancel: CancellationToken,
    pub task: JoinHandle<tunlet::error::Result<()>>,
}

impl ClientHandle {
    pub fn start(config: ExposeConfig, timing: Timing) -> Self {
        quiet_logs();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(tunlet::client::run(config, timing, cancel.clone()));
        Self { cancel, task }
    }

    pub async fn stop(self) -> tunlet::error::Result<()> {
        self.cancel.cancel();
        timeout(BUDGET, self.task)
            .await
            .expect("client stop timed out")
            .expect("client task panicked")
    }
}

/// A TCP echo service used as a forwarding target.
pub async fn echo_target() -> (SocketAddr, CancellationToken) {
    spawn_target(|mut socket| async move {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    // Mirror the half-close: finish writing, then close.
                    let _ = socket.shutdown().await;
                    return;
                }
                Ok(read) => {
                    if socket.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    })
    .await
}

/// A target that sends a banner before reading anything.
pub async fn banner_target(banner: &'static [u8]) -> (SocketAddr, CancellationToken) {
    spawn_target(move |mut socket| async move {
        if socket.write_all(banner).await.is_err() {
            return;
        }
        let mut buffer = vec![0u8; 4096];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    let _ = socket.shutdown().await;
                    return;
                }
                Ok(read) => {
                    if socket.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    })
    .await
}

/// A target that only answers after its peer has shut down its write half.
pub async fn after_eof_target(response: &'static [u8]) -> (SocketAddr, CancellationToken) {
    spawn_target(move |mut socket| async move {
        let mut request = Vec::new();
        if socket.read_to_end(&mut request).await.is_err() {
            return;
        }
        let _ = socket.write_all(&request).await;
        let _ = socket.write_all(response).await;
        let _ = socket.shutdown().await;
    })
    .await
}

pub async fn spawn_target<F, Fut>(handler: F) -> (SocketAddr, CancellationToken)
where
    F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(loopback(0)).await.expect("bind target");
    let addr = listener.local_addr().expect("target addr");
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((socket, _)) = accepted else { break };
                    let _ = socket.set_nodelay(true);
                    tokio::spawn(handler(socket));
                }
            }
        }
    });
    (addr, cancel)
}

/// An authenticated control connection driven directly by a test.
pub struct ControlClient {
    pub socket: TcpStream,
    pub session_id: SessionId,
    pub instance_id: InstanceId,
    pub assigned_port: u16,
    pub max_connections: u32,
    pub key: String,
}

impl std::fmt::Debug for ControlClient {
    /// Deliberately omits the key so a failing assertion cannot print it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlClient")
            .field("assigned_port", &self.assigned_port)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

#[derive(Debug)]
pub enum ControlError {
    Refused(ErrorCode),
    Other(String),
}

impl ControlClient {
    pub async fn connect(
        server: SocketAddr,
        key: &str,
        instance_id: InstanceId,
        mode: Mode,
        requested_port: u16,
    ) -> Result<Self, ControlError> {
        let mut socket = TcpStream::connect(server)
            .await
            .map_err(|error| ControlError::Other(error.to_string()))?;
        socket.set_nodelay(true).ok();
        protocol::write_preamble(&mut socket, Kind::Control)
            .await
            .map_err(|error| ControlError::Other(error.to_string()))?;
        let client_nonce = auth::random::<32>().expect("entropy");
        let hello = ControlHello {
            instance_id,
            client_nonce,
            mode,
            requested_port,
        };
        protocol::write_frame(&mut socket, &Frame::new(Type::ControlHello, hello.encode()))
            .await
            .map_err(|error| ControlError::Other(error.to_string()))?;

        let frame = read_frame(&mut socket).await?;
        if frame.ty == Type::Error {
            return Err(ControlError::Refused(
                protocol::decode_error(&frame.payload).expect("error code"),
            ));
        }
        let challenge = ControlChallenge::decode(&frame.payload)
            .map_err(|error| ControlError::Other(error.to_string()))?;
        let transcript =
            auth::control_transcript(&hello, &challenge.server_nonce, &challenge.session_id);
        let proof = auth::mac(key.as_bytes(), auth::LABEL_CONTROL_CLIENT, &transcript);
        protocol::write_frame(&mut socket, &Frame::new(Type::ControlProof, proof.to_vec()))
            .await
            .map_err(|error| ControlError::Other(error.to_string()))?;

        let frame = read_frame(&mut socket).await?;
        if frame.ty == Type::Error {
            return Err(ControlError::Refused(
                protocol::decode_error(&frame.payload).expect("error code"),
            ));
        }
        let registered = Registered::decode(&frame.payload)
            .map_err(|error| ControlError::Other(error.to_string()))?;
        Ok(Self {
            socket,
            session_id: challenge.session_id,
            instance_id,
            assigned_port: registered.assigned_port,
            max_connections: registered.max_connections,
            key: key.to_owned(),
        })
    }

    pub async fn next_frame(&mut self) -> Result<Frame, ControlError> {
        read_frame(&mut self.socket).await
    }

    /// Wait for the next OPEN, answering PING along the way. The whole wait is
    /// bounded, so a regression fails the test instead of hanging.
    pub async fn next_open(&mut self) -> Result<RequestId, ControlError> {
        let deadline = tokio::time::Instant::now() + BUDGET;
        loop {
            let frame = tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(ControlError::Other("no OPEN arrived within the budget".to_owned()));
                }
                frame = self.next_frame() => frame?,
            };
            match frame.ty {
                Type::Open => {
                    return Ok(protocol::decode_request_id(&frame.payload).expect("request id"));
                }
                Type::Ping => self.pong(&frame.payload).await?,
                Type::Error => {
                    return Err(ControlError::Refused(
                        protocol::decode_error(&frame.payload).expect("error code"),
                    ));
                }
                _ => {}
            }
        }
    }

    pub async fn pong(&mut self, payload: &[u8]) -> Result<(), ControlError> {
        protocol::write_frame(&mut self.socket, &Frame::new(Type::Pong, payload.to_vec()))
            .await
            .map_err(|error| ControlError::Other(error.to_string()))
    }

    pub async fn send(&mut self, ty: Type, payload: Vec<u8>) -> Result<(), ControlError> {
        protocol::write_frame(&mut self.socket, &Frame::new(ty, payload))
            .await
            .map_err(|error| ControlError::Other(error.to_string()))
    }

    /// Answer heartbeats for a while without expecting anything else.
    pub async fn keep_alive(&mut self, duration: Duration) {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            let frame = tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return,
                frame = read_frame(&mut self.socket) => frame,
            };
            match frame {
                Ok(frame) if frame.ty == Type::Ping => {
                    if self.pong(&frame.payload).await.is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    }
}

async fn read_frame(socket: &mut TcpStream) -> Result<Frame, ControlError> {
    match timeout(BUDGET, protocol::read_frame(socket)).await {
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(error)) => Err(ControlError::Other(error.to_string())),
        Err(_) => Err(ControlError::Other("frame read timed out".to_owned())),
    }
}

/// Complete a data handshake and return the socket positioned right after
/// DATA_READY, ready for raw application bytes.
pub async fn data_connect(
    server: SocketAddr,
    key: &str,
    session_id: SessionId,
    request_id: RequestId,
) -> Result<TcpStream, ErrorCode> {
    let (socket, outcome) = data_attempt(server, key, session_id, request_id, true).await;
    match outcome {
        Ok(()) => Ok(socket.expect("socket after ready")),
        Err(code) => Err(code),
    }
}

/// Run a data handshake, optionally stopping before DATA_READY. Returns the
/// socket so a test can inspect what follows.
pub async fn data_attempt(
    server: SocketAddr,
    key: &str,
    session_id: SessionId,
    request_id: RequestId,
    wait_ready: bool,
) -> (Option<TcpStream>, Result<(), ErrorCode>) {
    let Ok(mut socket) = TcpStream::connect(server).await else {
        return (None, Err(ErrorCode::InternalError));
    };
    socket.set_nodelay(true).ok();
    if protocol::write_preamble(&mut socket, Kind::Data)
        .await
        .is_err()
    {
        return (None, Err(ErrorCode::InternalError));
    }
    let client_nonce = auth::random::<32>().expect("entropy");
    let hello = DataHello {
        session_id,
        request_id,
        client_nonce,
    };
    if protocol::write_frame(&mut socket, &Frame::new(Type::DataHello, hello.encode()))
        .await
        .is_err()
    {
        return (None, Err(ErrorCode::InternalError));
    }
    let frame = match timeout(BUDGET, protocol::read_frame(&mut socket)).await {
        Ok(Ok(frame)) => frame,
        _ => return (None, Err(ErrorCode::InternalError)),
    };
    if frame.ty == Type::Error {
        return (
            Some(socket),
            Err(protocol::decode_error(&frame.payload).expect("error code")),
        );
    }
    let challenge = DataChallenge::decode(&frame.payload).expect("challenge");
    let transcript = auth::data_transcript(&hello, &challenge.server_nonce);
    let proof = auth::mac(key.as_bytes(), auth::LABEL_DATA_CLIENT, &transcript);
    if protocol::write_frame(&mut socket, &Frame::new(Type::DataProof, proof.to_vec()))
        .await
        .is_err()
    {
        return (None, Err(ErrorCode::InternalError));
    }
    if !wait_ready {
        return (Some(socket), Ok(()));
    }
    let frame = match timeout(BUDGET, protocol::read_frame(&mut socket)).await {
        Ok(Ok(frame)) => frame,
        _ => return (Some(socket), Err(ErrorCode::InternalError)),
    };
    if frame.ty == Type::Error {
        return (
            Some(socket),
            Err(protocol::decode_error(&frame.payload).expect("error code")),
        );
    }
    assert_eq!(frame.ty, Type::DataReady, "expected DATA_READY");
    (Some(socket), Ok(()))
}

/// Read exactly `len` bytes with a budget.
pub async fn read_exact_budgeted(socket: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; len];
    timeout(BUDGET, socket.read_exact(&mut buffer))
        .await
        .expect("read timed out")
        .expect("read failed");
    buffer
}

pub async fn read_to_end_budgeted(socket: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    timeout(BUDGET, socket.read_to_end(&mut buffer))
        .await
        .expect("read timed out")
        .expect("read failed");
    buffer
}

/// Deterministic pseudo-random payload including NUL and every byte value.
pub fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| ((index as u32).wrapping_mul(31).wrapping_add(seed as u32) % 256) as u8)
        .collect()
}
