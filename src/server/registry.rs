//! The registry actor controls port, session, and pending-request state.
//!
//! The actor does not perform blocking I/O, network operations, or DNS queries.
//! State transitions occur synchronously in the actor loop.

use crate::{
    config::ServerConfig,
    error::ErrorCode,
    log_debug, log_info, net,
    protocol::{Frame, InstanceId, Mode, RequestId, SessionId, Type},
    server::listener,
    timing::Timing,
};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use tokio::{
    net::TcpStream,
    sync::{Semaphore, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

/// Maximum number of bound public listener slots, active or reserved.
pub const MAX_SLOTS: usize = 1024;
/// Maximum pending plus active forwarded connections across the whole server.
pub const MAX_GLOBAL_CONNECTIONS: usize = 8192;
/// Maximum incoming handshakes that have not finished yet.
pub const MAX_HANDSHAKES: usize = 1024;
/// Bounded registry command channel.
pub const COMMAND_CAPACITY: usize = 1024;
/// Bounded per-control-connection writer queue.
pub const WRITER_CAPACITY: usize = 512;

/// A message queued for a control connection writer task.
#[derive(Clone, Debug)]
pub enum Outbound {
    Frame(Frame),
    /// Flush the outbound queue and close the control connection.
    CloseAfterFlush,
}

impl Outbound {
    pub fn frame(ty: Type, payload: Vec<u8>) -> Self {
        Self::Frame(Frame::new(ty, payload))
    }

    pub fn error(code: ErrorCode) -> Self {
        Self::frame(Type::Error, code.as_u16().to_be_bytes().to_vec())
    }
}

/// Registration parameters provided by an authenticated control connection.
pub struct RegisterRequest {
    pub session_id: SessionId,
    pub instance_id: InstanceId,
    pub mode: Mode,
    pub requested_port: u16,
    pub writer: mpsc::Sender<Outbound>,
    /// Cancels active data forwarding for this session.
    pub data_cancel: CancellationToken,
    /// Cancels the control connection.
    pub control_cancel: CancellationToken,
}

#[derive(Clone, Copy, Debug)]
pub struct Registration {
    pub assigned_port: u16,
    pub max_connections: u32,
    pub generation: u64,
}

#[derive(Debug)]
pub enum ClaimOutcome {
    Delivered,
    /// The request was not consumed. The socket comes back so the caller can
    /// report the reason before closing it.
    Rejected {
        code: ErrorCode,
        socket: Option<TcpStream>,
    },
}

pub enum Command {
    Register {
        request: Box<RegisterRequest>,
        reply: oneshot::Sender<std::result::Result<Registration, ErrorCode>>,
    },
    /// A public listener accepted a socket.
    AcceptedPublic {
        listener_id: u64,
        port: u16,
        socket: TcpStream,
        peer: SocketAddr,
        at: Instant,
    },
    /// A data connection passed its proof and wants its pending request.
    ClaimData {
        session_id: SessionId,
        request_id: RequestId,
        socket: TcpStream,
        reply: oneshot::Sender<ClaimOutcome>,
    },
    /// Check if a request is pending. Does not consume the request.
    PeekData {
        session_id: SessionId,
        request_id: RequestId,
        reply: oneshot::Sender<bool>,
    },
    /// The client could not complete its side of a request.
    OpenFailed {
        session_id: SessionId,
        request_id: RequestId,
        reason: crate::protocol::OpenFailure,
    },
    /// A control connection ended unexpectedly.
    SessionLost {
        session_id: SessionId,
        generation: u64,
    },
    /// A control connection sent GOODBYE.
    Goodbye {
        session_id: SessionId,
        generation: u64,
        reply: oneshot::Sender<()>,
    },
    /// An accepted public connection task finished.
    RequestFinished {
        session_id: SessionId,
        request_id: RequestId,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
struct SessionRef {
    session_id: SessionId,
    instance_id: InstanceId,
    generation: u64,
    port: u16,
    writer: mpsc::Sender<Outbound>,
    data_cancel: CancellationToken,
    control_cancel: CancellationToken,
    permits: Arc<Semaphore>,
}

enum SlotState {
    Active(SessionRef),
    Reserved {
        instance_id: InstanceId,
        generation: u64,
        expires_at: Instant,
    },
}

struct PortSlot {
    listener_id: u64,
    /// Cancels the accept loop and drops the bound listener.
    listener_cancel: CancellationToken,
    state: SlotState,
}

struct PendingRequest {
    generation: u64,
    deadline: Instant,
    sender: oneshot::Sender<TcpStream>,
}

pub struct Registry {
    config: ServerConfig,
    timing: Timing,
    commands: mpsc::Receiver<Command>,
    handle: mpsc::Sender<Command>,
    ports: BTreeMap<u16, PortSlot>,
    sessions: HashMap<SessionId, SessionRef>,
    pending: HashMap<(SessionId, RequestId), PendingRequest>,
    global_connections: Arc<Semaphore>,
    next_generation: u64,
    next_listener_id: u64,
}

impl Registry {
    pub fn new(
        config: ServerConfig,
        timing: Timing,
        commands: mpsc::Receiver<Command>,
        handle: mpsc::Sender<Command>,
    ) -> Self {
        Self {
            config,
            timing,
            commands,
            handle,
            ports: BTreeMap::new(),
            sessions: HashMap::new(),
            pending: HashMap::new(),
            global_connections: Arc::new(Semaphore::new(MAX_GLOBAL_CONNECTIONS)),
            next_generation: 1,
            next_listener_id: 1,
        }
    }

    /// Run until a Shutdown command arrives or the command channel closes.
    pub async fn run(mut self) {
        let mut sweep = tokio::time::interval(self.timing.sweep_interval);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = sweep.tick() => self.sweep(Instant::now()),
                command = self.commands.recv() => {
                    let Some(command) = command else { break };
                    if self.handle_command(command) {
                        break;
                    }
                }
            }
        }
        self.shutdown_all();
    }

    /// Returns true when the registry should stop.
    fn handle_command(&mut self, command: Command) -> bool {
        match command {
            Command::Register { request, reply } => {
                let outcome = self.register(*request);
                let _ = reply.send(outcome);
            }
            Command::AcceptedPublic {
                listener_id,
                port,
                socket,
                peer,
                at,
            } => self.accepted_public(listener_id, port, socket, peer, at),
            Command::PeekData {
                session_id,
                request_id,
                reply,
            } => {
                let now = Instant::now();
                let present = self
                    .pending
                    .get(&(session_id, request_id))
                    .is_some_and(|entry| entry.deadline > now);
                let _ = reply.send(present);
            }
            Command::ClaimData {
                session_id,
                request_id,
                socket,
                reply,
            } => {
                let outcome = self.claim(session_id, request_id, socket);
                let _ = reply.send(outcome);
            }
            Command::OpenFailed {
                session_id,
                request_id,
                reason,
            } => {
                // Dropping the pending entry drops its oneshot sender, which
                // wakes the waiting task so it can close the public socket.
                if self.pending.remove(&(session_id, request_id)).is_some() {
                    log_debug!("request failed on the client: {}", reason.message());
                }
            }
            Command::SessionLost {
                session_id,
                generation,
            } => self.session_lost(session_id, generation),
            Command::Goodbye {
                session_id,
                generation,
                reply,
            } => {
                self.goodbye(session_id, generation);
                let _ = reply.send(());
            }
            Command::RequestFinished {
                session_id,
                request_id,
            } => {
                self.pending.remove(&(session_id, request_id));
            }
            Command::Shutdown { reply } => {
                self.shutdown_all();
                let _ = reply.send(());
                return true;
            }
        }
        false
    }

    fn next_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("generation counter overflow");
        generation
    }

    fn register(
        &mut self,
        request: RegisterRequest,
    ) -> std::result::Result<Registration, ErrorCode> {
        let RegisterRequest {
            session_id,
            instance_id,
            mode,
            requested_port,
            writer,
            data_cancel,
            control_cancel,
        } = request;

        if requested_port != 0 && requested_port == self.config.listen.port() {
            // The control listener's numeric port is never a public port, even
            // on another bind address.
            return Err(ErrorCode::InvalidPort);
        }

        let port = match (mode, requested_port) {
            (Mode::Fresh, 0) => self.allocate_automatic(instance_id)?,
            (Mode::Fresh, port) => {
                self.ensure_slot(port, instance_id, false)?;
                port
            }
            (Mode::Resume, port) => {
                match self.ports.get(&port) {
                    Some(slot) => {
                        let owner = match &slot.state {
                            SlotState::Active(session) => session.instance_id,
                            SlotState::Reserved { instance_id, .. } => *instance_id,
                        };
                        if owner != instance_id {
                            // A different process owns this tunnel now.
                            return Err(ErrorCode::Replaced);
                        }
                    }
                    None => {
                        // Server restarted or the reservation expired.
                        self.ensure_slot(port, instance_id, true)?;
                    }
                }
                port
            }
        };

        let generation = self.next_generation();
        let session = SessionRef {
            session_id,
            instance_id,
            generation,
            port,
            writer,
            data_cancel,
            control_cancel,
            permits: Arc::new(Semaphore::new(self.config.max_connections as usize)),
        };

        // Install the new owner, displacing any previous one.
        let previous = {
            let slot = self
                .ports
                .get_mut(&port)
                .expect("slot exists after allocation");
            match std::mem::replace(&mut slot.state, SlotState::Active(session.clone())) {
                SlotState::Active(previous) => Some(previous),
                SlotState::Reserved { .. } => None,
            }
        };
        if let Some(previous) = previous {
            self.displace(previous);
        }
        self.sessions.insert(session_id, session);
        log_info!(
            "tunnel registered on port {port} ({} registration)",
            match mode {
                Mode::Fresh => "fresh",
                Mode::Resume => "resume",
            }
        );
        Ok(Registration {
            assigned_port: port,
            max_connections: self.config.max_connections,
            generation,
        })
    }

    /// Stop a replaced session and close its control connection.
    fn displace(&mut self, previous: SessionRef) {
        self.sessions.remove(&previous.session_id);
        self.drop_pending_for(previous.session_id);
        previous.data_cancel.cancel();
        let _ = previous
            .writer
            .try_send(Outbound::error(ErrorCode::Replaced));
        let _ = previous.writer.try_send(Outbound::CloseAfterFlush);
        let control_cancel = previous.control_cancel.clone();
        let flush = self.timing.takeover_flush;
        tokio::spawn(async move {
            tokio::time::sleep(flush).await;
            control_cancel.cancel();
        });
        log_info!("replaced the previous owner of port {}", previous.port);
    }

    /// Ensure a slot exists for `port`, binding a listener if needed.
    /// `exclusive_new` rejects reuse of a slot owned by someone else.
    fn ensure_slot(
        &mut self,
        port: u16,
        instance_id: InstanceId,
        exclusive_new: bool,
    ) -> std::result::Result<(), ErrorCode> {
        if self.ports.contains_key(&port) {
            if exclusive_new {
                return Err(ErrorCode::Replaced);
            }
            return Ok(());
        }
        if self.ports.len() >= MAX_SLOTS {
            return Err(ErrorCode::ServerBusy);
        }
        let _ = instance_id;
        self.bind_slot(port).map(|_| ())
    }

    fn bind_slot(&mut self, port: u16) -> std::result::Result<u64, ErrorCode> {
        let addr = SocketAddr::new(self.config.data_bind, port);
        let bound = match net::bind_listener(addr) {
            Ok(bound) => bound,
            Err(error) => {
                log_debug!("cannot bind public port {port}: {error}");
                return Err(if net::is_port_taken(&error) {
                    ErrorCode::PortUnavailable
                } else {
                    ErrorCode::InternalError
                });
            }
        };
        let listener_id = self.next_listener_id;
        self.next_listener_id += 1;
        let cancel = CancellationToken::new();
        listener::spawn(
            bound,
            listener_id,
            port,
            self.handle.clone(),
            cancel.clone(),
        );
        self.ports.insert(
            port,
            PortSlot {
                listener_id,
                listener_cancel: cancel,
                state: SlotState::Reserved {
                    // Placeholder state; the caller installs Active next.
                    instance_id: [0u8; 16],
                    generation: 0,
                    expires_at: Instant::now() + self.timing.reservation,
                },
            },
        );
        Ok(listener_id)
    }

    /// Allocate the lowest available port in the configured range.
    /// Reuses an existing reservation for the same instance if present.
    fn allocate_automatic(
        &mut self,
        instance_id: InstanceId,
    ) -> std::result::Result<u16, ErrorCode> {
        if let Some(port) = self.ports.iter().find_map(|(port, slot)| {
            let owner = match &slot.state {
                SlotState::Active(session) => session.instance_id,
                SlotState::Reserved { instance_id, .. } => *instance_id,
            };
            (owner == instance_id).then_some(*port)
        }) {
            return Ok(port);
        }
        if self.ports.len() >= MAX_SLOTS {
            return Err(ErrorCode::ServerBusy);
        }
        let (min, max) = self.config.allowed_ports;
        for port in min..=max {
            if port == self.config.listen.port() || self.ports.contains_key(&port) {
                continue;
            }
            match self.bind_slot(port) {
                Ok(_) => return Ok(port),
                // Another process holds this port: keep scanning.
                Err(ErrorCode::PortUnavailable) => continue,
                // A systemic failure such as an unusable bind address aborts
                // the scan instead of trying thousands of ports.
                Err(code) => return Err(code),
            }
        }
        Err(ErrorCode::NoPortAvailable)
    }

    fn accepted_public(
        &mut self,
        listener_id: u64,
        port: u16,
        socket: TcpStream,
        peer: SocketAddr,
        at: Instant,
    ) {
        let Some(slot) = self.ports.get(&port) else {
            return;
        };
        if slot.listener_id != listener_id {
            return;
        }
        let SlotState::Active(session) = &slot.state else {
            // Reserved: accept and close at once, never queue.
            log_debug!("closing connection to reserved port {port}");
            return;
        };
        let session = session.clone();
        let Ok(session_permit) = session.permits.clone().try_acquire_owned() else {
            log_debug!("tunnel on port {port} is at its connection limit");
            return;
        };
        let Ok(global_permit) = self.global_connections.clone().try_acquire_owned() else {
            log_debug!("server is at its global connection limit");
            return;
        };
        let mut request_id: RequestId = match crate::auth::random() {
            Ok(id) => id,
            Err(error) => {
                log_debug!("cannot create a request identifier: {error}");
                return;
            }
        };
        while self.pending.contains_key(&(session.session_id, request_id)) {
            match crate::auth::random() {
                Ok(id) => request_id = id,
                Err(_) => return,
            }
        }
        let (sender, receiver) = oneshot::channel();
        let deadline = at + self.timing.request_wait;
        if session
            .writer
            .try_send(Outbound::frame(Type::Open, request_id.to_vec()))
            .is_err()
        {
            // A full or closed writer queue fails the session rather than
            // silently dropping a required OPEN.
            log_debug!("control queue unavailable; failing session on port {port}");
            self.session_lost(session.session_id, session.generation);
            return;
        }
        self.pending.insert(
            (session.session_id, request_id),
            PendingRequest {
                generation: session.generation,
                deadline,
                sender,
            },
        );
        log_debug!(
            "accepted public connection from {} on port {port}",
            net::display_addr(&peer)
        );
        let commands = self.handle.clone();
        let cancel = session.data_cancel.clone();
        let session_id = session.session_id;
        tokio::spawn(async move {
            crate::server::listener::serve_public(
                socket, receiver, deadline, cancel, commands, session_id, request_id,
            )
            .await;
            drop(session_permit);
            drop(global_permit);
        });
    }

    fn claim(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
        socket: TcpStream,
    ) -> ClaimOutcome {
        let now = Instant::now();
        let reject = |socket: TcpStream| ClaimOutcome::Rejected {
            code: ErrorCode::RequestUnavailable,
            socket: Some(socket),
        };
        let Some(session) = self.sessions.get(&session_id) else {
            return reject(socket);
        };
        let generation = session.generation;
        let Some(entry) = self.pending.get(&(session_id, request_id)) else {
            return reject(socket);
        };
        // A stale generation, an expired deadline, or a replaced session all
        // leave the pending entry untouched.
        if entry.generation != generation || entry.deadline <= now {
            return reject(socket);
        }
        // Consume exactly once.
        let entry = self
            .pending
            .remove(&(session_id, request_id))
            .expect("entry present");
        match entry.sender.send(socket) {
            Ok(()) => ClaimOutcome::Delivered,
            Err(socket) => ClaimOutcome::Rejected {
                code: ErrorCode::RequestUnavailable,
                socket: Some(socket),
            },
        }
    }

    fn drop_pending_for(&mut self, session_id: SessionId) {
        self.pending.retain(|(id, _), _| *id != session_id);
    }

    fn session_lost(&mut self, session_id: SessionId, generation: u64) {
        let Some(session) = self.sessions.get(&session_id).cloned() else {
            return;
        };
        if session.generation != generation {
            return;
        }
        let port = session.port;
        let still_current = matches!(
            self.ports.get(&port).map(|slot| &slot.state),
            Some(SlotState::Active(current)) if current.generation == generation
        );
        self.sessions.remove(&session_id);
        self.drop_pending_for(session_id);
        session.data_cancel.cancel();
        session.control_cancel.cancel();
        if !still_current {
            return;
        }
        let expires_at = Instant::now() + self.timing.reservation;
        if let Some(slot) = self.ports.get_mut(&port) {
            slot.state = SlotState::Reserved {
                instance_id: session.instance_id,
                generation,
                expires_at,
            };
        }
        log_info!("tunnel on port {port} lost its control connection; reserving the listener");
    }

    fn goodbye(&mut self, session_id: SessionId, generation: u64) {
        let Some(session) = self.sessions.get(&session_id).cloned() else {
            return;
        };
        if session.generation != generation {
            return;
        }
        let port = session.port;
        self.sessions.remove(&session_id);
        self.drop_pending_for(session_id);
        session.data_cancel.cancel();
        let release = matches!(
            self.ports.get(&port).map(|slot| &slot.state),
            Some(SlotState::Active(current)) if current.generation == generation
        );
        if release {
            if let Some(slot) = self.ports.remove(&port) {
                slot.listener_cancel.cancel();
            }
            log_info!("tunnel on port {port} closed cleanly; released the listener");
        }
    }

    fn sweep(&mut self, now: Instant) {
        // Remove expired requests. The connection tasks also enforce timeouts.
        self.pending.retain(|_, entry| entry.deadline > now);
        let expired: Vec<(u16, u64)> = self
            .ports
            .iter()
            .filter_map(|(port, slot)| match &slot.state {
                SlotState::Reserved {
                    expires_at,
                    generation,
                    ..
                } if *expires_at <= now => Some((*port, *generation)),
                _ => None,
            })
            .collect();
        for (port, generation) in expired {
            // Only the reservation created by that generation is removed; a
            // newer owner would have replaced the slot state already.
            if let Some(slot) = self.ports.remove(&port) {
                slot.listener_cancel.cancel();
                log_info!(
                    "reservation on port {port} from generation {generation} expired; released the listener"
                );
            }
        }
    }

    fn shutdown_all(&mut self) {
        for session in self.sessions.values() {
            let _ = session
                .writer
                .try_send(Outbound::frame(Type::ServerShutdown, Vec::new()));
            let _ = session.writer.try_send(Outbound::CloseAfterFlush);
            session.data_cancel.cancel();
        }
        self.pending.clear();
        for (_, slot) in std::mem::take(&mut self.ports) {
            slot.listener_cancel.cancel();
        }
        // Control sockets are closed by the supervisor's global cancellation
        // after the notification has had its flush opportunity.
        self.sessions.clear();
    }
}

/// Cloneable handle for communication with the registry actor.
#[derive(Clone)]
pub struct RegistryHandle {
    commands: mpsc::Sender<Command>,
}

impl RegistryHandle {
    pub fn new(commands: mpsc::Sender<Command>) -> Self {
        Self { commands }
    }

    pub fn sender(&self) -> mpsc::Sender<Command> {
        self.commands.clone()
    }

    pub async fn register(
        &self,
        request: RegisterRequest,
    ) -> std::result::Result<Registration, ErrorCode> {
        let (reply, response) = oneshot::channel();
        if self
            .commands
            .send(Command::Register {
                request: Box::new(request),
                reply,
            })
            .await
            .is_err()
        {
            return Err(ErrorCode::InternalError);
        }
        response.await.unwrap_or(Err(ErrorCode::InternalError))
    }

    pub async fn peek(&self, session_id: SessionId, request_id: RequestId) -> bool {
        let (reply, response) = oneshot::channel();
        if self
            .commands
            .send(Command::PeekData {
                session_id,
                request_id,
                reply,
            })
            .await
            .is_err()
        {
            return false;
        }
        response.await.unwrap_or(false)
    }

    pub async fn claim(
        &self,
        session_id: SessionId,
        request_id: RequestId,
        socket: TcpStream,
    ) -> ClaimOutcome {
        let (reply, response) = oneshot::channel();
        if self
            .commands
            .send(Command::ClaimData {
                session_id,
                request_id,
                socket,
                reply,
            })
            .await
            .is_err()
        {
            return ClaimOutcome::Rejected {
                code: ErrorCode::InternalError,
                socket: None,
            };
        }
        response.await.unwrap_or(ClaimOutcome::Rejected {
            code: ErrorCode::InternalError,
            socket: None,
        })
    }

    pub async fn session_lost(&self, session_id: SessionId, generation: u64) {
        let _ = self
            .commands
            .send(Command::SessionLost {
                session_id,
                generation,
            })
            .await;
    }

    pub async fn goodbye(&self, session_id: SessionId, generation: u64) {
        let (reply, response) = oneshot::channel();
        if self
            .commands
            .send(Command::Goodbye {
                session_id,
                generation,
                reply,
            })
            .await
            .is_ok()
        {
            let _ = response.await;
        }
    }

    pub async fn open_failed(
        &self,
        session_id: SessionId,
        request_id: RequestId,
        reason: crate::protocol::OpenFailure,
    ) {
        let _ = self
            .commands
            .send(Command::OpenFailed {
                session_id,
                request_id,
                reason,
            })
            .await;
    }

    pub async fn shutdown(&self) {
        let (reply, response) = oneshot::channel();
        if self
            .commands
            .send(Command::Shutdown { reply })
            .await
            .is_ok()
        {
            let _ = response.await;
        }
    }
}
