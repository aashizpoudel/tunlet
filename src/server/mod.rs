//! Server supervisor: controls the inbound listener, registry actor, and worker tasks.

pub mod control;
pub mod data;
pub mod listener;
pub mod registry;

use crate::{
    config::ServerConfig,
    error::{AppError, Result},
    log_debug, log_info, net,
    protocol::{self, Kind},
    timing::Timing,
};
use registry::{COMMAND_CAPACITY, MAX_HANDSHAKES, Registry, RegistryHandle};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

/// Run the server until the cancellation token fires.
///
/// If `ready` is provided, sends the bound control socket address.
pub async fn run(
    config: ServerConfig,
    timing: Timing,
    cancel: CancellationToken,
    ready: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let listener = net::bind_listener(config.listen).map_err(|error| {
        AppError::Runtime(format!(
            "cannot listen on {}: {error}",
            net::display_addr(&config.listen)
        ))
    })?;
    let local = listener.local_addr()?;
    log_info!(
        "tunlet server listening on {} (control and data)",
        net::display_addr(&local)
    );
    log_info!(
        "automatic port range {}-{}, public bind address {}, {} connections per tunnel",
        config.allowed_ports.0,
        config.allowed_ports.1,
        config.data_bind,
        config.max_connections
    );
    if let Some(ready) = ready {
        let _ = ready.send(local);
    }

    let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
    let handle = RegistryHandle::new(commands.clone());
    let registry = Registry::new(config.clone(), timing, receiver, commands);
    let registry_task = tokio::spawn(registry.run());

    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    let mut tasks: JoinSet<()> = JoinSet::new();
    let key = config.key.clone();

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            // Clean up completed tasks to prevent unbounded set growth.
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    log_debug!("connection task ended abnormally: {error}");
                }
            }
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        log_debug!("accept failed: {error}");
                        continue;
                    }
                };
                let Ok(permit) = handshakes.clone().try_acquire_owned() else {
                    log_debug!("too many incomplete handshakes; closing a new connection");
                    continue;
                };
                let _ = socket.set_nodelay(true);
                log_debug!("incoming connection from {}", net::display_addr(&peer));
                let key = key.clone();
                let handle = handle.clone();
                tasks.spawn(async move {
                    let result = dispatch(socket, key, handle, timing).await;
                    drop(permit);
                    if let Err(error) = result {
                        log_debug!("connection ended: {error}");
                    }
                });
            }
        }
    }

    // Notify active clients and release listeners. Wait for active tasks to complete.
    log_info!("shutting down");
    handle.shutdown().await;
    let grace = timing.shutdown_grace;
    let _ = timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
    tasks.shutdown().await;
    let _ = timeout(Duration::from_secs(1), registry_task).await;
    Ok(())
}

async fn dispatch(
    mut socket: TcpStream,
    key: String,
    registry: RegistryHandle,
    timing: Timing,
) -> Result<()> {
    let kind = match timeout(timing.handshake, protocol::read_preamble(&mut socket)).await {
        Ok(Ok(kind)) => kind,
        Ok(Err(error)) => {
            if let AppError::Protocol(protocol_error) = &error {
                let _ = protocol::write_error(&mut socket, protocol_error.code).await;
            }
            return Err(error);
        }
        Err(_) => return Ok(()),
    };
    match kind {
        Kind::Control => control::serve(socket, key, registry, timing).await,
        Kind::Data => data::serve(socket, key, registry, timing).await,
    }
}
