//! Public TCP listener accept loops and connection forwarding tasks.
//!
//! The accept loop forwards accepted sockets directly to the registry actor.

use crate::{
    forward, log_debug,
    protocol::{self, Frame, RequestId, SessionId, Type},
    server::registry::Command,
};
use std::time::Instant;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

pub fn spawn(
    listener: TcpListener,
    listener_id: u64,
    port: u16,
    commands: mpsc::Sender<Command>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                accepted = listener.accept() => {
                    let (socket, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            log_debug!("accept on public port {port} failed: {error}");
                            continue;
                        }
                    };
                    let _ = socket.set_nodelay(true);
                    let command = Command::AcceptedPublic {
                        listener_id,
                        port,
                        socket,
                        peer,
                        at: Instant::now(),
                    };
                    // If the registry channel is full, drop the socket immediately.
                    if let Err(error) = commands.try_send(command) {
                        if matches!(error, mpsc::error::TrySendError::Closed(_)) {
                            break;
                        }
                        log_debug!("registry busy; closing a connection on port {port}");
                    }
                }
            }
        }
        // Dropping the listener closes the bound port.
        drop(listener);
    });
}

/// Wait for the authenticated data socket and forward application data.
///
/// Public sockets receive only application data or a TCP close.
/// Public sockets never receive protocol framing frames.
#[allow(clippy::too_many_arguments)]
pub async fn serve_public(
    mut public: TcpStream,
    data: oneshot::Receiver<TcpStream>,
    deadline: Instant,
    cancel: CancellationToken,
    commands: mpsc::Sender<Command>,
    session_id: SessionId,
    request_id: RequestId,
) {
    let outcome = tokio::select! {
        biased;
        () = cancel.cancelled() => None,
        _ = tokio::time::sleep_until(deadline.into()) => None,
        received = data => received.ok(),
    };
    let Some(mut data) = outcome else {
        let _ = public.shutdown().await;
        let _ = commands
            .send(Command::RequestFinished {
                session_id,
                request_id,
            })
            .await;
        return;
    };
    // Send DATA_READY before the request deadline expires.
    let ready_frame = Frame::empty(Type::DataReady);
    let ready = protocol::write_frame(&mut data, &ready_frame);
    let wrote = tokio::select! {
        biased;
        () = cancel.cancelled() => false,
        _ = tokio::time::sleep_until(deadline.into()) => false,
        result = ready => result.is_ok(),
    };
    if !wrote {
        let _ = public.shutdown().await;
        let _ = data.shutdown().await;
    } else {
        match forward::forward(public, data, &cancel).await {
            Ok((to_target, to_user)) => log_debug!(
                "forwarded connection finished: {to_target} bytes out, {to_user} bytes in"
            ),
            Err(error) => log_debug!("forwarded connection ended: {error}"),
        }
    }
    let _ = commands
        .send(Command::RequestFinished {
            session_id,
            request_id,
        })
        .await;
}
