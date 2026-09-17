//! Forward bidirectional TCP traffic and preserve half-close state.

use std::io;
use tokio::{io::copy_bidirectional, net::TcpStream};
use tokio_util::sync::CancellationToken;

/// Forward traffic in both directions until both sockets close.
///
/// When one side sends EOF, this function closes the opposite writer.
/// The reverse direction continues forwarding until it finishes.
/// Cancellation closes both sockets immediately.
pub async fn forward(
    mut left: TcpStream,
    mut right: TcpStream,
    cancel: &CancellationToken,
) -> io::Result<(u64, u64)> {
    let _ = left.set_nodelay(true);
    let _ = right.set_nodelay(true);
    tokio::select! {
        biased;
        result = copy_bidirectional(&mut left, &mut right) => result,
        () = cancel.cancelled() => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "forwarding cancelled",
        )),
    }
}
