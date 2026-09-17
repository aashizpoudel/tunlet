//! Handle operating system shutdown signals.
//!
//! Listens for Ctrl-C on all platforms and SIGTERM on Unix platforms.

use tokio_util::sync::CancellationToken;

/// Cancel the token when the system receives a shutdown signal.
///
/// This function returns when a signal arrives or when the token is cancelled.
pub async fn wait_for_signal(token: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                crate::log_debug!("SIGTERM handler unavailable: {error}");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    () = token.cancelled() => return,
                }
                token.cancel();
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            () = token.cancelled() => return,
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = token.cancelled() => return,
        }
    }
    token.cancel();
}
