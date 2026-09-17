//! Client supervisor: process identity, port persistence, and reconnection policy.

pub mod control;
pub mod data;

use crate::{auth, config::ExposeConfig, error::Result, log_debug, log_info, timing::Timing};
use control::{Attempt, ClientState};
use tokio_util::sync::CancellationToken;

/// Run the expose client until clean shutdown or fatal error.
pub async fn run(config: ExposeConfig, timing: Timing, cancel: CancellationToken) -> Result<()> {
    let mut state = ClientState {
        // Ephemeral process identifier. Stored in memory only.
        instance_id: auth::random::<16>()?,
        requested_port: config.remote_port,
        last_assigned: None,
        ever_registered: false,
    };

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        match control::attempt(&config, &mut state, timing, &cancel).await {
            Attempt::Clean => return Ok(()),
            Attempt::Fatal(error) => return Err(error),
            Attempt::Retry(reason) => {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                log_info!(
                    "reconnecting in {} seconds: {reason}",
                    timing.reconnect_delay.as_secs_f32()
                );
                // Fixed delay without backoff or jitter.
                tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(timing.reconnect_delay) => {}
                }
                log_debug!("retrying the control connection");
            }
        }
    }
}
