//! System timeouts and duration parameters.
//!
//! These internal parameters are constant.
//! Standard production code uses [`Timing::default`].
//! Test suites can inject [`Timing::fast`].

use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// Maximum time allowed for one handshake.
    pub handshake: Duration,
    /// Maximum time allowed for one control connection attempt, including DNS.
    pub control_attempt: Duration,
    /// Fixed delay before the next reconnection attempt.
    pub reconnect_delay: Duration,
    /// Reservation duration for a public listener after unexpected disconnection.
    pub reservation: Duration,
    /// Maximum time a public connection waits for a matching data connection.
    pub request_wait: Duration,
    /// Maximum time allowed to connect to the local target.
    pub target_connect: Duration,
    /// Interval between heartbeat pings.
    pub heartbeat_interval: Duration,
    /// Timeout for a matching PONG reply.
    pub heartbeat_timeout: Duration,
    /// Timeout for a control write operation.
    pub write_timeout: Duration,
    /// Time allowed for graceful shutdown before aborting remaining tasks.
    pub shutdown_grace: Duration,
    /// Time allowed to flush outbound frames for a replaced session.
    pub takeover_flush: Duration,
    /// Interval for periodic sweep of expired requests and reservations.
    pub sweep_interval: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            control_attempt: Duration::from_secs(10),
            reconnect_delay: Duration::from_secs(5),
            reservation: Duration::from_secs(300),
            request_wait: Duration::from_secs(10),
            target_connect: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(20),
            heartbeat_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(5),
            takeover_flush: Duration::from_secs(1),
            sweep_interval: Duration::from_millis(100),
        }
    }
}

impl Timing {
    /// Shorter timeouts for integration tests.
    pub fn fast() -> Self {
        Self {
            handshake: Duration::from_secs(2),
            control_attempt: Duration::from_secs(2),
            reconnect_delay: Duration::from_millis(100),
            reservation: Duration::from_millis(600),
            request_wait: Duration::from_millis(700),
            target_connect: Duration::from_millis(600),
            heartbeat_interval: Duration::from_millis(200),
            heartbeat_timeout: Duration::from_millis(300),
            write_timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_secs(2),
            takeover_flush: Duration::from_millis(100),
            sweep_interval: Duration::from_millis(20),
        }
    }
}
