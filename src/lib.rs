//! Tunlet: a small authenticated TCP tunnel.
//!
//! This library exposes entry points for integration tests.
//! Tests can inject a [`timing::Timing`] instance and a cancellation token.

pub mod auth;
pub mod cli;
pub mod client;
pub mod config;
pub mod error;
pub mod forward;
pub mod logging;
pub mod net;
pub mod protocol;
pub mod server;
pub mod shutdown;
pub mod timing;

pub use config::{ExposeConfig, ServerConfig};
pub use timing::Timing;
