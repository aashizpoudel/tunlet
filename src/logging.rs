//! Minimal logging to standard error.
//!
//! Quiet mode suppresses routine log messages.
//! The logger never prints configuration values or secret keys.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Info = 1,
    Debug = 2,
}

impl Level {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "error" => Self::Error,
            "info" => Self::Info,
            "debug" => Self::Debug,
            _ => return None,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static QUIET: AtomicBool = AtomicBool::new(false);

pub fn init(level: Level, quiet: bool) {
    LEVEL.store(level as u8, Ordering::Relaxed);
    QUIET.store(quiet, Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    !QUIET.load(Ordering::Relaxed) && (level as u8) <= LEVEL.load(Ordering::Relaxed)
}

pub fn log(level: Level, message: &str) {
    if enabled(level) {
        eprintln!("[{}] {}", level.label(), message);
    }
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::Error) {
            $crate::logging::log($crate::logging::Level::Error, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::Info) {
            $crate::logging::log($crate::logging::Level::Info, &format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::logging::enabled($crate::logging::Level::Debug) {
            $crate::logging::log($crate::logging::Level::Debug, &format!($($arg)*));
        }
    };
}
