//! Command-line argument parsing.
//!
//! This module does not access network services, read files, or modify environment variables.

use crate::{
    config::RawConfig,
    error::{AppError, Result},
};
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Server,
    Expose,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Expose => "expose",
        }
    }
}

#[derive(Clone, Debug)]
pub enum Command {
    Help,
    Version,
    Run {
        mode: Mode,
        config: PathBuf,
        /// True if `--config` was set on the command line.
        config_explicit: bool,
        cli: RawConfig,
    },
}

/// Flags that accept a value and map to a configuration key.
const VALUE_FLAGS: &[(&str, &str)] = &[
    ("--key", "KEY"),
    ("--listen", "LISTEN"),
    ("--data-bind", "DATA_BIND"),
    ("--allowed-ports", "ALLOWED_PORTS"),
    ("--max-connections", "MAX_CONNECTIONS"),
    ("--server", "SERVER"),
    ("--remote-port", "REMOTE_PORT"),
    ("--target", "TARGET"),
    ("--log-level", "LOG_LEVEL"),
];

fn value_flag(flag: &str) -> Option<&'static str> {
    VALUE_FLAGS
        .iter()
        .find(|(name, _)| *name == flag)
        .map(|(_, key)| *key)
}

pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command> {
    let args: Vec<String> = args
        .into_iter()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();

    let mut mode: Option<Mode> = None;
    let mut config = PathBuf::from(DEFAULT_CONFIG);
    let mut config_explicit = false;
    let mut cli = RawConfig::default();
    let mut index = 0usize;

    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "server" | "expose" => {
                if mode.is_some() {
                    return Err(AppError::Cli(format!("unexpected argument `{arg}`")));
                }
                mode = Some(if arg == "server" {
                    Mode::Server
                } else {
                    Mode::Expose
                });
            }
            _ => {
                let (flag, inline) = match arg.split_once('=') {
                    Some((flag, value)) => (flag, Some(value.to_owned())),
                    None => (arg, None),
                };
                if !flag.starts_with('-') {
                    return Err(AppError::Cli(format!("unexpected argument `{arg}`")));
                }
                if flag == "--config" {
                    let value = match inline {
                        Some(value) => value,
                        None => {
                            index += 1;
                            args.get(index).cloned().ok_or_else(|| {
                                AppError::Cli("--config requires a path".to_owned())
                            })?
                        }
                    };
                    if value.is_empty() {
                        return Err(AppError::Cli("--config requires a path".to_owned()));
                    }
                    config = PathBuf::from(value);
                    config_explicit = true;
                    index += 1;
                    continue;
                }
                // Flags other than `--config` must follow the subcommand.
                if mode.is_none() {
                    return Err(AppError::Cli(format!(
                        "`{flag}` must follow the server or expose subcommand"
                    )));
                }
                if flag == "--quiet" {
                    let value = inline.unwrap_or_else(|| "true".to_owned());
                    if value != "true" && value != "false" {
                        return Err(AppError::Cli(
                            "--quiet accepts only --quiet, --quiet=true, or --quiet=false"
                                .to_owned(),
                        ));
                    }
                    cli.values.insert("QUIET".to_owned(), value);
                    index += 1;
                    continue;
                }
                let key = value_flag(flag)
                    .ok_or_else(|| AppError::Cli(format!("unrecognized option `{flag}`")))?;
                let value = match inline {
                    Some(value) => value,
                    None => {
                        index += 1;
                        args.get(index)
                            .cloned()
                            .ok_or_else(|| AppError::Cli(format!("{flag} requires a value")))?
                    }
                };
                // The last duplicate flag takes precedence.
                cli.values.insert(key.to_owned(), value);
            }
        }
        index += 1;
    }

    let mode = mode.ok_or_else(|| {
        AppError::Cli("expected a subcommand: `server` or `expose`. Try --help".to_owned())
    })?;
    Ok(Command::Run {
        mode,
        config,
        config_explicit,
        cli,
    })
}

pub const DEFAULT_CONFIG: &str = "tunlet.cfg";

pub fn help() -> String {
    format!(
        "tunlet {version} - a small authenticated TCP tunnel

Usage:
  tunlet server [options]
  tunlet expose [options]

Common options:
  -h, --help                 show this help and exit
  -V, --version              show version and exit
      --config PATH          configuration file (default ./{DEFAULT_CONFIG})
      --key TEXT             shared key, any non-empty text (also TUNLET_KEY)
      --log-level LEVEL      error, info, or debug (default info)
      --quiet[=true|false]   suppress routine logs; --quiet=false undoes an
                             inherited quiet setting

server options:
      --listen ADDR          control and data listener, default :4000
                             (`:PORT` means 0.0.0.0:PORT; ports 1024-65535)
      --data-bind IP         bind address for public listeners, default 0.0.0.0
      --allowed-ports MIN-MAX
                             range used for automatic allocation only, default
                             10000-65535. A client asking for a specific port
                             outside this range is still allowed.
      --max-connections N    pending plus active public connections per tunnel,
                             default 256

expose options:
      --server HOST:PORT     public server control address (required)
      --target HOST:PORT     local target to forward to (required);
                             `:PORT` means 127.0.0.1:PORT
      --remote-port PORT     requested public port, 1024-65535. Omit to request
                             automatic allocation; the assigned port is printed
                             as `remote_port=N` on stdout.

Settings may come from flags, TUNLET_* environment variables, or the
configuration file, in that order of precedence. Application bytes are
forwarded unchanged and are not encrypted; see the README security section.
",
        version = env!("CARGO_PKG_VERSION")
    )
}

pub fn version() -> String {
    format!("tunlet {}", env!("CARGO_PKG_VERSION"))
}
