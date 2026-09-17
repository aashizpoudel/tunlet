//! Configuration file parsing, layer merging, and typed validation.
//!
//! Order of precedence: flags (highest), environment variables, file, defaults (lowest).
//! The system merges raw key-value pairs before validation.

use crate::{
    error::{AppError, Result},
    logging::Level,
    net::{self, Endpoint},
};
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

/// All valid configuration keys.
/// Keys for the alternate mode are accepted and ignored.
/// Unrecognized keys cause an error.
pub const NAMES: &[&str] = &[
    "KEY",
    "LISTEN",
    "DATA_BIND",
    "ALLOWED_PORTS",
    "MAX_CONNECTIONS",
    "SERVER",
    "REMOTE_PORT",
    "TARGET",
    "LOG_LEVEL",
    "QUIET",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawConfig {
    pub values: HashMap<String, String>,
}

impl RawConfig {
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            values: pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
}

/// Abstraction for environment access during testing.
pub trait EnvSource {
    fn get(&self, name: &str) -> Option<String>;
}

pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Fixed key-value map for testing.
pub struct MapEnv(pub HashMap<String, String>);

impl MapEnv {
    pub fn new<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self(
            pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        )
    }
}

impl EnvSource for MapEnv {
    fn get(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
}

/// Read only recognized `TUNLET_*` variables. Ignore unknown variables.
pub fn env_config(env: &dyn EnvSource) -> RawConfig {
    let mut values = HashMap::new();
    for name in NAMES {
        if let Some(value) = env.get(&format!("TUNLET_{name}")) {
            values.insert((*name).to_owned(), value);
        }
    }
    RawConfig { values }
}

/// Parse a configuration file.
/// If `required` is true, an absent file returns an error.
pub fn parse_file(path: &Path, required: bool) -> Result<RawConfig> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(RawConfig::default());
        }
        Err(error) => {
            return Err(AppError::Config(format!(
                "{}: cannot read configuration file: {error}",
                path.display()
            )));
        }
    };
    let bytes = match bytes.strip_prefix(&[0xef, 0xbb, 0xbf][..]) {
        Some(rest) => rest.to_vec(),
        None => bytes,
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        AppError::Config(format!(
            "{}: configuration file is not valid UTF-8",
            path.display()
        ))
    })?;

    let mut values = HashMap::new();
    for (offset, raw_line) in text.split('\n').enumerate() {
        let line_number = offset + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| config_line_error(path, line_number, "expected NAME=value"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(config_line_error(path, line_number, "empty setting name"));
        }
        if !NAMES.contains(&name) {
            return Err(config_line_error(path, line_number, "unknown setting name"));
        }
        let value = unquote(value.trim())
            .ok_or_else(|| config_line_error(path, line_number, "unterminated quoted value"))?;
        // The last duplicate key takes precedence.
        values.insert(name.to_owned(), value);
    }
    Ok(RawConfig { values })
}

/// Remove enclosing single or double quotes.
/// Internal characters are preserved literally without escape processing.
fn unquote(value: &str) -> Option<String> {
    let mut chars = value.chars();
    let first = chars.next();
    match first {
        Some(quote @ ('"' | '\'')) => {
            if value.chars().count() >= 2 && value.ends_with(quote) {
                let inner = &value[quote.len_utf8()..value.len() - quote.len_utf8()];
                Some(inner.to_owned())
            } else {
                None
            }
        }
        _ => Some(value.to_owned()),
    }
}

fn config_line_error(path: &Path, line: usize, reason: &str) -> AppError {
    // Do not output the configuration value in the error message.
    AppError::Config(format!("{}:{}: {}", path.display(), line, reason))
}

/// Merge configuration layers: file (lowest), then environment, then CLI flags (highest).
pub fn merge(file: RawConfig, env: RawConfig, cli: RawConfig) -> RawConfig {
    let mut merged = file;
    for (name, value) in env.values {
        merged.values.insert(name, value);
    }
    for (name, value) in cli.values {
        merged.values.insert(name, value);
    }
    merged
}

pub fn resolve(
    path: &Path,
    config_explicit: bool,
    cli: RawConfig,
    env: &dyn EnvSource,
) -> Result<RawConfig> {
    let file = parse_file(path, config_explicit)?;
    Ok(merge(file, env_config(env), cli))
}

pub fn default_path() -> PathBuf {
    PathBuf::from(crate::cli::DEFAULT_CONFIG)
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub key: String,
    pub listen: SocketAddr,
    pub data_bind: IpAddr,
    pub allowed_ports: (u16, u16),
    pub max_connections: u32,
    pub log_level: Level,
    pub quiet: bool,
}

#[derive(Clone, Debug)]
pub struct ExposeConfig {
    pub key: String,
    pub server: Endpoint,
    /// None specifies automatic port allocation.
    pub remote_port: Option<u16>,
    pub target: Endpoint,
    pub log_level: Level,
    pub quiet: bool,
}

fn required<'a>(raw: &'a RawConfig, name: &str) -> Result<&'a str> {
    match raw.get(name) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(AppError::Config(format!("{name} must not be empty"))),
        None => Err(AppError::Config(format!(
            "{name} is required (flag, TUNLET_{name}, or configuration file)"
        ))),
    }
}

fn quiet(raw: &RawConfig) -> Result<bool> {
    match raw.get("QUIET").unwrap_or("false") {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AppError::Config("QUIET must be true or false".to_owned())),
    }
}

fn log_level(raw: &RawConfig) -> Result<Level> {
    let value = raw.get("LOG_LEVEL").unwrap_or("info");
    Level::parse(value)
        .ok_or_else(|| AppError::Config("LOG_LEVEL must be error, info, or debug".to_owned()))
}

pub fn server(raw: &RawConfig) -> Result<ServerConfig> {
    let key = required(raw, "KEY")?.to_owned();
    let listen = net::parse_listen(raw.get("LISTEN").unwrap_or(":4000"))?;
    let data_bind = net::parse_bind_ip(raw.get("DATA_BIND").unwrap_or("0.0.0.0"))?;
    let allowed_ports = net::parse_port_range(raw.get("ALLOWED_PORTS").unwrap_or("10000-65535"))?;
    let max_connections: u32 = raw
        .get("MAX_CONNECTIONS")
        .unwrap_or("256")
        .parse()
        .map_err(|_| AppError::Config("MAX_CONNECTIONS must be an integer 1-65535".to_owned()))?;
    if max_connections == 0 || max_connections > 65535 {
        return Err(AppError::Config(
            "MAX_CONNECTIONS must be an integer 1-65535".to_owned(),
        ));
    }
    Ok(ServerConfig {
        key,
        listen,
        data_bind,
        allowed_ports,
        max_connections,
        log_level: log_level(raw)?,
        quiet: quiet(raw)?,
    })
}

pub fn expose(raw: &RawConfig) -> Result<ExposeConfig> {
    let key = required(raw, "KEY")?.to_owned();
    let server = net::parse_server(required(raw, "SERVER")?)?;
    let target = net::parse_target(required(raw, "TARGET")?)?;
    let remote_port = match raw.get("REMOTE_PORT") {
        None => None,
        Some(value) => {
            let port: u16 = value.parse().map_err(|_| {
                AppError::Config("REMOTE_PORT must be a port number 1024-65535".to_owned())
            })?;
            if port < 1024 {
                return Err(AppError::Config(
                    "REMOTE_PORT must be 1024-65535; omit it to request automatic allocation"
                        .to_owned(),
                ));
            }
            Some(port)
        }
    };
    Ok(ExposeConfig {
        key,
        server,
        remote_port,
        target,
        log_level: log_level(raw)?,
        quiet: quiet(raw)?,
    })
}
