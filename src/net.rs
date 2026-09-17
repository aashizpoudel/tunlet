//! Network address parsing, socket binding, and connection management.

use crate::error::{AppError, Result};
use socket2::{Domain, Protocol, Socket, Type as SocketType};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream, lookup_host},
    time::timeout,
};

/// An endpoint containing a host and port.
/// Outgoing addresses can use hostnames or IP literals.
/// Listener addresses must use IP literals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Format an IPv6 socket address with enclosing brackets.
pub fn display_addr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        Some((host, port))
    } else {
        let (host, port) = value.rsplit_once(':')?;
        // A bare IPv6 literal without brackets has more than one colon.
        if host.contains(':') {
            return None;
        }
        Some((host, port))
    }
}

fn parse_port(value: &str, field: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|_| AppError::Config(format!("{field} must be a port number")))
}

/// Parse the `--listen` address. Accepts `ADDR:PORT` or `:PORT` (default `0.0.0.0`).
/// The port must be between 1024 and 65535.
pub fn parse_listen(value: &str) -> Result<SocketAddr> {
    let (host, port) = if let Some(rest) = value.strip_prefix(':') {
        ("0.0.0.0", rest)
    } else {
        split_host_port(value)
            .ok_or_else(|| AppError::Config("LISTEN must be ADDR:PORT or :PORT".to_owned()))?
    };
    let ip: IpAddr = host
        .parse()
        .map_err(|_| AppError::Config("LISTEN address must be an IP literal".to_owned()))?;
    let port = parse_port(port, "LISTEN")?;
    if port < 1024 {
        return Err(AppError::Config(
            "LISTEN port must be 1024-65535".to_owned(),
        ));
    }
    Ok(SocketAddr::new(ip, port))
}

/// Parse `--data-bind`: an IP literal without a port.
pub fn parse_bind_ip(value: &str) -> Result<IpAddr> {
    value
        .parse()
        .map_err(|_| AppError::Config("DATA_BIND must be an IP literal without a port".to_owned()))
}

/// Parse `--server`: host and port (1024-65535).
pub fn parse_server(value: &str) -> Result<Endpoint> {
    let (host, port) = split_host_port(value)
        .ok_or_else(|| AppError::Config("SERVER must be HOST:PORT".to_owned()))?;
    if host.is_empty() {
        return Err(AppError::Config("SERVER must include a host".to_owned()));
    }
    let port = parse_port(port, "SERVER")?;
    if port < 1024 {
        return Err(AppError::Config(
            "SERVER port must be 1024-65535".to_owned(),
        ));
    }
    Ok(Endpoint {
        host: host.to_owned(),
        port,
    })
}

/// Parse `--target`: host and port (1-65535).
/// The syntax `:PORT` expands to `127.0.0.1:PORT`.
pub fn parse_target(value: &str) -> Result<Endpoint> {
    let (host, port) = if let Some(rest) = value.strip_prefix(':') {
        ("127.0.0.1", rest)
    } else {
        split_host_port(value)
            .ok_or_else(|| AppError::Config("TARGET must be HOST:PORT or :PORT".to_owned()))?
    };
    if host.is_empty() {
        return Err(AppError::Config("TARGET must include a host".to_owned()));
    }
    let port = parse_port(port, "TARGET")?;
    if port == 0 {
        return Err(AppError::Config("TARGET port must be 1-65535".to_owned()));
    }
    Ok(Endpoint {
        host: host.to_owned(),
        port,
    })
}

/// Parse `--allowed-ports`: range formatted as `MIN-MAX` (1024-65535).
pub fn parse_port_range(value: &str) -> Result<(u16, u16)> {
    let (min, max) = value
        .split_once('-')
        .ok_or_else(|| AppError::Config("ALLOWED_PORTS must be MIN-MAX".to_owned()))?;
    let min = parse_port(min.trim(), "ALLOWED_PORTS")?;
    let max = parse_port(max.trim(), "ALLOWED_PORTS")?;
    if min < 1024 || min > max {
        return Err(AppError::Config(
            "ALLOWED_PORTS must satisfy 1024 <= MIN <= MAX <= 65535".to_owned(),
        ));
    }
    Ok((min, max))
}

/// Bind a TCP listener to a local address.
/// IPv6 listeners bind exclusively to IPv6.
pub fn bind_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, SocketType::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // On Unix platforms, enable SO_REUSEADDR for reliable server restarts.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(std::net::TcpListener::from(socket))
}

/// Return true if the error indicates an occupied port.
pub fn is_port_taken(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}

/// Resolve DNS and connect within the specified timeout duration.
pub async fn dial(endpoint: &Endpoint, budget: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + budget;
    let host = if endpoint.host.parse::<IpAddr>().is_ok() && endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let budget_left = remaining(deadline)?;
    let addrs = timeout(budget_left, lookup_host(host))
        .await
        .map_err(|_| AppError::Runtime(format!("resolving {endpoint} timed out")))?
        .map_err(|error| AppError::Runtime(format!("resolving {endpoint} failed: {error}")))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(AppError::Runtime(format!(
            "{endpoint} resolved to no address"
        )));
    }
    let mut last: Option<io::Error> = None;
    for addr in addrs {
        let budget_left = remaining(deadline)?;
        match timeout(budget_left, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok(Err(error)) => last = Some(error),
            Err(_) => {
                return Err(AppError::Runtime(format!(
                    "connecting to {endpoint} timed out"
                )));
            }
        }
    }
    Err(AppError::Runtime(format!(
        "connecting to {endpoint} failed: {}",
        last.map(|e| e.to_string())
            .unwrap_or_else(|| "no address succeeded".to_owned())
    )))
}

/// Connect to a resolved socket address within the specified timeout duration.
pub async fn connect_addr(addr: SocketAddr, budget: Duration) -> Result<TcpStream> {
    let stream = timeout(budget, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            AppError::Runtime(format!("connecting to {} timed out", display_addr(&addr)))
        })??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let now = Instant::now();
    if now >= deadline {
        return Err(AppError::Runtime("connection budget expired".to_owned()));
    }
    Ok(deadline - now)
}

/// Return the loopback address for the specified IP address family.
pub fn loopback_for(bind: IpAddr) -> IpAddr {
    match bind {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    }
}
