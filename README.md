# Tunlet

Tunlet forwards raw TCP traffic from a public server to a machine behind a NAT.
One executable provides both modes:
- `tunlet server` on the public machine
- `tunlet expose` on the private machine

The private machine initiates all connections.
The machine behind the NAT does not require an inbound firewall rule or port forwarding.

```text
Internet user 1 -- TCP --> public-server:4555 -- data connection 1 --> expose --> localhost:4556
Internet user 2 -- TCP --> public-server:4555 -- data connection 2 --> expose --> localhost:4556

expose -- persistent control connection --> public-server:4000
expose -- on-demand data connection 1 ----> public-server:4000
expose -- on-demand data connection 2 ----> public-server:4000
```

Each public connection uses a dedicated data connection.
The system forwards application bytes without modification.
The system does not add multiplexing, framing, compression, inspection, or PROXY headers after the handshake.

## Quick Start

1. On the public machine, start the server:

```sh
tunlet server --listen :4000 --key 'a-long-shared-secret'
```

2. On the machine behind the NAT, expose a local service:

```sh
tunlet expose \
  --server tunnel.example.com:4000 \
  --remote-port 4555 \
  --target 127.0.0.1:4556 \
  --key 'a-long-shared-secret'
```

Connections to `tunnel.example.com:4555` now forward to `127.0.0.1:4556` on the private machine.

To let the server allocate a port automatically, omit `--remote-port`:

```sh
tunlet expose --server tunnel.example.com:4000 --target :4556 --key 'a-long-shared-secret'
```

After each successful registration, the expose process writes one line to standard output:

```text
remote_port=4555
```

The system writes this line even if quiet mode is active.
All other output goes to standard error.

### Firewall Configuration

Only the public machine requires inbound firewall rules:

- The control port (`--listen`, default 4000) for control and data connections.
- Each public service port that you expose (for example, 4555).

The private machine does not require inbound rules.
The local target sees the expose host as its TCP peer.
The system does not preserve the source address of the remote client.

## Commands and Settings

You can specify each setting by CLI flag, by environment variable, or in a configuration file.
The order of precedence is:

1. Command-line flags (highest)
2. `TUNLET_*` environment variables
3. Configuration file
4. Default values (lowest)

| Flag | Config / Environment Name | Mode | Description and Limits |
| --- | --- | --- | --- |
| `--config PATH` | *(CLI only)* | both | Path to configuration file. Default: `./tunlet.cfg`. |
| `--key TEXT` | `KEY` / `TUNLET_KEY` | both | Required. Shared secret key. Cannot be empty. |
| `--listen ADDR` | `LISTEN` | server | Listener address. Default: `:4000`. Valid ports: 1024-65535. |
| `--data-bind IP` | `DATA_BIND` | server | IP address for public listeners. Default: `0.0.0.0`. |
| `--allowed-ports MIN-MAX` | `ALLOWED_PORTS` | server | Automatic port range. Default: `10000-65535`. Limits: 1024-65535. |
| `--max-connections N` | `MAX_CONNECTIONS` | server | Maximum connections per tunnel. Default: `256`. Limits: 1-65535. |
| `--server HOST:PORT` | `SERVER` | expose | Required. Server address and control port (1024-65535). |
| `--remote-port PORT` | `REMOTE_PORT` | expose | Optional public port (1024-65535). Omit for automatic assignment. |
| `--target HOST:PORT` | `TARGET` | expose | Required. Local target address and port (1-65535). |
| `--log-level LEVEL` | `LOG_LEVEL` | both | Log level: `error`, `info`, or `debug`. Default: `info`. |
| `--quiet[=BOOL]` | `QUIET` | both | Suppress routine logs. Default: `false`. |

### Usage Notes

- `:PORT` expands to `0.0.0.0:PORT` for `--listen` and `127.0.0.1:PORT` for `--target`.
- Enclose IPv6 addresses in brackets: `--listen '[::1]:4000'`, `--target '[::1]:4556'`.
- An IPv6 listener does not accept IPv4 connections.
- The `--allowed-ports` range applies only to automatic allocation.
- Listener ports must be 1024 or higher. The system does not open privileged ports.
- The local target can use any port, including port 22.
- The `--quiet` flag defaults to `--quiet=true`. Use `--quiet=false` to disable an inherited quiet setting.
- The system accepts both `--flag value` and `--flag=value` syntax.
- If you repeat a flag, the system uses the last value.
- You can place `--config` before or after the subcommand.
- The `--help` and `--version` commands do not require a key or a configuration file.

### Configuration File Format

The default configuration file is `./tunlet.cfg`.
Use `--config PATH` to specify a different path.
The file uses a key-value format:

```dotenv
# server.cfg
LISTEN=:4000
DATA_BIND=0.0.0.0
ALLOWED_PORTS=10000-65535
MAX_CONNECTIONS=256
KEY=replace-this-example
LOG_LEVEL=info
```

```dotenv
# expose.cfg
SERVER=tunnel.example.com:4000
REMOTE_PORT=4555
TARGET=127.0.0.1:4556
KEY=replace-this-example
```

File Rules:
- Encode files in UTF-8. The parser supports an optional byte order mark (BOM).
- The parser supports both LF and CRLF line endings.
- Blank lines and comment lines starting with `#` are ignored.
- Lines use the `NAME=value` format. The parser trims surrounding whitespace.
- Names in the file must not include the `TUNLET_` prefix.
- Keys belonging to the other mode are ignored without error.
- Enclose values in single or double quotes to preserve special characters.
- If a key is repeated, the parser uses the last occurrence.
- If the default `./tunlet.cfg` file is absent, the program continues.
- If an explicitly specified `--config` file is absent or invalid, the program terminates with an error.

Example files are available in the [`examples/`](examples) directory.

## System Behavior

### Ownership and Replacement

- A client with the correct key can register or replace tunnel ports.
- If a client requests an active port with the correct key, the server disconnects the existing client.
- The displaced client receives a `REPLACED` error and terminates.
- If a non-Tunlet process occupies a port, the request fails with an error.
- Automatic allocation selects the lowest available port in the `--allowed-ports` range.
- If a control connection disconnects unexpectedly, the server reserves the public port for 5 minutes.
- During this reservation, new incoming connections close immediately.
- The same expose client can reconnect during the reservation to restore the tunnel.
- An orderly shutdown (Ctrl-C or SIGTERM) sends a `GOODBYE` message and releases the port immediately.
- If you restart expose without `--remote-port`, the server allocates a new port.

### Timeouts and Heartbeats

The system uses fixed timeouts:

| Operation | Duration | Behavior |
| --- | --- | --- |
| Handshake and control connect | 10 s | Includes DNS resolution time. |
| Reconnect delay | 5 s | Fixed interval. No backoff. |
| Heartbeat interval / timeout | 20 s / 10 s | Both directions send and monitor pings. |
| Public connection wait | 10 s | Time to establish the matching data connection. |
| Target connect | 10 s | Limit to connect to the local service. |
| Disconnect reservation | 5 min | Preserves listener for client reconnection. |
| Server shutdown | 5 s | Closes connections and releases listeners. |

Established forwarded connections do not have an idle timeout.
Connections remain open as long as the application endpoints remain connected.

### Logging and Exit Codes

Logs go to standard error.
The system does not log secret keys or full configuration structures.

| Exit Code | Description |
| --- | --- |
| 0 | Clean shutdown, `--help`, or `--version`. |
| 2 | Command-line argument or configuration syntax error. |
| 3 | Authentication, protocol, or registration failure. |
| 1 | Unhandled runtime error. |

## Security Considerations

Tunlet authenticates handshakes with HMAC-SHA-256 challenge-response using the shared secret key.
Both endpoints verify mutual authentication.
Each data connection authenticates a single-use request identifier with random nonces to prevent replay attacks.

**Application traffic is not encrypted:**

- HMAC verifies the key during handshake. It does not encrypt subsequent data.
- Use a strong, random key to prevent offline brute-force attacks.
- Tunnel protocols that provide native encryption (such as HTTPS or SSH) to secure application data.

## Service Configuration

### systemd (Linux)

Save this file as `/etc/systemd/system/tunlet-server.service`:

```ini
[Unit]
Description=Tunlet server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/tunlet server --config /etc/tunlet/server.cfg
Restart=always
RestartSec=5
User=tunlet
Group=tunlet
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Use a similar unit configuration for `tunlet expose`.
The `systemctl stop` command sends SIGTERM for a clean shutdown.

### launchd (macOS)

Save this file as `~/Library/LaunchAgents/com.example.tunlet.expose.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.tunlet.expose</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/tunlet</string>
    <string>expose</string>
    <string>--config</string>
    <string>/usr/local/etc/tunlet/expose.cfg</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/usr/local/var/log/tunlet.log</string>
</dict>
</plist>
```

### Windows Service

Run the binary under a service manager (such as `sc.exe` or Task Scheduler).
Set `--config` to a protected file accessible only by the service account.

## Build Instructions

```sh
cargo build --locked --release
```

The toolchain is defined in `rust-toolchain.toml`.
For protocol specifications, refer to [`docs/protocol.md`](docs/protocol.md).
