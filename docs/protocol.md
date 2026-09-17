# Tunlet wire protocol, version 1

This document describes what `src/protocol.rs`, `src/auth.rs`, `src/server/` and `src/client/`
actually implement. All integers are unsigned big-endian. Identifiers, nonces, and MACs are
fixed-length raw bytes, never hexadecimal text. TCP is a byte stream, so every field is read
with an exact-length read; one TCP read is not one message.

## Connections

Both connection kinds go to the same server listener (default port 4000).

- **Control**: one persistent connection per expose process. Carries authentication,
  registration, open requests, heartbeats, and shutdown.
- **Data**: one connection per public connection, opened by the expose process on demand.
  After its handshake it carries nothing but application bytes.

## Preamble

Every socket begins with exactly eight bytes, sent by the client:

```text
magic[4]     = ASCII "TTUN"   (54 54 55 4e)
version:u8   = 1
kind:u8      = 1 CONTROL | 2 DATA
reserved:u16 = 0
```

A wrong magic, a nonzero reserved field, or an unknown kind is a protocol error; an unknown
version is answered with `ERROR(UNSUPPORTED_VERSION)`.

## Framing

After the preamble, every handshake and control message is:

```text
type:u8 | payload_len:u16 | payload[payload_len]
```

The maximum payload is 1024 bytes. The reader validates the declared length against both that
maximum and the fixed length of the message type **before** allocating the payload buffer, and
rejects a type that is illegal on this connection kind or in the current state. Frames are
never partially applied: a truncated frame closes the connection.

| Type | Name | Payload, in order | Length |
| --- | --- | --- | --- |
| 0x01 | CONTROL_HELLO | instance_id[16], client_nonce[32], mode:u8, requested_port:u16 | 51 |
| 0x02 | CONTROL_CHALLENGE | server_nonce[32], session_id[16], server_mac[32] | 80 |
| 0x03 | CONTROL_PROOF | client_mac[32] | 32 |
| 0x04 | REGISTERED | assigned_port:u16, max_connections:u32, ready_mac[32] | 38 |
| 0x05 | OPEN | request_id[16] | 16 |
| 0x06 | OPEN_FAILED | request_id[16], reason:u8 | 17 |
| 0x07 | PING | sequence:u64 | 8 |
| 0x08 | PONG | sequence:u64 | 8 |
| 0x09 | GOODBYE | *(empty)* | 0 |
| 0x0a | GOODBYE_ACK | *(empty)* | 0 |
| 0x0b | SERVER_SHUTDOWN | *(empty)* | 0 |
| 0x20 | DATA_HELLO | session_id[16], request_id[16], client_nonce[32] | 64 |
| 0x21 | DATA_CHALLENGE | server_nonce[32], server_mac[32] | 64 |
| 0x22 | DATA_PROOF | client_mac[32] | 32 |
| 0x23 | DATA_READY | *(empty)* | 0 |
| 0x7f | ERROR | code:u16 | 2 |

`ERROR` is legal on both connection kinds. Every other type is legal on exactly one.

`CONTROL_HELLO.mode`: `0` = fresh process registration, `1` = automatic resume.
`requested_port` may be 0 only with mode 0, meaning automatic allocation; resume must name the
remembered port. A nonzero port below 1024 is rejected with `INVALID_PORT`.

`OPEN_FAILED.reason`: `1` target connect failed, `2` setup timeout, `3` data connect or
authentication failed, `4` client capacity or shutdown. Any other value is a protocol error.

### Error codes

| Code | Name | Client treatment |
| --- | --- | --- |
| 1 | AUTH_FAILED | fatal; generic authentication failure |
| 2 | PROTOCOL_ERROR | fatal |
| 3 | UNSUPPORTED_VERSION | fatal |
| 4 | INVALID_PORT | fatal |
| 5 | PORT_UNAVAILABLE | fatal; address unavailable or already occupied |
| 6 | NO_PORT_AVAILABLE | fatal; automatic range exhausted |
| 7 | REPLACED | fatal; another process owns this tunnel |
| 8 | SERVER_BUSY | retry the control connection after 5 s |
| 9 | REQUEST_UNAVAILABLE | close this data connection only |
| 10 | INTERNAL_ERROR | fatal for control; closes the affected data connection |

An error response never contains peer-supplied text or secret bytes. Public application
sockets never receive a Tunlet frame of any kind: they get application bytes or a TCP close.

## Control authentication

`K` is the exact UTF-8 key from configuration, used without trimming. Nonces are 32 fresh
random bytes per handshake; session and instance identifiers are 16 random bytes. An instance
identifier lives for one process, a session identifier for one control connection.

```text
T = control_preamble[8]
    || CONTROL_HELLO_payload[51]
    || server_nonce[32]
    || session_id[16]

server_mac = HMAC-SHA256(K, "tunlet/v1/control/server" 0x00 || T)
client_mac = HMAC-SHA256(K, "tunlet/v1/control/client" 0x00 || T)
ready_mac  = HMAC-SHA256(K, "tunlet/v1/control/ready"  0x00
                          || T || assigned_port:u16 || max_connections:u32)
```

Each label ends with a single zero byte. Verification uses the HMAC crate's constant-time
comparison.

```text
client                          server
  |-- preamble + CONTROL_HELLO --->|
  |                                | (no port is reserved, bound, or replaced yet)
  |<---- CONTROL_CHALLENGE --------|
  | verify server_mac              |
  |------- CONTROL_PROOF --------->|
  |                                | verify client_mac, then register or replace the port
  |<-------- REGISTERED -----------|  (first message after authentication)
  | verify ready_mac, print port   |
  |<---------- OPEN --------------->  ... and heartbeats
```

No handshake creates a reservation or disturbs an existing client before `CONTROL_PROOF`
verifies. After that commit point, a lost `REGISTERED` is treated as the loss of a newly
registered session; the same instance retrying a fresh registration idempotently reclaims its
slot rather than allocating another port. The whole handshake is bounded to 10 seconds, and
trickling bytes do not extend it.

## Data handshake

The server creates a random `request_id` for each accepted public connection, stores it with
the current session generation and a deadline of accept time plus 10 seconds, and sends `OPEN`
on the owning control connection.

```text
D = data_preamble[8] || DATA_HELLO_payload[64] || server_nonce[32]

server_mac = HMAC-SHA256(K, "tunlet/v1/data/server" 0x00 || D)
client_mac = HMAC-SHA256(K, "tunlet/v1/data/client" 0x00 || D)
```

```text
client                                   server
  | dial local target (concurrently)      |
  |-- preamble + DATA_HELLO ------------->|
  |                                       | request must look pending; not consumed yet
  |<------- DATA_CHALLENGE ---------------|
  | verify server_mac                     |
  | wait for the local target to connect  |
  |--------- DATA_PROOF ----------------->|
  |                                       | verify client_mac, then claim the request
  |                                       | atomically: still pending, unexpired, and owned
  |                                       | by the current session generation
  |<--------- DATA_READY -----------------|
  |=========== raw application bytes =====|
```

A failed proof never consumes a legitimate request, and a request is consumed at most once: two
valid proofs for the same request produce exactly one `DATA_READY`, and the loser gets
`ERROR(REQUEST_UNAVAILABLE)`. Because each connection gets a fresh server nonce, a captured
proof is useless on another connection.

After `DATA_READY` there are **no** protocol frames on a data connection. Both sides use exact
unbuffered reads throughout the handshake, so no application byte adjacent to `DATA_READY` can
be swallowed by a buffer.

The client's setup budget is 10 seconds from receiving `OPEN`, and the local target dial lives
inside that budget rather than adding another 10 seconds. The server's own request deadline is
authoritative. If either dial or the authentication fails, the client closes its partial
sockets and sends `OPEN_FAILED` best-effort; a late or duplicate `OPEN_FAILED` for an already
claimed or expired request is ignored.

## Heartbeats and shutdown

Both peers send `PING` every 20 seconds, starting 20 seconds after `REGISTERED`, and reply
immediately to a received `PING` with a `PONG` carrying the same sequence. Only a matching
outstanding `PONG` satisfies the 10-second deadline; other traffic does not, and there is at
most one outstanding ping per direction.

`GOODBYE` from the client is answered with `GOODBYE_ACK` and releases the port immediately.
`SERVER_SHUTDOWN` tells clients that the server is stopping so they retry rather than exit. A
control connection that ends without `GOODBYE` reserves its public listener for five minutes.
