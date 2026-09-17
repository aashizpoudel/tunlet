//! Phase 4: ownership, allocation, replacement, reservation, reconnection, and
//! heartbeats over real sockets, with injected short timing.

mod support;

use std::time::{Duration, Instant};
use support::{
    BUDGET, ClientHandle, ControlClient, ControlError, KEY, OTHER_KEY, ServerHandle, data_connect,
    echo_target, expose_config, free_port, loopback, occupy_port, read_exact_budgeted,
    server_config,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tunlet::{auth, error::ErrorCode, protocol::Mode, timing::Timing};

fn instance() -> [u8; 16] {
    auth::random::<16>().expect("entropy")
}

fn refused(error: ControlError) -> ErrorCode {
    match error {
        ControlError::Refused(code) => code,
        ControlError::Other(message) => panic!("expected a refusal, got {message}"),
    }
}

/// True when connecting to `port` succeeds and the peer closes at once, which
/// is what a reserved listener does.
async fn accepts_then_closes(port: u16) -> bool {
    let Ok(mut socket) = TcpStream::connect(loopback(port)).await else {
        return false;
    };
    let mut buffer = [0u8; 1];
    matches!(
        timeout(Duration::from_secs(2), socket.read(&mut buffer)).await,
        Ok(Ok(0))
    )
}

async fn port_is_listening(port: u16) -> bool {
    TcpStream::connect(loopback(port)).await.is_ok()
}

// ------------------------------------------------------------ allocation --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fixed_port_outside_the_automatic_range_is_allowed() {
    let control = free_port().await;
    let outside = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let client = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, outside)
        .await
        .expect("registration");
    assert_eq!(client.assigned_port, outside);
    assert_eq!(client.max_connections, 256);

    drop(client);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_port_owned_by_another_process_is_reported_clearly() {
    let control = free_port().await;
    let taken = free_port().await;
    let guard = occupy_port(taken).await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let error = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, taken)
        .await
        .expect_err("port is occupied");
    assert_eq!(refused(error), ErrorCode::PortUnavailable);

    // The other process keeps its listener untouched.
    assert!(guard.local_addr().is_ok());
    drop(guard);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_control_port_can_never_be_requested_as_a_public_port() {
    let control = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let error = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, control)
        .await
        .expect_err("control port is reserved");
    assert_eq!(refused(error), ErrorCode::InvalidPort);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privileged_public_port_is_refused_without_a_bind_attempt() {
    let control = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let error = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, 22)
        .await
        .expect_err("privileged listener");
    assert_eq!(refused(error), ErrorCode::InvalidPort);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_allocation_climbs_and_skips_occupied_ports() {
    let control = free_port().await;
    // Find 3 consecutive ports so the range contains exactly these 3 numbers.
    let mut base = free_port().await;
    let ports = loop {
        if base <= 65532 {
            let p0 = tokio::net::TcpListener::bind(loopback(base)).await;
            let p1 = tokio::net::TcpListener::bind(loopback(base + 1)).await;
            let p2 = tokio::net::TcpListener::bind(loopback(base + 2)).await;
            if let (Ok(l0), Ok(l1), Ok(l2)) = (p0, p1, p2) {
                drop(l0);
                drop(l1);
                drop(l2);
                break [base, base + 1, base + 2];
            }
        }
        base = free_port().await;
    };
    let guard = occupy_port(ports[0]).await;

    let server =
        ServerHandle::start(server_config(control, (ports[0], ports[2])), Timing::fast()).await;

    // The lowest port is held by another process, so allocation skips it.
    let lower = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, 0)
        .await
        .expect("registration");
    assert_eq!(lower.assigned_port, ports[1]);

    // The next client takes the next free port in ascending order.
    let higher = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, 0)
        .await
        .expect("registration");
    assert_eq!(higher.assigned_port, ports[2]);

    // The range is exhausted now.
    let error = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, 0)
        .await
        .expect_err("range exhausted");
    assert_eq!(refused(error), ErrorCode::NoPortAvailable);

    drop(guard);
    drop(lower);
    drop(higher);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_allocation_never_takes_over_a_reservation() {
    let control = free_port().await;
    let low = free_port().await;
    let high = free_port().await;
    let (low, high) = (low.min(high), low.max(high));
    let server = ServerHandle::start(server_config(control, (low, high)), Timing::fast()).await;

    let first = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, 0)
        .await
        .expect("registration");
    let reserved_port = first.assigned_port;
    // An unexpected disconnect reserves the listener.
    drop(first);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let second = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, 0)
        .await
        .expect("registration");
    assert_ne!(
        second.assigned_port, reserved_port,
        "a reserved slot must not be reallocated automatically"
    );
    // The reserved listener is still bound and closes new users immediately.
    assert!(accepts_then_closes(reserved_port).await);

    drop(second);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_registered_reply_does_not_leak_a_second_automatic_port() {
    let control = free_port().await;
    let low = free_port().await;
    let high = free_port().await;
    let (low, high) = (low.min(high), low.max(high));
    let server = ServerHandle::start(server_config(control, (low, high)), Timing::fast()).await;

    let identity = instance();
    let first = ControlClient::connect(server.addr, KEY, identity, Mode::Fresh, 0)
        .await
        .expect("registration");
    let port = first.assigned_port;
    // Simulate a REGISTERED reply that never reached the client.
    drop(first);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let retry = ControlClient::connect(server.addr, KEY, identity, Mode::Fresh, 0)
        .await
        .expect("retry registration");
    assert_eq!(
        retry.assigned_port, port,
        "the same instance must reuse its slot instead of allocating another"
    );

    drop(retry);
    server.stop().await;
}

// ----------------------------------------------------------- replacement --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_processes_with_the_same_key_hold_different_ports() {
    let control = free_port().await;
    let first_port = free_port().await;
    let second_port = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let first = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, first_port)
        .await
        .expect("first");
    let second = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, second_port)
        .await
        .expect("second");
    assert_eq!(first.assigned_port, first_port);
    assert_eq!(second.assigned_port, second_port);
    assert!(port_is_listening(first_port).await && port_is_listening(second_port).await);

    drop(first);
    drop(second);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_client_replaces_the_owner_and_cancels_its_traffic() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let mut old = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("first owner");

    // Establish a forwarded connection owned by the first session.
    let mut user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = old.next_open().await.expect("open");
    let mut data = data_connect(server.addr, KEY, old.session_id, request)
        .await
        .expect("data connection");
    user.write_all(b"before").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut data, 6).await, b"before");

    // A second authenticated client takes the same port.
    let new_owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("replacement");
    assert_eq!(new_owner.assigned_port, public);

    // The displaced client is told, and its forwarded traffic ends at once.
    let frame = timeout(BUDGET, old.next_frame())
        .await
        .expect("notification timed out")
        .expect("notification frame");
    assert_eq!(frame.ty, tunlet::protocol::Type::Error);
    assert_eq!(
        tunlet::protocol::decode_error(&frame.payload).expect("error code"),
        ErrorCode::Replaced
    );
    let mut buffer = [0u8; 1];
    let read = timeout(BUDGET, data.read(&mut buffer))
        .await
        .expect("data socket should close")
        .unwrap_or(0);
    assert_eq!(read, 0, "old forwarded traffic must be cancelled");

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_session_cannot_disturb_the_new_owner() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let old = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("first owner");
    let mut new_owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("replacement");

    // The displaced connection disappearing must not release the port or
    // remove the newer session.
    drop(old);
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = new_owner.next_open().await.expect("open for the new owner");
    let mut data = data_connect(server.addr, KEY, new_owner.session_id, request)
        .await
        .expect("data connection");
    user.write_all(b"after").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut data, 5).await, b"after");

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_displaced_process_is_told_replaced_when_it_resumes() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let displaced_identity = instance();
    let displaced =
        ControlClient::connect(server.addr, KEY, displaced_identity, Mode::Fresh, public)
            .await
            .expect("first owner");
    let new_owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("replacement");
    drop(displaced);

    // The displaced process retries with its remembered port. Even though it
    // holds the shared key, it must not reclaim the tunnel in a loop.
    let error = ControlClient::connect(server.addr, KEY, displaced_identity, Mode::Resume, public)
        .await
        .expect_err("resume must be refused");
    assert_eq!(refused(error), ErrorCode::Replaced);

    drop(new_owner);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_key_is_rejected_and_changes_no_ownership() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;

    let owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let error = ControlClient::connect(server.addr, OTHER_KEY, instance(), Mode::Fresh, public)
        .await
        .expect_err("wrong key");
    assert_eq!(refused(error), ErrorCode::AuthFailed);

    // The legitimate owner is untouched.
    assert_eq!(owner.assigned_port, public);
    assert!(port_is_listening(public).await);
    drop(owner);
    server.stop().await;
}

// ---------------------------------------------------------- reservations --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unexpected_disconnect_reserves_the_listener_and_closes_new_users() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    let identity = instance();
    let mut owner = ControlClient::connect(server.addr, KEY, identity, Mode::Fresh, public)
        .await
        .expect("owner");

    // An in-flight forwarded connection ends when control is lost.
    let user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open");
    let mut data = data_connect(server.addr, KEY, owner.session_id, request)
        .await
        .expect("data connection");
    drop(owner);

    let mut buffer = [0u8; 1];
    assert_eq!(
        timeout(BUDGET, data.read(&mut buffer))
            .await
            .expect("read")
            .unwrap_or(0),
        0,
        "existing data connections end when control is lost"
    );
    drop(user);

    // While reserved, new public users are accepted and closed at once.
    assert!(accepts_then_closes(public).await);

    // The same process may reclaim its port.
    let reclaimed = ControlClient::connect(server.addr, KEY, identity, Mode::Resume, public)
        .await
        .expect("same instance reclaims its reservation");
    assert_eq!(reclaimed.assigned_port, public);

    drop(reclaimed);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reservation_expires_and_releases_the_listener() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    let owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");
    drop(owner);

    // Wait past the injected reservation, then the port is free again.
    let deadline = Instant::now() + BUDGET;
    loop {
        if !port_is_listening(public).await {
            break;
        }
        assert!(Instant::now() < deadline, "reservation never expired");
        tokio::time::sleep(timing.sweep_interval).await;
    }

    // Another process can bind it now, which proves the listener was released.
    let guard = occupy_port(public).await;
    drop(guard);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_goodbye_releases_the_port_immediately() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");
    owner
        .send(tunlet::protocol::Type::Goodbye, Vec::new())
        .await
        .expect("goodbye");

    // The acknowledgement arrives and the listener goes away without waiting
    // for a reservation.
    let deadline = Instant::now() + BUDGET;
    loop {
        if !port_is_listening(public).await {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a clean goodbye must release the listener immediately"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(Instant::now() < deadline - timing.reservation);

    server.stop().await;
}

// ------------------------------------------------------------ heartbeats --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_client_loses_its_session_to_the_heartbeat_deadline() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    let mut silent = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    // Never answer PING. The server must give up after its heartbeat deadline.
    let started = Instant::now();
    while let Ok(frame) = timeout(BUDGET, silent.next_frame())
        .await
        .expect("no timeout")
    {
        // Only heartbeats are expected while the session is idle.
        assert_eq!(frame.ty, tunlet::protocol::Type::Ping);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= timing.heartbeat_interval,
        "the session ended before a ping was even due: {elapsed:?}"
    );
    assert!(
        elapsed < timing.heartbeat_interval + timing.heartbeat_timeout * 4,
        "the session outlived its heartbeat deadline: {elapsed:?}"
    );
    // The listener is reserved, not released.
    assert!(accepts_then_closes(public).await);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heartbeats_keep_an_idle_session_and_its_traffic_alive() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    // Open a forwarded connection, then leave it completely idle for far
    // longer than the heartbeat deadline: there is no idle timeout on traffic.
    let mut user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open");
    let mut data = data_connect(server.addr, KEY, owner.session_id, request)
        .await
        .expect("data connection");

    owner.keep_alive(timing.heartbeat_interval * 6).await;

    user.write_all(b"still-here").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut data, 10).await, b"still-here");
    data.write_all(b"and-back").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut user, 8).await, b"and-back");

    server.stop().await;
}

// ------------------------------------------------------------- reconnect --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_retries_on_a_fixed_delay() {
    let timing = Timing::fast();
    // A listener that accepts and immediately closes, so every attempt fails.
    let listener = TcpListener::bind(loopback(0)).await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (times, mut observed) = tokio::sync::mpsc::channel::<Instant>(16);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            if times.send(Instant::now()).await.is_err() {
                break;
            }
            drop(socket);
        }
    });

    let (target, target_cancel) = echo_target().await;
    let client = ClientHandle::start(expose_config(addr, Some(40000), target), timing);

    let mut stamps = Vec::new();
    while stamps.len() < 4 {
        let stamp = timeout(BUDGET, observed.recv())
            .await
            .expect("attempt timed out")
            .expect("channel open");
        stamps.push(stamp);
    }
    for pair in stamps.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= timing.reconnect_delay,
            "retries must wait the fixed delay, waited {gap:?}"
        );
        assert!(
            gap < timing.reconnect_delay * 10,
            "retries must not back off, waited {gap:?}"
        );
    }

    target_cancel.cancel();
    let _ = client.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_reconnects_after_the_server_restarts() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let (target, target_cancel) = echo_target().await;

    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;
    let client = ClientHandle::start(
        expose_config(loopback(control), Some(public), target),
        timing,
    );

    // First registration works.
    wait_until_forwarding(public).await;

    // Restart the server on the same control port.
    server.stop().await;
    let restarted = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    // The client resumes its remembered port without operator action.
    wait_until_forwarding(public).await;

    target_cancel.cancel();
    let _ = client.stop().await;
    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_with_a_wrong_key_exits_instead_of_retrying() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let (target, target_cancel) = echo_target().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    let mut config = expose_config(server.addr, Some(public), target);
    config.key = OTHER_KEY.to_owned();
    let client = ClientHandle::start(config, timing);
    let result = timeout(BUDGET, client.task)
        .await
        .expect("client should exit promptly")
        .expect("no panic");
    let error = result.expect_err("a wrong key is terminal");
    assert_eq!(error.exit_code(), 3);

    target_cancel.cancel();
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_local_target_affects_only_that_request() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    // Nothing is listening on this target port.
    let dead_target = loopback(free_port().await);
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;
    let client = ClientHandle::start(
        expose_config(server.addr, Some(public), dead_target),
        timing,
    );

    wait_for_listener(public).await;
    for _ in 0..3 {
        let mut user = TcpStream::connect(loopback(public)).await.expect("user");
        let mut buffer = [0u8; 1];
        let read = timeout(BUDGET, user.read(&mut buffer))
            .await
            .expect("the request must fail promptly")
            .unwrap_or(0);
        assert_eq!(read, 0, "a failed target closes only this connection");
    }
    // The tunnel itself is still registered and listening.
    assert!(port_is_listening(public).await);

    let _ = client.stop().await;
    server.stop().await;
}

async fn wait_for_listener(port: u16) {
    let deadline = Instant::now() + BUDGET;
    while !port_is_listening(port).await {
        assert!(Instant::now() < deadline, "port {port} never opened");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wait until a full round trip through the tunnel succeeds.
async fn wait_until_forwarding(port: u16) {
    let deadline = Instant::now() + BUDGET;
    loop {
        if let Ok(mut user) = TcpStream::connect(loopback(port)).await {
            if user.write_all(b"probe").await.is_ok() {
                let mut buffer = [0u8; 5];
                if timeout(Duration::from_millis(500), user.read_exact(&mut buffer))
                    .await
                    .is_ok_and(|result| result.is_ok())
                    && &buffer == b"probe"
                {
                    return;
                }
            }
        }
        assert!(Instant::now() < deadline, "tunnel never started forwarding");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
