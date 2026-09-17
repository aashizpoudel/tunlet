//! Phase 5: bounds, races, deadlines, shutdown, and IPv6.

mod support;

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use support::{
    BUDGET, ClientHandle, ControlClient, KEY, ServerHandle, data_attempt, data_connect,
    echo_target, expose_config, free_port, loopback, read_exact_budgeted, server_config,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tunlet::{
    auth,
    error::ErrorCode,
    protocol::{self, DataHello, Frame, Kind, Mode, Type},
    server::registry,
    timing::Timing,
};

fn instance() -> [u8; 16] {
    auth::random::<16>().expect("entropy")
}

async fn closed_promptly(socket: &mut TcpStream) -> bool {
    let mut buffer = [0u8; 1];
    matches!(
        timeout(BUDGET, socket.read(&mut buffer)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

// ------------------------------------------------------------ claim races --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_one_of_two_valid_proofs_claims_a_request() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;
    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let _user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open");

    // Two well-formed data connections race for the same request.
    let session = owner.session_id;
    let addr = server.addr;
    let first = tokio::spawn(async move { data_attempt(addr, KEY, session, request, true).await });
    let second = tokio::spawn(async move { data_attempt(addr, KEY, session, request, true).await });
    let (first, second) = (first.await.expect("task"), second.await.expect("task"));

    let winners = [&first.1, &second.1].iter().filter(|r| r.is_ok()).count();
    assert_eq!(winners, 1, "a request is consumed exactly once");
    let loser = [first.1, second.1]
        .into_iter()
        .find_map(|result| result.err())
        .expect("one must lose");
    assert_eq!(loser, ErrorCode::RequestUnavailable);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_captured_proof_is_useless_on_another_connection() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;
    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let _user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open");

    // Capture a valid proof by running the handshake once.
    let mut first = TcpStream::connect(server.addr).await.expect("connect");
    protocol::write_preamble(&mut first, Kind::Data)
        .await
        .expect("preamble");
    let hello = DataHello {
        session_id: owner.session_id,
        request_id: request,
        client_nonce: auth::random::<32>().expect("entropy"),
    };
    protocol::write_frame(&mut first, &Frame::new(Type::DataHello, hello.encode()))
        .await
        .expect("hello");
    let challenge = protocol::read_frame(&mut first).await.expect("challenge");
    let decoded = protocol::DataChallenge::decode(&challenge.payload).expect("decode");
    let captured = auth::mac(
        KEY.as_bytes(),
        auth::LABEL_DATA_CLIENT,
        &auth::data_transcript(&hello, &decoded.server_nonce),
    );

    // Replay it on a second connection, which gets a fresh server nonce.
    let mut second = TcpStream::connect(server.addr).await.expect("connect");
    protocol::write_preamble(&mut second, Kind::Data)
        .await
        .expect("preamble");
    protocol::write_frame(&mut second, &Frame::new(Type::DataHello, hello.encode()))
        .await
        .expect("hello");
    let _ = protocol::read_frame(&mut second).await.expect("challenge");
    protocol::write_frame(&mut second, &Frame::new(Type::DataProof, captured.to_vec()))
        .await
        .expect("proof");
    let response = protocol::read_frame(&mut second).await.expect("response");
    assert_eq!(response.ty, Type::Error);
    assert_eq!(
        protocol::decode_error(&response.payload).expect("code"),
        ErrorCode::AuthFailed
    );

    // The legitimate connection still owns the request.
    protocol::write_frame(&mut first, &Frame::new(Type::DataProof, captured.to_vec()))
        .await
        .expect("proof");
    let ready = protocol::read_frame(&mut first).await.expect("ready");
    assert_eq!(ready.ty, Type::DataReady);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invalid_proof_never_consumes_the_request() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;
    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let mut user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open");

    // A wrong proof is refused.
    let mut attacker = TcpStream::connect(server.addr).await.expect("connect");
    protocol::write_preamble(&mut attacker, Kind::Data)
        .await
        .expect("preamble");
    let hello = DataHello {
        session_id: owner.session_id,
        request_id: request,
        client_nonce: auth::random::<32>().expect("entropy"),
    };
    protocol::write_frame(&mut attacker, &Frame::new(Type::DataHello, hello.encode()))
        .await
        .expect("hello");
    let _ = protocol::read_frame(&mut attacker)
        .await
        .expect("challenge");
    protocol::write_frame(&mut attacker, &Frame::new(Type::DataProof, vec![0u8; 32]))
        .await
        .expect("proof");
    let response = protocol::read_frame(&mut attacker).await.expect("response");
    assert_eq!(
        protocol::decode_error(&response.payload).expect("code"),
        ErrorCode::AuthFailed
    );

    // The real client can still complete the same request.
    let mut data = data_connect(server.addr, KEY, owner.session_id, request)
        .await
        .expect("legitimate claim");
    user.write_all(b"ok").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut data, 2).await, b"ok");

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_expires_and_a_late_proof_is_refused() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;
    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let mut user = TcpStream::connect(loopback(public)).await.expect("user");
    let started = Instant::now();
    let request = owner.next_open().await.expect("open");

    // Nobody claims the request, so the public connection is closed when its
    // deadline passes. The control session is kept healthy meanwhile, so the
    // expiry is what closes the socket, not a lost session.
    let (closed, ()) = tokio::join!(
        closed_promptly(&mut user),
        owner.keep_alive(timing.request_wait + Duration::from_millis(200))
    );
    assert!(closed);
    let elapsed = started.elapsed();
    assert!(
        elapsed < timing.request_wait * 2,
        "the public wait must not stack deadlines: {elapsed:?}"
    );

    let (_, outcome) = data_attempt(server.addr, KEY, owner.session_id, request, true).await;
    assert_eq!(outcome.unwrap_err(), ErrorCode::RequestUnavailable);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_from_a_replaced_session_is_refused() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;
    let mut old = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let _user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = old.next_open().await.expect("open");

    let new_owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("replacement");

    let (_, outcome) = data_attempt(server.addr, KEY, old.session_id, request, true).await;
    assert_eq!(
        outcome.unwrap_err(),
        ErrorCode::RequestUnavailable,
        "a replaced session's request namespace is gone"
    );

    drop(new_owner);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_session_or_request_is_refused() {
    let control = free_port().await;
    let public = free_port().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), Timing::fast()).await;
    let owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let (_, outcome) = data_attempt(server.addr, KEY, [9u8; 16], [8u8; 16], true).await;
    assert_eq!(outcome.unwrap_err(), ErrorCode::RequestUnavailable);

    let (_, outcome) = data_attempt(server.addr, KEY, owner.session_id, [8u8; 16], true).await;
    assert_eq!(outcome.unwrap_err(), ErrorCode::RequestUnavailable);

    server.stop().await;
}

// ----------------------------------------------------------------- limits --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_connections_count_toward_the_per_tunnel_maximum() {
    let control = free_port().await;
    let public = free_port().await;
    let mut config = server_config(control, (20000, 20010));
    config.max_connections = 2;
    let server = ServerHandle::start(config, Timing::fast()).await;
    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");
    assert_eq!(owner.max_connections, 2);

    // Two pending requests fill the tunnel even though neither is forwarding.
    let _first = TcpStream::connect(loopback(public)).await.expect("user");
    let _second = TcpStream::connect(loopback(public)).await.expect("user");
    let mut third = TcpStream::connect(loopback(public)).await.expect("user");

    // The third is closed promptly rather than queued.
    assert!(closed_promptly(&mut third).await);

    // Exactly two OPEN messages were issued; the third connection got none.
    let _ = owner.next_open().await.expect("first open");
    let _ = owner.next_open().await.expect("second open");
    let extra = timeout(Duration::from_millis(200), owner.next_open()).await;
    assert!(extra.is_err(), "the over-limit connection must get no OPEN");
    // The cancelled read above may have consumed part of a heartbeat frame, so
    // this control connection is not used again.

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_permit_returns_after_a_request_succeeds_and_after_one_expires() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let mut config = server_config(control, (20000, 20010));
    config.max_connections = 1;
    let server = ServerHandle::start(config, timing).await;
    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    // A completed request releases its permit.
    let mut user = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open");
    let mut data = data_connect(server.addr, KEY, owner.session_id, request)
        .await
        .expect("data connection");
    user.write_all(b"one").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut data, 3).await, b"one");
    drop(user);
    drop(data);
    // At a maximum of one connection, the next request needs the previous
    // permit back, which happens when the forwarding task finishes.
    owner.keep_alive(Duration::from_millis(200)).await;

    let mut second = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open after success");
    let mut data = data_connect(server.addr, KEY, owner.session_id, request)
        .await
        .expect("data connection");
    second.write_all(b"two").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut data, 3).await, b"two");
    drop(second);
    drop(data);
    owner.keep_alive(Duration::from_millis(200)).await;

    // An expired request releases its permit too: this one is never answered.
    let mut abandoned = TcpStream::connect(loopback(public)).await.expect("user");
    let _ = owner.next_open().await.expect("open");
    // Heartbeats are answered while the request expires, so the permit is
    // released by the expiry rather than by a lost session.
    let (closed, ()) = tokio::join!(
        closed_promptly(&mut abandoned),
        owner.keep_alive(timing.request_wait + Duration::from_millis(200))
    );
    assert!(closed);
    owner.keep_alive(Duration::from_millis(100)).await;

    let mut third = TcpStream::connect(loopback(public)).await.expect("user");
    let request = owner.next_open().await.expect("open after expiry");
    let mut data = data_connect(server.addr, KEY, owner.session_id, request)
        .await
        .expect("data connection");
    third.write_all(b"three").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut data, 5).await, b"three");

    server.stop().await;
}

#[test]
fn the_fixed_global_bounds_match_the_specification() {
    assert_eq!(registry::MAX_HANDSHAKES, 1024);
    assert_eq!(registry::MAX_SLOTS, 1024);
    assert_eq!(registry::MAX_GLOBAL_CONNECTIONS, 8192);
    assert_eq!(registry::COMMAND_CAPACITY, 1024);
    assert_eq!(registry::WRITER_CAPACITY, 512);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_tunnel_does_not_disturb_another_one() {
    let control = free_port().await;
    let good_port = free_port().await;
    let bad_port = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;

    let (target, target_cancel) = echo_target().await;
    let good = ClientHandle::start(expose_config(server.addr, Some(good_port), target), timing);
    // This client's target does not exist.
    let dead = loopback(free_port().await);
    let bad = ClientHandle::start(expose_config(server.addr, Some(bad_port), dead), timing);

    // Wait for both tunnels to be listening.
    for port in [good_port, bad_port] {
        let deadline = Instant::now() + BUDGET;
        while TcpStream::connect(loopback(port)).await.is_err() {
            assert!(Instant::now() < deadline, "tunnel on {port} never opened");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // Repeated failures on one tunnel do not affect the other.
    for _ in 0..3 {
        let mut failing = TcpStream::connect(loopback(bad_port)).await.expect("user");
        assert!(closed_promptly(&mut failing).await);
    }
    let mut working = TcpStream::connect(loopback(good_port)).await.expect("user");
    working.write_all(b"unaffected").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut working, 10).await, b"unaffected");

    target_cancel.cancel();
    let _ = good.stop().await;
    let _ = bad.stop().await;
    server.stop().await;
}

// --------------------------------------------------------------- shutdown --

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_shutdown_notifies_clients_and_releases_listeners() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;
    let mut owner = ControlClient::connect(server.addr, KEY, instance(), Mode::Fresh, public)
        .await
        .expect("owner");

    let started = Instant::now();
    server.cancel.cancel();

    // The client is told to expect a shutdown rather than a failure.
    let mut saw_shutdown = false;
    while let Ok(frame) = owner.next_frame().await {
        if frame.ty == Type::ServerShutdown {
            saw_shutdown = true;
            break;
        }
    }
    assert!(
        saw_shutdown,
        "clients must be notified before the socket closes"
    );

    let result = timeout(BUDGET, server.task)
        .await
        .expect("shutdown timed out");
    result.expect("no panic").expect("clean shutdown");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown must complete within five seconds"
    );

    // Every listener is released.
    assert!(TcpStream::connect(loopback(public)).await.is_err());
    assert!(TcpStream::connect(loopback(control)).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_retries_after_an_orderly_server_shutdown() {
    let control = free_port().await;
    let public = free_port().await;
    let timing = Timing::fast();
    let (target, target_cancel) = echo_target().await;
    let server = ServerHandle::start(server_config(control, (20000, 20010)), timing).await;
    let client = ClientHandle::start(
        expose_config(loopback(control), Some(public), target),
        timing,
    );

    let deadline = Instant::now() + BUDGET;
    while TcpStream::connect(loopback(public)).await.is_err() {
        assert!(Instant::now() < deadline, "tunnel never opened");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    server.stop().await;
    // The client keeps running: an orderly shutdown is retryable, not fatal.
    tokio::time::sleep(timing.reconnect_delay * 3).await;
    assert!(!client.task.is_finished(), "the client must not exit");

    target_cancel.cancel();
    let _ = client.stop().await;
}

#[cfg(unix)]
#[test]
fn the_binary_stops_on_sigterm_within_the_grace_period() {
    use std::{
        process::{Command, Stdio},
        thread,
        time::Duration as StdDuration,
    };

    // A concrete free port, chosen the way the other fixtures do.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let mut child = Command::new(env!("CARGO_BIN_EXE_tunlet"))
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--key",
            "test-key",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    // Wait for the listener.
    let mut ready = false;
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(StdDuration::from_millis(25));
    }
    assert!(ready, "server never started listening");

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(status.success());

    let started = Instant::now();
    let exit = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None => {
                assert!(
                    started.elapsed() < StdDuration::from_secs(5),
                    "SIGTERM must stop the server within five seconds"
                );
                thread::sleep(StdDuration::from_millis(25));
            }
        }
    };
    assert_eq!(exit.code(), Some(0), "a signalled shutdown is clean");
}

// ------------------------------------------------------------------ IPv6 --

/// IPv6 loopback is not available on every execution host. When it is missing
/// the test reports an explicit skip instead of claiming a pass.
async fn ipv6_available() -> bool {
    TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .await
        .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_control_public_and_target_paths_work() {
    if !ipv6_available().await {
        eprintln!(
            "SKIPPED ipv6_control_public_and_target_paths_work: no IPv6 loopback on this host"
        );
        return;
    }
    let timing = Timing::fast();
    // An IPv6 target.
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .await
        .expect("bind IPv6 target");
    let target = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 1024];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let control_port = free_port().await;
    let public_port = free_port().await;
    let mut config = server_config(control_port, (20000, 20010));
    config.listen = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), control_port);
    config.data_bind = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let server = ServerHandle::start(config, timing).await;
    assert!(server.addr.is_ipv6());

    let client = ClientHandle::start(
        expose_config(server.addr, Some(public_port), target),
        timing,
    );

    let public = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), public_port);
    let deadline = Instant::now() + BUDGET;
    let mut user = loop {
        if let Ok(socket) = TcpStream::connect(public).await {
            break socket;
        }
        assert!(Instant::now() < deadline, "IPv6 tunnel never opened");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    user.write_all(b"v6").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut user, 2).await, b"v6");

    let _ = client.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ipv6_listener_does_not_serve_ipv4() {
    if !ipv6_available().await {
        eprintln!("SKIPPED an_ipv6_listener_does_not_serve_ipv4: no IPv6 loopback on this host");
        return;
    }
    let control_port = free_port().await;
    let mut config = server_config(control_port, (20000, 20010));
    config.listen = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), control_port);
    config.data_bind = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let server = ServerHandle::start(config, Timing::fast()).await;

    // Binding the same port on IPv4 proves the IPv6 listener is IPv6-only.
    let ipv4 = TcpListener::bind(loopback(control_port)).await;
    assert!(
        ipv4.is_ok(),
        "an IPv6 wildcard listener must not claim the IPv4 port as well"
    );
    drop(ipv4);
    server.stop().await;
}
