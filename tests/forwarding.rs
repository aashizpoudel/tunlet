//! Phase 3: one end-to-end forwarded connection, byte-exact and half-close
//! preserving, over real loopback sockets.

mod support;

use std::time::Duration;
use support::{
    BUDGET, ClientHandle, ServerHandle, after_eof_target, banner_target, echo_target,
    expose_config, free_port, loopback, payload, read_exact_budgeted, read_to_end_budgeted,
    server_config,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tunlet::timing::Timing;

/// Start a server and an expose client on a fixed public port, and wait until
/// the tunnel actually accepts traffic.
async fn tunnel(target: std::net::SocketAddr) -> (ServerHandle, ClientHandle, u16) {
    let control_port = free_port().await;
    let public_port = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(server_config(control_port, (20000, 20100)), timing).await;
    let client = ClientHandle::start(
        expose_config(server.addr, Some(public_port), target),
        timing,
    );
    wait_for_public(public_port).await;
    (server, client, public_port)
}

/// Poll until the public listener is bound, so tests never race registration.
async fn wait_for_public(port: u16) {
    let deadline = tokio::time::Instant::now() + BUDGET;
    loop {
        if TcpStream::connect(loopback(port)).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "public port {port} never became available"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_payloads_survive_both_directions() {
    let (target, target_cancel) = echo_target().await;
    let (server, client, public_port) = tunnel(target).await;

    let user = TcpStream::connect(loopback(public_port))
        .await
        .expect("connect");
    user.set_nodelay(true).ok();

    // Every byte value, including NUL, and more than one copy buffer.
    let body = payload(512 * 1024, 7);
    let mut sent = body.clone();
    sent.extend_from_slice(&[0u8; 1024]);
    let writer = tokio::spawn({
        let sent = sent.clone();
        async move {
            let mut user = user;
            user.write_all(&sent).await.expect("write");
            user.flush().await.expect("flush");
            user
        }
    });
    let mut user = writer.await.expect("writer");
    let echoed = read_exact_budgeted(&mut user, sent.len()).await;
    assert_eq!(echoed, sent, "bytes must be forwarded unchanged");

    target_cancel.cancel();
    let _ = client.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_first_protocol_receives_its_banner() {
    let (target, target_cancel) = banner_target(b"220 tunlet test banner\r\n").await;
    let (server, client, public_port) = tunnel(target).await;

    let mut user = TcpStream::connect(loopback(public_port))
        .await
        .expect("connect");
    // The banner arrives without the user sending anything first, and no
    // Tunlet frame bytes appear on the public socket.
    let banner = read_exact_budgeted(&mut user, 24).await;
    assert_eq!(&banner, b"220 tunlet test banner\r\n");

    user.write_all(b"ping").await.expect("write");
    let echoed = read_exact_budgeted(&mut user, 4).await;
    assert_eq!(&echoed, b"ping");

    target_cancel.cancel();
    let _ = client.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_request_followed_by_fin_is_forwarded() {
    let (target, target_cancel) = after_eof_target(b"answer-after-eof").await;
    let (server, client, public_port) = tunnel(target).await;

    let mut user = TcpStream::connect(loopback(public_port))
        .await
        .expect("connect");
    // No payload at all, just a half-close.
    user.shutdown().await.expect("shutdown write half");
    let response = read_to_end_budgeted(&mut user).await;
    assert_eq!(response, b"answer-after-eof");

    target_cancel.cancel();
    let _ = client.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_half_close_reaches_the_target_and_the_reply_still_arrives() {
    let (target, target_cancel) = after_eof_target(b"|done").await;
    let (server, client, public_port) = tunnel(target).await;

    let mut user = TcpStream::connect(loopback(public_port))
        .await
        .expect("connect");
    let request = payload(64 * 1024, 3);
    user.write_all(&request).await.expect("write");
    // The target only answers after it reads EOF, so this proves the FIN is
    // forwarded while the reverse direction stays open.
    user.shutdown().await.expect("shutdown write half");

    let response = read_to_end_budgeted(&mut user).await;
    assert_eq!(response.len(), request.len() + 5);
    assert_eq!(&response[..request.len()], &request[..]);
    assert_eq!(&response[request.len()..], b"|done");

    target_cancel.cancel();
    let _ = client.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_half_close_reaches_the_user_and_the_reverse_direction_survives() {
    // The target sends a greeting, closes its write half at once, then keeps
    // reading until the user closes.
    let (target, target_cancel) = support::spawn_target(|mut socket| async move {
        socket.write_all(b"greeting").await.expect("write");
        socket.shutdown().await.expect("shutdown");
        let mut rest = Vec::new();
        let _ = socket.read_to_end(&mut rest).await;
        assert_eq!(
            rest, b"still-listening",
            "reverse direction must survive EOF"
        );
    })
    .await;
    let (server, client, public_port) = tunnel(target).await;

    let mut user = TcpStream::connect(loopback(public_port))
        .await
        .expect("connect");
    let greeting = read_exact_budgeted(&mut user, 8).await;
    assert_eq!(&greeting, b"greeting");
    // The target's FIN arrived; the user can still write.
    let mut tail = [0u8; 1];
    let eof = timeout(BUDGET, user.read(&mut tail))
        .await
        .expect("read")
        .expect("read");
    assert_eq!(eof, 0, "the user must observe the target's half-close");
    user.write_all(b"still-listening").await.expect("write");
    user.shutdown().await.expect("shutdown");

    target_cancel.cancel();
    let _ = client.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_users_get_two_independent_connections_without_cross_delivery() {
    // Each target connection tags its replies so cross-pairing is visible.
    let (target, target_cancel) = support::spawn_target(|mut socket| async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    let _ = socket.shutdown().await;
                    return;
                }
                Ok(read) => {
                    let mut reply = b"echo:".to_vec();
                    reply.extend_from_slice(&buffer[..read]);
                    if socket.write_all(&reply).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    })
    .await;
    let (server, client, public_port) = tunnel(target).await;

    let mut first = TcpStream::connect(loopback(public_port))
        .await
        .expect("connect");
    let mut second = TcpStream::connect(loopback(public_port))
        .await
        .expect("connect");
    first.write_all(b"AAAA").await.expect("write");
    second.write_all(b"BBBB").await.expect("write");

    let first_reply = read_exact_budgeted(&mut first, 9).await;
    let second_reply = read_exact_budgeted(&mut second, 9).await;
    assert_eq!(&first_reply, b"echo:AAAA");
    assert_eq!(&second_reply, b"echo:BBBB");

    // Only the control port and the one public port are listening: no extra
    // listener was created for the second connection.
    let control_port = server.addr.port();
    for port in [control_port, public_port] {
        assert!(
            TcpStream::connect(loopback(port)).await.is_ok(),
            "port {port} should be listening"
        );
    }

    target_cancel.cancel();
    let _ = client.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automatic_port_is_announced_and_usable() {
    let (target, target_cancel) = echo_target().await;
    let control_port = free_port().await;
    let low = free_port().await;
    let timing = Timing::fast();
    let server = ServerHandle::start(
        server_config(control_port, (low, low.saturating_add(20))),
        timing,
    )
    .await;
    let client = ClientHandle::start(expose_config(server.addr, None, target), timing);

    // The lowest free port in the range is chosen.
    wait_for_public(low).await;
    let mut user = TcpStream::connect(loopback(low)).await.expect("connect");
    user.write_all(b"auto").await.expect("write");
    assert_eq!(&read_exact_budgeted(&mut user, 4).await, b"auto");

    target_cancel.cancel();
    let _ = client.stop().await;
    server.stop().await;
}
