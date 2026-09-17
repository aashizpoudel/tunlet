//! Phase 2: framing, state validation, and authentication transcripts.
//!
//! Golden byte fixtures and the HMAC known answers below were produced
//! independently of this implementation (Python `hmac`/`hashlib` against the
//! plan's transcript definition and RFC 4231), so a matching encoder and
//! decoder cannot agree on a wrong answer.

use tokio::io::{AsyncWriteExt, duplex};
use tunlet::{
    auth,
    error::ErrorCode,
    protocol::{
        self, ControlChallenge, ControlHello, DataChallenge, DataHello, Frame, Kind, Mode,
        OpenFailed, OpenFailure, Registered, Type, decode_preamble, encode_preamble,
    },
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

const KEY: &[u8] = b"test-key-lauda-lasoon";
const HELLO_HEX: &str = "000102030405060708090a0b0c0d0e0f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0011cb";
const DATA_HELLO_HEX: &str = "101112131415161718191a1b1c1d1e1f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
const CONTROL_SERVER_MAC: &str = "3b6caa96cad70c1839b46c52ecb56acc4e93d2ecd5b5cfbebd28e97c7acbcea3";
const CONTROL_CLIENT_MAC: &str = "f81cae82034a2435e48e96395155283e146d7cc745e5593a54d46a551f901b51";
const CONTROL_READY_MAC: &str = "434e271b288a4f98d039bde63229eb282e7bbbfdd33f503eb2491a7e130e95a6";
const DATA_SERVER_MAC: &str = "8f6ec9034dca5a428fa3226175f90c949dbdef34a35f1dbf2dc963ec78701efe";
const DATA_CLIENT_MAC: &str = "05c80507d99e46cf7e34f9fba1831c2913e08bafe8d0de3e2c12e508076827e8";

fn fixture_hello() -> ControlHello {
    ControlHello {
        instance_id: std::array::from_fn(|index| index as u8),
        client_nonce: std::array::from_fn(|index| 0x20 + index as u8),
        mode: Mode::Fresh,
        requested_port: 4555,
    }
}

fn fixture_server_nonce() -> [u8; 32] {
    std::array::from_fn(|index| 0x40 + index as u8)
}

fn fixture_session_id() -> [u8; 16] {
    std::array::from_fn(|index| 0x10 + index as u8)
}

fn fixture_data_hello() -> DataHello {
    DataHello {
        session_id: fixture_session_id(),
        request_id: std::array::from_fn(|index| 0x60 + index as u8),
        client_nonce: std::array::from_fn(|index| 0x70 + index as u8),
    }
}

// ---------------------------------------------------------------- fixtures --

#[test]
fn hmac_known_answers_from_rfc_4231() {
    // The label is prepended to the transcript, so an empty label reproduces a
    // plain HMAC-SHA-256 over the message.
    assert_eq!(
        hex(&auth::mac(&[0x0b; 20], b"", b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&auth::mac(b"Jefe", b"", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn labels_use_one_zero_byte() {
    assert_eq!(auth::LABEL_CONTROL_SERVER.last(), Some(&0u8));
    assert!(!auth::LABEL_CONTROL_SERVER.contains(&b'\\'));
    assert_eq!(
        auth::LABEL_CONTROL_SERVER.len(),
        "tunlet/v1/control/server".len() + 1
    );
    assert_eq!(auth::LABEL_DATA_CLIENT.last(), Some(&0u8));
}

#[test]
fn control_hello_matches_its_golden_bytes() {
    assert_eq!(hex(&fixture_hello().encode()), HELLO_HEX);
    assert_eq!(
        fixture_hello().encode().len(),
        Type::ControlHello.payload_len()
    );
}

#[test]
fn control_transcript_macs_match_independent_fixtures() {
    let transcript = auth::control_transcript(
        &fixture_hello(),
        &fixture_server_nonce(),
        &fixture_session_id(),
    );
    assert_eq!(transcript.len(), 8 + 51 + 32 + 16);
    assert_eq!(
        hex(&auth::mac(KEY, auth::LABEL_CONTROL_SERVER, &transcript)),
        CONTROL_SERVER_MAC
    );
    assert_eq!(
        hex(&auth::mac(KEY, auth::LABEL_CONTROL_CLIENT, &transcript)),
        CONTROL_CLIENT_MAC
    );
    let ready = auth::ready_transcript(&transcript, 4555, 256);
    assert_eq!(
        hex(&auth::mac(KEY, auth::LABEL_CONTROL_READY, &ready)),
        CONTROL_READY_MAC
    );
}

#[test]
fn data_transcript_macs_match_independent_fixtures() {
    let hello = fixture_data_hello();
    assert_eq!(hex(&hello.encode()), DATA_HELLO_HEX);
    let server_nonce: [u8; 32] = std::array::from_fn(|index| 0x90 + index as u8);
    let transcript = auth::data_transcript(&hello, &server_nonce);
    assert_eq!(transcript.len(), 8 + 64 + 32);
    assert_eq!(
        hex(&auth::mac(KEY, auth::LABEL_DATA_SERVER, &transcript)),
        DATA_SERVER_MAC
    );
    assert_eq!(
        hex(&auth::mac(KEY, auth::LABEL_DATA_CLIENT, &transcript)),
        DATA_CLIENT_MAC
    );
}

#[test]
fn preamble_is_exactly_eight_bytes() {
    assert_eq!(hex(&encode_preamble(Kind::Control)), "5454554e01010000");
    assert_eq!(hex(&encode_preamble(Kind::Data)), "5454554e01020000");
    assert_eq!(
        decode_preamble(&encode_preamble(Kind::Data)).unwrap(),
        Kind::Data
    );
}

// ------------------------------------------------------------- validation --

#[test]
fn preamble_rejects_bad_magic_version_reserved_and_kind() {
    let mut bytes = encode_preamble(Kind::Control);
    bytes[0] = b'X';
    assert_eq!(
        decode_preamble(&bytes).unwrap_err().code,
        ErrorCode::ProtocolError
    );

    let mut bytes = encode_preamble(Kind::Control);
    bytes[4] = 2;
    assert_eq!(
        decode_preamble(&bytes).unwrap_err().code,
        ErrorCode::UnsupportedVersion
    );

    let mut bytes = encode_preamble(Kind::Control);
    bytes[7] = 1;
    assert!(
        decode_preamble(&bytes).is_err(),
        "reserved bits must be zero"
    );

    let mut bytes = encode_preamble(Kind::Control);
    bytes[5] = 9;
    assert!(decode_preamble(&bytes).is_err(), "unknown connection kind");
}

#[test]
fn every_fixed_payload_length_is_enforced() {
    let cases: &[(Type, usize)] = &[
        (Type::ControlHello, 51),
        (Type::ControlChallenge, 80),
        (Type::ControlProof, 32),
        (Type::Registered, 38),
        (Type::Open, 16),
        (Type::OpenFailed, 17),
        (Type::Ping, 8),
        (Type::Pong, 8),
        (Type::Goodbye, 0),
        (Type::GoodbyeAck, 0),
        (Type::ServerShutdown, 0),
        (Type::DataHello, 64),
        (Type::DataChallenge, 64),
        (Type::DataProof, 32),
        (Type::DataReady, 0),
        (Type::Error, 2),
    ];
    for (ty, length) in cases {
        assert_eq!(ty.payload_len(), *length, "{ty:?} payload length");
    }
}

#[test]
fn message_types_are_partitioned_by_connection_kind() {
    assert!(Type::Open.is_control() && !Type::Open.is_data());
    assert!(Type::DataHello.is_data() && !Type::DataHello.is_control());
    // ERROR is legal on both.
    assert!(Type::Error.is_control() && Type::Error.is_data());
    let frame = Frame::empty(Type::DataReady);
    assert!(frame.require_kind(Kind::Control).is_err());
    assert!(frame.require_kind(Kind::Data).is_ok());
}

#[test]
fn control_hello_rejects_invalid_mode_and_ports() {
    let mut payload = unhex(HELLO_HEX);
    payload[48] = 2;
    assert!(ControlHello::decode(&payload).is_err(), "invalid mode");

    // Resume must name a port.
    let mut payload = unhex(HELLO_HEX);
    payload[48] = 1;
    payload[49] = 0;
    payload[50] = 0;
    assert_eq!(
        ControlHello::decode(&payload).unwrap_err().code,
        ErrorCode::InvalidPort
    );

    // A privileged port is never a valid request.
    let mut payload = unhex(HELLO_HEX);
    payload[49] = 0;
    payload[50] = 22;
    assert_eq!(
        ControlHello::decode(&payload).unwrap_err().code,
        ErrorCode::InvalidPort
    );

    // Port 0 with a fresh registration means automatic allocation.
    let mut payload = unhex(HELLO_HEX);
    payload[49] = 0;
    payload[50] = 0;
    assert_eq!(ControlHello::decode(&payload).unwrap().requested_port, 0);

    // Wrong length is rejected before any field is read.
    assert!(ControlHello::decode(&payload[..50]).is_err());
}

#[test]
fn registered_rejects_privileged_port_and_zero_maximum() {
    let good = Registered {
        assigned_port: 4555,
        max_connections: 256,
        ready_mac: [7u8; 32],
    };
    assert_eq!(Registered::decode(&good.encode()).unwrap(), good);

    let mut payload = good.encode();
    payload[0] = 0;
    payload[1] = 80;
    assert_eq!(
        Registered::decode(&payload).unwrap_err().code,
        ErrorCode::InvalidPort
    );

    let mut payload = good.encode();
    payload[2..6].copy_from_slice(&0u32.to_be_bytes());
    assert!(Registered::decode(&payload).is_err(), "zero maximum");
}

#[test]
fn open_failed_rejects_unknown_reasons() {
    let message = OpenFailed {
        request_id: [3u8; 16],
        reason: OpenFailure::SetupTimeout,
    };
    assert_eq!(OpenFailed::decode(&message.encode()).unwrap(), message);
    let mut payload = message.encode();
    payload[16] = 9;
    assert!(OpenFailed::decode(&payload).is_err());
    payload[16] = 0;
    assert!(OpenFailed::decode(&payload).is_err());
}

#[test]
fn error_codes_round_trip_and_reject_unknown_values() {
    for code in [
        ErrorCode::AuthFailed,
        ErrorCode::ProtocolError,
        ErrorCode::UnsupportedVersion,
        ErrorCode::InvalidPort,
        ErrorCode::PortUnavailable,
        ErrorCode::NoPortAvailable,
        ErrorCode::Replaced,
        ErrorCode::ServerBusy,
        ErrorCode::RequestUnavailable,
        ErrorCode::InternalError,
    ] {
        let payload = code.as_u16().to_be_bytes();
        assert_eq!(protocol::decode_error(&payload).unwrap(), code);
    }
    assert!(protocol::decode_error(&11u16.to_be_bytes()).is_err());
    assert!(protocol::decode_error(&[0]).is_err());
    // Only SERVER_BUSY is retryable for a client.
    assert!(!ErrorCode::ServerBusy.is_fatal_for_client());
    assert!(ErrorCode::Replaced.is_fatal_for_client());
}

// ---------------------------------------------------------------- framing --

#[tokio::test]
async fn frames_survive_being_split_across_reads() {
    let (mut client, mut server) = duplex(4096);
    let frame = Frame::new(Type::ControlHello, unhex(HELLO_HEX));
    let bytes = frame.encode();
    let writer = tokio::spawn(async move {
        for byte in bytes {
            client.write_all(&[byte]).await.unwrap();
            client.flush().await.unwrap();
            tokio::task::yield_now().await;
        }
        client
    });
    let decoded = protocol::read_frame(&mut server).await.unwrap();
    assert_eq!(decoded, frame);
    writer.await.unwrap();
}

#[tokio::test]
async fn several_frames_in_one_write_are_read_in_order() {
    let (mut client, mut server) = duplex(4096);
    let mut bytes = Vec::new();
    bytes.extend(Frame::new(Type::Ping, 1u64.to_be_bytes().to_vec()).encode());
    bytes.extend(Frame::new(Type::Pong, 2u64.to_be_bytes().to_vec()).encode());
    bytes.extend(Frame::empty(Type::Goodbye).encode());
    client.write_all(&bytes).await.unwrap();

    assert_eq!(
        protocol::read_frame(&mut server).await.unwrap().ty,
        Type::Ping
    );
    let pong = protocol::read_frame(&mut server).await.unwrap();
    assert_eq!(protocol::decode_sequence(&pong.payload).unwrap(), 2);
    assert_eq!(
        protocol::read_frame(&mut server).await.unwrap().ty,
        Type::Goodbye
    );
}

#[tokio::test]
async fn truncated_and_empty_streams_fail_without_hanging() {
    let (mut client, mut server) = duplex(4096);
    // Header only, then EOF.
    client.write_all(&[Type::Ping as u8, 0, 8]).await.unwrap();
    drop(client);
    assert!(protocol::read_frame(&mut server).await.is_err());

    let (client, mut server) = duplex(4096);
    drop(client);
    assert!(protocol::read_frame(&mut server).await.is_err());
}

#[tokio::test]
async fn oversized_and_mismatched_lengths_are_rejected_before_allocation() {
    // Declared length beyond the 1024-byte maximum.
    let (mut client, mut server) = duplex(4096);
    client
        .write_all(&[Type::ControlHello as u8, 0xff, 0xff])
        .await
        .unwrap();
    assert!(protocol::read_frame(&mut server).await.is_err());

    // Declared length that does not match the fixed size of the type.
    let (mut client, mut server) = duplex(4096);
    client.write_all(&[Type::Ping as u8, 0, 9]).await.unwrap();
    client.write_all(&[0u8; 9]).await.unwrap();
    assert!(protocol::read_frame(&mut server).await.is_err());
}

#[tokio::test]
async fn unknown_message_types_are_rejected() {
    let (mut client, mut server) = duplex(4096);
    client.write_all(&[0x55, 0, 0]).await.unwrap();
    assert!(protocol::read_frame(&mut server).await.is_err());
}

#[tokio::test]
async fn unexpected_message_for_the_state_is_rejected() {
    let frame = Frame::empty(Type::GoodbyeAck);
    assert!(frame.require_type(Type::ControlChallenge).is_err());
    assert!(frame.require_type(Type::GoodbyeAck).is_ok());
}

// -------------------------------------------------------- authentication --

#[test]
fn a_wrong_key_never_verifies() {
    let transcript = auth::control_transcript(
        &fixture_hello(),
        &fixture_server_nonce(),
        &fixture_session_id(),
    );
    let proof = auth::mac(KEY, auth::LABEL_CONTROL_CLIENT, &transcript);
    assert!(auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &transcript,
        &proof
    ));
    assert!(!auth::verify(
        b"wrong-key",
        auth::LABEL_CONTROL_CLIENT,
        &transcript,
        &proof
    ));
}

#[test]
fn a_proof_is_bound_to_every_transcript_field() {
    let base = auth::control_transcript(
        &fixture_hello(),
        &fixture_server_nonce(),
        &fixture_session_id(),
    );
    let proof = auth::mac(KEY, auth::LABEL_CONTROL_CLIENT, &base);

    // Changed requested port.
    let mut hello = fixture_hello();
    hello.requested_port = 4556;
    let altered = auth::control_transcript(&hello, &fixture_server_nonce(), &fixture_session_id());
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &altered,
        &proof
    ));

    // Changed mode.
    let mut hello = fixture_hello();
    hello.mode = Mode::Resume;
    let altered = auth::control_transcript(&hello, &fixture_server_nonce(), &fixture_session_id());
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &altered,
        &proof
    ));

    // Changed instance identity and client nonce.
    let mut hello = fixture_hello();
    hello.instance_id[0] ^= 0xff;
    let altered = auth::control_transcript(&hello, &fixture_server_nonce(), &fixture_session_id());
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &altered,
        &proof
    ));

    let mut hello = fixture_hello();
    hello.client_nonce[31] ^= 0x01;
    let altered = auth::control_transcript(&hello, &fixture_server_nonce(), &fixture_session_id());
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &altered,
        &proof
    ));

    // Changed server nonce and session identity.
    let mut server_nonce = fixture_server_nonce();
    server_nonce[0] ^= 0x80;
    let altered = auth::control_transcript(&fixture_hello(), &server_nonce, &fixture_session_id());
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &altered,
        &proof
    ));

    let mut session_id = fixture_session_id();
    session_id[15] ^= 0x01;
    let altered = auth::control_transcript(&fixture_hello(), &fixture_server_nonce(), &session_id);
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &altered,
        &proof
    ));
}

#[test]
fn a_reflected_proof_does_not_authenticate_the_other_direction() {
    let transcript = auth::control_transcript(
        &fixture_hello(),
        &fixture_server_nonce(),
        &fixture_session_id(),
    );
    let server_proof = auth::mac(KEY, auth::LABEL_CONTROL_SERVER, &transcript);
    let client_proof = auth::mac(KEY, auth::LABEL_CONTROL_CLIENT, &transcript);
    assert_ne!(server_proof, client_proof, "labels separate the directions");
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_CLIENT,
        &transcript,
        &server_proof
    ));
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_SERVER,
        &transcript,
        &client_proof
    ));
}

#[test]
fn the_final_assignment_is_authenticated() {
    let transcript = auth::control_transcript(
        &fixture_hello(),
        &fixture_server_nonce(),
        &fixture_session_id(),
    );
    let ready = auth::ready_transcript(&transcript, 4555, 256);
    let proof = auth::mac(KEY, auth::LABEL_CONTROL_READY, &ready);
    assert!(auth::verify(KEY, auth::LABEL_CONTROL_READY, &ready, &proof));

    // A different assigned port or maximum invalidates the proof.
    let moved = auth::ready_transcript(&transcript, 4556, 256);
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_READY,
        &moved,
        &proof
    ));
    let widened = auth::ready_transcript(&transcript, 4555, 512);
    assert!(!auth::verify(
        KEY,
        auth::LABEL_CONTROL_READY,
        &widened,
        &proof
    ));
}

#[test]
fn a_captured_data_proof_fails_under_a_fresh_challenge() {
    let hello = fixture_data_hello();
    let first: [u8; 32] = std::array::from_fn(|index| 0x90 + index as u8);
    let captured = auth::mac(
        KEY,
        auth::LABEL_DATA_CLIENT,
        &auth::data_transcript(&hello, &first),
    );

    // Same visible request ID, new server nonce: the captured proof is useless.
    let second: [u8; 32] = std::array::from_fn(|index| 0x11 + index as u8);
    let fresh = auth::data_transcript(&hello, &second);
    assert!(!auth::verify(
        KEY,
        auth::LABEL_DATA_CLIENT,
        &fresh,
        &captured
    ));

    // The same challenge still accepts the same proof.
    let replayed = auth::data_transcript(&hello, &first);
    assert!(auth::verify(
        KEY,
        auth::LABEL_DATA_CLIENT,
        &replayed,
        &captured
    ));
}

#[test]
fn a_data_proof_is_bound_to_its_session_and_request() {
    let hello = fixture_data_hello();
    let server_nonce: [u8; 32] = std::array::from_fn(|index| 0x90 + index as u8);
    let proof = auth::mac(
        KEY,
        auth::LABEL_DATA_CLIENT,
        &auth::data_transcript(&hello, &server_nonce),
    );

    let mut other = hello;
    other.request_id[0] ^= 0xff;
    assert!(!auth::verify(
        KEY,
        auth::LABEL_DATA_CLIENT,
        &auth::data_transcript(&other, &server_nonce),
        &proof
    ));

    let mut other = hello;
    other.session_id[0] ^= 0xff;
    assert!(!auth::verify(
        KEY,
        auth::LABEL_DATA_CLIENT,
        &auth::data_transcript(&other, &server_nonce),
        &proof
    ));
}

#[test]
fn control_and_data_transcripts_cannot_be_confused() {
    // The preambles differ in their kind byte, and the labels differ too.
    let control = auth::control_transcript(
        &fixture_hello(),
        &fixture_server_nonce(),
        &fixture_session_id(),
    );
    let data = auth::data_transcript(&fixture_data_hello(), &fixture_server_nonce());
    assert_ne!(control[5], data[5]);
    assert_ne!(
        auth::mac(KEY, auth::LABEL_CONTROL_CLIENT, &control),
        auth::mac(KEY, auth::LABEL_DATA_CLIENT, &control)
    );
}

#[test]
fn identities_come_from_operating_system_randomness() {
    let first = auth::random::<16>().expect("entropy");
    let second = auth::random::<16>().expect("entropy");
    assert_ne!(first, second);
    assert_ne!(first, [0u8; 16]);
}

#[test]
fn challenge_payloads_round_trip() {
    let challenge = ControlChallenge {
        server_nonce: fixture_server_nonce(),
        session_id: fixture_session_id(),
        server_mac: unhex(CONTROL_SERVER_MAC).try_into().unwrap(),
    };
    assert_eq!(
        ControlChallenge::decode(&challenge.encode()).unwrap(),
        challenge
    );
    assert!(ControlChallenge::decode(&challenge.encode()[..79]).is_err());

    let data = DataChallenge {
        server_nonce: fixture_server_nonce(),
        server_mac: unhex(DATA_SERVER_MAC).try_into().unwrap(),
    };
    assert_eq!(DataChallenge::decode(&data.encode()).unwrap(), data);
    assert!(DataChallenge::decode(&data.encode()[..63]).is_err());
}
