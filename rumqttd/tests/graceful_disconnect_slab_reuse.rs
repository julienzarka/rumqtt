//! Regression: a graceful MQTT DISCONNECT must never tear down an unrelated,
//! newer connection.
//!
//! A client that sends DISCONNECT and then closes its socket makes the router
//! remove its connection twice: once when the DISCONNECT packet is processed,
//! and once more when the remote link sees the socket close and emits
//! `Event::Disconnect` for the same `ConnectionId`. The router keeps its
//! connections in a `Slab`, which hands a freed id to the next connection. If
//! that next connection registers between the two removals, the second one
//! disconnects it: its client sees the socket close right after a successful
//! CONNACK, before the PUBACK it is waiting for.
//!
//! Each client here does CONNECT → CONNACK → PUBLISH QoS 1 → PUBACK →
//! DISCONNECT → close, many of them at once, so freed ids are reused while
//! stale disconnect events are still in flight.
//!
//! This loop is probabilistic (about 3 drops in 2000 rounds before the fix).
//! The deterministic guard is the router unit test
//! `disconnect_tests::stale_disconnect_does_not_remove_connection_that_reused_the_id`.

use std::net::TcpListener as StdTcpListener;
use std::time::Duration;

use rumqttd::{Broker, Config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CLIENTS: usize = 2000;
const CONCURRENCY: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn start_broker(port: u16) {
    let toml = format!(
        r#"
id = 0
[router]
id = 0
max_connections = 1000
max_outgoing_packet_count = 200
max_segment_size = 104857600
max_segment_count = 10
[v4.1]
name = "v4-1"
listen = "127.0.0.1:{port}"
next_connection_delay_ms = 0
[v4.1.connections]
connection_timeout_ms = 60000
max_payload_size = 20480
max_inflight_count = 100
dynamic_filters = true
"#
    );
    let config: Config = config::Config::builder()
        .add_source(config::File::from_str(&toml, config::FileFormat::Toml))
        .build()
        .expect("build config")
        .try_deserialize()
        .expect("deserialize config");

    std::thread::spawn(move || {
        let mut broker = Broker::new(config);
        broker.start().expect("broker start");
    });
}

fn wait_for_listener(port: u16) {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "broker never listened on {port}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn connect_packet(client_id: &str) -> Vec<u8> {
    let mut variable = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c];
    variable.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    variable.extend_from_slice(client_id.as_bytes());
    let mut packet = vec![0x10, variable.len() as u8];
    packet.extend(variable);
    packet
}

fn publish_qos1_packet(topic: &str, pkid: u16, payload: &[u8]) -> Vec<u8> {
    let mut variable = Vec::new();
    variable.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    variable.extend_from_slice(topic.as_bytes());
    variable.extend_from_slice(&pkid.to_be_bytes());
    variable.extend_from_slice(payload);
    let mut packet = vec![0x32, variable.len() as u8];
    packet.extend(variable);
    packet
}

const DISCONNECT: [u8; 2] = [0xe0, 0x00];

/// Outcome of one CONNECT → PUBLISH → DISCONNECT round. The strings are read
/// through `Debug` in the failure message.
#[derive(Debug)]
#[allow(dead_code)]
enum Round {
    Ok,
    /// CONNACK arrived, then the broker closed the socket before PUBACK.
    DroppedAfterConnAck(String),
    Other(String),
}

async fn one_round(port: u16, index: usize) -> Round {
    let client_id = format!("slab-reuse-{index}");
    let mut stream = match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(s) => s,
        Err(e) => return Round::Other(format!("tcp connect: {e}")),
    };

    if let Err(e) = stream.write_all(&connect_packet(&client_id)).await {
        return Round::Other(format!("write connect: {e}"));
    }
    let mut connack = [0u8; 4];
    match tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut connack)).await {
        Ok(Ok(_)) if connack == [0x20, 0x02, 0x00, 0x00] => {}
        other => return Round::Other(format!("connack: {other:?} {connack:?}")),
    }

    if let Err(e) = stream
        .write_all(&publish_qos1_packet("slab/reuse", 1, b"x"))
        .await
    {
        return Round::DroppedAfterConnAck(format!("write publish: {e}"));
    }
    let mut puback = [0u8; 4];
    match tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut puback)).await {
        Ok(Ok(_)) if puback == [0x40, 0x02, 0x00, 0x01] => {}
        Ok(Err(e)) => return Round::DroppedAfterConnAck(format!("{client_id} read puback: {e}")),
        other => return Round::Other(format!("puback: {other:?} {puback:?}")),
    }

    // Graceful teardown: DISCONNECT, then close the socket straight away.
    stream.write_all(&DISCONNECT).await.ok();
    drop(stream);
    Round::Ok
}

#[test]
fn graceful_disconnect_never_drops_a_newer_connection() {
    let port = free_port();
    start_broker(port);
    wait_for_listener(port);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let outcomes: Vec<Round> = runtime.block_on(async move {
        let mut outcomes = Vec::with_capacity(CLIENTS);
        let mut next = 0;
        let mut inflight = tokio::task::JoinSet::new();
        while next < CLIENTS || !inflight.is_empty() {
            while next < CLIENTS && inflight.len() < CONCURRENCY {
                inflight.spawn(one_round(port, next));
                next += 1;
            }
            if let Some(joined) = inflight.join_next().await {
                outcomes.push(joined.expect("round task panicked"));
            }
        }
        outcomes
    });

    let ok = outcomes.iter().filter(|o| matches!(o, Round::Ok)).count();
    let dropped: Vec<&Round> = outcomes
        .iter()
        .filter(|o| matches!(o, Round::DroppedAfterConnAck(_)))
        .collect();
    let other: Vec<&Round> = outcomes
        .iter()
        .filter(|o| matches!(o, Round::Other(_)))
        .collect();

    println!(
        "rounds={total} ok={ok} dropped_after_connack={dropped} other={other}",
        total = outcomes.len(),
        dropped = dropped.len(),
        other = other.len(),
    );
    assert!(
        dropped.is_empty() && other.is_empty(),
        "{d} of {n} connections were dropped after CONNACK, {o} failed otherwise; first: {first:?}",
        d = dropped.len(),
        n = outcomes.len(),
        o = other.len(),
        first = dropped.first().or(other.first()),
    );
}
