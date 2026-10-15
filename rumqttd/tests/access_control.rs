//! `AccessControl` over real sockets: who may CONNECT, and what a connection
//! may publish and subscribe to once its principal is bound. Speaks raw MQTT
//! so the v3.1.1 and v5 listeners are driven the same way and nothing but the
//! broker is under test.

use std::future::Future;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::time::Duration;

use rumqttd::{AccessControl, Broker, Config, PrincipalFuture};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const IO: Duration = Duration::from_secs(5);
/// Silence long enough to call "nothing was delivered".
const QUIET: Duration = Duration::from_millis(600);

#[derive(Debug)]
struct Users;

impl AccessControl for Users {
    fn authenticate(&self, _client_id: &str, user: &str, pass: &str) -> PrincipalFuture {
        let principal = match (user, pass) {
            ("alice", "pw-a") => Some("alice".to_owned()),
            ("bob", "pw-b") => Some("bob".to_owned()),
            _ => None,
        };
        Box::pin(async move { principal })
    }

    fn can_publish(&self, principal: &str, topic: &str, _payload: &[u8]) -> bool {
        topic.starts_with(&format!("{principal}/"))
    }

    fn can_subscribe(&self, principal: &str, filter: &str) -> bool {
        filter.starts_with(&format!("{principal}/")) && !filter.contains(['#', '+'])
    }
}

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// Admits a login-less CONNECT as `$anon`, which may publish only under `anon/`.
#[derive(Debug)]
struct OpenToAnonymous;

impl AccessControl for OpenToAnonymous {
    fn authenticate(&self, _client_id: &str, user: &str, pass: &str) -> PrincipalFuture {
        let principal = match (user, pass) {
            ("", "") => Some("$anon".to_owned()),
            ("alice", "pw-a") => Some("alice".to_owned()),
            _ => None,
        };
        Box::pin(async move { principal })
    }

    fn can_publish(&self, principal: &str, topic: &str, _payload: &[u8]) -> bool {
        let root = principal.trim_start_matches('$');
        topic.starts_with(&format!("{root}/"))
    }

    fn can_subscribe(&self, principal: &str, filter: &str) -> bool {
        let root = principal.trim_start_matches('$');
        filter.starts_with(&format!("{root}/")) && !filter.contains(['#', '+'])
    }
}

/// Returns `(v4 port, v5 port)`.
fn start_broker() -> (u16, u16) {
    start_broker_with(Arc::new(Users))
}

fn start_broker_with(access: Arc<dyn AccessControl>) -> (u16, u16) {
    let (p4, p5) = (free_port(), free_port());
    let toml = format!(
        r#"
id = 0
[router]
id = 0
max_connections = 100
max_outgoing_packet_count = 200
max_segment_size = 1048576
max_segment_count = 10
[v4.1]
name = "v4-1"
listen = "127.0.0.1:{p4}"
next_connection_delay_ms = 0
[v4.1.connections]
connection_timeout_ms = 5000
max_payload_size = 20480
max_inflight_count = 100
dynamic_filters = true
[v5.1]
name = "v5-1"
listen = "127.0.0.1:{p5}"
next_connection_delay_ms = 0
[v5.1.connections]
connection_timeout_ms = 5000
max_payload_size = 20480
max_inflight_count = 100
dynamic_filters = true
"#
    );
    let mut config: Config = config::Config::builder()
        .add_source(config::File::from_str(&toml, config::FileFormat::Toml))
        .build()
        .expect("build config")
        .try_deserialize()
        .expect("deserialize config");
    config.access_control = Some(access);
    std::thread::spawn(move || {
        let mut broker = Broker::new(config);
        broker.start().expect("broker start");
    });
    let deadline = std::time::Instant::now() + IO;
    for port in [p4, p5] {
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "no listener on {port}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    (p4, p5)
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn frame(first: u8, body: Vec<u8>) -> Vec<u8> {
    assert!(body.len() < 128, "test packets are small");
    let mut p = vec![first, body.len() as u8];
    p.extend(body);
    p
}

struct Will<'a> {
    topic: &'a str,
}

fn connect(version: u8, id: &str, login: Option<(&str, &str)>, will: Option<Will>) -> Vec<u8> {
    connect_session(version, id, login, will, true)
}

fn connect_session(
    version: u8,
    id: &str,
    login: Option<(&str, &str)>,
    will: Option<Will>,
    clean: bool,
) -> Vec<u8> {
    let mut flags = if clean { 0x02 } else { 0x00 };
    if will.is_some() {
        flags |= 0x04;
    }
    if login.is_some() {
        flags |= 0xc0;
    }
    let mut b = Vec::new();
    put_str(&mut b, "MQTT");
    b.push(version);
    b.push(flags);
    b.extend_from_slice(&60u16.to_be_bytes());
    if version == 5 {
        b.push(0); // properties
    }
    put_str(&mut b, id);
    if let Some(w) = will {
        if version == 5 {
            b.push(0); // will properties
        }
        put_str(&mut b, w.topic);
        put_str(&mut b, "bye");
    }
    if let Some((u, p)) = login {
        put_str(&mut b, u);
        put_str(&mut b, p);
    }
    frame(0x10, b)
}

fn subscribe(version: u8, pkid: u16, filter: &str) -> Vec<u8> {
    let mut b = pkid.to_be_bytes().to_vec();
    if version == 5 {
        b.push(0);
    }
    put_str(&mut b, filter);
    b.push(0x01); // QoS 1
    frame(0x82, b)
}

fn publish(version: u8, topic: &str, retain: bool, payload: &str) -> Vec<u8> {
    // QoS 1 so the broker acks even when it drops the message.
    let mut b = Vec::new();
    put_str(&mut b, topic);
    b.extend_from_slice(&7u16.to_be_bytes());
    if version == 5 {
        b.push(0);
    }
    b.extend_from_slice(payload.as_bytes());
    frame(0x32 | u8::from(retain), b)
}

struct Conn(TcpStream);

impl Conn {
    async fn open(port: u16, packet: Vec<u8>) -> Option<(Conn, Vec<u8>)> {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        s.write_all(&packet).await.ok()?;
        let mut c = Conn(s);
        let connack = c.read_packet().await?;
        Some((c, connack))
    }

    /// One whole packet, or `None` on close/timeout.
    async fn read_packet(&mut self) -> Option<Vec<u8>> {
        let mut head = [0u8; 2];
        tokio::time::timeout(IO, self.0.read_exact(&mut head))
            .await
            .ok()?
            .ok()?;
        let mut body = vec![0u8; head[1] as usize];
        tokio::time::timeout(IO, self.0.read_exact(&mut body))
            .await
            .ok()?
            .ok()?;
        let mut p = head.to_vec();
        p.extend(body);
        Some(p)
    }

    async fn send(&mut self, packet: &[u8]) {
        self.0.write_all(packet).await.expect("write");
    }

    /// Next packet within `QUIET`, if any.
    async fn maybe_packet(&mut self) -> Option<Vec<u8>> {
        let mut head = [0u8; 2];
        tokio::time::timeout(QUIET, self.0.read_exact(&mut head))
            .await
            .ok()?
            .ok()?;
        let mut body = vec![0u8; head[1] as usize];
        self.0.read_exact(&mut body).await.ok()?;
        let mut p = head.to_vec();
        p.extend(body);
        Some(p)
    }
}

/// CONNACK accepted: v4 `20 02 00 00`, v5 `20 03 00 00 00`.
fn accepted(connack: &[u8]) -> bool {
    connack.first() == Some(&0x20) && connack.get(3) == Some(&0x00)
}

async fn login(port: u16, v: u8, id: &str, user: &str, pass: &str) -> Option<Conn> {
    let (c, connack) = Conn::open(port, connect(v, id, Some((user, pass)), None)).await?;
    accepted(&connack).then_some(c)
}

/// SUBACK return code of a single-filter SUBSCRIBE.
async fn suback_code(c: &mut Conn, v: u8, pkid: u16, filter: &str) -> u8 {
    c.send(&subscribe(v, pkid, filter)).await;
    let p = c.read_packet().await.expect("SUBACK");
    assert_eq!(p[0], 0x90, "expected SUBACK, got {p:?}");
    *p.last().expect("code")
}

async fn puback(c: &mut Conn) {
    let p = c.read_packet().await.expect("PUBACK");
    assert_eq!(p[0], 0x40, "expected PUBACK, got {p:?}");
}

fn run<F: Future<Output = ()>>(test: impl FnOnce(u16, u16) -> F) {
    run_with(Arc::new(Users), test);
}

fn run_with<F: Future<Output = ()>>(
    access: Arc<dyn AccessControl>,
    test: impl FnOnce(u16, u16) -> F,
) {
    let (p4, p5) = start_broker_with(access);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
        .block_on(test(p4, p5));
}

#[test]
fn a_connect_without_valid_credentials_is_refused_on_every_listener() {
    run(|p4, p5| {
        async move {
            for (port, v) in [(p4, 4u8), (p5, 5u8)] {
                // No login at all, wrong password, unknown user, empty password.
                let anon = Conn::open(port, connect(v, "c", None, None)).await;
                assert!(
                    anon.map_or(true, |(_, ack)| !accepted(&ack)),
                    "v{v} anonymous"
                );
                for (u, p) in [
                    ("alice", "nope"),
                    ("mallory", "pw-a"),
                    ("alice", ""),
                    ("", ""),
                ] {
                    assert!(login(port, v, "c", u, p).await.is_none(), "v{v} {u}:{p}");
                }
                assert!(
                    login(port, v, "c", "alice", "pw-a").await.is_some(),
                    "v{v} valid"
                );
            }
        }
    });
}

/// A CONNECT with no login reaches `AccessControl::authenticate` as an empty
/// username and password, so the embedder decides whether it is anonymous. The
/// router no longer refuses it first.
#[test]
fn a_login_less_connect_is_the_embedders_to_admit_or_refuse() {
    run_with(Arc::new(OpenToAnonymous), |p4, p5| async move {
        for (port, v) in [(p4, 4u8), (p5, 5u8)] {
            let (mut anon, ack) = Conn::open(port, connect(v, "anon-c", None, None))
                .await
                .expect("connack");
            assert!(accepted(&ack), "v{v} anonymous is admitted by the embedder");
            // Bound to `$anon`: its own subtree only.
            assert_eq!(suback_code(&mut anon, v, 1, "anon/x").await < 0x80, true);
            assert!(suback_code(&mut anon, v, 2, "alice/x").await >= 0x80);
            // A named user with the wrong password is still refused.
            assert!(login(port, v, "c", "alice", "nope").await.is_none());
            assert!(login(port, v, "c", "alice", "pw-a").await.is_some());
        }
    });
}

/// The embedder that refuses the empty login keeps the old outcome.
#[test]
fn a_login_less_connect_is_still_refused_when_the_embedder_refuses_it() {
    run(|p4, p5| async move {
        for (port, v) in [(p4, 4u8), (p5, 5u8)] {
            let anon = Conn::open(port, connect(v, "c", None, None)).await;
            assert!(anon.map_or(true, |(_, ack)| !accepted(&ack)), "v{v}");
        }
    });
}

#[test]
fn a_clean_session_reconnect_needs_credentials_again() {
    run(|p4, _| async move {
        let c = login(p4, 4, "same", "alice", "pw-a").await.expect("first");
        drop(c);
        let anon = Conn::open(p4, connect(4, "same", None, None)).await;
        assert!(anon.map_or(true, |(_, ack)| !accepted(&ack)));
    });
}

#[test]
fn a_duplicate_client_id_from_another_principal_takes_nothing_over() {
    run(|p4, _| {
        async move {
            let mut alice = login(p4, 4, "shared-id", "alice", "pw-a")
                .await
                .expect("alice");
            let _bob = login(p4, 4, "shared-id", "bob", "pw-b").await.expect("bob");

            // Alice is still connected and still alice: the router did not
            // drop her for bob's identical client id.
            alice.send(&[0xc0, 0x00]).await;
            assert_eq!(
                alice.read_packet().await,
                Some(vec![0xd0, 0x00]),
                "alice dropped"
            );
            assert_eq!(suback_code(&mut alice, 4, 1, "alice/own").await, 0x01);
        }
    });
}

#[test]
fn the_same_principal_reconnecting_does_replace_its_old_connection() {
    run(|p4, _| async move {
        let mut old = login(p4, 4, "dup", "alice", "pw-a").await.expect("old");
        let _new = login(p4, 4, "dup", "alice", "pw-a").await.expect("new");
        old.send(&[0xc0, 0x00]).await;
        assert_eq!(
            old.read_packet().await,
            None,
            "old connection must be closed"
        );
    });
}

#[test]
fn publish_is_checked_against_the_principal_on_both_protocol_versions() {
    run(|p4, p5| {
        async move {
            for (port, v) in [(p4, 4u8), (p5, 5u8)] {
                let mut alice = login(port, v, &format!("a{v}"), "alice", "pw-a")
                    .await
                    .expect("a");
                let mut bob = login(port, v, &format!("b{v}"), "bob", "pw-b")
                    .await
                    .expect("b");
                let topic = format!("alice/v{v}");
                assert_eq!(suback_code(&mut alice, v, 1, &topic).await & 0x80, 0);

                // Bob's publish into alice's namespace is acked and dropped...
                bob.send(&publish(v, &topic, false, "forged")).await;
                puback(&mut bob).await;
                // ...alice's own is delivered; nothing came before it.
                alice.send(&publish(v, &topic, false, "real")).await;
                puback(&mut alice).await;
                let got = alice.read_packet().await.expect("delivery");
                assert_eq!(got[0] & 0xf0, 0x30, "v{v}");
                assert!(
                    String::from_utf8_lossy(&got).contains("real"),
                    "v{v} {got:?}"
                );
                assert!(!String::from_utf8_lossy(&got).contains("forged"), "v{v}");
            }
        }
    });
}

#[test]
fn a_denied_retained_publish_is_never_stored_or_replayed() {
    run(|p4, _| async move {
        let mut bob = login(p4, 4, "b", "bob", "pw-b").await.expect("bob");
        bob.send(&publish(4, "alice/ret", true, "poison")).await;
        puback(&mut bob).await;

        let mut alice = login(p4, 4, "a", "alice", "pw-a").await.expect("alice");
        assert_eq!(suback_code(&mut alice, 4, 1, "alice/ret").await & 0x80, 0);
        assert!(
            alice.maybe_packet().await.is_none(),
            "forged retained replayed"
        );
    });
}

#[test]
fn subscribe_is_checked_per_filter_wildcards_included() {
    run(|p4, p5| {
        async move {
            for (port, v) in [(p4, 4u8), (p5, 5u8)] {
                let mut alice = login(port, v, &format!("s{v}"), "alice", "pw-a")
                    .await
                    .expect("a");
                // Her own namespace is fine; another's, a wildcard that would
                // cover it, a root wildcard and a shared
                // subscription are each refused, and the connection survives.
                assert_eq!(suback_code(&mut alice, v, 1, "alice/ok").await & 0x80, 0);
                for (pkid, filter) in [
                    (2, "bob/secret"),
                    (3, "#"),
                    (4, "alice/#"),
                    (5, "+/secret"),
                    (6, "$share/g/bob/secret"),
                ] {
                    assert_eq!(
                        suback_code(&mut alice, v, pkid, filter).await,
                        0x80,
                        "v{v} {filter}"
                    );
                }
                alice.send(&[0xc0, 0x00]).await;
                assert_eq!(alice.read_packet().await, Some(vec![0xd0, 0x00]));
            }
        }
    });
}

#[test]
fn a_denied_subscribe_receives_no_retained_message() {
    run(|p4, _| async move {
        let mut bob = login(p4, 4, "b", "bob", "pw-b").await.expect("bob");
        bob.send(&publish(4, "bob/secret", true, "private")).await;
        puback(&mut bob).await;

        let mut alice = login(p4, 4, "a", "alice", "pw-a").await.expect("alice");
        assert_eq!(suback_code(&mut alice, 4, 1, "bob/secret").await, 0x80);
        assert!(
            alice.maybe_packet().await.is_none(),
            "retained leaked past the ACL"
        );
    });
}

#[test]
fn a_will_outside_the_principals_namespace_refuses_the_connect() {
    run(|p4, p5| async move {
        for (port, v) in [(p4, 4u8), (p5, 5u8)] {
            let forged = connect(
                v,
                "w",
                Some(("bob", "pw-b")),
                Some(Will {
                    topic: "alice/will",
                }),
            );
            let r = Conn::open(port, forged).await;
            assert!(
                r.map_or(true, |(_, ack)| !accepted(&ack)),
                "v{v} forged will"
            );
            let own = connect(
                v,
                "w2",
                Some(("bob", "pw-b")),
                Some(Will { topic: "bob/will" }),
            );
            let (_, ack) = Conn::open(port, own).await.expect("own will");
            assert!(accepted(&ack), "v{v} own will");
        }
    });
}

#[test]
fn a_second_connect_cannot_change_the_identity_of_a_connection() {
    run(|p4, _| {
        async move {
            let mut c = login(p4, 4, "ident", "bob", "pw-b").await.expect("bob");
            let mut alice = login(p4, 4, "a", "alice", "pw-a").await.expect("alice");
            assert_eq!(suback_code(&mut alice, 4, 1, "alice/x").await & 0x80, 0);

            // Bob's socket sends a CONNECT claiming to be alice.
            c.send(&connect(4, "ident", Some(("alice", "pw-a")), None))
                .await;
            c.send(&publish(4, "alice/x", false, "as-alice")).await;
            // Acked or closed, never delivered as alice.
            let _ = c.maybe_packet().await;
            assert!(
                alice.maybe_packet().await.is_none(),
                "identity changed after CONNECT"
            );
        }
    });
}

/// CONNECT with `clean_session = false`: the CONNACK (session-present flag) and
/// the connection.
async fn persistent(port: u16, id: &str, user: &str, pass: &str) -> Option<(Conn, bool)> {
    let packet = connect_session(4, id, Some((user, pass)), None, false);
    let (c, ack) = Conn::open(port, packet).await?;
    accepted(&ack).then(|| (c, ack.get(2).is_some_and(|f| f & 1 == 1)))
}

#[test]
fn a_persistent_session_cannot_be_resumed_or_drained_by_another_principal() {
    run(|p4, _| {
        async move {
            // Alice's persistent session subscribes, then goes away.
            let (mut a, resumed) = persistent(p4, "sess", "alice", "pw-a")
                .await
                .expect("alice");
            assert!(!resumed);
            assert_eq!(suback_code(&mut a, 4, 1, "alice/q").await & 0x80, 0);
            a.send(&[0xe0, 0x00]).await;
            drop(a);

            // A message is queued for her while she is offline.
            let mut feeder = login(p4, 4, "feeder", "alice", "pw-a")
                .await
                .expect("feeder");
            feeder
                .send(&publish(4, "alice/q", false, "for-alice-only"))
                .await;
            puback(&mut feeder).await;

            // Bob connects with the same client id and clean_session = false: he
            // gets a session of his own, not hers, and none of her messages.
            let (mut b, resumed) = persistent(p4, "sess", "bob", "pw-b").await.expect("bob");
            assert!(!resumed, "bob resumed alice's session");
            assert!(
                b.maybe_packet().await.is_none(),
                "bob received alice's queued message"
            );
            // He holds none of her subscriptions either.
            feeder.send(&publish(4, "alice/q", false, "second")).await;
            puback(&mut feeder).await;
            assert!(
                b.maybe_packet().await.is_none(),
                "bob inherited alice's subscription"
            );

            // Alice still has her session and her queued messages.
            let (mut a2, resumed) = persistent(p4, "sess", "alice", "pw-a")
                .await
                .expect("alice again");
            assert!(resumed, "alice lost her own session");
            let got = a2.read_packet().await.expect("queued message");
            assert!(
                String::from_utf8_lossy(&got).contains("for-alice-only"),
                "{got:?}"
            );
        }
    });
}
