use crate::link::local::{LinkError, LinkRx, LinkTx};
use crate::link::network;
use crate::link::network::Network;
use crate::local::LinkBuilder;
use crate::protocol::{ConnAck, Connect, ConnectReturnCode, Login, Packet, Protocol};
use crate::router::{Event, Notification};
use crate::{ConnectionId, ConnectionSettings};

use flume::{RecvError, SendError, Sender, TrySendError};
use std::cmp::min;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::time::error::Elapsed;
use tokio::{select, time};
use tracing::{trace, Span};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O")]
    Io(#[from] io::Error),
    #[error("Zero keep alive")]
    ZeroKeepAlive,
    #[error("Not connect packet")]
    NotConnectPacket(Packet),
    #[error("Network {0}")]
    Network(#[from] network::Error),
    #[error("Timeout")]
    Timeout(#[from] Elapsed),
    #[error("Channel send error")]
    Send(#[from] SendError<(ConnectionId, Event)>),
    #[error("Channel recv error")]
    Recv(#[from] RecvError),
    #[error("Got new session, disconnecting old one")]
    SessionEnd,
    #[error("Persistent session requires valid client id")]
    InvalidClientId,
    #[error("Unexpected router message")]
    NotConnectionAck,
    #[error("ConnAck error {0}")]
    ConnectionAck(String),
    #[error("Authentication error")]
    InvalidAuth,
    #[error("Channel try send error")]
    TrySend(#[from] TrySendError<(ConnectionId, Event)>),
    #[error("Link error = {0}")]
    Link(#[from] LinkError),
}

/// Orchestrates between Router and Network.
pub struct RemoteLink<P> {
    connect: Connect,
    pub(crate) connection_id: ConnectionId,
    network: Network<P>,
    link_tx: LinkTx,
    link_rx: LinkRx,
    notifications: VecDeque<Notification>,
    pub(crate) will_delay_interval: u32,
}

impl<P: Protocol> RemoteLink<P> {
    pub async fn new(
        router_tx: Sender<(ConnectionId, Event)>,
        tenant_id: Option<String>,
        mut network: Network<P>,
        connect_packet: Packet,
        dynamic_filters: bool,
        assigned_client_id: Option<String>,
        principal: Option<String>,
    ) -> Result<RemoteLink<P>, Error> {
        let Packet::Connect(connect, props, lastwill, lastwill_props, _) = connect_packet else {
            return Err(Error::NotConnectPacket(connect_packet));
        };

        // Register this connection with the router. Router replys with ack which if ok will
        // start the link. Router can sometimes reject the connection (ex max connection limit)
        let client_id = assigned_client_id.as_ref().unwrap_or(&connect.client_id);
        let clean_session = connect.clean_session;

        let topic_alias_max = props.as_ref().and_then(|p| p.topic_alias_max);
        let session_expiry = props
            .as_ref()
            .and_then(|p| p.session_expiry_interval)
            .unwrap_or(0);

        let delay_interval = lastwill_props
            .as_ref()
            .and_then(|f| f.delay_interval)
            .unwrap_or(0);

        // The Server delays publishing the Client’s Will Message until
        // the Will Delay Interval has passed or the Session ends, whichever happens first
        let will_delay_interval = min(session_expiry, delay_interval);

        let (link_tx, link_rx, notification) = LinkBuilder::new(client_id, router_tx)
            .tenant_id(tenant_id)
            .principal(principal)
            .clean_session(clean_session)
            .last_will(lastwill)
            .last_will_properties(lastwill_props)
            .dynamic_filters(dynamic_filters)
            .topic_alias_max(topic_alias_max.unwrap_or(0))
            .build()?;

        let id = link_rx.id();
        Span::current().record("connection_id", id);

        if let Some(mut packet) = notification.into() {
            if let Packet::ConnAck(_ack, props) = &mut packet {
                let mut new_props = props.clone().unwrap_or_default();
                new_props.assigned_client_identifier = assigned_client_id;
                *props = Some(new_props);
                network.write(packet).await?;
            }
        }

        Ok(RemoteLink {
            connect,
            connection_id: id,
            network,
            link_tx,
            link_rx,
            notifications: VecDeque::with_capacity(100),
            will_delay_interval,
        })
    }

    /// Event telling the router that this link's network connection closed.
    pub(crate) fn disconnect_event(&self) -> Event {
        self.link_tx.disconnect_event()
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        self.network.set_keepalive(self.connect.keep_alive);

        // Note:
        // Shouldn't result in bounded queue deadlocks because of blocking n/w send
        loop {
            select! {
                o = self.network.read() => {
                    let packet = o?;
                    let len = {
                        let mut buffer = self.link_tx.buffer();
                        buffer.push_back(packet);
                        self.network.readv(&mut buffer)?;
                        buffer.len()
                    };

                    trace!("Packets read from network, count = {}", len);
                    self.link_tx.notify().await?;
                }
                // Receive from router when previous when state isn't in collision
                // due to previously received data request
                o = self.link_rx.exchange(&mut self.notifications) => {
                    o?;
                    let mut packets = VecDeque::new();
                    let mut unscheduled = false;

                    for notif in self.notifications.drain(..) {
                        if let Some(packet) = notif.into() {
                            packets.push_back(packet);
                        } else {
                            unscheduled = true;
                        }

                    }
                    self.network.writev(packets).await?;
                    if unscheduled {
                        self.link_rx.wake().await?;
                    }
                }
            }
        }
    }
}

/// Read MQTT connect packet from network and verify it.
/// authentication and checks are done here.
pub async fn mqtt_connect<P>(
    config: Arc<ConnectionSettings>,
    network: &mut Network<P>,
    peer: Option<SocketAddr>,
) -> Result<(Packet, Option<String>), Error>
where
    P: Protocol,
{
    // Wait for MQTT connect packet and error out if it's not received in time to prevent
    // DOS attacks by filling total connections that the server can handle with idle open
    // connections which results in server rejecting new connections
    let connection_timeout_ms = config.connection_timeout_ms.into();
    let packet = time::timeout(Duration::from_millis(connection_timeout_ms), async {
        let packet = network.read().await?;
        Ok::<_, network::Error>(packet)
    })
    .await??;

    let (connect, _props, lastwill, login) = match packet {
        Packet::Connect(ref connect, ref props, ref lastwill, _, ref login) => {
            (connect, props, lastwill, login)
        }
        packet => return Err(Error::NotConnectPacket(packet)),
    };

    Span::current().record("client_id", &connect.client_id);

    let principal = match authenticate(&config, peer, login.as_ref(), &connect.client_id).await {
        Ok(principal) => principal,
        Err(e) => return Err(refuse(network, e).await),
    };

    // A will is published by the router after the client is gone, outside the
    // per-publish check: refuse a CONNECT whose will the principal could not
    // have published itself.
    if let (Some(access), Some(principal), Some(will)) =
        (&config.access_control, &principal, lastwill)
    {
        let topic = String::from_utf8_lossy(&will.topic);
        if !access.can_publish(principal, &topic, &will.message) {
            return Err(refuse(network, Error::InvalidAuth).await);
        }
    }

    // When keep_alive feature is disabled client can live forever, which is not good in
    // distributed broker context so currenlty we don't allow it.
    if connect.keep_alive == 0 {
        return Err(Error::ZeroKeepAlive);
    }

    let empty_client_id = connect.client_id.is_empty();
    let clean_session = connect.clean_session;

    if empty_client_id && !clean_session {
        let ack = ConnAck {
            session_present: false,
            code: ConnectReturnCode::ClientIdentifierNotValid,
        };

        let packet = Packet::ConnAck(ack, None);
        network.write(packet).await?;

        return Err(Error::InvalidClientId);
    }

    // Ok((connect, props, lastwill, lastwill_props))
    Ok((packet, principal))
}

/// Answer a refused CONNECT with CONNACK "not authorized" (return code 5, or
/// reason 0x87 on MQTT 5) before the connection closes, so the client sees a
/// refusal rather than a broker that went away. Every refusal gets the same
/// code: the client is not told whether the user or the password was wrong.
/// A failed write is ignored, because the connection is dropped either way.
async fn refuse<P: Protocol>(network: &mut Network<P>, error: Error) -> Error {
    let ack = ConnAck {
        session_present: false,
        code: ConnectReturnCode::NotAuthorized,
    };
    if let Err(e) = network.write(Packet::ConnAck(ack, None)).await {
        trace!(error = ?e, "CONNACK not authorized was not delivered");
    }
    error
}

/// Resolve the principal for a CONNECT: the embedder's [`crate::AccessControl`]
/// when installed (a CONNECT without a login is passed to it as an empty
/// username and password), else the legacy `auth` / `external_auth` check
/// (which binds no principal and refuses a CONNECT without a login when either
/// is configured).
async fn authenticate(
    config: &Arc<ConnectionSettings>,
    peer: Option<SocketAddr>,
    login: Option<&Login>,
    client_id: &str,
) -> Result<Option<String>, Error> {
    let Some(access) = &config.access_control else {
        handle_auth(config.clone(), login, client_id).await?;
        return Ok(None);
    };
    // A CONNECT without a login is the empty login: the embedder decides
    // whether it is an anonymous principal or a refusal, the same way it
    // decides for any other username it does not know.
    let (username, password) = login.map_or(("", ""), |l| (&*l.username, &*l.password));
    match access
        .authenticate_from(peer, client_id, username, password)
        .await
    {
        Some(principal) => Ok(Some(principal)),
        None => Err(Error::InvalidAuth),
    }
}

async fn handle_auth(
    config: Arc<ConnectionSettings>,
    login: Option<&Login>,
    client_id: &str,
) -> Result<(), Error> {
    if config.auth.is_none() && config.external_auth.is_none() {
        return Ok(());
    }

    // if authentication is configured and connect packet doesn't have login details
    // return an error
    let Some(login) = login else {
        return Err(Error::InvalidAuth);
    };

    let username = &login.username;
    let password = &login.password;

    if let Some(auth) = &config.external_auth {
        if !auth(
            client_id.to_owned(),
            username.to_owned(),
            password.to_owned(),
        )
        .await
        {
            return Err(Error::InvalidAuth);
        }

        return Ok(());
    }

    if let Some(pairs) = &config.auth {
        if let Some(stored_password) = pairs.get(username) {
            if stored_password.as_bytes().ct_eq(password.as_bytes()).into() {
                return Ok(());
            }
        }

        return Err(Error::InvalidAuth);
    }

    Err(Error::InvalidAuth)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use crate::{protocol::Login, ConnectionSettings};

    use super::handle_auth;

    fn config() -> ConnectionSettings {
        ConnectionSettings {
            connection_timeout_ms: 0,
            max_payload_size: 0,
            max_inflight_count: 0,
            auth: None,
            external_auth: None,
            access_control: None,
            dynamic_filters: false,
        }
    }

    fn login() -> Login {
        Login {
            username: "u".to_owned(),
            password: "p".to_owned(),
        }
    }

    #[tokio::test]
    async fn no_login_no_auth() {
        let cfg = Arc::new(config());
        let r = handle_auth(cfg, None, "").await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn some_login_no_auth() {
        let cfg = Arc::new(config());
        let login = login();
        let r = handle_auth(cfg, Some(&login), "").await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn login_matches_static_auth() {
        let login = login();
        let mut map = HashMap::<String, String>::new();
        map.insert(login.username.clone(), login.password.clone());

        let mut cfg = config();
        cfg.auth = Some(map);

        let r = handle_auth(Arc::new(cfg), Some(&login), "").await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn login_fails_static_no_external() {
        let login = login();
        let mut map = HashMap::<String, String>::new();
        map.insert("wrong".to_owned(), "wrong".to_owned());

        let mut cfg = config();
        cfg.auth = Some(map);

        let r = handle_auth(Arc::new(cfg), Some(&login), "").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn login_fails_static_matches_external() {
        let login = login();

        let mut map = HashMap::<String, String>::new();
        map.insert("wrong".to_owned(), "wrong".to_owned());

        let dynamic = |_: String, _: String, _: String| async { true };

        let mut cfg = config();
        cfg.auth = Some(map);
        cfg.set_auth_handler(dynamic);

        let r = handle_auth(Arc::new(cfg), Some(&login), "").await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn login_fails_static_fails_external() {
        let login = login();

        let mut map = HashMap::<String, String>::new();
        map.insert("wrong".to_owned(), "wrong".to_owned());

        let dynamic = |_: String, _: String, _: String| async { false };

        let mut cfg = config();
        cfg.auth = Some(map);
        cfg.set_auth_handler(dynamic);

        let r = handle_auth(Arc::new(cfg), Some(&login), "").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn external_auth_clousre_or_fnptr_type_check_or_fail_compile() {
        let closure = |_: String, _: String, _: String| async { false };
        async fn fnptr(_: String, _: String, _: String) -> bool {
            true
        }

        let mut cfg = config();
        cfg.set_auth_handler(closure);
        cfg.set_auth_handler(fnptr);
    }

    #[derive(Debug)]
    struct Fixed;

    impl crate::AccessControl for Fixed {
        fn authenticate(&self, _: &str, user: &str, pass: &str) -> crate::PrincipalFuture {
            let ok = (user == "alice" && pass == "pw").then(|| "alice".to_owned());
            Box::pin(async move { ok })
        }

        fn can_publish(&self, _: &str, _: &str, _: &[u8]) -> bool {
            true
        }

        fn can_subscribe(&self, _: &str, _: &str) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn access_control_binds_principal_and_refuses_bad_login() {
        let mut cfg = config();
        cfg.access_control = Some(Arc::new(Fixed));
        let cfg = Arc::new(cfg);

        let good = Login {
            username: "alice".to_owned(),
            password: "pw".to_owned(),
        };
        let bad = Login {
            username: "alice".to_owned(),
            password: "nope".to_owned(),
        };
        assert_eq!(
            super::authenticate(&cfg, None, Some(&good), "c")
                .await
                .unwrap(),
            Some("alice".to_owned())
        );
        assert!(super::authenticate(&cfg, None, Some(&bad), "c")
            .await
            .is_err());
        // Fixed refuses the empty login, so a login-less CONNECT is still refused.
        assert!(super::authenticate(&cfg, None, None, "c").await.is_err());
    }

    /// Admits the empty login as an anonymous principal and records what it was
    /// asked, so a test can tell "refused by the router" from "refused by the
    /// embedder".
    #[derive(Debug, Default)]
    struct Anonymous {
        asked: std::sync::Mutex<Vec<(String, String, String)>>,
    }

    impl crate::AccessControl for Anonymous {
        fn authenticate(&self, client_id: &str, user: &str, pass: &str) -> crate::PrincipalFuture {
            if let Ok(mut asked) = self.asked.lock() {
                asked.push((client_id.to_owned(), user.to_owned(), pass.to_owned()));
            }
            let principal = match (user, pass) {
                ("", "") => Some("$anon".to_owned()),
                ("alice", "pw") => Some("alice".to_owned()),
                _ => None,
            };
            Box::pin(async move { principal })
        }

        fn can_publish(&self, _: &str, _: &str, _: &[u8]) -> bool {
            true
        }

        fn can_subscribe(&self, _: &str, _: &str) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn a_login_less_connect_reaches_the_embedder_as_an_empty_login() {
        let access = Arc::new(Anonymous::default());
        let mut cfg = config();
        cfg.access_control = Some(access.clone());
        let cfg = Arc::new(cfg);

        let who = super::authenticate(&cfg, None, None, "c-1").await;
        assert_eq!(who.unwrap(), Some("$anon".to_owned()));
        assert_eq!(
            access.asked.lock().unwrap().clone(),
            vec![("c-1".to_owned(), String::new(), String::new())]
        );
    }

    #[tokio::test]
    async fn the_embedder_still_refuses_what_it_does_not_admit() {
        let mut cfg = config();
        cfg.access_control = Some(Arc::new(Anonymous::default()));
        let cfg = Arc::new(cfg);
        let bad = Login {
            username: "alice".to_owned(),
            password: "nope".to_owned(),
        };
        assert!(super::authenticate(&cfg, None, Some(&bad), "c")
            .await
            .is_err());
        let good = Login {
            username: "alice".to_owned(),
            password: "pw".to_owned(),
        };
        assert_eq!(
            super::authenticate(&cfg, None, Some(&good), "c")
                .await
                .unwrap(),
            Some("alice".to_owned())
        );
    }

    /// Without an `AccessControl` nothing changes: a login-less CONNECT is
    /// refused when `auth` or `external_auth` is configured, accepted when
    /// neither is, and in both cases binds no principal.
    #[tokio::test]
    async fn without_access_control_a_login_less_connect_keeps_the_legacy_rule() {
        let open = Arc::new(config());
        assert_eq!(
            super::authenticate(&open, None, None, "c").await.unwrap(),
            None
        );

        let mut with_static = config();
        with_static.auth = Some(HashMap::from([("u".to_owned(), "p".to_owned())]));
        assert!(super::authenticate(&Arc::new(with_static), None, None, "c")
            .await
            .is_err());

        let mut with_external = config();
        with_external.set_auth_handler(|_: String, _: String, _: String| async { true });
        assert!(
            super::authenticate(&Arc::new(with_external), None, None, "c")
                .await
                .is_err()
        );
    }

    /// Drive `mqtt_connect` over an in-memory socket and return what it
    /// decided plus the first packet the client reads back, if any.
    async fn connect_over_duplex(
        cfg: ConnectionSettings,
        login: Option<Login>,
        will: Option<crate::protocol::LastWill>,
    ) -> (
        Result<(crate::protocol::Packet, Option<String>), super::Error>,
        Option<crate::protocol::Packet>,
    ) {
        use crate::link::network::Network;
        use crate::protocol::{v4::V4, Connect, Packet};

        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client = Network::new(Box::new(client_io), 4096, 10, V4);
        let mut server = Network::new(Box::new(server_io), 4096, 10, V4);
        let connect = Connect {
            keep_alive: 30,
            client_id: "c".to_owned(),
            clean_session: true,
        };
        client
            .write(Packet::Connect(connect, None, will, None, login))
            .await
            .unwrap();

        let mut cfg = cfg;
        cfg.connection_timeout_ms = 1000;
        let decided = super::mqtt_connect(Arc::new(cfg), &mut server, None).await;
        drop(server);
        (decided, client.read().await.ok())
    }

    fn not_authorized(packet: Option<crate::protocol::Packet>) -> bool {
        matches!(
            packet,
            Some(crate::protocol::Packet::ConnAck(
                crate::protocol::ConnAck {
                    code: crate::protocol::ConnectReturnCode::NotAuthorized,
                    ..
                },
                _
            ))
        )
    }

    /// A refused CONNECT is answered with CONNACK return code 5 before the
    /// close, so a client can tell a refusal from a broker that went away.
    #[tokio::test]
    async fn a_refused_login_gets_connack_not_authorized_before_the_close() {
        let mut cfg = config();
        cfg.access_control = Some(Arc::new(Fixed));
        let bad = Login {
            username: "alice".to_owned(),
            password: "nope".to_owned(),
        };

        let (decided, reply) = connect_over_duplex(cfg, Some(bad), None).await;

        assert!(matches!(decided, Err(super::Error::InvalidAuth)));
        assert!(not_authorized(reply.clone()), "client read {reply:?}");
    }

    /// Same answer for the legacy static `auth` table, so the wire shape of a
    /// refusal does not depend on which check refused it.
    #[tokio::test]
    async fn a_refused_static_login_gets_connack_not_authorized() {
        let mut cfg = config();
        cfg.auth = Some(HashMap::from([("u".to_owned(), "p".to_owned())]));
        let bad = Login {
            username: "u".to_owned(),
            password: "wrong".to_owned(),
        };

        let (decided, reply) = connect_over_duplex(cfg, Some(bad), None).await;

        assert!(matches!(decided, Err(super::Error::InvalidAuth)));
        assert!(not_authorized(reply.clone()), "client read {reply:?}");
    }

    #[derive(Debug)]
    struct NoWill;

    impl crate::AccessControl for NoWill {
        fn authenticate(&self, _: &str, _: &str, _: &str) -> crate::PrincipalFuture {
            Box::pin(async { Some("p".to_owned()) })
        }

        fn can_publish(&self, _: &str, _: &str, _: &[u8]) -> bool {
            false
        }

        fn can_subscribe(&self, _: &str, _: &str) -> bool {
            true
        }
    }

    /// A will the principal could not publish refuses the CONNECT the same way.
    #[tokio::test]
    async fn a_refused_will_gets_connack_not_authorized() {
        let mut cfg = config();
        cfg.access_control = Some(Arc::new(NoWill));
        let will = crate::protocol::LastWill {
            topic: bytes::Bytes::from_static(b"other/topic"),
            message: bytes::Bytes::from_static(b"gone"),
            qos: crate::protocol::QoS::AtMostOnce,
            retain: false,
        };

        let (decided, reply) = connect_over_duplex(cfg, Some(login()), Some(will)).await;

        assert!(matches!(decided, Err(super::Error::InvalidAuth)));
        assert!(not_authorized(reply.clone()), "client read {reply:?}");
    }

    /// An accepted CONNECT is untouched: the CONNACK is still the router's
    /// to send, so `mqtt_connect` writes nothing.
    #[tokio::test]
    async fn an_accepted_login_writes_no_connack_here() {
        let mut cfg = config();
        cfg.access_control = Some(Arc::new(Fixed));
        let good = Login {
            username: "alice".to_owned(),
            password: "pw".to_owned(),
        };

        let (decided, reply) = connect_over_duplex(cfg, Some(good), None).await;

        assert!(decided.is_ok());
        assert!(reply.is_none(), "client read {reply:?}");
    }
}
