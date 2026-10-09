//! Embedder-supplied authentication and publish authorization.
//!
//! The router has no notion of users. An embedder that needs per-client
//! topic rules installs an [`AccessControl`] on [`crate::Config`]: it maps a
//! CONNECT's credentials to a *principal*, and the router then asks it whether
//! that principal may publish each message. In-process links (the embedder's
//! own `LinkBuilder` links) carry no principal and are never checked.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Resolves to the authenticated principal, or `None` to refuse the CONNECT.
pub type PrincipalFuture = Pin<Box<dyn Future<Output = Option<String>> + Send>>;

pub trait AccessControl: Send + Sync + fmt::Debug {
    /// Authenticate a CONNECT. `Some(principal)` admits the client and binds
    /// that principal to the connection for its lifetime.
    fn authenticate(&self, client_id: &str, username: &str, password: &str) -> PrincipalFuture;

    /// May `principal` publish `payload` on `topic`? A `false` drops the
    /// message: it is acked as usual (MQTT 3.1.1 has no negative PUBACK) but
    /// never reaches a subscriber. Also checked once against a CONNECT's last
    /// will, which refuses the CONNECT when denied. Runs on the router thread:
    /// keep it cheap and non-blocking.
    fn can_publish(&self, principal: &str, topic: &str, payload: &[u8]) -> bool;
}

pub type AccessControlRef = Arc<dyn AccessControl>;
