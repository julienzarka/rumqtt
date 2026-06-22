use std::fs::File;
use tokio::net::TcpStream;

#[cfg(feature = "use-native-tls")]
use {
    std::io::Read, tokio_native_tls::native_tls,
    tokio_native_tls::native_tls::Error as NativeTlsError,
};

use crate::TlsConfig;
#[cfg(feature = "verify-client-cert")]
use rustls::{server::WebPkiClientVerifier, RootCertStore};
#[cfg(feature = "use-rustls")]
use {
    rustls::{pki_types::PrivateKeyDer, Error as RustlsError, ServerConfig},
    rustls_pemfile::Item,
    std::{io::BufReader, sync::Arc},
    tracing::error,
};

use crate::link::network::N;

#[derive(Debug, thiserror::Error)]
#[error("Acceptor error")]
pub enum Error {
    #[error("I/O {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "use-native-tls")]
    #[error("Native TLS error {0}")]
    NativeTls(#[from] NativeTlsError),
    #[error("No peer certificate")]
    NoPeerCertificate,
    #[cfg(feature = "use-rustls")]
    #[error("Rustls error {0}")]
    Rustls(#[from] RustlsError),
    #[error("Server cert file {0} not found")]
    ServerCertNotFound(String),
    #[error("Invalid server cert file {0}")]
    InvalidServerCert(String),
    #[error("Invalid CA cert file {0}")]
    InvalidCACert(String),
    #[error("Invalid server key file {0}")]
    InvalidServerKey(String),
    #[error("Server private key file {0} not found")]
    ServerKeyNotFound(String),
    #[error("CA file {0} no found")]
    CaFileNotFound(String),
    #[cfg(not(feature = "use-native-tls"))]
    NativeTlsNotEnabled,
    #[cfg(not(feature = "use-rustls"))]
    RustlsNotEnabled,
    #[error("Invalid tenant id = {0}")]
    InvalidTenantId(String),
    #[error("Invalid tenant certificate")]
    InvalidTenant,
    #[error("Tenant id missing in certificate")]
    MissingTenantId,
    #[error("Tenant id missing in certificate")]
    CertificateParse,
}

#[cfg(feature = "verify-client-cert")]
/// Extract uid from certificate's subject organization field
fn extract_tenant_id(der: &[u8]) -> Result<Option<String>, Error> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|_| Error::CertificateParse)?;
    let tenant_id = match cert.subject().iter_organization().next() {
        Some(org) => match org.as_str() {
            Ok(val) => val.to_string(),
            Err(_) => return Err(Error::InvalidTenant),
        },
        None => {
            #[cfg(feature = "validate-tenant-prefix")]
            return Err(Error::MissingTenantId);
            #[cfg(not(feature = "validate-tenant-prefix"))]
            return Ok(None);
        }
    };

    if tenant_id.chars().any(|c| !c.is_alphanumeric()) {
        return Err(Error::InvalidTenantId(tenant_id));
    }

    Ok(Some(tenant_id))
}

#[allow(dead_code)]
pub enum TLSAcceptor {
    #[cfg(feature = "use-rustls")]
    Rustls { acceptor: tokio_rustls::TlsAcceptor },
    #[cfg(feature = "use-native-tls")]
    NativeTLS {
        acceptor: tokio_native_tls::TlsAcceptor,
    },
}

impl TLSAcceptor {
    pub fn new(config: &TlsConfig) -> Result<Self, Error> {
        match config {
            #[cfg(feature = "use-rustls")]
            TlsConfig::Rustls {
                capath,
                certpath,
                keypath,
            } => Self::rustls(capath, certpath, keypath),
            #[cfg(feature = "use-rustls")]
            TlsConfig::RustlsPem {
                ca_pem,
                cert_pem,
                key_pem,
            } => Self::rustls_pem(ca_pem, cert_pem, key_pem),
            #[cfg(feature = "use-rustls")]
            TlsConfig::RustlsReloadable(handle) => {
                // Snapshot the current material; subsequent rotations are picked
                // up on the next connection's acceptor rebuild.
                let bundle = handle.current();
                Self::rustls_pem(&bundle.ca_pem, &bundle.cert_pem, &bundle.key_pem)
            }
            #[cfg(feature = "use-native-tls")]
            TlsConfig::NativeTls {
                pkcs12path,
                pkcs12pass,
            } => Self::native_tls(pkcs12path, pkcs12pass),
            #[cfg(not(feature = "use-rustls"))]
            TlsConfig::Rustls { .. } => Err(Error::RustlsNotEnabled),
            #[cfg(not(feature = "use-rustls"))]
            TlsConfig::RustlsPem { .. } => Err(Error::RustlsNotEnabled),
            #[cfg(not(feature = "use-rustls"))]
            TlsConfig::RustlsReloadable(_) => Err(Error::RustlsNotEnabled),
            #[cfg(not(feature = "use-native-tls"))]
            TlsConfig::NativeTls { .. } => Err(Error::NativeTlsNotEnabled),
        }
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<(Option<String>, Box<dyn N>), Error> {
        match self {
            #[cfg(feature = "use-rustls")]
            TLSAcceptor::Rustls { acceptor } => {
                let stream = acceptor.accept(stream).await?;

                #[cfg(feature = "verify-client-cert")]
                let tenant_id = {
                    let (_, session) = stream.get_ref();
                    let peer_certificates = session
                        .peer_certificates()
                        .ok_or(Error::NoPeerCertificate)?;
                    extract_tenant_id(&peer_certificates[0])?
                };
                #[cfg(not(feature = "verify-client-cert"))]
                let tenant_id: Option<String> = None;

                let network = Box::new(stream);
                Ok((tenant_id, network))
            }
            #[cfg(feature = "use-native-tls")]
            TLSAcceptor::NativeTLS { acceptor } => {
                let stream = acceptor.accept(stream).await?;
                // native-tls doesn't support client certificate verification
                // let session = stream.get_ref();
                // let peer_certificate = session
                //     .peer_certificate()?
                //     .ok_or(Error::NoPeerCertificate)?
                //     .to_der()?;
                // let tenant_id = extract_tenant_id(&peer_certificate)?;
                let network = Box::new(stream);
                Ok((None, network))
            }
        }
    }

    #[cfg(feature = "use-native-tls")]
    fn native_tls(pkcs12_path: &String, pkcs12_pass: &str) -> Result<Self, Error> {
        // Get certificates
        let cert_file = File::open(pkcs12_path);
        let mut cert_file =
            cert_file.map_err(|_| Error::ServerCertNotFound(pkcs12_path.clone()))?;

        // Read cert into memory
        let mut buf = Vec::new();
        cert_file
            .read_to_end(&mut buf)
            .map_err(|_| Error::InvalidServerCert(pkcs12_path.clone()))?;

        // Get the identity
        let identity = native_tls::Identity::from_pkcs12(&buf, pkcs12_pass)
            .map_err(|_| Error::InvalidServerCert(pkcs12_path.clone()))?;

        // Builder
        let builder = native_tls::TlsAcceptor::builder(identity).build()?;

        // Create acceptor
        let acceptor = tokio_native_tls::TlsAcceptor::from(builder);
        Ok(TLSAcceptor::NativeTLS { acceptor })
    }

    #[cfg(feature = "use-rustls")]
    fn rustls(
        ca_path: &Option<String>,
        cert_path: &String,
        key_path: &String,
    ) -> Result<TLSAcceptor, Error> {
        #[cfg(feature = "verify-client-cert")]
        let Some(ca_path) = ca_path
        else {
            return Err(Error::CaFileNotFound(
                "capath must be specified in config when verify-client-cert is enabled."
                    .to_string(),
            ));
        };

        #[cfg(not(feature = "verify-client-cert"))]
        if ca_path.is_some() {
            tracing::warn!("verify-client-cert feature is disabled, CA cert will be ignored and no client authentication is done.");
        }

        let (certs, key) = {
            // Get certificates
            let cert_file = File::open(cert_path);
            let cert_file = cert_file.map_err(|_| Error::ServerCertNotFound(cert_path.clone()))?;
            let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::InvalidServerCert(cert_path.to_string()))?;

            // Get private key
            let key = first_private_key_in_pemfile(key_path)?;

            (certs, key)
        };

        let builder = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(Error::Rustls)?;

        // client authentication with a CA. CA isn't required otherwise
        #[cfg(feature = "verify-client-cert")]
        let builder = {
            let ca_file = File::open(ca_path);
            let ca_file = ca_file.map_err(|_| Error::CaFileNotFound(ca_path.clone()))?;
            let ca_file = &mut BufReader::new(ca_file);
            let ca_cert = rustls_pemfile::certs(ca_file)
                .next()
                .ok_or_else(|| Error::InvalidCACert(ca_path.to_string()))??;

            let mut store = RootCertStore::empty();
            store
                .add(ca_cert)
                .map_err(|_| Error::InvalidCACert(ca_path.to_string()))?;

            let verifier = WebPkiClientVerifier::builder(Arc::new(store))
                .build()
                .map_err(|e| Error::InvalidCACert(format!("{e}")))?;
            builder.with_client_cert_verifier(verifier)
        };

        #[cfg(not(feature = "verify-client-cert"))]
        let builder = builder.with_no_client_auth();

        let server_config = builder.with_single_cert(certs, key)?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        Ok(TLSAcceptor::Rustls { acceptor })
    }

    /// Build a rustls acceptor from in-memory PEM bytes instead of file paths.
    /// Mirrors [`Self::rustls`] but parses the cert chain, private key and
    /// optional CA from byte slices, so the embedder never has to materialise
    /// the private key to disk (and can hand the listener a rotated identity).
    #[cfg(feature = "use-rustls")]
    fn rustls_pem(
        ca_pem: &Option<Vec<u8>>,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<TLSAcceptor, Error> {
        #[cfg(feature = "verify-client-cert")]
        let Some(ca_pem) = ca_pem
        else {
            return Err(Error::CaFileNotFound(
                "ca_pem must be specified when verify-client-cert is enabled.".to_string(),
            ));
        };

        #[cfg(not(feature = "verify-client-cert"))]
        if ca_pem.is_some() {
            tracing::warn!("verify-client-cert feature is disabled, in-memory CA cert will be ignored and no client authentication is done.");
        }

        let (certs, key) = {
            let mut cert_rd = cert_pem;
            let certs = rustls_pemfile::certs(&mut cert_rd)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::InvalidServerCert("<in-memory cert>".to_string()))?;

            let key = first_private_key_in_pem_bytes(key_pem)?;

            (certs, key)
        };

        let builder = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(Error::Rustls)?;

        #[cfg(feature = "verify-client-cert")]
        let builder = {
            let mut ca_rd = ca_pem.as_slice();
            let ca_cert = rustls_pemfile::certs(&mut ca_rd)
                .next()
                .ok_or_else(|| Error::InvalidCACert("<in-memory ca>".to_string()))??;

            let mut store = RootCertStore::empty();
            store
                .add(ca_cert)
                .map_err(|_| Error::InvalidCACert("<in-memory ca>".to_string()))?;

            let verifier = WebPkiClientVerifier::builder(Arc::new(store))
                .build()
                .map_err(|e| Error::InvalidCACert(format!("{e}")))?;
            builder.with_client_cert_verifier(verifier)
        };

        #[cfg(not(feature = "verify-client-cert"))]
        let builder = builder.with_no_client_auth();

        let server_config = builder.with_single_cert(certs, key)?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        Ok(TLSAcceptor::Rustls { acceptor })
    }
}

#[cfg(feature = "use-rustls")]
/// Get the first private key in an in-memory PEM byte slice (sibling of
/// [`first_private_key_in_pemfile`] that reads bytes instead of a file).
fn first_private_key_in_pem_bytes(key_pem: &[u8]) -> Result<PrivateKeyDer<'static>, Error> {
    let mut rd = key_pem;
    loop {
        let item = rustls_pemfile::read_one(&mut rd).map_err(|err| {
            error!("Error reading in-memory key: {:?}", err);
            Error::InvalidServerKey("<in-memory key>".to_string())
        })?;

        match item {
            Some(Item::Sec1Key(key)) => return Ok(key.into()),
            Some(Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(Item::Pkcs8Key(key)) => return Ok(key.into()),
            None => {
                error!("No private key found in in-memory PEM");
                return Err(Error::InvalidServerKey("<in-memory key>".to_string()));
            }
            _ => {}
        }
    }
}

#[cfg(feature = "use-rustls")]
/// Get the first private key in a PEM file
fn first_private_key_in_pemfile(key_path: &String) -> Result<PrivateKeyDer<'static>, Error> {
    // Get private key
    let key_file = File::open(key_path);
    let key_file = key_file.map_err(|_| Error::ServerKeyNotFound(key_path.clone()))?;

    let rd = &mut BufReader::new(key_file);

    // keep reading Items one by one to find a Key, return error if none found.
    loop {
        let item = rustls_pemfile::read_one(rd).map_err(|err| {
            error!("Error reading key file: {:?}", err);
            Error::InvalidServerKey(key_path.clone())
        })?;

        match item {
            Some(Item::Sec1Key(key)) => {
                return Ok(key.into());
            }
            Some(Item::Pkcs1Key(key)) => {
                return Ok(key.into());
            }
            Some(Item::Pkcs8Key(key)) => {
                return Ok(key.into());
            }
            None => {
                error!("No private key found in {:?}", key_path);
                return Err(Error::InvalidServerKey(key_path.clone()));
            }
            _ => {}
        }
    }
}

/// mTLS verification (verify-client-cert): the `rustls_pem` branch builds a
/// `WebPkiClientVerifier` from the in-memory CA. mosqtt builds the fork without
/// this feature, so the branch was compile-checked only; this drives a real
/// handshake to prove the verifier accepts a CA-signed client cert and rejects
/// an unsigned one. Run with `--features use-rustls,verify-client-cert`.
#[cfg(all(test, feature = "verify-client-cert"))]
mod verify_client_cert_tests {
    use super::*;
    use std::sync::Arc;

    use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    /// An in-memory PKI: a CA, a CA-signed server leaf, a CA-signed client leaf
    /// (the valid case) and a self-signed client leaf (the rogue case).
    struct Pki {
        ca_pem: Vec<u8>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
        valid_client_cert: Vec<u8>,
        valid_client_key: Vec<u8>,
        rogue_client_cert: Vec<u8>,
        rogue_client_key: Vec<u8>,
    }

    fn leaf(san: &str) -> Certificate {
        Certificate::from_params(CertificateParams::new(vec![san.to_string()]))
            .expect("generate leaf")
    }

    fn make_pki() -> Pki {
        let mut ca_params = CertificateParams::new(Vec::<String>::new());
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = Certificate::from_params(ca_params).expect("generate CA");

        let server = leaf("localhost");
        let valid_client = leaf("valid-client");
        let rogue_client = leaf("rogue-client");

        Pki {
            ca_pem: ca.serialize_pem().expect("ca pem").into_bytes(),
            server_cert: server
                .serialize_pem_with_signer(&ca)
                .expect("server pem")
                .into_bytes(),
            server_key: server.serialize_private_key_pem().into_bytes(),
            valid_client_cert: valid_client
                .serialize_pem_with_signer(&ca)
                .expect("client pem")
                .into_bytes(),
            valid_client_key: valid_client.serialize_private_key_pem().into_bytes(),
            // Self-signed: NOT chained to the CA the server trusts.
            rogue_client_cert: rogue_client
                .serialize_pem()
                .expect("rogue pem")
                .into_bytes(),
            rogue_client_key: rogue_client.serialize_private_key_pem().into_bytes(),
        }
    }

    /// Test-only: accept any server certificate. We are testing client-cert
    /// verification on the server, not server-cert verification on the client.
    #[derive(Debug)]
    struct AcceptAnyServer(Arc<CryptoProvider>);
    impl ServerCertVerifier for AcceptAnyServer {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn client_config(client_cert_pem: &[u8], client_key_pem: &[u8]) -> ClientConfig {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &client_cert_pem[..])
            .collect::<Result<_, _>>()
            .expect("parse client certs");
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &client_key_pem[..])
            .expect("read client key")
            .expect("one client key");

        ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(provider)))
            .with_client_auth_cert(certs, key)
            .expect("client auth cert")
    }

    /// Run one mTLS handshake against a `rustls_pem`-built verify-client-cert
    /// listener using the given client identity. `Ok` iff the server accepted.
    async fn handshake(pki: &Pki, client_cert: &[u8], client_key: &[u8]) -> Result<(), ()> {
        let acceptor = TLSAcceptor::new(&TlsConfig::RustlsPem {
            ca_pem: Some(pki.ca_pem.clone()),
            cert_pem: pki.server_cert.clone(),
            key_pem: pki.server_key.clone(),
        })
        .expect("verify-client-cert acceptor builds from in-memory CA");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let connector = TlsConnector::from(Arc::new(client_config(client_cert, client_key)));
        let client = tokio::spawn(async move {
            let tcp = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let name = ServerName::try_from("localhost").expect("server name");
            // A rejected client cert surfaces as a connect/IO error here — ignore
            // it; the server side is what the assertions check.
            if let Ok(mut tls) = connector.connect(name, tcp).await {
                let _ = tls.write_all(b"x").await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            }
        });

        let (tcp, _) = listener.accept().await.expect("accept tcp");
        let result = acceptor.accept(tcp).await;
        let _ = client.await;
        result.map(|_| ()).map_err(|_| ())
    }

    #[tokio::test]
    async fn valid_client_cert_accepted_rogue_rejected() {
        // Unambiguous provider for the bare client builder; Err = already set.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = make_pki();

        assert!(
            handshake(&pki, &pki.valid_client_cert, &pki.valid_client_key)
                .await
                .is_ok(),
            "a client cert signed by the configured CA must be accepted"
        );
        assert!(
            handshake(&pki, &pki.rogue_client_cert, &pki.rogue_client_key)
                .await
                .is_err(),
            "a client cert not signed by the configured CA must be rejected"
        );
    }
}
