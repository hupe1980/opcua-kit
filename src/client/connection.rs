use crate::secure_channel::Identity;
pub use crate::secure_channel::SecurityPolicy;
use crate::ua::StatusCode;
use std::{fmt, sync::Arc, time::Duration};
use time::OffsetDateTime;
use x509_parser::prelude::X509Certificate;
#[path = "session.rs"]
mod session;
pub(super) use session::Session;

/// User authentication within the pinned encrypted session.
#[derive(Clone, Copy, Default)]
pub enum UserIdentity<'a> {
    /// Use the anonymous user token.
    #[default]
    Anonymous,
    /// Present a site account and password.
    Username {
        /// Site account name.
        username: &'a str,
        /// Password supplied by the host.
        password: &'a str,
    },
}
impl UserIdentity<'_> {
    pub(super) fn validate(self) -> Result<(), ConnectError> {
        if let Self::Username { username, password } = self
            && (username.trim().is_empty()
                || username.len() > 256
                || username.chars().any(char::is_control)
                || password.is_empty()
                || password.len() > 4096)
        {
            return Err(InvalidConfiguration(
                "expected a user name up to 256 bytes and password of 1–4096 bytes",
            ));
        }
        Ok(())
    }

    /// Scope label used in contracts, snapshots and readings.
    pub fn principal(self) -> String {
        match self {
            Self::Anonymous => "anonymous".to_owned(),
            Self::Username { username, .. } => format!("username:{username}"),
        }
    }
}

/// Select a channel policy and session user. The default is pinned Basic256Sha256 with an anonymous user.
#[derive(Clone, Copy, Default)]
pub struct ConnectionOptions<'a> {
    /// Explicit channel policy. A failed connection never falls back to a weaker policy.
    pub security_policy: SecurityPolicy,
    /// User token, independent of the client application certificate.
    pub user_identity: UserIdentity<'a>,
}

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Endpoint and application credentials shared by all pinned user sessions.
/// Certificate and unencrypted private key inputs use DER encoding (up to 64 KiB each).
#[derive(Clone, Copy)]
pub struct ConnectionConfig<'a> {
    /// Explicit opc.tcp URL including port, e.g. `opc.tcp://plc.example:4840`.
    pub endpoint: &'a str,
    /// URI from the reviewed server identity and its certificate SAN.
    pub server_application_uri: &'a str,
    /// Exact server leaf certificate, obtained through a trusted channel.
    pub server_certificate_der: &'a [u8],
    /// URI of the client application in its certificate SAN.
    pub client_application_uri: &'a str,
    /// Client application certificate, trusted by the selected server.
    pub client_certificate_der: &'a [u8],
    /// Private key matching the client certificate. Its storage remains the caller's responsibility.
    pub client_private_key_der: &'a [u8],
    /// Response timeout between one millisecond and 60 seconds.
    pub timeout: Duration,
}

/// A local configuration rejection or an OPC UA connection failure.
#[derive(Debug)]
pub enum ConnectError {
    /// A configuration or credential failed local validation before dialing the endpoint.
    InvalidConfiguration(&'static str),
    /// The secure channel or session could not be opened.
    Connection(StatusCode),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => f.write_str(reason),
            Self::Connection(error) => write!(f, "could not open secure OPC UA session: {error}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfiguration(_) => None,
            Self::Connection(error) => Some(error),
        }
    }
}

use ConnectError::InvalidConfiguration;

fn application_certificate<'a>(
    der: &'a [u8],
    uri: &str,
    server_host: Option<&str>,
    require_current: bool,
) -> Result<X509Certificate<'a>, ConnectError> {
    crate::certificate::application_certificate(der, uri, server_host, require_current)
        .map_err(InvalidConfiguration)
}

/// A separately provisioned successor leaf for the same server and host.
#[derive(Clone, Copy)]
pub struct CertificateRollover<'a> {
    /// DER-encoded replacement leaf, obtained out of band.
    pub replacement_der: &'a [u8],
    /// Last UTC second in which the original leaf may start a new connection.
    pub original_valid_until: OffsetDateTime,
}

impl CertificateRollover<'_> {
    pub(super) fn validate_length(&self) -> Result<(), ConnectError> {
        if !(1..=MAX_CREDENTIAL_BYTES).contains(&self.replacement_der.len()) {
            return Err(InvalidConfiguration(
                "replacement leaf must contain 1 to 65536 bytes",
            ));
        }
        Ok(())
    }
}

struct LeafPin {
    der: Vec<u8>,
    not_before: i64,
    not_after: i64,
}

impl ConnectionConfig<'_> {
    /// Validate the endpoint, user, certificate bindings and matching private key locally.
    /// This performs the same checks as a single-pin connection without dialing or resolving the host.
    pub fn validate(&self, options: ConnectionOptions<'_>) -> Result<(), ConnectError> {
        self.prepare(options, true).map(|_| ())
    }

    fn prepare(
        &self,
        options: ConnectionOptions<'_>,
        require_current: bool,
    ) -> Result<(LeafPin, Identity, &str), ConnectError> {
        self.validate_input_lengths()?;
        options.user_identity.validate()?;
        let (host, _) = crate::discovery::address(self.endpoint).map_err(|_| {
            InvalidConfiguration("expected opc.tcp://HOST:PORT with an optional path")
        })?;
        let server = application_certificate(
            self.server_certificate_der,
            self.server_application_uri,
            Some(host),
            require_current,
        )?;
        application_certificate(
            self.client_certificate_der,
            self.client_application_uri,
            None,
            true,
        )?;
        if self.client_private_key_der.first() != Some(&0x30) {
            return Err(InvalidConfiguration(
                "expected an unencrypted DER client private key",
            ));
        }

        let original = LeafPin {
            der: self.server_certificate_der.to_vec(),
            not_before: server.validity().not_before.timestamp(),
            not_after: server.validity().not_after.timestamp(),
        };
        let local = Identity::new(self.client_certificate_der, self.client_private_key_der)
            .map_err(|_| InvalidConfiguration("certificate and RSA private key must match"))?;
        Ok((original, local, host))
    }

    pub(super) fn validate_input_lengths(&self) -> Result<(), ConnectError> {
        if [
            self.endpoint,
            self.client_application_uri,
            self.server_application_uri,
        ]
        .iter()
        .any(|uri| uri.is_empty() || uri.len() > 2048 || uri.chars().any(char::is_control))
        {
            return Err(InvalidConfiguration(
                "endpoint and application URIs must contain 1–2048 bytes",
            ));
        }
        if !(Duration::from_millis(1)..=Duration::from_secs(60)).contains(&self.timeout) {
            return Err(InvalidConfiguration(
                "timeout must be between 1 ms and 60 s",
            ));
        }
        for bytes in [
            self.server_certificate_der,
            self.client_certificate_der,
            self.client_private_key_der,
        ] {
            if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
                return Err(InvalidConfiguration(
                    "each DER credential must contain 1 to 65536 bytes",
                ));
            }
        }
        Ok(())
    }
}

/// A native OPC UA client connected to one pinned server.
pub struct Client {
    pub(super) inner: Arc<Session>,
    pub(super) server_uri: String,
    pub(super) reads: tokio::sync::Mutex<super::ReadSession>,
    pub(super) metadata: tokio::sync::OnceCell<super::ReadMetadata>,
    pub(super) publish_groups: super::subscription::PublishGroups,
    pub(super) principal: String,
    pub(super) subscriptions: tokio::sync::Semaphore,
}

impl Client {
    /// Opens a Basic256Sha256 SignAndEncrypt channel and an anonymous user session.
    ///
    /// The initial handshake is synchronous. On an async executor, call this method
    /// on a blocking worker. Each channel establishment checks the pinned server leaf.
    pub fn connect(config: ConnectionConfig<'_>) -> Result<Self, ConnectError> {
        Self::connect_with(config, ConnectionOptions::default())
    }

    /// Open a pinned encrypted session with an explicit policy and user identity.
    pub fn connect_with(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
    ) -> Result<Self, ConnectError> {
        Self::connect_pinned(config, options, None)
    }

    /// Open a pinned session during a planned certificate replacement. New handshakes
    /// accept the original leaf until the specified deadline, or the replacement within
    /// its certificate validity period. Both must identify the configured host and URI.
    pub fn connect_with_rollover(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
        rollover: CertificateRollover<'_>,
    ) -> Result<Self, ConnectError> {
        Self::connect_pinned(config, options, Some(rollover))
    }

    pub(super) fn connect_pinned(
        config: ConnectionConfig<'_>,
        options: ConnectionOptions<'_>,
        rollover: Option<CertificateRollover<'_>>,
    ) -> Result<Self, ConnectError> {
        let (mut original, local, host) = config.prepare(options, rollover.is_none())?;
        let mut leaves = Vec::with_capacity(2);
        if let Some(rollover) = rollover {
            rollover.validate_length()?;
            if rollover.replacement_der == config.server_certificate_der {
                return Err(InvalidConfiguration(
                    "replacement and original leaf must differ",
                ));
            }
            let next = application_certificate(
                rollover.replacement_der,
                config.server_application_uri,
                Some(host),
                false,
            )?;
            original.not_after = original
                .not_after
                .min(rollover.original_valid_until.unix_timestamp());
            leaves.push(LeafPin {
                der: rollover.replacement_der.to_owned(),
                not_before: next.validity().not_before.timestamp(),
                not_after: next.validity().not_after.timestamp(),
            });
        }
        leaves.push(original);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        leaves.retain(|leaf| (leaf.not_before..=leaf.not_after).contains(&now));
        let selected = match leaves.as_slice() {
            [] => {
                return Err(ConnectError::Connection(
                    StatusCode::BadCertificateTimeInvalid,
                ));
            }
            [only] => only,
            overlapping => {
                // The receiver thumbprint must be known before encrypting the first OPN.
                // With two eligible leaves discovery selects between the provisioned keys.
                let endpoints =
                    crate::discovery::discover_endpoints(config.endpoint, config.timeout)
                        .map_err(|e| ConnectError::Connection(session::discovery_error(e)))?;
                overlapping
                    .iter()
                    .find(|leaf| {
                        endpoints.iter().any(|ep| {
                            ep.security_mode == 3
                                && ep.security_policy_uri == options.security_policy.uri()
                                && ep.application_uri == config.server_application_uri
                                && ep.certificate.starts_with(&leaf.der)
                        })
                    })
                    .ok_or(ConnectError::Connection(
                        StatusCode::BadCertificateUntrusted,
                    ))?
            }
        };
        let inner =
            Session::connect(config, options, local, selected).map_err(ConnectError::Connection)?;
        Ok(Self {
            inner: Arc::new(inner),
            principal: options.user_identity.principal(),
            subscriptions: tokio::sync::Semaphore::new(8),
            server_uri: config.server_application_uri.to_owned(),
            reads: tokio::sync::Mutex::default(),
            metadata: tokio::sync::OnceCell::new(),
            publish_groups: Default::default(),
        })
    }

    pub(super) fn initial_channel(&self) -> bool {
        self.inner.is_alive()
    }

    /// Authenticated contract scope: `anonymous` or `username:<account>`.
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Closes the session and stops the client's background driver.
    pub async fn disconnect(self) {
        self.inner.disconnect().await;
    }
}
