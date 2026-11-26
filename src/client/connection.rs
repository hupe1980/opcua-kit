use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
use std::time::Duration;

use open62541::{
    Certificate, ClientBuilder, CustomCertificateVerification, DataType, PrivateKey, ua,
};
use time::OffsetDateTime;
use x509_parser::prelude::X509Certificate;

/// Security policy for a SignAndEncrypt secure channel.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SecurityPolicy {
    /// Widely supported RSA policy.
    #[default]
    Basic256Sha256,
    /// RSA-OAEP key exchange with AES-128 symmetric encryption.
    Aes128Sha256RsaOaep,
    /// RSA-PSS signatures with AES-256 symmetric encryption.
    Aes256Sha256RsaPss,
}

impl SecurityPolicy {
    /// OPC UA policy URI for endpoint selection.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Basic256Sha256 => "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            Self::Aes128Sha256RsaOaep => {
                "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
            }
            Self::Aes256Sha256RsaPss => {
                "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
            }
        }
    }
}

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
    Connection(open62541::Error),
    /// Advertised endpoint descriptions exceeded bounds or were malformed.
    InvalidDiscovery,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => f.write_str(reason),
            Self::InvalidDiscovery => f.write_str("invalid or excessive endpoint descriptions"),
            Self::Connection(error) => write!(f, "could not open secure OPC UA session: {error}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfiguration(_) | Self::InvalidDiscovery => None,
            Self::Connection(error) => Some(error),
        }
    }
}

use ConnectError::InvalidConfiguration;

pub(super) fn endpoint_host(endpoint: &str) -> Result<&str, ConnectError> {
    let invalid = || InvalidConfiguration("expected opc.tcp://HOST:PORT with an optional path");
    if endpoint.len() > 2048
        || endpoint.bytes().any(|b| !b.is_ascii_graphic())
        || endpoint.contains(['?', '#', '\\'])
    {
        return Err(invalid());
    }
    let authority = endpoint
        .strip_prefix("opc.tcp://")
        .ok_or_else(invalid)?
        .split('/')
        .next()
        .ok_or_else(invalid)?;
    let (host, port) = authority.rsplit_once(':').ok_or_else(invalid)?;
    if !port.bytes().all(|b| b.is_ascii_digit()) || !port.parse::<u16>().is_ok_and(|p| p != 0) {
        return Err(invalid());
    }
    if let Some(ipv6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        ipv6.parse::<Ipv6Addr>().map_err(|_| invalid())?;
        return Ok(ipv6);
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.len() > 253
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid());
    }
    if name.bytes().all(|b| b.is_ascii_digit() || b == b'.') && name.parse::<IpAddr>().is_err() {
        return Err(invalid());
    }
    Ok(name)
}

fn application_certificate<'a>(
    der: &'a [u8],
    uri: &str,
    server_host: Option<&str>,
    require_current: bool,
) -> Result<X509Certificate<'a>, ConnectError> {
    crate::certificate::application_certificate(der, uri, server_host, require_current)
        .map_err(InvalidConfiguration)
}

// Only the synchronous initial handshake may accept a peer certificate. After
// it completes, the SDK must never establish another channel with cached IDs.
const CONNECTING: u8 = 0;
const VERIFIED: u8 = 1;
const ACTIVE: u8 = 2;
const INVALIDATED: u8 = 3;

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

struct ServerPin {
    leaves: Vec<LeafPin>,
    selected: AtomicU8,
    channel_state: Arc<AtomicU8>,
}

impl CustomCertificateVerification for ServerPin {
    fn verify_certificate(&self, certificate: &ua::ByteString) -> ua::StatusCode {
        if self.channel_state.load(Ordering::Acquire) >= ACTIVE {
            self.channel_state.store(INVALIDATED, Ordering::Release);
            return ua::StatusCode::BADCERTIFICATEUNTRUSTED;
        }
        // The OPC UA wire value may append issuers after the complete leaf DER.
        // Its embedded ASN.1 length delineates the pinned leaf unambiguously.
        let Some((index, leaf)) = self.leaves.iter().enumerate().find(|(_, leaf)| {
            certificate
                .as_bytes()
                .is_some_and(|presented| presented.starts_with(&leaf.der))
        }) else {
            return ua::StatusCode::BADCERTIFICATEUNTRUSTED;
        };
        if !(leaf.not_before..=leaf.not_after).contains(&OffsetDateTime::now_utc().unix_timestamp())
        {
            return ua::StatusCode::BADCERTIFICATETIMEINVALID;
        }
        // Require the same leaf for every certificate check within this handshake.
        let index = index as u8;
        if let Err(previous) =
            self.selected
                .compare_exchange(u8::MAX, index, Ordering::AcqRel, Ordering::Acquire)
            && previous != index
        {
            return ua::StatusCode::BADCERTIFICATEUNTRUSTED;
        }
        self.channel_state.store(VERIFIED, Ordering::Release);
        ua::StatusCode::GOOD
    }
}

impl ConnectionConfig<'_> {
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
    pub(super) inner: open62541::AsyncClient,
    pub(super) server_uri: String,
    pub(super) reads: tokio::sync::Mutex<super::ReadSession>,
    pub(super) metadata: tokio::sync::OnceCell<super::ReadMetadata>,
    channel_state: Arc<AtomicU8>,
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
        config.validate_input_lengths()?;
        options.user_identity.validate()?;
        let host = endpoint_host(config.endpoint)?;
        let server = application_certificate(
            config.server_certificate_der,
            config.server_application_uri,
            Some(host),
            rollover.is_none(),
        )?;
        application_certificate(
            config.client_certificate_der,
            config.client_application_uri,
            None,
            true,
        )?;
        if config.client_private_key_der.first() != Some(&0x30) {
            return Err(InvalidConfiguration(
                "expected an unencrypted DER client private key",
            ));
        }
        let channel_state = Arc::new(AtomicU8::new(CONNECTING));
        let mut original = LeafPin {
            der: config.server_certificate_der.to_vec(),
            not_before: server.validity().not_before.timestamp(),
            not_after: server.validity().not_after.timestamp(),
        };
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
        let pin = ServerPin {
            leaves,
            selected: AtomicU8::new(u8::MAX),
            channel_state: Arc::clone(&channel_state),
        };
        let description = ua::ApplicationDescription::init()
            .with_application_name("en", "opcua-kit")
            .with_application_type(ua::ApplicationType::CLIENT)
            .with_application_uri(config.client_application_uri);
        let builder = ClientBuilder::default_encryption(
            &Certificate::from_bytes(config.client_certificate_der),
            &PrivateKey::from_bytes(config.client_private_key_der),
        )
        .map_err(|_| {
            InvalidConfiguration(
                "cannot configure encryption using the client certificate and private key",
            )
        })?;
        let builder = match options.user_identity {
            UserIdentity::Anonymous => builder,
            UserIdentity::Username { username, password } => builder
                .user_identity_token(&ua::UserNameIdentityToken::new(username, password).into()),
        };
        let client = builder
            .client_description(description)
            .timeout(config.timeout)
            .security_policy_uri(
                ua::String::new(options.security_policy.uri()).expect("static policy URI"),
            )
            .security_mode(ua::MessageSecurityMode::SIGNANDENCRYPT)
            .certificate_verification(ua::CertificateVerification::custom(pin))
            .connect(config.endpoint)
            .map_err(ConnectError::Connection)?;
        // UA_Client_connect has finished synchronously. Seal the verifier before
        // into_async() gives the SDK background driver control of this client.
        if channel_state
            .compare_exchange(VERIFIED, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ConnectError::Connection(open62541::Error::Server(
                ua::StatusCode::BADCERTIFICATEUNTRUSTED,
            )));
        }
        Ok(Self {
            inner: client.into_async(),
            principal: options.user_identity.principal(),
            subscriptions: tokio::sync::Semaphore::new(8),
            server_uri: config.server_application_uri.to_owned(),
            reads: tokio::sync::Mutex::default(),
            metadata: tokio::sync::OnceCell::new(),
            channel_state,
        })
    }

    pub(super) fn initial_channel(&self) -> bool {
        self.channel_state.load(Ordering::Acquire) == ACTIVE
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replacement_channel_cannot_reuse_a_session_namespace_map() {
        let peer = ua::ByteString::new(b"test leaf");
        let state = Arc::new(AtomicU8::new(CONNECTING));
        let verifier = ServerPin {
            leaves: vec![LeafPin {
                der: b"test leaf".to_vec(),
                not_before: 0,
                not_after: i64::MAX,
            }],
            selected: AtomicU8::new(u8::MAX),
            channel_state: Arc::clone(&state),
        };
        assert_eq!(verifier.verify_certificate(&peer), ua::StatusCode::GOOD);
        assert_eq!(state.swap(ACTIVE, Ordering::AcqRel), VERIFIED);
        assert_eq!(
            verifier.verify_certificate(&peer),
            ua::StatusCode::BADCERTIFICATEUNTRUSTED
        );
        assert_eq!(state.load(Ordering::Acquire), INVALIDATED);
        assert_eq!(
            verifier.verify_certificate(&peer),
            ua::StatusCode::BADCERTIFICATEUNTRUSTED
        );
    }

    #[test]
    fn rollover_binds_one_leaf_for_the_whole_handshake() {
        let verifier = ServerPin {
            leaves: [b"planned".as_slice(), b"original".as_slice()]
                .iter()
                .map(|der| LeafPin {
                    der: der.to_vec(),
                    not_before: 0,
                    not_after: i64::MAX,
                })
                .collect(),
            selected: AtomicU8::new(u8::MAX),
            channel_state: Arc::new(AtomicU8::new(CONNECTING)),
        };
        let next = ua::ByteString::new(b"planned");
        assert_eq!(verifier.verify_certificate(&next), ua::StatusCode::GOOD);
        assert_eq!(
            verifier.verify_certificate(&ua::ByteString::new(b"original")),
            ua::StatusCode::BADCERTIFICATEUNTRUSTED
        );
        assert_eq!(verifier.verify_certificate(&next), ua::StatusCode::GOOD);
    }
}
