//! Synchronous OPC UA GetEndpoints over UA TCP. Uses the Rust standard library.
#![forbid(unsafe_code)]
mod binary;
mod transport;

use binary::{Decoder, Encoder};
use std::{
    error::Error,
    fmt, io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use transport::Connection;

const POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
const OPEN_REQUEST: u16 = 446;
const OPEN_RESPONSE: u16 = 449;
const ENDPOINTS_REQUEST: u16 = 428;
const ENDPOINTS_RESPONSE: u16 = 431;
const CLOSE_REQUEST: u16 = 452;

/// Errors from address validation, UA TCP transport or the discovery service.
#[derive(Debug)]
pub enum DiscoveryError {
    /// Expected an explicit OPC TCP host and port.
    InvalidEndpoint,
    /// The socket timeout must be between one millisecond and one minute.
    InvalidTimeout,
    /// Address resolution or socket I/O failed.
    Io(io::Error),
    /// The response was malformed, out of sequence, or exceeded a local limit.
    Protocol(&'static str),
    /// Raw UA TCP, chunk-abort or service status supplied by the peer.
    Status(u32),
}
impl From<io::Error> for DiscoveryError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => {
                f.write_str("expected opc.tcp://HOST:PORT with an optional path")
            }
            Self::InvalidTimeout => f.write_str("discovery timeout must be between 1 ms and 60 s"),
            Self::Io(e) => write!(f, "discovery transport: {e}"),
            Self::Protocol(reason) => write!(f, "invalid discovery response: {reason}"),
            Self::Status(status) => write!(f, "discovery returned OPC UA status 0x{status:08X}"),
        }
    }
}
impl Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Server-advertised user token policy. Token kinds 0, 1, 2 and 3 denote
/// anonymous, user name, certificate and issued token, respectively.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "commissioning", derive(serde::Serialize))]
pub struct EndpointToken {
    /// Policy identifier chosen by the server.
    pub policy_id: String,
    /// Raw OPC UA UserTokenType.
    pub kind: u32,
    /// Empty means to inherit the endpoint policy.
    pub security_policy_uri: String,
}

/// Unauthenticated discovery information. Independently approve the server leaf and URI before connecting.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "commissioning", derive(serde::Serialize))]
pub struct EndpointInfo {
    /// Unverified certificate chain supplied in GetEndpoints.
    #[cfg(feature = "client")]
    #[cfg_attr(feature = "commissioning", serde(skip))]
    pub(crate) certificate: Vec<u8>,
    /// Server-advertised endpoint URL.
    pub endpoint_url: String,
    /// Server-advertised application identity.
    pub application_uri: String,
    /// Raw MessageSecurityMode (1 None, 2 Sign, 3 SignAndEncrypt).
    pub security_mode: u32,
    /// Advertised secure-channel policy.
    pub security_policy_uri: String,
    /// Advertised transport profile.
    pub transport_profile_uri: String,
    /// User token policies in server order.
    pub user_tokens: Vec<EndpointToken>,
}

#[cfg(feature = "client")]
pub(crate) use transport::{address, secure_socket};

fn request(kind: u16, handle: u32, timeout: Duration) -> Encoder {
    let mut out = Encoder::default();
    out.node(kind);
    out.node(0); // Discovery has no session authentication token.
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = since_epoch.as_nanos() / 100 + 116_444_736_000_000_000;
    out.0.extend_from_slice(&(ticks as i64).to_le_bytes());
    out.u32(handle);
    out.u32(0); // No diagnostics requested.
    out.null();
    out.u32(timeout.as_millis() as u32);
    out.0.extend_from_slice(&[0, 0, 0]); // Null additional header.
    out
}

/// Discover up to 64 endpoints at one explicit URL without sending credentials.
/// The timeout covers socket operations after system DNS resolution. Returned
/// identities, policies and URLs are advertisements requiring independent review.
pub fn discover_endpoints(
    endpoint: &str,
    timeout: Duration,
) -> Result<Vec<EndpointInfo>, DiscoveryError> {
    if !(Duration::from_millis(1)..=Duration::from_secs(60)).contains(&timeout) {
        return Err(DiscoveryError::InvalidTimeout);
    }
    let mut conn = Connection::connect(endpoint, timeout)?;
    let mut open = request(OPEN_REQUEST, 1, timeout);
    open.u32(0); // ProtocolVersion.
    open.u32(0); // Issue.
    open.u32(1); // MessageSecurityMode None for discovery.
    open.null();
    open.u32(60_000);
    conn.send(b"OPN", 1, &open)?;
    let body = conn.receive(b"OPN", 1)?;
    let mut r = Decoder::new(&body);
    r.response(OPEN_RESPONSE, 1)?;
    if r.u32()? != 0 {
        return Err(DiscoveryError::Protocol("unsupported protocol version"));
    }
    let channel = r.u32()?;
    let token = r.u32()?;
    r.take(8)?; // CreatedAt.
    let lifetime = r.u32()?;
    r.blob(4096)?;
    r.finish()?;
    if channel != conn.channel || token == 0 || lifetime == 0 {
        return Err(DiscoveryError::Protocol("invalid security token"));
    }
    conn.token = token;
    let mut query = request(ENDPOINTS_REQUEST, 2, timeout);
    query.blob(endpoint.as_bytes());
    query.u32(0); // All locales.
    query.u32(0); // All transport profiles.
    conn.send(b"MSG", 2, &query)?;
    let body = conn.receive(b"MSG", 2)?;
    let mut r = Decoder::new(&body);
    r.response(ENDPOINTS_RESPONSE, 2)?;
    let mut endpoints = Vec::new();
    for _ in 0..r.count(64)? {
        endpoints.push(read_endpoint(&mut r)?);
    }
    r.finish()?;
    // CloseSecureChannel has no response. The socket also closes on every error path.
    let _ = conn.send(b"CLO", 3, &request(CLOSE_REQUEST, 3, timeout));
    Ok(endpoints)
}

fn read_endpoint(r: &mut Decoder<'_>) -> Result<EndpointInfo, DiscoveryError> {
    let endpoint_url = r.text()?.to_owned();
    let application_uri = r.text()?.to_owned();
    r.text()?; // ProductUri.
    r.localized_text()?;
    r.u32()?; // ApplicationType.
    r.text()?; // GatewayServerUri.
    r.text()?; // DiscoveryProfileUri.
    for _ in 0..r.count(256)? {
        r.text()?;
    }
    let certificate = r.blob(1024 * 1024)?;
    #[cfg(not(feature = "client"))]
    let _ = certificate;
    let security_mode = r.u32()?;
    let security_policy_uri = r.text()?.to_owned();
    let mut user_tokens = Vec::new();
    for _ in 0..r.count(64)? {
        let policy_id = r.text()?.to_owned();
        let kind = r.u32()?;
        r.text()?; // IssuedTokenType.
        r.text()?; // IssuerEndpointUrl.
        user_tokens.push(EndpointToken {
            policy_id,
            kind,
            security_policy_uri: r.text()?.to_owned(),
        });
    }
    let transport_profile_uri = r.text()?.to_owned();
    r.take(1)?; // SecurityLevel.
    Ok(EndpointInfo {
        #[cfg(feature = "client")]
        certificate: certificate.to_owned(),
        endpoint_url,
        application_uri,
        security_mode,
        security_policy_uri,
        user_tokens,
        transport_profile_uri,
    })
}
