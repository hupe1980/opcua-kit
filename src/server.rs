//! Serve host-owned scalar variables in an OPC UA address space.
//! The application owns the event loop, values and shutdown signal.
mod address;
mod services;
mod subscriptions;
mod transport;

pub use crate::secure_channel::SecurityPolicy;
use crate::secure_channel::{Identity, Peer};
use crate::ua::{DataValue, StatusCode, Variant, VariantType};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    io,
    marker::PhantomData,
    net::{SocketAddr, TcpListener},
    num::NonZeroU16,
    sync::{Arc, RwLock},
};

/// Failure to configure, run or update an embedded server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Invalid namespace URI or variable name.
    #[error("invalid namespace URI or variable name")]
    InvalidName,
    /// Endpoint or credentials failed local validation.
    #[error("{0}")]
    Configuration(&'static str),
    /// A variable already uses this browse name and NodeId.
    #[error("variable already exists")]
    DuplicateVariable,
    /// OPC UA value or credential validation failed.
    #[error("{0}")]
    Protocol(StatusCode),
    /// Listening socket or connection worker failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Host-provisioned server identity, single client pin and explicit bind address.
/// Secrets are borrowed during configuration and excluded from Debug output.
pub struct SecureServerConfig<'a> {
    /// One concrete listening IP and port. Its IP must match the server certificate SAN.
    pub bind: std::net::SocketAddr,
    /// Application URI from the server certificate.
    pub application_uri: &'a str,
    /// Public DER certificate for this server.
    pub certificate_der: &'a [u8],
    /// Matching unencrypted private key, encoded as DER.
    pub private_key_der: &'a [u8],
    /// Application URI from the provisioned client certificate.
    pub trusted_client_uri: &'a str,
    /// Exact DER leaf certificate of the one permitted application.
    pub trusted_client_certificate_der: &'a [u8],
}

const UA_NAMESPACE: &str = "http://opcfoundation.org/UA/";
const LOCAL_URI: &str = "urn:opcua-kit:server";
const NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
const TRANSPORT: &str = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";

struct Credentials {
    policy: SecurityPolicy,
    server: Identity,
    client: Peer,
    client_uri: String,
}

type Sample = Arc<RwLock<DataValue>>;

struct Host {
    started: crate::ua::DateTime,
    namespace: String,
    application_uri: String,
    bind: SocketAddr,
    credentials: Option<Credentials>,
    variables: RwLock<BTreeMap<String, (u32, Sample)>>,
}

/// A host-owned address space with one application namespace.
pub struct Server(Arc<Host>);

/// A blocking server event loop that can run on a host worker thread.
pub struct ServerRunner(Arc<Host>);

impl ServerRunner {
    /// Bind the selected endpoint and serve until the callback returns true.
    /// All active connections close before this method returns.
    pub fn run_until(self, shutdown: impl FnMut() -> bool) -> Result<(), ServerError> {
        let socket = TcpListener::bind(self.0.bind)?;
        transport::run(socket, self.0, shutdown)?;
        Ok(())
    }
}

/// Host-side handle to one scalar. Its Rust type fixes the OPC UA value type.
pub struct Variable<T> {
    sample: Sample,
    marker: PhantomData<fn(T)>,
}

impl<T: Into<Variant> + VariantType> Variable<T> {
    /// Update the value and its source timestamp atomically.
    pub fn set(&self, value: T) -> Result<(), ServerError> {
        let sample = scalar(value)?;
        *self.sample.write().unwrap_or_else(|e| e.into_inner()) = sample;
        Ok(())
    }
}

fn scalar<T: Into<Variant> + VariantType>(value: T) -> Result<DataValue, ServerError> {
    let value = value.into();
    if value.scalar_type_id() != Some(T::variant_type_id())
        || matches!(value, Variant::ExtensionObject(_))
    {
        return Err(ServerError::Protocol(StatusCode::BadTypeMismatch));
    }
    let limits = crate::ua::ContextOwned::default();
    if crate::ua::BinaryEncodable::encoded_len(&value, &limits.context())
        .map_err(ServerError::Protocol)?
        > transport::MESSAGE_LIMIT - 128
    {
        return Err(ServerError::Protocol(StatusCode::BadEncodingLimitsExceeded));
    }
    Ok(DataValue::new_now(value))
}

impl Server {
    /// Configure anonymous connections on the IPv4 loopback interface.
    pub fn loopback(
        port: NonZeroU16,
        namespace_uri: &str,
    ) -> Result<(Self, ServerRunner), ServerError> {
        Self::build(
            ([127, 0, 0, 1], port.get()).into(),
            LOCAL_URI,
            namespace_uri,
            None,
        )
    }

    /// Configure a Basic256Sha256 SignAndEncrypt endpoint for one pinned reader.
    pub fn secure(
        config: SecureServerConfig<'_>,
        namespace_uri: &str,
    ) -> Result<(Self, ServerRunner), ServerError> {
        Self::secure_with_policy(config, namespace_uri, SecurityPolicy::Basic256Sha256)
    }

    /// Configure one SignAndEncrypt policy for the pinned client and server identities.
    pub fn secure_with_policy(
        config: SecureServerConfig<'_>,
        namespace_uri: &str,
        policy: SecurityPolicy,
    ) -> Result<(Self, ServerRunner), ServerError> {
        if !is_unicast(config.bind.ip()) || config.bind.port() == 0 {
            return Err(ServerError::Configuration(
                "expected a concrete unicast bind IP and nonzero port",
            ));
        }
        for der in [
            config.certificate_der,
            config.private_key_der,
            config.trusted_client_certificate_der,
        ] {
            if !(1..=65535).contains(&der.len()) {
                return Err(ServerError::Configuration(
                    "credential length must be 1 to 65535 bytes",
                ));
            }
        }
        crate::certificate::application_certificate(
            config.certificate_der,
            config.application_uri,
            Some(&config.bind.ip().to_string()),
            true,
        )
        .map_err(ServerError::Configuration)?;
        crate::certificate::application_certificate(
            config.trusted_client_certificate_der,
            config.trusted_client_uri,
            None,
            true,
        )
        .map_err(ServerError::Configuration)?;
        let credentials = Credentials {
            policy,
            server: Identity::new(config.certificate_der, config.private_key_der)
                .map_err(ServerError::Protocol)?,
            client: Peer::new(config.trusted_client_certificate_der)
                .map_err(ServerError::Protocol)?,
            client_uri: config.trusted_client_uri.into(),
        };
        Self::build(
            config.bind,
            config.application_uri,
            namespace_uri,
            Some(credentials),
        )
    }

    fn build(
        bind: SocketAddr,
        uri: &str,
        namespace: &str,
        credentials: Option<Credentials>,
    ) -> Result<(Self, ServerRunner), ServerError> {
        if !valid_name(namespace) || namespace == UA_NAMESPACE || namespace == uri {
            return Err(ServerError::InvalidName);
        }
        let host = Arc::new(Host {
            started: crate::ua::DateTime::now(),
            bind,
            application_uri: uri.into(),
            namespace: namespace.into(),
            credentials,
            variables: RwLock::default(),
        });
        Ok((Self(host.clone()), ServerRunner(host)))
    }

    /// Add a typed, read-only scalar under Objects. Its browse name and string
    /// NodeId both equal `name`. A duplicate leaves the existing value intact.
    pub fn add_variable<T: Into<Variant> + VariantType>(
        &self,
        name: &str,
        initial: T,
    ) -> Result<Variable<T>, ServerError> {
        if !valid_name(name) {
            return Err(ServerError::InvalidName);
        }
        let mut variables = self.0.variables.write().unwrap_or_else(|e| e.into_inner());
        let Entry::Vacant(entry) = variables.entry(name.to_owned()) else {
            return Err(ServerError::DuplicateVariable);
        };
        let sample = Arc::new(RwLock::new(scalar(initial)?));
        entry.insert((T::variant_type_id() as u32, sample.clone()));
        Ok(Variable {
            sample,
            marker: PhantomData,
        })
    }
}

fn is_unicast(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none()
        }
    }
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 4096 && !name.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unspecified_multicast_broadcast_and_mapped_bind_addresses() {
        for text in [
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "::ffff:0.0.0.0",
        ] {
            assert!(!is_unicast(text.parse().unwrap()), "{text}");
        }
        assert!(is_unicast("127.0.0.1".parse().unwrap()));
        assert!(is_unicast("::1".parse().unwrap()));
    }

    #[test]
    fn invalid_and_duplicate_names_cannot_replace_application_variables() {
        let port = NonZeroU16::new(4840).unwrap();
        for namespace in ["", "x\0y", "http://opcfoundation.org/UA/"] {
            assert!(matches!(
                Server::loopback(port, namespace),
                Err(ServerError::InvalidName)
            ));
        }
        let (host, _runner) = Server::loopback(port, "urn:line").unwrap();
        assert!(matches!(
            host.add_variable("bad\nname", false),
            Err(ServerError::InvalidName)
        ));
        let counter = host.add_variable("Counter", 10_u64).unwrap();
        assert!(host.add_variable("Counter", true).is_err());
        counter.set(20).unwrap();
    }
}
