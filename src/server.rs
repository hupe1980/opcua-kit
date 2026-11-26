//! Embed an OPC UA address space that serves host-owned read-only variables.
//! The host owns the address space, the thread running the event loop, and shutdown.
//! Use an explicitly pinned secure endpoint across hosts, or opt into an anonymous local endpoint.
mod access;

use access::{PinnedReader, ReadOnly};
use std::{marker::PhantomData, num::NonZeroU16};

pub use open62541::ua;
use open62541::{Attributes, DataType, Node, ServerBuilder};
use open62541_sys as sys;

/// Failure to configure, run or update an embedded server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Namespace or variable name is empty, oversized, reserved, or contains control characters.
    #[error("invalid namespace URI or variable name")]
    InvalidName,
    /// Endpoint, credential or application identity failed local validation.
    #[error("{0}")]
    Configuration(&'static str),
    /// The native server returned an OPC UA error.
    #[error(transparent)]
    Native(#[from] open62541::Error),
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

/// A host-owned address space in one application namespace.
pub struct Server {
    server: open62541::Server,
    namespace: u16,
}

/// Blocking event loop. Move it onto the host's worker thread.
pub struct ServerRunner(open62541::ServerRunner);

impl ServerRunner {
    /// Start accepting connections, then run until the callback returns true.
    /// Startup errors (including an occupied port) are returned here.
    pub fn run_until(self, shutdown: impl FnMut() -> bool) -> Result<(), ServerError> {
        Ok(self.0.run_until_cancelled(shutdown)?)
    }
}

/// Host-side handle to a variable. Only values of its declared type can be set.
pub struct Variable<T> {
    server: open62541::Server,
    id: ua::NodeId,
    marker: PhantomData<fn(T)>,
}

impl<T: DataType> Variable<T> {
    /// Publish a new scalar from the local application.
    pub fn set(&self, value: T) -> Result<(), ServerError> {
        Ok(self
            .server
            .write_value(&self.id, &ua::Variant::scalar(value))?)
    }
}

impl Server {
    /// Configure an anonymous endpoint at `opc.tcp://127.0.0.1:<port>`.
    /// Variables use string NodeIds in the supplied application namespace.
    pub fn loopback(
        port: NonZeroU16,
        namespace_uri: &str,
    ) -> Result<(Self, ServerRunner), ServerError> {
        if !valid_name(namespace_uri) || namespace_uri == "http://opcfoundation.org/UA/" {
            return Err(ServerError::InvalidName);
        }
        let url = format!("opc.tcp://127.0.0.1:{port}");
        let (server, runner) = ServerBuilder::minimal(port.get(), None)
            .server_urls(&[&url])
            .access_control(ReadOnly)?
            .build();
        Self::address_space(server, runner, namespace_uri)
    }

    /// Bind a Basic256Sha256 / SignAndEncrypt endpoint on one explicitly selected IP.
    /// The peer presents the trusted client certificate and proves possession of its private key.
    /// The application session uses an anonymous user token with read-only permissions.
    pub fn secure(
        config: SecureServerConfig<'_>,
        namespace_uri: &str,
    ) -> Result<(Self, ServerRunner), ServerError> {
        if !valid_name(namespace_uri) || namespace_uri == "http://opcfoundation.org/UA/" {
            return Err(ServerError::InvalidName);
        }
        if !is_unicast(config.bind.ip()) || config.bind.port() == 0 {
            return Err(ServerError::Configuration(
                "expected a concrete unicast bind IP and nonzero port",
            ));
        }
        for credential in [
            config.certificate_der,
            config.private_key_der,
            config.trusted_client_certificate_der,
        ] {
            if !(1..=65535).contains(&credential.len()) {
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
        let (server, runner) = ServerBuilder::default_with_secure_security_policies(
            config.bind.port(),
            config.certificate_der,
            config.private_key_der,
        )?
        .server_urls(&[&format!("opc.tcp://{}", config.bind)])
        .access_control(PinnedReader {
            uri: config.application_uri,
            der: config.trusted_client_certificate_der,
        })?
        .build();
        Self::address_space(server, runner, namespace_uri)
    }

    fn address_space(
        server: open62541::Server,
        runner: open62541::ServerRunner,
        namespace_uri: &str,
    ) -> Result<(Self, ServerRunner), ServerError> {
        let namespace = server.add_namespace(namespace_uri);
        if namespace < 2 {
            return Err(ServerError::InvalidName);
        }
        Ok((Self { server, namespace }, ServerRunner(runner)))
    }

    /// Add a read-only scalar under Objects. Its browse name and string NodeId
    /// both equal `name`. A duplicate fails without replacing the existing value.
    pub fn add_variable<T: DataType>(
        &self,
        name: &str,
        initial: T,
    ) -> Result<Variable<T>, ServerError> {
        if !valid_name(name) {
            return Err(ServerError::InvalidName);
        }
        // SAFETY: DataType provides the live static UA_DataType descriptor for T.
        let data_type = unsafe { ua::NodeId::clone_raw(&(*T::data_type()).typeId) };
        let mut attrs = ua::VariableAttributes::init()
            .with_display_name(&ua::LocalizedText::new("", name)?)
            .with_data_type(&data_type)
            .with_value_rank(-1)
            .with_access_level(&ua::AccessLevelType::NONE.with_current_read(true));
        // SAFETY: attrs uniquely owns its initialized UA_VariableAttributes.
        // Clone into its owned Variant before publishing the complete node.
        unsafe {
            let attrs = &mut *attrs.as_mut_ptr();
            ua::Variant::scalar(initial).clone_into_raw(&mut attrs.value);
            attrs.specifiedAttributes |= sys::UA_NodeAttributesMask::UA_NODEATTRIBUTESMASK_VALUE.0;
        }
        let node = Node::new(
            ua::NodeId::ns0(sys::UA_NS0ID_OBJECTSFOLDER),
            ua::NodeId::ns0(sys::UA_NS0ID_ORGANIZES),
            ua::QualifiedName::new(self.namespace, name),
            attrs,
        )
        .with_type_definition(ua::NodeId::ns0(sys::UA_NS0ID_BASEDATAVARIABLETYPE))
        .with_requested_new_node_id(ua::NodeId::string(self.namespace, name));
        let id = self.server.add_node(node)?;
        Ok(Variable {
            server: self.server.clone(),
            id,
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
            host.add_variable("bad\nname", ua::Boolean::new(false)),
            Err(ServerError::InvalidName)
        ));
        let counter = host.add_variable("Counter", ua::UInt64::new(10)).unwrap();
        assert!(
            host.add_variable("Counter", ua::Boolean::new(true))
                .is_err()
        );
        counter.set(ua::UInt64::new(20)).unwrap();
    }
}
