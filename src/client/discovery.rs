//! Inspect one explicit discovery URL without supplying credentials or following advertised URLs.
use super::{ConnectError, connection::endpoint_host, ua};
use open62541::DataType;
use open62541_sys as sys;
use std::time::Duration;

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

/// Perform a synchronous GetEndpoints against one explicit endpoint (at most 64 descriptions).
/// Uses no client key or user credentials and never follows or trusts returned URLs.
pub fn discover_endpoints(
    endpoint: &str,
    timeout: Duration,
) -> Result<Vec<EndpointInfo>, ConnectError> {
    endpoint_host(endpoint)?;
    if !(Duration::from_millis(1)..=Duration::from_secs(60)).contains(&timeout) {
        return Err(ConnectError::InvalidConfiguration(
            "discovery timeout must be between 1 ms and 60 s",
        ));
    }
    // The wrapper's default get_endpoints() first selects an advertised session-capable
    // endpoint. That fails on servers advertising only encrypted/named-user sessions.
    // Pin the discovery channel to the supplied URL and the None policy allowed for
    // discovery. noSession/noReconnect prevent authentication and following redirects.
    let url = std::ffi::CString::new(endpoint).map_err(|_| ConnectError::InvalidDiscovery)?;
    // SAFETY: open62541's config initialization starts from an all-zero configuration.
    // A silent logger with a null clear callback is borrowed for the entire synchronous call.
    let mut logger: sys::UA_Logger = unsafe { std::mem::zeroed() };
    let mut config: sys::UA_ClientConfig = unsafe { std::mem::zeroed() };
    config.logging = &raw mut logger;
    let status = unsafe { sys::UA_ClientConfig_setDefault(&raw mut config) };
    if status != 0 {
        unsafe {
            sys::UA_ClientConfig_clear(&raw mut config);
        }
        return Err(ConnectError::Connection(open62541::Error::Server(
            ua::StatusCode::clone_raw(&status),
        )));
    }
    config.noSession = true;
    config.noReconnect = true;
    config.timeout = timeout.as_millis() as u32;
    config.endpoint.securityMode = sys::UA_MessageSecurityMode::UA_MESSAGESECURITYMODE_NONE;
    ua::String::new(endpoint)
        .expect("validated URL")
        .move_into_raw(&mut config.endpoint.endpointUrl);
    ua::String::new("http://opcfoundation.org/UA/SecurityPolicy#None")
        .expect("static URI")
        .move_into_raw(&mut config.endpoint.securityPolicyUri);
    // The native constructor takes ownership of the config's nested allocations on success.
    let client = unsafe { sys::UA_Client_newWithConfig(&raw const config) };
    if client.is_null() {
        unsafe { sys::UA_ClientConfig_clear(&raw mut config) };
        return Err(ConnectError::InvalidDiscovery);
    }
    let mut endpoints = Endpoints {
        len: 0,
        data: std::ptr::null_mut(),
    };
    let status = unsafe {
        sys::UA_Client_getEndpoints(
            client,
            url.as_ptr(),
            &raw mut endpoints.len,
            &raw mut endpoints.data,
        )
    };
    unsafe { sys::UA_Client_delete(client) };
    if status != 0 {
        return Err(ConnectError::Connection(open62541::Error::Server(
            ua::StatusCode::clone_raw(&status),
        )));
    }
    let invalid = || ConnectError::InvalidDiscovery;
    let descriptions =
        unsafe { super::wire::slice(endpoints.data, endpoints.len, 64) }.ok_or_else(invalid)?;
    let mut remaining = 1024 * 1024usize;
    let mut text = |s: &ua::String| {
        let b = s.as_bytes().unwrap_or_default();
        if b.len() > 4096 {
            return Err(invalid());
        }
        remaining = remaining.checked_sub(b.len()).ok_or_else(invalid)?;
        Ok(std::str::from_utf8(b).map_err(|_| invalid())?.to_owned())
    };
    descriptions
        .iter()
        .map(|raw| {
            // SAFETY: immutable nested fields borrowed for the lifetime of the owning SDK response.
            let ep = ua::EndpointDescription::raw_ref(raw);
            let tokens = unsafe {
                super::wire::slice(raw.userIdentityTokens, raw.userIdentityTokensSize, 64)
            }
            .ok_or_else(invalid)?;
            let user_tokens = tokens
                .iter()
                .map(|t| {
                    Ok(EndpointToken {
                        policy_id: text(ua::String::raw_ref(&t.policyId))?,
                        kind: t.tokenType.0,
                        security_policy_uri: text(ua::String::raw_ref(&t.securityPolicyUri))?,
                    })
                })
                .collect::<Result<_, ConnectError>>()?;
            Ok(EndpointInfo {
                endpoint_url: text(ep.endpoint_url())?,
                application_uri: text(ua::String::raw_ref(&raw.server.applicationUri))?,
                security_mode: raw.securityMode.0,
                security_policy_uri: text(ep.security_policy_uri())?,
                transport_profile_uri: text(ep.transport_profile_uri())?,
                user_tokens,
            })
        })
        .collect()
}

// Own the SDK-allocated array through validation and conversion, including every error path.
struct Endpoints {
    len: usize,
    data: *mut sys::UA_EndpointDescription,
}
impl Drop for Endpoints {
    fn drop(&mut self) {
        unsafe {
            sys::UA_Array_delete(
                self.data.cast(),
                self.len,
                &sys::UA_TYPES[sys::UA_TYPES_ENDPOINTDESCRIPTION as usize],
            );
        }
    }
}
