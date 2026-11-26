//! Read-only session authorization and pinned server security configuration.
use open62541::{AccessControl, DataType, DefaultAccessControl, ua};
use open62541_sys as sys;
use std::ffi::c_void;

pub(super) struct ReadOnly;

type Session = *const sys::UA_NodeId;
type Context = *mut c_void;
type NativeServer = *mut sys::UA_Server;
type Control = *mut sys::UA_AccessControl;

unsafe extern "C" fn rights(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: Session,
    _: Context,
) -> u32 {
    0
}
unsafe extern "C" fn access(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: Session,
    _: Context,
) -> u8 {
    1
}
unsafe extern "C" fn executable(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: Session,
    _: Context,
) -> bool {
    false
}
unsafe extern "C" fn callable(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: Session,
    _: Context,
    _: Session,
    _: Context,
) -> bool {
    false
}
unsafe extern "C" fn deny<T>(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: *const T,
) -> bool {
    false
}
unsafe extern "C" fn transfer(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: Session,
    _: Context,
) -> bool {
    false
}

unsafe extern "C" fn deny_history_update(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: Session,
    _: sys::UA_PerformUpdateType,
    _: *const sys::UA_DataValue,
) -> bool {
    false
}
unsafe extern "C" fn deny_history_delete(
    _: NativeServer,
    _: Control,
    _: Session,
    _: Context,
    _: Session,
    _: sys::UA_DateTime,
    _: sys::UA_DateTime,
    _: bool,
) -> bool {
    false
}

// SAFETY: the default plugin owns and replaces its configuration. We then install
// static callbacks which borrow no state and return constant permissions.
unsafe impl AccessControl for ReadOnly {
    type Sentinel = ();
    unsafe fn apply(self, config: &mut sys::UA_ServerConfig) -> open62541::Result<()> {
        // Application certificates authenticate secure channels. Keep the separate
        // user-certificate login policy disabled when installing the anonymous ACL.
        config.sessionPKI.verifyCertificate = None;
        unsafe { DefaultAccessControl::new(true, &[]).apply(config)? };
        config.maxSecureChannels = 32;
        config.maxSessions = 16;
        config.maxSubscriptions = 64;
        config.maxMonitoredItems = 1024;
        config.maxNodesPerRead = 1024;
        config.tcpMaxMsgSize = 4 * 1024 * 1024;
        config.tcpMaxChunks = 64;
        let ac = &mut config.accessControl;
        ac.getUserRightsMask = Some(rights);
        ac.getUserAccessLevel = Some(access);
        ac.getUserExecutable = Some(executable);
        ac.getUserExecutableOnObject = Some(callable);
        ac.allowAddNode = Some(deny);
        ac.allowDeleteNode = Some(deny);
        ac.allowAddReference = Some(deny);
        ac.allowDeleteReference = Some(deny);
        ac.allowTransferSubscription = Some(transfer);
        ac.allowHistoryUpdateUpdateData = Some(deny_history_update);
        ac.allowHistoryUpdateDeleteRawModified = Some(deny_history_delete);
        Ok(())
    }
}

pub(super) struct PinnedReader<'a> {
    pub(super) uri: &'a str,
    pub(super) der: &'a [u8],
}

type Activate = unsafe extern "C" fn(
    NativeServer,
    Control,
    *const sys::UA_EndpointDescription,
    *const sys::UA_ByteString,
    Session,
    *const sys::UA_ExtensionObject,
    *mut Context,
) -> sys::UA_StatusCode;

pub(super) struct ClientPin {
    der: ua::ByteString,
    activate: Activate,
}

unsafe extern "C" fn activate_pinned(
    server: NativeServer,
    ac: Control,
    endpoint: *const sys::UA_EndpointDescription,
    certificate: *const sys::UA_ByteString,
    session: Session,
    identity: *const sys::UA_ExtensionObject,
    context: *mut Context,
) -> sys::UA_StatusCode {
    // SAFETY: called by our live UA_Server. Its config context points to the boxed
    // sentinel installed below. open62541 supplies the selected endpoint and channel certificate.
    unsafe {
        let pin = &*((*sys::UA_Server_getConfig(server))
            .context
            .cast::<ClientPin>());
        if endpoint.is_null()
            || certificate.is_null()
            || (*endpoint).securityMode
                != sys::UA_MessageSecurityMode::UA_MESSAGESECURITYMODE_SIGNANDENCRYPT
            || !sys::UA_ByteString_equal(certificate, pin.der.as_ptr())
        {
            return sys::UA_STATUSCODE_BADUSERACCESSDENIED;
        }
        (pin.activate)(
            server,
            ac,
            endpoint,
            certificate,
            session,
            identity,
            context,
        )
    }
}

fn good(status: sys::UA_StatusCode) -> open62541::Result<()> {
    if status == sys::UA_STATUSCODE_GOOD {
        Ok(())
    } else {
        Err(open62541::Error::Server(ua::StatusCode::clone_raw(&status)))
    }
}

// SAFETY: ReadOnly replaces the default ACL. The boxed pin is owned by the SDK
// builder/runner sentinel until shutdown. SDK trust-list and endpoint functions
// copy the transient strings and certificates passed during configuration.
unsafe impl AccessControl for PinnedReader<'_> {
    type Sentinel = Box<ClientPin>;
    unsafe fn apply(self, config: &mut sys::UA_ServerConfig) -> open62541::Result<Self::Sentinel> {
        unsafe {
            ReadOnly.apply(config)?;
            // Discovery clients can inspect the advertised secure endpoint without
            // credentials. The server rejects CreateSession on this discovery channel.
            config.securityPolicyNoneDiscoveryOnly = true;
            good(sys::UA_ServerConfig_addSecurityPolicyNone(
                config,
                std::ptr::null(),
            ))?;
            let mut leaf = ua::ByteString::new(self.der);
            let mut group = ua::NodeId::ns0(
                sys::UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP,
            );
            // Zeroed optional lists are empty UA arrays. The memory store copies the one
            // borrowed ByteString and takes ownership of its own copy.
            let trust = sys::UA_TrustListDataType {
                specifiedLists: sys::UA_TrustListMasks::UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES.0,
                trustedCertificatesSize: 1,
                trustedCertificates: leaf.as_mut_ptr(),
                ..std::mem::zeroed()
            };
            good(sys::UA_CertificateGroup_Memorystore(
                &raw mut config.secureChannelPKI,
                group.as_mut_ptr(),
                &trust,
                config.logging,
                std::ptr::null(),
            ))?;

            ua::String::new(self.uri)?
                .clone_into_raw(&mut config.applicationDescription.applicationUri);
            sys::UA_Array_delete(
                config.endpoints.cast(),
                config.endpointsSize,
                ua::EndpointDescription::data_type(),
            );
            config.endpoints = std::ptr::null_mut();
            config.endpointsSize = 0;
            let policy =
                ua::String::new("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")?;
            good(sys::UA_ServerConfig_addEndpoint(
                config,
                // The C function borrows the backing bytes of this by-value UA_String.
                std::ptr::read(policy.as_ptr()),
                sys::UA_MessageSecurityMode::UA_MESSAGESECURITYMODE_SIGNANDENCRYPT,
            ))?;
            let mut pin = Box::new(ClientPin {
                der: leaf,
                activate: config
                    .accessControl
                    .activateSession
                    .ok_or(open62541::Error::Internal("missing session authentication"))?,
            });
            config.context = (&raw mut *pin).cast();
            config.accessControl.activateSession = Some(activate_pinned);
            Ok(pin)
        }
    }
}
