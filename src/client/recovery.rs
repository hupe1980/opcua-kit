//! Fresh, pinned sessions for long-running polling hosts.

use tokio::task::JoinHandle;

use super::{
    CertificateRollover, Client, ConnectError, ConnectionConfig, ConnectionOptions, ReadError,
    UserIdentity,
};

/// Relationship between the returned polling session and previous acquisitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// First authenticated session returned by this owner.
    Initial,
    /// The previously returned session is still usable.
    Continuing,
    /// A fresh authenticated session has replaced an interrupted one. Data may be missing.
    Reconnected,
}

/// One session lease. A new generation has a newly validated namespace table and read limit.
pub struct RecoveredSession<'a> {
    /// The ordinary pinned client. All read, subscription and commissioning APIs retain their semantics.
    pub client: &'a Client,
    /// Monotonically increasing successful session number, starting at one.
    pub generation: u64,
    /// Whether polling continues on the previous session or starts a fresh generation.
    pub state: SessionState,
}

/// A fresh session could not be authenticated and prepared. The caller chooses when to retry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecoveryError {
    /// Local validation, pinned-channel authentication or session activation failed.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// The server identity, namespace array or read limits could not be established.
    #[error("could not initialize fresh read-session metadata: {0}")]
    Bootstrap(#[source] ReadError),
    /// No Tokio runtime is available to drive the handshake.
    #[error("session recovery needs a running Tokio runtime")]
    NoRuntime,
    /// A connection worker terminated unexpectedly.
    #[error("session recovery worker did not complete")]
    Worker(#[from] tokio::task::JoinError),
    /// All session generation numbers have been used.
    #[error("read-session generation exhausted")]
    GenerationExhausted,
}

/// Reuses a pinned client until a channel change or failed/cancelled read retires its session.
/// Each call to [`Self::session`] starts at most one connection attempt with the original endpoint,
/// credentials, identity, policy and timeout. Schedule further attempts and backoff in the host.
/// A lost read remains visible to the caller. A fresh generation does not replay observations.
///
/// ```
/// use opcua_kit::{NodeId, client::{RecoveringClient, SessionState}};
///
/// async fn poll(owner: &mut RecoveringClient<'_>, node: &NodeId) -> Result<(), Box<dyn std::error::Error>> {
///     let session = owner.session().await?;
///     if session.state == SessionState::Reconnected {
///         eprintln!("coverage gap before generation {}", session.generation);
///     }
///     let sample = session.client.read_scalar::<u64>(node).await?;
///     println!("status={:#010x} register={:?}", sample.status, sample.value);
///     Ok(())
/// }
/// ```
pub struct RecoveringClient<'a> {
    config: ConnectionConfig<'a>,
    options: ConnectionOptions<'a>,
    rollover: Option<CertificateRollover<'a>>,
    current: Option<Client>,
    connecting: Option<JoinHandle<Result<Client, RecoveryError>>>,
    generation: u64,
}

fn session_health(client: &mut Client) -> Result<(), ReadError> {
    client.check_channel()?;
    if client.reads.get_mut().interrupted || !client.inner.state().connect_status.is_good() {
        return Err(ReadError::SessionInterrupted);
    }
    Ok(())
}

impl<'a> RecoveringClient<'a> {
    /// Bind the peer and credentials used for every generation. Network I/O begins at `session()`.
    pub fn new(config: ConnectionConfig<'a>, options: ConnectionOptions<'a>) -> Self {
        Self {
            config,
            options,
            rollover: None,
            current: None,
            connecting: None,
            generation: 0,
        }
    }

    /// Apply the same bounded two-leaf trust policy to each fresh handshake.
    pub fn new_with_rollover(
        config: ConnectionConfig<'a>,
        options: ConnectionOptions<'a>,
        rollover: CertificateRollover<'a>,
    ) -> Self {
        let mut owner = Self::new(config, options);
        owner.rollover = Some(rollover);
        owner
    }

    /// Acquire an authenticated session. The blocking handshake runs on a worker. Dropping this
    /// future leaves any pending attempt with the owner so its next call joins the same attempt.
    ///
    /// Check the generation before using results or recreating monitored items. The session lease
    /// reflects known channel and read failures; the socket can still fail during any operation.
    pub async fn session(&mut self) -> Result<RecoveredSession<'_>, RecoveryError> {
        let reusable = self
            .current
            .as_mut()
            .is_some_and(|c| session_health(c).is_ok());
        let state = if reusable {
            SessionState::Continuing
        } else {
            let next = self
                .generation
                .checked_add(1)
                .ok_or(RecoveryError::GenerationExhausted)?;
            if self.connecting.is_none() {
                self.connecting = Some(self.start_connection()?);
            }
            let result = self
                .connecting
                .as_mut()
                .expect("connection attempt installed")
                .await;
            self.connecting = None;
            let mut client = result??;
            // The original awaiter may have cancelled long before this caller joined the task.
            if let Err(source) = session_health(&mut client) {
                client.disconnect().await;
                return Err(RecoveryError::Bootstrap(source));
            }
            self.current = Some(client);
            self.generation = next;
            if next == 1 {
                SessionState::Initial
            } else {
                SessionState::Reconnected
            }
        };
        Ok(RecoveredSession {
            client: self.current.as_ref().expect("session prepared"),
            generation: self.generation,
            state,
        })
    }

    /// Transfer a newly prepared session to a protocol service that owns its entire lifecycle.
    pub(super) async fn into_client(mut self) -> Result<Client, RecoveryError> {
        self.session().await?;
        Ok(self.current.take().expect("session was prepared"))
    }

    fn start_connection(
        &mut self,
    ) -> Result<JoinHandle<Result<Client, RecoveryError>>, RecoveryError> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| RecoveryError::NoRuntime)?;
        let config = self.config;
        config.validate_input_lengths()?;
        self.options.user_identity.validate()?;
        // Borrow for the owner's lifetime; make bounded, temporary owned copies only while
        // a 'static blocking worker needs them. No user-supplied configuration is logged.
        let endpoint = config.endpoint.to_owned();
        let server_uri = config.server_application_uri.to_owned();
        let server_cert = config.server_certificate_der.to_owned();
        let rollover = self
            .rollover
            .map(|r| {
                r.validate_length()?;
                Ok::<_, ConnectError>((r.replacement_der.to_vec(), r.original_valid_until))
            })
            .transpose()?;
        let client_uri = config.client_application_uri.to_owned();
        let client_cert = config.client_certificate_der.to_owned();
        let client_key = config.client_private_key_der.to_owned();
        let timeout = config.timeout;
        let policy = self.options.security_policy;
        let login = match self.options.user_identity {
            UserIdentity::Anonymous => None,
            UserIdentity::Username { username, password } => {
                Some((username.to_owned(), password.to_owned()))
            }
        };
        let retired = self.current.take();
        Ok(runtime.spawn(async move {
            let client = tokio::task::spawn_blocking(move || {
                // An interrupted SDK driver's destructor can join its worker thread.
                drop(retired);
                let identity = match &login {
                    None => UserIdentity::Anonymous,
                    Some((username, password)) => UserIdentity::Username { username, password },
                };
                Client::connect_pinned(
                    ConnectionConfig {
                        endpoint: &endpoint,
                        server_application_uri: &server_uri,
                        server_certificate_der: &server_cert,
                        client_application_uri: &client_uri,
                        client_certificate_der: &client_cert,
                        client_private_key_der: &client_key,
                        timeout,
                    },
                    ConnectionOptions {
                        security_policy: policy,
                        user_identity: identity,
                    },
                    rollover
                        .as_ref()
                        .map(|(cert, deadline)| CertificateRollover {
                            replacement_der: cert,
                            original_valid_until: *deadline,
                        }),
                )
            })
            .await??;
            let initialized = client.read_session().await.map(|_| ());
            if let Err(source) = initialized {
                client.disconnect().await;
                return Err(RecoveryError::Bootstrap(source));
            }
            Ok(client)
        }))
    }

    /// Complete any pending attempt and gracefully disconnect its session.
    pub async fn disconnect(mut self) {
        if let Some(handle) = self.connecting.take()
            && let Ok(Ok(client)) = handle.await
        {
            client.disconnect().await;
        }
        if let Some(client) = self.current.take() {
            client.disconnect().await;
        }
    }
}

impl Drop for RecoveringClient<'_> {
    fn drop(&mut self) {
        if let Some(handle) = &self.connecting {
            // A synchronous handshake already running on the worker ends at its SDK timeout.
            handle.abort();
        }
    }
}
