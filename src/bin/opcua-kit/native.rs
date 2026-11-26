use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, ValueEnum};
use opcua_kit::commissioning::{Contract, Snapshot};
use opcua_kit::{
    Client, ConnectionConfig, ConnectionOptions, NodeId, Sample, SampleTimestamp, SecurityPolicy,
    UserIdentity, VariableDefinition,
};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Connection, Result, write_compact_line};

#[derive(Args)]
pub(super) struct NodeArgs {
    /// OPC UA TCP endpoint with an explicit port.
    #[arg(long, value_name = "URL")]
    endpoint: String,
    /// Expected server application URI.
    #[arg(long, value_name = "URI")]
    server_uri: String,
    #[command(flatten)]
    credentials: Credentials,
    /// Namespace URI for the selected node.
    #[arg(long, value_name = "URI")]
    namespace: String,
    /// Typed OPC UA identifier (i=, s=, g= or b=).
    #[arg(long, value_name = "ID")]
    id: String,
    /// Response timeout in seconds (1–60).
    #[arg(long, value_name = "SECONDS", default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=60))]
    timeout: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum Policy {
    #[value(name = "Basic256Sha256")]
    Basic,
    #[value(name = "Aes128_Sha256_RsaOaep")]
    Aes128,
    #[value(name = "Aes256_Sha256_RsaPss")]
    Aes256,
}
impl From<Policy> for SecurityPolicy {
    fn from(p: Policy) -> Self {
        match p {
            Policy::Basic => Self::Basic256Sha256,
            Policy::Aes128 => Self::Aes128Sha256RsaOaep,
            Policy::Aes256 => Self::Aes256Sha256RsaPss,
        }
    }
}

#[derive(Clone, Args)]
pub(super) struct SessionArgs {
    /// Exact native policy (default Basic256Sha256). The channel always signs and encrypts.
    #[arg(long, value_enum, requires = "client_uri")]
    security_policy: Option<Policy>,
    /// Site account for named-user authentication. Defaults to anonymous.
    #[arg(long, requires_all=["client_uri","password_file"])]
    username: Option<String>,
    /// UTF-8 password file. One terminal newline is removed.
    #[arg(long, requires = "username")]
    pub(super) password_file: Option<PathBuf>,
}
impl SessionArgs {
    fn principal(&self) -> String {
        self.username
            .as_ref()
            .map_or_else(|| "anonymous".to_owned(), |n| format!("username:{n}"))
    }
}

#[derive(Args)]
struct Credentials {
    #[command(flatten)]
    session: SessionArgs,
    /// Pinned server leaf certificate in DER format.
    #[arg(long, value_name = "DER_FILE")]
    server_cert: PathBuf,
    /// Application URI in the client certificate.
    #[arg(long, value_name = "URI")]
    client_uri: String,
    /// Client application certificate in DER format.
    #[arg(long, value_name = "DER_FILE")]
    client_cert: PathBuf,
    /// Unencrypted DER private key matching the client certificate.
    #[arg(long, value_name = "DER_FILE")]
    client_key: PathBuf,
}

impl Credentials {
    fn connect(&self, endpoint: &str, server_uri: &str, timeout: Duration) -> Result<Client> {
        let secret = self
            .session
            .password_file
            .as_ref()
            .map(|p| read_credential(p, "--password-file"))
            .transpose()?;
        let user_identity = match (&self.session.username, secret.as_deref()) {
            (None, None) => UserIdentity::Anonymous,
            (Some(username), Some(bytes)) => {
                let bytes = bytes
                    .strip_suffix(b"\r\n")
                    .or_else(|| bytes.strip_suffix(b"\n"))
                    .unwrap_or(bytes);
                UserIdentity::Username {
                    username,
                    password: std::str::from_utf8(bytes)
                        .map_err(|_| "password file must be UTF-8")?,
                }
            }
            _ => return Err("--username and --password-file must be supplied together".into()),
        };
        Ok(Client::connect_with(
            ConnectionConfig {
                endpoint,
                server_application_uri: server_uri,
                server_certificate_der: &read_credential(&self.server_cert, "--server-cert")?,
                client_application_uri: &self.client_uri,
                client_certificate_der: &read_credential(&self.client_cert, "--client-cert")?,
                client_private_key_der: &read_credential(&self.client_key, "--client-key")?,
                timeout,
            },
            ConnectionOptions {
                user_identity,
                security_policy: self
                    .session
                    .security_policy
                    .map(Into::into)
                    .unwrap_or_default(),
            },
        )?)
    }
}

fn read_credential(path: &Path, option: &str) -> Result<Vec<u8>> {
    let limit = if option == "--password-file" {
        4098u64
    } else {
        64 * 1024
    };
    let read_file = || -> io::Result<Vec<u8>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        if !path.metadata()?.is_file() {
            return Err(io::Error::other("expected a regular file"));
        }
        let file = options.open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > limit {
            return Err(io::Error::other(
                "expected a regular file within the credential size limit",
            ));
        }
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > limit {
            return Err(io::Error::other("empty or oversized credential file"));
        }
        Ok(bytes)
    };
    read_file().map_err(|error| format!("{option}: {error}").into())
}

fn clock(stamp: SampleTimestamp) -> Result<Value> {
    let base =
        OffsetDateTime::from_unix_timestamp_nanos(stamp.base_unix_nanos)?.format(&Rfc3339)?;
    Ok(json!({"baseUtc": base, "tenPicoseconds": stamp.ten_picoseconds}))
}

pub(super) enum Operation {
    Browse,
    Read,
    Describe { units: bool },
}

impl Operation {
    async fn execute(self, client: &Client, node: &NodeId) -> Result<(u8, Value)> {
        match self {
            Self::Browse => {
                let entries = client.browse_children(node).await?;
                let children:Vec<_>=entries.into_iter().map(|entry|json!({
                    "node":entry.node,"browseName":{"namespace":entry.browse_name.namespace,"name":entry.browse_name.name},
                    "referenceType":entry.reference_type,"nodeClass":entry.node_class.to_string()
                })).collect();
                Ok((0, Value::Array(children)))
            }
            Self::Read => read_document(client.read_scalar(node).await?),
            Self::Describe { units } => {
                let (mut code, mut document) =
                    definition_document(client.read_definition(node).await?)?;
                if units {
                    let evidence = client.read_engineering_units(node).await?;
                    if !evidence
                        .sample
                        .value
                        .as_ref()
                        .is_some_and(opcua_kit::EngineeringUnit::is_identified)
                    {
                        code = 3;
                    }
                    let stage = match evidence.stage {
                        opcua_kit::UnitStage::Browse => "browse",
                        opcua_kit::UnitStage::DataType => "dataType",
                        opcua_kit::UnitStage::ValueRank => "valueRank",
                        opcua_kit::UnitStage::Value => "value",
                    };
                    document["engineeringUnits"] = json!({
                        "stage": stage,
                        "property": evidence.property,
                        "status": evidence.sample.status,
                        "value": evidence.sample.value,
                    });
                }
                Ok((code, document))
            }
        }
    }
}

pub(super) fn run(args: NodeArgs, operation: Operation) -> Result<u8> {
    let node = NodeId::new(args.namespace, args.id)?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let client = args.credentials.connect(
        &args.endpoint,
        &args.server_uri,
        Duration::from_secs(args.timeout),
    )?;
    let (exit_code, document) = runtime.block_on(async {
        let result = operation.execute(&client, &node).await;
        client.disconnect().await;
        result
    })?;
    write_compact_line(&document, None)?;
    Ok(exit_code)
}

#[cfg(feature = "cems")]
pub(super) fn read_meter(args: Connection, client_uri: String, contract: &Contract) -> Result<u8> {
    let reading = collect(&args, &client_uri, contract, Client::read_meter)?;
    write_compact_line(&reading, None)?;
    Ok(0)
}

pub(super) fn snapshot(
    args: &Connection,
    client_uri: &str,
    contract: &Contract,
) -> Result<Snapshot> {
    collect(args, client_uri, contract, Client::read_snapshot)
}

fn collect<T, E: std::error::Error + 'static>(
    args: &Connection,
    client_uri: &str,
    contract: &Contract,
    operation: impl AsyncFnOnce(&Client, &Contract) -> std::result::Result<T, E>,
) -> Result<T> {
    if contract.principal() != args.session.principal() {
        return Err(
            "contract principal differs from the selected session user (default anonymous)".into(),
        );
    }
    let credentials = Credentials {
        session: args.session.clone(),
        client_uri: client_uri.to_owned(),
        server_cert: args
            .server_cert
            .clone()
            .ok_or("--server-cert is required for native collection")?,
        client_cert: args
            .client_cert
            .clone()
            .ok_or("--client-cert is required for native collection")?,
        client_key: args
            .client_key
            .clone()
            .ok_or("--client-key is required for native collection")?,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let timeout = Duration::from_secs(args.timeout);
    let deadline = tokio::time::Instant::now() + timeout;
    let client = credentials.connect(
        &args.endpoint,
        contract.application_uri(),
        timeout.min(Duration::from_secs(60)),
    )?;
    let result = runtime
        .block_on(async {
            // The synchronous handshake consumes part of the collection budget.
            let result = if tokio::time::Instant::now() < deadline {
                tokio::time::timeout_at(deadline, operation(&client, contract))
                    .await
                    .ok()
                    .filter(|_| tokio::time::Instant::now() < deadline)
            } else {
                None
            };
            client.disconnect().await;
            result
        })
        .ok_or("native collection deadline exceeded")??;
    Ok(result)
}

fn definition_document(definition: VariableDefinition) -> Result<(u8, Value)> {
    let data_type = definition.data_type?;
    let value_rank = definition.value_rank?;
    let complete = data_type.value.is_some() && value_rank.value.is_some();
    let document = json!({
        "dataType": {"status": data_type.status, "value": data_type.value},
        "valueRank": {"status": value_rank.status, "value": value_rank.value},
    });
    Ok((if complete { 0 } else { 3 }, document))
}

fn read_document(sample: Sample<u64>) -> Result<(u8, Value)> {
    if sample.status != 0 {
        return Err(format!("UInt64 read returned status 0x{:08X}", sample.status).into());
    }
    let value = sample.value.ok_or("UInt64 read returned no value")?;
    let document = json!({
        "status": sample.status,
        "value": value,
        "sourceTimestamp": sample.source_timestamp.map(clock).transpose()?,
        "serverTimestamp": sample.server_timestamp.map(clock).transpose()?,
    });
    Ok((0, document))
}
