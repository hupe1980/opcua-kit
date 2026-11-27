use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, ValueEnum};
use opcua_kit::commissioning::{Contract, Snapshot};
use opcua_kit::{
    Client, ConnectError, ConnectionConfig, ConnectionOptions, NodeId, Sample, SampleTimestamp,
    SecurityPolicy, UserIdentity, VariableDefinition, certificate_application_uri,
};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

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

#[derive(Args)]
pub(super) struct Credentials {
    /// Channel policy (default Basic256Sha256). All sessions sign and encrypt.
    #[arg(long, value_enum)]
    security_policy: Option<Policy>,
    /// Site account for named-user authentication. Defaults to anonymous.
    #[arg(long, requires = "password_file")]
    username: Option<String>,
    /// UTF-8 password file. One terminal newline is removed.
    #[arg(long, requires = "username")]
    pub(super) password_file: Option<PathBuf>,
    /// Pinned server leaf certificate in PEM or DER format.
    #[arg(long, value_name = "FILE")]
    pub(super) server_cert: PathBuf,
    /// Expected client application URI. Defaults to the URI in the client certificate.
    #[arg(long, value_name = "URI")]
    client_uri: Option<String>,
    /// Client application certificate in PEM or DER format.
    #[arg(long, value_name = "FILE")]
    pub(super) client_cert: PathBuf,
    /// Matching unencrypted PKCS#8 or PKCS#1 RSA private key in PEM or DER format.
    #[arg(long, value_name = "FILE")]
    pub(super) client_key: PathBuf,
}

impl Credentials {
    fn check_principal(&self, contract: &Contract) -> Result<()> {
        let principal = self
            .username
            .as_ref()
            .map_or_else(|| "anonymous".to_owned(), |u| format!("username:{u}"));
        if contract.principal() != principal {
            return Err(
                "contract principal differs from the selected session user (default anonymous)"
                    .into(),
            );
        }
        Ok(())
    }

    fn with_config<T>(
        &self,
        endpoint: &str,
        server_uri: &str,
        timeout: Duration,
        operation: impl FnOnce(
            ConnectionConfig<'_>,
            ConnectionOptions<'_>,
        ) -> std::result::Result<T, ConnectError>,
    ) -> Result<T> {
        let secret = self
            .password_file
            .as_ref()
            .map(|p| read_credential(p, "--password-file"))
            .transpose()?;
        let user_identity = match (&self.username, secret.as_deref()) {
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
        let server = read_der(&self.server_cert, "--server-cert", &["CERTIFICATE"])?;
        let client = read_der(&self.client_cert, "--client-cert", &["CERTIFICATE"])?;
        let key = read_der(
            &self.client_key,
            "--client-key",
            &["PRIVATE KEY", "RSA PRIVATE KEY"],
        )?;
        let client_uri = match &self.client_uri {
            Some(uri) => uri,
            None => certificate_application_uri(&client)?,
        };
        Ok(operation(
            ConnectionConfig {
                endpoint,
                server_application_uri: server_uri,
                server_certificate_der: &server,
                client_application_uri: client_uri,
                client_certificate_der: &client,
                client_private_key_der: &key,
                timeout,
            },
            ConnectionOptions {
                user_identity,
                security_policy: self.security_policy.map(Into::into).unwrap_or_default(),
            },
        )?)
    }
}

fn read_der(path: &Path, option: &str, labels: &[&str]) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = read_credential(path, option)?;
    if !bytes.trim_ascii_start().starts_with(b"-----BEGIN ") {
        return Ok(bytes);
    }
    let (label, decoded) = pem_rfc7468::decode_vec(bytes.trim_ascii())
        .map_err(|_| format!("{option}: expected one PEM-encoded credential"))?;
    let decoded = Zeroizing::new(decoded);
    if !labels.contains(&label) {
        return Err(format!(
            "{option}: unexpected PEM type; expected {}",
            labels.join(" or ")
        )
        .into());
    }
    Ok(decoded)
}

fn read_credential(path: &Path, option: &str) -> Result<Zeroizing<Vec<u8>>> {
    let limit = if option == "--password-file" {
        4098u64
    } else {
        64 * 1024
    };
    let read_file = || -> io::Result<Zeroizing<Vec<u8>>> {
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
        let mut bytes = Zeroizing::new(Vec::new());
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
    let client = args.credentials.with_config(
        &args.endpoint,
        &args.server_uri,
        Duration::from_secs(args.timeout),
        Client::connect_with,
    )?;
    let (exit_code, document) = runtime.block_on(async {
        let result = operation.execute(&client, &node).await;
        client.disconnect().await;
        result
    })?;
    write_compact_line(&document, None)?;
    Ok(exit_code)
}

pub(super) fn preflight(args: &Connection, contract: &Contract) -> Result<()> {
    args.credentials.check_principal(contract)?;
    args.credentials.with_config(
        &args.endpoint,
        contract.application_uri(),
        Duration::from_secs(args.timeout.min(60)),
        |config, options| config.validate(options),
    )
}

#[cfg(feature = "cems")]
pub(super) fn read_meter(args: Connection, contract: Contract) -> Result<u8> {
    let reading = collect(args, contract, Client::read_meter)?;
    write_compact_line(&reading, None)?;
    Ok(0)
}

pub(super) fn snapshot(args: Connection, contract: Contract) -> Result<Snapshot> {
    collect(args, contract, Client::read_snapshot)
}

fn collect<T: Send + 'static, E: std::error::Error + 'static>(
    args: Connection,
    contract: Contract,
    operation: impl AsyncFnOnce(&Client, &Contract) -> std::result::Result<T, E> + Send + 'static,
) -> Result<T> {
    args.credentials.check_principal(&contract)?;
    let budget = Duration::from_secs(args.timeout);
    let started = std::time::Instant::now();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    // DNS, handshake and disconnect can block independently of a service timeout.
    // Only the caller publishes output; the one-shot process exits at its deadline.
    std::thread::Builder::new()
        .name("opcua-collection".into())
        .spawn(move || {
            let run = || -> Result<T> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()?;
                let client = args.credentials.with_config(
                    &args.endpoint,
                    contract.application_uri(),
                    budget.min(Duration::from_secs(60)),
                    Client::connect_with,
                )?;
                runtime.block_on(async {
                    let value = operation(&client, &contract).await;
                    client.disconnect().await;
                    Ok(value?)
                })
            };
            let _ = sender.send(run().map_err(|error| error.to_string()));
        })?;
    match receiver.recv_timeout(budget.saturating_sub(started.elapsed())) {
        Ok(result) if started.elapsed() < budget => Ok(result?),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("collection worker stopped before returning a result".into())
        }
        _ => Err("collection deadline exceeded".into()),
    }
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
