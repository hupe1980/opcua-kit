use std::error::Error;
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::builder::{PathBufValueParser, TypedValueParser};
use clap::{Args, Parser, Subcommand, ValueEnum};
#[cfg(feature = "cems")]
use opcua_kit::commissioning::meter::{project_meter_trace, validate_meter_contract};
use opcua_kit::commissioning::{
    Contract, MAX_DOCUMENT_BYTES, Report, assess, compare, draft_contract, parse_contract,
    parse_snapshot,
};

mod capture;
mod display;
mod native;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, ValueEnum)]
enum DemoScenario {
    /// A changed signal type and a missing node.
    Commissioning,
    /// A temperature changes from Celsius to Fahrenheit while its type stays Double.
    Units,
}

impl DemoScenario {
    fn documents(self) -> [&'static [u8]; 3] {
        match self {
            Self::Commissioning => [
                include_bytes!("../../../fixtures/commissioning/contract.json"),
                include_bytes!("../../../fixtures/commissioning/before.json"),
                include_bytes!("../../../fixtures/commissioning/after.json"),
            ],
            Self::Units => [
                include_bytes!("../../../fixtures/units/contract.json"),
                include_bytes!("../../../fixtures/units/before.json"),
                include_bytes!("../../../fixtures/units/after.json"),
            ],
        }
    }
}

#[derive(Parser)]
#[command(
    name = "opcua-kit",
    version,
    about = "Check the OPC UA signals a gateway depends on",
    after_help = "Start offline with 'opcua-kit demo'. Run a subcommand with --help for examples."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Browse one local hierarchical level on a pinned session. Outputs stable URI-qualified node identities.
    Browse(native::NodeArgs),
    /// Inspect advertised OPC UA endpoints, policies and user tokens without sending credentials.
    Discover {
        /// Explicit opc.tcp discovery URL.
        #[arg(long)]
        endpoint: String,
        /// Request timeout in seconds.
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout: u64,
    },
    /// Read one UInt64 scalar over a pinned secure channel and print its status and clocks as JSON.
    #[command(
        after_help = "Example: opcua-kit read --endpoint opc.tcp://plc.example:4840 --server-uri urn:plant:server --server-cert server.der --client-uri urn:factory:dashboard --client-cert client.der --client-key client-key.der --namespace urn:factory:line-1 --id s=PartsProduced"
    )]
    Read(native::NodeArgs),
    /// Read a node's declared DataType and ValueRank over a pinned secure channel.
    #[command(
        after_help = "Prints JSON with the status of each requested field. Use --units to include the standard EngineeringUnits property. Exits 0 for complete metadata, 3 for incomplete metadata, or 1 on failure."
    )]
    Describe {
        #[command(flatten)]
        node: native::NodeArgs,
        /// Also inspect the standard EngineeringUnits property and report its identity.
        #[arg(long)]
        units: bool,
    },
    /// Run the packaged before/after example (one mismatch, exit 2).
    Demo {
        /// Choose the commissioning change to investigate.
        #[arg(long, value_enum, default_value_t = DemoScenario::Commissioning)]
        scenario: DemoScenario,
        /// Print a versioned JSON report suitable for CI.
        #[arg(long)]
        json: bool,
        /// Write the three editable example documents to a new directory and exit 0.
        #[arg(long, value_name = "NEW_DIR", conflicts_with = "json")]
        export: Option<PathBuf>,
    },
    /// Assess a current snapshot against a contract, optionally using an earlier baseline.
    #[command(
        after_help = "First inspection: opcua-kit check --contract plant.json --snapshot current.json\nCompare with a baseline: add --before baseline.json\nExit codes: 0 matched, 1 invalid input, 2 confirmed mismatch, 3 unverified."
    )]
    Check {
        /// Requirements for this device and principal.
        #[arg(long, value_name = "FILE")]
        contract: PathBuf,
        /// Current observation. Pass - to read a JSON snapshot from a pipe or redirection.
        #[arg(long, visible_alias = "after", value_name = "FILE|-")]
        snapshot: PathBuf,
        /// Optional baseline for detecting resolved mismatches.
        #[arg(long, value_name = "FILE")]
        before: Option<PathBuf>,
        /// Print a versioned JSON decision suitable for CI.
        #[arg(long)]
        json: bool,
    },
    /// Draft and validate commissioning contracts offline.
    #[command(subcommand)]
    Contract(ContractCommand),
    /// Read declared metadata from one OPC UA endpoint, or check field readiness offline.
    Capture(Capture),
    #[cfg(feature = "cems")]
    /// Read one approved cumulative import register or prepare its CEMS trace.
    #[command(subcommand)]
    Meter(MeterCommand),
}

#[cfg(feature = "cems")]
#[derive(Clone, Copy, ValueEnum)]
enum RegisterType {
    /// Exact unsigned register in Wh.
    Uint64,
    /// Binary32 register with a fractional observation.
    Float,
    /// Binary64 register above the binary32 unit-Wh limit.
    Double,
}

#[cfg(feature = "cems")]
#[derive(Subcommand)]
enum MeterCommand {
    /// Export an editable, offline import-register example for cemsd reconciliation.
    Example {
        /// Choose the register type for the synthetic shift.
        #[arg(long, value_enum, default_value_t = RegisterType::Uint64)]
        register_type: RegisterType,
        /// Create this new directory with a contract, readings and an independent window.
        #[arg(long, value_name = "NEW_DIR")]
        export: PathBuf,
    },
    /// Verify the declared register and write one timestamped reading as a JSON line.
    #[command(
        after_help = "Use one reviewed scalar UInt32, UInt64, Float or Double register in Wh. Supply --client-uri with DER credentials to read in process. Append successful observations to your readings file."
    )]
    Read {
        #[command(flatten)]
        connection: Connection,
        /// Read with the native client using this application URI and DER credentials.
        #[arg(long, value_name = "URI", conflicts_with = "insecure_loopback")]
        client_uri: Option<String>,
    },
    /// Project saved readings and independent quarter-hour closes into a cemsd trace.
    #[command(
        after_help = "Use '--output trace.json' to save a new trace, then run 'cemsd reconcile trace.json' to check its coverage and differences."
    )]
    Trace {
        /// Approved single-register contract used to collect the readings.
        #[arg(long, value_name = "FILE")]
        contract: PathBuf,
        /// Window with meter identity, Wh tolerance and independently closed intervals.
        #[arg(long, value_name = "FILE")]
        window: PathBuf,
        /// Meter evidence in JSON Lines format. Pass - for stdin.
        #[arg(long, value_name = "FILE|-")]
        readings: PathBuf,
        /// Save the validated trace to a new file. Omit for stdout.
        #[arg(long, value_name = "NEW_FILE", value_parser = new_output_path())]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ContractCommand {
    /// Write an editable contract from a reviewed device snapshot.
    #[command(
        after_help = "Review the signal list and expected metadata before using the draft to commission a device."
    )]
    Draft {
        /// Saved snapshot, or - to read one snapshot from stdin.
        #[arg(long, value_name = "FILE|-")]
        snapshot: PathBuf,
        /// Save the editable contract to a new file. Omit for stdout.
        #[arg(long, value_name = "NEW_FILE", value_parser = new_output_path())]
        output: Option<PathBuf>,
    },
    /// Validate a contract locally and print its signal count.
    Validate {
        /// Edited contract, or - to read one contract from stdin.
        #[arg(long, value_name = "FILE|-")]
        contract: PathBuf,
    },
}

#[derive(Args)]
struct Connection {
    #[command(flatten)]
    session: native::SessionArgs,
    /// Reviewed contract specifying the device, principal and signals.
    #[arg(long)]
    contract: PathBuf,
    /// An explicitly selected opc.tcp endpoint URL.
    #[arg(long)]
    endpoint: String,
    /// Pinned server leaf certificate (native: DER, Python collector: PEM or DER).
    #[arg(
        long,
        required_unless_present = "insecure_loopback",
        conflicts_with = "insecure_loopback"
    )]
    server_cert: Option<PathBuf>,
    /// Client application certificate (native: DER, Python collector: PEM or DER).
    #[arg(
        long,
        required_unless_present = "insecure_loopback",
        conflicts_with = "insecure_loopback"
    )]
    client_cert: Option<PathBuf>,
    /// Unencrypted client private key (native: DER, Python collector: PEM or DER).
    #[arg(
        long,
        required_unless_present = "insecure_loopback",
        conflicts_with = "insecure_loopback"
    )]
    client_key: Option<PathBuf>,
    /// Allow plaintext on a literal loopback IP address for local fixtures.
    #[arg(long)]
    insecure_loopback: bool,
    /// Network collection deadline in seconds.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout: u64,
}

#[derive(Args)]
struct Capture {
    #[command(flatten)]
    connection: Connection,
    /// Capture in process with DER credentials and the application URI in the client certificate.
    #[arg(long, value_name = "URI", conflicts_with_all = ["preflight", "insecure_loopback"])]
    client_uri: Option<String>,
    /// Check the cached runtime, contract and local security configuration without contacting the endpoint.
    #[arg(long, conflicts_with = "output")]
    preflight: bool,
    /// Atomically replace this snapshot after a successful capture. Default is stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("document exceeds 4 MiB".into());
    }
    Ok(bytes)
}

fn read_document(path: &Path) -> Result<Vec<u8>> {
    let result = (|| -> Result<Vec<u8>> {
        if !path.metadata()?.is_file() {
            return Err("expected a regular JSON file".into());
        }
        read_bounded(File::open(path)?)
    })();
    result.map_err(|e| {
        let path = path.to_string_lossy();
        // Leave the OS error visible even when the supplied path exceeds filesystem limits.
        match path.char_indices().nth(240) {
            Some((end, _)) => format!("{}…: {e}", &path[..end]),
            None => format!("{path}: {e}"),
        }
        .into()
    })
}

fn read_input(path: &Path, kind: &str) -> Result<Vec<u8>> {
    if path.as_os_str() != "-" {
        return read_document(path);
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(format!("pipe a {kind} to --{kind} - or pass --{kind} FILE").into());
    }
    read_bounded(stdin.lock()).map_err(|e| format!("{kind} on stdin: {e}").into())
}

fn new_output_path() -> impl TypedValueParser<Value = PathBuf> {
    PathBufValueParser::new().try_map(|path: PathBuf| {
        if path.as_os_str() == "-" {
            Err("omit --output to write to stdout, or use ./- for a file named '-'")
        } else {
            Ok(path)
        }
    })
}

fn json_line(json: &str) -> Option<impl FnOnce(&mut dyn Write) -> io::Result<()> + '_> {
    // serde_json already escapes controls inside strings, except for non-ASCII
    // terminal and directional characters. Preserve their meaning as JSON escapes.
    let controls = move || {
        json.char_indices()
            .filter(|(_, c)| !c.is_ascii() && display::unsafe_terminal_char(*c))
    };
    let extra: usize = controls().map(|(_, c)| 6 - c.len_utf8()).sum();
    if json.len() + extra >= MAX_DOCUMENT_BYTES {
        return None;
    }
    Some(move |writer: &mut dyn Write| {
        let mut out = io::BufWriter::new(writer);
        let mut start = 0;
        for (offset, c) in controls() {
            out.write_all(&json.as_bytes()[start..offset])?;
            write!(out, "\\u{:04x}", u32::from(c))?;
            start = offset + c.len_utf8();
        }
        out.write_all(&json.as_bytes()[start..])?;
        writeln!(out)?;
        out.flush()
    })
}

fn publish_json_line(json: &str, output: Option<&Path>) -> Result<bool> {
    let Some(write_line) = json_line(json) else {
        return Ok(false);
    };
    if let Some(path) = output {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| format!("prepare --output in its parent directory: {e}"))?;
        write_line(staged.as_file_mut())
            .and_then(|()| staged.as_file().sync_all())
            .map_err(|e| format!("write staged --output file: {e}"))?;
        // Arbitrate competing writers at publication, after the final byte.
        staged.persist_noclobber(path).map_err(|e| {
            if e.error.kind() == io::ErrorKind::AlreadyExists {
                "output already exists; choose a new file for --output".to_owned()
            } else {
                format!("create new --output file: {}", e.error)
            }
        })?;
    } else {
        write_line(&mut io::stdout().lock())?;
    }
    Ok(true)
}

fn write_compact_line(value: &impl serde::Serialize, output: Option<&Path>) -> Result<()> {
    let json = serde_json::to_string(value)?;
    if !publish_json_line(&json, output)? {
        return Err("JSON output exceeds 4 MiB".into());
    }
    Ok(())
}

fn write_draft(contract: &Contract, output: Option<&Path>) -> Result<u8> {
    // Stage each encoding, including room for the final newline. A near-limit
    // input can require compact JSON to fit the same document budget on replay.
    let mut buffer = vec![0; MAX_DOCUMENT_BYTES - 1];
    for pretty in [true, false] {
        let mut remaining = buffer.as_mut_slice();
        let result = if pretty {
            serde_json::to_writer_pretty(&mut remaining, contract)
        } else {
            serde_json::to_writer(&mut remaining, contract)
        };
        match result {
            Err(error) if error.io_error_kind() == Some(io::ErrorKind::WriteZero) => continue,
            result => result?,
        }
        let size = MAX_DOCUMENT_BYTES - 1 - remaining.len();
        if publish_json_line(std::str::from_utf8(&buffer[..size])?, output)? {
            return Ok(0);
        }
    }
    Err("draft contract exceeds 4 MiB".into())
}

fn write_report(report: Report, json: bool) -> Result<u8> {
    let mut out = io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        display::report(&mut out, &report)?;
    }
    Ok(report.exit_code())
}

fn export_example(dir: &Path, documents: [(&str, &[u8]); 3]) -> Result<u8> {
    // Exclusive creation prevents a repeated demo from overwriting someone's edits.
    std::fs::create_dir(dir)
        .map_err(|e| format!("create new example directory {}: {e}", dir.display()))?;
    let mut created = Vec::new();
    let write_files = (|| -> io::Result<()> {
        for (name, bytes) in documents {
            let path = dir.join(name);
            let mut file = File::create_new(&path)?;
            created.push(path);
            file.write_all(bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = write_files {
        // Remove only files we exclusively created. Other entries belong to the caller.
        for path in created {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir(dir);
        return Err(error.into());
    }
    writeln!(
        io::stdout(),
        "Wrote {}, {} and {} to {}",
        documents[0].0,
        documents[1].0,
        documents[2].0,
        display::safe(&dir.display().to_string())
    )?;
    Ok(0)
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Commands::Discover { endpoint, timeout } => {
            let result =
                opcua_kit::discover_endpoints(&endpoint, std::time::Duration::from_secs(timeout))?;
            write_compact_line(&result, None)?;
            Ok(0)
        }
        Commands::Browse(args) => native::run(args, native::Operation::Browse),
        Commands::Read(args) => native::run(args, native::Operation::Read),
        Commands::Describe { node, units } => {
            native::run(node, native::Operation::Describe { units })
        }
        Commands::Demo {
            export: Some(dir),
            scenario,
            ..
        } => {
            let [contract, before, after] = scenario.documents();
            export_example(
                &dir,
                [
                    ("contract.json", contract),
                    ("before.json", before),
                    ("after.json", after),
                ],
            )
        }
        Commands::Demo { json, scenario, .. } => {
            let [contract, before, after] = scenario.documents();
            let report = compare(
                &parse_contract(contract)?,
                &parse_snapshot(before)?,
                &parse_snapshot(after)?,
            )?;
            write_report(report, json)
        }
        Commands::Check {
            contract,
            before,
            snapshot,
            json,
        } => {
            let contract =
                parse_contract(&read_document(&contract)?).map_err(|e| format!("contract: {e}"))?;
            let before = if let Some(path) = before {
                Some(parse_snapshot(&read_document(&path)?).map_err(|e| format!("before: {e}"))?)
            } else {
                None
            };
            let current = parse_snapshot(&read_input(&snapshot, "snapshot")?)
                .map_err(|e| format!("snapshot: {e}"))?;
            let report = match before {
                Some(baseline) => compare(&contract, &baseline, &current)?,
                None => assess(&contract, &current)?,
            };
            write_report(report, json)
        }
        Commands::Contract(ContractCommand::Draft { snapshot, output }) => {
            let snapshot = parse_snapshot(&read_input(&snapshot, "snapshot")?)
                .map_err(|e| format!("snapshot: {e}"))?;
            write_draft(&draft_contract(&snapshot)?, output.as_deref())
        }
        Commands::Contract(ContractCommand::Validate { contract }) => {
            let contract = parse_contract(&read_input(&contract, "contract")?)
                .map_err(|e| format!("contract: {e}"))?;
            let count = contract.signal_count();
            let noun = if count == 1 { "signal" } else { "signals" };
            writeln!(io::stdout().lock(), "Valid contract ({count} {noun})")?;
            Ok(0)
        }
        Commands::Capture(args) => capture::run(args),
        #[cfg(feature = "cems")]
        Commands::Meter(MeterCommand::Example {
            export,
            register_type,
        }) => {
            let (contract, readings): (&[u8], &[u8]) = match register_type {
                RegisterType::Uint64 => (
                    include_bytes!("../../../fixtures/meter/contract.json"),
                    include_bytes!("../../../fixtures/meter/readings.ndjson"),
                ),
                RegisterType::Float => (
                    include_bytes!("../../../fixtures/meter/float-contract.json"),
                    include_bytes!("../../../fixtures/meter/float-readings.ndjson"),
                ),
                RegisterType::Double => (
                    include_bytes!("../../../fixtures/meter/double-contract.json"),
                    include_bytes!("../../../fixtures/meter/double-readings.ndjson"),
                ),
            };
            export_example(
                &export,
                [
                    ("contract.json", contract),
                    ("readings.ndjson", readings),
                    (
                        "window.json",
                        include_bytes!("../../../fixtures/meter/window.json"),
                    ),
                ],
            )
        }
        #[cfg(feature = "cems")]
        Commands::Meter(MeterCommand::Read {
            connection,
            client_uri,
        }) => {
            let contract = parse_contract(&read_document(&connection.contract)?)?;
            validate_meter_contract(&contract)?;
            if let Some(uri) = client_uri {
                native::read_meter(connection, uri, &contract)
            } else {
                capture::read_meter(&connection, &contract)
            }
        }
        #[cfg(feature = "cems")]
        Commands::Meter(MeterCommand::Trace {
            contract,
            window,
            readings,
            output,
        }) => {
            let contract =
                parse_contract(&read_document(&contract)?).map_err(|e| format!("contract: {e}"))?;
            validate_meter_contract(&contract)?;
            let window = read_document(&window)?;
            let readings = read_input(&readings, "readings")?;
            let result = project_meter_trace(&contract, &readings, &window)?;
            write_compact_line(&result.trace, output.as_deref())?;
            // Reporting follows publication. A disconnected logger must not turn
            // a completed save into a failure that prompts an unsafe retry.
            let _ = writeln!(
                io::stderr().lock(),
                "Meter trace: {} register points, {} excluded by status, {} without a usable source timestamp, {} excluded by floating-point precision, {} outside the window, {} duplicates.",
                result.trace.register.len(),
                result.skipped_status,
                result.skipped_source_time,
                result.skipped_precision,
                result.outside_window,
                result.duplicate_readings,
            );
            Ok(0)
        }
    }
}

fn print_diagnostic(message: &str) {
    let message = message.trim_end();
    // Parser errors can quote a whole argument. Keep ordinary usage hints intact.
    if message.len() <= 1024 {
        let _ = writeln!(io::stderr().lock(), "{message}");
    } else {
        let mut end = 1024;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        let _ = writeln!(
            io::stderr().lock(),
            "{}…\nRun 'opcua-kit --help' for usage.",
            &message[..end]
        );
    }
}

fn main() -> ExitCode {
    // Reject control-bearing arguments before a parser diagnostic can echo them.
    if std::env::args_os().any(|a| {
        a.to_string_lossy()
            .chars()
            .any(display::unsafe_terminal_char)
    }) {
        print_diagnostic("opcua-kit: argument contains a terminal control character");
        return ExitCode::FAILURE;
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if error.use_stderr() {
                print_diagnostic(&error.to_string());
                return ExitCode::FAILURE;
            }
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            print_diagnostic(&format!("opcua-kit: {}", display::safe(&error.to_string())));
            ExitCode::FAILURE
        }
    }
}
