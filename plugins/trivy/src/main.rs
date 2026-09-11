//! Trivy scan adapter. Runs `trivy kubernetes` for the context and namespace
//! sofka is showing and renders its JSON report as a sofka plugin report.
//!
//! The JSON is parsed straight from the child's pipe under a shared line budget:
//! a cluster-wide scan can name a finding for every image in every workload, and
//! none of that has to be held in memory at once.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

const EXECUTABLE: &str = "trivy";
const INSTALL: &str = "https://trivy.dev/latest/getting-started/installation/";
const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const STDERR_MAX_BYTES: usize = 64 * 1024;
/// Sofka refuses a report over 1 MiB, so the rendered text stops well short of
/// it: JSON escaping and section framing still have to fit.
const REPORT_MAX_LINES: usize = 4_000;
const REPORT_MAX_BYTES: usize = 512 * 1024;
const TRUNCATION_LINE: &str = "… report truncated; scan one namespace at a time to see the rest";

#[derive(Deserialize)]
struct Request {
    schema_version: u32,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
}

fn main() -> Result<(), String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(REQUEST_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > REQUEST_MAX_BYTES {
        return Err("request exceeds 1 MiB".into());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid request: {e}"))?;
    let output = serde_json::to_vec(&run(&request)?).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

fn run(request: &Request) -> Result<Value, String> {
    if request.schema_version != 1 {
        return Err("unsupported request schema_version".into());
    }
    let context = request.context.clone().unwrap_or_default();
    let namespace = request.namespace.clone().unwrap_or_default();
    let saved = request.inputs.get("report").map_or("", String::as_str);
    let envelope = if saved.is_empty() {
        scan(&context, &namespace)?
    } else {
        let file = std::fs::File::open(saved)
            .map_err(|e| format!("cannot read saved Trivy report {saved}: {e}"))?;
        parse(file)?
    };
    Ok(render(envelope, &context, &namespace))
}

// ---------------------------------------------------------------- discovery --

fn detect() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    detect_in_path(&path, std::env::current_exe().ok().as_deref())
}

/// PATH-parameterized so discovery stays testable without mutating the shared
/// environment. `own` is this adapter: a package directory that ends up on PATH
/// must not make it invoke itself.
fn detect_in_path(path: &OsStr, own: Option<&Path>) -> Option<PathBuf> {
    let own = own.and_then(|path| path.canonicalize().ok());
    std::env::split_paths(path)
        .map(|dir| dir.join(EXECUTABLE))
        .find(|candidate| is_executable(candidate) && candidate.canonicalize().ok() != own)
        .map(absolute)
}

fn absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

// ------------------------------------------------------------------ scanning --

fn configure(command: &mut Command, context: &str, namespace: &str) {
    command.args([
        "kubernetes",
        "--format",
        "json",
        "--report",
        "summary",
        "--quiet",
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
        "--parallel",
        "1",
        "--list-all-pkgs=false",
        "--disable-node-collector",
        "--timeout",
        "5m",
    ]);
    if !namespace.is_empty() {
        command.arg("--include-namespaces").arg(namespace);
    }
    if !context.is_empty() {
        // Trivy takes the kubeconfig context as the sole positional argument.
        command.arg(context);
    }
}

fn scan(context: &str, namespace: &str) -> Result<Envelope, String> {
    let executable =
        detect().ok_or_else(|| format!("trivy is not on PATH; install it from {INSTALL}"))?;
    let mut command = Command::new(&executable);
    configure(&mut command, context, namespace);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to start {}: {e}", executable.display()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture Trivy stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture Trivy stderr".to_string())?;
    // Drain stderr on its own thread: a chatty scan that fills the pipe would
    // otherwise block Trivy while this process waits on stdout.
    let errors = std::thread::spawn(move || bounded_read(stderr, STDERR_MAX_BYTES));
    let parsed = parse(&mut stdout);
    if parsed.is_err() {
        // Stop reading mid-document and Trivy dies of SIGPIPE, which would then
        // be reported instead of whatever actually went wrong.
        bounded_read(&mut stdout, STDERR_MAX_BYTES);
    }
    drop(stdout);
    let status = child
        .wait()
        .map_err(|e| format!("failed while waiting for Trivy: {e}"))?;
    let stderr = errors.join().unwrap_or_default();
    match parsed {
        Ok(envelope) if status.success() => Ok(envelope),
        Ok(_) => Err(scan_error(None, &status.to_string(), &stderr)),
        Err(error) => Err(scan_error(Some(error), &status.to_string(), &stderr)),
    }
}

/// What a failed scan should say. When Trivy produced no usable report, its own
/// diagnosis beats ours — including when it died of SIGPIPE because this process
/// stopped reading a document it could not parse.
fn scan_error(parse_error: Option<String>, status: &str, stderr: &[u8]) -> String {
    match parse_error {
        Some(error) => match first_line(stderr) {
            Some(detail) => format!("Trivy failed: {detail}"),
            None => error,
        },
        None => format!(
            "Trivy exited with {status}: {}",
            first_line(stderr).unwrap_or("no error output")
        ),
    }
}

fn bounded_read(mut reader: impl Read, limit: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8 * 1024];
    while let Ok(read) = reader.read(&mut chunk) {
        if read == 0 {
            break;
        }
        let keep = read.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk[..keep]);
    }
    bytes
}

fn first_line(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
}

/// `serde_json::from_reader` pulls one byte per `Read::read`, so an unbuffered
/// source costs a syscall per byte of the report. Trivy emits megabytes.
fn parse(reader: impl Read) -> Result<Envelope, String> {
    serde_json::from_reader(std::io::BufReader::with_capacity(256 * 1024, reader))
        .map_err(|e| format!("invalid JSON from Trivy: {e}"))
}

// ------------------------------------------------------------------ budgeting --

/// One line allowance shared by the whole report. A cluster-wide scan can raise
/// a finding for every image in every workload, so the renderer stops rather
/// than grows.
struct Budget {
    lines: usize,
    bytes: usize,
    truncated: bool,
}

impl Budget {
    fn new() -> Self {
        Self {
            lines: REPORT_MAX_LINES,
            bytes: REPORT_MAX_BYTES,
            truncated: false,
        }
    }

    fn accepting(&self) -> bool {
        !self.truncated && self.lines > 0
    }

    fn push(&mut self, lines: &mut Vec<String>, line: String) -> bool {
        if self.truncated || self.lines == 0 || line.len() > self.bytes {
            self.truncated = true;
            return false;
        }
        self.lines -= 1;
        self.bytes -= line.len();
        lines.push(line);
        true
    }

    /// Move an independently budgeted block in, stopping at the shared limit.
    fn absorb(&mut self, lines: &mut Vec<String>, block: Block) {
        for line in block.lines {
            if !self.push(lines, line) {
                return;
            }
        }
        self.truncated |= block.truncated;
    }
}

/// A block rendered under its own allowance, so one resource with thousands of
/// findings is bounded while it is parsed.
#[derive(Default)]
struct Block {
    lines: Vec<String>,
    truncated: bool,
}

// ------------------------------------------------------------------- severity --

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
enum Severity {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "LOW")]
    Low,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Counts {
    vulnerabilities: usize,
    misconfigurations: usize,
    secrets: usize,
    errors: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    unknown: usize,
}

impl Counts {
    fn record(&mut self, kind: Kind, severity: Severity) {
        match kind {
            Kind::Vulnerability => self.vulnerabilities += 1,
            Kind::Misconfiguration => self.misconfigurations += 1,
            Kind::Secret => self.secrets += 1,
        }
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Unknown => self.unknown += 1,
        }
    }

    fn merge(&mut self, other: Self) {
        self.vulnerabilities += other.vulnerabilities;
        self.misconfigurations += other.misconfigurations;
        self.secrets += other.secrets;
        self.errors += other.errors;
        self.critical += other.critical;
        self.high += other.high;
        self.medium += other.medium;
        self.low += other.low;
        self.unknown += other.unknown;
    }

    fn findings(self) -> usize {
        self.vulnerabilities + self.misconfigurations + self.secrets
    }

    fn tally(self) -> String {
        format!(
            "{} vulnerabilities · {} misconfigurations · {} secrets · C {} H {} M {} L {} U {}",
            self.vulnerabilities,
            self.misconfigurations,
            self.secrets,
            self.critical,
            self.high,
            self.medium,
            self.low,
            self.unknown
        )
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Vulnerability,
    Misconfiguration,
    Secret,
}

// ------------------------------------------------------------------- parsing --

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "ClusterName", default)]
    cluster_name: String,
    /// Trivy renamed this between versions; both spellings carry the same shape.
    #[serde(rename = "Findings", alias = "Resources", default)]
    findings: Scanned,
}

/// Every resource Trivy reported on, already rendered.
#[derive(Default)]
struct Scanned {
    resources: Vec<Rendered>,
    counts: Counts,
    truncated: bool,
}

struct Rendered {
    title: String,
    lines: Vec<String>,
}

impl<'de> Deserialize<'de> for Scanned {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScannedVisitor;

        impl<'de> Visitor<'de> for ScannedVisitor {
            type Value = Scanned;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy findings array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut budget = Budget::new();
                let mut scanned = Scanned::default();
                while budget.accepting() {
                    let Some(finding) = seq.next_element::<Finding>()? else {
                        break;
                    };
                    render_finding(&mut budget, &mut scanned, finding);
                }
                // Drain the rest so the stream stays well formed, and record that
                // what the user sees is not the whole report.
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    budget.truncated = true;
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                scanned.truncated = budget.truncated;
                Ok(scanned)
            }
        }

        deserializer.deserialize_seq(ScannedVisitor)
    }
}

#[derive(Deserialize)]
struct Finding {
    #[serde(rename = "Namespace", default)]
    namespace: String,
    #[serde(rename = "Kind", default)]
    kind: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Results", default)]
    results: Results,
    #[serde(rename = "Error", default)]
    error: String,
}

/// One resource's results, rendered under their own allowance.
#[derive(Default)]
struct Results {
    block: Block,
    counts: Counts,
}

impl<'de> Deserialize<'de> for Results {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResultsVisitor;

        impl<'de> Visitor<'de> for ResultsVisitor {
            type Value = Results;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy results array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut budget = Budget::new();
                let mut results = Results::default();
                while budget.accepting() {
                    let Some(result) = seq.next_element_seed(ResultSeed {
                        budget: &mut budget,
                        lines: &mut results.block.lines,
                    })?
                    else {
                        break;
                    };
                    results.counts.merge(result);
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    budget.truncated = true;
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                results.block.truncated = budget.truncated;
                Ok(results)
            }
        }

        deserializer.deserialize_seq(ResultsVisitor)
    }
}

/// One `Results` entry: a target plus its vulnerabilities, misconfigurations,
/// and secrets. Each list is rendered as it is read.
struct ResultSeed<'a> {
    budget: &'a mut Budget,
    lines: &'a mut Vec<String>,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ResultField {
    #[serde(rename = "Vulnerabilities")]
    Vulnerabilities,
    #[serde(rename = "Misconfigurations")]
    Misconfigurations,
    #[serde(rename = "Secrets")]
    Secrets,
    #[serde(other)]
    Other,
}

impl<'de> DeserializeSeed<'de> for ResultSeed<'_> {
    type Value = Counts;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResultVisitor<'a> {
            budget: &'a mut Budget,
            lines: &'a mut Vec<String>,
        }

        impl<'de> Visitor<'de> for ResultVisitor<'_> {
            type Value = Counts;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy result object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut counts = Counts::default();
                while let Some(field) = map.next_key()? {
                    let kind = match field {
                        ResultField::Vulnerabilities => Kind::Vulnerability,
                        ResultField::Misconfigurations => Kind::Misconfiguration,
                        ResultField::Secrets => Kind::Secret,
                        ResultField::Other => {
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };
                    map.next_value_seed(ItemsSeed {
                        kind,
                        budget: self.budget,
                        lines: self.lines,
                        counts: &mut counts,
                    })?;
                }
                Ok(counts)
            }
        }

        deserializer.deserialize_map(ResultVisitor {
            budget: self.budget,
            lines: self.lines,
        })
    }
}

struct ItemsSeed<'a> {
    kind: Kind,
    budget: &'a mut Budget,
    lines: &'a mut Vec<String>,
    counts: &'a mut Counts,
}

impl<'de> DeserializeSeed<'de> for ItemsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ItemsVisitor<'a> {
            kind: Kind,
            budget: &'a mut Budget,
            lines: &'a mut Vec<String>,
            counts: &'a mut Counts,
        }

        impl<'de> Visitor<'de> for ItemsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy finding array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.budget.accepting() {
                    let rendered = match self.kind {
                        Kind::Vulnerability => seq
                            .next_element::<Vulnerability>()?
                            .map(|item| (item.severity, item.render())),
                        Kind::Misconfiguration => seq
                            .next_element::<Misconfiguration>()?
                            .map(|item| (item.severity, item.render())),
                        Kind::Secret => seq
                            .next_element::<Secret>()?
                            .map(|item| (item.severity, item.render())),
                    };
                    let Some((severity, line)) = rendered else {
                        return Ok(());
                    };
                    self.counts.record(self.kind, severity);
                    self.budget.push(self.lines, line);
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.budget.truncated = true;
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(ItemsVisitor {
            kind: self.kind,
            budget: self.budget,
            lines: self.lines,
            counts: self.counts,
        })
    }
}

#[derive(Deserialize)]
struct Vulnerability {
    #[serde(rename = "VulnerabilityID", default)]
    id: String,
    #[serde(rename = "PkgName", default)]
    package: String,
    #[serde(rename = "InstalledVersion", default)]
    installed: String,
    #[serde(rename = "FixedVersion", default)]
    fixed: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

impl Vulnerability {
    fn render(&self) -> String {
        let mut line = format!("  [vulnerability] {} {}", self.severity.label(), self.id);
        if !self.package.is_empty() {
            let _ = write!(line, " · {}@{}", self.package, self.installed);
        }
        if !self.fixed.is_empty() {
            let _ = write!(line, " → {}", self.fixed);
        }
        if !self.title.is_empty() {
            let _ = write!(line, " — {}", self.title);
        }
        line
    }
}

#[derive(Deserialize)]
struct Misconfiguration {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Message", default)]
    message: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

impl Misconfiguration {
    fn render(&self) -> String {
        let mut line = format!("  [misconfiguration] {} {}", self.severity.label(), self.id);
        let detail = if self.title.is_empty() {
            &self.message
        } else {
            &self.title
        };
        if !detail.is_empty() {
            let _ = write!(line, " — {detail}");
        }
        line
    }
}

#[derive(Deserialize)]
struct Secret {
    #[serde(rename = "RuleID", default)]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Category", default)]
    category: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

impl Secret {
    fn render(&self) -> String {
        let mut line = format!("  [secret] {} {}", self.severity.label(), self.id);
        let detail = if self.title.is_empty() {
            &self.category
        } else {
            &self.title
        };
        if !detail.is_empty() {
            let _ = write!(line, " — {detail}");
        }
        line
    }
}

// ----------------------------------------------------------------- rendering --

/// A resource with nothing to report is left out entirely: a cluster-wide scan
/// touches every workload, and listing the clean ones would bury the findings.
fn render_finding(budget: &mut Budget, scanned: &mut Scanned, finding: Finding) {
    let mut counts = finding.results.counts;
    if !finding.error.is_empty() {
        counts.errors += 1;
    }
    if counts.findings() == 0 && counts.errors == 0 {
        return;
    }
    scanned.counts.merge(counts);

    let mut title = String::new();
    if !finding.namespace.is_empty() {
        let _ = write!(title, "{} · ", finding.namespace);
    }
    let _ = write!(title, "{}/{}", finding.kind, finding.name);

    let mut lines = Vec::new();
    budget.push(&mut lines, counts.tally());
    budget.absorb(&mut lines, finding.results.block);
    if !finding.error.is_empty() {
        budget.push(&mut lines, format!("  ERROR {}", finding.error));
    }
    scanned.resources.push(Rendered { title, lines });
}

fn render(envelope: Envelope, requested_context: &str, requested_namespace: &str) -> Value {
    let Envelope {
        cluster_name,
        findings,
    } = envelope;
    let counts = findings.counts;
    let mut rows = vec![
        json!(["Findings", counts.findings().to_string()]),
        json!(["Critical", counts.critical.to_string()]),
        json!(["High", counts.high.to_string()]),
        json!(["Medium", counts.medium.to_string()]),
        json!(["Low", counts.low.to_string()]),
        json!(["Vulnerabilities", counts.vulnerabilities.to_string()]),
        json!(["Misconfigurations", counts.misconfigurations.to_string()]),
        json!(["Secrets", counts.secrets.to_string()]),
    ];
    if !requested_context.is_empty() {
        rows.push(json!(["Context", requested_context]));
    }
    if !cluster_name.is_empty() {
        rows.push(json!(["Cluster", cluster_name]));
    }
    rows.push(json!([
        "Namespace",
        if requested_namespace.is_empty() {
            "all"
        } else {
            requested_namespace
        }
    ]));
    rows.push(json!(["Resources", findings.resources.len().to_string()]));
    if counts.errors > 0 {
        rows.push(json!(["Scan errors", counts.errors.to_string()]));
    }

    let mut sections = vec![json!({
        "title": "Summary",
        "columns": ["Field", "Value"],
        "rows": rows,
    })];
    for resource in findings.resources {
        sections.push(json!({"title": resource.title, "lines": resource.lines}));
    }
    if findings.truncated {
        sections.push(json!({"title": "Notice", "lines": [TRUNCATION_LINE]}));
    }
    json!({
        "schema_version": 1,
        "title": "Trivy scan",
        "sections": sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCAN: &str = include_str!("../fixtures/scan.json");

    fn parsed(json: &str) -> Envelope {
        parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn fixture_matches_expected_report() {
        let request: Request =
            serde_json::from_str(include_str!("../fixtures/request.json")).unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        assert_eq!(
            render(
                parsed(SCAN),
                request.context.as_deref().unwrap_or_default(),
                request.namespace.as_deref().unwrap_or_default(),
            ),
            expected
        );
        // CI runs the adapter from the repository root.
        assert_eq!(
            request.inputs.get("report").map(String::as_str),
            Some("plugins/trivy/fixtures/scan.json")
        );
    }

    #[test]
    fn every_finding_kind_is_counted_and_rendered() {
        let report = render(parsed(SCAN), "prod", "apps");
        let sections = report["sections"].as_array().unwrap();
        let rows: Vec<(String, String)> = sections[0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_str().unwrap().into(), r[1].as_str().unwrap().into()))
            .collect();
        let value = |name: &str| rows.iter().find(|(k, _)| k == name).unwrap().1.clone();
        assert_eq!(value("Findings"), "3");
        assert_eq!(value("Critical"), "1");
        assert_eq!(value("High"), "1");
        assert_eq!(value("Medium"), "1");
        assert_eq!(value("Vulnerabilities"), "1");
        assert_eq!(value("Misconfigurations"), "1");
        assert_eq!(value("Secrets"), "1");
        assert_eq!(value("Scan errors"), "1");

        assert_eq!(sections[1]["title"], "apps · Deployment/web");
        let lines: Vec<&str> = sections[1]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        assert!(lines[1].starts_with("  [vulnerability] CRITICAL CVE-2026-1234"));
        assert!(lines[1].contains("openssl@1.0 → 1.1"));
        assert!(lines[2].starts_with("  [misconfiguration] HIGH AVD-KSV-0001"));
        assert!(lines[3].starts_with("  [secret] MEDIUM generic-api-key"));
    }

    #[test]
    fn a_clean_resource_is_omitted_and_a_failed_one_is_kept() {
        let report = render(parsed(SCAN), "prod", "apps");
        let titles: Vec<&str> = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["title"].as_str().unwrap())
            .collect();
        assert!(!titles.iter().any(|t| t.contains("clean")));
        let errored = report["sections"][2].clone();
        assert_eq!(errored["title"], "kube-system · DaemonSet/agent");
        assert!(
            errored["lines"][1]
                .as_str()
                .unwrap()
                .contains("ERROR failed to pull image")
        );
    }

    #[test]
    fn the_older_resources_spelling_is_accepted() {
        let renamed = SCAN.replacen("\"Findings\"", "\"Resources\"", 1);
        let report = render(parsed(&renamed), "prod", "apps");
        assert_eq!(report["sections"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn unknown_severities_and_absent_fields_are_tolerated() {
        let json = r#"{"Findings":[{"Kind":"Pod","Name":"p","Results":[{
            "Vulnerabilities":[{"VulnerabilityID":"X","Severity":"NOPE"}],
            "Unknown":[{"whatever":1}]}]}]}"#;
        let report = render(parsed(json), "", "");
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Findings", "1"])));
        assert!(rows.contains(&json!(["Namespace", "all"])));
        assert!(!rows.iter().any(|r| r[0] == "Context"));
        assert!(
            report["sections"][1]["lines"][1]
                .as_str()
                .unwrap()
                .contains("[vulnerability] UNKNOWN X")
        );
    }

    #[test]
    fn an_unbounded_scan_is_truncated_with_a_notice() {
        let items: Vec<String> = (0..REPORT_MAX_LINES + 100)
            .map(|i| format!(r#"{{"VulnerabilityID":"CVE-{i}","Severity":"LOW"}}"#))
            .collect();
        let json = format!(
            r#"{{"Findings":[
                {{"Kind":"Pod","Name":"noisy","Results":[{{"Vulnerabilities":[{}]}}]}},
                {{"Kind":"Pod","Name":"later","Results":[{{"Secrets":[{{"RuleID":"k"}}]}}]}}
            ]}}"#,
            items.join(",")
        );
        let report = render(parsed(&json), "dev", "default");
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(sections.last().unwrap()["title"], "Notice");
        assert_eq!(sections.last().unwrap()["lines"][0], TRUNCATION_LINE);
        let rendered = serde_json::to_vec(&report).unwrap();
        assert!(rendered.len() < 1024 * 1024, "{} bytes", rendered.len());
    }

    #[test]
    fn rejects_unknown_request_schema_and_a_missing_saved_report() {
        let request: Request = serde_json::from_value(json!({"schema_version": 2})).unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("unsupported request schema_version")
        );
        let request: Request = serde_json::from_value(json!({
            "schema_version": 1,
            "inputs": {"report": "does/not/exist.json"},
        }))
        .unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("cannot read saved Trivy report")
        );
    }

    #[test]
    fn trivy_is_invoked_with_the_context_as_its_positional_argument() {
        let arguments = |context: &str, namespace: &str| {
            let mut command = Command::new("trivy");
            configure(&mut command, context, namespace);
            command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let scoped = arguments("prod", "apps");
        assert_eq!(&scoped[..4], ["kubernetes", "--format", "json", "--report"]);
        assert!(scoped.contains(&"--disable-telemetry".to_string()));
        assert!(scoped.contains(&"--disable-node-collector".to_string()));
        // --include-namespaces takes the namespace; the context is positional.
        let namespace = scoped
            .iter()
            .position(|a| a == "--include-namespaces")
            .unwrap();
        assert_eq!(scoped[namespace + 1], "apps");
        assert_eq!(scoped.last().unwrap(), "prod");
        // No namespace means every namespace, and no context means the current one.
        let unscoped = arguments("", "");
        assert!(!unscoped.contains(&"--include-namespaces".to_string()));
        assert_eq!(unscoped.last().unwrap(), "5m");
    }

    #[test]
    fn a_failed_scan_reports_what_trivy_said_rather_than_how_it_died() {
        assert_eq!(
            scan_error(
                Some("invalid JSON from Trivy: EOF".into()),
                "signal: 13 (SIGPIPE)",
                b"FATAL kubernetes scan error: unable to reach the cluster\n",
            ),
            "Trivy failed: FATAL kubernetes scan error: unable to reach the cluster"
        );
        assert_eq!(
            scan_error(
                Some("invalid JSON from Trivy: EOF".into()),
                "exit status: 1",
                b""
            ),
            "invalid JSON from Trivy: EOF"
        );
        assert_eq!(
            scan_error(None, "exit status: 2", b""),
            "Trivy exited with exit status: 2: no error output"
        );
    }

    #[test]
    fn discovery_never_selects_this_adapter() {
        let dir = std::env::temp_dir().join(format!("sofka-trivy-{}", std::process::id()));
        let package = dir.join("package");
        let system = dir.join("system");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::create_dir_all(&system).unwrap();
        let write = |path: &Path| {
            std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        };
        let own = package.join("trivy");
        write(&own);
        let path = std::env::join_paths([&package, &system]).unwrap();
        assert_eq!(detect_in_path(&path, Some(&own)), None);
        assert_eq!(detect_in_path(&path, None), Some(own.clone()));
        let system_trivy = system.join("trivy");
        write(&system_trivy);
        assert_eq!(detect_in_path(&path, Some(&own)), Some(system_trivy));
        let _ = std::fs::remove_dir_all(dir);
    }
}
