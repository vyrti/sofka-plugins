//! Popeye scan adapter. Runs the Popeye CLI for the context and namespace sofka
//! is showing and renders its JSON report as a sofka plugin report.
//!
//! The JSON is parsed straight from the child's pipe under a shared line budget,
//! so a scan of a large cluster never has to be held in memory in full.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};

/// Popeye ships standalone and as a Krew plugin; both spellings are accepted.
const EXECUTABLES: &[&str] = &["popeye", "kubectl-popeye"];
const INSTALL: &str = "https://github.com/derailed/popeye#installation";
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
            .map_err(|e| format!("cannot read saved Popeye report {saved}: {e}"))?;
        parse(file)?
    };
    Ok(render(envelope, &context, &namespace))
}

// ---------------------------------------------------------------- discovery --

/// Find a standalone or Krew-installed Popeye on the process PATH.
fn detect() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    detect_in_path(&path, std::env::current_exe().ok().as_deref())
}

/// PATH-parameterized so discovery stays testable without mutating the
/// environment Rust's parallel test runner shares. `own` is this adapter, which
/// is itself named `popeye` inside the package: a package directory that ends up
/// on PATH must not make the adapter invoke itself.
fn detect_in_path(path: &OsStr, own: Option<&Path>) -> Option<PathBuf> {
    let own = own.and_then(|path| path.canonicalize().ok());
    for dir in std::env::split_paths(path) {
        for name in EXECUTABLES {
            let candidate = dir.join(name);
            if !is_executable(&candidate) {
                continue;
            }
            if candidate.canonicalize().ok() == own {
                continue;
            }
            return Some(absolute(candidate));
        }
    }
    None
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
        "--out",
        "json",
        "--force-exit-zero",
        "--log-level",
        "0",
        "--logs",
        "none",
    ]);
    if !context.is_empty() {
        command.arg("--context").arg(context);
    }
    if namespace.is_empty() {
        command.arg("--all-namespaces");
    } else {
        command.arg("--namespace").arg(namespace);
    }
}

fn scan(context: &str, namespace: &str) -> Result<Envelope, String> {
    let executable =
        detect().ok_or_else(|| format!("popeye is not on PATH; install it from {INSTALL}"))?;
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
        .ok_or_else(|| "failed to capture Popeye stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture Popeye stderr".to_string())?;
    // Drain stderr on its own thread: a chatty scan that fills the pipe would
    // otherwise block Popeye while this process waits on stdout.
    let errors = std::thread::spawn(move || bounded_read(stderr, STDERR_MAX_BYTES));
    let parsed = parse(&mut stdout);
    if parsed.is_err() {
        // Stop reading mid-document and Popeye dies of SIGPIPE, which would
        // then be reported instead of whatever actually went wrong. Take the
        // rest of what it had to say first.
        bounded_read(&mut stdout, STDERR_MAX_BYTES);
    }
    drop(stdout);
    let status = child
        .wait()
        .map_err(|e| format!("failed while waiting for Popeye: {e}"))?;
    let stderr = errors.join().unwrap_or_default();
    match parsed {
        Ok(envelope) if status.success() => Ok(envelope),
        Ok(_) => Err(scan_error(None, &status.to_string(), &stderr)),
        Err(error) => Err(scan_error(Some(error), &status.to_string(), &stderr)),
    }
}

/// What a failed scan should say. When Popeye produced no usable report, its own
/// diagnosis beats ours — including when it died of SIGPIPE because this process
/// stopped reading a document it could not parse.
fn scan_error(parse_error: Option<String>, status: &str, stderr: &[u8]) -> String {
    match parse_error {
        Some(error) => match first_line(stderr) {
            Some(detail) => format!("Popeye failed: {detail}"),
            None => error,
        },
        None => format!(
            "Popeye exited with {status}: {}",
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

fn parse(reader: impl Read) -> Result<Envelope, String> {
    serde_json::from_reader(reader).map_err(|e| format!("invalid JSON from Popeye: {e}"))
}

// ------------------------------------------------------------------ budgeting --

/// One line allowance shared by the whole report. Popeye can raise an issue for
/// every resource in a cluster, so the renderer stops rather than grows.
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

/// A block rendered under its own allowance, so a single linter with a finding
/// for every resource in the cluster is bounded while it is parsed, before the
/// shared budget decides how much of it survives.
#[derive(Default)]
struct Block {
    lines: Vec<String>,
    truncated: bool,
}

// ------------------------------------------------------------------- parsing --

#[derive(Deserialize)]
struct Envelope {
    popeye: Report,
    #[serde(rename = "ClusterName", default)]
    cluster_name: String,
    #[serde(rename = "ContextName", default)]
    context_name: String,
}

struct Report {
    report_time: String,
    score: i64,
    grade: String,
    sections: Vec<Rendered>,
    errors: Vec<String>,
    truncated: bool,
}

/// One linter's findings, already rendered.
struct Rendered {
    title: String,
    lines: Vec<String>,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ReportField {
    #[serde(rename = "report_time")]
    ReportTime,
    #[serde(rename = "score")]
    Score,
    #[serde(rename = "grade")]
    Grade,
    #[serde(rename = "sections")]
    Sections,
    #[serde(rename = "errors")]
    Errors,
    #[serde(other)]
    Other,
}

impl<'de> Deserialize<'de> for Report {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReportVisitor;

        impl<'de> Visitor<'de> for ReportVisitor {
            type Value = Report;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye report object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut report_time = None;
                let mut score = None;
                let mut grade = None;
                let mut budget = Budget::new();
                let mut sections = Vec::new();
                let mut errors = Vec::new();

                while let Some(field) = map.next_key()? {
                    match field {
                        ReportField::ReportTime => report_time = Some(map.next_value()?),
                        ReportField::Score => score = Some(map.next_value()?),
                        ReportField::Grade => grade = Some(map.next_value()?),
                        ReportField::Sections => map.next_value_seed(SectionsSeed {
                            budget: &mut budget,
                            sections: &mut sections,
                        })?,
                        ReportField::Errors => map.next_value_seed(ErrorsSeed {
                            budget: &mut budget,
                            errors: &mut errors,
                        })?,
                        ReportField::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                Ok(Report {
                    report_time: report_time.unwrap_or_default(),
                    score: score.ok_or_else(|| M::Error::missing_field("score"))?,
                    grade: grade.unwrap_or_default(),
                    sections,
                    errors,
                    truncated: budget.truncated,
                })
            }
        }

        deserializer.deserialize_map(ReportVisitor)
    }
}

#[derive(Default, Deserialize)]
struct Tally {
    #[serde(default)]
    ok: usize,
    #[serde(default)]
    info: usize,
    #[serde(default, rename = "warning")]
    warnings: usize,
    #[serde(default)]
    error: usize,
    #[serde(default)]
    score: i64,
}

#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    level: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Section {
    linter: String,
    #[serde(default)]
    gvr: String,
    #[serde(default)]
    tally: Tally,
    #[serde(default)]
    issues: Issues,
}

struct SectionsSeed<'a> {
    budget: &'a mut Budget,
    sections: &'a mut Vec<Rendered>,
}

impl<'de> DeserializeSeed<'de> for SectionsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SectionsVisitor<'a> {
            budget: &'a mut Budget,
            sections: &'a mut Vec<Rendered>,
        }

        impl<'de> Visitor<'de> for SectionsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye sections array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.budget.accepting() {
                    let Some(section) = seq.next_element::<Section>()? else {
                        return Ok(());
                    };
                    self.sections.push(render_section(self.budget, section));
                }
                // Drain the rest so the stream stays well formed, and record
                // that the report the user sees is not the whole report.
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.budget.truncated = true;
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(SectionsVisitor {
            budget: self.budget,
            sections: self.sections,
        })
    }
}

/// A linter's resource-to-issues map, rendered under its own allowance.
#[derive(Default)]
struct Issues(Block);

impl<'de> Deserialize<'de> for Issues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssuesVisitor;

        impl<'de> Visitor<'de> for IssuesVisitor {
            type Value = Issues;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye resource-to-issues object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut budget = Budget::new();
                let mut block = Block::default();
                while budget.accepting() {
                    let Some(resource) = map.next_key::<String>()? else {
                        break;
                    };
                    budget.push(&mut block.lines, format!("  {resource}"));
                    map.next_value_seed(IssueListSeed {
                        budget: &mut budget,
                        lines: &mut block.lines,
                    })?;
                }
                if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    budget.truncated = true;
                    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                }
                block.truncated = budget.truncated;
                Ok(Issues(block))
            }
        }

        deserializer.deserialize_map(IssuesVisitor)
    }
}

struct IssueListSeed<'a> {
    budget: &'a mut Budget,
    lines: &'a mut Vec<String>,
}

impl<'de> DeserializeSeed<'de> for IssueListSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssueListVisitor<'a> {
            budget: &'a mut Budget,
            lines: &'a mut Vec<String>,
        }

        impl<'de> Visitor<'de> for IssueListVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye issue array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.budget.accepting() {
                    let Some(issue) = seq.next_element::<Issue>()? else {
                        return Ok(());
                    };
                    let level = match issue.level {
                        3 => "ERROR",
                        2 => "WARNING",
                        1 => "INFO",
                        _ => "OK",
                    };
                    self.budget
                        .push(self.lines, format!("    {level} {}", issue.message));
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.budget.truncated = true;
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(IssueListVisitor {
            budget: self.budget,
            lines: self.lines,
        })
    }
}

struct ErrorsSeed<'a> {
    budget: &'a mut Budget,
    errors: &'a mut Vec<String>,
}

impl<'de> DeserializeSeed<'de> for ErrorsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorsVisitor<'a> {
            budget: &'a mut Budget,
            errors: &'a mut Vec<String>,
        }

        impl<'de> Visitor<'de> for ErrorsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye errors object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                while self.budget.accepting() {
                    let Some((_key, error)) = map.next_entry::<IgnoredAny, String>()? else {
                        return Ok(());
                    };
                    self.budget.push(self.errors, error);
                }
                if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    self.budget.truncated = true;
                    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_map(ErrorsVisitor {
            budget: self.budget,
            errors: self.errors,
        })
    }
}

// ----------------------------------------------------------------- rendering --

fn render_section(budget: &mut Budget, section: Section) -> Rendered {
    let mut title = section.linter;
    let _ = write!(title, " — {}%", section.tally.score);
    if !section.gvr.is_empty() {
        let _ = write!(title, " ({})", section.gvr);
    }
    let mut lines = Vec::new();
    budget.push(
        &mut lines,
        format!(
            "ok {} · info {} · warning {} · error {}",
            section.tally.ok, section.tally.info, section.tally.warnings, section.tally.error
        ),
    );
    budget.absorb(&mut lines, section.issues.0);
    Rendered { title, lines }
}

fn render(envelope: Envelope, requested_context: &str, requested_namespace: &str) -> Value {
    let Envelope {
        popeye,
        cluster_name,
        context_name,
    } = envelope;
    let Report {
        report_time,
        score,
        grade,
        sections,
        errors,
        truncated,
    } = popeye;
    // Popeye reports the context it actually scanned; prefer it over the one
    // sofka asked for, which may have been inferred.
    let context = if context_name.is_empty() {
        requested_context
    } else {
        &context_name
    };
    let mut rows = vec![json!(["Score", format!("{score}% ({grade})")])];
    if !context.is_empty() {
        rows.push(json!(["Context", context]));
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
    if !report_time.is_empty() {
        rows.push(json!(["Scanned", report_time]));
    }
    rows.push(json!(["Linters", sections.len().to_string()]));

    let mut out = vec![json!({
        "title": "Summary",
        "columns": ["Field", "Value"],
        "rows": rows,
    })];
    for section in sections {
        out.push(json!({"title": section.title, "lines": section.lines}));
    }
    if !errors.is_empty() {
        out.push(json!({"title": "Report errors", "lines": errors}));
    }
    if truncated {
        out.push(json!({"title": "Notice", "lines": [TRUNCATION_LINE]}));
    }
    json!({
        "schema_version": 1,
        "title": "Popeye scan",
        "sections": out,
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
        // The scope in the request fixture is what produces the report fixture;
        // CI additionally runs the binary over both from the repository root.
        assert_eq!(
            render(
                parsed(SCAN),
                request.context.as_deref().unwrap_or_default(),
                request.namespace.as_deref().unwrap_or_default(),
            ),
            expected
        );
    }

    #[test]
    fn the_request_fixture_points_at_the_scan_fixture() {
        let request: Request =
            serde_json::from_str(include_str!("../fixtures/request.json")).unwrap();
        assert_eq!(request.schema_version, 1);
        // CI runs the adapter from the repository root.
        assert_eq!(
            request.inputs.get("report").map(String::as_str),
            Some("plugins/popeye/fixtures/scan.json")
        );
    }

    #[test]
    fn rejects_unknown_request_schema() {
        let request: Request = serde_json::from_value(json!({"schema_version": 2})).unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("unsupported request schema_version")
        );
    }

    #[test]
    fn a_missing_saved_report_is_an_error_and_never_starts_a_scan() {
        let request: Request = serde_json::from_value(json!({
            "schema_version": 1,
            "inputs": {"report": "does/not/exist.json"},
        }))
        .unwrap();
        assert!(
            run(&request)
                .unwrap_err()
                .contains("cannot read saved Popeye report")
        );
    }

    #[test]
    fn levels_and_tallies_render_as_the_document_view_shows_them() {
        let report = render(parsed(SCAN), "ignored", "apps");
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(report["title"], "Popeye scan");
        // Popeye's own context wins over the one sofka asked for.
        assert_eq!(sections[0]["rows"][1], json!(["Context", "prod"]));
        assert_eq!(sections[1]["title"], "pods — 50% (v1/pods)");
        let lines: Vec<&str> = sections[1]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line.as_str().unwrap())
            .collect();
        assert_eq!(
            lines,
            [
                "ok 2 · info 1 · warning 1 · error 1",
                "  apps/web",
                "    ERROR [POP-106] CrashLoopBackOff",
                "    WARNING [POP-107] No probes defined",
                "  apps/worker",
                "    INFO [POP-108] Unnamed port",
            ]
        );
        assert_eq!(sections[3]["title"], "Report errors");
        assert_eq!(sections[3]["lines"][0], "metrics-server unavailable");
    }

    #[test]
    fn an_unnamespaced_scan_reports_every_namespace() {
        let report = render(parsed(SCAN), "prod", "");
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert!(rows.contains(&json!(["Namespace", "all"])));
    }

    #[test]
    fn unknown_fields_and_absent_optional_fields_are_tolerated() {
        let minimal = r#"{"popeye": {"score": 100, "unknown": [1, 2]}}"#;
        let report = render(parsed(minimal), "dev", "default");
        let rows = report["sections"][0]["rows"].as_array().unwrap();
        assert_eq!(rows[0], json!(["Score", "100% ()"]));
        assert!(rows.contains(&json!(["Context", "dev"])));
        assert!(rows.contains(&json!(["Linters", "0"])));
        // No Scanned row, because Popeye reported no time.
        assert!(!rows.iter().any(|row| row[0] == "Scanned"));
        assert_eq!(report["sections"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_report_without_a_score_is_not_a_report() {
        assert!(parse(r#"{"popeye": {"grade": "A"}}"#.as_bytes()).is_err());
        assert!(parse(b"not json".as_slice()).is_err());
    }

    #[test]
    fn an_unbounded_scan_is_truncated_with_a_notice() {
        let issues: Vec<String> = (0..REPORT_MAX_LINES + 100)
            .map(|i| format!(r#"{{"level": 2, "message": "issue {i}"}}"#))
            .collect();
        let json = format!(
            r#"{{"popeye": {{"score": 1, "sections": [
                {{"linter": "pods", "tally": {{}}, "issues": {{"ns/a": [{}]}}}},
                {{"linter": "services", "tally": {{}}, "issues": {{}}}}
            ]}}}}"#,
            issues.join(",")
        );
        let report = render(parsed(&json), "dev", "default");
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(sections.last().unwrap()["title"], "Notice");
        let rendered = serde_json::to_vec(&report).unwrap();
        assert!(rendered.len() < 1024 * 1024, "{} bytes", rendered.len());
        assert!(sections[1]["lines"].as_array().unwrap().len() <= REPORT_MAX_LINES);
        // The budget is shared, so a linter that exhausts it costs the linters
        // after it. The notice is the only promise made about what is missing.
        assert!(
            !sections
                .iter()
                .any(|section| section["title"] == "services — 0%")
        );
        assert_eq!(sections.last().unwrap()["lines"][0], TRUNCATION_LINE);
    }

    #[test]
    fn popeye_is_invoked_with_a_bounded_machine_readable_scan() {
        let arguments = |context: &str, namespace: &str| {
            let mut command = Command::new("popeye");
            configure(&mut command, context, namespace);
            command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            arguments("prod", "apps"),
            [
                "--out",
                "json",
                "--force-exit-zero",
                "--log-level",
                "0",
                "--logs",
                "none",
                "--context",
                "prod",
                "--namespace",
                "apps",
            ]
        );
        assert_eq!(arguments("", "").last().unwrap(), "--all-namespaces");
    }

    #[test]
    fn discovery_accepts_both_spellings_and_never_selects_this_adapter() {
        let dir = std::env::temp_dir().join(format!("sofka-popeye-{}", std::process::id()));
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
        let own = package.join("popeye");
        write(&own);
        let path = std::env::join_paths([&package, &system]).unwrap();

        // With only this adapter on PATH, there is no Popeye to run.
        assert_eq!(detect_in_path(&path, Some(&own)), None);
        // Without the guard it would find itself.
        assert_eq!(detect_in_path(&path, None), Some(own.clone()));

        let krew = system.join("kubectl-popeye");
        write(&krew);
        assert_eq!(detect_in_path(&path, Some(&own)), Some(krew.clone()));

        // A standalone Popeye earlier on PATH wins over the Krew spelling.
        let standalone = system.join("popeye");
        write(&standalone);
        assert_eq!(detect_in_path(&path, Some(&own)), Some(standalone));

        let empty = std::ffi::OsString::from("");
        assert_eq!(detect_in_path(&empty, None), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_scan_reports_what_popeye_said_rather_than_how_it_died() {
        // Popeye could not reach the cluster, so it wrote no report and this
        // process closed the pipe on it.
        assert_eq!(
            scan_error(
                Some("invalid JSON from Popeye: EOF".into()),
                "signal: 13 (SIGPIPE)",
                b"E0911 couldn't get current server API group list\n",
            ),
            "Popeye failed: E0911 couldn't get current server API group list"
        );
        // Nothing on stderr either: our own parse error is all there is.
        assert_eq!(
            scan_error(
                Some("invalid JSON from Popeye: EOF".into()),
                "exit status: 1",
                b""
            ),
            "invalid JSON from Popeye: EOF"
        );
        // A complete report from a run that still failed keeps the status.
        assert_eq!(
            scan_error(None, "exit status: 2", b"partial scan\n"),
            "Popeye exited with exit status: 2: partial scan"
        );
        assert_eq!(
            scan_error(None, "exit status: 2", b""),
            "Popeye exited with exit status: 2: no error output"
        );
    }

    #[test]
    fn a_bounded_reader_keeps_only_its_limit_and_finds_the_first_message() {
        let bytes = bounded_read(&b"abcdefgh"[..], 3);
        assert_eq!(bytes, b"abc");
        assert_eq!(first_line(b"\n\n  boom  \nnext"), Some("boom"));
        assert_eq!(first_line(b"   \n"), None);
        assert_eq!(first_line(&[0xff, 0xfe]), None);
    }
}
