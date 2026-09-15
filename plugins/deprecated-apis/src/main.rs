//! Deprecated apiVersions. One adapter behind three sofka commands: `pluto`
//! and `kubent` scan the whole context with the tool of that name, and
//! `resource` pipes the selected object into `pluto detect -`.
//!
//! The first command argument selects the action. No argument means `pluto`,
//! so the CI fixture step, which runs the adapter without arguments, tests the
//! pluto pair.
//!
//! Both tools answer the same question and disagree about the shape of the
//! answer, so each item becomes a `Finding` and one renderer draws both. The
//! report groups findings by what they cost: removed apiVersions break on the
//! next upgrade, deprecated ones still work, and a removal with no replacement
//! needs a plan rather than an edit.
//!
//! Strings are borrowed, not copied. `Text` keeps the borrow that serde's own
//! `Cow` deserializer throws away, so a scan of a large cluster is read without
//! copying a field, and the report serializes straight into a buffered stdout
//! instead of an intermediate `Value` tree. Only a string that carries JSON
//! escapes is copied, because unescaping it needs new bytes.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{ErrorKind, Read, Write as _};
use std::process::{Command, Stdio};

use serde::de::{Deserializer, Visitor};
use serde::{Deserialize, Serialize};

const REQUEST_MAX_BYTES: usize = 1024 * 1024;
/// Sofka refuses a report over 1 MiB, so a tool that writes more than that
/// cannot produce a usable report either. The adapter still drains the pipe.
const OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const STDERR_MAX_BYTES: usize = 64 * 1024;
const REPLAY_MAX_BYTES: usize = 1024 * 1024;
const PLUTO: &str = "pluto";
const PLUTO_INSTALL: &str = "https://pluto.docs.fairwinds.com/installation/";
const KUBENT: &str = "kubent";
const KUBENT_INSTALL: &str = "https://github.com/doitintl/kube-no-trouble#installation";
/// Pluto exits 2, 3 or 4 when it finds something, which is a result and not a
/// failure. These flags keep the exit code about whether pluto itself worked.
const PLUTO_EXIT_FLAGS: [&str; 3] = [
    "--ignore-deprecations",
    "--ignore-removals",
    "--ignore-unavailable-replacements",
];

// ------------------------------------------------------------------- input --

/// A JSON string kept as a borrow into the buffer it was parsed from. Serde's
/// `Cow` deserializer copies every string, even with `#[serde(borrow)]`, so
/// this one keeps the borrow instead and copies only a string with escapes.
/// A missing field and an explicit `null` both read as empty.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct Text<'a>(Cow<'a, str>);

impl<'de: 'a, 'a> Deserialize<'de> for Text<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Keep;
        impl<'de> Visitor<'de> for Keep {
            type Value = Text<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or null")
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
                Ok(Text(Cow::Borrowed(value)))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Text(Cow::Owned(value.to_owned())))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Text::default())
            }
        }
        // `deserialize_str` refuses a null outright rather than offering it to
        // the visitor. JSON describes itself, so ask for whatever is there and
        // let `Keep` accept a string or a null and reject the rest.
        deserializer.deserialize_any(Keep)
    }
}

#[derive(Deserialize)]
struct Request<'a> {
    schema_version: u32,
    #[serde(borrow, default)]
    context: Text<'a>,
    #[serde(borrow, default)]
    namespace: Text<'a>,
    #[serde(borrow, default)]
    name: Text<'a>,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
    /// Kept raw: the selected object is forwarded to pluto byte for byte, not
    /// re-serialized, so pluto sees exactly what the API server returned.
    #[serde(borrow, default)]
    object: Option<&'a serde_json::value::RawValue>,
}

// ------------------------------------------------------------------- pluto --

#[derive(Default, Deserialize)]
struct PlutoReport<'a> {
    #[serde(borrow, default)]
    items: Vec<PlutoItem<'a>>,
    #[serde(borrow, default, rename = "target-versions")]
    target_versions: BTreeMap<Text<'a>, Text<'a>>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct PlutoItem<'a> {
    #[serde(borrow)]
    name: Text<'a>,
    #[serde(borrow)]
    namespace: Text<'a>,
    #[serde(borrow)]
    api: PlutoApi<'a>,
    deprecated: bool,
    removed: bool,
    #[serde(rename = "replacementAvailable")]
    replacement_available: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct PlutoApi<'a> {
    #[serde(borrow)]
    version: Text<'a>,
    #[serde(borrow)]
    kind: Text<'a>,
    #[serde(borrow, rename = "deprecated-in")]
    deprecated_in: Text<'a>,
    #[serde(borrow, rename = "removed-in")]
    removed_in: Text<'a>,
    #[serde(borrow, rename = "replacement-api")]
    replacement_api: Text<'a>,
    #[serde(borrow)]
    component: Text<'a>,
}

// ------------------------------------------------------------------ kubent --

/// kubent writes a bare array with capitalised keys, and no verdict of its
/// own: every rule set it ships is about an apiVersion that is already gone in
/// some release, so each finding is a removal.
#[derive(Default, Deserialize)]
#[serde(default)]
struct KubentItem<'a> {
    #[serde(borrow, rename = "Name")]
    name: Text<'a>,
    #[serde(borrow, rename = "Namespace")]
    namespace: Text<'a>,
    #[serde(borrow, rename = "Kind")]
    kind: Text<'a>,
    #[serde(borrow, rename = "ApiVersion")]
    api_version: Text<'a>,
    #[serde(borrow, rename = "RuleSet")]
    rule_set: Text<'a>,
    #[serde(borrow, rename = "ReplaceWith")]
    replace_with: Text<'a>,
}

// ----------------------------------------------------------------- finding --

/// One deprecated apiVersion, whichever tool found it.
struct Finding<'a> {
    name: Cow<'a, str>,
    namespace: Cow<'a, str>,
    kind: Cow<'a, str>,
    version: Cow<'a, str>,
    replacement: Cow<'a, str>,
    note: Cow<'a, str>,
    removed: bool,
    replaceable: bool,
}

impl<'a> Finding<'a> {
    fn from_pluto(item: &PlutoItem<'a>) -> Self {
        let api = &item.api;
        // An apiVersion that is deprecated but still served must not read as
        // already gone, so only a removal says "removed in".
        let note = match (
            item.removed,
            api.removed_in.0.is_empty(),
            api.deprecated_in.0.is_empty(),
        ) {
            (true, false, _) => Cow::Owned(format!("removed in {}", api.removed_in.0)),
            (false, false, false) => Cow::Owned(format!(
                "deprecated in {}, removed in {}",
                api.deprecated_in.0, api.removed_in.0
            )),
            (_, _, false) => Cow::Owned(format!("deprecated in {}", api.deprecated_in.0)),
            _ => Cow::Borrowed(""),
        };
        Finding {
            name: item.name.0.clone(),
            namespace: item.namespace.0.clone(),
            kind: api.kind.0.clone(),
            version: api.version.0.clone(),
            replacement: api.replacement_api.0.clone(),
            note,
            removed: item.removed,
            replaceable: item.replacement_available || !item.removed,
        }
    }

    fn from_kubent(item: &KubentItem<'a>) -> Self {
        // kubent spells "there is none" with these two words rather than with
        // an empty string; printing them verbatim would read like a resource
        // called <undefined> and an apiVersion called <removed>.
        let namespace = undefined(&item.namespace.0, "<undefined>");
        let replacement = undefined(&item.replace_with.0, "<removed>");
        Finding {
            name: item.name.0.clone(),
            namespace,
            kind: item.kind.0.clone(),
            version: item.api_version.0.clone(),
            replaceable: !replacement.is_empty(),
            replacement,
            note: item.rule_set.0.clone(),
            removed: true,
        }
    }

    /// `namespace/name — Kind old/v1beta1 → new/v1 (removed in v1.22.0)`
    #[allow(clippy::doc_markdown)]
    fn line(&self) -> Cow<'a, str> {
        let mut line = String::with_capacity(96);
        if !self.namespace.is_empty() {
            line.push_str(&self.namespace);
            line.push('/');
        }
        line.push_str(if self.name.is_empty() {
            "<unnamed>"
        } else {
            &self.name
        });
        line.push_str(" — ");
        if !self.kind.is_empty() {
            line.push_str(&self.kind);
            line.push(' ');
        }
        line.push_str(&self.version);
        if self.replacement.is_empty() {
            line.push_str(" → no replacement");
        } else {
            line.push_str(" → ");
            line.push_str(&self.replacement);
        }
        if !self.note.is_empty() {
            line.push_str(" (");
            line.push_str(&self.note);
            line.push(')');
        }
        Cow::Owned(line)
    }
}

/// A tool's placeholder for a missing value, read as missing.
fn undefined<'a>(value: &Cow<'a, str>, sentinel: &str) -> Cow<'a, str> {
    match &**value == sentinel {
        true => Cow::Borrowed(""),
        false => value.clone(),
    }
}

// ------------------------------------------------------------------ report --

#[derive(Serialize)]
struct Report<'a> {
    schema_version: u32,
    title: &'static str,
    sections: Vec<Section<'a>>,
}

#[derive(Serialize)]
struct Section<'a> {
    title: Cow<'a, str>,
    #[serde(flatten)]
    body: Body<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Body<'a> {
    Table {
        columns: [&'static str; 2],
        rows: Vec<[Cow<'a, str>; 2]>,
    },
    Lines {
        lines: Vec<Cow<'a, str>>,
    },
}

fn table<'a>(title: &'static str, rows: Vec<[Cow<'a, str>; 2]>) -> Section<'a> {
    Section {
        title: Cow::Borrowed(title),
        body: Body::Table {
            columns: ["Field", "Value"],
            rows,
        },
    }
}

fn lines<'a>(title: impl Into<Cow<'a, str>>, lines: Vec<Cow<'a, str>>) -> Section<'a> {
    Section {
        title: title.into(),
        body: Body::Lines { lines },
    }
}

/// A row, unless the value is empty.
fn row<'a>(field: &'static str, value: impl Into<Cow<'a, str>>) -> Option<[Cow<'a, str>; 2]> {
    let value = value.into();
    (!value.is_empty()).then_some([Cow::Borrowed(field), value])
}

fn context<'a>(request: &Request<'a>) -> [Cow<'a, str>; 2] {
    let context = match request.context.0.is_empty() {
        true => Cow::Borrowed("inferred"),
        false => request.context.0.clone(),
    };
    [Cow::Borrowed("Context"), context]
}

/// Removed first: those break on the next upgrade. A removal with no
/// replacement is worse still, because there is nothing to edit it into.
fn sections<'a>(findings: &[Finding<'a>]) -> Vec<Section<'a>> {
    let group = |keep: &dyn Fn(&Finding<'a>) -> bool| {
        findings
            .iter()
            .filter(|finding| keep(finding))
            .map(Finding::line)
            .collect::<Vec<_>>()
    };
    let stranded = group(&|f| f.removed && !f.replaceable);
    let removed = group(&|f| f.removed && f.replaceable);
    let deprecated = group(&|f| !f.removed);
    let mut sections = Vec::new();
    for (title, group) in [
        ("Removed with no replacement", stranded),
        ("Removed", removed),
        ("Deprecated", deprecated),
    ] {
        if !group.is_empty() {
            sections.push(lines(title, group));
        }
    }
    sections
}

fn verdict(findings: &[Finding<'_>]) -> String {
    if findings.is_empty() {
        return "no deprecated apiVersions".to_string();
    }
    let removed = findings.iter().filter(|f| f.removed).count();
    let deprecated = findings.len() - removed;
    match (removed, deprecated) {
        (0, _) => format!("{deprecated} deprecated"),
        (_, 0) => format!("{removed} removed"),
        _ => format!("{removed} removed, {deprecated} deprecated"),
    }
}

// ----------------------------------------------------------------- actions --

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action {
    Pluto,
    Kubent,
    Resource,
}

impl Action {
    /// The command arguments sofka passes from the manifest. Sofka appends
    /// nothing, so anything beyond the action is a manifest mistake.
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let action = match args.next().as_deref() {
            None | Some("pluto") => Action::Pluto,
            Some("kubent") => Action::Kubent,
            Some("resource") => Action::Resource,
            Some(other) => {
                return Err(format!(
                    "unknown action {other:?}; use pluto, kubent or resource"
                ));
            }
        };
        if let Some(extra) = args.next() {
            return Err(format!("unexpected argument {extra:?}"));
        }
        Ok(action)
    }

    fn tool(self) -> (&'static str, &'static str) {
        match self {
            Action::Kubent => (KUBENT, KUBENT_INSTALL),
            _ => (PLUTO, PLUTO_INSTALL),
        }
    }
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
    let action = Action::parse(std::env::args().skip(1))?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(REQUEST_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > REQUEST_MAX_BYTES {
        return Err("request exceeds 1 MiB".into());
    }
    let request = parse(&bytes)?;
    // Two steps, so everything that runs a tool happens here and the renderer
    // stays a pure function of these two buffers, which is also what lets the
    // report borrow from both instead of copying out of them.
    let source = fetch(action, &request)?;
    let report = render(action, &request, &source)?;
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    serde_json::to_writer(&mut stdout, &report).map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())
}

/// The request, borrowed from `bytes`, once it is one this adapter speaks.
/// The report schema stays `1` as well, separate from the manifest schema.
fn parse(bytes: &[u8]) -> Result<Request<'_>, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid request: {e}"))?;
    if request.schema_version != 1 {
        return Err("unsupported request schema_version".into());
    }
    Ok(request)
}

fn fetch(action: Action, request: &Request<'_>) -> Result<Vec<u8>, String> {
    if let Some(replayed) = replay(request)? {
        return Ok(replayed);
    }
    let (program, install) = action.tool();
    let (args, input) = match action {
        Action::Pluto => (pluto_arguments(request), None),
        Action::Kubent => (kubent_arguments(request), None),
        Action::Resource => (
            resource_arguments(),
            Some(
                request
                    .object
                    .ok_or("the request has no object to check")?
                    .get()
                    .as_bytes(),
            ),
        ),
    };
    let _ = writeln!(std::io::stderr(), "Scanning for deprecated apiVersions");
    let output = execute_tool(program, &args, input, install)?;
    let _ = writeln!(std::io::stderr(), "Scan finished; preparing the report");
    Ok(output)
}

fn render<'a>(
    action: Action,
    request: &Request<'a>,
    source: &'a [u8],
) -> Result<Report<'a>, String> {
    match action {
        Action::Kubent => {
            let items: Vec<KubentItem> = serde_json::from_slice(source)
                .map_err(|e| format!("{KUBENT} returned invalid JSON: {e}"))?;
            let findings: Vec<Finding> = items.iter().map(Finding::from_kubent).collect();
            let rows = [
                row("Verdict", verdict(&findings)),
                Some(context(request)),
                row("Scanned", "cluster and Helm v3 releases"),
                row("Findings", findings.len().to_string()),
            ];
            Ok(report(
                "Deprecated APIs (kubent)",
                rows.into_iter().flatten().collect(),
                &findings,
            ))
        }
        Action::Pluto | Action::Resource => {
            let parsed: PlutoReport = serde_json::from_slice(source)
                .map_err(|e| format!("{PLUTO} returned invalid JSON: {e}"))?;
            let findings: Vec<Finding> = parsed.items.iter().map(Finding::from_pluto).collect();
            let targets = parsed
                .target_versions
                .iter()
                .map(|(component, version)| format!("{}={}", component.0, version.0))
                .collect::<Vec<_>>()
                .join(" ");
            let scope = match action {
                Action::Resource => row("Selection", selection(request)),
                _ => row(
                    "Namespace",
                    request.inputs.get("namespace").cloned().unwrap_or_default(),
                ),
            };
            let rows = [
                row("Verdict", verdict(&findings)),
                Some(context(request)),
                scope,
                row("Target versions", targets),
                row("Findings", findings.len().to_string()),
            ];
            let title = match action {
                Action::Resource => "Deprecated APIs (selection)",
                _ => "Deprecated APIs (pluto)",
            };
            Ok(report(
                title,
                rows.into_iter().flatten().collect(),
                &findings,
            ))
        }
    }
}

fn report<'a>(
    title: &'static str,
    rows: Vec<[Cow<'a, str>; 2]>,
    findings: &[Finding<'a>],
) -> Report<'a> {
    let mut sections = vec![table("Summary", rows)];
    sections.extend(self::sections(findings));
    if findings.is_empty() {
        sections.push(lines(
            "Result",
            vec![Cow::Borrowed(
                "Nothing found. Every apiVersion checked is current for the target version.",
            )],
        ));
    }
    Report {
        schema_version: 1,
        title,
        sections,
    }
}

fn selection<'a>(request: &Request<'a>) -> Cow<'a, str> {
    match request.namespace.0.is_empty() {
        true => request.name.0.clone(),
        false => Cow::Owned(format!("{}/{}", request.namespace.0, request.name.0)),
    }
}

/// A saved tool report to render instead of running anything. Read with a
/// limit: the path is user input and may name something without an end.
fn replay(request: &Request<'_>) -> Result<Option<Vec<u8>>, String> {
    let path = request.inputs.get("report").map_or("", String::as_str);
    if path.is_empty() {
        return Ok(None);
    }
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read saved report {path}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(REPLAY_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read saved report {path}: {e}"))?;
    if bytes.len() > REPLAY_MAX_BYTES {
        return Err(format!("saved report {path} exceeds 1 MiB"));
    }
    Ok(Some(bytes))
}

// ------------------------------------------------------------------- tools --

fn pluto_arguments(request: &Request<'_>) -> Vec<String> {
    let mut args = vec![
        "detect-all-in-cluster".into(),
        "--output".into(),
        "json".into(),
    ];
    if !request.context.0.is_empty() {
        args.push("--kube-context".into());
        args.push(request.context.0.to_string());
    }
    if let Some(namespace) = request.inputs.get("namespace").filter(|n| !n.is_empty()) {
        args.push("--namespace".into());
        args.push(namespace.clone());
    }
    if let Some(version) = request
        .inputs
        .get("target_version")
        .filter(|v| !v.is_empty())
    {
        args.push("--target-versions".into());
        args.push(format!("k8s={version}"));
    }
    args.extend(PLUTO_EXIT_FLAGS.iter().map(|flag| flag.to_string()));
    args
}

fn resource_arguments() -> Vec<String> {
    let mut args = vec![
        "detect".into(),
        "-".into(),
        "--output".into(),
        "json".into(),
    ];
    args.extend(PLUTO_EXIT_FLAGS.iter().map(|flag| flag.to_string()));
    args
}

fn kubent_arguments(request: &Request<'_>) -> Vec<String> {
    let mut args = vec![
        "--output".into(),
        "json".into(),
        // kubent colours its progress log even when stdout is not a terminal,
        // and those escapes would land in sofka's activity popup.
        "--log-level".into(),
        "error".into(),
    ];
    if !request.context.0.is_empty() {
        args.push("--context".into());
        args.push(request.context.0.to_string());
    }
    if let Some(version) = request
        .inputs
        .get("target_version")
        .filter(|v| !v.is_empty())
    {
        args.push("--target-version".into());
        args.push(version.clone());
    }
    args
}

#[derive(Debug)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

/// Read to EOF, keeping at most `limit` bytes. Reading past the limit keeps
/// the child from getting SIGPIPE on a closed pipe; the caller decides what a
/// truncated capture means.
fn bounded_read(reader: impl Read, limit: usize) -> std::io::Result<Captured> {
    capture(reader, limit, None)
}

fn capture(
    mut reader: impl Read,
    limit: usize,
    mut forward: Option<&mut dyn std::io::Write>,
) -> std::io::Result<Captured> {
    let mut write_error = None;
    let mut captured = Captured {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut chunk = [0; 8 * 1024];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let keep = read.min(limit.saturating_sub(captured.bytes.len()));
        captured.bytes.extend_from_slice(&chunk[..keep]);
        if let Some(writer) = forward.as_mut()
            && write_error.is_none()
        {
            let result = (|| {
                writer.write_all(&chunk[..keep])?;
                if keep < read && !captured.truncated {
                    writer.write_all(
                        b"\n[deprecated-apis diagnostics truncated; scan continues]\n",
                    )?;
                }
                writer.flush()
            })();
            write_error = result.err();
        }
        if keep < read {
            captured.truncated = true;
        }
    }
    // A failed activity write must not discard the report the child produced.
    Ok(captured)
}

/// Run `program` with `args`, arguments passed separately, optionally writing
/// `input` to its stdin. Returns stdout on success. A failed run, a failed
/// read, or more than 1 MiB of stdout is an error, never a partial report.
fn execute_tool(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    install: &str,
) -> Result<Vec<u8>, String> {
    let command = format!("{program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start {program} ({e}); install it from {install}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("failed to capture {program} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("failed to capture {program} stderr"))?;
    // Feed stdin on its own thread and close it there. Writing inline would
    // deadlock as soon as the object outgrows the pipe buffer, because nothing
    // would be draining stdout meanwhile.
    let writer = input.map(|input| {
        let mut stdin = child.stdin.take();
        let input = input.to_vec();
        std::thread::spawn(move || {
            let result = stdin
                .as_mut()
                .map(|stdin| stdin.write_all(&input))
                .unwrap_or(Ok(()));
            drop(stdin);
            result
        })
    });
    // Drain stderr on its own thread so a chatty tool cannot block on a full
    // pipe while this process waits on stdout.
    let errors =
        std::thread::spawn(move || capture(stderr, STDERR_MAX_BYTES, Some(&mut std::io::stderr())));
    let output = bounded_read(stdout, OUTPUT_MAX_BYTES);
    let status = child
        .wait()
        .map_err(|e| format!("failed while waiting for {program}: {e}"))?;
    let errors = errors
        .join()
        .map_err(|_| format!("failed while reading {program} stderr"))?
        .map_err(|e| format!("failed while reading {program} stderr: {e}"))?;
    let output = output.map_err(|e| format!("failed while reading {program} stdout: {e}"))?;
    if let Some(writer) = writer {
        // A tool that stops reading early is not a failure by itself; only
        // report the write error when the tool also failed to produce output.
        let written = writer
            .join()
            .map_err(|_| format!("failed while writing to {program}"))?;
        if let Err(error) = written
            && !status.success()
        {
            return Err(format!("failed while writing to {program}: {error}"));
        }
    }
    if !status.success() {
        let detail = if errors.bytes.iter().all(u8::is_ascii_whitespace) {
            output.bytes
        } else {
            errors.bytes
        };
        return Err(format!(
            "{command} failed ({status}): {}",
            String::from_utf8_lossy(&detail).trim()
        ));
    }
    if output.truncated {
        return Err(format!(
            "{command} wrote more than 1 MiB; the report would be incomplete"
        ));
    }
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn read(name: &str) -> Vec<u8> {
        let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(path).unwrap()
    }

    fn expected(name: &str) -> Value {
        serde_json::from_slice(&read(name)).unwrap()
    }

    /// Render a fixture the way `execute` does, from bytes, so the borrowed
    /// lifetimes are the ones the adapter really uses.
    fn report(action: Action, request: &[u8], source: &[u8]) -> Result<Value, String> {
        let request = parse(request)?;
        Ok(serde_json::to_value(render(action, &request, source)?).unwrap())
    }

    fn rows_of(report: &Value) -> Vec<Value> {
        report["sections"][0]["rows"].as_array().unwrap().clone()
    }

    fn titles(report: &Value) -> Vec<String> {
        report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|section| section["title"].as_str().unwrap().to_string())
            .collect()
    }

    // ------------------------------------------------------------- fixtures --

    #[test]
    fn the_pluto_fixture_matches_its_report() {
        assert_eq!(
            report(Action::Pluto, &read("request.json"), &read("pluto.json")).unwrap(),
            expected("report.json")
        );
    }

    #[test]
    fn the_kubent_fixture_matches_its_report() {
        assert_eq!(
            report(
                Action::Kubent,
                &read("kubent-request.json"),
                &read("kubent.json")
            )
            .unwrap(),
            expected("kubent-report.json")
        );
    }

    #[test]
    fn the_resource_fixture_matches_its_report() {
        assert_eq!(
            report(
                Action::Resource,
                &read("resource-request.json"),
                &read("resource.json")
            )
            .unwrap(),
            expected("resource-report.json")
        );
    }

    #[test]
    fn every_request_fixture_replays_its_saved_tool_report() {
        for (request, saved) in [
            (
                "request.json",
                "plugins/deprecated-apis/fixtures/pluto.json",
            ),
            (
                "kubent-request.json",
                "plugins/deprecated-apis/fixtures/kubent.json",
            ),
            (
                "resource-request.json",
                "plugins/deprecated-apis/fixtures/resource.json",
            ),
        ] {
            let bytes = read(request);
            let parsed = parse(&bytes).unwrap();
            assert_eq!(parsed.inputs.get("report").map(String::as_str), Some(saved));
        }
    }

    // -------------------------------------------------------------- grouping --

    /// The order is the order of the work: what is already broken and cannot be
    /// fixed by an edit, then what is broken, then what still runs.
    #[test]
    fn findings_are_grouped_by_what_they_cost() {
        let report = report(Action::Pluto, &read("request.json"), &read("pluto.json")).unwrap();
        assert_eq!(
            titles(&report),
            [
                "Summary",
                "Removed with no replacement",
                "Removed",
                "Deprecated"
            ]
        );
        assert_eq!(
            rows_of(&report)[0],
            json!(["Verdict", "3 removed, 1 deprecated"])
        );
    }

    #[test]
    fn a_clean_scan_says_so_instead_of_showing_empty_groups() {
        for (action, source) in [
            (
                Action::Pluto,
                &b"{\"target-versions\":{\"k8s\":\"v1.31.0\"}}"[..],
            ),
            (Action::Kubent, &b"[]"[..]),
        ] {
            let request = match action {
                Action::Kubent => read("kubent-request.json"),
                _ => read("request.json"),
            };
            let report = report(action, &request, source).unwrap();
            assert_eq!(titles(&report), ["Summary", "Result"]);
            assert_eq!(
                rows_of(&report)[0],
                json!(["Verdict", "no deprecated apiVersions"])
            );
        }
    }

    #[test]
    fn a_verdict_names_only_the_kinds_of_finding_present() {
        let finding = |removed| Finding {
            name: Cow::Borrowed("a"),
            namespace: Cow::Borrowed(""),
            kind: Cow::Borrowed("Ingress"),
            version: Cow::Borrowed("extensions/v1beta1"),
            replacement: Cow::Borrowed(""),
            note: Cow::Borrowed(""),
            removed,
            replaceable: true,
        };
        assert_eq!(verdict(&[]), "no deprecated apiVersions");
        assert_eq!(verdict(&[finding(true)]), "1 removed");
        assert_eq!(verdict(&[finding(false)]), "1 deprecated");
        assert_eq!(
            verdict(&[finding(true), finding(false)]),
            "1 removed, 1 deprecated"
        );
    }

    // ----------------------------------------------------------------- lines --

    #[test]
    fn a_cluster_scoped_finding_has_no_namespace_prefix() {
        let report = report(Action::Pluto, &read("request.json"), &read("pluto.json")).unwrap();
        assert_eq!(
            report["sections"][1]["lines"],
            json!([
                "restricted — PodSecurityPolicy policy/v1beta1 → no replacement (removed in v1.25.0)"
            ])
        );
    }

    /// kubent spells a missing namespace and a missing replacement with words
    /// rather than empty strings.
    #[test]
    fn the_kubent_placeholders_are_read_as_missing() {
        let report = report(
            Action::Kubent,
            &read("kubent-request.json"),
            &read("kubent.json"),
        )
        .unwrap();
        let rendered = report.to_string();
        assert!(!rendered.contains("<undefined>"), "{rendered}");
        assert!(!rendered.contains("<removed>"), "{rendered}");
        assert_eq!(
            report["sections"][1]["lines"],
            json!([
                "restricted — PodSecurityPolicy policy/v1beta1 → no replacement (Deprecated APIs removed in 1.25)"
            ])
        );
    }

    /// An apiVersion that is still served must not read as already gone.
    #[test]
    fn a_deprecated_but_served_api_is_not_called_removed() {
        let report = report(Action::Pluto, &read("request.json"), &read("pluto.json")).unwrap();
        let deprecated = report["sections"][3]["lines"][0].as_str().unwrap();
        assert!(
            deprecated.ends_with("(deprecated in v1.23.0, removed in v1.26.0)"),
            "{deprecated}"
        );
    }

    #[test]
    fn an_unnamed_finding_is_still_listed() {
        let source = br#"{"items":[{"removed":true,"api":{"version":"v1beta1"}}]}"#;
        let report = report(Action::Pluto, &read("request.json"), source).unwrap();
        assert_eq!(
            report["sections"][1]["lines"],
            json!(["<unnamed> — v1beta1 → no replacement"])
        );
    }

    // --------------------------------------------------------------- the CLI --

    #[test]
    fn the_action_comes_from_the_first_argument_and_defaults_to_pluto() {
        let parse = |args: &[&str]| Action::parse(args.iter().map(|a| a.to_string()));
        assert_eq!(parse(&[]), Ok(Action::Pluto));
        assert_eq!(parse(&["pluto"]), Ok(Action::Pluto));
        assert_eq!(parse(&["kubent"]), Ok(Action::Kubent));
        assert_eq!(parse(&["resource"]), Ok(Action::Resource));
        assert!(parse(&["scan"]).unwrap_err().contains("unknown action"));
        assert!(parse(&["pluto", "now"]).unwrap_err().contains("unexpected"));
    }

    #[test]
    fn pluto_is_told_not_to_turn_findings_into_a_failing_exit_code() {
        let bytes = read("request.json");
        let request = parse(&bytes).unwrap();
        let args = pluto_arguments(&request);
        for flag in PLUTO_EXIT_FLAGS {
            assert!(args.iter().any(|arg| arg == flag), "{args:?}");
        }
        assert!(resource_arguments().contains(&"--ignore-removals".to_string()));
    }

    #[test]
    fn the_pluto_command_carries_the_context_namespace_and_target_version() {
        let mut request = expected("request.json");
        request["inputs"]["namespace"] = json!("apps");
        request["inputs"]["target_version"] = json!("v1.31.0");
        let bytes = serde_json::to_vec(&request).unwrap();
        let request = parse(&bytes).unwrap();
        assert_eq!(
            pluto_arguments(&request)[..9],
            [
                "detect-all-in-cluster",
                "--output",
                "json",
                "--kube-context",
                "development",
                "--namespace",
                "apps",
                "--target-versions",
                "k8s=v1.31.0"
            ]
        );
    }

    #[test]
    fn the_kubent_command_silences_its_coloured_progress_log() {
        let mut request = expected("kubent-request.json");
        request["inputs"]["target_version"] = json!("1.31.0");
        let bytes = serde_json::to_vec(&request).unwrap();
        let request = parse(&bytes).unwrap();
        assert_eq!(
            kubent_arguments(&request),
            [
                "--output",
                "json",
                "--log-level",
                "error",
                "--context",
                "development",
                "--target-version",
                "1.31.0"
            ]
        );
    }

    #[test]
    fn an_empty_input_is_left_off_the_command_rather_than_passed_as_empty() {
        let bytes = read("request.json");
        let request = parse(&bytes).unwrap();
        let args = pluto_arguments(&request);
        assert!(!args.iter().any(|arg| arg == "--namespace"), "{args:?}");
        assert!(
            !args.iter().any(|arg| arg == "--target-versions"),
            "{args:?}"
        );
    }

    // ---------------------------------------------------------- zero copying --

    #[test]
    fn strings_are_borrowed_from_the_tool_output_and_copied_only_when_escaped() {
        let source = br#"[{"Name":"plain","RuleSet":"a \"quoted\" set"}]"#;
        let items: Vec<KubentItem> = serde_json::from_slice(source).unwrap();
        assert!(matches!(items[0].name.0, Cow::Borrowed(_)));
        // Unescaping needs bytes that are not in the buffer, so only this copies.
        assert!(matches!(items[0].rule_set.0, Cow::Owned(_)));
    }

    #[test]
    fn the_selected_object_is_forwarded_as_the_exact_bytes_sofka_sent() {
        let bytes = read("resource-request.json");
        let request = parse(&bytes).unwrap();
        let raw = request.object.unwrap().get();
        assert!(raw.contains("autoscaling/v2beta2"));
        // A re-serialization would drop the original spacing; a raw slice keeps it.
        assert!(raw.contains("\n"), "the object was re-serialized: {raw}");
    }

    #[test]
    fn a_null_string_reads_as_empty_rather_than_failing() {
        let item: KubentItem =
            serde_json::from_slice(br#"{"Name":null,"Namespace":"apps"}"#).unwrap();
        assert_eq!(item.name.0, "");
        assert_eq!(item.namespace.0, "apps");
        let error = serde_json::from_slice::<KubentItem>(br#"{"Name":5}"#)
            .map(|_| ())
            .unwrap_err();
        assert!(
            error.to_string().contains("expected a string or null"),
            "{error}"
        );
    }

    // -------------------------------------------------------------- refusals --

    #[test]
    fn a_request_of_another_schema_is_refused_before_anything_runs() {
        let mut request = expected("request.json");
        request["schema_version"] = json!(2);
        let bytes = serde_json::to_vec(&request).unwrap();
        let refused = |bytes: &[u8]| parse(bytes).map(|_| ()).unwrap_err();
        assert_eq!(refused(&bytes), "unsupported request schema_version");
        assert!(refused(b"{").contains("invalid request"));
    }

    #[test]
    fn invalid_tool_output_is_an_error_rather_than_an_empty_report() {
        assert!(
            report(Action::Pluto, &read("request.json"), b"{")
                .unwrap_err()
                .contains("pluto returned invalid JSON")
        );
        // kubent writes an array; pluto's object shape is not one.
        assert!(
            report(Action::Kubent, &read("kubent-request.json"), b"{}")
                .unwrap_err()
                .contains("kubent returned invalid JSON")
        );
    }

    #[test]
    fn a_selection_check_without_an_object_is_refused() {
        let mut request = expected("resource-request.json");
        request["object"] = Value::Null;
        request["inputs"] = json!({});
        let bytes = serde_json::to_vec(&request).unwrap();
        let request = parse(&bytes).unwrap();
        assert_eq!(
            fetch(Action::Resource, &request).unwrap_err(),
            "the request has no object to check"
        );
    }

    #[test]
    fn the_saved_report_is_bounded_and_a_missing_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("deprecated-apis-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let large = dir.join("large.json");
        std::fs::write(&large, vec![b'x'; REPLAY_MAX_BYTES + 1]).unwrap();
        let replay_error = |path: std::path::PathBuf| {
            let mut request = expected("request.json");
            request["inputs"]["report"] = json!(path.to_string_lossy());
            let bytes = serde_json::to_vec(&request).unwrap();
            let request = parse(&bytes).unwrap();
            fetch(Action::Pluto, &request).unwrap_err()
        };
        assert!(replay_error(large).contains("exceeds 1 MiB"));
        assert!(replay_error(dir.join("missing.json")).contains("cannot read saved report"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    // ------------------------------------------------------------- the pipes --

    #[test]
    fn a_capture_is_bounded_but_still_drained_to_the_end() {
        let mut reader = std::io::Cursor::new(vec![b'x'; 4096]);
        let captured = bounded_read(&mut reader, 1024).unwrap();
        assert_eq!(captured.bytes.len(), 1024);
        assert!(captured.truncated);
        // Draining matters: a child blocked on a full pipe never exits.
        assert_eq!(reader.position(), 4096);
    }

    #[test]
    fn a_capture_propagates_a_read_failure_and_retries_an_interrupt() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        assert_eq!(bounded_read(Failing, 1024).unwrap_err().to_string(), "boom");

        struct Interrupted(u8);
        impl Read for Interrupted {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                match self.0 {
                    1 => Err(std::io::Error::from(ErrorKind::Interrupted)),
                    2 => {
                        buf[0] = b'o';
                        Ok(1)
                    }
                    _ => Ok(0),
                }
            }
        }
        assert_eq!(bounded_read(Interrupted(0), 1024).unwrap().bytes, b"o");
    }

    #[test]
    fn diagnostics_are_forwarded_with_a_notice_and_a_broken_writer_is_survived() {
        let mut forwarded = Vec::new();
        let captured = capture(&b"loud"[..], 2, Some(&mut forwarded)).unwrap();
        assert_eq!(captured.bytes, b"lo");
        let forwarded = String::from_utf8(forwarded).unwrap();
        assert!(
            forwarded.contains("deprecated-apis diagnostics truncated"),
            "{forwarded}"
        );

        /// Activity is a courtesy; losing it must not lose the report.
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from(ErrorKind::BrokenPipe))
            }
        }
        let captured = capture(&b"loud"[..], 64, Some(&mut Broken)).unwrap();
        assert_eq!(captured.bytes, b"loud");
    }

    #[test]
    fn a_missing_tool_points_at_its_installation() {
        let error = execute_tool("pluto-no-such-tool", &[], None, PLUTO_INSTALL).unwrap_err();
        assert!(
            error.contains("failed to start pluto-no-such-tool"),
            "{error}"
        );
        assert!(error.contains(PLUTO_INSTALL), "{error}");
    }

    /// A fake tool on disk; the adapter never starts a shell itself.
    #[cfg(unix)]
    fn fake_tool(name: &str, script: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir =
            std::env::temp_dir().join(format!("deprecated-apis-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    #[cfg(unix)]
    #[test]
    fn standard_input_reaches_the_tool() {
        let (dir, tool) = fake_tool("echoing", "cat");
        let output =
            execute_tool(tool.to_str().unwrap(), &[], Some(b"{\"piped\":true}"), "").unwrap();
        assert_eq!(output, b"{\"piped\":true}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// pluto reads stdin to the end, but a tool that exits early must not turn
    /// into a broken-pipe error while it still produced a usable report.
    #[cfg(unix)]
    #[test]
    fn a_tool_that_ignores_standard_input_still_reports() {
        let (dir, tool) = fake_tool("ignoring", "printf '{\"items\":[]}'");
        let big = vec![b'x'; 1024 * 1024];
        let output = execute_tool(tool.to_str().unwrap(), &[], Some(&big), "").unwrap();
        assert_eq!(output, b"{\"items\":[]}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_tool_reports_its_stderr_and_not_its_partial_stdout() {
        let (dir, tool) = fake_tool(
            "failing",
            "echo '{\"items\":['\necho 'Error: cannot reach the API server' >&2\nexit 1",
        );
        let args = vec!["detect-all-in-cluster".to_string()];
        let error = execute_tool(tool.to_str().unwrap(), &args, None, "").unwrap_err();
        assert!(error.contains("detect-all-in-cluster failed"), "{error}");
        assert!(error.contains("cannot reach the API server"), "{error}");
        assert!(!error.contains("items"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_silent_failing_tool_falls_back_to_its_stdout() {
        let (dir, tool) = fake_tool("quiet", "echo 'nothing to see'\nexit 2");
        let error = execute_tool(tool.to_str().unwrap(), &[], None, "").unwrap_err();
        assert!(error.contains("nothing to see"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_tool_that_floods_stderr_still_finishes() {
        let (dir, tool) = fake_tool(
            "noisy",
            "head -c 2097152 /dev/zero | tr '\\0' e >&2\nprintf '[]'",
        );
        let output = execute_tool(tool.to_str().unwrap(), &[], None, "").unwrap();
        assert_eq!(output, b"[]");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_tool_that_writes_over_the_limit_is_an_error_not_a_partial_report() {
        let (dir, tool) = fake_tool("flood", "head -c 2097152 /dev/zero | tr '\\0' e");
        let error = execute_tool(tool.to_str().unwrap(), &[], None, "").unwrap_err();
        assert!(error.contains("more than 1 MiB"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
