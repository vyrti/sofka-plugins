//! Velero. One adapter behind three sofka commands: `inspect` renders the
//! selected Backup or Restore, `trigger` runs `velero backup create
//! --from-schedule` for the selected Schedule, and `locations` reads the
//! BackupStorageLocations with kubectl and reports their health.
//!
//! The first command argument selects the action. No argument means `inspect`,
//! so the CI fixture step, which runs the adapter without arguments, tests the
//! inspect pair.
//!
//! `inspect` runs no tool at all. Sofka already sends the selected object, and
//! a Velero Backup or Restore carries its whole result in `status`, so the
//! report comes from the request itself.
//!
//! Strings are borrowed, not copied. `Text` keeps the borrow that serde's own
//! `Cow` deserializer throws away, so a large backup object is read without
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
const VELERO: &str = "velero";
const VELERO_INSTALL: &str = "https://velero.io/docs/main/basic-install/";
const KUBECTL: &str = "kubectl";
const KUBECTL_INSTALL: &str = "https://kubernetes.io/docs/tasks/tools/";
const GROUP: &str = "velero.io/";
const LOCATIONS: &str = "backupstoragelocations.velero.io";
/// Velero labels every scheduled backup with the schedule that produced it.
const SCHEDULE_LABEL: Text<'static> = Text(Cow::Borrowed("velero.io/schedule-name"));

// ------------------------------------------------------------------- input --

/// A JSON string kept as a borrow into the buffer it was parsed from. Serde's
/// `Cow` deserializer copies every string, even with `#[serde(borrow)]`, so
/// this one keeps the borrow instead and copies only a string with escapes.
/// A missing field and an explicit `null`, which Kubernetes writes for an
/// unset `creationTimestamp`, both read as empty.
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
    #[serde(borrow, default)]
    object: Option<Resource<'a>>,
}

/// Every Velero kind this adapter reads, in one model. A field a kind does not
/// have stays empty, which is what the renderer skips on anyway.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Resource<'a> {
    #[serde(borrow)]
    api_version: Text<'a>,
    #[serde(borrow)]
    kind: Text<'a>,
    #[serde(borrow)]
    metadata: Meta<'a>,
    #[serde(borrow)]
    spec: Spec<'a>,
    #[serde(borrow)]
    status: Status<'a>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Meta<'a> {
    #[serde(borrow)]
    name: Text<'a>,
    #[serde(borrow)]
    namespace: Text<'a>,
    #[serde(borrow)]
    labels: BTreeMap<Text<'a>, Text<'a>>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Spec<'a> {
    // Backup.
    #[serde(borrow)]
    ttl: Text<'a>,
    #[serde(borrow)]
    storage_location: Text<'a>,
    #[serde(borrow)]
    included_namespaces: Vec<Text<'a>>,
    #[serde(borrow)]
    excluded_namespaces: Vec<Text<'a>>,
    snapshot_volumes: Option<bool>,
    // Restore.
    #[serde(borrow)]
    backup_name: Text<'a>,
    #[serde(borrow)]
    schedule_name: Text<'a>,
    // Schedule.
    #[serde(borrow)]
    schedule: Text<'a>,
    paused: bool,
    // BackupStorageLocation.
    #[serde(borrow)]
    provider: Text<'a>,
    #[serde(borrow)]
    access_mode: Text<'a>,
    default: bool,
    #[serde(borrow)]
    validation_frequency: Text<'a>,
    #[serde(borrow)]
    object_storage: Storage<'a>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Storage<'a> {
    #[serde(borrow)]
    bucket: Text<'a>,
    #[serde(borrow)]
    prefix: Text<'a>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Status<'a> {
    #[serde(borrow)]
    phase: Text<'a>,
    #[serde(borrow)]
    start_timestamp: Text<'a>,
    #[serde(borrow)]
    completion_timestamp: Text<'a>,
    #[serde(borrow)]
    expiration: Text<'a>,
    #[serde(borrow)]
    failure_reason: Text<'a>,
    #[serde(borrow)]
    validation_errors: Vec<Text<'a>>,
    errors: u64,
    warnings: u64,
    progress: Progress,
    // BackupStorageLocation.
    #[serde(borrow)]
    message: Text<'a>,
    #[serde(borrow)]
    last_validation_time: Text<'a>,
    #[serde(borrow)]
    last_synced_time: Text<'a>,
    // Schedule.
    #[serde(borrow)]
    last_backup: Text<'a>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Progress {
    total_items: u64,
    items_backed_up: u64,
    items_restored: u64,
}

/// What `kubectl get ... --output json` returns for a collection.
#[derive(Default, Deserialize)]
struct List<'a> {
    #[serde(borrow, default)]
    items: Vec<Resource<'a>>,
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

/// A row, unless the value is empty. Velero leaves a field out until the phase
/// that fills it, so an empty row would only add noise.
fn row<'a>(field: &'static str, value: impl Into<Cow<'a, str>>) -> Option<[Cow<'a, str>; 2]> {
    let value = value.into();
    (!value.is_empty()).then_some([Cow::Borrowed(field), value])
}

fn texts<'a>(values: &[Text<'a>]) -> Vec<Cow<'a, str>> {
    values.iter().map(|value| value.0.clone()).collect()
}

/// `items` of `total`, or nothing while Velero has counted nothing yet.
fn progress(items: u64, total: u64) -> String {
    if total == 0 {
        String::new()
    } else {
        format!("{items} of {total} items")
    }
}

// ----------------------------------------------------------------- actions --

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action {
    Inspect,
    Trigger,
    Locations,
}

impl Action {
    /// The command arguments sofka passes from the manifest. Sofka appends
    /// nothing, so anything beyond the action is a manifest mistake.
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let action = match args.next().as_deref() {
            None | Some("inspect") => Action::Inspect,
            Some("trigger") => Action::Trigger,
            Some("locations") => Action::Locations,
            Some(other) => {
                return Err(format!(
                    "unknown action {other:?}; use inspect, trigger or locations"
                ));
            }
        };
        if let Some(extra) = args.next() {
            return Err(format!("unexpected argument {extra:?}"));
        }
        Ok(action)
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

/// Everything the action needs from outside the request: nothing for an
/// inspection, the Velero output for a trigger, the locations for a listing.
fn fetch(action: Action, request: &Request<'_>) -> Result<Vec<u8>, String> {
    match action {
        // Only a reading action replays saved output. A replayed trigger would
        // report a backup that nothing created.
        Action::Inspect => Ok(replay(request)?.unwrap_or_default()),
        Action::Trigger if dry_run(request) => {
            let _ = writeln!(std::io::stderr(), "Dry run: no backup will be created");
            Ok(Vec::new())
        }
        Action::Trigger => {
            let _ = writeln!(std::io::stderr(), "Creating a backup from the schedule");
            let output = execute_tool(VELERO, &trigger_arguments(request), VELERO_INSTALL)?;
            let _ = writeln!(
                std::io::stderr(),
                "Backup requested; Velero runs it in the background"
            );
            Ok(output)
        }
        Action::Locations => {
            if let Some(replayed) = replay(request)? {
                return Ok(replayed);
            }
            let _ = writeln!(
                std::io::stderr(),
                "Reading backup storage locations with kubectl"
            );
            let output = execute_tool(KUBECTL, &locations_arguments(request), KUBECTL_INSTALL)?;
            let _ = writeln!(
                std::io::stderr(),
                "Locations collected; preparing the report"
            );
            Ok(output)
        }
    }
}

fn render<'a>(
    action: Action,
    request: &Request<'a>,
    source: &'a [u8],
) -> Result<Report<'a>, String> {
    match action {
        Action::Inspect => {
            let replayed;
            let resource = match source.is_empty() {
                true => selected(request)?,
                false => {
                    replayed = serde_json::from_slice(source)
                        .map_err(|e| format!("the saved object is not valid JSON: {e}"))?;
                    &replayed
                }
            };
            check(resource, request, &["Backup", "Restore"])?;
            Ok(match &*resource.kind.0 {
                "Backup" => backup(request, resource),
                _ => restore(request, resource),
            })
        }
        Action::Trigger => {
            let schedule = selected(request)?;
            check(schedule, request, &["Schedule"])?;
            let output = text(source, VELERO)?;
            Ok(trigger(request, schedule, output, dry_run(request)))
        }
        Action::Locations => {
            let list: List = serde_json::from_slice(source)
                .map_err(|e| format!("{KUBECTL} returned invalid JSON: {e}"))?;
            for item in &list.items {
                if !item.api_version.0.starts_with(GROUP)
                    || &*item.kind.0 != "BackupStorageLocation"
                {
                    return Err(format!("{} is not a {LOCATIONS}", describe(item)));
                }
            }
            Ok(locations(request, list))
        }
    }
}

/// Only the exact string "true" triggers a backup, the same rule chaos-kill
/// applies to its dry_run input.
fn dry_run(request: &Request<'_>) -> bool {
    request.inputs.get("dry_run").is_some_and(|v| v == "true")
}

fn velero_namespace<'a>(request: &Request<'a>) -> Cow<'a, str> {
    match request.inputs.get("namespace") {
        Some(namespace) if !namespace.is_empty() => Cow::Owned(namespace.clone()),
        _ => request.namespace.0.clone(),
    }
}

/// A saved object or tool output to render instead of running anything. Read
/// with a limit: the path is user input and may name something without an end.
fn replay(request: &Request<'_>) -> Result<Option<Vec<u8>>, String> {
    let path = request.inputs.get("replay").map_or("", String::as_str);
    if path.is_empty() {
        return Ok(None);
    }
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot read saved output {path}: {e}"))?;
    let mut bytes = Vec::new();
    file.take(REPLAY_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read saved output {path}: {e}"))?;
    if bytes.len() > REPLAY_MAX_BYTES {
        return Err(format!("saved output {path} exceeds 1 MiB"));
    }
    Ok(Some(bytes))
}

fn text<'a>(bytes: &'a [u8], program: &str) -> Result<&'a str, String> {
    std::str::from_utf8(bytes).map_err(|e| format!("{program} wrote output that is not UTF-8: {e}"))
}

// --------------------------------------------------------------- selection --

fn describe(resource: &Resource<'_>) -> String {
    let api_version = match resource.api_version.0.is_empty() {
        true => "<no apiVersion>",
        false => &resource.api_version.0,
    };
    let kind = match resource.kind.0.is_empty() {
        true => "<no kind>",
        false => &resource.kind.0,
    };
    format!("a {kind} from {api_version}")
}

fn selected<'a, 'r>(request: &'r Request<'a>) -> Result<&'r Resource<'a>, String> {
    request.object.as_ref().ok_or_else(|| {
        format!(
            "the request has no object for {:?}; cannot verify it",
            request.name.0
        )
    })
}

/// Sofka matches scopes on the resource plural only, and `backups`,
/// `restores` and `schedules` are plurals other APIs also serve, so the object
/// has to prove it is the Velero kind the action expects. The name and
/// namespace are checked too: a trigger acts on this Schedule by name, and a
/// replayed object that names something else would report the wrong resource.
fn check(resource: &Resource<'_>, request: &Request<'_>, kinds: &[&str]) -> Result<(), String> {
    let name = &request.name.0;
    if name.is_empty() {
        return Err(format!("no {} selected", kinds.join(" or ")));
    }
    if request.namespace.0.is_empty() {
        return Err(format!("{name} has no namespace"));
    }
    if !resource.api_version.0.starts_with(GROUP) || !kinds.contains(&&*resource.kind.0) {
        return Err(format!(
            "{}/{name} is {}, not a {} {}",
            request.namespace.0,
            describe(resource),
            GROUP.trim_end_matches('/'),
            kinds.join(" or ")
        ));
    }
    for (field, actual, expected) in [
        ("name", &resource.metadata.name.0, name),
        (
            "namespace",
            &resource.metadata.namespace.0,
            &request.namespace.0,
        ),
    ] {
        if actual != expected {
            return Err(format!(
                "the selected object is {field} {actual:?}, the request names {expected:?}"
            ));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- tools --

/// The namespace and context flags Velero and kubectl share. A null context
/// means sofka has no explicit kubeconfig context; the tool then uses the
/// kubeconfig's current one, exactly like sofka did.
fn cluster_arguments(request: &Request<'_>, args: &mut Vec<String>, context_flag: &str) {
    let namespace = velero_namespace(request);
    if !namespace.is_empty() {
        args.push("--namespace".into());
        args.push(namespace.into_owned());
    }
    if !request.context.0.is_empty() {
        args.push(context_flag.into());
        args.push(request.context.0.to_string());
    }
}

fn trigger_arguments(request: &Request<'_>) -> Vec<String> {
    let mut args = vec![
        "backup".into(),
        "create".into(),
        "--from-schedule".into(),
        request.name.0.to_string(),
    ];
    cluster_arguments(request, &mut args, "--kubecontext");
    args
}

fn locations_arguments(request: &Request<'_>) -> Vec<String> {
    let mut args = vec![
        "get".into(),
        LOCATIONS.into(),
        "--output".into(),
        "json".into(),
    ];
    cluster_arguments(request, &mut args, "--context");
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
                    writer.write_all(b"\n[velero diagnostics truncated; operation continues]\n")?;
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

/// Run `program` with `args`, arguments passed separately. Returns stdout on
/// success. A failed run, a failed read, or more than 1 MiB of stdout is an
/// error, never a partial report.
fn execute_tool(program: &str, args: &[String], install: &str) -> Result<Vec<u8>, String> {
    let command = format!("{program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
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

// --------------------------------------------------------------- rendering --

fn context<'a>(request: &Request<'a>) -> [Cow<'a, str>; 2] {
    let context = match request.context.0.is_empty() {
        true => Cow::Borrowed("inferred"),
        false => request.context.0.clone(),
    };
    [Cow::Borrowed("Context"), context]
}

fn phase<'a>(status: &Status<'a>) -> Cow<'a, str> {
    match status.phase.0.is_empty() {
        true => Cow::Borrowed("no phase yet"),
        false => status.phase.0.clone(),
    }
}

/// The namespace lists, the validation errors and the failure reason, in the
/// order Velero fills them. Shared by backups and restores.
fn details<'a>(spec: &Spec<'a>, status: &Status<'a>) -> Vec<Section<'a>> {
    let mut sections = vec![lines(
        "Included namespaces",
        match spec.included_namespaces.is_empty() {
            true => vec![Cow::Borrowed("<all>")],
            false => texts(&spec.included_namespaces),
        },
    )];
    if !spec.excluded_namespaces.is_empty() {
        sections.push(lines(
            "Excluded namespaces",
            texts(&spec.excluded_namespaces),
        ));
    }
    if !status.validation_errors.is_empty() {
        sections.push(lines("Validation errors", texts(&status.validation_errors)));
    }
    if !status.failure_reason.0.is_empty() {
        sections.push(lines("Failure", vec![status.failure_reason.0.clone()]));
    }
    sections
}

fn backup<'a>(request: &Request<'a>, resource: &Resource<'a>) -> Report<'a> {
    let (spec, status) = (&resource.spec, &resource.status);
    let schedule = resource
        .metadata
        .labels
        .get(&SCHEDULE_LABEL)
        .map_or(Cow::Borrowed(""), |name| name.0.clone());
    let rows = [
        row("Verdict", phase(status)),
        Some(context(request)),
        row("Namespace", request.namespace.0.clone()),
        row("Backup", request.name.0.clone()),
        row("From schedule", schedule),
        row("Storage location", spec.storage_location.0.clone()),
        row("Started", status.start_timestamp.0.clone()),
        row("Completed", status.completion_timestamp.0.clone()),
        row("Expires", status.expiration.0.clone()),
        row("TTL", spec.ttl.0.clone()),
        row(
            "Volume snapshots",
            match spec.snapshot_volumes {
                Some(true) => "enabled",
                Some(false) => "disabled",
                None => "",
            },
        ),
        row(
            "Progress",
            progress(status.progress.items_backed_up, status.progress.total_items),
        ),
        row("Errors", status.errors.to_string()),
        row("Warnings", status.warnings.to_string()),
    ];
    let mut sections = vec![table("Summary", rows.into_iter().flatten().collect())];
    sections.extend(details(spec, status));
    Report {
        schema_version: 1,
        title: "Velero backup",
        sections,
    }
}

fn restore<'a>(request: &Request<'a>, resource: &Resource<'a>) -> Report<'a> {
    let (spec, status) = (&resource.spec, &resource.status);
    let rows = [
        row("Verdict", phase(status)),
        Some(context(request)),
        row("Namespace", request.namespace.0.clone()),
        row("Restore", request.name.0.clone()),
        row("From backup", spec.backup_name.0.clone()),
        row("From schedule", spec.schedule_name.0.clone()),
        row("Started", status.start_timestamp.0.clone()),
        row("Completed", status.completion_timestamp.0.clone()),
        row(
            "Progress",
            progress(status.progress.items_restored, status.progress.total_items),
        ),
        row("Errors", status.errors.to_string()),
        row("Warnings", status.warnings.to_string()),
    ];
    let mut sections = vec![table("Summary", rows.into_iter().flatten().collect())];
    sections.extend(details(spec, status));
    Report {
        schema_version: 1,
        title: "Velero restore",
        sections,
    }
}

fn trigger<'a>(
    request: &Request<'a>,
    schedule: &Resource<'a>,
    output: &'a str,
    dry_run: bool,
) -> Report<'a> {
    let rows = [
        row(
            "Verdict",
            match dry_run {
                true => "dry run, nothing was triggered",
                false => "backup requested",
            },
        ),
        Some(context(request)),
        row("Namespace", velero_namespace(request)),
        row("Schedule", request.name.0.clone()),
        row("Cron", schedule.spec.schedule.0.clone()),
        row("Paused", if schedule.spec.paused { "yes" } else { "" }),
        row("Schedule phase", schedule.status.phase.0.clone()),
        row("Last backup", schedule.status.last_backup.0.clone()),
    ];
    let command = format!("{VELERO} {}", trigger_arguments(request).join(" "));
    let mut sections = vec![
        table("Summary", rows.into_iter().flatten().collect()),
        lines("Command", vec![Cow::Owned(command)]),
    ];
    if dry_run {
        sections.push(lines(
            "Notice",
            vec![Cow::Borrowed(
                "Re-run with dry_run=false to create a backup from this schedule.",
            )],
        ));
    } else {
        let mut reported: Vec<Cow<'a, str>> = output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(Cow::Borrowed)
            .collect();
        if reported.is_empty() {
            reported.push(Cow::Borrowed("<no output>"));
        }
        sections.push(lines("velero output", reported));
        sections.push(lines(
            "Next",
            vec![
                Cow::Borrowed(
                    "Velero runs the backup in the background; the report does not wait for it.",
                ),
                Cow::Borrowed("Select the new Backup and use :velero-inspect to follow it."),
            ],
        ));
    }
    Report {
        schema_version: 1,
        title: "Trigger backup schedule",
        sections,
    }
}

fn locations<'a>(request: &Request<'a>, list: List<'a>) -> Report<'a> {
    let available = list
        .items
        .iter()
        .filter(|item| &*item.status.phase.0 == "Available")
        .count();
    let default = list
        .items
        .iter()
        .find(|item| item.spec.default)
        .map_or(Cow::Borrowed("none"), |item| item.metadata.name.0.clone());
    let rows = [
        row(
            "Verdict",
            match list.items.is_empty() {
                true => "no backup storage locations".to_string(),
                false => format!("{available} of {} available", list.items.len()),
            },
        ),
        Some(context(request)),
        row("Namespace", velero_namespace(request)),
        row("Default", default),
    ];
    let mut sections = vec![table("Summary", rows.into_iter().flatten().collect())];
    for item in &list.items {
        let (spec, status) = (&item.spec, &item.status);
        let rows = [
            row("Phase", phase(status)),
            row("Provider", spec.provider.0.clone()),
            row("Bucket", spec.object_storage.bucket.0.clone()),
            row("Prefix", spec.object_storage.prefix.0.clone()),
            row("Access mode", spec.access_mode.0.clone()),
            row("Default", if spec.default { "yes" } else { "" }),
            row("Validation every", spec.validation_frequency.0.clone()),
            row("Last validated", status.last_validation_time.0.clone()),
            row("Last synced", status.last_synced_time.0.clone()),
            row("Message", status.message.0.clone()),
        ];
        sections.push(Section {
            title: item.metadata.name.0.clone(),
            body: Body::Table {
                columns: ["Field", "Value"],
                rows: rows.into_iter().flatten().collect(),
            },
        });
    }
    Report {
        schema_version: 1,
        title: "Backup storage locations",
        sections,
    }
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

    /// Render a fixture request the way `execute` does, from bytes, so the
    /// borrowed lifetimes are the ones the adapter really uses.
    fn report(action: Action, request: &[u8], source: &[u8]) -> Result<Value, String> {
        let request: Request = serde_json::from_slice(request).unwrap();
        Ok(serde_json::to_value(render(action, &request, source)?).unwrap())
    }

    // ------------------------------------------------------------- fixtures --

    #[test]
    fn the_backup_fixture_matches_its_report() {
        let request = read("request.json");
        assert_eq!(
            report(Action::Inspect, &request, &[]).unwrap(),
            expected("report.json")
        );
    }

    #[test]
    fn the_restore_fixture_reports_progress_validation_and_failure() {
        let request = read("restore.json");
        let report = report(Action::Inspect, &request, &[]).unwrap();
        assert_eq!(report["title"], "Velero restore");
        assert!(
            report["sections"][0]["rows"]
                .as_array()
                .unwrap()
                .contains(&json!(["Progress", "118 of 214 items"]))
        );
        let titles: Vec<&str> = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|section| section["title"].as_str().unwrap())
            .collect();
        assert_eq!(
            titles,
            [
                "Summary",
                "Included namespaces",
                "Validation errors",
                "Failure"
            ]
        );
    }

    #[test]
    fn the_trigger_fixture_is_a_dry_run_that_matches_its_report() {
        let request = read("trigger-request.json");
        let parsed: Request = serde_json::from_slice(&request).unwrap();
        assert!(dry_run(&parsed));
        assert_eq!(
            report(Action::Trigger, &request, &[]).unwrap(),
            expected("trigger-report.json")
        );
    }

    #[test]
    fn the_locations_fixture_matches_its_report() {
        let request = read("locations-request.json");
        let locations = read("locations.json");
        assert_eq!(
            report(Action::Locations, &request, &locations).unwrap(),
            expected("locations-report.json")
        );
    }

    #[test]
    fn the_locations_request_fixture_replays_the_locations_fixture() {
        let bytes = read("locations-request.json");
        let request: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            request.inputs.get("replay").map(String::as_str),
            Some("plugins/velero/fixtures/locations.json")
        );
    }

    #[test]
    fn a_replayed_object_renders_the_same_report_as_the_request_object() {
        let request = read("request.json");
        let object = serde_json::to_vec(&expected("request.json")["object"]).unwrap();
        assert_eq!(
            report(Action::Inspect, &request, &object).unwrap(),
            expected("report.json")
        );
    }

    // --------------------------------------------------------- zero copying --

    #[test]
    fn strings_are_borrowed_from_the_request_and_copied_only_when_escaped() {
        let bytes = read("restore.json");
        let request: Request = serde_json::from_slice(&bytes).unwrap();
        let object = request.object.as_ref().unwrap();
        assert!(matches!(object.status.phase.0, Cow::Borrowed(_)));
        assert!(matches!(object.spec.backup_name.0, Cow::Borrowed(_)));
        assert!(matches!(
            object.spec.included_namespaces[0].0,
            Cow::Borrowed(_)
        ));
        // Unescaping needs bytes that are not in the request, so only these copy.
        assert!(matches!(object.status.failure_reason.0, Cow::Owned(_)));
        assert!(matches!(
            object.status.validation_errors[0].0,
            Cow::Owned(_)
        ));
    }

    /// Kubernetes writes `null` rather than omitting a field it has cleared.
    #[test]
    fn a_null_string_reads_as_empty_rather_than_failing() {
        let bytes = br#"{"kind": null, "status": {"phase": null, "failureReason": null}}"#;
        let resource: Resource = serde_json::from_slice(bytes).unwrap();
        assert_eq!(resource.kind.0, "");
        assert_eq!(resource.status.phase.0, "");
        assert_eq!(resource.status.failure_reason.0, "");
        // Anything that is not a string is still a mistake worth reporting.
        let error = serde_json::from_slice::<Resource>(br#"{"kind": 5}"#)
            .map(|_| ())
            .unwrap_err();
        assert!(
            error.to_string().contains("expected a string or null"),
            "{error}"
        );
    }

    #[test]
    fn a_request_of_another_schema_is_refused_before_anything_runs() {
        let bytes = read("request.json");
        assert!(parse(&bytes).is_ok());
        let mut request = expected("request.json");
        request["schema_version"] = json!(2);
        let bytes = serde_json::to_vec(&request).unwrap();
        let refused = |bytes: &[u8]| parse(bytes).map(|_| ()).unwrap_err();
        assert_eq!(refused(&bytes), "unsupported request schema_version");
        assert!(refused(b"{").contains("invalid request"));
    }

    /// A backup that ran clean: Velero leaves `errors`, `warnings` and
    /// `progress` out of the status entirely rather than writing zeros, which
    /// is the shape a real v1.18 cluster returns.
    #[test]
    fn a_status_without_counts_reports_zero_and_omits_progress() {
        let mut request = expected("request.json");
        request["object"]["status"] = json!({
            "phase": "Completed",
            "startTimestamp": "2026-09-14T02:00:01Z",
            "completionTimestamp": "2026-09-14T02:00:02Z",
        });
        let bytes = serde_json::to_vec(&request).unwrap();
        let report = report(Action::Inspect, &bytes, &[]).unwrap();
        let rows = report["sections"][0]["rows"].as_array().unwrap().clone();
        assert!(rows.contains(&json!(["Errors", "0"])));
        assert!(rows.contains(&json!(["Warnings", "0"])));
        assert!(!rows.iter().any(|row| row[0] == "Progress"));
    }

    // ---------------------------------------------------------- the adapter --

    #[test]
    fn the_action_comes_from_the_first_argument_and_defaults_to_inspect() {
        let parse = |args: &[&str]| Action::parse(args.iter().map(|a| a.to_string()));
        assert_eq!(parse(&[]), Ok(Action::Inspect));
        assert_eq!(parse(&["inspect"]), Ok(Action::Inspect));
        assert_eq!(parse(&["trigger"]), Ok(Action::Trigger));
        assert_eq!(parse(&["locations"]), Ok(Action::Locations));
        assert!(parse(&["delete"]).unwrap_err().contains("unknown action"));
        assert!(
            parse(&["trigger", "now"])
                .unwrap_err()
                .contains("unexpected")
        );
    }

    #[test]
    fn a_trigger_never_replays_saved_output() {
        let bytes = read("trigger-request.json");
        let mut request: Request = serde_json::from_slice(&bytes).unwrap();
        request
            .inputs
            .insert("replay".into(), "/does/not/exist".into());
        request.inputs.insert("dry_run".into(), "true".into());
        assert!(fetch(Action::Trigger, &request).unwrap().is_empty());
    }

    #[test]
    fn the_trigger_command_names_the_schedule_the_namespace_and_the_context() {
        let bytes = read("trigger-request.json");
        let request: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            trigger_arguments(&request),
            [
                "backup",
                "create",
                "--from-schedule",
                "daily-apps",
                "--namespace",
                "velero",
                "--kubecontext",
                "development"
            ]
        );
    }

    #[test]
    fn the_locations_command_reads_the_velero_namespace_from_the_input() {
        let bytes = read("locations-request.json");
        let mut request: Request = serde_json::from_slice(&bytes).unwrap();
        request
            .inputs
            .insert("namespace".into(), "backup-system".into());
        assert_eq!(
            locations_arguments(&request),
            [
                "get",
                LOCATIONS,
                "--output",
                "json",
                "--namespace",
                "backup-system",
                "--context",
                "development"
            ]
        );
    }

    // ------------------------------------------------------------- rendering --

    /// The trigger fixture with the dry run turned off, which is the request
    /// sofka sends once the operator confirms.
    fn live_trigger() -> Vec<u8> {
        let mut request = expected("trigger-request.json");
        request["inputs"]["dry_run"] = json!("false");
        serde_json::to_vec(&request).unwrap()
    }

    fn rows_of(report: &Value) -> Vec<Value> {
        report["sections"][0]["rows"].as_array().unwrap().clone()
    }

    /// Sofka sends a null context when it has no explicit kubeconfig context.
    #[test]
    fn a_request_without_a_context_reports_it_as_inferred() {
        let mut request = backup_request();
        request["context"] = Value::Null;
        let bytes = serde_json::to_vec(&request).unwrap();
        let report = report(Action::Inspect, &bytes, &[]).unwrap();
        assert!(rows_of(&report).contains(&json!(["Context", "inferred"])));
    }

    #[test]
    fn a_backup_velero_has_not_started_reports_no_phase_yet() {
        let mut request = backup_request();
        request["object"]["status"] = json!({});
        let bytes = serde_json::to_vec(&request).unwrap();
        let report = report(Action::Inspect, &bytes, &[]).unwrap();
        assert_eq!(rows_of(&report)[0], json!(["Verdict", "no phase yet"]));
    }

    #[test]
    fn a_backup_of_every_namespace_says_so_rather_than_showing_nothing() {
        let mut request = backup_request();
        request["object"]["spec"]["includedNamespaces"] = json!([]);
        request["object"]["spec"]["excludedNamespaces"] = json!([]);
        let bytes = serde_json::to_vec(&request).unwrap();
        let report = report(Action::Inspect, &bytes, &[]).unwrap();
        let sections = report["sections"].as_array().unwrap();
        assert_eq!(sections.len(), 2, "the excluded section is dropped");
        assert_eq!(
            sections[1],
            json!({"title": "Included namespaces", "lines": ["<all>"]})
        );
    }

    #[test]
    fn volume_snapshots_are_reported_only_when_the_spec_decides() {
        let row = |value: Value| {
            let mut request = backup_request();
            request["object"]["spec"]["snapshotVolumes"] = value;
            let bytes = serde_json::to_vec(&request).unwrap();
            let report = report(Action::Inspect, &bytes, &[]).unwrap();
            rows_of(&report)
                .into_iter()
                .find(|row| row[0] == "Volume snapshots")
        };
        assert_eq!(
            row(json!(true)),
            Some(json!(["Volume snapshots", "enabled"]))
        );
        assert_eq!(
            row(json!(false)),
            Some(json!(["Volume snapshots", "disabled"]))
        );
        assert_eq!(row(Value::Null), None);
    }

    #[test]
    fn a_live_trigger_reports_the_velero_output_and_what_comes_next() {
        let bytes = live_trigger();
        let output = b"Backup request \"daily-apps-1\" submitted successfully.\n\n";
        let report = report(Action::Trigger, &bytes, output).unwrap();
        assert_eq!(rows_of(&report)[0], json!(["Verdict", "backup requested"]));
        let titles: Vec<&str> = report["sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|section| section["title"].as_str().unwrap())
            .collect();
        assert_eq!(titles, ["Summary", "Command", "velero output", "Next"]);
        // The blank line velero prints is dropped, not rendered as a row.
        assert_eq!(
            report["sections"][2]["lines"],
            json!(["Backup request \"daily-apps-1\" submitted successfully."])
        );
    }

    #[test]
    fn a_silent_trigger_says_so_rather_than_showing_an_empty_section() {
        let bytes = live_trigger();
        let report = report(Action::Trigger, &bytes, b"  \n").unwrap();
        assert_eq!(report["sections"][2]["lines"], json!(["<no output>"]));
    }

    #[test]
    fn a_paused_schedule_is_reported_as_paused() {
        let mut request = expected("trigger-request.json");
        request["object"]["spec"]["paused"] = json!(true);
        let bytes = serde_json::to_vec(&request).unwrap();
        let report = report(Action::Trigger, &bytes, &[]).unwrap();
        assert!(rows_of(&report).contains(&json!(["Paused", "yes"])));
    }

    #[test]
    fn locations_without_a_default_say_none() {
        let request = read("locations-request.json");
        let list = json!({"items": [{
            "apiVersion": "velero.io/v1", "kind": "BackupStorageLocation",
            "metadata": {"name": "only", "namespace": "velero"},
            "status": {"phase": "Unavailable"},
        }]});
        let source = serde_json::to_vec(&list).unwrap();
        let report = report(Action::Locations, &request, &source).unwrap();
        assert_eq!(rows_of(&report)[0], json!(["Verdict", "0 of 1 available"]));
        assert!(rows_of(&report).contains(&json!(["Default", "none"])));
    }

    // -------------------------------------------------------------- refusal --

    fn refuse(action: Action, request: Value, source: &[u8]) -> String {
        let bytes = serde_json::to_vec(&request).unwrap();
        report(action, &bytes, source).unwrap_err()
    }

    fn backup_request() -> Value {
        expected("request.json")
    }

    #[test]
    fn a_backup_from_another_api_group_is_refused() {
        let mut request = backup_request();
        request["object"]["apiVersion"] = json!("backup.example.com/v1");
        let error = refuse(Action::Inspect, request, &[]);
        assert!(
            error.contains("not a velero.io Backup or Restore"),
            "{error}"
        );
    }

    #[test]
    fn a_schedule_is_not_inspected_as_a_backup() {
        let request = expected("trigger-request.json");
        let error = refuse(Action::Inspect, request, &[]);
        assert!(error.contains("Schedule"), "{error}");
    }

    #[test]
    fn an_object_that_names_another_resource_is_refused() {
        let mut request = backup_request();
        request["object"]["metadata"]["name"] = json!("weekly-apps-20260907020000");
        let error = refuse(Action::Inspect, request, &[]);
        assert!(error.contains("the request names"), "{error}");
    }

    #[test]
    fn a_trigger_without_an_object_is_refused() {
        let mut request = expected("trigger-request.json");
        request["object"] = Value::Null;
        let error = refuse(Action::Trigger, request, &[]);
        assert!(error.contains("no object"), "{error}");
    }

    #[test]
    fn a_selection_without_a_namespace_is_refused() {
        let mut request = backup_request();
        request["namespace"] = json!("");
        let error = refuse(Action::Inspect, request, &[]);
        assert!(error.contains("no namespace"), "{error}");
    }

    #[test]
    fn an_unnamed_selection_is_refused() {
        let mut request = backup_request();
        request["name"] = json!("");
        let error = refuse(Action::Inspect, request, &[]);
        assert_eq!(error, "no Backup or Restore selected");
    }

    #[test]
    fn an_object_from_another_namespace_is_refused() {
        let mut request = backup_request();
        request["object"]["metadata"]["namespace"] = json!("other");
        let error = refuse(Action::Inspect, request, &[]);
        assert!(error.contains("is namespace \"other\""), "{error}");
    }

    #[test]
    fn an_object_with_no_kind_at_all_is_described_rather_than_guessed() {
        let mut request = backup_request();
        request["object"] =
            json!({"metadata": {"name": "daily-apps-20260914020000", "namespace": "velero"}});
        let error = refuse(Action::Inspect, request, &[]);
        assert!(
            error.contains("a <no kind> from <no apiVersion>"),
            "{error}"
        );
    }

    #[test]
    fn a_list_of_something_other_than_locations_is_refused() {
        let request = read("locations-request.json");
        let list = json!({"items": [{"apiVersion": "v1", "kind": "ConfigMap"}]});
        let source = serde_json::to_vec(&list).unwrap();
        let error = report(Action::Locations, &request, &source).unwrap_err();
        assert!(error.contains("not a backupstoragelocations"), "{error}");
    }

    #[test]
    fn an_empty_list_of_locations_reports_that_there_are_none() {
        let request = read("locations-request.json");
        let source = br#"{"items": []}"#;
        let report = report(Action::Locations, &request, source).unwrap();
        assert_eq!(
            report["sections"][0]["rows"][0],
            json!(["Verdict", "no backup storage locations"])
        );
    }

    #[test]
    fn invalid_tool_output_is_an_error_rather_than_an_empty_report() {
        let request = read("locations-request.json");
        assert!(report(Action::Locations, &request, b"{").is_err());
        let trigger = read("trigger-request.json");
        assert!(report(Action::Trigger, &trigger, &[0xff]).is_err());
    }

    // ----------------------------------------------------------- the pipes --

    #[test]
    fn a_capture_is_bounded_but_still_drained_to_the_end() {
        let mut reader = std::io::Cursor::new(vec![b'x'; 4096]);
        let captured = bounded_read(&mut reader, 1024).unwrap();
        assert_eq!(captured.bytes.len(), 1024);
        assert!(captured.truncated);
        // Draining matters: a child blocked on a full pipe never exits.
        assert_eq!(reader.position(), 4096);
        let captured = bounded_read(&b"short"[..], 1024).unwrap();
        assert_eq!(captured.bytes, b"short");
        assert!(!captured.truncated);
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
        assert!(captured.truncated);
        let forwarded = String::from_utf8(forwarded).unwrap();
        assert!(forwarded.starts_with("lo"), "{forwarded}");
        assert!(
            forwarded.contains("velero diagnostics truncated"),
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
        let mut broken = Broken;
        let captured = capture(&b"loud"[..], 64, Some(&mut broken)).unwrap();
        assert_eq!(captured.bytes, b"loud");
    }

    #[test]
    fn a_missing_tool_points_at_its_installation() {
        let error = execute_tool("velero-no-such-tool", &[], VELERO_INSTALL).unwrap_err();
        assert!(
            error.contains("failed to start velero-no-such-tool"),
            "{error}"
        );
        assert!(error.contains(VELERO_INSTALL), "{error}");
    }

    /// A fake tool on disk; the adapter never starts a shell itself.
    #[cfg(unix)]
    fn fake_tool(name: &str, script: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("velero-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_tool_reports_its_stderr_and_not_its_partial_stdout() {
        let (dir, tool) = fake_tool(
            "failing",
            "echo '{\"items\":['\necho 'An error occurred: schedules.velero.io not found' >&2\nexit 1",
        );
        let args = vec!["get".to_string()];
        let error = execute_tool(tool.to_str().unwrap(), &args, "").unwrap_err();
        assert!(error.contains("failing get failed"), "{error}");
        assert!(error.contains("schedules.velero.io not found"), "{error}");
        assert!(!error.contains("items"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_silent_failing_tool_falls_back_to_its_stdout() {
        let (dir, tool) = fake_tool("quiet", "echo 'nothing to see'\nexit 2");
        let error = execute_tool(tool.to_str().unwrap(), &[], "").unwrap_err();
        assert!(error.contains("nothing to see"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_tool_that_floods_stderr_still_finishes() {
        let (dir, tool) = fake_tool(
            "noisy",
            "head -c 2097152 /dev/zero | tr '\\0' e >&2\nprintf 'done\\n'",
        );
        let output = execute_tool(tool.to_str().unwrap(), &[], "").unwrap();
        assert_eq!(output, b"done\n");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_tool_that_writes_over_the_limit_is_an_error_not_a_partial_report() {
        let (dir, tool) = fake_tool("flood", "head -c 2097152 /dev/zero | tr '\\0' e");
        let error = execute_tool(tool.to_str().unwrap(), &[], "").unwrap_err();
        assert!(error.contains("more than 1 MiB"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_replay_file_is_bounded_and_a_missing_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("velero-replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let large = dir.join("large.json");
        std::fs::write(&large, vec![b'x'; REPLAY_MAX_BYTES + 1]).unwrap();
        let replay_error = |path: std::path::PathBuf| {
            let mut request = expected("locations-request.json");
            request["inputs"]["replay"] = json!(path.to_string_lossy());
            let bytes = serde_json::to_vec(&request).unwrap();
            let request = parse(&bytes).unwrap();
            fetch(Action::Locations, &request).unwrap_err()
        };
        assert!(replay_error(large).contains("exceeds 1 MiB"));
        assert!(replay_error(dir.join("missing.json")).contains("cannot read saved output"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// An inspection replays a saved object in place of the selected one, and
    /// without a replay it reads nothing at all.
    #[test]
    fn an_inspection_reads_only_what_the_replay_names() {
        let saved = format!("{}/fixtures/locations.json", env!("CARGO_MANIFEST_DIR"));
        let mut request = backup_request();
        request["inputs"]["replay"] = json!(saved);
        let bytes = serde_json::to_vec(&request).unwrap();
        let request = parse(&bytes).unwrap();
        assert_eq!(
            fetch(Action::Inspect, &request).unwrap(),
            read("locations.json")
        );

        let bytes = read("request.json");
        let request = parse(&bytes).unwrap();
        assert!(fetch(Action::Inspect, &request).unwrap().is_empty());
    }
}
