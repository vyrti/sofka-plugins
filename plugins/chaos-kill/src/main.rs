//! Resiliency test. Deletes pods belonging to the selected workload and waits
//! for the workload to become ready again, reporting how long that took.
//!
//! Deleting a pod is something sofka can already do. What this adds is the
//! measurement afterwards: a workload that never comes back, or takes minutes
//! to, is the finding. Everything destructive is gated behind `dry_run`, which
//! defaults to on.

use std::collections::BTreeMap;
use std::io::{Read, Write as _};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const OUTPUT_MAX_BYTES: usize = 8 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
struct Request {
    schema_version: u32,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
    #[serde(default)]
    object: Option<Value>,
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
    // A captured pod list stands in for the cluster, so what this would pick
    // can be reviewed — and the packaged fixture test runs — without one.
    let saved = request.inputs.get("pods").map_or("", String::as_str);
    let report = if saved.is_empty() {
        run(&request, &Kubectl)?
    } else {
        run(&request, &Saved::open(saved, &request)?)?
    };
    let output = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|e| e.to_string())
}

/// Everything that touches the cluster, behind one trait so the decision logic
/// can be tested without one.
trait Cluster {
    fn pods(&self, scope: &Scope, selector: &str) -> Result<Value, String>;
    fn delete(&self, scope: &Scope, pods: &[String]) -> Result<(), String>;
    fn workload(&self, scope: &Scope) -> Result<Value, String>;
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

struct Kubectl;

impl Kubectl {
    fn run(scope: &Scope, args: &[&str]) -> Result<Vec<u8>, String> {
        let mut command = Command::new("kubectl");
        if !scope.context.is_empty() {
            command.arg("--context").arg(&scope.context);
        }
        if !scope.namespace.is_empty() {
            command.arg("--namespace").arg(&scope.namespace);
        }
        let output = command
            .args(args)
            .output()
            .map_err(|e| format!("failed to run kubectl: {e}"))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            let detail = detail.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            return Err(format!("kubectl {}: {detail}", args.join(" ")));
        }
        if output.stdout.len() > OUTPUT_MAX_BYTES {
            return Err("kubectl returned more than 8 MiB".into());
        }
        Ok(output.stdout)
    }
}

impl Cluster for Kubectl {
    fn pods(&self, scope: &Scope, selector: &str) -> Result<Value, String> {
        let out = Self::run(scope, &["get", "pods", "-l", selector, "-o", "json"])?;
        serde_json::from_slice(&out).map_err(|e| format!("invalid pod list: {e}"))
    }

    fn delete(&self, scope: &Scope, pods: &[String]) -> Result<(), String> {
        let mut args = vec!["delete", "pod", "--wait=false"];
        args.extend(pods.iter().map(String::as_str));
        Self::run(scope, &args).map(|_| ())
    }

    fn workload(&self, scope: &Scope) -> Result<Value, String> {
        let out = Self::run(scope, &["get", &scope.resource, &scope.name, "-o", "json"])?;
        serde_json::from_slice(&out).map_err(|e| format!("invalid workload: {e}"))
    }
}

/// Reads a captured pod list instead of a cluster. It can never delete, so a
/// saved run is a dry run whatever the inputs say.
struct Saved {
    pods: Value,
    workload: Value,
}

impl Saved {
    fn open(path: &str, request: &Request) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read saved pod list {path}: {e}"))?;
        Ok(Self {
            pods: serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid saved pod list {path}: {e}"))?,
            workload: request.object.clone().unwrap_or(Value::Null),
        })
    }
}

impl Cluster for Saved {
    fn pods(&self, _: &Scope, _: &str) -> Result<Value, String> {
        Ok(self.pods.clone())
    }

    fn delete(&self, _: &Scope, _: &[String]) -> Result<(), String> {
        Err("a saved pod list cannot be deleted from; clear the pods input".into())
    }

    fn workload(&self, _: &Scope) -> Result<Value, String> {
        Ok(self.workload.clone())
    }
}

struct Scope {
    context: String,
    namespace: String,
    resource: String,
    name: String,
}

struct Options {
    dry_run: bool,
    count: usize,
    wait: Duration,
}

impl Options {
    fn from(inputs: &BTreeMap<String, String>) -> Result<Self, String> {
        let seconds = |value: &str| -> Option<u64> {
            let value = value.trim();
            let (digits, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
                Some(i) => value.split_at(i),
                None => (value, "s"),
            };
            let n: u64 = digits.parse().ok()?;
            let per = match unit {
                "s" => 1,
                "m" => 60,
                _ => return None,
            };
            n.checked_mul(per).filter(|n| *n > 0)
        };
        Ok(Self {
            // Anything but an explicit "false" leaves the run harmless.
            dry_run: inputs.get("dry_run").is_none_or(|v| v != "false")
                || inputs.get("pods").is_some_and(|p| !p.is_empty()),
            count: inputs
                .get("count")
                .map_or(Ok(1), |v| v.parse::<usize>())
                .map_err(|_| "count must be a whole number".to_string())?
                .max(1),
            wait: Duration::from_secs(
                inputs
                    .get("wait")
                    .map_or(Some(120), |v| seconds(v))
                    .ok_or_else(|| "wait must be a positive time like \"120s\"".to_string())?,
            ),
        })
    }
}

/// A workload's pod selector, as `k=v,k=v`. Only `matchLabels` is supported:
/// `matchExpressions` cannot be expressed as a `-l` argument, and guessing
/// would delete the wrong pods.
fn selector(object: &Value) -> Result<String, String> {
    let labels = object
        .get("spec")
        .and_then(|s| s.get("selector"))
        .and_then(|s| s.get("matchLabels"))
        .and_then(Value::as_object)
        .ok_or_else(|| "workload has no spec.selector.matchLabels".to_string())?;
    if labels.is_empty() {
        return Err("workload selector is empty; refusing to match every pod".into());
    }
    Ok(labels
        .iter()
        .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(","))
}

/// Pods eligible to be killed, oldest first. Only running pods that are not
/// already terminating: deleting a pod that is on its way out proves nothing,
/// and the ordering makes a dry run tell the truth about the real one.
fn victims(pods: &Value, count: usize) -> Vec<String> {
    let mut running: Vec<(&str, &str)> = pods
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|pod| {
            pod.pointer("/status/phase").and_then(Value::as_str) == Some("Running")
                && pod.pointer("/metadata/deletionTimestamp").is_none()
        })
        .filter_map(|pod| {
            Some((
                pod.pointer("/metadata/name")?.as_str()?,
                pod.pointer("/metadata/creationTimestamp")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            ))
        })
        .collect();
    // RFC 3339 timestamps sort lexicographically; name breaks ties so the
    // order is total and a dry run matches the run that follows it.
    running.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(b.0)));
    running
        .into_iter()
        .take(count)
        .map(|(name, _)| name.to_string())
        .collect()
}

/// How many replicas a workload wants, and how many are ready. DaemonSets count
/// their own way, so both spellings are read.
fn readiness(object: &Value) -> (i64, i64) {
    let status = object.get("status");
    let number = |value: Option<&Value>| value.and_then(Value::as_i64).unwrap_or(0);
    let desired = status
        .and_then(|s| s.get("desiredNumberScheduled"))
        .map(|v| number(Some(v)))
        .unwrap_or_else(|| {
            number(
                object
                    .pointer("/spec/replicas")
                    .or_else(|| status.and_then(|s| s.get("replicas"))),
            )
        });
    let ready = status
        .and_then(|s| s.get("numberReady").or_else(|| s.get("readyReplicas")))
        .map(|v| number(Some(v)))
        .unwrap_or(0);
    (desired, ready)
}

struct Outcome {
    killed: Vec<String>,
    recovered: Option<Duration>,
    desired: i64,
    ready: i64,
    polls: usize,
}

fn run(request: &Request, cluster: &dyn Cluster) -> Result<Value, String> {
    if request.schema_version != 1 {
        return Err("unsupported request schema_version".into());
    }
    let object = request
        .object
        .as_ref()
        .ok_or_else(|| "select a workload to test".to_string())?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(|| "selected object has no name".to_string())?
        .to_string();
    let scope = Scope {
        context: request.context.clone().unwrap_or_default(),
        namespace: object
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| request.namespace.clone())
            .unwrap_or_default(),
        resource: kind.to_ascii_lowercase(),
        name: name.clone(),
    };
    if scope.namespace.is_empty() {
        return Err("a namespace is required; this never runs cluster-wide".into());
    }
    let options = Options::from(&request.inputs)?;
    let selector = selector(object)?;

    let pods = cluster.pods(&scope, &selector)?;
    let killed = victims(&pods, options.count);
    if killed.is_empty() {
        return Err(format!(
            "{kind}/{name} has no running pods to kill; nothing to test"
        ));
    }

    if options.dry_run {
        let (desired, ready) = readiness(&cluster.workload(&scope)?);
        return Ok(report(
            &kind,
            &scope,
            &selector,
            &options,
            &Outcome {
                killed,
                recovered: None,
                desired,
                ready,
                polls: 0,
            },
        ));
    }

    cluster.delete(&scope, &killed)?;
    let started = Instant::now();
    let mut polls = 0;
    let (mut desired, mut ready) = (0, 0);
    let mut recovered = None;
    while started.elapsed() < options.wait {
        cluster.sleep(POLL_INTERVAL);
        polls += 1;
        let (d, r) = readiness(&cluster.workload(&scope)?);
        (desired, ready) = (d, r);
        if desired > 0 && ready >= desired {
            recovered = Some(started.elapsed());
            break;
        }
    }
    Ok(report(
        &kind,
        &scope,
        &selector,
        &options,
        &Outcome {
            killed,
            recovered,
            desired,
            ready,
            polls,
        },
    ))
}

fn report(
    kind: &str,
    scope: &Scope,
    selector: &str,
    options: &Options,
    outcome: &Outcome,
) -> Value {
    let verdict = if options.dry_run {
        "dry run — nothing was deleted".to_string()
    } else if let Some(elapsed) = outcome.recovered {
        format!("recovered in {:.1}s", elapsed.as_secs_f64())
    } else {
        format!(
            "DID NOT RECOVER within {}s — {} of {} replicas ready",
            options.wait.as_secs(),
            outcome.ready,
            outcome.desired
        )
    };
    let mut rows = vec![
        json!(["Verdict", verdict]),
        json!(["Workload", format!("{kind}/{}", scope.name)]),
        json!(["Namespace", scope.namespace.clone()]),
        json!(["Selector", selector]),
        json!([
            if options.dry_run {
                "Would kill"
            } else {
                "Killed"
            },
            outcome.killed.len().to_string()
        ]),
        json!(["Desired replicas", outcome.desired.to_string()]),
        json!(["Ready replicas", outcome.ready.to_string()]),
    ];
    if !options.dry_run {
        rows.push(json!([
            "Waited up to",
            format!("{}s", options.wait.as_secs())
        ]));
        rows.push(json!(["Checks", outcome.polls.to_string()]));
    }

    let mut sections = vec![json!({
        "title": "Summary",
        "columns": ["Field", "Value"],
        "rows": rows,
    })];
    sections.push(json!({
        "title": if options.dry_run { "Pods that would be deleted" } else { "Pods deleted" },
        "lines": outcome.killed.iter().map(|p| format!("  {p}")).collect::<Vec<_>>(),
    }));
    if options.dry_run {
        sections.push(json!({
            "title": "Notice",
            "lines": ["Re-run with dry_run=false to delete these pods and measure recovery."],
        }));
    }
    json!({
        "schema_version": 1,
        "title": "Chaos kill",
        "sections": sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const PODS: &str = include_str!("../fixtures/pods.json");

    fn request() -> Request {
        serde_json::from_str(include_str!("../fixtures/request.json")).unwrap()
    }

    /// Records what the adapter asked the cluster to do, and replays a fixed
    /// sequence of readiness states.
    struct Fake {
        pods: Value,
        states: RefCell<Vec<(i64, i64)>>,
        deleted: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(states: Vec<(i64, i64)>) -> Self {
            Self {
                pods: serde_json::from_str(PODS).unwrap(),
                states: RefCell::new(states),
                deleted: RefCell::new(Vec::new()),
            }
        }
    }

    impl Cluster for Fake {
        fn pods(&self, _: &Scope, _: &str) -> Result<Value, String> {
            Ok(self.pods.clone())
        }

        fn delete(&self, _: &Scope, pods: &[String]) -> Result<(), String> {
            self.deleted.borrow_mut().extend_from_slice(pods);
            Ok(())
        }

        fn workload(&self, _: &Scope) -> Result<Value, String> {
            let mut states = self.states.borrow_mut();
            let (desired, ready) = if states.len() > 1 {
                states.remove(0)
            } else {
                *states.first().unwrap_or(&(3, 3))
            };
            Ok(json!({"spec": {"replicas": desired}, "status": {"readyReplicas": ready}}))
        }
    }

    fn rows(report: &Value) -> Vec<(String, String)> {
        report["sections"][0]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r[0].as_str().unwrap().into(), r[1].as_str().unwrap().into()))
            .collect()
    }

    fn value(report: &Value, field: &str) -> String {
        rows(report)
            .into_iter()
            .find(|(k, _)| k == field)
            .unwrap_or_else(|| panic!("no {field} row"))
            .1
    }

    #[test]
    fn a_dry_run_deletes_nothing() {
        let fake = Fake::new(vec![(3, 3)]);
        let report = run(&request(), &fake).unwrap();
        assert!(fake.deleted.borrow().is_empty(), "a dry run deleted pods");
        assert_eq!(value(&report, "Verdict"), "dry run — nothing was deleted");
        assert_eq!(value(&report, "Would kill"), "2");
        assert_eq!(report["sections"][2]["title"], "Notice");
    }

    #[test]
    fn anything_but_an_explicit_false_stays_a_dry_run() {
        for setting in ["true", "", "no", "FALSE", "0"] {
            let mut request = request();
            request.inputs.insert("dry_run".into(), setting.to_string());
            let fake = Fake::new(vec![(3, 3)]);
            run(&request, &fake).unwrap();
            assert!(
                fake.deleted.borrow().is_empty(),
                "dry_run={setting:?} deleted pods"
            );
        }
    }

    #[test]
    fn victims_are_the_oldest_running_pods_only() {
        let pods: Value = serde_json::from_str(PODS).unwrap();
        // Terminating and Pending pods are never chosen: deleting a pod that is
        // already going away proves nothing.
        assert_eq!(
            victims(&pods, 3),
            ["web-oldest", "web-middle", "web-newest"]
        );
        assert_eq!(victims(&pods, 1), ["web-oldest"]);
        assert_eq!(victims(&pods, 99).len(), 3);
        assert!(victims(&json!({"items": []}), 1).is_empty());
    }

    #[test]
    fn a_real_run_deletes_then_measures_recovery() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        // Degraded, still degraded, then whole again.
        let fake = Fake::new(vec![(3, 1), (3, 2), (3, 3)]);
        let report = run(&request, &fake).unwrap();
        assert_eq!(*fake.deleted.borrow(), ["web-oldest", "web-middle"]);
        assert!(value(&report, "Verdict").starts_with("recovered in"));
        assert_eq!(value(&report, "Ready replicas"), "3");
        assert_eq!(value(&report, "Checks"), "3");
        assert_eq!(report["sections"][1]["title"], "Pods deleted");
    }

    #[test]
    fn a_workload_that_never_comes_back_is_the_finding() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.remove("pods");
        // The deadline is wall-clock, so this really waits — briefly.
        request.inputs.insert("wait".into(), "2s".into());
        let fake = Fake::new(vec![(3, 1)]);
        let started = Instant::now();
        let report = run(&request, &fake).unwrap();
        let verdict = value(&report, "Verdict");
        assert!(verdict.contains("DID NOT RECOVER"), "{verdict}");
        assert!(verdict.contains("1 of 3"), "{verdict}");
        // It gave up at the deadline instead of polling forever.
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(value(&report, "Checks").parse::<usize>().unwrap() <= 3);
    }

    #[test]
    fn a_selector_it_cannot_express_is_refused_rather_than_guessed() {
        let mut expressions = request();
        expressions.object.as_mut().unwrap()["spec"]["selector"] =
            json!({"matchExpressions": [{"key": "app"}]});
        assert!(
            run(&expressions, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("matchLabels")
        );

        let mut empty = request();
        empty.object.as_mut().unwrap()["spec"]["selector"]["matchLabels"] = json!({});
        assert!(
            run(&empty, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("refusing to match every pod")
        );
    }

    #[test]
    fn it_never_runs_without_a_namespace_or_a_selection() {
        let mut unselected = request();
        unselected.object = None;
        assert!(
            run(&unselected, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("select a workload")
        );

        let mut unscoped = request();
        unscoped.namespace = None;
        unscoped.object.as_mut().unwrap()["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("namespace");
        assert!(
            run(&unscoped, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("never runs cluster-wide")
        );
    }

    #[test]
    fn a_workload_with_nothing_running_is_not_a_test() {
        let fake = Fake {
            pods: json!({"items": []}),
            ..Fake::new(vec![(3, 3)])
        };
        assert!(
            run(&request(), &fake)
                .unwrap_err()
                .contains("no running pods to kill")
        );
    }

    #[test]
    fn daemonsets_count_their_replicas_their_own_way() {
        assert_eq!(
            readiness(&json!({"status": {"desiredNumberScheduled": 4, "numberReady": 2}})),
            (4, 2)
        );
        assert_eq!(
            readiness(&json!({"spec": {"replicas": 3}, "status": {"readyReplicas": 3}})),
            (3, 3)
        );
        // A workload that reports nothing is not "ready": desired 0 never wins.
        assert_eq!(readiness(&json!({})), (0, 0));
    }

    #[test]
    fn the_selector_is_built_from_every_match_label() {
        let object = json!({"spec": {"selector": {"matchLabels": {"app": "web", "tier": "fe"}}}});
        assert_eq!(selector(&object).unwrap(), "app=web,tier=fe");
    }

    #[test]
    fn inputs_default_to_the_harmless_setting() {
        let options = Options::from(&BTreeMap::new()).unwrap();
        assert!(options.dry_run);
        assert_eq!(options.count, 1);
        assert_eq!(options.wait, Duration::from_secs(120));
        let bad: BTreeMap<String, String> = [("wait".to_string(), "10w".to_string())]
            .into_iter()
            .collect();
        assert!(Options::from(&bad).is_err());
    }

    #[test]
    fn a_saved_pod_list_can_never_delete() {
        let mut request = request();
        request.inputs.insert("dry_run".into(), "false".into());
        request.inputs.insert(
            "pods".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/pods.json").into(),
        );
        // Even with dry_run=false, a saved run stays a dry run.
        let saved = Saved::open(request.inputs.get("pods").unwrap(), &request).unwrap();
        let report = run(&request, &saved).unwrap();
        assert_eq!(value(&report, "Verdict"), "dry run — nothing was deleted");
        assert_eq!(value(&report, "Would kill"), "2");
        // And the delete path itself refuses outright.
        assert!(
            saved
                .delete(
                    &Scope {
                        context: String::new(),
                        namespace: "apps".into(),
                        resource: "deployments".into(),
                        name: "web".into(),
                    },
                    &["web-oldest".to_string()]
                )
                .is_err()
        );
    }

    #[test]
    fn fixture_matches_expected_report() {
        let request = request();
        let expected: Value =
            serde_json::from_str(include_str!("../fixtures/report.json")).unwrap();
        let saved = Saved {
            pods: serde_json::from_str(PODS).unwrap(),
            workload: request.object.clone().unwrap(),
        };
        assert_eq!(run(&request, &saved).unwrap(), expected);
        // CI runs the adapter from the repository root.
        assert_eq!(
            request.inputs.get("pods").map(String::as_str),
            Some("plugins/chaos-kill/fixtures/pods.json")
        );
    }

    #[test]
    fn rejects_unknown_request_schema() {
        let mut request = request();
        request.schema_version = 2;
        assert!(
            run(&request, &Fake::new(vec![(3, 3)]))
                .unwrap_err()
                .contains("unsupported request schema_version")
        );
    }
}
