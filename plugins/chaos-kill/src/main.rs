//! Chaos kill host. It runs the decision logic inside WebAssembly and keeps
//! every operating-system capability out here.
//!
//! The guest chooses which pods to kill, but it cannot reach a cluster. It asks
//! this host, and the host decides what is allowed: the context, the namespace,
//! the workload identity and the label selector all come from the sofka request
//! and never from the guest, a delete is refused unless the request itself
//! turned off `dry_run`, and the names in a delete must be pods this host
//! listed a moment earlier. A guest that went wrong can still pick a bad pod
//! from the workload. It cannot pick a pod belonging to anything else.

use std::collections::BTreeSet;
use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use wasmi::{
    Caller, CompilationMode, Config, Engine, Extern, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const RESPONSE_MAX_BYTES: usize = 8 * 1024 * 1024;
const MODULE_MAX_BYTES: usize = 8 * 1024 * 1024;
const GUEST_MEMORY_MAX_BYTES: usize = 128 * 1024 * 1024;
const SLEEP_MAX: Duration = Duration::from_secs(60);
/// The manifest caps `count` at 10. A delete never names more pods than that,
/// whatever the guest asks for.
const KILL_MAX: usize = 10;

const PODS_JSONPATH: &str = r#"jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.uid}{"\t"}{.metadata.creationTimestamp}{"\t"}{.metadata.deletionTimestamp}{"\t"}{.status.phase}{"\t"}{range .metadata.ownerReferences[?(@.controller==true)]}{.kind}{":"}{.uid}{end}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}"#;
const WORKLOAD_JSONPATH: &str = r#"jsonpath={.metadata.uid}{"\t"}{.spec.replicas}{"\t"}{.status.replicas}{"\t"}{.status.readyReplicas}{"\t"}{.status.desiredNumberScheduled}{"\t"}{.status.numberReady}"#;
const REPLICA_SETS_JSONPATH: &str = r#"jsonpath={range .items[*]}{.metadata.uid}{"\t"}{range .metadata.ownerReferences[?(@.controller==true)]}{.kind}{":"}{.uid}{end}{"\n"}{end}"#;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
enum HostRequest {
    Pods { selector: String },
    ReplicaSets { selector: String },
    Workload,
    Delete { pods: Vec<String> },
    ReadFile { path: String },
    Sleep { millis: u64 },
    Now,
}

/// What the host decided before the guest started, read from the sofka request.
struct Scope {
    context: String,
    namespace: String,
    resource: String,
    name: String,
    selector: String,
    dry_run: bool,
    count: usize,
}

struct HostState {
    scope: Scope,
    started: Instant,
    /// Pod names from the most recent listing. A delete may name only these.
    listed: BTreeSet<String>,
    deleted: bool,
    response: Option<Vec<u8>>,
    limits: StoreLimits,
}

fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn execute() -> Result<(), String> {
    let mut request = Vec::new();
    std::io::stdin()
        .take(REQUEST_MAX_BYTES as u64 + 1)
        .read_to_end(&mut request)
        .map_err(|e| e.to_string())?;
    if request.len() > REQUEST_MAX_BYTES {
        return Err("request exceeds 1 MiB".into());
    }
    let scope = scope(&request)?;
    let module = module_path()?;
    let wasm = read_bounded(&module, MODULE_MAX_BYTES)
        .map_err(|e| format!("cannot read the chaos-kill guest {}: {e}", module.display()))?;
    let report = execute_wasm(&wasm, &request, scope)?;
    std::io::stdout()
        .write_all(&report)
        .map_err(|e| e.to_string())
}

fn module_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("SOFKA_CHAOS_KILL_WASM") {
        return Ok(path.into());
    }
    let executable = std::env::current_exe()
        .map_err(|e| format!("cannot find the chaos-kill adapter path: {e}"))?;
    Ok(executable.with_file_name("chaos-kill.wasm"))
}

// ------------------------------------------------------------------- scope --

/// Reads the request the same way the guest does, so the host never has to
/// trust the guest for anything that decides which cluster object is touched.
fn scope(request: &[u8]) -> Result<Scope, String> {
    let request: Value =
        serde_json::from_slice(request).map_err(|e| format!("invalid request: {e}"))?;
    let text = |pointer: &str| {
        request
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let object = request
        .get("object")
        .ok_or_else(|| "select a workload to test".to_string())?;
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(|| "selected object has no name".to_string())?
        .to_string();
    let namespace = match object.pointer("/metadata/namespace").and_then(Value::as_str) {
        Some(namespace) => namespace.to_string(),
        None => text("/namespace"),
    };
    if namespace.is_empty() {
        return Err("a namespace is required; this never runs cluster-wide".into());
    }
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(kind, "Deployment" | "StatefulSet" | "DaemonSet") {
        return Err(format!(
            "{kind} is not supported; select a Deployment, StatefulSet, or DaemonSet"
        ));
    }
    let input = |key: &str| {
        request
            .pointer(&format!("/inputs/{key}"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    // A saved pod list replays a capture. It can never delete, whatever the
    // inputs say, so it is a dry run here too.
    let dry_run = input("dry_run") != "false" || !input("pods").is_empty();
    let count = input("count").parse::<usize>().unwrap_or(1).clamp(1, KILL_MAX);
    Ok(Scope {
        context: text("/context"),
        namespace,
        resource: kind.to_ascii_lowercase(),
        name,
        selector: selector(object)?,
        dry_run,
        count,
    })
}

/// The workload's own selector, as `k=v,k=v`. This repeats the guest's rule on
/// purpose: the host compares its answer with the guest's and refuses a
/// mismatch, so a widened selector cannot reach kubectl.
fn selector(object: &Value) -> Result<String, String> {
    let selector = object
        .pointer("/spec/selector")
        .ok_or_else(|| "workload has no spec.selector".to_string())?;
    if selector
        .get("matchExpressions")
        .and_then(Value::as_array)
        .is_some_and(|e| !e.is_empty())
    {
        return Err(
            "workload selector uses matchExpressions, which cannot be narrowed here; \
             refusing rather than deleting a wider set of pods"
                .into(),
        );
    }
    let labels = selector
        .get("matchLabels")
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

// -------------------------------------------------------------------- wasm --

fn execute_wasm(wasm: &[u8], request: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
    let engine = engine()?;
    let module = Module::new(&engine, wasm)
        .map_err(|e| format!("invalid chaos-kill guest: {e}"))?;
    let mut linker = Linker::new(&engine);
    linker
        .func_wrap("sofka_host", "request", host_request)
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("sofka_host", "read", host_read)
        .map_err(|e| e.to_string())?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(GUEST_MEMORY_MAX_BYTES)
        .instances(1)
        .memories(1)
        .tables(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        &engine,
        HostState {
            scope,
            started: Instant::now(),
            listed: BTreeSet::new(),
            deleted: false,
            response: None,
            limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|e| format!("cannot start the chaos-kill guest: {e}"))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| "chaos-kill guest has no memory export".to_string())?;
    let allocate = instance
        .get_typed_func::<u32, u32>(&store, "sofka_alloc")
        .map_err(|e| format!("chaos-kill guest has no allocator: {e}"))?;
    let deallocate = instance
        .get_typed_func::<(u32, u32), ()>(&store, "sofka_dealloc")
        .map_err(|e| format!("chaos-kill guest has no deallocator: {e}"))?;
    let guest_execute = instance
        .get_typed_func::<(u32, u32), u64>(&store, "sofka_execute")
        .map_err(|e| format!("chaos-kill guest has no entry point: {e}"))?;

    let request_length = u32::try_from(request.len()).map_err(|_| "request is too large")?;
    let request_pointer = allocate
        .call(&mut store, request_length)
        .map_err(|e| format!("cannot allocate the guest request: {e}"))?;
    if request_pointer == 0 {
        return Err("the guest refused the request allocation".into());
    }
    if let Err(error) = memory.write(&mut store, request_pointer as usize, request) {
        let _ = deallocate.call(&mut store, (request_pointer, request_length));
        return Err(format!("cannot write the guest request: {error}"));
    }
    let packed = guest_execute.call(&mut store, (request_pointer, request_length));
    let _ = deallocate.call(&mut store, (request_pointer, request_length));
    let packed = match packed {
        Ok(packed) => packed,
        // A trap after a delete loses the guest's report, and the pods are
        // already gone. Say what happened rather than only that the guest
        // failed: the delete is the part that cannot be repeated.
        Err(error) if store.data().deleted => {
            return Err(format!(
                "chaos-kill guest failed after deleting pods; recovery was not measured: {error}"
            ));
        }
        Err(error) => return Err(format!("chaos-kill guest failed: {error}")),
    };
    let response_pointer = packed as u32;
    let response_length = (packed >> 32) as u32;
    if response_pointer == 0
        || response_length == 0
        || response_length as usize > REQUEST_MAX_BYTES + 1
    {
        return Err("the guest returned an invalid response".into());
    }
    let mut response = vec![0; response_length as usize];
    let read = memory.read(&store, response_pointer as usize, &mut response);
    let _ = deallocate.call(&mut store, (response_pointer, response_length));
    read.map_err(|e| format!("cannot read the guest response: {e}"))?;
    match response.split_first() {
        Some((0, report)) => Ok(report.to_vec()),
        Some((_, message)) => Err(String::from_utf8_lossy(message).into_owned()),
        None => Err("the guest returned an empty response".into()),
    }
}

fn engine() -> Result<Engine, String> {
    let mode = match std::env::var("SOFKA_WASMI_MODE").as_deref() {
        Ok("eager") => CompilationMode::Eager,
        Ok("lazy") | Err(std::env::VarError::NotPresent) => CompilationMode::Lazy,
        Ok("lazy-translation") => CompilationMode::LazyTranslation,
        Ok(value) => return Err(format!("invalid SOFKA_WASMI_MODE {value}")),
        Err(error) => return Err(format!("cannot read SOFKA_WASMI_MODE: {error}")),
    };
    let mut config = Config::default();
    config
        .compilation_mode(mode)
        .ignore_custom_sections(true)
        .allow_start_fn(false)
        .set_min_stack_height(64 * 1024)
        .set_max_cached_stacks(0);
    Ok(Engine::new(&config))
}

fn host_request(
    mut caller: Caller<'_, HostState>,
    pointer: i32,
    length: i32,
) -> Result<i32, wasmi::Error> {
    let memory = guest_memory(&caller)?;
    let (pointer, length) = guest_range(pointer, length, REQUEST_MAX_BYTES)?;
    let mut request = vec![0; length];
    memory
        .read(&caller, pointer, &mut request)
        .map_err(|e| wasmi::Error::new(format!("cannot read the host request: {e}")))?;
    let response = match dispatch(caller.data_mut(), &request) {
        Ok(bytes) => encoded_response(0, bytes),
        Err(error) => encoded_response(1, error.into_bytes()),
    };
    let length = i32::try_from(response.len())
        .map_err(|_| wasmi::Error::new("the host response is too large"))?;
    caller.data_mut().response = Some(response);
    Ok(length)
}

fn host_read(
    mut caller: Caller<'_, HostState>,
    pointer: i32,
    length: i32,
) -> Result<i32, wasmi::Error> {
    let memory = guest_memory(&caller)?;
    let (pointer, length) = guest_range(pointer, length, RESPONSE_MAX_BYTES + 1)?;
    let response = caller
        .data_mut()
        .response
        .take()
        .ok_or_else(|| wasmi::Error::new("the host response was already read"))?;
    if response.len() != length {
        return Err(wasmi::Error::new("the host response length changed"));
    }
    memory
        .write(&mut caller, pointer, &response)
        .map_err(|e| wasmi::Error::new(format!("cannot write the host response: {e}")))?;
    Ok(length as i32)
}

fn guest_memory(caller: &Caller<'_, HostState>) -> Result<Memory, wasmi::Error> {
    match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err(wasmi::Error::new("chaos-kill guest has no memory export")),
    }
}

fn guest_range(pointer: i32, length: i32, maximum: usize) -> Result<(usize, usize), wasmi::Error> {
    let pointer = usize::try_from(pointer)
        .map_err(|_| wasmi::Error::new("negative guest pointer"))?;
    let length =
        usize::try_from(length).map_err(|_| wasmi::Error::new("negative guest length"))?;
    if length == 0 || length > maximum {
        return Err(wasmi::Error::new("invalid guest buffer length"));
    }
    Ok((pointer, length))
}

fn encoded_response(status: u8, mut body: Vec<u8>) -> Vec<u8> {
    if body.len() > RESPONSE_MAX_BYTES {
        body.truncate(RESPONSE_MAX_BYTES);
    }
    let mut response = Vec::with_capacity(body.len() + 1);
    response.push(status);
    response.extend(body);
    response
}

// ------------------------------------------------------------- host actions --

fn dispatch(state: &mut HostState, request: &[u8]) -> Result<Vec<u8>, String> {
    let request: HostRequest =
        serde_json::from_slice(request).map_err(|e| format!("invalid host request: {e}"))?;
    match request {
        HostRequest::Now => Ok(state.started.elapsed().as_millis().to_string().into_bytes()),
        HostRequest::Sleep { millis } => {
            std::thread::sleep(Duration::from_millis(millis).min(SLEEP_MAX));
            Ok(Vec::new())
        }
        HostRequest::ReadFile { path } => read_bounded(std::path::Path::new(&path), RESPONSE_MAX_BYTES)
            .map_err(|e| format!("cannot read saved pod list {path}: {e}")),
        HostRequest::Workload => {
            let scope = &state.scope;
            kubectl(
                scope,
                &["get", &scope.resource, &scope.name, "-o", WORKLOAD_JSONPATH],
            )
            .map(String::into_bytes)
        }
        HostRequest::ReplicaSets { selector } => {
            check_selector(&state.scope, &selector)?;
            kubectl(
                &state.scope,
                &[
                    "get",
                    "replicasets",
                    "-l",
                    &selector,
                    "-o",
                    REPLICA_SETS_JSONPATH,
                ],
            )
            .map(String::into_bytes)
        }
        HostRequest::Pods { selector } => {
            check_selector(&state.scope, &selector)?;
            let output = kubectl(
                &state.scope,
                &["get", "pods", "-l", &selector, "-o", PODS_JSONPATH],
            )?;
            // Remember what this listing contained. A delete may name only
            // pods the host itself has just seen under the workload's own
            // selector.
            state.listed = output
                .lines()
                .filter_map(|line| line.split('\t').next())
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect();
            Ok(output.into_bytes())
        }
        HostRequest::Delete { pods } => delete(state, &pods).map(|()| Vec::new()),
    }
}

fn check_selector(scope: &Scope, selector: &str) -> Result<(), String> {
    if selector == scope.selector {
        return Ok(());
    }
    Err(format!(
        "refusing a selector the workload does not have: {selector:?}"
    ))
}

/// Every reason a delete can be refused, checked here rather than in the guest.
fn delete(state: &mut HostState, pods: &[String]) -> Result<(), String> {
    if state.scope.dry_run {
        return Err("refusing to delete: this run is a dry run".into());
    }
    if state.deleted {
        return Err("refusing a second delete in one run".into());
    }
    if pods.is_empty() {
        return Err("refusing an empty delete".into());
    }
    if pods.len() > state.scope.count {
        return Err(format!(
            "refusing to delete {} pods; the request asked for {}",
            pods.len(),
            state.scope.count
        ));
    }
    if let Some(pod) = pods.iter().find(|pod| !state.listed.contains(*pod)) {
        return Err(format!(
            "refusing to delete {pod}: it is not a pod this host listed for the selected workload"
        ));
    }
    let mut args = vec!["delete", "pod", "--wait=false"];
    args.extend(pods.iter().map(String::as_str));
    state.deleted = true;
    kubectl(&state.scope, &args).map(|_| ())
}

fn kubectl(scope: &Scope, args: &[&str]) -> Result<String, String> {
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
    String::from_utf8(output.stdout).map_err(|e| format!("kubectl returned non-UTF-8 output: {e}"))
}

fn read_bounded(path: &std::path::Path, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::other("file is too large"));
    }
    Ok(bytes)
}
