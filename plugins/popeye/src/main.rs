use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use wasmi::{
    Caller, CompilationMode, Config, Engine, Extern, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

const EXECUTABLES: &[&str] = &["popeye", "kubectl-popeye"];
const INSTALL: &str = "https://github.com/derailed/popeye#installation";
const REQUEST_MAX_BYTES: usize = 1024 * 1024;
const SOURCE_MAX_BYTES: usize = 32 * 1024 * 1024;
const STDERR_MAX_BYTES: usize = 64 * 1024;
const MODULE_MAX_BYTES: usize = 8 * 1024 * 1024;
const GUEST_MEMORY_MAX_BYTES: usize = 128 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
enum HostRequest {
    ReadReport { path: String },
    RunPopeye { context: String, namespace: String },
}

struct HostState {
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
        .map_err(|error| error.to_string())?;
    if request.len() > REQUEST_MAX_BYTES {
        return Err("request exceeds 1 MiB".into());
    }
    let module = module_path()?;
    let wasm = read_bounded_file(&module, MODULE_MAX_BYTES)
        .map_err(|error| format!("cannot read Popeye guest {}: {error}", module.display()))?;
    let report = execute_wasm(&wasm, &request)?;
    std::io::stdout()
        .write_all(&report)
        .map_err(|error| error.to_string())
}

fn module_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("SOFKA_POPEYE_WASM") {
        return Ok(path.into());
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot find the Popeye adapter path: {error}"))?;
    Ok(executable.with_file_name("popeye.wasm"))
}

fn execute_wasm(wasm: &[u8], request: &[u8]) -> Result<Vec<u8>, String> {
    let engine = engine()?;
    let module =
        Module::new(&engine, wasm).map_err(|error| format!("invalid Popeye guest: {error}"))?;
    let mut linker = Linker::new(&engine);
    linker
        .func_wrap("sofka_host", "request", host_request)
        .map_err(|error| error.to_string())?;
    linker
        .func_wrap("sofka_host", "read", host_read)
        .map_err(|error| error.to_string())?;
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
            response: None,
            limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|error| format!("cannot start Popeye guest: {error}"))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| "Popeye guest has no memory export".to_string())?;
    let allocate = instance
        .get_typed_func::<u32, u32>(&store, "sofka_alloc")
        .map_err(|error| format!("Popeye guest has no allocator: {error}"))?;
    let deallocate = instance
        .get_typed_func::<(u32, u32), ()>(&store, "sofka_dealloc")
        .map_err(|error| format!("Popeye guest has no deallocator: {error}"))?;
    let guest_execute = instance
        .get_typed_func::<(u32, u32), u64>(&store, "sofka_execute")
        .map_err(|error| format!("Popeye guest has no entry point: {error}"))?;

    let request_length = u32::try_from(request.len()).map_err(|_| "request is too large")?;
    let request_pointer = allocate
        .call(&mut store, request_length)
        .map_err(|error| format!("cannot allocate guest request: {error}"))?;
    if request_pointer == 0 {
        return Err("guest refused the request allocation".into());
    }
    if let Err(error) = memory.write(&mut store, request_pointer as usize, request) {
        let _ = deallocate.call(&mut store, (request_pointer, request_length));
        return Err(format!("cannot write guest request: {error}"));
    }
    let packed = guest_execute.call(&mut store, (request_pointer, request_length));
    let _ = deallocate.call(&mut store, (request_pointer, request_length));
    let packed = packed.map_err(|error| format!("Popeye guest failed: {error}"))?;
    let response_pointer = packed as u32;
    let response_length = (packed >> 32) as u32;
    if response_pointer == 0
        || response_length == 0
        || response_length as usize > REQUEST_MAX_BYTES + 1
    {
        return Err("guest returned an invalid response".into());
    }
    let mut response = vec![0; response_length as usize];
    let read = memory.read(&store, response_pointer as usize, &mut response);
    let _ = deallocate.call(&mut store, (response_pointer, response_length));
    read.map_err(|error| format!("cannot read guest response: {error}"))?;
    match response.split_first() {
        Some((0, report)) => Ok(report.to_vec()),
        Some((_, message)) => Err(String::from_utf8_lossy(message).into_owned()),
        None => Err("guest returned an empty response".into()),
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
        .map_err(|error| wasmi::Error::new(format!("cannot read host request: {error}")))?;
    let response = match dispatch(&request) {
        Ok(bytes) => encoded_response(0, bytes),
        Err(error) => encoded_response(1, error.into_bytes()),
    };
    let length = i32::try_from(response.len())
        .map_err(|_| wasmi::Error::new("host response is too large"))?;
    caller.data_mut().response = Some(response);
    Ok(length)
}

fn host_read(
    mut caller: Caller<'_, HostState>,
    pointer: i32,
    length: i32,
) -> Result<i32, wasmi::Error> {
    let memory = guest_memory(&caller)?;
    let (pointer, length) = guest_range(pointer, length, SOURCE_MAX_BYTES + 1)?;
    let response = caller
        .data_mut()
        .response
        .take()
        .ok_or_else(|| wasmi::Error::new("host response was already read"))?;
    if response.len() != length {
        return Err(wasmi::Error::new("host response length changed"));
    }
    memory
        .write(&mut caller, pointer, &response)
        .map_err(|error| wasmi::Error::new(format!("cannot write host response: {error}")))?;
    Ok(length as i32)
}

fn guest_memory(caller: &Caller<'_, HostState>) -> Result<Memory, wasmi::Error> {
    match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err(wasmi::Error::new("Popeye guest has no memory export")),
    }
}

fn guest_range(pointer: i32, length: i32, maximum: usize) -> Result<(usize, usize), wasmi::Error> {
    let pointer =
        usize::try_from(pointer).map_err(|_| wasmi::Error::new("negative guest pointer"))?;
    let length = usize::try_from(length).map_err(|_| wasmi::Error::new("negative guest length"))?;
    if length == 0 || length > maximum {
        return Err(wasmi::Error::new("invalid guest buffer length"));
    }
    Ok((pointer, length))
}

fn encoded_response(status: u8, mut body: Vec<u8>) -> Vec<u8> {
    if body.len() > SOURCE_MAX_BYTES {
        body.truncate(SOURCE_MAX_BYTES);
    }
    let mut response = Vec::with_capacity(body.len() + 1);
    response.push(status);
    response.extend(body);
    response
}

fn dispatch(request: &[u8]) -> Result<Vec<u8>, String> {
    let request: HostRequest = serde_json::from_slice(request)
        .map_err(|error| format!("invalid host request: {error}"))?;
    match request {
        HostRequest::ReadReport { path } => read_bounded_file(Path::new(&path), SOURCE_MAX_BYTES)
            .map_err(|error| format!("cannot read saved Popeye report {path}: {error}")),
        HostRequest::RunPopeye { context, namespace } => run_popeye(&context, &namespace),
    }
}

fn run_popeye(context: &str, namespace: &str) -> Result<Vec<u8>, String> {
    let executable =
        detect().ok_or_else(|| format!("popeye is not on PATH; install it from {INSTALL}"))?;
    run_popeye_at(&executable, context, namespace)
}

fn run_popeye_at(executable: &Path, context: &str, namespace: &str) -> Result<Vec<u8>, String> {
    let mut command = Command::new(executable);
    configure(&mut command, context, namespace);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture Popeye stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture Popeye stderr".to_string())?;
    let output = std::thread::spawn(move || read_bounded(stdout, SOURCE_MAX_BYTES));
    let errors = std::thread::spawn(move || read_bounded(stderr, STDERR_MAX_BYTES));
    let status = child
        .wait()
        .map_err(|error| format!("failed while waiting for Popeye: {error}"))?;
    let output = output
        .join()
        .map_err(|_| "failed to collect Popeye output".to_string())?
        .map_err(|error| format!("failed to read Popeye output: {error}"))?;
    let errors = errors
        .join()
        .map_err(|_| "failed to collect Popeye errors".to_string())?
        .map_err(|error| format!("failed to read Popeye errors: {error}"))?;
    if output.exceeded {
        return Err("Popeye output exceeds 32 MiB".into());
    }
    if !status.success() {
        let detail = diagnosis(&output.bytes)
            .or_else(|| first_line(&errors.bytes))
            .unwrap_or("no error output");
        return Err(format!("Popeye exited with {status}: {detail}"));
    }
    if let Some(detail) = first_line(&output.bytes)
        && !detail.starts_with(['{', '['])
    {
        return Err(format!("Popeye failed: {detail}"));
    }
    Ok(output.bytes)
}

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

fn detect() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    detect_in_path(&path, std::env::current_exe().ok().as_deref())
}

fn detect_in_path(path: &OsStr, own: Option<&Path>) -> Option<PathBuf> {
    let own = own.and_then(|path| path.canonicalize().ok());
    for directory in std::env::split_paths(path) {
        for name in EXECUTABLES {
            let candidate = directory.join(name);
            if !is_executable(&candidate) || candidate.canonicalize().ok() == own {
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
            .map(|directory| directory.join(&path))
            .unwrap_or(path)
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

struct Captured {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn read_bounded(mut reader: impl Read, limit: usize) -> std::io::Result<Captured> {
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let mut chunk = [0; 16 * 1024];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let keep = read.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk[..keep]);
        exceeded |= keep < read;
    }
    Ok(Captured { bytes, exceeded })
}

fn read_bounded_file(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let capture = read_bounded(File::open(path)?, limit)?;
    if capture.exceeded {
        return Err(std::io::Error::other(format!(
            "file exceeds {} MiB",
            limit / 1024 / 1024
        )));
    }
    Ok(capture.bytes)
}

fn first_line(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
}

fn diagnosis(bytes: &[u8]) -> Option<&str> {
    first_line(bytes).filter(|line| !line.starts_with(['{', '[']))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_request_only_accepts_the_two_bridge_operations() {
        let read: HostRequest =
            serde_json::from_str(r#"{"operation":"read_report","path":"fixtures/scan.json"}"#)
                .unwrap();
        assert!(matches!(read, HostRequest::ReadReport { .. }));
        let run: HostRequest = serde_json::from_str(
            r#"{"operation":"run_popeye","context":"dev","namespace":"apps"}"#,
        )
        .unwrap();
        assert!(matches!(run, HostRequest::RunPopeye { .. }));
        assert!(
            serde_json::from_str::<HostRequest>(
                r#"{"operation":"exec","program":"sh","args":["-c","id"]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn popeye_arguments_are_fixed_and_scoped() {
        let arguments = |context: &str, namespace: &str| {
            let mut command = Command::new("popeye");
            configure(&mut command, context, namespace);
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
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
    fn bounded_reads_drain_but_do_not_retain_extra_bytes() {
        let capture = read_bounded(&b"abcdefgh"[..], 3).unwrap();
        assert_eq!(capture.bytes, b"abc");
        assert!(capture.exceeded);
    }

    #[test]
    fn host_reads_saved_reports_and_propagates_file_errors() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/scan.json");
        let request = serde_json::to_vec(&serde_json::json!({
            "operation": "read_report",
            "path": path,
        }))
        .unwrap();
        let report = dispatch(&request).unwrap();
        assert!(report.starts_with(b"{\n  \"popeye\""));

        let missing = br#"{"operation":"read_report","path":"does/not/exist.json"}"#;
        assert!(
            dispatch(missing)
                .unwrap_err()
                .contains("cannot read saved Popeye report")
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_process_bridge_propagates_popeye_failures() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory =
            std::env::temp_dir().join(format!("sofka-popeye-host-{}", std::process::id()));
        let executable = directory.join("popeye");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            &executable,
            "#!/bin/sh\necho 'Boom! access denied'\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = run_popeye_at(&executable, "dev", "apps").unwrap_err();
        assert!(error.contains("Boom! access denied"), "{error}");
        let _ = std::fs::remove_dir_all(directory);
    }
}
