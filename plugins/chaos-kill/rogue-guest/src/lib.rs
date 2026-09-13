//! A deliberately hostile chaos-kill guest. It ignores dry_run, widens the
//! selector, and names pods it was never shown. Nothing here is trusted by the
//! host; this is what the host is supposed to refuse.

#[link(wasm_import_module = "sofka_host")]
unsafe extern "C" {
    #[link_name = "request"]
    fn host_request(pointer: u32, length: u32) -> i32;
    #[link_name = "read"]
    fn host_read(pointer: u32, length: u32) -> i32;
}

fn call(request: &str) -> Result<String, String> {
    let length = unsafe { host_request(request.as_ptr() as u32, request.len() as u32) };
    if length <= 0 {
        return Err("invalid response length".into());
    }
    let mut response = vec![0u8; length as usize];
    let read = unsafe { host_read(response.as_mut_ptr() as u32, length as u32) };
    if read != length {
        return Err("incomplete response".into());
    }
    let (status, body) = response.split_first().unwrap();
    let body = String::from_utf8_lossy(body).into_owned();
    if *status == 0 { Ok(body) } else { Err(body) }
}

fn probe(out: &mut String, label: &str, request: &str) -> Option<String> {
    let result = call(request);
    out.push_str(label);
    match &result {
        Ok(body) => {
            let first = body.lines().next().unwrap_or("").chars().take(70).collect::<String>();
            out.push_str(&format!("\n    ALLOWED: {first}\n"));
        }
        Err(error) => out.push_str(&format!("\n    REFUSED: {error}\n")),
    }
    result.ok()
}

#[unsafe(export_name = "sofka_alloc")]
pub extern "C" fn allocate(length: u32) -> u32 {
    if length == 0 || length as usize > 1024 * 1024 {
        return 0;
    }
    Box::into_raw(vec![0u8; length as usize].into_boxed_slice()) as *mut u8 as u32
}

#[unsafe(export_name = "sofka_dealloc")]
pub unsafe extern "C" fn deallocate(pointer: u32, length: u32) {
    if pointer == 0 || length == 0 {
        return;
    }
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            pointer as *mut u8,
            length as usize,
        )));
    }
}

#[unsafe(export_name = "sofka_execute")]
pub unsafe extern "C" fn execute(_pointer: u32, _length: u32) -> u64 {
    let mut out = String::from("\n");

    probe(&mut out, "1. list every pod in the namespace (selector \"app\")",
          r#"{"operation":"pods","selector":"app"}"#);

    let listing = probe(&mut out, "2. list the workload's own pods (the honest call)",
                        r#"{"operation":"pods","selector":"app=web"}"#);

    probe(&mut out, "3. delete a pod the host never listed",
          r#"{"operation":"delete","pods":["kube-apiserver-docker-desktop"]}"#);

    let names: Vec<String> = listing
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split('\t').next())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();

    let many = format!(
        r#"{{"operation":"delete","pods":[{}]}}"#,
        names.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(",")
    );
    probe(&mut out, &format!("4. delete all {} listed pods at once (count asked for 1)", names.len()), &many);

    if let Some(first) = names.first() {
        let one = format!(r#"{{"operation":"delete","pods":["{first}"]}}"#);
        probe(&mut out, &format!("5. delete one listed pod ({first})"), &one);
        probe(&mut out, "6. delete a second time in the same run", &one);
    }

    let mut response = vec![0u8];
    response.extend(out.into_bytes());
    let response = response.into_boxed_slice();
    let length = response.len() as u32;
    let pointer = Box::into_raw(response) as *mut u8 as u32;
    (u64::from(length) << 32) | u64::from(pointer)
}
