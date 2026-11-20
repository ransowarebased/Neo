use self::protocol::{Request, RequestKind, Response, read_request, write_response};
use crate::process::ProcessTree;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:4040";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const MAX_CAPTURED_STREAM_SIZE: usize = 16 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 8;

struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Debug)]
pub enum ServerExit {
    Update,
}

pub fn serve(
    listen_address: &str,
    prepare_update: impl FnMut(&[u8]) -> Result<(), String> + Send + 'static,
    collect_telemetry: impl FnMut(u32, u32) -> Result<String, String> + Send + 'static,
) -> Result<ServerExit, String> {
    let listener = TcpListener::bind(listen_address)
        .map_err(|error| format!("failed to bind {listen_address}: {error}"))?;
    println!("neo listening on {listen_address} (plaintext, unauthenticated)");
    let mut wake_address = listener
        .local_addr()
        .map_err(|error| format!("failed to inspect listener: {error}"))?;
    if wake_address.ip().is_unspecified() {
        wake_address.set_ip(match wake_address.ip() {
            IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
        });
    }
    let prepare_update = Arc::new(Mutex::new(prepare_update));
    let collect_telemetry = Arc::new(Mutex::new(collect_telemetry));
    let connections = Arc::new(AtomicUsize::new(0));
    let update_pending = Arc::new(AtomicBool::new(false));
    let update_completed = Arc::new(AtomicBool::new(false));

    loop {
        if update_completed.load(Ordering::Acquire) {
            return Ok(ServerExit::Update);
        }
        let (mut stream, peer_address) = match listener.accept() {
            Ok(connection) => connection,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(format!("failed to accept a connection: {error}")),
        };
        if update_completed.load(Ordering::Acquire) {
            return Ok(ServerExit::Update);
        }
        if connections.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            eprintln!("connection from {peer_address} rejected: connection limit reached");
            continue;
        }
        if let Err(error) = configure_stream(&stream) {
            eprintln!("connection from {peer_address} rejected: {error}");
            continue;
        }
        connections.fetch_add(1, Ordering::Relaxed);
        let slot = ConnectionSlot(Arc::clone(&connections));
        let prepare_update = Arc::clone(&prepare_update);
        let collect_telemetry = Arc::clone(&collect_telemetry);
        let update_pending = Arc::clone(&update_pending);
        let update_completed = Arc::clone(&update_completed);
        let worker = std::thread::Builder::new()
            .name("road-connection".into())
            .spawn(move || {
                let _slot = slot;
                let mut prepare = |binary: &[u8]| {
                    if update_pending
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        return Err("an update is already pending".to_string());
                    }
                    let result = prepare_update
                        .lock()
                        .map_err(|_| "update callback failed".to_string())
                        .and_then(|mut callback| callback(binary));
                    if result.is_err() {
                        update_pending.store(false, Ordering::Release);
                    }
                    result
                };
                let mut collect = |mode, control| {
                    collect_telemetry
                        .lock()
                        .map_err(|_| "telemetry callback failed".to_string())
                        .and_then(|mut callback| callback(mode, control))
                };
                match handle_connection(
                    &mut stream,
                    &mut prepare,
                    &mut collect,
                    |stream, timeout| stream.set_write_timeout(Some(timeout)),
                ) {
                    Ok(true) => {
                        update_completed.store(true, Ordering::Release);
                        // Wake blocking accept after the update response has been sent.
                        let _ = TcpStream::connect_timeout(&wake_address, Duration::from_secs(1));
                    }
                    Ok(false) => {}
                    Err(error) => eprintln!("connection from {peer_address} failed: {error}"),
                }
            });
        if let Err(error) = worker {
            eprintln!("connection from {peer_address} rejected: failed to start worker: {error}");
        }
    }
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))
}

pub(crate) fn handle_connection<S: Read + Write>(
    stream: &mut S,
    prepare_update: &mut impl FnMut(&[u8]) -> Result<(), String>,
    collect_telemetry: &mut impl FnMut(u32, u32) -> Result<String, String>,
    set_write_timeout: impl Fn(&S, Duration) -> io::Result<()>,
) -> Result<bool, String> {
    let (request_id, request) = read_request(stream).map_err(|error| error.to_string())?;
    let (response, update) = match request {
        Request::Ping => (Response::success(RequestKind::Ping, "pong"), None),
        Request::Status => (Response::success(RequestKind::Status, status_text()), None),
        Request::Exec {
            arguments,
            timeout_ms,
        } => (execute(arguments, timeout_ms), None),
        Request::ExecStream {
            arguments,
            timeout_ms,
        } => {
            let mut write_failed = false;
            let response = execute_stream(arguments, timeout_ms, |stdout, stderr, remaining| {
                let result = set_write_timeout(stream, remaining).and_then(|()| {
                    write_response(
                        stream,
                        request_id,
                        &Response {
                            stdout,
                            stderr,
                            ..Response::success(RequestKind::ExecStream, "")
                        },
                    )
                    .map_err(io::Error::other)
                });
                write_failed = result.is_err();
                result
            });
            if write_failed {
                // A failed write may have left a partial frame on the connection.
                return Err(response.message);
            }
            set_write_timeout(stream, Duration::from_secs(10))
                .map_err(|error| error.to_string())?;
            (response, None)
        }
        Request::Telemetry { mode, control } => {
            let response = match collect_telemetry(mode, control) {
                Ok(snapshot) => Response::success(RequestKind::Telemetry, snapshot),
                Err(error) => Response::failure(RequestKind::Telemetry, error),
            };
            (response, None)
        }
        Request::Update { binary } => {
            let response =
                match validate_update_binary(&binary).and_then(|()| prepare_update(&binary)) {
                    Ok(()) => Response::success(RequestKind::Update, "update accepted"),
                    Err(error) => Response::failure(RequestKind::Update, error),
                };
            let update = response.success.then_some(());
            (response, update)
        }
    };
    let write_result = write_response(stream, request_id, &response);
    if update.is_some() {
        // A staged update remains committed if its acknowledgement cannot reach the client.
        if let Err(error) = write_result {
            eprintln!("failed to acknowledge staged update: {error}");
        }
        return Ok(true);
    }
    write_result.map_err(|error| error.to_string())?;
    Ok(false)
}

pub fn status_text() -> String {
    let status = hypervisor::query();
    let binary_fingerprint = current_binary_fingerprint()
        .map(|fingerprint| format!("{fingerprint:016x}"))
        .unwrap_or_else(|_| "unavailable".to_string());
    let mut text = format!(
        "agent=neo\nversion={}\nprocess_id={}\nbinary_fingerprint={}\nos={}\narch={}\nhypervisor_present={}\nhypervisor_vendor={}\nmatrixhv_present={}\nmatrixhv_protocol={}\n",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        binary_fingerprint,
        std::env::consts::OS,
        std::env::consts::ARCH,
        status.hypervisor_present,
        status.hypervisor_vendor,
        status.matrixhv_present,
        status.matrixhv_protocol,
    );
    if let Ok(executable) = std::env::current_exe() {
        text.push_str(&format!("executable_path={}\n", executable.display()));
    }
    text.push_str(
        "road_protocol=2\nexec_timeout=true\nexec_stream=true\nremote_memory_commands=true\nremote_memory_commands_scope=command_routing_only\ncapabilities_scope=advertised_features_not_operational_proof\nmemory_transport_scope=current_cpu_caller_level\n",
    );
    let runtime = matrixhv_sdk::runtime::query();
    text.push_str(&format!("diagnostic_transport={}\nnested_state_scope=l0_resident_cpu_slots\nnested_state_available={}\nnested_mask={:#x}\nl2_mask={:#x}\ncaller_level={}\n",
        runtime.present, runtime.diagnostic_available, runtime.nested_mask, runtime.l2_mask,
        if !runtime.diagnostic_available { "unknown" } else if runtime.caller_l2 { "l2" } else { "l1" }));
    text.push_str(&format!("l2_memory_advertised={}\n", runtime.l2_memory_advertised));
    text.push_str(&crate::telemetry::resident_session_status(
        status.matrixhv_present,
        status.matrixhv_protocol,
    ));
    text.push_str(&crate::telemetry::capability_status(
        status.matrixhv_present,
        status.matrixhv_protocol,
    ));
    if status.matrixhv_present {
        use neo::memory::{info_packet, invoke};
        use neo::protocol::memory::{
            AD_ENABLED, CPUID_PROFILE_CAPABILITY, CPUID_UNGATED_CAPABILITY, EVENT_V2_CAPABILITY,
            EVENT_V3_CAPABILITY, OBSERVATION_CAPABILITY, PRIVATE_SHARED_DATA_CAPABILITY,
            SYSCALL_PROFILE_CAPABILITY, word,
        };
        if let Ok(mut packet) = info_packet() {
            if invoke(&mut packet).is_ok() {
                let flags = word(&packet, 72);
                if flags & neo::protocol::memory::L2_MEMORY_CAPABILITY != 0 {
                    text.push_str("memory_address_space=l2_current_ept12\nmemory_operations=info_read_write\n");
                    if flags & neo::protocol::memory::L2_KERNEL_ROOT_CAPABILITY != 0 {
                        text.push_str(&format!("memory_kernel_root_discovery=scoped_l2_observations\nmemory_kernel_root_ready={}\nmemory_kernel_root_validation=executable_lstar_then_client_kernel_identity\n",
                            neo::protocol::memory::quad(&packet, 64) != 0));
                    } else {
                        text.push_str("memory_kernel_root_discovery=explicit_root_required\n");
                    }
                }
                text.push_str(&format!(
                    "memory_transport=true\nmemory_capabilities=0x{flags:x}\n"
                ));
                for (name, flag) in [
                    ("memory_ad_tracking", AD_ENABLED),
                    ("memory_cpuid_profile", CPUID_PROFILE_CAPABILITY),
                    ("memory_private_shared_data", PRIVATE_SHARED_DATA_CAPABILITY),
                    ("memory_syscall_profile", SYSCALL_PROFILE_CAPABILITY),
                    ("memory_cpuid_ungated", CPUID_UNGATED_CAPABILITY),
                    ("memory_event_v2", EVENT_V2_CAPABILITY),
                    ("memory_event_v3", EVENT_V3_CAPABILITY),
                    ("memory_observation", OBSERVATION_CAPABILITY),
                ] {
                    text.push_str(&format!("{name}={}\n", flags & flag != 0));
                }
            } else {
                text.push_str(if runtime.caller_l2 && !runtime.l2_memory_advertised {
                    "memory_transport=false\nmemory_transport_reason=l2_unsupported\n"
                } else {
                    "memory_transport=false\nmemory_transport_reason=unavailable_on_current_cpu\n"
                });
            }
        }
    } else {
        text.push_str("memory_transport=false\nmemory_transport_reason=matrixhv_absent\n");
    }
    text
}

fn current_binary_fingerprint() -> Result<u64, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("failed to resolve the neo executable: {error}"))?;
    let mut file = std::fs::File::open(&executable)
        .map_err(|error| format!("failed to open {}: {error}", executable.display()))?;
    let mut fingerprint = 0xcbf2_9ce4_8422_2325u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {}: {error}", executable.display()))?;
        if count == 0 {
            return Ok(fingerprint);
        }
        for byte in &buffer[..count] {
            fingerprint ^= u64::from(*byte);
            fingerprint = fingerprint.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

pub fn ping_text() -> String {
    "pong".to_string()
}

pub(crate) fn execute(arguments: Vec<String>, timeout_ms: u64) -> Response {
    if !(1..=3_600_000).contains(&timeout_ms) {
        return Response::failure(
            RequestKind::Exec,
            "invalid execution timeout; expected 1..=3600000 ms",
        );
    }
    let Some((program, program_arguments)) = arguments.split_first() else {
        return Response::failure(RequestKind::Exec, "no executable was provided");
    };
    let output = (|| -> io::Result<_> {
        let mut command = Command::new(program);
        command
            .args(program_arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (mut child, tree) = ProcessTree::spawn(&mut command)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        std::thread::scope(|scope| {
            let stdout = scope.spawn(move || capture_stream(&mut stdout));
            let stderr = scope.spawn(move || capture_stream(&mut stderr));
            let mut status = None;
            let wait = (|| -> io::Result<bool> {
                loop {
                    if status.is_none() {
                        status = child.try_wait()?;
                    }
                    if status.is_some() && stdout.is_finished() && stderr.is_finished() {
                        return Ok(false);
                    }
                    // Descendants may retain inherited pipes after the direct child exits.
                    if Instant::now() >= deadline {
                        return Ok(true);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            })();
            let terminated = tree.terminate();
            drop(tree);
            if status.is_none() {
                let _ = child.kill();
                status = Some(child.wait()?);
            }
            let stdout = stdout
                .join()
                .map_err(|_| io::Error::other("stdout capture thread panicked"))?;
            let stderr = stderr
                .join()
                .map_err(|_| io::Error::other("stderr capture thread panicked"))?;
            terminated?;
            Ok((status.unwrap(), stdout?, stderr?, wait?))
        })
    })();
    match output {
        Ok((status, stdout, stderr, timed_out)) => {
            let success = !timed_out && status.success();
            Response {
                request_kind: RequestKind::Exec,
                success,
                exit_code: if timed_out { Some(124) } else { status.code() },
                message: if timed_out {
                    format!("process timed out after {timeout_ms} ms")
                } else if success {
                    "process completed".into()
                } else {
                    "process failed".into()
                },
                stdout,
                stderr,
            }
        }
        Err(error) => Response::failure(
            RequestKind::Exec,
            format!("failed to start or supervise {program}: {error}"),
        ),
    }
}

type StreamChunk = (Vec<u8>, Vec<u8>);

fn stream_pipe(
    mut pipe: impl Read,
    stderr: bool,
    sender: std::sync::mpsc::SyncSender<io::Result<StreamChunk>>,
) {
    let mut buffer = [0; 64 * 1024];
    loop {
        let chunk = match pipe.read(&mut buffer) {
            Ok(0) => return,
            Ok(length) if stderr => Ok((Vec::new(), buffer[..length].to_vec())),
            Ok(length) => Ok((buffer[..length].to_vec(), Vec::new())),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = sender.send(Err(error));
                return;
            }
        };
        if sender.send(chunk).is_err() {
            return;
        }
    }
}

fn execute_stream(
    arguments: Vec<String>,
    timeout_ms: u64,
    mut emit: impl FnMut(Vec<u8>, Vec<u8>, Duration) -> io::Result<()>,
) -> Response {
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};

    let kind = RequestKind::ExecStream;
    let output = (|| -> io::Result<Option<std::process::ExitStatus>> {
        let (program, arguments) = arguments.split_first().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "no executable was provided")
        })?;
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (mut child, tree) = ProcessTree::spawn(&mut command)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // A slow receiver applies backpressure to the pipes without growing the server heap.
        let (sender, receiver) = sync_channel(8);
        std::thread::scope(|scope| {
            let stdout_sender = sender.clone();
            scope.spawn(move || stream_pipe(stdout, false, stdout_sender));
            scope.spawn(move || stream_pipe(stderr, true, sender));
            let mut status = None;
            let mut pipes_open = true;
            let result = (|| {
                loop {
                    if status.is_none() {
                        status = child.try_wait()?;
                    }
                    if status.is_some() && !pipes_open {
                        return Ok(status);
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    let interval = remaining.min(Duration::from_millis(10));
                    if pipes_open {
                        match receiver.recv_timeout(interval) {
                            Ok(chunk) => {
                                let (stdout, stderr) = chunk?;
                                let remaining = deadline.saturating_duration_since(Instant::now());
                                if remaining.is_zero() {
                                    return Ok(None);
                                }
                                if let Err(error) = emit(stdout, stderr, remaining) {
                                    if Instant::now() >= deadline {
                                        return Ok(None);
                                    }
                                    return Err(error);
                                }
                            }
                            Err(RecvTimeoutError::Timeout) => {}
                            Err(RecvTimeoutError::Disconnected) => pipes_open = false,
                        }
                    } else {
                        std::thread::sleep(interval);
                    }
                }
            })();
            drop(receiver);
            let terminated = tree.terminate();
            drop(tree);
            if status.is_none() {
                let _ = child.kill();
                child.wait()?;
            }
            terminated?;
            result
        })
    })();
    let (exit_code, message) = match output {
        Ok(Some(status)) if status.success() => (0, String::new()),
        Ok(Some(status)) => (status.code().unwrap_or(1), "process failed".into()),
        Ok(None) => (124, format!("process timed out after {timeout_ms} ms")),
        Err(error) => (1, format!("failed to start or supervise process: {error}")),
    };
    Response {
        exit_code: Some(exit_code),
        success: exit_code == 0,
        message,
        ..Response::success(kind, "")
    }
}

pub(crate) fn capture_stream(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => return Ok(captured),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        // Drain both pipes after reaching the capture limit so the child can finish.
        let retained = count.min(MAX_CAPTURED_STREAM_SIZE - captured.len());
        captured.extend_from_slice(&buffer[..retained]);
    }
}

pub(crate) fn validate_update_binary(binary: &[u8]) -> Result<(), String> {
    if binary.is_empty() {
        return Err("update binary is empty".to_string());
    }
    #[cfg(target_os = "windows")]
    if !valid_pe_update(binary) {
        return Err("update is not a complete Windows x64 PE executable".to_string());
    }
    #[cfg(target_os = "linux")]
    if !valid_elf_update(binary) {
        return Err("update is not a complete Linux x64 ELF executable".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn valid_pe_update(binary: &[u8]) -> bool {
    let parse = || -> Option<bool> {
        let dos_header = binary.get(..64)?;
        if !dos_header.starts_with(b"MZ") {
            return Some(false);
        }
        let pe_offset = u32::from_le_bytes(dos_header[60..64].try_into().ok()?) as usize;
        if pe_offset < 64 {
            return Some(false);
        }
        let pe_header = binary.get(pe_offset..pe_offset.checked_add(24)?)?;
        let section_count = u16::from_le_bytes(pe_header[6..8].try_into().ok()?) as usize;
        let optional_size = u16::from_le_bytes(pe_header[20..22].try_into().ok()?) as usize;
        let characteristics = u16::from_le_bytes(pe_header[22..24].try_into().ok()?);
        if &pe_header[..4] != b"PE\0\0"
            || u16::from_le_bytes(pe_header[4..6].try_into().ok()?) != 0x8664
            || !(1..=96).contains(&section_count)
            || optional_size < 112
            || characteristics & 0x2002 != 2
        {
            return Some(false);
        }
        let optional_offset = pe_offset.checked_add(24)?;
        let section_offset = optional_offset.checked_add(optional_size)?;
        let optional_header = binary.get(optional_offset..section_offset)?;
        if u16::from_le_bytes(optional_header[..2].try_into().ok()?) != 0x20b
            || ![2, 3].contains(&u16::from_le_bytes(
                optional_header[68..70].try_into().ok()?,
            ))
        {
            return Some(false);
        }
        let entry_point = u32::from_le_bytes(optional_header[16..20].try_into().ok()?);
        let image_size = u32::from_le_bytes(optional_header[56..60].try_into().ok()?);
        let header_size = u32::from_le_bytes(optional_header[60..64].try_into().ok()?) as usize;
        let directory_count =
            u32::from_le_bytes(optional_header[108..112].try_into().ok()?) as usize;
        let section_end = section_offset.checked_add(section_count.checked_mul(40)?)?;
        if entry_point == 0
            || entry_point >= image_size
            || header_size < section_end
            || header_size > binary.len()
            || 112usize.checked_add(directory_count.checked_mul(8)?)? > optional_size
        {
            return Some(false);
        }
        let mut executable_entry = false;
        for section in binary.get(section_offset..section_end)?.as_chunks::<40>().0 {
            let virtual_size = u32::from_le_bytes(section[8..12].try_into().ok()?);
            let virtual_start = u32::from_le_bytes(section[12..16].try_into().ok()?);
            let raw_size = u32::from_le_bytes(section[16..20].try_into().ok()?) as usize;
            let raw_start = u32::from_le_bytes(section[20..24].try_into().ok()?) as usize;
            let flags = u32::from_le_bytes(section[36..40].try_into().ok()?);
            if raw_size != 0 && raw_start.checked_add(raw_size)? > binary.len() {
                return Some(false);
            }
            let virtual_end = virtual_start.checked_add(virtual_size.max(raw_size as u32))?;
            if virtual_end > image_size {
                return Some(false);
            }
            executable_entry |= flags & 0x2000_0000 != 0
                && (virtual_start..virtual_end).contains(&entry_point)
                && entry_point - virtual_start < raw_size as u32;
        }
        Some(executable_entry)
    };
    parse().unwrap_or(false)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn valid_elf_update(binary: &[u8]) -> bool {
    let parse = || -> Option<bool> {
        let header = binary.get(..64)?;
        if &header[..7] != b"\x7fELF\x02\x01\x01"
            || ![0, 3].contains(&header[7])
            || ![2, 3].contains(&u16::from_le_bytes(header[16..18].try_into().ok()?))
            || u16::from_le_bytes(header[18..20].try_into().ok()?) != 62
            || u32::from_le_bytes(header[20..24].try_into().ok()?) != 1
            || u16::from_le_bytes(header[52..54].try_into().ok()?) != 64
            || u16::from_le_bytes(header[54..56].try_into().ok()?) != 56
        {
            return Some(false);
        }
        let entry_point = u64::from_le_bytes(header[24..32].try_into().ok()?);
        let table_start =
            usize::try_from(u64::from_le_bytes(header[32..40].try_into().ok()?)).ok()?;
        let count = u16::from_le_bytes(header[56..58].try_into().ok()?) as usize;
        if entry_point == 0 || table_start < 64 || count == 0 || count == 0xffff {
            return Some(false);
        }
        let table_end = table_start.checked_add(count.checked_mul(56)?)?;
        let mut executable_entry = false;
        for segment in binary.get(table_start..table_end)?.as_chunks::<56>().0 {
            if u32::from_le_bytes(segment[..4].try_into().ok()?) != 1 {
                continue;
            }
            let flags = u32::from_le_bytes(segment[4..8].try_into().ok()?);
            let offset = u64::from_le_bytes(segment[8..16].try_into().ok()?);
            let virtual_start = u64::from_le_bytes(segment[16..24].try_into().ok()?);
            let file_size = u64::from_le_bytes(segment[32..40].try_into().ok()?);
            let memory_size = u64::from_le_bytes(segment[40..48].try_into().ok()?);
            if file_size > memory_size || offset.checked_add(file_size)? > binary.len() as u64 {
                return Some(false);
            }
            let virtual_end = virtual_start.checked_add(memory_size)?;
            executable_entry |= flags & 1 != 0
                && (virtual_start..virtual_end).contains(&entry_point)
                && entry_point - virtual_start < file_size;
        }
        Some(executable_entry)
    };
    parse().unwrap_or(false)
}

pub mod protocol {
    use std::io::{self, Read, Write};

    const MAGIC: [u8; 4] = *b"ROAD";
    pub const PROTOCOL_VERSION: u16 = 2;
    pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 290_000;
    pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;
    const MAX_COMMAND_ARGUMENTS: usize = 4096;
    // Allow the UTF-8 expansion and length fields of a Win32 command line.
    const MAX_EXEC_REQUEST_BYTES: usize = if cfg!(windows) {
        256 * 1024
    } else {
        8 * 1024 * 1024
    };
    const FRAME_READ_CHUNK: usize = 8192;
    const RESPONSE_FAILURE: u32 = 1;
    // Only escape the ambiguous value, keeping ordinary ROAD v2 frames compatible.
    const RESPONSE_MIN_EXIT_CODE: u32 = 2;
    const HEADER_SIZE: usize = 20;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u16)]
    pub enum RequestKind {
        Ping = 1,
        Status = 2,
        Exec = 3,
        Update = 4,
        Telemetry = 5,
        ExecStream = 6,
    }

    impl TryFrom<u16> for RequestKind {
        type Error = ProtocolError;

        fn try_from(value: u16) -> Result<Self, Self::Error> {
            match value {
                1 => Ok(Self::Ping),
                2 => Ok(Self::Status),
                3 => Ok(Self::Exec),
                4 => Ok(Self::Update),
                5 => Ok(Self::Telemetry),
                6 => Ok(Self::ExecStream),
                _ => Err(ProtocolError::InvalidKind(value)),
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Request {
        Ping,
        Status,
        Exec {
            arguments: Vec<String>,
            timeout_ms: u64,
        },
        ExecStream {
            arguments: Vec<String>,
            timeout_ms: u64,
        },
        Update {
            binary: Vec<u8>,
        },
        Telemetry {
            mode: u32,
            control: u32,
        },
    }

    impl Request {
        pub fn kind(&self) -> RequestKind {
            match self {
                Self::Ping => RequestKind::Ping,
                Self::Status => RequestKind::Status,
                Self::Exec { .. } => RequestKind::Exec,
                Self::ExecStream { .. } => RequestKind::ExecStream,
                Self::Update { .. } => RequestKind::Update,
                Self::Telemetry { .. } => RequestKind::Telemetry,
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Response {
        pub request_kind: RequestKind,
        pub success: bool,
        pub exit_code: Option<i32>,
        pub message: String,
        pub stdout: Vec<u8>,
        pub stderr: Vec<u8>,
    }

    impl Response {
        pub fn success(request_kind: RequestKind, message: impl Into<String>) -> Self {
            Self {
                request_kind,
                success: true,
                exit_code: None,
                message: message.into(),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        pub fn failure(request_kind: RequestKind, message: impl Into<String>) -> Self {
            Self {
                request_kind,
                success: false,
                exit_code: None,
                message: message.into(),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }
    }

    #[derive(Debug)]
    pub enum ProtocolError {
        Io(io::Error),
        InvalidMagic,
        InvalidVersion(u16),
        InvalidKind(u16),
        InvalidResponseKind(u16),
        FrameTooLarge(usize),
        TruncatedPayload,
        InvalidUtf8,
        InvalidPayload(&'static str),
    }

    impl std::fmt::Display for ProtocolError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(error) => write!(formatter, "I/O error: {error}"),
                Self::InvalidMagic => formatter.write_str("invalid ROAD frame magic"),
                Self::InvalidVersion(version) => {
                    write!(formatter, "unsupported ROAD protocol version {version}")
                }
                Self::InvalidKind(kind) => write!(formatter, "unknown ROAD request kind {kind}"),
                Self::InvalidResponseKind(kind) => {
                    write!(formatter, "invalid ROAD response kind {kind}")
                }
                Self::FrameTooLarge(size) => {
                    write!(formatter, "ROAD frame size {size} exceeds the limit")
                }
                Self::TruncatedPayload => formatter.write_str("truncated ROAD payload"),
                Self::InvalidUtf8 => formatter.write_str("ROAD payload contains invalid UTF-8"),
                Self::InvalidPayload(reason) => write!(formatter, "invalid ROAD payload: {reason}"),
            }
        }
    }

    impl std::error::Error for ProtocolError {}

    impl From<io::Error> for ProtocolError {
        fn from(error: io::Error) -> Self {
            Self::Io(error)
        }
    }

    pub fn write_request(
        writer: &mut impl Write,
        request_id: u64,
        request: &Request,
    ) -> Result<(), ProtocolError> {
        let payload_size = match request {
            Request::Ping | Request::Status => 0,
            Request::Telemetry { .. } => 8,
            Request::Exec {
                arguments,
                timeout_ms,
            }
            | Request::ExecStream {
                arguments,
                timeout_ms,
            } => {
                if !(1..=MAX_COMMAND_ARGUMENTS).contains(&arguments.len()) {
                    return Err(ProtocolError::InvalidPayload(
                        "invalid command argument count",
                    ));
                }
                if !(1..=3_600_000).contains(timeout_ms) {
                    return Err(ProtocolError::InvalidPayload("invalid execution timeout"));
                }
                let fixed = if *timeout_ms == DEFAULT_EXEC_TIMEOUT_MS {
                    4
                } else {
                    12
                };
                encoded_size(fixed, arguments.iter().map(String::len))?
            }
            Request::Update { binary } => encoded_size(0, [binary.len()])?,
        };
        validate_request_size(request.kind(), payload_size)?;
        let mut payload = Vec::with_capacity(payload_size);
        match request {
            Request::Ping | Request::Status => {}
            Request::Telemetry { mode, control } => {
                put_u32(&mut payload, *mode);
                put_u32(&mut payload, *control);
            }
            Request::Exec {
                arguments,
                timeout_ms,
            }
            | Request::ExecStream {
                arguments,
                timeout_ms,
            } => {
                let count = u32::try_from(arguments.len())
                    .map_err(|_| ProtocolError::InvalidPayload("too many command arguments"))?;
                put_u32(&mut payload, count);
                for argument in arguments {
                    put_bytes(&mut payload, argument.as_bytes())?;
                }
                if *timeout_ms != DEFAULT_EXEC_TIMEOUT_MS {
                    payload.extend_from_slice(&timeout_ms.to_le_bytes());
                }
            }
            Request::Update { binary } => put_bytes(&mut payload, binary)?,
        }
        write_frame(writer, request.kind() as u16, request_id, &payload)
    }

    pub fn read_request(reader: &mut impl Read) -> Result<(u64, Request), ProtocolError> {
        let (raw_kind, request_id, payload_size) = read_header(reader)?;
        let kind = RequestKind::try_from(raw_kind)?;
        validate_request_size(kind, payload_size)?;
        if kind == RequestKind::Update {
            let mut length = [0; 4];
            reader.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length != payload_size - 4 {
                return Err(ProtocolError::InvalidPayload(
                    "invalid update payload length",
                ));
            }
            let binary = read_payload(reader, length)?;
            return Ok((request_id, Request::Update { binary }));
        }
        let payload = read_payload(reader, payload_size)?;
        let mut cursor = Cursor::new(&payload);
        let request = match kind {
            RequestKind::Ping => Request::Ping,
            RequestKind::Status => Request::Status,
            RequestKind::Exec | RequestKind::ExecStream => {
                let count = cursor.read_u32()? as usize;
                if !(1..=MAX_COMMAND_ARGUMENTS).contains(&count) {
                    return Err(ProtocolError::InvalidPayload(
                        "invalid command argument count",
                    ));
                }
                let mut arguments = Vec::with_capacity(count);
                for _ in 0..count {
                    let bytes = cursor.read_bytes()?;
                    let argument = String::from_utf8(bytes.to_vec())
                        .map_err(|_| ProtocolError::InvalidUtf8)?;
                    arguments.push(argument);
                }
                // Requests without an explicit deadline retain a bounded default.
                let timeout_ms = if cursor.offset == payload.len() {
                    DEFAULT_EXEC_TIMEOUT_MS
                } else {
                    u64::from_le_bytes(cursor.take(8)?.try_into().unwrap())
                };
                if !(1..=3_600_000).contains(&timeout_ms) {
                    return Err(ProtocolError::InvalidPayload("invalid execution timeout"));
                }
                if kind == RequestKind::ExecStream {
                    Request::ExecStream {
                        arguments,
                        timeout_ms,
                    }
                } else {
                    Request::Exec {
                        arguments,
                        timeout_ms,
                    }
                }
            }
            RequestKind::Update => unreachable!("update payload is read directly"),
            RequestKind::Telemetry => {
                if payload.is_empty() {
                    Request::Telemetry {
                        mode: 0,
                        control: 0,
                    }
                } else {
                    Request::Telemetry {
                        mode: cursor.read_u32()?,
                        control: cursor.read_u32()?,
                    }
                }
            }
        };
        cursor.finish()?;
        Ok((request_id, request))
    }

    pub fn write_response(
        writer: &mut impl Write,
        request_id: u64,
        response: &Response,
    ) -> Result<(), ProtocolError> {
        let payload_size = encoded_size(
            8,
            [
                response.message.len(),
                response.stdout.len(),
                response.stderr.len(),
            ],
        )?;
        let mut payload = Vec::with_capacity(payload_size);
        let mut flags = if response.success {
            0
        } else {
            RESPONSE_FAILURE
        };
        if response.exit_code == Some(i32::MIN) {
            if !matches!(
                response.request_kind,
                RequestKind::Exec | RequestKind::ExecStream
            ) {
                return Err(ProtocolError::InvalidPayload(
                    "unexpected process exit code",
                ));
            }
            flags |= RESPONSE_MIN_EXIT_CODE;
        }
        put_u32(&mut payload, flags);
        put_i32(&mut payload, response.exit_code.unwrap_or(i32::MIN));
        put_bytes(&mut payload, response.message.as_bytes())?;
        put_bytes(&mut payload, &response.stdout)?;
        put_bytes(&mut payload, &response.stderr)?;
        write_frame(
            writer,
            0x8000 | response.request_kind as u16,
            request_id,
            &payload,
        )
    }

    pub fn read_response(reader: &mut impl Read) -> Result<(u64, Response), ProtocolError> {
        let (raw_kind, request_id, payload_size) = read_header(reader)?;
        if raw_kind & 0x8000 == 0 {
            return Err(ProtocolError::InvalidResponseKind(raw_kind));
        }
        let request_kind = RequestKind::try_from(raw_kind & 0x7fff)?;
        if payload_size < 20 {
            return Err(ProtocolError::TruncatedPayload);
        }
        let payload = read_payload(reader, payload_size)?;
        let mut cursor = Cursor::new(&payload);
        let flags = cursor.read_u32()?;
        if flags & !(RESPONSE_FAILURE | RESPONSE_MIN_EXIT_CODE) != 0 {
            return Err(ProtocolError::InvalidPayload("invalid response status"));
        }
        let raw_exit_code = cursor.read_i32()?;
        let has_min_exit_code = flags & RESPONSE_MIN_EXIT_CODE != 0;
        if has_min_exit_code
            && (raw_exit_code != i32::MIN
                || !matches!(request_kind, RequestKind::Exec | RequestKind::ExecStream))
        {
            return Err(ProtocolError::InvalidPayload("inconsistent exit code flag"));
        }
        let message = String::from_utf8(cursor.read_bytes()?.to_vec())
            .map_err(|_| ProtocolError::InvalidUtf8)?;
        let stdout = cursor.read_bytes()?.to_vec();
        let stderr = cursor.read_bytes()?.to_vec();
        cursor.finish()?;
        Ok((
            request_id,
            Response {
                request_kind,
                success: flags & RESPONSE_FAILURE == 0,
                exit_code: (has_min_exit_code || raw_exit_code != i32::MIN)
                    .then_some(raw_exit_code),
                message,
                stdout,
                stderr,
            },
        ))
    }

    fn write_frame(
        writer: &mut impl Write,
        kind: u16,
        request_id: u64,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge(payload.len()));
        }
        let payload_size = u32::try_from(payload.len())
            .map_err(|_| ProtocolError::FrameTooLarge(payload.len()))?;
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&kind.to_le_bytes());
        header[8..12].copy_from_slice(&payload_size.to_le_bytes());
        header[12..20].copy_from_slice(&request_id.to_le_bytes());
        writer.write_all(&header)?;
        writer.write_all(payload)?;
        writer.flush()?;
        Ok(())
    }

    fn read_header(reader: &mut impl Read) -> Result<(u16, u64, usize), ProtocolError> {
        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header)?;
        if header[0..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        let version = u16::from_le_bytes([header[4], header[5]]);
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion(version));
        }
        let kind = u16::from_le_bytes([header[6], header[7]]);
        let payload_size = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        if payload_size > MAX_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge(payload_size));
        }
        let request_id = u64::from_le_bytes(header[12..20].try_into().unwrap());
        Ok((kind, request_id, payload_size))
    }

    fn validate_request_size(kind: RequestKind, size: usize) -> Result<(), ProtocolError> {
        let valid = match kind {
            RequestKind::Ping | RequestKind::Status => size == 0,
            RequestKind::Exec | RequestKind::ExecStream => {
                if size > MAX_EXEC_REQUEST_BYTES {
                    return Err(ProtocolError::FrameTooLarge(size));
                }
                size >= 8
            }
            RequestKind::Update => (4..=MAX_FRAME_SIZE).contains(&size),
            RequestKind::Telemetry => matches!(size, 0 | 8),
        };
        if valid {
            Ok(())
        } else {
            Err(ProtocolError::InvalidPayload(
                "invalid request payload size",
            ))
        }
    }

    fn read_payload(reader: &mut impl Read, size: usize) -> Result<Vec<u8>, ProtocolError> {
        // A header alone never reserves the advertised size. Grow as bytes arrive.
        let mut payload = Vec::new();
        let mut chunk = [0; FRAME_READ_CHUNK];
        while payload.len() < size {
            let length = (size - payload.len()).min(chunk.len());
            reader.read_exact(&mut chunk[..length])?;
            payload.try_reserve(length).map_err(io::Error::other)?;
            payload.extend_from_slice(&chunk[..length]);
        }
        Ok(payload)
    }

    fn put_u32(buffer: &mut Vec<u8>, value: u32) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn encoded_size(
        initial: usize,
        field_sizes: impl IntoIterator<Item = usize>,
    ) -> Result<usize, ProtocolError> {
        field_sizes.into_iter().try_fold(initial, |total, size| {
            let total = total
                .checked_add(4)
                .and_then(|total| total.checked_add(size))
                .ok_or(ProtocolError::FrameTooLarge(usize::MAX))?;
            if total > MAX_FRAME_SIZE {
                Err(ProtocolError::FrameTooLarge(total))
            } else {
                Ok(total)
            }
        })
    }

    fn put_i32(buffer: &mut Vec<u8>, value: i32) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn put_bytes(buffer: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
        let size =
            u32::try_from(value.len()).map_err(|_| ProtocolError::FrameTooLarge(value.len()))?;
        put_u32(buffer, size);
        buffer.extend_from_slice(value);
        Ok(())
    }

    struct Cursor<'a> {
        payload: &'a [u8],
        offset: usize,
    }

    impl<'a> Cursor<'a> {
        fn new(payload: &'a [u8]) -> Self {
            Self { payload, offset: 0 }
        }

        fn read_u32(&mut self) -> Result<u32, ProtocolError> {
            let bytes = self.take(4)?;
            Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
        }

        fn read_i32(&mut self) -> Result<i32, ProtocolError> {
            let bytes = self.take(4)?;
            Ok(i32::from_le_bytes(bytes.try_into().unwrap()))
        }

        fn read_bytes(&mut self) -> Result<&'a [u8], ProtocolError> {
            let size = self.read_u32()? as usize;
            self.take(size)
        }

        fn take(&mut self, size: usize) -> Result<&'a [u8], ProtocolError> {
            let end = self
                .offset
                .checked_add(size)
                .ok_or(ProtocolError::TruncatedPayload)?;
            let bytes = self
                .payload
                .get(self.offset..end)
                .ok_or(ProtocolError::TruncatedPayload)?;
            self.offset = end;
            Ok(bytes)
        }

        fn finish(self) -> Result<(), ProtocolError> {
            if self.offset == self.payload.len() {
                Ok(())
            } else {
                Err(ProtocolError::InvalidPayload("trailing bytes"))
            }
        }
    }
}
pub mod hypervisor {
    use neo::protocol::{
        MATRIXHV_STATUS_LEAF, MATRIXHV_STATUS_SIGNATURE_EAX, MATRIXHV_STATUS_SIGNATURE_EBX,
        MATRIXHV_STATUS_SIGNATURE_ECX,
    };
    #[derive(Debug)]
    pub struct HypervisorStatus {
        pub hypervisor_present: bool,
        pub hypervisor_vendor: String,
        pub matrixhv_present: bool,
        pub matrixhv_protocol: u32,
    }

    const HYPERVISOR_PRESENT_BIT: u32 = 1 << 31;
    const HYPERVISOR_VENDOR_LEAF: u32 = 0x4000_0000;

    pub fn query() -> HypervisorStatus {
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::x86_64::__cpuid_count;

            let feature = __cpuid_count(1, 0);
            let hypervisor_present = feature.ecx & HYPERVISOR_PRESENT_BIT != 0;
            let vendor = if hypervisor_present {
                let result = __cpuid_count(HYPERVISOR_VENDOR_LEAF, 0);
                let mut bytes = Vec::with_capacity(12);
                bytes.extend_from_slice(&result.ebx.to_le_bytes());
                bytes.extend_from_slice(&result.ecx.to_le_bytes());
                bytes.extend_from_slice(&result.edx.to_le_bytes());
                String::from_utf8_lossy(&bytes)
                    .trim_end_matches('\0')
                    .to_string()
            } else {
                "none".to_string()
            };
            let matrixhv = __cpuid_count(MATRIXHV_STATUS_LEAF, 0);
            let matrixhv_present = matrixhv.eax == MATRIXHV_STATUS_SIGNATURE_EAX
                && matrixhv.ebx == MATRIXHV_STATUS_SIGNATURE_EBX
                && matrixhv.ecx == MATRIXHV_STATUS_SIGNATURE_ECX;
            HypervisorStatus {
                hypervisor_present,
                hypervisor_vendor: vendor,
                matrixhv_present,
                matrixhv_protocol: if matrixhv_present { matrixhv.edx } else { 0 },
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        HypervisorStatus {
            hypervisor_present: false,
            hypervisor_vendor: "unsupported-architecture".to_string(),
            matrixhv_present: false,
            matrixhv_protocol: 0,
        }
    }
}
