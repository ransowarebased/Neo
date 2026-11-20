# Neo

Neo is the host-side CLI, TCP control server, and telemetry agent for the [MatrixHV](https://github.com/ransowarebased/MatrixHV) hypervisor. It is a client of the MatrixHV host API, not part of the UEFI core.

Neo targets MatrixHV status protocol 10 (`MATRIXHV_STATUS_PROTOCOL` in `matrixhv_sdk::protocol`). Commands that use the MatrixHV API require a running MatrixHV core.

Keep both checkouts updated together: Neo uses the SDK's runtime diagnostics, nested-state preflight, and scoped L2 memory status definitions.

## Dependencies

Neo uses the Rust SDK from the sibling MatrixHV checkout.

```toml
matrixhv-sdk = { version = "1.0.0", path = "../MatrixHV/sdk" }
```

The CLI uses `matrixhv_sdk::update` to validate the signed update package against the state ABI reported by the running hypervisor.

## Build

Windows host:

```powershell
cargo build --release --features cli --target x86_64-pc-windows-msvc
```

The executable is written to `target/x86_64-pc-windows-msvc/release/neo.exe` (or `builds/` when using the packaging scripts).

Linux host:

```sh
cargo build --release --features cli --target x86_64-unknown-linux-gnu
```

A musl static build is also supported when that target and linker are installed:

```powershell
.\scripts\build_release.ps1
```

That script builds both the Windows MSVC and Linux musl binaries and stages them under `builds/`.

## Usage

```powershell
neo.exe matrix status
neo.exe matrix status --json
neo.exe status --json
neo.exe telemetry
neo.exe telemetry enable
neo.exe telemetry disable
neo.exe --help
```

The ROAD server listens on `127.0.0.1:4040` by default. Use `serve --listen ADDRESS:PORT` to bind a specific interface. ROAD connections are plaintext and unauthenticated.

### Runtime status and nested guests

`status` distinguishes L0 diagnostic presence, advertised capabilities, and memory transport availability on the current CPU and caller level. `nested_mask` and `l2_mask` describe resident L0 CPU slots. `remote_memory_commands` indicates command routing support; it does not establish memory transport availability.

When the resident core confirms L2 memory transport, operations are limited to `INFO`, `READ`, and `WRITE` in the current EPT12 address space. Kernel-root status reports whether scoped observations are available and a root is ready; Neo must still validate the kernel image identity. Resident session status describes the L0 interception allocation and does not provide L2 session or profile inventory.

`matrix status --json` returns structured status fields and the original report. On Windows, deactivation and resident updates require verified active CPU diagnostic coverage and are rejected while nested virtualization is active. Status reports identify partial processor coverage and unsupported nested VM-exit probes.

Memory errors distinguish `MEMORY_TRANSPORT_UNAVAILABLE` from `HYPERVISOR_INACTIVE`. `WRITE_COMMITTED_RESPONSE_LOST` means L2 target bytes were written but response delivery failed; inspect the result before retrying.

### Telemetry

With a compatible resident core, general telemetry reports observed L2 WRMSR exit classes and percentages, requested and active nested APIC controls, and EPT revalidation counters. Capability-gated memory diagnostics include a consistency marker for the sampled request state. WRMSR counters cover observed exits, and sequential snapshots can produce approximate interval deltas.

For an interval capture with automatic restoration of the previous telemetry enable state, use `MatrixHV/tests/collect_l2_wrmsr_profile.py` from the sibling checkout.

AMD64 stack walking supports unwind metadata versions 1 and 2. Version 2 epilogs can be unwound from captured metadata and stack bytes.

## Tests

```sh
cargo test --locked --features cli
```

Tests cover structured local and remote CLI responses, unavailable transports, nested runtime status, telemetry formatting, and memory error classification. Hardware runtime checks require a separately booted MatrixHV core.
