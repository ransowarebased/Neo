# Neo

Neo is the host-side CLI, TCP control server, and telemetry agent for the [MatrixHV](https://github.com/ransowarebased/MatrixHV) hypervisor. It is a client of the MatrixHV host API, not part of the UEFI core.

Neo targets MatrixHV status protocol 10 (`MATRIXHV_STATUS_PROTOCOL` in `matrixhv_sdk::protocol`). Commands that use the MatrixHV API require a running MatrixHV core.

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
neo.exe telemetry enable
neo.exe telemetry disable
neo.exe --help
```

The ROAD server listens on `127.0.0.1:4040` by default. Use `serve --listen ADDRESS:PORT` to bind a specific interface. ROAD connections are plaintext and unauthenticated.

AMD64 stack walking supports unwind metadata versions 1 and 2. Version 2 epilogs can be unwound from captured metadata and stack bytes.

## Tests

```sh
cargo test --features cli
```
