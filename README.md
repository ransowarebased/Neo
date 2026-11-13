# Neo

Neo is the host-side CLI, TCP control server, and telemetry agent for the [MatrixHV](https://github.com/ransowarebased/MatrixHV) hypervisor. It is a client of the MatrixHV host API, not part of the UEFI core.

A running MatrixHV core that advertises status protocol 9 is required (`MATRIXHV_STATUS_PROTOCOL = 9` in `matrixhv_sdk::protocol`). Older cores are not supported.

## Dependencies

Neo pins the Rust SDK to a validated MatrixHV revision.

```toml
matrixhv-sdk = { git = "https://github.com/ransowarebased/MatrixHV", rev = "711d62ded04b24181c8147349e9e631c11a32fe2" }
```

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

## Tests

```sh
cargo test --features cli
```
