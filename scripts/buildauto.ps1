#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [switch]$SkipPackage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$BuildRoot = Join-Path $ProjectRoot 'builds'
$ManifestPath = Join-Path $ProjectRoot 'Cargo.toml'
$HostCargoTargetRoot = Join-Path $BuildRoot '.cargo-target-host'
$ConfigurationName = $Configuration.ToLowerInvariant()
$CargoProfile = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
$OutputRoot = Join-Path $BuildRoot $ConfigurationName
$WindowsTargetTriple = 'x86_64-pc-windows-msvc'
$LinuxTargetTriple = 'x86_64-unknown-linux-musl'

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Cargo manifest not found: $ManifestPath"
}

$CargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $CargoCommand) {
    throw 'cargo was not found in PATH.'
}
$RustcCommand = Get-Command rustc -ErrorAction SilentlyContinue
if ($null -eq $RustcCommand) {
    throw 'rustc was not found in PATH.'
}

New-Item -ItemType Directory -Path $HostCargoTargetRoot -Force | Out-Null
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$WindowsArguments = @(
    'build',
    '--manifest-path', $ManifestPath,
    '--features', 'cli',
    '--target', $WindowsTargetTriple,
    '--target-dir', $HostCargoTargetRoot,
    '--bin', 'neo'
)
$LinuxArguments = @(
    'build',
    '--manifest-path', $ManifestPath,
    '--features', 'cli',
    '--target', $LinuxTargetTriple,
    '--target-dir', $HostCargoTargetRoot,
    '--bin', 'neo'
)
if ($Configuration -eq 'Release') {
    $WindowsArguments += '--release'
    $LinuxArguments += '--release'
}

Write-Host "Building Neo Windows agent ($Configuration)..."
& $CargoCommand.Source @WindowsArguments
if ($LASTEXITCODE -ne 0) {
    throw "Neo Windows build failed with exit code $LASTEXITCODE."
}

Write-Host "Building Neo Linux agent ($Configuration)..."
$LinuxLinkerVariable = 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER'
$PreviousLinuxLinker = [System.Environment]::GetEnvironmentVariable($LinuxLinkerVariable, 'Process')
if ([string]::IsNullOrWhiteSpace($PreviousLinuxLinker)) {
    $RustTargetLib = (& $RustcCommand.Source --print target-libdir).Trim()
    $RustLld = Join-Path (Split-Path -Parent $RustTargetLib) 'bin\rust-lld.exe'
    if (-not (Test-Path -LiteralPath $RustLld -PathType Leaf)) {
        throw "Rust LLD linker not found: $RustLld"
    }
    [System.Environment]::SetEnvironmentVariable($LinuxLinkerVariable, $RustLld, 'Process')
}
try {
    & $CargoCommand.Source @LinuxArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Neo Linux build failed with exit code $LASTEXITCODE."
    }
}
finally {
    if ([string]::IsNullOrWhiteSpace($PreviousLinuxLinker)) {
        [System.Environment]::SetEnvironmentVariable($LinuxLinkerVariable, $null, 'Process')
    }
}

$BuiltWindowsNeo = Join-Path $HostCargoTargetRoot "$WindowsTargetTriple\$CargoProfile\neo.exe"
$BuiltLinuxNeo = Join-Path $HostCargoTargetRoot "$LinuxTargetTriple\$CargoProfile\neo"
$Artifacts = @(
    @{ Source = $BuiltWindowsNeo; Destination = (Join-Path $OutputRoot 'neo.exe') },
    @{ Source = $BuiltLinuxNeo; Destination = (Join-Path $OutputRoot 'neo') }
)
foreach ($Artifact in $Artifacts) {
    if (-not (Test-Path -LiteralPath $Artifact.Source -PathType Leaf)) {
        throw "Expected Neo binary was not produced: $($Artifact.Source)"
    }
    Copy-Item -LiteralPath $Artifact.Source -Destination $Artifact.Destination -Force
    Write-Host "Staged Neo binary: $($Artifact.Destination)"
}

if (-not $SkipPackage) {
    $PackageScript = Join-Path $PSScriptRoot 'package.ps1'
    & $PackageScript -Configuration $Configuration
}

Write-Output (Join-Path $OutputRoot 'neo.exe')
