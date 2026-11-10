#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$BuildRoot = Join-Path $ProjectRoot 'builds'
$ConfigurationName = $Configuration.ToLowerInvariant()
$OutputRoot = Join-Path $BuildRoot $ConfigurationName
$WindowsNeoPath = Join-Path $OutputRoot 'neo.exe'
$LinuxNeoPath = Join-Path $OutputRoot 'neo'
$PackageRoot = Join-Path $BuildRoot 'packages'
$StagingRoot = [System.IO.Path]::GetFullPath((Join-Path $BuildRoot ".package\$ConfigurationName"))
$BuildRootPrefix = $BuildRoot.TrimEnd('\') + '\'
if (-not $StagingRoot.StartsWith($BuildRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use package staging outside the build directory: $StagingRoot"
}
$ArchivePath = Join-Path $PackageRoot "Neo-$ConfigurationName.zip"
$HashPath = "$ArchivePath.sha256"

foreach ($BinaryPath in @($WindowsNeoPath, $LinuxNeoPath)) {
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        throw "Staged Neo binary not found: $BinaryPath"
    }
}

if (Test-Path -LiteralPath $StagingRoot) {
    Remove-Item -LiteralPath $StagingRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
New-Item -ItemType Directory -Path $PackageRoot -Force | Out-Null

try {
    Copy-Item -LiteralPath $WindowsNeoPath -Destination (Join-Path $StagingRoot 'neo.exe') -Force
    Copy-Item -LiteralPath $LinuxNeoPath -Destination (Join-Path $StagingRoot 'neo') -Force

    if (Test-Path -LiteralPath $ArchivePath) {
        Remove-Item -LiteralPath $ArchivePath -Force
    }
    if (Test-Path -LiteralPath $HashPath) {
        Remove-Item -LiteralPath $HashPath -Force
    }

    $PackageEntries = Get-ChildItem -LiteralPath $StagingRoot -Force
    Compress-Archive -Path $PackageEntries.FullName -DestinationPath $ArchivePath -CompressionLevel Optimal

    $Hash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  $(Split-Path -Leaf $ArchivePath)" | Set-Content -LiteralPath $HashPath -Encoding ASCII
}
finally {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force
    }
}

Write-Host "Created package: $ArchivePath"
Write-Host "Created SHA-256 file: $HashPath"
Write-Output $ArchivePath
