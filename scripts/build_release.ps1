#requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipPackage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BuildScript = Join-Path $PSScriptRoot 'buildauto.ps1'
& $BuildScript -Configuration Release -SkipPackage:$SkipPackage
