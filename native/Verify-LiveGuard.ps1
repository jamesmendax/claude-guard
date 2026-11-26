#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only live environment verification and acceptance checklist helper for Claude Guard Native.
.DESCRIPTION
    Inspects the real Windows host without modifying firewall rules, proxy settings, time zone,
    or DNS settings. Optionally saves a masked acceptance report for live-test sign-off
    (VPN disconnect/reconnect, production Claude update, and refresh verification).
#>
[CmdletBinding()]
param(
    [string]$ConsolePath,
    [string]$ReportPath,
    [switch]$CheckExit,
    [switch]$Cli
)

$ErrorActionPreference = 'Stop'

function Resolve-GuardConsole([string]$ExplicitPath) {
    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "Console executable not found at: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }
    $buildDir = Join-Path $PSScriptRoot '.build'
    if (Test-Path -LiteralPath $buildDir -PathType Container) {
        $candidate = Get-ChildItem -LiteralPath $buildDir -Filter 'ClaudeGuardNativeConsole-*-x64.exe' |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    $installedRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Claude Guard Native'
    if (Test-Path -LiteralPath $installedRoot -PathType Container) {
        $installed = Get-ChildItem -LiteralPath $installedRoot -Directory |
            Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'ClaudeGuardNativeConsole.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if ($installed) { return $installed }
    }
    throw 'Could not locate ClaudeGuardNativeConsole.exe. Build first with ./native/Build-NativeGuard.ps1 or pass -ConsolePath.'
}

function Invoke-ConsoleJson([string]$Exe, [string[]]$Arguments) {
    $psi = [Diagnostics.ProcessStartInfo]::new($Exe)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = Split-Path -Parent $Exe
    $psi.Arguments = (@($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' ')
    $proc = [Diagnostics.Process]::Start($psi)
    try {
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        $code = $proc.ExitCode
    } finally {
        $proc.Dispose()
    }
    $parsed = $null
    if ($stdout.Trim().StartsWith('{')) {
        try { $parsed = $stdout | ConvertFrom-Json } catch { $parsed = $null }
    }
    $raw = (@($stdout.Trim(), $stderr.Trim()) | Where-Object { $_ }) -join [Environment]::NewLine
    [pscustomobject]@{
        ExitCode = $code
        Raw = $raw
        Json = $parsed
    }
}

$exe = Resolve-GuardConsole $ConsolePath
$lines = [Collections.Generic.List[string]]::new()
$lines.Add('=== Claude Guard Native Live Verification Report (Read-Only) ===')
$lines.Add('Timestamp (UTC): ' + [DateTime]::UtcNow.ToString('o'))
$lines.Add('Console: ' + $exe)
$lines.Add('OS: ' + [Environment]::OSVersion.VersionString)
$lines.Add('PowerShell: ' + $PSVersionTable.PSVersion.ToString() + ' (' + $PSVersionTable.PSEdition + ')')
$lines.Add('')

# 1. Package checksum check (if portable build folder with SHA256SUMS.txt)
$packageDir = Split-Path -Parent $exe
if (Test-Path -LiteralPath (Join-Path $packageDir 'SHA256SUMS.txt') -PathType Leaf) {
    $verify = Invoke-ConsoleJson $exe @('--verify-package')
    $lines.Add("[1] Package checksums: " + $(if ($verify.ExitCode -eq 0) { 'PASS' } else { "FAIL (exit=$($verify.ExitCode))" }))
    if ($verify.Raw) { $lines.Add('    ' + ($verify.Raw -replace "`r?`n", ' | ')) }
} else {
    $lines.Add('[1] Package checksums: SKIPPED (installed copy without portable SHA256SUMS.txt)')
}

# 2. Desktop / CLI status check
$statusArgs = if ($Cli) { @('--status', '--cli') } else { @('--status') }
$status = Invoke-ConsoleJson $exe $statusArgs
$lines.Add("[2] Guard status ($($statusArgs -join ' ')): " + $(if ($status.ExitCode -eq 0) { 'READY' } else { "NOT READY (exit=$($status.ExitCode))" }))
if ($status.Json) {
    $j = $status.Json
    $lines.Add("    Route:       $($j.Route) (VPN: $($j.VpnName))")
    $lines.Add("    Firewall:    $($j.Firewall) (blocked adapters=$($j.BlockedAdapterCount), targets=$($j.ProtectedTargetCount))")
    $lines.Add("    Claude:      $($j.Claude) (DesktopReady=$($j.DesktopReady), CliReady=$($j.CliReady))")
    $lines.Add("    ProxyIssue:  $($j.ProxyIssue)")
    $lines.Add("    ExitStatus:  $($j.ExitStatus) ($($j.ExitCountry) $($j.ExitColo))")
    $lines.Add("    RefreshTask: $($j.RefreshTaskState)")
    $lines.Add("    Message:     $($j.Message)")
} else {
    $lines.Add('    Raw output: ' + $status.Raw)
}

# 3. Optional read-only exit probe
if ($CheckExit) {
    $exitRes = Invoke-ConsoleJson $exe @('--check-exit')
    $lines.Add("[3] Read-only exit probe (--check-exit): " + $(if ($exitRes.ExitCode -eq 0) { 'PASS' } else { "FAIL (exit=$($exitRes.ExitCode))" }))
    if ($exitRes.Json) {
        $ej = $exitRes.Json
        $lines.Add("    Host: $($ej.Host) | MaskedIp: $($ej.MaskedIp) | Country: $($ej.Country) | Colo: $($ej.Colo) | LatencyMs: $($ej.LatencyMs)")
        $lines.Add("    PolicyAllowed: $($ej.PolicyAllowed) | Message: $($ej.Message)")
    } else {
        $lines.Add('    Raw output: ' + $exitRes.Raw)
    }
} else {
    $lines.Add('[3] Read-only exit probe: SKIPPED (pass -CheckExit to run a live IPv4 TLS probe)')
}

$lines.Add('')
$lines.Add('=== Manual Live Acceptance Checklist (Run in a Disposable VM or Test Host) ===')
$lines.Add('[ ] Live VPN disconnect test: start guarded session, disconnect VPN adapter, confirm event-driven detection stops Claude and no direct packets leave physical NIC.')
$lines.Add('[ ] Live VPN reconnect test: restore VPN adapter, run --status, confirm readiness returns without stale errors.')
$lines.Add('[ ] Production Claude update test: update Claude Desktop / CLI path, confirm scheduled refresh adds new path rules before retiring obsolete ones.')
$lines.Add('[ ] Session time-zone crash recovery test: launch with --time-zone, forcibly end guard process, confirm next launch restores prior Windows time zone.')
$lines.Add('[ ] Proxy/WPAD diagnostic test: toggle Windows "Automatically detect settings" or HTTP_PROXY, confirm Guard reports the exact cause.')

$text = $lines -join [Environment]::NewLine
Write-Output $text

if ($ReportPath) {
    [IO.File]::WriteAllText($ReportPath, $text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Output ""
    Write-Output "Saved report to: $ReportPath"
}
