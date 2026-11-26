#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Compiled Native Guard assemblies target Windows inbox .NET Framework 4.8 (including System.Web.Extensions).
# When invoked from PowerShell 7 (.NET Core), delegate transparently to Windows PowerShell 5.1.
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

$script:Checks = 0

function Assert-Case([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw "FAIL: $Description" }
    $script:Checks++
    Write-Output "PASS: $Description"
}

function Assert-Throws([scriptblock]$Action, [string]$Expected) {
    try { $null = & $Action }
    catch {
        if ($_.Exception.Message -like "*$Expected*") {
            $script:Checks++
            Write-Output "PASS: Rejected invalid input ($Expected)"
            return
        }
        throw
    }
    throw "Expected failure containing '$Expected'."
}

$buildDir = Join-Path $PSScriptRoot '.build'
$consoleExe = Join-Path $buildDir 'ClaudeGuardNativeConsole-2.0.0-x64.exe'
if (-not (Test-Path -LiteralPath $consoleExe -PathType Leaf)) {
    throw "Build Native Guard first with ./native/Build-NativeGuard.ps1 (missing $consoleExe)."
}

# Load compiled Native Guard types directly from the built executable for offline unit tests.
$null = [Reflection.Assembly]::LoadFrom($consoleExe)

# --- 1. ExitProbe.ParseTrace ---
$validTrace = "fl=123f45`nh=claude.ai`nip=203.0.113.42`nts=1700000000.000`ncolo=NRT`nloc=JP`n"
$parsed = [ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $validTrace, 85)
Assert-Case ($parsed.Ok -and $parsed.Ip -ceq '203.0.113.42' -and $parsed.MaskedIp -ceq '203.0.*.*' -and
    $parsed.Country -ceq 'JP' -and $parsed.Colo -ceq 'NRT' -and $parsed.LatencyMs -eq 85) 'ParseTrace extracts canonical IPv4, masked IPv4, country, and colo.'

$unknownLoc = [ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', "ip=198.51.100.7`nloc=XX`ncolo=SJC`n", 40)
Assert-Case ($unknownLoc.Ok -and $unknownLoc.Country -ceq '') 'ParseTrace discards special non-country codes like XX.'

$torLoc = [ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', "ip=198.51.100.7`nloc=T1`n", 40)
Assert-Case ($torLoc.Ok -and $torLoc.Country -ceq '') 'ParseTrace discards Tor pseudo-country code T1.'

$ipv6Trace = [ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', "ip=2001:db8::1`nloc=US`n", 30)
Assert-Case (-not $ipv6Trace.Ok -and -not $ipv6Trace.TransientFailure) 'ParseTrace rejects IPv6 addresses under IPv4-only verification.'

$emptyTrace = [ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', '', 10)
Assert-Case (-not $emptyTrace.Ok -and $emptyTrace.TransientFailure) 'ParseTrace marks empty response as transient failure.'

# --- 2. ExitProbe.ExtractHttp200Body ---
$plainHttp = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`n`r`nip=203.0.113.42`nloc=US`n"
$body1 = [ClaudeGuardNative.ExitProbe]::ExtractHttp200Body($plainHttp)
Assert-Case ($body1 -like '*ip=203.0.113.42*') 'ExtractHttp200Body parses plain HTTP/1.1 200 responses.'

$chunkPayload = "ip=203.0.113.9`nloc=SG`n"
$hexLen = [Convert]::ToString($chunkPayload.Length, 16)
$chunkedHttp = "HTTP/1.1 200 OK`r`nTransfer-Encoding: chunked`r`n`r`n$hexLen`r`n$chunkPayload`r`n0`r`n`r`n"
$body2 = [ClaudeGuardNative.ExitProbe]::ExtractHttp200Body($chunkedHttp)
Assert-Case ($body2 -ceq $chunkPayload) 'ExtractHttp200Body decodes chunked Transfer-Encoding responses.'

Assert-Throws { [ClaudeGuardNative.ExitProbe]::ExtractHttp200Body("HTTP/1.1 403 Forbidden`r`n`r`nblocked") } '403 Forbidden'

# --- 3. ExitProbe.Evaluate ---
$disabledPolicy = [ClaudeGuardNative.ExitPolicy]::CreateDefault()
$evalOff = [ClaudeGuardNative.ExitProbe]::Evaluate([ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $validTrace, 50), $disabledPolicy)
Assert-Case ($evalOff.Ok -and $evalOff.PolicyAllowed) 'Disabled exit policy allows observation without blocking.'

$emptyEnabled = [ClaudeGuardNative.ExitPolicy]::CreateDefault()
$emptyEnabled.Enabled = $true
$evalEmpty = [ClaudeGuardNative.ExitProbe]::Evaluate([ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $validTrace, 50), $emptyEnabled)
Assert-Case (-not $evalEmpty.PolicyAllowed -and $evalEmpty.Message -like '*no allowed country codes or IPv4*') 'Enabled exit policy with empty allowlists fails closed.'

$countryPolicy = [ClaudeGuardNative.ExitPolicy]::CreateDefault()
$countryPolicy.Enabled = $true
$countryPolicy.AllowedCountries = @('US', 'JP')
$evalCountryOk = [ClaudeGuardNative.ExitProbe]::Evaluate([ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $validTrace, 50), $countryPolicy)
Assert-Case ($evalCountryOk.PolicyAllowed) 'Country allowlist permits matching country code (JP).'

$cnTrace = "ip=203.0.113.99`nloc=CN`ncolo=PVG`n"
$evalCountryDeny = [ClaudeGuardNative.ExitProbe]::Evaluate([ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $cnTrace, 50), $countryPolicy)
Assert-Case (-not $evalCountryDeny.PolicyAllowed -and $evalCountryDeny.Message -like '*outside allowed countries*') 'Country allowlist blocks non-allowlisted country.'

$ipPolicy = [ClaudeGuardNative.ExitPolicy]::CreateDefault()
$ipPolicy.Enabled = $true
$ipPolicy.AllowedIpv4s = @('203.0.113.42')
$evalIpOk = [ClaudeGuardNative.ExitProbe]::Evaluate([ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $validTrace, 50), $ipPolicy)
Assert-Case ($evalIpOk.PolicyAllowed) 'IPv4 allowlist permits exact IPv4 match.'

$evalIpDeny = [ClaudeGuardNative.ExitProbe]::Evaluate([ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $cnTrace, 50), $ipPolicy)
Assert-Case (-not $evalIpDeny.PolicyAllowed -and $evalIpDeny.Message -like '*not in the allowlist*') 'IPv4 allowlist blocks non-matching IPv4.'

$bothPolicy = [ClaudeGuardNative.ExitPolicy]::CreateDefault()
$bothPolicy.Enabled = $true
$bothPolicy.AllowedCountries = @('US')
$bothPolicy.AllowedIpv4s = @('203.0.113.42')
$evalBothMismatch = [ClaudeGuardNative.ExitProbe]::Evaluate([ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', $validTrace, 50), $bothPolicy)
Assert-Case (-not $evalBothMismatch.PolicyAllowed) 'Combined country and IPv4 allowlists require both to match.'

# --- 4. ExitPolicyStore validation & atomic persistence ---
Assert-Case ([ClaudeGuardNative.ExitPolicyStore]::MaskIpv4('198.51.100.25') -ceq '198.51.*.*') 'MaskIpv4 preserves only the first two octets.'
Assert-Throws { [ClaudeGuardNative.ExitPolicyStore]::NormalizeCountries([string[]]@('XX')) } 'Invalid ISO'
Assert-Throws { [ClaudeGuardNative.ExitPolicyStore]::NormalizeIpv4s([string[]]@('2001:db8::1')) } 'Invalid canonical IPv4'
Assert-Throws { [ClaudeGuardNative.ExitPolicyStore]::NormalizeHost('bad host/path') } 'Invalid exit probe host'

$tempDir = Join-Path ([IO.Path]::GetTempPath()) ('exit-policy-fixture-' + [guid]::NewGuid().ToString('N'))
$policyFile = Join-Path $tempDir 'exit-policy.json'
try {
    $toSave = [ClaudeGuardNative.ExitPolicy]::CreateDefault()
    $toSave.Enabled = $true
    $toSave.TargetHost = 'CLAUDE.AI'
    $toSave.AllowedCountries = @('jp', 'us', 'JP')
    $toSave.AllowedIpv4s = @('203.0.113.42', '198.51.100.7')
    $toSave.MonitorIntervalSeconds = 5
    $toSave.TransientFailureTolerance = 9
    [ClaudeGuardNative.ExitPolicyStore]::Save($toSave, $policyFile)
    $loaded = [ClaudeGuardNative.ExitPolicyStore]::Load($policyFile)
    Assert-Case (
        $loaded.Enabled -and $loaded.TargetHost -ceq 'claude.ai' -and
        ($loaded.AllowedCountries -join ',') -ceq 'JP,US' -and
        ($loaded.AllowedIpv4s -join ',') -ceq '198.51.100.7,203.0.113.42' -and
        $loaded.MonitorIntervalSeconds -eq 15 -and
        $loaded.TransientFailureTolerance -eq 5
    ) 'ExitPolicyStore normalizes, deduplicates, clamps interval & retry tolerance, and saves atomically.'

    $toSave.MonitorIntervalSeconds = 999
    $toSave.TransientFailureTolerance = 0
    [ClaudeGuardNative.ExitPolicyStore]::Save($toSave, $policyFile)
    $reloaded = [ClaudeGuardNative.ExitPolicyStore]::Load($policyFile)
    Assert-Case ($reloaded.MonitorIntervalSeconds -eq 300 -and $reloaded.TransientFailureTolerance -eq 3 -and [IO.Directory]::GetFiles($tempDir).Length -eq 1) 'ExitPolicyStore defaults zero retry tolerance to 3 and replaces atomically.'
} finally {
    if ([IO.File]::Exists($policyFile)) { [IO.File]::Delete($policyFile) }
    if ([IO.Directory]::Exists($tempDir)) { [IO.Directory]::Delete($tempDir) }
}

# --- 4b. Weak-network jitter tolerance vs zero-tolerance mismatch ---
$retryPolicy = [ClaudeGuardNative.ExitPolicy]::CreateDefault()
$retryPolicy.Enabled = $true
$retryPolicy.AllowedCountries = @('US')
$retryPolicy.TransientFailureTolerance = 3

$attemptList = [Collections.Generic.List[int]]::new()
$jitterProbe = [Func[int, ClaudeGuardNative.ExitProbeResult]]{
    param([int]$attempt)
    $attemptList.Add($attempt)
    if ($attempt -lt 3) {
        $r = [ClaudeGuardNative.ExitProbeResult]::new()
        $r.Ok = $false; $r.TransientFailure = $true; $r.Message = 'Simulated HY2 packet drop'
        return $r
    }
    return [ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', "ip=203.0.113.10`nloc=US`ncolo=SJC`n", 60)
}
$jitterOk = [ClaudeGuardNative.ExitProbe]::CheckWithProbe($retryPolicy, $true, 0, $jitterProbe)
Assert-Case ($jitterOk.Ok -and $jitterOk.PolicyAllowed -and $attemptList.Count -eq 3) 'Transient packet loss recovers on 3rd attempt without falsely killing Claude.'

$allFailCount = 0
$allFailProbe = [Func[int, ClaudeGuardNative.ExitProbeResult]]{
    param([int]$attempt)
    $script:allFailCount = $attempt
    $r = [ClaudeGuardNative.ExitProbeResult]::new()
    $r.Ok = $false; $r.TransientFailure = $true; $r.Message = 'Timeout'
    return $r
}
$jitterFail = [ClaudeGuardNative.ExitProbe]::CheckWithProbe($retryPolicy, $true, 0, $allFailProbe)
Assert-Case (-not $jitterFail.PolicyAllowed -and $script:allFailCount -eq 3 -and $jitterFail.Message -like '*3 attempts*') 'Confirmed transient outage fails closed after exhausting retry tolerance.'

$mismatchCalls = 0
$mismatchProbe = [Func[int, ClaudeGuardNative.ExitProbeResult]]{
    param([int]$attempt)
    $script:mismatchCalls = $attempt
    return [ClaudeGuardNative.ExitProbe]::ParseTrace('claude.ai', "ip=203.0.113.99`nloc=CN`ncolo=PVG`n", 40)
}
$mismatchRes = [ClaudeGuardNative.ExitProbe]::CheckWithProbe($retryPolicy, $true, 0, $mismatchProbe)
Assert-Case (-not $mismatchRes.PolicyAllowed -and $script:mismatchCalls -eq 1) 'Explicit disallowed country fails immediately on attempt 1 with zero retries.'

$tlsCalls = 0
$tlsProbe = [Func[int, ClaudeGuardNative.ExitProbeResult]]{
    param([int]$attempt)
    $script:tlsCalls = $attempt
    $r = [ClaudeGuardNative.ExitProbeResult]::new()
    $r.Ok = $false; $r.TransientFailure = $false; $r.Message = 'TLS verification failed'
    return $r
}
$tlsRes = [ClaudeGuardNative.ExitProbe]::CheckWithProbe($retryPolicy, $true, 0, $tlsProbe)
Assert-Case (-not $tlsRes.PolicyAllowed -and $script:tlsCalls -eq 1) 'Non-transient TLS failure fails immediately on attempt 1 with zero retries.'

# --- 4c. DesktopHygiene scan, MCP-safe quarantine, restore, and shortcut creation ---
$hygieneRoot = Join-Path ([IO.Path]::GetTempPath()) ('desktop-hygiene-fixture-' + [guid]::NewGuid().ToString('N'))
$classicClaude = Join-Path $hygieneRoot 'Roaming\Claude'
$storeClaude = Join-Path $hygieneRoot 'Store\LocalCache\Roaming\Claude'
$qRoot = Join-Path $hygieneRoot 'quarantine'
$shortcutOut = Join-Path $hygieneRoot 'Claude (Native Guard).lnk'
try {
    $null = [IO.Directory]::CreateDirectory((Join-Path $classicClaude 'Cache'))
    $null = [IO.Directory]::CreateDirectory((Join-Path $classicClaude 'logs'))
    $null = [IO.Directory]::CreateDirectory((Join-Path $storeClaude 'Network'))
    [IO.File]::WriteAllText((Join-Path $classicClaude 'Cache\blob.bin'), 'cached-bytes')
    [IO.File]::WriteAllText((Join-Path $classicClaude 'Cookies'), 'cookie-data')
    [IO.File]::WriteAllText((Join-Path $classicClaude 'logs\main.log'), 'log-line')
    [IO.File]::WriteAllText((Join-Path $classicClaude 'claude_desktop_config.json'), '{"mcpServers":{"demo":{}}}')
    [IO.File]::WriteAllText((Join-Path $storeClaude 'Network\Cookies'), 'store-cookie')
    [IO.File]::WriteAllText((Join-Path $storeClaude 'claude_desktop_config.json'), '{"mcpServers":{"store":{}}}')

    $fakeStartup = @([ClaudeGuardNative.DesktopStartupEntry]@{ Source = 'RegistryRun'; Name = 'Claude'; Detail = 'Claude.exe'; Enabled = $true })
    $scan1 = [ClaudeGuardNative.DesktopHygiene]::Scan($classicClaude, [string[]]@($storeClaude), $fakeStartup, $qRoot)
    Assert-Case (
        $scan1.HasAutoStartEnabled -and $scan1.Locations.Count -eq 2 -and
        $scan1.Locations[0].HasMcpConfig -and $scan1.Locations[1].HasMcpConfig -and
        $scan1.Locations[0].CleanableItems.Count -eq 3 -and $scan1.Locations[1].CleanableItems.Count -eq 1
    ) 'DesktopHygiene discovers Classic + Store data dirs, auto-start warning, and marks MCP configs protected.'

    $qRes = [ClaudeGuardNative.DesktopHygiene]::Quarantine($scan1, $qRoot)
    Assert-Case (
        $qRes.MovedCount -eq 4 -and $qRes.PreservedMcpCount -eq 2 -and
        [IO.File]::Exists((Join-Path $classicClaude 'claude_desktop_config.json')) -and
        [IO.File]::Exists((Join-Path $storeClaude 'claude_desktop_config.json')) -and
        -not [IO.File]::Exists((Join-Path $classicClaude 'Cookies')) -and
        -not [IO.Directory]::Exists((Join-Path $classicClaude 'Cache')) -and
        [IO.File]::Exists((Join-Path $qRes.BackupDirectory 'manifest.json'))
    ) 'DesktopHygiene quarantines cache/cookies/logs while leaving claude_desktop_config.json completely untouched.'

    $restoredCount = [ClaudeGuardNative.DesktopHygiene]::Restore($qRes.BackupDirectory)
    Assert-Case (
        $restoredCount -eq 4 -and
        [IO.File]::Exists((Join-Path $classicClaude 'Cookies')) -and
        [IO.File]::Exists((Join-Path $classicClaude 'Cache\blob.bin')) -and
        [IO.File]::Exists((Join-Path $storeClaude 'Network\Cookies')) -and
        -not [IO.Directory]::Exists($qRes.BackupDirectory)
    ) 'DesktopHygiene restores all quarantined items cleanly and removes the consumed backup directory.'

    $createdLnk = [ClaudeGuardNative.DesktopHygiene]::CreateGuardedShortcut($consoleExe, $shortcutOut)
    Assert-Case ([IO.File]::Exists($createdLnk) -and (Get-Item -LiteralPath $createdLnk).Length -gt 0) 'CreateGuardedShortcut creates a valid Windows .lnk shortcut.'
} finally {
    if ([IO.Directory]::Exists($hygieneRoot)) { [IO.Directory]::Delete($hygieneRoot, $true) }
}

# --- 5. Event-driven NetworkChangeWatcher ---
$watcher = [ClaudeGuardNative.NetworkChangeWatcher]::new($true)
try {
    Assert-Case ($watcher.IsActive) 'NetworkChangeWatcher registers native Windows IP Helper notifications.'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $watcher.ScheduleTriggerForTest(60)
    $woke = $watcher.Wait(4000)
    $timer.Stop()
    Assert-Case ($woke -and $timer.ElapsedMilliseconds -lt 1500 -and $watcher.EventCount -ge 1) 'NetworkChangeWatcher wakes wait loop immediately when a change event fires.'
} finally {
    $watcher.Dispose()
}
$watcher.TriggerForTest()
Assert-Case (-not $watcher.Wait(10)) 'Disposed NetworkChangeWatcher ignores late triggers safely.'

# --- 6. Packaged console CLI smoke checks ---
$verifyOut = & $consoleExe --verify-package
Assert-Case ($LASTEXITCODE -eq 0 -and ($verifyOut | Out-String) -like '*checksums verified*') 'Built console --verify-package validates SHA256SUMS.txt.'

$helpOut = & $consoleExe --help
Assert-Case ($LASTEXITCODE -eq 0 -and ($helpOut | Out-String) -like '*--check-exit*' -and ($helpOut | Out-String) -like '*--stop-claude*') 'Built console --help documents --check-exit and --stop-claude.'

$psi = [Diagnostics.ProcessStartInfo]::new($consoleExe, '--unknown-flag')
$psi.UseShellExecute = $false
$psi.RedirectStandardError = $true
$psi.RedirectStandardOutput = $true
$psi.CreateNoWindow = $true
$proc = [Diagnostics.Process]::Start($psi)
try {
    $null = $proc.StandardOutput.ReadToEnd()
    $errText = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    Assert-Case ($proc.ExitCode -eq 2 -and $errText -like '*Claude Guard Native*') 'Built console returns exit code 2 for unknown arguments.'
} finally {
    $proc.Dispose()
}

Write-Output "$script:Checks offline exit-policy, event-watcher, and CLI checks passed."
