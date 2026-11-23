#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$package = Join-Path (Split-Path -Parent $PSScriptRoot) 'package'
$script:Passed = 0
$script:Failures = New-Object 'Collections.Generic.List[string]'

# Import the functions without running any script entrypoints or reading user data.
foreach ($file in @('guard-common.ps1','guard-network.ps1','guard-isolation.ps1','setup-firewall.ps1','guard-autorefresh.ps1','guard-runtime.ps1')) {
    $path = Join-Path $package $file
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($errors.Message -join ', ') }
    foreach ($item in @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] })) {
        . ([scriptblock]::Create($item.Extent.Text))
    }
}
$script:GuardRulePrefix = 'Claude-VPN-Guard-Block'
$script:GuardIsolationPrefix = 'ClaudeDesktopPrivacyIsolation-Managed-'
function Start-Process { throw 'Real native process is forbidden by this test.' }
function New-NetFirewallRule { throw 'Real firewall write is forbidden by this test.' }
function Remove-NetFirewallRule { throw 'Real firewall write is forbidden by this test.' }
function Set-NetFirewallRule { throw 'Real firewall write is forbidden by this test.' }
function Get-NetFirewallRule { throw 'Real firewall read is forbidden by this test.' }
function Get-NetAdapter { throw 'Real adapter read is forbidden by this test.' }
function Get-AppxPackage { throw 'Real package read is forbidden by this test.' }
function Invoke-WebRequest { throw 'Real network request is forbidden by this test.' }
function Invoke-GuardPrivacy { throw 'Real diagnostic read is forbidden by this test.' }
function Assert-Equal($Expected,$Actual,[string]$Message) {
    if ($Expected -cne $Actual) { throw "$Message (expected '$Expected', got '$Actual')" }
}
function Assert-Exists([string]$Command) {
    if (-not (Get-Command $Command -CommandType Function -ErrorAction SilentlyContinue)) { throw "$Command is missing." }
}
function Test-Case([string]$Name,[scriptblock]$Body) {
    try { & $Body; $script:Passed++; Write-Output "PASS $Name" }
    catch { $script:Failures.Add($Name); Write-Output "FAIL $Name -- $($_.Exception.Message)" }
}
$apps = [pscustomobject]@{
    Programs = @('C:\Fake\VersionB\App.exe','D:\Fake\VersionB\App.exe')
    Packages = @([pscustomobject]@{Sid='S-1-15-2-1-2-3-4-5-6-7';Root='C:\Fake\VersionB'})
}
$adapters = @(
    [pscustomobject]@{Name='Ethernet';InterfaceGuid=[guid]'10000000-0000-0000-0000-000000000001';Status='Up';Ipv4Present=$true;IpInterfacePresent=$true}
    [pscustomobject]@{Name='IPv6 only';InterfaceGuid=[guid]'10000000-0000-0000-0000-000000000002';Status='Up';Ipv4Present=$false;IpInterfacePresent=$true}
)
Test-Case 'IPv6 covers every interface with no Teredo dependency' {
    $specs = @(Get-GuardSpecifications $apps $adapters)
    $ipv6 = @($specs | Where-Object RemoteAddress -eq '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    Assert-Equal 3 $ipv6.Count 'Each exact path and package needs an IPv6 rule'
    Assert-Equal 3 @($ipv6 | Where-Object Alias -eq 'Any').Count 'IPv6 includes the pinned tunnel'
    Assert-Equal 3 @($specs | Where-Object Alias -eq 'Ethernet').Count 'IPv4 is blocked on the untrusted adapter'
    Assert-Equal 0 @($specs | Where-Object Alias -eq 'IPv6 only').Count 'IPv6-only adapters need no IPv4 rule'
}
Test-Case 'Offline tunnel pins identity and treats a replacement as untrusted' {
    function Get-GuardNetworkAdapters { $adapters }
    function Get-NetIPInterface { $adapters | ForEach-Object { [pscustomobject]@{InterfaceIndex=$_.ifIndex;AddressFamily='IPv4'} } }
    $adapters[0] | Add-Member -Name ifIndex -MemberType NoteProperty -Value 11 -Force
    $adapters[1] | Add-Member -Name ifIndex -MemberType NoteProperty -Value 22 -Force
    $pinned = Get-GuardPinnedVpnAdapter '10000000-0000-0000-0000-000000000009'
    $blocked = @(Get-GuardBlockedAdapters $pinned -AllowVpnDown)
    Assert-Equal 'Not Present' $pinned.Status 'A missing pinned adapter is not replaced'
    Assert-Equal 2 $blocked.Count 'Both current adapters are untrusted when the pinned tunnel is missing'
}
Test-Case 'Emergency paths follow a version and alias change, while package names remain stable' {
    Assert-Exists Get-GuardIsolationSpecifications
    $before = [pscustomobject]@{Programs=@('C:\Fake\VersionA\App.exe');Packages=$apps.Packages}
    $prior = @(Get-GuardIsolationSpecifications $before)
    $specs = @(Get-GuardIsolationSpecifications $apps)
    Assert-Equal 6 $specs.Count 'Each program or package has two directions'
    Assert-Equal 3 @($specs | Where-Object Direction -eq 'Inbound').Count 'Inbound count'
    Assert-Equal 6 @($specs | Where-Object Alias -eq 'Any').Count 'Isolation includes all interfaces'
    Assert-Equal 2 @($specs | Where-Object { $_.Package -and $_.Name -in $prior.Name }).Count 'Stable package identity survives upgrades'
    Assert-Equal 0 @($specs | Where-Object { $_.Program -and $_.Name -in $prior.Name }).Count 'New version paths receive new rules'
}
Test-Case 'An unreadable Cowork service process keeps the protected session unresolved' {
    function Get-Process {
        [pscustomobject]@{Id=111;ProcessName='cowork-svc';Path=$null;HasExited=$false}
        [pscustomobject]@{Id=112;ProcessName='cowork-svc';Path=$null;HasExited=$true}
        [pscustomobject]@{Id=113;ProcessName='unrelated';Path=$null;HasExited=$false}
    }
    $snapshot=Get-GuardProcessSnapshot $apps
    Assert-Equal 0 $snapshot.Processes.Count 'No unknown process should be identified for termination'
    Assert-Equal 1 $snapshot.Errors.Count 'The live Cowork service cannot be treated as absent'
}
Test-Case 'Only the confirmed Store service in session zero is excluded from Desktop shutdown' {
    function Get-Process {
        [pscustomobject]@{Id=111;ProcessName='cowork-svc';SessionId=0;Path=$null;HasExited=$false}
        [pscustomobject]@{Id=112;ProcessName='cowork-svc';SessionId=1;Path=$null;HasExited=$false}
    }
    $storeService=[pscustomobject]@{Id=111;Path='C:\Fake\app\resources\cowork-svc.exe'}
    $snapshot=Get-GuardProcessSnapshot $apps $storeService
    Assert-Equal 0 $snapshot.Processes.Count 'The verified service does not own a Desktop session'
    Assert-Equal 1 $snapshot.Errors.Count 'An unrelated process with the same name still blocks'
    Assert-Equal $true ($snapshot.Errors[0] -match '\b112\b') 'The unrelated process is the unresolved one'
}
Test-Case 'A rule configured but not enforced does not verify emergency isolation' {
    $spec=[pscustomobject]@{Program='C:\Fake\App.exe';Package=$null;Alias='Any';Direction='Outbound'}
    $rule=[pscustomobject]@{Name='fake';Enabled='True';Direction='Outbound';Action='Block';Profile='Any';PrimaryStatus='OK';EnforcementStatus=@('NotApplicable')}
    function Get-GuardRuleFilter($Rule,$Kind,$Cache) {
        switch ($Kind) {
            'Application' { [pscustomobject]@{Program='C:\Fake\App.exe';Package=''} }
            'Interface' { [pscustomobject]@{InterfaceAlias='Any'} }
            'Port' { [pscustomobject]@{Protocol='Any';LocalPort='Any';RemotePort='Any';IcmpType='Any'} }
            'Address' { [pscustomobject]@{LocalAddress='Any';RemoteAddress='Any'} }
            'Service' { [pscustomobject]@{Service='Any'} }
            'InterfaceType' { [pscustomobject]@{InterfaceType='Any'} }
            'Security' { [pscustomobject]@{Authentication='NotRequired';Encryption='NotRequired';LocalUser='Any';RemoteUser='Any';RemoteMachine='Any'} }
        }
    }
    $covered=Test-GuardRule $rule $spec -RequireEnforced
    Assert-Equal $false $covered 'A policy entry alone is insufficient'
    Assert-Equal $false (Test-GuardRule $rule $spec) 'Normal coverage also requires active evidence'
    $rule.EnforcementStatus=@('ProfileInactive','Enforced')
    Assert-Equal $true (Test-GuardRule $rule $spec -RequireEnforced) 'Enforced on the active profile'
}
Test-Case 'Hold stops the launcher before session setup' {
    function Get-GuardIsolationMode { 'Active' }
    function New-Object { throw 'Reached session setup' }
    $message=''
    try { Invoke-GuardLaunch } catch { $message=$_.Exception.Message }
    Assert-Equal 'Claude privacy isolation is active or could not be verified.' $message 'Guard must refuse before initialization'
}
Test-Case 'Stale or old refresh records cannot be shown as current' {
    Assert-Exists Get-GuardRefreshStatusView
    $time=[datetime]'2030-01-01T12:00:00Z'
    $fresh=[pscustomobject]@{Version=2;Utc='2030-01-01T11:59:00Z';LastVerifiedUtc='2030-01-01T11:51:00Z';Coverage='Verified';Proxy='Clear';Tunnel='Ready';Isolation='Verified';Reason='Current'}
    Assert-Equal $true (Get-GuardRefreshStatusView $fresh $time).Ok 'A fresh, verified check is current'
    $fresh.LastVerifiedUtc='2030-01-01T11:44:59Z'
    Assert-Equal $false (Get-GuardRefreshStatusView $fresh $time).Ok 'A stale coverage result is never current'
    Assert-Equal 'Stale' (Get-GuardRefreshStatusView $fresh $time).Freshness 'Stale status is visible'
    $fresh.Version=1; $fresh | Add-Member -MemberType NoteProperty -Name Ok -Value $true
    Assert-Equal $false (Get-GuardRefreshStatusView $fresh $time).Ok 'An old-format success is never current'
}
Test-Case 'Proxy or tunnel failure is visible even with verified rules' {
    Assert-Exists Get-GuardRefreshStatusView
    $time=[datetime]'2030-01-01T12:00:00Z'
    $status=[pscustomobject]@{Version=2;Utc='2030-01-01T11:59:00Z';LastVerifiedUtc='2030-01-01T11:59:00Z';Coverage='Verified';Proxy='Unknown';Tunnel='Unavailable';Isolation='Verified';Reason='Current'}
    $view=Get-GuardRefreshStatusView $status $time
    Assert-Equal $false $view.Ok 'Verified rules do not imply healthy proxy or tunnel'
    Assert-Equal 'Unavailable' $view.Tunnel 'Tunnel failure is surfaced'
    Assert-Equal 'Verified' $view.Coverage 'The confirmed coverage result is preserved'
}
Test-Case 'Timed out refresh tracks the same child without starting a second writer' {
    $script:Starts=0
    $script:Attempts=New-Object 'Collections.Generic.List[object]'
    $script:Child=[pscustomobject]@{HasExited=$false}
    $script:Child | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($milliseconds) if ($milliseconds -ne 300000) { throw 'Wrong refresh wait' }; $false }
    $script:Child | Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
    function Start-GuardBackgroundSetup([guid]$Id) { $script:Starts++; $script:Child }
    function Save-GuardAutoRefreshStatus($Result,[string]$LastVerifiedUtc) { $script:Attempts.Add($Result) }
    function Get-GuardInventory { [pscustomobject]@{Programs=@('C:\Fake\VersionB\App.exe');Packages=@()} }
    function New-GuardChangeMonitor { return $null }
    function Start-Sleep {}
    Start-GuardAutoRefreshLoop -PollSeconds 0 -CheckMinutes 0 -RetryMinutes 0 -MaxIterations 3
    Assert-Equal 1 $script:Starts 'A timed out child is still the only writer'
    Assert-Equal 'TimedOut' $script:Attempts[-1].Reason 'The old success is replaced with a timeout result'
}
function Test-RuleTransactionFault([string]$Fault) {
    $script:Rules=@{'Claude-VPN-Guard-Block-old'='True';'ClaudeDesktopPrivacyIsolation-old'='True';'Claude-VPN-Guard-Block-foreign'='True'}
    $script:OriginalState='{"Version":2,"Rules":["Claude-VPN-Guard-Block-old"]}'
    $script:SavedState=$script:OriginalState
    $script:Journal=$null
    $script:VerifyCalls=0
    $script:FailRetirement=$Fault -eq 'Retirement'
    function Get-GuardStateContent { $script:SavedState }
    function Get-GuardRules {
        foreach($name in $script:Rules.Keys | Where-Object { $_ -like 'Claude-VPN-Guard-Block-*' }) {
            [pscustomobject]@{Name=$name;Enabled=$script:Rules[$name]}
        }
    }
    function Save-GuardFirewallJournal($Journal) { $script:Journal=$Journal }
    function Get-GuardFirewallJournal { $script:Journal }
    function Clear-GuardFirewallJournal { $script:Journal=$null }
    function Add-GuardFirewallBlock($Specification,[string]$Name) {
        $script:Rules[$Name]='True'
        if ($Fault -eq 'Creation') { throw 'Simulated creation failure after provider write' }
    }
    function Get-GuardFirewallRuleNamed([string]$Name,[string]$PolicyStore='PersistentStore') {
        if ($script:Rules.ContainsKey($Name)) { [pscustomobject]@{Name=$Name;Enabled=$script:Rules[$Name]} }
    }
    function Set-NetFirewallRule([string]$Name,[string]$Enabled,[string]$PolicyStore) { $script:Rules[$Name]=$Enabled }
    function Remove-NetFirewallRule([string]$Name,[string]$PolicyStore) {
        if ($Name -eq 'Claude-VPN-Guard-Block-old' -and $script:FailRetirement) { throw 'Simulated retirement failure' }
        $script:Rules.Remove($Name)
    }
    function Save-GuardFirewallState($State) {
        if ($Fault -eq 'Commit') { throw 'Simulated state commit failure' }
        $script:SavedState=$State | ConvertTo-Json -Compress
    }
    function Assert-GuardSetupCoverage {
        $script:VerifyCalls++
        if ($Fault -eq 'Coverage' -and $script:VerifyCalls -eq 2) { throw 'Simulated effective rule failure' }
    }
    $spec=[pscustomobject]@{Program='C:\Fake\App.exe';Alias='Ethernet'}
    $vpn=[pscustomobject]@{InterfaceGuid='10000000-0000-0000-0000-000000000009'}
    $failure=''
    try { Invoke-GuardRuleTransaction $vpn @($adapters[0]) @($spec) } catch { $failure=$_.Exception.Message }
    if ($Fault -eq 'Retirement') {
        Assert-Equal 'Simulated retirement failure' $failure 'Retirement error is surfaced'
        Assert-Equal 'False' $script:Rules['Claude-VPN-Guard-Block-old'] 'Committed candidate remains when old deletion fails'
        Assert-Equal $true ([bool]$script:Journal) 'Retry retains the journal'
        $script:FailRetirement=$false
        Repair-GuardFirewallTransaction
        Assert-Equal 3 $script:Rules.Count 'Retry removes only the disabled former generation'
    } else {
        $expected=@{Creation='Simulated creation failure after provider write';Coverage='Simulated effective rule failure';Commit='Simulated state commit failure'}
        Assert-Equal $expected[$Fault] $failure 'The failure is surfaced'
        Assert-Equal 'True' $script:Rules['Claude-VPN-Guard-Block-old'] 'Original rule restored'
        Assert-Equal $script:OriginalState $script:SavedState 'Uncommitted state preserved'
        Assert-Equal 3 $script:Rules.Count 'Only transaction-created entries were removed'
    }
    Assert-Equal 'True' $script:Rules['ClaudeDesktopPrivacyIsolation-old'] 'Emergency rule retained'
    Assert-Equal 'True' $script:Rules['Claude-VPN-Guard-Block-foreign'] 'A foreign prefix lookalike is retained'
    Assert-Equal $null $script:Journal 'Completed recovery clears its journal'
}
foreach ($fault in @('Creation','Coverage','Commit','Retirement')) {
    Test-Case "Rule transaction recovers from $fault failure" { Test-RuleTransactionFault $fault }
}
Test-Case 'Blocked tunnel or proxy means two all-interface address families' {
    $specs=@(Get-GuardSpecifications $apps $adapters -BlockAll)
    Assert-Equal 6 $specs.Count 'Two address families for three known targets'
    Assert-Equal 6 @($specs | Where-Object Alias -eq 'Any').Count 'A new adapter has no escape path'
    Assert-Equal 3 @($specs | Where-Object RemoteAddress -eq '0.0.0.0-255.255.255.255').Count 'All IPv4 destinations are blocked'
    Assert-Equal 3 @($specs | Where-Object RemoteAddress -eq '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').Count 'All IPv6 destinations are blocked'
}
Test-Case 'Loss of network conditions during verification closes the next policy' {
    $script:Modes=New-Object 'Collections.Generic.List[bool]'
    function Repair-GuardFirewallTransaction {}
    function Assert-GuardProfiles {}
    function Get-GuardInventory { $apps }
    function Get-GuardIsolationMode { 'Off' }
    function Get-GuardProxyState { 'Clear' }
    function Get-GuardStateContent { '{"Version":2,"VpnGuid":"10000000-0000-0000-0000-000000000009","Rules":["Claude-VPN-Guard-Block-old"]}' }
    function Get-GuardVpnAdapter($Pinned) { [pscustomobject]@{InterfaceGuid=$Pinned} }
    function Get-GuardAdapters { $adapters }
    function Assert-GuardSetupCoverage($Vpn,$Adapters,$Names,[switch]$AllowVpnDown,[switch]$BlockAll) {
        $script:Modes.Add([bool]$BlockAll)
        if (-not $BlockAll) {
            $failure=New-Object InvalidOperationException 'Simulate loss of readiness'
            $failure.Data['GuardNetworkChanged']=$true
            throw $failure
        }
    }
    $value=Invoke-GuardBackgroundRefresh
    Assert-Equal 2 $script:Modes.Count 'Rechecks using the closed rule family once'
    Assert-Equal $true $script:Modes[1] 'The second check must assume all interfaces are untrusted'
    Assert-Equal 'BlockAll' $value.Policy 'Never publishes the obsolete pinned policy'
    Assert-Equal 'Unavailable' $value.Tunnel 'Signals the failed prerequisite'
}
Write-Output ('RESULT Passed={0} Failed={1}' -f $script:Passed,$script:Failures.Count)
if ($script:Failures.Count) { exit 1 }
