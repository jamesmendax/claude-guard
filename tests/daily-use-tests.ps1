#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../package/guard-runtime.ps1"

$now = [datetime]::Parse('2026-11-21T16:00:00Z').ToUniversalTime()
$sha = 'A' * 64
$other = 'B' * 64
$endpoint = 18793
$script:passed = 0
$script:failed = 0

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) { throw "Expected [$Expected], actual [$Actual]." }
}
function Assert-Rejected([scriptblock]$Body) {
    try { & $Body | Out-Null } catch { return }
    throw 'Expected the operation to be rejected.'
}
function Test-Case([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL ${Name}: $($_.Exception.Message)" }
}
function New-GoodState {
    @{
        Isolation='Off'; Mode='Daily'; Policy='Verified'; Inventory='Verified'
        Proxy='Ready'; Exit='Match'; Gate='Open'; Generation=$sha
        Lease=@{Generation=$sha; CheckedUtc=$now.AddSeconds(-2).ToString('o'); ExpiresUtc=$now.AddSeconds(8).ToString('o')}
        Port=$endpoint;Session='Clear'
    }
}
function New-VlessNode {
    @{
        type='vless'; network='tcp'; server='203.0.113.17'; port=443
        uuid='d95bdb2e-9d99-4ee3-a1aa-841b1c976e89'; tls=$true
        servername='synthetic.invalid'; flow='xtls-rprx-vision'
        'client-fingerprint'='chrome'; udp=$true
        'reality-opts'=@{'public-key'='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';'short-id'='1234abcd'}
    }
}

Test-Case 'Verified linked lease and open gate can launch' {
    $result = Get-GuardDailyDecision (New-GoodState) $now
    Assert-Equal 'Ready' $result.Readiness
    Assert-Equal $true $result.CanLaunch
    Assert-Equal 18793 $result.ProxyPort
}
Test-Case 'The manual launcher stays closed throughout deployment and automatically unlocks when its owner exits' {
    $oldEvent=$script:GuardDailyRevisionEvent
    $oldMutex=$script:GuardDailyLaunchMutex
    $testId=[guid]::NewGuid().ToString('N')
    $script:GuardDailyRevisionEvent='Local\GuardRevisionTest_'+$testId
    $script:GuardDailyLaunchMutex='Local\GuardRevisionSessionTest_'+$testId
    $marker=$null
    try{
        Assert-Equal $false (Test-GuardDailyRevisionInProgress)
        $marker=[Threading.EventWaitHandle]::new($true,'ManualReset',$script:GuardDailyRevisionEvent)
        function Get-GuardDailyStatus { [pscustomobject]@{CanLaunch=$true} }
        function Get-GuardInventory { throw 'A guarded launch reached discovery during installation.' }
        $reason=try{Invoke-GuardDailyDesktop $false}catch{$_.Exception.Message}
        Assert-Equal 'Guard maintenance is in progress.' $reason
        $marker.Dispose()
        Assert-Equal $false (Test-GuardDailyRevisionInProgress)
    }finally{
        if($marker){$marker.Dispose()}
        $script:GuardDailyRevisionEvent=$oldEvent
        $script:GuardDailyLaunchMutex=$oldMutex
    }
}
Test-Case 'Emergency wins over a previously ready lease' {
    $s=New-GoodState; $s.Isolation='Active'
    $result=Get-GuardDailyDecision $s $now
    Assert-Equal 'Emergency' $result.Readiness
    Assert-Equal $false $result.CanLaunch
}
Test-Case 'Rules verified under BlockAll do not permit launch' {
    $s=New-GoodState; $s.Mode='BlockAll'
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
}
Test-Case 'Tunnel up and an open port cannot cover a failed node' {
    $s=New-GoodState; $s.Proxy='Down'; $s.Tunnel='Ready'
    Assert-Equal 'WaitingForProxy' (Get-GuardDailyDecision $s $now).Readiness
}
Test-Case 'Exit change and unverified source keep the launch locked' {
    foreach($exitProof in @('Mismatch','Unverified')) {
        $s=New-GoodState; $s.Exit=$exitProof
        Assert-Equal 'Locked' (Get-GuardDailyDecision $s $now).Readiness
    }
}
Test-Case 'Readiness expires and is invalid on a rollback of the clock' {
    $s=New-GoodState
    Assert-Equal $false (Get-GuardDailyDecision $s $now.AddSeconds(8)).CanLaunch
    Assert-Equal $false (Get-GuardDailyDecision $s $now.AddSeconds(-3)).CanLaunch
    $s.Lease.ExpiresUtc=$now.AddHours(1).ToString('o')
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
}
Test-Case 'Old generation and unverified filters close startup' {
    $s=New-GoodState; $s.Lease.Generation=$other
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
    $s=New-GoodState; $s.Policy='Configured'
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
}
Test-Case 'Unknown inventory, missing watcher or closed gate keep startup blocked' {
    $s=New-GoodState; $s.Inventory='Unknown'
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
    $s=New-GoodState; $s.Gate='Closed'
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
    $s=New-GoodState; $s.Lease=$null
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
}
Test-Case 'Dedicated relay forwards through exactly one VLESS node' {
    $source=New-VlessNode
    $result=New-GuardDedicatedProxyConfig $source $endpoint
    Assert-Equal '127.0.0.1' $result.'bind-address'
    Assert-Equal $endpoint $result.'mixed-port'
    Assert-Equal $false $result.ipv6
    Assert-Equal $false $result.tun.enable
    Assert-Equal $false $result.dns.enable
    Assert-Equal $false $result.proxies[0].udp
    Assert-Equal $true $source.udp
    Assert-Equal 1 @($result.proxies).Count
    Assert-Equal 'MATCH,guard-pinned' ($result.rules -join ',')
    Assert-Equal $null $result.'proxy-groups'
    Assert-Equal $null $result.'proxy-providers'
    Assert-Equal $null $result.'external-controller'
}
Test-Case 'Hostname, loopback, insecure TLS and alternate dialing are rejected as upstreams' {
    foreach($bad in @('upstream.invalid','127.0.0.1','::1','0.0.0.0','239.0.0.1')){
        $node=New-VlessNode; $node.server=$bad
        Assert-Rejected { New-GuardDedicatedProxyConfig $node $endpoint }
    }
    $node=New-VlessNode; $node['dialer-proxy']='DIRECT'
    Assert-Rejected { New-GuardDedicatedProxyConfig $node $endpoint }
    $node=New-VlessNode; $node['skip-cert-verify']=$true
    Assert-Rejected { New-GuardDedicatedProxyConfig $node $endpoint }
}
Test-Case 'Read one exact saved Bettbox node, preserving only supported fields' {
    $yaml=@'
proxies:
  - name: "different"
    type: direct
  - name: 'picked'
    type: vless
    server: 203.0.113.17
    port: 443
    uuid: d95bdb2e-9d99-4ee3-a1aa-841b1c976e89
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: synthetic.invalid
    reality-opts:
      public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      short-id: '1234abcd'
    client-fingerprint: chrome
proxy-groups:
  - name: "picked"
    type: fallback
'@
    $node=Read-GuardBettboxVlessNode $yaml 'picked'
    Assert-Equal '203.0.113.17' $node.server
    Assert-Equal 443 $node.port
    Assert-Equal '1234abcd' $node.'reality-opts'.'short-id'
    Assert-Rejected { Read-GuardBettboxVlessNode $yaml 'elsewhere' }
    Assert-Rejected { Read-GuardBettboxVlessNode ($yaml -replace 'udp: true','dialer-proxy: DIRECT') 'picked' }
    Assert-Rejected { Read-GuardBettboxVlessNode ($yaml -replace 'port: 443',"port: 443`n    port: 8388") 'picked' }
}
Test-Case 'Failed session closes policy before requesting process exit' {
    $events=New-Object 'Collections.Generic.List[string]'
    $result=Stop-GuardDailySession @{ 
        CloseGate={ $events.Add('blocked'); $true }
        Snapshot={ $events.Add('snapshot'); [pscustomobject]@{Id=99;Start=5} }
        RequestClose={ param($p) $events.Add('close') }
        Wait={ param($ms) $events.Add("wait-$ms") }
        ForceStop={ param($p) $events.Add('force') }
    }
    Assert-Equal 'blocked,snapshot,close,wait-5000,snapshot,force,snapshot' ($events -join ',')
    Assert-Equal $false $result.Exited
    Assert-Equal $true $result.NetworkBlocked
}
Test-Case 'If closure cannot verify network protection nothing can reopen the gate' {
    $events=New-Object 'Collections.Generic.List[string]'
    $result=Stop-GuardDailySession @{
        CloseGate={$events.Add('failed-gate');$false}
        Snapshot={$events.Add('snapshot')}
        RequestClose={throw 'unexpected'}
        Wait={throw 'unexpected'}
        ForceStop={throw 'unexpected'}
    }
    Assert-Equal $false $result.NetworkBlocked
    Assert-Equal $true $result.Exited
    Assert-Equal 'failed-gate,snapshot,snapshot' ($events -join ',')
}
Test-Case 'Force stop skips a reused PID' {
    $first=[pscustomobject]@{Id=42; Start=5}
    $replacement=[pscustomobject]@{Id=42; Start=7}
    $snapshots=New-Object 'Collections.Generic.Queue[object]'
    $snapshots.Enqueue($first); $snapshots.Enqueue($replacement); $snapshots.Enqueue($replacement)
    $result=Stop-GuardDailySession @{
        CloseGate={$true};Snapshot={$snapshots.Dequeue()};RequestClose={};Wait={}
        ForceStop={throw 'unexpected kill on reused PID'}
    }
    Assert-Equal $false $result.Exited
    Assert-Equal 0 $result.StopErrors
}
Test-Case 'Candidate verified before conflict retirement and failed switch rolls back blocked' {
    $runs=New-Object 'Collections.Generic.List[string]'
    $ops=@{
        ReadJournal={}
        WriteJournal={}
        ClearJournal={}
        SaveBefore={ $runs.Add('snapshot'); 'a'*32 }
        InstallClosedPolicy={ $runs.Add('install-closed') }
        VerifyClosedPolicy={ $runs.Add('verify-closed'); $true }
        RetireConflicts={ $runs.Add('retire'); throw 'fault' }
        WriteMode={ throw 'unexpected publish' }
        VerifyCommit={ throw 'unexpected verify' }
        RestoreIsolation={ $runs.Add('restore-isolation'); $true }
    }
    Assert-Rejected { Invoke-GuardDailyPolicySwitch $ops }
    Assert-Equal 'snapshot,install-closed,verify-closed,retire,restore-isolation' ($runs -join ',')
}
Test-Case 'A failed effective-policy verification never retires a conflict' {
    $ops=@{
        ReadJournal={}
        WriteJournal={}
        ClearJournal={}
        SaveBefore={'a'*32}
        InstallClosedPolicy={}
        VerifyClosedPolicy={$false}
        RetireConflicts={throw 'unexpected retire'}
        WriteMode={throw 'unexpected publish'}
        VerifyCommit={throw 'unexpected verify'}
        RestoreIsolation={$true}
    }
    Assert-Rejected { Invoke-GuardDailyPolicySwitch $ops }
}

Test-Case 'Gate publication error revokes partial admission' {
    $events=New-Object 'Collections.Generic.List[string]'
    $state=New-GoodState
    $actual=[datetime]::UtcNow
    $state.Lease.CheckedUtc=$actual.AddSeconds(-1).ToString('o')
    $state.Lease.ExpiresUtc=$actual.AddSeconds(10).ToString('o')
    $result=Set-GuardDailyAdmission $state @{
        OpenVerified={$events.Add('open');$true}
        CloseVerified={$events.Add('close');$true}
        Publish={param($item,$decision) if($decision.CanLaunch){$events.Add('publish-ready');throw 'write failed'}
            $events.Add('publish-locked')}
    }
    Assert-Equal 'open,publish-ready,close,publish-locked' ($events -join ',')
    Assert-Equal $false $result.CanLaunch
}
Test-Case 'Fault while opening the gate ends with a closed gate' {
    $events=New-Object 'Collections.Generic.List[string]'
    $state=New-GoodState
    $actual=[datetime]::UtcNow
    $state.Lease.CheckedUtc=$actual.AddSeconds(-1).ToString('o')
    $state.Lease.ExpiresUtc=$actual.AddSeconds(10).ToString('o')
    $result=Set-GuardDailyAdmission $state @{
        OpenVerified={$events.Add('open');throw 'open failed'}
        CloseVerified={$events.Add('close');$true}
        Publish={param($item,$decision) if($decision.CanLaunch){throw 'unsafe'}; $events.Add('publish-locked')}
    }
    Assert-Equal 'open,close,publish-locked' ($events -join ',')
    Assert-Equal $false $result.CanLaunch
}


Test-Case 'Coverage readback must be current and belong to the active generation' {
    $format='o'
    Assert-Equal $true (Test-GuardRuleReceipt $sha $sha 'Verified' 'Verified' $now.AddSeconds(-2).ToString($format) $now)
    Assert-Equal $false (Test-GuardRuleReceipt $sha $other 'Verified' 'Verified' $now.AddSeconds(-2).ToString($format) $now)
    Assert-Equal $false (Test-GuardRuleReceipt $sha $sha 'Verified' 'Verified' $now.AddSeconds(-15).ToString($format) $now)
    Assert-Equal $false (Test-GuardRuleReceipt $sha $sha 'Verified' 'Configured' $now.AddSeconds(-2).ToString($format) $now)
}
Test-Case 'A close acknowledgement has to match the generation and requested gate' {
    $closed=@{Generation=$sha;CloseName='fixture-gate';Policy='Verified';Gate='Closed';RulesUtc=$now.AddSeconds(1)}
    Assert-Equal $true (Test-GuardCurrentGateClosed $closed $sha 'fixture-gate' $now)
    Assert-Equal $false (Test-GuardCurrentGateClosed $closed $other 'fixture-gate' $now)
    Assert-Equal $false (Test-GuardCurrentGateClosed $closed $sha 'different-gate' $now)
    Assert-Equal $false (Test-GuardCurrentGateClosed $closed $sha 'fixture-gate' $now.AddSeconds(2))
}
Test-Case 'Ending a paused Desktop still signals the controller to clean up its session' {
    $signal=[Threading.ManualResetEvent]::new($false)
    function Get-GuardDailyStatus {
        [pscustomobject]@{Generation=$sha;CloseName='fixture-gate';Policy='Verified';Gate='Closed'
            RulesUtc=[datetime]::UtcNow}
    }
    try {
        Assert-Equal $true (Request-GuardDailyGateClose $signal $sha 'fixture-gate')
        Assert-Equal $true $signal.WaitOne(0)
    } finally { $signal.Dispose() }
}
Test-Case 'An unavailable status still leaves the shutdown signal set' {
    $signal=[Threading.ManualResetEvent]::new($false)
    function Get-GuardDailyStatus { throw 'Status temporarily unavailable.' }
    try {
        Assert-Equal $false (Request-GuardDailyGateClose $signal $sha 'fixture-gate')
        Assert-Equal $true $signal.WaitOne(0)
    } finally { $signal.Dispose() }
}
Test-Case 'Unknown process identity prevents a completed shutdown result' {
    $result=Stop-GuardDailySession @{
        CloseGate={$true};Snapshot={throw 'process unavailable'}
        RequestClose={throw 'unexpected close'};Wait={throw 'unexpected wait'}
        ForceStop={throw 'unexpected terminate'}
    }
    Assert-Equal $false $result.Exited
    Assert-Equal $true $result.NetworkBlocked
    Assert-Equal $true ($result.StopErrors -gt 0)
}
Test-Case 'Recovery holds admission while a prior Desktop process is unresolved' {
    $s=New-GoodState; $s.Session='Stopping'
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
    $s.Session='Unknown'
    Assert-Equal $false (Get-GuardDailyDecision $s $now).CanLaunch
}


Test-Case 'Interrupted cutover restores isolation before starting another transition' {
    $events=New-Object 'Collections.Generic.List[string]'
    $backup=[guid]::NewGuid().ToString('N')
    $pending=@{Version=1;Phase='ConflictsRetired';BackupId=$backup}
    $result=Invoke-GuardDailyPolicySwitch @{
        ReadJournal={$pending}
        RestoreIsolation={param($entry) Assert-Equal $backup $entry.BackupId; $events.Add('restore'); $true}
        ClearJournal={$events.Add('clear')}
        SaveBefore={throw 'No new transition may begin during recovery'}
    }
    Assert-Equal 'RecoveredIsolation' $result
    Assert-Equal 'restore,clear' ($events -join ',')
}
Test-Case 'Failed recovery retains the journal and keeps new permits closed' {
    $events=New-Object 'Collections.Generic.List[string]'
    Assert-Rejected {
        Invoke-GuardDailyPolicySwitch @{
            ReadJournal={@{Version=1;Phase='ConflictsRetired';BackupId=('a'*32)}}
            RestoreIsolation={$events.Add('restore');$false}
            ClearJournal={$events.Add('clear')}
        }
    }
    Assert-Equal 'restore' ($events -join ',')
}


Test-Case 'A corrupt daily marker closes the launcher and stops legacy refresh selection' {
    function Get-GuardIsolationMode { 'Off' }
    function Get-GuardDataPath { 'fixture-mode.json' }
    function Get-Item { [pscustomobject]@{Name='fixture-mode.json'} }
    function Read-GuardDailyRecord { throw 'malformed mode' }
    $result=Get-GuardDailyStatus
    Assert-Equal $true $result.Configured
    Assert-Equal 'Locked' $result.Readiness
    Assert-Equal $false $result.CanLaunch
}
Test-Case 'Emergency isolation short circuits the daily controller lookup' {
    function Get-GuardIsolationMode { 'Active' }
    function Get-GuardDataPath { throw 'daily state must be ignored while isolated' }
    $result=Get-GuardDailyStatus
    Assert-Equal 'Emergency' $result.Readiness
    Assert-Equal $false $result.CanLaunch
}
Test-Case 'A synthetic child exits when the bounded force-stop step runs' {
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $child=Start-Process -FilePath $shell -ArgumentList '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 90"' -WindowStyle Hidden -PassThru
    $events=New-Object 'Collections.Generic.List[string]'
    try {
        $result=Stop-GuardDailySession @{
            CloseGate={$events.Add('closed');$true}
            Snapshot={
                if(-not $child.HasExited){[pscustomobject]@{Id=$child.Id;Start=$child.StartTime.Ticks;Process=$child}}
            }
            RequestClose={param($item) $events.Add('asked');$null=$item.Process.CloseMainWindow()}
            Wait={param($milliseconds) $events.Add("wait-$milliseconds");Start-Sleep -Milliseconds 50}
            ForceStop={param($item) $events.Add('force');$item.Process.Kill();$null=$item.Process.WaitForExit(2000)}
        }
        Assert-Equal 'closed,asked,wait-5000,force' ($events -join ',')
        Assert-Equal $true $child.HasExited
        Assert-Equal $true $result.NetworkBlocked
        Assert-Equal $true $result.Exited
    } finally {
        if(-not $child.HasExited){$child.Kill();$null=$child.WaitForExit(2000)}
        $child.Dispose()
    }
}

Write-Host "RESULT Passed=$script:passed Failed=$script:failed"
if ($script:failed) { exit 1 }

