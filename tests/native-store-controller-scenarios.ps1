# Dot-sourced only by the installed-driver normal package lab.
. (Join-Path $repo 'package\guard-common.ps1')
. (Join-Path $repo 'package\guard-daily-plan.ps1')
. (Join-Path $repo 'package\guard-daily-notifications.ps1')
. (Join-Path $PSScriptRoot 'native-store-stability.ps1')
$scenarioDir=Join-Path $stage 'store-controller'
Initialize-GuardAdministratorDirectory $scenarioDir
$activeRecord=Read-GuardDailyRecord 'daily-provisioned.json'
$scenario=[ordered]@{
    ProbeTimeoutNoExit=$false;ProofExpiryBlocks=$false;SameProcessAfterRecheck=$false
    UpstreamFailureWhileAdapterUp=$false;UpstreamClosedBeforeExit=$false
    BackendExitBlocksExistingAndNew=$false;ManualRecovery=$false
    PausedExitConfirmed=$false;PausedExitCleanupSignal=$false;PausedExitClearedSandbox=$false;PausedExitManualReopen=$false
    ObservePauseMs=$null;ObserveUpstreamMs=$null;ExitAfterConfirmedBlockMs=$null;BackendExitBeforeProofExpiry=$false
    BackupCasesPassed=$false;NormalRequests=$null;BackupAfterPrimaryFailure=$false;SlowPrimaryRoundMs=$null;OptOutRequests=$null
    BothUnavailablePaused=$false;MismatchStopped=$false;MismatchLastReason=$null;TransportLastReason=$null
    MismatchBlockReadbackUtc=$null;MismatchProcessExitUtc=$null;TransportBlockReadbackUtc=$null;TransportProcessExitUtc=$null
    NotificationsPassed=$false
    ReconnectDirectAttempts=0;ReconnectDirectTcp=0;ReconnectDirectUdp=0
    ReconnectControlTcp=0;ReconnectControlUdp=0;Stability=$null;Error=$null;ErrorLine=$null
}
$workerControl=$null
$witnessService=$null
$witnessSettings=Join-Path $scenarioDir 'witness.json'
$witnessRequests=Join-Path $scenarioDir 'requests.txt'
$primaryOnly=Join-Path $scenarioDir 'primary-only'
$scenarioCloseName='Local\GuardStoreFixture_'+[guid]::NewGuid().ToString('N')
$scenarioClose=[Threading.EventWaitHandle]::new($false,'ManualReset',$scenarioCloseName)
$holdWitness=Join-Path $scenarioDir 'hold-witness'
$pausedExitCleanup=Join-Path $scenarioDir 'paused-exit-cleanup'
$quitReceipt=Join-Path $scenarioDir 'quit-request.json'
$lingering=$null

function Read-StoreScenarioHealth {
    Read-GuardDailyJsonFile (Join-Path $scenarioDir 'daily-health.json')
}
function Wait-StoreScenario([string]$Description,[scriptblock]$Check) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        if($workerControl.Process.HasExited){
            $failure=if($workerControl.ErrorOutput.IsCompleted){$workerControl.ErrorOutput.Result}
            throw "The Store controller fixture exited during $Description. $failure"
        }
        try{$value=& $Check}catch{$value=$null}
        if($value){return $value}
        Start-Sleep -Milliseconds 100
    }while($timer.Elapsed.TotalSeconds -lt (3*$script:GuardDailyMaxLeaseSeconds))
    throw "Timed out waiting for $Description."
}
function Confirm-StoreScenarioAdapter {
    $adapter=Get-GuardPinnedVpnAdapter $activeRecord.VpnGuid
    ($adapter.Name -ceq 'Bettbox' -and $adapter.Status -eq 'Up')
}
function Confirm-StoreScenarioGateClosed {
    [ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($newPlan,[uint16]$replacement.Weight) -eq $newPlan.BootCount
}
function Set-StoreWitness([string]$Primary,[string]$Secondary){
    Save-GuardAdministratorJson $witnessSettings ([ordered]@{cloudflare=$Primary;ipify=$Secondary
        expectedIpv4='203.0.113.99';otherIpv4='203.0.113.98';receiptPath='requests.txt'})
}
function Read-StoreWitnessCounts {
    $lines=[IO.File]::ReadAllLines($witnessRequests)
    [pscustomobject]@{Primary=@($lines -ceq 'CloudflareTrace').Count;Backup=@($lines -ceq 'Ipify').Count}
}
function Read-StoreFixtureRecord([string]$Name){
    Read-GuardDailyJsonFile (Join-Path $scenarioDir $Name)
}
function Read-StoreScenarioNotice([switch]$LastStop) {
    & {
        function Get-GuardDataPath([string]$Name) {Join-Path $scenarioDir $Name}
        Read-GuardDailyNotice -LastStop:$LastStop
    }
}
function Get-StoreNoticeStatus($Health) {
    $state=@{Mode='Daily';Isolation='Off'}
    foreach($field in 'Policy','Inventory','Gate','Proxy','Exit','Failure','Session','Terminating','Generation','Port','Lease'){
        $state[$field]=$Health.$field
    }
    $decision=Get-GuardDailyDecision $state
    [pscustomobject]@{Readiness=$decision.Readiness;CanLaunch=$decision.CanLaunch;Gate=$Health.Gate;Generation=$Health.Generation}
}
function Confirm-StoreStopNotice($Notice,[string]$Reason,[datetime]$ExitUtc) {
    $shown=Get-GuardDailyPresentation $Notice $null
    if($Notice.Phase -cne 'Stopped' -or $Notice.Reason -cne $Reason -or $Notice.Utc -lt $ExitUtc -or
        $shown.Key -cne "$($Notice.Id):fault" -or $shown.Text -notlike "*$(Get-GuardDailyNoticeReasonText $Reason)*已退出*" -or
        (Get-GuardDailyPresentation $Notice $null @($shown.Key))){
        throw 'A confirmed fixture stop must report one specific reason after actual process exit.'
    }
}
function Confirm-StoreRecoveryNotice($Stopped) {
    $null=Wait-StoreScenario 'the same stopped incident ready for manual reopen' {
        $notice=Read-StoreScenarioNotice
        if($notice.Phase -cne 'Ready' -or $notice.Id -cne $Stopped.Id -or $notice.Reason -cne $Stopped.Reason){return $false}
        $status=Get-StoreNoticeStatus (Read-StoreScenarioHealth)
        $shown=Get-GuardDailyPresentation $notice $status @("$($Stopped.Id):fault")
        $shown.Key -ceq "$($Stopped.Id):recovery" -and $shown.Text -like '*手动打开 Claude*' -and
            -not (Get-GuardDailyPresentation $notice $status @($shown.Key)) -and
            [GuardInstalledSandboxieFixtureReadback]::ProcessCount() -eq 0
    }
}
function Confirm-StoreDirectControl {
    $endpoint=[Net.IPEndPoint]::new([Net.IPAddress]::Loopback,$directPort)
    $tcp=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $udp=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try{
        if(-not $tcp.ConnectAsync($endpoint.Address,$endpoint.Port).Wait(1000)){throw 'The unprotected TCP control could not connect.'}
        if($udp.Send([byte[]]@(0x44),1,$endpoint) -ne 1){throw 'The unprotected UDP control could not send.'}
    }finally{$tcp.Dispose();$udp.Dispose()}
    $packets=Read-DirectPackets
    if($packets.TcpCount -ne 1 -or $packets.UdpCount -ne 1){throw 'The independent TCP and UDP recovery controls were not reachable.'}
    $packets
}

try {
    if(-not (Confirm-StoreScenarioAdapter)){throw 'The existing Bettbox adapter was unavailable before the fixture.'}
    Close-NormalFixture $session; $session=$null
    $policy.Dispose();$policy=$null
    if(-not (Confirm-StoreScenarioGateClosed)){throw 'The candidate fixture did not start with a closed native policy.'}
    Set-StoreWitness 'match' 'match'
    $serviceImage=Join-Path $stage 'fixture-witness-service.exe'
    [IO.File]::Copy($observer,$serviceImage)
    $servicePort=[GuardLoopbackLab]::FindPrivatePort()
    $witnessArgs='"'+(Join-Path $PSScriptRoot 'exit-observer-fixture.mjs')+'" serve '+$servicePort+' "'+$witnessSettings+'"'
    $witnessService=Start-GuardDailyChild $serviceImage $witnessArgs ''
    $serviceClock=[Diagnostics.Stopwatch]::StartNew()
    do{
        if($witnessService.Process.HasExited){throw "Local TLS witness exited. $($witnessService.ErrorOutput.GetAwaiter().GetResult())"}
        $listener=[Net.Sockets.TcpClient]::new()
        try{$listener.Connect([Net.IPAddress]::Loopback,$servicePort);break}catch{Start-Sleep -Milliseconds 100}finally{$listener.Dispose()}
    }while($serviceClock.Elapsed.TotalSeconds -lt 7)
    if($serviceClock.Elapsed.TotalSeconds -ge 7){throw 'The isolated TLS witness did not become ready.'}
    $echo.ConnectWitnessPort=$servicePort
    Save-GuardAdministratorJson (Join-Path $scenarioDir 'fixture.json') ([pscustomobject]@{
        Package=$replacement.Package;Family=$replacement.Family;ImageHash=$replacement.ImageSha256
        Policy=[ordered]@{
            Deployment=$replacement.Deployment;Sublayer=$replacement.Sublayer;AssignedWeight=$replacement.Weight
            Image=$image;PackageSid=$replacement.PackageSid;Relay=$relay;RelayPort=$relayPort;Observer=$observer
            Upstream='127.0.0.1';UpstreamPort=$echo.Port;BaselineKeys=$replacement.BaselineKeys;BootKeys=$replacement.BootKeys
        }
        Box=$sandboxieBox;CloseBarrier=$scenarioCloseName;RelayPid=$forward.Process.Id
        RelayStartUtc=$forward.Process.StartTime.ToUniversalTime().ToString('o')
    })
    $workerSource=Join-Path $PSScriptRoot 'native-store-controller-worker.ps1'
    Assert-GuardSandboxieAdministratorPath $workerSource
    $shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $workerArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$workerSource+'" -Directory "'+$scenarioDir+'"'
    $workerControl=Start-GuardDailyChild $shell $workerArgs ''
    $null=Wait-StoreScenario 'initially verified fixture' { (Read-StoreScenarioHealth).Gate -ceq 'Open' }
    $session=Start-NormalFixture
    $sessionId=$session.Process.Id
    if((Invoke-NormalCommand "open|$relayPort") -cne 'Echo'){throw 'The Store replacement could not use its approved route.'}
    $firstCloseId=(Read-StoreScenarioHealth).CloseId
    $null=Wait-StoreScenario 'a verified primary response during the active Store session' {
        (Read-StoreScenarioHealth).Session -ceq 'Active' -and (Read-StoreFixtureRecord 'observation-metrics.json').PrimaryProofs -gt 0
    }
    $scenario.NormalRequests=Read-StoreWitnessCounts
    if($scenario.NormalRequests.Primary -lt 1 -or $scenario.NormalRequests.Backup -ne 0){throw 'The backup received an unnecessary request.'}
    $initialClosures=(Read-StoreFixtureRecord 'gate-metrics.json').ClosedTransitions
    Set-StoreWitness 'timeout' 'match'
    $secondary=Wait-StoreScenario 'a timed-out primary and a real secondary HTTPS response through the same relay' {
        $observed=Read-StoreFixtureRecord 'observation-metrics.json'
        if($observed.BackupProofs -gt 0 -and (Read-StoreScenarioHealth).Gate -ceq 'Open'){$observed}
    }
    $scenario.SlowPrimaryRoundMs=$secondary.LastBackupDurationMs
    $scenario.BackupAfterPrimaryFailure=$scenario.SlowPrimaryRoundMs -ge 7000 -and
        $scenario.SlowPrimaryRoundMs -le (1000*$script:GuardDailyMaxLeaseSeconds) -and
        (Read-StoreFixtureRecord 'gate-metrics.json').ClosedTransitions -eq $initialClosures -and
        -not $session.Process.HasExited -and $session.Process.Id -eq $sessionId -and
        (Read-StoreScenarioHealth).CloseId -ceq $firstCloseId -and (Invoke-NormalCommand 'existing') -ceq 'Echo'
    if(-not $scenario.BackupAfterPrimaryFailure){throw 'The backup did not preserve the verified Store session.'}
    if([IO.File]::Exists((Join-Path $scenarioDir 'daily-notice.json')) -or
        [IO.File]::Exists((Join-Path $scenarioDir 'daily-last-guard-stop.json'))){
        throw 'A slow primary covered by the still-valid lease produced an unexpected notification.'
    }
    [IO.File]::WriteAllText($primaryOnly,'Only the primary witness is enabled')
    Set-StoreWitness 'match' 'match'
    $null=Wait-StoreScenario 'completion of a fresh primary-only query' {(Read-StoreFixtureRecord 'observation-metrics.json').PrimaryOnlyProofs -gt 0}
    $beforeOptOut=Read-StoreWitnessCounts
    Set-StoreWitness 'invalid' 'match'
    $null=Wait-StoreScenario 'a user-disabled backup and an unavailable primary' {
        $sample=Read-StoreScenarioHealth
        $sample.Gate -ceq 'Closed' -and $sample.Session -ceq 'Rechecking'
    }
    $afterOptOut=Read-StoreWitnessCounts
    $scenario.OptOutRequests=[pscustomobject]@{Primary=$afterOptOut.Primary-$beforeOptOut.Primary;Backup=$afterOptOut.Backup-$beforeOptOut.Backup}
    if($scenario.OptOutRequests.Primary -lt 1 -or $scenario.OptOutRequests.Backup -ne 0 -or $session.Process.HasExited -or
        -not (Confirm-StoreScenarioGateClosed)){throw 'The disabled backup or the uncertain-result pause failed.'}
    Set-StoreWitness 'match' 'match'
    [IO.File]::Delete($primaryOnly)
    $null=Wait-StoreScenario 'same process after restoring primary-only checks' {(Read-StoreScenarioHealth).Session -ceq 'Active'}
    $beforeBoth=Read-StoreWitnessCounts
    Set-StoreWitness 'invalid' 'invalid'
    $null=Wait-StoreScenario 'both external witnesses unavailable' {
        $sample=Read-StoreScenarioHealth
        $sample.Gate -ceq 'Closed' -and $sample.Session -ceq 'Rechecking' -and (Read-StoreWitnessCounts).Backup -gt $beforeBoth.Backup
    }
    $scenario.BothUnavailablePaused=-not $session.Process.HasExited -and (Confirm-StoreScenarioGateClosed) -and
        (Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable' -and -not [IO.File]::Exists($quitReceipt)
    if(-not $scenario.BothUnavailablePaused){throw 'Two uncertain results caused an unverified exit or a network opening.'}
    Set-StoreWitness 'match' 'match'
    $null=Wait-StoreScenario 'same session after both witnesses recover' {(Read-StoreScenarioHealth).Session -ceq 'Active'}
    if((Invoke-NormalCommand "open|$relayPort") -cne 'Echo'){throw 'The session did not recover after both witnesses failed.'}
    Set-StoreWitness 'reject' 'mismatch'
    $null=Wait-StoreScenario 'mismatched IPv4 from the backup' {
        $sample=Read-StoreScenarioHealth
        $sample.Exit -ceq 'Mismatch' -and $sample.Gate -ceq 'Closed' -and [IO.File]::Exists($quitReceipt)
    }
    if($session.Process.HasExited -or -not (Confirm-StoreScenarioGateClosed) -or
        (Invoke-NormalCommand 'existing') -cne 'Unavailable' -or (Invoke-NormalCommand "new|$relayPort") -cne 'Unavailable'){
        throw 'The candidate did not block the existing and new connections before stopping for a mismatched address.'
    }
    $mismatchBlockedAt=[datetime]::UtcNow
    $scenario.MismatchBlockReadbackUtc=$mismatchBlockedAt.ToString('o')
    if([IO.File]::Exists((Join-Path $scenarioDir 'daily-last-guard-stop.json'))){
        throw 'Wrong IPv4 was marked as stopped while the protected fixture was still alive.'
    }
    $null=$scenarioClose.Set()
    $null=Wait-StoreScenario 'confirmed exit and readable cause for a wrong IPv4' {
        $session.Process.WaitForExit(0) -and (Read-StoreFixtureRecord 'daily-last-guard-stop.json').Reason -ceq 'ExitChanged'
    }
    $scenario.MismatchStopped=$true
    $mismatchExitedAt=[GuardMsixProbe]::ReadCompletedExitUtc($session.Process,$session.StartedUtc)
    $scenario.MismatchProcessExitUtc=$mismatchExitedAt.ToString('o')
    if($mismatchExitedAt -le $mismatchBlockedAt){throw 'The wrong-address exit did not follow the native block readback.'}
    $mismatchStop=Read-StoreScenarioNotice -LastStop
    Confirm-StoreStopNotice $mismatchStop 'ExitChanged' $mismatchExitedAt
    $scenario.MismatchLastReason=$mismatchStop.Reason
    Close-NormalFixture $session; $session=$null
    Set-StoreWitness 'match' 'match'
    $null=Wait-StoreScenario 'ready for a manual reopen after wrong IPv4' {
        $sample=Read-StoreScenarioHealth
        $sample.Gate -ceq 'Open' -and $sample.Session -ceq 'Clear' -and $sample.CloseId -cne $firstCloseId
    }
    Confirm-StoreRecoveryNotice $mismatchStop
    [IO.File]::Delete($quitReceipt)
    $null=$scenarioClose.Reset()
    $session=Start-NormalFixture
    $sessionId=$session.Process.Id
    if((Invoke-NormalCommand "open|$relayPort") -cne 'Echo'){throw 'Manual reopen failed after a wrong address.'}
    $firstCloseId=(Read-StoreScenarioHealth).CloseId
    $null=Wait-StoreScenario 'active reopened session' {(Read-StoreScenarioHealth).Session -ceq 'Active'}
    $scenario.BackupCasesPassed=$true
    $pace=[Diagnostics.Stopwatch]::StartNew()
    [IO.File]::WriteAllText($holdWitness,'Synthetic neutral witness timeout')
    $closed=Wait-StoreScenario 'a proof timeout with no shutdown request' {
        $sample=Read-StoreScenarioHealth
        if($sample.Gate -ceq 'Closed' -and $sample.Session -ceq 'Rechecking'){$sample}
    }
    $scenario.ObservePauseMs=$pace.ElapsedMilliseconds
    $scenario.ProbeTimeoutNoExit=-not $session.Process.HasExited -and $session.Process.Id -eq $sessionId -and
        $closed.CloseId -ceq $firstCloseId -and -not (Test-Path -LiteralPath (Join-Path $scenarioDir 'quit-request.json'))
    $scenario.ProofExpiryBlocks=(Test-NormalRelay) -and (Confirm-StoreScenarioGateClosed) -and
        (Invoke-NormalCommand 'existing') -ceq 'Unavailable' -and (Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable'
    if(-not $scenario.ProbeTimeoutNoExit -or -not $scenario.ProofExpiryBlocks){throw 'The healthy Store session did not pause safely.'}
    $pauseNotice=Wait-StoreScenario 'a pause notification while the original window stays open' {
        $notice=Read-StoreScenarioNotice
        if($notice.Phase -ceq 'Paused'){$notice}
    }
    $pauseShown=Get-GuardDailyPresentation $pauseNotice (Get-StoreNoticeStatus $closed)
    if($pauseShown.Key -cne "$($pauseNotice.Id):pause" -or $pauseShown.Text -notlike '*窗口仍保留*' -or
        (Get-GuardDailyPresentation $pauseNotice (Get-StoreNoticeStatus $closed) @($pauseShown.Key))){
        throw 'A verified proof pause did not produce one notice that preserves the window.'
    }
    [IO.File]::Delete($holdWitness)
    $open=Wait-StoreScenario 'rechecking recovery' {
        $sample=Read-StoreScenarioHealth
        if($sample.Gate -ceq 'Open' -and $sample.Session -ceq 'Active'){$sample}
    }
    $scenario.SameProcessAfterRecheck=$open.CloseId -ceq $firstCloseId -and $session.Process.Id -eq $sessionId -and
        (Invoke-NormalCommand "open|$relayPort") -ceq 'Echo'
    if(-not $scenario.SameProcessAfterRecheck){throw 'The original Store session did not recover after the proof resumed.'}
    $null=Wait-StoreScenario 'a resumed notice for the same pause' {
        $notice=Read-StoreScenarioNotice
        if($notice.Phase -cne 'Resumed' -or $notice.Id -cne $pauseNotice.Id){return $false}
        $status=Get-StoreNoticeStatus (Read-StoreScenarioHealth)
        $shown=Get-GuardDailyPresentation $notice $status @($pauseShown.Key)
        $shown.Key -ceq "$($pauseNotice.Id):recovery" -and $shown.Text -like '*已恢复联网*'
    }

    $helperReceipt=(Invoke-NormalCommand "linger|$moved") -split '\|'
    if($helperReceipt.Count -ne 2 -or $helperReceipt[0] -cne 'LingerStarted' -or $helperReceipt[1] -notmatch '^[1-9][0-9]*$'){
        throw 'The Store fixture did not start its windowless helper.'
    }
    $lingering=Get-Process -Id ([int]$helperReceipt[1]) -ErrorAction Stop
    $null=Wait-StoreScenario 'the windowless helper in the fixture sandbox' {
        -not $lingering.HasExited -and [GuardInstalledSandboxieFixtureReadback]::Box($lingering.Id) -ceq $sandboxieBox
    }
    [IO.File]::WriteAllText($pausedExitCleanup,'Track the fixture sandbox during explicit exit')
    [IO.File]::WriteAllText($holdWitness,'Pause the fixture before closing its main window')
    $null=Wait-StoreScenario 'verified pause before manual exit' {
        $sample=Read-StoreScenarioHealth
        $sample.Gate -ceq 'Closed' -and $sample.Policy -ceq 'Verified' -and $sample.Session -ceq 'Rechecking'
    }
    if(-not (Confirm-StoreScenarioGateClosed)){throw 'The fixture network was not blocked before the manual exit.'}
    if((Invoke-NormalCommand 'quit-confirmed') -cne 'Quitting' -or -not $session.Process.WaitForExit(3000)){
        throw 'The Store fixture did not complete its normal exit while networking was paused.'
    }
    $scenario.PausedExitConfirmed=$true
    Close-NormalFixture $session; $session=$null
    if($lingering.HasExited -or [GuardInstalledSandboxieFixtureReadback]::Box($lingering.Id) -cne $sandboxieBox){
        throw 'The windowless helper did not reproduce the reported remnant.'
    }
    $paused=Read-StoreScenarioHealth
    if($paused.Gate -cne 'Closed' -or $paused.Policy -cne 'Verified' -or $paused.Session -cne 'Rechecking' -or
        $paused.CloseId -cne $firstCloseId){throw 'The paused session changed before the launcher cleanup request.'}
    $pausedClose=Get-GuardDailyCloseName $paused.CloseId
    $fixtureStatus=[pscustomobject]@{Generation=$paused.Generation;CloseName=$pausedClose;Policy=$paused.Policy
        Gate=$paused.Gate;RulesUtc=[datetime]::ParseExact($paused.RulesUtc,'o',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind)}
    $event=[Threading.EventWaitHandle]::OpenExisting($pausedClose)
    try{
        $null=$scenarioClose.Set()
        $ack=& {
            . (Join-Path $repo 'package\guard-runtime.ps1')
            function Get-GuardDailyStatus { $fixtureStatus }
            Request-GuardDailyGateClose $event $fixtureStatus.Generation $fixtureStatus.CloseName
        }
        $scenario.PausedExitCleanupSignal=$ack -eq $true -and $event.WaitOne(0)
        if(-not $scenario.PausedExitCleanupSignal){throw 'The launcher skipped the cleanup signal while networking was paused.'}
    }finally{$event.Dispose()}
    $null=Wait-StoreScenario 'verified cleanup of the windowless remnant' {
        $lingering.HasExited -and [GuardInstalledSandboxieFixtureReadback]::ProcessCount() -eq 0 -and
            (Confirm-StoreScenarioGateClosed)
    }
    $scenario.PausedExitClearedSandbox=$true
    [IO.File]::Delete($pausedExitCleanup)
    [IO.File]::Delete($quitReceipt)
    $null=$scenarioClose.Reset()
    [IO.File]::Delete($holdWitness)
    $null=Wait-StoreScenario 'ready for manual restart after paused exit' {
        $sample=Read-StoreScenarioHealth
        $sample.Gate -ceq 'Open' -and $sample.Session -ceq 'Clear' -and $sample.CloseId -cne $firstCloseId
    }
    if([GuardInstalledSandboxieFixtureReadback]::ProcessCount() -ne 0){throw 'The Store fixture automatically started after the manual exit.'}
    $afterManual=Read-StoreScenarioNotice -LastStop
    if($afterManual.Id -cne $mismatchStop.Id -or $afterManual.Utc -ne $mismatchStop.Utc -or $afterManual.Reason -cne $mismatchStop.Reason){
        throw 'Manual exit incorrectly replaced the confirmed stop history.'
    }
    $session=Start-NormalFixture
    $scenario.PausedExitManualReopen=(Invoke-NormalCommand "open|$relayPort") -ceq 'Echo'
    if(-not $scenario.PausedExitManualReopen){throw 'The Store fixture could not connect after being opened again.'}

    $pace.Restart()
    $echo.RejectTransport=$true
    $down=Wait-StoreScenario 'confirmed disconnected loopback upstream' {
        $sample=Read-StoreScenarioHealth
        if($sample.Reason -ceq 'UpstreamTransportDown' -and $sample.Gate -ceq 'Closed' -and
            (Test-Path -LiteralPath (Join-Path $scenarioDir 'quit-request.json'))){$sample}
    }
    $scenario.ObserveUpstreamMs=$pace.ElapsedMilliseconds
    $afterBlock=[Diagnostics.Stopwatch]::StartNew()
    $scenario.UpstreamFailureWhileAdapterUp=(Confirm-StoreScenarioAdapter) -and -not $forward.Process.HasExited
    if($session.Process.HasExited -or -not (Confirm-StoreScenarioGateClosed)){throw 'No verified closed policy before the protected fixture exit.'}
    $transportBlockedAt=[datetime]::UtcNow
    $scenario.TransportBlockReadbackUtc=$transportBlockedAt.ToString('o')
    $stray=Read-DirectPackets
    if($stray.TcpCount -or $stray.UdpCount){throw 'The direct receivers saw unexpected traffic before the recovery race.'}
    $normal=Confirm-StoreDirectControl
    $scenario.ReconnectControlTcp=$normal.TcpCount
    $scenario.ReconnectControlUdp=$normal.UdpCount
    for($retry=0;$retry -lt 3;$retry++){
        if($session.Process.HasExited -or (Invoke-NormalCommand 'existing') -cne 'Unavailable' -or
            (Invoke-NormalCommand "new|$relayPort") -cne 'Unavailable' -or (Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){
            throw 'The live protected substitute did not retry behind a closed policy.'
        }
        $attempt=Read-DirectPackets
        $scenario.ReconnectDirectAttempts++
        $scenario.ReconnectDirectTcp+=$attempt.TcpCount
        $scenario.ReconnectDirectUdp+=$attempt.UdpCount
    }
    if($scenario.ReconnectDirectTcp -or $scenario.ReconnectDirectUdp -or $session.Process.HasExited){
        throw 'Protected traffic reached a direct receiver during recovery.'
    }
    $echo.RejectTransport=$false
    $scenario.UpstreamClosedBeforeExit=(Test-NormalRelay) -and
        (Invoke-NormalCommand 'existing') -ceq 'Unavailable' -and (Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable'
    $beforeTransportExit=Read-StoreFixtureRecord 'daily-last-guard-stop.json'
    if($beforeTransportExit.Id -cne $mismatchStop.Id -or $beforeTransportExit.Reason -cne $mismatchStop.Reason){
        throw 'Transport failure was marked as stopped while the protected fixture was still alive.'
    }
    if((Read-StoreFixtureRecord 'quit-request.json').Id -ne $session.Process.Id -or $session.Process.WaitForExit(0)){
        throw 'The protected Store process was not alive at the release of the verified block barrier.'
    }
    $scenario.TransportBarrierReleasedUtc=[datetime]::UtcNow.ToString('o')
    $null=$scenarioClose.Set()
    $null=Wait-StoreScenario 'completed exit and recorded upstream fault for the same Store process' {
        $session.Process.WaitForExit(0) -and (Read-StoreFixtureRecord 'daily-last-guard-stop.json').Reason -ceq 'UpstreamTransportDown'
    }
    $scenario.ExitAfterConfirmedBlockMs=$afterBlock.ElapsedMilliseconds
    $transportExitUtc=[GuardMsixProbe]::ReadCompletedExitUtc($session.Process,$session.StartedUtc)
    $scenario.TransportProcessExitUtc=$transportExitUtc.ToString('o')
    if($transportExitUtc -le $transportBlockedAt){throw 'The transport-failure exit did not follow the native block readback.'}
    Close-NormalFixture $session; $session=$null
    $null=Wait-StoreScenario 'the recovered controller without a relaunch' {(Read-StoreScenarioHealth).Gate -ceq 'Open'}
    $null=Wait-StoreScenario 'verified stop history for the closed test upstream' {
        (Read-StoreFixtureRecord 'daily-last-guard-stop.json').Reason -ceq 'UpstreamTransportDown'
    }
    $transportStop=Read-StoreScenarioNotice -LastStop
    Confirm-StoreStopNotice $transportStop 'UpstreamTransportDown' $transportExitUtc
    $scenario.TransportLastReason=$transportStop.Reason
    Confirm-StoreRecoveryNotice $transportStop
    if(@(Get-Process -Name fixture-desktop -ErrorAction SilentlyContinue | Where-Object Path -IEQ $image).Count){
        throw 'The terminated fixture was automatically restarted.'
    }
    $session=Start-NormalFixture
    $scenario.ManualRecovery=(Invoke-NormalCommand "open|$relayPort") -ceq 'Echo' -and
        (Invoke-NormalCommand "new|$relayPort") -ceq 'Echo'
    if(-not $scenario.ManualRecovery){throw 'The replacement did not recover via an explicit Store activation.'}
    $scenario.NotificationsPassed=$true
    $null=Wait-StoreScenario 'active session on the registered Store replacement' {(Read-StoreScenarioHealth).Session -ceq 'Active'}
    $scenario.Stability=Invoke-StoreStability -AfterUpgrade:$AfterUpgrade

    $lastOpen=Read-StoreScenarioHealth
    $oldDeadline=[datetime]::ParseExact($lastOpen.Lease.ExpiresUtc,'o',[Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $workerControl.Process.Kill()
    if(-not $workerControl.Process.WaitForExit(5000)){throw 'The isolated WFP owner did not exit.'}
    $scenario.BackendExitBeforeProofExpiry=$workerControl.Process.ExitTime.ToUniversalTime() -lt $oldDeadline
    $scenario.BackendExitBlocksExistingAndNew=$scenario.BackendExitBeforeProofExpiry -and
        -not $session.Process.HasExited -and (Confirm-StoreScenarioGateClosed) -and (Test-NormalRelay) -and
        (Invoke-NormalCommand 'existing') -ceq 'Unavailable' -and (Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable'
    if(-not $scenario.BackendExitBlocksExistingAndNew){throw 'The surviving Store fixture could not prove blocking after the controller exited.'}
    [pscustomobject]$scenario
}catch{
    $scenario.Error=$_.Exception.Message
    $scenario.ErrorLine=$_.InvocationInfo.ScriptLineNumber
    throw
}finally{
    $null=$scenarioClose.Set()
    try{
        Stop-GuardDailyChild $workerControl
        Close-NormalFixture $session; $session=$null
        $echo.RejectTransport=$false
        $echo.ConnectWitnessPort=0
        Stop-GuardDailyChild $witnessService
    }finally{
        $scenarioClose.Dispose()
        [IO.File]::Delete($holdWitness)
        [IO.File]::Delete($pausedExitCleanup)
        [IO.File]::Delete($primaryOnly)
        if($lingering){$lingering.Dispose()}
        Save-GuardAdministratorJson (Join-Path $stage 'store-controller-scenarios.json') $scenario
    }
}
