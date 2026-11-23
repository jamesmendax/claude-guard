#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot/../package/guard-runtime.ps1"
. "$PSScriptRoot/../package/guard-daily-plan.ps1"
$controllerFile="$PSScriptRoot/../package/guard-daily-controller.ps1"
if(Test-Path -LiteralPath $controllerFile){. $controllerFile}

function Assert-Equal($expected,$actual){
    if($expected -cne $actual){throw "Expected [$expected], got [$actual]."}
}
function Test-Case([string]$name,[scriptblock]$test){
    try{& $test; $script:passed++; Write-Host "PASS $name"}
    catch{$script:failed++; Write-Host "FAIL ${name}: $($_.Exception.Message)"}
}
function New-Fixture{
    $state=@{Proxy='Ready';Exit='Match';Processes=0;Permit=$false;Events=(New-Object 'Collections.Generic.List[string]')
        Records=@{};FailClose=$false;FailWrite=$false;Stubborn=$false;ThrowProbe=$false;Generation=('A'*64);FailInventory=$false}
    $operations=@{
        ReadIsolation={'Off'}
        VerifyInventory={-not $state.FailInventory}.GetNewClosure()
        ReadPath={
            if($state.ThrowProbe){throw 'probe failed'}
            $now=[datetime]::UtcNow
            [pscustomobject]@{Proxy=$state.Proxy;Exit=$state.Exit
                Lease=@{Generation=$state.Generation;CheckedUtc=$now.ToString('o');ExpiresUtc=$now.AddSeconds(5).ToString('o')}}
        }.GetNewClosure()
        OpenVerified={ $state.Events.Add('permit'); $state.Permit=$true; $true }.GetNewClosure()
        CloseVerified={
            $state.Events.Add('revoke')
            if($state.FailClose){return $false}
            $state.Permit=$false; $true
        }.GetNewClosure()
        WriteRecord={
            param($name,$record)
            if($state.FailWrite){throw 'write failed'}
            $state.Events.Add($name)
            $state.Records[$name]=$record
        }.GetNewClosure()
        Snapshot={
            if($state.Processes){[pscustomobject]@{Id=410;Start=220}}
        }.GetNewClosure()
        RequestClose={param($entry)
            $state.Events.Add('request-exit')
            if($state.Permit){throw 'quit requested before permit was revoked'}
        }.GetNewClosure()
        Wait={param($milliseconds) $state.Events.Add("wait-$milliseconds")}.GetNewClosure()
        ForceStop={param($entry)
            $state.Events.Add('force-exit')
            if(-not $state.Stubborn){$state.Processes=0}
        }.GetNewClosure()
    }
    $mode=@{Generation=('A'*64);Port=18793;DesktopHashes=@('D'*64)
        ScopeName=('claude-guard-'+('1'*32));ScopeSid='S-1-15-2-21-22-23-24-25-26-27'}
    [pscustomobject]@{State=$state;Ops=$operations;Mode=$mode}
}
$script:passed=0
$script:failed=0

Test-Case 'Observed outage revokes the permit before closing the process' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true $controller.Decision.CanLaunch
        $f.State.Processes=1
        $f.State.Proxy='Down';$f.State.Exit='Unverified';$f.State.Events.Clear()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false $f.State.Permit
        Assert-Equal 0 $f.State.Processes
        Assert-Equal 'WaitingForProxy' $controller.Decision.Readiness
        Assert-Equal 'revoke,daily-health.json,daily-last-stop.json,request-exit,wait-5000,force-exit' ($f.State.Events -join ',')
        Assert-Equal 'Closed' $f.State.Records['daily-health.json'].Gate
        Assert-Equal 'ProxyNotReady' $f.State.Records['daily-last-stop.json'].Reason
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'Recovery rotates the close signal and publishes ready with no process launch' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $previous=$controller.Mode.CloseId
        $f.State.Processes=1
        $null=$controller.Signal.Set()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false $f.State.Permit
        Assert-Equal 0 $f.State.Processes
        Assert-Equal $previous $f.State.Records['daily-health.json'].CloseId
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true $controller.Decision.CanLaunch
        Assert-Equal 0 $f.State.Processes
        Assert-Equal $false ($previous -ceq $controller.Mode.CloseId)
        Assert-Equal $controller.Mode.CloseId $f.State.Records['daily-health.json'].CloseId
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'A surviving job owner delays recovery when the original executable has exited' {
    $f=New-Fixture
    $session=@{Busy=$false;Repairs=0}
    $f.Ops.LaunchSessionBusy={$session.Busy}.GetNewClosure()
    $f.Ops.AfterClosed={$session.Repairs++}.GetNewClosure()
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true $controller.Decision.CanLaunch
        $previous=$controller.Mode.CloseId
        $session.Busy=$true
        $null=$controller.Signal.Set()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'Closed' $controller.Gate
        $f.State.Events.Clear()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'ShutdownPending' $controller.Decision.Reason
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'ShutdownPending' $controller.Decision.Reason
        Assert-Equal $false ($f.State.Events.Contains('permit'))
        Assert-Equal $false $f.State.Permit
        Assert-Equal 0 $session.Repairs
        Assert-Equal $previous $controller.Mode.CloseId
        $session.Busy=$false
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true $controller.Decision.CanLaunch
        Assert-Equal $false ($previous -ceq $controller.Mode.CloseId)
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'Missing AppContainer binding prevents the controller from starting' {
    $f=New-Fixture
    $f.Mode.Remove('ScopeSid')
    $denied=$false
    try{
        $unexpected=New-GuardDailyController $f.Mode
        $unexpected.Signal.Dispose()
    }catch{$denied=$_.Exception.Message -like '*AppContainer binding*'}
    Assert-Equal $true $denied
}
Test-Case 'Sandboxie controller binds its status to the approved box and package' {
    $f=New-Fixture
    $f.Mode.Containment='Sandboxie'
    $f.Mode.ScopeName='GuardDesktop'
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'Sandboxie' $f.State.Records['daily-mode.json'].Containment
        Assert-Equal 'Sandboxie' $f.State.Records['daily-health.json'].Containment
        $f.Mode.ScopeName='UnrelatedBox'
        Assert-Equal $false (Test-GuardDailyScopeBinding $f.Mode)
        $f.State.FailInventory=$true
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false $f.State.Permit
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'An unverified observation pauses network permission without ending the same session' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $closeId=$controller.Mode.CloseId
        $f.State.Processes=1
        $f.State.ThrowProbe=$true
        $f.State.Events.Clear()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'Rechecking' $controller.Decision.Readiness
        Assert-Equal $false $f.State.Permit
        Assert-Equal $false $controller.Signal.WaitOne(0)
        Assert-Equal $false ($f.State.Events.Contains('request-exit') -or $f.State.Events.Contains('force-exit'))
        Assert-Equal 1 $f.State.Processes
        $f.State.ThrowProbe=$false
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true $f.State.Permit
        Assert-Equal $closeId $controller.Mode.CloseId
        Assert-Equal 1 $f.State.Processes
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'Closing the Desktop during a network pause cleans up its remaining boxed processes' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Processes=1
        $f.State.ThrowProbe=$true
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'Rechecking' $controller.Decision.Readiness
        Assert-Equal 1 $f.State.Processes
        $closeName=Get-GuardDailyCloseName $controller.Mode.CloseId
        function Get-GuardDailyStatus {
            [pscustomobject]@{Generation=$controller.Mode.Generation;CloseName=$closeName
                Policy='Verified';Gate=$controller.Gate;RulesUtc=[datetime]::UtcNow}
        }
        Assert-Equal $true (Request-GuardDailyGateClose $controller.Signal $controller.Mode.Generation $closeName)
        $f.State.Events.Clear()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false $f.State.Permit
        Assert-Equal $true ($f.State.Events.Contains('request-exit'))
        Assert-Equal $true ($f.State.Events.IndexOf('revoke') -lt $f.State.Events.IndexOf('request-exit'))
        Assert-Equal 0 $f.State.Processes
        $f.State.ThrowProbe=$false
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true $controller.Decision.CanLaunch
        Assert-Equal 0 $f.State.Processes
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'A confirmed failure during a recheck terminates the original session' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Processes=1
        $f.State.ThrowProbe=$true
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.ThrowProbe=$false
        $f.State.Proxy='Down'
        $f.State.Events.Clear()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true $controller.Signal.WaitOne(0)
        Assert-Equal $false $f.State.Permit
        Assert-Equal $true ($f.State.Events.IndexOf('revoke') -lt $f.State.Events.IndexOf('request-exit'))
        Assert-Equal 0 $f.State.Processes
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'The exit probe starts before the slower inventory check and publishes its fresh result' {
    $f=New-Fixture
    $f.Mode.RouteHash='E'*64
    $f.Mode.ExpectedIpv4='203.0.113.99'
    $proof=@{Started=$false;Finished=$false;Opened=$false}
    $relay=[pscustomobject]@{Ready=$true;ProcessId=450;Port=$f.Mode.Port;RouteHash=$f.Mode.RouteHash
        StartedUtc=[datetime]::UtcNow.AddMinutes(-1).ToString('o')}
    $halt=[Threading.ManualResetEvent]::new($false)
    try{
        $f.Ops.ReadRelay={$relay}.GetNewClosure()
        $f.Ops.ReadObservation={
            param($identity)
            if($proof.Finished){
                [pscustomobject]@{Generation=$f.Mode.Generation;RouteHash=$identity.RouteHash;RelayId=$identity.ProcessId
                    RelayStartedUtc=$identity.StartedUtc;CheckedUtc=[datetime]::UtcNow.ToString('o');HttpStatus=200
                    Ipv4=$f.Mode.ExpectedIpv4}
            }else{$proof.Started=$true}
        }.GetNewClosure()
        $f.Ops.VerifyInventory={$proof.Finished=$proof.Started;$true}.GetNewClosure()
        $f.Ops.OpenVerified={$proof.Opened=$true;$true}.GetNewClosure()
        $f.Ops.WriteRecord={param($name,$record) $null=$halt.Set()}.GetNewClosure()
        Start-GuardDailyHost $f.Mode $f.Ops $halt -StartProbeBeforeInventory
        Assert-Equal $true $proof.Opened
    }finally{$halt.Dispose()}
}
Test-Case 'A finished observer is collected after process inspection with both relay identity checks' {
    foreach($scenario in 'Fresh','Pending','Replaced','Unavailable'){
        $f=New-Fixture
        $f.Mode.RouteHash='E'*64
        $f.Mode.ExpectedIpv4='203.0.113.99'
        $now=[datetime]::UtcNow
        $relay=@{Ready=$true;ProcessId=450;Port=$f.Mode.Port;RouteHash=$f.Mode.RouteHash;StartedUtc=$now.AddMinutes(-1).ToString('o')}
        $prior=@{Generation=$f.Mode.Generation;RouteHash=$relay.RouteHash;RelayId=450;RelayStartedUtc=$relay.StartedUtc
            CheckedUtc=$now.AddMilliseconds(-10091).ToString('o');HttpStatus=200;Ipv4=$f.Mode.ExpectedIpv4}
        $next=$prior.Clone()
        $next.CheckedUtc=$now.ToString('o')
        $run=@{Inspected=$false;Collected=0;Granted=$null}
        $halt=[Threading.ManualResetEvent]::new($false)
        try{
            $f.Ops.ReadRelay={$relay.Clone()}.GetNewClosure()
            $f.Ops.ReadObservation={
                param($identity,$completedOnly)
                if(-not $completedOnly){return $prior}
                if(-not $run.Inspected){throw 'Early collection'}
                $run.Collected++
                if($scenario -ceq 'Replaced'){$relay.ProcessId++}
                $next
            }.GetNewClosure()
            $f.Ops.ObservationCompleted={
                if($scenario -ceq 'Unavailable'){throw 'Worker no longer readable'}
                $run.Inspected -and $scenario -cne 'Pending'
            }.GetNewClosure()
            $f.Ops.Snapshot={$run.Inspected=$true}.GetNewClosure()
            $f.Ops.OpenVerified={param($deadline,$signal) $run.Granted=$deadline.ToString('o');$true}.GetNewClosure()
            $f.Ops.WriteRecord={param($name,$record) $null=$halt.Set()}.GetNewClosure()
            Start-GuardDailyHost $f.Mode $f.Ops $halt -StartProbeBeforeInventory
            $expected=switch($scenario){Fresh{$now.AddSeconds(15).ToString('o')} Pending{$now.AddMilliseconds(-10091).AddSeconds(15).ToString('o')}}
            Assert-Equal $expected $run.Granted
            Assert-Equal ([int]($scenario -in 'Fresh','Replaced')) $run.Collected
        }finally{$halt.Dispose()}
    }
}
Test-Case 'A changed exit finishing during process inspection blocks the old session before requesting exit' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Processes=1
        $f.State.Events.Clear()
        $good=$f.Ops.ReadPath
        $f.Ops.ObservationCompleted={$true}
        $f.Ops.ReadPath={
            param($completedOnly)
            if($completedOnly){return @{Proxy='Ready';Exit='Mismatch'}}
            & $good
        }.GetNewClosure()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'ExitChanged' $controller.Decision.Reason
        Assert-Equal $false $f.State.Events.Contains('permit')
        Assert-Equal $true $f.State.Events.Contains('request-exit')
        Assert-Equal $true ($f.State.Events.IndexOf('revoke') -lt $f.State.Events.IndexOf('request-exit'))
        Assert-Equal 0 $f.State.Processes
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'A confirmed early outage keeps its precedence over a later good observation' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Processes=1
        $f.Ops.ReadEarlyPath={ [pscustomobject]@{Proxy='Down';Exit='Unverified';Failure='UpstreamTransportDown'} }
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'UpstreamTransportDown' $controller.Decision.Reason
        Assert-Equal $false $f.State.Permit
        Assert-Equal 0 $f.State.Processes
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'A process that will not exit keeps healthy recovery closed' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Processes=1; $f.State.Stubborn=$true
        $f.State.Proxy='Down'
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Proxy='Ready'
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'ShutdownPending' $controller.Decision.Reason
        Assert-Equal $false $f.State.Permit
        Assert-Equal 1 $f.State.Processes
        Assert-Equal $false $controller.Shutdown.Exited
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'A failed close readback cannot be advertised as closed or rearmed' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.FailClose=$true; $f.State.Proxy='Down'
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'Unknown' $controller.Gate
        Assert-Equal 'Unknown' $f.State.Records['daily-health.json'].Policy
        $f.State.Proxy='Ready'; $f.State.Events.Clear()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false ($f.State.Events.Contains('permit'))
        Assert-Equal $false $controller.Decision.CanLaunch
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'Old path evidence and a changed route both prohibit opening' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $f.State.Generation='B'*64
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false $controller.Decision.CanLaunch
        $f.State.Generation='A'*64; $f.State.Exit='Mismatch'
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'ExitChanged' $controller.Decision.Reason
        Assert-Equal $false $f.State.Permit
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'A publication error after opening revokes the permit and faults closed' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $f.State.FailWrite=$true
        $fault=$false
        try{$null=Invoke-GuardDailyControllerCycle $controller $f.Ops}catch{$fault=$true}
        Assert-Equal $true $fault
        Assert-Equal $false $f.State.Permit
        Assert-Equal 'Closed' $controller.Gate
    }finally{$controller.Signal.Dispose()}
}
if(-not ('GuardCycleWaitFixture' -as [type])){
    Add-Type -TypeDefinition @'
using System.Collections.Generic;
using System.Threading;
public sealed class GuardCycleWaitFixture : WaitHandle {
    public readonly List<int> Waits = new List<int>();
    public override bool WaitOne(int millisecondsTimeout) {
        Waits.Add(millisecondsTimeout);
        return Waits.Count == 2;
    }
}
'@
}
function Measure-FixtureControllerWait([int]$Interval,[int]$CheckMilliseconds,[bool]$Verified){
    $f=New-Fixture
    $f.Ops.VerifyInventory={
        [Threading.Thread]::Sleep($CheckMilliseconds)
        $Verified
    }.GetNewClosure()
    $controller=New-GuardDailyController $f.Mode
    $halt=[GuardCycleWaitFixture]::new()
    try{
        Start-GuardDailyController $controller $f.Ops $halt -PollMilliseconds $Interval
        Assert-Equal 2 $halt.Waits.Count
        Assert-Equal 0 $halt.Waits[0]
        Assert-Equal $Verified ($f.State.Events.Contains('permit'))
        $halt.Waits[1]
    }finally{$halt.Dispose();$controller.Signal.Dispose()}
}
Test-Case 'An open lease starts its next check immediately after a slow verified cycle' {
    Assert-Equal 0 (Measure-FixtureControllerWait 100 120 $true)
}
Test-Case 'A quick open cycle waits only for the unused portion of its polling interval' {
    $delay=Measure-FixtureControllerWait 3000 65 $true
    Assert-Equal $true ($delay -gt 0 -and $delay -le 2950)
}
Test-Case 'A closed gate keeps its full retry delay after a slow inspection' {
    Assert-Equal 100 (Measure-FixtureControllerWait 100 120 $false)
}

Test-Case 'Stopping the monitor loop revokes its admission' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    $halt=New-Object Threading.ManualResetEvent($false)
    $publish=$f.Ops.WriteRecord
    $f.Ops.WriteRecord={
        param($name,$record)
        & $publish $name $record
        if($name -ceq 'daily-health.json' -and $record.Gate -ceq 'Open'){$null=$halt.Set()}
    }.GetNewClosure()
    try{
        Start-GuardDailyController $controller $f.Ops $halt -PollMilliseconds 250
        Assert-Equal $false $f.State.Permit
        Assert-Equal 'Closed' $f.State.Records['daily-health.json'].Gate
    }finally{$halt.Dispose(); $controller.Signal.Dispose()}
}

Test-Case 'Close-event handling revokes the permit before it checks inventory' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $null=$controller.Signal.Set()
        $f.State.Events.Clear()
        $s=$f.State
        $f.Ops.VerifyInventory={ $s.Events.Add('inventory'); $true }.GetNewClosure()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'revoke' $f.State.Events[0]
        Assert-Equal 'inventory' $f.State.Events[1]
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'An unverified network block neither requests exit nor force-stops a live process' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Processes=1; $f.State.Proxy='Down'; $f.State.FailClose=$true
        $f.State.Events.Clear()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false ($f.State.Events.Contains('request-exit') -or $f.State.Events.Contains('force-exit'))
        Assert-Equal 1 $f.State.Processes
        Assert-Equal $false $controller.Shutdown.NetworkBlocked
        $f.State.FailClose=$false
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 0 $f.State.Processes
    }finally{$controller.Signal.Dispose()}
}
Test-Case 'An adapter receives the current lease deadline and its own close event' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $context=@{}
        $f.Ops.OpenVerified={param($deadline,$signal) $context.Deadline=$deadline; $context.Signal=$signal; $true}.GetNewClosure()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $true ($context.Deadline -is [datetime] -and $context.Deadline.Kind -eq 'Utc')
        Assert-Equal $true ([object]::ReferenceEquals($controller.Signal,$context.Signal))
        Assert-Equal $true $controller.Decision.CanLaunch
        Assert-Equal $null $f.State.Records['daily-health.json'].Admission
    }finally{$controller.Signal.Dispose()}
}

Add-Type -Path "$PSScriptRoot/../package/guard-wfp.cs","$PSScriptRoot/loopback-lab.cs"
Test-Case 'Only a successful admission readback publishes native continuity evidence' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $renewed=[datetime]::UtcNow
        $constructor=[ClaudeGuard.Network.AdmissionRenewal].GetConstructors([Reflection.BindingFlags]'Instance,NonPublic')[0]
        $receipt=$constructor.Invoke([object[]]@([long]4,$renewed,[double]1500))
        $f.Ops.OpenVerified={$receipt}.GetNewClosure()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $health=$f.State.Records['daily-health.json']
        Assert-Equal 'Open' $health.Gate
        Assert-Equal 4 $health.Admission.Period
        Assert-Equal ($renewed.ToString('o')) $health.Admission.RenewedUtc
        Assert-Equal 1500 $health.Admission.PreviousOverlapMilliseconds

        $f.Ops.OpenVerified={param($deadline,$signal) $null=$signal.Set();$receipt}.GetNewClosure()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $health=$f.State.Records['daily-health.json']
        Assert-Equal 'Closed' $health.Gate
        Assert-Equal $null $health.Admission
    }finally{$controller.Signal.Dispose()}
}
$first='C:\GuardFixture\First.exe'
$second='C:\GuardFixture\Second.exe'
$relay='C:\GuardFixture\Relay.exe'
$deployment=[guid]'94354d54-4c61-4f9a-93c8-f4d278428473'

Test-Case 'The same protected programs and endpoint reproduce the installed rule identities' {
    $a=[ClaudeGuard.Network.GuardPolicy]::Create(@($first,$second),@($first),@(),$null,$relay,18793,'203.0.113.10',443)
    $b=[ClaudeGuard.Network.GuardPolicy]::Create(@($second,$first.ToLowerInvariant()),@($first),@(),$null,$relay,18793,'203.0.113.10',443)
    $a=$a.ForPersistentUse($deployment)
    $b=$b.ForPersistentUse($deployment)
    Assert-Equal $false ($a.PersistentSublayer -eq [guid]::Empty)
    Assert-Equal $a.PersistentSublayer $b.PersistentSublayer
    Assert-Equal ($a.GetBaselineKeys() -join ',') ($b.GetBaselineKeys() -join ',')
}
Test-Case 'A package or endpoint change cannot reattach to the old protection' {
    $a=[ClaudeGuard.Network.GuardPolicy]::Create(@($first),@($first),@(),$null,$relay,18793,'203.0.113.10',443)
    $b=[ClaudeGuard.Network.GuardPolicy]::Create(@($first),@($first),@(),$null,$relay,18793,'203.0.113.11',443)
    $c=[ClaudeGuard.Network.GuardPolicy]::Create(@($first),@($first),@('S-1-15-2-12-23-34-45-56-67-78'),$null,$relay,18793,'203.0.113.10',443)
    $original=$a.ForPersistentUse($deployment)
    Assert-Equal $false ($original.PersistentSublayer -eq $b.ForPersistentUse($deployment).PersistentSublayer)
    Assert-Equal $false ($original.PersistentSublayer -eq $c.ForPersistentUse($deployment).PersistentSublayer)
    Assert-Equal 4 ($c.BaseCount-$a.BaseCount)
}

Test-Case 'Service coverage cannot accidentally target every Windows service' {
    $rejected=$false
    try{
        $null=[ClaudeGuard.Network.GuardPolicy]::Create(@($first),@($first),@(),'S-1-5-80-0',$relay,18793,'203.0.113.10',443)
    }catch{$rejected=$true}
    Assert-Equal $true $rejected
}

Test-Case 'Registered Cowork services contribute their own identities across path changes' {
    function Get-ItemProperty {
        param($LiteralPath,$ErrorAction)
        if($LiteralPath -like '*\CoworkVMServiceStore'){
            [pscustomobject]@{Type=0x210;ServiceSidType=1}
        }else{
            throw [Management.Automation.ItemNotFoundException]::new()
        }
    }
    function Resolve-GuardServiceSid {
        param($Name)
        Assert-Equal 'CoworkVMServiceStore' $Name
        'S-1-5-80-11-22-33-44-55'
    }
    $services=@(Get-GuardDailyServiceSids)
    Assert-Equal 'S-1-5-80-11-22-33-44-55' ($services -join ',')
    $unscoped=[ClaudeGuard.Network.GuardPolicy]::Create(@($first),@($first),@(),$null,$relay,18793,'203.0.113.10',443)
    $scoped=[ClaudeGuard.Network.GuardPolicy]::CreateWithServices(@($first),@($first),@(),$services,$relay,18793,'203.0.113.10',443,$null)
    $changed=[ClaudeGuard.Network.GuardPolicy]::CreateWithServices(@($second),@($second),@(),$services,$relay,18793,'203.0.113.10',443,$null)
    Assert-Equal 4 ($scoped.BaseCount-$unscoped.BaseCount)
    Assert-Equal $scoped.BaseCount $changed.BaseCount
    Assert-Equal $unscoped.AdmissionCount $scoped.AdmissionCount
    Assert-Equal $false ($scoped.ForPersistentUse($deployment).PersistentSublayer -eq $unscoped.ForPersistentUse($deployment).PersistentSublayer)
}

Test-Case 'A registered Cowork service without its own usable service SID blocks preparation' {
    function Get-ItemProperty { [pscustomobject]@{Type=0x210;ServiceSidType=0} }
    $rejected=$false
    try{ $null=Get-GuardDailyServiceSids }catch{ $rejected=$_.Exception.Message -like '*dedicated service identity*' }
    Assert-Equal $true $rejected
}

Test-Case 'Early boot rules are separate deterministic blocks without network permits' {
    $plan=[ClaudeGuard.Network.GuardPolicy]::Create(@($first),@($first),@(),$null,$relay,18793,'203.0.113.10',443)
    $ordinary=$plan.ForPersistentUse($deployment)
    $boot=$plan.WithEarlyBootBlocks().ForPersistentUse($deployment)
    $again=$plan.WithEarlyBootBlocks().ForPersistentUse($deployment)
    Assert-Equal 4 $boot.BootCount
    Assert-Equal $ordinary.BaseCount $boot.BaseCount
    Assert-Equal $ordinary.AdmissionCount $boot.AdmissionCount
    Assert-Equal $false ($ordinary.PersistentSublayer -eq $boot.PersistentSublayer)
    Assert-Equal ($boot.GetBootKeys() -join ',') ($again.GetBootKeys() -join ',')
    Assert-Equal 0 @($boot.GetBootKeys() | Where-Object { $_ -in $boot.GetBaselineKeys() }).Count
}

Test-Case 'The startup fixture protects only its exact image, with no shared port or permit' {
    $image='C:\GuardFixture\guard-boot-client.exe'
    $plan=[GuardLoopbackLab]::CreateStartupPlan($image,$deployment)
    $again=[GuardLoopbackLab]::CreateStartupPlan($image,$deployment)
    Assert-Equal 4 $plan.BaseCount
    Assert-Equal 2 $plan.BootCount
    Assert-Equal 0 $plan.AdmissionCount
    Assert-Equal $plan.PersistentSublayer $again.PersistentSublayer
    $fields=[Reflection.BindingFlags]'Instance,NonPublic'
    foreach($phase in 'Baseline','Boot'){
        foreach($rule in $plan.GetType().GetField($phase,$fields).GetValue($plan)){
            Assert-Equal $false $rule.GetType().GetField('Permit',$fields).GetValue($rule)
            $conditions=@($rule.GetType().GetField('Conditions',$fields).GetValue($rule))
            Assert-Equal 1 $conditions.Count
            Assert-Equal $image $conditions[0].GetType().GetField('Data',$fields).GetValue($conditions[0])
        }
    }
}

Test-Case 'An isolated launch permits one TCP proxy endpoint by container identity' {
    $containersid='S-1-15-2-21-22-23-24-25-26-27'
    $package='S-1-15-2-11-12-13-14-15-16-17'
    $plain=[ClaudeGuard.Network.GuardPolicy]::Create(@($first,$second),@($first,$second),@($package),$null,$relay,18793,'203.0.113.10',443)
    $isolated=[ClaudeGuard.Network.GuardPolicy]::CreateForAppContainer(@($first,$second),@($first,$second),@($package),@(),
        $containersid,$relay,18793,'203.0.113.10',443,$null)
    Assert-Equal ($plain.BaseCount+4) $isolated.BaseCount
    Assert-Equal 1 $isolated.AdmissionCount
    $fields=[Reflection.BindingFlags]'Instance,NonPublic'
    $rule=$isolated.GetType().GetField('Admission',$fields).GetValue($isolated)[0]
    $conditions=@($rule.GetType().GetField('Conditions',$fields).GetValue($rule))
    $actual=@($conditions | ForEach-Object { $_.GetType().GetField('Data',$fields).GetValue($_).ToString() })
    Assert-Equal ($containersid+',127.0.0.1,18793,6') ($actual -join ',')
    $rejected=$false
    try{
        $null=[ClaudeGuard.Network.GuardPolicy]::CreateForAppContainer(@($first),@($first),@($package),@(),
            $package,$relay,18793,'203.0.113.10',443,$null)
    }catch{$rejected=$_.Exception.InnerException.Message -like '*distinct*'}
    Assert-Equal $true $rejected
}

function New-PathObservationFixture {
    $now=[datetime]::UtcNow
    [pscustomobject]@{
        Now=$now
        Profile=@{Generation=('A'*64);RouteHash=('B'*64);Port=18793;ExpectedIpv4='203.0.113.99'}
        Relay=@{Ready=$true;RouteHash=('B'*64);Port=18793;ProcessId=512;StartedUtc=$now.AddMinutes(-1).ToString('o')}
        Observation=@{Generation=('A'*64);RouteHash=('B'*64);RelayId=512;RelayStartedUtc=$now.AddMinutes(-1).ToString('o')
            HttpStatus=200;Ipv4='203.0.113.99';CheckedUtc=$now.AddSeconds(-1).ToString('o')}
    }
}
Test-Case 'Only fresh exit evidence from the same relay earns a fixed expiry' {
    $f=New-PathObservationFixture
    $path=Get-GuardDailyPathDecision $f.Profile $f.Relay $f.Observation $f.Now
    Assert-Equal 'Ready' $path.Proxy
    Assert-Equal 'Match' $path.Exit
    Assert-Equal $f.Now.AddSeconds(14).ToString('o') $path.Lease.ExpiresUtc
    $again=Get-GuardDailyPathDecision $f.Profile $f.Relay $f.Observation $f.Now.AddSeconds(9)
    Assert-Equal $path.Lease.ExpiresUtc $again.Lease.ExpiresUtc
    $expired=Get-GuardDailyPathDecision $f.Profile $f.Relay $f.Observation $f.Now.AddSeconds(15)
    Assert-Equal $null $expired.Lease
}
Test-Case 'A dead or replaced relay and a changed public IPv4 all withhold permission' {
    $f=New-PathObservationFixture
    $f.Observation.Ipv4='203.0.113.100'
    $result=Get-GuardDailyPathDecision $f.Profile $f.Relay $f.Observation $f.Now
    Assert-Equal 'Mismatch' $result.Exit
    Assert-Equal $null $result.Lease
    $f.Observation.Ipv4=$f.Profile.ExpectedIpv4
    $f.Relay.ProcessId=513
    Assert-Equal $null (Get-GuardDailyPathDecision $f.Profile $f.Relay $f.Observation $f.Now).Lease
    $f.Relay.ProcessId=512
    $f.Relay.Ready=$false
    Assert-Equal 'Down' (Get-GuardDailyPathDecision $f.Profile $f.Relay $f.Observation $f.Now).Proxy
}

Test-Case 'Only a current transport failure from the same relay can trigger a hard outage' {
    $f=New-PathObservationFixture
    $failure=$f.Observation.Clone()
    $failure.Remove('HttpStatus')
    $failure.Remove('Ipv4')
    $failure.Fault='UpstreamTransportDown'
    Assert-Equal 'Unknown' (Get-GuardDailyPathDecision $f.Profile $f.Relay $null $f.Now).Proxy
    $decision=Get-GuardDailyPathDecision $f.Profile $f.Relay $failure $f.Now
    Assert-Equal 'Down' $decision.Proxy
    Assert-Equal 'UpstreamTransportDown' $decision.Failure
    Assert-Equal $null $decision.Lease
    $failure.RelayId++
    Assert-Equal 'Unknown' (Get-GuardDailyPathDecision $f.Profile $f.Relay $failure $f.Now).Proxy
}

function New-ObservationFixture {
    $work=@{Finished=$false;NextProof=$null;Started=0;Stopped=0}
    $ops=@{
        Start={param($relay) $work.Started++; [pscustomobject]@{Id=$work.Started}}.GetNewClosure()
        Poll={param($worker,$relay) [pscustomobject]@{Finished=$work.Finished;Proof=$work.NextProof}}.GetNewClosure()
        Stop={param($worker) $work.Stopped++}.GetNewClosure()
    }
    [pscustomobject]@{Cache=@{ProcessId=0;StartedUtc='';RouteHash='';AttemptUtc=[datetime]::MinValue;Proof=$null;Worker=$null}
        Work=$work;Ops=$ops}
}

Test-Case 'A slow observation can be in flight while a healthy relay keeps its previous proof' {
    $f=New-PathObservationFixture
    $fixture=New-ObservationFixture
    $cache=$fixture.Cache
    $ops=$fixture.Ops
    Assert-Equal $null (Get-GuardDailyObservation $cache $f.Relay $ops $f.Now)
    $fixture.Work.Finished=$true
    $fixture.Work.NextProof=$f.Observation
    $prior=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(1)
    $fixture.Work.Finished=$false
    $retry=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(12)
    Assert-Equal 2 $fixture.Work.Started
    Assert-Equal 1 $fixture.Work.Stopped
    Assert-Equal $prior.CheckedUtc $retry.CheckedUtc
    $deadline=(Get-GuardDailyPathDecision $f.Profile $f.Relay $retry $f.Now.AddSeconds(12)).Lease.ExpiresUtc
    Assert-Equal $f.Now.AddSeconds(14).ToString('o') $deadline
    Assert-Equal $null (Get-GuardDailyPathDecision $f.Profile $f.Relay $retry $f.Now.AddSeconds(15)).Lease
    $fresh=$f.Observation.Clone()
    $fresh.CheckedUtc=$f.Now.AddSeconds(13).ToString('o')
    $fixture.Work.Finished=$true
    $fixture.Work.NextProof=$fresh
    $retry=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(13)
    Assert-Equal $f.Now.AddSeconds(28).ToString('o') (Get-GuardDailyPathDecision $f.Profile $f.Relay $retry $f.Now.AddSeconds(13)).Lease.ExpiresUtc
}

Test-Case 'A late poll starts no request and a timed-out response retains only the old deadline' {
    $f=New-PathObservationFixture
    $fixture=New-ObservationFixture
    $cache=$fixture.Cache
    $ops=$fixture.Ops
    Assert-Equal $null (Get-GuardDailyObservation $cache $f.Relay $ops $f.Now -PollOnly)
    Assert-Equal 0 $fixture.Work.Started
    $null=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now
    $fixture.Work.Finished=$true
    $fixture.Work.NextProof=$f.Observation
    $prior=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(5) -PollOnly
    Assert-Equal 1 $fixture.Work.Started
    $null=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(5)
    $fixture.Work.NextProof=$null
    $retry=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(11) -PollOnly
    Assert-Equal 2 $fixture.Work.Started
    Assert-Equal $prior.CheckedUtc $retry.CheckedUtc
    Assert-Equal $f.Now.AddSeconds(14).ToString('o') (Get-GuardDailyPathDecision $f.Profile $f.Relay $retry $f.Now.AddSeconds(12)).Lease.ExpiresUtc
    $f.Relay.ProcessId++
    Assert-Equal $null (Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(12) -PollOnly)
    Assert-Equal 2 $fixture.Work.Started
}
Test-Case 'An overdue worker is discarded and a relay replacement invalidates proof and pending work' {
    $f=New-PathObservationFixture
    $fixture=New-ObservationFixture
    $cache=$fixture.Cache
    $ops=$fixture.Ops
    $null=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now
    Assert-Equal $null (Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds($script:GuardDailyMaxLeaseSeconds))
    Assert-Equal 1 $fixture.Work.Stopped
    Assert-Equal 2 $fixture.Work.Started
    $fixture.Work.Finished=$true
    $fixture.Work.NextProof=$f.Observation
    $f.Relay.ProcessId++
    Assert-Equal $null (Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds($script:GuardDailyMaxLeaseSeconds+1))
    Assert-Equal 2 $fixture.Work.Stopped
    Assert-Equal 3 $fixture.Work.Started
}

Test-Case 'A valid observation of a changed exit overrides the cached known exit' {
    $f=New-PathObservationFixture
    $fixture=New-ObservationFixture
    $cache=$fixture.Cache
    $ops=$fixture.Ops
    $null=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now
    $fixture.Work.Finished=$true
    $fixture.Work.NextProof=$f.Observation
    $null=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(1)
    $fixture.Work.Finished=$false
    $null=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(5)
    $changed=$f.Observation.Clone()
    $changed.Ipv4='203.0.113.100'
    $changed.CheckedUtc=$f.Now.AddSeconds(6).ToString('o')
    $fixture.Work.Finished=$true
    $fixture.Work.NextProof=$changed
    $fresh=Get-GuardDailyObservation $cache $f.Relay $ops $f.Now.AddSeconds(6)
    Assert-Equal 'Mismatch' (Get-GuardDailyPathDecision $f.Profile $f.Relay $fresh $f.Now.AddSeconds(6)).Exit
}

Test-Case 'The host rechecks relay identity before opening and never launches the desktop' {
    foreach($replace in @($false,$true)){
        $fixtures=New-Fixture
        $observation=New-PathObservationFixture
        $fixtures.Mode.RouteHash=$observation.Profile.RouteHash
        $fixtures.Mode.ExpectedIpv4=$observation.Profile.ExpectedIpv4
        $state=$fixtures.State
        $relayState=$observation.Relay
        $sample=$observation.Observation
        $halt=[Threading.ManualResetEvent]::new($false)
        try{
            $fixtures.Ops.ReadRelay={ $relayState }.GetNewClosure()
            $fixtures.Ops.ReadObservation={
                if($replace){$relayState.ProcessId++}
                $sample
            }.GetNewClosure()
            $fixtures.Ops.WriteRecord={ param($name,$record) $state.Records[$name]=$record; $null=$halt.Set() }.GetNewClosure()
            Start-GuardDailyHost $fixtures.Mode $fixtures.Ops $halt
            Assert-Equal (-not $replace) ($state.Events.Contains('permit'))
            Assert-Equal $false $state.Permit
            Assert-Equal 0 $state.Processes
        }finally{$halt.Dispose()}
    }
}

Test-Case 'Only the registered version images can use a live package-family relay lease' {
    $main='C:\GuardFixture\v1\desktop.exe'
    $helper='C:\GuardFixture\v1\worker.exe'
    $future='C:\GuardFixture\v2\desktop.exe'
    $sid='S-1-15-2-21-22-23-24-25-26-27'
    $base=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage([string[]]@($main,$helper),[string[]]@($main),
        [string[]]@($sid),$null,$sid,'C:\GuardFixture\relay.exe',18793,'203.0.113.10',443,'C:\GuardFixture\observer.exe'
    ).WithEarlyBootBlocks().ForPersistentUse([guid]::NewGuid())
    $versioned=$base.WithRegisteredPackageAdmission([string[]]@($helper,$main,$main))
    Assert-Equal $base.PersistentSublayer $versioned.PersistentSublayer
    Assert-Equal ($base.GetBaselineKeys() -join ',') ($versioned.GetBaselineKeys() -join ',')
    Assert-Equal ($base.GetBootKeys() -join ',') ($versioned.GetBootKeys() -join ',')
    Assert-Equal 2 $versioned.AdmissionCount
    $attributes=[Reflection.BindingFlags]'Instance,NonPublic'
    $rules=$base.GetType().GetField('Admission',$attributes)
    $original=@($rules.GetValue($base))[0]
    $conditionField=$original.GetType().GetField('Conditions',$attributes)
    $originalConditions=$conditionField.GetValue($original)
    $field=$originalConditions[0].GetType().GetField('Field',$attributes)
    $value=$originalConditions[0].GetType().GetField('Data',$attributes)
    $paths=@(foreach($rule in $rules.GetValue($versioned)){
        $conditions=$conditionField.GetValue($rule)
        Assert-Equal ($originalConditions.Count+1) $conditions.Count
        for($i=0;$i -lt $originalConditions.Count;$i++){
            Assert-Equal ($field.GetValue($originalConditions[$i])) ($field.GetValue($conditions[$i+1]))
            Assert-Equal ($value.GetValue($originalConditions[$i]).ToString()) ($value.GetValue($conditions[$i+1]).ToString())
        }
        $value.GetValue($conditions[0])
    })
    Assert-Equal (@($main,$helper) -join ',') ($paths -join ',')
    $denied=$false
    try{$null=$base.WithRegisteredPackageAdmission([string[]]@($future))}catch{$denied=$true}
    Assert-Equal $true $denied
}
Test-Case 'A replacement image at the same path invalidates the approved inventory' {
    $path='C:\GuardFixture\Claude.exe'
    $approved=[pscustomobject]@{Path=$path;Hash=('A'*64)}
    Assert-Equal $true (Test-GuardDailyDesktopImages @($approved) @($approved))
    $new=[pscustomobject]@{Path=$path;Hash=('B'*64)}
    Assert-Equal $false (Test-GuardDailyDesktopImages @($approved) @($new))
    Assert-Equal $false (Test-GuardDailyDesktopImages @($approved) @($approved,$approved))
}
Test-Case 'Automatic maintenance accepts a newer version of the same registered Store application only' {
    $prefix='AnthropicPBC.Claude_'
    $suffix='_x64__fnn82j28hfe8t'
    $scope='S-1-15-2-21-22-23-24-25-26-27'
    $appId='AnthropicPBC.Claude_fnn82j28hfe8t!Claude'
    $previous=@{Containment='Sandboxie';PackageFullName=($prefix+'1.2.3.4'+$suffix);ScopeSid=$scope;AppId=$appId}
    $current=@{PackageFullName=($prefix+'1.2.4.0'+$suffix);PackageSid=$scope;AppId=$appId}
    Assert-Equal $true (Test-GuardDailyStoreUpgrade $previous $current)
    $current.AppId+='Helper'
    Assert-Equal $false (Test-GuardDailyStoreUpgrade $previous $current)
    $current.AppId=$appId
    $current.PackageFullName=$prefix+'1.2.3.2'+$suffix
    Assert-Equal $false (Test-GuardDailyStoreUpgrade $previous $current)
    $current.PackageFullName=$prefix+'1.2.4.0'+$suffix
    $current.PackageSid='S-1-15-2-21-22-23-24-25-26-28'
    Assert-Equal $false (Test-GuardDailyStoreUpgrade $previous $current)
}
Test-Case 'A version change recovers the exact old policy paths without reading removed files' {
    $oldName='AnthropicPBC.Claude_1.2.3.4_x64__fnn82j28hfe8t'
    $newName='AnthropicPBC.Claude_1.2.4.0_x64__fnn82j28hfe8t'
    $record=[pscustomobject]@{PackageFullName=$oldName}
    $app=@{PackageFullName=$newName}
    $exe="C:\Program Files\WindowsApps\$newName\app\Claude.exe"
    $helper='C:\GuardFixture\helper.exe'
    $current=[pscustomobject]@{Programs=@($exe,$helper);DesktopPaths=@($exe);Packages=@()}
    $recovered=Get-GuardDailyRecordedInventory $record $current $app
    Assert-Equal ("C:\Program Files\WindowsApps\$oldName\app\Claude.exe") $recovered.DesktopPaths[0]
    Assert-Equal $helper $recovered.Programs[1]
    $saved=[pscustomobject]@{Programs=@('C:\Worker\retired.exe');DesktopPaths=@($helper);Packages=@()}
    $record | Add-Member -NotePropertyName PolicyInventory -NotePropertyValue $saved
    $recovered=Get-GuardDailyRecordedInventory $record $current $app
    Assert-Equal $saved.Programs[0] $recovered.Programs[0]
}
Test-Case 'Relay recovery waits for verified closure and exit of the old application' {
    $f=New-Fixture
    $controller=New-GuardDailyController $f.Mode
    try{
        $s=$f.State
        $f.Ops.AfterClosed={$s.Events.Add('relay-recovery')}.GetNewClosure()
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        $f.State.Processes=1; $f.State.Proxy='Down'; $f.State.FailClose=$true
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false $s.Events.Contains('relay-recovery')
        $f.State.FailClose=$false; $f.State.Stubborn=$true
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal $false $s.Events.Contains('relay-recovery')
        $f.State.Stubborn=$false
        $null=Invoke-GuardDailyControllerCycle $controller $f.Ops
        Assert-Equal 'relay-recovery' ($s.Events | Select-Object -Last 1)
        Assert-Equal 0 $s.Processes
    }finally{$controller.Signal.Dispose()}
}

Write-Host "RESULT Passed=$script:passed Failed=$script:failed"
if($script:failed){exit 1}

