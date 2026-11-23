#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. "$root\release\install-guard-helpers.ps1"

function Assert-ReleaseCase([bool]$Condition,[string]$Description) {
    if(-not $Condition){throw "FAIL $Description"}
    "PASS $Description"
}
function Invoke-IsolatedReleaseCase([string]$Failure,[switch]$BrokenRestore) {
    $events=[Collections.Generic.List[string]]::new()
    $result=[ordered]@{Phase='Preparing';FailedPhase=$null;Installed=$false;Restored=$false;Error=$null;RestoreError=$null}
    $operations=@{}
    foreach($name in 'Preflight','Backup','Close','Install','Verify','Commit'){
        $phase=$name
        $operations[$name]={
            $events.Add($phase)
            if($Failure -ceq $phase){throw "Synthetic $phase error"}
        }.GetNewClosure()
    }
    $operations.Publish={$events.Add('Publish '+$result.Phase)}.GetNewClosure()
    $operations.Restore={
        $events.Add('Restore prior closed policy')
        if($BrokenRestore){throw 'Synthetic restoration error'}
    }.GetNewClosure()
    Invoke-GuardReleaseChange $operations $result
    [pscustomobject]@{Result=$result;Events=$events.ToArray()}
}

$good=Invoke-IsolatedReleaseCase ''
$ordered=$good.Result.Installed -and -not $good.Result.Restored -and $good.Result.Phase -ceq 'Completed' -and
    ($good.Events -join ',') -ceq 'Preflight,Backup,Publish Close,Close,Publish Install,Install,Publish Verify,Verify,Publish Completed,Commit'
Assert-ReleaseCase $ordered 'installation backs up, closes protection, applies, and reports success after readiness'

foreach($failed in 'Preflight','Backup'){
    $case=Invoke-IsolatedReleaseCase $failed
    $rejected=-not $case.Result.Installed -and -not $case.Result.Restored -and $case.Result.Phase -ceq 'Rejected' -and
        'Close' -notin $case.Events -and 'Install' -notin $case.Events -and 'Restore prior closed policy' -notin $case.Events
    Assert-ReleaseCase $rejected "$failed failure never starts mutating the installed protection"
}
foreach($failed in 'Close','Install','Verify'){
    $case=Invoke-IsolatedReleaseCase $failed
    $restored=$case.Result.Phase -ceq 'RolledBack' -and $case.Result.FailedPhase -ceq $failed -and
        $case.Result.Restored -and -not $case.Result.Installed -and $case.Events[-2] -ceq 'Restore prior closed policy'
    Assert-ReleaseCase $restored "$failed failure runs and verifies the rollback"
}
$failedRestore=Invoke-IsolatedReleaseCase 'Verify' -BrokenRestore
$incomplete=$failedRestore.Result.Phase -ceq 'RollbackIncomplete' -and -not $failedRestore.Result.Restored -and
    -not $failedRestore.Result.Installed -and $failedRestore.Result.RestoreError -ceq 'Synthetic restoration error'
Assert-ReleaseCase $incomplete 'an incomplete recovery does not report that protection was restored'
$failedCommit=Invoke-IsolatedReleaseCase 'Commit'
Assert-ReleaseCase ($failedCommit.Result.Phase -ceq 'RolledBack' -and $failedCommit.Result.Restored) 'failure committing the receipt still runs the protected rollback'

$accepted=Get-GuardReleaseCanonicalIpv4 '203.0.113.6'
Assert-ReleaseCase ($accepted -ceq '203.0.113.6') 'the exact synthetic IPv4 is preserved'
foreach($invalid in '203.0.113.006','203.0.113.999','203.113.6','2001:db8::1'){
    $rejected=$false
    try{$null=Get-GuardReleaseCanonicalIpv4 $invalid}catch{$rejected=$true}
    Assert-ReleaseCase $rejected "alternate or invalid address $invalid is rejected"
}
$one=Get-GuardReleaseGeneration @('scope','package-v1','relay-first')
$two=Get-GuardReleaseGeneration @('scope','package-v1','relay-second')
$bound=$one -cmatch '\A[A-F0-9]{64}\z' -and $two -cne $one -and
    (Get-GuardReleaseGeneration @('scope','package-v1','relay-first')) -ceq $one
Assert-ReleaseCase $bound 'node changes produce a different stable deployment generation'

$plan=& "$root\release\install-guard.ps1" -Plan
$readOnly=$plan.Mode -cin 'Fresh','Update' -and $plan.RequiresAdministrator -and $plan.RequiresRegisteredStoreDesktop -and
    $plan.RequiresBettboxTunnel -and -not $plan.LaunchesDesktop -and -not $plan.Installed
Assert-ReleaseCase $readOnly 'public planning runs without administrator access or desktop launch'

& {
    . "$root\package\guard-daily.ps1"
    $systemShell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $digest='A'*64
    $testRoot=Join-Path ([IO.Path]::GetTempPath()) ('guard-runner-fixture-'+[guid]::NewGuid().ToString('N'))
    $testImage=Join-Path $testRoot ('release-install-'+('a'*32)+'\ClaudeGuardSetup.exe')
    $sample=[pscustomobject]@{
        Pending=$false;Event=$false;RunnerPresent=$false;ExpectedPid=19321;ReadError=$false
        Started=[datetime]::UtcNow.AddSeconds(-5);ActualStarted=[datetime]::MinValue;Disposed=0;Version=1
        Image=$systemShell;ExpectedHash=$digest;ActualHash=$digest;HashCalls=0;ActualOwner=$ownerSid
    }
    function Test-GuardDailyReleasePending {$sample.Pending}
    function Test-GuardDailyRevisionInProgress {$sample.Event}
    function Get-GuardDataPath($Name) {Join-Path $testRoot $Name}
    function Get-GuardDailyReleaseImageHash($Path) {
        if($Path -ine $testImage){throw 'Unexpected fixture path.'}
        $sample.HashCalls++
        $sample.ActualHash
    }
    function Get-CimInstance($ClassName,$Filter,$OperationTimeoutSec,$ErrorAction) {[pscustomobject]@{Id=$sample.ExpectedPid}}
    function Invoke-CimMethod($InputObject,$MethodName,$OperationTimeoutSec,$ErrorAction) {
        [pscustomobject]@{ReturnValue=0;Sid=$sample.ActualOwner}
    }
    function Read-GuardDailyRecord {
        param($Name)
        if($sample.ReadError -or $Name -cne 'release-install-pending.json'){throw 'Synthetic protected read failure.'}
        [pscustomobject]@{
            Version=$sample.Version;Stage='release-install-'+('a'*32);Operation=('b'*32);OwnerSid=$ownerSid
            RunnerPid=$sample.ExpectedPid;RunnerStartedUtc=$sample.Started.ToString('o');RunnerSha256=$sample.ExpectedHash
        }
    }
    function Get-Process {
        param($Id,$ErrorAction)
        if(-not $sample.RunnerPresent -or $Id -ne $sample.ExpectedPid){throw 'Synthetic absent runner.'}
        $process=[pscustomobject]@{
            ProcessName=[IO.Path]::GetFileNameWithoutExtension($sample.Image);Path=$sample.Image
            HasExited=$false;StartTime=$sample.ActualStarted;Tracker=$sample
        }
        $process | Add-Member ScriptMethod Dispose {$this.Tracker.Disposed++} -PassThru
    }
    Assert-ReleaseCase (Test-GuardDailyReleaseControllerMayRun) 'a normal controller starts with no pending install'
    $sample.Pending=$true
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'a pending reboot without the maintenance signal holds the controller closed'
    $sample.Event=$true
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'a stale pending install with a signal and no installer still holds the controller closed'
    $sample.RunnerPresent=$true
    $sample.ActualStarted=$sample.Started.AddTicks(1)
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'a process reusing the installer PID cannot open a pending controller'
    $sample.ActualStarted=$sample.Started
    Assert-ReleaseCase (Test-GuardDailyReleaseControllerMayRun) 'the same live installer PID and start time may run the verification controller'
    Assert-ReleaseCase ($sample.Disposed -eq 2) 'both available synthetic installer process handles are released'
    $sample.Version=2
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'a journal for the single-window installer rejects the legacy shell'
    $sample.Image=$testImage
    $sample.ActualHash='B'*64
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'a protected name alone cannot replace the pinned installer hash'
    $sample.ActualHash=$digest
    $sample.ActualOwner='S-1-5-21-1-2-3-4'
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'the pinned installer must run as the recorded Windows account'
    $sample.ActualOwner=$ownerSid
    Assert-ReleaseCase (Test-GuardDailyReleaseControllerMayRun) 'the pinned single-window process may verify the pending release'
    $hashed=$sample.HashCalls
    Assert-ReleaseCase ((Test-GuardDailyReleaseControllerMayRun) -and $sample.HashCalls -eq $hashed) 'a verified runner still checks process identity without hashing it in every cycle'
    $sample.ActualStarted=$sample.Started.AddTicks(1)
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'cached image verification cannot admit a reused process ID'
    $sample.ReadError=$true
    Assert-ReleaseCase (-not (Test-GuardDailyReleaseControllerMayRun)) 'an unreadable pending record holds the controller closed'
    function Get-GuardIsolationMode {'Off'}
    function Get-GuardDataPath {Join-Path ([IO.Path]::GetTempPath()) ('guard-release-unavailable-'+[guid]::NewGuid().ToString('N'))}
    $ordinary=Get-GuardDailyStatus
    $installer=Get-GuardDailyStatus -VerifyDuringRevision
    Assert-ReleaseCase (-not $ordinary.CanLaunch -and $ordinary.Reason -ceq 'RevisionInProgress' -and
        $installer.Reason -cne 'RevisionInProgress') 'ordinary launch stays locked by pending marker while the verifier may read runtime status'
}

& {
    . "$root\package\guard-daily.ps1"
    $source=Join-Path $root 'release\install-guard.ps1'
    $syntax=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$null,[ref]$null)
    foreach($name in 'Read-GuardReleaseProof','Test-GuardReleaseProofStatus','Wait-GuardReleaseReady'){
        $function=$syntax.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name},$true)
        . ([scriptblock]::Create($function.Extent.Text))
    }
    $fixture=[pscustomobject]@{Index=0;StatusChecks=0;WorkerChecks=0;Generation=('A'*64);CloseId=('c'*32)
        Started=[datetime]::UtcNow.AddSeconds(-30);Base=[datetime]::UtcNow.AddSeconds(-11)}
    $timeline=0,0,1,2,2,-1,3,3,4,5,6,7,8
    function Read-GuardDailyRecord($Name) {
        if($Name -cne 'daily-health.json'){throw 'Expected a health receipt'}
        $index=$timeline[$fixture.Index]
        $checked=$fixture.Base.AddMilliseconds(([math]::Max($index,0))*500)
        [pscustomobject]@{
            Version=2;Generation=$fixture.Generation;SupervisorId=100;SupervisorStartUtc=$fixture.Started.ToString('o')
            CloseId=$fixture.CloseId;Gate=$(if($index -lt 0){'Closed'}else{'Open'});Exit='Match';Reason='Verified'
            Policy='Verified';Inventory='Verified';Proxy='Ready';Session='Clear';Containment='Sandboxie'
            RulesUtc=$checked.AddMilliseconds(250).ToString('o')
            Admission=@{Period=$(if($index -ge 3){2}else{1});PreviousOverlapMilliseconds=6000
                RenewedUtc=$checked.AddMilliseconds(100).ToString('o')}
            Lease=@{Generation=$fixture.Generation;CheckedUtc=$checked.ToString('o');ExpiresUtc=$checked.AddSeconds(15).ToString('o')}
        }
    }
    function Get-GuardDailyStatus([switch]$VerifyDuringRevision) {
        $fixture.StatusChecks++
        $health=Read-GuardDailyRecord 'daily-health.json'
        $start=if($fixture.Index -eq 0){$fixture.Started.AddTicks(1)}else{$fixture.Started}
        $close=if($fixture.Index -eq 2){'d'*32}else{$fixture.CloseId}
        [pscustomobject]@{
            CanLaunch=[bool]$VerifyDuringRevision;Generation=$fixture.Generation;Containment='Sandboxie';SupervisorId=100
            SupervisorStartUtc=$start.ToString('o');CloseName=Get-GuardDailyCloseName $close
            AdmissionPeriod=$health.Admission.Period;LeaseCheckedUtc=$health.Lease.CheckedUtc
        }
    }
    function Get-GuardReleaseStoreWorkerStatus($Record,$Health) {
        $fixture.WorkerChecks++
        'Ready'
    }
    function Start-Sleep([int]$Milliseconds){
        if($fixture.Index -ge $timeline.Count-1){throw 'The fixture exhausted its receipts.'}
        $fixture.Index++
    }
    $diagnostics=[ordered]@{}
    $count=Wait-GuardReleaseReady $fixture $fixture.Started 6 -RequireStoreWorker -Diagnostics $diagnostics
    Assert-ReleaseCase ($count -eq 6 -and $diagnostics.TimeoutSeconds -eq 120 -and $diagnostics.ContinuityResets -eq 1 -and
        $diagnostics.FreshProofsObserved -eq 7 -and $diagnostics.MinimumNativeOverlapMs -gt 0 -and
        $diagnostics.MinimumReadableOverlapMs -gt 0 -and $diagnostics.WorkerStatus -ceq 'Ready' -and
        $fixture.StatusChecks -eq 9 -and $fixture.WorkerChecks -eq 2) 'verification rejects wrong runner or close signal, avoids repeated full scans, and restarts six proofs after a gap'
}
