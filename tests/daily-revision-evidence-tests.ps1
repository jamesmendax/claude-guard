#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\daily-revision-evidence.ps1"
. "$PSScriptRoot\..\package\guard-daily.ps1"

& {
    . "$PSScriptRoot\native-store-prestage-fixture.ps1"
    $null=Get-Command Invoke-GuardDailyStoreStage -CommandType Function -ErrorAction Stop
    Stop-GuardDailyChild $null
    $child=Start-GuardDailyChild (Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe') '/d /c echo GuardStoreFixtureReady' ''
    try{
        if(-not $child.Process.WaitForExit(5000) -or $child.Process.ExitCode -ne 0 -or
            $child.Output.GetAwaiter().GetResult().Trim() -cne 'GuardStoreFixtureReady'){
            throw 'The fresh Store fixture could not run and read its helper process.'
        }
    }finally{Stop-GuardDailyChild $child}
}
'PASS Standalone Store fixture loads its stage, starts its child and cleans up after an early error'

& {
    $fixture=(Get-Command "$PSScriptRoot\native-normal-package-lab.ps1").ScriptBlock.Ast
    $block=$fixture.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -ceq '$record.Upgrade.DirectBlocked'},$true)
    if(-not $block){throw 'No registered replacement direct-packet assertion was found.'}
    $body=$block.Parent.Statements
    $index=$body.IndexOf($block)
    if($index -lt 1 -or $body[$index-1].Right.Extent.Text -cne 'Read-DirectPackets'){
        throw 'The registered replacement check must read the direct-packet witness.'
    }
    $probe=[scriptblock]::Create($body[$index-1].Extent.Text+[Environment]::NewLine+$block.Extent.Text)
    foreach($enabled in $false,$true){
        & {
            param([switch]$AfterUpgrade)
            function Read-DirectPackets {[pscustomobject]@{Tcp=$false;Udp=$false}}
            $record=@{Upgrade=@{}}
            . $probe
            if($AfterUpgrade.IsPresent -ne $enabled -or $record.Upgrade.DirectBlocked -ne $true){
                throw 'The registered replacement witness changed the selected stability mode.'
            }
        } -AfterUpgrade:$enabled
    }
}
'PASS Actual replacement packet readback preserves both PowerShell switch modes'

function New-RevisionTestRecord {
    $before='2026-11-22T20:00:04.0000000Z'
    $blocked='2026-11-22T20:00:04.2000000Z'
    $registered='2026-11-22T20:00:04.8000000Z'
    $after='2026-11-22T20:00:05.0000000Z'
    $verified='2026-11-22T20:00:07.0000000Z'
    $package='GuardMsixFixture.'+('a'*32)+'_2.0.0.0_x64__8689sk8k9f0by'
    @{
        Passed=$true;SandboxieRestored=$true;UpgradeVerified=$true;ParentDirectBlocked=$true;ChildDirectBlocked=$true;DnsPolicyBlocked=$true
        StorePrestage=@{Passed=$true;FirstTcpBlocked=$true;FirstUdpBlocked=$true;RealPackageFirstActivation=$true
            OriginalV1ConnectedWhileArmed=$true;FirstRelayBlocked=$true;SameRegisteredPackageUnblocked=$true;IndependentCleanupVerified=$true}
        Upgrade=@{OldConnectedDuringPrestage=$true;ControlRemovedBeforeDeployment=$true;FuturePathReadBack=$true
            FirstTcpUdpBlocked=$true;FallbackBlockedWithOldAdmission=$true;NewConnectedAfterVerifiedHandoff=$true;RenamedHelperBlocked=$true
            RegisteredPackage=$package;VerifiedUtc=$verified
            OldAdmissionBeforeFirst=2;OldAdmissionAfterFirst=2;OldAdmissionBeforeFallback=2;OldAdmissionAfterFallback=2
            NoPrestageAttempt=@{RelayResult='Unavailable';Package=$package;FirstTcpUdpUtc=$after}
            ActualPrestage=@{Passed=$true;CandidateVerified=$true;MatchedAdd400=$true;StateStatus='Protected';RecordId574=101
                StateRecordId=101;RecordId400=103;NativeBootRules=4;Actual574=$before;RulesUtc=$blocked;Registered400=$registered
                First=@{RelayResult='Unavailable';Package=$package;InstallStartedUtc='2026-11-22T20:00:03.5000000Z'
                    AddReturnedUtc=$registered;FirstTcpUdpUtc=$after}}
            InterruptedHandoff=@{InstallExitCode=73;InstallPid=6;RecoverPid=7;PreCommitWeight=200;BootRules=4
                OfflineWhileInterrupted=$true;OfflineAfterRecovery=$true;SameClosedRules=$true;OldAdmissionClosed=$true;CleanupVerified=$true}}
        CandidateController=@{ProbeTimeoutNoExit=$true;ProofExpiryBlocks=$true;SameProcessAfterRecheck=$true;UpstreamFailureWhileAdapterUp=$true
            UpstreamClosedBeforeExit=$true;BackendExitBlocksExistingAndNew=$true;ManualRecovery=$true;PausedExitConfirmed=$true
            PausedExitCleanupSignal=$true;PausedExitClearedSandbox=$true;PausedExitManualReopen=$true;BackupCasesPassed=$true
            BackupAfterPrimaryFailure=$true;BothUnavailablePaused=$true;MismatchStopped=$true;NotificationsPassed=$true;SlowPrimaryRoundMs=8000
            ReconnectDirectAttempts=3;ReconnectControlTcp=1;ReconnectControlUdp=1;ReconnectDirectTcp=0;ReconnectDirectUdp=0
            MismatchLastReason='ExitChanged';TransportLastReason='UpstreamTransportDown';MismatchBlockReadbackUtc=$blocked
            MismatchProcessExitUtc=$after;TransportBlockReadbackUtc=$blocked;TransportProcessExitUtc=$after
            Stability=@{Passed=$true;RegisteredPackage=$package;StartedUtc='2026-11-22T20:00:08.0000000Z'
                ElapsedSeconds=3600;FalseExits=0;UnexpectedPauses=0;ClosedTransitions=0;DirectTcpPackets=0
                DirectUdpPackets=0;DirectChecks=60;ControlTcpPackets=60;ControlUdpPackets=60;Downloads=60
                ProofRenewals=300;MinimumNativeOverlapMilliseconds=1000;MinimumReadableOverlapMilliseconds=800}}
    }
}

function Test-RevisionRejection([string]$Label,[scriptblock]$Change){
    $record=New-RevisionTestRecord
    & $Change $record
    $rejected=$false
    try{Assert-DailyRevisionStoreEvidence $record 0}catch{$rejected=$true}
    if(-not $rejected){throw "The deployment accepted $Label."}
    Write-Output "PASS Rejects $Label"
}

$control=New-RevisionTestRecord
Assert-DailyRevisionStoreEvidence $control 0
'PASS Accepts a complete evidence contract from the isolated sample'
$handoff=New-RevisionTestRecord
$handoff.CandidateController=$null
$handoff.Upgrade.InterruptedHandoff.CleanupVerified=$false
Assert-DailyRevisionStoreUpgradeEvidence $handoff
'PASS Validates the full handoff before the controller scenarios and final fixture teardown'
$handoff.Upgrade.ActualPrestage.RulesUtc='2026-11-22T20:00:04.8010000Z'
$rejected=$false
try{Assert-DailyRevisionStoreUpgradeEvidence $handoff}catch{$rejected=$_.Exception.Message -like '*did not precede registration*'}
if(-not $rejected){throw 'The hour was allowed after named-path blocks arrived late, even though the first attempt was blocked.'}
'PASS Rejects late named-path arming at the handoff gate even when first traffic was blocked'
$early=New-RevisionTestRecord
$early.Upgrade.ActualPrestage.RulesUtc='2026-11-22T20:00:03.9000000Z'
$early.Upgrade.ActualPrestage.DirectoryNoticeUtc='2026-11-22T20:00:03.6000000Z'
$early.Upgrade.ActualPrestage.StagingStartedUtc='2026-11-22T20:00:03.7000000Z'
$early.Upgrade.ActualPrestage.DirectoryNoticePackage=$early.Upgrade.RegisteredPackage
$early.Upgrade.ActualPrestage.DirectoryNoticeRoot='C:\Program Files\WindowsApps\'+$early.Upgrade.RegisteredPackage
$early.Upgrade.ActualPrestage.DirectoryNoticeVerified=$true
Assert-DailyRevisionStoreUpgradeEvidence $early
'PASS Allows authenticated native arming before deploy event 574 for the same replacement'
$early.Upgrade.ActualPrestage.DirectoryNoticePackage='Other'
$rejected=$false
try{Assert-DailyRevisionStoreUpgradeEvidence $early}catch{$rejected=$true}
if(-not $rejected){throw 'Pre-event arming was accepted with a mismatched native notification.'}
'PASS Rejects a pre-event native notification for a different candidate'
Test-RevisionRejection 'unremoved replacement rules' {param($r) $r.Upgrade.InterruptedHandoff.CleanupVerified=$false}
Test-RevisionRejection 'a no-prestage result from a different replacement' {param($r) $r.Upgrade.NoPrestageAttempt.Package='Other'}
Test-RevisionRejection 'a full hour on a different Store registration' {param($r) $r.CandidateController.Stability.RegisteredPackage='Other'}
Test-RevisionRejection 'a soak started before the handoff' {param($r) $r.CandidateController.Stability.StartedUtc=$r.Upgrade.ActualPrestage.RulesUtc}
Test-RevisionRejection 'a fixture with a textual truth value' {param($r) $r.StorePrestage.FirstTcpBlocked='true'}
Test-RevisionRejection 'a missing independent MSIX cleanup receipt' {param($r) $r.StorePrestage.Remove('IndependentCleanupVerified')}
Test-RevisionRejection 'an unrelated Store completion event' {param($r) $r.Upgrade.ActualPrestage.MatchedAdd400=$false}
Test-RevisionRejection 'temporary blocks installed after registration' {param($r) $r.Upgrade.ActualPrestage.RulesUtc=$r.Upgrade.ActualPrestage.First.FirstTcpUdpUtc}
Test-RevisionRejection 'an old admission already expired during the fallback control' {param($r) $r.Upgrade.OldAdmissionAfterFallback=0}
Test-RevisionRejection 'a Store recovery replayed by the original owner' {param($r) $r.Upgrade.InterruptedHandoff.RecoverPid=$r.Upgrade.InterruptedHandoff.InstallPid}
Test-RevisionRejection 'a stop reported before the system block was verified' {param($r) $r.CandidateController.TransportProcessExitUtc=$r.CandidateController.TransportBlockReadbackUtc}
Test-RevisionRejection 'a protected UDP packet during reconnection' {param($r) $r.CandidateController.ReconnectDirectUdp=1}
Test-RevisionRejection 'a short Store run despite its success flag' {param($r) $r.CandidateController.Stability.ElapsedSeconds=3599.99}
Test-RevisionRejection 'an unobserved direct receiver during the soak' {param($r) $r.CandidateController.Stability.ControlTcpPackets=59}
Test-RevisionRejection 'a native admission gap hidden by an open health record' {param($r) $r.CandidateController.Stability.MinimumNativeOverlapMilliseconds=0}
Test-RevisionRejection 'a late readable Store renewal' {param($r) $r.CandidateController.Stability.MinimumReadableOverlapMilliseconds=-50}

$baselineStage='native-acceptance-'+('1'*32)
$baseline=@{Kind='PriorStoreHour';Passed=$true;SourceStage=$baselineStage
    ElapsedSeconds=3600.01;VerifiedFiles=79}
function New-RegressionExample {
    $r=New-RevisionTestRecord
    $s=$r.CandidateController.Stability
    foreach($entry in @{
        Kind='PostUpgradeRegression';MinimumSeconds=120;ElapsedSeconds=120.012;HealthChecks=61;ExistingChecks=12;NewChecks=12;IdleChecks=36
        Downloads=4;DownloadedBytes=262144;DirectChecks=4;ControlTcpPackets=4;ControlUdpPackets=4;ProofRenewals=24
        MinimumProofOverlapMilliseconds=800;PrimaryProofs=24;BackupProofs=0
    }.GetEnumerator()){$s[$entry.Key]=$entry.Value}
    $r
}
Assert-DailyRevisionStoreEvidence (New-RegressionExample) 0 $baseline $baselineStage 79
'PASS Accepts the source-bound historical hour with the complete new Store regression'
foreach($case in 'MissingBaseline','WrongStage','ShortBaseline','MissingControl','ShortRun','DirectPacket','ExpiredPermit'){
    $record=New-RegressionExample
    $prior=$baseline.Clone()
    switch($case){
        'MissingBaseline' {$prior=$null}
        'WrongStage' {$prior.SourceStage='Unrelated'}
        'ShortBaseline' {$prior.ElapsedSeconds=3599}
        'MissingControl' {$record.CandidateController.Stability.ControlUdpPackets=3}
        'ShortRun' {$record.CandidateController.Stability.ElapsedSeconds=119.99}
        'DirectPacket' {$record.CandidateController.Stability.DirectTcpPackets=1}
        'ExpiredPermit' {$record.CandidateController.Stability.MinimumNativeOverlapMilliseconds=0}
    }
    $rejected=$false
    try{Assert-DailyRevisionStoreEvidence $record 0 $prior $baselineStage 79}catch{$rejected=$true}
    if(-not $rejected){throw "The post-upgrade evidence accepted $case."}
    "PASS Rejects incomplete or unrelated incremental evidence ($case)"
}

$generation='C'*64
$start=[datetime]::SpecifyKind([datetime]'2026-11-22 20:00:00',[DateTimeKind]::Utc)
function Send-TestHealth($Monitor,[int]$Checked,[int]$Read,[int]$Period=1,$NativeMs=8000){
    $sample=@{Generation=$generation;Gate='Open';Policy='Verified';Inventory='Verified';Exit='Match';Reason='Verified'
        CloseId=('a'*32);SupervisorId=100;SupervisorStartUtc=$start.AddMinutes(-1).ToString('o')
        Lease=@{Generation=$generation;CheckedUtc=$start.AddSeconds($Checked).ToString('o');ExpiresUtc=$start.AddSeconds($Checked+15).ToString('o')}
        Admission=@{Period=$Period;RenewedUtc=$start.AddSeconds($Checked+1).ToString('o');PreviousOverlapMilliseconds=$NativeMs}
        RulesUtc=$start.AddSeconds($Checked+2).ToString('o')}
    Update-DailyRevisionProofMonitor $Monitor $sample $generation $start.AddSeconds($Read)
}
$monitor=New-DailyRevisionProofMonitor
foreach($second in 0,5,10,15,20,25){
    Send-TestHealth $monitor $second ($second+3)
    Send-TestHealth $monitor $second ($second+4)
}
if($monitor.Streak -ne 6 -or $monitor.Fresh -ne 6 -or $monitor.Trace.Count -ne 6 -or
    $monitor.MinimumReadable -ne 7000 -or $monitor.MinimumNative -ne 8000){throw 'The verifier miscounted genuinely continuous proofs.'}
'PASS Counts six distinct readable and native renewals from the same owner'
Send-TestHealth $monitor 36 41
if($monitor.Streak -ne 1 -or $monitor.Trace[6].ReadableOverlapMs -ne -1000){throw 'Late publication did not break the proof streak.'}
'PASS A proof seen at the endpoint before expiry still fails when read too late'
Send-TestHealth $monitor 41 44 2
if($monitor.Streak -ne 1){throw 'A native reopen was accepted as continuous.'}
Send-TestHealth $monitor 46 49 2 0
if($monitor.Streak -ne 1){throw 'Native expiry was accepted as continuous.'}
'PASS A reopened native permit or nonpositive native overlap breaks the streak'
Send-TestHealth $monitor 46 61 2
if($monitor.Streak -ne 0 -or $monitor.ExpiredSamples -ne 1 -or $monitor.LastState -cne 'ExpiredHealth'){throw 'Stale health was accepted.'}
Send-TestHealth $monitor 57 60 2
Update-DailyRevisionProofMonitor $monitor $null $generation $start.AddSeconds(62)
if($monitor.Streak -ne 0 -or $monitor.LastState -cne 'WaitingForGeneration'){throw 'Missing health preserved the streak.'}
'PASS Expired or unreadable health resets the streak and leaves a trace'
