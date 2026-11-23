#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\daily-revision-evidence.ps1"
. "$PSScriptRoot\daily-revision-baseline.ps1"

function Assert-BaselineRejection([scriptblock]$Operation,[string]$Expected){
    try{& $Operation | Out-Null}
    catch{
        if($_.Exception.Message -notlike "*$Expected*"){throw}
        "PASS rejects $Expected"
        return
    }
    throw "Expected rejection of $Expected."
}

function New-BaselineReceiptFixture {
    $zero=[datetime]::new(2026,11,23,8,0,0,[DateTimeKind]::Utc)
    $stability=[pscustomobject]@{
        Version=1;State='Passed';Passed=$true;MinimumSeconds=3600;ElapsedSeconds=3600.5
        StartedUtc=$zero.AddSeconds(10).ToString('o');EndedUtc=$zero.AddSeconds(3610.5).ToString('o')
        ProcessId=1;ProcessStartedUtc=$zero.AddSeconds(9).ToString('o');HealthChecks=1801;MaximumHealthGapMilliseconds=2100
        FalseExits=0;UnexpectedPauses=0;ClosedTransitions=0;DirectChecks=60;DirectTcpPackets=0;DirectUdpPackets=0
        ControlTcpPackets=60;ControlUdpPackets=60;Downloads=60;DownloadedBytes=3932160;ProofRenewals=640
        MinimumNativeOverlapMilliseconds=9000;MinimumReadableOverlapMilliseconds=8000;Error=$null
    }
    $controller=[pscustomobject]@{
        MismatchStopped=$true;UpstreamFailureWhileAdapterUp=$true;UpstreamClosedBeforeExit=$true
        BackendExitBlocksExistingAndNew=$true;ProofExpiryBlocks=$true;BothUnavailablePaused=$true
        MismatchLastReason='ExitChanged';TransportLastReason='UpstreamTransportDown'
        MismatchBlockReadbackUtc=$zero.AddSeconds(1).ToString('o');MismatchProcessExitUtc=$zero.AddSeconds(2).ToString('o')
        TransportBlockReadbackUtc=$zero.AddSeconds(3).ToString('o');TransportProcessExitUtc=$zero.AddSeconds(4).ToString('o')
        Stability=$stability;Error=$null
    }
    $upgrade=[pscustomobject]@{
        FirstTcpUdpBlocked=$true;FallbackBlockedWithOldAdmission=$true;NewConnectedAfterVerifiedHandoff=$true;RenamedHelperBlocked=$true
        ActualPrestage=[pscustomobject]@{
            Passed=$false;StateStatus='Protected';CandidateVerified=$true;MatchedAdd400=$true;NativeBootRules=4
            Received574=$zero.AddSeconds(3611).ToString('o');Registered400=$zero.AddSeconds(3612).ToString('o')
            RulesUtc=$zero.AddSeconds(3613).ToString('o')
            First=[pscustomobject]@{FirstTcpUdpUtc=$zero.AddSeconds(3614).ToString('o');RelayResult='Unavailable'}
        }
    }
    $lab=[pscustomobject]@{
        Phase='Completed';Passed=$false;UpgradeVerified=$false;Error=$null;CleanupErrors=@()
        HealthyProxy=$true;ParentDirectBlocked=$true;ChildDirectBlocked=$true;DnsPolicyBlocked=$true;ExistingFlowBlocked=$true
        NewFlowBlocked=$true;ExitedAfterBlock=$true;ManualRecovery=$true;Cleanup=$true;SandboxieRestored=$true
        Upgrade=$upgrade;CandidateController=$controller
    }
    $revision=[pscustomobject]@{
        Phase='StoreSubstitute';Passed=$false;Switched=$false;Restored=$true;ProxyContinuous=$true
        Fixture=$controller;Upgrade=$upgrade;StartedUtc=$zero.ToString('o');CompletedUtc=$zero.AddSeconds(3615).ToString('o')
    }
    [pscustomobject]@{Revision=$revision;Lab=$lab;Controller=$controller;Stability=$stability}
}

function Test-BaselineReceiptChange([scriptblock]$Change,[string]$Expected){
    $fixture=New-BaselineReceiptFixture
    & $Change $fixture
    Assert-BaselineRejection {
        Assert-DailyRevisionBaselineReceipts $fixture.Revision $fixture.Lab $fixture.Controller $fixture.Stability
    } $Expected
}

$fixture=New-BaselineReceiptFixture
Assert-DailyRevisionBaselineReceipts $fixture.Revision $fixture.Lab $fixture.Controller $fixture.Stability
'PASS accepts independently verified hour and two shutdowns despite the late registration'
Test-BaselineReceiptChange {param($f) $f.Stability.ElapsedSeconds=3599.99} 'hour of continuous protection'
Test-BaselineReceiptChange {param($f) $f.Stability.DirectUdpPackets=1} 'hour of continuous protection'
Test-BaselineReceiptChange {param($f) $f.Stability.ControlTcpPackets=59} 'hour of continuous protection'
Test-BaselineReceiptChange {param($f) $f.Stability.MinimumNativeOverlapMilliseconds=0} 'hour of continuous protection'
Test-BaselineReceiptChange {param($f) $f.Controller.MismatchProcessExitUtc=$f.Controller.MismatchBlockReadbackUtc} 'native block before each process exited'
Test-BaselineReceiptChange {param($f) $f.Controller.TransportProcessExitUtc=$f.Controller.MismatchBlockReadbackUtc} 'native block before each process exited'
Test-BaselineReceiptChange {param($f) $f.Revision.Switched=$true} 'expected late Store registration evidence'
Test-BaselineReceiptChange {param($f) $f.Lab.CandidateController=[pscustomobject]@{MismatchStopped=$true}} 'receipts disagree'

$old=@{'package\guard-wfp.cs'=('A'*64);'tests\loopback-lab.cs'=('B'*64)}
$new=@{'package\guard-wfp.cs'=('C'*64);'tests\loopback-lab.cs'=('B'*64)}
$approved=[ordered]@{'package\guard-wfp.cs'=@{Previous=('A'*64);Current=('C'*64);Reason='Exact reviewed fixture change'}}
$result=@(Compare-DailyRevisionBaselineFiles $old $new $approved)
if($result.Count -ne 1 -or $result[0].File -cne 'package\guard-wfp.cs'){throw 'The review binding did not return the approved change.'}
'PASS accepts only the exact reviewed previous and current hashes'
Assert-BaselineRejection {Compare-DailyRevisionBaselineFiles $old $new @{}} 'unreviewed code change'
Assert-BaselineRejection {Compare-DailyRevisionBaselineFiles $old $old $approved} 'stale or unexpected approved difference'
$new['package\guard-wfp.cs']='D'*64
Assert-BaselineRejection {Compare-DailyRevisionBaselineFiles $old $new $approved} 'unreviewed code change'
$new.Remove('tests\loopback-lab.cs')
Assert-BaselineRejection {Compare-DailyRevisionBaselineFiles $old $new $approved} 'fixture input set changed'
Assert-BaselineRejection {Read-DailyRevisionBaseline -CurrentStage $PSScriptRoot -ApprovedDifferences @{}} 'current administrator-owned native stage'
