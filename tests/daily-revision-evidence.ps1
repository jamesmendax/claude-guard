function Assert-DailyRevisionFlags($Record,[string]$Scenario,[string[]]$Names) {
    foreach($name in $Names){
        if($Record.$name -isnot [bool] -or -not $Record.$name){throw "The Store receipt did not confirm $Scenario ($name)."}
    }
}

function Read-DailyRevisionUtc($Time){
    if($Time -is [datetime] -and $Time.Kind -eq 'Utc'){return $Time}
    $utc=[datetime]::MinValue
    if(-not [datetime]::TryParseExact([string]$Time,'o',[Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,[ref]$utc) -or $utc.Kind -ne 'Utc'){
        throw 'The Store receipt is missing a precise UTC time.'
    }
    $utc
}

function Assert-DailyRevisionStoreUpgradeEvidence($Lab){
    Assert-DailyRevisionFlags $Lab 'the completed Store version handoff' @('UpgradeVerified')
    Assert-DailyRevisionFlags $Lab.StorePrestage 'independent first-packet attribution' @('Passed','FirstTcpBlocked','FirstUdpBlocked',
        'RealPackageFirstActivation','OriginalV1ConnectedWhileArmed','FirstRelayBlocked','SameRegisteredPackageUnblocked','IndependentCleanupVerified')

    $upgrade=$Lab.Upgrade
    $prestage=$upgrade.ActualPrestage
    Assert-DailyRevisionFlags $upgrade 'the version handoff' @('OldConnectedDuringPrestage','ControlRemovedBeforeDeployment',
        'FuturePathReadBack','FirstTcpUdpBlocked','FallbackBlockedWithOldAdmission','NewConnectedAfterVerifiedHandoff','RenamedHelperBlocked')
    Assert-DailyRevisionFlags $prestage 'the real Store update event' @('Passed','CandidateVerified','MatchedAdd400')
    if($prestage.StateStatus -cne 'Protected' -or $prestage.RecordId574 -lt 1 -or $prestage.StateRecordId -ne $prestage.RecordId574 -or
        $prestage.RecordId400 -le $prestage.RecordId574 -or $prestage.NativeBootRules -lt 2 -or
        $prestage.First.RelayResult -cne 'Unavailable' -or $upgrade.NoPrestageAttempt.RelayResult -cne 'Unavailable'){
        throw 'The real Store update lacks its correlated early receipt, verified native blocks or blocked first attempts.'
    }
    $armed=Read-DailyRevisionUtc $prestage.RulesUtc
    if($armed -lt (Read-DailyRevisionUtc $prestage.Actual574)){
        Assert-DailyRevisionFlags $prestage 'the real Store directory notification' @('DirectoryNoticeVerified')
        $observed=Read-DailyRevisionUtc $prestage.DirectoryNoticeUtc
        $staging=Read-DailyRevisionUtc $prestage.StagingStartedUtc
        $noticeRoot=[string]$prestage.DirectoryNoticeRoot
        if($prestage.DirectoryNoticePackage -cne $prestage.First.Package -or
            $noticeRoot -notmatch '\A[A-Z]:\\(?:Program Files\\)?WindowsApps\\[A-Za-z0-9._-]+\z' -or
            (Split-Path -Leaf $noticeRoot) -cne $prestage.First.Package -or
            $observed -lt (Read-DailyRevisionUtc $prestage.First.InstallStartedUtc) -or $observed -gt $staging -or $staging -gt $armed){
            throw 'The native directory notification did not identify this exact deploying Store candidate before its rules were armed.'
        }
    }
    if($armed -ge (Read-DailyRevisionUtc $prestage.Registered400) -or
        $armed -ge (Read-DailyRevisionUtc $prestage.First.AddReturnedUtc) -or $armed -ge (Read-DailyRevisionUtc $prestage.First.FirstTcpUdpUtc)){
        throw 'The future Store blocks did not precede registration and the first attempt.'
    }
    foreach($field in 'OldAdmissionBeforeFirst','OldAdmissionAfterFirst','OldAdmissionBeforeFallback','OldAdmissionAfterFallback'){
        if($upgrade.$field -lt 1){throw "The old Store admission was unavailable ($field)."}
    }
    $handoff=$upgrade.InterruptedHandoff
    Assert-DailyRevisionFlags $handoff 'recovery after interruption' @('OfflineWhileInterrupted','OfflineAfterRecovery',
        'SameClosedRules','OldAdmissionClosed')
    if($handoff.InstallExitCode -ne 73 -or $handoff.InstallPid -lt 1 -or $handoff.RecoverPid -lt 1 -or
        $handoff.InstallPid -eq $handoff.RecoverPid -or $null -eq $handoff.PreCommitWeight -or $handoff.BootRules -lt 1){
        throw 'The interrupted Store handoff did not recover the saved policy in another process.'
    }
    if($upgrade.RegisteredPackage -cnotmatch '\AGuardMsixFixture\.[a-f0-9]{32}_2\.0\.0\.0_x64__[a-z0-9]{13}\z' -or
        $upgrade.RegisteredPackage -cne $prestage.First.Package -or $upgrade.RegisteredPackage -cne $upgrade.NoPrestageAttempt.Package -or
        (Read-DailyRevisionUtc $upgrade.VerifiedUtc) -lt (Read-DailyRevisionUtc $upgrade.NoPrestageAttempt.FirstTcpUdpUtc)){
        throw 'The Store handoff did not verify the same registered replacement exercised by both first-packet controls.'
    }
}

function Assert-DailyRevisionStoreEvidence($Lab,[int]$ExitCode,$VerifiedBaseline=$null,
    [string]$ExpectedBaselineStage,[int]$ExpectedBaselineFiles){
    if($ExitCode -ne 0){throw "The Store fixture stopped at $($Lab.Phase). $($Lab.Error)"}
    Assert-DailyRevisionFlags $Lab 'the Store run and restoration' @('Passed','SandboxieRestored',
        'ParentDirectBlocked','ChildDirectBlocked','DnsPolicyBlocked')
    Assert-DailyRevisionStoreUpgradeEvidence $Lab
    Assert-DailyRevisionFlags $Lab.Upgrade.InterruptedHandoff 'the removal of the recovered replacement policy' @('CleanupVerified')

    $controller=$Lab.CandidateController
    Assert-DailyRevisionFlags $controller 'protected Store sessions' @('ProbeTimeoutNoExit','ProofExpiryBlocks','SameProcessAfterRecheck',
        'UpstreamFailureWhileAdapterUp','UpstreamClosedBeforeExit','BackendExitBlocksExistingAndNew','ManualRecovery','PausedExitConfirmed',
        'PausedExitCleanupSignal','PausedExitClearedSandbox','PausedExitManualReopen','BackupCasesPassed','BackupAfterPrimaryFailure','BothUnavailablePaused',
        'MismatchStopped','NotificationsPassed')
    if($controller.SlowPrimaryRoundMs -lt 7000 -or $controller.SlowPrimaryRoundMs -gt 15000 -or
        $controller.ReconnectDirectAttempts -lt 3 -or $controller.ReconnectControlTcp -lt 1 -or $controller.ReconnectControlUdp -lt 1 -or
        $controller.ReconnectDirectTcp -ne 0 -or $controller.ReconnectDirectUdp -ne 0){
        throw 'The slow lookup or direct connection recovery controls did not verify.'
    }
    if($controller.MismatchLastReason -cne 'ExitChanged' -or $controller.TransportLastReason -cne 'UpstreamTransportDown' -or
        (Read-DailyRevisionUtc $controller.MismatchBlockReadbackUtc) -ge (Read-DailyRevisionUtc $controller.MismatchProcessExitUtc) -or
        (Read-DailyRevisionUtc $controller.TransportBlockReadbackUtc) -ge (Read-DailyRevisionUtc $controller.TransportProcessExitUtc)){
        throw 'The stop history did not confirm the reason and native block before each process exit.'
    }
    $soak=$controller.Stability
    Assert-DailyRevisionFlags $soak 'registered Store stability' @('Passed')
    if($soak.RegisteredPackage -cne $Lab.Upgrade.RegisteredPackage -or
        (Read-DailyRevisionUtc $soak.StartedUtc) -le (Read-DailyRevisionUtc $Lab.Upgrade.VerifiedUtc)){
        throw 'The Store soak did not start on the verified registered replacement after the handoff.'
    }
    if($VerifiedBaseline -or $soak.Kind -ceq 'PostUpgradeRegression'){
        Assert-DailyRevisionFlags $VerifiedBaseline 'the protected prior Store hour' @('Passed')
        if($VerifiedBaseline.Kind -cne 'PriorStoreHour' -or
            $ExpectedBaselineStage -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z' -or
            $VerifiedBaseline.SourceStage -cne $ExpectedBaselineStage -or
            $VerifiedBaseline.ElapsedSeconds -lt 3600 -or $ExpectedBaselineFiles -lt 1 -or
            $VerifiedBaseline.VerifiedFiles -ne $ExpectedBaselineFiles){
            throw 'The post-upgrade regression requires a complete, source-bound prior hour.'
        }
        if($soak.Kind -cne 'PostUpgradeRegression' -or $soak.MinimumSeconds -ne 120 -or $soak.ElapsedSeconds -lt 120 -or
            $soak.HealthChecks -lt 50 -or $soak.ExistingChecks -lt 8 -or $soak.NewChecks -lt 8 -or $soak.IdleChecks -lt 20 -or
            $soak.Downloads -lt 4 -or $soak.DownloadedBytes -ne (65536L*[long]$soak.Downloads) -or $soak.DirectChecks -lt 4 -or
            $soak.DirectTcpPackets -ne 0 -or $soak.DirectUdpPackets -ne 0 -or
            $soak.ControlTcpPackets -ne $soak.DirectChecks -or $soak.ControlUdpPackets -ne $soak.DirectChecks -or
            $soak.FalseExits -ne 0 -or $soak.UnexpectedPauses -ne 0 -or $soak.ClosedTransitions -ne 0 -or
            $soak.ProofRenewals -lt 7 -or $soak.PrimaryProofs -lt 1 -or $soak.BackupProofs -ne 0 -or
            $soak.MinimumProofOverlapMilliseconds -le 0 -or $soak.MinimumNativeOverlapMilliseconds -le 0 -or
            $soak.MinimumReadableOverlapMilliseconds -le 0){
            throw 'The fresh Store regression did not verify its traffic, idle, direct controls and continuous admission.'
        }
        return
    }
    if($soak.ElapsedSeconds -lt 3600 -or $soak.FalseExits -ne 0 -or $soak.UnexpectedPauses -ne 0 -or $soak.ClosedTransitions -ne 0 -or
        $soak.DirectTcpPackets -ne 0 -or $soak.DirectUdpPackets -ne 0 -or $soak.DirectChecks -lt 60 -or
        $soak.ControlTcpPackets -ne $soak.DirectChecks -or $soak.ControlUdpPackets -ne $soak.DirectChecks -or $soak.Downloads -lt 60 -or
        $soak.ProofRenewals -lt 239 -or $soak.MinimumNativeOverlapMilliseconds -le 0 -or $soak.MinimumReadableOverlapMilliseconds -le 0){
        throw 'The Store soak did not demonstrate an uninterrupted hour with reachable control receivers and zero direct traffic.'
    }
}

function New-DailyRevisionProofMonitor {
    @{
        Fresh=0;Streak=0;Last=$null;LastState='';MinimumPublished=$null;MinimumReadable=$null;MinimumNative=$null
        ExpiredSamples=0;Trace=[Collections.Generic.List[object]]::new()
    }
}

function Update-DailyRevisionProofMonitor($Monitor,$Health,[string]$Generation,[datetime]$ReadUtc) {
    $state='WaitingForGeneration'
    if($Health -and $Health.Generation -ceq $Generation){
        $state=[string]$Health.Reason
        if($Health.Gate -ceq 'Open' -and $state -ceq 'Verified'){
            $checked=Read-DailyRevisionUtc $Health.Lease.CheckedUtc
            $expires=Read-DailyRevisionUtc $Health.Lease.ExpiresUtc
            $published=Read-DailyRevisionUtc $Health.RulesUtc
            $armed=Read-DailyRevisionUtc $Health.Admission.RenewedUtc
            $started=Read-DailyRevisionUtc $Health.SupervisorStartUtc
            if($Health.Lease.Generation -cne $Generation -or $Health.Policy -cne 'Verified' -or $Health.Inventory -cne 'Verified' -or
                $Health.Exit -cne 'Match' -or $Health.SupervisorId -lt 1 -or $started -gt $checked -or
                [string]$Health.CloseId -cnotmatch '^[a-f0-9]{32}$' -or $Health.Admission.Period -lt 1 -or
                $checked -gt $armed -or $armed -gt $published -or $published -gt $ReadUtc -or $expires -le $checked -or
                ($expires-$checked).TotalSeconds -gt $script:GuardDailyMaxLeaseSeconds){
                throw 'The controller published inconsistent rule or proof timestamps during production verification.'
            }
            if($ReadUtc -lt $expires){
                $last=$Monitor.Last
                $sameSession=$last -and $last.Pid -eq $Health.SupervisorId -and $last.Started -eq $started -and
                    $last.CloseId -ceq $Health.CloseId -and $last.Period -eq $Health.Admission.Period
                if($sameSession -and $last.Checked -eq $checked){return}
                if($sameSession -and $checked -lt $last.Checked){throw 'The controller returned an older exit proof.'}
                $readable=if($last){($last.Expires-$ReadUtc).TotalMilliseconds}
                $written=if($last){($last.Expires-$published).TotalMilliseconds}
                $native=$Health.Admission.PreviousOverlapMilliseconds
                if($sameSession -and $readable -gt 0 -and $native -gt 0){
                    $Monitor.Streak++
                    $Monitor.MinimumPublished=if($null -eq $Monitor.MinimumPublished){$written}else{[math]::Min($written,$Monitor.MinimumPublished)}
                    $Monitor.MinimumReadable=if($null -eq $Monitor.MinimumReadable){$readable}else{[math]::Min($readable,$Monitor.MinimumReadable)}
                    $Monitor.MinimumNative=if($null -eq $Monitor.MinimumNative){$native}else{[math]::Min($native,$Monitor.MinimumNative)}
                }else{
                    $Monitor.Streak=1
                    $Monitor.MinimumPublished=$null
                    $Monitor.MinimumReadable=$null
                    $Monitor.MinimumNative=$null
                }
                $Monitor.Fresh++
                $Monitor.LastState='Verified'
                $Monitor.Last=@{Pid=$Health.SupervisorId;Started=$started;CloseId=$Health.CloseId;Period=$Health.Admission.Period
                    Checked=$checked;Expires=$expires}
                $Monitor.Trace.Add([pscustomobject]@{State='Verified';Streak=$Monitor.Streak;SupervisorId=$Health.SupervisorId
                    SupervisorStartUtc=$started.ToString('o');Period=$Health.Admission.Period;CheckedUtc=$checked.ToString('o')
                    ExpiresUtc=$expires.ToString('o');RenewedUtc=$armed.ToString('o');RulesUtc=$published.ToString('o')
                    ReadUtc=$ReadUtc.ToString('o');NativeOverlapMs=$native;ReadableOverlapMs=$readable})
                return
            }
            $state='ExpiredHealth'
            $Monitor.ExpiredSamples++
        }
    }
    if($Monitor.LastState -cne $state){
        $Monitor.Trace.Add([pscustomobject]@{State=$state;ReadUtc=$ReadUtc.ToString('o')})
        $Monitor.LastState=$state
    }
    $Monitor.Last=$null
    $Monitor.Streak=0
    $Monitor.MinimumPublished=$null
    $Monitor.MinimumReadable=$null
    $Monitor.MinimumNative=$null
}
