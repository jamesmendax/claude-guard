function Get-DailyRevisionBaselineFiles([string]$Root){
    # Batch entry points and the baseline checker are covered by the new launch
    # manifest. Everything staged for execution inside the fixture is compared.
    $entryPoints=@('tests\run-daily-revision.ps1','tests\run-native-acceptance.ps1',
        'tests\daily-revision-baseline.ps1','tests\daily-revision-baseline-tests.ps1','tests\daily-revision-baseline-pins.json')
    $files=@{}
    foreach($folder in 'package','tests','sdk'){
        $directory=Join-Path $Root $folder
        Assert-GuardSandboxieAdministratorPath $directory
        foreach($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop){
            if($item.PSIsContainer -or $item.Name -cnotmatch '\A[A-Za-z0-9._-]+\z'){
                throw 'The fixture contains an unexpected input path.'
            }
            Assert-GuardSandboxieAdministratorPath $item.FullName
            $name=$folder+'\'+$item.Name.ToLowerInvariant()
            if($name -notin $entryPoints){$files[$name]=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash}
        }
    }
    $files
}

function Get-DailyRevisionBaselineManifestHash([System.Collections.IDictionary]$Files){
    [string[]]$names=@($Files.Keys)
    [Array]::Sort($names,[StringComparer]::Ordinal)
    $manifest=($names | ForEach-Object {$_+'='+$Files[$_]}) -join [char]10
    $sha=[Security.Cryptography.SHA256]::Create()
    try{[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($manifest))).Replace('-','')}
    finally{$sha.Dispose()}
}

function Compare-DailyRevisionBaselineFiles([System.Collections.IDictionary]$Previous,[System.Collections.IDictionary]$Current,
    [System.Collections.IDictionary]$ApprovedDifferences){
    if($Previous.Count -ne $Current.Count){throw 'The current fixture input set changed.'}
    $used=0
    foreach($name in @($Previous.Keys | Sort-Object)){
        if(-not $Current.Contains($name)){throw "The current fixture is missing $name."}
        if($Previous[$name] -ceq $Current[$name]){continue}
        $pin=$ApprovedDifferences[$name]
        if(-not $pin -or $pin.Previous -cne $Previous[$name] -or $pin.Current -cne $Current[$name] -or
            $pin.Reason -isnot [string] -or [string]::IsNullOrWhiteSpace($pin.Reason)){
            throw "The current fixture has an unreviewed code change in $name."
        }
        $used++
        [pscustomobject]@{File=$name;Previous=$pin.Previous;Current=$pin.Current;Reason=$pin.Reason}
    }
    if($used -ne $ApprovedDifferences.Count){throw 'The baseline contains a stale or unexpected approved difference.'}
}

function Read-DailyRevisionBaselineReceipt([string]$Root,[string]$Name,[string]$ExpectedHash){
    $path=Join-Path $Root $Name
    Assert-GuardSandboxieAdministratorPath $path
    $read=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if($read.Length -gt 32KB -or (Get-FileHash -InputStream $read -Algorithm SHA256).Hash -cne $ExpectedHash){
            throw "The signed-off historical receipt changed ($Name)."
        }
        $read.Position=0
        $reader=[IO.StreamReader]::new($read,[Text.Encoding]::UTF8,$true)
        try{ConvertFrom-Json -InputObject ($reader.ReadToEnd()) -ErrorAction Stop}
        finally{$reader.Dispose()}
    }finally{$read.Dispose()}
}

function Assert-DailyRevisionBaselineReceipts($Revision,$Lab,$Controller,$Stability){
    if($Revision.Phase -cne 'StoreSubstitute' -or $Revision.Passed -cne $false -or $Revision.Switched -cne $false -or
        $Lab.Phase -cne 'Completed' -or $Lab.Passed -cne $false -or $Lab.UpgradeVerified -cne $false -or
        $Lab.Error -or $Lab.CleanupErrors.Count -or $Controller.Error){
        throw 'The historical fixture did not finish with the expected late Store registration evidence.'
    }
    Assert-DailyRevisionFlags $Revision 'historical restoration' @('Restored','ProxyContinuous')
    Assert-DailyRevisionFlags $Lab 'historical traffic and restoration' @('HealthyProxy','ParentDirectBlocked','ChildDirectBlocked',
        'DnsPolicyBlocked','ExistingFlowBlocked','NewFlowBlocked','ExitedAfterBlock','ManualRecovery','Cleanup','SandboxieRestored')
    if(($Revision.Fixture | ConvertTo-Json -Depth 20 -Compress) -cne ($Controller | ConvertTo-Json -Depth 20 -Compress) -or
        ($Lab.CandidateController | ConvertTo-Json -Depth 20 -Compress) -cne ($Controller | ConvertTo-Json -Depth 20 -Compress) -or
        ($Controller.Stability | ConvertTo-Json -Depth 20 -Compress) -cne ($Stability | ConvertTo-Json -Depth 20 -Compress) -or
        ($Revision.Upgrade.ActualPrestage | ConvertTo-Json -Depth 20 -Compress) -cne ($Lab.Upgrade.ActualPrestage | ConvertTo-Json -Depth 20 -Compress)){
        throw 'The historical administrator receipts disagree with one another.'
    }

    $prestage=$Lab.Upgrade.ActualPrestage
    Assert-DailyRevisionFlags $prestage 'historical Store readback' @('CandidateVerified','MatchedAdd400')
    Assert-DailyRevisionFlags $Lab.Upgrade 'historical packet checks and handoff' @('FirstTcpUdpBlocked',
        'FallbackBlockedWithOldAdmission','NewConnectedAfterVerifiedHandoff','RenamedHelperBlocked')
    $armed=Read-DailyRevisionUtc $prestage.RulesUtc
    $registered=Read-DailyRevisionUtc $prestage.Registered400
    $firstTraffic=Read-DailyRevisionUtc $prestage.First.FirstTcpUdpUtc
    if($prestage.Passed -cne $false -or $prestage.StateStatus -cne 'Protected' -or $prestage.First.RelayResult -cne 'Unavailable' -or
        $prestage.NativeBootRules -lt 2 -or (Read-DailyRevisionUtc $prestage.Received574) -gt $registered -or
        $registered -ge $armed -or $armed -ge $firstTraffic){
        throw 'The historical Store timing did not identify the late rule commit and blocked first traffic.'
    }

    Assert-DailyRevisionFlags $Controller 'historical fail-closed probes' @('MismatchStopped','UpstreamFailureWhileAdapterUp',
        'UpstreamClosedBeforeExit','BackendExitBlocksExistingAndNew','ProofExpiryBlocks','BothUnavailablePaused')
    $mismatchBlock=Read-DailyRevisionUtc $Controller.MismatchBlockReadbackUtc
    $mismatchExit=Read-DailyRevisionUtc $Controller.MismatchProcessExitUtc
    $transportBlock=Read-DailyRevisionUtc $Controller.TransportBlockReadbackUtc
    $transportExit=Read-DailyRevisionUtc $Controller.TransportProcessExitUtc
    $batchStart=Read-DailyRevisionUtc $Revision.StartedUtc
    $started=Read-DailyRevisionUtc $Stability.StartedUtc
    $ended=Read-DailyRevisionUtc $Stability.EndedUtc
    if($Controller.MismatchLastReason -cne 'ExitChanged' -or $Controller.TransportLastReason -cne 'UpstreamTransportDown' -or
        $batchStart -gt $mismatchBlock -or $mismatchBlock -ge $mismatchExit -or $mismatchExit -ge $transportBlock -or
        $transportBlock -ge $transportExit -or $transportExit -ge $started){
        throw 'The historical exit receipts did not show a native block before each process exited.'
    }
    Assert-DailyRevisionFlags $Stability 'historical one-hour stability' @('Passed')
    $elapsed=[double]$Stability.ElapsedSeconds
    if($Stability.Version -ne 1 -or $Stability.State -cne 'Passed' -or $Stability.Error -or $Stability.MinimumSeconds -lt 3600 -or
        [double]::IsNaN($elapsed) -or [double]::IsInfinity($elapsed) -or $elapsed -lt 3600 -or ($ended-$started).TotalSeconds -lt 3600 -or
        $ended -ge $registered -or (Read-DailyRevisionUtc $Revision.CompletedUtc) -le $firstTraffic -or
        $Stability.ProcessId -lt 1 -or (Read-DailyRevisionUtc $Stability.ProcessStartedUtc) -gt $started -or
        $Stability.FalseExits -ne 0 -or $Stability.UnexpectedPauses -ne 0 -or $Stability.ClosedTransitions -ne 0 -or
        $Stability.DirectTcpPackets -ne 0 -or $Stability.DirectUdpPackets -ne 0 -or $Stability.DirectChecks -lt 60 -or
        $Stability.ControlTcpPackets -ne $Stability.DirectChecks -or $Stability.ControlUdpPackets -ne $Stability.DirectChecks -or
        $Stability.Downloads -lt 60 -or $Stability.DownloadedBytes -ne ($Stability.Downloads*65536) -or $Stability.HealthChecks -lt 1790 -or
        $Stability.MaximumHealthGapMilliseconds -le 0 -or $Stability.MaximumHealthGapMilliseconds -gt 15000 -or
        $Stability.ProofRenewals -lt 239 -or $Stability.MinimumNativeOverlapMilliseconds -le 0 -or
        $Stability.MinimumReadableOverlapMilliseconds -le 0){
        throw 'The historical soak did not prove an hour of continuous protection with successful traffic controls.'
    }
}

function Read-DailyRevisionBaseline([string]$CurrentStage,[System.Collections.IDictionary]$ApprovedDifferences,
    [System.Collections.IDictionary]$BaselinePins){
    $base=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
    if((Split-Path -Parent $CurrentStage) -ine $base -or (Split-Path -Leaf $CurrentStage) -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z'){
        throw 'A separate current administrator-owned native stage is required.'
    }
    $source=[string]$BaselinePins.SourceStage
    if($source -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z'){throw 'A pinned administrator-owned baseline stage is required.'}
    $prior=Join-Path $base $source
    if($CurrentStage -ieq $prior){throw 'A separate current administrator-owned native stage is required.'}
    foreach($folder in $base,$prior,$CurrentStage){Assert-GuardSandboxieAdministratorPath $folder}

    # Pins must come from the reviewed private baseline, independently of the receipt files.
    $receiptNames=@('daily-revision-result.json','normal-package-receipt.json','store-controller-scenarios.json','store-stability.json')
    if($BaselinePins.FileCount -isnot [int] -or $BaselinePins.FileCount -lt 1 -or
        [string]$BaselinePins.ManifestSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or -not $BaselinePins.Receipts){
        throw 'The baseline file count, manifest hash and receipt hashes must be pinned.'
    }
    $receipts=@{}
    foreach($name in $receiptNames){
        $hash=[string]$BaselinePins.Receipts[$name]
        if($hash -cnotmatch '\A[A-F0-9]{64}\z'){throw "The baseline receipt is missing its pinned hash ($name)."}
        $receipts[$name]=Read-DailyRevisionBaselineReceipt $prior $name $hash
    }
    $revision=$receipts['daily-revision-result.json']
    $lab=$receipts['normal-package-receipt.json']
    $controller=$receipts['store-controller-scenarios.json']
    $stability=$receipts['store-stability.json']
    Assert-DailyRevisionBaselineReceipts $revision $lab $controller $stability

    $observerSha='86FC4785327DB5F5C7558DC6156C543B433C313E813A222E088086222AB4AFA6'
    foreach($name in 'normal-fixture-observer.exe','fixture-witness-service.exe'){
        $image=Join-Path $prior $name
        Assert-GuardSandboxieAdministratorPath $image
        if((Get-FileHash -LiteralPath $image -Algorithm SHA256 -ErrorAction Stop).Hash -cne $observerSha){
            throw 'A historical observer binary changed.'
        }
    }
    $old=Get-DailyRevisionBaselineFiles $prior
    $new=Get-DailyRevisionBaselineFiles $CurrentStage
    $manifest=Get-DailyRevisionBaselineManifestHash $old
    if($old.Count -ne $BaselinePins.FileCount -or $manifest -cne $BaselinePins.ManifestSha256){
        throw 'The historical fixture inputs no longer match the frozen manifest.'
    }
    if($null -eq $ApprovedDifferences){$ApprovedDifferences=@{}}
    $changes=@(Compare-DailyRevisionBaselineFiles $old $new $ApprovedDifferences)
    [pscustomobject]@{
        Kind='PriorStoreHour';Passed=$true;SourceStage=$source;ElapsedSeconds=$stability.ElapsedSeconds;VerifiedFiles=$old.Count
        StartedUtc=$stability.StartedUtc;EndedUtc=$stability.EndedUtc;ProofRenewals=$stability.ProofRenewals
        DirectChecks=$stability.DirectChecks;DirectTcpPackets=$stability.DirectTcpPackets;DirectUdpPackets=$stability.DirectUdpPackets
        ControlTcpPackets=$stability.ControlTcpPackets;ControlUdpPackets=$stability.ControlUdpPackets
        Downloads=$stability.Downloads;DownloadedBytes=$stability.DownloadedBytes
        MismatchBlockReadbackUtc=$controller.MismatchBlockReadbackUtc;MismatchProcessExitUtc=$controller.MismatchProcessExitUtc
        TransportBlockReadbackUtc=$controller.TransportBlockReadbackUtc;TransportProcessExitUtc=$controller.TransportProcessExitUtc
        ObserverSha256=$observerSha;PreviousManifestSha256=$manifest;CurrentManifestSha256=(Get-DailyRevisionBaselineManifestHash $new)
        ApprovedDifferences=$changes
    }
}
