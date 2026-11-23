# Called by the isolated, Windows Store substitute scenario after its first verified connection.
function Invoke-StoreStability {
    param([switch]$AfterUpgrade)

    $receiptName=if($AfterUpgrade){'store-upgrade-stability.json'}else{'store-stability.json'}
    $receiptPath=Join-Path $stage $receiptName
    $gatePath=Join-Path $scenarioDir 'gate-metrics.json'
    $observationsPath=Join-Path $scenarioDir 'observation-metrics.json'
    $minimum=if($AfterUpgrade){
        @{Seconds=120;Health=50;TrafficRounds=4;Existing=8;New=8;Idle=20;Renewals=7;RoundMs=30000;ActiveMs=12000}
    }else{
        @{Seconds=3600;Health=0;TrafficRounds=60;Existing=60;New=60;Idle=60;Renewals=239;RoundMs=60000;ActiveMs=20000}
    }
    $record=[ordered]@{
        Version=1;State='Starting';Passed=$false;MinimumSeconds=$minimum.Seconds;IntervalMilliseconds=2000
        RegisteredPackage=$package.PackageFullName
        StartedUtc=$null;EndedUtc=$null;ElapsedSeconds=0;ProcessId=$null;ProcessStartedUtc=$null
        HealthChecks=0;MaximumHealthGapMilliseconds=0;IdleChecks=0;ExistingChecks=0;NewChecks=0
        Downloads=0;DownloadedBytes=0;DirectChecks=0;DirectTcpPackets=0;DirectUdpPackets=0
        ControlTcpPackets=0;ControlUdpPackets=0;FalseExits=0;UnexpectedPauses=0;ClosedTransitions=0
        ProofRenewals=0;PrimaryProofs=0;BackupProofs=0;MinimumProofOverlapMilliseconds=$null
        MinimumNativeOverlapMilliseconds=$null;MinimumReadableOverlapMilliseconds=$null;AdmissionPeriod=$null;Error=$null
    }
    if($AfterUpgrade){$record.Kind='PostUpgradeRegression'}
    $startGate=$null
    $startObservations=$null
    $timer=[Diagnostics.Stopwatch]::new()
    $culture=[Globalization.CultureInfo]::InvariantCulture
    $timeFormat=[Globalization.DateTimeStyles]::RoundtripKind

    function Read-StoreStabilityCounters([string]$Path,[string[]]$Names) {
        $sample=Read-GuardDailyJsonFile $Path
        foreach($name in $Names){
            $number=0L
            if(-not [long]::TryParse([string]$sample.$name,[ref]$number) -or $number -lt 0){
                throw "Missing or invalid Store fixture counter $name."
            }
        }
        $sample
    }

    function Read-StoreStabilityUtc($Value) {
        if($Value -is [datetime]){
            if($Value.Kind -eq 'Utc'){return $Value}
            return
        }
        $date=[datetime]::MinValue
        if([datetime]::TryParseExact([string]$Value,'o',$culture,$timeFormat,[ref]$date) -and $date.Kind -eq 'Utc'){$date}
    }

    function Update-StoreStabilityCounters {
        $gate=Read-StoreStabilityCounters $gatePath @('ClosedTransitions')
        $observations=Read-StoreStabilityCounters $observationsPath @('PrimaryProofs','BackupProofs')
        $closed=[long]$gate.ClosedTransitions-[long]$startGate.ClosedTransitions
        $primary=[long]$observations.PrimaryProofs-[long]$startObservations.PrimaryProofs
        $backup=[long]$observations.BackupProofs-[long]$startObservations.BackupProofs
        if($closed -lt $record.ClosedTransitions -or $primary -lt $record.PrimaryProofs -or $backup -lt $record.BackupProofs){
            throw 'A Store fixture counter went backwards.'
        }
        $record.ClosedTransitions=$closed
        $record.UnexpectedPauses=[math]::Max($record.UnexpectedPauses,$closed)
        $record.PrimaryProofs=$primary
        $record.BackupProofs=$backup
    }

    function Measure-StoreDirectWitness {
        $before=Read-DirectPackets
        if((Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){throw 'The protected TCP and UDP probes did not run.'}
        $negative=Read-DirectPackets
        $record.DirectChecks++
        $record.DirectTcpPackets+=$before.TcpCount+$negative.TcpCount
        $record.DirectUdpPackets+=$before.UdpCount+$negative.UdpCount
        if($record.DirectTcpPackets -ne 0 -or $record.DirectUdpPackets -ne 0){
            throw 'A protected direct probe reached the local receiver.'
        }

        $positive=Confirm-StoreDirectControl
        $record.ControlTcpPackets+=$positive.TcpCount
        $record.ControlUdpPackets+=$positive.UdpCount
    }

    try{
        if($AfterUpgrade){
            $fixture=Read-GuardDailyJsonFile (Join-Path $scenarioDir 'fixture.json')
            $registered=([string]$record.RegisteredPackage).Split('_')
            $old=([string]$replacement.OldPackage).Split('_')
            $registeredVersion=$null
            $oldVersion=$null
            if($fixture.Package -cne $record.RegisteredPackage -or $replacement.Package -cne $record.RegisteredPackage -or
                $registered.Count -ne 5 -or $old.Count -ne 5 -or $registered[0] -cne $old[0] -or
                $registered[4] -cne $old[4] -or -not [version]::TryParse($registered[1],[ref]$registeredVersion) -or
                -not [version]::TryParse($old[1],[ref]$oldVersion) -or $registeredVersion -le $oldVersion){
                throw 'The post-upgrade stability process is not bound to the newer registered Store fixture.'
            }
        }
        $startGate=Read-StoreStabilityCounters $gatePath @('ClosedTransitions')
        $startObservations=Read-StoreStabilityCounters $observationsPath @('PrimaryProofs','BackupProofs')
        $closeId=(Read-StoreScenarioHealth).CloseId
        if([string]$closeId -cnotmatch '^[a-f0-9]{32}$'){throw 'The Store fixture has no valid close signal.'}
        $record.ProcessId=$session.Process.Id
        $record.ProcessStartedUtc=$session.Process.StartTime.ToUniversalTime().ToString('o')
        $record.StartedUtc=[datetime]::UtcNow.ToString('o')
        $record.State='Running'
        $timer.Start()
        Save-GuardAdministratorJson $receiptPath $record
        $nextHealth=0L
        $lastHealth=0L
        $lastTrafficRound=-1
        $previousProof=[datetime]::MinValue
        $previousExpiry=[datetime]::MinValue
        $useExisting=$true
        while($true){
            $sleep=$nextHealth-$timer.ElapsedMilliseconds
            if($sleep -gt 0){Start-Sleep -Milliseconds ([int]$sleep)}
            $healthTime=$timer.ElapsedMilliseconds
            $record.MaximumHealthGapMilliseconds=[math]::Max($record.MaximumHealthGapMilliseconds,$healthTime-$lastHealth)
            $lastHealth=$healthTime
            if($record.MaximumHealthGapMilliseconds -gt ($script:GuardDailyMaxLeaseSeconds*1000)){
                throw 'The stability observer missed an entire exit proof lifetime.'
            }
            if($workerControl.Process.HasExited){throw 'The Store fixture controller exited during stability verification.'}
            if($session.Process.HasExited -or $session.Process.Id -ne $record.ProcessId -or
                $session.Process.StartTime.ToUniversalTime().ToString('o') -cne $record.ProcessStartedUtc){
                $record.FalseExits++
                throw 'The original Store substitute exited during healthy use.'
            }

            $health=Read-StoreScenarioHealth
            $now=[datetime]::UtcNow
            $checked=Read-StoreStabilityUtc $health.Lease.CheckedUtc
            $expiry=Read-StoreStabilityUtc $health.Lease.ExpiresUtc
            $armed=Read-StoreStabilityUtc $health.Admission.RenewedUtc
            if($health.Gate -cne 'Open' -or $health.CloseId -cne $closeId -or $health.Session -cne 'Active' -or
                $health.Policy -cne 'Verified' -or $health.Inventory -cne 'Verified' -or $health.Exit -cne 'Match' -or
                $health.SupervisorId -ne $workerControl.Process.Id -or $health.Admission.Period -lt 1 -or
                ($record.AdmissionPeriod -and $health.Admission.Period -ne $record.AdmissionPeriod) -or
                -not $checked -or -not $expiry -or -not $armed -or $checked -gt $armed -or $armed -gt $now -or $expiry -le $now -or
                ($expiry-$checked).TotalSeconds -gt $script:GuardDailyMaxLeaseSeconds){
                $record.UnexpectedPauses++
                throw 'The healthy Store session lost its verified connection during stability verification.'
            }
            $record.AdmissionPeriod=$health.Admission.Period
            $record.HealthChecks++
            if($checked -lt $previousProof){throw 'The Store fixture published an older exit proof.'}
            if($previousProof -ne [datetime]::MinValue -and $checked -gt $previousProof){
                $overlap=($previousExpiry-$checked).TotalMilliseconds
                $record.MinimumProofOverlapMilliseconds=if($null -eq $record.MinimumProofOverlapMilliseconds){$overlap}
                    else{[math]::Min($record.MinimumProofOverlapMilliseconds,$overlap)}
                if($overlap -le 0){throw 'The previous exit proof expired before the replacement was observed.'}
                $native=$health.Admission.PreviousOverlapMilliseconds
                $readable=($previousExpiry-$now).TotalMilliseconds
                if($native -le 0 -or $readable -le 0){throw 'The Store test could not verify continuous native admission and readable health.'}
                $record.MinimumNativeOverlapMilliseconds=if($null -eq $record.MinimumNativeOverlapMilliseconds){$native}
                    else{[math]::Min($native,$record.MinimumNativeOverlapMilliseconds)}
                $record.MinimumReadableOverlapMilliseconds=if($null -eq $record.MinimumReadableOverlapMilliseconds){$readable}
                    else{[math]::Min($readable,$record.MinimumReadableOverlapMilliseconds)}
                $record.ProofRenewals++
            }
            $previousProof=$checked
            $previousExpiry=$expiry
            if($healthTime -ge ($record.MinimumSeconds*1000)){break}

            $trafficRound=[int][math]::Floor($healthTime/$minimum.RoundMs)
            if(($healthTime % $minimum.RoundMs) -lt $minimum.ActiveMs){
                if($useExisting){
                    if((Invoke-NormalCommand 'existing') -cne 'Echo'){throw 'The original protected TCP connection did not respond.'}
                    $record.ExistingChecks++
                }else{
                    if((Invoke-NormalCommand "new|$relayPort") -cne 'Echo'){throw 'A new protected TCP connection did not respond.'}
                    $record.NewChecks++
                }
                $useExisting=-not $useExisting
            }else{$record.IdleChecks++}
            if($trafficRound -ne $lastTrafficRound){
                if((Invoke-NormalCommand "download|$relayPort") -cne 'Downloaded|65536'){
                    throw 'The Store substitute did not verify the complete 64 KiB payload.'
                }
                $record.Downloads++
                $record.DownloadedBytes+=65536
                Measure-StoreDirectWitness
                Update-StoreStabilityCounters
                $record.ElapsedSeconds=$timer.Elapsed.TotalSeconds
                Save-GuardAdministratorJson $receiptPath $record
                if($record.ClosedTransitions -ne 0){throw 'The Store fixture recorded an unexpected pause between health samples.'}
                $lastTrafficRound=$trafficRound
            }
            $nextHealth+=$record.IntervalMilliseconds
            # Do not count several immediate reads as samples after a scheduling delay.
            while($nextHealth -le $healthTime){$nextHealth+=$record.IntervalMilliseconds}
        }
    }catch{$record.Error=$_.Exception.Message}
    finally{
        $timer.Stop()
        $record.ElapsedSeconds=$timer.Elapsed.TotalSeconds
        $record.EndedUtc=[datetime]::UtcNow.ToString('o')
        if($startGate -and $startObservations){
            try{Update-StoreStabilityCounters}catch{if(-not $record.Error){$record.Error=$_.Exception.Message}}
        }
        $record.Passed=-not $record.Error -and $record.ElapsedSeconds -ge $record.MinimumSeconds -and
            $record.FalseExits -eq 0 -and $record.UnexpectedPauses -eq 0 -and $record.ClosedTransitions -eq 0 -and
            $record.DirectTcpPackets -eq 0 -and $record.DirectUdpPackets -eq 0 -and $record.DirectChecks -ge $minimum.TrafficRounds -and
            $record.ControlTcpPackets -eq $record.DirectChecks -and $record.ControlUdpPackets -eq $record.DirectChecks -and
            $record.Downloads -ge $minimum.TrafficRounds -and $record.ExistingChecks -ge $minimum.Existing -and
            $record.NewChecks -ge $minimum.New -and $record.IdleChecks -ge $minimum.Idle -and $record.HealthChecks -ge $minimum.Health -and
            $record.MinimumProofOverlapMilliseconds -gt 0 -and $record.MinimumNativeOverlapMilliseconds -gt 0 -and
            $record.MinimumReadableOverlapMilliseconds -gt 0 -and $record.ProofRenewals -ge $minimum.Renewals -and
            $record.PrimaryProofs -gt 0 -and $record.BackupProofs -eq 0
        if(-not $record.Passed -and -not $record.Error){
            $record.Error=if($AfterUpgrade){'The post-upgrade Store regression evidence was incomplete.'}
                else{'The one-hour Store fixture evidence was incomplete.'}
        }
        $record.State=if($record.Passed){'Passed'}else{'Failed'}
        Save-GuardAdministratorJson $receiptPath $record
    }
    if(-not $record.Passed){throw $record.Error}
    [pscustomobject]$record
}
