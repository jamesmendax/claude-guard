#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$NodePath=(Get-Command node.exe -CommandType Application -ErrorAction Stop).Source,
    [string]$OutputDirectory=[IO.Path]::GetTempPath(),
    [switch]$WithTraffic
)

$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'package\guard-daily.ps1')
. (Join-Path $root 'package\guard-daily-plan.ps1')
. (Join-Path $root 'package\guard-daily-controller.ps1')

$node=(Get-Item -LiteralPath $NodePath).FullName
$fixtureScript=Join-Path $PSScriptRoot 'exit-observer-fixture.mjs'
$observerScript=Join-Path $PSScriptRoot 'cloudflare-exit-probe.mjs'
$runId=[guid]::NewGuid().ToString('N')
$folder=if($WithTraffic){'observer-traffic-endurance-'}else{'observer-endurance-'}
$directory=Join-Path $OutputDirectory ($folder+$runId)
$null=[IO.Directory]::CreateDirectory($directory)
$progressPath=Join-Path $directory 'progress.json'
$finalPath=Join-Path $directory 'final.json'
$controlPath=Join-Path $directory 'fixture-control.json'
$witnessPath=Join-Path $directory 'fixture-requests.txt'
$stopPath=Join-Path $directory 'stop.requested'
$record=[ordered]@{
    Version=1;Scope='LoopbackObserverAndControllerComponents';RunId=$runId;State='Starting';Passed=$false
    ProcessStartedUtc=[datetime]::UtcNow.ToString('o');MeasurementStartedUtc=$null;EndedUtc=$null
    MinimumSeconds=$(if($WithTraffic){14400}else{3600});ElapsedSeconds=0;Port=0
    NodeSha256=(Get-FileHash -LiteralPath $node).Hash;ObserverSha256=(Get-FileHash -LiteralPath $observerScript).Hash
    FixtureSha256=(Get-FileHash -LiteralPath $fixtureScript).Hash
    PreflightMismatchClosed=$false;PreflightReplacedRelayClosed=$false
    Polls=0;VerifiedRenewals=0;PrimaryRenewals=0;BackupRenewals=0;InjectedHttp503=0;InjectedHttpTimeout=0
    CloudflareAttempts=0;IpifyAttempts=0;BackupWhilePrimaryHealthy=0
    UnexpectedMismatches=0;MissedProofSamples=0;WorkerFailures=0;WorstRenewalGapMilliseconds=0
    MinimumProofOverlapMilliseconds=$null;WorstObservedProofAgeMilliseconds=0;Error=$null
}
$trafficRecord=$null
if($WithTraffic){
    $record.Scope='LoopbackObserverControllerAndTrafficComponents'
    $trafficRecord=[ordered]@{
        ExistingEchoes=0;NewEchoes=0;IdleReconnects=0;VerifiedDownloads=0;VerifiedDownloadBytes=0
        EchoesDuringTimeout=0;DownloadsDuringTimeout=0;SuccessfulTimeoutFailovers=0;Successful503Failovers=0
        LongestTimeoutFailoverMilliseconds=0;ShortestTimeoutFailoverMilliseconds=$null;TrafficFailures=0
        RelayImageSha256=$null;TrafficFixtureSha256=$null
    }
    $record.Traffic=$trafficRecord
}
$clock=[Diagnostics.Stopwatch]::new()
$fixture=$null
$forwarder=$null
$echo=$null
$retained=$null
$digest=$null
$cancelled=$false
$cache=@{ProcessId=0;StartedUtc='';RouteHash='';AttemptUtc=[datetime]::MinValue;Proof=$null;Worker=$null}

function Write-EnduranceJson([string]$Path,$Value) {
    $pending=$Path+'.pending'
    [IO.File]::WriteAllText($pending,($Value | ConvertTo-Json -Depth 5))
    if([IO.File]::Exists($Path)){[IO.File]::Replace($pending,$Path,[NullString]::Value)}
    else{[IO.File]::Move($pending,$Path)}
}

function Set-EnduranceWitness([string]$Primary) {
    Write-EnduranceJson $controlPath @{
        cloudflare=$Primary;ipify='match';expectedIpv4='203.0.113.17';otherIpv4='203.0.113.18'
        receiptPath=(Split-Path -Leaf $witnessPath)
    }
}

function Get-EndurancePort {
    for($i=0;$i -lt 20;$i++){
        $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,(Get-Random -Minimum 20000 -Maximum 47000))
        $listener.ExclusiveAddressUse=$true
        try{$listener.Start();return $listener.LocalEndpoint.Port}
        catch [Net.Sockets.SocketException]{}
        finally{$listener.Stop()}
    }
    throw 'No isolated loopback port was available.'
}

function Open-EnduranceTraffic([int]$Port){
    $client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try{
        if(-not $client.ConnectAsync([Net.IPAddress]::Loopback,$Port).Wait(1500)){throw 'The loopback traffic client did not connect.'}
        $client.ReceiveTimeout=1250
        $client.SendTimeout=1250
        $client
    }catch{$client.Dispose();throw}
}

function Test-EnduranceEcho($Client){
    $stream=$Client.GetStream()
    $stream.WriteByte(0x53)
    if($stream.ReadByte() -ne 0x53){throw 'The established loopback stream did not return its echo.'}
}

function Read-EnduranceDownload([int]$Port){
    $client=Open-EnduranceTraffic $Port
    try{
        $stream=$client.GetStream()
        $stream.WriteByte(0x42)
        $received=[byte[]]::new(65536)
        $total=0
        while($total -lt $received.Length){
            $count=$stream.Read($received,$total,$received.Length-$total)
            if($count -eq 0){throw 'The loopback download ended before 64 KiB.'}
            $total+=$count
        }
        if([Convert]::ToBase64String($digest.ComputeHash($received)) -cne $expectedDownloadHash){
            throw 'The loopback download content changed.'
        }
        $total
    }finally{$client.Dispose()}
}

try{
    Write-EnduranceJson $progressPath $record
    Write-Output "Observer endurance started $($record.ProcessStartedUtc). Progress: $progressPath"
    $witnessPort=Get-EndurancePort
    Set-EnduranceWitness 'mismatch'
    $fixture=Start-GuardDailyChild $node ('"'+$fixtureScript+'" serve '+$witnessPort+' "'+$controlPath+'"') ''
    $startWait=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-GuardDailyRelayListener $witnessPort $fixture.Process.Id)){
        if($fixture.Process.HasExited -or $startWait.Elapsed.TotalSeconds -ge 15){throw 'The isolated Node witness did not start.'}
        Start-Sleep -Milliseconds 150
    }
    $record.Port=$witnessPort
    $relayProcess=$fixture.Process
    if($WithTraffic){
        # Reuse the native fixture's data source and its forwarding mode. No package client is started.
        $sources=@('msix-normal-package-client.cs','msix-identity-probe.cs','native-process-scope-client.cs',
            'native-local-dns-client.cs','loopback-lab.cs' | ForEach-Object {Join-Path $PSScriptRoot $_})
        Add-Type -Path (@((Join-Path $root 'package\guard-wfp.cs'))+$sources)
        $relaySource=Join-Path $PSScriptRoot 'loopback-probe.cs'
        $relayImage=Join-Path $directory 'observer-test-relay.exe'
        $compiler=Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        & $compiler /nologo /platform:x64 /warnaserror+ "/out:$relayImage" $relaySource
        if($LASTEXITCODE -ne 0){throw 'The loopback test forwarder did not compile.'}
        $trafficRecord.RelayImageSha256=(Get-FileHash -LiteralPath $relayImage).Hash
        $trafficRecord.TrafficFixtureSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'msix-normal-package-client.cs')).Hash
        $echo=[GuardNormalEchoWitness]::new()
        $echo.ConnectWitnessPort=$witnessPort
        $record.Port=Get-EndurancePort
        $forwarder=[GuardLoopbackLab]::StartRelay($relayImage,$record.Port,$echo.Port)
        $relayProcess=$forwarder.Process
        if(-not (Test-GuardDailyRelayListener $record.Port $relayProcess.Id)){throw 'The loopback forwarder did not own its listener.'}
        $retained=Open-EnduranceTraffic $record.Port
        Test-EnduranceEcho $retained
        $digest=[Security.Cryptography.SHA256]::Create()
        $pattern=[byte[]]::new(65536)
        for($i=0;$i -lt $pattern.Length;$i++){$pattern[$i]=[byte]($i -band 255)}
        $expectedDownloadHash=[Convert]::ToBase64String($digest.ComputeHash($pattern))
    }
    $relay=[pscustomobject]@{
        Ready=$true;ProcessId=$relayProcess.Id;Port=$record.Port;RouteHash=('A'*64)
        StartedUtc=$relayProcess.StartTime.ToUniversalTime().ToString('o')
    }
    $profile=@{Generation=('B'*64);RouteHash=$relay.RouteHash;Port=$relay.Port;ExpectedIpv4='203.0.113.17'}
    $observeArgs='--use-bundled-ca "'+$fixtureScript+'" observe'
    $inputText=@{port=$relay.Port;backupExitLookup=$true} | ConvertTo-Json -Compress
    $preflight=Start-GuardDailyChild $node $observeArgs $inputText
    try{
        if(-not $preflight.Process.WaitForExit(14000) -or -not $preflight.Output.Wait(1000)){
            throw 'The controlled mismatch observation did not finish.'
        }
        $sample=Read-GuardDailyObservationWorker $preflight $relay $profile.Generation $null -BackupExitLookup
        $mismatch=Get-GuardDailyPathDecision $profile $relay $sample.Proof
        $journal=@([IO.File]::ReadAllLines($witnessPath))
        $record.PreflightMismatchClosed=$mismatch.Exit -ceq 'Mismatch' -and -not $mismatch.Lease -and
            $journal.Count -eq 1 -and $journal[0] -ceq 'CloudflareTrace'
        if(-not $record.PreflightMismatchClosed){throw 'The trusted wrong IPv4 was not rejected without a backup call.'}
        $replacement=$relay.PSObject.Copy()
        $replacement.ProcessId++
        $replaced=Get-GuardDailyPathDecision $profile $replacement $sample.Proof
        $record.PreflightReplacedRelayClosed=$replaced.Exit -ceq 'Unverified' -and -not $replaced.Lease
        if(-not $record.PreflightReplacedRelayClosed){throw 'A replacement identity inherited an old proof.'}
    }finally{Stop-GuardDailyChild $preflight}

    Set-EnduranceWitness 'match'
    $run=@{NextInjection=$(if($WithTraffic){30}else{300});LastJournalIndex=1}
    $observer=@{
        Start={
            $inject=$clock.IsRunning -and $clock.Elapsed.TotalSeconds -ge $run.NextInjection -and $run.NextInjection -lt $record.MinimumSeconds
            $mode='match'
            if($inject){
                $run.NextInjection+=600
                if($WithTraffic -and $record.InjectedHttpTimeout -le $record.InjectedHttp503){
                    $mode='timeout';$record.InjectedHttpTimeout++
                }else{$mode='reject';$record.InjectedHttp503++}
            }
            Set-EnduranceWitness $mode
            Start-GuardDailyChild $node $observeArgs $inputText |
                Add-Member -NotePropertyName PrimaryMode -NotePropertyValue $mode -PassThru
        }
        Poll={
            param($worker,$identity)
            $sample=Read-GuardDailyObservationWorker $worker $identity $profile.Generation $null -BackupExitLookup
            if(-not $sample.Finished){return}
            if(-not $sample.Proof){$record.WorkerFailures++;return $sample}
            $journal=[IO.File]::ReadAllLines($witnessPath)
            $newRows=@($journal | Select-Object -Skip $run.LastJournalIndex)
            $run.LastJournalIndex=$journal.Length
            $record.CloudflareAttempts+=@($newRows | Where-Object {$_ -ceq 'CloudflareTrace'}).Count
            $record.IpifyAttempts+=@($newRows | Where-Object {$_ -ceq 'Ipify'}).Count
            $injected=$worker.PrimaryMode -cne 'match'
            if(-not $injected){$record.BackupWhilePrimaryHealthy+=@($newRows | Where-Object {$_ -ceq 'Ipify'}).Count}
            $expected=if($injected){'CloudflareTrace,Ipify'}else{'CloudflareTrace'}
            $expectedProvider=if($injected){'Ipify'}else{'CloudflareTrace'}
            if(($newRows -join ',') -cne $expected -or $sample.Proof.Provider -cne $expectedProvider){
                $record.WorkerFailures++
            }elseif($WithTraffic -and $worker.PrimaryMode -ceq 'timeout'){
                $duration=($worker.Process.ExitTime.ToUniversalTime()-$worker.Process.StartTime.ToUniversalTime()).TotalMilliseconds
                if($duration -lt 7000){$record.WorkerFailures++}
                $trafficRecord.SuccessfulTimeoutFailovers++
                $trafficRecord.LongestTimeoutFailoverMilliseconds=[math]::Max($trafficRecord.LongestTimeoutFailoverMilliseconds,$duration)
                $trafficRecord.ShortestTimeoutFailoverMilliseconds=if($null -eq $trafficRecord.ShortestTimeoutFailoverMilliseconds){$duration}
                    else{[math]::Min($trafficRecord.ShortestTimeoutFailoverMilliseconds,$duration)}
            }elseif($WithTraffic -and $worker.PrimaryMode -ceq 'reject'){
                $trafficRecord.Successful503Failovers++
            }
            $sample
        }
        Stop={param($worker) Stop-GuardDailyChild $worker}
    }
    $previous=[datetime]::MinValue
    $previousExpiry=[datetime]::MinValue
    $nextProgress=0
    $warmup=[Diagnostics.Stopwatch]::StartNew()
    $lastTrafficMinute=-1
    $latestTraffic=0.0
    $nextTraffic=0.0
    while($true){
        if([IO.File]::Exists($stopPath)){$cancelled=$true;break}
        if($fixture.Process.HasExited -or $relayProcess.HasExited){throw 'A dedicated loopback fixture process exited.'}
        $observation=Get-GuardDailyObservation $cache $relay $observer
        if($record.WorkerFailures){throw 'A query result or per-worker provider trace was unexpected.'}
        $now=[datetime]::UtcNow
        $result=Get-GuardDailyPathDecision $profile $relay $observation $now
        if($result.Exit -ceq 'Mismatch'){$record.UnexpectedMismatches++;throw 'An unexpected exit mismatch was returned.'}
        if($clock.IsRunning){
            $record.Polls++
            if($result.Exit -cne 'Match' -or -not $result.Lease){$record.MissedProofSamples++;throw 'No current verified proof during the sustained check.'}
        }elseif(-not $result.Lease){
            if($warmup.Elapsed.TotalSeconds -ge 15){throw 'The approved IPv4 was not verified during warmup.'}
            Start-Sleep -Milliseconds 500
            continue
        }else{
            $record.MeasurementStartedUtc=$now.ToString('o')
            $record.State='Running'
            $clock.Start()
        }
        $observed=[datetime]::ParseExact($result.Lease.CheckedUtc,'o',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind)
        $expires=[datetime]::ParseExact($result.Lease.ExpiresUtc,'o',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind)
        if(($expires-$observed).TotalSeconds -ne $script:GuardDailyMaxLeaseSeconds -or $observed -lt $previous){
            throw 'A proof changed its original expiry or arrived out of order.'
        }
        $record.WorstObservedProofAgeMilliseconds=[math]::Max($record.WorstObservedProofAgeMilliseconds,($now-$observed).TotalMilliseconds)
        if($observed -gt $previous){
            if($previous -ne [datetime]::MinValue){
                $overlap=($previousExpiry-$now).TotalMilliseconds
                $record.WorstRenewalGapMilliseconds=[math]::Max($record.WorstRenewalGapMilliseconds,($observed-$previous).TotalMilliseconds)
                $record.MinimumProofOverlapMilliseconds=if($null -eq $record.MinimumProofOverlapMilliseconds){$overlap}
                    else{[math]::Min($record.MinimumProofOverlapMilliseconds,$overlap)}
                if($overlap -le 0){throw 'A replacement proof could not be applied before the existing lease expired.'}
            }
            $record.VerifiedRenewals++
            if($observation.Provider -ceq 'Ipify'){$record.BackupRenewals++}else{$record.PrimaryRenewals++}
            $previous=$observed
            $previousExpiry=$expires
        }
        $record.ElapsedSeconds=$clock.Elapsed.TotalSeconds
        if($WithTraffic -and $record.ElapsedSeconds -lt $record.MinimumSeconds -and $record.ElapsedSeconds -ge $nextTraffic){
            $minute=[int][math]::Floor($record.ElapsedSeconds/60)
            $waiting=$cache.Worker.PrimaryMode -ceq 'timeout'
            try{
                if($minute -ne $lastTrafficMinute){
                    $fresh=Open-EnduranceTraffic $record.Port
                    try{Test-EnduranceEcho $fresh}finally{$fresh.Dispose()}
                    $trafficRecord.NewEchoes++
                    if($record.ElapsedSeconds-$latestTraffic -ge 30){$trafficRecord.IdleReconnects++}
                    $trafficRecord.VerifiedDownloadBytes+=Read-EnduranceDownload $record.Port
                    $trafficRecord.VerifiedDownloads++
                    $latestTraffic=$clock.Elapsed.TotalSeconds
                    $lastTrafficMinute=$minute
                }
                if($waiting -or ($record.ElapsedSeconds % 60) -lt 20){
                    Test-EnduranceEcho $retained
                    $trafficRecord.ExistingEchoes++
                    $latestTraffic=$clock.Elapsed.TotalSeconds
                    if($waiting){
                        $trafficRecord.EchoesDuringTimeout++
                        $trafficRecord.VerifiedDownloadBytes+=Read-EnduranceDownload $record.Port
                        $trafficRecord.VerifiedDownloads++
                        $trafficRecord.DownloadsDuringTimeout++
                    }
                }
                $nextTraffic=$record.ElapsedSeconds+2
            }catch{$trafficRecord.TrafficFailures++;throw}
        }
        if($record.ElapsedSeconds -ge $nextProgress){
            if(-not (Test-GuardDailyRelayListener $relay.Port $relay.ProcessId)){throw 'The isolated listener changed ownership.'}
            Write-EnduranceJson $progressPath $record
            $nextProgress+=60
        }
        if($record.ElapsedSeconds -ge $record.MinimumSeconds){break}
        Start-Sleep -Milliseconds 500
    }
}catch{$record.Error=$_.Exception.Message}
finally{
    $clock.Stop()
    $record.ElapsedSeconds=$clock.Elapsed.TotalSeconds
    $record.EndedUtc=[datetime]::UtcNow.ToString('o')
    try{Stop-GuardDailyChild $cache.Worker}finally{
        try{
            if($retained){$retained.Dispose()}
            if($digest){$digest.Dispose()}
            if($forwarder){$forwarder.Dispose()}
        }finally{try{if($echo){$echo.Dispose()}}finally{Stop-GuardDailyChild $fixture}}
    }
    $expectedInjections=if($WithTraffic){24}else{6}
    $record.Passed=-not $record.Error -and $record.ElapsedSeconds -ge $record.MinimumSeconds -and
        $record.PreflightMismatchClosed -and $record.PreflightReplacedRelayClosed -and $record.VerifiedRenewals -ge ($record.MinimumSeconds/15) -and
        $record.PrimaryRenewals -gt 0 -and $record.BackupRenewals -eq $expectedInjections -and
        ($record.InjectedHttp503+$record.InjectedHttpTimeout) -eq $expectedInjections -and
        $record.BackupWhilePrimaryHealthy -eq 0 -and $record.UnexpectedMismatches -eq 0 -and $record.MissedProofSamples -eq 0 -and
        $record.WorkerFailures -eq 0 -and $record.MinimumProofOverlapMilliseconds -gt 0
    if($WithTraffic){
        $record.Passed=$record.Passed -and $trafficRecord.ExistingEchoes -ge 480 -and $trafficRecord.NewEchoes -ge 240 -and
            $trafficRecord.IdleReconnects -ge 180 -and $trafficRecord.VerifiedDownloads -ge 240 -and
            $trafficRecord.EchoesDuringTimeout -ge 24 -and $trafficRecord.DownloadsDuringTimeout -ge 24 -and
            $trafficRecord.SuccessfulTimeoutFailovers -eq 12 -and $trafficRecord.Successful503Failovers -eq 12 -and
            $trafficRecord.TrafficFailures -eq 0
    }
    if(-not $record.Passed -and -not $record.Error -and -not $cancelled){$record.Error='The required component endurance evidence was incomplete.'}
    $record.State=if($record.Passed){'Passed'}elseif($cancelled){'Cancelled'}else{'Failed'}
    Write-EnduranceJson $progressPath $record
    Write-EnduranceJson $finalPath $record
}
if($cancelled){Write-Output "Observer endurance cancelled safely. Result: $finalPath";exit 2}
if(-not $record.Passed){throw $record.Error}
Write-Output "Observer endurance passed $($record.ElapsedSeconds) seconds. Result: $finalPath"
