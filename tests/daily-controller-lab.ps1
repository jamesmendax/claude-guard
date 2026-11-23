#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [switch]$Kernel,
    [switch]$PersistentBaseline,
    [ValidateRange(0,600)][int]$ActiveSeconds=0
)
$ErrorActionPreference='Stop'
if($PersistentBaseline -and -not $Kernel){throw 'The persistent test baseline requires kernel filtering.'}
$package=Join-Path (Split-Path -Parent $PSScriptRoot) 'package'
. "$package\guard-common.ps1"
$records=Join-Path $Directory 'controller-state'
function Get-GuardDataPath([string]$Name){Join-Path $records $Name}
function Get-GuardIsolationMode{'Off'}
if(-not $Kernel){
    # Only the unelevated fixture bypasses admin ownership, in its new evidence folder.
    function Read-GuardDailyRecord([string]$Name){
        [IO.File]::ReadAllText((Get-GuardDataPath $Name)) | ConvertFrom-Json -ErrorAction Stop
    }
}

function Require-GuardLab([bool]$Condition,[string]$Message){
    if(-not $Condition){throw $Message}
    Write-Host "PASS $Message"
}
function Wait-GuardLab([scriptblock]$Check,[string]$Message,[int]$LimitMs=12000){
    $clock=[Diagnostics.Stopwatch]::StartNew()
    do{
        $value=& $Check
        if($value){return $value}
        if($pending -and $pending.IsCompleted){
            throw "Controller exited while waiting for $Message. $($worker.Streams.Error)"
        }
        Start-Sleep -Milliseconds 60
    }while($clock.ElapsedMilliseconds -lt $LimitMs)
    $status=Get-GuardDailyStatus
    $recent=if($events){($events.ToArray() | Select-Object -Last 5) -join ', '}
    throw "Timed out waiting for $Message. Gate=$($status.Gate), state=$($status.Readiness), recent events=[$recent]."
}
$target=Join-Path $Directory 'guard-lab-client.exe'
$alias=Join-Path $Directory 'guard-lab-alias.exe'
$observer=Join-Path $Directory 'guard-lab-health.exe'
$relay=Join-Path $Directory 'guard-lab-relay.exe'
$control=Join-Path $Directory 'guard-lab-control.exe'
$relayPort=[GuardLoopbackLab]::FindPrivatePort()
$loopback=[Net.IPAddress]::Loopback
$upstream=$null; $direct=$null; $policy=$null; $forwarding=$null; $first=$null; $next=$null; $last=$null
$persistentInstalled=$false
$assignedWeight=0
$retiredImage=$null
$replacement=$null
$replacementWeight=$null
$worker=$null; $pending=$null
$halt=[Threading.ManualResetEvent]::new($false)
$paused=[Threading.ManualResetEvent]::new($false)
$continueExit=[Threading.ManualResetEvent]::new($false)
$holdProbe=[Threading.ManualResetEvent]::new($false)
$probeWaiting=[Threading.ManualResetEvent]::new($false)
$releaseProbe=[Threading.ManualResetEvent]::new($false)
$slowObservations=[Threading.ManualResetEvent]::new([bool]$ActiveSeconds)
$sessions=New-Object 'System.Collections.Concurrent.ConcurrentDictionary[int,System.Diagnostics.Process]'
$events=New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
try{
    $upstream=[GuardLoopbackLab+TlsWitness]::new($loopback,$Certificate)
    $direct=[GuardLoopbackLab+TlsWitness]::new($loopback,$Certificate)
    $programs=@($target,$alias)
    $packageSids=@()
    $serviceSid=$null
    if($PersistentBaseline){
        $retiredImage=Join-Path $Directory ('guard-lab-retired-'+[guid]::NewGuid().ToString('N')+'.exe')
        [IO.File]::Copy($target,$retiredImage)
        $programs+=,$retiredImage
        # These synthetic identities cover the native boot filter shapes. No
        # package or service is created or started by this fixture.
        $packageSids=@('S-1-15-2-12-23-34-45-56-67-78')
        $serviceSid='S-1-5-80-11-22-33-44-55'
    }
    $plan=[ClaudeGuard.Network.GuardPolicy]::Create(
        [string[]]$programs,[string[]]@($target,$alias),[string[]]$packageSids,$serviceSid,
        $relay,[uint16]$relayPort,'127.0.0.1',[uint16]$upstream.Port,$observer)
    if($PersistentBaseline){
        $deployment=[guid]::NewGuid()
        $plan=$plan.WithEarlyBootBlocks().ForPersistentUse($deployment)
        # Preserve enough detail to reproduce the exact fixture rules after an interrupted run.
        $record=[pscustomobject]@{
            Scope='LoopbackFixture';Deployment=$deployment;Sublayer=$plan.PersistentSublayer
            Programs=$programs;DesktopPaths=@($target,$alias);PackageSids=$packageSids;ServiceSid=$serviceSid
            Relay=$relay;Observer=$observer;RelayPort=$relayPort
            Upstream='127.0.0.1';UpstreamPort=$upstream.Port;BaselineKeys=$plan.GetBaselineKeys()
            BootKeys=$plan.GetBootKeys();AssignedSublayerWeight=$null
        }
        $recordPath=Join-Path $Directory 'persistent-fixture.json'
        [IO.File]::WriteAllText($recordPath,($record | ConvertTo-Json -Depth 4))
        $assignedWeight=[ClaudeGuard.Network.WindowsPolicySession]::InstallPersistent($plan)
        $persistentInstalled=$true
        $record.AssignedSublayerWeight=$assignedWeight
        [IO.File]::WriteAllText($recordPath,($record | ConvertTo-Json -Depth 4))
        Write-Host "OBSERVED RequestedSublayerWeight=$([ClaudeGuard.Network.WindowsPolicySession]::RequestedSublayerWeight) AssignedSublayerWeight=$assignedWeight"
        $bootRules=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($plan,$assignedWeight)
        Require-GuardLab ($bootRules -eq $plan.BootCount -and $bootRules -gt 0) 'Scoped startup blocks were read back from Windows'
        Write-Host "OBSERVED InstalledPersistentRules=$($plan.BaseCount) InstalledBootTimeRules=$bootRules"
    }elseif($Kernel){
        $policy=[ClaudeGuard.Network.WindowsPolicySession]::new($plan)
    }
    $forwarding=[GuardLoopbackLab]::StartRelay($relay,$relayPort,$upstream.Port)
    Require-GuardLab ([GuardLoopbackLab]::Echo($control,'4',$direct.Port,$Certificate)) 'Direct observation point is reachable by its control program'
    $directBefore=$direct.Accepted
    Require-GuardLab ([GuardLoopbackLab]::Echo($observer,'4',$relayPort,$Certificate)) 'Health observer reaches the chosen relay before readiness'
    if($PersistentBaseline){
        $badWeight=[uint16]($assignedWeight -bxor 1)
        $rejectedWeight=$false
        $wrong=$null
        try{
            $wrong=[ClaudeGuard.Network.WindowsPolicySession]::AttachPersistent($plan,$badWeight)
        }catch [Management.Automation.MethodInvocationException]{
            $rejectedWeight=$_.Exception.InnerException.Message.StartsWith('Sublayer weight changed.')
        }finally{if($wrong){$wrong.Dispose()}}
        Require-GuardLab $rejectedWeight 'A later readback must match the originally assigned weight'
        Require-GuardLab ([GuardLoopbackLab]::RejectsUnexpectedFilter($plan,[uint16]$assignedWeight,$target,[uint16]$direct.Port)) 'An extra permit is rejected by the closed rule readback'
        $policy=[ClaudeGuard.Network.WindowsPolicySession]::AttachPersistent($plan,$assignedWeight)
        $rejected=$false
        try{$policy.Open()}catch [Management.Automation.MethodInvocationException]{
            $rejected=$_.Exception.InnerException.Message -eq 'The installed policy requires a bounded lease.'
        }
        Require-GuardLab $rejected 'Installed rules reject an unbounded permit'
        $policy.Dispose()
        $policy=$null
        Require-GuardLab (-not [GuardLoopbackLab]::Echo($target,'4',$relayPort,$Certificate)) 'The installed rules stay closed when the controller session ends'
        $policy=[ClaudeGuard.Network.WindowsPolicySession]::AttachPersistent($plan,$assignedWeight)
        Require-GuardLab ($null -ne $policy) 'A replacement controller reads back the same installed rules'
    }
    if($Kernel){
        Require-GuardLab (-not [GuardLoopbackLab]::Echo($control,'4',$relayPort,$Certificate)) 'An unrelated client cannot use the dedicated listener'
        Require-GuardLab (-not [GuardLoopbackLab]::Echo($target,'4',$relayPort,$Certificate)) 'Test client starts blocked'
        Require-GuardLab (-not [GuardLoopbackLab]::Echo($observer,'4',$direct.Port,$Certificate)) 'Health observer cannot bypass the relay to a different endpoint'
        $receiptSignal=[Threading.ManualResetEvent]::new($false)
        try{
            $initialDeadline=[datetime]::UtcNow.AddSeconds(4)
            $firstReceipt=$policy.OpenUntilWithReceipt($initialDeadline,$receiptSignal,$true)
            $duplicateReceipt=$policy.OpenUntilWithReceipt($initialDeadline,$receiptSignal,$true)
            $nextReceipt=$policy.OpenUntilWithReceipt([datetime]::UtcNow.AddSeconds(5),$receiptSignal,$true)
            Require-GuardLab ($firstReceipt.Period -gt 0 -and $null -eq $firstReceipt.PreviousOverlapMilliseconds -and
                $firstReceipt.RenewedUtc.Kind -eq 'Utc') 'First native opening has a new period and no predecessor'
            Require-GuardLab ([object]::ReferenceEquals($firstReceipt,$duplicateReceipt)) 'A duplicate proof preserves its first native renewal receipt'
            Require-GuardLab ($nextReceipt.Period -eq $firstReceipt.Period -and
                $nextReceipt.RenewedUtc -ge $firstReceipt.RenewedUtc -and
                $nextReceipt.PreviousOverlapMilliseconds -gt 0) 'A native renewal tracks positive overlap in the same period'
            Require-GuardLab ($receiptSignal.WaitOne(10000)) 'Native expiry revokes the renewed fixture admission'
            $null=$receiptSignal.Reset()
            $reopenedReceipt=$policy.OpenUntilWithReceipt([datetime]::UtcNow.AddSeconds(5),$receiptSignal,$true)
            Require-GuardLab ($reopenedReceipt.Period -gt $nextReceipt.Period -and
                $null -eq $reopenedReceipt.PreviousOverlapMilliseconds) 'Native reopening after expiry starts a new period'
        }finally{
            try{$policy.Close()}finally{$receiptSignal.Dispose()}
        }
    }

    $profile=@{Generation=('B'*64);RouteHash=('E'*64);ExpectedIpv4='203.0.113.99';LeaseSeconds=$(if($ActiveSeconds){15}else{5})
        Port=$relayPort;DesktopHashes=@((Get-FileHash -LiteralPath $target).Hash)
        ScopeName=('claude-guard-'+('2'*32));ScopeSid='S-1-15-2-21-22-23-24-25-26-27'}
    $upstreamLost=[Threading.ManualResetEvent]::new($false)
    $work={
        param($package,$records,$profile,$kernelPolicy,$halt,$paused,$continueExit,$sessions,$events,$observerExecutable,
            $certificate,$target,$relayProcess,$holdProbe,$probeWaiting,$releaseProbe,$slowObservations,$upstreamLost)
        $ErrorActionPreference='Stop'
        . "$package\guard-common.ps1"
        . "$package\guard-daily-controller.ps1"
        $localProof={
            param($identity)
            if([GuardLoopbackLab]::Echo($observerExecutable,'4',$profile.Port,$certificate)){
                [pscustomobject]@{Generation=$profile.Generation;RouteHash=$profile.RouteHash;Ipv4=$profile.ExpectedIpv4
                    RelayId=$identity.ProcessId;RelayStartedUtc=$identity.StartedUtc;HttpStatus=200
                    CheckedUtc=[datetime]::UtcNow.ToString('o')}
            }
        }
        $cache=@{ProcessId=0;StartedUtc='';RouteHash='';AttemptUtc=[datetime]::MinValue;Proof=$null;Worker=$null}
        $background=@{
            Start={ [datetime]::UtcNow.AddMilliseconds(2600) }
            Poll={
                param($readyAt,$identity)
                if([datetime]::UtcNow -ge $readyAt){@{Finished=$true;Proof=(& $localProof $identity)}}
            }
            Stop={}
        }
        Start-GuardDailyHost $profile @{
                ReadIsolation={'Off'}
                VerifyInventory={(Get-FileHash -LiteralPath $target -ErrorAction Stop).Hash -cin $profile.DesktopHashes}
                ReadRelay={
                    if($relayProcess.HasExited){return}
                    [pscustomobject]@{Ready=$true;RouteHash=$profile.RouteHash;Port=$profile.Port
                        ProcessId=$relayProcess.Id;StartedUtc=$relayProcess.StartTime.ToUniversalTime().ToString('o')}
                }
                ReadObservation={
                    param($identity)
                    if($slowObservations.WaitOne(0)){
                        Get-GuardDailyObservation $cache $identity $background
                        return
                    }
                    if($holdProbe.WaitOne(0)){
                        $null=$probeWaiting.Set()
                        if(-not $releaseProbe.WaitOne(15000)){throw 'Timed out waiting for the lab to release the health probe.'}
                    }
                    $proof=& $localProof $identity
                    if($proof){return $proof}
                    if($upstreamLost.WaitOne(0)){
                        return [pscustomobject]@{Fault='UpstreamTransportDown';Generation=$profile.Generation
                            RouteHash=$profile.RouteHash;RelayId=$identity.ProcessId;RelayStartedUtc=$identity.StartedUtc
                            CheckedUtc=[datetime]::UtcNow.ToString('o')}
                    }
                }
                OpenVerified={
                    param($deadline,$signal)
                    if($kernelPolicy){$kernelPolicy.OpenUntil($deadline,$signal)}
                    $true
                }
                CloseVerified={
                    if($kernelPolicy){$kernelPolicy.Close()}
                    $events.Enqueue('network-revoked')
                    $true
                }
                WriteRecord={
                    param($name,$record)
                    $file=Join-Path $records $name
                    if($kernelPolicy){Save-GuardAdministratorJson $file $record}
                    else{
                        $null=[IO.Directory]::CreateDirectory($records)
                        $temporary=$file+'.fixture-tmp'
                        [IO.File]::WriteAllText($temporary,($record|ConvertTo-Json -Depth 5))
                        Move-Item -LiteralPath $temporary -Destination $file -Force
                    }
                }
                Snapshot={
                    foreach($process in $sessions.Values){
                        if(-not $process.HasExited){
                            [pscustomobject]@{Id=$process.Id;Start=$process.StartTime.ToUniversalTime().Ticks;Process=$process}
                        }
                    }
                }
                RequestClose={
                    param($entry)
                    $events.Enqueue("exit-request-$($entry.Id)")
                    $null=$entry.Process.CloseMainWindow()
                }
                Wait={
                    param($milliseconds)
                    $null=$paused.Set()
                    $null=$continueExit.WaitOne($milliseconds)
                }
                ForceStop={
                    param($entry)
                    if(-not $entry.Process.HasExited){
                        if($entry.Process.StartTime.ToUniversalTime().Ticks -ne $entry.Start){throw 'Fixture process identity changed.'}
                        $entry.Process.Kill()
                        if(-not $entry.Process.WaitForExit(2000)){throw 'Fixture process did not exit.'}
                        $events.Enqueue("exited-$($entry.Id)")
                    }
                }
            } $halt
    }
    $worker=[PowerShell]::Create()
    $null=$worker.AddScript($work.ToString()).AddArgument($package).AddArgument($records).AddArgument($profile).
        AddArgument($policy).AddArgument($halt).AddArgument($paused).AddArgument($continueExit).AddArgument($sessions).
        AddArgument($events).AddArgument($observer).AddArgument($Certificate).AddArgument($target).AddArgument($forwarding.Process).
        AddArgument($holdProbe).AddArgument($probeWaiting).AddArgument($releaseProbe).AddArgument($slowObservations).
        AddArgument($upstreamLost)
    $pending=$worker.BeginInvoke()
    $ready=Wait-GuardLab {
        $status=Get-GuardDailyStatus
        if($status.CanLaunch){$status}
    } 'the controller readback to become ready'
    Require-GuardLab (@(Get-Process -Name 'guard-lab-client' -ErrorAction SilentlyContinue |
        Where-Object Path -EQ $target).Count -eq 0) 'Ready status does not start the client'
    $first=[GuardLoopbackLab]::StartTls($target,'4',$relayPort,$Certificate)
    Require-GuardLab ($first.Read() -ceq 'READY' -and $first.Push([guid]::NewGuid().ToString('N'))) 'Manually started client can exchange data through the chosen relay'
    $firstId=$first.Process.Id
    $null=$sessions.TryAdd($firstId,$first.Process)
    if($ActiveSeconds){
        $healthy=[Diagnostics.Stopwatch]::StartNew()
        $messages=0
        while($healthy.Elapsed.TotalSeconds -lt $ActiveSeconds){
            if($first.Process.HasExited -or -not $first.Push([guid]::NewGuid().ToString('N'))){
                throw 'The healthy session stopped transferring data.'
            }
            $messages++
            Start-Sleep -Milliseconds 850
        }
        Require-GuardLab ((Get-GuardDailyStatus).CanLaunch -and -not $first.Process.HasExited) 'The original healthy client remains open'
        Write-Host "OBSERVED ActiveClientSeconds=$ActiveSeconds ProtectedMessages=$messages DelayedObservationMs=2600"
        $null=$slowObservations.Reset()
        $profile.LeaseSeconds=5
    }
    $fault=[Diagnostics.Stopwatch]::StartNew()
    $upstream.Pause()
    $null=$upstreamLost.Set()

    $closed=Wait-GuardLab {
        $status=Get-GuardDailyStatus
        if($status.Gate -ceq 'Closed' -and $status.Policy -ceq 'Verified' -and
            $status.Readiness -ceq 'WaitingForProxy' -and $paused.WaitOne(0)){$status}
    } 'independent upstream failure detection and verified revocation'
    $blockedMs=$fault.ElapsedMilliseconds
    Require-GuardLab ($closed.CloseName -ceq $ready.CloseName -and -not $forwarding.Process.HasExited) 'Live relay lost its upstream and the monitor closed the same session'
    $observed=$events.ToArray()
    $stopIndex=[Array]::IndexOf($observed,"exit-request-$firstId")
    $order=if($Kernel){'Windows verified the network block before the process received the exit request'}
        else{'The controller closed its software test gate before requesting process exit'}
    Require-GuardLab ($stopIndex -gt 0 -and $observed[$stopIndex-1] -ceq 'network-revoked') $order
    Require-GuardLab (-not $first.Process.HasExited) 'Original client still exists after the controller reports closure'
    $upstream.Resume()
    $null=$upstreamLost.Reset()
    Require-GuardLab ([GuardLoopbackLab]::Echo($observer,'4',$relayPort,$Certificate)) 'The resumed relay answers the independent observer'
    if($Kernel){
        Require-GuardLab (-not [GuardLoopbackLab]::Echo($alias,'4',$relayPort,$Certificate)) 'Recovered relay is still blocked during an unfinished shutdown'
        Require-GuardLab (-not [GuardLoopbackLab]::Echo($alias,'4',$direct.Port,$Certificate)) 'Client cannot connect directly during shutdown'
    }
    $null=$continueExit.Set()
    $null=Wait-GuardLab {if($first.Process.HasExited -and $events.ToArray() -ccontains "exited-$firstId"){$true}} 'the first client to exit automatically'
    $exitMs=$fault.ElapsedMilliseconds
    Require-GuardLab ($events.ToArray() -ccontains "exited-$firstId") 'Background monitor stopped the original client'

    $recovered=Wait-GuardLab {
        $status=Get-GuardDailyStatus
        if($status.CanLaunch -and $status.CloseName -cne $ready.CloseName){$status}
    } 'readiness after the original relay recovers'
    Require-GuardLab (@(Get-Process -Name 'guard-lab-client' -ErrorAction SilentlyContinue |
        Where-Object Path -EQ $target).Count -eq 0) 'Recovery only publishes ready and creates no client process'
    $next=[GuardLoopbackLab]::StartTls($target,'4',$relayPort,$Certificate)
    Require-GuardLab ($next.Read() -ceq 'READY' -and $next.Push([guid]::NewGuid().ToString('N'))) 'Manual relaunch uses the original recovered relay'
    $nextId=$next.Process.Id
    $null=$sessions.TryAdd($nextId,$next.Process)

    # Keep the registered client idle so the monitor has to terminate it.
    $activeFlow=$null
    try{
        if($Kernel){
            $activeFlow=[GuardLoopbackLab]::StartTls($alias,'4',$relayPort,$Certificate)
            Require-GuardLab ($activeFlow.Read() -ceq 'READY' -and $activeFlow.Push([guid]::NewGuid().ToString('N'))) 'Independent established test flow is healthy before the stall'
        }
        $null=$holdProbe.Set()
        $null=Wait-GuardLab {if($probeWaiting.WaitOne(0)){$true}} 'the synthetic health check to stall'
        $rights=[Security.AccessControl.EventWaitHandleRights]::Synchronize
        if(-not $Kernel){$rights=$rights -bor [Security.AccessControl.EventWaitHandleRights]::Modify}
        $closeEvent=[Threading.EventWaitHandle]::OpenExisting($recovered.CloseName,$rights)
        try{
            if($Kernel){
                Require-GuardLab ($closeEvent.WaitOne(6500)) 'The kernel lease expired while the health check was still stalled'
                Require-GuardLab ([GuardLoopbackLab]::Echo($observer,'4',$relayPort,$Certificate)) 'The upstream is still healthy during the stalled health check'
                Require-GuardLab (-not [GuardLoopbackLab]::Echo($alias,'4',$relayPort,$Certificate)) 'The expired lease blocks new connections even with a healthy relay'
                $beforePayloads=$upstream.Received
                $existingFlowBlocked=try{-not $activeFlow.Push([guid]::NewGuid().ToString('N'))}catch{$true}
                Require-GuardLab ($existingFlowBlocked -and $upstream.Received -eq $beforePayloads) 'The expired lease blocks data on an already established connection'
            }else{
                $stamp=Read-GuardDailyRecord 'daily-health.json'
                Require-GuardLab ((Get-GuardDailyCloseName $stamp.CloseId) -ceq $recovered.CloseName) 'The stalled health check owns the current close event'
                $deadline=[datetime]::ParseExact($stamp.Lease.ExpiresUtc,'o',
                    [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
                $remainingMilliseconds=[Math]::Max(0,[Math]::Ceiling(($deadline-[datetime]::UtcNow).TotalMilliseconds))
                Start-Sleep -Milliseconds ([int]$remainingMilliseconds+25)
                $expired=Get-GuardDailyStatus
                Require-GuardLab (-not $expired.CanLaunch -and $expired.Reason -ceq 'HealthLeaseInvalid') 'An expired health check prevents new launches while the monitor is stalled'
                # Model the expiry notification here. The kernel run above
                # exercises actual Windows permit revocation.
                Require-GuardLab ($closeEvent.Set()) 'Fixture signalled the expired admission to the stalled monitor'
            }
            Require-GuardLab (-not $next.Process.HasExited) 'The registered client is still alive before the monitor resumes'
        }finally{$closeEvent.Dispose()}
    }finally{if($activeFlow){$activeFlow.Dispose()}}
    $null=$holdProbe.Reset()
    $null=$releaseProbe.Set()
    $null=Wait-GuardLab {if($next.Process.HasExited -and $events.ToArray() -ccontains "exited-$nextId"){$true}} 'shutdown after the stalled check resumes'
    $observed=$events.ToArray()
    $stopIndex=[Array]::IndexOf($observed,"exit-request-$nextId")
    Require-GuardLab ($stopIndex -gt 0 -and $observed[$stopIndex-1] -ceq 'network-revoked') 'The recovered controller confirmed closure before requesting exit'
    Write-Host 'PASS The controller terminated the still-live client after the stalled check resumed'
    $null=Wait-GuardLab {
        $status=Get-GuardDailyStatus
        if($status.CanLaunch -and $status.CloseName -cne $recovered.CloseName){$status}
    } 'a new manual-launch opportunity after the stale session has exited'
    Require-GuardLab (@(Get-Process -Name 'guard-lab-client' -ErrorAction SilentlyContinue |
        Where-Object Path -EQ $target).Count -eq 0) 'Stalled-check recovery creates no protected client process'
    $last=[GuardLoopbackLab]::StartTls($target,'4',$relayPort,$Certificate)
    Require-GuardLab ($last.Read() -ceq 'READY') 'A user-initiated launch still works after watchdog recovery'
    $lastId=$last.Process.Id
    $null=$sessions.TryAdd($lastId,$last.Process)
    $forwarding.Process.Kill()
    if(-not $forwarding.Process.WaitForExit(5000)){throw 'The private relay did not exit.'}
    $null=Wait-GuardLab {if($last.Process.HasExited -and $events.ToArray() -ccontains "exited-$lastId"){$true}} 'client exit after the relay process disappears'
    Require-GuardLab ($events.ToArray() -ccontains "exited-$lastId") 'Relay exit also triggers automatic client shutdown'
    Require-GuardLab ($events.ToArray() -cnotcontains 'exited-no-such-process') 'Shutdown evidence distinguishes actual exits from missing events'
    if($Kernel){
        Require-GuardLab ($direct.Accepted -eq $directBefore) 'Direct observation point received zero protected connections'
        Write-Host "OBSERVED UpstreamFailureToBlockMs=$blockedMs UpstreamFailureToClientExitMs=$exitMs"
    }else{
        Write-Host "OBSERVED FixtureFailureToGateCloseMs=$blockedMs FixtureFailureToClientExitMs=$exitMs"
    }
}finally{
    $null=$continueExit.Set()
    $null=$halt.Set()
    $null=$releaseProbe.Set()
    try{
        if($pending){
            if(-not $pending.AsyncWaitHandle.WaitOne(15000)){throw 'Controller did not stop in time.'}
            $null=$worker.EndInvoke($pending)
            if($worker.HadErrors){throw "Controller error: $($worker.Streams.Error)"}
        }
    }finally{
        if($worker){$worker.Dispose()}
        if($first){$first.Dispose()}
        if($next){$next.Dispose()}
        if($last){$last.Dispose()}
        if($forwarding){$forwarding.Dispose()}
        try{
            if($policy){$policy.Dispose()}
            if($retiredImage){[IO.File]::Delete($retiredImage)}
            if($persistentInstalled){
                $native=[ClaudeGuard.Network.WindowsPolicySession]
                $native::VerifyNoPersistentAdmission($plan,$assignedWeight)
                $replacement=[ClaudeGuard.Network.GuardPolicy]::Create(
                    [string[]]@($target,$alias),[string[]]@($target,$alias),[string[]]$packageSids,$serviceSid,
                    $relay,[uint16]$relayPort,'127.0.0.1',[uint16]$upstream.Port,$observer
                ).WithEarlyBootBlocks().ForPersistentUse([guid]::NewGuid())
                $bootRules=$native::ReadBootFilterCount($replacement,0,$true)
                Require-GuardLab ($bootRules -eq 0) 'An interrupted pre-commit attempt has no replacement rules'
                try{
                    $replacementWeight=$native::InstallPersistent($replacement)
                    $count=$native::ReadBootFilterCount($replacement,$replacementWeight)
                    Require-GuardLab ($count -eq $replacement.BootCount -and $count -gt 0) 'Closed replacement rules coexist with the previous rules after the old image is removed'
                    $native::RemovePersistent($plan,$assignedWeight)
                    $native::RemovePersistent($plan,$assignedWeight)
                    Require-GuardLab ($native::ReadBootFilterCount($replacement,$replacementWeight) -eq $count) 'Exact retirement leaves the closed replacement rules intact'
                }finally{
                    if($null -ne $replacementWeight){$native::RemovePersistent($replacement,$replacementWeight)}
                    $native::RemovePersistent($plan,$assignedWeight)
                }
                Write-Host 'PASS The persistent fixture filters were removed'
                Write-Host 'OBSERVED PersistentFixtureRollback=VerifiedWithMissingImageAndRetry'
            }
        }finally{
            if($upstream){$upstream.Dispose()}
            if($direct){$direct.Dispose()}
            $halt.Dispose();$paused.Dispose();$continueExit.Dispose()
            $holdProbe.Dispose();$probeWaiting.Dispose();$releaseProbe.Dispose()
            $slowObservations.Dispose()
            if($upstreamLost){$upstreamLost.Dispose()}
        }
    }
}
$kernelResult=if($Kernel){'Passed'}else{'NotRun'}
Write-Host "RESULT DailyController=Passed Kernel=$kernelResult ManualRecovery=Passed StallRecovery=Passed"

