#Requires -Version 5.1

. "$PSScriptRoot\guard-daily-notifications.ps1"

function New-GuardDailyControllerSignal($Controller) {
    $id=[guid]::NewGuid().ToString('N')
    $acl=New-Object Security.AccessControl.EventWaitHandleSecurity
    $launchRights=[Security.AccessControl.EventWaitHandleRights]::Modify -bor [Security.AccessControl.EventWaitHandleRights]::Synchronize
    foreach($sid in @('S-1-5-18','S-1-5-32-544',$Controller.LaunchUserSid)){
        $rights=if($sid -in 'S-1-5-18','S-1-5-32-544'){'FullControl'}else{$launchRights}
        $rule=New-Object Security.AccessControl.EventWaitHandleAccessRule (
            [Security.Principal.SecurityIdentifier]::new($sid), $rights, 'Allow')
        $acl.AddAccessRule($rule)
    }
    $created=$false
    $name=Get-GuardDailyCloseName $id
    $signal=if($PSVersionTable.PSEdition -ceq 'Core'){[Threading.EventWaitHandleAcl]::Create($false,'ManualReset',$name,[ref]$created,$acl)}
        else{[Threading.EventWaitHandle]::new($false,'ManualReset',$name,[ref]$created,$acl)}
    if(-not $created){$signal.Dispose(); throw 'An existing close event could not be used.'}
    $previous=$Controller.Signal
    $Controller.Mode.CloseId=$id
    $Controller.Signal=$signal
    if($previous){$previous.Dispose()}
}

function New-GuardDailyController([System.Collections.IDictionary]$Profile) {
    if(-not (Test-GuardDailyScopeBinding $Profile)){throw 'A verified AppContainer binding or Sandboxie package binding is required.'}
    if([string]$Profile.Generation -cnotmatch '^[A-F0-9]{64}$' -or $Profile.Port -lt 1024 -or $Profile.Port -ge 49152 -or
        @($Profile.DesktopHashes | Where-Object { $_ -cmatch '^[A-F0-9]{64}$' }).Count -ne @($Profile.DesktopHashes).Count -or
        -not @($Profile.DesktopHashes).Count){throw 'Invalid daily controller profile.'}
    $process=[Diagnostics.Process]::GetCurrentProcess()
    try{
        $supervisorStart=$process.StartTime.ToUniversalTime().ToString('o')
    }finally{$process.Dispose()}
    $launchUser=if($Profile.LaunchUserSid){[string]$Profile.LaunchUserSid}else{[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
    $controller=[pscustomobject]@{
        Mode=[pscustomobject]@{Version=2;Mode='Daily';Generation=$Profile.Generation;Port=[int]$Profile.Port
            DesktopHashes=@($Profile.DesktopHashes);CloseId=$null;ScopeName=$Profile.ScopeName;ScopeSid=$Profile.ScopeSid
            Containment=[string]$Profile.Containment}
        SupervisorStartUtc=$supervisorStart; LaunchUserSid=$launchUser
        Signal=$null; PublishedCloseId=$null
        Gate='Closed'; Decision=$null; Shutdown=$null; LastLease=$null
        Rechecking=$false; StopPending=$false
        Notice=$null; NoticeCause=$null; NoticeProcess=$false; NoticeCloseAction=$false; NoticeStopped=$false; ObservedSession=$false
    }
    New-GuardDailyControllerSignal $controller
    $controller
}

function Write-GuardDailyControllerRecords($Controller,$State,$Decision,[scriptblock]$WriteRecord) {
    $lastLease=$Controller.LastLease
    $justClosed=$Controller.Gate -ceq 'Open' -and $State.Gate -cne 'Open'
    $Controller.Gate=$State.Gate
    $Controller.Decision=$Decision
    $Controller.LastLease=if($State.Gate -ceq 'Open'){$State.Lease}
    $mode=$Controller.Mode
    $health=[pscustomobject]@{
        Version=2;Generation=$mode.Generation;Port=$mode.Port;CloseId=$mode.CloseId
        ScopeName=$mode.ScopeName;ScopeSid=$mode.ScopeSid;Containment=$mode.Containment
        SupervisorId=$PID;SupervisorStartUtc=$Controller.SupervisorStartUtc
        Policy=$State.Policy;Inventory=$State.Inventory
        RulesUtc=$(if($State.Policy -ceq 'Verified'){[datetime]::UtcNow.ToString('o')})
        Proxy=$State.Proxy;Exit=$State.Exit;Session=$State.Session;Gate=$State.Gate;Lease=$State.Lease
        Admission=$(if($State.Gate -ceq 'Open'){$State.Admission})
        Reason=$Decision.Reason;Failure=$State.Failure;Terminating=$State.Terminating
    }
    # A reader seeing either half of a rotation requires the same CloseId.
    & $WriteRecord 'daily-health.json' $health | Out-Null
    if($Controller.PublishedCloseId -cne $mode.CloseId){
        & $WriteRecord 'daily-mode.json' ([pscustomobject]@{
            Version=$mode.Version;Mode=$mode.Mode;Generation=$mode.Generation;Port=$mode.Port
            DesktopHashes=@($mode.DesktopHashes);CloseId=$mode.CloseId
            ScopeName=$mode.ScopeName;ScopeSid=$mode.ScopeSid;Containment=$mode.Containment
        }) | Out-Null
        $Controller.PublishedCloseId=$mode.CloseId
    }
    if($justClosed){
        try{
            & $WriteRecord 'daily-last-stop.json' ([pscustomobject]@{
                Utc=[datetime]::UtcNow.ToString('o');Reason=$Decision.Reason;Gate=$State.Gate
                CloseSignal=$Controller.Signal.WaitOne(0);Session=$State.Session
                LastProofUtc=$lastLease.CheckedUtc;LastProofExpiryUtc=$lastLease.ExpiresUtc
                CycleMs=[int]$State.CycleClock.ElapsedMilliseconds
            }) | Out-Null
        }catch{}
    }
}

function Test-GuardDailySessionStillOwned($Operations) {
    if(-not $Operations.LaunchSessionBusy){return $false}
    try{(& $Operations.LaunchSessionBusy) -ne $false}catch{$true}
}

function Get-GuardDailyObservation($Cache,$Relay,$Observer,[datetime]$NowUtc=[datetime]::UtcNow,[switch]$PollOnly) {
    if($Relay.Ready -ne $true -or $Cache.ProcessId -ne $Relay.ProcessId -or $Cache.StartedUtc -cne $Relay.StartedUtc -or
        $Cache.RouteHash -cne $Relay.RouteHash -or $Cache.AttemptUtc -gt $NowUtc){
        $worker=$Cache.Worker
        $Cache.Worker=$null
        $Cache.ProcessId=$Relay.ProcessId
        $Cache.StartedUtc=$Relay.StartedUtc
        $Cache.RouteHash=$Relay.RouteHash
        $Cache.AttemptUtc=[datetime]::MinValue
        $Cache.Proof=$null
        if($worker){& $Observer.Stop $worker | Out-Null}
    }
    if($Relay.Ready -ne $true){return}
    if($Cache.Worker){
        $sample=try{& $Observer.Poll $Cache.Worker $Relay}catch{@{Finished=$true}}
        if($sample.Finished -or ($NowUtc-$Cache.AttemptUtc).TotalSeconds -ge $script:GuardDailyMaxLeaseSeconds){
            if($sample.Finished -and $sample.Failure){$Cache.Proof=$sample.Failure}
            elseif($sample.Finished -and $sample.Proof){$Cache.Proof=$sample.Proof}
            $worker=$Cache.Worker
            $Cache.Worker=$null
            & $Observer.Stop $worker | Out-Null
        }
    }
    if(-not $PollOnly -and -not $Cache.Worker -and ($NowUtc-$Cache.AttemptUtc).TotalSeconds -ge 5){
        $Cache.AttemptUtc=$NowUtc
        $Cache.Worker=try{& $Observer.Start $Relay}catch{$null}
    }
    # Path verification still applies the original observation time and expiry.
    $Cache.Proof
}

function Invoke-GuardDailyControllerCycle($Controller,[System.Collections.IDictionary]$Operations,[switch]$Closing) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    if($Controller.StopPending -and $Controller.Shutdown.NetworkBlocked -and $Controller.Shutdown.Exited -and
        -not (Test-GuardDailySessionStillOwned $Operations)){$Controller.StopPending=$false}
    $knownSession=$Controller.Gate -ceq 'Open' -or $Controller.Rechecking
    $requestedClose=$knownSession -and $Controller.Signal.WaitOne(0)
    $terminating=$Closing -or $Controller.StopPending -or $requestedClose
    $forceClose=$terminating -or $Controller.Gate -ceq 'Unknown'
    if($forceClose){
        $closedBeforeInspection=try{(& $Operations.CloseVerified) -eq $true}catch{$false}
    }
    $isolation=try{& $Operations.ReadIsolation}catch{'Unknown'}
    $path=$null
    if(-not $forceClose -and $isolation -ceq 'Off' -and $Operations.ReadEarlyPath){
        # Run the bounded observer while Windows checks the inventory.
        $early=try{& $Operations.ReadEarlyPath}catch{$null}
        if($early.Proxy -ceq 'Down' -or $early.Exit -ceq 'Mismatch'){
            $path=$early
            $forceClose=$true
            $closedBeforeInspection=try{(& $Operations.CloseVerified) -eq $true}catch{$false}
        }
    }
    $inventory=try{
        $found=& $Operations.VerifyInventory
        if($found -is [bool]){if($found){'Verified'}else{'Changed'}}else{'Unknown'}
    }catch{'Unknown'}
    $state=@{
        Isolation=$isolation;Mode='Daily';Generation=$Controller.Mode.Generation;Port=$Controller.Mode.Port
        Inventory=$inventory;Policy='Verified';Proxy='Unknown';Exit='Unverified';Lease=$null;Admission=$null
        Gate='Closed';Session=$(if($knownSession -and -not $terminating){'Rechecking'}else{'Stopping'})
        CycleClock=$clock;Terminating=$terminating;Failure=$null
    }
    if(-not $forceClose -and $isolation -ceq 'Off' -and $inventory -ceq 'Verified'){
        $path=try{& $Operations.ReadPath}catch{$null}
    }
    if($path.Proxy -ceq 'Ready' -and $path.Exit -ceq 'Match'){
        $running=@(try {& $Operations.Snapshot} catch{[pscustomobject]@{Start=0}})
        if($Operations.WriteNotice){$Controller.ObservedSession=@($running | Where-Object Start).Count -gt 0}
        $busy=$running.Count -eq 0 -and (Test-GuardDailySessionStillOwned $Operations)
        # A proof may finish while Windows checks process ownership. Collect it before
        # arming the firewall, using the same two listener checks and no new request.
        if($Operations.ObservationCompleted){
            try{if(& $Operations.ObservationCompleted){$path=& $Operations.ReadPath $true}}
            catch{$path=$null}
        }
        if($path.Proxy -ceq 'Ready' -and $path.Exit -ceq 'Match'){
            if(-not $running.Count -and -not $busy){$state.Session='Clear'}
            elseif($knownSession -and -not @($running | Where-Object {-not $_.Start}).Count){$state.Session='Active'}
        }
    }
    if($path){
        $state.Proxy=$path.Proxy
        $state.Exit=$path.Exit
        $state.Lease=$path.Lease
        $state.Failure=$path.Failure
    }
    $terminating=$terminating -or $isolation -ceq 'Active' -or $inventory -ceq 'Changed' -or
        $state.Proxy -ceq 'Down' -or $state.Exit -ceq 'Mismatch'
    if($terminating){$state.Session='Stopping'; $state.Terminating=$true}

    if (-not $forceClose -and -not $terminating -and -not $knownSession -and $Controller.PublishedCloseId) {
        # Rotate only when a fresh, identical route is able to open the gate.
        $state.Gate='Open'
        if((Get-GuardDailyDecision $state).CanLaunch){New-GuardDailyControllerSignal $Controller}
        $state.Gate='Closed'
    }
    $admission=@{
        OpenVerified={
            if($Controller.Signal.WaitOne(0)){return $false}
            $expires=[datetime]::ParseExact($state.Lease.ExpiresUtc,'o',
                [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            $verified=& $Operations.OpenVerified $expires $Controller.Signal
            if(-not $verified -or $Controller.Signal.WaitOne(0) -or -not (Get-GuardDailyDecision $state).CanLaunch){return $false}
            if($verified -is [bool]){return $verified}
            if($verified -isnot [ClaudeGuard.Network.AdmissionRenewal]){return $false}
            $state.Admission=[pscustomobject]@{
                Period=$verified.Period;RenewedUtc=$verified.RenewedUtc.ToString('o')
                PreviousOverlapMilliseconds=$verified.PreviousOverlapMilliseconds
            }
            $true
        }
        CloseVerified=$(if($forceClose){{ $closedBeforeInspection }}else{$Operations.CloseVerified})
        Publish={
            param($appliedState,$decision)
            Write-GuardDailyControllerRecords $Controller $appliedState $decision $Operations.WriteRecord
        }
    }
    try{
        $result=Set-GuardDailyAdmission $state $admission
    }finally{
        if($Operations.WriteNotice -and -not $Controller.Signal.WaitOne(0) -and -not $Controller.NoticeCause){
            $Controller.NoticeCause=if($isolation -ceq 'Active'){'IsolationActive'}
                elseif($inventory -ceq 'Changed'){
                    if($Operations.StoreUpdateDetected.Value -eq $true){'StoreUpdateHandoff'}
                    else{'CoverageUnverified'}
                }
                elseif($state.Exit -ceq 'Mismatch'){'ExitChanged'}
                elseif($state.Proxy -ceq 'Down'){
                    if($state.Failure -cin @('UpstreamTransportDown','RelayIdentityChanged')){$state.Failure}
                    else{'ProxyNotReady'}
                }elseif($Closing){'ControllerStopped'}
                elseif($state.Gate -ceq 'Unknown'){'StateUnknown'}
        }
        $Controller.Rechecking=$knownSession -and -not $terminating -and $state.Gate -ceq 'Closed'
        if($state.Gate -cne 'Open' -and -not $Controller.Rechecking){
            $Controller.StopPending=$true
            $Controller.Shutdown=Stop-GuardDailySession @{
                CloseGate={ $state.Gate -ceq 'Closed' }
                NotifyClosure={ $null=$Controller.Signal.Set() }
                Snapshot=$Operations.Snapshot; RequestClose=$Operations.RequestClose
                Wait=$Operations.Wait; ForceStop=$Operations.ForceStop
            }
            if($Operations.WriteNotice -and $Controller.NoticeCause){
                $Controller.NoticeProcess=$Controller.NoticeProcess -or $Controller.Shutdown.ObservedProcess
                $Controller.NoticeCloseAction=$Controller.NoticeCloseAction -or $Controller.Shutdown.ConfirmedCloseAction
            }
            if($Controller.Shutdown.NetworkBlocked -and $Controller.Shutdown.Exited -and -not (Test-GuardDailySessionStillOwned $Operations)){
                if($Operations.WriteNotice){
                    if($Controller.NoticeCause -and $Controller.NoticeCloseAction){
                        $Controller.NoticeStopped=$true
                    }elseif(-not $Controller.NoticeStopped){
                        $Controller.NoticeCause=$null
                        $Controller.NoticeProcess=$false
                        $Controller.NoticeCloseAction=$false
                    }
                    $Controller.ObservedSession=$false
                }
                $Controller.StopPending=$false
                if(-not $Closing -and $Operations.AfterClosed){& $Operations.AfterClosed | Out-Null}
            }
        }
    }
    if($Operations.WriteNotice){
        try{
            Update-GuardDailyNotice $Controller $Operations $state
        }catch{}
    }
    $result
}

function Start-GuardDailyController($Controller,[System.Collections.IDictionary]$Operations,
    [Threading.WaitHandle]$Halt,[ValidateRange(100,5000)][int]$PollMilliseconds=500) {
    try{
        $verified=try{(& $Operations.CloseVerified) -eq $true}catch{$false}
        $Controller.Gate=if($verified){'Closed'}else{'Unknown'}
        while(-not $Halt.WaitOne(0)){
            $cycleClock=[Diagnostics.Stopwatch]::StartNew()
            $null=Invoke-GuardDailyControllerCycle $Controller $Operations
            $delay=$PollMilliseconds
            if($Controller.Gate -ceq 'Open'){
                # Windows checks count toward the polling interval of an open lease.
                # Closed gates retain the normal retry delay.
                $delay=[int][Math]::Max(0L, $PollMilliseconds-$cycleClock.ElapsedMilliseconds)
            }
            if($Halt.WaitOne($delay)){break}
        }
    }finally{
        $null=Invoke-GuardDailyControllerCycle $Controller $Operations -Closing
    }
}

function Start-GuardDailyHost($Profile,[System.Collections.IDictionary]$Operations,
    [Threading.WaitHandle]$Halt,[ValidateRange(100,5000)][int]$PollMilliseconds=500,[switch]$StartProbeBeforeInventory) {
    $getPathDecision=${function:Get-GuardDailyPathDecision}
    $bindings=@{}
    foreach($key in $Operations.Keys){$bindings[$key]=$Operations[$key]}
    $bindings.ReadPath={
        param([bool]$completedOnly=$false)
        $relay=& $Operations.ReadRelay
        $observation=if($relay.Ready){ & $Operations.ReadObservation $relay $completedOnly }
        # The process and its listener can change while the observer is running.
        $current=& $Operations.ReadRelay
        if((!$relay.Ready -or !$current.Ready) -and $Operations.ClearObservation){
            & $Operations.ClearObservation | Out-Null
        }
        if($relay.Ready -and $current.Ready -and ($relay.ProcessId -ne $current.ProcessId -or
            $relay.StartedUtc -cne $current.StartedUtc -or $relay.RouteHash -cne $current.RouteHash)){
            return [pscustomobject]@{Proxy='Down';Exit='Unverified';Lease=$null;Failure='RelayIdentityChanged'}
        }
        & $getPathDecision $Profile $current $observation
    }.GetNewClosure()
    if($StartProbeBeforeInventory){$bindings.ReadEarlyPath=$bindings.ReadPath}
    $controller=New-GuardDailyController $Profile
    Initialize-GuardDailyNotice $controller $bindings
    try{Start-GuardDailyController $controller $bindings $Halt $PollMilliseconds}
    finally{$controller.Signal.Dispose()}
}

