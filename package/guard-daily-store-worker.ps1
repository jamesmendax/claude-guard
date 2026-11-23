#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][int]$SupervisorId,
    [Parameter(Mandatory=$true)][long]$SupervisorStart,
    [Parameter(Mandatory=$true)][ValidatePattern('\A[A-F0-9]{64}\z')][string]$Generation
)

$ErrorActionPreference='Stop'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard\daily'
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if($PSScriptRoot -ine $root -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Store preprotection requires the installed administrator controller.'
}

. "$PSScriptRoot\guard-runtime.ps1"
. "$PSScriptRoot\guard-daily-plan.ps1"
. "$PSScriptRoot\guard-sandboxie.ps1"
. "$PSScriptRoot\guard-daily-store-stage.ps1"
Add-Type -Path (Join-Path $PSScriptRoot 'guard-wfp.cs')

$supervisor=Get-Process -Id $SupervisorId
$wake=$null
try{
    $parentStarted=$supervisor.StartTime.ToUniversalTime()
    if($parentStarted.Ticks -ne $SupervisorStart){return}
    $record=Read-GuardDailyRecord 'daily-provisioned.json'
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($record.Generation -cne $Generation -or $record.LaunchUserSid -cne $sid -or
        $record.Containment -cne 'Sandboxie' -or -not (Test-GuardDailyScopeBinding $record)){return}
    $process=[Diagnostics.Process]::GetCurrentProcess()
    try{
        $identity=@{Pid=$PID;ParentPid=$SupervisorId;StartedUtc=$process.StartTime.ToUniversalTime().ToString('o')
            ParentStartedUtc=$parentStarted.ToString('o');WatcherSubscribed=$false;DirectoryWatching=$false}
    }finally{$process.Dispose()}
    $cache=@{Inventory=$null;Paths=$null;Device=$null}
    $app=$null
    $route=$null
    $pending=@()
    $pendingDirectories=@()
    $recentRecords=[Collections.Generic.HashSet[long]]::new()
    $recordOrder=[Collections.Generic.Queue[long]]::new()
    $replayDue=[datetime]::MinValue
    $subscribeDue=[datetime]::MinValue
    $directoryDue=[datetime]::MinValue
    while(-not $supervisor.HasExited){
        if($wake -and $wake.Failed){$wake.Dispose(); $wake=$null; $replayDue=[datetime]::MinValue}
        if(-not $wake -and [datetime]::UtcNow -ge $subscribeDue){
            $subscribeDue=[datetime]::UtcNow.AddSeconds(5)
            try{$wake=[ClaudeGuard.Network.StoreDeploymentWake]::new()}catch{}
            $identity.WatcherSubscribed=$null -ne $wake
            $replayDue=[datetime]::MinValue
            $directoryDue=[datetime]::MinValue
        }
        if($wake){
            if(-not $wake.DirectoryWatching -and $cache.Device -and [datetime]::UtcNow -ge $directoryDue){
                $directoryDue=[datetime]::UtcNow.AddSeconds(5)
                $null=$wake.WatchDirectory($cache.WindowsAppsRoot,$record.PackageFullName)
            }
            $newEvents=@($wake.Drain() | Where-Object Id -In 574,855)
            foreach($notice in $wake.DrainDirectoryNotices()){
                if($pendingDirectories.Package -ccontains $notice.Package){continue}
                $pendingDirectories+=,$notice
                try{
                    $record574=$wake.QueryPreparation($notice.Package)
                    if($record574){$newEvents+=,$record574}
                }catch{}
            }
            foreach($event in $newEvents){
                $recordId=[long]$event.RecordId
                if(-not $recentRecords.Add($recordId)){continue}
                $recordOrder.Enqueue($recordId)
                if($recordOrder.Count -gt 256){$null=$recentRecords.Remove($recordOrder.Dequeue())}
                $pending+=,$event
            }
            if($wake.TakeReplayRequest() -or $pending.Count -gt 128 -or $pendingDirectories.Count -gt 128){
                $replayDue=[datetime]::MinValue
                $pending=@($pending | Select-Object -Last 128)
                $pendingDirectories=@($pendingDirectories | Select-Object -Last 128)
            }
        }
        $directoryWatching=[bool]($wake -and $wake.DirectoryWatching)
        if($directoryWatching -ne $identity.DirectoryWatching){
            $identity.DirectoryWatching=$directoryWatching
            $replayDue=[datetime]::MinValue
        }
        if(($pending.Count -or $pendingDirectories.Count) -and $cache.Device){
            try{
                $orderedEvents=@($pending | Sort-Object RecordId)
                if(Invoke-GuardDailyStoreStage $record $app $route $identity $cache $orderedEvents -Fast -DirectoryNotices $pendingDirectories){
                    $pending=@()
                    $pendingDirectories=@()
                }
            }catch{$replayDue=[datetime]::MinValue}
        }
        try{
            if([datetime]::UtcNow -ge $replayDue){
                $replayDue=[datetime]::UtcNow.AddSeconds(5)
                if((Read-GuardDailyRecord 'daily-provisioned.json').Generation -cne $Generation){return}
                $app=Confirm-GuardDailySandboxieApp $record
                $route=Read-GuardDailyRelayConfig $record.Port
                if($route.Hash -ceq $record.RouteHash -and (Get-GuardIsolationMode) -ceq 'Off'){
                    $null=Invoke-GuardDailyStoreStage $record $app $route $identity $cache
                }
            }
        }catch{
            # Keep the active generation untouched. A registered update is
            # handled by the supervisor's verified maintenance path.
        }
        $wait=if($wake -and $cache.Device -and -not $wake.DirectoryWatching -and [datetime]::UtcNow -ge $directoryDue){0}
            elseif(($pending.Count -or $pendingDirectories.Count) -and $cache.Device){35}else{5000}
        if($wake){$null=$wake.Wait($wait)}
        elseif($supervisor.WaitForExit($wait)){return}
    }
}finally{
    try{if($wake){$wake.Dispose()}}
    finally{$supervisor.Dispose()}
}
