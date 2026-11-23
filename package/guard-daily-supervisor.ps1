#Requires -Version 5.1
param([switch]$Run,[switch]$Prepare,[switch]$Sandboxie,[switch]$VerifySandboxie)

$ErrorActionPreference='Stop'
if(@($Run,$Prepare,$VerifySandboxie | Where-Object {$_}).Count -gt 1){throw 'Choose one daily controller operation.'}
if($Sandboxie -and -not $Prepare){throw 'Select the containment type only during preparation.'}

if($Run -or $VerifySandboxie){
    $standardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard\daily'
    if([IO.Path]::GetFullPath($PSScriptRoot) -ine $standardRoot){
        throw 'The daily controller must run from its administrator-owned installation.'
    }
    $user=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not $user.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        throw 'The daily controller requires its installed Windows administrator task.'
    }
    $trusted=@('S-1-5-18','S-1-5-32-544')
    $change=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    $files=@('guard-runtime.ps1','guard-common.ps1','guard-privacy.ps1','guard-diagnostics.ps1','guard-isolation.ps1',
        'guard-network.ps1','guard-daily.ps1','guard-daily-controller.ps1','guard-daily-plan.ps1','guard-wfp.cs','guard-app-container.cs',
        'guard-lookup-preferences.ps1','guard-daily-notifications.ps1','guard-daily-notifier.ps1','guard-daily-notifier-task.ps1',
        'guard-daily-supervisor.ps1','guard-sandboxie.ps1','guard-daily-package.ps1','guard-relay-evidence.cs',
        'guard-daily-store-stage.ps1','guard-daily-store-worker.ps1',
        'guard-dedicated-relay.exe','guard-exit-observer.exe','cloudflare-exit-probe.mjs','relay-data')
    $paths=@((Split-Path -Parent $standardRoot),$standardRoot) + @($files | ForEach-Object {Join-Path $standardRoot $_})
    foreach($path in $paths){
        $dir=Get-Item -LiteralPath $path -Force
        $acl=Get-Acl -LiteralPath $path
        if(($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){
            throw 'The daily controller installation has an untrusted path.'
        }
        foreach($entry in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            if($entry.AccessControlType -eq 'Allow' -and ($entry.FileSystemRights -band $change) -and
                $entry.IdentityReference.Value -notin $trusted){throw 'The controller installation is writable outside its administrator.'}
        }
    }
}

. "$PSScriptRoot\guard-runtime.ps1"
. "$PSScriptRoot\guard-daily-controller.ps1"
if($VerifySandboxie){
    . "$PSScriptRoot\guard-sandboxie.ps1"
    . "$PSScriptRoot\guard-daily-plan.ps1"
    $record=Read-GuardDailyRecord 'daily-provisioned.json'
    if($record.Containment -cne 'Sandboxie' -or -not (Test-GuardDailyScopeBinding $record)){
        throw 'The production package is not provisioned for Sandboxie.'
    }
    $app=Confirm-GuardDailySandboxieApp $record
    $driverRoot=Join-Path $PSScriptRoot 'sandboxie'
    $until=[datetime]::UtcNow.AddSeconds(25)
    do {
        try{
            if((Test-GuardSandboxieProtection $driverRoot $app.Root $record.Port) -and
                -not @(Get-GuardSandboxieProcessEntries $driverRoot).Count){
                'SandboxieReady'
                return
            }
            $reason='The production sandbox is not empty and verified.'
        }catch{$reason=$_.Exception.Message}
        Start-Sleep -Milliseconds 200
    }while([datetime]::UtcNow -lt $until)
    throw $reason
}
if(-not $Run -and -not $Prepare){
    $state=Get-GuardDailyStatus
    [pscustomobject]@{
        Ready=$state.CanLaunch;Readiness=$state.Readiness;Reason=$state.Reason
        Provisioned=Test-Path -LiteralPath (Get-GuardDataPath 'daily-provisioned.json') -PathType Leaf
    } | ConvertTo-Json -Compress
    return
}

. "$PSScriptRoot\guard-daily-plan.ps1"

$installRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard\daily'
$relayImage=Join-Path $installRoot 'guard-dedicated-relay.exe'
$observerImage=Join-Path $installRoot 'guard-exit-observer.exe'
$observerScript=Join-Path $installRoot 'cloudflare-exit-probe.mjs'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Add-Type -Path (Join-Path $PSScriptRoot 'guard-wfp.cs')
Add-Type -Path (Join-Path $PSScriptRoot 'guard-app-container.cs')
if($Prepare){
    $candidate=Split-Path -Parent $PSScriptRoot
    $evidence=Join-Path $candidate 'evidence'
    $referencePath=Join-Path $evidence 'cloudflare-exit-probe.json'
    $reference=Get-Content -LiteralPath $referencePath -Raw | ConvertFrom-Json
    $expected=$null
    if($reference.Status -cne 'Observed' -or $reference.HttpStatus -ne 200 -or
        -not [ipaddress]::TryParse([string]$reference.Ipv4,[ref]$expected) -or
        $expected.AddressFamily -ne 'InterNetwork' -or $expected.ToString() -cne $reference.Ipv4){
        throw 'The existing public IPv4 receipt could not be used as a reference.'
    }
    $port=18793
    $route=Read-GuardDailyRelayConfig $port
    $id=[guid]::NewGuid()
    $registration=$null
    $vpnGuid=$null
    $containment='AppContainer'
    if($Sandboxie){
        . "$PSScriptRoot\guard-sandboxie.ps1"
        $registration=Get-GuardSandboxieApp
        $containment='Sandboxie'
        $scopeName='GuardDesktop'
        $scopeSid=$registration.PackageSid
        $firewall=Get-Content -LiteralPath (Get-GuardStatePath) -Raw | ConvertFrom-Json
        $vpn=Get-GuardVpnAdapter ([string]$firewall.VpnGuid)
        if($vpn.Name -cne 'Bettbox'){throw 'The active pinned adapter is not Bettbox.'}
        $vpnGuid=([guid]$vpn.InterfaceGuid).ToString('D')
    }else{
        $scopeName='claude-guard-'+$id.ToString('N')
        $scopeSid=[ClaudeGuard.Processes.GuardAppContainer]::DeriveSid($scopeName)
    }
    $inventory=Get-GuardInventory -LocalOnly
    if($Sandboxie -and $registration.DesktopPath -notin @($inventory.DesktopPaths)){
        throw 'The registered Desktop executable is missing from the protected inventory.'
    }
    $plan=New-GuardInstalledPolicy $route $port $id $inventory $scopeSid $containment
    $desktopImages=@(Read-GuardDailyDesktopImages $inventory)
    $desktopHashes=@($desktopImages | ForEach-Object Hash)
    $relaySource=Join-Path $evidence 'mihomo-syntax\mihomo\mihomo-windows-amd64-v1.exe'
    $relayHash=(Get-FileHash -LiteralPath $relaySource -Algorithm SHA256).Hash
    if($relayHash -cne 'CF894375DBC00AB6708C1314AC35BBD29059F4C37F315353AACA7F1A9C566DE6'){
        throw 'The approved relay asset changed.'
    }
    $observerSource=Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex\tools\node-v24.22.3\node.exe'
    $scriptSource=Join-Path $candidate 'tests\cloudflare-exit-probe.mjs'
    $observerHash=(Get-FileHash -LiteralPath $observerSource -Algorithm SHA256).Hash
    $scriptHash=(Get-FileHash -LiteralPath $scriptSource -Algorithm SHA256).Hash
    $assets=@(
        [pscustomobject]@{Source=$relaySource;Target=$relayImage;Sha256=$relayHash}
        [pscustomobject]@{Source=$observerSource;Target=$observerImage;Sha256=$observerHash}
        [pscustomobject]@{Source=$scriptSource;Target=$observerScript;Sha256=$scriptHash}
    )
    foreach($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object Extension -In '.ps1','.cs','.cmd')){
        $assets+=[pscustomobject]@{Source=$file.FullName;Target=(Join-Path $installRoot $file.Name)
            Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash}
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try{
        $binding=@($plan.PersistentSublayer,$route.Hash,$expected.ToString(),$sid,$scopeName,$scopeSid,$containment,
                   $registration.PackageFullName,$registration.AppId,$vpnGuid)+@($assets.Sha256)+$desktopHashes
        $generation=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($binding -join '|')))).Replace('-','')
    }finally{$sha.Dispose()}
    $draft=[ordered]@{
        Version=2;Generation=$generation;DeploymentId=$id;Sublayer=$plan.PersistentSublayer;AssignedSublayerWeight=$null
        LaunchUserSid=$sid;Port=$port;RouteHash=$route.Hash;DesktopHashes=$desktopHashes;DesktopImages=$desktopImages
        ScopeName=$scopeName;ScopeSid=$scopeSid;Containment=$containment;VpnGuid=$vpnGuid
        PackageFullName=$registration.PackageFullName;PackageRoot=$registration.Root
        AppId=$registration.AppId;DesktopPath=$registration.DesktopPath
        ExpectedIpv4=$expected.ToString();ReferenceUtc=$reference.Utc;Witness=$null;BackupExitLookup=$true
        RelaySha256=$relayHash;ObserverSha256=$observerHash;ObserverScriptSha256=$scriptHash
        BaselineKeys=$plan.GetBaselineKeys();BootKeys=$plan.GetBootKeys();Assets=$assets
    }
    $outputPath=Join-Path $evidence $(if($Sandboxie){'daily-sandboxie-provisioning-draft.json'}else{'daily-provisioning-draft.json'})
    $draft | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outputPath -Encoding UTF8
    [pscustomobject]@{
        Prepared=$true;Draft=$outputPath;Assets=$assets.Count;BaselineRules=$plan.BaseCount;BootRules=$plan.BootCount
        ExpectedIpv4=$expected.ToString();NativeRulesWritten=$false;ObserverApproved=$false
    } | ConvertTo-Json -Compress
    return
}

if(-not (Test-GuardDailyReleaseControllerMayRun)){throw 'An interrupted Guard installation requires recovery.'}
$record=Read-GuardDailyRecord 'daily-provisioned.json'
$sandboxed=$record.Containment -ceq 'Sandboxie'
if($record.Version -ne 2 -or $record.LaunchUserSid -cne $sid -or -not (Test-GuardDailyScopeBinding $record) -or
    (-not $sandboxed -and [ClaudeGuard.Processes.GuardAppContainer]::DeriveSid($record.ScopeName) -cne $record.ScopeSid) -or
    $record.Witness -cne 'CloudflareTrace' -or
    ($record.PSObject.Properties['BackupExitLookup'] -and $record.BackupExitLookup -isnot [bool]) -or
    (Get-GuardIsolationMode) -cne 'Off'){
    throw 'The installed configuration has no active daily route and approved observer.'
}
if(-not ('ClaudeGuard.Network.RelayListener' -as [type])){
    Add-Type -Path (Join-Path $PSScriptRoot 'guard-relay-evidence.cs')
}
foreach($asset in @(@($relayImage,$record.RelaySha256),@($observerImage,$record.ObserverSha256),@($observerScript,$record.ObserverScriptSha256))){
    $file=Get-Item -LiteralPath $asset[0] -Force
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $asset[1]){
        throw 'A daily controller asset changed.'
    }
}
$route=Read-GuardDailyRelayConfig $record.Port
if($route.Hash -cne $record.RouteHash){throw 'The selected Bettbox route changed.'}
$driverRoot=$null
if($sandboxed){
    . "$PSScriptRoot\guard-sandboxie.ps1"
    . "$PSScriptRoot\guard-daily-store-stage.ps1"
    . "$PSScriptRoot\guard-daily-package.ps1"
    $driverRoot=Join-Path $installRoot 'sandboxie'
    $app=Get-GuardSandboxieApp
    if($app.PackageFullName -cne $record.PackageFullName -or (Test-Path -LiteralPath (Get-GuardDataPath 'daily-package-pending.json'))){
        $record=Update-GuardDailyPackage $record $app $route
    }
    $null=Confirm-GuardDailySandboxieApp $record
}
$profile=@{
    Generation=[string]$record.Generation;RouteHash=[string]$record.RouteHash;Port=[int]$record.Port
    ExpectedIpv4=[string]$record.ExpectedIpv4;DesktopHashes=@($record.DesktopHashes);LaunchUserSid=$sid
    ScopeName=[string]$record.ScopeName;ScopeSid=[string]$record.ScopeSid;Containment=[string]$record.Containment
}
$inventory=Get-GuardInventory -LocalOnly
$plan=New-GuardInstalledPolicy $route $profile.Port ([guid]$record.DeploymentId) $inventory $profile.ScopeSid $profile.Containment
if($plan.PersistentSublayer -ne [guid]$record.Sublayer){throw 'The approved program inventory changed.'}
if(-not (Test-GuardDailyDesktopImages $record.DesktopImages @(Read-GuardDailyDesktopImages $inventory))){
    throw 'The approved Desktop image changed.'
}
$assignedWeight=[uint16]0
if($null -eq $record.AssignedSublayerWeight -or
    -not [uint16]::TryParse([string]$record.AssignedSublayerWeight,[ref]$assignedWeight)){
    throw 'The installed rule weight is missing from the protected deployment receipt.'
}
if($sandboxed){
    $prefix=$app.Root.TrimEnd('\')+'\'
    $registeredImages=[string[]]@($inventory.Programs | Where-Object {$_.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)})
    $plan=$plan.WithRegisteredPackageAdmission($registeredImages)
}
$policy=[ClaudeGuard.Network.WindowsPolicySession]::AttachPersistent($plan,$assignedWeight)
$halt=[Threading.ManualResetEvent]::new($false)
$upgradeDetected=@{Value=$false}
$storeWorker=@{Child=$null;RetryUtc=[datetime]::MinValue}
$processContext=@{Inventory=$null;Service=$null}
$relayContext=@{Child=$null;AttemptUtc=[datetime]::MinValue}
$observationCache=@{ProcessId=0;StartedUtc='';RouteHash='';AttemptUtc=[datetime]::MinValue;Proof=$null;Worker=$null}
$runtimeRelay=$route.Json | ConvertFrom-Json
# The approved route and its literal endpoint stay bound to the protected
# fingerprint. Owned relay evidence is inspected in memory only.
$runtimeRelay.'log-level'='info'
$runtimeRelayJson=$runtimeRelay | ConvertTo-Json -Depth 8 -Compress
$approvedUpstream="$($route.Upstream.server):$($route.Upstream.port)"
$observer=@{
    Start={
        $backup=Test-GuardDailyBackupLookupEnabled $record
        Start-GuardDailyChild $observerImage ('--use-bundled-ca "'+$observerScript+'" --protected-listener') (
            @{port=$profile.Port;backupExitLookup=$backup} | ConvertTo-Json -Compress) |
            Add-Member -NotePropertyName BackupExitLookup -NotePropertyValue $backup -PassThru
    }
    Poll={
        param($worker,$relay)
        Read-GuardDailyObservationWorker $worker $relay $profile.Generation -RelayEvidence $relayContext.Child.RelayEvidence `
            -BackupExitLookup:$worker.BackupExitLookup
    }
    Stop={param($worker) Stop-GuardDailyChild $worker}
}
$ensureStoreWorker={
    if(-not $sandboxed -or [datetime]::UtcNow -lt $storeWorker.RetryUtc -or
        ($storeWorker.Child -and -not $storeWorker.Child.Process.HasExited)){return}
    $storeWorker.RetryUtc=[datetime]::UtcNow.AddSeconds(10)
    try{
        $exited=$storeWorker.Child
        $storeWorker.Child=$null
        Stop-GuardDailyChild $exited
        $self=[Diagnostics.Process]::GetCurrentProcess()
        try{$started=$self.StartTime.ToUniversalTime().Ticks}finally{$self.Dispose()}
        $worker=Join-Path $PSScriptRoot 'guard-daily-store-worker.ps1'
        $shell=Join-Path $PSHOME 'powershell.exe'
        $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -SupervisorId {1} -SupervisorStart {2} -Generation {3}' -f
            $worker,$PID,$started,$record.Generation
        $storeWorker.Child=Start-GuardDailyChild $shell $arguments ''
    }catch{Write-Warning 'The Store preprotection worker is unavailable.'}
}
try{
    & $ensureStoreWorker
    $homeDir=Join-Path $PSScriptRoot 'relay-data'
    $operations=@{
        ReadIsolation={
            if(-not (Test-GuardDailyReleaseControllerMayRun)){return 'Unknown'}
            Get-GuardIsolationMode
        }
        LaunchSessionBusy={Test-GuardDailyLaunchSessionBusy}
        VerifyInventory={
            if($sandboxed){
                $app=Get-GuardSandboxieApp
                if(Test-GuardDailyStoreUpgrade $record $app){
                    $upgradeDetected.Value=$true
                    $null=$halt.Set()
                    return $false
                }
                & $ensureStoreWorker
                $null=Confirm-GuardDailySandboxieApp $record $app
                if(-not (Test-GuardSandboxieProtection $driverRoot $app.Root $profile.Port)){return $false}
            }
            $current=Get-GuardInventory -LocalOnly
            $processContext.Inventory=$current
            $processContext.Service=$null
            if($sandboxed){
                $processContext.Service=Get-GuardDailyStoreService $current $app.Root
                foreach($entry in @(Get-GuardDailyProcessEntries $current $null $processContext.Service)){
                    if(-not $entry.Start){throw 'A process identity could not be checked.'}
                    $contained=try{Test-GuardSandboxieProcess $driverRoot $entry.Id}
                    catch{if(Test-GuardProcessExited $entry.Process){continue};throw}
                    if(-not $contained -and -not (Test-GuardProcessExited $entry.Process)){return $false}
                }
            }
            if((New-GuardInstalledPolicy $route $profile.Port ([guid]$record.DeploymentId) $current $profile.ScopeSid $profile.Containment).PersistentSublayer -ne $plan.PersistentSublayer){
                return $false
            }
            Test-GuardDailyDesktopImages $record.DesktopImages @(Read-GuardDailyDesktopImages $current)
        }
        AfterClosed={
            if($relayContext.Child -and -not $relayContext.Child.Process.HasExited){return}
            if(([datetime]::UtcNow-$relayContext.AttemptUtc).TotalSeconds -lt 5){return}
            $relayContext.AttemptUtc=[datetime]::UtcNow
            if((Get-GuardIsolationMode) -cne 'Off' -or -not (Test-GuardDailyReleaseControllerMayRun)){return}
            try{
                if((Read-GuardDailyRelayConfig $profile.Port).Hash -cne $profile.RouteHash){return}
                Stop-GuardDailyChild $relayContext.Child
                $relayContext.Child=$null
                $relayContext.Child=Start-GuardDailyChild $relayImage ('-d "'+$homeDir+'" -f -') $runtimeRelayJson -MonitorUpstreamEndpoint $approvedUpstream
            }catch{Write-Warning 'The dedicated relay could not be started. Desktop remains offline.'}
        }
        ReadRelay={
            if($sandboxed -and -not [ClaudeGuard.Network.RelayListener]::IsAdapterUp([guid]$record.VpnGuid,'Bettbox')){
                return
            }
            $owner=$relayContext.Child.Process
            if(-not $owner -or $owner.HasExited -or (Read-GuardDailyRelayConfig $profile.Port).Hash -cne $profile.RouteHash){return}
            if(-not (Test-GuardDailyRelayListener $profile.Port $owner.Id)){return}
            [pscustomobject]@{
                Ready=$true;RouteHash=$profile.RouteHash;Port=$profile.Port
                ProcessId=$owner.Id;StartedUtc=$owner.StartTime.ToUniversalTime().ToString('o')
            }
        }
        ReadObservation={
            param($identity,[bool]$completedOnly=$false)
            Get-GuardDailyObservation $observationCache $identity $observer -PollOnly:$completedOnly
        }
        ObservationCompleted={
            $worker=$observationCache.Worker
            $worker -and $worker.Process.HasExited -and $worker.Output.IsCompleted
        }
        ClearObservation={Get-GuardDailyObservation $observationCache $null $observer}
        OpenVerified={
            param($deadline,$signal)
            if(-not (Test-GuardDailyReleaseControllerMayRun)){return $false}
            if($sandboxed -and -not (Test-GuardSandboxieProtection $driverRoot $record.PackageRoot $profile.Port)){return $false}
            $policy.OpenUntilWithReceipt($deadline,$signal,$false)
        }
        CloseVerified={$policy.Close(); $true}
        WriteRecord={param($name,$value) Save-GuardAdministratorJson (Get-GuardDataPath $name) $value}
        WriteNotice={param($name,$value) Save-GuardAdministratorJson (Get-GuardDataPath $name) $value}
        ReadPendingStopNotice={Read-GuardDailyPendingStopNotice}
        StoreUpdateDetected=$upgradeDetected
        Snapshot={
            if($sandboxed){Get-GuardDailySandboxedEntries $processContext.Inventory $driverRoot $processContext.Service}
            else{Get-GuardDailyProcessEntries (Get-GuardInventory -LocalOnly) $null}
        }
        RequestClose={param($entry)
            if(-not $entry.Process.HasExited -and $entry.Process.Id -eq $entry.Id -and $entry.Process.StartTime.ToUniversalTime().Ticks -eq $entry.Start){
                $entry.Process.CloseMainWindow()
            }
        }
        Wait={param($ms) Start-Sleep -Milliseconds $ms}
        ForceStop={
            param($entry)
            if(-not $entry.Process.HasExited -and $entry.Process.Id -eq $entry.Id -and $entry.Process.StartTime.ToUniversalTime().Ticks -eq $entry.Start){
                $entry.Process.Kill()
                if(-not $entry.Process.WaitForExit(2000)){throw 'The protected process did not exit.'}
                $true
            }
        }
    }
    Start-GuardDailyHost $profile $operations $halt 1000 -StartProbeBeforeInventory
}finally{
    try{$policy.Dispose()}finally{
        try{Stop-GuardDailyChild $observationCache.Worker}
        finally{
            try{Stop-GuardDailyChild $relayContext.Child}
            finally{Stop-GuardDailyChild $storeWorker.Child; $halt.Dispose()}
        }
    }
}
if($upgradeDetected.Value){throw 'A newer Store package was registered. Restart the controller to verify the replacement policy.'}
