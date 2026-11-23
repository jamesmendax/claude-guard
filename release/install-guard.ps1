#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Plan')]
param(
    [Parameter(ParameterSetName='Plan')][switch]$Plan,
    [Parameter(Mandatory,ParameterSetName='Install')][switch]$Install,
    [Parameter(Mandatory,ParameterSetName='Recover')][switch]$Recover,
    [Parameter(ParameterSetName='Install')][switch]$RouteOnly,
    [Parameter(ParameterSetName='Install')][pscredential]$NodeProfile,
    [Parameter(ParameterSetName='Install')][ValidatePattern('\A[A-F0-9]{64}\z')][string]$RequirePriorGeneration,
    [Parameter(ParameterSetName='Install')][Parameter(ParameterSetName='Recover')][hashtable]$NodeOperations,
    [Parameter(ParameterSetName='Install')][Parameter(ParameterSetName='Recover')][scriptblock]$ProgressCallback,
    [string]$ExpectedIpv4,
    [guid]$VpnGuid=[guid]::Empty
)
$ErrorActionPreference='Stop'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
$daily=Join-Path $root 'daily'
$stage=Split-Path -Parent $PSScriptRoot
$provisioned=Join-Path $root 'daily-provisioned.json'
if(-not $Install -and -not $Recover){
    [pscustomobject]@{
        Mode=if(Test-Path -LiteralPath $provisioned -PathType Leaf){'Update'}else{'Fresh'}
        Installed=$false;RequiresAdministrator=$true;RequiresRegisteredStoreDesktop=$true
        RequiresBettboxTunnel=$true;RequiresVerifiedIpv4=-not [IO.File]::Exists($provisioned);LaunchesDesktop=$false
        RecoveryPending=[IO.File]::Exists((Join-Path $root 'release-install-pending.json'))
    }
    return
}

$admin=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not [Environment]::Is64BitProcess -or
    $PSVersionTable.PSEdition -ne 'Desktop'){
    throw 'Installation requires Windows PowerShell 5.1 x64 in the approved administrator session.'
}
if((Split-Path -Parent $stage) -ine $root -or (Split-Path -Leaf $stage) -cnotmatch '\Arelease-install-[a-f0-9]{32}\z' -or
    $PSScriptRoot -ine (Join-Path $stage 'release')){
    throw 'Installation requires the approved administrator-owned release directory.'
}
function Assert-GuardReleaseBootstrapPath([string]$Path) {
    $file=Get-Item -LiteralPath $Path -Force
    $acl=Get-Acl -LiteralPath $Path
    $allowed=@('S-1-5-18','S-1-5-32-544')
    $writes=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed -or
        @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $writes) -and $_.IdentityReference.Value -notin $allowed
        }).Count){throw 'An administrator cannot run this release from a writable or redirected location.'}
}
$helpers=Join-Path $PSScriptRoot 'install-guard-helpers.ps1'
foreach($path in $root,$stage,$PSScriptRoot,$PSCommandPath,$helpers){Assert-GuardReleaseBootstrapPath $path}
. $helpers
$package=Join-Path $stage 'package'
$runtime=Join-Path $stage 'runtime'
Assert-GuardReleaseOwnedPath $package -Directory
Assert-GuardReleaseOwnedPath $runtime -Directory
$packageFiles=$script:GuardReleasePackageFiles+@('guard-profile-store.ps1','guard-node-profile.ps1','guard-region-profile.ps1')
$assets=@(
    foreach($name in $packageFiles){Get-GuardReleaseAsset (Join-Path $package $name) (Join-Path $daily $name)}
    foreach($name in $script:GuardReleaseRuntimePins.Keys){
        Get-GuardReleaseAsset (Join-Path $runtime $name) (Join-Path $daily $name) $script:GuardReleaseRuntimePins[$name]
    }
)
. "$package\guard-runtime.ps1"
. "$package\guard-daily-plan.ps1"
. "$package\guard-profile-store.ps1"
$bettboxProfileModule=Join-Path $package 'guard-bettbox-profile.ps1'
Assert-GuardReleaseOwnedPath $bettboxProfileModule
. $bettboxProfileModule
. "$package\guard-sandboxie.ps1"
. "$package\guard-daily-notifier-task.ps1"
. "$package\guard-daily-store-stage.ps1"
Add-Type -Path "$package\guard-wfp.cs"

$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$taskName='ClaudeVPNGuard Daily Controller'
$supervisor=Join-Path $daily 'guard-daily-supervisor.ps1'
$relay=Join-Path $daily 'guard-dedicated-relay.exe'
$observer=Join-Path $daily 'guard-exit-observer.exe'
$driverRoot=Join-Path $daily 'sandboxie'
$runtimeHome=Join-Path $daily 'relay-data'
$taskArguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$supervisor+'" -Run'
$backgroundControllerArguments='--background-controller'
$journalFile=Join-Path $root 'release-install-pending.json'
$statusFile=Join-Path $stage 'install-result.json'
$result=[ordered]@{Operation=$null;Mode=$null;Phase='Preparing';Installed=$false;Restored=$false;RestoredClosed=$false;BootRules=0;FreshProofs=0
    LocaleVerification=$null;SiteAcceptLanguage=$null;LocaleRollback=$null;LocaleFailure=$null
    BrowserStatus=$null;WebsiteStatus=$null;AllSettingsVerified=$null
    PhaseTimes=[ordered]@{};Verification=[ordered]@{};RestoreVerification=[ordered]@{}
    Generation=$null;PriorGeneration=$null;HadPrior=$null
    FailedPhase=$null;Error=$null;RestoreError=$null}
$state=@{Previous=$null;Record=$null;OldPolicy=$null;Policy=$null;OldWeight=$null;Weight=$null
    Fresh=$false;NewPolicy=$false;OldPolicyRetired=$false;PriorRouteUnavailable=$false;RootCreated=$false;DriverChanged=$false
    ControllerStopped=$false;ControllerCreated=$false;NotifierTouched=$false;ProfileTouched=$false
    Notifier=$null;ControllerAction=$null;Profile=$null;Replaced=@{};CreatedFiles=[Collections.Generic.List[string]]::new()}
$operationMutex=$null
$firewallMutex=$null
$launchMutex=$null
$operationHeld=$false
$firewallHeld=$false
$launchHeld=$false
$revision=$null
$rollbackRunner=$null
$runner=[Diagnostics.Process]::GetCurrentProcess()
try{
    $runnerStarted=$runner.StartTime.ToUniversalTime().ToString('o')
    $bootstrap=Join-Path $stage 'ClaudeGuardSetup.exe'
    if($runner.Path -ine $bootstrap){throw 'Use the protected Guard setup executable to change the installation.'}
    $runnerSha256=Get-GuardDailyReleaseImageHash $bootstrap
}finally{$runner.Dispose()}

function Send-GuardReleaseProgress([string]$Phase,$Verification) {
    if(-not $result.PhaseTimes.Contains($Phase)){$result.PhaseTimes[$Phase]=[datetime]::UtcNow.ToString('o')}
    if($ProgressCallback){
        try{
            $null=& $ProgressCallback ([pscustomobject]@{
                Phase=$Phase;Proofs=[int]$Verification.Proofs;RequiredProofs=[int]$Verification.RequiredProofs
                Status=[string]$Verification.Status;WorkerStatus=[string]$Verification.WorkerStatus
                ElapsedSeconds=[int]$Verification.ElapsedSeconds;TimeoutSeconds=[int]$Verification.TimeoutSeconds
            })
        }catch{}
    }
}

function Save-GuardReleaseReceipt {
    $result.Generation=$state.Record.Generation
    $result.PriorGeneration=$state.Previous.Generation
    if($result.Mode -cin 'Fresh','Update','RouteOnly' -or $state.Record){$result.HadPrior=-not $state.Fresh}
    if($operationPath -and [IO.Directory]::Exists($operationPath)){
        Save-GuardAdministratorJson (Join-Path $operationPath 'result.json') $result
    }
    Save-GuardAdministratorJson $statusFile $result
}
function Save-GuardReleaseJournal {
    $runnerId=$PID
    $started=$runnerStarted
    $version=2
    if($rollbackRunner){
        if($rollbackRunner.HasExited){throw 'The protected rollback runner has stopped.'}
        $runnerId=$rollbackRunner.Id
        $started=$rollbackRunner.StartTime.ToUniversalTime().ToString('o')
        $version=1
    }
    Save-GuardAdministratorJson $journalFile ([pscustomobject]@{
        Version=$version;Stage=Split-Path -Leaf $stage;Operation=$result.Operation;OwnerSid=$sid;Phase=$result.Phase;Fresh=$state.Fresh
        RunnerPid=$runnerId;RunnerStartedUtc=$started;RunnerSha256=$runnerSha256
        Deployment=$state.Record.DeploymentId;Sublayer=$state.Record.Sublayer;Weight=$state.Weight
        PriorDeployment=$state.Previous.DeploymentId;PriorSublayer=$state.Previous.Sublayer;PriorWeight=$state.OldWeight
        NewPolicy=$state.NewPolicy;OldPolicyRetired=$state.OldPolicyRetired;RootCreated=$state.RootCreated
        PriorRouteUnavailable=$state.PriorRouteUnavailable
        ControllerStopped=$state.ControllerStopped;ControllerCreated=$state.ControllerCreated;DriverChanged=$state.DriverChanged
        ProfileTouched=$state.ProfileTouched;NotifierTouched=$state.NotifierTouched
        HadStoreStage=$state.HadStoreStage;Replaced=@($state.Replaced.Values);CreatedFiles=$state.CreatedFiles.ToArray()
    })
}
function Start-GuardReleaseRollbackRunner {
    # The prior release recognizes a PowerShell runner. EOF ends it if this setup process exits.
    $launch=[Diagnostics.ProcessStartInfo]::new($shell,'-NoProfile -NonInteractive -Command "[void][Console]::In.ReadToEnd()"')
    $launch.UseShellExecute=$false
    $launch.CreateNoWindow=$true
    $launch.RedirectStandardInput=$true
    $script:rollbackRunner=[Diagnostics.Process]::Start($launch)
    if(-not $script:rollbackRunner){throw 'The protected rollback runner could not start.'}
    Save-GuardReleaseJournal
}
function Test-GuardReleaseControllerAction($Action) {
    if($Action.Execute -ieq $shell -and $Action.Arguments -ceq $taskArguments -and -not $Action.WorkingDirectory){return $true}
    if($Action.Arguments -cne $backgroundControllerArguments -or $Action.WorkingDirectory -ine $daily){return $false}
    try{[bool](Get-GuardDailyReleaseImageHash $Action.Execute)}catch{$false}
}
function Get-GuardReleaseControllerTask {
    $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if($task -and (@($task.Actions).Count -ne 1 -or -not (Test-GuardReleaseControllerAction $task.Actions[0]) -or
        $task.Principal.RunLevel -ne 'Highest' -or
        $task.Principal.LogonType -ne 'Interactive' -or (ConvertTo-GuardNotifierSid $task.Principal.UserId) -cne $sid)){
        throw 'A different task owns the Guard controller name.'
    }
    $task
}
function Set-GuardReleaseControllerAction($Action) {
    $task=Get-GuardReleaseControllerTask
    if(-not $task -or $task.State -ne 'Disabled' -or -not (Test-GuardReleaseControllerAction $Action)){
        throw 'The Guard controller task cannot be safely migrated.'
    }
    $current=$task.Actions[0]
    if($current.Execute -ieq $Action.Execute -and $current.Arguments -ceq $Action.Arguments -and
        [string]$current.WorkingDirectory -ieq [string]$Action.WorkingDirectory){return}
    $options=@{Execute=$Action.Execute;Argument=$Action.Arguments}
    if($Action.WorkingDirectory){$options.WorkingDirectory=$Action.WorkingDirectory}
    $replacement=New-ScheduledTaskAction @options
    Set-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $replacement -ErrorAction Stop | Out-Null
    $verified=(Get-GuardReleaseControllerTask).Actions[0]
    if($verified.Execute -ine $Action.Execute -or $verified.Arguments -cne $Action.Arguments -or
        [string]$verified.WorkingDirectory -ine [string]$Action.WorkingDirectory){
        throw 'The Guard controller task migration could not be verified.'
    }
}
function Stop-GuardReleaseController {
    $task=Get-GuardReleaseControllerTask
    if(-not $task){return}
    Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
    if($task.State -eq 'Running'){Stop-ScheduledTask -InputObject $task -ErrorAction Stop}
    $until=[datetime]::UtcNow.AddSeconds($script:GuardDailyMaxLeaseSeconds)
    do{
        $owners=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop |
            Where-Object {$_.CommandLine -like ('*"'+$supervisor+'" -Run')})
        if(-not $owners.Count){return}
        Start-Sleep -Milliseconds 150
    }while([datetime]::UtcNow -lt $until)
    throw 'The installed controller did not stop.'
}
function Start-GuardReleaseController {
    Enable-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
}
function Stop-GuardReleaseOwnedRelay {
    foreach($owner in @(Get-CimInstance Win32_Process -Filter "Name='guard-dedicated-relay.exe'" -ErrorAction Stop |
        Where-Object ExecutablePath -IEQ $relay)){
        $process=Get-Process -Id $owner.ProcessId -ErrorAction Stop
        try{
            if($process.Path -ine $relay -or
                [math]::Abs(($process.StartTime.ToUniversalTime()-$owner.CreationDate.ToUniversalTime()).TotalMilliseconds) -gt 1){
                throw 'The Guard relay process identity changed.'
            }
            $process.Kill()
            if(-not $process.WaitForExit(4000)){throw 'The owned Guard relay did not stop.'}
        }finally{$process.Dispose()}
    }
}
function Test-GuardReleaseIdle {
    -not @(Get-Process -Name Claude -ErrorAction SilentlyContinue).Count
}
function Release-GuardReleaseLaunchLock {
    if($launchHeld){$launchMutex.ReleaseMutex();Set-Variable -Name launchHeld -Value $false -Scope Script}
}
function Enter-GuardReleaseFirewallLock {
    if($firewallHeld){return}
    try{$held=$firewallMutex.WaitOne(10000)}catch [Threading.AbandonedMutexException]{$held=$true}
    if(-not $held){throw 'Another task currently owns the Windows firewall update.'}
    Set-Variable -Name firewallHeld -Value $true -Scope Script
}
function Exit-GuardReleaseFirewallLock {
    if($firewallHeld){$firewallMutex.ReleaseMutex();Set-Variable -Name firewallHeld -Value $false -Scope Script}
}
function Register-GuardReleaseController {
    $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Highest
    $action=New-ScheduledTaskAction -Execute $bootstrap -Argument $backgroundControllerArguments -WorkingDirectory $daily
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
    $options=@{MultipleInstances='IgnoreNew';ExecutionTimeLimit=[timespan]::Zero;RestartCount=3
        RestartInterval=[timespan]::FromMinutes(1);AllowStartIfOnBatteries=$true;DontStopIfGoingOnBatteries=$true}
    $settings=New-ScheduledTaskSettingsSet @options
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
}
function Get-GuardReleaseStoreWorkerStatus($Record,$Health) {
    try{
        $store=Read-GuardDailyRecord 'daily-store-inventory.json'
        $worker=$store.Worker
        if($store.Generation -cne $Record.Generation -or $store.Package -cne $Record.PackageFullName -or
            $worker.ParentPid -ne $Health.SupervisorId -or $worker.ParentStartedUtc -cne $Health.SupervisorStartUtc){
            return 'IdentityPending'
        }
        if($worker.EventLogReadable -ne $true){return 'EventLogUnreadable'}
        if($worker.WatcherSubscribed -ne $true){return 'EventWatcherUnavailable'}
        if($worker.DirectoryWatching -ne $true){return 'DirectoryWatcherUnavailable'}
        $published=[datetimeoffset]::Parse($worker.VerifiedUtc).UtcDateTime
        $started=[datetimeoffset]::Parse($Health.SupervisorStartUtc).UtcDateTime
        if($published -lt $started -or $published -gt [datetime]::UtcNow){return 'ReceiptTimeInvalid'}
        $process=Get-Process -Id $worker.Pid -ErrorAction Stop
        try{
            if($process.ProcessName -cne 'powershell' -or $process.HasExited -or
                $process.StartTime.ToUniversalTime().ToString('o') -cne $worker.StartedUtc){return 'ProcessUnavailable'}
            'Ready'
        }finally{$process.Dispose()}
    }catch{'ReceiptUnavailable'}
}

function Read-GuardReleaseProof($Record,[datetime]$Since) {
    try{
        $health=Read-GuardDailyRecord 'daily-health.json'
        $now=[datetime]::UtcNow
        if($health.Generation -cne $Record.Generation){return @{Status='WaitingForGeneration'}}
        if($health.Gate -cne 'Open' -or $health.Reason -cne 'Verified'){return @{Status='WaitingForProof'}}
        $checked=[datetimeoffset]::Parse($health.Lease.CheckedUtc).UtcDateTime
        $expiry=[datetimeoffset]::Parse($health.Lease.ExpiresUtc).UtcDateTime
        $renewed=[datetimeoffset]::Parse($health.Admission.RenewedUtc).UtcDateTime
        $published=[datetimeoffset]::Parse($health.RulesUtc).UtcDateTime
        if($expiry -le $now){return @{Status='ProofExpired'}}
        if($health.Version -ne 2 -or $health.Containment -cne 'Sandboxie' -or
            $health.Policy -cne 'Verified' -or $health.Inventory -cne 'Verified' -or $health.Proxy -cne 'Ready' -or
            $health.Exit -cne 'Match' -or $health.Session -cnotin 'Clear','Active' -or $health.Terminating -or
            $health.Lease.Generation -cne $Record.Generation -or $health.Admission.Period -lt 1 -or
            $health.SupervisorId -lt 1 -or $health.SupervisorStartUtc -isnot [string] -or
            $health.CloseId -cnotmatch '\A[a-f0-9]{32}\z' -or $checked -lt $Since -or
            $expiry -le $checked -or ($expiry-$checked).TotalSeconds -gt $script:GuardDailyMaxLeaseSeconds -or
            $checked -gt $renewed -or $renewed -gt $published -or $published -gt $now){
            return @{Status='ProofInvalid'}
        }
        $session=@($health.SupervisorId,$health.SupervisorStartUtc,$health.CloseId,$health.Admission.Period) -join '|'
        @{Status='Ready';Health=$health;Checked=$checked;Expires=$expiry;Renewed=$renewed;ReadUtc=$now;Session=$session}
    }catch{@{Status='ReceiptUnavailable'}}
}

function Test-GuardReleaseProofStatus($Proof,$Live) {
    $health=$Proof.Health
    $Live.CanLaunch -and $Live.Generation -ceq $health.Generation -and $Live.Containment -ceq 'Sandboxie' -and
        $Live.SupervisorId -eq $health.SupervisorId -and $Live.SupervisorStartUtc -ceq $health.SupervisorStartUtc -and
        $Live.CloseName -ceq (Get-GuardDailyCloseName $health.CloseId) -and
        $Live.AdmissionPeriod -eq $health.Admission.Period -and $Live.LeaseCheckedUtc -ceq $health.Lease.CheckedUtc
}

function Wait-GuardReleaseReady($Record,[datetime]$Since,[int]$RequiredProofs,[switch]$RequireStoreWorker,
    [System.Collections.IDictionary]$Diagnostics,[scriptblock]$Progress) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $timeout=if($RequireStoreWorker){120}else{90}
    $prior=$null
    $lastCrossCheck=$null
    $count=0
    $workerStatus=if($RequireStoreWorker){'WaitingForController'}else{'NotRequired'}
    $nextWorkerCheck=0
    $nextProgress=0
    if($null -eq $Diagnostics){$Diagnostics=[ordered]@{}}
    $Diagnostics.RequiredProofs=$RequiredProofs
    $Diagnostics.TimeoutSeconds=$timeout
    $Diagnostics.PeakProofs=0
    $Diagnostics.FreshProofsObserved=0
    $Diagnostics.ContinuityResets=0
    $Diagnostics.StatusChecks=0
    do{
        $proof=Read-GuardReleaseProof $Record $Since
        $status=$proof.Status
        if($proof.Status -cne 'Ready'){
            if($count){$Diagnostics.ContinuityResets++}
            $prior=$null
            $count=0
        }else{
            if(-not $Diagnostics.FirstReadableUtc){$Diagnostics.FirstReadableUtc=$proof.ReadUtc.ToString('o')}
            $newProof=-not $prior -or $proof.Session -cne $prior.Session -or $proof.Checked -ne $prior.Checked
            $proofId=$proof.Session+'|'+$proof.Checked.ToString('o')
            if($RequireStoreWorker -and $clock.ElapsedMilliseconds -ge $nextWorkerCheck){
                $workerStatus=Get-GuardReleaseStoreWorkerStatus $Record $proof.Health
                $nextWorkerCheck=$clock.ElapsedMilliseconds+1000
            }
            # A repeated receipt cannot increment a streak. Only a new receipt or final commit needs a full readback.
            if(($newProof -and $lastCrossCheck -cne $proofId) -or
                ($count -ge $RequiredProofs -and $workerStatus -cin 'Ready','NotRequired')){
                $lastCrossCheck=$proofId
                $Diagnostics.StatusChecks++
                $live=try{Get-GuardDailyStatus -VerifyDuringRevision}catch{$null}
                $same=Read-GuardReleaseProof $Record $Since
                $sameProof=$same.Status -ceq 'Ready' -and $same.Checked -eq $proof.Checked -and $same.Session -ceq $proof.Session -and
                    $same.Expires -eq $proof.Expires -and $same.Renewed -eq $proof.Renewed
                if(-not $sameProof){
                    $status='ProofChangedDuringCheck'
                    if($same.Status -cne 'Ready' -or $same.Session -cne $proof.Session -or
                        ($prior -and $prior.Expires -le $same.ReadUtc)){
                        if($count){$Diagnostics.ContinuityResets++}
                        $prior=$null
                        $count=0
                    }
                }elseif(-not (Test-GuardReleaseProofStatus $proof $live)){
                    $status='StatusNotReady'
                    if($count){$Diagnostics.ContinuityResets++}
                    $prior=$null
                    $count=0
                }else{
                    if($newProof){
                        if($prior -and $proof.Session -ceq $prior.Session -and $proof.Checked -gt $prior.Checked -and
                            $proof.ReadUtc -lt $prior.Expires -and $proof.Renewed -lt $prior.Expires -and
                            [double]$proof.Health.Admission.PreviousOverlapMilliseconds -gt 0){
                            $count++
                            $native=[double]$proof.Health.Admission.PreviousOverlapMilliseconds
                            $readable=($prior.Expires-$proof.ReadUtc).TotalMilliseconds
                            $Diagnostics.MinimumNativeOverlapMs=if($null -eq $Diagnostics.MinimumNativeOverlapMs){$native}
                                else{[math]::Min($Diagnostics.MinimumNativeOverlapMs,$native)}
                            $Diagnostics.MinimumReadableOverlapMs=if($null -eq $Diagnostics.MinimumReadableOverlapMs){$readable}
                                else{[math]::Min($Diagnostics.MinimumReadableOverlapMs,$readable)}
                        }else{
                            if($count){$Diagnostics.ContinuityResets++}
                            $count=1
                        }
                        $prior=$proof
                        $Diagnostics.LastRenewedUtc=$proof.Renewed.ToString('o')
                        $Diagnostics.FreshProofsObserved++
                        $Diagnostics.PeakProofs=[math]::Max($Diagnostics.PeakProofs,$count)
                    }
                    if($count -ge $RequiredProofs){
                        if($RequireStoreWorker){$workerStatus=Get-GuardReleaseStoreWorkerStatus $Record $same.Health}
                        $final=Read-GuardReleaseProof $Record $Since
                        if($final.Status -cne 'Ready' -or $final.Session -cne $proof.Session -or $final.Checked -ne $proof.Checked -or
                            $final.Expires -ne $proof.Expires -or $final.Renewed -ne $proof.Renewed){
                            $status='ProofChangedDuringCheck'
                        }elseif($workerStatus -cin 'Ready','NotRequired'){
                            $status='Verified'
                        }else{$status='WaitingForStoreWorker'}
                    }
                }
            }
        }
        $Diagnostics.Status=$status
        $Diagnostics.Proofs=$count
        $Diagnostics.WorkerStatus=$workerStatus
        $Diagnostics.ElapsedSeconds=[int][math]::Floor($clock.Elapsed.TotalSeconds)
        if($Progress -and ($status -ceq 'Verified' -or $clock.ElapsedMilliseconds -ge $nextProgress)){
            $null=& $Progress $Diagnostics
            $nextProgress=$clock.ElapsedMilliseconds+1000
        }
        if($status -ceq 'Verified' -and $clock.Elapsed.TotalSeconds -lt $timeout){return $count}
        Start-Sleep -Milliseconds 250
    }while($clock.Elapsed.TotalSeconds -lt $timeout)
    throw 'The installed Guard did not publish fresh, continuous exit and firewall proofs with both Store watchers ready.'
}
function New-GuardReleasePolicy($Route,$Record,$Inventory) {
    $scope=New-GuardInstalledPolicy $Route $Record.Port ([guid]$Record.DeploymentId) $Inventory $Record.ScopeSid 'Sandboxie'
    $prefix=$Record.PackageRoot.TrimEnd('\')+'\'
    $paths=[string[]]@($Inventory.Programs | Where-Object {$_.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)})
    $scope.WithRegisteredPackageAdmission($paths)
}
function Assert-GuardReleaseClosed($Policy,[uint16]$Weight) {
    $count=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($Policy,$Weight)
    if($count -le 0 -or $count -ne $Policy.BootCount){throw 'Persistent fail-closed rules did not verify.'}
    $count
}
function Open-GuardReleaseLaunchLock {
    if($launchHeld){return}
    try{$acquired=$launchMutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$acquired=$true}
    if(-not $acquired){throw 'A guarded desktop session is active.'}
    Set-Variable -Name launchHeld -Value $true -Scope Script
    if(-not (Test-GuardReleaseIdle)){throw 'Close the desktop before starting Guard maintenance.'}
}
function Test-GuardReleaseSandboxie($Record){
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$supervisor+'" -VerifySandboxie'
    $child=Start-GuardDailyChild $shell $arguments ''
    try{
        if(-not $child.Process.WaitForExit(35000) -or $child.Process.ExitCode -ne 0 -or
            $child.Output.GetAwaiter().GetResult().Trim() -cne 'SandboxieReady'){
            throw 'The installed Sandboxie protection did not verify.'
        }
        $null=Confirm-GuardDailySandboxieApp $Record
    }finally{Stop-GuardDailyChild $child}
}
function Remove-GuardReleaseProfile {
    if($state.ProfileTouched){
        try{$result.LocaleRollback=& $NodeOperations.Restore $state.Profile}
        catch{throw 'The previous encrypted node, Windows region, or Edge website language settings could not be restored.'}
    }
}
function Set-GuardReleaseLocaleFailure($Failure){
    $code=[string]$Failure.Exception.Data['GuardLocaleFailure']
    if($code -cnotin @('WindowsPreviewChanged','WindowsReadback','WindowsTimeZone','WindowsHomeLocation','WindowsRegionalFormat',
        'WindowsLanguages','WindowsUiLanguageOverride','WindowsInputMethodOverride','WindowsCultureFromLanguageListOptOut',
        'EdgeApply','EdgeSettingsOpen','EdgeSettingsWindow','EdgeSettingsPage','EdgeProfile','EdgeLanguageUnavailable','EdgeLanguageOrder',
        'EdgePreviewChanged','EdgeReadback','EdgeSiteReadback','EdgeSiteNoRequest','EdgeSiteMismatch')){return $false}
    $result.LocaleFailure=$code
    $true
}
function Save-GuardReleasePolicyIdentity($Record,$Policy,$Inventory,[string]$Name) {
    $route=if($Name -ceq 'candidate-policy.json'){$state.Route}else{$state.PriorRoute}
    $endpoint=ConvertTo-SecureString ('{0}|{1}' -f $route.Upstream.server,$route.Upstream.port) -AsPlainText -Force
    try{$protectedEndpoint=ConvertFrom-SecureString -SecureString $endpoint}finally{$endpoint.Dispose()}
    Save-GuardAdministratorJson (Join-Path $backup $Name) ([pscustomobject]@{
        Deployment=$Record.DeploymentId;Sublayer=$Policy.PersistentSublayer;Port=$Record.Port
        ProtectedEndpoint=$protectedEndpoint
        ScopeSid=$Record.ScopeSid;PackageRoot=$Record.PackageRoot;PolicyInventory=$Inventory
        BaselineKeys=$Policy.GetBaselineKeys();BootKeys=$Policy.GetBootKeys()
    })
}
function Read-GuardReleaseRecoveryJson([string]$Path) {
    Assert-GuardReleaseOwnedPath $Path
    Read-GuardDailyJsonFile $Path
}
function Read-GuardReleaseRecoveryPolicy($Record,[string]$Name) {
    $backupPolicy=Read-GuardReleaseRecoveryJson (Join-Path $backup $Name)
    if($backupPolicy.Deployment -ne $Record.DeploymentId -or $backupPolicy.Sublayer -ne $Record.Sublayer -or
        $backupPolicy.Port -ne $Record.Port -or $backupPolicy.ScopeSid -cne $Record.ScopeSid -or
        $backupPolicy.PackageRoot -ine $Record.PackageRoot){throw 'The recovery route does not match its protected deployment.'}
    try{
        $protected=ConvertTo-SecureString -String $backupPolicy.ProtectedEndpoint -ErrorAction Stop
        $encoded=[pscredential]::new('OwnedEndpoint',$protected).GetNetworkCredential().Password
        $parts=@($encoded.Split('|'))
        if($parts.Count -ne 2 -or $parts[1] -notmatch '\A[0-9]{1,5}\z' -or [int]$parts[1] -lt 1 -or [int]$parts[1] -gt 65535){
            throw 'Invalid endpoint.'
        }
        $address=Get-GuardReleaseCanonicalIpv4 $parts[0]
    }catch{throw 'The protected recovery endpoint could not be restored by this Windows account.'}
    finally{if($protected){$protected.Dispose()}}
    $verifiedRoute=@{Upstream=@{server=$address;port=[int]$parts[1]}}
    $policy=New-GuardReleasePolicy $verifiedRoute $Record $backupPolicy.PolicyInventory
    if(-not (Test-GuardDailyPolicyBinding $Record $policy) -or -not (Test-GuardDailyPolicyBinding $backupPolicy $policy)){
        throw 'The exact saved Windows firewall plan could not be reconstructed.'
    }
    $policy
}
function Initialize-GuardReleaseRecovery($Journal) {
    foreach($dir in (Split-Path -Parent $operationPath),$operationPath,$backup){Assert-GuardReleaseOwnedPath $dir -Directory}
    foreach($name in 'Fresh','NewPolicy','OldPolicyRetired','RootCreated','ControllerStopped','ControllerCreated',
        'DriverChanged','ProfileTouched','NotifierTouched','HadStoreStage'){
        if($Journal.$name -isnot [bool]){throw 'The protected recovery flags are invalid.'}
        $state[$name]=$Journal.$name
    }
    if($Journal.PSObject.Properties['PriorRouteUnavailable']){
        if($Journal.PriorRouteUnavailable -isnot [bool] -or ($Journal.PriorRouteUnavailable -and $state.Fresh)){
            throw 'The protected prior route recovery flag is invalid.'
        }
        $state.PriorRouteUnavailable=$Journal.PriorRouteUnavailable
    }
    $state.Weight=$Journal.Weight
    $state.OldWeight=$Journal.PriorWeight
    $state.Record=Read-GuardReleaseRecoveryJson (Join-Path $backup 'candidate-provisioned.json')
    if($state.Record.LaunchUserSid -cne $sid -or $state.Record.DeploymentId -ne $Journal.Deployment -or
        $state.Record.Sublayer -ne $Journal.Sublayer){throw 'The protected candidate is not the pending installation.'}
    $state.Policy=Read-GuardReleaseRecoveryPolicy $state.Record 'candidate-policy.json'
    if(-not $state.Fresh){
        $state.Previous=Read-GuardReleaseRecoveryJson (Join-Path $backup 'daily-provisioned.json')
        if($state.Previous.LaunchUserSid -cne $sid -or $state.Previous.DeploymentId -ne $Journal.PriorDeployment -or
            $state.Previous.Sublayer -ne $Journal.PriorSublayer){throw 'The protected prior deployment identity changed.'}
        if($state.PriorRouteUnavailable -and ($state.Previous.Version -ne 2 -or $state.Previous.PSObject.Properties['ProxyMode'])){
            throw 'The protected prior route recovery flag does not match the saved installation.'
        }
        $state.OldPolicy=Read-GuardReleaseRecoveryPolicy $state.Previous 'previous-policy.json'
        $tasks=Read-GuardReleaseRecoveryJson (Join-Path $backup 'tasks.json')
        $state.Notifier=$tasks.Notifier
        $state.ControllerAction=$tasks.ControllerAction
        if(-not (Test-GuardReleaseControllerAction $state.ControllerAction)){
            throw 'The previous Guard controller task action is not valid.'
        }
    }
    if($state.ProfileTouched){
        if(-not $NodeOperations -or $NodeOperations.Restore -isnot [scriptblock]){
            throw 'Recovery needs the encrypted node and region restoration operation.'
        }
        $state.Profile=Read-GuardReleaseRecoveryJson (Join-Path $backup 'node-snapshot.json')
    }
    $restorable=@($assets.Target)+@(foreach($name in 'daily-store-inventory.json','daily-notice.json','daily-last-guard-stop.json'){
        Join-Path $root $name
    })
    foreach($item in $Journal.Replaced){
        if(-not $item){continue}
        if($item.Target -notin $restorable -or $item.Source -ine (Join-Path $backup (Split-Path -Leaf $item.Target)) -or
            $item.Sha256 -cnotmatch '\A[A-F0-9]{64}\z' -or $state.Replaced.ContainsKey($item.Target)){
            throw 'A rollback path does not belong to the verified release.'
        }
        $null=Get-GuardReleaseAsset $item.Source $item.Target $item.Sha256
        $state.Replaced[$item.Target]=$item
    }
    foreach($item in $Journal.CreatedFiles){
        if($item -notin $restorable -or $state.Replaced.ContainsKey($item)){throw 'An unexpected file is marked for rollback.'}
        $state.CreatedFiles.Add($item)
    }
}

$operations=@{
    Publish={Save-GuardReleaseReceipt}
    Progress={param($Phase) Send-GuardReleaseProgress $Phase}
    Preflight={
        if([IO.File]::Exists($journalFile) -or [IO.File]::Exists((Join-Path $root 'daily-package-pending.json'))){
            throw 'A previous Guard transaction requires recovery before any new deployment.'
        }
        if(-not (Test-GuardReleaseIdle)){throw 'Close the desktop before starting Guard maintenance.'}
        $state.Previous=if([IO.File]::Exists($provisioned)){Read-GuardDailyRecord 'daily-provisioned.json'}
        $state.Fresh=-not $state.Previous
        $result.Mode=if($state.Fresh){'Fresh'}elseif($RouteOnly){'RouteOnly'}else{'Update'}
        if($RequirePriorGeneration -and $state.Previous.Generation -cne $RequirePriorGeneration){
            throw 'The installed Guard generation changed. Review the current settings before applying the node.'
        }
        if($RouteOnly -and ($state.Fresh -or -not $NodeProfile)){throw 'Route-only changes require an installed release and a verified node.'}
        if($NodeProfile){
            foreach($name in 'Snapshot','Apply','Restore'){
                if($NodeOperations[$name] -isnot [scriptblock]){throw 'Node changes require the protected configuration transaction.'}
            }
            if(-not $ExpectedIpv4){throw 'The selected node needs a verified public IPv4.'}
        }
        $state.App=Get-GuardSandboxieApp
        $inventory=Get-GuardInventory -LocalOnly
        if($state.App.DesktopPath -notin @($inventory.DesktopPaths)){throw 'The registered desktop does not belong to the protected inventory.'}
        $recordInventory=[pscustomobject]@{Programs=@($inventory.Programs);DesktopPaths=@($inventory.DesktopPaths)
            Packages=@($inventory.Packages | ForEach-Object{[pscustomobject]@{Sid=$_.Sid}});ServiceSids=@(Get-GuardDailyServiceSids)}
        $desktopImages=@(Read-GuardDailyDesktopImages $inventory)
        $state.Isolation=Get-GuardIsolationMode
        if($state.Isolation -cnotin 'Off','Active'){throw 'Could not establish the current Guard isolation state.'}
        if($state.Fresh){
            if($state.Isolation -cne 'Off'){
                throw 'Existing legacy isolation must be migrated by its verified legacy cutover before using this installer.'
            }
            if(-not $ExpectedIpv4 -or [IO.Directory]::Exists($daily) -or (Get-GuardReleaseControllerTask) -or
                (Get-GuardDailyNotifierTaskSnapshot $sid $daily) -or
                @(Get-Service SbieDrv,SbieSvc -ErrorAction SilentlyContinue).Count -or
                @('daily-mode.json','daily-health.json','daily-transition.json' | Where-Object {[IO.File]::Exists((Join-Path $root $_))}).Count -or
                [IO.File]::Exists((Join-Path ([Environment]::GetFolderPath('Windows')) 'Sandboxie.ini'))){
                throw 'A first installation requires an unused Guard controller, unused Sandboxie service names and a verified IPv4.'
            }
            foreach($name in 'SbieDrv','SbieSvc'){
                if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name") -or
                    (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$name")){
                    throw 'Another installation already owns the Sandboxie services.'
                }
            }
            $port=18793
            if(@(Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue).Count){throw 'The dedicated loopback port is already in use.'}
            $vendor=Join-Path $stage 'vendor'
            $sourceDriver=Join-Path $vendor 'sandboxie'
            foreach($path in $vendor,$sourceDriver,(Join-Path $sourceDriver '32')){Assert-GuardReleaseOwnedPath $path -Directory}
            $state.VendorAssets=@(foreach($name in $script:GuardReleaseVendorPins.Keys){
                Get-GuardReleaseAsset (Join-Path $sourceDriver $name) (Join-Path $driverRoot $name) $script:GuardReleaseVendorPins[$name]
            })
            $record=[pscustomobject]@{
                Version=2;Generation=$null;DeploymentId=[guid]::NewGuid();Sublayer=$null;AssignedSublayerWeight=$null
                LaunchUserSid=$sid;Port=$port;RouteHash=$null;DesktopHashes=@($desktopImages.Hash);DesktopImages=$desktopImages
                ScopeName='GuardDesktop';ScopeSid=$state.App.PackageSid;Containment='Sandboxie';VpnGuid=$null;ProxyMode=$null
                PackageFullName=$state.App.PackageFullName;PackageRoot=$state.App.Root;AppId=$state.App.AppId;DesktopPath=$state.App.DesktopPath
                ExpectedIpv4=$null;ReferenceUtc=$null;Witness='CloudflareTrace';BackupExitLookup=$true
                RelaySha256=$null;ObserverSha256=$null;ObserverScriptSha256=$null
                BaselineKeys=@();BootKeys=@();Assets=@();PolicyInventory=$recordInventory
            }
        }else{
            $previousTask=Get-GuardReleaseControllerTask
            if($state.Previous.Version -ne 2 -or $state.Previous.LaunchUserSid -cne $sid -or
                $state.Previous.Containment -cne 'Sandboxie' -or $state.Isolation -cne 'Off' -or
                -not $previousTask -or -not (Test-GuardDailyScopeBinding $state.Previous)){
                throw 'The current Guard deployment and interactive administrator did not verify.'
            }
            $action=$previousTask.Actions[0]
            $state.ControllerAction=[pscustomobject]@{
                Execute=$action.Execute;Arguments=$action.Arguments;WorkingDirectory=[string]$action.WorkingDirectory
            }
            foreach($path in $daily,$driverRoot,$runtimeHome){Assert-GuardReleaseOwnedPath $path -Directory}
            $null=Confirm-GuardDailySandboxieApp $state.Previous $state.App
            if(-not (Test-GuardDailyDesktopImages $state.Previous.DesktopImages $desktopImages)){
                throw 'The protected desktop images changed before deployment.'
            }
            $port=$state.Previous.Port
            $state.Notifier=Get-GuardDailyNotifierTaskSnapshot $sid $daily
            $record=$state.Previous | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            if(-not $record.PSObject.Properties['BackupExitLookup']){
                $record | Add-Member NoteProperty BackupExitLookup $true
            }
            $record | Add-Member NoteProperty PolicyInventory $recordInventory -Force
        }
        if($RouteOnly){
            foreach($name in 'guard-profile-store.ps1','guard-node-profile.ps1','guard-daily-plan.ps1','guard-daily-supervisor.ps1','guard-daily-package.ps1'){
                $candidate=$assets | Where-Object Target -IEQ (Join-Path $daily $name)
                $null=Get-GuardReleaseAsset $candidate.Target $candidate.Target $candidate.Sha256
            }
        }
        if($NodeProfile){
            try{
                $state.Route=Get-GuardNodeProfileRoute -Profile $NodeProfile -Port $port
                $state.Profile=& $NodeOperations.Snapshot
            }catch{throw 'The supplied node or its rollback configuration could not be verified.'}
            if(-not $state.Profile){throw 'The previous configuration could not be captured.'}
            $record | Add-Member NoteProperty ProxyMode 'Manual' -Force
        }
        if(-not $state.Fresh){
            $legacySelection=$NodeProfile -and -not $state.Previous.PSObject.Properties['ProxyMode']
            $readError=$null
            try{$state.PriorRoute=Read-GuardDailyRelayConfig $port}
            catch{if(-not $legacySelection){throw}; $readError=$_}
            if($state.PriorRoute.Hash -cne $state.Previous.RouteHash -and $legacySelection -and
                $state.Profile.Node.Exists -is [bool] -and -not $state.Profile.Node.Exists){
                $path=Get-GuardNodeStorePath
                if(-not ((Test-GuardNodeStoreItem (Split-Path -Parent $path) -Directory) -and (Test-GuardNodeStoreItem $path))){
                    $null=Get-GuardReleaseCanonicalIpv4 $ExpectedIpv4
                    $state.PriorRoute=Find-GuardPriorBettboxRoute -ExpectedHash $state.Previous.RouteHash -Port $port
                    if(-not $state.PriorRoute -or $state.PriorRoute.Hash -cne $state.Previous.RouteHash){
                        throw 'The previously approved Guard route could not be recovered from the saved Bettbox profiles.'
                    }
                    # The saved route can verify the old filters. Bettbox is still using its current selection.
                    $state.PriorRouteUnavailable=$true
                }
            }
            if($readError -and -not $state.PriorRouteUnavailable){throw $readError}
            if($state.PriorRoute.Hash -cne $state.Previous.RouteHash){throw 'The previously approved Guard route changed.'}
            $state.OldWeight=[uint16]$state.Previous.AssignedSublayerWeight
            $state.OldPolicy=New-GuardReleasePolicy $state.PriorRoute $state.Previous $recordInventory
            if(-not (Test-GuardDailyPolicyBinding $state.Previous $state.OldPolicy)){throw 'The older firewall scope could not be reconstructed.'}
        }
        if(-not $NodeProfile){
            $state.Route=if($state.PriorRoute){$state.PriorRoute}else{Read-GuardDailyRelayConfig $port}
        }
        $pinned=if($record.VpnGuid){$record.VpnGuid}elseif($VpnGuid -ne [guid]::Empty){$VpnGuid.ToString('D')}else{
            $adapters=@(Get-GuardNetworkAdapters | Where-Object {$_.Name -ceq 'Bettbox' -and $_.Status -eq 'Up'})
            if($adapters.Count -ne 1){throw 'Connect the single Bettbox TUN adapter before installing Guard.'}
            ([guid]$adapters[0].InterfaceGuid).ToString('D')
        }
        if($VpnGuid -ne [guid]::Empty -and [guid]$pinned -ne $VpnGuid){throw 'Installation cannot change the approved Bettbox interface.'}
        $vpn=Get-GuardVpnAdapter $pinned
        if($vpn.Name -cne 'Bettbox'){throw 'The approved Bettbox tunnel does not own the current route.'}
        $record.VpnGuid=([guid]$vpn.InterfaceGuid).ToString('D')
        if(-not $state.Route -or $state.Route.Hash -cnotmatch '\A[A-F0-9]{64}\z'){throw 'The exact candidate relay could not be verified.'}
        $record.RouteHash=$state.Route.Hash
        if($ExpectedIpv4){
            $record.ExpectedIpv4=Get-GuardReleaseCanonicalIpv4 $ExpectedIpv4
            $record.ReferenceUtc=[datetime]::UtcNow.ToString('o')
        }else{$null=Get-GuardReleaseCanonicalIpv4 $record.ExpectedIpv4}
        $state.NewPolicy=$state.Fresh -or $record.RouteHash -cne $state.Previous.RouteHash
        if($state.NewPolicy -and -not $state.Fresh){$record.DeploymentId=[guid]::NewGuid()}
        $state.Policy=if($state.NewPolicy){New-GuardReleasePolicy $state.Route $record $recordInventory}else{$state.OldPolicy}
        $record.Sublayer=$state.Policy.PersistentSublayer
        $record.BaselineKeys=$state.Policy.GetBaselineKeys()
        $record.BootKeys=$state.Policy.GetBootKeys()
        if($state.NewPolicy){$record.AssignedSublayerWeight=$null}else{$state.Weight=$state.OldWeight}
        if(-not $RouteOnly){
            $record.Assets=$assets
            $record.ObserverSha256=($assets | Where-Object Target -IEQ $observer).Sha256
            $record.RelaySha256=($assets | Where-Object Target -IEQ $relay).Sha256
            $record.ObserverScriptSha256=($assets | Where-Object Target -IEQ (Join-Path $daily 'cloudflare-exit-probe.mjs')).Sha256
        }
        $record.Generation=Get-GuardReleaseGeneration (@(
            $record.DeploymentId,$record.Sublayer,$record.RouteHash,$record.ExpectedIpv4,$sid,$record.ScopeSid,
            $record.PackageFullName,$record.AppId,$record.VpnGuid,$(if($state.Previous){$state.Previous.Generation})
        )+@($record.Assets.Sha256)+@($record.DesktopHashes))
        $state.Record=$record
        $state.HadStoreStage=[IO.File]::Exists((Join-Path $root 'daily-store-stage.json'))
    }
    Backup={
        Initialize-GuardAdministratorDirectory (Split-Path -Parent $operationPath)
        Initialize-GuardAdministratorDirectory $operationPath
        Initialize-GuardAdministratorDirectory $backup
        if(-not $state.Fresh){
            $original=Get-GuardReleaseAsset $provisioned (Join-Path $backup 'daily-provisioned.json')
            Set-GuardReleaseAsset $original
            # A legacy record may predate PolicyInventory. Save the inventory used to verify its policy.
            Save-GuardReleasePolicyIdentity $state.Previous $state.OldPolicy $state.Record.PolicyInventory 'previous-policy.json'
            $taskXml=Export-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
            Save-GuardAdministratorJson (Join-Path $backup 'tasks.json') ([pscustomobject]@{
                ControllerXml=$taskXml;ControllerAction=$state.ControllerAction;Notifier=$state.Notifier
            })
            if(-not $RouteOnly){
                foreach($file in $assets){
                    if([IO.File]::Exists($file.Target)){
                        $old=Get-GuardReleaseAsset $file.Target (Join-Path $backup (Split-Path -Leaf $file.Target))
                        Set-GuardReleaseAsset $old
                        $state.Replaced[$file.Target]=[pscustomobject]@{Source=$old.Target;Target=$old.Source;Sha256=$old.Sha256}
                    }else{$state.CreatedFiles.Add($file.Target)}
                }
            }
            foreach($name in 'daily-store-inventory.json','daily-notice.json','daily-last-guard-stop.json'){
                $target=Join-Path $root $name
                if([IO.File]::Exists($target)){
                    $old=Get-GuardReleaseAsset $target (Join-Path $backup $name)
                    Set-GuardReleaseAsset $old
                    $state.Replaced[$target]=[pscustomobject]@{Source=$old.Target;Target=$old.Source;Sha256=$old.Sha256}
                }else{$state.CreatedFiles.Add($target)}
            }
        }
        if($NodeProfile){Save-GuardAdministratorJson (Join-Path $backup 'node-snapshot.json') $state.Profile}
        Save-GuardReleasePolicyIdentity $state.Record $state.Policy $state.Record.PolicyInventory 'candidate-policy.json'
        Save-GuardAdministratorJson (Join-Path $backup 'candidate-provisioned.json') $state.Record
        Save-GuardReleaseJournal
    }
    Close={
        if(-not $state.Fresh){
            $state.ControllerStopped=$true
            Save-GuardReleaseJournal
            Stop-GuardReleaseController
            $null=Assert-GuardReleaseClosed $state.OldPolicy $state.OldWeight
            Stop-GuardReleaseOwnedRelay
        }
        if(-not (Test-GuardReleaseIdle)){throw 'The desktop is no longer closed.'}
    }
    Install={
        if($state.Fresh){
            $state.RootCreated=$true
            Save-GuardReleaseJournal
            foreach($path in $daily,$runtimeHome,$driverRoot,(Join-Path $driverRoot '32'),(Join-Path $root 'sandbox-data')){
                Initialize-GuardAdministratorDirectory $path
            }
        }
        if(-not $RouteOnly){
            if($state.Notifier -and $state.Notifier.Running){
                $state.NotifierTouched=$true
                Save-GuardReleaseJournal
                Stop-ScheduledTask -TaskName $script:GuardDailyNotifierTaskName -TaskPath '\' -ErrorAction Stop
                Wait-GuardDailyNotifierTaskStopped
            }
            foreach($file in $assets){
                Set-GuardReleaseAsset $file
            }
        }
        if($state.NewPolicy){
            $save=[Action[uint16]]{
                param([uint16]$Weight)
                $state.Weight=$Weight
                Save-GuardReleaseJournal
            }
            $state.Weight=[ClaudeGuard.Network.WindowsPolicySession]::InstallPersistent($state.Policy,$save)
        }
        $result.BootRules=Assert-GuardReleaseClosed $state.Policy $state.Weight
        if($NodeProfile){
            $state.ProfileTouched=$true
            Save-GuardReleaseJournal
            $persistLocale={param($snapshot) Save-GuardAdministratorJson (Join-Path $backup 'node-snapshot.json') $snapshot}
            try{$null=& $NodeOperations.Apply $NodeProfile $persistLocale}
            catch{
                if(Set-GuardReleaseLocaleFailure $_){
                    if($result.LocaleFailure -clike 'Windows*'){throw 'Windows locale settings could not be applied.'}
                    throw 'Edge website language settings could not be applied.'
                }
                throw 'The selected encrypted node or region settings could not be applied.'
            }
        }
        if((Read-GuardDailyRelayConfig $state.Record.Port).Hash -cne $state.Record.RouteHash){
            throw 'The persisted node does not reproduce the verified relay.'
        }
        $state.Record.AssignedSublayerWeight=$state.Weight
        Save-GuardAdministratorJson $provisioned $state.Record
        if($state.Fresh){
            foreach($file in $state.VendorAssets){Set-GuardReleaseAsset $file}
            $state.DriverChanged=$true
            Save-GuardReleaseJournal
            Install-GuardReleaseDriver $driverRoot $state.App.Root $state.Record.Port (Join-Path $root 'sandbox-data\GuardDesktop')
        }
        Test-GuardReleaseSandboxie $state.Record
        if($state.NewPolicy -and -not $state.Fresh){
            $state.OldPolicyRetired=$true
            Save-GuardReleaseJournal
            [ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($state.OldPolicy,$state.OldWeight)
        }
        if($state.Fresh){
            $state.ControllerCreated=$true
            Save-GuardReleaseJournal
            Register-GuardReleaseController
        }elseif(-not $RouteOnly){
            Set-GuardReleaseControllerAction ([pscustomobject]@{
                Execute=$bootstrap;Arguments=$backgroundControllerArguments;WorkingDirectory=$daily
            })
        }
        if(-not $RouteOnly){
            $state.NotifierTouched=$true
            Save-GuardReleaseJournal
            $notice=Install-GuardDailyNotifierTask $sid $daily $bootstrap
            if($notice.Enabled -and -not $notice.Running){Start-ScheduledTask -TaskName $script:GuardDailyNotifierTaskName -TaskPath '\' -ErrorAction Stop}
        }
    }
    Verify={
        if(-not (Test-GuardReleaseIdle)){throw 'A desktop process started during deployment.'}
        $since=[datetime]::UtcNow
        Release-GuardReleaseLaunchLock
        Exit-GuardReleaseFirewallLock
        Start-GuardReleaseController
        $progress={param($Details) Send-GuardReleaseProgress 'Verify' $Details}
        $result.FreshProofs=Wait-GuardReleaseReady $state.Record $since 6 -RequireStoreWorker -Diagnostics $result.Verification -Progress $progress
        if(-not (Test-GuardReleaseIdle)){throw 'The desktop must stay closed throughout deployment.'}
        if($NodeProfile -and $NodeOperations.Verify){
            Send-GuardReleaseProgress 'VerifyLocale' $result.Verification
            try{$locale=& $NodeOperations.Verify}
            catch{
                if(Set-GuardReleaseLocaleFailure $_){
                    if($result.LocaleFailure -clike 'Windows*'){throw 'Windows locale settings did not pass final readback.'}
                    throw 'Edge website language settings did not pass final readback.'
                }
                throw 'The selected node region settings did not pass final readback.'
            }
            if(-not (Test-GuardReleaseIdle)){throw 'The desktop must stay closed throughout deployment.'}
            $result.LocaleVerification=$locale
            $result.SiteAcceptLanguage=$locale.SiteAcceptLanguage
            $result.BrowserStatus=$locale.BrowserStatus
            $result.WebsiteStatus=$locale.WebsiteStatus
            $result.AllSettingsVerified=$locale.AllSettingsVerified
        }
    }
    Commit={[IO.File]::Delete($journalFile)}
    Restore={
        $result.LocaleVerification=$null
        $result.SiteAcceptLanguage=$null
        $result.BrowserStatus=$null
        $result.WebsiteStatus=$null
        $result.AllSettingsVerified=$null
        Open-GuardReleaseLaunchLock
        Enter-GuardReleaseFirewallLock
        if(-not (Test-GuardReleaseIdle)){throw 'The guarded desktop must stay closed during rollback.'}
        if($state.ControllerStopped -or $state.ControllerCreated -or $state.PriorRouteUnavailable){
            Stop-GuardReleaseController
            Stop-GuardReleaseOwnedRelay
        }
        if($state.NotifierTouched){Restore-GuardDailyNotifierTask $null $sid $daily}
        if(-not $state.HadStoreStage -and [IO.File]::Exists((Join-Path $root 'daily-store-stage.json'))){
            Undo-GuardDailyStoreStage $state.Record
        }
        if($state.NewPolicy -and -not $state.Fresh -and $state.OldPolicyRetired){
            $oldClosed=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($state.OldPolicy,$state.OldWeight,$true)
            if(-not $oldClosed){
                $saveOld=[Action[uint16]]{
                    param([uint16]$Weight)
                    $state.OldWeight=$Weight
                    Save-GuardReleaseJournal
                }
                $state.OldWeight=[ClaudeGuard.Network.WindowsPolicySession]::InstallPersistent($state.OldPolicy,$saveOld)
            }
            $null=Assert-GuardReleaseClosed $state.OldPolicy $state.OldWeight
        }
        Remove-GuardReleaseProfile
        if($state.Fresh){
            if($state.ControllerCreated -and (Get-GuardReleaseControllerTask)){
                Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
            }
            if($state.DriverChanged -and [IO.Directory]::Exists($driverRoot)){Remove-GuardReleaseDriver $driverRoot}
            if($state.NewPolicy -and $null -ne $state.Weight){[ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($state.Policy,$state.Weight)}
            if($state.RootCreated -and [IO.Directory]::Exists($daily)){
                Assert-GuardReleaseOwnedPath $daily -Directory
                $archived=Join-Path $operationPath 'retired-daily'
                if((Resolve-Path -LiteralPath $daily).ProviderPath -ine $daily -or
                    @(Get-ChildItem -LiteralPath $daily -Force -Recurse -Attributes ReparsePoint).Count){
                    throw 'The first-install directory changed before archival.'
                }
                [IO.Directory]::Move($daily,$archived)
            }
            if($state.RootCreated){
                foreach($name in 'daily-provisioned.json','daily-mode.json','daily-health.json','daily-store-inventory.json'){
                    [IO.File]::Delete((Join-Path $root $name))
                }
            }
        }else{
            foreach($file in $state.Replaced.Values){Set-GuardReleaseAsset $file}
            foreach($path in $state.CreatedFiles){
                if([IO.File]::Exists($path)){Assert-GuardReleaseOwnedPath $path;[IO.File]::Delete($path)}
            }
            $original=Join-Path $backup 'daily-provisioned.json'
            if($state.OldWeight -eq $state.Previous.AssignedSublayerWeight){
                Set-GuardReleaseAsset (Get-GuardReleaseAsset $original $provisioned)
            }else{
                $state.Previous.AssignedSublayerWeight=$state.OldWeight
                Save-GuardAdministratorJson $provisioned $state.Previous
            }
            if($state.NewPolicy -and $null -ne $state.Weight){[ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($state.Policy,$state.Weight)}
            if($state.NotifierTouched){Restore-GuardDailyNotifierTask $state.Notifier $sid $daily}
            if($state.ControllerStopped -or $state.PriorRouteUnavailable){
                $closedRules=Assert-GuardReleaseClosed $state.OldPolicy $state.OldWeight
                Set-GuardReleaseControllerAction $state.ControllerAction
                if($state.PriorRouteUnavailable){
                    $health=Join-Path $root 'daily-health.json'
                    if(Test-Path -LiteralPath $health){Assert-GuardReleaseOwnedPath $health;[IO.File]::Delete($health)}
                    $result.RestoreVerification.Status='Closed'
                    $result.RestoreVerification.BootRules=$closedRules
                }else{
                    if($state.ControllerAction.Execute -ieq $shell){Start-GuardReleaseRollbackRunner}
                    $since=[datetime]::UtcNow
                    Release-GuardReleaseLaunchLock
                    Exit-GuardReleaseFirewallLock
                    Start-GuardReleaseController
                    $progress={param($Details) Send-GuardReleaseProgress 'RollingBack' $Details}
                    $null=Wait-GuardReleaseReady $state.Previous $since 2 -Diagnostics $result.RestoreVerification -Progress $progress
                }
            }
        }
        [IO.File]::Delete($journalFile)
        $result.RestoredClosed=$state.PriorRouteUnavailable
    }
}
try{
    $operationMutex=[Threading.Mutex]::new($false,'Global\ClaudeVPNGuard_ReleaseInstall')
    try{$operationHeld=$operationMutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$operationHeld=$true}
    if(-not $operationHeld){throw 'Another Guard deployment is running.'}
    $firewallMutex=[Threading.Mutex]::new($false,'Global\ClaudeVPNGuard_FirewallSetup')
    $launchMutex=[Threading.Mutex]::new($false,$script:GuardDailyLaunchMutex)
    Open-GuardReleaseLaunchLock
    $created=$false
    $revision=[Threading.EventWaitHandle]::new($true,'ManualReset',$script:GuardDailyRevisionEvent,[ref]$created)
    if(-not $created){throw 'Another session owns Guard maintenance.'}
    Enter-GuardReleaseFirewallLock
    if($Recover){
        $pending=Read-GuardReleaseRecoveryJson $journalFile
        if($pending.Version -notin 1,2 -or $pending.Stage -cne (Split-Path -Leaf $stage) -or $pending.OwnerSid -cne $sid -or
            $pending.RunnerSha256 -cne $runnerSha256 -or
            $pending.Operation -cnotmatch '\A[a-f0-9]{32}\z'){
            throw 'Use the same protected installer and Windows account that began the pending deployment.'
        }
        $result.Operation=$pending.Operation
    }else{$result.Operation=[guid]::NewGuid().ToString('N')}
    $operationPath=Join-Path (Join-Path $stage 'operations') $result.Operation
    $backup=Join-Path $operationPath 'previous'
    if($Recover){
        $result.Mode='Recover'
        Send-GuardReleaseProgress 'RollingBack'
        try{
            try{
                $priorResult=Read-GuardReleaseRecoveryJson (Join-Path $operationPath 'result.json')
                if($priorResult.Operation -ceq $result.Operation -and $priorResult.Phase -ceq 'RollbackIncomplete'){
                    $result.FailedPhase=$priorResult.FailedPhase
                    $result.Error=$priorResult.Error
                    if($priorResult.Verification){$result.Verification=$priorResult.Verification}
                }
            }catch{}
            Initialize-GuardReleaseRecovery $pending
            Save-GuardReleaseJournal
            & $operations.Restore
            $result.Phase='RolledBack'
            $result.Restored=$true
        }catch{
            $result.Phase='RollbackIncomplete'
            $result.RestoreError=$_.Exception.Message
        }
        Send-GuardReleaseProgress $result.Phase
        Save-GuardReleaseReceipt
    }else{
        Invoke-GuardReleaseChange $operations $result
    }
}finally{
    if($rollbackRunner){
        try{$rollbackRunner.StandardInput.Close();$null=$rollbackRunner.WaitForExit(2000)}
        catch{}
        finally{$rollbackRunner.Dispose()}
    }
    Release-GuardReleaseLaunchLock
    Exit-GuardReleaseFirewallLock
    if($revision){$revision.Dispose()}
    if($launchMutex){$launchMutex.Dispose()}
    if($firewallMutex){$firewallMutex.Dispose()}
    if($operationHeld){$operationMutex.ReleaseMutex()}
    if($operationMutex){$operationMutex.Dispose()}
}
[pscustomobject]$result
