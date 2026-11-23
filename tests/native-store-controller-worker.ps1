#Requires -Version 5.1
param([Parameter(Mandatory)][string]$Directory)
$ErrorActionPreference='Stop'
$fixtureStage=Split-Path -Parent $PSScriptRoot
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
if((Split-Path $fixtureStage -Parent) -ine $root -or (Split-Path $fixtureStage -Leaf) -cnotmatch '^native-acceptance-[a-f0-9]{32}$' -or
    $Directory -ine (Join-Path $fixtureStage 'store-controller')){
    throw 'Expected the scoped native store fixture.'
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Fixture WFP verification requires the native batch.'}
$sources=Join-Path $fixtureStage 'package'
. "$sources\guard-common.ps1"
. "$sources\guard-daily-controller.ps1"
. "$sources\guard-daily-plan.ps1"
. "$PSScriptRoot\native-installed-sandboxie-fixture.ps1"
foreach($dir in $fixtureStage,$PSScriptRoot,$Directory){
    Assert-GuardSandboxieAdministratorPath $dir
}
function Get-GuardDataPath([string]$Name){Join-Path $Directory $Name}
function Get-GuardIsolationMode{'Off'}
$inputs=Read-GuardDailyRecord 'fixture.json'
$scope=$inputs.Policy
$packageIdentity=[regex]::Match([string]$inputs.Package,'\A(?<name>GuardMsixFixture\.[a-f0-9]{32})_2\.0\.0\.0_x64__(?<issuer>[a-z0-9]{13})\z')
if(-not $packageIdentity.Success -or $scope.Upstream -cne '127.0.0.1' -or
    $scope.Observer -ine (Join-Path $fixtureStage 'normal-fixture-observer.exe') -or
    $scope.Relay -ine (Join-Path $fixtureStage 'normal-fixture-relay.exe')){
    throw 'The worker can only manage the synthetic package and loopback route.'
}
$packageName=$packageIdentity.Groups['name'].Value
$family=$packageName+'_'+$packageIdentity.Groups['issuer'].Value
$registered=@(Get-AppxPackage -Name $packageName -ErrorAction Stop | Where-Object Name -CEQ $packageName)
if($registered.Count -ne 1 -or $registered[0].PackageFullName -cne $inputs.Package -or
    $registered[0].PackageFamilyName -cne $family -or $inputs.Family -cne $family -or $registered[0].Status -ne 'Ok' -or
    (Split-Path -Leaf $registered[0].InstallLocation) -cne $inputs.Package -or $scope.PackageSid -cne (Get-GuardPackageSid $family)){
    throw 'The controller worker did not receive the verified Store replacement identity.'
}
$packageRoot=$registered[0].InstallLocation
$physicalRoot=Get-GuardStorePhysicalPackageRoot $packageRoot
$images=@((Join-Path $packageRoot 'fixture-desktop.exe'),(Join-Path $packageRoot 'fixture-helper-v2.exe'))
if($scope.Image -ine $images[0]){throw 'The controller worker image is outside the registered replacement.'}
foreach($image in $images){
    $physicalImage=Get-GuardStorePhysicalImage $packageRoot $physicalRoot $image
    if((Get-FileHash -LiteralPath $physicalImage).Hash -cne $inputs.ImageHash){
        throw 'A registered replacement controller image changed after the verified handoff.'
    }
}
Add-Type -Path "$sources\guard-wfp.cs"
$sandboxPaths=Get-GuardInstalledSandboxieFixturePaths $fixtureStage
$native=Get-GuardInstalledSandboxieFixtureNative $sandboxPaths.Driver
$nativePolicy=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage(
    [string[]]$images,[string[]]@($scope.Image),[string[]]@($scope.PackageSid),$null,$scope.PackageSid,
    $scope.Relay,[uint16]$scope.RelayPort,'127.0.0.1',[uint16]$scope.UpstreamPort,$scope.Observer
).WithEarlyBootBlocks().ForPersistentUse([guid]$scope.Deployment)
$nativePolicy=$nativePolicy.WithRegisteredPackageAdmission([string[]]$images)
if(-not (Test-GuardDailyPolicyBinding $scope $nativePolicy)){throw 'Fixture rule keys do not match.'}
$policyHandle=[ClaudeGuard.Network.WindowsPolicySession]::AttachPersistent($nativePolicy,[uint16]$scope.AssignedWeight)
$canonicalImage=Get-GuardFinalPath $scope.Image
$relayOwner=Get-Process -Id ([int]$inputs.RelayPid) -ErrorAction Stop
$halt=[Threading.ManualResetEvent]::new($false)
$closeBarrier=[Threading.EventWaitHandle]::OpenExisting($inputs.CloseBarrier)
$profile=@{Generation=('E'*64);RouteHash=('D'*64);ExpectedIpv4='203.0.113.99';Port=$scope.RelayPort
    DesktopHashes=@($inputs.ImageHash);ScopeName='GuardDesktop';ScopeSid=$scope.PackageSid;Containment='Sandboxie'}
$cache=@{ProcessId=0;StartedUtc='';RouteHash='';AttemptUtc=[datetime]::MinValue;Proof=$null;Worker=$null}

function Get-StoreFixtureEntries {
    foreach($proc in @(Get-Process -Name fixture-desktop -ErrorAction SilentlyContinue)){
        if($proc.HasExited){continue}
        $path=$proc.Path
        if($path -and ($path -ieq $scope.Image -or (Get-GuardFinalPath $path) -ieq $canonicalImage)){
            [pscustomobject]@{Id=$proc.Id;Start=$proc.StartTime.ToUniversalTime().Ticks;Process=$proc}
        }
    }
}
function Get-StoreFixtureShutdownEntries {
    $main=@(Get-StoreFixtureEntries)
    $main
    if(-not (Test-Path -LiteralPath (Get-GuardDataPath 'paused-exit-cleanup'))){return}
    foreach($fixturePid in [GuardInstalledSandboxieFixtureReadback]::ProcessIds()){
        if($fixturePid -in $main.Id){continue}
        $process=Get-Process -Id $fixturePid -ErrorAction SilentlyContinue
        if(-not $process -or $process.HasExited -or [GuardInstalledSandboxieFixtureReadback]::Box($fixturePid) -cne $inputs.Box){continue}
        [pscustomobject]@{Id=$process.Id;Start=$process.StartTime.ToUniversalTime().Ticks;Process=$process}
    }
}
function Test-StoreUpstreamDisconnected {
    $socket=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $transportClosed=$false
    try {
        $socket.Connect([Net.IPAddress]::Loopback,[int]$scope.UpstreamPort)
        $socket.ReceiveTimeout=500
        $stream=$socket.GetStream()
        $stream.WriteByte(0x47)
        $reply=$stream.ReadByte()
        $transportClosed=$reply -eq -1
    }catch{
        $cause=$_.Exception
        while($cause.InnerException){$cause=$cause.InnerException}
        $transportClosed=$cause -is [Net.Sockets.SocketException] -and
            $cause.SocketErrorCode -in [Net.Sockets.SocketError]::ConnectionRefused,[Net.Sockets.SocketError]::ConnectionReset
    }finally{$socket.Dispose()}
    $transportClosed
}
$observationMetrics=[ordered]@{PrimaryProofs=0;PrimaryOnlyProofs=0;BackupProofs=0;LastBackupDurationMs=$null;LastProvider='';LastProofUtc=$null}
$gateMetrics=[ordered]@{LastGate='';ClosedTransitions=0}
$observeArgs='"'+(Join-Path $PSScriptRoot 'exit-observer-fixture.mjs')+'" observe'
$fixtureObserver=@{
    Start={
        param($identity)
        $pending=@{Child=$null;Failure=$null;Backup=$false}
        if(Test-Path -LiteralPath (Get-GuardDataPath 'hold-witness')){return $pending}
        if(Test-StoreUpstreamDisconnected){
            $pending.Failure=[pscustomobject]@{Generation=$profile.Generation;RouteHash=$identity.RouteHash
                RelayId=$identity.ProcessId;RelayStartedUtc=$identity.StartedUtc
                CheckedUtc=[datetime]::UtcNow.ToString('o');Fault='UpstreamTransportDown'}
        }else{
            $pending.Backup=-not (Test-Path -LiteralPath (Get-GuardDataPath 'primary-only'))
            $inputText=@{port=$scope.RelayPort;backupExitLookup=$pending.Backup} | ConvertTo-Json -Compress
            $pending.Child=Start-GuardDailyChild $scope.Observer $observeArgs $inputText
        }
        $pending
    }
    Poll={
        param($pending,$identity)
        if(Test-Path -LiteralPath (Get-GuardDataPath 'hold-witness')){return}
        if($pending.Failure){return @{Finished=$true;Failure=$pending.Failure}}
        if(-not $pending.Child){return @{Finished=$true}}
        $sample=Read-GuardDailyObservationWorker $pending.Child $identity $profile.Generation $null -BackupExitLookup:$pending.Backup
        if($sample.Proof){
            if($sample.Proof.Provider -ceq 'Ipify'){
                $observationMetrics.BackupProofs++
                $process=$pending.Child.Process
                $observationMetrics.LastBackupDurationMs=[math]::Round(($process.ExitTime.ToUniversalTime()-$process.StartTime.ToUniversalTime()).TotalMilliseconds)
            }else{$observationMetrics.PrimaryProofs++}
            if(-not $pending.Backup -and $sample.Proof.Provider -ceq 'CloudflareTrace'){$observationMetrics.PrimaryOnlyProofs++}
            $observationMetrics.LastProvider=$sample.Proof.Provider
            $observationMetrics.LastProofUtc=$sample.Proof.CheckedUtc
            Save-GuardAdministratorJson (Get-GuardDataPath 'observation-metrics.json') $observationMetrics
        }
        $sample
    }
    Stop={param($pending) Stop-GuardDailyChild $pending.Child}
}
try{
    Start-GuardDailyHost $profile @{
        ReadIsolation={'Off'}
        VerifyInventory={
            $native::RequireReady()
            if((Get-FileHash -LiteralPath $scope.Image).Hash -cne $inputs.ImageHash){return $false}
            foreach($entry in @(Get-StoreFixtureEntries)){
                if([GuardInstalledSandboxieFixtureReadback]::Box($entry.Id) -cne $inputs.Box){return $false}
            }
            $true
        }
        ReadRelay={
            if($relayOwner.HasExited -or $relayOwner.Path -ine $scope.Relay -or
                $relayOwner.StartTime.ToUniversalTime().ToString('o') -cne $inputs.RelayStartUtc -or
                -not (Test-GuardDailyRelayListener $profile.Port $relayOwner.Id)){return}
            [pscustomobject]@{Ready=$true;RouteHash=$profile.RouteHash;Port=$profile.Port;ProcessId=$relayOwner.Id;StartedUtc=$inputs.RelayStartUtc}
        }
        ReadObservation={param($identity) Get-GuardDailyObservation $cache $identity $fixtureObserver}
        OpenVerified={param($deadline,$signal) $policyHandle.OpenUntilWithReceipt($deadline,$signal,$false)}
        CloseVerified={$policyHandle.Close();$true}
        WriteRecord={
            param($name,$data)
            if($name -ceq 'daily-health.json' -and $data.Gate -cne $gateMetrics.LastGate){
                if($gateMetrics.LastGate -ceq 'Open' -and $data.Gate -cne 'Open'){$gateMetrics.ClosedTransitions++}
                $gateMetrics.LastGate=$data.Gate
                Save-GuardAdministratorJson (Get-GuardDataPath 'gate-metrics.json') $gateMetrics
            }
            Save-GuardAdministratorJson (Get-GuardDataPath $name) $data
        }
        WriteNotice={param($name,$data) Save-GuardAdministratorJson (Get-GuardDataPath $name) $data}
        Snapshot={Get-StoreFixtureShutdownEntries}
        RequestClose={
            param($entry)
            # Block verification precedes the barrier. The parent observes
            # traffic while this same Store process is deliberately still alive.
            Save-GuardAdministratorJson (Get-GuardDataPath 'quit-request.json') ([pscustomobject]@{Id=$entry.Id;Utc=[datetime]::UtcNow.ToString('o')})
        }
        Wait={param($ms) $null=$closeBarrier.WaitOne($script:GuardDailyMaxLeaseSeconds*1000)}
        ForceStop={
            param($entry)
            if(-not $entry.Process.HasExited -and $entry.Process.Id -eq $entry.Id -and $entry.Process.StartTime.ToUniversalTime().Ticks -eq $entry.Start){
                $entry.Process.Kill()
                if(-not $entry.Process.WaitForExit(2000)){throw 'The fixture did not exit.'}
                $true
            }
        }
    } $halt -StartProbeBeforeInventory
}finally{
    try{
        $policyHandle.Dispose()
        if($cache.Worker){Stop-GuardDailyChild $cache.Worker.Child}
    }finally{
        $relayOwner.Dispose();$closeBarrier.Dispose();$halt.Dispose()
    }
}
