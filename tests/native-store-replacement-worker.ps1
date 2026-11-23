#Requires -Version 5.1
param([ValidateSet('InstallAndInterrupt','Recover','Remove')][string]$StoreReplacementOperation)

function New-GuardNativeReplacementPlans($Journal,[string]$Stage) {
    $name=[regex]::Match([string]$Journal.Package,'\A(?<name>GuardMsixFixture\.[a-f0-9]{32})_2\.0\.0\.0_x64__(?<issuer>[a-z0-9]{13})\z')
    if(-not $name.Success -or $Journal.Version -ne 1 -or
        $Journal.OldPackage -cne $Journal.Package.Replace('_2.0.0.0_','_1.0.0.0_')){
        throw 'The replacement journal does not identify the generated test package.'
    }
    $family=$name.Groups['name'].Value+'_'+$name.Groups['issuer'].Value
    if($Journal.Family -cne $family -or $Journal.PackageSid -cne (Get-GuardPackageSid $family)){
        throw 'The replacement package identity disagrees with its verified family.'
    }
    $root=[string]$Journal.PackageRoot
    if($root -notmatch '\A[A-Z]:\\(?:[A-Za-z0-9 ._-]+\\)*WindowsApps\\[^\\]+\z' -or
        [IO.Path]::GetFullPath($root) -ine $root -or (Split-Path -Leaf $root) -cne $Journal.Package){
        throw 'The Store fixture root is outside its exact versioned WindowsApps folder.'
    }
    $old=$Journal.OldPolicy
    $oldRoot=Join-Path (Split-Path -Parent $root) $Journal.OldPackage
    $oldImage=Join-Path $oldRoot 'fixture-desktop.exe'
    $images=@((Join-Path $root 'fixture-desktop.exe'),(Join-Path $root 'fixture-helper-v2.exe'))
    if(($Journal.Images -join '|') -ine ($images -join '|') -or $old.Image -ine $oldImage -or
        $old.PackageSid -cne $Journal.PackageSid -or $old.Upstream -cne '127.0.0.1' -or
        $old.Relay -ine (Join-Path $Stage 'normal-fixture-relay.exe') -or
        $old.Observer -ine (Join-Path $Stage 'normal-fixture-observer.exe') -or
        $old.RelayPort -lt 20000 -or $old.RelayPort -gt 47999 -or $old.UpstreamPort -lt 1024 -or
        $old.UpstreamPort -gt 65535 -or $old.UpstreamPort -eq $old.RelayPort -or
        $Journal.ImageSha256 -cnotmatch '\A[0-9A-F]{64}\z'){
        throw 'The replacement journal escaped the isolated fixture programs or loopback tuples.'
    }
    $sid=[string]$Journal.PackageSid
    $oldPlan=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage(
        [string[]]@($oldImage),[string[]]@($oldImage),[string[]]@($sid),$null,$sid,
        $old.Relay,[uint16]$old.RelayPort,'127.0.0.1',[uint16]$old.UpstreamPort,$old.Observer
    ).WithEarlyBootBlocks().ForPersistentUse([guid]$old.Deployment).WithRegisteredPackageAdmission([string[]]@($oldImage))
    $newPlan=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage(
        [string[]]$images,[string[]]@($images[0]),[string[]]@($sid),$null,$sid,
        $old.Relay,[uint16]$old.RelayPort,'127.0.0.1',[uint16]$old.UpstreamPort,$old.Observer
    ).WithEarlyBootBlocks().ForPersistentUse([guid]$Journal.Deployment).WithRegisteredPackageAdmission([string[]]$images)
    foreach($binding in @(@{Plan=$oldPlan;Receipt=$old},@{Plan=$newPlan;Receipt=$Journal})){
        if($binding.Plan.PersistentSublayer -ne [guid]$binding.Receipt.Sublayer -or
            ($binding.Plan.GetBaselineKeys() -join ',') -cne ($binding.Receipt.BaselineKeys -join ',') -or
            ($binding.Plan.GetBootKeys() -join ',') -cne ($binding.Receipt.BootKeys -join ',')){
            throw 'The replacement journal cannot reproduce its exact saved Windows rule keys.'
        }
    }
    if($oldPlan.PersistentSublayer -eq $newPlan.PersistentSublayer){throw 'The replacement requires its own closed rule group.'}
    [pscustomobject]@{Old=$oldPlan;New=$newPlan;Name=$name.Groups['name'].Value}
}

function Invoke-GuardNativeReplacementChild([ValidateSet('InstallAndInterrupt','Recover','Remove')][string]$Operation) {
    $worker=Join-Path $PSScriptRoot 'native-store-replacement-worker.ps1'
    Assert-GuardSandboxieAdministratorPath $worker
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -StoreReplacementOperation {1}' -f $worker,$Operation
    $child=Start-GuardDailyChild (Join-Path $PSHOME 'powershell.exe') $arguments ''
    try{
        if(-not $child.Process.WaitForExit(12000)){throw 'The isolated replacement policy worker exceeded its deadline.'}
        $expected=if($Operation -ceq 'InstallAndInterrupt'){73}else{0}
        if($child.Process.ExitCode -ne $expected){
            throw ("Replacement worker $Operation failed. "+$child.ErrorOutput.GetAwaiter().GetResult().Trim())
        }
        [pscustomobject]@{Pid=$child.Process.Id;ExitCode=$child.Process.ExitCode}
    }finally{Stop-GuardDailyChild $child}
}

if(-not $StoreReplacementOperation){return}
$ErrorActionPreference='Stop'
$stage=Split-Path -Parent $PSScriptRoot
$guardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if((Split-Path -Parent $stage) -ine $guardRoot -or (Split-Path -Leaf $stage) -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z' -or
    $PSScriptRoot -ine (Join-Path $stage 'tests') -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'The replacement test requires its own administrator-controlled native acceptance stage.'
}
$sources=@('guard-common.ps1','guard-sandboxie.ps1','guard-wfp.cs','guard-network.ps1','guard-isolation.ps1','guard-daily.ps1' |
    ForEach-Object {Join-Path $stage "package\$_"})
# Check the input chain before dot-sourcing any staged function.
$trusted=@('S-1-5-18','S-1-5-32-544')
$write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
foreach($path in @($guardRoot,$stage,$PSScriptRoot,(Join-Path $stage 'package'),$PSCommandPath)+$sources){
    $item=Get-Item -LiteralPath $path -Force
    $acl=Get-Acl -LiteralPath $path
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
        @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $write) -and $_.IdentityReference.Value -notin $trusted
        }).Count){
        throw 'A replacement worker input is outside administrator control.'
    }
}
. $sources[0]
. $sources[1]
Add-Type -Path $sources[2]

$journalPath=Join-Path $stage 'store-replacement-policy.json'
$mutex=[Threading.Mutex]::new($false,('Local\GuardStoreReplacement_'+(Split-Path -Leaf $stage)))
$held=$false
try{
    try{$held=$mutex.WaitOne(2000)}catch [Threading.AbandonedMutexException]{$held=$true}
    if(-not $held){throw 'Another isolated replacement worker is still running.'}
    Assert-GuardDailyStatePath $journalPath
    $journal=Read-GuardDailyJsonFile $journalPath
    $plans=New-GuardNativeReplacementPlans $journal $stage
    $native=[ClaudeGuard.Network.WindowsPolicySession]
    if($StoreReplacementOperation -ceq 'Remove'){
        if(@(Get-Process -Name fixture-desktop,fixture-helper-v2 -ErrorAction SilentlyContinue | Where-Object {
            -not $_.HasExited -and (-not $_.Path -or $_.Path -iin $journal.Images)
        }).Count){throw 'Replacement protection is retained while a fixture program is still running.'}
        if($null -ne $journal.Weight){
            $native::RemovePersistent($plans.New,[uint16]$journal.Weight)
        }elseif($native::ReadBootFilterCount($plans.New,0,$true) -ne 0){
            throw 'The journal has no weight for the installed replacement rules.'
        }
        $journal.Phase='Removed'
        $journal.Removed=$true
        Save-GuardAdministratorJson $journalPath $journal
        return
    }

    $app=@(Get-AppxPackage -Name $plans.Name -ErrorAction Stop)
    if($app.Count -ne 1 -or $app[0].Name -cne $plans.Name -or $app[0].PackageFullName -cne $journal.Package -or
        $app[0].PackageFamilyName -cne $journal.Family -or $app[0].InstallLocation -ine $journal.PackageRoot -or
        $app[0].Status -ne 'Ok'){
        throw 'Windows did not register the same generated replacement described by the journal.'
    }
    $physicalRoot=Get-GuardStorePhysicalPackageRoot $app[0].InstallLocation
    foreach($image in $journal.Images){
        $physical=Get-GuardStorePhysicalImage $app[0].InstallLocation $physicalRoot $image
        if((Get-FileHash -LiteralPath $physical -Algorithm SHA256).Hash -cne $journal.ImageSha256){
            throw 'A registered replacement fixture program does not have the recorded hash.'
        }
    }
    foreach($asset in $journal.OldPolicy.Relay,$journal.OldPolicy.Observer){Assert-GuardSandboxieAdministratorPath $asset}
    $native::VerifyNoPersistentAdmission($plans.Old,[uint16]$journal.OldPolicy.AssignedWeight)
    $recordWeight=[Action[uint16]]{
        param([uint16]$Weight)
        $journal.Weight=$Weight
        Save-GuardAdministratorJson $journalPath $journal
    }
    if($StoreReplacementOperation -ceq 'InstallAndInterrupt'){
        if($journal.Phase -cne 'Prepared' -or $null -ne $journal.Weight){throw 'The fixture replacement has already begun.'}
        $journal.InstallPid=$PID
        $journal.Phase='InstallingClosed'
        Save-GuardAdministratorJson $journalPath $journal
        $null=$native::InstallPersistent($plans.New,$recordWeight)
        # Leave the persisted before-commit record intact. The next process
        # must discover independently whether Windows committed the rules.
        exit 73
    }
    if($journal.Phase -cnotin 'InstallingClosed','RecoveredClosed' -or $journal.InstallPid -le 0 -or $journal.InstallPid -eq $PID){
        throw 'No independent interrupted installation could be recovered.'
    }
    $count=if($null -ne $journal.Weight){$native::ReadBootFilterCount($plans.New,[uint16]$journal.Weight,$true)}else{0}
    $reused=$count -gt 0
    if(-not $reused){
        $journal.Weight=$native::InstallPersistent($plans.New,$recordWeight)
        $count=$native::ReadBootFilterCount($plans.New,[uint16]$journal.Weight)
    }
    if($count -ne $plans.New.BootCount -or $count -eq 0){
        throw 'The replacement policy could not be recovered as one closed rule set.'
    }
    $journal.RecoverPid=$PID
    $journal.ReusedClosedRules=$reused
    $journal.OldAdmissionClosed=$true
    $journal.BootRules=$count
    $journal.Phase='RecoveredClosed'
    Save-GuardAdministratorJson $journalPath $journal
}finally{
    if($held){$mutex.ReleaseMutex()}
    $mutex.Dispose()
}
