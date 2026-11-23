#Requires -Version 5.1
$ErrorActionPreference='Stop'
$source=Split-Path -Parent $PSScriptRoot
. "$source\release\install-guard-helpers.ps1"
. "$source\package\guard-node-profile.ps1"

# Execute the actual transaction blocks, never the elevated entry point.
$parseErrors=$null
$tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $source 'release\install-guard.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors){throw ($parseErrors | Out-String)}
function Get-SetupAssignment([string]$Name){
    $match=$ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq ('$'+$Name)},$true)
    if(-not $match){throw "Missing installed transaction assignment $Name."}
    $match
}
$transaction=Get-SetupAssignment operations
$allowed=@('Add-Member','Assert-GuardReleaseClosed','Assert-GuardReleaseOwnedPath','Confirm-GuardDailySandboxieApp','ConvertFrom-Json',
    'ConvertTo-Json','Enter-GuardReleaseFirewallLock','Exit-GuardReleaseFirewallLock','Export-ScheduledTask','ForEach-Object','Get-ChildItem',
    'Get-GuardDailyNotifierTaskSnapshot','Get-GuardDailyServiceSids','Get-GuardInventory','Get-GuardIsolationMode','Get-GuardNetworkAdapters',
    'Get-GuardNodeProfileRoute','Get-GuardReleaseAsset','Get-GuardReleaseCanonicalIpv4','Get-GuardReleaseControllerTask','Get-GuardReleaseGeneration',
    'Get-GuardSandboxieApp','Get-GuardVpnAdapter','Get-NetTCPConnection','Get-Service','Initialize-GuardAdministratorDirectory',
    'Install-GuardDailyNotifierTask','Install-GuardReleaseDriver','Join-Path','New-GuardReleasePolicy','Open-GuardReleaseLaunchLock',
    'Read-GuardDailyDesktopImages','Read-GuardDailyRecord','Read-GuardDailyRelayConfig','Register-GuardReleaseController','Release-GuardReleaseLaunchLock',
    'Remove-GuardReleaseDriver','Remove-GuardReleaseProfile','Resolve-Path','Restore-GuardDailyNotifierTask','Save-GuardAdministratorJson',
    'Save-GuardReleaseJournal','Save-GuardReleasePolicyIdentity','Save-GuardReleaseReceipt','Send-GuardReleaseProgress',
    'Set-GuardReleaseAsset','Set-GuardReleaseControllerAction','Split-Path','Start-GuardReleaseRollbackRunner',
    'Start-GuardReleaseController','Start-ScheduledTask','Stop-GuardReleaseController','Stop-GuardReleaseOwnedRelay','Stop-ScheduledTask',
    'Test-GuardDailyDesktopImages','Test-GuardDailyPolicyBinding','Test-GuardDailyScopeBinding','Test-GuardReleaseIdle','Test-GuardReleaseSandboxie',
    'Test-Path','Undo-GuardDailyStoreStage','Unregister-ScheduledTask','Wait-GuardDailyNotifierTaskStopped','Wait-GuardReleaseReady','Where-Object')
foreach($command in $transaction.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)){
    if($command.GetCommandName() -in $allowed -or
        $command.Extent.Text -cin '& $NodeOperations.Apply $NodeProfile','& $NodeOperations.Snapshot'){continue}
    throw 'Review the installer transaction command before running this isolated test.'
}
$allowedStatic=@('[ClaudeGuard.Network.WindowsPolicySession]::InstallPersistent','[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount',
    '[ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent','[Environment]::GetFolderPath','[guid]::NewGuid',
    '[IO.Directory]::Exists','[IO.Directory]::Move','[IO.File]::Delete','[IO.File]::Exists')
foreach($call in $transaction.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static},$true)){
    if(($call.Expression.Extent.Text+'::'+$call.Member.Extent.Text) -notin $allowedStatic){
        throw 'Review the installer transaction API before running this isolated test.'
    }
}
$windowsPath="[Environment]::GetFolderPath('Windows')"
if(-not $transaction.Extent.Text.Contains($windowsPath)){throw 'Review the fixture redirection for the Windows path.'}
$operationSource=$transaction.Extent.Text.Replace($windowsPath,'$fixtureWindows')
$initialState=(Get-SetupAssignment state).Extent.Text
$initialResult=(Get-SetupAssignment result).Extent.Text
$safeFunctions=@('Save-GuardReleaseReceipt','Save-GuardReleaseJournal','New-GuardReleasePolicy','Assert-GuardReleaseClosed',
    'Remove-GuardReleaseProfile','Save-GuardReleasePolicyIdentity','Read-GuardReleaseRecoveryJson','Read-GuardReleaseRecoveryPolicy',
    'Initialize-GuardReleaseRecovery')
foreach($name in $safeFunctions){
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false)
    if(-not $definition){throw "Missing production helper $name."}
    . ([scriptblock]::Create($definition.Extent.Text))
}

if('ClaudeGuard.Network.WindowsPolicySession' -as [type]){throw 'Run in a clean process without the production WFP assembly.'}
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
namespace ClaudeGuard.Network {
    public sealed class IntegrationPolicy {
        public Guid PersistentSublayer { get; private set; }
        public int BootCount { get { return 2; } }
        public IntegrationPolicy(Guid id) { PersistentSublayer = id; }
        public IntegrationPolicy WithRegisteredPackageAdmission(string[] images) {
            if (images.Length != 1) throw new InvalidOperationException("Incorrect fixture image inventory");
            return this;
        }
        public string[] GetBaselineKeys() { return new[] { PersistentSublayer.ToString("D") }; }
        public string[] GetBootKeys() { return new[] { PersistentSublayer.ToString("D"), "Fixture" }; }
    }
    public static class WindowsPolicySession {
        public static readonly Dictionary<Guid, ushort> Closed = new Dictionary<Guid, ushort>();
        public static readonly List<string> Actions = new List<string>();
        public static ushort InstallPersistent(IntegrationPolicy plan, Action<ushort> beforeCommit) {
            if (Closed.ContainsKey(plan.PersistentSublayer)) throw new InvalidOperationException("Duplicate WFP sublayer");
            const ushort weight = 60000;
            beforeCommit(weight);
            Closed.Add(plan.PersistentSublayer, weight);
            Actions.Add("Install:" + plan.PersistentSublayer.ToString("D"));
            return weight;
        }
        public static int ReadBootFilterCount(IntegrationPolicy plan, ushort weight, bool allowMissing = false) {
            if (!Closed.ContainsKey(plan.PersistentSublayer) && allowMissing) return 0;
            if (!Closed.ContainsKey(plan.PersistentSublayer) || Closed[plan.PersistentSublayer] != weight)
                throw new InvalidOperationException("Fixture closed rule readback disagrees");
            return plan.BootCount;
        }
        public static void RemovePersistent(IntegrationPolicy plan, ushort weight) {
            if (ReadBootFilterCount(plan, weight, true) == 0) return;
            Closed.Remove(plan.PersistentSublayer);
            Actions.Add("Remove:" + plan.PersistentSublayer.ToString("D"));
        }
    }
}
'@

$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$fixtureRoot=Join-Path $base ('guard-setup-tests-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($fixtureRoot)
function Assert-SetupFixturePath([string]$Path){
    $full=[IO.Path]::GetFullPath($Path)
    if($full -ine $fixtureRoot -and -not $full.StartsWith($fixtureRoot+'\',[StringComparison]::OrdinalIgnoreCase)){
        throw 'The integration fixture attempted a path outside its private temporary directory.'
    }
}
function Assert-GuardReleaseOwnedPath([string]$Path,[switch]$Directory){
    Assert-SetupFixturePath $Path
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -ne [bool]$Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'The integration fixture asset has an unexpected type.'
    }
}
function Get-Acl([string]$LiteralPath){
    Assert-SetupFixturePath $LiteralPath
    $item=[pscustomobject]@{}
    Add-Member -InputObject $item -MemberType ScriptMethod -Name SetOwner -Value {param($owner)}
    $item
}
function Set-Acl([string]$LiteralPath,$AclObject){Assert-SetupFixturePath $LiteralPath}
function Test-Path([string]$LiteralPath){
    if($LiteralPath.StartsWith('HKLM:\',[StringComparison]::OrdinalIgnoreCase)){return $false}
    Assert-SetupFixturePath $LiteralPath
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
}
function Initialize-GuardAdministratorDirectory([string]$Path){Assert-SetupFixturePath $Path; $null=[IO.Directory]::CreateDirectory($Path)}
function Save-GuardAdministratorJson([string]$Path,$Data){
    Assert-SetupFixturePath $Path
    if($model.FailCompletion -and $Path -ieq $statusFile -and $Data.Phase -ceq 'Completed'){
        $model.CompletionSawJournal=[IO.File]::Exists($journalFile)
        throw 'Injected completion receipt failure'
    }
    Initialize-GuardAdministratorDirectory (Split-Path -Parent $Path)
    [IO.File]::WriteAllText($Path,($Data | ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
}
function Read-GuardDailyRecord([string]$Name){Read-GuardDailyJsonFile (Join-Path $root $Name)}
function Read-GuardDailyRelayConfig([int]$Port){if($model.Profile){Get-GuardNodeProfileRoute $model.Profile $Port}else{Get-GuardNodeProfileRoute $baselineProfile $Port}}
function Get-GuardSandboxieApp {$fixtureApp}
function Get-GuardInventory([switch]$LocalOnly){[pscustomobject]@{Programs=@($fixtureApp.DesktopPath);DesktopPaths=@($fixtureApp.DesktopPath);Packages=@(@{Sid=$fixtureApp.PackageSid})}}
function Get-GuardDailyServiceSids {}
function Read-GuardDailyDesktopImages($Inventory){[pscustomobject]@{Path=$fixtureApp.DesktopPath;Hash=('D'*64)}}
function Get-GuardIsolationMode {'Off'}
function Get-GuardNetworkAdapters {[pscustomobject]@{Name='Bettbox';Status='Up';InterfaceGuid=$vpnId}}
function Get-GuardVpnAdapter([string]$Id){if([guid]$Id -eq $vpnId){Get-GuardNetworkAdapters}}
function Get-NetTCPConnection([int]$LocalPort){if($model.PortTaken){[pscustomobject]@{LocalPort=$LocalPort}}}
function Get-Service {if($model.Driver){[pscustomobject]@{Name='SbieDrv'}}}
function Test-GuardReleaseIdle {-not $model.DesktopRunning}
function Test-GuardDailyScopeBinding($Record){$Record.ScopeSid -ceq $fixtureApp.PackageSid}
function Confirm-GuardDailySandboxieApp($Record,$App){if($Record.PackageFullName -cne $fixtureApp.PackageFullName){throw 'Unexpected fixture package'}}
function Test-GuardDailyPolicyBinding($Record,$Policy){([string]$Record.Sublayer -eq [string]$Policy.PersistentSublayer) -and
    (($Record.BootKeys -join '|') -ceq ($Policy.GetBootKeys() -join '|'))}
function New-GuardInstalledPolicy($Route,[int]$Port,[guid]$Deployment,$Inventory,$ScopeSid,$Containment){
    if(-not $Route.Upstream.server -or $ScopeSid -cne $fixtureApp.PackageSid){throw 'Missing scoped fixture endpoint'}
    [ClaudeGuard.Network.IntegrationPolicy]::new($Deployment)
}
function Open-GuardReleaseLaunchLock {$model.LaunchHeld=$true}
function Release-GuardReleaseLaunchLock {$model.LaunchHeld=$false}
function Enter-GuardReleaseFirewallLock {$model.FirewallHeld=$true}
function Exit-GuardReleaseFirewallLock {$model.FirewallHeld=$false}
function Get-GuardReleaseControllerTask {if($model.Controller){[pscustomobject]@{Actions=@($model.ControllerAction)}}}
function Test-GuardReleaseControllerAction($Action){$Action.Execute -in $shell,$bootstrap}
function Set-GuardReleaseControllerAction($Action){
    if($model.ControllerRunning -or -not (Test-GuardReleaseControllerAction $Action)){throw 'Controller action cannot be changed'}
    $model.ControllerAction=$Action
}
function Register-GuardReleaseController {
    if($model.Controller){throw 'Duplicate task'}
    $model.Controller=$true
    $model.ControllerAction=[pscustomobject]@{Execute=$bootstrap;Arguments=$backgroundControllerArguments;WorkingDirectory=$daily}
}
function Start-GuardReleaseRollbackRunner {$model.RollbackAnchored=$true}
function Send-GuardReleaseProgress($Phase,$Details){$model.ProgressPhase=$Phase}
function Stop-GuardReleaseController {$model.ControllerRunning=$false}
function Start-GuardReleaseController {if(-not $model.Controller -or $model.LaunchHeld){throw 'Controller cannot start'}; $model.ControllerRunning=$true}
function Stop-GuardReleaseOwnedRelay {}
function Export-ScheduledTask {'<OwnedFixtureTask/>'}
function Unregister-ScheduledTask {$model.Controller=$false;$model.ControllerRunning=$false}
function Start-ScheduledTask {$model.NotifierRunning=$true}
function Stop-ScheduledTask {$model.NotifierRunning=$false}
function Wait-GuardDailyNotifierTaskStopped {if($model.NotifierRunning){throw 'The fixture notifier is still running.'}}
function Get-GuardDailyNotifierTaskSnapshot($Sid,$Daily){if($model.Notifier){[pscustomobject]@{Enabled=$true;Running=$model.NotifierRunning}}}
function Install-GuardDailyNotifierTask($Sid,$Daily){$model.Notifier=$true; Get-GuardDailyNotifierTaskSnapshot $Sid $Daily}
function Restore-GuardDailyNotifierTask($Previous,$Sid,$Daily){$model.Notifier=[bool]$Previous;$model.NotifierRunning=[bool]$Previous.Running}
function Install-GuardReleaseDriver($Driver,$PackageRoot,$Port,$DataRoot){
    Assert-SetupFixturePath $Driver
    $installed=Read-GuardDailyRecord 'daily-provisioned.json'
    if(-not [ClaudeGuard.Network.WindowsPolicySession]::Closed.ContainsKey([guid]$installed.Sublayer)){throw 'Driver setup preceded WFP protection'}
    $model.Driver=$true
    [IO.File]::WriteAllText((Join-Path $Driver 'Sandboxie.ini'),'Fixture')
}
function Remove-GuardReleaseDriver($Driver){Assert-SetupFixturePath $Driver;$model.Driver=$false}
function Test-GuardReleaseSandboxie($Record){if(-not $model.Driver -or -not [IO.File]::Exists((Join-Path $driverRoot 'Sandboxie.ini'))){throw 'Fixture driver readback failed'}}
function Undo-GuardDailyStoreStage {Assert-SetupFixturePath $root;[IO.File]::Delete((Join-Path $root 'daily-store-stage.json'))}
function Wait-GuardReleaseReady($Record,[datetime]$Since,[int]$RequiredProofs,[switch]$RequireStoreWorker,$Diagnostics,$Progress){
    if(-not $model.ControllerRunning -or $model.FirewallHeld -or -not $model.Driver -or
        -not [ClaudeGuard.Network.WindowsPolicySession]::Closed.ContainsKey([guid]$Record.Sublayer) -or
        (Read-GuardDailyRelayConfig $Record.Port).Hash -cne $Record.RouteHash){throw 'Fixture readiness dependencies did not verify'}
    if($model.FailReady -and $RequiredProofs -eq 6){throw 'Injected readiness failure'}
    if($RequiredProofs -eq 2 -and $model.ControllerAction.Execute -ieq $shell -and -not $model.RollbackAnchored){
        throw 'The prior PowerShell controller needs the compatible rollback runner.'
    }
    $RequiredProofs
}

function Assert-Setup([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}; Write-Host "PASS $Message"}
function New-SetupTestNode([string]$Server){
    New-GuardNodeProfile -Fields @{ServerIpv4=$Server;ServerPort=443;Uuid='00000000-0000-4000-8000-000000000009';
        ServerName='fixture.test';RealityPublicKey=('A'*43);RealityShortId='';ClientFingerprint='chrome'}
}

function Invoke-SetupTestTransaction([switch]$RouteOnly,[pscredential]$NodeProfile,[switch]$Recovery){
    . ([scriptblock]::Create($initialState))
    . ([scriptblock]::Create($initialResult))
    . ([scriptblock]::Create($operationSource))
    $NodeOperations=@{
        Snapshot={@{HadProfile=[bool]$model.Profile;Protected=if($model.Profile){ConvertFrom-SecureString -SecureString $model.Profile.Password}}}
        Apply={param($profile) $model.Profile=$profile}
        Restore={param($snapshot)
            if($model.FailRestore){throw 'Injected profile rollback failure'}
            $model.Profile=if($snapshot.HadProfile){[pscredential]::new('GuardNodeProfile',(ConvertTo-SecureString $snapshot.Protected))}
        }
    }
    $model.LaunchHeld=$true
    $model.FirewallHeld=$true
    try{
        $pending=if($Recovery){Read-GuardReleaseRecoveryJson $journalFile}
        $result.Operation=if($Recovery){$pending.Operation}else{[guid]::NewGuid().ToString('N')}
        $operationPath=Join-Path (Join-Path $stage 'operations') $result.Operation
        $backup=Join-Path $operationPath 'previous'
        if($Recovery){
            Initialize-GuardReleaseRecovery $pending
            & $operations.Restore
            $result.Restored=$true
            $result.Phase='RolledBack'
        }else{Invoke-GuardReleaseChange $operations $result}
        [pscustomobject]$result
    }finally{$model.LaunchHeld=$false;$model.FirewallHeld=$false}
}

try{
    $root=Join-Path $fixtureRoot 'state'
    $fixtureWindows=Join-Path $fixtureRoot 'windows'
    $stage=Join-Path $root ('release-install-'+[guid]::NewGuid().ToString('N'))
    $daily=Join-Path $root 'daily'
    $runtimeHome=Join-Path $daily 'relay-data'
    $driverRoot=Join-Path $daily 'sandboxie'
    $vendor=Join-Path $stage 'vendor\sandboxie'
    foreach($directory in $root,$stage,$fixtureWindows,$vendor,(Join-Path $vendor '32')){Initialize-GuardAdministratorDirectory $directory}
    $vendorFile=Join-Path $vendor 'KmdUtil.exe'
    [IO.File]::WriteAllText($vendorFile,'Synthetic vendor payload')
    $script:GuardReleaseVendorPins=@{'KmdUtil.exe'=(Get-FileHash -LiteralPath $vendorFile).Hash}
    $provisioned=Join-Path $root 'daily-provisioned.json'
    $journalFile=Join-Path $root 'release-install-pending.json'
    $statusFile=Join-Path $stage 'install-result.json'
    $relay=Join-Path $daily 'guard-dedicated-relay.exe'
    $observer=Join-Path $daily 'guard-exit-observer.exe'
    $vpnId=[guid]::NewGuid()
    $VpnGuid=[guid]::Empty
    $sid='S-1-5-21-1000-1000-1000-1001'
    $ExpectedIpv4='203.0.113.61'
    $taskName='Only the integration task'
    $bootstrap=Join-Path $stage 'ClaudeGuardSetup.exe'
    $shell=Join-Path $fixtureWindows 'powershell.exe'
    $backgroundControllerArguments='--background-controller'
    $legacyControllerAction=[pscustomobject]@{Execute=$shell;Arguments='fixture legacy action';WorkingDirectory=$null}
    $model=@{Profile=$null;Driver=$false;Controller=$false;ControllerRunning=$false;Notifier=$false;NotifierRunning=$false}
    $fixtureApp=[pscustomobject]@{PackageFullName='GuardMsixFixture.11111111111141118111111111111111_2.0.0.0_x64__1111111111111'
        Root=(Join-Path $fixtureRoot 'store-fixture');PackageSid='S-1-15-2-111-222-333-444-555-666-777';AppId='Desktop'}
    $fixtureApp | Add-Member NoteProperty DesktopPath (Join-Path $fixtureApp.Root 'fixture-desktop.exe')
    $baselineProfile=New-SetupTestNode '203.0.113.41'
    $nextProfile=New-SetupTestNode '203.0.113.42'
    $thirdProfile=New-SetupTestNode '203.0.113.43'
    $assetNames=@('guard-dedicated-relay.exe','guard-exit-observer.exe','cloudflare-exit-probe.mjs','guard-profile-store.ps1',
        'guard-node-profile.ps1','guard-daily-plan.ps1','guard-daily-supervisor.ps1','guard-daily-package.ps1')
    function Get-SetupFixtureRelease([int]$Version){
        foreach($name in $assetNames){
            $payload=Join-Path $stage $name
            [IO.File]::WriteAllText($payload,"Synthetic release $Version, $name")
            Get-GuardReleaseAsset $payload (Join-Path $daily $name)
        }
    }
    $assets=@(Get-SetupFixtureRelease 1)
    $model.FailReady=$true
    $freshFailure=Invoke-SetupTestTransaction -NodeProfile $baselineProfile
    if(-not $freshFailure.Restored){throw "Fresh rollback failed: $($freshFailure.Error), $($freshFailure.RestoreError)"}
    Assert-Setup (-not $freshFailure.Installed -and $freshFailure.FailedPhase -ceq 'Verify' -and -not $model.Controller -and
        -not $model.Driver -and -not $model.Notifier -and -not $model.Profile -and -not [IO.Directory]::Exists($daily) -and
        -not [IO.File]::Exists($provisioned) -and -not [IO.File]::Exists($journalFile) -and
        [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 0) 'A failed fresh install removes its files, services, tasks, profile and closed rules before a retry.'
    $model.FailReady=$false
    $fresh=Invoke-SetupTestTransaction -NodeProfile $baselineProfile
    if(-not $fresh.Installed){throw "Fresh fixture failed: $($fresh.FailedPhase), $($fresh.Error), $($fresh.RestoreError)"}
    $firstRecord=Read-GuardDailyRecord 'daily-provisioned.json'
    Assert-Setup ($fresh.Mode -ceq 'Fresh' -and $fresh.FreshProofs -eq 6 -and $model.Driver -and $model.ControllerRunning -and
        $firstRecord.RouteHash -ceq (Get-GuardNodeProfileRoute $baselineProfile 18793).Hash -and -not [IO.File]::Exists($journalFile)) `
        'Fresh install verifies closed rules, persists its selected node, installs files and reaches the controller readiness check.'

    $model.ControllerAction=$legacyControllerAction
    $assets=@(Get-SetupFixtureRelease 2)
    $update=Invoke-SetupTestTransaction
    if(-not $update.Installed){throw "Update fixture failed: $($update.FailedPhase), $($update.Error), $($update.RestoreError)"}
    $updatedRecord=Read-GuardDailyRecord 'daily-provisioned.json'
    $newRelayHash=(Get-FileHash -LiteralPath $relay).Hash
    Assert-Setup ($update.Mode -ceq 'Update' -and $updatedRecord.DeploymentId -eq $firstRecord.DeploymentId -and
        $updatedRecord.Generation -cne $firstRecord.Generation -and $newRelayHash -ceq $assets[0].Sha256 -and
        $model.ControllerAction.Execute -ieq $bootstrap -and $model.ControllerAction.Arguments -ceq '--background-controller' -and
        [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1) 'Existing update migrates its task and replaces the generation while retaining the same-route WFP policy.'

    $model.ControllerAction=$legacyControllerAction
    $assets=@(Get-SetupFixtureRelease 3)
    $model.FailReady=$true
    $failedUpdate=Invoke-SetupTestTransaction
    Assert-Setup (-not $failedUpdate.Installed -and $failedUpdate.Restored -and $failedUpdate.FailedPhase -ceq 'Verify' -and
        (Get-FileHash -LiteralPath $relay).Hash -ceq $newRelayHash -and
        (Read-GuardDailyRecord 'daily-provisioned.json').Generation -ceq $updatedRecord.Generation -and
        $model.ControllerRunning -and $model.ControllerAction.Execute -ieq $shell -and $model.RollbackAnchored -and
        $model.NotifierRunning -and [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1) `
        'An unsuccessful full update restores the previous file bytes, provisioning and both owned tasks.'
    $model.FailReady=$false
    $assets=@(Get-SetupFixtureRelease 2)

    $switched=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $nextProfile
    if(-not $switched.Installed){throw "Route fixture failed: $($switched.FailedPhase), $($switched.Error), $($switched.RestoreError)"}
    $nodeRecord=Read-GuardDailyRecord 'daily-provisioned.json'
    $actions=[ClaudeGuard.Network.WindowsPolicySession]::Actions
    Assert-Setup ($switched.Mode -ceq 'RouteOnly' -and $nodeRecord.DeploymentId -ne $updatedRecord.DeploymentId -and
        $nodeRecord.RouteHash -ceq (Get-GuardNodeProfileRoute $nextProfile 18793).Hash -and
        $newRelayHash -ceq (Get-FileHash -LiteralPath $relay).Hash -and
        $actions[$actions.Count-2] -ceq ('Install:'+$nodeRecord.Sublayer) -and $actions[$actions.Count-1] -ceq ('Remove:'+$updatedRecord.Sublayer)) `
        'A node switch installs its closed policy before retiring the old one and preserves installed binaries.'

    $model.FailReady=$true
    $rolledBack=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $thirdProfile
    $restoredRecord=Read-GuardDailyRecord 'daily-provisioned.json'
    Assert-Setup (-not $rolledBack.Installed -and $rolledBack.Restored -and $rolledBack.FailedPhase -ceq 'Verify' -and
        $restoredRecord.Generation -ceq $nodeRecord.Generation -and $model.ControllerRunning -and
        (Read-GuardDailyRelayConfig 18793).Hash -ceq $nodeRecord.RouteHash -and
        [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1 -and -not [IO.File]::Exists($journalFile)) `
        'A failed candidate readiness check restores the prior node, provisioning, closed rule set and running task.'

    $model.FailRestore=$true
    $pending=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $thirdProfile
    Assert-Setup ($pending.Phase -ceq 'RollbackIncomplete' -and [IO.File]::Exists($journalFile)) 'Incomplete rollback retains its recovery journal.'
    $rejected=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $nextProfile
    Assert-Setup ($rejected.Phase -ceq 'Rejected' -and [IO.File]::Exists($journalFile)) 'A second install is rejected before touching a pending transaction.'
    $model.FailRestore=$false
    $recovered=Invoke-SetupTestTransaction -Recovery
    Assert-Setup ($recovered.Restored -and (Read-GuardDailyRecord 'daily-provisioned.json').Generation -ceq $nodeRecord.Generation -and
        $model.ControllerRunning -and [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1 -and
        -not [IO.File]::Exists($journalFile)) 'Recovery reconstructs both policies from the protected journal and completes the interrupted rollback.'

    $model.FailReady=$false
    $retry=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $thirdProfile
    Assert-Setup ($retry.Installed -and (Read-GuardDailyRelayConfig 18793).Hash -ceq (Get-GuardNodeProfileRoute $thirdProfile 18793).Hash -and
        [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1) 'The same requested node can be applied after recovery without duplicate tasks or policies.'

    $committed=Read-GuardDailyRecord 'daily-provisioned.json'
    $model.FailCompletion=$true
    $receiptFailure=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $nextProfile
    Assert-Setup ($model.CompletionSawJournal -and -not $receiptFailure.Installed -and $receiptFailure.Restored -and
        (Read-GuardDailyRecord 'daily-provisioned.json').Generation -ceq $committed.Generation -and $model.ControllerRunning -and
        -not [IO.File]::Exists($journalFile)) 'The durable rollback journal is still present if writing the final success receipt fails.'
}finally{
    $folder=Get-Item -LiteralPath $fixtureRoot -Force
    if($folder.Parent.FullName.TrimEnd('\') -ine $base -or $folder.Name -cnotmatch '^guard-setup-tests-[a-f0-9]{32}$' -or
        ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected integration cleanup directory.'}
    [IO.Directory]::Delete($folder.FullName,$true)
}
