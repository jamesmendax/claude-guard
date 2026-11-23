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
    'ConvertTo-Json','Enter-GuardReleaseFirewallLock','Exit-GuardReleaseFirewallLock','Export-ScheduledTask','Find-GuardPriorBettboxRoute','ForEach-Object','Get-ChildItem',
    'Get-GuardDailyNotifierTaskSnapshot','Get-GuardDailyServiceSids','Get-GuardInventory','Get-GuardIsolationMode','Get-GuardNetworkAdapters',
    'Get-GuardNodeProfileRoute','Get-GuardNodeStorePath','Get-GuardReleaseAsset','Get-GuardReleaseCanonicalIpv4','Get-GuardReleaseControllerTask','Get-GuardReleaseGeneration',
    'Get-GuardSandboxieApp','Get-GuardVpnAdapter','Get-NetTCPConnection','Get-Service','Initialize-GuardAdministratorDirectory',
    'Install-GuardDailyNotifierTask','Install-GuardReleaseDriver','Join-Path','New-GuardReleasePolicy','Open-GuardReleaseLaunchLock',
    'Read-GuardDailyDesktopImages','Read-GuardDailyRecord','Read-GuardDailyRelayConfig','Register-GuardReleaseController','Release-GuardReleaseLaunchLock',
    'Remove-GuardReleaseDriver','Remove-GuardReleaseProfile','Resolve-Path','Restore-GuardDailyNotifierTask','Save-GuardAdministratorJson',
    'Save-GuardReleaseJournal','Save-GuardReleasePolicyIdentity','Save-GuardReleaseReceipt','Send-GuardReleaseProgress',
    'Set-GuardReleaseAsset','Set-GuardReleaseControllerAction','Set-GuardReleaseLocaleFailure','Split-Path','Start-GuardReleaseRollbackRunner',
    'Start-GuardReleaseController','Start-ScheduledTask','Stop-GuardReleaseController','Stop-GuardReleaseOwnedRelay','Stop-ScheduledTask',
    'Test-GuardDailyDesktopImages','Test-GuardDailyPolicyBinding','Test-GuardDailyScopeBinding','Test-GuardNodeStoreItem','Test-GuardReleaseIdle','Test-GuardReleaseSandboxie',
    'Test-Path','Undo-GuardDailyStoreStage','Unregister-ScheduledTask','Wait-GuardDailyNotifierTaskStopped','Wait-GuardReleaseReady','Where-Object')
foreach($command in $transaction.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)){
    if($command.GetCommandName() -in $allowed -or
        $command.Extent.Text -cin '& $NodeOperations.Apply $NodeProfile $persistLocale','& $NodeOperations.Snapshot','& $NodeOperations.Verify'){continue}
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
    'Remove-GuardReleaseProfile','Set-GuardReleaseLocaleFailure','Save-GuardReleasePolicyIdentity','Read-GuardReleaseRecoveryJson','Read-GuardReleaseRecoveryPolicy',
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
        private readonly string endpoint;
        public IntegrationPolicy(Guid id, string endpoint) { PersistentSublayer = id; this.endpoint = endpoint; }
        public IntegrationPolicy WithRegisteredPackageAdmission(string[] images) {
            if (images.Length != 1) throw new InvalidOperationException("Incorrect fixture image inventory");
            return this;
        }
        public string[] GetBaselineKeys() { return new[] { PersistentSublayer.ToString("D") }; }
        public string[] GetBootKeys() { return new[] { PersistentSublayer.ToString("D"), endpoint }; }
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
function Test-Path([string]$LiteralPath,[string]$PathType='Any'){
    if($LiteralPath.StartsWith('HKLM:\',[StringComparison]::OrdinalIgnoreCase)){return $false}
    Assert-SetupFixturePath $LiteralPath
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType
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
function Read-GuardDailyRelayConfig([int]$Port){
    if($model.Profile){return Get-GuardNodeProfileRoute $model.Profile $Port}
    if($model.LegacyReadThrows){throw 'Injected unsupported current Bettbox selection'}
    $selection=if($model.LegacySelection){$model.LegacySelection}else{$baselineProfile}
    Get-GuardNodeProfileRoute $selection $Port
}
function Find-GuardPriorBettboxRoute([string]$ExpectedHash,[int]$Port){
    $model.PriorSearches++
    if($ExpectedHash -cne (Read-GuardDailyRecord 'daily-provisioned.json').RouteHash -or $Port -ne 18793){
        throw 'The fixture search was not pinned to the approved relay.'
    }
    $model.SavedPriorRoute
}
function Get-GuardNodeStorePath {Join-Path $root 'node-private\selected-node.json'}
function Test-GuardNodeStoreItem([string]$Path,[switch]$Directory){
    Assert-SetupFixturePath $Path
    [bool]($model.Profile -or $model.ManualStorePresent)
}
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
    (($Record.BaselineKeys -join '|') -ceq ($Policy.GetBaselineKeys() -join '|')) -and
    (($Record.BootKeys -join '|') -ceq ($Policy.GetBootKeys() -join '|'))}
function New-GuardInstalledPolicy($Route,[int]$Port,[guid]$Deployment,$Inventory,$ScopeSid,$Containment){
    if(-not $Route.Upstream.server -or $ScopeSid -cne $fixtureApp.PackageSid -or
        $fixtureApp.DesktopPath -notin @($Inventory.Programs)){throw 'Missing scoped fixture endpoint or inventory'}
    [ClaudeGuard.Network.IntegrationPolicy]::new($Deployment,('{0}|{1}' -f $Route.Upstream.server,$Route.Upstream.port))
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
function Start-GuardReleaseController {
    if(-not $model.Controller -or $model.LaunchHeld){throw 'Controller cannot start'}
    $model.Starts++
    $model.ControllerRunning=$true
}
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
    if($RequiredProofs -eq 2){$model.OldReadinessChecks++}
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

function Invoke-SetupTestTransaction([switch]$RouteOnly,[pscredential]$NodeProfile,[switch]$Recovery,[switch]$StopAfterBackup,
    [string]$RequirePriorGeneration,[switch]$VerifyLocale){
    . ([scriptblock]::Create($initialState))
    . ([scriptblock]::Create($initialResult))
    . ([scriptblock]::Create($operationSource))
    $NodeOperations=@{
        Snapshot={[pscustomobject]@{
            Node=[pscustomobject]@{Exists=[bool]$model.Profile;Protected=if($model.Profile){ConvertFrom-SecureString -SecureString $model.Profile.Password}}
            Version=2; Region=$model.Region;WindowsLocale=$model.WindowsLocale;BrowserLocale=$model.BrowserLocale
        }}
        Apply={param($profile,$persistLocale)
            $snapshot=Read-GuardReleaseRecoveryJson (Join-Path $backup 'node-snapshot.json')
            if($snapshot.WindowsLocale -cne $model.WindowsLocale -or $snapshot.BrowserLocale -cne $model.BrowserLocale){
                throw 'Fixture locale settings were not journaled before the first write'
            }
            $model.Profile=$profile; $model.Region='Fixture candidate zone'
            if($VerifyLocale){
                Add-Member -InputObject $state.Profile -NotePropertyName 'WindowsPendingWrite' -NotePropertyValue 'RegionalFormat'
                & $persistLocale $state.Profile
                if((Read-GuardReleaseRecoveryJson (Join-Path $backup 'node-snapshot.json')).WindowsPendingWrite -cne 'RegionalFormat'){
                    throw 'The protected transaction did not persist a before-write marker'
                }
                $model.WindowsLocale='ja-JP';$model.BrowserLocale='ja,en-US,en'
                $state.Profile.WindowsPendingWrite=$null
                & $persistLocale $state.Profile
            }
        }
        Restore={param($snapshot)
            if($model.FailRestore){throw 'Injected profile rollback failure'}
            $model.Profile=if($snapshot.Node.Exists){[pscredential]::new('GuardNodeProfile',(ConvertTo-SecureString $snapshot.Node.Protected))}
            $model.Region=$snapshot.Region;$model.WindowsLocale=$snapshot.WindowsLocale;$model.BrowserLocale=$snapshot.BrowserLocale
        }
    }
    if($VerifyLocale){
        $NodeOperations.Verify={
            if(-not [IO.File]::Exists($journalFile) -or $result.FreshProofs -ne 6 -or
                $model.WindowsLocale -cne 'ja-JP' -or $model.BrowserLocale -cne 'ja,en-US,en'){
                throw 'The fixture verified locale outside the protected verification phase'
            }
            if($model.FailSiteLanguage){
                $failure=[InvalidOperationException]::new('Synthetic private path C:\private\fixture-browser-data\Preferences')
                $failure.Data['GuardLocaleFailure']='EdgeSiteMismatch'
                throw $failure
            }
            [pscustomobject]@{SiteAcceptLanguage='ja,en-US;q=0.9,en;q=0.8'}
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
        }elseif($StopAfterBackup){
            & $operations.Preflight
            $result.Phase='Backup'
            & $operations.Backup
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
    $model=@{Profile=$null;Driver=$false;Controller=$false;ControllerRunning=$false;Notifier=$false;NotifierRunning=$false
        Region='Fixture original zone';WindowsLocale='en-US';BrowserLocale='en-US,en';PriorSearches=0;Starts=0;OldReadinessChecks=0}
    $fixtureApp=[pscustomobject]@{PackageFullName='GuardMsixFixture.9e866f72bae947b08f86410f529dd2d1_2.0.0.0_x64__8689sk8k9f0by'
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
    $oldJournal=Read-GuardReleaseRecoveryJson $journalFile
    $oldJournal.Version=1
    $oldJournal.PSObject.Properties.Remove('PriorRouteUnavailable')
    Save-GuardAdministratorJson $journalFile $oldJournal
    $model.FailRestore=$false
    $recovered=Invoke-SetupTestTransaction -Recovery
    Assert-Setup ($recovered.Restored -and (Read-GuardDailyRecord 'daily-provisioned.json').Generation -ceq $nodeRecord.Generation -and
        $model.ControllerRunning -and [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1 -and
        -not [IO.File]::Exists($journalFile)) 'Recovery still accepts a prior journal without the new flag and reopens the verified prior route.'

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

    $model.FailCompletion=$false
    $model.FailSiteLanguage=$true
    $siteFailure=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $nextProfile -VerifyLocale
    Assert-Setup (-not $siteFailure.Installed -and $siteFailure.Restored -and $siteFailure.FailedPhase -ceq 'Verify' -and
        $siteFailure.Error -ceq 'Edge website language settings did not pass final readback.' -and
        $siteFailure.LocaleFailure -ceq 'EdgeSiteMismatch' -and -not $siteFailure.SiteAcceptLanguage -and
        $siteFailure.Error -notmatch 'private|Preferences' -and
        $model.WindowsLocale -ceq 'en-US' -and $model.BrowserLocale -ceq 'en-US,en' -and -not [IO.File]::Exists($journalFile)) `
        'A real site readback failure prevents commit and restores the prior Windows and Edge settings.'
    $model.FailSiteLanguage=$false
    $verifiedLocale=Invoke-SetupTestTransaction -RouteOnly -NodeProfile $thirdProfile -VerifyLocale
    Assert-Setup ($verifiedLocale.Installed -and $verifiedLocale.SiteAcceptLanguage -ceq 'ja,en-US;q=0.9,en;q=0.8' -and
        $model.WindowsLocale -ceq 'ja-JP' -and $model.BrowserLocale -ceq 'ja,en-US,en' -and -not [IO.File]::Exists($journalFile)) `
        'The verified website header is included only after its protected acceptance succeeds.'

    $legacyRecord=Read-GuardDailyRecord 'daily-provisioned.json'
    $legacyRecord.PSObject.Properties.Remove('ProxyMode')
    $legacyRecord.PSObject.Properties.Remove('PolicyInventory')
    Save-GuardAdministratorJson $provisioned $legacyRecord
    $legacyBytes=[IO.File]::ReadAllText($provisioned)
    $legacyZone='Fixture original zone'
    $model.Region=$legacyZone
    $model.Profile=$null
    $model.ControllerAction=$legacyControllerAction
    $model.RollbackAnchored=$false
    $model.LegacyReadThrows=$true
    $oldRoute=Get-GuardNodeProfileRoute $thirdProfile $legacyRecord.Port
    $jpProfile=New-GuardNodeProfile -Fields @{
        Transport='WebSocketTls';ServerIpv4='203.0.113.44';ServerPort=443
        Uuid='00000000-0000-4000-8000-000000000010';ServerName='jp.fixture.test'
        WebSocketHost='edge.fixture.test';WebSocketPath='/jp'
    }
    $jpRoute=Get-GuardNodeProfileRoute $jpProfile $legacyRecord.Port
    $assets=@(Get-SetupFixtureRelease 4)
    $health=Join-Path $root 'daily-health.json'
    [IO.File]::WriteAllText($health,'stale fixture health')
    $starts=$model.Starts
    $readinessChecks=$model.OldReadinessChecks

    $model.SavedPriorRoute=$oldRoute
    $unprobed=Invoke-SetupTestTransaction
    $stalePreview=Invoke-SetupTestTransaction -NodeProfile $jpProfile -RequirePriorGeneration ('F'*64)
    $model.ManualStorePresent=$true
    $unreadableManual=Invoke-SetupTestTransaction -NodeProfile $jpProfile
    $model.ManualStorePresent=$false
    Assert-Setup ($unprobed.Phase -ceq 'Rejected' -and $stalePreview.Phase -ceq 'Rejected' -and
        $unreadableManual.Phase -ceq 'Rejected' -and $model.PriorSearches -eq 0 -and $model.ControllerRunning -and
        -not [IO.File]::Exists($journalFile) -and [IO.File]::ReadAllText($provisioned) -ceq $legacyBytes) `
        'Migration rejects missing explicit node, stale installed generation and an unreadable existing manual store before searching.'

    $model.SavedPriorRoute=$jpRoute
    $unrelated=Invoke-SetupTestTransaction -NodeProfile $jpProfile -RequirePriorGeneration $legacyRecord.Generation
    $model.SavedPriorRoute=[pscustomobject]@{Hash=$oldRoute.Hash;Upstream=$jpRoute.Upstream}
    $differentRules=Invoke-SetupTestTransaction -NodeProfile $jpProfile -RequirePriorGeneration $legacyRecord.Generation
    Assert-Setup ($unrelated.Phase -ceq 'Rejected' -and $differentRules.Phase -ceq 'Rejected' -and $model.PriorSearches -eq 2 -and
        $model.ControllerRunning -and $model.Starts -eq $starts -and -not [IO.File]::Exists($journalFile) -and
        [IO.File]::ReadAllText($provisioned) -ceq $legacyBytes) `
        'Migration requires the exact approved old route hash and persistent firewall keys before writing a journal.'

    $model.SavedPriorRoute=$oldRoute
    $null=Invoke-SetupTestTransaction -NodeProfile $jpProfile -StopAfterBackup -RequirePriorGeneration $legacyRecord.Generation
    $earlyJournal=Read-GuardReleaseRecoveryJson $journalFile
    Assert-Setup ($earlyJournal.PriorRouteUnavailable -eq $true -and -not $earlyJournal.ControllerStopped -and
        $model.ControllerRunning -and [IO.File]::Exists($health)) 'The backup records closed rollback before touching the old controller.'
    $earlyRecovery=Invoke-SetupTestTransaction -Recovery
    Assert-Setup ($earlyRecovery.Restored -and $earlyRecovery.RestoredClosed -and -not $model.ControllerRunning -and
        $model.Starts -eq $starts -and $model.OldReadinessChecks -eq $readinessChecks -and
        [IO.File]::ReadAllText($provisioned) -ceq $legacyBytes -and -not [IO.File]::Exists($health) -and
        -not [IO.File]::Exists($journalFile) -and [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1) `
        'Recovery before the close step disables the old controller, removes stale readiness and verifies the exact closed rules.'

    $model.LegacyReadThrows=$false
    $model.LegacySelection=$jpProfile
    $model.FailReady=$true
    [IO.File]::WriteAllText($health,'stale fixture health')
    $failedMigration=Invoke-SetupTestTransaction -NodeProfile $jpProfile -RequirePriorGeneration $legacyRecord.Generation
    Assert-Setup ($failedMigration.Restored -and $failedMigration.RestoredClosed -and $failedMigration.FailedPhase -ceq 'Verify' -and
        $failedMigration.RestoreVerification.Status -ceq 'Closed' -and $failedMigration.RestoreVerification.BootRules -eq 2 -and
        $model.ControllerAction.Execute -ieq $shell -and -not $model.ControllerRunning -and -not $model.RollbackAnchored -and
        $model.Starts -eq ($starts+1) -and $model.OldReadinessChecks -eq $readinessChecks -and
        -not $model.Profile -and $model.Region -ceq $legacyZone -and (Get-FileHash -LiteralPath $relay).Hash -ceq $newRelayHash -and
        [IO.File]::ReadAllText($provisioned) -ceq $legacyBytes -and -not [IO.File]::Exists($health) -and
        -not [IO.File]::Exists($journalFile) -and [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1 -and
        [ClaudeGuard.Network.WindowsPolicySession]::Closed.ContainsKey([guid]$legacyRecord.Sublayer)) `
        'A different current Bettbox hash allows migration, and failed readiness restores node absence, time zone, files and exact old rules with the gate closed.'

    $model.FailRestore=$true
    [IO.File]::WriteAllText($health,'stale fixture health')
    $incompleteMigration=Invoke-SetupTestTransaction -NodeProfile $jpProfile -RequirePriorGeneration $legacyRecord.Generation
    Assert-Setup ($incompleteMigration.Phase -ceq 'RollbackIncomplete' -and -not $incompleteMigration.RestoredClosed -and
        -not $model.ControllerRunning -and (Read-GuardReleaseRecoveryJson $journalFile).PriorRouteUnavailable -eq $true) `
        'A restoration failure keeps the closed rollback journal for another process.'
    $model.FailRestore=$false
    $resumedMigration=Invoke-SetupTestTransaction -Recovery
    Assert-Setup ($resumedMigration.Restored -and $resumedMigration.RestoredClosed -and -not $model.ControllerRunning -and
        $model.Starts -eq ($starts+2) -and $model.OldReadinessChecks -eq $readinessChecks -and
        -not $model.Profile -and $model.Region -ceq $legacyZone -and [IO.File]::ReadAllText($provisioned) -ceq $legacyBytes -and
        -not [IO.File]::Exists($health) -and -not [IO.File]::Exists($journalFile)) `
        'Resuming a legacy rollback restores the original snapshot and keeps the old route closed.'

    $model.LegacyReadThrows=$true
    $model.FailReady=$false
    $migration=Invoke-SetupTestTransaction -NodeProfile $jpProfile -RequirePriorGeneration $legacyRecord.Generation
    $jpRecord=Read-GuardDailyRecord 'daily-provisioned.json'
    Assert-Setup ($migration.Installed -and $migration.FreshProofs -eq 6 -and -not $migration.RestoredClosed -and
        $model.ControllerRunning -and $model.ControllerAction.Execute -ieq $bootstrap -and $model.Region -ceq 'Fixture candidate zone' -and
        $jpRecord.ProxyMode -ceq 'Manual' -and $jpRecord.RouteHash -ceq $jpRoute.Hash -and
        (Read-GuardDailyRelayConfig $jpRecord.Port).Hash -ceq $jpRoute.Hash -and -not [IO.File]::Exists($journalFile) -and
        [ClaudeGuard.Network.WindowsPolicySession]::Closed.Count -eq 1 -and
        [ClaudeGuard.Network.WindowsPolicySession]::Closed.ContainsKey([guid]$jpRecord.Sublayer)) `
        'An unsupported current legacy selection can migrate to a verified WebSocket TLS node and commit its exact route and firewall policy.'
}finally{
    $folder=Get-Item -LiteralPath $fixtureRoot -Force
    if($folder.Parent.FullName.TrimEnd('\') -ine $base -or $folder.Name -cnotmatch '^guard-setup-tests-[a-f0-9]{32}$' -or
        ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected integration cleanup directory.'}
    [IO.Directory]::Delete($folder.FullName,$true)
}
