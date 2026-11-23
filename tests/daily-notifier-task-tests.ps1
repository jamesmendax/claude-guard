#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot/../package/guard-daily-notifier-task.ps1"
Import-Module Microsoft.PowerShell.Utility

function Assert-Equal($expected,$actual) {
    if($expected -cne $actual){throw "Expected [$expected], received [$actual]."}
}

function Assert-Rejected([scriptblock]$Action) {
    $rejected=$false
    try{& $Action}catch{$rejected=$true}
    Assert-Equal $true $rejected
}

$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard\daily'
$sid='S-1-5-21-1-2-3-4'
$script:f=@{Task=$null;Registrations=0;Removed=0;Started=0;Stopped=0;Migrations=0}

$PSModuleAutoLoadingPreference='None'
function New-ScheduledTaskPrincipal {
    param($UserId,$LogonType,$RunLevel)
    [pscustomobject]@{UserId=$UserId;GroupId=$null;LogonType=$LogonType;RunLevel=$RunLevel}
}
function New-ScheduledTaskTrigger {
    param([switch]$AtLogOn,$User)
    if(-not $AtLogOn){throw 'Expected a logon trigger'}
    [pscustomobject]@{CimClass=@{CimClassName='MSFT_TaskLogonTrigger'};UserId=$User;Enabled=$true}
}
function New-ScheduledTaskAction {
    param($Execute,$Argument,$WorkingDirectory)
    [pscustomobject]@{CimClass=@{CimClassName='MSFT_TaskExecAction'};Execute=$Execute
        Arguments=$Argument;WorkingDirectory=$WorkingDirectory}
}
function New-ScheduledTaskSettingsSet {
    param($MultipleInstances,$ExecutionTimeLimit,[switch]$Hidden,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries)
    [pscustomobject]@{MultipleInstances=$MultipleInstances;ExecutionTimeLimit=[System.Xml.XmlConvert]::ToString($ExecutionTimeLimit)
        Hidden=[bool]$Hidden;DisallowStartIfOnBatteries=(-not $AllowStartIfOnBatteries)
        StopIfGoingOnBatteries=(-not $DontStopIfGoingOnBatteries);RunOnlyIfIdle=$false;RunOnlyIfNetworkAvailable=$false
        Enabled=$true;AllowDemandStart=$true;AllowHardTerminate=$true}
}

function Assert-GuardDailyNotifierInstallRoot {param($InstallRoot) Assert-Equal $root $InstallRoot}
function Get-ScheduledTask {param($TaskPath,$ErrorAction) $script:f.Task}
function Export-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction) $script:f.Task | ConvertTo-Json -Depth 10 -Compress}
function Register-ScheduledTask {
    param($TaskName,$TaskPath,$Action,$Trigger,$Settings,$Principal,$ErrorAction,$Xml)
    $script:f.Registrations++
    if($Xml){
        $script:f.Task=$Xml | ConvertFrom-Json
        $script:f.Task.State='Ready'
        return
    }
    $script:f.Task=[pscustomobject]@{TaskName=$TaskName;TaskPath=$TaskPath;State='Ready'
        Actions=@($Action);Triggers=@($Trigger);Principal=$Principal;Settings=$Settings}
}
function Set-ScheduledTask {
    param($TaskName,$TaskPath,$Action,$ErrorAction)
    Assert-Equal 'Ready' $script:f.Task.State
    $script:f.Migrations++
    $script:f.Task.Actions=@($Action)
}
function Start-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction) $script:f.Started++;$script:f.Task.State='Running'}
function Stop-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction) $script:f.Stopped++;$script:f.Task.State='Ready'}
function Unregister-ScheduledTask {param($TaskName,$TaskPath,$Confirm,$ErrorAction) $script:f.Removed++;$script:f.Task=$null}
function Enable-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction) $script:f.Task.Settings.Enabled=$true}
function Disable-ScheduledTask {param($TaskName,$TaskPath,$ErrorAction) $script:f.Task.Settings.Enabled=$false}

Assert-Equal $null (Get-GuardDailyNotifierTaskSnapshot -LaunchUserSid $sid -InstallRoot $root)
$new=Install-GuardDailyNotifierTask -LaunchUserSid $sid -InstallRoot $root
Assert-Equal $true $new.Enabled
Assert-Equal $false $new.Running
Assert-Equal 'Limited' $script:f.Task.Principal.RunLevel
Assert-Equal 'Interactive' $script:f.Task.Principal.LogonType
Assert-Equal $sid $script:f.Task.Triggers[0].UserId
'PASS registered task uses the same limited interactive user and a single logon trigger'

$script:f.Task.State='Running'
$previous=Get-GuardDailyNotifierTaskSnapshot -LaunchUserSid $sid -InstallRoot $root
$null=Install-GuardDailyNotifierTask -LaunchUserSid $sid -InstallRoot $root
Assert-Equal 1 $script:f.Registrations
$script:f.Task.State='Ready'
$script:f.Task.Settings.Enabled=$false
Restore-GuardDailyNotifierTask -Snapshot $previous -LaunchUserSid $sid -InstallRoot $root
Assert-Equal 1 $script:f.Started
Assert-Equal 0 $script:f.Removed
Assert-Equal $true $script:f.Task.Settings.Enabled
'PASS existing matching task is reused and previous enabled and running state is recoverable'

$action=$script:f.Task.Actions[0]
$arguments=$action.Arguments
$action.Arguments='untrusted'
Assert-Rejected {Get-GuardDailyNotifierTaskSnapshot -LaunchUserSid $sid -InstallRoot $root}
Assert-Rejected {Restore-GuardDailyNotifierTask -Snapshot $null -LaunchUserSid $sid -InstallRoot $root}
Assert-Equal 0 $script:f.Removed
$action.Arguments=$arguments
$script:f.Task.Principal.RunLevel='Highest'
Assert-Rejected {Install-GuardDailyNotifierTask -LaunchUserSid $sid -InstallRoot $root}
$script:f.Task.Principal.RunLevel='Limited'
Assert-Rejected {Get-GuardDailyNotifierTaskSnapshot -LaunchUserSid 'S-1-5-21-1-2-3-5' -InstallRoot $root}
'PASS mismatched task command, elevation and user are refused without mutation'

Restore-GuardDailyNotifierTask -Snapshot $null -LaunchUserSid $sid -InstallRoot $root
Assert-Equal 1 $script:f.Stopped
Assert-Equal 1 $script:f.Removed
Assert-Equal $null $script:f.Task
'PASS rollback stops and removes only a newly created matching task'

$launcher=Join-Path (Split-Path -Parent $root) ('release-install-'+('a'*32)+'\ClaudeGuardSetup.exe')
function Get-GuardDailyReleaseImageHash {param($Path) Assert-Equal $launcher $Path; 'A'*64}
$legacy=Install-GuardDailyNotifierTask $sid $root
$script:f.Task.State='Running'
Assert-Rejected {Install-GuardDailyNotifierTask $sid $root $launcher}
Assert-Equal 0 $script:f.Migrations
$script:f.Task.State='Ready'
$migrated=Install-GuardDailyNotifierTask $sid $root $launcher
Assert-Equal '--background-notifier' $migrated.Arguments
Assert-Equal $launcher $migrated.Execute
Assert-Equal 1 $script:f.Migrations
Assert-Equal 'Limited' $script:f.Task.Principal.RunLevel
Assert-Equal $sid $script:f.Task.Triggers[0].UserId
$null=Install-GuardDailyNotifierTask $sid $root $launcher
Assert-Equal 1 $script:f.Migrations
Restore-GuardDailyNotifierTask $null $sid $root
Restore-GuardDailyNotifierTask $legacy $sid $root
Assert-Equal $legacy.Arguments $script:f.Task.Actions[0].Arguments
Assert-Equal $legacy.Execute $script:f.Task.Actions[0].Execute
'PASS the existing limited task moves once to the protected GUI launcher and restores its exact legacy action'
