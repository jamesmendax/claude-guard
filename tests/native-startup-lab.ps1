#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$AfterBoot)

$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$guardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
$stageName=Split-Path -Leaf $root
if((Split-Path -Parent $root) -ine $guardRoot -or $stageName -cnotmatch '^native-acceptance-(?<id>[a-f0-9]{32})$'){
    throw 'A protected native acceptance stage is required.'
}
$deployment=[guid]::ParseExact($Matches.id,'N')
$taskName='ClaudeVPNGuard Startup Fixture '+$deployment.ToString('N')
$fixture=Join-Path $root 'startup-fixture'
$receipt=Join-Path $root 'startup-fixture.json'
$image=Join-Path $fixture 'guard-boot-client.exe'
$control=Join-Path $fixture 'guard-boot-control.exe'
$powerShell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$arguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -AfterBoot'
$trusted=@('S-1-5-18','S-1-5-32-544')
$write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'

function Assert-StartupPath([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    $acl=Get-Acl -LiteralPath $Path
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
        @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $write) -and $_.IdentityReference.Value -notin $trusted
        }).Count){throw 'An untrusted path was found in the startup fixture.'}
}

function Read-StartupBootTime {
    for($attempt=0;$attempt -lt 4;$attempt++){
        try {
            $started=(Get-CimInstance Win32_OperatingSystem -Property LastBootUpTime -OperationTimeoutSec 6).LastBootUpTime
            if(-not $started){throw 'The Windows startup time is unavailable.'}
            return $started.ToUniversalTime()
        }catch{
            if($attempt -eq 3){throw}
            Start-Sleep -Seconds 1
        }
    }
}

foreach($path in $guardRoot,$root){Assert-StartupPath $path}
try{
    $package=Join-Path $root 'package'
    foreach($path in $PSScriptRoot,$package,$PSCommandPath){Assert-StartupPath $path}
    . (Join-Path $package 'guard-common.ps1')
    Add-Type -Path (Join-Path $package 'guard-wfp.cs'),(Join-Path $PSScriptRoot 'loopback-lab.cs')
    $plan=[GuardLoopbackLab]::CreateStartupPlan($image,$deployment)
    $boot=Read-StartupBootTime
    if($AfterBoot){
        Assert-StartupPath $receipt
        $record=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        if($record.Version -ne 1 -or [guid]$record.Deployment -ne $deployment -or [guid]$record.Sublayer -ne $plan.PersistentSublayer){
            throw 'The saved startup fixture does not match this protected stage.'
        }
        $before=[datetime]::ParseExact($record.BootBeforeUtc,'o',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    }
}catch{
    if($AfterBoot){$_ | Out-String | Set-Content -LiteralPath (Join-Path $root 'startup-observer-error.txt') -Encoding UTF8}
    throw
}

function Read-StartupTask {
    try{Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop}
    catch{if($_.FullyQualifiedErrorId -cne 'CmdletizationQuery_NotFound,Get-ScheduledTask'){throw}}
}
function Assert-StartupTask($Task) {
    if(-not $Task -or @($Task.Actions).Count -ne 1 -or $Task.Actions[0].Execute -ine $powerShell -or
        $Task.Actions[0].Arguments -cne $arguments -or $Task.Actions[0].WorkingDirectory -ine $root -or
        $Task.Principal.UserId -notin 'SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18' -or
        @($Task.Triggers).Count -ne 1 -or $Task.Triggers[0].CimClass.CimClassName -ne 'MSFT_TaskBootTrigger' -or
        -not $Task.Triggers[0].Enabled -or $Task.State -eq 'Disabled'){
        throw 'The one-time startup task did not match the approved action.'
    }
}
function Save-StartupReceipt {Save-GuardAdministratorJson $receipt $record}
function Test-StartupWitness([string]$Source,[bool]$Expected) {
    $received4=[GuardLoopbackLab]::StartupDatagramReceived($Source,'4')
    $received6=[GuardLoopbackLab]::StartupDatagramReceived($Source,'6')
    if($received4 -ne $Expected -or $received6 -ne $Expected){
        throw "Startup witness expected receipt=$Expected, IPv4=$received4, IPv6=$received6."
    }
}
function Remove-StartupFixture {
    if($null -ne $record.AssignedWeight){
        [ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($plan,[uint16]$record.AssignedWeight)
    }
    $record.RulesRemoved=$true
    $task=Read-StartupTask
    if($task){
        Assert-StartupTask $task
        Unregister-ScheduledTask -InputObject $task -Confirm:$false
        if(Read-StartupTask){throw 'The startup fixture task remains registered.'}
    }
    $record.TaskRemoved=$true
}

if($AfterBoot){
    if($boot -le $before){return}
    $record.BootAfterUtc=$boot.ToString('o')
    $record.StartupTaskUtc=[datetime]::UtcNow.ToString('o')
    try{
        if($record.Status -ceq 'Armed'){
            foreach($path in $fixture,$image,$control){Assert-StartupPath $path}
            if((Get-FileHash -LiteralPath $image).Hash -cne $record.ImageSha256 -or
                (Get-FileHash -LiteralPath $control).Hash -cne $record.ImageSha256){throw 'A startup fixture executable changed.'}
            (Get-Service BFE).WaitForStatus('Running',[timespan]::FromSeconds(25))
            $record.BootRulesAfter=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($plan,[uint16]$record.AssignedWeight)
            $record.Status='WitnessRunning'
            Save-StartupReceipt
            Test-StartupWitness $control $true
            Test-StartupWitness $image $false
            $record.FirstFixtureDatagramsBlocked=$true
            $record.Status='PostBootWitnessPassed'
        }elseif($record.Status -cin 'Preparing','WitnessRunning'){
            $record.Status='PreparationInterrupted'
        }
    }catch{
        $record.Status='PostBootWitnessFailed'
        $record.Error=$_.Exception.Message
    }finally{
        try{Remove-StartupFixture}catch{
            $record.CleanupError=$_.Exception.Message
        }
        Save-StartupReceipt
    }
    if($record.Status -cne 'PostBootWitnessPassed' -or -not $record.RulesRemoved -or -not $record.TaskRemoved){exit 1}
    return
}

if((Test-Path -LiteralPath $receipt) -or (Test-Path -LiteralPath $fixture) -or (Read-StartupTask)){
    throw 'This startup fixture stage has already been used.'
}
if((Get-Service Schedule).Status -ne 'Running'){throw 'Windows Task Scheduler is unavailable.'}
Initialize-GuardAdministratorDirectory $fixture
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /warnaserror+ /platform:x64 "/out:$image" (Join-Path $PSScriptRoot 'loopback-probe.cs')
if($LASTEXITCODE -ne 0){throw 'The startup fixture failed to compile.'}
[IO.File]::Copy($image,$control)
Test-StartupWitness $image $true
Test-StartupWitness $control $true
$record=[ordered]@{
    Version=1;Deployment=$deployment;Sublayer=$plan.PersistentSublayer;TaskName=$taskName
    Status='Preparing';BootBeforeUtc=$boot.ToString('o');BootAfterUtc=$null;StartupTaskUtc=$null
    AssignedWeight=$null;ImageSha256=(Get-FileHash -LiteralPath $image).Hash
    BootKeys=@($plan.GetBootKeys());PersistentKeys=@($plan.GetBaselineKeys());BootRulesInstalled=$null;BootRulesAfter=$null
    BlockedBeforeReboot=$false;FirstFixtureDatagramsBlocked=$false;MeasuredBeforeBfe=$false
    RulesRemoved=$false;TaskRemoved=$false;Error=$null;CleanupError=$null
}
Save-StartupReceipt
try{
    $action=New-ScheduledTaskAction -Execute $powerShell -Argument $arguments -WorkingDirectory $root
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 3) `
        -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 1)
    $null=Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description 'One-time synthetic loopback verification and cleanup after the next Windows boot.'
    Assert-StartupTask (Read-StartupTask)
    $recordWeight=[Action[uint16]]{
        param($weight)
        $record.AssignedWeight=$weight
        Save-StartupReceipt
    }
    $assigned=[ClaudeGuard.Network.WindowsPolicySession]::InstallPersistent($plan,$recordWeight)
    $record.BootRulesInstalled=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($plan,$assigned)
    Test-StartupWitness $control $true
    Test-StartupWitness $image $false
    $record.BlockedBeforeReboot=$true
    $record.Status='Armed'
    Save-StartupReceipt
}catch{
    $record.Status='InstallFailed'
    $record.Error=$_.Exception.Message
    try{Remove-StartupFixture}catch{$record.CleanupError=$_.Exception.Message}
    Save-StartupReceipt
    throw
}
Write-Output "RESULT StartupFixture=Armed RuntimeRules=$($plan.BaseCount) BootRules=$($record.BootRulesInstalled) NextBootOnly=True"
