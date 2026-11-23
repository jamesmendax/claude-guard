#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Open')]
param(
    [Parameter(ParameterSetName='Status')][switch]$Status,
    [Parameter(ParameterSetName='LastStop')][switch]$LastStop,
    [Parameter(ParameterSetName='BackupLookup')][ValidateSet('On','Off')][string]$BackupLookup
)

$ErrorActionPreference='Stop'
. "$PSScriptRoot\guard-runtime.ps1"
if($Status){
    $state=Get-GuardDailyStatus
    $state | Select-Object Readiness,CanLaunch,Reason,Policy | ConvertTo-Json -Compress
    return
}
if($LastStop){
    Get-GuardDailyLastStopText
    return
}
if($BackupLookup){
    $enabled=$BackupLookup -eq 'On'
    Set-GuardDailyBackupLookupPreference -Enabled $enabled | Out-Null
    if(-not $enabled){'已关闭备用出口核对。';return}
    $view=Get-GuardDailyBackupLookupView
    if(-not $view.Preferred){'暂时无法确认备用核对偏好。'}
    elseif($view.Checked){"已启用备用出口核对。$($view.Details)"}
    else{'已保存允许使用的偏好。当前部署未开放备用出口核对。'}
    return
}

$state=try{Get-GuardDailyStatus}catch{$null}
if(-not $state.CanLaunch){
    $message=Get-GuardDailyUnavailableText $state
    try{
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show($message,'Claude 防护')
    }catch{Write-Warning $message}
    exit 1
}
Invoke-GuardDailyDesktop $false
