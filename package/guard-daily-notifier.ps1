#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\guard-runtime.ps1"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$instance=[Threading.Mutex]::new($false,'Local\ClaudeVPNGuardDailyNotifier')
$ownsInstance=$false
try{
    try{$ownsInstance=$instance.WaitOne(0)}catch [Threading.AbandonedMutexException]{$ownsInstance=$true}
    if(-not $ownsInstance){return}

    $cache=Join-Path $env:LOCALAPPDATA 'ClaudeVPNGuard\DailyNoticeSeen.json'
    $script:guardSeen=@()
    try{
        if((Get-Item -LiteralPath $cache).Length -le 4096){
            $script:guardSeen=@(Get-Content -LiteralPath $cache -Raw | ConvertFrom-Json | Where-Object {
                $_ -is [string] -and $_ -cmatch '^[a-f0-9]{32}:(pause|fault|recovery|exit)$'
            } | Select-Object -Last 24)
        }
    }catch{}

    $icon=[Windows.Forms.NotifyIcon]::new()
    $menu=[Windows.Forms.ContextMenuStrip]::new()
    $timer=[Windows.Forms.Timer]::new()
    try{
        $icon.Icon=[Drawing.SystemIcons]::Shield
        $icon.Text='Claude 防护'
        $icon.ContextMenuStrip=$menu
        $history=$menu.Items.Add('查看上次会话结束原因')
        $history.Add_Click({
            [void][Windows.Forms.MessageBox]::Show((Get-GuardDailyLastStopText),'Claude 防护')
        })
        $backup=$menu.Items.Add('备用出口核对')
        $refreshBackup={
            $view=Get-GuardDailyBackupLookupView
            $backup.Text=$view.Text
            $backup.ToolTipText=$view.Details
            $backup.Checked=$view.Checked
            $backup.Enabled=$view.CanChange
        }
        & $refreshBackup
        $backup.Add_Click({
            try{
                $view=Get-GuardDailyBackupLookupView
                if($view.CanChange){
                    Set-GuardDailyBackupLookupPreference -Enabled ($view.Available -and -not $view.Preferred)
                }
                & $refreshBackup
            }catch{
                [void][Windows.Forms.MessageBox]::Show('无法保存备用出口核对设置。','Claude 防护')
            }
        })
        $menu.Add_Opening({
            try{& $refreshBackup}catch{}
        })
        $icon.Visible=$true
        $timer.Interval=1000
        $timer.Add_Tick({
            try{
                $notice=Read-GuardDailyNotice
                $message=Get-GuardDailyPresentation $notice -Seen $script:guardSeen -ReadStatus {Get-GuardDailyStatus}
                if(-not $message){$message=Get-GuardDailyObservedExitPresentation -Seen $script:guardSeen}
                if(-not $message){return}
                $script:guardSeen=@($script:guardSeen + $message.Key | Select-Object -Last 24)
                $icon.ShowBalloonTip(5000,'Claude 防护',$message.Text,[Windows.Forms.ToolTipIcon]::Info)
                try{
                    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $cache))
                    ConvertTo-Json -InputObject @($script:guardSeen) -Compress |
                        Set-Content -LiteralPath $cache -Encoding UTF8
                }catch{}
            }catch{}
        })
        $timer.Start()
        [Windows.Forms.Application]::Run()
    }finally{
        $timer.Dispose()
        $icon.Visible=$false
        $icon.Dispose()
        $menu.Dispose()
    }
}finally{
    if($ownsInstance){$instance.ReleaseMutex()}
    $instance.Dispose()
}
