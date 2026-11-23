$script:GuardDailyNotifierTaskName='ClaudeVPNGuard Daily Notifications'

function Get-GuardDailyNotifierTaskSpec([string]$LaunchUserSid,[string]$InstallRoot,[string]$BootstrapPath) {
    $execute=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $arguments='-NoProfile -NonInteractive -WindowStyle Hidden -STA -ExecutionPolicy Bypass -File "'+
        (Join-Path $InstallRoot 'guard-daily-notifier.ps1')+'"'
    if($BootstrapPath){
        $null=Get-GuardDailyReleaseImageHash $BootstrapPath
        $execute=$BootstrapPath
        $arguments='--background-notifier'
    }
    [pscustomobject]@{
        User=([Security.Principal.SecurityIdentifier]::new($LaunchUserSid)).Value
        Execute=$execute
        Arguments=$arguments
        Directory=$InstallRoot
    }
}

function ConvertTo-GuardNotifierSid([string]$Account) {
    if($Account -match '^S-1-'){return ([Security.Principal.SecurityIdentifier]::new($Account)).Value}
    ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-GuardDailyNotifierTaskDefinition($Task,$Spec) {
    $actions=@($Task.Actions)
    $triggers=@($Task.Triggers)
    $settings=$Task.Settings
    if($Task.TaskName -cne $script:GuardDailyNotifierTaskName -or $Task.TaskPath -cne '\' -or
        $actions.Count -ne 1 -or $actions[0].CimClass.CimClassName -cne 'MSFT_TaskExecAction' -or
        $actions[0].Execute -ine $Spec.Execute -or $actions[0].Arguments -cne $Spec.Arguments -or
        $actions[0].WorkingDirectory -ine $Spec.Directory -or $triggers.Count -ne 1 -or
        $triggers[0].CimClass.CimClassName -cne 'MSFT_TaskLogonTrigger' -or
        $triggers[0].Enabled -ne $true -or (ConvertTo-GuardNotifierSid $triggers[0].UserId) -cne $Spec.User -or
        $triggers[0].StartBoundary -or $triggers[0].EndBoundary -or $triggers[0].Delay -or
        $triggers[0].Repetition.Interval -or $triggers[0].Repetition.Duration -or
        (ConvertTo-GuardNotifierSid $Task.Principal.UserId) -cne $Spec.User -or $Task.Principal.GroupId -or
        $Task.Principal.RunLevel -ne 'Limited' -or $Task.Principal.LogonType -ne 'Interactive' -or
        $settings.MultipleInstances -ne 'IgnoreNew' -or $settings.ExecutionTimeLimit -ne 'PT0S' -or
        $settings.Hidden -ne $true -or $settings.DisallowStartIfOnBatteries -ne $false -or
        $settings.StopIfGoingOnBatteries -ne $false -or $settings.RunOnlyIfIdle -ne $false -or
        $settings.RunOnlyIfNetworkAvailable -ne $false -or $settings.AllowDemandStart -ne $true -or
        $settings.AllowHardTerminate -ne $true){
        throw 'The existing notification task does not match the protected interactive task.'
    }
}

function Assert-GuardDailyNotifierInstallRoot([string]$InstallRoot) {
    $expected=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard\daily'
    if([IO.Path]::GetFullPath($InstallRoot) -ine $expected){throw 'The notification task requires the protected daily installation.'}
    $trusted=@('S-1-5-18','S-1-5-32-544')
    $change=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach($path in @((Split-Path -Parent $expected),$expected,(Join-Path $expected 'guard-daily-notifier.ps1'))){
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){
            throw 'The notification task has an untrusted runtime path.'
        }
        foreach($entry in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            if($entry.AccessControlType -eq 'Allow' -and ($entry.FileSystemRights -band $change) -and
                $entry.IdentityReference.Value -notin $trusted){throw 'The notification runtime is writable outside its administrator.'}
        }
    }
}

function Get-GuardDailyNotifierTaskSnapshot([string]$LaunchUserSid,[string]$InstallRoot) {
    $task=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object TaskName -IEQ $script:GuardDailyNotifierTaskName)
    if(-not $task.Count){return}
    if($task.Count -ne 1){throw 'The notification task identity is ambiguous.'}
    $action=@($task[0].Actions)[0]
    $bootstrap=if($action.Arguments -ceq '--background-notifier'){$action.Execute}
    $spec=Get-GuardDailyNotifierTaskSpec $LaunchUserSid $InstallRoot $bootstrap
    Assert-GuardDailyNotifierTaskDefinition $task[0] $spec
    [pscustomobject]@{
        Xml=(Export-ScheduledTask -TaskName $script:GuardDailyNotifierTaskName -TaskPath '\' -ErrorAction Stop)
        Enabled=$task[0].Settings.Enabled -eq $true
        Running=$task[0].State -eq 'Running'
        Execute=$spec.Execute
        Arguments=$spec.Arguments
    }
}

function Install-GuardDailyNotifierTask([string]$LaunchUserSid,[string]$InstallRoot,[string]$BootstrapPath) {
    Assert-GuardDailyNotifierInstallRoot $InstallRoot
    $previous=Get-GuardDailyNotifierTaskSnapshot $LaunchUserSid $InstallRoot
    if($previous -and -not $BootstrapPath){return $previous}
    $spec=Get-GuardDailyNotifierTaskSpec $LaunchUserSid $InstallRoot $BootstrapPath
    if($previous -and $previous.Execute -ieq $spec.Execute -and $previous.Arguments -ceq $spec.Arguments){return $previous}
    $action=New-ScheduledTaskAction -Execute $spec.Execute -Argument $spec.Arguments -WorkingDirectory $spec.Directory
    if($previous){
        if($previous.Running){throw 'Stop the notification task before migrating its launcher.'}
        Set-ScheduledTask -TaskName $script:GuardDailyNotifierTaskName -TaskPath '\' -Action $action -ErrorAction Stop | Out-Null
        $snapshot=Get-GuardDailyNotifierTaskSnapshot $LaunchUserSid $InstallRoot
        if(-not $snapshot -or $snapshot.Execute -ine $spec.Execute -or $snapshot.Arguments -cne $spec.Arguments -or
            $snapshot.Enabled -ne $previous.Enabled){
            throw 'The notification task migration could not be verified.'
        }
        return $snapshot
    }
    $principal=New-ScheduledTaskPrincipal -UserId $spec.User -LogonType Interactive -RunLevel Limited
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $spec.User
    $options=@{MultipleInstances='IgnoreNew';ExecutionTimeLimit=[timespan]::Zero;Hidden=$true
        AllowStartIfOnBatteries=$true;DontStopIfGoingOnBatteries=$true}
    $settings=New-ScheduledTaskSettingsSet @options
    $registered=$false
    try{
        $definition=@{TaskName=$script:GuardDailyNotifierTaskName;TaskPath='\';Action=$action
            Trigger=$trigger;Settings=$settings;Principal=$principal}
        Register-ScheduledTask @definition -ErrorAction Stop | Out-Null
        $registered=$true
        $snapshot=Get-GuardDailyNotifierTaskSnapshot $LaunchUserSid $InstallRoot
        if(-not $snapshot -or -not $snapshot.Enabled){throw 'The notification task registration could not be verified.'}
        $snapshot
    }catch{
        if($registered){
            Unregister-ScheduledTask -TaskName $script:GuardDailyNotifierTaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
        }
        throw
    }
}

function Wait-GuardDailyNotifierTaskStopped {
    for($attempt=0;$attempt -lt 20;$attempt++){
        $task=Get-ScheduledTask -TaskName $script:GuardDailyNotifierTaskName -TaskPath '\' -ErrorAction Stop
        if($task.State -ne 'Running'){return}
        Start-Sleep -Milliseconds 250
    }
    throw 'The installed notification task did not stop.'
}

function Restore-GuardDailyNotifierTask($Snapshot,[string]$LaunchUserSid,[string]$InstallRoot) {
    $name=$script:GuardDailyNotifierTaskName
    $current=Get-GuardDailyNotifierTaskSnapshot $LaunchUserSid $InstallRoot
    if(-not $Snapshot){
        if($current){
            if($current.Running){
                Stop-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
                Wait-GuardDailyNotifierTaskStopped
            }
            Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false -ErrorAction Stop
            if(Get-GuardDailyNotifierTaskSnapshot $LaunchUserSid $InstallRoot){throw 'The notification task remains registered.'}
        }
        return
    }
    if(-not $current){
        Assert-GuardDailyNotifierInstallRoot $InstallRoot
        Register-ScheduledTask -TaskName $name -TaskPath '\' -Xml $Snapshot.Xml -ErrorAction Stop | Out-Null
        $current=Get-GuardDailyNotifierTaskSnapshot $LaunchUserSid $InstallRoot
        if(-not $current){throw 'The previous notification task could not be restored.'}
    }
    if($current.Running -and -not $Snapshot.Running){Stop-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop}
    if($current.Enabled -and -not $Snapshot.Enabled){Disable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null}
    if(-not $current.Enabled -and $Snapshot.Enabled){Enable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null}
    if(-not $current.Running -and $Snapshot.Running){Start-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop}
    for($attempt=0;$attempt -lt 6;$attempt++){
        $restored=Get-GuardDailyNotifierTaskSnapshot $LaunchUserSid $InstallRoot
        if($restored -and $restored.Enabled -eq $Snapshot.Enabled -and $restored.Running -eq $Snapshot.Running){return}
        Start-Sleep -Milliseconds 200
    }
    throw 'The previous notification task state could not be restored.'
}
