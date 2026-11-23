# The user preference can opt out of a second IP lookup. Only the protected
# deployment record can enable it. Neither setting contains a route or address.
function Get-GuardDailyBackupLookupPreference {
    $key=$null
    try {
        $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\ClaudeVPNGuard')
        if(-not $key -or 'DisableBackupExitLookup' -notin $key.GetValueNames()){return $true}
        if($key.GetValueKind('DisableBackupExitLookup') -ne [Microsoft.Win32.RegistryValueKind]::DWord){return $false}
        return $key.GetValue('DisableBackupExitLookup') -eq 0
    }catch{return $false}finally{if($key){$key.Dispose()}}
}

function Set-GuardDailyBackupLookupPreference([Parameter(Mandatory)][bool]$Enabled) {
    $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\ClaudeVPNGuard')
    try{$key.SetValue('DisableBackupExitLookup',[int](-not $Enabled),[Microsoft.Win32.RegistryValueKind]::DWord)}
    finally{$key.Dispose()}
}

function Test-GuardDailyBackupLookupEnabled($Record) {
    $Record.BackupExitLookup -is [bool] -and $Record.BackupExitLookup -eq $true -and
        (Get-GuardDailyBackupLookupPreference)
}
