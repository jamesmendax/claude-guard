[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Read', 'Apply', 'Restore')]
    [string]$Mode,
    [string]$Address,
    [ValidateSet('strict', 'fallback')]
    [string]$Fallback = 'strict'
)

$ErrorActionPreference = 'Stop'
$backupPath = 'SOFTWARE\ClaudeGuardNative\EncryptedDns'
$backupName = 'ResolverBackupV1'

function Get-ResolverBackup {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backupPath)
    if ($null -eq $key) { return }
    try {
        $json = $key.GetValue($backupName)
        if ($null -eq $json) { return }
        $backup = $json | ConvertFrom-Json
        $ip = $null
        $template = $null
        if (-not [Net.IPAddress]::TryParse([string]$backup.Address, [ref]$ip) -or
            $ip.ToString() -cne $backup.Address -or
            -not [Uri]::TryCreate([string]$backup.Template, [UriKind]::Absolute, [ref]$template) -or
            $template.Scheme -ne 'https' -or
            $backup.AutoUpgrade -isnot [bool] -or $backup.AllowFallback -isnot [bool] -or
            $backup.NewFallback -isnot [bool]) {
            throw 'The stored DNS backup is invalid.'
        }
        $backup
    } finally {
        $key.Dispose()
    }
}

function Save-ResolverBackup($Backup) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($backupPath)
    try {
        $key.SetValue($backupName, ($Backup | ConvertTo-Json -Compress), [Microsoft.Win32.RegistryValueKind]::String)
        $key.Flush()
    } finally {
        $key.Dispose()
    }
}

function Clear-ResolverBackup {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backupPath, $true)
    try {
        $key.DeleteValue($backupName)
        $key.Flush()
    } finally {
        $key.Dispose()
    }
}

function Get-Resolver([string]$Ip) {
    $rows = @(Get-DnsClientDohServerAddress | Where-Object ServerAddress -eq $Ip)
    if ($rows.Count -ne 1) {
        throw "Windows no longer has one known HTTPS template for $Ip."
    }
    $rows[0]
}

function Test-Resolver($Resolver, [string]$Template, [bool]$AutoUpgrade, [bool]$AllowFallback) {
    $Resolver.DohTemplate -ceq $Template -and
        $Resolver.AutoUpgrade -eq $AutoUpgrade -and
        $Resolver.AllowFallbackToUdp -eq $AllowFallback
}

$commands = 'Get-DnsClientServerAddress', 'Get-DnsClientDohServerAddress', 'Set-DnsClientDohServerAddress'
foreach ($command in $commands) {
    if (-not (Get-Command -Name $command -Module DnsClient -ErrorAction SilentlyContinue)) {
        throw 'This Windows installation does not provide the DNS-over-HTTPS commands.'
    }
}

$backup = Get-ResolverBackup
if ($Mode -eq 'Read') {
    $assignments = @(Get-DnsClientServerAddress)
    [pscustomobject]@{ Kind = 'Backup'; Address = [string]$backup.Address }
    foreach ($entry in Get-DnsClientDohServerAddress) {
        $template = $null
        if (-not [Uri]::TryCreate($entry.DohTemplate, [UriKind]::Absolute, [ref]$template) -or
            $template.Scheme -ne 'https') { continue }
        $aliases = @($assignments | Where-Object { $_.ServerAddresses -contains $entry.ServerAddress } |
            Select-Object -ExpandProperty InterfaceAlias -Unique)
        if ($aliases.Count -eq 0) { continue }
        [pscustomobject]@{
            Kind = 'Resolver'
            Address = $entry.ServerAddress
            Interfaces = $aliases -join ', '
            Template = $entry.DohTemplate
            AutoUpgrade = $entry.AutoUpgrade
            AllowFallback = $entry.AllowFallbackToUdp
        }
    }
    return
}

if ($Mode -eq 'Apply') {
    if ($null -ne $backup) { throw 'Restore the previous DNS change before applying another one.' }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or $ip.ToString() -cne $Address -or
        $Address.Contains('%')) { throw 'The resolver address is invalid.' }
    $configured = Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses -contains $Address }
    if (-not $configured) { throw 'This resolver is no longer configured on a Windows network adapter.' }
    $entry = Get-Resolver $Address
    $template = $null
    if (-not [Uri]::TryCreate($entry.DohTemplate, [UriKind]::Absolute, [ref]$template) -or
        $template.Scheme -ne 'https') { throw 'The resolver lacks an HTTPS template.' }
    $allowFallback = $Fallback -eq 'fallback'
    if (Test-Resolver $entry $entry.DohTemplate $true $allowFallback) {
        'Windows already has these encryption settings for the selected resolver.'
        return
    }
    $backup = [pscustomobject]@{
        Address = $Address
        Template = $entry.DohTemplate
        AutoUpgrade = [bool]$entry.AutoUpgrade
        AllowFallback = [bool]$entry.AllowFallbackToUdp
        NewFallback = $allowFallback
    }
    Save-ResolverBackup $backup
    try {
        $latest = Get-Resolver $Address
        if (-not (Test-Resolver $latest $backup.Template $backup.AutoUpgrade $backup.AllowFallback)) {
            throw 'Windows DNS settings changed during setup. Refresh and check the new settings.'
        }
    } catch {
        Clear-ResolverBackup
        throw
    }
    try {
        Set-DnsClientDohServerAddress -ServerAddress $Address -AutoUpgrade $true -AllowFallbackToUdp $allowFallback
        if (-not (Test-Resolver (Get-Resolver $Address) $backup.Template $true $allowFallback)) {
            throw 'The Windows readback differs from the requested settings.'
        }
    } catch {
        throw "The DNS change could not be verified. The original settings are saved for Restore. $($_.Exception.Message)"
    }
    "Windows confirmed the DNS-over-HTTPS settings for $Address."
    return
}

if ($null -eq $backup) { throw 'There is no saved DNS change to restore.' }
$entry = Get-Resolver $backup.Address
if (-not (Test-Resolver $entry $backup.Template $backup.AutoUpgrade $backup.AllowFallback)) {
    if (-not (Test-Resolver $entry $backup.Template $true $backup.NewFallback)) {
        throw "The Windows settings for $($backup.Address) changed after the backup. Restore stopped to preserve the current settings."
    }
    Set-DnsClientDohServerAddress -ServerAddress $backup.Address -AutoUpgrade $backup.AutoUpgrade -AllowFallbackToUdp $backup.AllowFallback
    if (-not (Test-Resolver (Get-Resolver $backup.Address) $backup.Template $backup.AutoUpgrade $backup.AllowFallback)) {
        throw 'Windows could not verify the restored settings. The backup is still available.'
    }
}
Clear-ResolverBackup
"Windows confirmed the original DNS settings for $($backup.Address)."
