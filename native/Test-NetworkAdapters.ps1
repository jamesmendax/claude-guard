#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'NetworkAdapters.ps1')

$script:Checks = 0
function Assert-NetworkCase([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw $Description }
    $script:Checks++
}

function Assert-NetworkFailure([scriptblock]$Action, [string]$Expected) {
    $actual = ''
    try { $null = & $Action } catch { $actual = $_.Exception.Message }
    if ($actual -notlike "*$Expected*") { throw "Expected '$Expected', received '$actual'." }
    $script:Checks++
}

function New-Route([string]$Prefix, [int]$Index, [int]$Metric = 0, [string]$State = 'Alive') {
    [pscustomobject]@{ DestinationPrefix = $Prefix; InterfaceIndex = $Index; RouteMetric = $Metric; State = $State }
}

function Get-GuardNetworkSnapshot { $script:Snapshot }
function Get-NetRoute {
    [CmdletBinding()]
    param([string]$AddressFamily, [string]$PolicyStore)
    $script:Routes
}

$vpn = [pscustomobject]@{
    Name = 'Fixture VPN'
    ifIndex = 9
    InterfaceGuid = '5f8dbfac-d66c-4ad5-bfc0-45df4d5ae045'
    Status = 'Up'
    HardwareInterface = $false
    IpBound = $true
    Ipv4Present = $true
    InterfaceDescription = 'Custom tunnel description'
    DriverDescription = 'Wintun Userspace Tunnel'
    DriverProvider = 'WireGuard LLC'
}
$wired = [pscustomobject]@{
    Name = 'Fixture Ethernet'
    ifIndex = 11
    InterfaceGuid = '99c64f62-a043-4e7b-8aab-8dfb6560b4a7'
    Status = 'Up'
    HardwareInterface = $true
    IpBound = $true
    Ipv4Present = $true
}
$ipv6Only = [pscustomobject]@{
    Name = 'Fixture IPv6'
    ifIndex = 14
    InterfaceGuid = '5d04644c-9c7c-49fa-be3d-0361dcb935a5'
    Status = 'Disconnected'
    HardwareInterface = $false
    IpBound = $true
    Ipv4Present = $false
}
$ipv4Interfaces = @{
    9 = [pscustomobject]@{ InterfaceMetric = 5; ConnectionState = 'Connected' }
    11 = [pscustomobject]@{ InterfaceMetric = 25; ConnectionState = 'Connected' }
}
$script:Snapshot = [pscustomobject]@{ Adapters = @($vpn, $wired, $ipv6Only); Ipv4Interfaces = $ipv4Interfaces }
$default = New-Route '0.0.0.0/0' 11
$split = @((New-Route '0.0.0.0/1' 9), (New-Route '128.0.0.0/1' 9), $default)
$script:Routes = $split

Assert-NetworkCase ((Get-GuardVpnAdapter $vpn.InterfaceGuid).ifIndex -eq $vpn.ifIndex) 'A complete split default via the pinned Wintun adapter is accepted.'
Assert-NetworkFailure { Get-GuardVpnAdapter $wired.InterfaceGuid } 'no longer uses the saved VPN'
$script:Routes = @($split[0], $default)
Assert-NetworkFailure { Get-GuardVpnAdapter } 'Internet routes use different interfaces'

$script:Routes = $split + @(New-Route '192.168.1.0/24' 11)
Assert-NetworkCase ((Get-GuardVpnAdapter).ifIndex -eq $vpn.ifIndex) 'A private LAN route can bypass the tunnel.'
$script:Routes = $split + @(New-Route '192.0.2.65/32' 11)
Assert-NetworkFailure { Get-GuardVpnAdapter } 'Internet routes use different interfaces'
$ipv4Interfaces[11].ConnectionState = 'Disconnected'
Assert-NetworkCase ((Get-GuardVpnAdapter).ifIndex -eq $vpn.ifIndex) 'A disconnected non-VPN interface does not win an Internet route.'
$blocked = @(Get-GuardBlockedAdapters (Get-GuardVpnAdapter))
Assert-NetworkCase ($blocked.Count -eq 2 -and $blocked.Name -contains $wired.Name -and
    $blocked.Name -contains $ipv6Only.Name -and @($blocked | Where-Object Ipv4Present).Count -eq 1) 'Disconnected IPv4 and IPv6 adapters retain their scope.'
$ipv4Interfaces[11].ConnectionState = 'Connected'

$script:Routes = $split + @(New-Route '128.0.0.0/1' 11)
Assert-NetworkCase ((Get-GuardVpnAdapter).ifIndex -eq $vpn.ifIndex) 'The lower combined interface and route metric wins equal prefixes.'
$ipv4Interfaces[11].InterfaceMetric = 5
Assert-NetworkFailure { Get-GuardVpnAdapter } 'ambiguous across network interfaces'
$ipv4Interfaces[9].InterfaceMetric = $null
Assert-NetworkFailure { Get-GuardVpnAdapter } 'ambiguous across network interfaces'
$script:Routes = $split
Assert-NetworkCase ((Get-GuardVpnAdapter).ifIndex -eq $vpn.ifIndex) 'An unset metric does not prevent selection with unambiguous route prefixes.'
$ipv4Interfaces[9].InterfaceMetric = 5
$ipv4Interfaces[11].InterfaceMetric = 25

$script:Routes = @($default)
$vpn.Status = 'Disconnected'
$ipv4Interfaces[9].ConnectionState = 'Disconnected'
Assert-NetworkFailure { Get-GuardVpnAdapter } 'No active VPN tunnel'
$pinWhenDown = Get-GuardPinnedVpnAdapter $vpn.InterfaceGuid
Assert-NetworkFailure { Get-GuardBlockedAdapters $pinWhenDown } 'selected VPN adapter is disconnected'
Assert-NetworkCase (@(Get-GuardBlockedAdapters $pinWhenDown -AllowVpnDown).Count -eq 2) 'Refresh can preserve the saved scope while its VPN is disconnected.'
$vpn.Status = 'Up'
$ipv4Interfaces[9].ConnectionState = 'Connected'

$script:Routes = $split
$vpn.DriverProvider = 'Unknown provider'
Assert-NetworkFailure { Get-GuardVpnAdapter } 'VPN type is not recognized'
$vpn.DriverProvider = 'WireGuard LLC'
$vpn.HardwareInterface = $true
Assert-NetworkFailure { Get-GuardVpnAdapter } 'No active VPN tunnel'
$vpn.HardwareInterface = $false
$vpn.DriverDescription = 'TAP-Windows driver'
$vpn.InterfaceDescription = 'TAP-Windows Adapter V9'
Assert-NetworkCase ((Get-GuardVpnAdapter).ifIndex -eq $vpn.ifIndex) 'A recognized TAP-Windows driver can own the full route.'

$script:Routes = @((New-Route '0.0.0.0/1' 9))
Assert-NetworkFailure { Get-GuardVpnAdapter } 'full Internet address range could not be verified'
$script:Routes = @((New-Route '0.0.0.0/0' 9 -State 'Probe'), $default)
Assert-NetworkFailure { Get-GuardVpnAdapter } 'full Internet address range could not be verified'
$script:Routes = $split + @(New-Route '192.0.2.65/32' 20)
Assert-NetworkFailure { Get-GuardVpnAdapter } 'IPv4 route appeared on an unverified network interface'

function Test-GuardSystemProxy { $script:ProxyPresent }
$proxyVariables = @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'GLOBAL_AGENT_HTTP_PROXY')
$oldProxy = @{}
foreach ($name in $proxyVariables) { $oldProxy[$name] = [Environment]::GetEnvironmentVariable($name) }
try {
    foreach ($name in $proxyVariables) { [Environment]::SetEnvironmentVariable($name, $null) }
    $script:ProxyPresent = $true
    Assert-NetworkFailure { Assert-GuardNoProxy } 'Windows proxy or automatic proxy discovery is configured'
    $script:ProxyPresent = $false
    [Environment]::SetEnvironmentVariable('HTTPS_PROXY', 'http://127.0.0.1:81')
    Assert-NetworkFailure { Assert-GuardNoProxy } 'process proxy is configured'
}
finally {
    foreach ($name in $proxyVariables) { [Environment]::SetEnvironmentVariable($name, $oldProxy[$name]) }
}

Write-Output "$script:Checks offline Windows adapter and route checks passed."
