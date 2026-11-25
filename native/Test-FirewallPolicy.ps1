#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'FirewallPolicy.ps1')

function Reset-FirewallFixture {
    $inventory = @{
        Programs = @('C:\Fixture\Claude.exe')
        Packages = @(@{ Sid = 'S-1-15-2-1-2-3-4-5-6-7' })
    }
    $adapters = @(
        @{ Name = 'Test Ethernet'; Status = 'Up'; Ipv4Present = $true }
        @{ Name = 'Test Wi-Fi'; Status = 'Disconnected'; Ipv4Present = $true }
        @{ Name = 'Test IPv6 Adapter'; Status = 'Up'; Ipv4Present = $false }
    )
    $script:Specs = @(Get-GuardSpecifications $inventory $adapters)
    $script:Rules = @{}
    $script:Filters = @{}
    for ($i = 0; $i -lt $script:Specs.Count; $i++) {
        $spec = $script:Specs[$i]
        $name = "Test-Rule-$i"
        $script:Rules[$name] = [pscustomobject]@{
            Name = $name; Enabled = 'True'; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'
            PolicyStoreSource = 'PersistentStore'; PolicyStoreSourceType = 'Local'; EdgeTraversalPolicy = 'Block'
            PrimaryStatus = if ($spec.RequireEnforced) { 'OK' } else { 'Inactive' }
            EnforcementStatus = @('ProfileInactive'; if ($spec.RequireEnforced) { 'Enforced' } else { 'NoInterface' })
        }
        $script:Filters[$name] = @{
            Application = @{ InstanceID = $name; Program = $spec.Program; Package = $spec.Package }
            Address = @{
                InstanceID = $name; LocalAddress = 'Any'
                RemoteAddress = if ($spec.RemoteAddress) { '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' } else { 'Any' }
            }
            Interface = @{ InstanceID = $name; InterfaceAlias = $spec.Alias }
            InterfaceType = @{ InstanceID = $name; InterfaceType = 'Any' }
            Port = @{ InstanceID = $name; Protocol = 'Any'; LocalPort = 'Any'; RemotePort = 'Any'; IcmpType = 'Any'; DynamicTarget = 'Any' }
            Security = @{
                InstanceID = $name; Authentication = 'NotRequired'; Encryption = 'NotRequired'
                OverrideBlockRules = $false; LocalUser = 'Any'; RemoteUser = 'Any'; RemoteMachine = 'Any'
            }
            Service = @{ InstanceID = $name; Service = 'Any' }
        }
    }
    $script:RuleNames = @($script:Rules.Keys)
    $script:Profiles = @('Domain','Private','Public' | ForEach-Object {
        [pscustomobject]@{ Name = $_; Enabled = 'True'; AllowLocalFirewallRules = 'True'; DisabledInterfaceAliases = $null }
    })
}

function Get-NetFirewallRule {
    [CmdletBinding()]
    param($PolicyStore, $Name)
    if ($PolicyStore -ne 'ActiveStore') { throw 'Fixture expected the effective store.' }
    $script:Rules.Values | Where-Object Name -In $Name
}

function Get-NetFirewallProfile {
    [CmdletBinding()]
    param($PolicyStore)
    if ($PolicyStore -ne 'ActiveStore') { throw 'Fixture expected the effective store.' }
    $script:Profiles
}

function Get-NetFirewallApplicationFilter {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]$script:Filters[$Rule.Name].Application }
}

function Get-NetFirewallAddressFilter {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]$script:Filters[$Rule.Name].Address }
}

function Get-NetFirewallInterfaceFilter {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]$script:Filters[$Rule.Name].Interface }
}

function Get-NetFirewallInterfaceTypeFilter {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]$script:Filters[$Rule.Name].InterfaceType }
}

function Get-NetFirewallPortFilter {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]$script:Filters[$Rule.Name].Port }
}

function Get-NetFirewallSecurityFilter {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]$script:Filters[$Rule.Name].Security }
}

function Get-NetFirewallServiceFilter {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]$script:Filters[$Rule.Name].Service }
}

function Assert-FirewallRejection([string]$Description, [string]$Expected, [scriptblock]$Check) {
    try {
        & $Check
    } catch {
        if (!$_.Exception.Message.Contains($Expected)) { throw }
        Write-Output "PASS: $Description"
        return
    }
    throw "Firewall policy accepted an invalid fixture: $Description"
}

Reset-FirewallFixture
if ($script:Specs.Count -ne 6 -or $script:Specs.Alias -contains 'Test IPv6 Adapter') {
    throw 'Unexpected firewall scope count.'
}
Assert-GuardProfiles
Assert-GuardCoverage $script:Specs $script:RuleNames -DuringRefresh
'PASS: Allowed full IPv6 blocks and disconnected eligible interfaces while retaining executable and package coverage.'

Reset-FirewallFixture
$script:Rules.Remove('Test-Rule-0')
Assert-FirewallRejection 'A missing effective rule invalidates coverage.' 'missing a recorded firewall rule' {
    Assert-GuardCoverage $script:Specs $script:RuleNames
}

Reset-FirewallFixture
$script:Rules['Test-Rule-0'].Enabled = 'False'
Assert-FirewallRejection 'A disabled effective rule invalidates coverage.' 'has been changed' {
    Assert-GuardCoverage $script:Specs $script:RuleNames
}

Reset-FirewallFixture
$script:Filters['Test-Rule-0'].Port.RemotePort = '443'
Assert-FirewallRejection 'A port-limited block invalidates coverage.' 'narrower match' {
    Assert-GuardCoverage $script:Specs $script:RuleNames
}

Reset-FirewallFixture
$script:Filters['Test-Rule-0'].Application.Program = 'C:\Fixture\Other.exe'
Assert-FirewallRejection 'An unrelated executable rule does not satisfy the original target.' 'no longer cover' {
    Assert-GuardCoverage $script:Specs $script:RuleNames
}

Reset-FirewallFixture
$script:Rules['Test-Rule-0'].PrimaryStatus = 'Inactive'
$script:Rules['Test-Rule-0'].EnforcementStatus = @('NoInterface')
Assert-FirewallRejection 'A currently connected interface needs an enforced block.' 'not enforcing' {
    Assert-GuardCoverage $script:Specs $script:RuleNames
}

Reset-FirewallFixture
$script:Filters['Test-Rule-4'].Address.RemoteAddress = '2001:db8::/32'
Assert-FirewallRejection 'A partial IPv6 block cannot satisfy global IPv6 coverage.' 'unexpected remote address scope' {
    Assert-GuardCoverage $script:Specs $script:RuleNames
}

Assert-FirewallRejection 'Wildcard names cannot expand the recorded firewall policy.' 'identities are invalid' {
    Assert-GuardCoverage $script:Specs @('Test-Rule-*')
}

Reset-FirewallFixture
$script:Profiles[1].AllowLocalFirewallRules = 'False'
Assert-FirewallRejection 'Group policy disabling local rule merge prevents guarded launch.' 'must be enabled' {
    Assert-GuardProfiles
}

Reset-FirewallFixture
$script:Profiles[1].DisabledInterfaceAliases = @('Test Ethernet')
Assert-FirewallRejection 'An interface exempted from the firewall prevents guarded launch.' 'must be enabled' {
    Assert-GuardProfiles
}

Reset-FirewallFixture
$duplicateName = 'Test-Rule-Exact-Duplicate'
$script:Rules[$duplicateName] = $script:Rules['Test-Rule-0'].PSObject.Copy()
$script:Rules[$duplicateName].Name = $duplicateName
$script:Filters[$duplicateName] = @{}
foreach ($kind in $script:Filters['Test-Rule-0'].Keys) {
    $script:Filters[$duplicateName][$kind] = $script:Filters['Test-Rule-0'][$kind].Clone()
    $script:Filters[$duplicateName][$kind].InstanceID = $duplicateName
}
$candidates = @($script:RuleNames) + @($duplicateName, 'Test-Rule-Missing')
$reusable = @(Get-GuardReusableRules $script:Specs $candidates)
$ipv6Key = Get-GuardFirewallKey 'Any' 'C:\Fixture\Claude.exe' '' $script:GuardIpv6RemoteRange
if ($reusable.Count -ne 6 -or @($reusable.Key | Sort-Object -Unique).Count -ne 6 -or
    $reusable.Key -notcontains $ipv6Key -or $reusable.Name -contains 'Test-Rule-Missing') {
    throw 'A missing or duplicate candidate changed the selected required scopes.'
}
'PASS: Selected one effective rule per scope despite duplicate and missing candidates.'

Reset-FirewallFixture
$script:Filters['Test-Rule-0'].Port.RemotePort = '443'
$script:Rules['Test-Rule-1'].Enabled = 'False'
$script:Filters['Test-Rule-4'].Application.Program = 'C:\Fixture\Other.exe'
$reusable = @(Get-GuardReusableRules $script:Specs $script:RuleNames)
if ($reusable.Count -ne 3 -or @($reusable.Name | Where-Object { $_ -in ('Test-Rule-0','Test-Rule-1','Test-Rule-4') }).Count) {
    throw 'Changed or unrelated candidates were selected for reuse.'
}
'PASS: Reuse skips narrowed, disabled, and unrelated active rules without discarding sound candidates.'

Reset-FirewallFixture
$script:Filters['Test-Rule-0'].Remove('Service')
$script:Filters['Test-Rule-1'].Address.IsNegated = $true
$reusable = @(Get-GuardReusableRules $script:Specs $script:RuleNames)
if ($reusable.Count -ne 4 -or $reusable.Name -contains 'Test-Rule-0' -or $reusable.Name -contains 'Test-Rule-1') {
    throw 'An incomplete or negated association was accepted for reuse.'
}
'PASS: Reuse skips candidates with missing or negated filters.'

'13 offline firewall policy checks passed.'
