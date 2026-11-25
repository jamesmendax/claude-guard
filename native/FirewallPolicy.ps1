# Windows Firewall rules for the executable and package identities in a Claude inventory.

$script:GuardIpv6RemoteRange = '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'

function Get-GuardRules {
    param([ValidateSet('PersistentStore','ActiveStore')][string]$PolicyStore = 'PersistentStore')

    Get-NetFirewallRule -PolicyStore $PolicyStore -Name 'ClaudeGuardNative-Block-*' -ErrorAction Stop |
        Where-Object Name -CMatch '^ClaudeGuardNative-Block-[a-f0-9]{32}-[0-9]+$'
}

function Get-GuardSpecifications($Inventory, $Adapters) {
    $targets = [Collections.Generic.List[object]]::new()
    foreach ($path in @($Inventory.Programs | Sort-Object -Unique)) {
        if ($path -notmatch '^[a-z]:\\[^*?]+\.exe$') {
            throw 'The firewall inventory contains an invalid application path.'
        }
        $targets.Add([pscustomobject]@{ Program = $path; Package = $null })
    }
    foreach ($sid in @($Inventory.Packages | ForEach-Object Sid | Sort-Object -Unique)) {
        if ($sid -cnotmatch '^S-1-15-2(?:-[0-9]+){7}$') {
            throw 'The firewall inventory contains an invalid package identity.'
        }
        $targets.Add([pscustomobject]@{ Program = $null; Package = $sid })
    }
    foreach ($adapter in $Adapters) {
        if ($adapter.Ipv4Present -eq $false) { continue }
        $alias = [string]$adapter.Name
        if (!$alias -or $alias -ieq 'Any' -or $alias -match '[\x00-\x1f]') {
            throw 'A non-VPN network interface has no usable firewall alias.'
        }
        foreach ($target in $targets) {
            [pscustomobject]@{
                Alias = $alias
                Program = $target.Program
                Package = $target.Package
                RemoteAddress = $null
                RequireEnforced = $adapter.Status -ieq 'Up' -and $adapter.Ipv4Present -ne $false
            }
        }
    }
    foreach ($target in $targets) {
        [pscustomobject]@{
            Alias = 'Any'
            Program = $target.Program
            Package = $target.Package
            RemoteAddress = $script:GuardIpv6RemoteRange
            RequireEnforced = $true
        }
    }
}

function Assert-GuardProfiles {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    foreach ($name in ('Domain','Private','Public')) {
        $profile = @($profiles | Where-Object Name -EQ $name)
        if ($profile.Count -ne 1 -or [string]$profile[0].Enabled -ne 'True' -or
            [string]$profile[0].AllowLocalFirewallRules -notin ('True','NotConfigured') -or
            @($profile[0].DisabledInterfaceAliases | Where-Object { $_ -and $_ -ne 'NotConfigured' }).Count) {
            throw "Windows Firewall profile '$name' must be enabled and apply local rules on every interface."
        }
    }
}

function Get-GuardFirewallFilters($Rules) {
    $commands = @{
        Application = 'Get-NetFirewallApplicationFilter'
        Address = 'Get-NetFirewallAddressFilter'
        Interface = 'Get-NetFirewallInterfaceFilter'
        InterfaceType = 'Get-NetFirewallInterfaceTypeFilter'
        Port = 'Get-NetFirewallPortFilter'
        Security = 'Get-NetFirewallSecurityFilter'
        Service = 'Get-NetFirewallServiceFilter'
    }
    $filters = @{}
    foreach ($type in $commands.Keys) {
        $command = $commands[$type]
        $index = @{}
        foreach ($filter in @($Rules | & $command -ErrorAction Stop)) {
            $id = [string]$filter.InstanceID
            if (!$id) { continue }
            # A duplicate or negated association cannot certify this rule.
            $index[$id] = if (!$index.ContainsKey($id) -and !$filter.IsNegated) { $filter }
        }
        $filters[$type] = $index
    }
    $filters
}

function Get-GuardFirewallKey([string]$Alias, [string]$Program, [string]$Package, [string]$RemoteAddress) {
    $separator = [string][char]31
    $Alias, $Program, $Package, $RemoteAddress -join $separator
}

function Test-GuardFirewallValue($Value, [string]$Expected) {
    $values = @($Value)
    $values.Count -eq 1 -and [string]$values[0] -ieq $Expected
}

function Get-GuardFirewallRequirements($Specifications) {
    $required = @{}
    foreach ($spec in $Specifications) {
        $remote = if ($spec.RemoteAddress) { [string]$spec.RemoteAddress } else { 'Any' }
        $key = Get-GuardFirewallKey $spec.Alias $spec.Program $spec.Package $remote
        if ($required.ContainsKey($key)) {
            throw 'The application inventory produced duplicate firewall scopes.'
        }
        $required[$key] = $spec.RequireEnforced -ne $false
    }
    $required
}

function Get-GuardEffectiveRuleKey($Rule, $Filters, $Required) {
    $name = [string]$Rule.Name
    if ([string]$Rule.Enabled -ne 'True' -or [string]$Rule.Action -ne 'Block' -or
        [string]$Rule.Direction -ne 'Outbound' -or [string]$Rule.Profile -ne 'Any' -or
        [string]$Rule.PolicyStoreSourceType -ne 'Local' -or
        [string]$Rule.PolicyStoreSource -ne 'PersistentStore' -or
        [string]$Rule.EdgeTraversalPolicy -ne 'Block' -or
        $Rule.LooseSourceMapping -or $Rule.LocalOnlyMapping -or $Rule.Owner -or
        $Rule.PolicyAppId -or $Rule.PackageFamilyName -or
        @($Rule.Platforms | Where-Object { $_ }).Count -or
        @($Rule.RemoteDynamicKeywordAddresses | Where-Object { $_ }).Count) {
        throw "A recorded firewall rule has been changed: $name"
    }
    foreach ($type in $Filters.Keys) {
        if (!$Filters[$type][$name]) {
            throw "Windows is missing an unambiguous associated filter for rule $name."
        }
    }
    $application = $Filters.Application[$name]
    $address = $Filters.Address[$name]
    $port = $Filters.Port[$name]
    $security = $Filters.Security[$name]
    if (!(Test-GuardFirewallValue $address.LocalAddress 'Any') -or
        !(Test-GuardFirewallValue $Filters.InterfaceType[$name].InterfaceType 'Any') -or
        !(Test-GuardFirewallValue $Filters.Service[$name].Service 'Any') -or
        !(Test-GuardFirewallValue $port.Protocol 'Any') -or
        !(Test-GuardFirewallValue $port.LocalPort 'Any') -or
        !(Test-GuardFirewallValue $port.RemotePort 'Any') -or
        !(Test-GuardFirewallValue $port.IcmpType 'Any') -or
        !(Test-GuardFirewallValue $port.DynamicTarget 'Any') -or
        [string]$security.Authentication -ne 'NotRequired' -or
        [string]$security.Encryption -ne 'NotRequired' -or
        [string]$security.OverrideBlockRules -ne 'False' -or
        !(Test-GuardFirewallValue $security.LocalUser 'Any') -or
        !(Test-GuardFirewallValue $security.RemoteUser 'Any') -or
        !(Test-GuardFirewallValue $security.RemoteMachine 'Any')) {
        throw "A recorded firewall rule now has a narrower match: $name"
    }

    $aliases = @($Filters.Interface[$name].InterfaceAlias)
    $addresses = @($address.RemoteAddress)
    if ($aliases.Count -ne 1 -or !$aliases[0] -or $addresses.Count -ne 1) {
        throw "A recorded firewall rule has an unexpected interface or address scope: $name"
    }
    $remote = [string]$addresses[0]
    if ($remote -eq '::/0') { $remote = $script:GuardIpv6RemoteRange }
    if ($remote -notin ('Any',$script:GuardIpv6RemoteRange)) {
        throw "A recorded firewall rule has an unexpected remote address scope: $name"
    }
    $program = [string]$application.Program
    if ($program -ieq 'Any') { $program = '' }
    $package = [string]$application.Package
    if ($package -ieq 'Any') { $package = '' }
    if ((!$program -and !$package) -or ($program -and $package)) {
        throw "A recorded firewall rule no longer identifies one application: $name"
    }
    $key = Get-GuardFirewallKey $aliases[0] $program $package $remote

    $enforcement = @($Rule.EnforcementStatus)
    $isEnforced = [string]$Rule.PrimaryStatus -eq 'OK' -and $enforcement -contains 'Enforced'
    $isDisconnected = [string]$Rule.PrimaryStatus -eq 'Inactive' -and $enforcement -contains 'NoInterface'
    if (@($enforcement | Where-Object { $_ -notin ('Enforced','ProfileInactive','NoInterface') }).Count -or
        (!$isEnforced -and (!$isDisconnected -or $Required[$key] -ne $false))) {
        throw "Windows is not enforcing a recorded firewall rule: $name"
    }
    $key
}

function Get-GuardReusableRules($Specifications, [string[]]$CandidateNames) {
    $names = @($CandidateNames | Where-Object { $_ -cmatch '^[A-Za-z0-9-]{1,128}$' } | Sort-Object -Unique)
    if (!$names.Count) { return }
    $required = Get-GuardFirewallRequirements $Specifications
    if (!$required.Count) { return }

    # Parts of a saved generation may have been deleted. Other provider errors
    # mean the effective store could not be read and must abort the update.
    $queryErrors = @()
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $names -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
    foreach ($queryError in $queryErrors) {
        if ($queryError.FullyQualifiedErrorId -ne 'CmdletizationQuery_NotFound_InstanceID,Get-NetFirewallRule') {
            throw $queryError
        }
    }
    $candidates = @($rules | Group-Object Name | Where-Object Count -EQ 1 |
        ForEach-Object { $_.Group[0] } | Where-Object Name -In $names)
    if (!$candidates.Count) { return }
    $filters = Get-GuardFirewallFilters $candidates
    foreach ($rule in $candidates) {
        try {
            $key = Get-GuardEffectiveRuleKey $rule $filters $required
        } catch {
            continue
        }
        if ($required.ContainsKey($key)) {
            [pscustomobject]@{ Name = [string]$rule.Name; Key = $key }
            $required.Remove($key)
        }
    }
}

function Assert-GuardCoverage($Specifications, [string[]]$RuleNames, [switch]$DuringRefresh) {
    $names = @($RuleNames | Sort-Object -Unique)
    if (!$names.Count -or $names.Count -ne $RuleNames.Count -or
        @($names | Where-Object { $_ -cnotmatch '^[A-Za-z0-9-]{1,128}$' }).Count) {
        throw 'The recorded firewall rule identities are invalid.'
    }
    $required = Get-GuardFirewallRequirements $Specifications
    if (!$required.Count -or ($DuringRefresh -and $required.Count -ne $names.Count)) {
        throw 'The recorded firewall rules do not cover the application inventory.'
    }

    # Associated effective-store queries also work for standard users, unlike
    # querying every filter in that store.
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $names -ErrorAction Stop)
    if ($rules.Count -ne $names.Count) {
        throw 'Windows is missing a recorded firewall rule.'
    }
    $filters = Get-GuardFirewallFilters $rules
    $recorded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $names) { $null = $recorded.Add($name) }
    foreach ($rule in $rules) {
        if (!$recorded.Remove([string]$rule.Name)) {
            throw 'Windows returned an unexpected or ambiguous effective firewall rule.'
        }
        $key = Get-GuardEffectiveRuleKey $rule $filters $required
        if ($required.ContainsKey($key)) { $required.Remove($key) }
    }
    if ($required.Count -or $recorded.Count) {
        throw 'The recorded Windows Firewall rules no longer cover every required application and interface.'
    }
}


function Assert-GuardAdministratorDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The firewall state path must be an ordinary directory.'
    }
    $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
    $sidType = [Security.Principal.SecurityIdentifier]
    $administrators = 'S-1-5-32-544'
    $system = 'S-1-5-18'
    if (!$acl.AreAccessRulesProtected -or $acl.GetOwner($sidType).Value -notin ($administrators,$system)) {
        throw 'The firewall state directory is not owned and protected by administrators.'
    }
    $expected = @{
        $administrators = [Security.AccessControl.FileSystemRights]::FullControl
        $system = [Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-545' = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
            [Security.AccessControl.FileSystemRights]::Synchronize
    }
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($access in $acl.GetAccessRules($true, $true, $sidType)) {
        $principal = $access.IdentityReference.Value
        if (!$expected.ContainsKey($principal) -or $access.AccessControlType -ne 'Allow' -or
            $access.FileSystemRights -ne $expected[$principal] -or $access.InheritanceFlags -ne $inherit -or
            $access.PropagationFlags -ne 'None' -or $access.IsInherited) {
            throw 'The firewall state directory has unexpected Windows permissions.'
        }
        $expected.Remove($principal)
    }
    if ($expected.Count) { throw 'The firewall state directory is missing required Windows permissions.' }
}

function Initialize-GuardAdministratorDirectory([string]$Path) {
    if (!(Test-Path -LiteralPath $Path)) {
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $acl.SetOwner($admin)
        foreach ($sid in ('S-1-5-32-544','S-1-5-18','S-1-5-32-545')) {
            $rights = if ($sid -eq 'S-1-5-32-545') { 'ReadAndExecute' } else { 'FullControl' }
            $principal = [Security.Principal.SecurityIdentifier]::new($sid)
            $access = [Security.AccessControl.FileSystemAccessRule]::new($principal, $rights, $inherit, 'None', 'Allow')
            $acl.AddAccessRule($access)
        }
        $folder = [IO.DirectoryInfo]::new($Path)
        # Apply the descriptor at creation, before the directory can contain state.
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            $folder.Create($acl)
        } else {
            [IO.FileSystemAclExtensions]::Create($folder, $acl)
        }
    }
    Assert-GuardAdministratorDirectory $Path
}
