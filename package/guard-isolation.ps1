# Shared privacy hold, scoped block rules, and refresh status.
$script:GuardIsolationPrefix = 'ClaudeDesktopPrivacyIsolation-Managed-'
$script:GuardLegacyIsolationPrefix = 'ClaudeDesktopPrivacyIsolation-140def61a8b54dbc83d567248c81fcdd-'

function Get-GuardDataPath([string]$Name) {
    $directory=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
    Join-Path $directory $Name
}
function Get-GuardIsolationMode {
    $path=Get-GuardDataPath 'privacy-isolation.json'
    try {
        $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { return 'Unknown' }
        $data=[IO.File]::ReadAllText($path) | ConvertFrom-Json -ErrorAction Stop
        if ($data.Version -eq 1 -and $data.Mode -ceq 'Active') { return 'Active' }
        return 'Unknown'
    } catch {
        if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { return 'Unknown' }
    }
    # The original restrictions remain a hold signal if the marker is missing.
    try {
        $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
            Where-Object { [string]$_.Enabled -eq 'True' -and
                ($_.Name -like "$script:GuardLegacyIsolationPrefix*" -or $_.Name -like "$script:GuardIsolationPrefix*") })
        if ($rules.Count) { 'Active' } else { 'Off' }
    } catch { 'Unknown' }
}
function Assert-GuardLaunchPermitted {
    if ((Get-GuardIsolationMode) -ne 'Off') {
        throw 'Claude privacy isolation is active or could not be verified.'
    }
}
function Get-GuardIsolationSpecifications($Inventory) {
    if (-not @($Inventory.Programs | Where-Object { $_ }).Count) {
        throw 'No confirmed programs for privacy isolation.'
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $targets=@(foreach ($path in @($Inventory.Programs | Sort-Object -Unique)) {
            if ($path -notmatch '^[A-Za-z]:\\.+\.exe$' -or $path -match '[*?]') { throw 'Invalid program path for privacy isolation.' }
            [pscustomobject]@{Program=[IO.Path]::GetFullPath($path);Package=$null}
        })
        $targets+=@(foreach ($package in @($Inventory.Packages | Sort-Object Sid -Unique)) {
            if ($package.Sid -notmatch '^S-1-15-2(?:-\d+){7}$') { throw 'Invalid package identity for privacy isolation.' }
            [pscustomobject]@{Program=$null;Package=[string]$package.Sid}
        })
        foreach ($target in $targets) {
            foreach ($direction in @('Inbound','Outbound')) {
                $identity=('{0}|{1}|{2}' -f $direction,$target.Program,$target.Package).ToUpperInvariant()
                $hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity))).Replace('-','').ToLowerInvariant()
                [pscustomobject]@{Name="$script:GuardIsolationPrefix$hash";Program=$target.Program;Package=$target.Package;Alias='Any';Direction=$direction}
            }
        }
    } finally { $sha.Dispose() }
}
function Get-GuardFirewallRuleNamed([string]$Name,[string]$PolicyStore='PersistentStore') {
    try {
        $rule=@(Get-NetFirewallRule -Name $Name -PolicyStore $PolicyStore -ErrorAction Stop)
        if ($rule.Count -ne 1 -or $rule[0].Name -ne $Name) { throw 'Rule identity did not resolve uniquely.' }
        $rule[0]
    } catch {
        if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
    }
}
function Add-GuardFirewallBlock($Specification,[string]$Name) {
    $direction=if ($Specification.Direction) { $Specification.Direction } else { 'Outbound' }
    $parameters=@{
        Name=$Name; DisplayName="Claude Guard: block on $($Specification.Alias)"
        Direction=$direction; Action='Block'; Profile='Any'; Enabled='True'
        PolicyStore='PersistentStore'; ErrorAction='Stop'
    }
    if ($Name -like "$script:GuardIsolationPrefix*") {
        $parameters.DisplayName='Claude Desktop Privacy Isolation'
        $parameters.Group='Claude Desktop Privacy Isolation'
    }
    if ($Specification.Alias -and $Specification.Alias -ne 'Any') { $parameters.InterfaceAlias=$Specification.Alias }
    if ($Specification.RemoteAddress) { $parameters.RemoteAddress=$Specification.RemoteAddress }
    if ($Specification.Program) { $parameters.Program=$Specification.Program } else { $parameters.Package=$Specification.Package }
    New-NetFirewallRule @parameters | Out-Null
}
function Assert-GuardIsolationRules($Inventory,[switch]$ConfiguredOnly) {
    $specifications=@(Get-GuardIsolationSpecifications $Inventory)
    $store=if ($ConfiguredOnly) { 'PersistentStore' } else { 'ActiveStore' }
    $rules=@(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop |
        Where-Object { $_.Name -like "$script:GuardIsolationPrefix*" -or $_.Name -like "$script:GuardLegacyIsolationPrefix*" })
    $byName=@{}
    foreach ($rule in $rules) { $byName[$rule.Name]=$rule }
    $cache=@{}
    foreach ($spec in $specifications) {
        $rule=$byName[$spec.Name]
        if (-not $rule) { throw "An emergency block is missing from $store." }
        if (Test-GuardRule $rule $spec -RequireEnforced -ConfiguredOnly:$ConfiguredOnly -FilterCache $cache) { continue }
        if ($ConfiguredOnly) { throw 'An emergency block does not match its persistent configuration.' }
        $isDuplicate=@($rule.EnforcementStatus | ForEach-Object { [string]$_ }) -contains 'Duplicate'
        if ($isDuplicate -and (Test-GuardRule $rule $spec -RequireEnforced -AllowDuplicate -FilterCache $cache)) {
            $match=$rules | Where-Object {
                $_.Name -ne $rule.Name -and (Test-GuardRule $_ $spec -RequireEnforced -FilterCache $cache)
            } | Select-Object -First 1
            if ($match) { continue }
        }
        throw 'An emergency block does not have effective coverage.'
    }
    $specifications.Count
}
function Sync-GuardIsolationRules($Inventory) {
    $existing=@{}
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
            Where-Object Name -Like "$script:GuardIsolationPrefix*")) { $existing[$rule.Name]=$rule }
    $cache=@{}
    foreach ($spec in @(Get-GuardIsolationSpecifications $Inventory)) {
        $rule=$existing[$spec.Name]
        if (-not $rule) {
            Add-GuardFirewallBlock $spec $spec.Name
            $rule=Get-GuardFirewallRuleNamed $spec.Name
        }
        if (-not $rule -or -not (Test-GuardRule $rule $spec -ConfiguredOnly -FilterCache $cache)) {
            throw 'An emergency block does not match its saved configuration.'
        }
    }
    Assert-GuardIsolationRules $Inventory
}
function Get-GuardRefreshStatusView($Data,[datetime]$NowUtc=[datetime]::UtcNow) {
    if ($Data.Version -ne 2) {
        return [pscustomobject]@{Ok=$false;Freshness='Unknown';Coverage='Unknown';Proxy='Unknown';Tunnel='Unknown';Isolation='Unknown';Reason='NoCurrentStatus';LastVerifiedUtc=$null}
    }
    $verified=[datetime]::MinValue
    $attempt=[datetime]::MinValue
    $parse=[Globalization.DateTimeStyles]::RoundtripKind
    $culture=[Globalization.CultureInfo]::InvariantCulture
    $valid=[datetime]::TryParse([string]$Data.LastVerifiedUtc,$culture,$parse,[ref]$verified) -and
        [datetime]::TryParse([string]$Data.Utc,$culture,$parse,[ref]$attempt)
    $freshness=if (-not $valid) { 'Unknown' }
        elseif ($verified.ToUniversalTime() -gt $attempt.ToUniversalTime() -or $attempt.ToUniversalTime() -gt $NowUtc.ToUniversalTime()) { 'Unknown' }
        elseif (($NowUtc.ToUniversalTime()-$verified.ToUniversalTime()).TotalMinutes -gt 15) { 'Stale' }
        else { 'Current' }
    $healthy=$freshness -eq 'Current' -and $Data.Coverage -eq 'Verified' -and $Data.Proxy -eq 'Clear' -and
        $Data.Tunnel -eq 'Ready' -and $Data.Isolation -in @('Off','Verified') -and $Data.Reason -in @('Current','Refreshed')
    [pscustomobject]@{
        Ok=$healthy; Freshness=$freshness; Coverage=$Data.Coverage; Proxy=$Data.Proxy
        Tunnel=$Data.Tunnel; Isolation=$Data.Isolation; Reason=$Data.Reason; LastVerifiedUtc=$Data.LastVerifiedUtc
    }
}
