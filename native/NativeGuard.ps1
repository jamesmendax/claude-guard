param(
    [ValidateSet('Status','StatusCli','Configure','Launch','LaunchCli','Refresh','RemoveRules','StopClaude')][string]$Mode,
    [string]$TimeZoneId,
    [string[]]$CliArguments
)

$ErrorActionPreference = 'Stop'
$script:GuardRulePrefix = 'ClaudeGuardNative-Block'
$script:GuardSignatureCache = @{}
$script:GuardShutdownConfirmSeconds = 5
$script:GuardInventoryRefreshSeconds = 10
$script:ProgramDataRoot = [Environment]::GetFolderPath('CommonApplicationData')
$script:GuardFolder = Join-Path $script:ProgramDataRoot 'ClaudeGuardNative'
$script:GuardState = Join-Path $script:GuardFolder 'firewall.json'

function New-GuardResult([string]$Message = 'Checking local protection.') {
    [pscustomobject]@{
        Ok = $true
        Ready = $false
        CanConfigure = $false
        Route = 'Not checked'
        Firewall = 'Not checked'
        Claude = 'Not checked'
        Message = $Message
        ExitCode = 0
        VpnName = ''
        BlockedAdapterCount = 0
        ProtectedTargetCount = 0
        DesktopReady = $false
        CliReady = $false
        ProxyIssue = 'None'
        ExitStatus = 'Not checked'
        ExitIp = ''
        ExitMaskedIp = ''
        ExitCountry = ''
        ExitColo = ''
        RefreshTaskState = 'Not checked'
        DesktopAutoStart = $false
        RunningClaudeCount = 0
    }
}

function Test-GuardDesktopAutoStart {
    if ('ClaudeGuardNative.DesktopHygiene' -as [type]) {
        return [bool][ClaudeGuardNative.DesktopHygiene]::HasAutoStartWarning()
    }
    $false
}

function Get-GuardRefreshTaskState {
    if (-not (Get-Command -Name 'Get-ScheduledTask' -ErrorAction SilentlyContinue)) {
        return 'Unavailable'
    }
    try {
        $task = Get-ScheduledTask -TaskPath '\' -ErrorAction SilentlyContinue |
            Where-Object TaskName -eq 'Claude Guard Native Refresh' | Select-Object -First 1
        if (-not $task) { return 'Not installed' }
        $state = [string]$task.State
        $info = $null
        if (Get-Command -Name 'Get-ScheduledTaskInfo' -ErrorAction SilentlyContinue) {
            try { $info = Get-ScheduledTaskInfo -TaskName 'Claude Guard Native Refresh' -TaskPath '\' -ErrorAction SilentlyContinue }
            catch { $info = $null }
        }
        if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) {
            return ("$state (last: " + $info.LastRunTime.ToString('yyyy-MM-dd HH:mm') + ')')
        }
        return $state
    } catch {
        return 'Unavailable'
    }
}

function Get-GuardExitPolicy {
    if ('ClaudeGuardNative.ExitPolicyStore' -as [type]) {
        return [ClaudeGuardNative.ExitPolicyStore]::Load()
    }
    $null
}

function Get-GuardAdapterIpv4($Vpn) {
    if (-not $Vpn -or -not $Vpn.ifIndex) { return $null }
    if (-not (Get-Command -Name 'Get-NetIPAddress' -ErrorAction SilentlyContinue)) { return $null }
    try {
        $addr = Get-NetIPAddress -InterfaceIndex ([int]$Vpn.ifIndex) -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
            Select-Object -First 1
        if ($addr) { return [string]$addr.IPAddress }
    } catch { }
    $null
}

function Invoke-GuardExitCheck($Policy, [bool]$AllowRetry, [string]$LocalIpv4) {
    if (-not $Policy -or -not $Policy.Enabled) { return $null }
    if (-not ('ClaudeGuardNative.ExitProbe' -as [type])) { return $null }
    [ClaudeGuardNative.ExitProbe]::CheckWithPolicy($Policy, 6000, $AllowRetry, $LocalIpv4)
}

function New-GuardNetworkWatcher {
    if ('ClaudeGuardNative.NetworkChangeWatcher' -as [type]) {
        return [ClaudeGuardNative.NetworkChangeWatcher]::new($true)
    }
    $null
}

function Wait-GuardMonitorTick($Watcher, [int]$Milliseconds) {
    if ($Watcher) {
        return [bool]$Watcher.Wait($Milliseconds)
    }
    Start-Sleep -Milliseconds $Milliseconds
    return $false
}

function Assert-GuardNativeFolder {
    try { $item = Get-Item -LiteralPath $script:GuardFolder -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return }
    if ($item -and (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint))) {
        throw 'The native firewall state directory is not a regular directory.'
    }
    Assert-GuardAdministratorDirectory $script:GuardFolder
}

function Read-GuardNativeState {
    Assert-GuardNativeFolder
    if (-not (Test-Path -LiteralPath $script:GuardState -PathType Leaf)) { return $null }
    $file = Get-Item -LiteralPath $script:GuardState -Force
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 1MB) {
        throw 'The native firewall state file could not be trusted.'
    }
    $state = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $pin = [guid]::Empty
    $names = @($state.Rules)
    if ($state.Version -ne 1 -or -not [guid]::TryParse([string]$state.VpnGuid, [ref]$pin) -or
        $pin -eq [guid]::Empty -or -not $names.Count -or
        @($names | Where-Object { $_ -cnotmatch '^ClaudeGuardNative-Block-[a-f0-9]{32}-[0-9]+$' }).Count -or
        @($names | Sort-Object -Unique).Count -ne $names.Count) {
        throw 'The native firewall state file is incomplete or invalid.'
    }
    if ($state.OwnerSid -and $state.OwnerSid -cne (Get-GuardNativeOwner)) {
        throw 'This native firewall policy belongs to another Windows user.'
    }
    $state
}

function Get-GuardNativeOwner {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $identity.User.Value } finally { $identity.Dispose() }
}

function Assert-GuardNoDailyPolicy {
    $daily = Join-Path $script:ProgramDataRoot 'ClaudeVPNGuard\daily-mode.json'
    if (Test-Path -LiteralPath $daily) {
        throw 'The installed Daily Guard policy is still configured. Native Guard cannot verify a native launch while that separate policy is present.'
    }
}

function Get-GuardNativeDesktop($Inventory) {
    $paths = @($Inventory.DesktopPaths | Where-Object { (Split-Path -Leaf $_) -ieq 'Claude.exe' })
    foreach ($path in $paths) {
        if (-not (Test-GuardAnthropicSignature $path)) { continue }
        $registered = @($Inventory.Packages | Where-Object {
            $path.StartsWith($_.Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($registered.Count -gt 1) { throw 'More than one Store package matched Claude.' }
        $appId = $null
        if ($registered.Count -eq 1) {
            $family = $registered[0].Family
            $package = @(Get-AppxPackage -ErrorAction Stop | Where-Object PackageFamilyName -eq $family)
            if ($package.Count -ne 1) { throw 'Claude Store registration changed.' }
            $manifest = Get-AppxPackageManifest -Package $package[0].PackageFullName -ErrorAction Stop
            $entry = @($manifest.Package.Applications.Application | Where-Object {
                $_.Id -and $_.Executable -and ([IO.Path]::GetFullPath((Join-Path $package[0].InstallLocation $_.Executable)) -ieq $path)
            })
            if ($entry.Count -ne 1) { continue }
            $appId = "$family!$($entry[0].Id)"
        }
        [pscustomobject]@{ Path = $path; AppId = $appId }
        return
    }
    throw 'No supported, publisher-verified Claude Desktop installation was found.'
}

function Get-GuardNativeCli($Inventory) {
    if (-not $Inventory.CliPath -or $Inventory.Programs -notcontains $Inventory.CliPath -or
        -not (Test-GuardAnthropicSignature $Inventory.CliPath)) {
        throw 'No supported, publisher-verified native Claude Code executable was found on PATH.'
    }
    [pscustomobject]@{ Path = $Inventory.CliPath; AppId = $null }
}

function Get-GuardNativeContext([string]$Pin, $Status, [switch]$Cli, [switch]$Setup, [switch]$AllowVpnDown, $CachedInventory) {
    if ($AllowVpnDown) {
        if (-not $Pin) { throw 'A saved VPN is required for background refresh.' }
        $vpn = Get-GuardPinnedVpnAdapter $Pin
    } else {
        Assert-GuardNoProxy
        $vpn = Get-GuardVpnAdapter $Pin
    }
    if ($Status) {
        $Status.Route = 'VPN route verified'
        if ($vpn.Name) { $Status.VpnName = [string]$vpn.Name }
    }
    $adapters = @(Get-GuardBlockedAdapters $vpn -AllowVpnDown:$AllowVpnDown)
    if (-not $adapters.Count) { throw 'Windows did not expose the other interfaces for verification.' }
    if ($Status) {
        $Status.BlockedAdapterCount = @($adapters | Where-Object { $_.Ipv4Present -ne $false }).Count
    }
    $inventory = if ($null -ne $CachedInventory) { $CachedInventory } else { Get-GuardInventory }
    if ($Status) {
        $Status.ProtectedTargetCount = @($inventory.Programs).Count + @($inventory.Packages).Count
        try { $null = Get-GuardNativeDesktop $inventory; $Status.DesktopReady = $true } catch { $Status.DesktopReady = $false }
        try { $null = Get-GuardNativeCli $inventory; $Status.CliReady = $true } catch { $Status.CliReady = $false }
    }
    if ($Cli) {
        $desktop = Get-GuardNativeCli $inventory
    } elseif ($Setup) {
        try { $desktop = Get-GuardNativeDesktop $inventory }
        catch { $desktop = Get-GuardNativeCli $inventory }
    } else {
        $desktop = Get-GuardNativeDesktop $inventory
    }
    if ($Status) { $Status.Claude = if ($Cli) { 'Claude Code verified' } else { 'Desktop verified' } }
    $specifications = @(Get-GuardSpecifications $inventory $adapters)
    if (-not $specifications.Count) { throw 'No Claude firewall coverage could be determined.' }
    [pscustomobject]@{ Vpn = $vpn; Adapters = $adapters; Inventory = $inventory; Desktop = $desktop; Rules = $specifications }
}

function Get-GuardNativeFingerprint($Context) {
    $parts = @([string]$Context.Vpn.InterfaceGuid, [string]$Context.Desktop.Path, [string]$Context.Desktop.AppId)
    $parts += @($Context.Adapters | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.InterfaceGuid, $_.Name, $_.Status, $_.Ipv4Present
    } | Sort-Object)
    $parts += @($Context.Rules | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.Alias, $_.Program, $_.Package, $_.RemoteAddress
    } | Sort-Object)
    $parts -join [Environment]::NewLine
}

function Assert-GuardNativeCoverage($State, $Context) {
    Assert-GuardProfiles
    foreach ($adapter in $Context.Adapters) {
        if ($adapter.Ipv4Present -eq $false) { continue }
        if (-not @($State.Adapters | Where-Object { $_.Guid -eq "$($adapter.InterfaceGuid)" -and $_.Alias -eq $adapter.Name }).Count) {
            throw 'A network interface changed since the native rules were applied.'
        }
    }
    Assert-GuardCoverage $Context.Rules @($State.Rules)
}

function Get-GuardNativeClientProcesses($Inventory) {
    $running = @(Get-GuardRunningProcesses $Inventory)
    $background = @($running | Where-Object { $_.SessionId -eq 0 -and $_.ProcessName -ieq 'cowork-svc' })
    if ($background.Count) {
        $service = Get-CimInstance Win32_Service -Filter "Name='CoworkVMServiceStore'" -ErrorAction Stop
        $instance = @($background | Where-Object Id -EQ $service.ProcessId)
        if ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem' -and $instance.Count -eq 1) {
            $image = [string]$instance[0].Path
            $registered = [string]$service.PathName
            $pathMatches = $registered -match '^\s*(?:"([^"]+)"|(.+?\.exe))(?=\s|$)'
            $servicePath = if ($pathMatches) { $Matches[1] + $Matches[2] }
            $packageRoot = @($Inventory.Packages | Where-Object {
                $_.Family -eq 'AnthropicPBC.Claude_fnn82j28hfe8t' -and
                    $image.StartsWith($_.Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
            })
            # The signed Windows service still has outbound rules. It is not an open Desktop or CLI session.
            if ($image -and $image -ieq $servicePath -and $packageRoot.Count -eq 1 -and
                (Test-GuardAnthropicSignature $image)) {
                return @($running | Where-Object Id -NE $instance[0].Id)
            }
        }
    }
    $running
}

function Get-GuardNativeStatus([switch]$Cli) {
    $answer = New-GuardResult
    $answer.RefreshTaskState = Get-GuardRefreshTaskState
    $answer.DesktopAutoStart = Test-GuardDesktopAutoStart
    try {
        $state = Read-GuardNativeState
        Assert-GuardNoDailyPolicy
        $context = Get-GuardNativeContext '' $answer -Cli:$Cli
        Assert-GuardProfiles
        $runningClients = @(Get-GuardNativeClientProcesses $context.Inventory)
        $answer.RunningClaudeCount = $runningClients.Count
        if ($runningClients.Count) {
            $answer.Claude = 'Already running'
            throw 'Close the existing Claude session before starting or setting up this guard.'
        }
        $answer.CanConfigure = $true
        if (-not $state) {
            $answer.Firewall = 'Setup required'
            $answer.Message = 'Set up the scoped Windows Firewall rules to enable guarded launch.'
            return $answer
        }
        if ([guid]$state.VpnGuid -ne [guid]$context.Vpn.InterfaceGuid) {
            $answer.Firewall = 'Setup required'
            $answer.Message = 'The VPN changed. Confirm firewall setup for the new route before launching.'
            return $answer
        }
        Assert-GuardNativeCoverage $state $context
        $answer.Firewall = 'Effective blocks verified'

        $exitPolicy = Get-GuardExitPolicy
        if ($exitPolicy -and $exitPolicy.Enabled) {
            $localIpv4 = Get-GuardAdapterIpv4 $context.Vpn
            $exitResult = Invoke-GuardExitCheck $exitPolicy $true $localIpv4
            if ($exitResult) {
                $answer.ExitIp = [string]$exitResult.Ip
                $answer.ExitMaskedIp = [string]$exitResult.MaskedIp
                $answer.ExitCountry = [string]$exitResult.Country
                $answer.ExitColo = [string]$exitResult.Colo
                if (-not $exitResult.PolicyAllowed) {
                    $answer.ExitStatus = if ($exitResult.Ok) { 'Policy mismatch' } else { 'Probe failed' }
                    $answer.Ready = $false
                    $answer.Message = [string]$exitResult.Message
                    return $answer
                }
                $answer.ExitStatus = 'Verified'
            }
        } else {
            $answer.ExitStatus = 'Disabled'
        }

        $answer.Ready = $true
        $answer.Message = if ($answer.ExitStatus -eq 'Verified') {
            'The verified local route, firewall rules, and public IPv4 exit are ready for a guarded launch.'
        } else {
            'The verified local route and rules are ready for a guarded launch.'
        }
    } catch {
        if ($_.Exception -and $_.Exception.Data -and $_.Exception.Data.Contains('ProxyIssue')) {
            $answer.ProxyIssue = [string]$_.Exception.Data['ProxyIssue']
        }
        if ($answer.Route -eq 'Not checked') { $answer.Route = 'Unverified' }
        if ($answer.Firewall -eq 'Not checked') { $answer.Firewall = 'Unverified' }
        $answer.Message = $_.Exception.Message
    }
    $answer
}

function Save-GuardNativeState($State) {
    Assert-GuardNativeFolder
    Initialize-GuardAdministratorDirectory $script:GuardFolder
    $temp = Join-Path $script:GuardFolder ('state-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temp, ($State | ConvertTo-Json -Depth 5 -Compress))
        if ([IO.File]::Exists($script:GuardState)) {
            [IO.File]::Replace($temp, $script:GuardState, [NullString]::Value)
        } else {
            [IO.File]::Move($temp, $script:GuardState)
        }
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

function Remove-GuardNativeRules([string[]]$Names) {
    if (!$Names.Count) { return }
    $owned = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Names) {
        if ($name -cnotmatch '^ClaudeGuardNative-Block-[a-f0-9]{32}-[0-9]+$') { throw 'Unexpected rule identity.' }
        $null = $owned.Add($name)
    }
    $rules = @(Get-GuardRules | Where-Object { $owned.Contains($_.Name) })
    if ($rules.Count) { $rules | Remove-NetFirewallRule -ErrorAction Stop }
}

function Set-GuardNativeProtection([switch]$Refresh) {
    $mutex = [Threading.Mutex]::new($false, 'Global\ClaudeGuardNativeFirewallSetup')
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { throw 'Another firewall setup is in progress.' }
        Assert-GuardNoDailyPolicy
        Assert-GuardProfiles
        $previous = Read-GuardNativeState
        # Setup is an explicit user action. Inspect the current VPN rather than silently preserving a stale selection.
        if ($Refresh -and -not $previous) {
            return (New-GuardResult 'No saved native firewall policy is available to refresh.')
        }
        if ($Refresh -and -not $previous.OwnerSid) {
            throw 'Run firewall setup once to record the Windows account that owns this policy.'
        }
        $pin = if ($Refresh) { [string]$previous.VpnGuid } else { '' }
        $context = Get-GuardNativeContext $pin -Setup -AllowVpnDown:$Refresh
        if (@(Get-GuardNativeClientProcesses $context.Inventory).Count) {
            if ($Refresh) { return (New-GuardResult 'Refresh deferred while Claude is running.') }
            throw 'Close Claude before applying native firewall rules.'
        }
        if ($Refresh) {
            try {
                Assert-GuardNativeCoverage $previous $context
                $answer = New-GuardResult 'Saved rule coverage passed its background check.'
                $answer.Firewall = 'Effective blocks verified'
                return $answer
            } catch {
                # The saved native scope stays active until the replacement has passed verification.
            }
        }
        $generation = [guid]::NewGuid().ToString('N')
        $previousRules = @(Get-GuardRules | Where-Object Name -cmatch '^ClaudeGuardNative-Block-[a-f0-9]{32}-[0-9]+$' | Select-Object -ExpandProperty Name)
        $reusable = @{}
        foreach ($match in Get-GuardReusableRules $context.Rules $previousRules) {
            $reusable[$match.Key] = $match.Name
        }
        $selected = [Collections.Generic.List[string]]::new()
        $staged = [Collections.Generic.List[string]]::new()
        $committed = $false
        try {
            foreach ($spec in $context.Rules) {
                $remote = if ($spec.RemoteAddress) { $spec.RemoteAddress } else { 'Any' }
                $key = Get-GuardFirewallKey $spec.Alias $spec.Program $spec.Package $remote
                if ($reusable.ContainsKey($key)) {
                    $selected.Add($reusable[$key])
                    continue
                }
                $name = "$script:GuardRulePrefix-$generation-$($staged.Count)"
                $params = @{
                    Name = $name
                    DisplayName = "Claude Guard Native: block on $($spec.Alias)"
                    PolicyStore = 'PersistentStore'
                    Direction = 'Outbound'
                    Action = 'Block'
                    Profile = 'Any'
                    Enabled = 'True'
                    ErrorAction = 'Stop'
                }
                if ($spec.Alias -ne 'Any') { $params.InterfaceAlias = $spec.Alias }
                if ($spec.RemoteAddress) { $params.RemoteAddress = $spec.RemoteAddress }
                if ($spec.Program) { $params.Program = $spec.Program } else { $params.Package = $spec.Package }
                $staged.Add($name)
                New-NetFirewallRule @params | Out-Null
                $selected.Add($name)
            }
            Assert-GuardCoverage $context.Rules $selected.ToArray() -DuringRefresh
            $current = Get-GuardNativeContext ([string]$context.Vpn.InterfaceGuid) -Setup -AllowVpnDown:$Refresh
            if ((Get-GuardNativeFingerprint $current) -cne (Get-GuardNativeFingerprint $context)) {
                throw 'The VPN, adapter inventory or Claude installation changed during setup.'
            }
            if (@(Get-GuardNativeClientProcesses $current.Inventory).Count) {
                throw 'A Claude session appeared during firewall setup.'
            }
            $state = [pscustomobject]@{
                Version = 1
                OwnerSid = Get-GuardNativeOwner
                VpnGuid = [string]$context.Vpn.InterfaceGuid
                Rules = $selected.ToArray()
                Adapters = @($context.Adapters | ForEach-Object {
                    [pscustomobject]@{ Guid = [string]$_.InterfaceGuid; Alias = $_.Name }
                })
            }
            Save-GuardNativeState $state
            $committed = $true
        } finally {
            if (-not $committed) { Remove-GuardNativeRules $staged.ToArray() }
        }
        Remove-GuardNativeRules @($previousRules | Where-Object { !$selected.Contains($_) })
        $current = Get-GuardNativeContext ([string]$state.VpnGuid) -Setup -AllowVpnDown:$Refresh
        Assert-GuardNativeCoverage $state $current
        if ($Refresh) {
            $answer = New-GuardResult 'Rules refreshed for the saved VPN.'
            $answer.Firewall = 'Effective blocks verified'
            return $answer
        }
        $answer = Get-GuardNativeStatus
        if (-not $answer.Ready) { $answer = Get-GuardNativeStatus -Cli }
        if ($answer.Ready) { return $answer }
        $answer.Firewall = 'Rules applied'
        $answer.Ok = $true
        $answer.Message = 'Windows applied the scoped rules. Check the launch status again. ' + $answer.Message
        $answer
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Remove-GuardNativeProtection {
    $null = Read-GuardNativeState
    if (@(Get-GuardRunningProcesses (Get-GuardInventory)).Count) {
        throw 'Close Claude before removing the native rules.'
    }
    $names = @(Get-GuardRules | Where-Object Name -cmatch '^ClaudeGuardNative-Block-[a-f0-9]{32}-[0-9]+$' | Select-Object -ExpandProperty Name)
    Remove-GuardNativeRules $names
    if (@(Get-GuardRules | Where-Object Name -cmatch '^ClaudeGuardNative-Block-[a-f0-9]{32}-[0-9]+$').Count) {
        throw 'Some native firewall rules could not be removed.'
    }
    if ([IO.File]::Exists($script:GuardState)) { [IO.File]::Delete($script:GuardState) }
    New-GuardResult 'Native firewall rules removed.'
}

function Invoke-GuardNativeDesktop([switch]$Cli, [string]$Zone, [string[]]$Arguments) {
    Assert-GuardNoDailyPolicy
    $state = Read-GuardNativeState
    if (-not $state) { throw 'The native firewall rules need to be set up before launch.' }
    $context = Get-GuardNativeContext ([string]$state.VpnGuid) -Cli:$Cli
    Assert-GuardNativeCoverage $state $context
    if (@(Get-GuardNativeClientProcesses $context.Inventory).Count) {
        throw 'Close the existing Claude session before opening a guarded one.'
    }
    $exitPolicy = Get-GuardExitPolicy
    $localIpv4 = Get-GuardAdapterIpv4 $context.Vpn
    if ($exitPolicy -and $exitPolicy.Enabled) {
        $preExit = Invoke-GuardExitCheck $exitPolicy $true $localIpv4
        if ($preExit -and -not $preExit.PolicyAllowed) {
            throw ([string]$preExit.Message)
        }
    }
    $snapshot = Get-GuardNativeFingerprint $context
    $started = $null
    $startedIdentity = $null
    $watcher = $null
    $exitCode = 0
    try {
        Start-GuardSessionZone $Zone
        $beforeLaunch = Get-GuardNativeContext ([string]$state.VpnGuid) -Cli:$Cli
        if ((Get-GuardNativeFingerprint $beforeLaunch) -cne $snapshot) {
            throw 'The route, adapter inventory or Claude installation changed before launch.'
        }
        Assert-GuardNativeCoverage $state $beforeLaunch
        $watcher = New-GuardNetworkWatcher
        if ($Cli) {
            $started = Start-GuardNativeCli $context.Desktop.Path $Arguments
        } elseif ($context.Desktop.AppId) {
            $id = Start-GuardWindowsApplication $context.Desktop.AppId ''
            $started = Get-Process -Id $id -ErrorAction Stop
        } else {
            $started = Start-Process -FilePath $context.Desktop.Path -PassThru -ErrorAction Stop
        }
        if (-not $started) { throw 'Windows did not start the guarded process.' }
        $startedIdentity = Get-GuardStartedProcessIdentity $started $context.Desktop.Path
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $inventoryClock = [Diagnostics.Stopwatch]::StartNew()
        $exitClock = [Diagnostics.Stopwatch]::StartNew()
        $seen = $false
        $wokeByEvent = $false
        do {
            if ($Cli -and $started.HasExited) {
                $exitCode = $started.ExitCode
                break
            }
            $running = @(Get-GuardNativeClientProcesses $context.Inventory)
            if ($running.Count) { $seen = $true }
            if (-not $running.Count -and $started.HasExited -and $seen) { break }
            if (-not $seen -and $clock.Elapsed.TotalSeconds -gt 15) {
                throw 'The Claude process could not be confirmed after startup.'
            }
            Assert-GuardNoDailyPolicy
            $inventoryRefreshSec = if ($script:GuardInventoryRefreshSeconds -gt 0) { [int]$script:GuardInventoryRefreshSeconds } else { 10 }
            $needFullInventory = $wokeByEvent -or ($inventoryClock.Elapsed.TotalSeconds -ge $inventoryRefreshSec)
            if ($needFullInventory) {
                $current = Get-GuardNativeContext ([string]$state.VpnGuid) -Cli:$Cli
                $inventoryClock.Restart()
            } else {
                $current = Get-GuardNativeContext ([string]$state.VpnGuid) -Cli:$Cli -CachedInventory $context.Inventory
            }
            if ((Get-GuardNativeFingerprint $current) -cne $snapshot) {
                throw 'The route, adapter inventory or Claude installation changed during this session.'
            }
            Assert-GuardNativeCoverage $state $current
            if ($exitPolicy -and $exitPolicy.Enabled) {
                $interval = if ($exitPolicy.MonitorIntervalSeconds -ge 15) { [int]$exitPolicy.MonitorIntervalSeconds } else { 45 }
                if ($wokeByEvent -or ($exitClock.Elapsed.TotalSeconds -ge $interval)) {
                    $sessionExit = Invoke-GuardExitCheck $exitPolicy $true $localIpv4
                    $exitClock.Restart()
                    if ($sessionExit -and -not $sessionExit.PolicyAllowed) {
                        throw ('Exit verification failed during this session. ' + [string]$sessionExit.Message)
                    }
                }
            }
            $wokeByEvent = Wait-GuardMonitorTick $watcher 1000
        } while ($true)
    } catch {
        if ($started) {
            try { Stop-GuardRunningProcesses $context.Inventory $started $startedIdentity }
            catch { throw ('Protection verification failed and Claude may still be open. ' + $_.Exception.Message) }
        }
        throw
    } finally {
        try {
            if ($watcher) { $watcher.Dispose() }
        } finally {
            try { Restore-GuardSessionZone }
            finally { if ($started) { $started.Dispose() } }
        }
    }
    if ($Cli) {
        $answer = New-GuardResult 'The guarded Claude Code session ended.'
        $answer.ExitCode = $exitCode
        return $answer
    }
    $answer = Get-GuardNativeStatus
    if ($answer.Ready) { $answer.Message = 'The guarded Claude session ended.' }
    $answer
}

function Get-GuardNativeCliCommandLine([string[]]$Arguments) {
    $escaped = foreach ($argument in $Arguments) { ConvertTo-GuardNativeArgument $argument }
    $escaped -join ' '
}

function Stop-GuardClaudeSessions {
    $inventory = Get-GuardInventory
    $clients = @(Get-GuardNativeClientProcesses $inventory)
    if (-not $clients.Count) {
        $answer = Get-GuardNativeStatus
        $answer.Ok = $true
        $answer.Message = 'No running Claude Desktop or CLI sessions were found.'
        return $answer
    }
    $stopped = 0
    foreach ($client in $clients) {
        $proc = $null
        try {
            $proc = Get-Process -Id ([int]$client.Id) -ErrorAction SilentlyContinue
            if (-not $proc -or $proc.HasExited) { continue }
            $identity = Get-GuardStartedProcessIdentity $proc ([string]$client.Path)
            Stop-GuardRunningProcesses $inventory $proc $identity
            $stopped++
        } finally {
            if ($proc) { $proc.Dispose() }
        }
    }
    $remaining = @(Get-GuardNativeClientProcesses $inventory)
    if ($remaining.Count) {
        throw "Stopped $stopped process tree(s), but $($remaining.Count) Claude process(es) are still running."
    }
    $answer = Get-GuardNativeStatus
    $answer.Ok = $true
    $answer.Message = "Stopped $stopped Claude process tree(s). " + $answer.Message
    $answer
}

function Start-GuardNativeCli([string]$Path, [string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new($Path)
    $info.UseShellExecute = $false
    $info.WorkingDirectory = (Get-Location).ProviderPath
    $info.Arguments = Get-GuardNativeCliCommandLine $Arguments
    [Diagnostics.Process]::Start($info)
}

try {
    switch ($Mode) {
        'Status' { Get-GuardNativeStatus }
        'StatusCli' { Get-GuardNativeStatus -Cli }
        'Configure' { Set-GuardNativeProtection }
        'Launch' { Invoke-GuardNativeDesktop -Zone $TimeZoneId }
        'LaunchCli' { Invoke-GuardNativeDesktop -Cli -Zone $TimeZoneId -Arguments $CliArguments }
        'Refresh' { Set-GuardNativeProtection -Refresh }
        'RemoveRules' { Remove-GuardNativeProtection }
        'StopClaude' { Stop-GuardClaudeSessions }
    }
} catch {
    $answer = New-GuardResult $_.Exception.Message
    $answer.Ok = $false
    $answer.Firewall = 'Unverified'
    $answer
}
