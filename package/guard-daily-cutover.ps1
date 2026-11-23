# Legacy firewall cutover. The caller owns the firewall setup mutex, persists
# the snapshot before suspending refresh, and verifies closed WFP before retirement.

function Get-GuardLegacyProtectedItem([string]$Path,[switch]$Directory,[switch]$Optional) {
    try { $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch {
        if ($Optional -and $_.CategoryInfo.Category -eq 'ObjectNotFound') { return }
        throw
    }
    if ($item.PSIsContainer -ne $Directory.IsPresent -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'A legacy Guard path has an unexpected type or is a link.'
    }
    $trusted=@('S-1-5-18','S-1-5-32-544')
    $writeRights=[Security.AccessControl.FileSystemRights](
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw 'A legacy Guard path has an untrusted owner.'
    }
    foreach ($access in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($access.AccessControlType -eq 'Allow' -and ($access.FileSystemRights -band $writeRights) -and
            $access.IdentityReference.Value -notin $trusted) {
            throw 'A legacy Guard path can be written by an untrusted account.'
        }
    }
    $item
}

function ConvertFrom-GuardLegacyMarkerBytes([string]$Base64) {
    $bytes=[Convert]::FromBase64String($Base64)
    if ($bytes.Length -gt 32KB -or [Convert]::ToBase64String($bytes) -cne $Base64) {
        throw 'The legacy isolation marker backup is invalid.'
    }
    $stream=[IO.MemoryStream]::new($bytes,$false)
    $reader=[IO.StreamReader]::new($stream)
    try { $marker=$reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop }
    finally { $reader.Dispose() }
    if ($marker.Version -ne 1 -or $marker.Mode -cne 'Active') { throw 'The legacy isolation marker is invalid.' }
    ,$bytes
}

function Get-GuardLegacyMarkerBytes {
    $path=Get-GuardDataPath 'privacy-isolation.json'
    $null=Get-GuardLegacyProtectedItem (Split-Path -Parent $path) -Directory
    $item=Get-GuardLegacyProtectedItem $path -Optional
    if (-not $item) { return }
    if ($item.Length -gt 32KB) { throw 'The legacy isolation marker exceeds its size limit.' }
    $base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
    $null=ConvertFrom-GuardLegacyMarkerBytes $base64
    $base64
}

function Restore-GuardLegacyMarker([string]$Base64) {
    $current=Get-GuardLegacyMarkerBytes
    if ($current -and $current -cne $Base64) { throw 'The legacy isolation marker changed after backup.' }
    if ($current -or -not $Base64) { return }

    $path=Get-GuardDataPath 'privacy-isolation.json'
    $temporary="$path.$([guid]::NewGuid().ToString('N')).tmp"
    $bytes=ConvertFrom-GuardLegacyMarkerBytes $Base64
    $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        $acl=Get-Acl -LiteralPath $temporary -ErrorAction Stop
        $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
        Set-Acl -LiteralPath $temporary -AclObject $acl -ErrorAction Stop
        $null=Get-GuardLegacyProtectedItem $temporary
        [IO.File]::Move($temporary,$path)
    } finally { [IO.File]::Delete($temporary) }
}

function Get-GuardLegacyRegularRuleNames {
    $path=Get-GuardStatePath
    $null=Get-GuardLegacyProtectedItem (Split-Path -Parent $path) -Directory
    if (Get-GuardLegacyProtectedItem (Get-GuardDataPath 'firewall-transaction.json') -Optional) {
        throw 'A legacy firewall transaction is pending.'
    }
    $null=Get-GuardLegacyProtectedItem $path
    $state=[IO.File]::ReadAllText($path) | ConvertFrom-Json -ErrorAction Stop
    $names=@($state.Rules)
    $pattern='\A{0}-[a-f0-9]{{32}}-[0-9]+\z' -f [regex]::Escape($script:GuardRulePrefix)
    if ($state.Version -ne 2 -or -not $names.Count -or
        @($names | Where-Object { $_ -isnot [string] -or $_ -notmatch $pattern }).Count -or
        @($names | Sort-Object -Unique).Count -ne $names.Count) {
        throw 'The legacy firewall state does not identify a unique set of rules.'
    }
    $names
}

function Get-GuardLegacyRuleMap([string]$PolicyStore,[string[]]$RegularNames) {
    $rules=@{}
    $regularPattern='\A{0}-[a-f0-9]{{32}}-[0-9]+\z' -f [regex]::Escape($script:GuardRulePrefix)
    $managedPattern='\A{0}[a-f0-9]{{64}}\z' -f [regex]::Escape($script:GuardIsolationPrefix)
    $historicalPattern='\A{0}[CD]-(?:In|Out)\z' -f [regex]::Escape($script:GuardLegacyIsolationPrefix)
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore $PolicyStore -ErrorAction Stop)) {
        $name=[string]$rule.Name
        if ($name -in $RegularNames) {
            $owned=$rule.Direction -eq 'Outbound' -and $rule.DisplayName -like 'Claude Guard: block on *' -and -not $rule.Group
        } elseif ($name -match $managedPattern) {
            $owned=$rule.Group -eq 'Claude Desktop Privacy Isolation' -and $rule.DisplayName -eq $rule.Group -and
                $rule.Direction -in @('Inbound','Outbound')
        } elseif ($name -match $historicalPattern) {
            $direction=if ($name.EndsWith('-In',[StringComparison]::OrdinalIgnoreCase)) { 'Inbound' } else { 'Outbound' }
            $owned=$rule.Group -eq 'Claude Desktop Emergency Privacy Isolation' -and $rule.Direction -eq $direction
        } else {
            if ([string]$rule.Enabled -ne 'False' -and
                (($name -match $regularPattern -and $rule.DisplayName -like 'Claude Guard: block on *') -or
                $name -like "$script:GuardIsolationPrefix*" -or $name -like "$script:GuardLegacyIsolationPrefix*")) {
                throw "An unexpected enabled legacy firewall rule exists in $PolicyStore."
            }
            continue
        }
        if (-not $owned -or $rule.InstanceID -ne $name -or $rules.ContainsKey($name) -or
            $rule.PolicyStoreSourceType -ne 'Local' -or $rule.PolicyStoreSource -ne 'PersistentStore' -or
            $rule.Action -ne 'Block' -or $rule.Profile -ne 'Any' -or [string]$rule.Enabled -notin @('True','False')) {
            throw "A legacy firewall rule has an unexpected identity in $PolicyStore."
        }
        $rules[$name]=$rule
    }
    if ($PolicyStore -eq 'PersistentStore' -and @($RegularNames | Where-Object { -not $rules.ContainsKey($_) }).Count) {
        throw 'A recorded legacy firewall rule is missing from PersistentStore.'
    }
    $rules
}

function Get-GuardLegacySnapshotRegularNames($Snapshot) {
    if ($Snapshot.Version -ne 1 -or -not @($Snapshot.Rules | Where-Object { $_ }).Count -or
        -not $Snapshot.PSObject.Properties['MarkerBytes'] -or
        $Snapshot.Task.Enabled -isnot [bool] -or $Snapshot.Task.WasRunning -isnot [bool] -or
        ($Snapshot.Task.WasRunning -and -not $Snapshot.Task.Enabled)) {
        throw 'The legacy protection snapshot is invalid.'
    }
    if ($null -ne $Snapshot.MarkerBytes) { $null=ConvertFrom-GuardLegacyMarkerBytes $Snapshot.MarkerBytes }
    $regular=@(Get-GuardLegacyRegularRuleNames)
    $names=@($Snapshot.Rules | ForEach-Object { $_.Name })
    if (@($names | Sort-Object -Unique).Count -ne $names.Count -or
        @($regular | Where-Object { $_ -notin $names }).Count -or
        @($Snapshot.Rules | Where-Object { $_.Enabled -cnotin @('True','False') }).Count) {
        throw 'The legacy rule list changed after backup.'
    }
    $regular
}

function Assert-GuardLegacyRuleStates($Snapshot,[hashtable]$Rules,[string]$PolicyStore,[switch]$Retired,[switch]$ValidateOnly) {
    $names=@($Snapshot.Rules | ForEach-Object { $_.Name })
    if (@($Rules.Keys | Where-Object { $_ -notin $names }).Count) {
        throw "The legacy firewall scope changed in $PolicyStore."
    }
    foreach ($original in $Snapshot.Rules) {
        $current=$Rules[$original.Name]
        $expected=if ($Retired) { 'False' } else { $original.Enabled }
        if (-not $current) {
            if ($PolicyStore -eq 'PersistentStore' -or (-not $ValidateOnly -and $expected -eq 'True')) {
                throw "A recorded legacy firewall rule is missing from $PolicyStore."
            }
        } elseif (-not $ValidateOnly -and [string]$current.Enabled -cne $expected) {
            throw "A legacy firewall rule has an unexpected enabled state in $PolicyStore."
        }
    }
}

function Get-GuardLegacyRefreshTask($Pin) {
    $name='ClaudeVPNGuard Auto Refresh'
    $taskPath='\'
    $tasks=@(Get-ScheduledTask -TaskName $name -TaskPath $taskPath -ErrorAction Stop)
    if ($tasks.Count -ne 1) { throw 'The scheduled task could not be uniquely identified.' }
    $task=$tasks[0]
    $runtime=Get-GuardDataPath 'auto-refresh'
    $scriptPath=Join-Path $runtime 'guard-autorefresh.ps1'
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $scriptPath
    $owner=[string]$task.Principal.UserId
    if ($owner -notmatch '^S-1-') {
        $owner=([Security.Principal.NTAccount]$owner).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    $expectedOwner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($task.TaskName -cne $name -or $task.TaskPath -cne $taskPath -or $owner -ne $expectedOwner -or
        $task.Principal.RunLevel -ne 'Highest' -or $task.Principal.LogonType -ne 'S4U' -or
        $task.Settings.MultipleInstances -ne 'IgnoreNew' -or $task.Settings.Enabled -isnot [bool] -or
        $task.State -notin @('Ready','Disabled','Queued','Running') -or @($task.Actions).Count -ne 1 -or
        $task.Actions[0].Execute -ine $shell -or $task.Actions[0].Arguments -ine $arguments -or
        $task.Actions[0].WorkingDirectory) {
        throw 'The legacy refresh task has an unexpected configuration.'
    }
    $null=Get-GuardLegacyProtectedItem (Split-Path -Parent $runtime) -Directory
    $null=Get-GuardLegacyProtectedItem $runtime -Directory
    $null=Get-GuardLegacyProtectedItem $scriptPath
    $hash=(Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($Pin -and ($Pin.TaskName -cne $name -or $Pin.TaskPath -cne $taskPath -or
        $Pin.ScriptPath -ine $scriptPath -or $Pin.ScriptHash -cne $hash -or $Pin.PrincipalSid -cne $owner)) {
        throw 'The legacy refresh task changed after backup.'
    }
    [pscustomobject]@{
        TaskName=$name;TaskPath=$taskPath;ScriptPath=$scriptPath;ScriptHash=$hash;PrincipalSid=$owner
        Enabled=$task.Settings.Enabled;State=[string]$task.State;WasRunning=($task.State -eq 'Running')
    }
}

function Test-GuardLegacyRefreshIdle($Task) {
    if ($Task.Enabled -or $Task.State -ne 'Disabled') { return $false }
    # A child of the stopped watcher must leave while the caller still owns the mutex.
    $watcher=[regex]::Escape($Task.ScriptPath)
    $worker=[regex]::Escape((Join-Path (Split-Path -Parent $Task.ScriptPath) 'setup-firewall.ps1'))
    $pattern='(?:^|\s)-File\s+"(?:{0}"(?:\s|$)|{1}"\s+-NonInteractive\s+-Background\s+-RefreshId\s+[a-f0-9-]{{36}}(?:\s|$))' -f $watcher,$worker
    foreach ($process in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop)) {
        if ($process.CommandLine -match $pattern) { return $false }
    }
    $true
}

function New-GuardLegacyProtectionSnapshot {
    $regular=@(Get-GuardLegacyRegularRuleNames)
    $saved=Get-GuardLegacyRuleMap PersistentStore $regular
    $active=Get-GuardLegacyRuleMap ActiveStore $regular
    $marker=Get-GuardLegacyMarkerBytes
    $task=Get-GuardLegacyRefreshTask
    $enabledState=$task.State -in @('Ready','Running')
    if ($task.State -eq 'Queued' -or $task.Enabled -ne $enabledState) {
        throw 'The legacy refresh task is not in a stable state for backup.'
    }
    $rules=@(foreach ($name in @($saved.Keys | Sort-Object)) {
        [pscustomobject]@{Name=$name;Enabled=[string]$saved[$name].Enabled}
    })
    $snapshot=[pscustomobject]@{Version=1;Rules=$rules;MarkerBytes=$marker;Task=$task}
    Assert-GuardLegacyRuleStates $snapshot $active ActiveStore
    if (-not @($rules | Where-Object { $_.Name -notin $regular -and $_.Enabled -eq 'True' }).Count -or
        (Get-GuardIsolationMode) -ne 'Active') {
        throw 'The original emergency isolation could not be confirmed.'
    }
    $snapshot
}

function Stop-GuardLegacyRefresh($Snapshot) {
    if ($Snapshot.Version -ne 1 -or -not $Snapshot.Task) { throw 'The legacy refresh task backup is invalid.' }
    $task=Get-GuardLegacyRefreshTask $Snapshot.Task
    $identity=@{TaskName=$task.TaskName;TaskPath=$task.TaskPath;ErrorAction='Stop'}
    if ($task.Enabled) {
        Disable-ScheduledTask @identity | Out-Null
        $task=Get-GuardLegacyRefreshTask $Snapshot.Task
        if ($task.Enabled) { throw 'The legacy refresh task could not be disabled.' }
    }
    if ($task.State -in @('Running','Queued')) {
        try { Stop-ScheduledTask @identity | Out-Null }
        catch {
            $task=Get-GuardLegacyRefreshTask $Snapshot.Task
            if ($task.State -ne 'Disabled') { throw }
        }
    }
    $wait=[Diagnostics.Stopwatch]::StartNew()
    do {
        if (Test-GuardLegacyRefreshIdle (Get-GuardLegacyRefreshTask $Snapshot.Task)) { return }
        Start-Sleep -Milliseconds 250
    } while ($wait.Elapsed.TotalSeconds -lt 30)
    throw 'The legacy refresh task or its worker did not stop.'
}

function Disable-GuardLegacyBlocks($Snapshot) {
    $regular=@(Get-GuardLegacySnapshotRegularNames $Snapshot)
    if (-not (Test-GuardLegacyRefreshIdle (Get-GuardLegacyRefreshTask $Snapshot.Task))) {
        throw 'The legacy refresh task is still active.'
    }
    $marker=Get-GuardLegacyMarkerBytes
    if ($marker -and $marker -cne $Snapshot.MarkerBytes) { throw 'The legacy isolation marker changed after backup.' }
    $saved=Get-GuardLegacyRuleMap PersistentStore $regular
    $active=Get-GuardLegacyRuleMap ActiveStore $regular
    Assert-GuardLegacyRuleStates $Snapshot $saved PersistentStore -ValidateOnly
    Assert-GuardLegacyRuleStates $Snapshot $active ActiveStore -ValidateOnly
    $enabled=@($saved.Values | Where-Object { [string]$_.Enabled -eq 'True' } | ForEach-Object { $_.Name })
    if ($enabled.Count) {
        Set-NetFirewallRule -Name $enabled -PolicyStore PersistentStore -Enabled False -ErrorAction Stop | Out-Null
    }
    $marker=Get-GuardLegacyMarkerBytes
    if ($marker) {
        if ($marker -cne $Snapshot.MarkerBytes) { throw 'The legacy isolation marker changed after backup.' }
        [IO.File]::Delete((Get-GuardDataPath 'privacy-isolation.json'))
    }
}

function Test-GuardLegacyBlocksRetired($Snapshot) {
    $regular=@(Get-GuardLegacySnapshotRegularNames $Snapshot)
    foreach ($store in @('PersistentStore','ActiveStore')) {
        Assert-GuardLegacyRuleStates $Snapshot (Get-GuardLegacyRuleMap $store $regular) $store -Retired
    }
    if ((Get-GuardIsolationMode) -ne 'Off' -or (Get-GuardLegacyMarkerBytes) -or
        -not (Test-GuardLegacyRefreshIdle (Get-GuardLegacyRefreshTask $Snapshot.Task))) {
        throw 'The legacy isolation hold or refresh task is still active.'
    }
    $true
}

function Restore-GuardLegacyProtection($Snapshot) {
    $regular=@(Get-GuardLegacySnapshotRegularNames $Snapshot)
    $saved=Get-GuardLegacyRuleMap PersistentStore $regular
    $active=Get-GuardLegacyRuleMap ActiveStore $regular
    Assert-GuardLegacyRuleStates $Snapshot $saved PersistentStore -ValidateOnly
    Assert-GuardLegacyRuleStates $Snapshot $active ActiveStore -ValidateOnly
    Restore-GuardLegacyMarker $Snapshot.MarkerBytes
    foreach ($enabled in @('True','False')) {
        $names=@($Snapshot.Rules | Where-Object { $_.Enabled -ceq $enabled -and [string]$saved[$_.Name].Enabled -cne $enabled } |
            ForEach-Object { $_.Name })
        if ($names.Count) {
            Set-NetFirewallRule -Name $names -PolicyStore PersistentStore -Enabled $enabled -ErrorAction Stop | Out-Null
        }
    }
    foreach ($store in @('PersistentStore','ActiveStore')) {
        Assert-GuardLegacyRuleStates $Snapshot (Get-GuardLegacyRuleMap $store $regular) $store
    }
    if ((Get-GuardLegacyMarkerBytes) -cne $Snapshot.MarkerBytes -or (Get-GuardIsolationMode) -ne 'Active') {
        throw 'The restored legacy isolation hold could not be verified.'
    }
    Assert-GuardProfiles
    $inventory=Get-GuardInventory -LocalOnly
    $verifiedNames=@(Get-GuardIsolationSpecifications $inventory | ForEach-Object Name | Sort-Object)
    $null=Assert-GuardIsolationRules $inventory
    $currentNames=@(Get-GuardIsolationSpecifications (Get-GuardInventory -LocalOnly) | ForEach-Object Name | Sort-Object)
    if (($verifiedNames -join '|') -cne ($currentNames -join '|')) {
        throw 'Claude isolation coverage changed while verifying restoration.'
    }

    $task=Get-GuardLegacyRefreshTask $Snapshot.Task
    $identity=@{TaskName=$task.TaskName;TaskPath=$task.TaskPath;ErrorAction='Stop'}
    if (-not $Snapshot.Task.Enabled) {
        Stop-GuardLegacyRefresh $Snapshot
        return $true
    }
    if (-not $task.Enabled) {
        Enable-ScheduledTask @identity | Out-Null
        $task=Get-GuardLegacyRefreshTask $Snapshot.Task
        if (-not $task.Enabled) { throw 'The restored legacy refresh task is not enabled.' }
    }
    if ($Snapshot.Task.WasRunning -and $task.State -notin @('Queued','Running')) {
        Start-ScheduledTask @identity | Out-Null
    }
    $wait=[Diagnostics.Stopwatch]::StartNew()
    do {
        $task=Get-GuardLegacyRefreshTask $Snapshot.Task
        if ($task.Enabled -and (-not $Snapshot.Task.WasRunning -or $task.WasRunning)) { return $true }
        Start-Sleep -Milliseconds 250
    } while ($wait.Elapsed.TotalSeconds -lt 30)
    throw 'The restored legacy refresh task could not be verified.'
}
