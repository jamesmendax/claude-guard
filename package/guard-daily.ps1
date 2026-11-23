# Daily Desktop state shared by the status check, launcher and refresh task.
. "$PSScriptRoot\guard-lookup-preferences.ps1"
$script:GuardDailyMaxLeaseSeconds=15
$script:GuardDailyLaunchMutex='Global\ClaudeVPNGuard_LaunchSession'
$script:GuardDailyRevisionEvent='Global\ClaudeVPNGuard_DailyRevision'
$script:GuardVlessKeys=@('type','network','server','port','uuid','tls','servername','flow','client-fingerprint','udp','reality-opts')

function Test-GuardDailyScopeBinding($Record) {
    if([string]$Record.ScopeSid -cnotmatch '\AS-1-15-2-(?:[0-9]+-){6}[0-9]+\z'){return $false}
    if($Record.Containment -ceq 'Sandboxie'){return $Record.ScopeName -ceq 'GuardDesktop'}
    if($Record.Containment -and $Record.Containment -cne 'AppContainer'){return $false}
    [string]$Record.ScopeName -cmatch '\Aclaude-guard-[a-f0-9]{32}\z'
}

function Test-GuardDailyRevisionInProgress {
    try{$event=[Threading.EventWaitHandle]::OpenExisting($script:GuardDailyRevisionEvent)}
    catch [Threading.WaitHandleCannotBeOpenedException]{return $false}
    catch [UnauthorizedAccessException]{return $true}
    try{return $true}finally{$event.Dispose()}
}

function Test-GuardDailyReleasePending {
    try{
        $null=Get-Item -LiteralPath (Get-GuardDataPath 'release-install-pending.json') -Force -ErrorAction Stop
        $true
    }catch{
        $_.CategoryInfo.Category -ne 'ObjectNotFound'
    }
}

function Get-GuardDailyReleaseImageHash([string]$Path) {
    if(-not [IO.Path]::IsPathRooted($Path) -or [IO.Path]::GetFullPath($Path) -ine $Path -or
        [IO.Path]::GetFileName($Path) -cne 'ClaudeGuardSetup.exe'){
        throw 'The Guard launcher is outside the protected installation.'
    }
    $stage=Split-Path -Parent $Path
    $root=Split-Path -Parent (Get-GuardDataPath 'release-install-pending.json')
    $leaf=Split-Path -Leaf $stage
    if((Split-Path -Parent $stage) -ine $root -or $leaf -cnotmatch '\Arelease-install-[a-f0-9]{32}\z'){
        throw 'The Guard launcher is outside the protected installation.'
    }
    foreach($item in $root,$stage,$Path){Assert-GuardDailyStatePath $item}
    $sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    if($sha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $leaf -cne ('release-install-'+$sha256.Substring(0,32).ToLowerInvariant())){
        throw 'The protected Guard launcher does not match its stage.'
    }
    $sha256
}

function Test-GuardDailyReleaseControllerMayRun {
    if(-not (Test-GuardDailyReleasePending)){return $true}
    $installer=$null
    try{
        if(-not (Test-GuardDailyRevisionInProgress)){return $false}
        $pending=Read-GuardDailyRecord 'release-install-pending.json'
        if($pending.Version -notin 1,2 -or
            $pending.Stage -cnotmatch '\Arelease-install-[a-f0-9]{32}\z' -or
            $pending.Operation -cnotmatch '\A[a-f0-9]{32}\z' -or
            $pending.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
            $pending.RunnerPid -le 0 -or $pending.RunnerStartedUtc -isnot [string]){
            return $false
        }
        $installer=Get-Process -Id ([int]$pending.RunnerPid) -ErrorAction Stop
        if($installer.HasExited -or $installer.StartTime.ToUniversalTime().ToString('o') -cne $pending.RunnerStartedUtc){
            return $false
        }
        if($pending.Version -eq 1){
            $legacyShell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
            return $installer.ProcessName -ceq 'powershell' -and $installer.Path -ieq $legacyShell
        }
        $path=Get-GuardDataPath ($pending.Stage+'\ClaudeGuardSetup.exe')
        if($installer.Path -ine $path -or $pending.RunnerSha256 -cnotmatch '\A[A-F0-9]{64}\z'){return $false}
        $identity=@($pending.Operation,$pending.RunnerPid,$pending.RunnerStartedUtc,$path,$pending.RunnerSha256) -join '|'
        # Every check confirms the live process identity. Hash the administrator-owned image once per runner.
        if($script:GuardDailyReleaseRunnerVerified -cne $identity){
            if((Get-GuardDailyReleaseImageHash $path) -cne $pending.RunnerSha256){return $false}
            $owned=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$pending.RunnerPid) -OperationTimeoutSec 3 -ErrorAction Stop
            $owner=Invoke-CimMethod -InputObject $owned -MethodName GetOwnerSid -OperationTimeoutSec 3 -ErrorAction Stop
            if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $pending.OwnerSid){return $false}
            $script:GuardDailyReleaseRunnerVerified=$identity
        }
        $true
    }catch{$false}
    finally{if($installer){$installer.Dispose()}}
}

function Test-GuardDailyLaunchSessionBusy {
    $rights=[Security.AccessControl.MutexRights]::Synchronize -bor [Security.AccessControl.MutexRights]::Modify
    try{
        $mutex=if($PSVersionTable.PSEdition -ceq 'Core'){[Threading.MutexAcl]::OpenExisting($script:GuardDailyLaunchMutex,$rights)}
            else{[Threading.Mutex]::OpenExisting($script:GuardDailyLaunchMutex,$rights)}
    }
    catch [Threading.WaitHandleCannotBeOpenedException]{return $false}
    $owned=$false
    try{
        try{$owned=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$owned=$true;return $true}
        return (-not $owned)
    }finally{
        if($owned){$mutex.ReleaseMutex()}
        $mutex.Dispose()
    }
}

function Open-GuardDailyCloseSignal([string]$Name,[Security.AccessControl.EventWaitHandleRights]$Rights) {
    if($PSVersionTable.PSEdition -ceq 'Core'){[Threading.EventWaitHandleAcl]::OpenExisting($Name,$Rights)}
    else{[Threading.EventWaitHandle]::OpenExisting($Name,$Rights)}
}

function Get-GuardDailyDecision($State,[datetime]$NowUtc=[datetime]::UtcNow) {
    $result=[ordered]@{Readiness='Locked';CanLaunch=$false;Reason='StateUnknown';ProxyPort=0}
    if ($State.Isolation -ceq 'Active') {
        $result.Readiness='Emergency'
        $result.Reason='IsolationActive'
    } elseif ($State.Isolation -ceq 'Off' -and $State.Mode -ceq 'Daily') {
        if ($State.Policy -cne 'Verified' -or $State.Inventory -cne 'Verified') {
            $result.Reason='CoverageUnverified'
        } elseif ($State.Proxy -ceq 'Down') {
            $result.Readiness='WaitingForProxy'
            $result.Reason=if($State.Failure){$State.Failure}else{'ProxyNotReady'}
        } elseif ($State.Exit -ceq 'Mismatch') {
            $result.Reason='ExitChanged'
        } elseif ($State.Terminating) {
            $result.Reason='ShutdownPending'
        } elseif ($State.Session -ceq 'Rechecking') {
            $result.Readiness='Rechecking'
            $result.Reason='ProofPending'
        } elseif ($State.Exit -cne 'Match') {
            $result.Reason='ExitUnverified'
        } elseif ($State.Session -cnotin @('Clear','Active')) {
            $result.Reason='ShutdownPending'
        } elseif ($State.Proxy -cne 'Ready') {
            $result.Readiness='WaitingForProxy'
            $result.Reason='ProxyNotReady'
        } elseif ($State.Gate -cne 'Open') {
            $result.Reason='NetworkGateClosed'
        } else {
            $observed=[datetime]::MinValue
            $expires=[datetime]::MinValue
            $style=[Globalization.DateTimeStyles]::RoundtripKind
            $culture=[Globalization.CultureInfo]::InvariantCulture
            $validDates=[datetime]::TryParseExact([string]$State.Lease.CheckedUtc,'o',$culture,$style,[ref]$observed) -and
                [datetime]::TryParseExact([string]$State.Lease.ExpiresUtc,'o',$culture,$style,[ref]$expires)
            $port=0
            if ([string]$State.Generation -notmatch '^[A-Fa-f0-9]{64}$' -or
                $State.Generation -cne $State.Lease.Generation -or
                -not $validDates -or $observed.Kind -eq 'Unspecified' -or $expires.Kind -eq 'Unspecified' -or
                $observed.ToUniversalTime() -gt $NowUtc.ToUniversalTime() -or $expires.ToUniversalTime() -le $NowUtc.ToUniversalTime() -or
                ($expires.ToUniversalTime()-$observed.ToUniversalTime()).TotalSeconds -gt $script:GuardDailyMaxLeaseSeconds) {
                $result.Reason='HealthLeaseInvalid'
            } elseif (-not [int]::TryParse([string]$State.Port,[ref]$port) -or $port -lt 1024 -or $port -gt 49151) {
                $result.Reason='ProxyPortInvalid'
            } else {
                $result.Readiness='Ready'
                $result.CanLaunch=$true
                $result.Reason='Verified'
                $result.ProxyPort=$port
            }
        }
    }
    [pscustomobject]$result
}

function Read-GuardBettboxVlessNode([string]$ProfileText,[string]$SelectedName) {
    # The installed profile uses block-form YAML. Reject other forms instead of
    # reinterpreting them. No YAML tags, overrides, aliases or provider expansion.
    if (-not $SelectedName -or $ProfileText.Length -gt 2MB) { throw 'Bettbox selection is missing or oversized.' }
    $sections=[regex]::Matches($ProfileText,'(?ms)^proxies:[ \t]*\r?\n(.*?)(?=^\S|\z)')
    if ($sections.Count -ne 1) { throw 'Expected a single block-form proxies section.' }
    $found=@()
    foreach ($block in [regex]::Split($sections[0].Groups[1].Value,'(?m)(?=^  - )')) {
        if (-not $block.Trim()) { continue }
        $first=[regex]::Match($block,'^  - name: (?<name>[^\r\n]+)')
        if (-not $first.Success) { continue }
        $name=$first.Groups['name'].Value.Trim().Trim('"',"'")
        if ($name -ceq $SelectedName) { $found+=,$block }
    }
    if ($found.Count -ne 1) { throw 'The saved Bettbox selection did not identify exactly one supported node.' }
    $node=@{}
    $reality=$null
    foreach ($line in @($found[0] -split '\r?\n' | Select-Object -Skip 1)) {
        if (-not $line.Trim()) { continue }
        if ($line -ceq '    reality-opts:') {
            if ($node.ContainsKey('reality-opts')) { throw 'Duplicate Reality settings.' }
            $reality=@{}
            $node['reality-opts']=$reality
            continue
        }
        $field=[regex]::Match($line,'^(?<indent> {4}| {6})(?<key>[a-z][a-z0-9-]*): (?<value>\S.*?)\s*$')
        if (-not $field.Success) { throw 'Unsupported structure in the selected Bettbox node.' }
        $key=$field.Groups['key'].Value
        $map=$node
        if ($field.Groups['indent'].Length -eq 6) {
            if ($null -eq $reality -or $key -notin @('public-key','short-id')) { throw 'Unsupported nested proxy field.' }
            $map=$reality
        } else {
            $reality=$null
            if ($key -cnotin $script:GuardVlessKeys -or $key -ceq 'reality-opts') { throw 'Unsupported proxy field.' }
        }
        if ($map.ContainsKey($key)) { throw 'Duplicate field in the selected Bettbox node.' }
        $value=$field.Groups['value'].Value
        if ($value -match '^(?:"[a-zA-Z0-9_.:-]*"|''[a-zA-Z0-9_.:-]*''|[a-zA-Z0-9_.:-]+)$') {
            $value=$value.Trim('"',"'")
        } else { throw 'Unsupported scalar in the selected Bettbox node.' }
        $map[$key]=switch ($key) {
            port {
                $number=0
                if (-not [int]::TryParse($value,[ref]$number)) { throw 'Invalid proxy port.' }
                $number
            }
            { $_ -in 'tls','udp' } {
                if ($value -cnotin 'true','false') { throw 'Invalid proxy boolean.' }
                $value -ceq 'true'
            }
            default { $value }
        }
    }
    $node
}

function New-GuardDedicatedProxyConfig([System.Collections.IDictionary]$Node,[int]$Port) {
    if (-not $Node -or @($Node.Keys | Where-Object { $_ -cnotin $script:GuardVlessKeys }).Count -or $Port -lt 1024 -or $Port -gt 49151) {
        throw 'Unsupported dedicated proxy configuration.'
    }
    $ip=$null
    $id=[guid]::Empty
    $remotePort=0
    if ($Node.type -cne 'vless' -or $Node.network -cne 'tcp' -or $Node.tls -isnot [bool] -or -not $Node.tls -or
        -not [ipaddress]::TryParse([string]$Node.server,[ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or
        $ip.ToString() -cne $Node.server -or [ipaddress]::IsLoopback($ip) -or $ip.GetAddressBytes()[0] -in @(0) -or $ip.GetAddressBytes()[0] -ge 224 -or
        -not [int]::TryParse([string]$Node.port,[ref]$remotePort) -or $remotePort -lt 1 -or $remotePort -gt 65535 -or
        -not [guid]::TryParseExact([string]$Node.uuid,'D',[ref]$id) -or $id -eq [guid]::Empty -or
        [Uri]::CheckHostName([string]$Node.servername) -ne [UriHostNameType]::Dns -or
        $Node.flow -cnotin '','xtls-rprx-vision',$null -or [string]$Node.'client-fingerprint' -notmatch '^[a-z][a-z0-9-]{0,30}$') {
        throw 'The dedicated route requires a pinned IPv4 and VLESS TCP with verified TLS identity.'
    }
    $reality=$Node['reality-opts']
    if ($reality -isnot [System.Collections.IDictionary] -or @($reality.Keys).Count -ne 2 -or
        [string]$reality.'public-key' -cnotmatch '^[A-Za-z0-9_-]{43}$' -or [string]$reality.'short-id' -cnotmatch '^(?:[0-9a-fA-F]{2}){0,8}$') {
        throw 'Invalid Reality identity settings.'
    }
    $proxy=[ordered]@{name='guard-pinned';type='vless';network='tcp';server=$ip.ToString();port=$remotePort
        uuid=$id.ToString();tls=$true;servername=$Node.servername;'client-fingerprint'=$Node.'client-fingerprint';udp=$false
        'reality-opts'=[ordered]@{'public-key'=$reality.'public-key';'short-id'=[string]$reality.'short-id'}}
    if ($Node.flow) { $proxy.flow=$Node.flow }
    [ordered]@{
        'mixed-port'=$Port;'allow-lan'=$false;'bind-address'='127.0.0.1';mode='rule';ipv6=$false
        'find-process-mode'='off';'log-level'='silent'
        tun=@{enable=$false};dns=@{enable=$false}
        proxies=@($proxy);rules=@('MATCH,guard-pinned')
    }
}

function Test-GuardDailyDesktopImages($Approved,$Current) {
    $expected=@($Approved | Sort-Object Path)
    $found=@($Current | Sort-Object Path)
    if(-not $expected.Count -or $expected.Count -ne $found.Count){return $false}
    for($i=0;$i -lt $expected.Count;$i++){
        if(-not $expected[$i].Path -or $expected[$i].Path -ine $found[$i].Path -or
            [string]$expected[$i].Hash -cnotmatch '^[A-F0-9]{64}$' -or $expected[$i].Hash -cne $found[$i].Hash){
            return $false
        }
    }
    $true
}

function Resolve-GuardServiceSid([string]$Name) {
    ([Security.Principal.NTAccount]::new('NT SERVICE',$Name)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-GuardDailyServiceSids {
    foreach($name in 'CoworkVMServiceStore','CoworkVMService'){
        try{
            $config=Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction Stop
        }catch [Management.Automation.ItemNotFoundException]{continue}
        if(-not ($config.Type -band 0x10) -or ($config.Type -band 0x20) -or $config.ServiceSidType -notin 1,3){
            throw "The installed $name service has no dedicated service identity for network protection."
        }
        Resolve-GuardServiceSid $name
    }
}

function Get-GuardDailyStoreService($Inventory,[string]$PackageRoot) {
    $name='CoworkVMServiceStore'
    $path=Join-Path $PackageRoot 'app\resources\cowork-svc.exe'
    if($path -notin @($Inventory.Programs) -or $path -in @($Inventory.DesktopPaths)){return}
    $service=Get-CimInstance Win32_Service -Filter "Name='$name'" -OperationTimeoutSec 3 -ErrorAction Stop
    if($service.State -ne 'Running' -or $service.ProcessId -le 0 -or $service.StartName -ine 'LocalSystem' -or
        ([string]$service.PathName).Trim('"') -ine $path -or
        (Resolve-GuardServiceSid $name) -notin @(Get-GuardDailyServiceSids)){return}
    # The installed policy blocks the dedicated service SID and this exact
    # program path. It runs in session zero and does not own a Desktop window.
    [pscustomobject]@{Id=[int]$service.ProcessId;Path=$path}
}

function Get-GuardDailyPathDecision($Profile,$Relay,$Observation,[datetime]$NowUtc=[datetime]::UtcNow) {
    $result=[pscustomobject]@{Proxy='Down';Exit='Unverified';Lease=$null;Failure=$null}
    if($Relay.Ready -ne $true -or $Relay.ProcessId -le 0 -or $Relay.Port -ne $Profile.Port -or
        [string]$Profile.Generation -cnotmatch '^[A-F0-9]{64}$' -or
        [string]$Profile.RouteHash -cnotmatch '^[A-F0-9]{64}$' -or $Relay.RouteHash -cne $Profile.RouteHash){
        return $result
    }
    $result.Proxy='Unknown'
    if(-not $Observation -or $Observation.Generation -cne $Profile.Generation -or
        $Observation.RouteHash -cne $Profile.RouteHash -or $Observation.RelayId -ne $Relay.ProcessId -or
        $Observation.RelayStartedUtc -cne $Relay.StartedUtc){return $result}

    $seen=[datetime]::MinValue
    $started=[datetime]::MinValue
    $style=[Globalization.DateTimeStyles]::RoundtripKind
    $culture=[Globalization.CultureInfo]::InvariantCulture
    if(-not [datetime]::TryParseExact([string]$Observation.CheckedUtc,'o',$culture,$style,[ref]$seen) -or
        -not [datetime]::TryParseExact([string]$Relay.StartedUtc,'o',$culture,$style,[ref]$started) -or
        $seen.Kind -ne 'Utc' -or $started.Kind -ne 'Utc' -or $seen -lt $started -or $seen -gt $NowUtc.ToUniversalTime()){
        return $result
    }
    $leaseSeconds=$script:GuardDailyMaxLeaseSeconds
    if($null -ne $Profile.LeaseSeconds){
        $leaseSeconds=0
        if(-not [int]::TryParse([string]$Profile.LeaseSeconds,[ref]$leaseSeconds) -or
            $leaseSeconds -lt 1 -or $leaseSeconds -gt $script:GuardDailyMaxLeaseSeconds){return $result}
    }
    $expires=$seen.AddSeconds($leaseSeconds)
    if($expires -le $NowUtc.ToUniversalTime()){return $result}
    if($Observation.Fault -ceq 'UpstreamTransportDown'){
        $result.Proxy='Down'
        $result.Failure='UpstreamTransportDown'
        return $result
    }
    if($Observation.HttpStatus -ne 200){return $result}

    $observed=$null
    $expected=$null
    if(-not [ipaddress]::TryParse([string]$Observation.Ipv4,[ref]$observed) -or
        -not [ipaddress]::TryParse([string]$Profile.ExpectedIpv4,[ref]$expected) -or
        $observed.AddressFamily -ne 'InterNetwork' -or $expected.AddressFamily -ne 'InterNetwork' -or
        $observed.ToString() -cne $Observation.Ipv4 -or $expected.ToString() -cne $Profile.ExpectedIpv4){
        return $result
    }
    $result.Proxy='Ready'
    $result.Exit=if($observed.Equals($expected)){'Match'}else{'Mismatch'}
    if($result.Exit -ceq 'Match'){
        $result.Lease=@{
            Generation=$Profile.Generation;CheckedUtc=$seen.ToString('o');ExpiresUtc=$expires.ToString('o')
        }
    }
    $result
}

function Stop-GuardDailySession([System.Collections.IDictionary]$Operations) {
    $errors=0
    $unknown=$false
    $blocked=$false
    $confirmedCloseAction=$false
    try { $blocked=(& $Operations.CloseGate) -eq $true } catch { $errors++ }
    $initial=@(try { & $Operations.Snapshot } catch { $errors++; $unknown=$true })
    if($blocked -and $Operations.NotifyClosure){
        try{$null=& $Operations.NotifyClosure}catch{$errors++}
    }
    if ($blocked -and $initial.Count) {
        $identities=@{}
        foreach ($entry in $initial) {
            if (-not $entry.Id -or -not $entry.Start) { $errors++; $unknown=$true; continue }
            $identities[$entry.Id]=$entry.Start
            try {
                $sent=& $Operations.RequestClose $entry
                if($sent -is [bool] -and $sent){$confirmedCloseAction=$true}
            } catch { $errors++ }
        }
        $null=& $Operations.Wait 5000
        $current=@(try{ & $Operations.Snapshot }catch{ $errors++; $unknown=$true })
        foreach ($entry in $current) {
            if (-not $entry.Id -or -not $entry.Start) { $errors++; $unknown=$true; continue }
            $knownIdentity=$identities.ContainsKey($entry.Id)
            if ($knownIdentity -and $identities[$entry.Id] -ne $entry.Start) { continue }
            try {
                $sent=& $Operations.ForceStop $entry
                if($knownIdentity -and $sent -is [bool] -and $sent){$confirmedCloseAction=$true}
            } catch { $errors++ }
        }
    }
    $remaining=@(try { & $Operations.Snapshot } catch { $errors++; $unknown=$true })
    $count=@($remaining | Where-Object Start).Count
    if(@($remaining | Where-Object {-not $_.Start}).Count){$unknown=$true}
    [pscustomobject]@{NetworkBlocked=$blocked;Exited=((-not $count) -and (-not $unknown));Remaining=$count;StopErrors=$errors;UnknownProcesses=$unknown
        ObservedProcess=@($initial | Where-Object Start).Count -gt 0;ConfirmedCloseAction=$confirmedCloseAction}
}

function Invoke-GuardDailyPolicySwitch([System.Collections.IDictionary]$Operations) {
    # Caller owns Global\ClaudeVPNGuard_FirewallSetup. RestoreIsolation must
    # verify both stores and leave the candidate admission handle closed.
    $prior=& $Operations.ReadJournal
    if($prior){
        if($prior.Version -ne 1 -or $prior.BackupId -cnotmatch '^[a-f0-9]{32}$' -or
            $prior.Phase -cnotin 'Prepared','CandidateVerified','ConflictsRetired','ModeWritten'){
            throw 'Invalid daily transition record. Keep candidate admission disabled.'
        }
        if((& $Operations.RestoreIsolation $prior) -ne $true){throw 'Could not verify recovery to emergency isolation.'}
        & $Operations.ClearJournal
        return 'RecoveredIsolation'
    }
    $backupId=& $Operations.SaveBefore
    if($backupId -cnotmatch '^[a-f0-9]{32}$'){throw 'The recovery snapshot was not identified.'}
    $journal=[pscustomobject]@{Version=1;Phase='Prepared';BackupId=$backupId}
    & $Operations.WriteJournal $journal
    try {
        & $Operations.InstallClosedPolicy
        if ((& $Operations.VerifyClosedPolicy) -ne $true) { throw 'New closed policy could not be verified.' }
        $journal.Phase='CandidateVerified'
        & $Operations.WriteJournal $journal
        & $Operations.RetireConflicts
        $journal.Phase='ConflictsRetired'
        & $Operations.WriteJournal $journal
        & $Operations.WriteMode
        $journal.Phase='ModeWritten'
        & $Operations.WriteJournal $journal
        if ((& $Operations.VerifyCommit) -ne $true) { throw 'Committed policy could not be verified.' }
        & $Operations.ClearJournal
    } catch {
        $failure=$_
        if ((& $Operations.RestoreIsolation $journal) -ne $true) {
            throw 'Daily policy switch failed and restored isolation could not be verified. Leave the candidate gate closed.'
        }
        & $Operations.ClearJournal
        throw $failure
    }
    'CommittedClosed'
}

function Read-GuardDailyJsonFile([string]$Path,[switch]$VerifyStatePath) {
    $share=[IO.FileShare]::Read -bor [IO.FileShare]::Delete
    for($attempt=0;;$attempt++){
        try{
            if($VerifyStatePath){Assert-GuardDailyStatePath $Path}
            $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
            break
        }catch{
            $errorBase=$_.Exception.GetBaseException()
            $code=$errorBase.HResult -band 65535
            # Windows can briefly lock or hide the target name during replacement.
            $missing=$errorBase -is [Management.Automation.ItemNotFoundException]
            if($attempt -ge 8 -or (-not $missing -and $code -notin 2,32,33)){throw}
            [Threading.Thread]::Sleep(25)
        }
    }
    try{
        if($stream.Length -gt 32KB){throw 'Daily state exceeded the size limit.'}
        $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true)
        try{$json=$reader.ReadToEnd()}finally{$reader.Dispose()}
    }finally{$stream.Dispose()}
    if($PSVersionTable.PSVersion -ge [version]'7.5'){
        return (ConvertFrom-Json -InputObject $json -DateKind String -ErrorAction Stop)
    }
    ConvertFrom-Json -InputObject $json -ErrorAction Stop
}
function Assert-GuardDailyStatePath([string]$Path) {
    $trusted=@('S-1-5-18','S-1-5-32-544')
    $writeRights=[Security.AccessControl.FileSystemRights](
        [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'An untrusted daily state path was found.'}
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'A daily state owner is untrusted.'}
    foreach($access in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($access.AccessControlType -eq 'Allow' -and
            ($access.FileSystemRights -band $writeRights) -and $access.IdentityReference.Value -notin $trusted){
            throw 'A daily state path is writable outside the controller.'
        }
    }
}
function Read-GuardDailyRecord([string]$Name) {
    $path=Get-GuardDataPath $Name
    Assert-GuardDailyStatePath (Split-Path -Parent $path)
    Read-GuardDailyJsonFile $path -VerifyStatePath
}

function Test-GuardRuleReceipt([string]$Expected,[string]$Actual,[string]$Policy,[string]$Inventory,[string]$Observed,[datetime]$NowUtc) {
    $time=[datetime]::MinValue
    if($Expected -cnotmatch '^[A-F0-9]{64}$' -or $Expected -cne $Actual -or $Policy -cne 'Verified' -or $Inventory -cne 'Verified' -or
        -not [datetime]::TryParseExact($Observed,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$time) -or
        $time.Kind -eq 'Unspecified'){
        return $false
    }
    $age=($NowUtc.ToUniversalTime()-$time.ToUniversalTime()).TotalSeconds
    $age -ge 0 -and $age -lt $script:GuardDailyMaxLeaseSeconds
}

function Test-GuardCurrentGateClosed($Status,[string]$Generation,[string]$CloseName,[datetime]$RequestedUtc) {
    $Status.Policy -ceq 'Verified' -and $Status.Gate -ceq 'Closed' -and
        $Status.Generation -ceq $Generation -and $Status.CloseName -ceq $CloseName -and
        $Status.RulesUtc -is [datetime] -and $Status.RulesUtc -ge $RequestedUtc
}

function Get-GuardDailyCloseName([string]$Id) {
    'Global\ClaudeVPNGuard_DailyClose_'+$Id
}

function Get-GuardDailyStatus([switch]$VerifyDuringRevision) {
    $isolation=Get-GuardIsolationMode
    $state=@{Isolation=$isolation}
    $closeName=$null; $paths=@(); $generation=$null; $configured=$false; $rulesUtc=$null
    $scopeName=$null; $scopeSid=$null; $containment=$null; $supervisorId=$null; $supervisorStartUtc=$null
    if($isolation -eq 'Off'){
        $signal=$null
        $supervisor=$null
        try{
            # An inaccessible record is a transitional fault. Only confirmed
            # absence allows the existing emergency refresh code to run.
            $configured=$true
            try{ $null=Get-Item -LiteralPath (Get-GuardDataPath 'daily-mode.json') -Force -ErrorAction Stop }
            catch{
                if($_.CategoryInfo.Category -eq 'ObjectNotFound'){$configured=$false}
                throw
            }
            $mode=Read-GuardDailyRecord 'daily-mode.json'
            if($mode.Version -ne 2 -or $mode.Mode -cne 'Daily' -or -not (Test-GuardDailyScopeBinding $mode) -or
                [string]$mode.Generation -cnotmatch '^[A-F0-9]{64}$' -or
                [string]$mode.CloseId -cnotmatch '^[a-f0-9]{32}$' -or
                @($mode.DesktopHashes).Count -eq 0 -or @($mode.DesktopHashes | Where-Object { $_ -cnotmatch '^[A-F0-9]{64}$' }).Count){
                throw 'Malformed daily mode record.'
            }
            $state.Mode='Daily'
            if(Test-Path -LiteralPath (Get-GuardDataPath 'daily-package-pending.json')){
                throw 'Store package maintenance is pending.'
            }
            $generation=$mode.Generation
            $paths=@($mode.DesktopHashes)
            $closeName=Get-GuardDailyCloseName $mode.CloseId
            $health=Read-GuardDailyRecord 'daily-health.json'
            if($health.Version -ne 2 -or $health.Generation -cne $mode.Generation -or $health.Port -ne $mode.Port -or
                $health.ScopeName -cne $mode.ScopeName -or $health.ScopeSid -cne $mode.ScopeSid -or
                [string]$health.Containment -cne [string]$mode.Containment){
                throw 'Daily mode and health records disagree.'
            }
            if($health.CloseId -cne $mode.CloseId){throw 'Daily mode and health close events disagree.'}
            $supervisor=Get-Process -Id ([int]$health.SupervisorId) -ErrorAction Stop
            if($supervisor.HasExited -or $supervisor.StartTime.ToUniversalTime().ToString('o') -cne $health.SupervisorStartUtc){
                throw 'The supervisor process identity changed.'
            }
            $supervisorId=$supervisor.Id
            $supervisorStartUtc=$health.SupervisorStartUtc
            $signal=Open-GuardDailyCloseSignal $closeName ([Security.AccessControl.EventWaitHandleRights]::Synchronize)
            if(Test-GuardRuleReceipt $mode.Generation $health.Generation $health.Policy $health.Inventory $health.RulesUtc ([datetime]::UtcNow)){
                $state.Policy='Verified'
                $rulesUtc=[datetime]::ParseExact($health.RulesUtc,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            }else{$state.Policy='Unknown'}
            $state.Inventory=$health.Inventory
            $state.Exit=$health.Exit
            $state.Proxy=$health.Proxy
            $state.Gate=if($signal.WaitOne(0) -and $health.Gate -eq 'Open'){'Closing'}else{$health.Gate}
            $state.Generation=$mode.Generation
            $state.Port=$mode.Port
            $state.Lease=$health.Lease
            $state.AdmissionPeriod=$health.Admission.Period
            $state.Session=$health.Session
            $state.Terminating=$health.Terminating
            $state.Failure=$health.Failure
            $scopeName=$mode.ScopeName
            $scopeSid=$mode.ScopeSid
            $containment=$mode.Containment
        }catch{
            $state.Policy='Unknown'
        }finally{
            if($signal){$signal.Dispose()}
            if($supervisor){$supervisor.Dispose()}
        }
    }
    $result=Get-GuardDailyDecision $state
    if(-not $VerifyDuringRevision -and $result.Readiness -cne 'Emergency' -and ((Test-GuardDailyReleasePending) -or
        ($result.CanLaunch -and (Test-GuardDailyRevisionInProgress)))){
        $result.Readiness='Locked'
        $result.CanLaunch=$false
        $result.Reason='RevisionInProgress'
    }
    $result | Add-Member -NotePropertyMembers @{
        Configured=$configured;Generation=$generation;DesktopHashes=$paths
        ScopeName=$scopeName;ScopeSid=$scopeSid;Containment=$containment
        CloseName=$closeName;Gate=$state.Gate;Policy=$state.Policy;RulesUtc=$rulesUtc
        SupervisorId=$supervisorId;SupervisorStartUtc=$supervisorStartUtc
        LeaseCheckedUtc=$state.Lease.CheckedUtc;AdmissionPeriod=$state.AdmissionPeriod
        Proxy=$state.Proxy;Exit=$state.Exit;Inventory=$state.Inventory
    } -PassThru
}

function Set-GuardDailyAdmission([System.Collections.IDictionary]$State,[System.Collections.IDictionary]$AdmissionOperations) {
    # A controller owns the native dynamic admission handle. It publishes its
    # state only after checking that opening or closing succeeded.
    $State.Gate='Open'
    $result=Get-GuardDailyDecision $State
    if($result.CanLaunch) {
        try{
            if((& $AdmissionOperations.OpenVerified) -eq $true){
                & $AdmissionOperations.Publish $State $result
                return $result
            }
        }catch{
            # Revocation also handles a partially installed or unpublished permit.
        }
    }
    $closed=try{(& $AdmissionOperations.CloseVerified) -eq $true}catch{$false}
    $State.Gate=if($closed){'Closed'}else{'Unknown'}
    if(-not $closed){$State.Policy='Unknown'}
    $result=Get-GuardDailyDecision $State
    & $AdmissionOperations.Publish $State $result
    $result
}


