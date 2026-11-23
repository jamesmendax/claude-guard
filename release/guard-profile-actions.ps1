# Shared by the setup window and its background runspace. No action runs on import.
$packageDirectory=Join-Path (Split-Path -Parent $PSScriptRoot) 'package'
. (Join-Path $packageDirectory 'guard-common.ps1')
. (Join-Path $packageDirectory 'guard-node-profile.ps1')
. (Join-Path $packageDirectory 'guard-profile-store.ps1')
. (Join-Path $packageDirectory 'guard-region-profile.ps1')
. (Join-Path $packageDirectory 'guard-sandboxie.ps1')

function Get-GuardSettingsProbeAssets([string]$Stage){
    $runtime=Join-Path $Stage 'runtime'
    @{
        RelayPath=Join-Path $runtime 'guard-dedicated-relay.exe'
        RelaySha256='CF894375DBC00AB6708C1314AC35BBD29059F4C37F315353AACA7F1A9C566DE6'
        ObserverPath=Join-Path $runtime 'guard-exit-observer.exe'
        ObserverSha256='86FC4785327DB5F5C7558DC6156C543B433C313E813A222E088086222AB4AFA6'
        ObserverScriptPath=Join-Path $runtime 'cloudflare-exit-probe.mjs'
        ObserverScriptSha256='E586ED2C31398A9ACD43AB1E4374611F2C515BFDD24AEF4E0E7027F5D17C3C37'
    }
}

function Get-GuardSettingsNodePreview([string]$Stage,[pscredential]$Profile,[Threading.CancellationToken]$Token){
    $provisioned=Get-GuardDataPath 'daily-provisioned.json'
    $installed=if([IO.File]::Exists($provisioned)){Read-GuardDailyRecord 'daily-provisioned.json'}
    $pinned=if($installed){$installed.VpnGuid}else{
        $adapters=@(Get-GuardNetworkAdapters|Where-Object {$_.Name -ceq 'Bettbox' -and $_.Status -eq 'Up'})
        if($adapters.Count -ne 1){throw 'Connect the Bettbox tunnel before checking the node.'}
        $adapters[0].InterfaceGuid
    }
    $vpn=Get-GuardVpnAdapter ([string]$pinned)
    if($vpn.Name -cne 'Bettbox'){throw 'The active tunnel does not match the approved Bettbox adapter.'}
    $backup=if($installed){Test-GuardDailyBackupLookupEnabled $installed}else{$true}
    Invoke-GuardNodeProbe -Profile $Profile -Assets (Get-GuardSettingsProbeAssets $Stage) -CancellationToken $Token -BackupExitLookup:$backup
}

function Get-GuardSettingsTimeZones([string]$Stage){
    $source=Get-Content -LiteralPath (Join-Path $Stage 'release\guard-region-zones.json') -Encoding UTF8 -Raw -ErrorAction Stop|ConvertFrom-Json
    if($source.Version -ne 1 -or ($source.Territories.JP -join ',') -cne 'Tokyo Standard Time' -or @($source.Territories.US).Count -lt 2){
        throw 'The release time zone catalog is invalid.'
    }
    $installed=@{}
    $items=@(foreach($zone in [TimeZoneInfo]::GetSystemTimeZones()){
        $installed[$zone.Id]=$true
        if($zone.Id -cnotin 'Tokyo Standard Time','Pacific Standard Time'){
            [pscustomobject]@{Id=('Windows/'+$zone.Id);Label=$zone.DisplayName}
        }
    })
    [pscustomobject]@{Territories=$source.Territories;Installed=$installed;Items=$items}
}

function Get-GuardSettingsRegionChoice($Catalog,[string]$Id,[string]$CountryCode){
    $known=@()
    $valid=@()
    if($CountryCode -cmatch '^[A-Z]{2}$'){
        $value=$Catalog.Territories.PSObject.Properties[$CountryCode]
        if($value){$known=@($value.Value);$valid=@($known|Where-Object {$Catalog.Installed.ContainsKey($_)})}
    }
    if($Id -ceq 'Automatic'){
        if($known.Count -ne 1 -or $valid.Count -ne 1){return [pscustomobject]@{RequiresChoice=$true;TimeZoneCount=$known.Count}}
        $zone=$valid[0]
        $Id=if($zone -ceq 'Tokyo Standard Time'){'Japan'}elseif($zone -ceq 'Pacific Standard Time'){'UsPacific'}else{'Windows/'+$zone}
    }
    $profile=Get-GuardRegionProfile $Id
    if(-not $profile.Default -and $known.Count -and $profile.WindowsTimeZoneId -cnotin $known){
        throw 'The selected time zone does not match the observed country.'
    }
    if($profile.CountryCode -and $CountryCode -and $profile.CountryCode -cne $CountryCode){
        # Windows may assign the same time zone to several territories.
        $Id='Windows/'+$profile.WindowsTimeZoneId
    }
    [pscustomobject]@{RequiresChoice=$false;Id=$Id;TimeZoneId=$profile.WindowsTimeZoneId}
}

function Assert-GuardSettingsPreview([pscredential]$Profile,$Proof,[datetimeoffset]$Now=[datetimeoffset]::UtcNow){
    if(-not $Profile -or $Proof.Passed -isnot [bool] -or -not $Proof.Passed -or $Proof.State -cne 'Completed' -or
        $Proof.Provider -cnotin @('CloudflareTrace','Ipify')){throw 'Verify the node before applying it.'}
    $ip=$null
    if(-not [ipaddress]::TryParse([string]$Proof.ExitIpv4,[ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or $ip.ToString() -cne $Proof.ExitIpv4){
        throw 'The node must have a verified IPv4 exit.'
    }
    $checked=[datetimeoffset]::MinValue
    if(-not [datetimeoffset]::TryParse([string]$Proof.CheckedUtc,[Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,[ref]$checked) -or $checked -gt $Now -or ($Now-$checked).TotalMinutes -gt 5){
        throw 'The node check expired. Check its exit again.'
    }
    $route=Get-GuardNodeProfileRoute -Profile $Profile -Port 18881
    if($route.ProfileFingerprint -cne $Proof.ProfileFingerprint){throw 'The entered node has changed since the exit check.'}
}

function New-GuardSettingsNodeOperations($RegionPlan,$RegionOperations,[string]$ExpectedFingerprint){
    $context=@{Snapshot=$null}
    $snapshot={
        $context.Snapshot=[pscustomobject]@{Version=1;Node=(Get-GuardNodeStoreSnapshot);Region=$RegionPlan}
        $context.Snapshot
    }.GetNewClosure()
    # The installation backend flushes this snapshot to its protected journal before Apply.
    $persist={param($pending)
        if(-not $context.Snapshot -or $pending.ProfileId -cne $context.Snapshot.Region.ProfileId -or
            $pending.CurrentTimeZoneId -cne $context.Snapshot.Region.CurrentTimeZoneId){
            throw 'The saved Windows settings do not match the preview.'
        }
    }.GetNewClosure()
    $apply={
        param([pscredential]$Selection)
        if(-not $context.Snapshot -or -not $ExpectedFingerprint -or
            (Get-GuardNodeProfileRoute -Profile $Selection -Port 18881).ProfileFingerprint -cne $ExpectedFingerprint){
            throw 'The node does not match its protected transaction.'
        }
        Save-GuardNodeProfile $Selection
        $null=Invoke-GuardRegionProfileChange -Plan $RegionPlan -Operations $RegionOperations -PersistUndo $persist
    }.GetNewClosure()
    $restore={
        param($saved)
        if($saved.Version -ne 1 -or -not $saved.Node -or -not $saved.Region){throw 'Invalid protected settings recovery record.'}
        $failed=$false
        try{Restore-GuardNodeStoreSnapshot $saved.Node}catch{$failed=$true}
        try{$null=Undo-GuardRegionProfileChange -Plan $saved.Region -Operations $RegionOperations}catch{$failed=$true}
        if($failed){throw 'The encrypted node or Windows time zone could not be restored.'}
    }.GetNewClosure()
    @{Snapshot=$snapshot;Apply=$apply;Restore=$restore}
}

function Test-GuardSetupShortcut([string]$Link,[string]$Target,[string]$Arguments){
    if(-not [IO.File]::Exists($Link) -or ([IO.File]::GetAttributes($Link) -band [IO.FileAttributes]::ReparsePoint)){return $false}
    $shell=New-Object -ComObject WScript.Shell
    try{
        $item=$shell.CreateShortcut($Link)
        $item.TargetPath -ieq $Target -and [string]$item.Arguments -ceq $Arguments
    }finally{
        if($item){$null=[Runtime.InteropServices.Marshal]::ReleaseComObject($item)}
        $null=[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
}

function Write-GuardSetupShortcut([string]$Folder,[string]$Leaf,[string]$Target,[string]$Arguments,[string]$Description){
    Assert-GuardSandboxieAdministratorPath $Target
    Assert-GuardSandboxieAdministratorPath $Folder
    $link=Join-Path $Folder $Leaf
    if([IO.File]::Exists($link)){
        Assert-GuardSandboxieAdministratorPath $link
        if(Test-GuardSetupShortcut $link $Target $Arguments){return}
    }
    $temporary=Join-Path $Folder ('ClaudeGuard-'+[guid]::NewGuid().ToString('N')+'.lnk')
    $shell=New-Object -ComObject WScript.Shell
    try{
        $shortcut=$shell.CreateShortcut($temporary)
        $shortcut.TargetPath=$Target;$shortcut.Arguments=$Arguments;$shortcut.WorkingDirectory=Split-Path -Parent $Target
        $shortcut.Description=$Description
        $shortcut.Save()
        $acl=Get-Acl -LiteralPath $temporary -ErrorAction Stop
        $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
        Set-Acl -LiteralPath $temporary -AclObject $acl -ErrorAction Stop
        if([IO.File]::Exists($link)){[IO.File]::Replace($temporary,$link,$temporary+'.bak')}
        else{[IO.File]::Move($temporary,$link)}
        if(-not (Test-GuardSetupShortcut $link $Target $Arguments)){throw 'Windows shortcut readback failed.'}
    }finally{
        if($shortcut){$null=[Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)}
        $null=[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
        [IO.File]::Delete($temporary);[IO.File]::Delete($temporary+'.bak')
    }
}

function Install-GuardSettingsShortcut([string]$Stage,[string]$BootstrapPath){
    $root=[IO.Path]::GetFullPath($Stage).TrimEnd('\')+'\'
    $target=[IO.Path]::GetFullPath($BootstrapPath)
    if(-not $target.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($target) -cne 'ClaudeGuardSetup.exe'){throw 'The permanent Guard settings launcher could not be located.'}
    Write-GuardSetupShortcut ([Environment]::GetFolderPath('CommonPrograms')) 'Claude Guard Settings.lnk' $target '--settings' '管理 Claude Guard 节点、允许的出口和时区'
}

function Install-GuardDesktopEntry {
    $target=Get-GuardDataPath 'daily\open-claude-daily.cmd'
    $leaf='Claude Desktop - Guarded.lnk'
    $userDesktop=[Environment]::GetFolderPath('DesktopDirectory')
    $personal=if($userDesktop){Join-Path $userDesktop $leaf}
    $alreadyGuarded=try{$personal -and (Test-GuardSetupShortcut $personal $target '')}catch{$false}
    if($alreadyGuarded){return 'Desktop'}
    if(-not ($personal -and [IO.File]::Exists($personal))){
        try{
            Write-GuardSetupShortcut ([Environment]::GetFolderPath('CommonDesktopDirectory')) $leaf $target '' '通过 Claude Guard 手动打开'
            return 'Desktop'
        }catch{}
    }
    Write-GuardSetupShortcut ([Environment]::GetFolderPath('CommonPrograms')) $leaf $target '' '通过 Claude Guard 手动打开'
    'StartMenu'
}

function Test-GuardSettingsInstalledVersion([string]$Stage){
    if(-not [IO.File]::Exists((Get-GuardDataPath 'daily-provisioned.json'))){return $false}
    . (Join-Path $Stage 'release\install-guard-helpers.ps1')
    $daily=Get-GuardDataPath 'daily'
    $files=$script:GuardReleasePackageFiles+@('guard-profile-store.ps1','guard-node-profile.ps1','guard-region-profile.ps1')
    foreach($name in $files){
        $installed=Join-Path $daily $name
        if(-not [IO.File]::Exists($installed) -or
            (Get-FileHash -LiteralPath $installed -ErrorAction Stop).Hash -cne
            (Get-FileHash -LiteralPath (Join-Path (Join-Path $Stage 'package') $name) -ErrorAction Stop).Hash){return $false}
    }
    foreach($name in $script:GuardReleaseRuntimePins.Keys){
        $installed=Join-Path $daily $name
        if(-not [IO.File]::Exists($installed) -or
            (Get-FileHash -LiteralPath $installed -ErrorAction Stop).Hash -cne $script:GuardReleaseRuntimePins[$name]){return $false}
    }
    $true
}

function Invoke-GuardSettingsInstall([string]$Stage,[string]$BootstrapPath,[pscredential]$Profile,$Proof,$RegionPlan,[scriptblock]$ProgressCallback){
    $options=@{Install=$true}
    if($ProgressCallback){$options.ProgressCallback=$ProgressCallback}
    if($Profile){
        Assert-GuardSettingsPreview $Profile $Proof
        if(-not $RegionPlan){throw 'Preview the Windows settings before applying this node.'}
        $options.NodeProfile=$Profile
        $options.ExpectedIpv4=$Proof.ExitIpv4
        $options.NodeOperations=New-GuardSettingsNodeOperations $RegionPlan (New-GuardWindowsRegionOperations) $Proof.ProfileFingerprint
        if(Test-GuardSettingsInstalledVersion $Stage){$options.RouteOnly=$true}
    }
    $install=Join-Path $Stage 'release\install-guard.ps1'
    $out=@(& $install @options)
    if($out.Count -ne 1 -or $out[0].Installed -ne $true){
        $last=$out|Select-Object -Last 1
        if(-not $last){return [pscustomobject]@{Installed=$false;Restored=$false;SettingsShortcut=$false}}
        return ($last | Add-Member -NotePropertyMembers @{SettingsShortcut=$false} -PassThru)
    }
    $shortcut=$true
    try{Install-GuardSettingsShortcut $Stage $BootstrapPath}catch{$shortcut=$false}
    $entry=try{Install-GuardDesktopEntry}catch{'File'}
    $out[0] | Add-Member -NotePropertyMembers @{SettingsShortcut=$shortcut;GuardedEntry=$entry} -PassThru
}

function Invoke-GuardSettingsRecovery([scriptblock]$ProgressCallback){
    $pending=Read-GuardDailyRecord 'release-install-pending.json'
    if($pending.Version -notin 1,2 -or [string]$pending.Stage -cnotmatch '\Arelease-install-[a-f0-9]{32}\z' -or
        $pending.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'Invalid pending recovery identity.'}
    $folder=Get-GuardDataPath $pending.Stage
    $release=Join-Path $folder 'release'
    $entry=Join-Path $release 'install-guard.ps1'
    foreach($path in $folder,$release,$entry){Assert-GuardSandboxieAdministratorPath $path}
    $ops=New-GuardSettingsNodeOperations $null (New-GuardWindowsRegionOperations) ''
    $options=@{Recover=$true;NodeOperations=$ops}
    if($ProgressCallback -and (Get-Command -Name $entry).Parameters.ContainsKey('ProgressCallback')){
        $options.ProgressCallback=$ProgressCallback
    }
    & $entry @options
}
