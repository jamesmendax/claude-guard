# Shared by the setup window and its background runspace. No action runs on import.
$packageDirectory=Join-Path (Split-Path -Parent $PSScriptRoot) 'package'
. (Join-Path $packageDirectory 'guard-common.ps1')
. (Join-Path $packageDirectory 'guard-node-profile.ps1')
. (Join-Path $packageDirectory 'guard-bettbox-profile.ps1')
. (Join-Path $packageDirectory 'guard-profile-store.ps1')
. (Join-Path $packageDirectory 'guard-region-profile.ps1')
. (Join-Path $packageDirectory 'guard-node-locale.ps1')
. (Join-Path $packageDirectory 'guard-sandboxie.ps1')
. (Join-Path $packageDirectory 'guard-windows-locale.ps1')
. (Join-Path $packageDirectory 'guard-browser-languages.ps1')
. (Join-Path $PSScriptRoot 'guard-site-language.ps1')

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

function Assert-GuardSettingsCurrentBettbox([pscredential]$Profile,$Proof){
    Assert-GuardSettingsPreview $Profile $Proof
    $current=Get-GuardCurrentBettboxProfile
    try{
        if((Get-GuardNodeProfileRoute -Profile $current -Port 18881).ProfileFingerprint -cne $Proof.ProfileFingerprint){
            throw 'The current Bettbox selection changed during the check.'
        }
    }finally{
        if($current){$current.Password.Dispose()}
    }
}

function New-GuardSettingsLocaleFailure([string]$Message,[string]$Code,[Exception]$Cause){
    $exception=[InvalidOperationException]::new($Message,$Cause)
    $exception.Data['GuardLocaleFailure']=$Code
    $exception
}

function Get-GuardSettingsBrowserFailure([Exception]$Exception,[string]$Default){
    for($cause=$Exception;$cause;$cause=$cause.InnerException){
        switch -Exact ($cause.Message){
            'Edge did not load the one-time local page for its language settings.' {return 'EdgeSettingsOpen'}
            'Edge loaded the local page without exposing an identifiable settings window.' {return 'EdgeSettingsWindow'}
            'Edge did not expose its address box in the new settings window.' {return 'EdgeSettingsWindow'}
            'Edge lost the address in the new settings window.' {return 'EdgeSettingsPage'}
            'Edge could not open its own settings page.' {return 'EdgeSettingsPage'}
            'Edge did not expose its preferred-languages settings.' {return 'EdgeSettingsPage'}
            'Edge opened a different profile. Its language settings were not changed.' {return 'EdgeProfile'}
            'The selected Edge profile could not be verified.' {return 'EdgeProfile'}
            'The regular Windows user token is unavailable for the Edge check.' {return 'EdgeProfile'}
            'The Edge check requires the original user''s regular Windows session.' {return 'EdgeProfile'}
            'Edge did not offer the requested preferred language.' {return 'EdgeLanguageUnavailable'}
            'Edge does not allow adding a preferred language.' {return 'EdgeLanguageUnavailable'}
            'Edge could not confirm the preferred language selection.' {return 'EdgeLanguageUnavailable'}
            'Edge does not allow changing the preferred language order.' {return 'EdgeLanguageOrder'}
            'Edge does not allow the requested preferred language operation.' {return 'EdgeLanguageOrder'}
            'Edge language preferences changed during the operation.' {return 'EdgePreviewChanged'}
            'Edge or its website language preferences changed after the preview.' {return 'EdgePreviewChanged'}
            'Edge did not save the requested website language change.' {return 'EdgeReadback'}
            'The local website received no verifiable request from the selected Edge browser.' {return 'EdgeSiteNoRequest'}
            'The local website received a different preferred language from Edge.' {return 'EdgeSiteMismatch'}
        }
        if($cause.Message -cmatch '\AWindows could not open the regular Edge profile \([0-9]{1,6}\)\.\z'){return 'EdgeProfile'}
    }
    $Default
}

function Get-GuardSettingsWindowsFailure($Plan,[string]$PendingWrite){
    if($PendingWrite -cin (Get-GuardWindowsLocaleSettings)){return 'Windows'+$PendingWrite}
    try{
        $current=Get-GuardWindowsLocaleState
        if($current.OwnerSid -ceq $Plan.After.OwnerSid){
            foreach($setting in (Get-GuardWindowsLocaleSettings)){
                if(-not (Test-GuardWindowsLocaleSetting $current $Plan.After $setting)){return 'Windows'+$setting}
            }
        }
    }catch{}
    'WindowsReadback'
}

function Get-GuardSettingsWindowsLocaleAcceptance($Plan){
    try{
        $operations=New-GuardWindowsLocaleOperations
        $independent=& $operations.ReadIndependentLanguages 0
    }catch{
        throw (New-GuardSettingsLocaleFailure 'Windows preferred languages did not pass independent readback.' 'WindowsLanguages' $_.Exception)
    }
    try{
        $current=Get-GuardWindowsLocaleState $operations
        $snapshot=@{Read={$current}.GetNewClosure()}
        $matchesTarget=Test-GuardWindowsLocalePlan -Plan $Plan -Operations $snapshot
        if($matchesTarget -and (Test-GuardWindowsIndependentLanguageOrder $independent $Plan.After $Plan.LocaleName)){
            return @{State=$current;LanguageStatus='Verified'}
        }
        $matchesOriginalList=Test-GuardWindowsLocalePlan -Plan $Plan -AllowOriginalLanguages -Operations $snapshot
        if($matchesOriginalList -and (Test-GuardWindowsIndependentLanguageOrder $independent $Plan.Before '')){
            return @{State=$current;LanguageStatus='ManualRequired'}
        }
    }catch{
        throw (New-GuardSettingsLocaleFailure 'Windows locale settings did not pass final readback.' 'WindowsReadback' $_.Exception)
    }
    $code=if($matchesTarget -or $matchesOriginalList){'WindowsLanguages'}else{Get-GuardSettingsWindowsFailure $Plan}
    throw (New-GuardSettingsLocaleFailure 'Windows locale settings did not pass final readback.' $code)
}

function New-GuardSettingsNodeOperations($RegionPlan,$RegionOperations,[string]$ExpectedFingerprint,[scriptblock]$BeforeApply,
    $WindowsLocalePlan,$BrowserLocalePlan,$BrowserTarget){
    if($BrowserLocalePlan -and -not $WindowsLocalePlan){throw 'A Windows locale plan is required.'}
    if(-not $BrowserTarget -and $BrowserLocalePlan){
        $BrowserTarget=@{Profile=$BrowserLocalePlan.Profile;PrimaryLanguage=$BrowserLocalePlan.PrimaryLanguage}
    }
    $context=@{Snapshot=$null;BrowserStatus='ManualRequired'}
    $snapshot={
        $saved=[ordered]@{Version=1;Node=(Get-GuardNodeStoreSnapshot);Region=$RegionPlan}
        if($WindowsLocalePlan){
            $saved.Version=2
            $saved.WindowsLocale=$WindowsLocalePlan
            $saved.BrowserLocale=$BrowserLocalePlan
            $saved.WindowsLocaleTouched=$false
            $saved.BrowserLocaleTouched=$false
            $saved.WindowsPendingWrite=$null
        }
        $context.Snapshot=[pscustomobject]$saved
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
        param([pscredential]$Selection,[scriptblock]$PersistProgress)
        if(-not $context.Snapshot -or -not $ExpectedFingerprint -or
            (Get-GuardNodeProfileRoute -Profile $Selection -Port 18881).ProfileFingerprint -cne $ExpectedFingerprint){
            throw 'The node does not match its protected transaction.'
        }
        if($BeforeApply){$null=& $BeforeApply}
        if($WindowsLocalePlan){
            try{$windowsCurrent=Test-GuardWindowsLocalePlan -Plan $WindowsLocalePlan -Before}
            catch{throw (New-GuardSettingsLocaleFailure 'Windows locale settings could not be applied.' 'WindowsReadback' $_.Exception)}
            if(-not $windowsCurrent){
                throw (New-GuardSettingsLocaleFailure 'Windows locale settings changed after the preview.' 'WindowsPreviewChanged')
            }
        }
        Save-GuardNodeProfile $Selection
        $null=Invoke-GuardRegionProfileChange -Plan $RegionPlan -Operations $RegionOperations -PersistUndo $persist
        if($WindowsLocalePlan){
            $profileSnapshot=$context.Snapshot
            $persistWindows={
                param([string]$Pending)
                if($Pending){$profileSnapshot.WindowsLocaleTouched=$true}
                $profileSnapshot.WindowsPendingWrite=$Pending
                if($PersistProgress){$null=& $PersistProgress $profileSnapshot}
            }.GetNewClosure()
            try{$null=Set-GuardWindowsLocalePlan -Plan $WindowsLocalePlan -PersistWrite $persistWindows -AllowManualPreferredLanguage}
            catch{
                $code=Get-GuardSettingsWindowsFailure $WindowsLocalePlan $profileSnapshot.WindowsPendingWrite
                throw (New-GuardSettingsLocaleFailure 'Windows locale settings could not be applied.' $code $_.Exception)
            }
            try{
                if($BrowserLocalePlan -and (Test-GuardBrowserLanguagePlan -Plan $BrowserLocalePlan -Before)){
                    $mode=Get-GuardBrowserLanguageApplyMode -Plan $BrowserLocalePlan
                    if($mode -cin 'Offline','Unchanged'){
                        if($mode -ceq 'Offline'){
                            $profileSnapshot.BrowserLocaleTouched=$true
                            if($PersistProgress){$null=& $PersistProgress $profileSnapshot}
                        }
                        $null=Set-GuardBrowserLanguagePlan -Plan $BrowserLocalePlan
                        $context.BrowserStatus='Saved'
                    }
                }
            }catch{
                if($_.Exception.Data['GuardBrowserFailure'] -ceq 'EdgeLanguageManualRequired'){
                    $profileSnapshot.BrowserLocaleTouched=$false
                    if($PersistProgress){$null=& $PersistProgress $profileSnapshot}
                }else{
                    $code=Get-GuardSettingsBrowserFailure $_.Exception 'EdgeApply'
                    throw (New-GuardSettingsLocaleFailure 'Edge website language settings could not be applied.' $code $_.Exception)
                }
            }
        }
    }.GetNewClosure()
    $restore={
        param($saved)
        if($saved.Version -notin 1,2 -or -not $saved.Node -or -not $saved.Region -or
            ($saved.Version -eq 2 -and (-not $saved.WindowsLocale -or ($saved.BrowserLocaleTouched -and -not $saved.BrowserLocale)))){
            throw 'Invalid protected settings recovery record.'
        }
        $failed=$false
        $preserved=$false
        if($saved.Version -eq 2){
            if($saved.BrowserLocaleTouched -eq $true){
                try{$null=Restore-GuardBrowserLanguagePlan -Plan $saved.BrowserLocale}catch{$failed=$true}
            }
            if($saved.WindowsLocaleTouched -eq $true){
                try{
                    $preserved=(Restore-GuardWindowsLocalePlan -Plan $saved.WindowsLocale -PendingWrite $saved.WindowsPendingWrite) -ceq 'PreservedManualChange'
                }catch{$failed=$true}
            }
        }
        try{
            $zone=Undo-GuardRegionProfileChange -Plan $saved.Region -Operations $RegionOperations
            $preserved=$preserved -or $zone -ceq 'PreservedManualChange'
        }catch{$failed=$true}
        try{Restore-GuardNodeStoreSnapshot $saved.Node}catch{$failed=$true}
        if($failed){throw 'The encrypted node, Windows region, or Edge website languages could not be restored.'}
        if($preserved){'PreservedManualChange'}
    }.GetNewClosure()
    $operations=@{Snapshot=$snapshot;Apply=$apply;Restore=$restore}
    if($WindowsLocalePlan){
        $operations.Verify={
            if($RegionPlan.ProfileId -cne 'Keep'){
                $zone=& $RegionOperations.Read
                if($zone.Id -cne $RegionPlan.WindowsTimeZoneId -or
                    ($RegionPlan.Changes.Count -and $zone.DaylightDisabled -ne $RegionPlan.Changes[0].After.DaylightDisabled)){
                    throw (New-GuardSettingsLocaleFailure 'Windows time zone did not pass final readback.' 'WindowsTimeZone')
                }
            }
            $windows=Get-GuardSettingsWindowsLocaleAcceptance $WindowsLocalePlan
            $header=$null
            if($context.BrowserStatus -ceq 'Saved'){
                try{$browserVerified=Test-GuardBrowserLanguagePlan -Plan $BrowserLocalePlan}
                catch{throw (New-GuardSettingsLocaleFailure 'Edge website language settings did not pass final readback.' 'EdgeReadback' $_.Exception)}
                if(-not $browserVerified){
                    throw (New-GuardSettingsLocaleFailure 'Edge website language settings did not pass final readback.' 'EdgeReadback')
                }
                try{
                    $header=Test-GuardBrowserSiteLanguageQuiet -Plan $BrowserLocalePlan
                    if($header -isnot [string] -or $header -cnotmatch '\A[A-Za-z0-9,;= .\-]{1,512}\z'){
                        throw 'The saved website language sample is invalid.'
                    }
                }catch{
                    if($_.Exception.Message -cne 'A recent website-language check from this Edge profile is required.'){
                        $code=Get-GuardSettingsBrowserFailure $_.Exception 'EdgeSiteReadback'
                        throw (New-GuardSettingsLocaleFailure 'Edge website Accept-Language did not pass final readback.' $code $_.Exception)
                    }
                }
            }
            [pscustomobject]@{
                CountryCode=$windows.State.CountryCode;LocaleName=$windows.State.LocaleName
                PreferredLanguages=@($windows.State.Languages | ForEach-Object LanguageTag)
                WindowsLanguageStatus=$windows.LanguageStatus;ExpectedWindowsLanguage=$WindowsLocalePlan.LocaleName
                BrowserLanguages=$(if($context.BrowserStatus -ceq 'Saved'){$BrowserLocalePlan.After.AcceptLanguages})
                BrowserProfile=$BrowserTarget.Profile;ExpectedBrowserLanguage=$BrowserTarget.PrimaryLanguage
                BrowserStatus=$context.BrowserStatus;WebsiteStatus=$(if($header){'Verified'}else{'AwaitingBrowser'})
                AllSettingsVerified=($windows.LanguageStatus -ceq 'Verified' -and [bool]$header);SiteAcceptLanguage=$header
            }
        }.GetNewClosure()
    }
    $operations
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
    $target=Join-Path $Stage 'ClaudeGuardSetup.exe'
    $actions=try{@((Get-ScheduledTask -TaskName 'ClaudeVPNGuard Daily Controller' -TaskPath '\' -ErrorAction Stop).Actions)}
        catch{return $false}
    if(@($actions).Count -ne 1 -or $actions[0].Execute -ine $target -or
        $actions[0].Arguments -cne '--background-controller'){return $false}
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

function Invoke-GuardSettingsInstall([string]$Stage,[string]$BootstrapPath,[pscredential]$Profile,$Proof,$RegionPlan,
    [scriptblock]$ProgressCallback,[string]$RequirePriorGeneration,[scriptblock]$BeforeApply,$WindowsLocalePlan,$BrowserLocalePlan,$BrowserTarget){
    $options=@{Install=$true}
    if($ProgressCallback){$options.ProgressCallback=$ProgressCallback}
    if($RequirePriorGeneration){$options.RequirePriorGeneration=$RequirePriorGeneration}
    if($Profile){
        Assert-GuardSettingsPreview $Profile $Proof
        if(-not $RegionPlan){throw 'Preview the Windows settings before applying this node.'}
        if($WindowsLocalePlan -and ($Proof.CountryCode -cnotmatch '\A[A-Z]{2}\z' -or
            $Proof.CountryCode -cne $WindowsLocalePlan.After.CountryCode)){
            throw 'The verified exit country does not match the reviewed Windows locale.'
        }
        $options.NodeProfile=$Profile
        $options.ExpectedIpv4=$Proof.ExitIpv4
        $recheck={
            Assert-GuardSettingsPreview $Profile $Proof
            if($BeforeApply){$null=& $BeforeApply}
        }.GetNewClosure()
        $options.NodeOperations=New-GuardSettingsNodeOperations $RegionPlan (New-GuardWindowsRegionOperations) `
            $Proof.ProfileFingerprint $recheck $WindowsLocalePlan $BrowserLocalePlan $BrowserTarget
        if(Test-GuardSettingsInstalledVersion $Stage){$options.RouteOnly=$true}
    }
    $install=Join-Path $Stage 'release\install-guard.ps1'
    if($BeforeApply){$null=& $BeforeApply}
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
