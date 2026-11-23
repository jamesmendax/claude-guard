#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\release\guard-profile-actions.ps1"
$area=Join-Path ([IO.Path]::GetTempPath()) ('guard-profile-store-tests-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($area)
function Get-GuardDataPath([string]$Name){Join-Path $area $Name}
function Require([bool]$Check,[string]$Text){if(-not $Check){throw $Text};"PASS $Text"}
function Reject([scriptblock]$Action,[string]$Text){$denied=$false;try{$null=& $Action}catch{$denied=$true};Require $denied $Text}
$link='vless://6b1f71fb-b22c-41b7-8fe7-ceccb87c2fa3@198.51.100.81:443?type=ws&security=tls&sni=example.test&host=example.test&path=%2Fsocket&encryption=none'
try{
    $profile=New-GuardNodeProfile -Text $link
    $route=Get-GuardNodeProfileRoute $profile 18881
    $now=[datetimeoffset]::UtcNow
    $proof=[pscustomobject]@{Passed=$true;State='Completed';Provider='CloudflareTrace';ExitIpv4='198.51.100.13'
        CheckedUtc=$now.UtcDateTime.ToString('o');ProfileFingerprint=$route.ProfileFingerprint}
    Assert-GuardSettingsPreview $profile $proof $now
    'PASS A verified manual exit is accepted without a second configured egress'
    $zones=Get-GuardSettingsTimeZones (Split-Path -Parent $PSScriptRoot)
    Require ((Get-GuardSettingsRegionChoice $zones 'Automatic' JP).Id -ceq 'Japan') 'A Japanese exit selects Tokyo using the bundled territory map'
    $regionRead=@{Read={[pscustomobject]@{Id='UTC';DaylightDisabled=$false;AutomaticTimeZoneEnabled=$false}}}
    foreach($example in @(
        @{Country='PW';Choice='Automatic';Zone='Tokyo Standard Time'},
        @{Country='TL';Choice='Automatic';Zone='Tokyo Standard Time'},
        @{Country='CA';Choice='UsPacific';Zone='Pacific Standard Time'},
        @{Country='ZZ';Choice='Japan';Zone='Tokyo Standard Time'}
    )){
        $choice=Get-GuardSettingsRegionChoice $zones $example.Choice $example.Country
        $plan=New-GuardRegionProfilePlan $choice.Id $example.Country $regionRead
        Require ($choice.Id -ceq ('Windows/'+$example.Zone) -and $plan.Changes[0].After.Id -ceq $example.Zone) `
            ("The selected Windows time zone applies to {0} independently of a city shortcut's country" -f $example.Country)
    }
    Require ((Get-GuardSettingsRegionChoice $zones 'Automatic' US).RequiresChoice) 'A United States exit asks for a city instead of assuming the West Coast'
    Require ((Get-GuardSettingsRegionChoice $zones 'Automatic' '').RequiresChoice) 'Missing geography requires a choice without another network lookup'
    Require ((Get-GuardSettingsRegionChoice $zones 'Windows/Eastern Standard Time' US).TimeZoneId -ceq 'Eastern Standard Time') 'Other installed Windows time zones can be selected'
    Reject {Get-GuardSettingsRegionChoice $zones 'UsPacific' JP} 'A verified Japanese exit does not silently select a conflicting country'
    Reject {Assert-GuardSettingsPreview $profile $proof $now.AddMinutes(6)} 'An expired node check cannot be applied'
    $proof.ProfileFingerprint='A'*64
    Reject {Assert-GuardSettingsPreview $profile $proof $now} 'A different node cannot inherit a successful check'
    $proof.ProfileFingerprint=$route.ProfileFingerprint
    Require (-not (Get-GuardNodeStoreSnapshot).Exists) 'An absent private directory selects the compatible legacy route'

    $storePath=Get-GuardNodeStorePath
    $dir=Split-Path -Parent $storePath
    $null=[IO.Directory]::CreateDirectory($dir)
    Reject {Get-GuardNodeStoreSnapshot} 'A user-owned private directory cannot silently select a different route'
    [IO.Directory]::Delete($dir)

    & {
        function Restore-GuardNodeStoreSnapshot($state){$script:encrypted=$state}
        Save-GuardNodeProfile $profile
        $serialized=$script:encrypted|ConvertTo-Json -Depth 6 -Compress
        Require ($script:encrypted.Exists -and $serialized -notlike '*example.test*' -and $serialized -notlike '*6b1f71fb*') 'The persistent snapshot contains only DPAPI ciphertext and account metadata'
        function Get-GuardNodeStoreSnapshot { $script:encrypted }
        $restored=Read-GuardSavedNodeRoute 18881
        Require ($restored.Hash -ceq $route.Hash -and $restored.ProfileFingerprint -ceq $route.ProfileFingerprint) 'The current Windows account decrypts the original exact route'
        $script:encrypted.Record.ProtectedValue='00'*100
        Reject {Read-GuardSavedNodeRoute 18881} 'Unreadable credentials stop the route reader'
    }
    $testState=@{Id='Pacific Standard Time';DaylightDisabled=$false;Store='previous';Writes=0}
    function Get-GuardNodeStoreSnapshot {[pscustomobject]@{Exists=$true;Value=$testState.Store}}
    function Save-GuardNodeProfile($inputProfile){$testState.Store=(Get-GuardNodeProfileRoute $inputProfile 18881).ProfileFingerprint}
    function Restore-GuardNodeStoreSnapshot($saved){$testState.Store=$saved.Value}
    $regionOps=@{Read={ [pscustomobject]@{Id=$testState.Id;DaylightDisabled=$testState.DaylightDisabled;AutomaticTimeZoneEnabled=$false} }
        Write={param($target)$testState.Id=$target.Id;$testState.DaylightDisabled=$target.DaylightDisabled;$testState.Writes++}}
    $plan=New-GuardRegionProfilePlan -ProfileId Japan -Operations $regionOps
    $rejected=New-GuardSettingsNodeOperations $plan $regionOps $route.ProfileFingerprint {throw 'Fixture selection changed'}
    $null=& $rejected.Snapshot
    Reject {& $rejected.Apply $profile} 'A changed source selection blocks the final protected apply'
    Require ($testState.Store -ceq 'previous' -and $testState.Id -ceq 'Pacific Standard Time' -and $testState.Writes -eq 0) `
        'A failed source recheck leaves the node and Windows time zone untouched'
    $ops=New-GuardSettingsNodeOperations $plan $regionOps $route.ProfileFingerprint
    Reject {& $ops.Apply $profile} 'The private node cannot change before a rollback snapshot exists'
    $saved=& $ops.Snapshot
    & $ops.Apply $profile
    Require ($testState.Store -ceq $route.ProfileFingerprint -and $testState.Id -ceq 'Tokyo Standard Time') 'The explicit Japan choice applies the checked route and time zone together'
    $copy=$saved | ConvertTo-Json -Depth 8 |ConvertFrom-Json
    & $ops.Restore $copy
    Require ($testState.Store -ceq 'previous' -and $testState.Id -ceq 'Pacific Standard Time') 'The serialized recovery snapshot restores the prior node and time zone'
    $keep=New-GuardRegionProfilePlan -ProfileId Keep -Operations $regionOps
    $unchanged=New-GuardSettingsNodeOperations $keep $regionOps $route.ProfileFingerprint
    $null=& $unchanged.Snapshot
    & $unchanged.Apply $profile
    Require ($testState.Writes -eq 2) 'Choosing the current time zone does not write Windows settings'

    $testState.Store='previous'
    $testState.WindowsLocale='en-US'
    $testState.WindowsPreferred='en-US'
    $testState.BrowserLocale='en-US,en'
    $windowsLocale=[pscustomobject]@{LocaleName='ja-JP';Before=@{LocaleName='en-US';Languages=@(@{LanguageTag='en-US'})}
        After=@{CountryCode='JP';LocaleName='ja-JP';Languages=@(@{LanguageTag='ja-JP'})}}
    $browserLocale=[pscustomobject]@{Changed=$true;Profile='Default';PrimaryLanguage='ja'
        Before=@{AcceptLanguages='en-US,en'};After=@{AcceptLanguages='ja,en-US,en'}}
    function New-GuardWindowsLocaleOperations {
        @{
            Read={[pscustomobject]@{LocaleName=$testState.WindowsLocale;CountryCode='JP';Languages=@(@{LanguageTag=$testState.WindowsPreferred})}}
            ReadIndependentLanguages={
                param($Delay)
                $testState.IndependentLanguageReads++
                if($testState.IndependentLanguage){$testState.IndependentLanguage}else{$testState.WindowsPreferred}
            }
        }
    }
    function Get-GuardWindowsLocaleState($Operations){& $Operations.Read}
    function Test-GuardWindowsIndependentLanguageOrder($Actual,$Expected,$Target){$Actual -ceq $Expected.Languages[0].LanguageTag}
    function Test-GuardWindowsLocalePlan($Plan,[switch]$Before,[switch]$AllowOriginalLanguages,$Operations){
        if(-not $Operations){$Operations=New-GuardWindowsLocaleOperations}
        $observed=& $Operations.Read
        $locale=if($Before){$Plan.Before.LocaleName}else{$Plan.After.LocaleName}
        $language=if($Before -or $AllowOriginalLanguages){$Plan.Before.Languages[0].LanguageTag}else{$Plan.After.Languages[0].LanguageTag}
        $observed.LocaleName -ceq $locale -and $observed.Languages[0].LanguageTag -ceq $language
    }
    function Set-GuardWindowsLocalePlan($Plan,[scriptblock]$PersistWrite,[switch]$AllowManualPreferredLanguage){
        & $PersistWrite 'RegionalFormat'
        $testState.WindowsLocale=$Plan.After.LocaleName
        $testState.WindowsPreferred=$Plan.After.Languages[0].LanguageTag
        & $PersistWrite $null
    }
    function Restore-GuardWindowsLocalePlan($Plan,[string]$PendingWrite){
        $testState.WindowsLocale=$Plan.Before.LocaleName
        $testState.WindowsPreferred=$Plan.Before.Languages[0].LanguageTag
    }
    function Set-GuardBrowserLanguagePlan($Plan){
        $testState.BrowserLocale=$Plan.After.AcceptLanguages
        if($testState.FailBrowserApply){throw 'A browser write stopped after the value changed.'}
    }
    function Test-GuardBrowserLanguagePlan($Plan,[switch]$Before){
        $testState.BrowserLocale -ceq $(if($Before){$Plan.Before.AcceptLanguages}else{$Plan.After.AcceptLanguages})
    }
    function Get-GuardBrowserLanguageApplyMode($Plan){if($testState.BrowserBusy){'ManualRequired'}else{'Offline'}}
    function Test-GuardBrowserSiteLanguageQuiet($Plan){
        if($testState.NoRecentHeader){throw 'A recent website-language check from this Edge profile is required.'}
        if($testState.FailHeader){throw 'The local website received a different preferred language from Edge.'}
        'ja,en-US;q=0.9,en;q=0.8'
    }
    function Restore-GuardBrowserLanguagePlan($Plan){
        if($testState.FailBrowserRestore){throw 'The profile could not be restored on this attempt.'}
        $testState.BrowserLocale=$Plan.Before.AcceptLanguages
    }
    $full=New-GuardSettingsNodeOperations $plan $regionOps $route.ProfileFingerprint -WindowsLocalePlan $windowsLocale -BrowserLocalePlan $browserLocale
    $snapshot=& $full.Snapshot
    $copy=($snapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
    Require ($copy.Version -eq 2 -and $copy.WindowsLocale.Before.LocaleName -ceq 'en-US' -and
        $copy.BrowserLocale.Before.AcceptLanguages -ceq 'en-US,en') 'The protected prewrite snapshot keeps both locale plans for later recovery'
    $testState.WindowsLocale='fr-FR'
    Reject {& $full.Apply $profile} 'A stale Windows locale preview stops before writing the node or browser'
    Require ($testState.Store -ceq 'previous' -and $testState.BrowserLocale -ceq 'en-US,en') 'A stale locale plan leaves the other saved settings untouched'
    $testState.WindowsLocale='en-US'
    $testState.BrowserBusy=$true
    $null=& $full.Apply $profile
    $manual=& $full.Verify
    Require ($testState.WindowsLocale -ceq 'ja-JP' -and $testState.BrowserLocale -ceq 'en-US,en' -and
        $manual.BrowserStatus -ceq 'ManualRequired' -and $manual.WebsiteStatus -ceq 'AwaitingBrowser' -and
        -not $manual.AllSettingsVerified -and -not $manual.SiteAcceptLanguage) 'A busy Edge profile is untouched while the other settings are accepted'
    & $full.Restore $snapshot
    $testState.BrowserBusy=$false
    $snapshot=& $full.Snapshot
    $testState.BrowserLocale='en-GB,en'
    $null=& $full.Apply $profile
    $manual=& $full.Verify
    Require ($manual.BrowserStatus -ceq 'ManualRequired' -and $testState.BrowserLocale -ceq 'en-GB,en') 'A stale Edge plan preserves changes that appeared after review'
    & $full.Restore $snapshot
    $testState.BrowserLocale='en-US,en'
    $snapshot=& $full.Snapshot
    $testState.FailBrowserApply=$true
    $persist={
        param($progressSnapshot)
        $testState.ProgressSnapshots+=,($progressSnapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
    }
    $applyError=$null
    try{$null=& $full.Apply $profile $persist}catch{$applyError=$_.Exception}
    Require ($applyError.Message -ceq 'Edge website language settings could not be applied.' -and
        $applyError.Data['GuardLocaleFailure'] -ceq 'EdgeApply' -and $testState.BrowserLocale -ceq 'ja,en-US,en') `
        'An unclassified partial browser write reports only its step and stops the transaction'
    Require ($testState.ProgressSnapshots.Count -eq 3 -and
        $testState.ProgressSnapshots[0].WindowsPendingWrite -ceq 'RegionalFormat' -and
        $testState.ProgressSnapshots[0].WindowsLocaleTouched -and -not $testState.ProgressSnapshots[0].BrowserLocaleTouched -and
        $testState.ProgressSnapshots[2].BrowserLocaleTouched) 'Protected progress records identify partial writes before each locale mutation'
    $copy=$testState.ProgressSnapshots[-1]
    $testState.FailBrowserRestore=$true
    Reject {& $full.Restore $copy} 'Failed browser recovery leaves the installer able to retry its protected snapshot'
    Require ($testState.Store -ceq 'previous' -and $testState.Id -ceq 'Pacific Standard Time' -and
        $testState.WindowsLocale -ceq 'en-US') 'Recovery attempts all prior settings even when restoring the browser fails'
    $testState.FailBrowserRestore=$false
    $testState.FailBrowserApply=$false
    $recovery=New-GuardSettingsNodeOperations $null $regionOps ''
    & $recovery.Restore $copy
    Require ($testState.BrowserLocale -ceq 'en-US,en') 'A new recovery process can restore the serialized Edge website language settings'
    $null=& $full.Snapshot
    $null=& $full.Apply $profile
    $testState.NoRecentHeader=$true
    $unverified=& $full.Verify
    Require ($unverified.BrowserStatus -ceq 'Saved' -and $unverified.WebsiteStatus -ceq 'AwaitingBrowser' -and
        -not $unverified.SiteAcceptLanguage -and -not $unverified.AllSettingsVerified) 'Saved Edge settings still require a real website sample'
    $testState.NoRecentHeader=$false
    $testState.FailHeader=$true
    $verifyError=$null
    try{$null=& $full.Verify}catch{$verifyError=$_.Exception}
    Require ($verifyError.Message -ceq 'Edge website Accept-Language did not pass final readback.' -and
        $verifyError.Data['GuardLocaleFailure'] -ceq 'EdgeSiteMismatch') `
        'A mismatched real website request fails final verification and reports the specific step'
    $testState.FailHeader=$false
    $verified=& $full.Verify
    Require ($verified.SiteAcceptLanguage -ceq 'ja,en-US;q=0.9,en;q=0.8' -and $verified.CountryCode -ceq 'JP' -and
        $verified.PreferredLanguages[0] -ceq 'ja-JP' -and $verified.WindowsLanguageStatus -ceq 'Verified' -and $verified.AllSettingsVerified) `
        'Successful verification supplies the measured site header and independently read-back Windows language'
    $testState.WindowsPreferred='en-US'
    $reads=$testState.IndependentLanguageReads
    $manual=& $full.Verify
    Require ($testState.IndependentLanguageReads -eq $reads+1 -and $manual.WindowsLanguageStatus -ceq 'ManualRequired' -and
        $manual.PreferredLanguages[0] -ceq 'en-US' -and $manual.LocaleName -ceq 'ja-JP' -and $manual.SiteAcceptLanguage -and -not $manual.AllSettingsVerified) `
        'A reverted Windows list makes the full receipt partial while independent region and website evidence remain valid'
    $testState.WindowsPreferred='ja-JP'
    $testState.IndependentLanguage='en-US'
    $verifyError=$null
    try{$null=& $full.Verify}catch{$verifyError=$_.Exception}
    Require ($verifyError.Data['GuardLocaleFailure'] -ceq 'WindowsLanguages') `
        'Cached Windows language cannot override a disagreeing independent readback'

    $local=@([pscustomobject]@{Name='Teredo Tunneling Pseudo-Interface';InterfaceType=131;InterfaceGuid=[guid]::NewGuid();ifIndex=7;NetLuid=1402},
        [pscustomobject]@{Name='Bettbox';InterfaceGuid=[guid]::NewGuid();ifIndex=8;NetLuid=1102})
    $identity=[pscustomobject]@{SourceGuid=$local[0].InterfaceGuid;GuidRoundTrip=$local[0].InterfaceGuid;NetLuidDecimal='1402'
        IndexLuidDecimal='1402';InterfaceIndex=7}
    $checked=Assert-GuardTeredoIdentity $local $identity
    Require ($checked.Verified -and [guid]$checked.VpnGuid -eq $local[1].InterfaceGuid) 'Fresh Windows adapter identities resolve without a previous machine GUID'
    $identity.GuidRoundTrip=[guid]::NewGuid()
    Reject {Assert-GuardTeredoIdentity $local $identity} 'The wrong native tunnel identity is rejected on a fresh computer'

    & {
        # Only ACL mutation is substituted. Create, replace and read real Windows Shell links in this isolated directory.
        function Assert-GuardSandboxieAdministratorPath([string]$Path){
            $absolute=[IO.Path]::GetFullPath($Path)
            if($absolute -ine $area -and -not $absolute.StartsWith($area+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture shortcut path.'}
        }
        function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction) Assert-GuardSandboxieAdministratorPath $LiteralPath}
        $target=Join-Path $area 'synthetic-guarded.cmd'
        [IO.File]::WriteAllText($target,'@exit /b 0')
        Write-GuardSetupShortcut $area 'Guard Test.lnk' $target '' 'Guard fixture'
        $linkPath=Join-Path $area 'Guard Test.lnk'
        Require (Test-GuardSetupShortcut $linkPath $target '') 'A normal Windows shortcut reopens the exact guarded launcher on a clean install'
        Write-GuardSetupShortcut $area 'Guard Test.lnk' $target '--settings' 'Guard settings fixture'
        Require (Test-GuardSetupShortcut $linkPath $target '--settings') 'An update replaces and verifies an existing settings shortcut'
    }
}finally{
    if($profile){$profile.Password.Dispose()}
    $actual=[IO.Path]::GetFullPath($area);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if([IO.Path]::GetDirectoryName($actual).TrimEnd('\') -eq $base.TrimEnd('\') -and
        [IO.Path]::GetFileName($actual) -cmatch '^guard-profile-store-tests-[a-f0-9]{32}$' -and [IO.Directory]::Exists($actual)){
        Remove-Item -LiteralPath $actual -Recurse -Force
    }
}
