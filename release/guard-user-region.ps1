# Regional settings for the Windows account that owns an already-approved route.
function Get-GuardUserRegionPath([string]$Name,[switch]$Create) {
    $local=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if(-not $local){throw 'The Windows user settings directory is unavailable.'}
    $directory=[IO.DirectoryInfo]::new((Join-Path $local 'ClaudeVPNGuard'))
    for($parent=$directory;$parent;$parent=$parent.Parent){
        if($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){
            throw 'The user settings directory is redirected.'
        }
    }
    if($Create -and -not $directory.Exists){$directory.Create()}
    $path=Join-Path $directory.FullName $Name
    if([IO.File]::Exists($path) -and ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint)){
        throw 'The user settings file is redirected.'
    }
    $path
}

function Read-GuardUserRegionJson([string]$Name) {
    $path=Get-GuardUserRegionPath $Name
    try{$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::Read -bor [IO.FileShare]::Delete))}
    catch [IO.FileNotFoundException]{return}
    catch [IO.DirectoryNotFoundException]{return}
    try{
        if($stream.Length -gt 256KB){throw 'The user region record is too large.'}
        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true))
        try{$reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop}
        finally{$reader.Dispose()}
    }finally{$stream.Dispose()}
}

function Save-GuardUserRegionJson([string]$Name,$Value) {
    $path=Get-GuardUserRegionPath $Name -Create
    $temporary=$path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try{
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 16 -Compress))
        if($bytes.Length -gt 256KB){throw 'The user region record is too large.'}
        $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,
            [IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}
        finally{$stream.Dispose()}
        $null=Get-GuardUserRegionPath $Name
        if([IO.File]::Exists($path)){[IO.File]::Replace($temporary,$path,[NullString]::Value)}
        else{[IO.File]::Move($temporary,$path)}
    }finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}

function New-GuardUserRegionMutex([string]$OwnerSid) {
    $sid=[Security.Principal.SecurityIdentifier]::new($OwnerSid)
    $security=[Security.AccessControl.MutexSecurity]::new()
    $security.SetAccessRule([Security.AccessControl.MutexAccessRule]::new(
        $sid,[Security.AccessControl.MutexRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    $created=$false
    [Threading.Mutex]::new($false,('Global\ClaudeVPNGuard_UserRegion_'+$OwnerSid),[ref]$created,$security)
}

function Get-GuardUserRegionResult([string]$BundleRoot,[string]$CountryCode,$Operations) {
    $ErrorActionPreference='Stop'
    $saved=if($Operations){& $Operations.ReadResult}else{Read-GuardUserRegionJson 'user-region-result.json'}
    if(-not $BundleRoot){return $saved}
    if(-not $Operations){
        . (Join-Path $BundleRoot 'release\guard-profile-actions.ps1')
        $Operations=New-GuardUserRegionOperations
    }
    if($saved){return (Get-GuardUserRegionReceiptView $saved $Operations)}
    $current=try{& $Operations.ReadState}catch{}
    $binding=try{
        $record=& $Operations.ReadBinding
        if(-not (Test-GuardUserRegionIpv4 $record.ExpectedIpv4)){throw 'No verified pinned IPv4.'}
        Assert-GuardUserRegionBinding $record (& $Operations.Owner) $record.ExpectedIpv4
        $record
    }catch{}
    # A shared Windows time zone cannot establish a country. Use an
    # explicitly supplied country only as a proposed regional target.
    $target=$null
    $plan=if($binding -and $CountryCode -cmatch '\A[A-Z]{2}\z'){
        try{& $Operations.Plan $BundleRoot $CountryCode}catch{}
    }
    if($plan -and $current.TimeZone -ceq $plan.Zone.WindowsTimeZoneId){
        $target=$CountryCode
        $edge=if($plan.Edge){$plan.Edge.After}else{@{AcceptLanguages=$plan.PrimaryLanguage;DisplayLocale=$plan.EdgeBefore.DisplayLocale}}
        $targets=Format-GuardUserRegionState $plan.Windows.After @{Id=$plan.Zone.WindowsTimeZoneId} $edge
    }
    [pscustomobject]@{
        Version=1;Outcome='Preview';Utc=[datetime]::UtcNow.ToString('o');RequestId=$null;Generation=$binding.Generation
        CountryCode=$target;ExpectedIpv4=$binding.ExpectedIpv4;ObservedIpv4=$null;GuardHealth=(Get-GuardUserRegionHealth $Operations)
        Before=$current;After=$current;Current=$current;Targets=$targets;PrimaryLanguage=$null;BrowserProfile=$null
        WindowsLanguageStatus='NotChecked';WindowsLanguageReason=$null
        EdgeStatus='NotChecked';WebsiteStatus='NotChecked';SiteAcceptLanguage=$null
        Message='Current settings and saved route only. The exit country and website language have not been checked.'
    }
}

function Test-GuardUserRegionIpv4([string]$Value) {
    $address=$null
    [ipaddress]::TryParse($Value,[ref]$address) -and $address.AddressFamily -eq 'InterNetwork' -and $address.ToString() -ceq $Value
}

function Assert-GuardUserRegionBinding($Binding,[string]$OwnerSid,[string]$ExpectedIpv4,$Previous) {
    $vpn=[guid]::Empty
    if($null -eq $Binding -or $Binding.Version -ne 2 -or $Binding.Containment -cne 'Sandboxie' -or
        $Binding.Generation -cnotmatch '\A[A-F0-9]{64}\z' -or $Binding.RouteHash -cnotmatch '\A[A-F0-9]{64}\z' -or
        $Binding.SelectionHash -cne $Binding.RouteHash -or $Binding.Port -lt 1024 -or $Binding.Port -ge 49152 -or
        $Binding.LaunchUserSid -cne $OwnerSid -or $Binding.ExpectedIpv4 -cne $ExpectedIpv4 -or
        -not [guid]::TryParse([string]$Binding.VpnGuid,[ref]$vpn) -or $vpn -eq [guid]::Empty -or
        ($Previous -and ($Binding.Generation -cne $Previous.Generation -or $Binding.RouteHash -cne $Previous.RouteHash -or
            $Binding.Port -ne $Previous.Port -or $Binding.VpnGuid -ne $Previous.VpnGuid))){
        throw 'The current Bettbox selection and pinned IPv4 must match the existing Guard record for this Windows account.'
    }
}

function Test-GuardUserRegionProbe($Proof,[string]$CountryCode,[string]$ExpectedIpv4) {
    $checked=[datetimeoffset]::MinValue
    $now=[datetimeoffset]::UtcNow
    $Proof.Passed -is [bool] -and $Proof.Passed -and $Proof.State -ceq 'Completed' -and $Proof.Provider -ceq 'CloudflareTrace' -and
        $Proof.CountryCode -ceq $CountryCode -and $Proof.ExitIpv4 -ceq $ExpectedIpv4 -and
        [datetimeoffset]::TryParse([string]$Proof.CheckedUtc,[ref]$checked) -and $checked -le $now -and
        ($now-$checked).TotalMinutes -lt 5
}

function Format-GuardUserRegionState($Windows,$Zone,$Edge) {
    [pscustomobject]@{
        TimeZone=$Zone.Id;CountryCode=$Windows.CountryCode;LocaleName=$Windows.LocaleName
        ShortDate=$Windows.Format.ShortDate;ShortTime=$Windows.Format.ShortTime
        PreferredLanguages=@($Windows.Languages | ForEach-Object LanguageTag)
        DisplayLanguage=$Windows.EffectiveUiLanguage;DefaultInputMethod=$Windows.EffectiveInputMethod
        EdgeLanguages=$Edge.AcceptLanguages;EdgeDisplayLanguage=$Edge.DisplayLocale
    }
}

function Get-GuardUserRegionPlan([string]$BundleRoot,[string]$CountryCode) {
    $zones=Get-GuardSettingsTimeZones $BundleRoot
    $choice=Get-GuardSettingsRegionChoice $zones 'Automatic' $CountryCode
    $target=Get-GuardNodeLocaleTarget -CountryCode $CountryCode
    if($choice.RequiresChoice -or $target.RequiresChoice){throw 'Windows has no unique time zone and regional format for this country.'}
    $ops=New-GuardWindowsRegionOperations
    $zone=New-GuardRegionProfilePlan -ProfileId $choice.Id -ObservedCountryCode $CountryCode -Operations $ops
    $windows=New-GuardWindowsLocalePlan -Target $target
    $state=Get-GuardBrowserLanguageState
    $edge=if($state.Available){try{New-GuardBrowserLanguagePlan -Target $target.LanguageTag -State $state}catch{}}
    $primary=if($edge){$edge.PrimaryLanguage}else{
        try{Resolve-GuardEdgeLanguage $target.LanguageTag @(([string]$state.AcceptLanguages).Split(','))}
        catch{$target.LanguageTag}
    }
    [pscustomobject]@{
        Zone=$zone;Windows=$windows;Edge=$edge;EdgeBefore=$state
        PrimaryLanguage=$primary
    }
}

function New-GuardUserRegionOperations {
    @{
        Owner={([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value}
        Lock={param($sid) New-GuardUserRegionMutex $sid}
        ReadResult={Read-GuardUserRegionJson 'user-region-result.json'}
        SaveResult={param($value) Save-GuardUserRegionJson 'user-region-result.json' $value}
        ReadJournal={Read-GuardUserRegionJson 'user-region-recovery.json'}
        SaveJournal={param($value) Save-GuardUserRegionJson 'user-region-recovery.json' $value}
        ClearJournal={[IO.File]::Delete((Get-GuardUserRegionPath 'user-region-recovery.json'))}
        ReadBinding={
            if((Test-GuardDailyReleasePending) -or (Test-GuardDailyRevisionInProgress) -or
                [IO.File]::Exists((Get-GuardDataPath 'daily-package-pending.json'))){
                throw 'Guard maintenance is pending.'
            }
            $record=Read-GuardDailyRecord 'daily-provisioned.json'
            if(-not (Test-GuardDailyScopeBinding $record)){throw 'The approved Guard route could not be verified.'}
            $selection=Get-GuardCurrentBettboxProfile
            try{$hash=(Get-GuardNodeProfileRoute $selection $record.Port).Hash}
            finally{$selection.Password.Dispose()}
            [pscustomobject]@{
                Version=$record.Version;Containment=$record.Containment;Generation=$record.Generation
                LaunchUserSid=$record.LaunchUserSid;RouteHash=$record.RouteHash;SelectionHash=$hash
                Port=$record.Port;ExpectedIpv4=$record.ExpectedIpv4;VpnGuid=$record.VpnGuid
            }
        }
        Probe={
            param($root,$binding)
            if((Get-GuardVpnAdapter ([string]$binding.VpnGuid)).Name -cne 'Bettbox'){throw 'The approved Bettbox tunnel is unavailable.'}
            $selection=Get-GuardCurrentBettboxProfile
            try{
                if((Get-GuardNodeProfileRoute $selection $binding.Port).Hash -cne $binding.RouteHash){throw 'The selected route changed.'}
                $proof=Invoke-GuardNodeProbe -Profile $selection -Assets (Get-GuardSettingsProbeAssets $root) -BackupExitLookup:$false
                Assert-GuardSettingsPreview $selection $proof
                $proof
            }finally{$selection.Password.Dispose()}
        }
        ReadHealth={Get-GuardDailyStatus}
        Plan={param($root,$country) Get-GuardUserRegionPlan $root $country}
        ReadState={
            $windows=Get-GuardWindowsLocaleState
            $zone=& (New-GuardWindowsRegionOperations).Read
            $edge=Get-GuardBrowserLanguageState
            Format-GuardUserRegionState $windows $zone $edge
        }
        ApplyZone={
            param($plan)
            Invoke-GuardRegionProfileChange -Plan $plan -Operations (New-GuardWindowsRegionOperations) -PersistUndo {}
        }
        VerifyZone={
            param($plan)
            $zone=& (New-GuardWindowsRegionOperations).Read
            $zone.Id -ceq $plan.WindowsTimeZoneId -and (-not $plan.Changes.Count -or -not $zone.DaylightDisabled)
        }
        RestoreZone={param($plan) Undo-GuardRegionProfileChange -Plan $plan -Operations (New-GuardWindowsRegionOperations)}
        ApplyWindows={param($plan,$persist) Set-GuardWindowsLocalePlan -Plan $plan -PersistWrite $persist -AllowManualPreferredLanguage}
        VerifyWindows={param($plan,$manualLanguages) Test-GuardWindowsLocalePlan -Plan $plan -AllowOriginalLanguages:$manualLanguages}
        CheckLiveLanguages={
            param($target)
            $independent=Get-GuardWindowsIndependentLanguages 0
            $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if($independent.OwnerSid -cne $owner){return $false}
            foreach($source in 'Saved','Native','WinRt'){
                if(-not (Test-GuardWindowsPreferredLanguage $independent.$source[0] $target)){return $false}
            }
            $true
        }
        WindowsDifferences={
            param($plan)
            Get-GuardWindowsLocaleDifferences (Get-GuardWindowsLocaleState) $plan.After $plan
        }
        RestoreWindows={param($plan,$pending) Restore-GuardWindowsLocalePlan -Plan $plan -PendingWrite $pending}
        EdgeMode={
            param($plan)
            $edgeOperations=Get-GuardEdgeLanguageOperations
            if(& $edgeOperations.IsBusy){return 'ManualRequired'}
            Get-GuardBrowserLanguageApplyMode -Plan $plan -Operations $edgeOperations
        }
        ApplyEdge={param($plan) Set-GuardBrowserLanguagePlan -Plan $plan}
        VerifyEdge={param($plan) Test-GuardBrowserLanguagePlan -Plan $plan}
        RestoreEdge={param($plan) Restore-GuardBrowserLanguagePlan -Plan $plan}
        QuietSite={param($plan) Test-GuardBrowserSiteLanguageQuiet -Plan $plan}
        CurrentEdgePlan={
            param($target)
            New-GuardBrowserLanguagePlan -Target $target -State (Get-GuardBrowserLanguageState)
        }
        ConfirmSite={param($plan) Confirm-GuardBrowserSiteLanguage -Plan $plan}
    }
}

function Get-GuardUserRegionHealth($Operations) {
    $record=try{& $Operations.ReadHealth}catch{}
    $health=[ordered]@{CheckedUtc=[datetime]::UtcNow.ToString('o')}
    foreach($name in 'Readiness','Reason','Gate','Policy','Exit','Proxy'){
        $value=[string]$record.$name
        $health[$name]=if($value -cmatch '\A[A-Za-z][A-Za-z0-9]{0,63}\z'){$value}else{'Unknown'}
    }
    [pscustomobject]$health
}

function Get-GuardUserRegionReceiptView($Saved,$Operations) {
    $view=$Saved.PSObject.Copy()
    $current=try{& $Operations.ReadState}catch{}
    $view | Add-Member -NotePropertyName Current -NotePropertyValue $current -Force
    $view.GuardHealth=Get-GuardUserRegionHealth $Operations
    if($view.Outcome -cnotin 'Applied','ManualRequired'){return $view}
    $expected=@($view.Targets.PreferredLanguages)[0]
    $primary=@($current.PreferredLanguages)[0]
    $verified=$false
    if($current -and $expected -and ($primary -ieq $expected -or ($primary -ieq 'ja' -and $expected -ieq 'ja-JP'))){
        $verified=if($Operations.CheckLiveLanguages){try{& $Operations.CheckLiveLanguages $expected}catch{$false}}else{$true}
    }
    $status=if($verified){'Verified'}elseif($current){'ManualRequired'}else{'NotChecked'}
    $reason=if($status -ceq 'ManualRequired'){'PreferredLanguageNotRetained'}
    $view | Add-Member -NotePropertyName WindowsLanguageStatus -NotePropertyValue $status -Force
    $view | Add-Member -NotePropertyName WindowsLanguageReason -NotePropertyValue $reason -Force
    if($status -ceq 'ManualRequired'){
        $view.Outcome='ManualRequired'
        $view.Message='Windows preferred language needs attention. See the current region and format separately.'
    }elseif($status -ceq 'NotChecked'){
        $view.Outcome='ManualRequired'
        $view.Message='Current Windows preferred language could not be checked.'
    }elseif($view.EdgeStatus -ceq 'PreferencesVerified'){
        $view.Outcome='Applied'
        $view.Message='Windows regional settings and Edge website language preferences were verified.'
    }
    $view
}

function Restore-GuardUserRegion($Journal,[string]$OwnerSid,$Operations) {
    if($Journal.Version -ne 1 -or $Journal.OwnerSid -cne $OwnerSid -or
        $Journal.RequestId -cnotmatch '\A[a-f0-9]{32}\z' -or -not $Journal.Zone -or -not $Journal.Windows -or
        $Journal.Windows.Before.OwnerSid -cne $OwnerSid){throw 'The saved user region recovery record is invalid.'}
    $failed=$false
    if($Journal.EdgeAttempted){
        try{$null=& $Operations.RestoreEdge $Journal.Edge}catch{$failed=$true}
    }
    if($Journal.WindowsAttempted){
        try{if((& $Operations.RestoreWindows $Journal.Windows $Journal.WindowsPendingWrite) -ceq 'PreservedManualChange'){$failed=$true}}
        catch{$failed=$true}
    }
    if($Journal.ZoneAttempted){
        try{if((& $Operations.RestoreZone $Journal.Zone) -ceq 'PreservedManualChange'){$failed=$true}}
        catch{$failed=$true}
    }
    if($failed){throw 'Some prior regional settings need review. The recovery record was kept.'}
    $null=& $Operations.ClearJournal
}

function Get-GuardUserRegionDiagnostic([string]$Step,[Exception]$Exception) {
    $result=[ordered]@{
        Step=$Step;WindowsStage=$null;WindowsSetting=$null;WindowsDifferences=@()
        WindowsRollback=$null;EdgeFailure=$null;NativeError=$null;ErrorType=$Exception.GetType().Name;Recovery=$null
    }
    for($cause=$Exception;$cause;$cause=$cause.InnerException){
        if(-not $result.WindowsStage -and $cause.Data['GuardWindowsLocaleStage']){
            $result.WindowsStage=[string]$cause.Data['GuardWindowsLocaleStage']
            $result.WindowsSetting=[string]$cause.Data['GuardWindowsLocaleSetting']
            $result.WindowsRollback=[string]$cause.Data['GuardWindowsLocaleRollback']
            $result.WindowsDifferences=@($cause.Data['GuardWindowsLocaleDifferences'] | Where-Object {
                $_ -is [string] -and $_ -cmatch '\A[A-Za-z][A-Za-z0-9.]{0,79}\z'
            } | Select-Object -First 32)
        }
        $edge=[string]$cause.Data['GuardBrowserFailure']
        if(-not $result.EdgeFailure -and $edge -cmatch '\AEdge[A-Za-z0-9]{1,64}\z'){$result.EdgeFailure=$edge}
        if($null -eq $result.NativeError){
            if($cause -is [ComponentModel.Win32Exception]){$result.NativeError=$cause.NativeErrorCode}
            elseif($cause -is [Runtime.InteropServices.COMException]){$result.NativeError=$cause.HResult}
        }
    }
    [pscustomobject]$result
}

function Invoke-GuardUserRegion(
    [Parameter(Mandatory)][string]$BundleRoot,[Parameter(Mandatory)][string]$CountryCode,
    [Parameter(Mandatory)][string]$ExpectedIpv4,[Parameter(Mandatory)][string]$RequestId,$Operations
) {
    $ErrorActionPreference='Stop'
    if($RequestId -cnotmatch '\A[a-f0-9]{32}\z' -or $CountryCode -cnotmatch '\A[A-Z]{2}\z' -or
        -not (Test-GuardUserRegionIpv4 $ExpectedIpv4)){throw 'The region request requires a country code and a canonical IPv4 address.'}
    if(-not $Operations){
        . (Join-Path $BundleRoot 'release\guard-profile-actions.ps1')
        . (Join-Path $BundleRoot 'package\guard-daily-plan.ps1')
        $Operations=New-GuardUserRegionOperations
    }
    $result=[pscustomobject][ordered]@{
        Version=1;Outcome='Failed';Utc=$null;RequestId=$RequestId;Generation=$null
        CountryCode=$CountryCode;ExpectedIpv4=$ExpectedIpv4;ObservedIpv4=$null;GuardHealth=$null
        Before=$null;After=$null;Current=$null;Targets=$null;PrimaryLanguage=$null;BrowserProfile=$null
        WindowsLanguageStatus='NotChecked';WindowsLanguageReason=$null
        EdgeStatus='NotChecked';WebsiteStatus='NotChecked';SiteAcceptLanguage=$null;Message=$null;Diagnostics=$null
    }
    $owner=& $Operations.Owner
    $mutex=& $Operations.Lock $owner
    $held=$false
    $journal=$null
    $published=$false
    $phase='RecoveryRequired'
    $step='PriorRecovery'
    try{
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){
            $result.Outcome='Busy'
            $result.Message='Another regional settings action is running for this Windows account.'
            return $result
        }
        $old=& $Operations.ReadJournal
        $previous=& $Operations.ReadResult
        if($old){
            if($old.OwnerSid -ceq $owner -and $previous.RequestId -ceq $old.RequestId -and
                $previous.Generation -ceq $old.Generation -and $previous.Outcome -cin 'Applied','ManualRequired'){
                $null=& $Operations.ClearJournal
            }else{Restore-GuardUserRegion $old $owner $Operations}
        }
        $phase='RouteMismatch'
        $step='InitialRouteBinding'
        $binding=& $Operations.ReadBinding
        Assert-GuardUserRegionBinding $binding $owner $ExpectedIpv4
        $result.Generation=$binding.Generation
        if($previous.RequestId -ceq $RequestId -and $previous.Generation -ceq $binding.Generation -and
            $previous.CountryCode -ceq $CountryCode -and $previous.ExpectedIpv4 -ceq $ExpectedIpv4 -and
            $previous.Outcome -cin 'Applied','ManualRequired'){
            return (Get-GuardUserRegionReceiptView $previous $Operations)
        }
        $phase='ProbeMismatch'
        $step='ExitProbe'
        $proof=& $Operations.Probe $BundleRoot $binding
        if(Test-GuardUserRegionIpv4 ([string]$proof.ExitIpv4)){$result.ObservedIpv4=$proof.ExitIpv4}
        if(-not (Test-GuardUserRegionProbe $proof $CountryCode $ExpectedIpv4)){throw 'The observed exit did not match the requested country and IPv4.'}
        $phase='PlanningFailed'
        $step='Plan'
        $plan=& $Operations.Plan $BundleRoot $CountryCode
        $result.PrimaryLanguage=$plan.PrimaryLanguage
        $result.BrowserProfile=$plan.EdgeBefore.Profile
        $result.Before=Format-GuardUserRegionState $plan.Windows.Before @{Id=$plan.Zone.CurrentTimeZoneId} $plan.EdgeBefore
        $edgeTarget=if($plan.Edge){$plan.Edge.After}else{@{AcceptLanguages=$plan.PrimaryLanguage;DisplayLocale=$plan.EdgeBefore.DisplayLocale}}
        $result.Targets=Format-GuardUserRegionState $plan.Windows.After @{Id=$plan.Zone.WindowsTimeZoneId} $edgeTarget
        $phase='RouteMismatch'
        $step='PreApplyRouteBinding'
        Assert-GuardUserRegionBinding (& $Operations.ReadBinding) $owner $ExpectedIpv4 $binding
        if(-not (Test-GuardUserRegionProbe $proof $CountryCode $ExpectedIpv4)){throw 'The exit check is no longer current.'}

        $phase='ApplyFailed'
        $step='UserRecoveryJournal'
        $journal=[pscustomobject]@{
            Version=1;OwnerSid=$owner;RequestId=$RequestId;Generation=$binding.Generation
            Zone=$plan.Zone;Windows=$plan.Windows;Edge=$plan.Edge
            ZoneAttempted=$false;WindowsAttempted=$false;WindowsPendingWrite=$null;EdgeAttempted=$false
        }
        $saveJournal=$Operations.SaveJournal
        $journal.ZoneAttempted=$true
        try{$null=& $saveJournal $journal}catch{$journal.ZoneAttempted=$false;throw}
        $step='WindowsTimeZoneApply'
        $null=& $Operations.ApplyZone $plan.Zone
        $step='UserRecoveryJournal'
        $journal.WindowsAttempted=$true
        try{$null=& $saveJournal $journal}catch{$journal.WindowsAttempted=$false;throw}
        $persist={param($setting) $journal.WindowsPendingWrite=$setting; $null=& $saveJournal $journal}.GetNewClosure()
        $step='WindowsLocaleApply'
        $windowsOutcome=& $Operations.ApplyWindows $plan.Windows $persist
        $manualLanguages=$windowsOutcome -ceq 'ManualRequired'
        $step='WindowsTimeZoneVerification'
        if(-not (& $Operations.VerifyZone $plan.Zone)){throw 'Windows time zone did not pass readback.'}
        $step='WindowsLocaleVerification'
        if(-not (& $Operations.VerifyWindows $plan.Windows $manualLanguages)){
            $differences=if($Operations.WindowsDifferences){try{& $Operations.WindowsDifferences $plan.Windows}catch{}}
            $failure=[InvalidOperationException]::new('Windows regional settings did not pass readback.')
            $failure.Data['GuardWindowsLocaleStage']='FinalMismatch'
            $failure.Data['GuardWindowsLocaleDifferences']=@($differences)
            throw $failure
        }
        $result.WindowsLanguageStatus=if($manualLanguages){'ManualRequired'}else{'Verified'}
        if($manualLanguages){$result.WindowsLanguageReason='PreferredLanguageNotRetained'}
        $result.EdgeStatus='ManualRequired'
        $result.WebsiteStatus='AwaitingBrowser'
        $step='EdgeAvailability'
        if($plan.Edge -and (& $Operations.EdgeMode $plan.Edge) -cne 'ManualRequired'){
            $step='UserRecoveryJournal'
            $journal.EdgeAttempted=$true
            try{$null=& $saveJournal $journal}catch{$journal.EdgeAttempted=$false;throw}
            try{
                $step='EdgeApply'
                $null=& $Operations.ApplyEdge $plan.Edge
                $step='EdgeVerification'
                if(-not (& $Operations.VerifyEdge $plan.Edge)){throw 'Edge did not save the preferred languages.'}
                $result.EdgeStatus='PreferencesVerified'
            }catch{
                if($_.Exception.Data['GuardBrowserFailure'] -cne 'EdgeLanguageManualRequired'){throw}
            }
            if($result.EdgeStatus -ceq 'PreferencesVerified'){
                $cached=try{& $Operations.QuietSite $plan.Edge}catch{}
                if($cached -is [string] -and $cached -cmatch '\A[A-Za-z0-9,;= .\-]{1,512}\z'){
                    $result.SiteAcceptLanguage=$cached
                    $result.WebsiteStatus='Verified'
                }
            }
        }
        $step='FinalRouteBinding'
        Assert-GuardUserRegionBinding (& $Operations.ReadBinding) $owner $ExpectedIpv4 $binding
        $step='FinalSettingsRead'
        $result.After=& $Operations.ReadState
        $result.Current=$result.After
        $manualEdge=$result.EdgeStatus -ceq 'ManualRequired'
        $result.Outcome=if($manualLanguages -or $manualEdge){'ManualRequired'}else{'Applied'}
        $result.Message=if($manualLanguages -and $manualEdge){'Windows region and format were verified. Preferred languages in Windows and Edge need attention.'}
            elseif($manualLanguages){'Windows region and format and Edge preferences were verified. Windows preferred language needs attention.'}
            elseif($manualEdge){'Windows regional settings were verified. Edge website languages need attention.'}
            else{'Windows regional settings and Edge website language preferences were verified.'}
        $result.GuardHealth=Get-GuardUserRegionHealth $Operations
        $result.Utc=[datetime]::UtcNow.ToString('o')
        $step='ResultPublication'
        $null=& $Operations.SaveResult $result
        $published=$true
        try{$null=& $Operations.ClearJournal}catch{}
        return $result
    }catch{
        $diagnostic=Get-GuardUserRegionDiagnostic $step $_.Exception
        $diagnostic.Recovery='NotRequired'
        if($held -and $journal -and -not $published){
            try{
                Restore-GuardUserRegion $journal $owner $Operations
                $diagnostic.Recovery='Verified'
            }catch{$phase='RecoveryRequired'}
        }
        if($phase -ceq 'RecoveryRequired'){$diagnostic.Recovery='Outstanding'}
        if($held){
            $result.After=try{& $Operations.ReadState}catch{}
            $result.GuardHealth=Get-GuardUserRegionHealth $Operations
        }
        $result.Outcome=if($phase -ceq 'RecoveryRequired'){'RecoveryRequired'}else{'Failed'}
        $result.EdgeStatus='NotChecked'
        $result.WindowsLanguageStatus='NotChecked'
        $result.WindowsLanguageReason=$null
        $result.WebsiteStatus='NotChecked'
        $result.SiteAcceptLanguage=$null
        $result.Diagnostics=$diagnostic
        $result.Message=switch -Exact ($phase){
            'RecoveryRequired' {'Prior regional settings need review before another change.'}
            'RouteMismatch' {'The current Bettbox selection and pinned IPv4 must match the existing Guard record.'}
            'ProbeMismatch' {'The observed exit did not match the requested country and IPv4, or could not be verified.'}
            'PlanningFailed' {'Windows could not prepare a matching regional settings change while preserving the current menu and keyboard.'}
            default {'The regional change failed. The prior settings were verified.'}
        }
        $result.Utc=[datetime]::UtcNow.ToString('o')
        if($held){try{$null=& $Operations.SaveResult $result}catch{}}
        return $result
    }finally{
        if($held){$mutex.ReleaseMutex()}
        $mutex.Dispose()
    }
}

function Confirm-GuardUserRegionSite([Parameter(Mandatory)][string]$BundleRoot,$Operations) {
    $ErrorActionPreference='Stop'
    if(-not $Operations){
        . (Join-Path $BundleRoot 'release\guard-profile-actions.ps1')
        . (Join-Path $BundleRoot 'package\guard-daily-plan.ps1')
        $Operations=New-GuardUserRegionOperations
    }
    $owner=& $Operations.Owner
    $mutex=& $Operations.Lock $owner
    $held=$false
    try{
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'Another regional settings action is running.'}
        $receipt=& $Operations.ReadResult
        if($receipt.Version -ne 1 -or $receipt.Outcome -cnotin 'Applied','ManualRequired' -or
            $receipt.RequestId -cnotmatch '\A[a-f0-9]{32}\z' -or
            $receipt.PrimaryLanguage -cnotmatch '\A[A-Za-z0-9-]{1,45}\z' -or
            $receipt.BrowserProfile -cnotmatch '\A(?:Default|Profile [1-9][0-9]*)\z'){
            throw 'Apply the regional settings for the current route before checking website languages.'
        }
        $pending=& $Operations.ReadJournal
        if($pending){
            if($pending.OwnerSid -cne $owner -or $pending.RequestId -cne $receipt.RequestId -or
                $pending.Generation -cne $receipt.Generation){throw 'Prior regional settings need review before a website check.'}
            $null=& $Operations.ClearJournal
        }
        $binding=& $Operations.ReadBinding
        Assert-GuardUserRegionBinding $binding $owner $receipt.ExpectedIpv4
        if($binding.Generation -cne $receipt.Generation){throw 'The approved route changed since the regional settings were applied.'}
        $plan=& $Operations.CurrentEdgePlan $receipt.PrimaryLanguage
        if($plan.Changed -or $plan.Profile -cne $receipt.BrowserProfile -or $plan.PrimaryLanguage -ine $receipt.PrimaryLanguage){
            throw 'Put the requested language first in the same Edge profile before checking a website.'
        }
        try{$header=& $Operations.ConfirmSite $plan}
        catch{throw 'The website did not return a verifiable language header from the selected Edge profile.'}
        if($header -isnot [string] -or $header -cnotmatch '\A[A-Za-z0-9,;= .\-]{1,512}\z'){
            throw 'The website did not return a verifiable language header.'
        }
        Assert-GuardUserRegionBinding (& $Operations.ReadBinding) $owner $receipt.ExpectedIpv4 $binding
        if(-not (& $Operations.VerifyEdge $plan)){throw 'Edge website languages changed while checking the header.'}
        $receipt.After=& $Operations.ReadState
        $receipt | Add-Member -NotePropertyName Current -NotePropertyValue $receipt.After -Force
        $receipt.EdgeStatus='PreferencesVerified'
        $receipt.WebsiteStatus='Verified'
        $receipt.SiteAcceptLanguage=$header
        $receipt.Message='The selected Edge profile sent the verified website language header.'
        $receipt.GuardHealth=Get-GuardUserRegionHealth $Operations
        $receipt.Utc=[datetime]::UtcNow.ToString('o')
        $null=& $Operations.SaveResult $receipt
        return $header
    }finally{
        if($held){$mutex.ReleaseMutex()}
        $mutex.Dispose()
    }
}
