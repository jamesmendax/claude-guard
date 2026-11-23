# This layer changes the Windows time zone only. Route verification and the
# protected switch journal are owned by the caller.
function Get-GuardRegionProfiles {
    [pscustomobject]@{Id='Keep';CountryCode=$null;IanaTimeZone=$null;WindowsTimeZoneId=$null;Default=$true}
    [pscustomobject]@{Id='Japan';CountryCode='JP';IanaTimeZone='Asia/Tokyo';WindowsTimeZoneId='Tokyo Standard Time';Default=$false}
    [pscustomobject]@{Id='UsPacific';CountryCode='US';IanaTimeZone='America/Los_Angeles';WindowsTimeZoneId='Pacific Standard Time';Default=$false}
}

function New-GuardWindowsRegionOperations {
    @{
        Read={
            [TimeZoneInfo]::ClearCachedData()
            $zone=Get-TimeZone -ErrorAction Stop
            $settings=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -ErrorAction Stop
            $auto=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate' -ErrorAction SilentlyContinue).Start
            [pscustomobject]@{
                Id=$zone.Id;DaylightDisabled=($settings.DynamicDaylightTimeDisabled -eq 1)
                AutomaticTimeZoneEnabled=$(if($auto -in 3,4){$auto -eq 3})
            }
        }
        Write={
            param($State)
            $zone=[TimeZoneInfo]::FindSystemTimeZoneById($State.Id)
            $target=$zone.Id
            if($State.DaylightDisabled){$target+='_dstoff'}
            $null=& (Join-Path ([Environment]::GetFolderPath('System')) 'tzutil.exe') /s $target 2>&1
            if($LASTEXITCODE -ne 0){throw 'Windows refused the time zone change.'}
        }
    }
}

function Get-GuardRegionProfile([string]$ProfileId){
    if($ProfileId.StartsWith('Windows/',[StringComparison]::Ordinal)){
        $id=$ProfileId.Substring(8)
        $zone=[TimeZoneInfo]::GetSystemTimeZones() | Where-Object { [string]::Equals($_.Id,$id,[StringComparison]::Ordinal) } | Select-Object -First 1
        if(-not $zone){throw 'Select a supported Windows time zone.'}
        return [pscustomobject]@{Id=$ProfileId;CountryCode=$null;IanaTimeZone=$null;WindowsTimeZoneId=$id;Default=$false}
    }
    $profile=Get-GuardRegionProfiles | Where-Object Id -CEQ $ProfileId
    if(-not $profile){throw 'Select a supported region profile.'}
    $profile
}

function Assert-GuardRegionTimeZone($State){
    if($State.Id -isnot [string] -or [string]::IsNullOrWhiteSpace($State.Id) -or
        $State.Id -match '[\x00-\x1f]' -or $State.DaylightDisabled -isnot [bool]){
        throw 'The Windows time zone state is unavailable or invalid.'
    }
}

function Test-GuardRegionTimeZone($Left,$Right){
    $Left.Id -ceq $Right.Id -and $Left.DaylightDisabled -eq $Right.DaylightDisabled
}

function Assert-GuardRegionCountry($Profile,[string]$Country){
    if($Profile.Default -or -not $Country -or -not $Profile.CountryCode){return}
    if($Country -cnotmatch '\A[A-Z]{2}\z' -or $Country -cne $Profile.CountryCode){
        throw 'The observed country does not match the selected time zone profile.'
    }
}

function New-GuardRegionProfilePlan([string]$ProfileId='Keep',[string]$ObservedCountryCode,$Operations){
    $profile=Get-GuardRegionProfile $ProfileId
    $country=$ObservedCountryCode.ToUpperInvariant()
    Assert-GuardRegionCountry $profile $country
    $changes=@()
    $automatic=$null
    $before=$null
    if(-not $profile.Default){
        if($Operations.Read -isnot [scriptblock]){throw 'A Windows time zone reader is required.'}
        $before=& $Operations.Read
        Assert-GuardRegionTimeZone $before
        $automatic=$before.AutomaticTimeZoneEnabled
        if($before.Id -cne $profile.WindowsTimeZoneId){
            $changes=@([pscustomobject]@{
                Name='TimeZone';Scope='Machine'
                Before=[pscustomobject]@{Id=$before.Id;DaylightDisabled=$before.DaylightDisabled}
                After=[pscustomobject]@{Id=$profile.WindowsTimeZoneId;DaylightDisabled=$false}
            })
        }
    }
    [pscustomobject]@{
        Version=1;ProfileId=$profile.Id;CountryCode=$profile.CountryCode;WindowsTimeZoneId=$profile.WindowsTimeZoneId
        ObservedCountryCode=$(if($country){$country})
        LocationBasis=$(if($profile.Default){'Keep'}elseif($country){'ManualSelectionAndCountryMatch'}else{'ManualSelection'})
        CurrentTimeZoneId=$before.Id;AutomaticTimeZoneEnabled=$automatic;Changes=$changes
    }
}

function Get-GuardRegionProfileChange($Plan){
    $profile=Get-GuardRegionProfile $Plan.ProfileId
    Assert-GuardRegionCountry $profile $Plan.ObservedCountryCode
    $changes=@($Plan.Changes)
    if($Plan.Version -ne 1 -or $changes.Count -gt 1 -or ($profile.Default -and $changes.Count)){
        throw 'The region profile plan is invalid.'
    }
    if(-not $changes.Count){return}
    $change=$changes[0]
    Assert-GuardRegionTimeZone $change.Before
    Assert-GuardRegionTimeZone $change.After
    if($change.Name -cne 'TimeZone' -or $change.Scope -cne 'Machine' -or
        $change.After.Id -cne $profile.WindowsTimeZoneId -or $change.After.DaylightDisabled -or $change.Before.Id -ceq $change.After.Id){
        throw 'The plan does not describe one approved Windows time zone change.'
    }
    $change
}

function Restore-GuardRegionTimeZone($Change,$Operations,[switch]$ApplyFailed){
    $current=& $Operations.Read
    Assert-GuardRegionTimeZone $current
    if(Test-GuardRegionTimeZone $current $Change.Before){return 'Unchanged'}
    # During a failed write the target ID can be visible before the new daylight
    # setting is verified. A later rollback preserves an independently changed time zone.
    if(-not (Test-GuardRegionTimeZone $current $Change.After) -and -not ($ApplyFailed -and $current.Id -ceq $Change.After.Id)){
        return 'PreservedManualChange'
    }
    $null=& $Operations.Write $Change.Before
    $verified=& $Operations.Read
    Assert-GuardRegionTimeZone $verified
    if(-not (Test-GuardRegionTimeZone $verified $Change.Before)){throw 'Windows did not restore the original time zone.'}
    'Restored'
}

function Undo-GuardRegionProfileChange($Plan,$Operations){
    $change=Get-GuardRegionProfileChange $Plan
    if(-not $change){return 'Unchanged'}
    if($Operations.Read -isnot [scriptblock] -or $Operations.Write -isnot [scriptblock]){throw 'Time zone operations are required.'}
    Restore-GuardRegionTimeZone $change $Operations
}

function Invoke-GuardRegionProfileChange($Plan,$Operations,[scriptblock]$PersistUndo){
    $ErrorActionPreference='Stop'
    $change=Get-GuardRegionProfileChange $Plan
    if(-not $change){
        if($Plan.ProfileId -ceq 'Keep'){return 'Unchanged'}
        if($Operations.Read -isnot [scriptblock]){throw 'A Windows time zone reader is required.'}
        $current=& $Operations.Read
        Assert-GuardRegionTimeZone $current
        if($current.Id -cne (Get-GuardRegionProfile $Plan.ProfileId).WindowsTimeZoneId){
            throw 'The Windows time zone changed after the preview. Preview the change again.'
        }
        return 'Unchanged'
    }
    if($Operations.Read -isnot [scriptblock] -or $Operations.Write -isnot [scriptblock] -or -not $PersistUndo){
        throw 'Time zone operations and a protected rollback journal are required.'
    }
    $current=& $Operations.Read
    Assert-GuardRegionTimeZone $current
    if(-not (Test-GuardRegionTimeZone $current $change.Before)){throw 'The Windows time zone changed after the preview. Preview the change again.'}
    $null=& $PersistUndo $Plan
    $current=& $Operations.Read
    Assert-GuardRegionTimeZone $current
    if(-not (Test-GuardRegionTimeZone $current $change.Before)){throw 'The Windows time zone changed after the preview. Preview the change again.'}
    try{
        $null=& $Operations.Write $change.After
        $verified=& $Operations.Read
        Assert-GuardRegionTimeZone $verified
        if(-not (Test-GuardRegionTimeZone $verified $change.After)){throw 'Windows did not apply the selected time zone.'}
        return 'Applied'
    }catch{
        try{$restored=Restore-GuardRegionTimeZone $change $Operations -ApplyFailed}
        catch{throw 'The time zone change failed and rollback could not be verified. Keep the rollback journal.'}
        if($restored -ceq 'PreservedManualChange'){
            throw 'The time zone change failed. The time zone now differs from the plan. Keep the rollback journal.'
        }
        throw 'The time zone change failed. The original time zone was verified.'
    }
}
