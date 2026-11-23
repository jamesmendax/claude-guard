#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-region-profile.ps1"

function Assert-RegionTest([bool]$Condition,[string]$Message){
    if(-not $Condition){throw "FAIL: $Message"}
    "PASS: $Message"
}

function Assert-RegionError([scriptblock]$Operation,[string]$Expected){
    try{& $Operation | Out-Null}
    catch{
        if($_.Exception.Message -notlike "*$Expected*"){throw}
        return
    }
    throw "Expected error: $Expected"
}

function New-RegionTestFixture {
    $state=[pscustomobject]@{
        Id='Pacific Standard Time';DaylightDisabled=$true;AutomaticTimeZoneEnabled=$true
        WriteMode='Normal';Saved=$null;Events=[System.Collections.Generic.List[string]]::new()
    }
    $operations=@{
        Read={
            [pscustomobject]@{Id=$state.Id;DaylightDisabled=$state.DaylightDisabled;AutomaticTimeZoneEnabled=$state.AutomaticTimeZoneEnabled}
        }.GetNewClosure()
        Write={
            param($target)
            $state.Events.Add('Write '+$target.Id)
            if($state.WriteMode -ceq 'RefuseRollback' -and $target.Id -ceq 'Pacific Standard Time'){throw 'simulated rollback failure'}
            $state.Id=$target.Id
            $state.DaylightDisabled=$target.DaylightDisabled
            if($target.Id -ceq 'Tokyo Standard Time'){
                if($state.WriteMode -in 'ThrowAfterWrite','RefuseRollback'){throw 'simulated failure after writing the target'}
                if($state.WriteMode -ceq 'WrongDaylight'){$state.DaylightDisabled=$true}
            }
        }.GetNewClosure()
    }
    $save={param($plan) $state.Saved=$plan; $state.Events.Add('Save')}.GetNewClosure()
    [pscustomobject]@{State=$state;Operations=$operations;Save=$save}
}

$profiles=@(Get-GuardRegionProfiles)
Assert-RegionTest ($profiles.Count -eq 3 -and @($profiles | Where-Object Default)[0].Id -ceq 'Keep') 'the options expose Keep, Japan and US Pacific, with Keep selected by default'
$systemZones=@([TimeZoneInfo]::GetSystemTimeZones())
foreach($zone in $systemZones){
    $entry=Get-GuardRegionProfile ('Windows/'+$zone.Id)
    if($entry.WindowsTimeZoneId -cne $zone.Id){throw 'An installed time zone cannot be selected by its exact name.'}
}
Assert-RegionTest ($systemZones.Count -gt 0) 'every time zone shown by Windows can be selected, including identifiers containing parentheses'
foreach($invalid in 'Windows/pacific standard time','Windows/Not a real zone','Windows/../UTC'){
    Assert-RegionError {Get-GuardRegionProfile $invalid} 'supported Windows time zone'
}
Assert-RegionTest $true 'names absent from the installed Windows list and wrong-case spellings are rejected'
$keep=New-GuardRegionProfilePlan
Assert-RegionTest ($keep.Changes.Count -eq 0 -and (Invoke-GuardRegionProfileChange -Plan $keep) -ceq 'Unchanged') 'old installs and default plans perform no time-zone read or write'

$f=New-RegionTestFixture
$plan=New-GuardRegionProfilePlan -ProfileId Japan -ObservedCountryCode jp -Operations $f.Operations
Assert-RegionTest ($plan.Changes.Count -eq 1 -and $plan.Changes[0].Name -ceq 'TimeZone' -and $plan.Changes[0].Scope -ceq 'Machine' -and
    $plan.Changes[0].After.Id -ceq 'Tokyo Standard Time' -and $plan.LocationBasis -ceq 'ManualSelectionAndCountryMatch' -and
    $plan.AutomaticTimeZoneEnabled -and $f.State.Events.Count -eq 0) 'a matched Japan preview identifies only the Windows time-zone change without writing'
Assert-RegionError {New-GuardRegionProfilePlan -ProfileId Japan -ObservedCountryCode US -Operations $f.Operations} 'observed country does not match'
Assert-RegionTest ($f.State.Events.Count -eq 0) 'mismatched country is rejected without a write'
$manual=New-GuardRegionProfilePlan -ProfileId Japan -Operations $f.Operations
Assert-RegionTest ($manual.LocationBasis -ceq 'ManualSelection' -and -not $manual.ObservedCountryCode) 'when country evidence is unavailable, the preview says the time zone was manually selected'
Assert-RegionTest ((Invoke-GuardRegionProfileChange -Plan $plan -Operations $f.Operations -PersistUndo $f.Save) -ceq 'Applied' -and
    $f.State.Id -ceq 'Tokyo Standard Time' -and ($f.State.Events -join '|') -ceq 'Save|Write Tokyo Standard Time') 'apply saves the undo plan before the first write and verifies Tokyo'
$saved=$f.State.Saved | ConvertTo-Json -Depth 8 | ConvertFrom-Json
Assert-RegionTest ((Undo-GuardRegionProfileChange -Plan $saved -Operations $f.Operations) -ceq 'Restored' -and
    $f.State.Id -ceq 'Pacific Standard Time' -and $f.State.DaylightDisabled -and $f.State.AutomaticTimeZoneEnabled) 'a saved rollback restores the previous time zone and daylight preference'
Assert-RegionTest ((Undo-GuardRegionProfileChange -Plan $saved -Operations $f.Operations) -ceq 'Unchanged') 'repeated rollback is safe'

$f=New-RegionTestFixture
$plan=New-GuardRegionProfilePlan -ProfileId Japan -Operations $f.Operations
Assert-RegionError {Invoke-GuardRegionProfileChange -Plan $plan -Operations $f.Operations -PersistUndo {Write-Error 'simulated journal failure'}} 'simulated journal failure'
Assert-RegionTest ($f.State.Events.Count -eq 0 -and $f.State.Id -ceq 'Pacific Standard Time') 'a journal failure prevents the first write'
$f.State.Id='Eastern Standard Time'
Assert-RegionError {Invoke-GuardRegionProfileChange -Plan $plan -Operations $f.Operations -PersistUndo $f.Save} 'after the preview'
Assert-RegionTest ($f.State.Events.Count -eq 0) 'a stale preview is rejected before saving or writing'

foreach($mode in 'ThrowAfterWrite','WrongDaylight','RefuseRollback'){
    $f=New-RegionTestFixture
    $f.State.WriteMode=$mode
    $plan=New-GuardRegionProfilePlan -ProfileId Japan -Operations $f.Operations
    $errorExpected=if($mode -ceq 'RefuseRollback'){'rollback could not be verified'}else{'original time zone was verified'}
    Assert-RegionError {Invoke-GuardRegionProfileChange -Plan $plan -Operations $f.Operations -PersistUndo $f.Save} $errorExpected
    Assert-RegionTest ($f.State.Saved -and ($f.State.Events -join '|') -ceq 'Save|Write Tokyo Standard Time|Write Pacific Standard Time') "a failed write or readback preserves the recovery plan and attempts rollback ($mode)"
    if($mode -cne 'RefuseRollback'){
        Assert-RegionTest ($f.State.Id -ceq 'Pacific Standard Time' -and $f.State.DaylightDisabled) "rollback verifies the original settings ($mode)"
    }
}

$f=New-RegionTestFixture
$f.State.Id='Tokyo Standard Time'
$f.State.DaylightDisabled=$false
$same=New-GuardRegionProfilePlan -ProfileId Japan -Operations $f.Operations
Assert-RegionTest ((Invoke-GuardRegionProfileChange -Plan $same -Operations $f.Operations) -ceq 'Unchanged') 'choosing the current time zone does not require a write or journal'
$f.State.Id='Eastern Standard Time'
Assert-RegionError {Invoke-GuardRegionProfileChange -Plan $same -Operations $f.Operations} 'after the preview'
Assert-RegionTest ($f.State.Events.Count -eq 0) 'an unchanged preview detects a new time zone before apply'

$f=New-RegionTestFixture
$f.State.Id='Tokyo Standard Time'
$f.State.DaylightDisabled=$false
$pacific=New-GuardRegionProfilePlan -ProfileId UsPacific -ObservedCountryCode US -Operations $f.Operations
Assert-RegionTest ($pacific.Changes[0].After.Id -ceq 'Pacific Standard Time' -and
    (Invoke-GuardRegionProfileChange -Plan $pacific -Operations $f.Operations -PersistUndo $f.Save) -ceq 'Applied') 'an explicit US Pacific selection previews and applies the Pacific time zone instead of inferring a city from a country'
$f.State.Id='Eastern Standard Time'
Assert-RegionTest ((Undo-GuardRegionProfileChange -Plan $pacific -Operations $f.Operations) -ceq 'PreservedManualChange' -and
    $f.State.Id -ceq 'Eastern Standard Time') 'later rollback preserves an independent manual time-zone change'
