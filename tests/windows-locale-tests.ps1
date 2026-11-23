#Requires -Version 5.1
param([switch]$ReadWindows)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-windows-locale.ps1"

function Assert-LocaleTest([bool]$Condition,[string]$Message){
    if(-not $Condition){throw "FAIL: $Message"}
    "PASS: $Message"
}

function Assert-LocaleError([scriptblock]$Operation,[string]$Expected,[string]$Stage,[string]$Setting,[string]$Difference){
    try{& $Operation | Out-Null}
    catch{
        if($_.Exception.Message -notlike "*$Expected*"){throw}
        if($Stage -and $_.Exception.Data['GuardWindowsLocaleStage'] -cne $Stage){throw "Expected Windows diagnostic stage $Stage"}
        if($Setting -and $_.Exception.Data['GuardWindowsLocaleSetting'] -cne $Setting){throw "Expected Windows diagnostic setting $Setting"}
        if($Difference -and $Difference -cnotin $_.Exception.Data['GuardWindowsLocaleDifferences']){
            throw "Expected Windows diagnostic field $Difference"
        }
        return
    }
    throw "Expected error: $Expected"
}

function New-LocaleTestFixture {
    $format=[ordered]@{}
    foreach($field in (Get-GuardWindowsLocaleFields).Keys){$format[$field]='0'}
    $format.ShortDate='MM-dd-yyyy'
    $format.LongDate='dddd, MMMM d, yyyy'
    $format.ShortTime='hh-mm tt'
    $format.LongTime='hh-mm-ss tt'
    $format.Currency='$'
    $targetFormat=[ordered]@{}
    foreach($field in $format.Keys){$targetFormat[$field]=$format[$field]}
    $targetFormat.ShortDate='yyyy/MM/dd'
    $targetFormat.LongDate='yyyy-MM-dd'
    $targetFormat.ShortTime='H:mm'
    $targetFormat.LongTime='H:mm:ss'
    $targetFormat.Currency='JPY'
    $targetFormat=[pscustomobject]$targetFormat
    $japanese=[pscustomobject]@{
        LanguageTag='ja-JP'; InputMethodTips=@()
        Spellchecking=$true; Handwriting=$false
    }
    $state=[pscustomobject]@{
        OwnerSid='S-1-5-21-10-20-30-1001';GeoId=244;CountryCode='US';LocaleName='en-US'
        Format=[pscustomobject]$format; CultureFromLanguageListOptOut=$false
        Languages=@(
            [pscustomobject]@{LanguageTag='en-US';InputMethodTips=@('0409:00020409','0409:00000409');Spellchecking=$true;Handwriting=$false}
            [pscustomobject]@{LanguageTag='fr-CA';InputMethodTips=@('0C0C:00011009');Spellchecking=$false;Handwriting=$true}
        )
        UiLanguageOverride='';EffectiveUiLanguage='en-US'
        InputMethodOverride='';InputMethodOverrideAvailable=$false
        DefaultInputLocale='F0020409';EffectiveInputMethod='0409:00020409'
    }
    $fixture=[pscustomobject]@{
        Target=[pscustomobject]@{CountryCode='JP';GeoId=122;LocaleName='ja-JP'}
        State=$state;Japanese=$japanese;Mode='Normal';Events=[Collections.Generic.List[string]]::new();Operations=$null
    }
    $fixture.Operations=@{
        Read={
            ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $fixture.State -Depth 8 -Compress)
        }.GetNewClosure()
        DefaultFormat={
            param($localeName)
            if($localeName -cne 'ja-JP'){throw 'Unexpected test format'}
            ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $targetFormat -Depth 5 -Compress)
        }.GetNewClosure()
        DefaultLanguage={
            param($localeName)
            if($localeName -cne 'ja-JP'){throw 'Unexpected test language'}
            ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $fixture.Japanese -Depth 5 -Compress)
        }.GetNewClosure()
        Write={
            param($setting,$requested)
            $fixture.Events.Add($setting)
            $current=$fixture.State
            $copy=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $requested -Depth 8 -Compress)
            switch -Exact ($setting){
                'HomeLocation' {
                    $current.GeoId=$copy.GeoId
                    $current.CountryCode=$copy.CountryCode
                }
                'RegionalFormat' {
                    if($fixture.Mode -ceq 'RollbackFailure' -and $copy.LocaleName -ceq 'en-US'){throw 'Fixture rejected rollback'}
                    $current.LocaleName=$copy.LocaleName
                    if($fixture.Mode -in 'PartialFormat','RollbackFailure' -and $copy.LocaleName -ceq 'ja-JP'){
                        $current.Format.ShortDate=$copy.Format.ShortDate
                        throw 'Fixture changed dates before the regional format write failed'
                    }
                    $current.Format=$copy.Format
                }
                'Languages' {
                    $current.Languages=$copy.Languages
                    if($fixture.Mode -ceq 'CanonicalJapanese' -and $copy.Languages[0].LanguageTag -ceq 'ja-JP'){
                        $current.Languages[0].LanguageTag='ja'
                        $current.Languages[0].Handwriting=$true
                    }
                    if($fixture.Mode -ceq 'PartialLanguages' -and $copy.Languages[0].LanguageTag -ceq 'ja-JP'){
                        $current.Languages[1].InputMethodTips=@('0409:00000409')
                    }
                    if($fixture.Mode -ceq 'NormalizesLanguage' -and $copy.Languages[0].LanguageTag -ceq 'ja-JP'){
                        $current.Languages[0].InputMethodTips=@('0411:00000411')
                    }
                    if($fixture.Mode -ceq 'ChangesEffectiveInput'){
                        if($copy.Languages[0].LanguageTag -ceq 'ja-JP'){
                            $current.DefaultInputLocale='F0030409'
                        }else{
                            $current.DefaultInputLocale='F0020409'
                        }
                    }
                }
                default {$current.$setting=$copy.$setting}
            }
        }.GetNewClosure()
    }
    $fixture
}

$fixture=New-LocaleTestFixture
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
Assert-LocaleTest ($fixture.Events.Count -eq 0 -and $plan.After.GeoId -eq 122 -and $plan.After.CountryCode -ceq 'JP' -and
    $plan.After.LocaleName -ceq 'ja-JP' -and $plan.After.Format.ShortDate -ceq 'yyyy/MM/dd' -and $plan.After.Format.ShortTime -ceq 'H:mm') 'Preview selects the Japan home location and default Japanese dates and times without any writes'
Assert-LocaleTest (($plan.After.Languages.LanguageTag -join '|') -ceq 'ja-JP|en-US|fr-CA' -and
    $plan.After.Languages[0].InputMethodTips.Count -eq 0 -and
    ($plan.After.Languages[1].InputMethodTips -join '|') -ceq '0409:00020409|0409:00000409' -and
    $plan.After.Languages[2].Handwriting -and -not $plan.After.Languages[2].Spellchecking) 'Japan goes first and existing language, keyboard, spelling and handwriting preferences carry over'
Assert-LocaleTest ($plan.After.UiLanguageOverride -ceq 'en-US' -and $plan.After.EffectiveUiLanguage -ceq 'en-US' -and
    $plan.After.InputMethodOverride -ceq '' -and $plan.After.EffectiveInputMethod -ceq '0409:00020409' -and
    $plan.After.DefaultInputLocale -ceq 'F0020409' -and $plan.After.CultureFromLanguageListOptOut) 'The plan keeps the automatic keyboard setting and independently observed default layout'
$saved=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $plan -Depth 10)
Assert-LocaleTest ((Set-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations) -ceq 'Applied' -and
    (Test-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations) -and
    ($fixture.Events -join '|') -ceq 'UiLanguageOverride|CultureFromLanguageListOptOut|HomeLocation|RegionalFormat|Languages') 'The saved plan keeps the menu language and changes the preferred list without writing a keyboard preference'
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations) -ceq 'Restored' -and
    (Test-GuardWindowsLocalePlan -Plan $saved -Before -Operations $fixture.Operations) -and
    $fixture.State.Format.ShortDate -ceq 'MM-dd-yyyy' -and -not $fixture.State.UiLanguageOverride -and
    -not $fixture.State.InputMethodOverride -and -not $fixture.State.CultureFromLanguageListOptOut) 'Rollback after JSON round-trip restores custom date patterns and automatic preferences'
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations) -ceq 'Unchanged') 'Repeated rollback performs no writes'

$fixture=New-LocaleTestFixture
$fixture.Mode='CanonicalJapanese'
$fixture.State.InputMethodOverride='0412:00000412'
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$saved=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $plan -Depth 10)
Assert-LocaleTest ((Set-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations) -ceq 'Applied' -and
    (Test-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations) -and
    $fixture.State.Languages[0].LanguageTag -ceq 'ja' -and $fixture.State.LocaleName -ceq 'ja-JP' -and
    $fixture.State.Languages[0].InputMethodTips.Count -eq 0) 'Windows may save the newly added Japanese preference as ja with its handwriting default'
$retry=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
Assert-LocaleTest ($retry.After.Languages.Count -eq 3 -and $retry.After.Languages[0].LanguageTag -ceq 'ja' -and
    'Languages' -cnotin $retry.Changes) 'An existing native ja preference is reused without adding ja-JP'
$fixture.State.Languages[1].Handwriting=$true
Assert-LocaleTest (-not (Test-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations)) 'Japanese normalization does not relax verification of an existing language'
$fixture.State.Languages[1].Handwriting=$false
$fixture.State.Languages[0].InputMethodTips=@('0411:00000411')
Assert-LocaleTest (-not (Test-GuardWindowsLocalePlan -Plan $saved -Operations $fixture.Operations)) 'A Japanese keyboard created during normalization fails verification'
$fixture.State.Languages[0].InputMethodTips=@()
$fixture.State.GeoId=$saved.Before.GeoId
$fixture.State.CountryCode=$saved.Before.CountryCode
$fixture.State.LocaleName=$saved.Before.LocaleName
$fixture.State.Format=$saved.Before.Format
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $saved -PendingWrite Languages -Operations $fixture.Operations) -ceq 'Restored' -and
    (Test-GuardWindowsLocalePlan -Plan $saved -Before -Operations $fixture.Operations)) 'A prior journal recognizes the exact normalized language order after earlier recovery restored the location and format'

$fixture=New-LocaleTestFixture
$fixture.State.Languages+=@($fixture.Japanese)
$fixture.Japanese.InputMethodTips=@('0411:00000411')
$fixture.Japanese.Handwriting=$false
Assert-LocaleError {New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations} 'could change the automatic default input method'
Assert-LocaleTest ($fixture.Events.Count -eq 0) 'An existing target keyboard that would take precedence over the automatic default prevents apply'
$fixture.State.UiLanguageOverride='en-US'
$fixture.State.InputMethodOverride='0C0C:00011009'
$fixture.State.InputMethodOverrideAvailable=$true
$fixture.State.DefaultInputLocale='F0030C0C'
$fixture.State.EffectiveInputMethod='0C0C:00011009'
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
Assert-LocaleTest ($plan.After.Languages.Count -eq 3 -and $plan.After.Languages[0].InputMethodTips[0] -ceq '0411:00000411' -and
    -not $plan.After.Languages[0].Handwriting -and 'InputMethodOverride' -notin $plan.Changes -and
    'UiLanguageOverride' -notin $plan.Changes) 'An existing Japanese entry moves up with its selected keyboard and explicit overrides stay intact'
$null=Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations
$fixture.Events.Clear()
$already=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
Assert-LocaleTest ($already.Changes.Count -eq 0 -and (Set-GuardWindowsLocalePlan -Plan $already -Operations $fixture.Operations) -ceq 'Unchanged' -and
    $fixture.Events.Count -eq 0) 'A profile already in place is verified without writing'
$fixture.State.Format.ShortDate='yyyy.MM.dd'
$formatOnly=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
Assert-LocaleTest (($formatOnly.Changes -join '|') -ceq 'RegionalFormat') 'A custom date pattern is reset even when the locale name is already Japanese'

$fixture=New-LocaleTestFixture
$fixture.State.InputMethodOverride='0412:00000412'
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$null=Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations
Assert-LocaleTest ($fixture.State.InputMethodOverride -ceq '0412:00000412' -and
    $fixture.State.EffectiveInputMethod -ceq '0409:00020409' -and $fixture.State.DefaultInputLocale -ceq 'F0020409' -and
    (Restore-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations) -ceq 'Restored' -and
    $fixture.State.InputMethodOverride -ceq '0412:00000412' -and $fixture.State.EffectiveInputMethod -ceq '0409:00020409') 'Apply and rollback preserve both the stale saved override and the working default'

$fixture=New-LocaleTestFixture
$badCountry=[pscustomobject]@{CountryCode='JP';GeoId=244;LocaleName='ja-JP'}
Assert-LocaleError {New-GuardWindowsLocalePlan -Target $badCountry -State $fixture.State -Operations $fixture.Operations} 'must match the selected country'
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$fixture.State.Format.ShortDate='dd.MM.yyyy'
Assert-LocaleError {Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations} 'after the preview'
$fixture.State.OwnerSid='S-1-5-21-10-20-30-1002'
Assert-LocaleError {Restore-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations} 'different Windows user'
Assert-LocaleTest ($fixture.Events.Count -eq 0) 'Country mismatch, stale preview and a different Windows user all prevent writes'

foreach($mode in 'PartialFormat','PartialLanguages','NormalizesLanguage','ChangesEffectiveInput','RollbackFailure'){
    $fixture=New-LocaleTestFixture
    $fixture.Mode=$mode
    $plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
    $diagnostic=switch($mode){
        'PartialFormat' {@{Stage='NativeWrite';Setting='RegionalFormat'}}
        'PartialLanguages' {@{Stage='SettingMismatch';Setting='Languages';Difference='Languages.1.InputMethodTips'}}
        'NormalizesLanguage' {@{Stage='SettingMismatch';Setting='Languages';Difference='Languages.0.InputMethodTips'}}
        'ChangesEffectiveInput' {@{Stage='FinalMismatch';Difference='DefaultInputLocale'}}
        'RollbackFailure' {@{Stage='NativeWrite';Setting='RegionalFormat'}}
    }
    if($mode -ceq 'RollbackFailure'){
        Assert-LocaleError {Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations} 'rollback could not be verified for RegionalFormat' @diagnostic
        Assert-LocaleTest ($fixture.State.GeoId -eq 244 -and -not $fixture.State.InputMethodOverride -and -not $fixture.State.UiLanguageOverride) 'A rollback write failure is reported and independent settings are still restored'
    }else{
        Assert-LocaleError {Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations} 'previous settings were verified' @diagnostic
        Assert-LocaleTest (Test-GuardWindowsLocalePlan -Plan $plan -Before -Operations $fixture.Operations) "Verification rejects an unintended Windows change and restores the preview ($mode)"
    }
}

$fixture=New-LocaleTestFixture
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$null=Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations
$fixture.State.GeoId=39
$fixture.State.CountryCode='CA'
$fixture.State.Format.ShortDate='dd.MM.yyyy'
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations) -ceq 'PreservedManualChange' -and
    $fixture.State.GeoId -eq 39 -and $fixture.State.Format.ShortDate -ceq 'dd.MM.yyyy' -and
    ($fixture.State.Languages.LanguageTag -join '|') -ceq 'en-US|fr-CA' -and $fixture.State.CultureFromLanguageListOptOut) 'Later rollback keeps a manual country and date-format change while restoring the original language list'

$fixture=New-LocaleTestFixture
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$null=Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations
$fixture.State.Languages[1].InputMethodTips=@('0409:00000409','0409:00020409')
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations) -ceq 'PreservedManualChange' -and
    $fixture.State.Languages[1].InputMethodTips[0] -ceq '0409:00000409' -and $fixture.State.InputMethodOverride -ceq '' -and
    $fixture.State.UiLanguageOverride -ceq 'en-US' -and $fixture.State.GeoId -eq 244) 'Rollback preserves a manually edited language list and avoids changing the effective menus and default keyboard'

$fixture=New-LocaleTestFixture
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
Assert-LocaleError {Set-GuardWindowsLocalePlan -Plan $plan -PersistWrite {throw 'Fixture could not save the write marker'} -Operations $fixture.Operations} 'could not save the write marker'
Assert-LocaleTest ($fixture.Events.Count -eq 0) 'Failure to save the first write marker prevents the first setting change'
$persist={param($setting) $fixture.Events.Add("Save:$setting")}.GetNewClosure()
$null=Set-GuardWindowsLocalePlan -Plan $plan -PersistWrite $persist -Operations $fixture.Operations
$expected=@(foreach($setting in $plan.Changes){"Save:$setting"; $setting})+@('Save:')
Assert-LocaleTest (($fixture.Events -join '|') -ceq ($expected -join '|')) 'Each setting write follows its durable marker and final verification clears the marker'
$fixture.State.Format.LongTime=$plan.Before.Format.LongTime
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $plan -PendingWrite RegionalFormat -Operations $fixture.Operations) -ceq 'Restored' -and
    (Test-GuardWindowsLocalePlan -Plan $plan -Before -Operations $fixture.Operations)) 'Recovery uses a saved marker to repair a recognizable interrupted format change'
$null=Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations
$fixture.State.Languages[1].InputMethodTips=@()
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $plan -PendingWrite Languages -Operations $fixture.Operations) -ceq 'PreservedManualChange' -and
    $fixture.State.Languages[1].InputMethodTips.Count -eq 0) 'Recovery preserves a keyboard edit while a language-order write marker remains'
$fixture=New-LocaleTestFixture
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$null=Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations
$fixture.State.Format.ShortDate='dd.MM.yyyy'
Assert-LocaleTest ((Restore-GuardWindowsLocalePlan -Plan $plan -PendingWrite RegionalFormat -Operations $fixture.Operations) -ceq 'PreservedManualChange' -and
    $fixture.State.Format.ShortDate -ceq 'dd.MM.yyyy') 'A durable marker does not override an independent regional format change'

$fixture=New-LocaleTestFixture
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$fixture.Operations.ReadIndependentLanguages={
    param($delay)
    $fixture.Events.Add('Independent '+$delay)
    $order=@($fixture.State.Languages.LanguageTag)
    [pscustomobject]@{OwnerSid=$fixture.State.OwnerSid;Saved=$order;Native=$order;WinRt=$order}
}.GetNewClosure()
Assert-LocaleTest ((Set-GuardWindowsLocalePlan -Plan $plan -Operations $fixture.Operations) -ceq 'Applied' -and
    'Independent 40' -cin $fixture.Events) 'A changed language order waits for a fresh independent read'
$fixture.Events.Clear()
$already=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
Assert-LocaleTest ((Set-GuardWindowsLocalePlan -Plan $already -Operations $fixture.Operations) -ceq 'Unchanged' -and
    ($fixture.Events -join '|') -ceq 'Independent 0') 'An unchanged language order is read independently without a settling delay'

$fixture=New-LocaleTestFixture
$plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $fixture.State -Operations $fixture.Operations
$fixture.Operations.ReadIndependentLanguages={
    param($delay)
    $fixture.State.Languages=$plan.Before.Languages
    $order=@($fixture.State.Languages.LanguageTag)
    [pscustomobject]@{OwnerSid=$fixture.State.OwnerSid;Saved=$order;Native=$order;WinRt=$order}
}.GetNewClosure()
Assert-LocaleTest ((Set-GuardWindowsLocalePlan -Plan $plan -AllowManualPreferredLanguage -Operations $fixture.Operations) -ceq 'ManualRequired' -and
    (Test-GuardWindowsLocalePlan -Plan $plan -AllowOriginalLanguages -Operations $fixture.Operations) -and
    $fixture.State.CountryCode -ceq 'JP' -and $fixture.State.LocaleName -ceq 'ja-JP') 'An independently observed language reversion preserves the verified country and format and marks that row manual'

if($ReadWindows){
    $state=Get-GuardWindowsLocaleState
    $plan=New-GuardWindowsLocalePlan -Target $fixture.Target -State $state
    Assert-LocaleTest ((Test-GuardWindowsLocalePlan -Plan $plan -Before) -and $plan.After.CountryCode -ceq 'JP' -and
        (Test-GuardWindowsPreferredLanguage $plan.After.Languages[0].LanguageTag 'ja-JP') -and $plan.After.Format.ShortDate -ceq 'yyyy/MM/dd' -and
        $plan.After.EffectiveUiLanguage -ceq $state.EffectiveUiLanguage -and $plan.After.EffectiveInputMethod -ceq $state.EffectiveInputMethod -and
        $plan.After.DefaultInputLocale -ceq $state.DefaultInputLocale -and $plan.After.InputMethodOverride -ceq $state.InputMethodOverride) 'Windows PowerShell reads the independent default keyboard and previews Japan without changing its saved override'
}
