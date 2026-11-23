#Requires -Version 5.1
param([switch]$ReadWindows)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'release\guard-user-region.ps1')

function Assert-UserRegionTest([bool]$Condition,[string]$Message) {
    if(-not $Condition){throw "FAIL: $Message"}
    "PASS: $Message"
}

function New-UserRegionTestFixture {
    $owner='S-1-5-21-10-20-30-1001'
    $ip='198.51.100.54'
    $binding=[pscustomobject]@{
        Version=2;Containment='Sandboxie';Generation=('A'*64);LaunchUserSid=$owner
        RouteHash=('B'*64);SelectionHash=('B'*64);Port=18881;ExpectedIpv4=$ip
        VpnGuid='16dc07ec-e087-4649-acc6-63091bd44c5a'
    }
    $before=[pscustomobject]@{
        OwnerSid=$owner;CountryCode='US';LocaleName='en-US';Format=@{ShortDate='M/d/yyyy';ShortTime='h:mm tt'}
        Languages=@([pscustomobject]@{LanguageTag='en-US'});EffectiveUiLanguage='en-US';EffectiveInputMethod='0409:00000409'
    }
    $after=$before.PSObject.Copy()
    $after.CountryCode='JP';$after.LocaleName='ja-JP'
    $after.Format=@{ShortDate='yyyy/MM/dd';ShortTime='H:mm'}
    $after.Languages=@([pscustomobject]@{LanguageTag='ja-JP'},$before.Languages[0])
    $edgeBefore=[pscustomobject]@{Profile='Default';AcceptLanguages='en-US,en';DisplayLocale='en'}
    $edgeAfter=$edgeBefore.PSObject.Copy()
    $edgeAfter.AcceptLanguages='ja,en-US,en'
    $plan=[pscustomobject]@{
        Zone=[pscustomobject]@{CurrentTimeZoneId='Pacific Standard Time';WindowsTimeZoneId='Tokyo Standard Time'}
        Windows=[pscustomobject]@{Before=$before;After=$after}
        Edge=[pscustomobject]@{Profile='Default';Before=$edgeBefore;After=$edgeAfter;PrimaryLanguage='ja';Changed=$true}
        EdgeBefore=$edgeBefore;PrimaryLanguage='ja'
    }
    $fixture=[pscustomobject]@{
        Owner=$owner;Ip=$ip;RequestId=('c'*32);Binding=$binding;ProofCountry='JP';Mode='Normal';ProofAge=0
        Plan=$plan;Events=[Collections.Generic.List[string]]::new();Zone=[pscustomobject]@{Id=$plan.Zone.CurrentTimeZoneId}
        Windows=$before;Edge=$edgeBefore;Receipt=$null;Journal=$null;Operations=$null
    }
    $copy={param($value) if($null -ne $value){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $value -Depth 14 -Compress)}}
    $format=(Get-Command Format-GuardUserRegionState).ScriptBlock
    $fixture.Operations=@{
        Owner={$fixture.Owner}.GetNewClosure(); Lock={[Threading.Mutex]::new()}
        ReadResult={& $copy $fixture.Receipt}.GetNewClosure()
        SaveResult={param($receipt) $fixture.Receipt=& $copy $receipt; $fixture.Events.Add('result')}.GetNewClosure()
        ReadJournal={& $copy $fixture.Journal}.GetNewClosure()
        SaveJournal={
            param($journal)
            if($fixture.Mode -ceq 'JournalDenied'){throw 'Fixture refused the journal'}
            $fixture.Journal=& $copy $journal
            $fixture.Events.Add('journal')
        }.GetNewClosure()
        ClearJournal={$fixture.Journal=$null; $fixture.Events.Add('clear')}.GetNewClosure()
        ReadBinding={$fixture.Events.Add('binding'); & $copy $fixture.Binding}.GetNewClosure()
        Probe={
            $fixture.Events.Add('probe')
            [pscustomobject]@{
                Passed=$true;State='Completed';Provider='CloudflareTrace';CountryCode=$fixture.ProofCountry
                ExitIpv4=$fixture.Ip;CheckedUtc=[datetime]::UtcNow.AddMinutes(-$fixture.ProofAge).ToString('o')
            }
        }.GetNewClosure()
        ReadHealth={@{Readiness='Locked';Reason='ScopeUnknown';Gate='Closed';Policy='Unknown';Proxy='Unavailable';Exit='Unverified'}}
        Plan={& $copy $fixture.Plan}.GetNewClosure()
        ReadState={& $format $fixture.Windows $fixture.Zone $fixture.Edge}.GetNewClosure()
        ApplyZone={
            param($plan)
            if(-not $fixture.Journal.ZoneAttempted){throw 'Zone recovery was not saved'}
            $fixture.Events.Add('zone');$fixture.Zone.Id=$plan.WindowsTimeZoneId
        }.GetNewClosure()
        VerifyZone={param($plan) $fixture.Zone.Id -ceq $plan.WindowsTimeZoneId}.GetNewClosure()
        RestoreZone={param($plan) $fixture.Events.Add('restore-zone'); $fixture.Zone.Id=$plan.CurrentTimeZoneId; 'Restored'}.GetNewClosure()
        ApplyWindows={
            param($plan,$persist)
            if(-not $fixture.Journal.WindowsAttempted){throw 'Windows recovery was not saved'}
            & $persist 'Languages'
            if($fixture.Journal.WindowsPendingWrite -cne 'Languages'){throw 'Windows write marker was not saved'}
            $fixture.Events.Add('windows');$fixture.Windows=& $copy $plan.After
            if($fixture.Mode -ceq 'WindowsReadbackError'){
                $failure=[InvalidOperationException]::new('Fixture error contains example-route-secret',[ComponentModel.Win32Exception]::new(87))
                $failure.Data['GuardWindowsLocaleStage']='SettingMismatch'
                $failure.Data['GuardWindowsLocaleSetting']='RegionalFormat'
                $failure.Data['GuardWindowsLocaleDifferences']=@('Format.ShortDate')
                throw $failure
            }
            & $persist $null
            if($fixture.Mode -ceq 'WindowsLanguageReverted'){
                $fixture.Windows.Languages=$plan.Before.Languages
                return 'ManualRequired'
            }
        }.GetNewClosure()
        VerifyWindows={param($plan) $fixture.Windows.LocaleName -ceq $plan.After.LocaleName}.GetNewClosure()
        RestoreWindows={
            param($plan,$pending)
            $fixture.Events.Add('restore-windows')
            if($fixture.Mode -ceq 'RestoreDenied'){throw 'Fixture refused recovery'}
            $fixture.Windows=& $copy $plan.Before
            'Restored'
        }.GetNewClosure()
        EdgeMode={if($fixture.Mode -ceq 'BusyEdge'){'ManualRequired'}else{'Offline'}}.GetNewClosure()
        ApplyEdge={
            param($plan)
            if(-not $fixture.Journal.EdgeAttempted){throw 'Edge recovery was not saved'}
            $fixture.Events.Add('edge');$fixture.Edge=& $copy $plan.After
            if($fixture.Mode -cin 'EdgeReadbackError','RestoreDenied'){throw 'Fixture produced an Edge error'}
        }.GetNewClosure()
        VerifyEdge={param($plan) $fixture.Edge.AcceptLanguages -ceq $plan.After.AcceptLanguages}.GetNewClosure()
        RestoreEdge={param($plan) $fixture.Events.Add('restore-edge'); $fixture.Edge=& $copy $plan.Before; 'Restored'}.GetNewClosure()
        QuietSite={$fixture.Events.Add('quiet-cache'); if($fixture.Mode -ceq 'WithCache'){'ja,en-US;q=0.9'}}.GetNewClosure()
        CurrentEdgePlan={
            param($target)
            $plan=& $copy $fixture.Plan.Edge
            $plan.Changed=$fixture.Edge.AcceptLanguages.Split(',')[0] -cne $target
            $plan
        }.GetNewClosure()
        ConfirmSite={$fixture.Events.Add('confirm'); 'ja,en-US;q=0.9'}.GetNewClosure()
    }
    $fixture
}

function Invoke-UserRegionFixture($Fixture) {
    Invoke-GuardUserRegion -BundleRoot $root -CountryCode JP -ExpectedIpv4 $Fixture.Ip -RequestId $Fixture.RequestId -Operations $Fixture.Operations
}

$fixture=New-UserRegionTestFixture
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'Applied' -and $result.RequestId -ceq $fixture.RequestId -and
    $result.ObservedIpv4 -ceq $fixture.Ip -and $result.After.CountryCode -ceq 'JP' -and
    $result.After.DefaultInputMethod -ceq $result.Before.DefaultInputMethod -and $result.After.TimeZone -ceq 'Tokyo Standard Time' -and
    $result.EdgeStatus -ceq 'PreferencesVerified' -and $result.WebsiteStatus -ceq 'AwaitingBrowser' -and
    $result.GuardHealth.Readiness -ceq 'Locked' -and -not $fixture.Journal) 'Apply keeps the actual Guard readiness separate from regional settings'
Assert-UserRegionTest (@($fixture.Events | Where-Object {$_ -ceq 'probe'}).Count -eq 1 -and
    'confirm' -cnotin $fixture.Events -and 'quiet-cache' -cin $fixture.Events -and -not $result.SiteAcceptLanguage) 'Apply performs one exit probe and reads only the quiet site cache'
$result=Invoke-UserRegionFixture $fixture
$cached=Get-GuardUserRegionResult -Operations $fixture.Operations
Assert-UserRegionTest (@($fixture.Events | Where-Object {$_ -ceq 'probe'}).Count -eq 1 -and
    $result.Outcome -ceq 'Applied' -and $cached.Outcome -ceq 'Applied' -and 'confirm' -cnotin $fixture.Events) 'Status and a duplicate completed request do not send another probe'
$fixture.Windows.Languages=$fixture.Plan.Windows.Before.Languages
$view=Get-GuardUserRegionResult -BundleRoot $root -Operations $fixture.Operations
$replayed=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($view.Outcome -ceq 'ManualRequired' -and $view.WindowsLanguageStatus -ceq 'ManualRequired' -and
    $view.Current.PreferredLanguages[0] -ceq 'en-US' -and $view.Current.LocaleName -ceq 'ja-JP' -and
    $view.After.PreferredLanguages[0] -ceq 'ja-JP' -and $fixture.Receipt.Outcome -ceq 'Applied' -and
    $replayed.WindowsLanguageStatus -ceq 'ManualRequired' -and @($fixture.Events | Where-Object {$_ -ceq 'probe'}).Count -eq 1) 'Status and idempotent replay report a reverted Windows preference while preserving the historical receipt'
$fixture.Windows.Languages=$fixture.Plan.Windows.After.Languages
$header=Confirm-GuardUserRegionSite -BundleRoot $root -Operations $fixture.Operations
Assert-UserRegionTest ($header -ceq 'ja,en-US;q=0.9' -and $fixture.Receipt.WebsiteStatus -ceq 'Verified' -and
    $fixture.Receipt.SiteAcceptLanguage -ceq $header -and $fixture.Receipt.RequestId -ceq $fixture.RequestId) 'Explicit confirmation updates the same receipt with the actual header'
$fixture.Binding.Generation='D'*64
try{Confirm-GuardUserRegionSite -BundleRoot $root -Operations $fixture.Operations | Out-Null; throw 'Fixture expected rejection'}
catch{if($_.Exception.Message -notlike '*route changed*'){throw}}
Assert-UserRegionTest (@($fixture.Events | Where-Object {$_ -ceq 'confirm'}).Count -eq 1) 'A changed approved generation prevents another website confirmation'

$fixture=New-UserRegionTestFixture
$fixture.Binding.SelectionHash='E'*64
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'Failed' -and 'probe' -cnotin $fixture.Events -and 'zone' -cnotin $fixture.Events) 'A different saved Bettbox selection prevents all writes and the probe'
foreach($reason in 'WrongCountry','StaleProof'){
    $fixture=New-UserRegionTestFixture
    if($reason -ceq 'WrongCountry'){$fixture.ProofCountry='US'}else{$fixture.ProofAge=6}
    $result=Invoke-UserRegionFixture $fixture
    Assert-UserRegionTest ($result.Outcome -ceq 'Failed' -and @($fixture.Events | Where-Object {$_ -ceq 'probe'}).Count -eq 1 -and
        'journal' -cnotin $fixture.Events) "An unusable exit measurement prevents changing settings ($reason)"
}

$fixture=New-UserRegionTestFixture
$fixture.Mode='BusyEdge'
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'ManualRequired' -and $result.EdgeStatus -ceq 'ManualRequired' -and
    $result.After.EdgeLanguages -ceq $result.Before.EdgeLanguages -and $result.After.LocaleName -ceq 'ja-JP' -and
    'edge' -cnotin $fixture.Events -and 'confirm' -cnotin $fixture.Events) 'Busy Edge is left alone while Windows settings apply'

$fixture=New-UserRegionTestFixture
$fixture.Mode='WindowsLanguageReverted'
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'ManualRequired' -and $result.WindowsLanguageStatus -ceq 'ManualRequired' -and
    $result.After.LocaleName -ceq 'ja-JP' -and $result.After.PreferredLanguages[0] -ceq 'en-US' -and
    $result.EdgeStatus -ceq 'PreferencesVerified' -and $result.Targets.PreferredLanguages[0] -ceq 'ja-JP' -and -not $fixture.Journal) 'Language-only manual outcome preserves verified Windows format and Edge preferences'

$fixture=New-UserRegionTestFixture
$fixture.Mode='JournalDenied'
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'Failed' -and 'zone' -cnotin $fixture.Events -and
    'restore-zone' -cnotin $fixture.Events) 'Failure to save recovery prevents the first setting write'

$fixture=New-UserRegionTestFixture
$fixture.Mode='EdgeReadbackError'
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'Failed' -and $result.After.LocaleName -ceq 'en-US' -and -not $fixture.Journal -and
    $result.Diagnostics.Step -ceq 'EdgeApply' -and $result.Diagnostics.Recovery -ceq 'Verified' -and
    (($fixture.Events | Where-Object {$_ -like 'restore-*'}) -join '|') -ceq 'restore-edge|restore-windows|restore-zone') 'Unexpected failure rolls back attempted settings in reverse order'

$fixture=New-UserRegionTestFixture
$fixture.Mode='WindowsReadbackError'
$result=Invoke-UserRegionFixture $fixture
$serialized=ConvertTo-Json $result -Depth 12
Assert-UserRegionTest ($result.Diagnostics.Step -ceq 'WindowsLocaleApply' -and $result.Diagnostics.WindowsStage -ceq 'SettingMismatch' -and
    $result.Diagnostics.WindowsSetting -ceq 'RegionalFormat' -and $result.Diagnostics.WindowsDifferences[0] -ceq 'Format.ShortDate' -and
    $result.Diagnostics.NativeError -eq 87 -and $serialized -cnotmatch 'example-route-secret') 'The receipt records the Windows mismatch and native error without saving the exception text'

$fixture=New-UserRegionTestFixture
$fixture.Mode='RestoreDenied'
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'RecoveryRequired' -and $fixture.Journal -and
    $fixture.Windows.LocaleName -ceq 'ja-JP') 'An incomplete rollback leaves the journal for a safe retry'
$fixture.Mode='Normal'
$fixture.Binding.SelectionHash='E'*64
$fixture.RequestId='f'*32
$result=Invoke-UserRegionFixture $fixture
Assert-UserRegionTest ($result.Outcome -ceq 'Failed' -and -not $fixture.Journal -and $fixture.Windows.LocaleName -ceq 'en-US' -and
    @($fixture.Events | Where-Object {$_ -ceq 'probe'}).Count -eq 1) 'A new request finishes recovery before any fresh probe'

if($ReadWindows){
    . (Join-Path $root 'release\guard-profile-actions.ps1')
    . (Join-Path $root 'package\guard-daily-plan.ps1')
    $plan=Get-GuardUserRegionPlan $root 'JP'
    $operations=New-GuardUserRegionOperations
    $state=& $operations.ReadState
    $mutex=& $operations.Lock (& $operations.Owner)
    try{$held=$mutex.WaitOne(0); if($held){$mutex.ReleaseMutex()}}
    finally{$mutex.Dispose()}
    Assert-UserRegionTest ($held -and $plan.Zone.WindowsTimeZoneId -ceq 'Tokyo Standard Time' -and
        $plan.Windows.After.LocaleName -ceq 'ja-JP' -and $state.DefaultInputMethod -ceq $plan.Windows.After.EffectiveInputMethod) 'The native read-only Japan plan preserves the current default input'
}
