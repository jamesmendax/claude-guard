#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\release\guard-window-actions.ps1"

function Assert-Window([bool]$Check,[string]$Name){
    if(-not $Check){throw $Name}
    "PASS $Name"
}
function Find-Check($Result,[string]$Key){$Result.Checks|Where-Object Key -CEQ $Key}

$generation='A'*64
$fixture=@{
    Installed=$false;Pending=$false;Zone='UTC';Auto=$true;StatusReads=0;ProbeCalls=0;InstallCalls=0;Country='JP';Age=0;Now=[datetime]::UtcNow
    SelectedReads=0;SafeWrites=0;RetireCalls=0
    Active=[pscustomobject]@{Version=2;Generation=$generation;PackageFullName='Store.Fixture';ProxyMode='Manual';ExpectedIpv4='198.51.100.1'
        Port=18793;RouteHash=('B'*64);Containment='Sandboxie';LaunchUserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
    Status=[pscustomobject]@{Generation=$generation;CanLaunch=$true;Gate='Open';Proxy='Ready';Exit='Match';Inventory='Verified';Policy='Verified'
        Containment='Sandboxie';Readiness='Ready';Reason='Verified'}
}
$script:GuardWindowInstaller={
    param([switch]$Plan)
    if(-not $Plan){throw 'Unsafe installer access.'}
    [pscustomobject]@{Mode=$(if($fixture.Installed){'Update'}else{'Fresh'});RecoveryPending=$fixture.Pending}
}
function Read-GuardDailyRecord([string]$Name){
    switch -CaseSensitive ($Name){
        'daily-provisioned.json' {if($fixture.Installed){$fixture.Active}}
        'release-install-pending.json' {$fixture.Journal}
        'setup-last-window-error.json' {
            if($fixture.BadWindowJson){throw 'Malformed diagnostic fixture.'};$fixture.WindowError
        }
        default {throw "Unexpected fixture read $Name."}
    }
}
function Read-GuardDailyNotice {if($fixture.GuardStop){$fixture.GuardStop}}
function Read-GuardDailyObservedExit {if($fixture.ObservedExit){$fixture.ObservedExit}}
function Get-GuardDailyStatus {$fixture.StatusReads++;$fixture.Status}
function Get-GuardWindowEntry {'Desktop'}
function Get-GuardWindowStoreState {if($fixture.Worker){$fixture.Worker}}
function Test-GuardDailyBackupLookupEnabled {$false}
function New-GuardWindowsRegionOperations {
    @{Read={ [pscustomobject]@{Id=$fixture.Zone;DaylightDisabled=$false;AutomaticTimeZoneEnabled=$fixture.Auto} }
        Write={throw 'Unsafe Windows time zone write.'}}
}
function Get-GuardWindowsLocaleState {
    [pscustomobject]@{CountryCode='US';GeoId=244;LocaleName='en-US';Languages=@(@{LanguageTag='en-US'})
        EffectiveUiLanguage='en-US';EffectiveInputMethod='0409:00000409'}
}
function New-GuardWindowsLocalePlan($Target,$State){
    @{Before=$State;After=@{CountryCode=$Target.CountryCode;GeoId=$Target.GeoId;LocaleName=$Target.LocaleName
        Languages=@(@{LanguageTag=$Target.LanguageTag})}}
}
function Get-GuardBrowserLanguageState([string]$Profile){
    $langs=if($fixture.BrowserLanguages){$fixture.BrowserLanguages}else{'en-US,en'}
    $currentProfile=if($fixture.BrowserProfile){$fixture.BrowserProfile}else{'Default'}
    @{Available=(-not $fixture.BrowserBlocked);AcceptLanguages=$langs;SelectedLanguages=$langs;DisplayLocale='en-US'
        Browser='Edge';Profile=$currentProfile;Executable='C:\Guard-Fixture\msedge.exe'}
}
function New-GuardBrowserLanguagePlan([string]$Target,$State){
    if(-not $State.Available){throw 'Fixture Edge profile unavailable.'}
    $language=$Target.Split('-')[0]
    @{Before=$State;After=@{AcceptLanguages="$language,en-US,en"};PrimaryLanguage=$language;Profile=$State.Profile}
}
function Get-GuardBrowserLanguageApplyMode($Plan){if($fixture.BrowserBusy){'ManualRequired'}else{'Offline'}}
function Get-GuardSettingsNodePreview($stage,$profile,$token){
    $fixture.ProbeCalls++
    [pscustomobject]@{Passed=$true;State='Completed';Provider='CloudflareTrace';ExitIpv4='198.51.100.44';CountryCode=$fixture.Country
        CheckedUtc=$fixture.Now.AddMinutes(-$fixture.Age).ToString('o');ProfileFingerprint=(Get-GuardNodeProfileRoute $profile 18881).ProfileFingerprint}
}
function Get-GuardCurrentBettboxProfile {
    $fixture.SelectedReads++
    if($fixture.SelectionUnavailable){throw 'The current Bettbox selection could not be verified.'}
    $selected=if($fixture.ChangeSelection -and $fixture.SelectedReads -eq $fixture.ChangeSelection){
        $link.Replace('198.51.100.81','198.51.100.82')
    }else{$link}
    New-GuardNodeProfile -Text $selected
}
function Invoke-GuardSettingsInstall($Stage,$Launcher,$Profile,$Proof,$RegionPlan,$ProgressCallback,$RequirePriorGeneration,$BeforeApply,
    $WindowsLocalePlan,$BrowserLocalePlan,$BrowserTarget){
    $fixture.InstallCalls++
    $fixture.ReceivedPlan=$RegionPlan
    $fixture.ReceivedWindowsLocale=$WindowsLocalePlan
    $fixture.ReceivedBrowserLocale=$BrowserLocalePlan
    $fixture.ReceivedGeneration=$RequirePriorGeneration
    if($fixture.ProtectedPreflightError){
        return [pscustomobject]@{Installed=$false;Restored=$false;Phase='Rejected';FailedPhase='Preflight'
            Error=$fixture.ProtectedPreflightError}
    }
    if($BeforeApply){
        try{$null=& $BeforeApply;$null=& $BeforeApply}
        catch{return [pscustomobject]@{Installed=$false;Restored=$true;RestoredClosed=$true;HadPrior=$true;Phase='RolledBack';FailedPhase='Install'}}
        $fixture.SafeWrites++
    }
    if($fixture.FailSiteLanguage){
        return @{Installed=$false;Restored=$true;FailedPhase='Verify';Error='Edge website language settings did not pass final readback.'
            LocaleFailure='EdgeSiteMismatch'}
    }
    if($fixture.PartialInstall){
        return [pscustomobject]@{Installed=$true;Phase='Completed';Operation=('c'*32);Generation=$generation
            BrowserStatus='ManualRequired';WebsiteStatus='AwaitingBrowser';AllSettingsVerified=$false
            LocaleVerification=[pscustomobject]@{BrowserProfile=$BrowserTarget.Profile;ExpectedBrowserLanguage=$BrowserTarget.PrimaryLanguage}}
    }
    [pscustomobject]@{Installed=$true;Phase='Completed';Operation=('c'*32);Generation=$generation;GuardedEntry='Desktop'
        SiteAcceptLanguage='ja,en-US;q=0.9,en;q=0.8'
        FreshProofs=6;Verification=@{RequiredProofs=6;Proofs=6;Status='Verified';WorkerStatus='Ready'}}
}

$scratch=Join-Path ([IO.Path]::GetTempPath()) ('guard-window-evidence-tests-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($scratch)
function Get-GuardDataPath([string]$Name){Join-Path $scratch $Name}
$link='vless://6b1f71fb-b22c-41b7-8fe7-ceccb87c2fa3@198.51.100.81:443?type=ws&security=tls&sni=example.test&host=example.test&path=%2Fsocket&encryption=none'

if('ClaudeGuard.SiteLanguage' -as [type]){throw 'Run the fixture without the real browser helper.'}
Add-Type -TypeDefinition @'
namespace ClaudeGuard {
    public static class SiteLanguage {
        public static int QuietChecks;
        public static int ConfirmChecks;
        public static string Recent(string executable, string profile, string expected, string preferences) {
            QuietChecks++;
            return null;
        }
        public static string Confirm(string executable, string profile, string expected, string preferences) {
            ConfirmChecks++;
            if (profile != "Default" || expected != "ja" || !preferences.StartsWith("ja,"))
                throw new System.InvalidOperationException("Fixture did not receive the currently saved Japanese language.");
            return "ja,en-US;q=0.9,en;q=0.8";
        }
    }
}
'@

try{
    $homeView=Get-GuardWindowHome
    Assert-Window ($homeView.Mode -ceq 'Fresh' -and -not $homeView.Ready -and $fixture.StatusReads -eq 0 -and -not $homeView.LastStop.HasRecord) 'Fresh home reads neither a live health sample nor a prior incident'
    Assert-Window (($homeView.Checks|Where-Object Group -CEQ 'environment').Count -eq 10 -and
        (Find-Check $homeView 'offset').Status -ceq 'derived' -and (Find-Check $homeView 'webrtc').Status -ceq 'uncollected' -and
        (Find-Check $homeView 'store-desktop').Status -ceq 'waiting') 'Audit distinguishes Windows-derived values from browser references and unverified prerequisites'
    Assert-Window (@(Get-GuardWindowHome).Count -eq 1 -and @($homeView.Checks|Where-Object {$_ -isnot [Collections.IDictionary]}).Count -eq 0) 'Bridge emits one home dictionary with plain check dictionaries'

    $fixture.Installed=$true
    $fixture.Worker='DirectoryWatcherUnavailable'
    $fixture.GuardStop=[pscustomobject]@{Id=('b'*32);Utc=$fixture.Now.AddMinutes(-2);Reason='StoreUpdateHandoff'}
    $fixture.ObservedExit=[pscustomobject]@{Id=('d'*32);Utc=$fixture.Now.AddMinutes(-1);ExitCode='0xC0000005';NetworkClosed=$false}
    $script:GuardWindowLastOperation=[pscustomobject]@{Operation=('a'*32);Generation=$generation;Installed=$true;FreshProofs=6
        Verification=@{RequiredProofs=6;Proofs=6;Status='Verified';WorkerStatus='Ready'}}
    $homeView=Get-GuardWindowHome
    Assert-Window ($fixture.StatusReads -eq 1 -and $homeView.Ready -and $homeView.GuardedEntry -ceq 'Desktop' -and
        (Find-Check $homeView 'actual-ip').Current -ceq '198.51.100.1') 'Installed home shares one live health read and displays only a verified matching exit'
    Assert-Window ($homeView.LastStop.SourceKind -ceq 'LauncherObserved' -and $homeView.LastStop.ExitCode -ceq '0xC0000005' -and
        (Find-Check $homeView 'store').Status -ceq 'failed' -and $homeView.Receipt.WorkerStatus -ceq 'Ready') 'Newest recorded process exit and live Store watcher failure stay distinct from a past successful acceptance'
    $fixture.Status.CanLaunch=$false
    $fixture.Status.Exit='Mismatch'
    $fixture.Status.Reason='ExitChanged'
    $fixture.Status.Gate='Closed'
    $homeView=Get-GuardWindowHome
    Assert-Window (-not $homeView.Ready -and (Find-Check $homeView 'actual-ip').Status -ceq 'failed' -and
        (Find-Check $homeView 'actual-ip').Current -notmatch '\d+\.\d+\.\d+\.\d+' -and
        $homeView.LastStop.ExitCode -ceq '0xC0000005') 'Exit mismatch leaves an uncaptured measured address unknown and never replaces the incident'

    $fixture.WindowError=[pscustomobject]@{Schema=1;Component='GuardSettingsWindow';Kind='RuntimeError';HResult='0x80131500'
        TimeUtc=$fixture.Now.ToString('o');Message=$link}
    [IO.File]::WriteAllText((Get-GuardDataPath 'setup-last-window-error.json'),'fixture')
    $errorView=Get-GuardWindowLastError
    Assert-Window ($errorView.HasRecord -and $errorView.HResult -ceq '0x80131500' -and
        ($errorView|ConvertTo-Json) -notmatch 'vless|example.test') 'Guard settings window diagnostic exposes only validated fixed fields'
    $fixture.BadWindowJson=$true
    Assert-Window ((Get-GuardWindowLastError).ReadState -ceq 'Unreadable') 'Malformed window diagnostic is not treated as a desktop or network incident'

    $statusReads=$fixture.StatusReads
    $missing=Get-GuardWindowRegion 'Automatic'
    Assert-Window ($missing.RequiresChoice -and (Find-Check $missing 'actual-ip').Blocks) 'Candidate plan without a proof blocks application'
    $proof=Get-GuardWindowProbe $link ([Threading.CancellationToken]::None)
    Assert-Window ($proof.Ok -and ([datetime]$proof.ExpiresUtc-[datetime]$proof.CheckedUtc).TotalMinutes -eq 5) 'Candidate expiry uses the exact proof timestamp and five-minute lifetime'
    $candidate=Get-GuardWindowRegion 'Automatic'
    Assert-Window (-not $candidate.RequiresChoice -and $candidate.ZoneId -ceq 'Japan' -and $candidate.CountryCode -ceq 'JP' -and
        (Find-Check $candidate 'actual-ip').Current -ceq '198.51.100.44' -and (Find-Check $candidate 'automatic-zone').Status -ceq 'attention' -and
        (Find-Check $candidate 'windows-zone').Change -and (Find-Check $candidate 'daylight').Status -ceq 'follows') 'Verified Japanese candidate displays actual measurement, intended time zone, daylight and automatic-setting warning'
    Assert-Window ((Find-Check $candidate 'windows-home-region').Expected -ceq 'JP' -and
        (Find-Check $candidate 'windows-regional-format').Expected -ceq 'ja-JP' -and
        (Find-Check $candidate 'windows-preferred-languages').Expected -ceq 'ja-JP' -and
        (Find-Check $candidate 'edge-website-languages').Expected -ceq 'ja,en-US,en' -and
        (Find-Check $candidate 'edge-site-readback').Status -ceq 'waiting') 'The Japanese preview specifies all four locale values and marks the website header as awaiting verification'
    $fixture.Zone='Eastern Standard Time'
    $change=Set-GuardWindowNode 'Automatic'
    Assert-Window (-not $change.Success -and $fixture.InstallCalls -eq 0) 'A changed Windows time zone invalidates the reviewed plan before invoking the installer'
    $candidate=Get-GuardWindowRegion 'UsPacific'
    Assert-Window ($candidate.RequiresChoice -and (Find-Check $candidate 'country').Blocks) 'A known country conflict blocks the candidate'

    $fixture.Country='US'
    $null=Get-GuardWindowProbe $link ([Threading.CancellationToken]::None)
    $candidate=Get-GuardWindowRegion 'Automatic'
    Assert-Window ($candidate.RequiresChoice -and (Find-Check $candidate 'windows-zone').Status -ceq 'choice' -and
        (Find-Check $candidate 'actual-ip').Status -ceq 'ok') 'A verified US exit requires a time zone choice while keeping the IPv4 proof'
    $candidate=Get-GuardWindowRegion 'Keep' 'en-US'
    Assert-Window (-not $candidate.RequiresChoice -and -not (Find-Check $candidate 'windows-zone').Change) 'Keep leaves the existing Windows time zone unchanged'
    Assert-Window (-not (Set-GuardWindowNode 'Automatic' 'en-US').Success -and $fixture.InstallCalls -eq 0) 'Apply requires the exact reviewed choice'
    Assert-Window ((Set-GuardWindowNode 'Keep' 'en-US').Success -and $fixture.ReceivedPlan.ProfileId -ceq 'Keep' -and
        $fixture.ProbeCalls -eq 2 -and $fixture.StatusReads -eq $statusReads) 'Applying the reviewed plan preserves the proof and runs no extra network or health check'
    $fixture.Country=$null
    $null=Get-GuardWindowProbe $link ([Threading.CancellationToken]::None)
    $missingCountry=Get-GuardWindowRegion 'Windows/UTC'
    Assert-Window (-not $missingCountry.RequiresChoice -and (Find-Check $missingCountry 'country').Blocks -and
        (Find-Check $missingCountry 'windows-home-region').Blocks -and -not (Set-GuardWindowNode 'Windows/UTC').Success) `
        'A manual time zone cannot replace missing country proof for the locale changes'
    $script:GuardWindowProof.CheckedUtc=$fixture.Now.AddMinutes(-6).ToString('o')
    $candidate=Get-GuardWindowRegion 'Keep'
    Assert-Window ($candidate.RequiresChoice -and (Find-Check $candidate 'actual-ip').Status -ceq 'stale' -and
        (Find-Check $candidate 'actual-ip').Blocks) 'Expired proof remains blocked even when keeping Windows settings'

    $result=[pscustomobject]@{Installed=$false;Restored=$true;HadPrior=$true;Phase='RolledBack';FailedPhase='Verify'
        Error='The installed Guard did not publish fresh, continuous exit and firewall proofs.';Operation=('f'*32);PriorGeneration=$generation
        Verification=@{RequiredProofs=6;Proofs=6;Status='WaitingForStoreWorker';WorkerStatus='DirectoryWatcherUnavailable'}
        RestoreVerification=@{RequiredProofs=2;Proofs=2;Status='Verified';WorkerStatus='NotRequired'}}
    $view=ConvertTo-GuardWindowResult $result
    Assert-Window (-not $view.Success -and $view.Restored -and $view.FailedPhase -ceq 'Verify' -and
        $view.WorkerStatus -ceq 'DirectoryWatcherUnavailable' -and $view.FreshProofs -eq 6 -and $view.RestoreProofs -eq 2 -and
        $view.Message -match '目录' -and $view.Details -match '2 / 2') 'Result retains the failed phase, specific watcher and actual rollback proofs'
    $script:GuardWindowLastOperation=$result
    $homeView=Get-GuardWindowHome
    Assert-Window ($homeView.Receipt.Restored -and (Find-Check $homeView 'previous-operation').Status -ceq 'restored' -and
        (Find-Check $homeView 'firewall').Detail -match '2 / 2') 'Home links restoration receipt to the installed generation'
    $fixture.Active.Generation='E'*64
    $homeView=Get-GuardWindowHome
    Assert-Window (-not $homeView.Receipt -and -not $homeView.Ready -and -not (Find-Check $homeView 'previous-operation')) 'An unrelated install generation invalidates old health and receipt assertions'
    $fixture.Pending=$true
    $fixture.Journal=@{Operation=$result.Operation}
    $homeView=Get-GuardWindowHome
    Assert-Window ($homeView.RecoveryPending -and -not $homeView.Ready -and (Find-Check $homeView 'previous-operation').Status -ceq 'blocked') 'Pending recovery overrides past readiness and installed proof history'

    $fixture.InstallCalls=0
    $fixture.ProbeCalls=0
    $fixture.Country='JP'
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').Success -and $fixture.SelectedReads -eq 0) `
        'The explicit current-node operation stops for pending recovery before reading Bettbox'
    $fixture.Pending=$false
    $fixture.Installed=$false
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').Success -and $fixture.SelectedReads -eq 0) `
        'The explicit current-node operation cannot start a first installation'
    $fixture.Installed=$true
    $owner=$fixture.Active.LaunchUserSid
    $fixture.Active.LaunchUserSid='S-1-5-18'
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').Success -and $fixture.SelectedReads -eq 0) `
        'A different installed Windows account stops before reading the selected node'
    $fixture.Active.LaunchUserSid=$owner
    Assert-Window (-not (Set-GuardWindowCurrentNode jp '198.51.100.44').Success -and
        -not (Set-GuardWindowCurrentNode JP '198.51.100.044').Success -and $fixture.SelectedReads -eq 0) `
        'Lowercase country and noncanonical IPv4 stop before reading the selected node'
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.45').Success -and
        -not (Set-GuardWindowCurrentNode FR '198.51.100.44').Success -and $fixture.ProbeCalls -eq 2 -and $fixture.InstallCalls -eq 0) `
        'A different measured country or IPv4 stops before the transaction'
    $fixture.Country=$null
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').Success -and $fixture.InstallCalls -eq 0) `
        'An unverified observed country stops before the transaction'
    $fixture.Country='US'
    Assert-Window (-not (Set-GuardWindowCurrentNode US '198.51.100.44').Success -and $fixture.InstallCalls -eq 0) `
        'A verified country with multiple Windows time zones stops before the transaction'
    $fixture.Country='JP'
    $fixture.Age=6
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').Success -and $fixture.InstallCalls -eq 0) `
        'A stale current-node proof stops before the transaction'
    $fixture.Age=0
    $fixture.SelectionUnavailable=$true
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').Success -and $fixture.InstallCalls -eq 0) `
        'An unreadable selection cannot reach deployment'
    $fixture.SelectionUnavailable=$false
    $fixture.ChangeSelection=$fixture.SelectedReads+3
    $view=Set-GuardWindowCurrentNode JP '198.51.100.44' $true
    Assert-Window (-not $view.Success -and $view.RestoredClosed -and $view.Message -match '节点在核对期间发生变化' -and
        $fixture.SafeWrites -eq 0 -and $fixture.RetireCalls -eq 0) 'A changed Bettbox selection aborts the write and preserves the closed rollback receipt'
    $fixture.ChangeSelection=0

    # The real retirement module is never called by a fixture.
    $fixtureRelease=Join-Path $scratch 'release'
    $null=[IO.Directory]::CreateDirectory($fixtureRelease)
    $retirementPath=Join-Path $fixtureRelease 'guard-release-retirement.ps1'
    [IO.File]::WriteAllText($retirementPath,@'
function Remove-GuardSupersededSetup($Stage,$Result){
    $fixture.RetireCalls++
    if($Stage -cne $scratch -or $Result.Operation -cne ('c'*32) -or $Result.Installed -ne $true){throw 'Invalid committed fixture'}
    if($fixture.FailRetire){throw 'Retirement fixture failed'}
    @{Status='Removed'}
}
'@)
    $script:GuardWindowStage=$scratch
    $script:GuardWindowProgressCallback={param($progress)$fixture.Phase=$progress.Phase}
    $before=$fixture.SelectedReads
    $view=Set-GuardWindowCurrentNode JP '198.51.100.44'
    Assert-Window ($view.Success -and $fixture.ReceivedPlan.WindowsTimeZoneId -ceq 'Tokyo Standard Time' -and
        $fixture.ReceivedGeneration -ceq $fixture.Active.Generation -and $fixture.SelectedReads -eq $before+3 -and
        $fixture.SafeWrites -eq 1 -and $fixture.RetireCalls -eq 0 -and $fixture.ReceivedWindowsLocale.After.LocaleName -ceq 'ja-JP' -and
        $fixture.ReceivedWindowsLocale.After.GeoId -eq 122 -and $fixture.ReceivedBrowserLocale.PrimaryLanguage -ceq 'ja' -and
        $view.SiteAcceptLanguage -ceq 'ja,en-US;q=0.9,en;q=0.8') 'The current-node command supplies all Japanese settings and returns the verified web header'
    $view=Set-GuardWindowCurrentNode JP '198.51.100.44' $true
    Assert-Window ($view.Success -and $fixture.SafeWrites -eq 2 -and $fixture.RetireCalls -eq 1 -and
        $fixture.Phase -ceq 'RetirePrevious' -and $view.Details -match '已清理') 'Explicit retirement receives the successful installer receipt after commit'
    $fixture.FailRetire=$true
    $view=Set-GuardWindowCurrentNode JP '198.51.100.44' $true
    Assert-Window ($view.Success -and $fixture.SafeWrites -eq 3 -and $fixture.RetireCalls -eq 2 -and
        $view.Details -match '仍保留') 'A retirement failure leaves the committed node change successful'
    $before=$fixture.SelectedReads
    $seed=Get-GuardWindowProbe -CurrentBettbox $true -Token ([Threading.CancellationToken]::None)
    $candidate=Get-GuardWindowRegion 'Automatic'
    $view=Set-GuardWindowNode 'Automatic'
    Assert-Window ($seed.Ok -and $seed.ExitIpv4 -ceq '198.51.100.44' -and -not $candidate.RequiresChoice -and
        $view.Success -and $fixture.SafeWrites -eq 4 -and $fixture.SelectedReads -eq $before+3 -and
        $fixture.ReceivedGeneration -ceq $fixture.Active.Generation -and $fixture.ReceivedPlan.WindowsTimeZoneId -ceq 'Tokyo Standard Time') `
        'The Nodes-page selection previews the measured exit and Tokyo, then rechecks the source on normal Apply'
    $null=Get-GuardWindowProbe -CurrentBettbox $true -Token ([Threading.CancellationToken]::None)
    $null=Get-GuardWindowRegion 'Automatic'
    $fixture.ChangeSelection=$fixture.SelectedReads+1
    $view=Set-GuardWindowNode 'Automatic'
    Assert-Window (-not $view.Success -and $view.Message -match '节点在核对期间发生变化' -and $fixture.SafeWrites -eq 4) `
        'Changing the selection after a Nodes-page preview blocks its protected write'

    $fixture.ChangeSelection=0
    $fixture.BrowserBlocked=$true
    $fixture.PartialInstall=$true
    $null=Get-GuardWindowProbe $link ([Threading.CancellationToken]::None)
    $candidate=Get-GuardWindowRegion 'Automatic'
    $view=Set-GuardWindowNode 'Automatic'
    Assert-Window (-not (Find-Check $candidate 'edge-website-languages').Blocks -and (Find-Check $candidate 'edge-website-languages').Issue -and
        $view.Success -and $view.WebsiteStatus -ceq 'AwaitingBrowser' -and $view.ManualKeys -ccontains 'edge-website-languages' -and
        $view.Message -match '手动调整 Edge' -and $view.Message -notmatch '6 项设置已完成' -and
        -not $view.AllSettingsVerified -and -not $view.SiteAcceptLanguage) `
        'An unavailable Edge profile leaves the other settings eligible and returns an explicit partial result'
    $fixture.BrowserBlocked=$false
    $fixture.PartialInstall=$false
    $fixture.FailSiteLanguage=$true
    $view=Set-GuardWindowCurrentNode JP '198.51.100.44' $true
    Assert-Window (-not $view.Success -and $view.Restored -and -not $view.SiteAcceptLanguage -and $fixture.RetireCalls -eq 2 -and
        $view.Details -match '测试网页收到的 Edge 首选语言与预览不一致') `
        'Failed website language verification shows its specific cause, rolls back and keeps the prior release'
    $fixture.FailSiteLanguage=$false
    $fixture.Country='CA'
    $null=Get-GuardWindowProbe $link ([Threading.CancellationToken]::None)
    $candidate=Get-GuardWindowRegion 'Keep'
    Assert-Window ('fr-CA' -cin $candidate.LocaleChoices -and (Find-Check $candidate 'windows-regional-format').Status -ceq 'choice') `
        'A multilingual country offers verified country formats rather than picking one'
    $candidate=Get-GuardWindowRegion 'Keep' 'fr-CA'
    Assert-Window ((Find-Check $candidate 'windows-regional-format').Expected -ceq 'fr-CA' -and
        -not (Set-GuardWindowNode 'Keep' 'en-CA').Success -and (Set-GuardWindowNode 'Keep' 'fr-CA').Success -and
        $fixture.ReceivedWindowsLocale.After.LocaleName -ceq 'fr-CA') 'The exact locale reviewed in the UI is required to apply it'

    $fixture.BrowserLanguages='ja,en-US,en'
    $quiet=Get-GuardWindowManualCheck 'edge-website-languages' 'ja'
    Assert-Window (-not $quiet.Verified -and $quiet.Message -match '尚未核实' -and [ClaudeGuard.SiteLanguage]::QuietChecks -eq 1 -and
        [ClaudeGuard.SiteLanguage]::ConfirmChecks -eq 0) 'Normal recheck reaches the real quiet verifier without opening Edge or trusting preferences alone'
    $fixture.BrowserLanguages='en-US,en'
    Assert-Window (-not (Get-GuardWindowManualCheck 'edge-website-languages' 'ja' -ConfirmEdge $true).Verified -and
        [ClaudeGuard.SiteLanguage]::ConfirmChecks -eq 0) 'Explicit browser verification is deferred until the saved Edge language matches'
    $fixture.BrowserLanguages='ja,en-US,en'
    $operation='d'*32
    $operationDirectory=Join-Path $scratch ('operations\'+$operation)
    $null=[IO.Directory]::CreateDirectory($operationDirectory)
    $activeOperation=[pscustomobject]@{
        Installed=$true;Operation=$operation;Generation=$generation;WebsiteStatus='AwaitingBrowser';BrowserStatus='ManualRequired';AllSettingsVerified=$false
        SiteAcceptLanguage=$null;LocaleVerification=[pscustomobject]@{BrowserProfile='Default';ExpectedBrowserLanguage='ja'
            WindowsLanguageStatus='Verified';ExpectedWindowsLanguage='ja-JP'}
    }
    $operationResult=Join-Path $operationDirectory 'result.json'
    $stageResult=Join-Path $scratch 'install-result.json'
    $readback=Join-Path $operationDirectory 'website-readback.json'
    function Assert-GuardDailyStatePath([string]$Path){
        if($Path -ne $scratch -and -not $Path.StartsWith($scratch+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Outside fixture path.'}
    }
    function Read-GuardDailyJsonFile([string]$Path,[switch]$VerifyStatePath){
        Assert-GuardDailyStatePath $Path
        [IO.File]::ReadAllText($Path)|ConvertFrom-Json
    }
    function Save-GuardAdministratorJson([string]$Path,$Data){
        Assert-GuardDailyStatePath $Path
        [IO.File]::WriteAllText($Path,($Data|ConvertTo-Json -Depth 8))
    }
    Save-GuardAdministratorJson $operationResult $activeOperation
    Save-GuardAdministratorJson $stageResult $activeOperation
    $fixture.Active.Generation='F'*64
    $mismatch=Get-GuardWindowManualCheck 'edge-website-languages' 'ja' -ConfirmEdge $true -Operation $operation
    Assert-Window ($mismatch.Verified -and -not $mismatch.OperationVerified -and -not [IO.File]::Exists($readback)) `
        'A real website sample from a superseded installation cannot alter the current receipt'
    $fixture.Active.Generation=$generation
    $confirmed=Get-GuardWindowManualCheck 'edge-website-languages' 'ja' -ConfirmEdge $true -Operation $operation
    $updated=Get-GuardWindowWebsiteReadback $activeOperation
    Assert-Window ($confirmed.OperationVerified -and $updated.AllSettingsVerified -and $updated.WebsiteStatus -ceq 'Verified' -and
        $updated.SiteAcceptLanguage -ceq 'ja,en-US;q=0.9,en;q=0.8') 'Explicit native HTTP verification completes only its matching protected operation'
    $activeOperation.LocaleVerification.WindowsLanguageStatus='ManualRequired'
    $view=ConvertTo-GuardWindowResult $activeOperation
    Assert-Window ($view.Success -and -not $view.AllSettingsVerified -and $view.ManualKeys -ccontains 'windows-preferred-languages' -and
        $view.ManualKeys -ccontains 'edge-website-languages' -and $view.ManualTargets['windows-preferred-languages'].Expected -ceq 'ja-JP' -and
        $view.Message -match 'Windows 首选语言需手动调整' -and $view.Message -notmatch '6 项设置已完成') `
        'The installed route can keep both language tasks pending without claiming six settings completed'
    $updated=Get-GuardWindowWebsiteReadback $activeOperation
    $view=ConvertTo-GuardWindowResult $updated
    Assert-Window ($view.SiteAcceptLanguage -and $view.WebsiteStatus -ceq 'Verified' -and -not $view.AllSettingsVerified -and
        $view.ManualKeys -ccontains 'windows-preferred-languages' -and $view.ManualKeys -cnotcontains 'edge-website-languages') `
        'A later website sample cannot turn pending Windows preferred languages into a verified full operation'

    $fixture.Country='JP'
    $fixture.ProtectedPreflightError='Expected one healthy Claude Store package registered for this user.'
    $fixture.Active.ExpectedIpv4='198.51.100.44'
    $oldProfile=New-GuardNodeProfile -Text $link
    try{$fixture.Active.RouteHash=(Get-GuardNodeProfileRoute $oldProfile $fixture.Active.Port).Hash}
    finally{$oldProfile.Password.Dispose()}
    $scoped=Set-GuardWindowCurrentNode JP '198.51.100.44'
    Assert-Window (-not $scoped.Success -and $scoped.UserRegionCountry -ceq 'JP' -and $scoped.UserRegionIpv4 -ceq '198.51.100.44') `
        'A Store registration rejection offers the user-only locale action for the exact installed current route'
    $null=Get-GuardWindowProbe $link ([Threading.CancellationToken]::None)
    $null=Get-GuardWindowRegion 'Automatic'
    $scoped=Set-GuardWindowNode 'Automatic'
    Assert-Window (-not $scoped.Success -and $scoped.UserRegionCountry -ceq 'JP' -and $scoped.UserRegionIpv4 -ceq '198.51.100.44') `
        'The normal reviewed route reaches the same user-only option without claiming a protection update'
    $fixture.Active.ExpectedIpv4='198.51.100.1'
    $scoped=Set-GuardWindowCurrentNode JP '198.51.100.44'
    Assert-Window (-not $scoped.UserRegionCountry) 'A verified exit different from the already-allowed address gets no user-only action'
    $fixture.Active.ExpectedIpv4='198.51.100.44'
    $routeHash=$fixture.Active.RouteHash
    $fixture.Active.RouteHash='B'*64
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').UserRegionCountry) `
        'A new route with the same public IPv4 cannot inherit the user-only action'
    $fixture.Active.RouteHash=$routeHash
    $fixture.ProtectedPreflightError='A previous Guard transaction requires recovery before any new deployment.'
    Assert-Window (-not (Set-GuardWindowCurrentNode JP '198.51.100.44').UserRegionCountry) `
        'An unrelated protected preflight failure does not offer user-only changes'
}finally{
    $null=Clear-GuardWindowPreview
    [IO.File]::Delete((Join-Path $scratch 'setup-last-window-error.json'))
    if($retirementPath){[IO.File]::Delete($retirementPath)}
    if($fixtureRelease){[IO.Directory]::Delete($fixtureRelease)}
    foreach($file in $readback,$operationResult,$stageResult){if($file){[IO.File]::Delete($file)}}
    if($operationDirectory){[IO.Directory]::Delete($operationDirectory);[IO.Directory]::Delete((Split-Path -Parent $operationDirectory))}
    [IO.Directory]::Delete($scratch)
}
