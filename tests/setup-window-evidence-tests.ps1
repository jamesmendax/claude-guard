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
    Active=[pscustomobject]@{Generation=$generation;PackageFullName='Store.Fixture';ProxyMode='Manual';ExpectedIpv4='198.51.100.1';Port=18793;RouteHash=('B'*64)}
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
function Get-GuardSettingsNodePreview($stage,$profile,$token){
    $fixture.ProbeCalls++
    [pscustomobject]@{Passed=$true;State='Completed';Provider='CloudflareTrace';ExitIpv4='198.51.100.44';CountryCode=$fixture.Country
        CheckedUtc=$fixture.Now.AddMinutes(-$fixture.Age).ToString('o');ProfileFingerprint=(Get-GuardNodeProfileRoute $profile 18881).ProfileFingerprint}
}
function Invoke-GuardSettingsInstall($Stage,$Launcher,$Profile,$Proof,$RegionPlan,$ProgressCallback){
    $fixture.InstallCalls++
    $fixture.ReceivedPlan=$RegionPlan
    [pscustomobject]@{Installed=$true;Phase='Completed';Operation=('c'*32);Generation=$generation;GuardedEntry='Desktop'
        FreshProofs=6;Verification=@{RequiredProofs=6;Proofs=6;Status='Verified';WorkerStatus='Ready'}}
}

$scratch=Join-Path ([IO.Path]::GetTempPath()) ('guard-window-evidence-tests-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($scratch)
function Get-GuardDataPath([string]$Name){Join-Path $scratch $Name}
$link='vless://6b1f71fb-b22c-41b7-8fe7-ceccb87c2fa3@198.51.100.81:443?type=ws&security=tls&sni=example.test&host=example.test&path=%2Fsocket&encryption=none'

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
    $candidate=Get-GuardWindowRegion 'Keep'
    Assert-Window (-not $candidate.RequiresChoice -and -not (Find-Check $candidate 'windows-zone').Change) 'Keep leaves the existing Windows time zone unchanged'
    Assert-Window (-not (Set-GuardWindowNode 'Automatic').Success -and $fixture.InstallCalls -eq 0) 'Apply requires the exact reviewed choice'
    Assert-Window ((Set-GuardWindowNode 'Keep').Success -and $fixture.ReceivedPlan.ProfileId -ceq 'Keep' -and
        $fixture.ProbeCalls -eq 2 -and $fixture.StatusReads -eq $statusReads) 'Applying the reviewed plan preserves the proof and runs no extra network or health check'
    $fixture.Country=$null
    $null=Get-GuardWindowProbe $link ([Threading.CancellationToken]::None)
    Assert-Window ((Get-GuardWindowRegion 'Automatic').RequiresChoice -and -not (Get-GuardWindowRegion 'Windows/UTC').RequiresChoice) 'Missing country still permits a manually chosen Windows time zone'
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
}finally{
    $null=Clear-GuardWindowPreview
    [IO.File]::Delete((Join-Path $scratch 'setup-last-window-error.json'))
    [IO.Directory]::Delete($scratch)
}
