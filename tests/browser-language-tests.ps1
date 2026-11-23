#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-browser-languages.ps1"

function Assert-BrowserLanguage([bool]$Condition,[string]$Message) {
    if (!$Condition) { throw "FAIL: $Message" }
    "PASS: $Message"
}
function Assert-BrowserLanguageError([scriptblock]$Call,[string]$Expected,[string]$Code) {
    try { & $Call | Out-Null } catch {
        if ($_.Exception.Message -notlike "*$Expected*" -or
            ($Code -and $_.Exception.Data['GuardBrowserFailure'] -cne $Code)) { throw }
        return
    }
    throw "Expected error: $Expected"
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('guard-edge-closed-test-' + [Guid]::NewGuid().ToString('N'))
$profilePath = Join-Path $fixtureRoot 'Default'
$otherProfile = Join-Path $fixtureRoot 'Profile 1'
$null = New-Item -ItemType Directory -Path $profilePath,$otherProfile -Force
$preferences = Join-Path $profilePath 'Preferences'
$otherPreferences = Join-Path $otherProfile 'Preferences'
$localStatePath = Join-Path $fixtureRoot 'Local State'
$localState = '{"intl":{"app_locale":"de"},"profile":{"last_used":"Default","info_cache":{"Default":{},"Profile 1":{}}}}'
$beforeLanguages = 'en-US,en,zh-CN,zh-TW'
$afterLanguages = 'ja,en-US,en,zh-CN,zh-TW'
$layout = @'
{
  "other":{"intl":{"accept_languages":"unrelated","selected_languages":"unrelated"},"scan":"quote: \" and bracket: ]"},
  "int\u006c": {
    "selected_languages" : "@before@",
    "writing": {"accept_languages":"nested and untouched"},
    "accept_languages": "@before@",
    "app_locale": "de"
  },
  "large": [1, true, null, {}, { "items":[false, "a,b:{c}"] }],
  "complete": true
}
'@
$layout = $layout.Replace('@before@',$beforeLanguages)
$afterText = $layout.Replace('"' + $beforeLanguages + '"','"' + $afterLanguages + '"')
$utf8Bom = [Text.UTF8Encoding]::new($true,$true)
$rawUtf8 = [Text.UTF8Encoding]::new($false,$true)
$beforeTextWithBom = [string][char]0xfeff + $layout
$afterTextWithBom = [string][char]0xfeff + $afterText
[IO.File]::WriteAllText($preferences,$layout,$utf8Bom)
[IO.File]::WriteAllText($otherPreferences,$layout,$utf8Bom)
[IO.File]::WriteAllText($localStatePath,$localState)
$test = [pscustomobject]@{
    Running=$false; Writes=0; ReadCount=0; FailReadback=$false; ChangeUnrelatedOnRead=0; StartRaceOnWrite=$false
}
$read = {
    param($Profile)
    $test.ReadCount++
    if ($test.ChangeUnrelatedOnRead -eq $test.ReadCount) {
        $raw = [IO.File]::ReadAllText($preferences)
        [IO.File]::WriteAllText($preferences,$raw.Replace('"complete": true','"complete": false'),$utf8Bom)
    }
    $snapshot = Get-GuardEdgeLanguageSnapshot -DataRoot $fixtureRoot -Profile $Profile
    if ($test.FailReadback -and $snapshot.AcceptLanguages -ceq $afterLanguages) { $snapshot.DisplayLocale = 'fr' }
    [pscustomobject]@{
        Browser='Edge'; Profile=$snapshot.Profile; Executable='C:\Fixture\msedge.exe'; Available=$true; Reason=$null
        AcceptLanguages=$snapshot.AcceptLanguages; SelectedLanguages=$snapshot.SelectedLanguages; DisplayLocale=$snapshot.DisplayLocale
    }
}.GetNewClosure()
$operations = @{
    Read=$read
    IsRunning={ $test.Running }.GetNewClosure()
    IsBusy={ $test.Running -or [IO.File]::Exists((Join-Path $fixtureRoot 'lockfile')) }.GetNewClosure()
    Write={
        param($Plan,$Current,$Target,$ops,$Restore)
        $test.Writes++
        $check = $ops.IsRunning
        if ($test.StartRaceOnWrite) {
            $count = [int[]]@(0)
            $check = { $count[0]++; $count[0] -ge 3 }.GetNewClosure()
        }
        $arguments=@{DataRoot=$fixtureRoot;Profile=$Plan.Profile;Current=$Current;Target=$Target;IsRunning=$check;Read=$ops.Read;Restore=$Restore}
        Set-GuardEdgeOfflineLanguagePreferences @arguments
    }.GetNewClosure()
}

try {
    $state = & $read
    $plan = New-GuardBrowserLanguagePlan -Target JP -State $state
    Assert-BrowserLanguage ($plan.PrimaryLanguage -ceq 'ja' -and $plan.After.AcceptLanguages -ceq $afterLanguages -and
        $plan.Before.AcceptLanguages -ceq $beforeLanguages -and $plan.After.DisplayLocale -ceq 'de' -and $test.Writes -eq 0) 'preview puts Japanese first and preserves fallback order and the menu language'
    $saved = $plan | ConvertTo-Json -Depth 6 -Compress | ConvertFrom-Json

    $test.Running = $true
    Assert-BrowserLanguage ((Get-GuardBrowserLanguageApplyMode $saved $operations) -ceq 'ManualRequired') 'an active Edge profile asks for a deliberate manual change'
    Assert-BrowserLanguageError { Set-GuardBrowserLanguagePlan $saved $operations } 'Edge is open or its profile is busy' 'EdgeLanguageManualRequired'
    Assert-BrowserLanguage ($test.Writes -eq 0 -and $rawUtf8.GetString([IO.File]::ReadAllBytes($preferences)) -ceq $beforeTextWithBom) 'apply never writes to a running Edge profile'
    $test.Running = $false

    $lockPath = Join-Path $fixtureRoot 'lockfile'
    $foreignLock = [IO.FileStream]::new($lockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        Assert-BrowserLanguage ((Get-GuardBrowserLanguageApplyMode $saved $operations) -ceq 'ManualRequired') 'a competing Edge profile lock is detected before apply'
        Assert-BrowserLanguageError { Set-GuardBrowserLanguagePlan $saved $operations } 'Edge is open or its profile is busy' 'EdgeLanguageManualRequired'
        Assert-BrowserLanguage ([IO.File]::Exists($lockPath) -and $rawUtf8.GetString([IO.File]::ReadAllBytes($preferences)) -ceq $beforeTextWithBom) 'apply never replaces an existing Edge lock'
    } finally { $foreignLock.Dispose(); [IO.File]::Delete($lockPath) }

    $test.StartRaceOnWrite = $true
    Assert-BrowserLanguageError { Set-GuardBrowserLanguagePlan $saved $operations } 'Edge is open or its profile is busy' 'EdgeLanguageManualRequired'
    Assert-BrowserLanguage (![IO.File]::Exists($lockPath) -and
        $rawUtf8.GetString([IO.File]::ReadAllBytes($preferences)) -ceq $beforeTextWithBom) 'Edge startup before the atomic rename aborts and releases the owned lock'
    $test.StartRaceOnWrite = $false

    $test.ChangeUnrelatedOnRead = $test.ReadCount + 3
    Assert-BrowserLanguageError { Set-GuardBrowserLanguagePlan $saved $operations } 'changed during the operation'
    $independent = $beforeTextWithBom.Replace('"complete": true','"complete": false')
    Assert-BrowserLanguage ($rawUtf8.GetString([IO.File]::ReadAllBytes($preferences)) -ceq $independent) 'a concurrent unrelated file edit is preserved'
    $test.ChangeUnrelatedOnRead = 0
    [IO.File]::WriteAllText($preferences,$layout,$utf8Bom)

    $test.FailReadback = $true
    Assert-BrowserLanguageError { Set-GuardBrowserLanguagePlan $saved $operations } 'did not save the requested website language change'
    Assert-BrowserLanguage ($rawUtf8.GetString([IO.File]::ReadAllBytes($preferences)) -ceq $beforeTextWithBom) 'a failed readback restores the checked atomic backup'
    $test.FailReadback = $false

    Assert-BrowserLanguage ((Get-GuardBrowserLanguageApplyMode $saved $operations) -ceq 'Offline' -and
        (Set-GuardBrowserLanguagePlan $saved $operations) -ceq 'Applied' -and
        (Test-GuardBrowserLanguagePlan $saved $operations)) 'a serialized plan writes and verifies both Edge preferences while closed'
    Assert-BrowserLanguage ($rawUtf8.GetString([IO.File]::ReadAllBytes($preferences)) -ceq $afterTextWithBom -and
        $rawUtf8.GetString([IO.File]::ReadAllBytes($otherPreferences)) -ceq $beforeTextWithBom -and
        [IO.File]::ReadAllText($localStatePath) -ceq $localState) 'the replacement preserves other bytes, encoding, other profiles, and Local State'
    $test.Running = $true
    Assert-BrowserLanguageError { Restore-GuardBrowserLanguagePlan $saved $operations } 'Edge is open or its profile is busy' 'EdgeLanguageManualRequired'
    $manual = New-GuardBrowserLanguagePlan JP (& $read)
    Assert-BrowserLanguage ((Get-GuardBrowserLanguageApplyMode $manual $operations) -ceq 'Unchanged' -and
        (Set-GuardBrowserLanguagePlan $manual $operations) -ceq 'Unchanged') 'a manual change already saved in Edge requires no automatic write'
    $test.Running = $false
    Assert-BrowserLanguage ((Restore-GuardBrowserLanguagePlan $saved $operations) -ceq 'Restored' -and
        (Restore-GuardBrowserLanguagePlan $saved $operations) -ceq 'Unchanged' -and
        $rawUtf8.GetString([IO.File]::ReadAllBytes($preferences)) -ceq $beforeTextWithBom) 'undo restores the exact original list and can be repeated'
    Assert-BrowserLanguage (@(Get-ChildItem -LiteralPath $profilePath -Filter 'Preferences.guard-*').Count -eq 0) 'success and recovered failures leave no preference backup or pending file'

    foreach ($target in 'en-CA','fr-CA','de-DE','es-MX','zh-TW') {
        Assert-BrowserLanguage ((New-GuardBrowserLanguagePlan $target (& $read)).PrimaryLanguage -ceq $target) "the exact supported country variant is retained ($target)"
    }
    Assert-BrowserLanguage ((New-GuardBrowserLanguagePlan 'ko-KR' (& $read)).PrimaryLanguage -ceq 'ko') 'an unavailable regional variant uses the same neutral language'
    Assert-BrowserLanguageError { New-GuardBrowserLanguagePlan 'zh-Hans-SG' (& $read) } 'same-script'
    Assert-BrowserLanguage $true 'a fallback that would discard the requested script is rejected'
    Assert-BrowserLanguageError {
        [ClaudeGuard.EdgePreferenceEditor]::Rewrite('{"intl":{"accept_languages":"en","accept_languages":"en","selected_languages":"en"}}','en','ja,en')
    } 'ambiguous language settings'
    Assert-BrowserLanguage $true 'duplicate language keys are rejected instead of rewriting ambiguous settings'

    $junction = Join-Path $fixtureRoot 'redirected'
    $null = New-Item -ItemType Junction -Path $junction -Target $fixtureRoot
    try {
        Assert-BrowserLanguageError {
            [ClaudeGuard.EdgePreferenceEditor]::PinDirectories((Join-Path $junction 'Default'))
        } 'settings is redirected'
        Assert-BrowserLanguage $true 'a redirected ancestor is rejected before any write'
    } finally { [IO.Directory]::Delete($junction) }

    $pin = [ClaudeGuard.EdgePreferenceEditor]::PinDirectories($profilePath)
    $moved = Join-Path $fixtureRoot 'attempted-move'
    $denied = $false
    try {
        try { [IO.Directory]::Move($profilePath,$moved) }
        catch [IO.IOException] { $denied = $true }
        catch [UnauthorizedAccessException] { $denied = $true }
        Assert-BrowserLanguage ($denied -and [IO.Directory]::Exists($profilePath)) 'another writer cannot replace the pinned profile directory'
    } finally { $pin.Dispose() }
} finally {
    $resolved = [IO.Path]::GetFullPath($fixtureRoot)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($resolved) -ieq $parent -and [IO.Path]::GetFileName($resolved) -match '^guard-edge-closed-test-[a-f0-9]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
