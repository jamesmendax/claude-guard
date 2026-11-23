#Requires -Version 5.1
[CmdletBinding()]
param([ValidateRange(1024,49151)][int]$RelayPort=18793,
    [string]$SettingsDirectory=(Join-Path $env:APPDATA 'com.appshub\Bettbox'))
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-daily.ps1"
$settingsDir=$SettingsDirectory
$settings=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $settingsDir 'config.json') | ConvertFrom-Json
$profile=@($settings.profiles | Where-Object { $_.id -ceq $settings.currentProfileId })
if($profile.Count -ne 1 -or $profile[0].id -cnotmatch '^[A-Za-z0-9_-]+$') {throw 'The Bettbox saved profile cannot be uniquely identified.'}
$source=Join-Path $settingsDir ('profiles\'+$profile[0].id+'.yaml')
$bytes=[IO.File]::ReadAllBytes($source)
$hash=[Security.Cryptography.SHA256]::Create()
try {
    $sourceDigest=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','')
    $text=[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    $node=Read-GuardBettboxVlessNode $text $profile[0].selectedMap.GLOBAL
    $dedicated=New-GuardDedicatedProxyConfig $node $RelayPort
    $sys=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $observed=@(Get-NetTCPConnection -LocalPort 7890 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        $owner=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{Process=$owner.ProcessName;Loopback=$_.LocalAddress -in '127.0.0.1','::1'}
    })
    $adapter=Get-NetAdapter -Name 'Bettbox' -ErrorAction SilentlyContinue
    $summary=[ordered]@{
        Utc=[datetime]::UtcNow.ToString('o')
        SavedProfileSha256=$sourceDigest
        SystemProxyConfigured=([bool]$sys.ProxyEnable)
        SystemProxyPointsToLocalBettbox=([bool]([string]$sys.ProxyServer -match '(?:localhost|127\.0\.0\.1):7890'))
        TunStatus=[string]$adapter.Status
        Listener=$observed
        SavedMode=[string]$settings.patchClashConfig.mode
        SavedProfileContainsDirectToken=($text -match '(?i)\bDIRECT\b')
        SavedProfileContainsFallbackGroup=($text -match '(?im)\btype\s*:\s*["'']?(?:fallback|url-test)\b')
        SavedProfileCanBeOverridden=([bool]$profile[0].useScriptOverride)
        CandidateUsesSavedSelection=$true
        CandidateNodeCount=@($dedicated.proxies).Count
        CandidateUsesOnlyPinnedRelayRule=($dedicated.rules[0] -ceq 'MATCH,guard-pinned')
        CandidateTransport='VLESS Reality TCP'
        CandidateDestinationUsesLiteralIpv4=$true
        CandidateRelayUsesLoopback=($dedicated.'bind-address' -ceq '127.0.0.1')
        RuntimeEffectiveNodeVerified=$false
        PublicExitVerified=$false
    }
    $summary | ConvertTo-Json -Depth 4
} finally {
    $hash.Dispose()
    [Array]::Clear($bytes,0,$bytes.Length)
}

