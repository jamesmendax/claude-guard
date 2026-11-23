#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'package\guard-node-locale.ps1')
Add-Type -Path (Join-Path $root 'release\GuardSiteLanguage.cs')

function Assert-Result([bool]$Matches,[string]$Description){
    if(-not $Matches){throw "FAIL: $Description"}
    "PASS: $Description"
}

$japan=Get-GuardNodeLocaleTarget 'JP'
Assert-Result ($japan.GeoId -eq 122 -and $japan.LocaleName -ceq 'ja-JP' -and
    $japan.LanguageTag -ceq 'ja-JP' -and -not $japan.RequiresChoice) 'Japan resolves to its Windows country and Japanese format'
$canada=Get-GuardNodeLocaleTarget 'CA'
Assert-Result ($canada.RequiresChoice -and -not $canada.LocaleName -and
    $canada.Choices -ccontains 'en-CA' -and $canada.Choices -ccontains 'fr-CA') 'a multilingual country requires a choice'
$french=Get-GuardNodeLocaleTarget 'CA' 'fr-CA'
Assert-Result (-not $french.RequiresChoice -and $french.LocaleName -ceq 'fr-CA') 'a supported language and country pair resolves'
$closed=[ClaudeGuard.SiteLanguage]::Recent('test-edge','Default','ja','ja,en-US')
Assert-Result ($null -eq $closed) 'a quiet check returns no proof and opens no browser'
foreach($setting in @('windows-time-zone','windows-home-region','windows-regional-format','windows-preferred-languages','edge-website-languages')){
    $link=[ClaudeGuard.SiteLanguage]::GetManualDestination($setting)
    Assert-Result ($link -cin @('ms-settings:dateandtime','ms-settings:regionlanguage','microsoft-edge:edge://settings/languages')) 'manual actions have a fixed Settings destination'
}
$rejected=$false
try{$null=[ClaudeGuard.SiteLanguage]::GetManualDestination('https://invalid.example/')}catch{$rejected=$true}
Assert-Result $rejected 'unrecognized manual settings ids cannot launch arbitrary URLs'
foreach($inputCase in @(@('CA','ja-JP'),@('JP','ja'),@('XX',''),@('jP',''))){
    $rejected=$false
    try{$null=Get-GuardNodeLocaleTarget $inputCase[0] $inputCase[1]}catch{$rejected=$true}
    Assert-Result $rejected 'invalid or mismatched country and locale are rejected'
}
foreach($case in @(
        @('ja,en-US;q=0.9,en;q=0.8','ja-JP',$true),
        @('ja-JP,ja;q=0.9,en;q=0.8','ja',$true),
        @('fr-CA,fr;q=0.9','fr-CA',$true),
        @('en-US,en;q=0.9,ja;q=0.8','ja',$false),
        @('ja;q=0.8,en;q=0.9','ja',$false),
        @('ja;q=0','ja',$false),
        @('*,ja;q=0.9','ja',$false),
        @('zh-Hant,zh;q=0.9','zh-Hans',$false),
        @('en-GB,en;q=0.9','en-US',$false),
        @("ja`r`nInjected: x",'ja',$false),
        @('ja;q=no','ja',$false)
    )){
    $matched=[ClaudeGuard.SiteLanguage]::MatchesFirstLanguage($case[0],$case[1])
    Assert-Result ($matched -eq $case[2]) 'website acceptance checks the actual first language and priority'
}
