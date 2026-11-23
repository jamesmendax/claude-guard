#Requires -Version 5.1
param([string]$ChildDirectory,[string]$ChildHash,[int]$ChildPort)

$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-bettbox-profile.ps1"

if($ChildDirectory){
    $route=Find-GuardPriorBettboxRoute -ExpectedHash $ChildHash -Port $ChildPort -BettboxDirectory $ChildDirectory
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($route.Json))
    return
}

function Assert-Bettbox([bool]$Passed,[string]$Check) {
    if(-not $Passed){throw "FAIL: $Check"}
    "PASS $Check"
}

function Assert-BettboxRejected([scriptblock]$Operation,[string]$Check,[switch]$Prior) {
    $expected=if($Prior){'The prior Bettbox route could not be verified.'}else{'The current Bettbox selection could not be verified.'}
    $message=$null
    try{$null=& $Operation}catch{$message=$_.Exception.Message}
    Assert-Bettbox ($message -ceq $expected) $Check
}

function Write-BettboxFixture([string]$Path,[string]$Text) {
    [IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false))
}

function Write-BettboxSettings([string]$ProfileId,[string]$Selection,[string]$Mode='global') {
    $active=@{id='active';selectedMap=@{GLOBAL=$Selection};useScriptOverride=$true
        scriptOverride='throw "Fixture override must never run"'}
    $prior=@{id='prior'}
    if($ProfileId -ceq $prior.id){$prior.selectedMap=@{GLOBAL=$Selection}}
    $settings=@{currentProfileId=$ProfileId;patchClashConfig=@{mode=$Mode};profiles=@($active,$prior)}
    Write-BettboxFixture $settingsFile ($settings | ConvertTo-Json -Depth 6 -Compress)
}

$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$fixture=[IO.Path]::Combine($tempRoot,('guard-bettbox-fixture-'+[guid]::NewGuid().ToString('N')))
$directory=Join-Path $fixture 'com.appshub\Bettbox'
$profilesFolder=Join-Path $directory 'profiles'
$settingsFile=Join-Path $directory 'config.json'
$activeFile=Join-Path $profilesFolder 'active.yaml'
$priorFile=Join-Path $profilesFolder 'prior.yaml'
$junction=Join-Path $fixture 'redirected'
$oldAppData=$env:APPDATA
$port=18793
$wsUuid='00000000-0000-4000-8000-000000000011'
$realityUuid='00000000-0000-4000-8000-000000000012'
$key='A'*43
$wsYaml=@"
mixed-port: 7890
proxies:
  - name: 'Tokyo, fixture'
    type: vless
    server: 203.0.113.42
    port: 8443
    uuid: $wsUuid
    tls: true
    servername: server.example.test
    skip-cert-verify: false
    network: ws
    ws-opts:
      path: '/guard/socket?mode=fixture'
      headers:
        Host: edge.example.test
    ip-version: ipv4
proxy-groups:
  - name: fixture-group
    type: select
    proxies: ['Tokyo, fixture']
rules:
  - MATCH,fixture-group
"@
$realityYaml=@"
proxies:
  - name: reality-fixture
    type: vless
    server: 203.0.113.42
    port: 8443
    uuid: $realityUuid
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: server.example.test
    reality-opts:
      public-key: $key
      short-id: ''
    client-fingerprint: chrome
"@
$wsFields=@{Transport='WebSocketTls';ServerIpv4='203.0.113.42';ServerPort=8443;Uuid=$wsUuid
    ServerName='server.example.test';WebSocketHost='edge.example.test';WebSocketPath='/guard/socket?mode=fixture'}
$expectedWs=Get-GuardNodeProfileRoute (New-GuardNodeProfile -Fields $wsFields) $port
$oldNode=Read-GuardBettboxVlessNode $realityYaml 'reality-fixture'
$oldConfig=New-GuardDedicatedProxyConfig $oldNode $port
$oldConfig['geo-auto-update']=$false
$oldJson=$oldConfig | ConvertTo-Json -Depth 8 -Compress
$oldHash=Get-GuardNodeTextHash $oldJson

try{
    $null=[IO.Directory]::CreateDirectory($profilesFolder)
    $env:APPDATA=$fixture
    Write-BettboxSettings 'active' 'fixture-group'
    Write-BettboxFixture $activeFile $wsYaml
    Write-BettboxFixture $priorFile $realityYaml
    $profile=Get-GuardCurrentBettboxProfile
    $route=Get-GuardNodeProfileRoute $profile $port
    Assert-Bettbox ($profile -is [pscredential] -and $route.Json -ceq $expectedWs.Json -and
        $route.ProfileFingerprint -ceq $expectedWs.ProfileFingerprint) 'A saved one-child manual group yields the canonical verified WebSocket route even when the script-override flag is active'
    $prior=Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port $port
    Assert-Bettbox ($prior.Json -ceq $oldJson -and $prior.Hash -ceq $oldHash) 'The old Reality route is restored byte-for-byte from an inactive saved profile with the same endpoint and a different UUID'

    Write-BettboxFixture $activeFile ($wsYaml.Replace("    ip-version: ipv4","    client-fingerprint: chrome`r`n    ip-version: ipv4"))
    $fingerprintRoute=Get-GuardNodeProfileRoute (Get-GuardCurrentBettboxProfile) $port
    $wsFields.ClientFingerprint='chrome'
    $expectedFingerprintRoute=Get-GuardNodeProfileRoute (New-GuardNodeProfile -Fields $wsFields) $port
    Assert-Bettbox ($fingerprintRoute.Json -ceq $expectedFingerprintRoute.Json) 'An explicit WebSocket fingerprint participates in the canonical route'

    Write-BettboxSettings 'prior' 'reality-fixture'
    $direct=Get-GuardNodeProfileRoute (Get-GuardCurrentBettboxProfile) $port
    Assert-Bettbox ($direct.Json -ceq $oldJson -and $direct.ProfileFingerprint -ceq $prior.ProfileFingerprint) 'A directly selected legacy Reality node yields the original route and canonical profile'

    Write-BettboxSettings 'active' 'fixture-group'
    Write-BettboxFixture $activeFile $realityYaml
    $duplicate=Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port $port
    Assert-Bettbox ($duplicate.Json -ceq $oldJson) 'Identical saved copies resolve to one canonical route'
    $shell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $child=& $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath -ChildDirectory $directory -ChildHash $oldHash -ChildPort $port
    Assert-Bettbox ($LASTEXITCODE -eq 0 -and $child -ceq [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($oldJson))) 'A fresh Windows PowerShell 5.1 process reproduces the exact old route bytes'
    Assert-BettboxRejected {Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port ($port+1)} 'The same node at a different relay port does not match' -Prior
    Assert-BettboxRejected {Find-GuardPriorBettboxRoute -ExpectedHash ('0'*64) -Port $port} 'No endpoint or name fallback is allowed when the full hash is missing' -Prior
    Assert-BettboxRejected {Find-GuardPriorBettboxRoute -ExpectedHash $oldHash.ToLowerInvariant() -Port $port} 'An invalid stored hash format fails closed' -Prior
    Write-BettboxFixture $activeFile $wsYaml
    $priorWithoutSelection=Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port $port
    Assert-Bettbox ($priorWithoutSelection.Json -ceq $oldJson) 'Rollback can read a saved leaf without selection metadata from its old profile'

    foreach($bad in @(
        @{Check='A dynamic group is rejected';Text=$wsYaml.Replace('type: select','type: url-test')}
        @{Check='A multi-child group is rejected';Text=$wsYaml.Replace("['Tokyo, fixture']","['Tokyo, fixture', DIRECT]")}
        @{Check='A provider group is rejected';Text=$wsYaml.Replace('type: select',"type: select`r`n    use: [fixture-provider]")}
        @{Check='Repeated names are rejected';Text=$wsYaml.Replace('fixture-group',"'Tokyo, fixture'")}
        @{Check='Improperly nested proxy blocks are rejected';Text=$wsYaml.Replace('    network: ws','   network: ws')}
        @{Check='Disabled certificate checks are rejected';Text=$wsYaml.Replace('skip-cert-verify: false','skip-cert-verify: true')}
        @{Check='Quoted TLS booleans are rejected';Text=$wsYaml.Replace('tls: true','tls: "true"')}
        @{Check='An unspecified certificate policy is rejected for WebSocket';Text=$wsYaml.Replace('    skip-cert-verify: false','')}
        @{Check='Duplicate node fields are rejected';Text=$wsYaml.Replace('port: 8443',"port: 8443`r`n    port: 8443")}
        @{Check='A quoted duplicate key is rejected';Text=$wsYaml.Replace('port: 8443',"port: 8443`r`n    'port': 8443")}
        @{Check='A sibling cannot introduce a second effective node name';Text=$wsYaml.Replace('proxy-groups:',"  - name: sibling`r`n    'name': 'Tokyo, fixture'`r`n    type: direct`r`nproxy-groups:")}
        @{Check='Repeated Host is rejected';Text=$wsYaml.Replace('Host: edge.example.test',"Host: edge.example.test`r`n        Host: edge.example.test")}
        @{Check='An unsafe path is rejected';Text=$wsYaml.Replace('/guard/socket?mode=fixture','/guard/%0d%0a')}
        @{Check='A second document is rejected';Text=$wsYaml+"`r`n---`r`nmode: rule"}
    )){
        Write-BettboxFixture $activeFile $bad.Text
        Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} $bad.Check
    }
    Write-BettboxFixture $activeFile ($wsYaml.Replace("proxies: ['Tokyo, fixture']","proxies:`r`n      - 'Tokyo, fixture'"))
    $blockRoute=Get-GuardNodeProfileRoute (Get-GuardCurrentBettboxProfile) $port
    Assert-Bettbox ($blockRoute.Json -ceq $expectedWs.Json) 'A one-child block list is also deterministic'
    Write-BettboxFixture $activeFile $wsYaml

    Write-BettboxSettings 'active' 'fixture-group' 'rule'
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} 'Current saved selection requires global mode'
    Write-BettboxSettings 'active' 'Fixture-Group'
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} 'Selection is case-sensitive'
    Write-BettboxSettings 'missing' 'fixture-group'
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} 'A missing selected profile fails closed'
    Write-BettboxSettings 'active' 'fixture-group'
    $settings=[IO.File]::ReadAllText($settingsFile)
    Write-BettboxFixture $settingsFile ($settings.Replace('"GLOBAL":"fixture-group"','"GLOBAL":"fixture-group","fixture-group":"different"'))
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} 'An explicit contradictory child selection fails closed'
    Write-BettboxFixture $settingsFile ($settings.Replace('"GLOBAL":"fixture-group"','"GLOBAL":"fixture-group","fixture-group":"Tokyo, fixture"'))
    $explicit=Get-GuardNodeProfileRoute (Get-GuardCurrentBettboxProfile) $port
    Assert-Bettbox ($explicit.Json -ceq $expectedWs.Json) 'An explicit matching child selection is accepted'
    Write-BettboxFixture $settingsFile ($settings.Replace('"GLOBAL":','"GLO\u0042AL":"fixture-group","GLOBAL":'))
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} 'Escaped duplicate JSON keys fail closed'
    Write-BettboxFixture $settingsFile ($settings.TrimEnd('}')+',}')
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} 'Malformed settings fail with a sanitized error'
    Write-BettboxFixture $settingsFile ($settings.Replace('"prior"','"ACTIVE"'))
    Assert-BettboxRejected {Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port $port} 'Case-ambiguous profile paths are rejected' -Prior
    Write-BettboxFixture $settingsFile ($settings.Replace('"prior"','"..\\outside"'))
    Assert-BettboxRejected {Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port $port} 'Profile IDs cannot escape the saved profile directory' -Prior
    Write-BettboxFixture $settingsFile $settings

    Write-BettboxFixture $activeFile ($wsYaml+(' '*2MB))
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile} 'Oversized profile files fail closed'
    Write-BettboxFixture $activeFile $wsYaml
    $null=New-Item -ItemType Junction -Path $junction -Target $directory
    Assert-BettboxRejected {Get-GuardCurrentBettboxProfile -BettboxDirectory $junction} 'Redirected Bettbox directories are rejected'
    Assert-BettboxRejected {Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port $port -BettboxDirectory $junction} 'Rollback rejects redirected Bettbox directories' -Prior

    [IO.File]::Delete($priorFile)
    Assert-BettboxRejected {Find-GuardPriorBettboxRoute -ExpectedHash $oldHash -Port $port} 'A missing saved old node fails closed' -Prior
}finally{
    $env:APPDATA=$oldAppData
    if([IO.Directory]::Exists($junction)){[IO.Directory]::Delete($junction)}
    $resolved=[IO.Path]::GetFullPath($fixture)
    if($resolved.StartsWith($tempRoot+'\',[StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolved) -cmatch '\Aguard-bettbox-fixture-[a-f0-9]{32}\z' -and
        [IO.Directory]::Exists($resolved)){[IO.Directory]::Delete($resolved,$true)}
}
