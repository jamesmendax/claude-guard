#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$MihomoPath,
    [string]$NodePath=(Get-Command node.exe -CommandType Application -ErrorAction Stop).Source
)

$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-node-profile.ps1"

function Assert-NodeProbe([bool]$Passed,[string]$Check) {
    if(-not $Passed){throw "FAIL: $Check"}
    "PASS $Check"
}

function Assert-NodeRejected([scriptblock]$Operation,[string]$Check) {
    $rejected=$false
    try{$null=& $Operation}catch{$rejected=$true}
    Assert-NodeProbe $rejected $Check
}

$uuid='00000000-0000-4000-8000-000000000009'
$key='A'*43
$fields=@{ServerIpv4='203.0.113.41';ServerPort=443;Uuid=$uuid;ServerName='example.test';ClientFingerprint='chrome'
    RealityPublicKey=$key;RealityShortId='';Flow='xtls-rprx-vision'}
$link="vless://$uuid@203.0.113.41:443?type=tcp&security=reality&pbk=$key&sni=example.test&fp=chrome&sid=&flow=xtls-rprx-vision&encryption=none#fixture"
$profile=New-GuardNodeProfile -Fields $fields
$fromLink=New-GuardNodeProfile -Text $link
$rebuilt=[pscredential]::new($profile.UserName,$profile.Password.Copy())
$profileRoute=Get-GuardNodeProfileRoute $profile 18793
$linkRoute=Get-GuardNodeProfileRoute $fromLink 18793
$rebuiltRoute=Get-GuardNodeProfileRoute $rebuilt 18793
Assert-NodeProbe ($profileRoute.Json -ceq $linkRoute.Json -and $profileRoute.Hash -ceq $rebuiltRoute.Hash -and
    $profileRoute.ProfileFingerprint -ceq $linkRoute.ProfileFingerprint) 'Manual entry, one link and a rebuilt PSCredential bind the same route'
$configured=New-GuardDedicatedProxyConfig (Get-GuardNodeProfileMaterial $profile).Node 18793
$configured['geo-auto-update']=$false
Assert-NodeProbe (($configured | ConvertTo-Json -Depth 8 -Compress) -ceq $profileRoute.Json) 'The fixed-port route matches the installed configuration format'
Assert-NodeProbe (($profile | ConvertTo-Json -Depth 4) -notmatch [regex]::Escape($uuid)) 'The profile carrier does not display the UUID'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link.Replace('&sid=','&sid=&sid=aa'))} 'Repeated query fields are rejected'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link.Replace('&sid=','&sid=&allowInsecure=1'))} 'Unknown security options are rejected'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link.Replace('&sid=','&sid=%GG'))} 'Malformed escapes are rejected'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link+"`n"+$link)} 'Pasted batches are rejected'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link+' '+$link)} 'A second link cannot hide inside a display label'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link.Replace('203.0.113.41','127.0.0.1'))} 'A trial cannot proxy directly to the host loopback'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link.Replace('203.0.113.41','example.test'))} 'The node must identify one literal IPv4 upstream'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link.Replace('&sid=',''))} 'Omitted identity fields are not guessed'

$wsFields=@{Transport='WebSocketTls';ServerIpv4='203.0.113.42';ServerPort=8443;Uuid=$uuid;ServerName='example.test'
    WebSocketHost='edge.example.test';WebSocketPath='/guard/socket?mode=fixture'}
$wsLink="vless://$uuid@203.0.113.42:8443?type=ws&security=tls&sni=example.test&host=edge.example.test&path=%2Fguard%2Fsocket%3Fmode%3Dfixture#fixture"
$wsProfile=New-GuardNodeProfile -Fields $wsFields
$wsLinkProfile=New-GuardNodeProfile -Text $wsLink
$wsRoute=Get-GuardNodeProfileRoute $wsProfile 18793
Assert-NodeProbe ((Get-GuardNodeProfileRoute $wsLinkProfile 18793).Hash -ceq $wsRoute.Hash -and
    $wsRoute.Upstream.network -ceq 'ws' -and $wsRoute.Upstream.server -ceq '203.0.113.42' -and
    $wsRoute.Upstream.tls -eq $true -and $wsRoute.Upstream.'skip-cert-verify' -eq $false -and
    $wsRoute.Upstream.'ws-opts'.path -ceq '/guard/socket?mode=fixture' -and
    $wsRoute.Upstream.'ws-opts'.headers.Host -ceq 'edge.example.test' -and
    $wsRoute.Upstream.servername -ceq 'example.test') 'WebSocket manual entry and link pin the same IPv4 and verified TLS route'
Assert-NodeRejected {New-GuardNodeProfile -Text ($wsLink.Replace('security=tls','security=none'))} 'WebSocket without TLS is rejected'
Assert-NodeRejected {New-GuardNodeProfile -Text ($wsLink.Replace('&host=','&allowInsecure=1&host='))} 'WebSocket callers cannot disable certificate checks'
Assert-NodeRejected {New-GuardNodeProfile -Text ($wsLink.Replace('&host=',"&pbk=$key&host="))} 'Reality credentials cannot be mixed into WebSocket TLS'
Assert-NodeRejected {New-GuardNodeProfile -Text ($wsLink.Replace('&host=','&flow=xtls-rprx-vision&host='))} 'XTLS flow cannot be mixed into WebSocket TLS'
Assert-NodeRejected {New-GuardNodeProfile -Text ($link.Replace('&sid=','&path=%2Fother&sid='))} 'TCP Reality is not silently converted into WebSocket'
Assert-NodeRejected {New-GuardNodeProfile -Text ($wsLink.Replace('mode%3Dfixture','mode%0D%0AInjected'))} 'WebSocket path cannot inject HTTP request headers'

$assetScript=(Join-Path $PSScriptRoot 'node-profile-loopback-fixture.mjs')
$assets=@{
    RelayPath=(Resolve-Path -LiteralPath $MihomoPath).ProviderPath
    RelaySha256='CF894375DBC00AB6708C1314AC35BBD29059F4C37F315353AACA7F1A9C566DE6'
    ObserverPath=(Resolve-Path -LiteralPath $NodePath).ProviderPath
    ObserverSha256='86FC4785327DB5F5C7558DC6156C543B433C313E813A222E088086222AB4AFA6'
    ObserverScriptPath=$assetScript
    ObserverScriptSha256=(Get-FileHash -LiteralPath $assetScript -Algorithm SHA256).Hash
}
$tempBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$tempPath=Join-Path $tempBase ('guard-node-tests-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($tempPath)

function Invoke-DefaultObserverFixture($Route,[int]$Port){
    $relay=$null
    $observer=$null
    try{
        $relay=Start-GuardDailyChild $assets.RelayPath ('-d "'+$tempPath+'" -f -') $Route.Json
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while(-not (Test-GuardDailyRelayListener $Port $relay.Process.Id)){
            if($relay.Process.HasExited -or $clock.ElapsedMilliseconds -gt 5000){throw 'The default observation relay did not start.'}
            Start-Sleep -Milliseconds 40
        }
        $observer=Start-GuardDailyChild $assets.ObserverPath ('--use-bundled-ca "'+$assetScript+'"') (
            @{port=$Port;backupExitLookup=$true;deadlineMs=14000} | ConvertTo-Json -Compress)
        if(-not $observer.Process.WaitForExit(5000) -or $observer.Process.ExitCode -ne 0 -or -not $observer.Output.Wait(1000)){
            throw 'The default observer did not get its verified fixture response.'
        }
        $observer.Output.GetAwaiter().GetResult() | ConvertFrom-Json
    }finally{
        try{Stop-GuardNodeProbeChild $observer}finally{Stop-GuardNodeProbeChild $relay}
    }
}

function Invoke-IsolatedNodeCase([string]$Mode,[int]$CancelAfter=0,[switch]$DefaultObserver) {
    $testPort=Get-GuardNodeProbePort
    $upstreamPort=Get-GuardNodeProbePort
    while($upstreamPort -eq $testPort){$upstreamPort=Get-GuardNodeProbePort}
    $receipt=Join-Path $tempPath $(if($DefaultObserver){'default-observer.txt'}else{$Mode+'.txt'})
    $useWss=$Mode -cin 'trusted-wss','missing-ca-wss'
    $upstream=$null
    $websocket=$null
    $cancel=[Threading.CancellationTokenSource]::new()
    try{
        $upstreamMode=if($useWss){'success'}else{$Mode}
        $upstream=Start-GuardDailyChild $assets.ObserverPath ('"'+$assetScript+'" serve '+$upstreamPort+' '+$upstreamMode+' "'+$receipt+'"') ''
        $timer=[Diagnostics.Stopwatch]::StartNew()
        while(-not (Test-GuardDailyRelayListener $upstreamPort $upstream.Process.Id)){
            if($upstream.Process.HasExited -or $timer.ElapsedMilliseconds -gt 5000){throw 'The synthetic upstream did not start.'}
            Start-Sleep -Milliseconds 30
        }
        $fixtureRoute=if($useWss -or $Mode -ceq 'untrusted-ws'){$wsRoute}else{$profileRoute}
        # The loopback override is test-only. No public destination is dialed by the fixture.
        $config=$fixtureRoute.Json | ConvertFrom-Json
        $config.'mixed-port'=$testPort
        $config.proxies[0].server='127.0.0.1'
        $config.proxies[0].port=$upstreamPort
        if($useWss){
            $wssPort=Get-GuardNodeProbePort
            while($wssPort -eq $testPort -or $wssPort -eq $upstreamPort){$wssPort=Get-GuardNodeProbePort}
            $wssReceipt=Join-Path $tempPath ($Mode+'-handshake.txt')
            $websocket=Start-GuardDailyChild $assets.ObserverPath ('"'+$assetScript+'" serve-wss '+$wssPort+' '+$upstreamPort+' "'+$wssReceipt+'"') ''
            $timer.Restart()
            while(-not (Test-GuardDailyRelayListener $wssPort $websocket.Process.Id)){
                if($websocket.Process.HasExited -or $timer.ElapsedMilliseconds -gt 5000){throw 'The synthetic WebSocket upstream did not start.'}
                Start-Sleep -Milliseconds 30
            }
            $config.proxies[0].port=$wssPort
            $config.proxies[0].servername='api.ipify.org'
            if($Mode -ceq 'trusted-wss'){
                $fixtureCa=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'exit-observer-fixture-cert.pem'))
                # The pinned Mihomo spelling is intentional. This trust anchor is private to the test child.
                $config | Add-Member -NotePropertyName tls -NotePropertyValue @{'custom-certifactes'=@($fixtureCa)}
            }
        }elseif($Mode -cne 'untrusted-ws'){
            $config.proxies[0].tls=$false
            foreach($property in 'client-fingerprint','reality-opts','servername','flow'){$config.proxies[0].PSObject.Properties.Remove($property)}
        }
        $route=[pscustomobject]@{Json=($config | ConvertTo-Json -Depth 8 -Compress);Hash=$fixtureRoute.Hash
            ProfileFingerprint=$fixtureRoute.ProfileFingerprint}
        if($CancelAfter){$cancel.CancelAfter($CancelAfter)}
        $before=@(Get-ChildItem -LiteralPath $tempBase -Directory -Filter 'guard-node-probe-*' | ForEach-Object Name)
        $result=if($DefaultObserver){Invoke-DefaultObserverFixture $route $testPort}
            else{Invoke-GuardNodeProbeRuntime $route $assets $testPort $cancel.Token ($Mode -ceq 'fallback')}
        $after=@(Get-ChildItem -LiteralPath $tempBase -Directory -Filter 'guard-node-probe-*' | ForEach-Object Name)
        if(@($after | Where-Object {$_ -notin $before}).Count){throw 'The trial left an isolated relay work directory.'}
        $socket=[Net.Sockets.TcpListener]::new([ipaddress]::Loopback,$testPort)
        try{$socket.ExclusiveAddressUse=$true;$socket.Start()}finally{$socket.Stop()}
        $requests=if([IO.File]::Exists($receipt)){[IO.File]::ReadAllLines($receipt)}
        $expected=if($Mode -ceq 'fallback'){'PinnedTlsRequest:Cloudflare,PinnedTlsRequest:Ipify'}else{'PinnedTlsRequest:Cloudflare'}
        $expectedRequests=if($Mode -ceq 'untrusted-ws'){@($requests | Select-Object -Unique) -ceq 'PinnedWebSocketTlsAttempt'}
            elseif($Mode -ceq 'missing-ca-wss'){-not $requests}
            else{($requests -join ',') -ceq $expected}
        if($useWss){
            $handshake=if([IO.File]::Exists($wssReceipt)){[IO.File]::ReadAllLines($wssReceipt)}
            $validHandshake=if($Mode -ceq 'trusted-wss'){($handshake -join ',') -ceq 'PinnedWssSni,PinnedWssUpgrade'}
                else{@($handshake | Select-Object -Unique) -ceq 'PinnedWssSni'}
            if(-not $validHandshake -or -not $expectedRequests){
                throw "The verified WebSocket fixture did not get the expected handshake and tunnel requests ($($result.ErrorCode), handshake: $($handshake -join ','), tunnel: $($requests -join ','))."
            }
        }
        if(-not $expectedRequests){
            throw "The isolated relay did not carry the authenticated fixture request ($($result.ErrorCode))."
        }
        $result
    }finally{
        try{Stop-GuardNodeProbeChild $websocket}finally{
            try{Stop-GuardNodeProbeChild $upstream}finally{$cancel.Dispose()}
        }
    }
}

try{
    $relayPin=Open-GuardNodeProbeAsset $assets.RelayPath $assets.RelaySha256
    $syntax=$null
    try{
        $syntax=Start-GuardDailyChild $assets.RelayPath ('-t -d "'+$tempPath+'" -f -') $wsRoute.Json
        Assert-NodeProbe ($syntax.Process.WaitForExit(5000) -and $syntax.Process.ExitCode -eq 0) 'Pinned Mihomo accepts the WebSocket TLS route sent through stdin'
    }finally{
        try{Stop-GuardNodeProbeChild $syntax}finally{$relayPin.Dispose()}
    }
    $good=Invoke-IsolatedNodeCase success
    Assert-NodeProbe ($good.Passed -and $good.State -ceq 'Completed' -and $good.ExitIpv4 -ceq '203.0.113.51' -and
        $good.Provider -ceq 'CloudflareTrace' -and $good.CountryCode -ceq 'JP' -and
        $good.ProfileFingerprint -ceq $profileRoute.ProfileFingerprint) 'One verified Cloudflare request returns its IPv4 and JP'
    $default=Invoke-IsolatedNodeCase success -DefaultObserver
    Assert-NodeProbe ($default.Ok -and $default.Ipv4 -ceq '203.0.113.51' -and
        -not $default.PSObject.Properties['CountryCode']) 'With its default input and one request, the ordinary observer keeps its old output shape'
    foreach($countryCase in 'no-loc','duplicate-loc','invalid-loc'){
        $countryResult=Invoke-IsolatedNodeCase $countryCase
        Assert-NodeProbe ($countryResult.Passed -and $countryResult.ExitIpv4 -ceq '203.0.113.51' -and -not $countryResult.CountryCode) `
            "One verified Cloudflare request returns the IPv4 without country for $countryCase"
    }
    $backup=Invoke-IsolatedNodeCase fallback
    Assert-NodeProbe ($backup.Passed -and $backup.Provider -ceq 'Ipify' -and $backup.ExitIpv4 -ceq '203.0.113.52' -and -not $backup.CountryCode) `
        'The ordinary two-request failover returns the backup IPv4 without a country'
    $invalid=Invoke-IsolatedNodeCase invalid
    Assert-NodeProbe (-not $invalid.Passed -and $invalid.State -ceq 'Failed' -and $invalid.ErrorCode -ceq 'ProbeExitUnverified' -and
        -not $invalid.ExitIpv4) 'An invalid HTTPS response produces no IPv4 and releases its listener and work directory'
    $cancelled=Invoke-IsolatedNodeCase hold 3000
    Assert-NodeProbe (-not $cancelled.Passed -and $cancelled.State -ceq 'Cancelled' -and $cancelled.ErrorCode -ceq 'ProbeCancelled' -and
        -not $cancelled.ExitIpv4) 'Cancellation during an actual isolated request stops both probe processes and clears scratch state'
    $untrusted=Invoke-IsolatedNodeCase 'untrusted-ws'
    Assert-NodeProbe (-not $untrusted.Passed -and $untrusted.ErrorCode -ceq 'ProbeExitUnverified' -and -not $untrusted.ExitIpv4) `
        'Live WebSocket TLS uses the pinned synthetic upstream and SNI, and rejects its untrusted certificate'
    $trustedWss=Invoke-IsolatedNodeCase 'trusted-wss'
    Assert-NodeProbe ($trustedWss.Passed -and $trustedWss.ExitIpv4 -ceq '203.0.113.51' -and $trustedWss.Provider -ceq 'CloudflareTrace' -and
        $trustedWss.CountryCode -ceq 'JP') 'Live VLESS over WebSocket checks SNI, Host, path and both TLS layers and returns one verified JP response'
    $missingCaWss=Invoke-IsolatedNodeCase 'missing-ca-wss'
    Assert-NodeProbe (-not $missingCaWss.Passed -and $missingCaWss.ErrorCode -ceq 'ProbeExitUnverified' -and -not $missingCaWss.ExitIpv4) `
        'The identical WebSocket endpoint fails before Upgrade when the Mihomo child does not trust the fixture certificate'
    $badAssets=$assets.Clone()
    $badAssets.RelaySha256='A'*64
    $blocked=Invoke-GuardNodeProbe -Profile $profile -Assets $badAssets
    Assert-NodeProbe (-not $blocked.Passed -and $blocked.ErrorCode -ceq 'ProbeAssetsUnverified') 'An unapproved asset hash prevents launching the candidate'
}finally{
    $directory=Get-Item -LiteralPath $tempPath -Force
    if($directory.Parent.FullName.TrimEnd('\') -ine $tempBase -or $directory.Name -cnotmatch '^guard-node-tests-[a-f0-9]{32}$' -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected fixture cleanup directory.'}
    [IO.Directory]::Delete($directory.FullName,$true)
}
