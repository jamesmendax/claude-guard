#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$MihomoPath,
    [string]$NodePath=(Get-Command node.exe -CommandType Application -ErrorAction Stop).Source
)

$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-daily.ps1"
. "$PSScriptRoot\..\package\guard-daily-plan.ps1"

if((Get-FileHash -LiteralPath $MihomoPath -Algorithm SHA256).Hash -cne 'CF894375DBC00AB6708C1314AC35BBD29059F4C37F315353AACA7F1A9C566DE6'){
    throw 'This relay evidence test requires the exact pinned Mihomo release.'
}
$MihomoPath=(Resolve-Path -LiteralPath $MihomoPath).ProviderPath
$node=(Resolve-Path -LiteralPath $NodePath).ProviderPath
$probe=Join-Path $PSScriptRoot 'cloudflare-exit-probe.mjs'
$generation='A'*64
$routeHash='B'*64
$base=(Get-Item -LiteralPath ([IO.Path]::GetTempPath())).FullName.TrimEnd('\')
$workingDirectory=(New-Item -ItemType Directory -Path (Join-Path $base ('guard-relay-evidence-'+[guid]::NewGuid().ToString('N')))).FullName

function Assert-RelayEvidence([bool]$Condition,[string]$Message){
    if(-not $Condition){throw "FAIL: $Message"}
    "PASS: $Message"
}

function Open-TestListener([int]$Port){
    $server=[Net.Sockets.TcpListener]::new([ipaddress]::Loopback,$Port)
    $server.ExclusiveAddressUse=$true
    $server.Start()
    $server
}

function Find-TestProxyPort {
    # The observer accepts only nonprivileged ports below 49152.
    for($i=0;$i -lt 30;$i++){
        try{$reservation=Open-TestListener (Get-Random -Minimum 19000 -Maximum 41000)}
        catch{continue}
        try{return $reservation.LocalEndpoint.Port}finally{$reservation.Stop()}
    }
    throw 'Could not reserve a synthetic relay listener.'
}

function Start-SyntheticRelay([int]$ProxyPort,[int]$UpstreamPort){
    # The VLESS stub is always loopback and never contacts the requested domain.
    $config=[ordered]@{
        'mixed-port'=$ProxyPort;'allow-lan'=$false;'bind-address'='127.0.0.1';mode='rule';ipv6=$false
        'find-process-mode'='off';'geo-auto-update'=$false;'log-level'='info'
        tun=@{enable=$false};dns=@{enable=$false}
        proxies=@(@{name='guard-pinned';type='vless';network='tcp';server='127.0.0.1';port=$UpstreamPort
            uuid='00000000-0000-4000-8000-000000000009';tls=$false;udp=$false})
        rules=@('MATCH,guard-pinned')
    }
    Start-GuardDailyChild $MihomoPath ('-d "'+$workingDirectory+'" -f -') ($config | ConvertTo-Json -Depth 8 -Compress) `
        -MonitorUpstreamEndpoint "127.0.0.1:$UpstreamPort"
}

function Wait-SyntheticRelay($Child,[int]$Port){
    $until=[datetime]::UtcNow.AddSeconds($script:GuardDailyMaxLeaseSeconds)
    while(-not (Test-GuardDailyRelayListener $Port $Child.Process.Id)){
        if($Child.Process.HasExited -or [datetime]::UtcNow -ge $until){throw 'The synthetic Mihomo listener did not start.'}
        Start-Sleep -Milliseconds 100
    }
}

function Invoke-PinnedRelayTest([bool]$AcceptFirstHop){
    $upstream=Open-TestListener 0
    $upstreamPort=$upstream.LocalEndpoint.Port
    $port=Find-TestProxyPort
    $relayChild=$null
    $worker=$null
    $accepted=$null
    try{
        if($AcceptFirstHop){$pending=$upstream.AcceptTcpClientAsync()}else{$upstream.Stop()}
        $relayChild=Start-SyntheticRelay $port $upstreamPort
        $relay=[pscustomobject]@{
            Ready=$true;ProcessId=$relayChild.Process.Id;Port=$port;RouteHash=$routeHash
            StartedUtc=$relayChild.Process.StartTime.ToUniversalTime().ToString('o')
        }
        Wait-SyntheticRelay $relayChild $port
        $worker=Start-GuardDailyChild $node ('--use-bundled-ca "'+$probe+'" --protected-listener') (
            @{port=$port;backupExitLookup=$true} | ConvertTo-Json -Compress)
        if($AcceptFirstHop){
            if(-not $pending.Wait(5000)){throw 'The synthetic upstream did not receive the pinned connection.'}
            $accepted=$pending.GetAwaiter().GetResult()
            $stream=$accepted.GetStream()
            # Let Mihomo write the VLESS request before this test-only receiver
            # returns a VLESS header and non-TLS payload. No external HTTPS runs.
            $buffer=New-Object byte[] 4096
            $stream.ReadTimeout=5000
            if($stream.Read($buffer,0,$buffer.Length) -lt 1){throw 'The fixture did not receive a VLESS request.'}
            $response=[byte[]]@(0,0,71,85,65,82,68)
            $stream.Write($response,0,$response.Length)
            $stream.Flush()
            $accepted.Dispose()
            $accepted=$null
        }
        if(-not $worker.Process.WaitForExit(16000)){throw 'The synthetic relay observer did not exit.'}
        if(-not $worker.Output.Wait(1000)){throw 'The observer did not emit its receipt.'}
        $raw=$worker.Output.GetAwaiter().GetResult()
        $data=if($PSVersionTable.PSVersion -ge [version]'7.5'){
            ConvertFrom-Json -InputObject $raw -DateKind String
        }elseif($PSVersionTable.PSEdition -eq 'Core'){
            $settings=[Newtonsoft.Json.JsonSerializerSettings]::new()
            $settings.DateParseHandling=[Newtonsoft.Json.DateParseHandling]::None
            [Newtonsoft.Json.JsonConvert]::DeserializeObject($raw,[Collections.Generic.Dictionary[string,object]],$settings)
        }else{
            $raw | ConvertFrom-Json
        }
        Assert-RelayEvidence ($data.Stage -ceq 'TLS' -and $data.QueryIssued -eq $false -and $data.SourcePort -gt 0) 'observer stayed inside the synthetic tunnel and reported its loopback port'
        $after=$worker.Process.ExitTime.ToUniversalTime()
        $before=([datetimeoffset]::Parse($data.ConnectedUtc)).UtcDateTime
        $kind=$relayChild.RelayEvidence.ReadAttempt([int]$data.SourcePort,$before,$after).ToString()
        $sample=Read-GuardDailyObservationWorker $worker $relay $generation -RelayEvidence $relayChild.RelayEvidence
        Assert-RelayEvidence ($sample.Finished -and -not $sample.Proof -and -not $relayChild.Process.HasExited) 'synthetic upstream result arrived while its local relay was still listening'
        if($AcceptFirstHop){
            Assert-RelayEvidence ($kind -ceq 'SetupReached' -and -not $sample.Failure) 'an actual pinned first-hop success followed by endpoint failure does not trigger shutdown'
        }else{
            Assert-RelayEvidence ($data.Outcome -ceq 'PeerClosedBeforeTls' -and $kind -ceq 'FirstHopDown') 'the pinned Mihomo exhausted its own exact first-hop dials before closing the observer'
            Assert-RelayEvidence ($sample.Failure.Fault -ceq 'UpstreamTransportDown' -and
                $sample.Failure.Generation -ceq $generation -and $sample.Failure.RouteHash -ceq $routeHash -and
                $sample.Failure.RelayId -eq $relay.ProcessId -and $sample.Failure.RelayStartedUtc -ceq $relay.StartedUtc) 'the hard failure is bound to the approved relay and observation'
            $relay.ProcessId++
            $other=Read-GuardDailyObservationWorker $worker $relay $generation -RelayEvidence $relayChild.RelayEvidence
            Assert-RelayEvidence (-not $other.Failure) 'evidence from any other relay identity is rejected'
        }
    }finally{
        if($accepted){$accepted.Dispose()}
        $upstream.Stop()
        Stop-GuardDailyChild $worker
        Stop-GuardDailyChild $relayChild
    }
}

function Test-ProviderCorrelation {
    $shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $fixture=@'
$start=[datetime]::UtcNow
for($i=0;$i -le 10;$i++){
    $stamp=$start.AddTicks($i).ToString('o')
    if($i -eq 0){
        'time="{0}" level=info msg="[TCP] 127.0.0.1:30000 --> 1.1.1.1:443 match Match using guard-pinned"' -f $stamp
    }else{
        'time="{0}" level=warning msg="[TCP] dial guard-pinned (match Match/) 127.0.0.1:30000 --> api.ipify.org:443 error: 127.0.0.1:30111 connect error: dial tcp 127.0.0.1:30111: connection refused"' -f $stamp
    }
}
'@
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($fixture))
    $child=Start-GuardDailyChild $shell ('-NoProfile -NonInteractive -EncodedCommand '+$encoded) '' -MonitorUpstreamEndpoint '127.0.0.1:30111'
    try{
        if(-not $child.Process.WaitForExit(4000)){throw 'The local relay log fixture did not end.'}
        $child.Process.WaitForExit()
        $finished=$child.Process.ExitTime.ToUniversalTime()
        $begin=$child.RelayEvidence.StartedUtc
        Assert-RelayEvidence ($child.RelayEvidence.ReadAttempt(30000,$begin,$finished,'api.ipify.org:443').ToString() -ceq 'FirstHopDown') `
            'the backup destination retains its separately correlated first-hop evidence'
        Assert-RelayEvidence ($child.RelayEvidence.ReadAttempt(30000,$begin,$finished,'1.1.1.1:443').ToString() -ceq 'SetupReached') `
            'backup dial failures cannot be attributed to the primary destination on the same port'
        Assert-RelayEvidence ($child.RelayEvidence.ReadAttempt(30000,$begin,$finished,'unknown.example:443').ToString() -ceq 'Unconfirmed') `
            'an unknown destination cannot confirm a transport failure'
    }finally{Stop-GuardDailyChild $child}
}

function Read-LocalVlessBytes($Stream,[int]$Count){
    $buffer=[byte[]]::new($Count)
    $read=0
    while($read -lt $Count){
        $part=$Stream.Read($buffer,$read,$Count-$read)
        if($part -le 0){throw 'The local VLESS fixture received a truncated header.'}
        $read+=$part
    }
    ,$buffer
}

function Test-PinnedRelayForwardsBackupDomain {
    $upstream=Open-TestListener 0
    $client=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $accepted=$null
    $relay=$null
    try{
        $pending=$upstream.AcceptTcpClientAsync()
        $port=Find-TestProxyPort
        $relay=Start-SyntheticRelay $port $upstream.LocalEndpoint.Port
        Wait-SyntheticRelay $relay $port
        if(-not $client.ConnectAsync([Net.IPAddress]::Loopback,$port).Wait(3000)){throw 'The offline client could not reach its relay.'}
        $stream=$client.GetStream()
        $stream.ReadTimeout=3000
        $request=[Text.Encoding]::ASCII.GetBytes("CONNECT api.ipify.org:443 HTTP/1.1`r`nHost: api.ipify.org:443`r`n`r`n")
        $stream.Write($request,0,$request.Length)
        $response=[Text.StringBuilder]::new()
        do{
            $next=$stream.ReadByte()
            if($next -lt 0 -or $response.Length -ge 1024){throw 'The local relay did not return a bounded CONNECT receipt.'}
            $null=$response.Append([char]$next)
        }while(-not $response.ToString().EndsWith("`r`n`r`n",[StringComparison]::Ordinal))
        if($response.ToString() -cnotmatch '^HTTP/1\.1 200 '){throw 'The local relay rejected the backup CONNECT.'}
        $stream.WriteByte(0x16)
        if(-not $pending.Wait(5000)){throw 'The fixed synthetic upstream received no VLESS connection.'}
        $accepted=$pending.GetAwaiter().GetResult()
        $remote=$accepted.GetStream()
        $remote.ReadTimeout=5000
        $header=Read-LocalVlessBytes $remote 23
        Assert-RelayEvidence ($header[0] -eq 0 -and $header[17] -eq 0 -and $header[18] -eq 1 -and
            $header[19] -eq 1 -and $header[20] -eq 187 -and $header[21] -eq 2 -and $header[22] -eq 13) `
            'the actual pinned VLESS relay requested a domain on TCP port 443'
        $hostBytes=Read-LocalVlessBytes $remote $header[22]
        Assert-RelayEvidence ([Text.Encoding]::ASCII.GetString($hostBytes) -ceq 'api.ipify.org') `
            'the fixed upstream received the unresolved backup domain, with no second upstream'
    }finally{
        if($accepted){$accepted.Dispose()}
        $client.Dispose()
        $upstream.Stop()
        Stop-GuardDailyChild $relay
    }
}

try{
    Invoke-PinnedRelayTest $false
    Invoke-PinnedRelayTest $true
    Test-ProviderCorrelation
    Test-PinnedRelayForwardsBackupDomain
}finally{
    $resolved=(Get-Item -LiteralPath $workingDirectory -Force).FullName
    if((Split-Path -Parent $resolved) -ine $base -or (Split-Path -Leaf $resolved) -notmatch '^guard-relay-evidence-[a-f0-9]{32}$'){
        throw 'The synthetic relay scratch path changed.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
