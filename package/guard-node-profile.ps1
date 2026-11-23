#Requires -Version 5.1

. "$PSScriptRoot\guard-daily.ps1"
. "$PSScriptRoot\guard-daily-plan.ps1"

function ConvertFrom-GuardNodeLink([string]$Text) {
    if([string]::IsNullOrWhiteSpace($Text) -or $Text.Length -gt 4096){throw 'Paste one VLESS link of at most 4096 characters.'}
    $text=$Text.Trim()
    if($text.Length -gt 8 -and $text.IndexOf('://',8,[StringComparison]::Ordinal) -ge 0){throw 'Paste only one VLESS link.'}
    $link=[regex]::Match($text,'\Avless://(?<id>[0-9a-fA-F-]{36})@(?<address>[0-9.]{7,15}):(?<port>[0-9]{1,5})\?(?<query>[^#\s]+)(?:#[^\r\n\x00-\x1f]*)?\z')
    if(-not $link.Success){throw 'Use one VLESS link with a literal IPv4 server, port and query parameters.'}
    $parameters=@{}
    foreach($part in $link.Groups['query'].Value.Split('&')){
        $pair=$part.Split('=',2)
        if($pair.Count -ne 2 -or $pair[0] -cnotin 'type','security','pbk','sni','fp','sid','flow','encryption','host','path' -or
            $parameters.ContainsKey($pair[0]) -or $pair[1] -match '%(?![0-9a-fA-F]{2})'){
            throw 'The VLESS link contains an unsupported, repeated or malformed parameter.'
        }
        $parameters[$pair[0]]=[uri]::UnescapeDataString($pair[1])
    }
    if($parameters.ContainsKey('encryption') -and $parameters.encryption -cne 'none'){
        throw 'VLESS encryption must be none if present.'
    }
    $fields=@{
        ServerIpv4=$link.Groups['address'].Value;ServerPort=$link.Groups['port'].Value;Uuid=$link.Groups['id'].Value
        ServerName=$parameters.sni
    }
    if($parameters.ContainsKey('fp')){$fields.ClientFingerprint=$parameters.fp}
    if($parameters.type -ceq 'tcp' -and $parameters.security -ceq 'reality'){
        if($parameters.ContainsKey('host') -or $parameters.ContainsKey('path')){throw 'Reality TCP cannot include WebSocket settings.'}
        $fields.RealityPublicKey=$parameters.pbk
        $fields.RealityShortId=$parameters.sid
        $fields.Flow=$parameters.flow
    }elseif($parameters.type -ceq 'ws' -and $parameters.security -ceq 'tls'){
        if($parameters.ContainsKey('pbk') -or $parameters.ContainsKey('sid') -or $parameters.ContainsKey('flow')){
            throw 'WebSocket TLS cannot include Reality or XTLS flow settings.'
        }
        $fields.Transport='WebSocketTls'
        $fields.WebSocketHost=$parameters.host
        $fields.WebSocketPath=$parameters.path
    }else{throw 'Use VLESS TCP with Reality or VLESS WebSocket with verified TLS.'}
    $fields
}

function ConvertTo-GuardNodeFields([System.Collections.IDictionary]$Fields) {
    if(-not $Fields){throw 'Enter one explicit VLESS node.'}
    $transport=if($Fields.Contains('Transport')){$Fields.Transport}else{'RealityTcp'}
    if($transport -isnot [string] -or $transport -cnotin 'RealityTcp','WebSocketTls'){throw 'Choose RealityTcp or WebSocketTls.'}
    $required=@('ServerIpv4','ServerPort','Uuid','ServerName')
    if($transport -ceq 'WebSocketTls'){
        $required+=@('WebSocketHost','WebSocketPath')
        $allowed=$required+@('Transport','ClientFingerprint')
    }else{
        $required+=@('ClientFingerprint','RealityPublicKey','RealityShortId')
        $allowed=$required+@('Transport','Flow')
    }
    if(@($Fields.Keys | Where-Object {$_ -cnotin $allowed}).Count){
        throw 'The node contains unsupported fields.'
    }
    foreach($field in $required){if(-not $Fields.Contains($field) -or $null -eq $Fields[$field]){throw "Enter $field explicitly."}}
    $server=$null
    if($Fields.ServerIpv4 -isnot [string] -or -not [ipaddress]::TryParse($Fields.ServerIpv4,[ref]$server) -or
        $server.AddressFamily -ne 'InterNetwork' -or $server.ToString() -cne $Fields.ServerIpv4 -or
        [ipaddress]::IsLoopback($server) -or $server.GetAddressBytes()[0] -eq 0 -or $server.GetAddressBytes()[0] -ge 224){
        throw 'Use a canonical unicast IPv4 server outside the local loopback range.'
    }
    $port=0
    if([string]$Fields.ServerPort -cnotmatch '^[0-9]{1,5}$' -or -not [int]::TryParse([string]$Fields.ServerPort,[ref]$port) -or
        $port -lt 1 -or $port -gt 65535){throw 'Enter a server port between 1 and 65535.'}
    $uuid=[guid]::Empty
    if($Fields.Uuid -isnot [string] -or -not [guid]::TryParseExact($Fields.Uuid,'D',[ref]$uuid) -or $uuid -eq [guid]::Empty){
        throw 'Enter a nonzero VLESS UUID in the standard hyphenated form.'
    }
    if($Fields.ServerName -isnot [string] -or $Fields.ServerName.Length -gt 253 -or
        $Fields.ServerName -cnotmatch '^[A-Za-z0-9.-]+$' -or [uri]::CheckHostName($Fields.ServerName) -ne [UriHostNameType]::Dns){
        throw 'Enter the Reality server name as an explicit DNS hostname.'
    }
    if($Fields.Contains('ClientFingerprint') -and
        ($Fields.ClientFingerprint -isnot [string] -or $Fields.ClientFingerprint -cnotmatch '^[a-z][a-z0-9-]{0,30}$')){
        throw 'Enter the client fingerprint used by the node.'
    }
    if($transport -ceq 'WebSocketTls'){
        $hostParts=[regex]::Match([string]$Fields.WebSocketHost,'\A(?<name>[A-Za-z0-9.-]{1,253})(?::(?<port>[0-9]{1,5}))?\z')
        $hostPort=0
        if($Fields.WebSocketHost -isnot [string] -or -not $hostParts.Success -or
            [uri]::CheckHostName($hostParts.Groups['name'].Value) -cnotin 'Dns','IPv4' -or
            ($hostParts.Groups['port'].Success -and (-not [int]::TryParse($hostParts.Groups['port'].Value,[ref]$hostPort) -or
            $hostPort -lt 1 -or $hostPort -gt 65535))){throw 'Enter a WebSocket Host name, with an optional port.'}
        if($Fields.WebSocketPath -isnot [string] -or $Fields.WebSocketPath.Length -gt 1024 -or
            $Fields.WebSocketPath -cnotmatch '\A/(?!/)[A-Za-z0-9._~!$&()*+,;=:@/?%\[\]-]*\z' -or
            $Fields.WebSocketPath -match '%(?![0-9A-Fa-f]{2})|%(?:0[0-9A-F]|1[0-9A-F]|7F)'){
            throw 'Enter a WebSocket path beginning with one slash and containing no controls or fragment.'
        }
        $clean=[ordered]@{
            Transport=$transport;ServerIpv4=$server.ToString();ServerPort=$port;Uuid=$uuid.ToString('D');ServerName=$Fields.ServerName
            WebSocketHost=$Fields.WebSocketHost;WebSocketPath=$Fields.WebSocketPath
        }
        if($Fields.Contains('ClientFingerprint')){$clean.ClientFingerprint=$Fields.ClientFingerprint}
        return $clean
    }
    if($Fields.RealityPublicKey -isnot [string] -or $Fields.RealityPublicKey -cnotmatch '^[A-Za-z0-9_-]{43}$'){
        throw 'Enter a 43-character base64url Reality public key.'
    }
    if($Fields.RealityShortId -isnot [string] -or $Fields.RealityShortId -cnotmatch '^(?:[0-9a-fA-F]{2}){0,8}$'){
        throw 'Enter the Reality short ID as zero to eight hexadecimal byte pairs.'
    }
    if($Fields.Flow -cnotin $null,'','xtls-rprx-vision'){throw 'Use an empty flow or xtls-rprx-vision.'}
    [ordered]@{
        ServerIpv4=$server.ToString();ServerPort=$port;Uuid=$uuid.ToString('D');ServerName=$Fields.ServerName
        ClientFingerprint=$Fields.ClientFingerprint;RealityPublicKey=$Fields.RealityPublicKey
        RealityShortId=$Fields.RealityShortId;Flow=[string]$Fields.Flow
    }
}

function New-GuardNodeProfile {
    [CmdletBinding(DefaultParameterSetName='Fields')]
    param(
        [Parameter(Mandatory,ParameterSetName='Fields')][System.Collections.IDictionary]$Fields,
        [Parameter(Mandatory,ParameterSetName='Text')][string]$Text
    )
    if($PSCmdlet.ParameterSetName -eq 'Text'){$Fields=ConvertFrom-GuardNodeLink $Text}
    $canonical=(ConvertTo-GuardNodeFields $Fields) | ConvertTo-Json -Depth 3 -Compress
    [pscredential]::new('GuardNodeProfile',(ConvertTo-SecureString -String $canonical -AsPlainText -Force))
}

function Get-GuardNodeTextHash([string]$Text) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','')}
    finally{$sha.Dispose()}
}

function Get-GuardNodeProfileMaterial([pscredential]$Profile) {
    if(-not $Profile -or $Profile.UserName -cne 'GuardNodeProfile' -or $Profile.Password.Length -gt 4096){
        throw 'Use a locally validated node profile.'
    }
    $canonical=$Profile.GetNetworkCredential().Password
    try{
        $inputFields=ConvertFrom-Json -InputObject $canonical -ErrorAction Stop
        $fields=@{}
        foreach($property in $inputFields.PSObject.Properties){$fields.Add($property.Name,$property.Value)}
        $clean=ConvertTo-GuardNodeFields $fields
        if(($clean | ConvertTo-Json -Depth 3 -Compress) -cne $canonical){throw 'Invalid node data.'}
    }catch{throw 'The selected node profile is invalid. Enter or paste the node again.'}
    $node=if($clean.Transport -ceq 'WebSocketTls'){
        $webSocket=[ordered]@{name='guard-pinned';type='vless';network='ws';server=$clean.ServerIpv4;port=$clean.ServerPort
            uuid=$clean.Uuid;tls=$true;servername=$clean.ServerName;udp=$false;'skip-cert-verify'=$false
            'ws-opts'=[ordered]@{path=$clean.WebSocketPath;headers=[ordered]@{Host=$clean.WebSocketHost}}}
        if($clean.ClientFingerprint){$webSocket['client-fingerprint']=$clean.ClientFingerprint}
        $webSocket
    }else{
        [ordered]@{type='vless';network='tcp';tls=$true;server=$clean.ServerIpv4;port=$clean.ServerPort
            uuid=$clean.Uuid;servername=$clean.ServerName;'client-fingerprint'=$clean.ClientFingerprint;flow=$clean.Flow
            'reality-opts'=[ordered]@{'public-key'=$clean.RealityPublicKey;'short-id'=$clean.RealityShortId}}
    }
    [pscustomobject]@{Node=$node;ProfileFingerprint=(Get-GuardNodeTextHash $canonical)}
}

# This method exposes the explicit route only to the administrator transaction that needs it.
function Get-GuardNodeProfileRoute([pscredential]$Profile,[int]$Port) {
    $material=Get-GuardNodeProfileMaterial $Profile
    $config=if($material.Node.network -ceq 'ws'){
        if($Port -lt 1024 -or $Port -gt 49151){throw 'The isolated listener port is outside the supported range.'}
        [ordered]@{
            'mixed-port'=$Port;'allow-lan'=$false;'bind-address'='127.0.0.1';mode='rule';ipv6=$false
            'find-process-mode'='off';'log-level'='silent'
            tun=@{enable=$false};dns=@{enable=$false}
            proxies=@($material.Node);rules=@('MATCH,guard-pinned')
        }
    }else{New-GuardDedicatedProxyConfig $material.Node $Port}
    $config['geo-auto-update']=$false
    $json=$config | ConvertTo-Json -Depth 8 -Compress
    [pscustomobject]@{Json=$json;Hash=(Get-GuardNodeTextHash $json);Upstream=$config.proxies[0];ProfileFingerprint=$material.ProfileFingerprint}
}

function Get-GuardNodeProbePort {
    for($attempt=0;$attempt -lt 24;$attempt++){
        $port=Get-Random -Minimum 20000 -Maximum 49152
        $reservation=[Net.Sockets.TcpListener]::new([ipaddress]::Loopback,$port)
        try{
            $reservation.ExclusiveAddressUse=$true
            $reservation.Start()
            return $port
        }catch [Net.Sockets.SocketException]{}finally{$reservation.Stop()}
    }
    throw 'A separate loopback port was not available.'
}

function Open-GuardNodeProbeAsset([string]$Path,[string]$ExpectedHash) {
    if($ExpectedHash -cnotmatch '^[A-F0-9]{64}$' -or $Path -notmatch '\A[A-Za-z]:\\' -or
        [IO.Path]::GetFullPath($Path) -ine $Path){throw 'Invalid probe asset pin.'}
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid probe asset path.'}
    $parent=$item.Directory
    while($parent){
        if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'A probe asset directory is redirected.'}
        $parent=$parent.Parent
    }
    $stream=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if((Get-FileHash -InputStream $stream -Algorithm SHA256 -ErrorAction Stop).Hash -cne $ExpectedHash){
            throw 'The selected probe asset does not match its approved hash.'
        }
        $stream
    }catch{$stream.Dispose();throw}
}

function Stop-GuardNodeProbeChild($Child) {
    if(-not $Child){return}
    try{
        if(-not $Child.Process.HasExited){
            try{$Child.Process.Kill()}catch{if(-not $Child.Process.HasExited){throw}}
        }
        if(-not $Child.Process.WaitForExit(2500)){throw 'An isolated probe process did not exit.'}
    }finally{$Child.Process.Dispose()}
}

function Invoke-GuardNodeProbeRuntime($Route,$Assets,[int]$Port,[Threading.CancellationToken]$CancellationToken,[bool]$BackupExitLookup) {
    $result=[ordered]@{Passed=$false;State='Failed';ErrorCode='ProbeAssetsUnverified';ExitIpv4=$null;Provider=$null
        CheckedUtc=$null;ProfileFingerprint=$Route.ProfileFingerprint;CountryCode=$null}
    $assetLocks=@()
    $observer=$null
    $relay=$null
    $work=$null
    $base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    try{
        $CancellationToken.ThrowIfCancellationRequested()
        $assetLocks+=,(Open-GuardNodeProbeAsset $Assets.RelayPath $Assets.RelaySha256)
        $assetLocks+=,(Open-GuardNodeProbeAsset $Assets.ObserverPath $Assets.ObserverSha256)
        $assetLocks+=,(Open-GuardNodeProbeAsset $Assets.ObserverScriptPath $Assets.ObserverScriptSha256)
        $result.ErrorCode='ProbeRelayUnavailable'
        $config=$Route.Json | ConvertFrom-Json
        $random=[byte[]]::new(24)
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try{$rng.GetBytes($random)}finally{$rng.Dispose()}
        $credential='guardprobe:'+([BitConverter]::ToString($random).Replace('-','').ToLowerInvariant())
        $authorization=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($credential))
        $config | Add-Member -NotePropertyName authentication -NotePropertyValue @($credential)
        $config | Add-Member -NotePropertyName profile -NotePropertyValue @{'store-selected'=$false;'store-fake-ip'=$false}
        $work=Join-Path $base ('guard-node-probe-'+[guid]::NewGuid().ToString('N'))
        if([IO.Directory]::Exists($work)){throw 'The probe work directory already exists.'}
        $null=[IO.Directory]::CreateDirectory($work)
        $CancellationToken.ThrowIfCancellationRequested()
        $relay=Start-GuardDailyChild $Assets.RelayPath ('-d "'+$work+'" -f -') ($config | ConvertTo-Json -Depth 8 -Compress)
        $clock=[Diagnostics.Stopwatch]::StartNew()
        while(-not (Test-GuardDailyRelayListener $Port $relay.Process.Id)){
            $CancellationToken.ThrowIfCancellationRequested()
            if($relay.Process.HasExited -or $clock.ElapsedMilliseconds -ge 7000){throw 'The isolated relay did not start.'}
            $null=$CancellationToken.WaitHandle.WaitOne(80)
        }
        $result.ErrorCode='ProbeExitUnverified'
        $CancellationToken.ThrowIfCancellationRequested()
        $identity=@{RouteHash=$Route.Hash;ProcessId=$relay.Process.Id;StartedUtc=$relay.Process.StartTime.ToUniversalTime().ToString('o')}
        $deadline=if($BackupExitLookup){14000}else{7500}
        $observer=Start-GuardDailyChild $Assets.ObserverPath ('--use-bundled-ca "'+$Assets.ObserverScriptPath+'"') (
            @{port=$Port;authorization=$authorization;backupExitLookup=$BackupExitLookup;deadlineMs=$deadline;includeCountry=$true} | ConvertTo-Json -Compress)
        $clock.Restart()
        while(-not $observer.Process.HasExited -or -not $observer.Output.IsCompleted){
            $CancellationToken.ThrowIfCancellationRequested()
            if($clock.ElapsedMilliseconds -ge ($deadline+1000)){$result.ErrorCode='ProbeTimedOut';throw 'The isolated exit check timed out.'}
            $null=$CancellationToken.WaitHandle.WaitOne(80)
        }
        $CancellationToken.ThrowIfCancellationRequested()
        $sample=Read-GuardDailyObservationWorker $observer $identity $Route.ProfileFingerprint -BackupExitLookup:$BackupExitLookup
        if(-not $sample.Proof -or $relay.Process.HasExited -or
            $relay.Process.StartTime.ToUniversalTime().ToString('o') -cne $identity.StartedUtc -or
            -not (Test-GuardDailyRelayListener $Port $relay.Process.Id)){throw 'The isolated exit check could not verify the route.'}
        $result.Passed=$true
        $result.State='Completed'
        $result.ErrorCode=$null
        $result.ExitIpv4=$sample.Proof.Ipv4
        $result.Provider=$sample.Proof.Provider
        $result.CheckedUtc=$sample.Proof.CheckedUtc
        if($sample.Proof.Provider -ceq 'CloudflareTrace'){
            try{
                $details=ConvertFrom-Json -InputObject ($observer.Output.GetAwaiter().GetResult()) -ErrorAction Stop
                if($details.Provider -ceq $sample.Proof.Provider -and $details.Ipv4 -ceq $sample.Proof.Ipv4 -and
                    $details.CountryCode -is [string] -and $details.CountryCode -cmatch '\A[A-Z]{2}\z'){
                    $result.CountryCode=$details.CountryCode
                }
            }catch{}
        }
    }catch [OperationCanceledException]{
        $result.State='Cancelled'
        $result.ErrorCode='ProbeCancelled'
    }catch{
        # A worker/config parser may put credentials in its own errors. Never forward that output.
    }finally{
        $clean=$true
        try{Stop-GuardNodeProbeChild $observer}catch{$clean=$false}
        try{Stop-GuardNodeProbeChild $relay}catch{$clean=$false}
        foreach($assetLock in $assetLocks){if($assetLock){$assetLock.Dispose()}}
        if($work -and [IO.Directory]::Exists($work)){
            try{
                $directory=Get-Item -LiteralPath $work -Force -ErrorAction Stop
                if($directory.Parent.FullName.TrimEnd('\') -ine $base -or $directory.Name -cnotmatch '^guard-node-probe-[a-f0-9]{32}$' -or
                    ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected probe cleanup directory.'}
                [IO.Directory]::Delete($directory.FullName,$true)
            }catch{$clean=$false}
        }
        if(-not $clean){
            $result.Passed=$false;$result.State='Failed';$result.ErrorCode='ProbeCleanupFailed'
            $result.ExitIpv4=$null;$result.Provider=$null;$result.CheckedUtc=$null;$result.CountryCode=$null
        }
    }
    [pscustomobject]$result
}

function Invoke-GuardNodeProbe {
    param(
        [Parameter(Mandatory)][pscredential]$Profile,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Assets,
        [Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None,
        [switch]$BackupExitLookup
    )
    if($CancellationToken.IsCancellationRequested){
        return [pscustomobject]@{Passed=$false;State='Cancelled';ErrorCode='ProbeCancelled';ExitIpv4=$null;Provider=$null
            CheckedUtc=$null;ProfileFingerprint=$null;CountryCode=$null}
    }
    $port=Get-GuardNodeProbePort
    $route=Get-GuardNodeProfileRoute $Profile $port
    Invoke-GuardNodeProbeRuntime $route $Assets $port $CancellationToken ([bool]$BackupExitLookup)
}
