# Shared by the daily policy preparer, supervisor and deployment.
function Read-GuardDailyRelayConfig([int]$Port) {
    $profileModule=Join-Path $PSScriptRoot 'guard-profile-store.ps1'
    if([IO.File]::Exists($profileModule)){
        . $profileModule
        $saved=Read-GuardSavedNodeRoute -Port $Port
        if($null -ne $saved){return $saved}
    }elseif([IO.Directory]::Exists((Get-GuardDataPath 'node-private'))){
        throw 'The manually selected node reader is missing.'
    }
    $folder=Join-Path $env:APPDATA 'com.appshub\Bettbox'
    $settings=Get-Content -LiteralPath (Join-Path $folder 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $profiles=@($settings.profiles | Where-Object id -CEQ $settings.currentProfileId)
    if($profiles.Count -ne 1 -or $profiles[0].id -cnotmatch '^[A-Za-z0-9_-]+$'){
        throw 'The current Bettbox selection could not be identified.'
    }
    $profile=Get-Content -LiteralPath (Join-Path $folder ('profiles\'+$profiles[0].id+'.yaml')) -Raw -Encoding UTF8
    $node=Read-GuardBettboxVlessNode $profile $profiles[0].selectedMap.GLOBAL
    $config=New-GuardDedicatedProxyConfig $node $Port
    $config['geo-auto-update']=$false
    $json=$config | ConvertTo-Json -Depth 8 -Compress
    $sha=[Security.Cryptography.SHA256]::Create()
    try{
        $hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))).Replace('-','')
        [pscustomobject]@{Hash=$hash;Json=$json;Upstream=$config.proxies[0]}
    }finally{$sha.Dispose()}
}

function New-GuardInstalledPolicy($Route,[int]$Port,[guid]$Deployment,$Inventory,[string]$ScopeSid,[string]$Containment) {
    $daily=Get-GuardDataPath 'daily'
    $relay=Join-Path $daily 'guard-dedicated-relay.exe'
    $observer=Join-Path $daily 'guard-exit-observer.exe'
    $programs=[string[]]$Inventory.Programs
    $desktops=[string[]]$Inventory.DesktopPaths
    $packages=[string[]]@($Inventory.Packages | ForEach-Object Sid)
    $services=[string[]]@(if($Inventory.PSObject.Properties['ServiceSids']){$Inventory.ServiceSids}else{Get-GuardDailyServiceSids})
    if($Containment -ceq 'Sandboxie'){
        $plan=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage($programs,$desktops,$packages,$services,
            $ScopeSid,$relay,[uint16]$Port,[string]$Route.Upstream.server,[uint16]$Route.Upstream.port,$observer)
    }else{
        $plan=[ClaudeGuard.Network.GuardPolicy]::CreateForAppContainer($programs,$desktops,$packages,$services,
            $ScopeSid,$relay,[uint16]$Port,[string]$Route.Upstream.server,[uint16]$Route.Upstream.port,$observer)
    }
    $plan.WithEarlyBootBlocks().ForPersistentUse($Deployment)
}

function Read-GuardDailyDesktopImages($Inventory) {
    foreach($path in @($Inventory.DesktopPaths)){
        [pscustomobject]@{Path=$path;Hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    }
}

function Confirm-GuardDailySandboxieApp($Record,$App) {
    if(-not $App){$App=Get-GuardSandboxieApp}
    if($app.PackageSid -cne $Record.ScopeSid -or $app.PackageFullName -cne $Record.PackageFullName -or
        $app.AppId -cne $Record.AppId -or $app.Root -ine $Record.PackageRoot -or
        $app.DesktopPath -ine $Record.DesktopPath){
        throw 'The registered Windows desktop package changed.'
    }
    $app
}

function Get-GuardDailyStoreVersion([string]$Package) {
    $match=[regex]::Match($Package,'\AAnthropicPBC\.Claude_(?<version>(?:[0-9]{1,5}\.){3}[0-9]{1,5})_x64__fnn82j28hfe8t\z')
    if(-not $match.Success){return}
    $value=$match.Groups['version'].Value
    $version=[version]$value
    if($version.ToString() -ceq $value -and -not @($value.Split('.') | Where-Object {[int]$_ -gt 65535}).Count){
        $version
    }
}

function Test-GuardDailyStoreUpgrade($Record,$App) {
    if($Record.Containment -cne 'Sandboxie' -or $Record.ScopeSid -cne $App.PackageSid -or $Record.AppId -cne $App.AppId){
        return $false
    }
    $old=Get-GuardDailyStoreVersion $Record.PackageFullName
    $new=Get-GuardDailyStoreVersion $App.PackageFullName
    $null -ne $old -and $null -ne $new -and $new -gt $old
}

function Get-GuardDailyRecordedInventory($Record,$Current,$App) {
    if($Record.PolicyInventory){return $Record.PolicyInventory}
    if(Get-Command Get-GuardStoreSavedInventory -CommandType Function -ErrorAction SilentlyContinue){
        $saved=Get-GuardStoreSavedInventory $Record
        if($saved){return $saved}
    }
    # The original installation stored rule keys but not the complete input list.
    # The caller compares every reconstructed policy key before using it.
    [pscustomobject]@{
        Programs=@($Current.Programs | ForEach-Object {$_.Replace($App.PackageFullName,$Record.PackageFullName)})
        DesktopPaths=@($Current.DesktopPaths | ForEach-Object {$_.Replace($App.PackageFullName,$Record.PackageFullName)})
        Packages=@($Current.Packages)
    }
}

function Test-GuardDailyPolicyBinding($Record,$Plan) {
    $Plan.PersistentSublayer -eq [guid]$Record.Sublayer -and
        ($Plan.GetBaselineKeys() -join ',') -ceq ($Record.BaselineKeys -join ',') -and
        ($Plan.GetBootKeys() -join ',') -ceq ($Record.BootKeys -join ',')
}

function Start-GuardDailyChild([string]$Image,[string]$Arguments,[string]$InputText,[string]$MonitorUpstreamEndpoint) {
    if($MonitorUpstreamEndpoint -and -not ('ClaudeGuard.Network.RelayEvidence' -as [type])){
        Add-Type -Path (Join-Path $PSScriptRoot 'guard-relay-evidence.cs') -ErrorAction Stop
    }
    $launch=[Diagnostics.ProcessStartInfo]::new($Image,$Arguments)
    $launch.UseShellExecute=$false
    $launch.CreateNoWindow=$true
    $launch.RedirectStandardInput=$true
    $launch.RedirectStandardOutput=$true
    $launch.RedirectStandardError=$true
    foreach($name in @($launch.EnvironmentVariables.Keys)){
        if($name -match '^(CLASH_|MIHOMO_|NODE_|SSL_CERT_)|^(HTTP|HTTPS|ALL|NO)_PROXY$|^OPENSSL_CONF$'){
            $launch.EnvironmentVariables.Remove($name)
        }
    }
    if($MonitorUpstreamEndpoint){$launch.EnvironmentVariables['CLICOLOR_FORCE']='0'}
    $process=[Diagnostics.Process]::Start($launch)
    try{
        $evidence=$null
        $output=$null
        $errorOutput=$null
        if($MonitorUpstreamEndpoint){
            $evidence=[ClaudeGuard.Network.RelayEvidence]::new($process,$MonitorUpstreamEndpoint)
            $process.BeginErrorReadLine()
        }else{
            $output=$process.StandardOutput.ReadToEndAsync()
            $errorOutput=$process.StandardError.ReadToEndAsync()
        }
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
        [pscustomobject]@{Process=$process;Output=$output;ErrorOutput=$errorOutput;RelayEvidence=$evidence}
    }catch{
        if(-not $process.HasExited){$process.Kill()}
        $process.Dispose()
        throw
    }
}

function Stop-GuardDailyChild($Child) {
    if(-not $Child){return}
    try{
        if(-not $Child.Process.HasExited){
            $Child.Process.Kill()
            $null=$Child.Process.WaitForExit(3000)
        }
    }finally{$Child.Process.Dispose()}
}

function Read-GuardDailyObservationWorker($Worker,$Relay,[string]$Generation,$RelayEvidence,[switch]$BackupExitLookup) {
    $process=$Worker.Process
    if(-not $process.HasExited -or -not $Worker.Output.IsCompleted){return}
    $result=@{Finished=$true;Proof=$null;Failure=$null}
    $seen=$process.ExitTime.ToUniversalTime()
    $started=$process.StartTime.ToUniversalTime()
    if($seen -lt $started -or ($seen-$started).TotalSeconds -gt $script:GuardDailyMaxLeaseSeconds){return $result}
    $raw=$Worker.Output.GetAwaiter().GetResult()
    if(-not $raw -or $raw.Length -gt 4096){return $result}
    $data=if($PSVersionTable.PSVersion -ge [version]'7.5'){
        ConvertFrom-Json -InputObject $raw -DateKind String
    }elseif($PSVersionTable.PSEdition -eq 'Core'){
        # The strict UTC receipt check needs the timestamp exactly as Node wrote it.
        $settings=[Newtonsoft.Json.JsonSerializerSettings]::new()
        $settings.DateParseHandling=[Newtonsoft.Json.DateParseHandling]::None
        [Newtonsoft.Json.JsonConvert]::DeserializeObject($raw,[Collections.Generic.Dictionary[string,object]],$settings)
    }else{
        $raw | ConvertFrom-Json
    }
    if($data.Provider -isnot [string] -or $data.Ok -isnot [bool] -or $data.QueryIssued -isnot [bool]){return $result}
    $destination=switch -CaseSensitive ($data.Provider){
        'CloudflareTrace'{'1.1.1.1:443'}
        'Ipify'{if($BackupExitLookup){'api.ipify.org:443'}}
    }
    if(-not $destination){return $result}
    $address=$null
    if($process.ExitCode -eq 0 -and $data.Ok -eq $true -and $data.QueryIssued -eq $true -and $data.HttpStatus -eq 200 -and
        $data.Stage -ceq 'Trace' -and [ipaddress]::TryParse([string]$data.Ipv4,[ref]$address) -and
        $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $address.ToString() -ceq $data.Ipv4){
        $result.Proof=[pscustomobject]@{
            Generation=$Generation;RouteHash=$Relay.RouteHash;RelayId=$Relay.ProcessId
            RelayStartedUtc=$Relay.StartedUtc;Ipv4=$data.Ipv4;HttpStatus=$data.HttpStatus
            CheckedUtc=$seen.ToString('o');Provider=$data.Provider
        }
        return $result
    }
    if($process.ExitCode -ne 1 -or $data.Ok -ne $false -or $data.QueryIssued -ne $false -or
        $data.Stage -cne 'TLS' -or $data.Outcome -cne 'PeerClosedBeforeTls' -or -not $RelayEvidence -or
        $RelayEvidence.ProcessId -ne $Relay.ProcessId -or $RelayEvidence.StartedUtc.ToString('o') -cne $Relay.StartedUtc){
        return $result
    }
    $sourcePort=0
    $connected=[datetimeoffset]::MinValue
    if(-not [int]::TryParse([string]$data.SourcePort,[ref]$sourcePort) -or
        -not [datetimeoffset]::TryParseExact([string]$data.ConnectedUtc,"yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal,[ref]$connected) -or
        $connected.UtcDateTime -lt $started -or $connected.UtcDateTime -gt $seen){
        return $result
    }
    if($RelayEvidence.ReadAttempt($sourcePort,$connected.UtcDateTime,$seen,[string]$destination).ToString() -ceq 'FirstHopDown'){
        $result.Failure=[pscustomobject]@{
            Fault='UpstreamTransportDown';Generation=$Generation;RouteHash=$Relay.RouteHash;RelayId=$Relay.ProcessId
            RelayStartedUtc=$Relay.StartedUtc;CheckedUtc=$seen.ToString('o')
        }
    }
    $result
}

function Test-GuardDailyRelayListener([int]$Port,[int]$OwnerId) {
    if($Port -lt 1 -or $Port -gt 65535 -or $OwnerId -le 0){return $false}
    try{
        if(-not ('ClaudeGuard.Network.RelayEvidence' -as [type])){
            Add-Type -Path (Join-Path $PSScriptRoot 'guard-relay-evidence.cs') -ErrorAction Stop
        }
        [ClaudeGuard.Network.RelayListener]::IsExclusiveLoopback($Port,$OwnerId)
    }catch{return $false}
}
