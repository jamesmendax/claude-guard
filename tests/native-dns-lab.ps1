#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,[object]$AppContainerScope)
$ErrorActionPreference='Stop'
$Directory=(Get-Item -LiteralPath $Directory -Force).FullName
$trusted=@('S-1-5-18','S-1-5-32-544')
$write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
$item=Get-Item -LiteralPath $Directory -Force
if(-not $item.PSIsContainer -or $Directory -notmatch '^[A-Za-z]:\\'){throw 'A protected local build directory is required.'}
while($item){
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'A working directory ancestor is a link.'}
    $item=$item.Parent
}
$acl=Get-Acl -LiteralPath $Directory
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
    @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $write) -and $_.IdentityReference.Value -notin $trusted
    }).Count){throw 'The build directory must be administrator controlled.'}
if($AppContainerScope -and $AppContainerScope.GetType().FullName -cne 'GuardFixtureAppContainer'){
    throw 'The DNS fixture requires a test-owned AppContainer scope.'
}
$id=[guid]::NewGuid().ToString('N')
$zone="g$id.test"
$names=@('before','blocked','after' | ForEach-Object {"$_.$zone"})
$tag="ClaudeGuardDns-$id"
$image=Join-Path $Directory ("native-dns-$id.exe")
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$wfp=Join-Path (Split-Path -Parent $PSScriptRoot) 'package\guard-wfp.cs'
& $compiler /nologo /warnaserror+ /platform:x64 /main:GuardNativeDnsFixture "/out:$image" $wfp `
    (Join-Path $PSScriptRoot 'native-dns-client.cs') (Join-Path $PSScriptRoot 'native-process-scope-client.cs')
if($LASTEXITCODE -ne 0){throw 'Native DNS fixture compilation failed.'}
$assembly=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes($image))
$fixture=$assembly.GetType('GuardNativeDnsFixture',$true)
$loop="127.$([Convert]::ToByte($id.Substring(0,2),16)).$([Convert]::ToByte($id.Substring(2,2),16)).$((([Convert]::ToByte($id.Substring(4,2),16)) % 254)+1)"
$existing=@(Get-DnsClientServerAddress | ForEach-Object ServerAddresses)
$existing+=@(Get-DnsClientNrptPolicy -Effective | ForEach-Object { @($_.NameServers)+@($_.DirectAccessDnsServers) })
if($loop -in $existing -or @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -eq 53 -and $_.LocalAddress -in @($loop,'0.0.0.0','::') }).Count){
    throw 'The proposed private DNS endpoint is in use.'
}
$dnsService=Get-CimInstance Win32_Service -Filter "Name='Dnscache'"
if($dnsService.State -ne 'Running'){throw 'The Windows DNS Client service is unavailable.'}
$socket=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
$policy=$null
$attempted=$false
$rows=@()
$lateBlockedIds=[Collections.Generic.HashSet[int]]::new()
function Confirm-DnsRoute([string]$Name){
    $effective=@(Get-DnsClientNrptPolicy -Effective -Namespace $Name)
    if($effective.Count -ne 1 -or $Name -notin @($effective[0].Namespace) -or
       @($effective[0].NameServers).Count -ne 1 -or @($effective[0].NameServers)[0] -ne $loop -or
       $effective[0].DirectAccessEnabled -eq $true){throw 'No exclusive effective local DNS route for the exact synthetic name.'}
}
function Invoke-DnsTrial([string]$Name,[switch]$Contained){
    Confirm-DnsRoute $Name
    $qname=[Collections.Generic.List[byte]]::new()
    foreach($label in $Name.Split('.')){$qname.Add([byte]$label.Length);$qname.AddRange([Text.Encoding]::ASCII.GetBytes($label))}
    $qname.AddRange([byte[]](0,0,1,0,1))
    $question=$qname.ToArray()
    $ids=[Collections.Generic.HashSet[int]]::new()
    $owner='Unknown'
    if($Contained){
        $child=$AppContainerScope.Start($image,($Name+'. '+$AppContainerScope.Identity.Value),$false)
    }else{
        $start=[Diagnostics.ProcessStartInfo]::new($image,($Name+'.'))
        $start.UseShellExecute=$false
        $start.CreateNoWindow=$true
        $child=[Diagnostics.Process]::Start($start)
    }
    try{
        $timer=[Diagnostics.Stopwatch]::StartNew()
        $finishedAt=$null
        while($timer.Elapsed.TotalSeconds -lt 18){
            if($socket.Available -eq 0){
                if($child.WaitForExit(0)){
                    if($null -eq $finishedAt){$finishedAt=$timer.ElapsedMilliseconds}
                    if($timer.ElapsedMilliseconds-$finishedAt -ge 500){break}
                }
                Start-Sleep -Milliseconds 15
                continue
            }
            $from=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
            $packet=$socket.Receive([ref]$from)
            if($Name -ceq $names[2] -and [Net.IPAddress]::IsLoopback($from.Address) -and $packet.Length -ge 64){
                $blockedWire=([char]7)+'blocked'+([char]33)+'g'+$id+([char]4)+'test'+([char]0)
                if([string]::Equals([Text.Encoding]::ASCII.GetString($packet,12,$blockedWire.Length),$blockedWire,
                        [StringComparison]::OrdinalIgnoreCase)){
                    $null=$lateBlockedIds.Add(($packet[0]*256 + $packet[1]))
                }
            }
            if(-not [Net.IPAddress]::IsLoopback($from.Address) -or $packet.Length -lt (12+$question.Length) -or
               ($packet[2] -band 128) -or $packet[4] -ne 0 -or $packet[5] -ne 1){continue}
            $actual=[Text.Encoding]::ASCII.GetString($packet,12,$question.Length)
            if(-not [string]::Equals($actual,[Text.Encoding]::ASCII.GetString($question),[StringComparison]::OrdinalIgnoreCase)){continue}
            $null=$ids.Add(($packet[0]*256 + $packet[1]))
            # Return a TTL-zero TEST-NET A record. Keep the original query case and ID.
            $reply=[byte[]](@($packet[0],$packet[1],129,128,0,1,0,1,0,0,0,0)+
                $packet[12..(11+$question.Length)]+@(192,12,0,1,0,1,0,0,0,0,0,4,192,0,2,53))
            $null=$socket.Send($reply,$reply.Length,$from)
            $owners=@(Get-NetUDPEndpoint -LocalPort $from.Port -ErrorAction SilentlyContinue |
                Where-Object LocalAddress -In @('0.0.0.0',$from.Address.ToString()) | ForEach-Object OwningProcess | Sort-Object -Unique)
            if($owners.Count -eq 1){
                if($owners[0] -eq $dnsService.ProcessId){$owner='DnsClientServiceHost'}
                elseif($owners[0] -eq $child.Id){$owner='TestClient'}
            }
        }
        $code=if($child.WaitForExit(0)){$child.ExitCode}else{$null}
        Confirm-DnsRoute $Name
        [pscustomobject]@{Case=$Name.Split('.')[0];ExitCode=$code;Observed=($ids.Count -gt 0);QueryIds=@($ids);SocketOwner=$owner}
    }finally{
        try{if(-not $Contained -and -not $child.HasExited){$child.Kill();$null=$child.WaitForExit(3000)}}finally{$child.Dispose()}
    }
}
try{
    $socket.ExclusiveAddressUse=$true
    $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($loop),53))
    if(@(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -eq $tag -or @($_.Namespace | Where-Object {$_ -in $names}).Count }).Count){
        throw 'The temporary DNS ownership markers already exist.'
    }
    $attempted=$true
    Add-DnsClientNrptRule -Namespace $names -NameServers $loop -DisplayName $tag -Comment $tag | Out-Null
    foreach($name in $names){Confirm-DnsRoute $name}
    $rows+=Invoke-DnsTrial $names[0]
    if(-not $rows[0].Observed -or $rows[0].ExitCode -ne 0){throw 'The positive DNS witness was not verified.'}
    if($AppContainerScope){
        $rows+=Invoke-DnsTrial $names[1] -Contained
    }else{
        $policy=$fixture::CloseOnlyFixtureImage($image)
        Write-Host "OBSERVED RequestedSublayerWeight=$([ClaudeGuard.Network.WindowsPolicySession]::RequestedSublayerWeight) AssignedSublayerWeight=$($policy.AssignedSublayerWeight)"
        $rows+=Invoke-DnsTrial $names[1]
        $policy.Dispose();$policy=$null
    }
    $rows+=Invoke-DnsTrial $names[2]
    if(-not $rows[2].Observed -or $rows[2].ExitCode -ne 0){throw 'The final positive DNS witness was not verified.'}
}finally{
    try{if($policy){$policy.Dispose()}}finally{
        try{
            if($attempted){
                $owned=@(Get-DnsClientNrptRule | Where-Object {$_.DisplayName -ceq $tag -and $_.Comment -ceq $tag})
                foreach($row in $owned){
                    if(@($row.Namespace).Count -ne 3 -or @($row.Namespace | Where-Object {$_ -notin $names}).Count -or
                        @($row.NameServers).Count -ne 1 -or @($row.NameServers)[0] -ne $loop){throw 'The transient DNS rule changed ownership.'}
                    Remove-DnsClientNrptRule -Name $row.Name -Force
                }
                if(@(Get-DnsClientNrptRule | Where-Object DisplayName -CEQ $tag).Count){throw 'Temporary NRPT rule removal failed.'}
                $cleanupClock=[Diagnostics.Stopwatch]::StartNew()
                do{
                    $remaining=@(Get-DnsClientNrptPolicy -Effective | Where-Object {
                        @($_.Namespace | Where-Object {$_ -in $names}).Count -gt 0
                    })
                    if($remaining.Count){Start-Sleep -Milliseconds 200}
                }while($remaining.Count -and $cleanupClock.Elapsed.TotalSeconds -lt 5)
                if($remaining.Count){throw 'The temporary effective DNS policy is still present.'}
            }
        }finally{
            $socket.Dispose()
            if($AppContainerScope){[IO.File]::Delete($image)}
        }
    }
}
if($lateBlockedIds.Count){
    $rows[1].Observed=$true
    $rows[1].QueryIds=@(@($rows[1].QueryIds)+@($lateBlockedIds) | Sort-Object -Unique)
}
$state=if($rows[1].Observed){'ApplicationBlockDidNotContainDns'}
    elseif($rows[1].ExitCode -in @(5,10013)){'ExplicitlyDenied'}else{'Inconclusive'}
$report=[pscustomobject]@{State=$state;Pass=($state -eq 'ExplicitlyDenied');Trials=$rows}
[Console]::WriteLine(($report | ConvertTo-Json -Depth 5 -Compress))
if($state -ne 'ExplicitlyDenied'){throw "Native DNS acceptance failed: $state"}
