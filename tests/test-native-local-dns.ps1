#Requires -Version 5.1
$ErrorActionPreference='Stop'
$id=[guid]::NewGuid().ToString('N')
$zone="g$id.test"
$names=@('before','container','after' | ForEach-Object {"$_.$zone"})
function Assert-GuardSyntheticDnsPolicyAbsent([string]$Name) {
    # A matching NRPT rule would take precedence over the fixture's local server.
    try{$existing=@(Get-DnsClientNrptPolicy -Effective -Namespace $Name -ErrorAction Stop)}
    catch{
        if($_.FullyQualifiedErrorId -like 'WIN32 4312,Get-DnsClientNrptPolicy'){return}
        throw
    }
    if($existing.Count){throw 'An existing DNS policy applies to the synthetic name.'}
}
foreach($name in $names){Assert-GuardSyntheticDnsPolicyAbsent $name}
$folder=Join-Path ([IO.Path]::GetTempPath()) ('guard-dns-witness-'+$id)
$image=Join-Path $folder 'dns-query-fixture.exe'
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$loop="127.$([Convert]::ToByte($id.Substring(0,2),16)).$([Convert]::ToByte($id.Substring(2,2),16)).$((([Convert]::ToByte($id.Substring(4,2),16)) % 254)+1)"
$socket=$null
$scope=$null

Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;

public static class GuardUdpOwner
{
    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size,
        bool sort, uint family, uint tableClass, uint reserved);

    public static int FindIPv4(int port, string address)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 1, 0);
        int expectedAddress = BitConverter.ToInt32(IPAddress.Parse(address).GetAddressBytes(), 0);
        for (int attempt = 0; attempt < 3 && size >= 4; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint status = GetExtendedUdpTable(buffer, ref size, false, 2, 1, 0);
                if (status == 122) continue;
                if (status != 0) return 0;
                int count = Marshal.ReadInt32(buffer);
                if (count < 0 || count > (size - 4) / 12) return 0;
                int owner = 0;
                for (int offset = 4; offset < 4 + 12 * count; offset += 12)
                {
                    int local = Marshal.ReadInt32(buffer, offset);
                    if (local != 0 && local != expectedAddress) continue;
                    ushort localPort = (ushort)IPAddress.NetworkToHostOrder(Marshal.ReadInt16(buffer, offset + 4));
                    if (localPort != port) continue;
                    int found = Marshal.ReadInt32(buffer, offset + 8);
                    if (owner != 0 && found != owner) return 0;
                    owner = found;
                }
                return owner;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return 0;
    }
}
'@

function Invoke-GuardLocalDns([string]$Name,[bool]$Contained){
    $nameWire=[Collections.Generic.List[byte]]::new()
    foreach($label in $Name.Split('.')){$nameWire.Add([byte]$label.Length);$nameWire.AddRange([Text.Encoding]::ASCII.GetBytes($label))}
    $nameWire.AddRange([byte[]](0,0,1,0,1))
    $question=$nameWire.ToArray()
    $expected=[Text.Encoding]::ASCII.GetString($question)
    Assert-GuardSyntheticDnsPolicyAbsent $Name
    if($Contained){
        $child=$scope.Start($image,($Name+'. '+$loop+' '+$scope.Identity.Value),$false)
    }else{
        $start=[Diagnostics.ProcessStartInfo]::new($image,($Name+'. '+$loop+' none'))
        $start.UseShellExecute=$false
        $start.CreateNoWindow=$true
        $process=[Diagnostics.Process]::Start($start)
        $child=$process
    }
    $observed=$false
    $owner='NoMatchingPacket'
    try{
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $exitedAt=$null
        while($clock.ElapsedMilliseconds -lt 10000){
            if($socket.Available -eq 0){
                if($child.WaitForExit(0)){
                    if($null -eq $exitedAt){$exitedAt=$clock.ElapsedMilliseconds}
                    if($clock.ElapsedMilliseconds-$exitedAt -ge 300){break}
                }
                Start-Sleep -Milliseconds 10
                continue
            }
            $origin=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
            $packet=$socket.Receive([ref]$origin)
            if(-not [Net.IPAddress]::IsLoopback($origin.Address) -or $packet.Length -lt (12+$question.Length) -or
                ($packet[2] -band 128) -or $packet[4] -ne 0 -or $packet[5] -ne 1){continue}
            $query=[Text.Encoding]::ASCII.GetString($packet,12,$question.Length)
            if(-not [string]::Equals($query,$expected,[StringComparison]::OrdinalIgnoreCase)){continue}
            $observed=$true
            # Identify the sender before releasing the request with its local answer.
            $sender=[GuardUdpOwner]::FindIPv4($origin.Port,$origin.Address.ToString())
            $owner=if($sender -eq $dnsService.ProcessId){'DnsClientServiceHost'}
                elseif($sender -eq $child.Id){'FixtureProcess'}elseif($owner -eq 'NoMatchingPacket'){'Unknown'}else{$owner}
            $reply=[byte[]](@($packet[0],$packet[1],129,128,0,1,0,1,0,0,0,0)+
                $packet[12..(11+$question.Length)]+@(192,12,0,1,0,1,0,0,0,0,0,4,192,0,2,53))
            $null=$socket.Send($reply,$reply.Length,$origin)
        }
        $code=if($child.WaitForExit(0)){$child.ExitCode}
        [pscustomobject]@{Case=$Name.Split('.')[0];ExitCode=$code;Packet=$observed;Owner=$owner}
    }finally{
        try{
            if(-not $Contained -and -not $child.HasExited){$child.Kill();$null=$child.WaitForExit(2000)}
        }finally{$child.Dispose()}
    }
}

try{
    $null=New-Item -ItemType Directory -Path $folder
    & $compiler /nologo /warnaserror+ /platform:x64 /main:GuardLocalDnsClient "/out:$image" `
        (Join-Path $PSScriptRoot 'native-process-scope-client.cs') (Join-Path $PSScriptRoot 'native-local-dns-client.cs')
    if($LASTEXITCODE -ne 0){throw 'Local DNS probe compilation failed.'}
    Add-Type -Path (Join-Path $PSScriptRoot '..\package\guard-app-container.cs'),(Join-Path $PSScriptRoot 'native-app-container.cs')
    $scope=[GuardFixtureAppContainer]::new()
    $acl=Get-Acl -LiteralPath $folder
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($scope.Identity,'ReadAndExecute',
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $folder -AclObject $acl
    $dnsService=Get-CimInstance Win32_Service -Filter "Name='Dnscache'"
    if($dnsService.State -ne 'Running'){throw 'The Windows DNS Client service is unavailable.'}
    $socket=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $socket.ExclusiveAddressUse=$true
    $socket.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($loop),53))
    # SIO_UDP_CONNRESET. Late test replies must not mark this witness socket dead.
    $null=$socket.Client.IOControl(-1744830452,[byte[]]@(0,0,0,0),$null)
    $before=Invoke-GuardLocalDns $names[0] $false
    if($before.Packet -and $before.ExitCode -eq 0){
        $contained=Invoke-GuardLocalDns $names[1] $true
        $after=Invoke-GuardLocalDns $names[2] $false
    }else{$contained=$null;$after=$null}
    $result=[pscustomobject]@{Utc=[datetime]::UtcNow.ToString('o');ExplicitLoopbackResolver=$true;
        ControlsBothPassed=($before.Packet -and $before.ExitCode -eq 0 -and $after.Packet -and $after.ExitCode -eq 0);
        Before=$before;AppContainer=$contained;After=$after}
}finally{
    try{if($scope){$scope.Dispose()}}finally{
        if($socket){$socket.Dispose()}
        [IO.File]::Delete($image)
        if([IO.Directory]::Exists($folder)){[IO.Directory]::Delete($folder,$false)}
    }
}
$result | ConvertTo-Json -Depth 4 -Compress
