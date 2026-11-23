#Requires -Version 5.1
param([switch]$PreloadNative,[switch]$Benchmark)

$ErrorActionPreference='Stop'
$package=Join-Path $PSScriptRoot '..\package'
if($PreloadNative){Add-Type -Path (Join-Path $package 'guard-relay-evidence.cs')}
. (Join-Path $package 'guard-daily-plan.ps1')

function Assert-RelayListener([bool]$Condition,[string]$Message){
    if(-not $Condition){throw "FAIL: $Message"}
    "PASS: $Message"
}

function Open-TestListener([ipaddress]$Address,[int]$Port=0){
    $listener=[Net.Sockets.TcpListener]::new($Address,$Port)
    try{
        $listener.ExclusiveAddressUse=$true
        if($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6){$listener.Server.DualMode=$false}
        $listener.Start()
        $listener
    }catch{$listener.Stop();throw}
}

function Test-PreviousListener([int]$Port,[int]$OwnerId){
    $sockets=@(try{Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop}
        catch{if($_.CategoryInfo.Category -ne 'ObjectNotFound'){throw}})
    $sockets.Count -eq 1 -and $sockets[0].LocalAddress -ceq '127.0.0.1' -and $sockets[0].OwningProcess -eq $OwnerId
}

$listener=Open-TestListener ([ipaddress]::Loopback)
$port=$listener.LocalEndpoint.Port
try{
    if(-not $PreloadNative){
        & {
            function Add-Type { throw 'Synthetic native helper load failure.' }
            Assert-RelayListener (-not (Test-GuardDailyRelayListener $port $PID)) 'an unavailable native helper denies a valid listener'
        }
    }
    $first=Measure-Command { $script:accepted=Test-GuardDailyRelayListener $port $PID }
    Assert-RelayListener $accepted 'one listener on 127.0.0.1 owned by the expected PID is accepted'
    Assert-RelayListener (-not (Test-GuardDailyRelayListener $port ($PID+1))) 'a different PID is rejected'
    Assert-RelayListener (-not (Test-GuardDailyRelayListener 0 $PID) -and
        -not (Test-GuardDailyRelayListener 65536 $PID) -and
        -not (Test-GuardDailyRelayListener $port 0)) 'invalid ports and PIDs are rejected'

    $extra=Open-TestListener ([ipaddress]::IPv6Loopback) $port
    try{
        Assert-RelayListener (-not (Test-GuardDailyRelayListener $port $PID)) 'an extra IPv6 listener on the same port is rejected'
    }finally{$extra.Stop()}

    $extra=Open-TestListener ([ipaddress]'127.0.0.2') $port
    try{
        Assert-RelayListener (-not (Test-GuardDailyRelayListener $port $PID)) 'an extra IPv4 listener on the same port is rejected'
    }finally{$extra.Stop()}

    if($Benchmark){
        $previousFirst=Measure-Command { $script:oldAccepted=Test-PreviousListener $port $PID }
        Assert-RelayListener $oldAccepted 'the previous Windows cmdlet accepts the same synthetic listener'
        $previous=@(1..5 | ForEach-Object {(Measure-Command {if(-not (Test-PreviousListener $port $PID)){throw 'Previous check failed.'}}).TotalMilliseconds})
        $current=@(1..100 | ForEach-Object {(Measure-Command {if(-not (Test-GuardDailyRelayListener $port $PID)){throw 'Native check failed.'}}).TotalMilliseconds})
        [pscustomobject]@{
            PSVersion=$PSVersionTable.PSVersion.ToString();Preloaded=[bool]$PreloadNative
            PreviousFirstMs=[Math]::Round($previousFirst.TotalMilliseconds,3)
            PreviousMedianMs=[Math]::Round(($previous | Sort-Object)[2],3)
            PreviousMaxMs=[Math]::Round(($previous | Measure-Object -Maximum).Maximum,3)
            NativeFirstMs=[Math]::Round($first.TotalMilliseconds,3)
            NativeMedianMs=[Math]::Round(($current | Sort-Object)[49],3)
            NativeMaxMs=[Math]::Round(($current | Measure-Object -Maximum).Maximum,3)
        } | ConvertTo-Json -Compress
    }
}finally{$listener.Stop()}
Assert-RelayListener (-not (Test-GuardDailyRelayListener $port $PID)) 'a released port is rejected'

foreach($address in @([ipaddress]::Any,[ipaddress]::IPv6Any,[ipaddress]::IPv6Loopback,[ipaddress]'127.0.0.2')){
    $different=Open-TestListener $address
    try{
        Assert-RelayListener (-not (Test-GuardDailyRelayListener $different.LocalEndpoint.Port $PID)) "a listener on $address is rejected"
    }finally{$different.Stop()}
}

# Native table fixtures use a 4-byte count and 24-byte IPv4 or 56-byte IPv6 rows.
$readRows=[ClaudeGuard.Network.RelayListener].GetMethod('MatchesRows',[Reflection.BindingFlags]'Static,NonPublic')
$table=[Runtime.InteropServices.Marshal]::AllocHGlobal(60)
try{
    [Runtime.InteropServices.Marshal]::WriteInt32($table,0)
    Assert-RelayListener ($readRows.Invoke($null,@($table,4,$false,$port,$PID))) 'a valid empty IPv6 table is accepted'
    Assert-RelayListener (-not $readRows.Invoke($null,@($table,60,$false,$port,$PID))) 'a table size claiming more than the reported row count is rejected'
    [Runtime.InteropServices.Marshal]::WriteInt32($table,1)
    Assert-RelayListener (-not $readRows.Invoke($null,@($table,59,$false,$port,$PID))) 'a table with a truncated row is rejected'
    [Runtime.InteropServices.Marshal]::WriteInt32($table,52,0)
    Assert-RelayListener (-not $readRows.Invoke($null,@($table,60,$false,$port,$PID))) 'a row from an invalid listening state is rejected'

    [Runtime.InteropServices.Marshal]::WriteInt32($table,4,2)
    [Runtime.InteropServices.Marshal]::WriteInt32($table,8,0x010200c0) # 192.0.2.1
    [Runtime.InteropServices.Marshal]::WriteByte($table,12,[byte]($port -shr 8))
    [Runtime.InteropServices.Marshal]::WriteByte($table,13,[byte]($port -band 255))
    [Runtime.InteropServices.Marshal]::WriteInt32($table,24,$PID)
    Assert-RelayListener (-not $readRows.Invoke($null,@($table,28,$true,$port,$PID))) 'a native IPv4 row bound to a non-loopback address is rejected'
}finally{[Runtime.InteropServices.Marshal]::FreeHGlobal($table)}

# Select controls using Windows' independent, read-only adapter inventory.
$adapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
    $_.InterfaceGuid -and $_.Name -cmatch '[A-Za-z]' -and $_.Name -ine 'Bettbox'
})
$upAdapter=$adapters | Where-Object {$_.InterfaceAdminStatus -eq 1 -and $_.InterfaceOperationalStatus -eq 1} |
    Select-Object -First 1
if(-not $upAdapter){throw 'This adapter contract requires a local administratively and operationally up test interface.'}
$adapterGuid=[guid]$upAdapter.InterfaceGuid
$adapterAlias=[string]$upAdapter.Name
$unlistedGuid=[guid]::NewGuid()
$differentCase=if($adapterAlias -ceq $adapterAlias.ToUpperInvariant()){$adapterAlias.ToLowerInvariant()}
    else{$adapterAlias.ToUpperInvariant()}

Assert-RelayListener ([ClaudeGuard.Network.RelayListener]::IsAdapterUp($adapterGuid,$adapterAlias)) `
    'the exact GUID and alias of an administratively and operationally up adapter are accepted'
Assert-RelayListener (-not [ClaudeGuard.Network.RelayListener]::IsAdapterUp($adapterGuid,$adapterAlias+'-wrong')) `
    'an up adapter GUID with the wrong alias is rejected'
Assert-RelayListener (-not [ClaudeGuard.Network.RelayListener]::IsAdapterUp($unlistedGuid,$adapterAlias)) `
    'an unknown GUID with a real adapter alias is rejected'
Assert-RelayListener (-not [ClaudeGuard.Network.RelayListener]::IsAdapterUp([guid]::Empty,$adapterAlias)) `
    'an empty GUID with a real adapter alias is rejected'
Assert-RelayListener (-not [ClaudeGuard.Network.RelayListener]::IsAdapterUp($adapterGuid,'')) `
    'an empty alias with a real adapter GUID is rejected'
Assert-RelayListener (-not [ClaudeGuard.Network.RelayListener]::IsAdapterUp($adapterGuid,$differentCase)) `
    'a case-only mismatch in the adapter alias is rejected'

$downAdapter=$adapters | Where-Object {$_.InterfaceAdminStatus -eq 2 -or $_.InterfaceOperationalStatus -eq 2} |
    Select-Object -First 1
if($downAdapter){
    Assert-RelayListener (-not [ClaudeGuard.Network.RelayListener]::IsAdapterUp([guid]$downAdapter.InterfaceGuid,[string]$downAdapter.Name)) `
        'an administratively or operationally down adapter is rejected even with its exact GUID and alias'
}else{'SKIP: no local down adapter is available for the read-only control'}
