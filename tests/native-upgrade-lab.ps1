#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not [Environment]::Is64BitProcess -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Use an already elevated x64 Windows PowerShell process for the synthetic WFP fixture.'
}

function Test-FirstDatagram([string]$Image,[bool]$Expected,[string]$Case){
    $token=[guid]::NewGuid().ToString('N')
    $message=@(& $Image udp 4 $witness.Client.LocalEndPoint.Port $token)
    $exitCode=$LASTEXITCODE
    if($exitCode -ne 0 -and ($exitCode -ne 1 -or ($message -join '') -cne 'REJECT SocketException')){
        throw "$Case probe failed unexpectedly ($exitCode, $message)."
    }
    $received=$witness.Client.Poll(1000000,[Net.Sockets.SelectMode]::SelectRead)
    if($received){
        $sender=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $body=[Text.Encoding]::ASCII.GetString($witness.Receive([ref]$sender))
        if(-not [Net.IPAddress]::IsLoopback($sender.Address) -or $body -cne $token){
            throw "$Case witness received a foreign or delayed token."
        }
    }
    if($received -ne $Expected -or ($received -and $exitCode -ne 0)){
        throw "$Case expected receipt=$Expected, observed receipt=$received, process exit=$exitCode."
    }
    Write-Output "PASS $Case first-datagram-received=$received"
}

$root=Split-Path -Parent $PSScriptRoot
$directory=Join-Path $root ('evidence/native-upgrade-'+[guid]::NewGuid().ToString('N'))
$v1=Join-Path $directory 'version-1'
$v2=Join-Path $directory 'version-2'
$null=New-Item -ItemType Directory -Path $v1 -Force
$old=Join-Path $v1 'fixture-desktop.exe'
$oldHelper=Join-Path $v1 'fixture-helper.exe'
$next=Join-Path $v2 'fixture-desktop.exe'
$nextHelper=Join-Path $v2 'fixture-helper.exe'
$control=Join-Path $directory 'fixture-control.exe'
$relay=Join-Path $directory 'fixture-relay.exe'
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
& $compiler /nologo /warnaserror+ /platform:x64 "/out:$old" (Join-Path $PSScriptRoot 'loopback-probe.cs')
if($LASTEXITCODE -ne 0){throw 'Probe compilation failed.'}
foreach($destination in $oldHelper,$control,$relay){Copy-Item -LiteralPath $old -Destination $destination}
Add-Type -Path (Join-Path $root 'package/guard-wfp.cs'),(Join-Path $PSScriptRoot 'loopback-lab.cs')
$witness=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
$oldPolicy=$null
$expandedPolicy=$null
try{
    $relayPort=[GuardLoopbackLab]::FindPrivatePort()
    # This upstream is a synthetic TCP tuple. No relay or upstream connection is started.
    $upstreamPort=if($relayPort -eq 19091){19092}else{19091}
    Test-FirstDatagram $old $true 'old desktop before policy'
    Test-FirstDatagram $oldHelper $true 'old helper before policy'
    $oldPlan=[ClaudeGuard.Network.GuardPolicy]::Create([string[]]@($old,$oldHelper),[string[]]@($old),
        [string[]]@(),$null,$relay,$relayPort,'127.0.0.1',$upstreamPort)
    $oldPolicy=[ClaudeGuard.Network.WindowsPolicySession]::new($oldPlan)
    Write-Output "OBSERVED RequestedSublayerWeight=$([ClaudeGuard.Network.WindowsPolicySession]::RequestedSublayerWeight) AssignedSublayerWeight=$($oldPolicy.AssignedSublayerWeight)"
    Test-FirstDatagram $old $false 'old desktop under old policy'
    Test-FirstDatagram $oldHelper $false 'old helper under old policy'
    # An unpackaged native process has no AppContainer or MSIX package identity.
    # Introduce the new executable paths only after the old policy has been installed.
    $null=New-Item -ItemType Directory -Path $v2
    Copy-Item -LiteralPath $old -Destination $next
    Copy-Item -LiteralPath $oldHelper -Destination $nextHelper
    Test-FirstDatagram $next $true 'new desktop first launch under old policy'
    Test-FirstDatagram $nextHelper $true 'new helper first launch under old policy'
    $expandedPlan=[ClaudeGuard.Network.GuardPolicy]::Create([string[]]@($old,$oldHelper,$next,$nextHelper),
        [string[]]@($old,$next),[string[]]@(),$null,$relay,$relayPort,'127.0.0.1',$upstreamPort)
    $expandedPolicy=[ClaudeGuard.Network.WindowsPolicySession]::new($expandedPlan)
    Test-FirstDatagram $next $false 'new desktop after explicit path coverage'
    Test-FirstDatagram $nextHelper $false 'new helper after explicit path coverage'
    Test-FirstDatagram $control $true 'independent witness control'
}finally{
    try{if($expandedPolicy){$expandedPolicy.Dispose()}}
    finally{try{if($oldPolicy){$oldPolicy.Dispose()}}finally{$witness.Dispose()}}
}
Write-Output 'RESULT NativePathUpgradeCounterexample=Observed Transport=IPv4LoopbackUDP ExactFullTrustMSIX=Unverified'
