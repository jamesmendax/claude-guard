#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$UpgradeFile,
    [Parameter(Mandatory=$true)][string]$Package,
    [Parameter(Mandatory=$true)][int]$DirectPort,
    [Parameter(Mandatory=$true)][int]$RelayPort,
    [switch]$ActivateOnly
)
$ErrorActionPreference='Stop'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
$stage=Split-Path -Parent $PSScriptRoot
if((Split-Path -Parent $stage) -ine $root -or
    (Split-Path -Leaf $stage) -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z' -or
    $Package -cnotmatch '\AGuardMsixFixture\.[a-f0-9]{32}_2\.0\.0\.0_x64__[a-z0-9]{13}\z' -or
    -not $UpgradeFile.StartsWith("$stage\",[StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFullPath($UpgradeFile) -ine $UpgradeFile -or
    [IO.Path]::GetFileName($UpgradeFile) -cne 'fixture-2.0.0.0.msix' -or
    $DirectPort -lt 1024 -or $DirectPort -gt 65535 -or $RelayPort -lt 1024 -or $RelayPort -gt 65535){
    throw 'Only the isolated native Store test package and loopback ports may be activated.'
}
Add-Type -Path (Join-Path $PSScriptRoot 'msix-identity-probe.cs')
$m=[regex]::Match($Package,'\A(?<name>GuardMsixFixture\.[a-f0-9]{32})_2\.0\.0\.0_x64__(?<issuer>[a-z0-9]{13})\z')
$name=$m.Groups['name'].Value
$family=$name+'_'+$m.Groups['issuer'].Value
$nonce=[guid]::NewGuid().ToString('N')
$pipe=[IO.Pipes.NamedPipeServerStream]::new("GuardNormalPackage-$nonce",'InOut',1,'Byte','Asynchronous')
$reader=$null
$writer=$null
$peer=$null
try{
    $pending=$pipe.BeginWaitForConnection($null,$null)
    $installStarted=[datetime]::UtcNow
    if(-not $ActivateOnly){Add-AppxPackage -Path $UpgradeFile -AllowUnsigned}
    $addReturned=[datetime]::UtcNow
    $activateCalled=[datetime]::UtcNow
    $activated=[GuardMsixProbe]::Activate($family+'!Desktop',"upgrade-first $nonce $Package $DirectPort $RelayPort")
    if(-not $activated){throw 'Windows returned no Store test activation PID.'}
    if(-not $pending.AsyncWaitHandle.WaitOne(9000)){throw 'The first-attempt fixture reported no result.'}
    $pipe.EndWaitForConnection($pending)
    $reader=[IO.StreamReader]::new($pipe)
    $line=$reader.ReadLineAsync()
    if(-not $line.Wait(3000)){throw 'The first-attempt fixture did not complete its receipt.'}
    $receipt=$line.Result -split '\|'
    if($receipt.Count -ne 6 -or $receipt[0] -cne $nonce -or $receipt[1] -cne $Package -or
        $receipt[5] -cnotin 'Echo','Unavailable'){
        throw 'The first network attempt did not come from the replacement fixture.'
    }
    # Sandboxie can change the process returned by activation. Verify the
    # actual pipe peer while it waits for our acknowledgement.
    $peerId=[GuardMsixProbe]::PipeClientId($pipe)
    $peer=[Diagnostics.Process]::GetProcessById($peerId)
    $registered=@(Get-AppxPackage -Name $name -ErrorAction Stop | Where-Object Name -CEQ $name)
    if($registered.Count -ne 1 -or $registered[0].PackageFullName -cne $Package -or
        $registered[0].PackageFamilyName -cne $family -or $registered[0].Version.ToString() -cne '2.0.0.0' -or
        (Split-Path -Leaf $registered[0].InstallLocation) -cne $Package -or
        (Split-Path -Leaf (Split-Path -Parent $registered[0].InstallLocation)) -ine 'WindowsApps'){
        throw 'The replacement Store fixture did not match the expected registration.'
    }
    . (Join-Path $stage 'package\guard-common.ps1')
    $expectedImage=Join-Path $registered[0].InstallLocation 'fixture-desktop.exe'
    $peerImage=$peer.MainModule.FileName
    if(-not $peerImage -or (Get-GuardFinalPath $peerImage) -ine (Get-GuardFinalPath $expectedImage)){
        throw 'The first-attempt pipe peer was not the registered Store fixture image.'
    }
    $writer=[IO.StreamWriter]::new($pipe,[Text.UTF8Encoding]::new($false),1024,$true)
    $writer.AutoFlush=$true
    $writer.WriteLine($nonce)
    [pscustomobject]@{
        Package=$Package;InstallStartedUtc=$installStarted.ToString('o');AddReturnedUtc=$addReturned.ToString('o')
        ActivationCalledUtc=$activateCalled.ToString('o');FirstProcessUtc=$receipt[2];FirstTcpUdpUtc=$receipt[3]
        FirstRelayUtc=$receipt[4];RelayResult=$receipt[5];Pid=$peerId
    } | ConvertTo-Json -Compress
}finally{
    if($peer){$peer.Dispose()}
    if($writer){$writer.Dispose()}
    if($reader){$reader.Dispose()}
    $pipe.Dispose()
}
