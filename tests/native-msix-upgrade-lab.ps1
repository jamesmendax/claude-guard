#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MakeAppx,[Parameter(Mandatory)][string]$Directory,
    [switch]$PackOnly,[switch]$ScopedVariant,[switch]$NormalRelayVariant,[switch]$IncludeUpgrade)
$ErrorActionPreference='Stop'
if((($ScopedVariant -or $NormalRelayVariant) -and -not $PackOnly) -or ($ScopedVariant -and $NormalRelayVariant) -or
    ($IncludeUpgrade -and -not $NormalRelayVariant)){
    throw 'Choose one package builder variant.'
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not [Environment]::Is64BitProcess -or (-not $PackOnly -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
    throw 'Use an already elevated x64 Windows PowerShell process.'
}
$tool=(Get-Item -LiteralPath $MakeAppx).FullName
if(-not (Get-Command Add-AppxPackage).Parameters.ContainsKey('AllowUnsigned')){throw 'Unsigned package support is required.'}
$id=[guid]::NewGuid().ToString('N')
$name="GuardMsixFixture.$id"
$publisher='CN=GuardMsixFixture, OID.2.25.311729368913984317654407730594956997722=1'
if(-not $PackOnly -and @(Get-AppxPackage -Name $name -AllUsers).Count){throw 'Fixture identity already exists.'}
$work=Join-Path ([IO.Path]::GetFullPath($Directory)) ("msix-upgrade-"+$id)
$stage=Join-Path $work 'payload'
$null=New-Item -ItemType Directory -Path $stage -Force
$source=Join-Path $PSScriptRoot $(if($ScopedVariant){'native-process-scope-client.cs'}else{'msix-identity-probe.cs'})
$desktop=Join-Path $stage 'fixture-desktop.exe'
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if($NormalRelayVariant){
    $clientSources=@('msix-normal-package-client.cs','msix-identity-probe.cs','native-local-dns-client.cs','native-process-scope-client.cs' |
        ForEach-Object {Join-Path $PSScriptRoot $_})
    & $compiler /nologo /target:winexe /platform:x64 /warnaserror+ /main:GuardNormalPackageClient "/out:$desktop" @clientSources
}else{
    & $compiler /nologo /target:winexe /platform:x64 /warnaserror+ "/out:$desktop" $source
}
if($LASTEXITCODE -ne 0){throw 'MSIX probe compilation failed.'}
Copy-Item -LiteralPath $desktop -Destination (Join-Path $stage 'fixture-helper.exe')
$relay=Join-Path $work 'fixture-relay.exe'
Copy-Item -LiteralPath $desktop -Destination $relay
Add-Type -AssemblyName System.Drawing
foreach($size in 44,50,150){
    $bitmap=[Drawing.Bitmap]::new($size,$size)
    try{$bitmap.Save((Join-Path $stage "logo-$size.png"),[Drawing.Imaging.ImageFormat]::Png)}finally{$bitmap.Dispose()}
}
$versions=if($ScopedVariant -or ($NormalRelayVariant -and -not $IncludeUpgrade)){@('1.0.0.0')}else{@('1.0.0.0','2.0.0.0')}
foreach($version in $versions){
    $helper='fixture-helper.exe'
    if($NormalRelayVariant -and $version -ceq '2.0.0.0'){
        $helper='fixture-helper-v2.exe'
        Move-Item -LiteralPath (Join-Path $stage 'fixture-helper.exe') -Destination (Join-Path $stage $helper)
    }
    $manifest=@"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
 xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
 xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" IgnorableNamespaces="uap rescap">
 <Identity Name="$name" Publisher="$publisher" Version="$version" ProcessorArchitecture="x64"/>
 <Properties><DisplayName>Guard MSIX Fixture</DisplayName><PublisherDisplayName>Guard Fixture</PublisherDisplayName><Logo>logo-50.png</Logo></Properties>
 <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.22000.0" MaxVersionTested="10.0.22621.0"/></Dependencies>
 <Resources><Resource Language="en-us"/></Resources>
 <Applications><Application Id="Desktop" Executable="fixture-desktop.exe" EntryPoint="Windows.FullTrustApplication">
 <uap:VisualElements DisplayName="Guard MSIX Fixture" Description="Loopback fixture" BackgroundColor="transparent" Square150x150Logo="logo-150.png" Square44x44Logo="logo-44.png"/>
 </Application><Application Id="Helper" Executable="$helper" EntryPoint="Windows.FullTrustApplication">
 <uap:VisualElements DisplayName="Guard MSIX Fixture Helper" Description="Loopback fixture" BackgroundColor="transparent" Square150x150Logo="logo-150.png" Square44x44Logo="logo-44.png"/>
 </Application></Applications><Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>
"@
    [IO.File]::WriteAllText((Join-Path $stage 'AppxManifest.xml'),$manifest,[Text.UTF8Encoding]::new($false))
    & $tool pack /d $stage /p (Join-Path $work "fixture-$version.msix") /o | Out-Host
    if($LASTEXITCODE -ne 0){throw "MakeAppx failed for $version."}
}
if($PackOnly){
    if($ScopedVariant -or $NormalRelayVariant){
        [pscustomobject]@{Name=$name;File=(Join-Path $work 'fixture-1.0.0.0.msix');Image=$desktop
            UpgradeFile=if($IncludeUpgrade){Join-Path $work 'fixture-2.0.0.0.msix'}}
    }
    else{[pscustomobject]@{PackedVersions=2;RegisteredPackages=0} | ConvertTo-Json -Compress}
    return
}
$pkgRoot=Split-Path -Parent $PSScriptRoot
Add-Type -Path $source,(Join-Path $pkgRoot 'package/guard-wfp.cs'),(Join-Path $PSScriptRoot 'loopback-lab.cs')
function Read-FixturePackage([string]$Version){
    $list=@(Get-AppxPackage -Name $name | Where-Object {$_.Name -ceq $name -and $_.Version.ToString() -ceq $Version})
    if($list.Count -ne 1){throw "Expected a current-user fixture registration for $Version."}
    $list[0]
}
function Read-FirstPacket($Package,[string]$Executable){
    $path=Join-Path $Package.InstallLocation $Executable
    $challenge=[guid]::NewGuid().ToString('N')
    $witness=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    $pipe=[IO.Pipes.NamedPipeServerStream]::new("GuardMsixFixture-$challenge",[IO.Pipes.PipeDirection]::In,1,
        [IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous)
    try{
        $pending=$pipe.BeginWaitForConnection($null,$null)
        $port=$witness.Client.LocalEndPoint.Port
        $appId=if($Executable -ceq 'fixture-desktop.exe'){'Desktop'}else{'Helper'}
        $null=[GuardMsixProbe]::Activate(($Package.PackageFamilyName+'!'+$appId),"$challenge $port $($Package.PackageFullName)")
        if(-not $pending.AsyncWaitHandle.WaitOne(10000)){throw 'Package process did not report its identity.'}
        $pipe.EndWaitForConnection($pending)
        $reader=[IO.StreamReader]::new($pipe)
        try{
            $line=$reader.ReadLineAsync()
            if(-not $line.Wait(5000)){throw 'Package process identity receipt timed out.'}
            $fields=@($line.Result -split '\|')
        }finally{$reader.Dispose()}
        if($fields.Count -ne 5 -or $fields[0] -cne $challenge -or $fields[1] -cne $Package.PackageFullName -or
            $fields[2] -cne '0' -or $fields[3] -ine $path -or $fields[4] -cnotin 'Sent','AccessDenied'){
            throw "Invalid full-trust process or socket receipt: $($fields -join ' ')."
        }
        $received=$witness.Client.Poll(1000000,[Net.Sockets.SelectMode]::SelectRead)
        if($received){
            $sender=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
            if([Text.Encoding]::ASCII.GetString($witness.Receive([ref]$sender)) -cne $challenge -or
                -not [Net.IPAddress]::IsLoopback($sender.Address) -or $fields[4] -cne 'Sent'){throw 'Unexpected witness data.'}
        }
        Write-Host "OBSERVED Package=$($Package.PackageFullName) Executable=$Executable TokenIsAppContainer=0 Socket=$($fields[4]) FirstPacket=$received"
        $received
    }finally{$pipe.Dispose();$witness.Dispose()}
}
$policy=$null
$executables=@('fixture-desktop.exe','fixture-helper.exe')
$family=$null
$attempted=$false
try{
    $attempted=$true
    Add-AppxPackage -Path (Join-Path $work 'fixture-1.0.0.0.msix') -AllowUnsigned
    $v1=Read-FixturePackage '1.0.0.0'
    $family=$v1.PackageFamilyName
    foreach($exe in $executables){if(-not (Read-FirstPacket $v1 $exe)){throw 'V1 positive control failed.'}}
    $paths=@($executables | ForEach-Object {Join-Path $v1.InstallLocation $_})
    $sid=[GuardMsixProbe]::PackageSid($family)
    $relayPort=[GuardLoopbackLab]::FindPrivatePort()
    $plan=[ClaudeGuard.Network.GuardPolicy]::Create([string[]]$paths,[string[]]@($paths[0]),[string[]]@($sid),$null,$relay,$relayPort,'127.0.0.1',19091)
    $policy=[ClaudeGuard.Network.WindowsPolicySession]::new($plan)
    Write-Host "OBSERVED RequestedSublayerWeight=$([ClaudeGuard.Network.WindowsPolicySession]::RequestedSublayerWeight) AssignedSublayerWeight=$($policy.AssignedSublayerWeight)"
    foreach($exe in $executables){if(Read-FirstPacket $v1 $exe){throw 'V1 covered path reached witness.'}}
    Add-AppxPackage -Path (Join-Path $work 'fixture-2.0.0.0.msix') -AllowUnsigned
    $v2=Read-FixturePackage '2.0.0.0'
    if($v2.PackageFamilyName -cne $family -or $v2.InstallLocation -ieq $v1.InstallLocation){throw 'Package did not move to the next generation.'}
    $outcomes=@(foreach($exe in $executables){Read-FirstPacket $v2 $exe})
    $policy.Dispose()
    $policy=$null
    foreach($exe in $executables){if(-not (Read-FirstPacket $v2 $exe)){throw 'V2 post-policy positive control failed.'}}
}finally{
    try{if($policy){$policy.Dispose()}}
    finally{
        if($attempted){
            foreach($pkg in @(Get-AppxPackage -AllUsers -Name $name)){
                if($pkg.Name -cne $name -or $pkg.Version.ToString() -cnotin '1.0.0.0','2.0.0.0' -or
                    ($family -and $pkg.PackageFamilyName -cne $family)){throw 'Unexpected registration during cleanup.'}
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            }
            if(@(Get-AppxPackage -AllUsers -Name $name).Count){throw "Fixture cleanup incomplete: $name"}
        }
    }
}
Write-Output "RESULT FullTrustMSIXUpgrade=Measured DesktopFirstPacket=$($outcomes[0]) HelperFirstPacket=$($outcomes[1]) PackageCleanup=Verified Transport=IPv4LoopbackUDP"
