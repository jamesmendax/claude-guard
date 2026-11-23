#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,[switch]$Packaged)

$ErrorActionPreference='Stop'
$stage=(Get-Item -LiteralPath $Directory -Force).FullName
$guardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
if((Split-Path -Parent $stage) -ine $guardRoot -or (Split-Path -Leaf $stage) -cnotmatch '^native-acceptance-[a-f0-9]{32}$' -or
    $PSScriptRoot -ine (Join-Path $stage 'tests')){
    throw 'A protected native-acceptance stage is required.'
}
$admins=[Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$trusted=@('S-1-5-18',$admins.Value)
$write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
foreach($path in $guardRoot,$stage){
    $item=Get-Item -LiteralPath $path -Force
    $acl=Get-Acl -LiteralPath $path
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
        @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $write) -and $_.IdentityReference.Value -notin $trusted
        }).Count){throw 'The native fixture stage is writable by another identity.'}
}

$folder=Join-Path $stage ('contained-relay-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $folder
$image=Join-Path $folder 'fixture-parent.exe'
$moved=Join-Path $folder ('fixture-helper-'+[guid]::NewGuid().ToString('N')+'.exe')
$childImage=$image; $childHelper=$moved
$relay=Join-Path $folder 'fixture-relay.exe'
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$checkNet=Join-Path $env:SystemRoot 'System32\CheckNetIsolation.exe'
$wfp=Join-Path $stage 'package\guard-wfp.cs'
$directTcp=$null; $directUdp=$null; $upstream=$null; $scope=$null; $policy=$null; $forward=$null
$changedExemption=$false
$fixtureName=$null
$fixturePackageSids=@()

function Read-LoopbackExemptions {
    $list=& $checkNet LoopbackExempt -s
    if($LASTEXITCODE -ne 0){throw 'Windows could not read the loopback exemptions.'}
    @([regex]::Matches(($list -join "`n"),'(?<![0-9-])S-1-15-2-(?:[0-9]+-){6}[0-9]+(?![0-9-])') |
        ForEach-Object Value | Sort-Object -Unique)
}

function Assert-DirectWitnessControl {
    $start=[Diagnostics.ProcessStartInfo]::new($childImage,('parent '+$directPort+' none "'+$childHelper+'"'))
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $process=[Diagnostics.Process]::Start($start)
    try{
        if(-not $process.WaitForExit(8000) -or $process.ExitCode -ne 0){throw 'The unprotected direct control did not complete.'}
    }finally{
        try{if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(2000)}}finally{$process.Dispose()}
    }
    foreach($marker in 81,82){
        if(-not $directTcp.Pending() -or $directUdp.Available -eq 0){throw 'A direct control packet did not appear.'}
        $accepted=$directTcp.AcceptTcpClient()
        try{
            $accepted.ReceiveTimeout=1000
            if($accepted.GetStream().ReadByte() -ne $marker){throw 'Unexpected TCP control packet.'}
        }finally{$accepted.Dispose()}
        $origin=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $packet=$directUdp.Receive([ref]$origin)
        if($packet.Length -ne 1 -or $packet[0] -ne $marker -or -not [Net.IPAddress]::IsLoopback($origin.Address)){
            throw 'Unexpected UDP control packet.'
        }
    }
}

function Invoke-ContainedSession([bool]$PermitOpen){
    $arguments='parent '+$directPort+' '+$sid+' "'+$childHelper+'" '+$relayPort
    $signal=[Threading.ManualResetEvent]::new($false)
    $child=$null
    try{
        if($PermitOpen){
            $hash=(Get-FileHash -LiteralPath $childImage -Algorithm SHA256).Hash
            $child=[ClaudeGuard.Processes.GuardAppContainer]::StartVerified($scope.Name,$sid,$childImage,$hash,$arguments,$signal)
        }else{
            $child=$scope.Start($childImage,$arguments,$false)
        }
        if(-not $child.WaitForExit(12000) -or $child.ExitCode -ne 0){throw 'The isolated parent or new-path helper did not complete.'}
    }finally{
        try{if($child){$child.Dispose()}}finally{$signal.Dispose()}
    }
    $seen=@()
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $limit=if($PermitOpen){2500}else{350}
    do{
        if($upstream.Pending()){
            $accepted=$upstream.AcceptTcpClient()
            try{
                $accepted.ReceiveTimeout=1000
                $seen+=,$accepted.GetStream().ReadByte()
            }finally{$accepted.Dispose()}
        }elseif($PermitOpen -and $seen.Count -ge 2){break}
        else{Start-Sleep -Milliseconds 20}
    }while($watch.ElapsedMilliseconds -lt $limit)
    if($directTcp.Pending() -or $directUdp.Available -gt 0){throw 'A protected parent or new-path helper reached the direct receiver.'}
    $markers=($seen | Sort-Object) -join ','
    $expected=if($PermitOpen){'81,82'}else{''}
    if($markers -cne $expected){throw "The dedicated relay witness disagreed with the permit state ($PermitOpen)."}
}

try{
    if($Packaged){
        $packed=& (Join-Path $PSScriptRoot 'native-msix-upgrade-lab.ps1') -Directory $stage `
            -MakeAppx (Join-Path $stage 'sdk\makeappx.exe') -PackOnly -ScopedVariant
        if($packed.Name -cnotmatch '^GuardMsixFixture\.[a-f0-9]{32}$' -or @(Get-AppxPackage -Name $packed.Name -AllUsers).Count){
            throw 'The isolated MSIX fixture name could not be reserved.'
        }
        $fixtureName=$packed.Name
        Add-AppxPackage -Path $packed.File -AllowUnsigned
        $package=@(Get-AppxPackage -Name $fixtureName | Where-Object {$_.Name -ceq $fixtureName -and $_.Version.ToString() -ceq '1.0.0.0'})
        if($package.Count -ne 1){throw 'The isolated MSIX test package was not registered.'}
        $childImage=Join-Path $package[0].InstallLocation 'fixture-desktop.exe'
        $childHelper=Join-Path $package[0].InstallLocation 'fixture-helper.exe'
    }else{
        & $compiler /nologo /warnaserror+ /platform:x64 "/out:$image" (Join-Path $PSScriptRoot 'native-process-scope-client.cs')
        if($LASTEXITCODE -ne 0){throw 'Contained fixture compilation failed.'}
        [IO.File]::Copy($image,$moved)
    }
    & $compiler /nologo /warnaserror+ /platform:x64 "/out:$relay" (Join-Path $PSScriptRoot 'loopback-probe.cs')
    if($LASTEXITCODE -ne 0){throw 'Contained fixture relay compilation failed.'}
    $types=@($wfp,(Join-Path $stage 'package\guard-app-container.cs'),(Join-Path $PSScriptRoot 'loopback-lab.cs'),(Join-Path $PSScriptRoot 'native-app-container.cs'),
        (Join-Path $PSScriptRoot 'msix-identity-probe.cs'))
    Add-Type -Path $types
    if($Packaged){$fixturePackageSids=@([GuardMsixProbe]::PackageSid($package[0].PackageFamilyName))}
    $scope=[GuardFixtureAppContainer]::new()
    $sid=$scope.Identity.Value
    $acl=Get-Acl -LiteralPath $folder
    $acl.SetOwner($admins)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($scope.Identity,'ReadAndExecute',
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $folder -AclObject $acl
    $before=@(Read-LoopbackExemptions)
    if($sid -in $before){throw 'The synthetic sid already has a loopback exemption.'}

    $loop=[Net.IPAddress]::Loopback
    $directTcp=[Net.Sockets.TcpListener]::new($loop,0)
    $directTcp.ExclusiveAddressUse=$true
    $directTcp.Start()
    $directPort=([Net.IPEndPoint]$directTcp.LocalEndpoint).Port
    $directUdp=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $directUdp.ExclusiveAddressUse=$true
    $directUdp.Client.Bind([Net.IPEndPoint]::new($loop,$directPort))
    Assert-DirectWitnessControl
    $upstream=[Net.Sockets.TcpListener]::new($loop,0)
    $upstream.ExclusiveAddressUse=$true
    $upstream.Start()
    $upstreamPort=([Net.IPEndPoint]$upstream.LocalEndpoint).Port
    $relayPort=[GuardLoopbackLab]::FindPrivatePort()
    # Only the original path is registered. The moved child can reach the relay
    # by the enclosing AppContainer identity alone.
    $plan=[ClaudeGuard.Network.GuardPolicy]::CreateForAppContainer([string[]]@($childImage),[string[]]@($childImage),
        [string[]]$fixturePackageSids,[string[]]@(),$sid,$relay,[uint16]$relayPort,'127.0.0.1',[uint16]$upstreamPort,$null)
    $policy=[ClaudeGuard.Network.WindowsPolicySession]::new($plan)
    $forward=[GuardLoopbackLab]::StartRelay($relay,$relayPort,$upstreamPort)

    $changedExemption=$true
    & $checkNet LoopbackExempt -a "-p=$sid" | Out-Null
    if($LASTEXITCODE -ne 0 -or $sid -notin @(Read-LoopbackExemptions)){throw 'The isolated fixture loopback exemption did not read back.'}
    Invoke-ContainedSession $false
    $policy.Open()
    Invoke-ContainedSession $true
    & (Join-Path $PSScriptRoot 'native-dns-lab.ps1') -Directory $folder -AppContainerScope $scope
    $policy.Close()
    Invoke-ContainedSession $false

    # A close request must revoke the relay permit independently of lease expiry.
    $closeRequest=[Threading.EventWaitHandle]::new($false,'ManualReset')
    try{
        $deadline=[datetime]::UtcNow.AddSeconds(15)
        $policy.OpenUntil($deadline,$closeRequest)
        Invoke-ContainedSession $true
        if(-not $closeRequest.Set()){throw 'Could not signal the fixture close request.'}
        Start-Sleep -Milliseconds 300
        Invoke-ContainedSession $false
        if([datetime]::UtcNow -ge $deadline){throw 'The close-request check reached the lease deadline.'}
    }finally{
        try{$policy.Close()}finally{$closeRequest.Dispose()}
    }
}finally{
    try{
        try{if($policy){$policy.Close()}}finally{
            if($changedExemption){
                & $checkNet LoopbackExempt -d "-p=$sid" | Out-Null
                if($LASTEXITCODE -ne 0 -or (@(Read-LoopbackExemptions) -join ',') -cne ($before -join ',')){
                    throw 'Loopback exemption cleanup failed its readback.'
                }
            }
        }
    }finally{
        try{if($policy){$policy.Dispose()}}finally{
            try{if($forward){$forward.Dispose()}}finally{
                if($directTcp){$directTcp.Stop()}
                if($directUdp){$directUdp.Dispose()}
                if($upstream){$upstream.Stop()}
                try{if($scope){$scope.Dispose()}}finally{
                    try{
                        if($fixtureName){
                            foreach($installed in @(Get-AppxPackage -Name $fixtureName -AllUsers)){
                                if($installed.Name -cne $fixtureName -or $installed.Version.ToString() -cne '1.0.0.0'){
                                    throw 'Unexpected package during fixture cleanup.'
                                }
                                Remove-AppxPackage -Package $installed.PackageFullName -AllUsers
                            }
                            if(@(Get-AppxPackage -Name $fixtureName -AllUsers).Count){throw 'The isolated MSIX fixture remains registered.'}
                        }
                    }finally{
                        [IO.File]::Delete($relay)
                        [IO.File]::Delete($moved)
                        [IO.File]::Delete($image)
                        if(-not [IO.Directory]::GetFileSystemEntries($folder).Length){[IO.Directory]::Delete($folder,$false)}
                    }
                }
            }
        }
    }
}
Write-Output "RESULT ScopedRelay=Verified NewPath=Contained SystemDnsWithRelayOpen=Denied Cleanup=Verified Packaged=$([bool]$Packaged) CloseSignalBeforeExpiry=Verified"
