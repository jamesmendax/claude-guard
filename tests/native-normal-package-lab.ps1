#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Directory,
    [string]$MakeAppxPath,
    [switch]$ControlOnly,
    [switch]$Sandboxie,
    [switch]$InstalledSandboxie,
    [switch]$CandidateController,
    [switch]$AfterUpgrade
)

$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$guardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if($Sandboxie -and $ControlOnly){throw 'The Sandboxie case requires the protected package fixture.'}
if($InstalledSandboxie -and -not $Sandboxie){throw 'Installed-driver testing requires the Sandboxie package fixture.'}
if($CandidateController -and -not $InstalledSandboxie){throw 'Candidate controller testing requires the installed-driver fixture.'}
if($AfterUpgrade -and -not $CandidateController){throw 'The post-upgrade regression requires the registered replacement controller fixture.'}
if($ControlOnly){
    if(-not $MakeAppxPath){throw 'Provide the Windows SDK makeappx.exe with -MakeAppxPath.'}
    $makeAppx=(Get-Item -LiteralPath $MakeAppxPath -ErrorAction Stop).FullName
    $stage=Join-Path $tempRoot ('guard-normal-control-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($stage)
}else{
    if($MakeAppxPath){throw 'The protected lab requires the SDK tool from its administrator-owned stage.'}
    $admin=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'An approved Windows administrator session is required.'}
    $stage=(Get-Item -LiteralPath $Directory -Force).FullName
    if((Split-Path -Parent $stage) -ine $guardRoot -or (Split-Path -Leaf $stage) -cnotmatch '^native-acceptance-[a-f0-9]{32}$' -or
        $PSScriptRoot -ine (Join-Path $stage 'tests')){throw 'A protected native acceptance stage is required.'}
    foreach($path in $guardRoot,$stage,$PSScriptRoot){
        $item=Get-Item -LiteralPath $path -Force
        $acl=Get-Acl -LiteralPath $path
        $trusted=@('S-1-5-18','S-1-5-32-544')
        $write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
            @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
                $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $write) -and $_.IdentityReference.Value -notin $trusted
            }).Count){throw 'The package test stage is not administrator controlled.'}
    }
    $makeAppx=Join-Path $stage 'sdk\makeappx.exe'
}
. (Join-Path $repo 'package\guard-common.ps1')
$sandboxDirectory=$null
$sandboxStarted=$false
if($Sandboxie){
    if($InstalledSandboxie){
        . (Join-Path $PSScriptRoot 'native-installed-sandboxie-fixture.ps1')
        $sandboxDirectory=Join-Path $guardRoot 'daily\sandboxie'
    }else{
        . (Join-Path $PSScriptRoot 'native-sandboxie-fixture.ps1')
        $sandboxDirectory=Join-Path $stage 'sandboxie'
    }
}
$loop=[Net.IPAddress]::Loopback
$record=[ordered]@{
    ControlOnly=[bool]$ControlOnly;NormalEntry=$false;Control=$false;HealthyProxy=$false;ParentDirectBlocked=$false
    ChildDirectBlocked=$false;ChildIdentity=$null;DnsBefore=$null;DnsProtected=$null;DnsBlocked=$false
    OutageDetected=$false;FirewallClosed=$false;ExistingFlowBlocked=$false;NewFlowBlocked=$false
    ExitedAfterBlock=$false;ManualRecovery=$false;Cleanup=$false;Passed=$false;Phase='Setup';Error=$null;CleanupErrors=@()
    Sandboxie=[bool]$Sandboxie;SandboxiePolicyVerified=$false;SandboxiePackageVerified=$false;SandboxieRemoved=$false
    DnsPolicyBefore=$null;DnsPolicyProtected=$null;DnsPolicyBlocked=$false
    PersistentPolicy=$null;UpgradeVerified=$false;Upgrade=$null
}
if($InstalledSandboxie){
    $record.InstalledSandboxie=$true
    $record.SandboxieRestored=$false
}
if($CandidateController){$record.CandidateController=$null}
$package=$null; $fixtureName=$null; $session=$null; $policy=$null; $echo=$null; $forward=$null
$fixtureImages=@()
$directTcp=$null; $directUdp=$null; $dnsSocket=$null
$dnsPolicyTag=$null; $leaseSignal=$null
$receiptPath=Join-Path $stage 'normal-package-receipt.json'

function Close-NormalFixture($Session) {
    if(-not $Session){return}
    try{
        if($Session.Process -and -not $Session.Process.HasExited){
            try{if($Session.Writer){$Session.Writer.WriteLine('quit')}}catch{}
            if(-not $Session.Process.WaitForExit(2000)){
                $Session.Process.Kill()
                if(-not $Session.Process.WaitForExit(2000)){throw 'The fixture process did not exit during cleanup.'}
            }
        }
    }finally{
        if($Session.Pipe){$Session.Pipe.Dispose()}
        if($Session.Process){$Session.Process.Dispose()}
    }
}
function Read-NormalReply($Session,[int]$Milliseconds=7000) {
    $read=$Session.Reader.ReadLineAsync()
    if(-not $read.Wait($Milliseconds)){throw 'The controlled package process timed out.'}
    if([string]::IsNullOrEmpty($read.Result)){throw 'The controlled package process closed its test pipe.'}
    if($read.Result.StartsWith('ERROR|')){throw "The controlled package process reported $($read.Result)."}
    $read.Result
}
function Invoke-NormalCommand([string]$Command) {
    $session.Writer.WriteLine($Command)
    Read-NormalReply $session
}
function Start-NormalFixture {
    $nonce=[guid]::NewGuid().ToString('N')
    $id=if($ControlOnly){'Unpackaged'}else{$package.PackageFullName}
    $arguments="session $nonce $id"
    $client=[pscustomobject]@{Pipe=[IO.Pipes.NamedPipeServerStream]::new("GuardNormalPackage-$nonce",'InOut',1,'Byte','Asynchronous');Process=$null;StartedUtc=$null;Reader=$null;Writer=$null}
    try{
        $pending=$client.Pipe.BeginWaitForConnection($null,$null)
        if($ControlOnly){
            $start=[Diagnostics.ProcessStartInfo]::new($image,$arguments)
            $start.UseShellExecute=$false; $start.CreateNoWindow=$true
            $client.Process=[Diagnostics.Process]::Start($start)
        }else{
            $pidReceipt=[GuardMsixProbe]::Activate($package.PackageFamilyName+'!Desktop',$arguments)
            if(-not $pidReceipt){throw 'Windows returned no activation process.'}
        }
        if(-not $pending.AsyncWaitHandle.WaitOne(7000)){throw 'The normal package entry did not connect to its test pipe.'}
        $client.Pipe.EndWaitForConnection($pending)
        $peer=[GuardMsixProbe]::PipeClientId($client.Pipe)
        if($ControlOnly -and $peer -ne $client.Process.Id){throw 'The control pipe does not belong to the launched fixture.'}
        if(-not $ControlOnly){
            $started=[Diagnostics.Process]::GetProcessById($peer)
            try{
                $startedImage=$started.MainModule.FileName
                if(-not $startedImage -or ($startedImage -ine $image -and
                    (Get-GuardFinalPath $startedImage) -ine (Get-GuardFinalPath $image))){
                    throw 'The peer of the Store activation was not the registered fixture image.'
                }
                # An external observer needs a handle held across exit to read Windows' exact exit time.
                if($CandidateController -and $started.get_Handle() -eq [IntPtr]::Zero){
                    throw 'The Store fixture exit time could not be observed.'
                }
                $client.StartedUtc=$started.StartTime.ToUniversalTime()
                $client.Process=$started
            }
            catch{$started.Dispose();throw}
        }
        $client.Reader=[IO.StreamReader]::new($client.Pipe)
        $client.Writer=[IO.StreamWriter]::new($client.Pipe,[Text.UTF8Encoding]::new($false));$client.Writer.AutoFlush=$true
        if((Read-NormalReply $client) -cne "READY|$id"){throw 'The fixture identity did not match its normal package registration.'}
        if($sandboxStarted){
            $box = if($InstalledSandboxie){
                [GuardInstalledSandboxieFixtureReadback]::Box($client.Process.Id)
            }else{[GuardSandboxieFixtureReadback]::Box($client.Process.Id)}
            if($box -cne $sandboxieBox){throw 'The activated Windows package is outside the configured sandbox.'}
        }
        $client
    }catch{Close-NormalFixture $client;throw}
}
function Renew-NormalPackageLease {
    try{
        $verified = if($InstalledSandboxie){
            $native = Get-GuardSandboxieNative $sandboxDirectory
            $native::RequireReady()
            [GuardInstalledSandboxieFixtureReadback]::Box($session.Process.Id) -ceq $sandboxieBox
        }else{
            [GuardSandboxieFixtureReadback]::DriverStatus() -eq 0 -and
                [GuardSandboxieFixtureReadback]::Box($session.Process.Id) -ceq $sandboxieBox
        }
    }catch{$verified=$false}
    if(-not $verified){
        $policy.Close()
        throw 'The package requires verified Sandboxie containment before the relay gate can open.'
    }
    $policy.OpenUntil([datetime]::UtcNow.AddSeconds(14),$leaseSignal)
}
function Read-DirectPackets {
    Start-Sleep -Milliseconds 150
    $tcpCount=0; $udpCount=0
    while($directTcp.Pending()){
        $client=$directTcp.AcceptTcpClient()
        try{$tcpCount++}finally{$client.Dispose()}
    }
    while($directUdp.Available -gt 0){
        $remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $packet=$directUdp.Receive([ref]$remote)
        if($packet.Length -eq 1 -and $packet[0] -eq 0x44 -and [Net.IPAddress]::IsLoopback($remote.Address)){$udpCount++}
    }
    [pscustomobject]@{Tcp=($tcpCount -gt 0);Udp=($udpCount -gt 0);TcpCount=$tcpCount;UdpCount=$udpCount}
}
function Test-NormalRelay {
    $arguments=if($CandidateController){'"'+(Join-Path $PSScriptRoot 'exit-observer-fixture.mjs')+'" echo '+$relayPort}else{"observer $relayPort"}
    $start=[Diagnostics.ProcessStartInfo]::new($observer,$arguments)
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $probe=[Diagnostics.Process]::Start($start)
    try{
        if(-not $probe.WaitForExit(3500)){throw 'The test relay observer timed out.'}
        if($probe.ExitCode -notin 0,1){throw 'The test relay observer failed to run.'}
        $probe.ExitCode -eq 0
    }finally{
        try{if(-not $probe.HasExited){$probe.Kill();$null=$probe.WaitForExit(2000)}}finally{$probe.Dispose()}
    }
}
function Get-NormalDnsPolicy([string]$Name) {
    try{Get-DnsClientNrptPolicy -Effective -Namespace $Name -ErrorAction Stop}
    catch{if($_.FullyQualifiedErrorId -notlike 'WIN32 4312,Get-DnsClientNrptPolicy'){throw}}
}
function Confirm-NormalDnsRoute([string]$Name) {
    $effective=@(Get-NormalDnsPolicy $Name)
    if($effective.Count -ne 1 -or $Name -notin @($effective[0].Namespace) -or
        @($effective[0].NameServers).Count -ne 1 -or @($effective[0].NameServers)[0] -ne $dnsAddress -or
        $effective[0].DirectAccessEnabled -eq $true){throw 'The exact synthetic DNS name has no exclusive local resolver.'}
}
function Invoke-NormalDns([string]$Label,[switch]$WindowsPolicy) {
    $name="$Label.g$dnsId.test"
    if($WindowsPolicy){
        Confirm-NormalDnsRoute $name
        $resolver='WindowsPolicy'
    }else{
        if(@(Get-NormalDnsPolicy $name).Count){throw 'A host DNS policy already applies to the synthetic test name.'}
        $resolver=$dnsAddress
    }
    $wire=[Collections.Generic.List[byte]]::new()
    foreach($part in $name.Split('.')){$wire.Add([byte]$part.Length);$wire.AddRange([Text.Encoding]::ASCII.GetBytes($part))}
    $wire.AddRange([byte[]](0,0,1,0,1));$question=$wire.ToArray()
    $expected=[Text.Encoding]::ASCII.GetString($question)
    $session.Writer.WriteLine("dns|$name.|$resolver")
    $pending=$session.Reader.ReadLineAsync()
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $seen=$false
    $finishedAt=$null
    while($watch.ElapsedMilliseconds -lt 10000){
        if($dnsSocket.Available){
            $from=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
            $bytes=$dnsSocket.Receive([ref]$from)
            if([Net.IPAddress]::IsLoopback($from.Address) -and $bytes.Length -ge (12+$question.Length) -and
                ($bytes[2] -band 128) -eq 0 -and $bytes[4] -eq 0 -and $bytes[5] -eq 1 -and
                [Text.Encoding]::ASCII.GetString($bytes,12,$question.Length) -ieq $expected){
                $seen=$true
                $reply=[byte[]](@($bytes[0],$bytes[1],129,128,0,1,0,1,0,0,0,0)+
                    $bytes[12..(11+$question.Length)]+@(192,12,0,1,0,1,0,0,0,0,0,4,192,0,2,53))
                $null=$dnsSocket.Send($reply,$reply.Length,$from)
            }
        }else{
            if($pending.IsCompleted){
                if($null -eq $finishedAt){$finishedAt=$watch.ElapsedMilliseconds}
                if($watch.ElapsedMilliseconds-$finishedAt -ge 500){break}
            }
            Start-Sleep -Milliseconds 15
        }
    }
    $code=0
    if(-not $pending.IsCompleted -or -not [int]::TryParse($pending.Result,[ref]$code)){throw 'The synthetic DNS request did not report a result.'}
    if($WindowsPolicy){Confirm-NormalDnsRoute $name}
    [pscustomobject]@{Packet=$seen;ExitCode=$code}
}

try{
    $packed=& (Join-Path $PSScriptRoot 'native-msix-upgrade-lab.ps1') -MakeAppx $makeAppx -Directory $stage -PackOnly -NormalRelayVariant -IncludeUpgrade:$Sandboxie
    if($packed.Name -cnotmatch '^GuardMsixFixture\.[a-f0-9]{32}$'){throw 'Invalid generated package name.'}
    $image=$packed.Image
    if(-not $ControlOnly){
        if(@(Get-AppxPackage -Name $packed.Name -AllUsers).Count){throw 'The generated package name is already registered.'}
        $fixtureName=$packed.Name
        Add-AppxPackage -Path $packed.File -AllowUnsigned
        $installed=@(Get-AppxPackage -Name $fixtureName | Where-Object {$_.Name -ceq $fixtureName -and $_.Version.ToString() -ceq '1.0.0.0'})
        if($installed.Count -ne 1){throw 'The intended full-trust package was not registered.'}
        $package=$installed[0]
        $image=Join-Path $package.InstallLocation 'fixture-desktop.exe'
        $fixtureImages+=,$image
        if((Get-FileHash -LiteralPath $image).Hash -cne (Get-FileHash -LiteralPath $packed.Image).Hash){throw 'The installed fixture image changed.'}
    }
    $observer=Join-Path $stage 'normal-fixture-observer.exe'
    if($CandidateController){
        $installedObserver=Join-Path $guardRoot 'daily\guard-exit-observer.exe'
        Assert-GuardSandboxieAdministratorPath $installedObserver
        $expectedObserver=(Read-GuardDailyRecord 'daily-provisioned.json').ObserverSha256
        if((Get-FileHash -LiteralPath $installedObserver).Hash -cne $expectedObserver){throw 'Installed observer checksum changed.'}
        [IO.File]::Copy($installedObserver,$observer)
        if((Get-FileHash -LiteralPath $observer).Hash -cne $expectedObserver){throw 'Staged observer checksum changed.'}
    }else{[IO.File]::Copy($packed.Image,$observer)}
    $controlChild=Join-Path $stage ('guard-new-helper-'+[guid]::NewGuid().ToString('N')+'.exe')
    [IO.File]::Copy($packed.Image,$controlChild)
    $relay=Join-Path $stage 'normal-fixture-relay.exe'
    $compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /platform:x64 /warnaserror+ "/out:$relay" (Join-Path $PSScriptRoot 'loopback-probe.cs')
    if($LASTEXITCODE -ne 0){throw 'The loopback relay failed to compile.'}
    $sources=@('msix-normal-package-client.cs','msix-identity-probe.cs','native-process-scope-client.cs','native-local-dns-client.cs','loopback-lab.cs' |
        ForEach-Object {Join-Path $PSScriptRoot $_})
    Add-Type -Path (@((Join-Path $repo 'package\guard-wfp.cs'))+$sources)
    if($CandidateController){
        . (Join-Path $PSScriptRoot 'native-store-prestage-fixture.ps1')
    }
    $echo=[GuardNormalEchoWitness]::new()
    $relayPort=[GuardLoopbackLab]::FindPrivatePort()
    $forward=[GuardLoopbackLab]::StartRelay($relay,$relayPort,$echo.Port)
    $directTcp=[Net.Sockets.TcpListener]::new($loop,0)
    $directTcp.ExclusiveAddressUse=$true; $directTcp.Start()
    $directPort=$directTcp.LocalEndpoint.Port
    $directUdp=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $directUdp.ExclusiveAddressUse=$true; $directUdp.Client.Bind([Net.IPEndPoint]::new($loop,$directPort))
    $dnsId=[guid]::NewGuid().ToString('N')
    $dnsAddress="127.21.$([Convert]::ToByte($dnsId.Substring(0,2),16)).$((([Convert]::ToByte($dnsId.Substring(2,2),16))%254)+1)"
    $dnsSocket=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $dnsSocket.ExclusiveAddressUse=$true; $dnsSocket.Client.Bind([Net.IPEndPoint]::new([ipaddress]$dnsAddress,53))
    $null=$dnsSocket.Client.IOControl(-1744830452,[byte[]]@(0,0,0,0),$null)
    if($Sandboxie){
        $dnsPolicyNames=@("policybefore.g$dnsId.test","policyblocked.g$dnsId.test","upgraded.g$dnsId.test")
        foreach($name in $dnsPolicyNames){
            if(@(Get-NormalDnsPolicy $name).Count){throw 'The intended synthetic DNS route already exists.'}
        }
        $dnsPolicyTag="ClaudeGuardDns-$dnsId"
        Add-DnsClientNrptRule -Namespace $dnsPolicyNames -NameServers $dnsAddress -DisplayName $dnsPolicyTag -Comment $dnsPolicyTag | Out-Null
    }

    $record.Phase='PositiveControls'
    $session=Start-NormalFixture
    $record.NormalEntry=-not $ControlOnly
    if((Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){throw 'The direct positive control did not run.'}
    $main=Read-DirectPackets
    $null=Invoke-NormalCommand "child|$controlChild|$directPort"
    $child=Read-DirectPackets
    $record.DnsBefore=Invoke-NormalDns 'before'
    if($Sandboxie){
        $record.DnsPolicyBefore=Invoke-NormalDns 'policybefore' -WindowsPolicy
        if(-not $record.DnsPolicyBefore.Packet -or $record.DnsPolicyBefore.ExitCode -ne 0){throw 'The ordinary Windows DNS query did not reach its local test resolver.'}
    }
    if(-not $main.Tcp -or -not $main.Udp -or -not $child.Tcp -or -not $child.Udp -or
        -not $record.DnsBefore.Packet -or $record.DnsBefore.ExitCode -ne 0 -or (Invoke-NormalCommand "open|$relayPort") -cne 'Echo'){
        throw 'The relay, direct child, or DNS positive control did not reach its receiver.'
    }
    $record.Control=$true
    if($CandidateController){
        $record.StorePrestage=Test-GuardNativeStorePrestage $stage $makeAppx $package $directPort $relayPort
        if($record.StorePrestage.Passed -ne $true){throw 'The Store-package future-path first-packet acceptance failed.'}
    }
    if(-not $ControlOnly){
        $record.Phase='ProtectedPackage'
        Close-NormalFixture $session; $session=$null
        $sid=[GuardMsixProbe]::PackageSid($package.PackageFamilyName)
        if($Sandboxie){
            $record.Phase='InstallClosedPackagePolicy'
            $deployment=[guid]::NewGuid()
            $plan=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage(
                [string[]]@($image),[string[]]@($image),[string[]]@($sid),$null,$sid,
                $relay,[uint16]$relayPort,'127.0.0.1',[uint16]$echo.Port,$observer
            ).WithEarlyBootBlocks().ForPersistentUse($deployment)
            if($CandidateController){$plan=$plan.WithRegisteredPackageAdmission([string[]]@($image))}
            $record.PersistentPolicy=[ordered]@{
                Deployment=$deployment;Sublayer=$plan.PersistentSublayer;AssignedWeight=$null
                Image=$image;PackageSid=$sid;Relay=$relay;RelayPort=$relayPort;Observer=$observer
                Upstream='127.0.0.1';UpstreamPort=$echo.Port;BaselineKeys=$plan.GetBaselineKeys();BootKeys=$plan.GetBootKeys()
                BootRulesReadback=$null;ClosedBeforeDriver=$false;Removed=$false
            }
            if($InstalledSandboxie){$record.PersistentPolicy.ClosedBeforeContainment=$false}
            # Keep the rollback identity in the protected stage before the WFP transaction commits.
            $saveWeight=[Action[uint16]]{
                param([uint16]$Weight)
                $record.PersistentPolicy.AssignedWeight=$Weight
                $record | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $receiptPath -Encoding UTF8
            }
            $assignedWeight=[ClaudeGuard.Network.WindowsPolicySession]::InstallPersistent($plan,$saveWeight)
            $record.PersistentPolicy.BootRulesReadback=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($plan,$assignedWeight)
            if($plan.BootCount -eq 0 -or $record.PersistentPolicy.BootRulesReadback -ne $plan.BootCount){
                throw 'The test package baseline lost its early boot blocks.'
            }
            $policy=[ClaudeGuard.Network.WindowsPolicySession]::AttachPersistent($plan,$assignedWeight)
            $policy.Close()

            $record.Phase=if($InstalledSandboxie){'ClosedBeforeContainment'}else{'ClosedBeforeDriver'}
            if(-not $InstalledSandboxie -and (Get-Service -Name SbieDrv,SbieSvc -ErrorAction SilentlyContinue)){
                throw 'The no-driver test requires Sandboxie to be absent.'
            }
            if(-not (Test-NormalRelay)){throw 'The relay witness is not healthy with the baseline closed.'}
            $session=Start-NormalFixture
            $relayBlocked=(Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable'
            if((Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){throw 'The closed baseline direct probe did not run.'}
            $closed=Read-DirectPackets
            $closedBeforeContainment=$relayBlocked -and -not $closed.Tcp -and -not $closed.Udp
            $record.PersistentPolicy[$record.Phase]=$closedBeforeContainment
            if(-not $closedBeforeContainment){throw 'The package sent a packet without its relay permit and Sandboxie containment.'}
            Close-NormalFixture $session; $session=$null

            if($InstalledSandboxie){
                $record.Phase='UseInstalledSandboxie'
                Start-GuardInstalledSandboxieFixture $stage $package.InstallLocation $relayPort
            }else{
                $record.Phase='LoadSandboxie'
                Start-GuardSandboxieFixture $sandboxDirectory $package.InstallLocation $relayPort
            }
            $record.SandboxiePolicyVerified=$true
            $sandboxStarted=$true
            $leaseSignal=[Threading.ManualResetEvent]::new($false)
        }else{
            $plan=[GuardLoopbackLab]::CreateNormalPackagePlan($image,$sid,$relay,[uint16]$relayPort,[uint16]$echo.Port)
            $policy=[ClaudeGuard.Network.WindowsPolicySession]::new($plan)
            $policy.Open()
        }
        $record.Phase='ProtectedPackage'
        $session=Start-NormalFixture
        $record.SandboxiePackageVerified=$sandboxStarted
        if($Sandboxie){Renew-NormalPackageLease}
        $record.HealthyProxy=(Invoke-NormalCommand "open|$relayPort") -ceq 'Echo'
        if($Sandboxie){Renew-NormalPackageLease}
        if((Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){throw 'The protected direct probe did not run.'}
        $main=Read-DirectPackets
        $record.ParentDirectBlocked=-not $main.Tcp -and -not $main.Udp
        $moved=Join-Path $stage ('guard-new-helper-'+[guid]::NewGuid().ToString('N')+'.exe')
        [IO.File]::Copy($packed.Image,$moved)
        $childReceipt=@((Invoke-NormalCommand "child|$moved|$directPort") -split '\|')
        $child=Read-DirectPackets
        if($childReceipt.Count -eq 2 -and $childReceipt[0] -ceq 'ChildAttempted' -and $childReceipt[1] -ceq 'Unpackaged'){
            $record.ChildIdentity=$childReceipt[1]
            $record.ChildDirectBlocked=-not $child.Tcp -and -not $child.Udp
        }
        if($Sandboxie){Renew-NormalPackageLease}
        $record.DnsProtected=Invoke-NormalDns 'container'
        $record.DnsBlocked=-not $record.DnsProtected.Packet -and $record.DnsProtected.ExitCode -in 5,10013,1460,11002
        if($Sandboxie){
            Renew-NormalPackageLease
            $record.DnsPolicyProtected=Invoke-NormalDns 'policyblocked' -WindowsPolicy
            $record.DnsPolicyBlocked=-not $record.DnsPolicyProtected.Packet -and $record.DnsPolicyProtected.ExitCode -in 5,10013,1460,11002
            Renew-NormalPackageLease
        }
        $record.Phase='Outage'
        if(-not $record.HealthyProxy -or -not (Test-NormalRelay)){throw 'A healthy proxy was not available for the outage test.'}
        $echo.Paused=$true
        $record.OutageDetected=-not (Test-NormalRelay)
        if(-not $record.OutageDetected){throw 'The observer did not detect the synthetic outage.'}
        $shutdown=Stop-GuardDailySession @{
            CloseGate={
                $policy.Close(); $record.FirewallClosed=$true
                # Restore the witness without restoring the app permit so an
                # unavailable upstream cannot explain the blocked packets.
                $echo.Paused=$false
                if(-not (Test-NormalRelay)){throw 'The independent relay control did not recover.'}
                $record.ExistingFlowBlocked=(Invoke-NormalCommand 'existing') -ceq 'Unavailable'
                $record.NewFlowBlocked=(Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable'
                $true
            }
            Snapshot={if(-not $session.Process.HasExited){[pscustomobject]@{Id=$session.Process.Id;Start=$session.Process.StartTime.ToUniversalTime().Ticks}}}
            RequestClose={param($entry) $session.Writer.WriteLine('quit')}
            Wait={param($ms) $null=$session.Process.WaitForExit($ms)}
            ForceStop={param($entry) $session.Process.Kill();$null=$session.Process.WaitForExit(2000)}
        }
        $record.ExitedAfterBlock=$shutdown.NetworkBlocked -and $shutdown.Exited -and $record.ExistingFlowBlocked -and $record.NewFlowBlocked
        if($shutdown.Exited){
            Close-NormalFixture $session; $session=$null
            if(-not $Sandboxie){$policy.Open()}
            Start-Sleep -Milliseconds 500
            $automatic=@(Get-Process -Name fixture-desktop -ErrorAction SilentlyContinue | Where-Object {$_.Path -ieq $image})
            if(-not $automatic.Count){
                $session=Start-NormalFixture
                if($Sandboxie){
                    $null=$leaseSignal.Reset()
                    Renew-NormalPackageLease
                }
                $record.ManualRecovery=(Invoke-NormalCommand "open|$relayPort") -ceq 'Echo'
            }
        }
        if($CandidateController){
            if(-not $record.ManualRecovery -or -not $record.ParentDirectBlocked -or -not $record.ChildDirectBlocked -or
                -not $record.DnsBlocked -or -not $record.DnsPolicyBlocked -or -not $record.ExitedAfterBlock){
                throw 'The installed-driver fixture must pass isolation and manual recovery before the upgrade.'
            }
        }
        if($Sandboxie -and $record.ManualRecovery){
            $record.Phase='PackageUpgrade'
            $family=$package.PackageFamilyName
            $record.Upgrade=[ordered]@{NewInstallationPath=$false;Sandboxed=$false;RelayBlocked=$false;DirectBlocked=$false
                DnsBlocked=$false;DnsReceipt=$null}
            if($CandidateController){
                $scope=Get-GuardNativeStorePackagePrestage $package $packed $stage
                $packagePrestage=$null
                if(-not $session){$session=Start-NormalFixture}
                $null=$leaseSignal.Reset()
                Renew-NormalPackageLease
                if((Invoke-NormalCommand "open|$relayPort") -cne 'Echo'){throw 'The old package was not admitted before preprotection.'}
                $prestageControl=Start-GuardNativeStorePathBlocks $scope.Paths $image (Join-Path $stage 'store-old-session-control.json') $scope.Device
                try{
                    $record.Upgrade.OldConnectedDuringPrestage=$prestageControl.Journal.Verified -and
                        -not $session.Process.HasExited -and (Invoke-NormalCommand 'existing') -ceq 'Echo' -and
                        (Invoke-NormalCommand "new|$relayPort") -ceq 'Echo'
                    if(-not $record.Upgrade.OldConnectedDuringPrestage){throw 'Preprotection interrupted the old Store session.'}
                }finally{Stop-GuardNativeStorePathBlocks $prestageControl}
                $record.Upgrade.ControlRemovedBeforeDeployment=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount(
                    $prestageControl.Plan,[uint16]$prestageControl.Journal.Weight,$true) -eq 0
                if(-not $record.Upgrade.ControlRemovedBeforeDeployment){
                    throw 'The manual control blocks were still present before the real upgrade.'
                }
                $null=Read-DirectPackets
                Renew-NormalPackageLease
                $record.Upgrade.OldAdmissionBeforeFirst=$policy.ReadLiveAdmissionCount()
                Close-NormalFixture $session; $session=$null
                $record.Upgrade.ActualPrestage=Invoke-GuardNativeStoreUpgradeObservation $scope $directPort $relayPort ([ref]$packagePrestage)
                $record.Upgrade.OldAdmissionAfterFirst=$policy.ReadLiveAdmissionCount()
                $packets=Read-DirectPackets
                $record.Upgrade.FirstTcpUdpBlocked=-not $packets.Tcp -and -not $packets.Udp
                Stop-GuardNativeStorePathBlocks $packagePrestage
                $record.Upgrade.OldAdmissionBeforeFallback=$policy.ReadLiveAdmissionCount()
                $record.Upgrade.NoPrestageAttempt=Invoke-GuardNativeStoreUpgradeWithoutPrestage $scope $directPort $relayPort
                $record.Upgrade.OldAdmissionAfterFallback=$policy.ReadLiveAdmissionCount()
                $fallbackPackets=Read-DirectPackets
                $record.Upgrade.FallbackBlockedWithOldAdmission=$record.Upgrade.OldAdmissionBeforeFirst -gt 0 -and
                    $record.Upgrade.OldAdmissionAfterFirst -gt 0 -and $record.Upgrade.OldAdmissionBeforeFallback -gt 0 -and
                    $record.Upgrade.OldAdmissionAfterFallback -gt 0 -and
                    $record.Upgrade.NoPrestageAttempt.RelayResult -ceq 'Unavailable' -and -not $fallbackPackets.Tcp -and -not $fallbackPackets.Udp
                # Remove old permissions by handle even if the versioned
                # executable was already removed from WindowsApps.
                try{$policy.Dispose()}catch{
                    [ClaudeGuard.Network.WindowsPolicySession]::VerifyNoPersistentAdmission($plan,[uint16]$assignedWeight)
                }finally{$policy=$null}
            }else{
                $policy.Close()
                Close-NormalFixture $session; $session=$null
                $policy.Dispose(); $policy=$null
                Add-AppxPackage -Path $packed.UpgradeFile -AllowUnsigned
            }
            $installed=@(Get-AppxPackage -Name $fixtureName | Where-Object {$_.Name -ceq $fixtureName})
            if($installed.Count -ne 1 -or $installed[0].Version.ToString() -cne '2.0.0.0' -or
                $installed[0].InstallLocation -ieq $package.InstallLocation -or $installed[0].PackageFamilyName -cne $family){
                throw 'The substitute did not move to the next registered version of the same package.'
            }
            $package=$installed[0]
            $image=Join-Path $package.InstallLocation 'fixture-desktop.exe'
            $fixtureImages+=,$image
            if((Get-FileHash -LiteralPath $image).Hash -cne (Get-FileHash -LiteralPath $packed.Image).Hash -or -not (Test-NormalRelay)){
                throw 'The upgraded image or independent relay control could not be verified.'
            }
            if($CandidateController){
                $physicalRoot=Get-GuardStorePhysicalPackageRoot $package.InstallLocation
                $physicalImage=Get-GuardStorePhysicalImage $package.InstallLocation $physicalRoot $image
                if($physicalImage -notin $scope.Paths){throw 'The replacement was installed at a different physical path.'}
                [ClaudeGuard.Network.GuardPolicy]::VerifyStorePathIdentity($physicalImage,$scope.Device)
                $record.Upgrade.FuturePathReadBack=$true
            }
            $session=Start-NormalFixture
            $record.Upgrade.NewInstallationPath=$true
            $record.Upgrade.Sandboxed=$true
            $record.Upgrade.RelayBlocked=(Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable'
            if((Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){throw 'The upgraded direct probe did not run.'}
            $upgradePackets=Read-DirectPackets
            $record.Upgrade.DirectBlocked=-not $upgradePackets.Tcp -and -not $upgradePackets.Udp
            $dns=Invoke-NormalDns 'upgraded' -WindowsPolicy
            $record.Upgrade.DnsReceipt=$dns
            if($dns.ExitCode -in 9,87){throw "The DNS test client rejected the upgraded substitute input ($($dns.ExitCode))."}
            $record.Upgrade.DnsBlocked=-not $dns.Packet -and $dns.ExitCode -in 5,10013,1460,11002
            $record.UpgradeVerified=$record.Upgrade.RelayBlocked -and $record.Upgrade.DirectBlocked -and $record.Upgrade.DnsBlocked
            if($CandidateController){
                Close-NormalFixture $session; $session=$null
                $renamed=Join-Path $package.InstallLocation 'fixture-helper-v2.exe'
                $physicalHelper=Get-GuardStorePhysicalImage $package.InstallLocation $physicalRoot $renamed
                if($physicalHelper -in $scope.Paths -or
                    (Test-Path -LiteralPath (Join-Path $package.InstallLocation 'fixture-helper.exe'))){
                    throw 'The replacement test package did not have the expected renamed helper.'
                }
                $newDeployment=[guid]::NewGuid()
                $newPlan=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage(
                    [string[]]@($image,$renamed),[string[]]@($image),[string[]]@($sid),$null,$sid,
                    $relay,[uint16]$relayPort,'127.0.0.1',[uint16]$echo.Port,$observer
                ).WithEarlyBootBlocks().ForPersistentUse($newDeployment)
                $newPlan=$newPlan.WithRegisteredPackageAdmission([string[]]@($image,$renamed))
                $replacementWorker=Join-Path $PSScriptRoot 'native-store-replacement-worker.ps1'
                Assert-GuardSandboxieAdministratorPath $replacementWorker
                . $replacementWorker
                $replacementReceipt=Join-Path $stage 'store-replacement-policy.json'
                $replacement=[ordered]@{
                    Version=1;Package=$package.PackageFullName;OldPackage=$scope.OldPackage
                    Family=$package.PackageFamilyName;PackageSid=$sid;PackageRoot=$package.InstallLocation
                    ImageSha256=(Get-FileHash -LiteralPath $packed.Image -Algorithm SHA256).Hash
                    OldPolicy=$record.PersistentPolicy;Deployment=$newDeployment
                    Sublayer=$newPlan.PersistentSublayer;BaselineKeys=$newPlan.GetBaselineKeys();BootKeys=$newPlan.GetBootKeys()
                    Weight=$null;Images=@($image,$renamed);Phase='Prepared';Removed=$false
                    InstallPid=$null;RecoverPid=$null;ReusedClosedRules=$false;OldAdmissionClosed=$false;BootRules=$null
                }
                if(Test-Path -LiteralPath $replacementReceipt){throw 'The isolated replacement journal already exists.'}
                Save-GuardAdministratorJson $replacementReceipt $replacement
                $install=Invoke-GuardNativeReplacementChild InstallAndInterrupt
                Assert-GuardDailyStatePath $replacementReceipt
                $interrupted=Read-GuardDailyJsonFile $replacementReceipt
                $record.Upgrade.InterruptedHandoff=[ordered]@{
                    InstallPid=$install.Pid;InstallExitCode=$install.ExitCode
                    PreCommitWeight=$interrupted.Weight;InterruptedPhase=$interrupted.Phase
                    OfflineWhileInterrupted=$false;OfflineAfterRecovery=$false;SameClosedRules=$false
                    OldAdmissionClosed=$false;RecoverPid=$null;BootRules=$null;CleanupVerified=$false
                }
                if($interrupted.Phase -cne 'InstallingClosed' -or $null -eq $interrupted.Weight -or $interrupted.InstallPid -ne $install.Pid){
                    throw 'The independent installer did not leave a recoverable interrupted journal.'
                }
                $session=Start-NormalFixture
                if((Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){throw 'The interrupted replacement direct probe did not run.'}
                $closedPackets=Read-DirectPackets
                $record.Upgrade.InterruptedHandoff.OfflineWhileInterrupted=-not $closedPackets.Tcp -and -not $closedPackets.Udp -and
                    (Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable' -and (Test-NormalRelay)
                $recover=Invoke-GuardNativeReplacementChild Recover
                Assert-GuardDailyStatePath $replacementReceipt
                $replacement=Read-GuardDailyJsonFile $replacementReceipt
                $record.Upgrade.InterruptedHandoff.RecoverPid=$recover.Pid
                $record.Upgrade.InterruptedHandoff.BootRules=$replacement.BootRules
                $record.Upgrade.InterruptedHandoff.OldAdmissionClosed=$replacement.OldAdmissionClosed -eq $true
                $record.Upgrade.InterruptedHandoff.SameClosedRules=$recover.Pid -ne $install.Pid -and
                    $replacement.InstallPid -eq $install.Pid -and $replacement.RecoverPid -eq $recover.Pid -and
                    $replacement.Phase -ceq 'RecoveredClosed' -and $replacement.ReusedClosedRules -eq $true -and
                    $replacement.Weight -eq $interrupted.Weight -and $replacement.BootRules -eq $newPlan.BootCount -and
                    $replacement.Sublayer -ceq $interrupted.Sublayer -and
                    ($replacement.BaselineKeys -join ',') -ceq ($interrupted.BaselineKeys -join ',') -and
                    ($replacement.BootKeys -join ',') -ceq ($interrupted.BootKeys -join ',')
                if((Invoke-NormalCommand "direct|$directPort") -cne 'Attempted'){throw 'The recovered replacement direct probe did not run.'}
                $recoveredPackets=Read-DirectPackets
                $record.Upgrade.InterruptedHandoff.OfflineAfterRecovery=-not $recoveredPackets.Tcp -and -not $recoveredPackets.Udp -and
                    (Invoke-NormalCommand "new|$relayPort") -ceq 'Unavailable' -and (Test-NormalRelay)
                if(-not $record.Upgrade.InterruptedHandoff.SameClosedRules -or -not $record.Upgrade.InterruptedHandoff.OldAdmissionClosed -or
                    -not $record.Upgrade.InterruptedHandoff.OfflineWhileInterrupted -or -not $record.Upgrade.InterruptedHandoff.OfflineAfterRecovery){
                    throw 'The interrupted replacement did not keep or recover a single verified closed policy.'
                }
                Close-NormalFixture $session; $session=$null
                Restore-GuardInstalledSandboxieFixture $stage
                Start-GuardInstalledSandboxieFixture $stage $package.InstallLocation $relayPort
                Stop-GuardNativeStorePathBlocks $packagePrestage
                [ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($plan,$assignedWeight)
                $policy=[ClaudeGuard.Network.WindowsPolicySession]::AttachPersistent($newPlan,[uint16]$replacement.Weight)
                $session=Start-NormalFixture
                $null=$leaseSignal.Reset()
                Renew-NormalPackageLease
                $record.Upgrade.NewConnectedAfterVerifiedHandoff=(Invoke-NormalCommand "open|$relayPort") -ceq 'Echo'
                $renamedResult=Invoke-NormalCommand "child|$renamed|$directPort"
                $renamedPackets=Read-DirectPackets
                $record.Upgrade.RenamedHelperBlocked=$renamedResult -like 'ChildAttempted|*' -and
                    -not $renamedPackets.Tcp -and -not $renamedPackets.Udp
                $record.UpgradeVerified=$record.UpgradeVerified -and $record.Upgrade.NewConnectedAfterVerifiedHandoff -and
                    $record.Upgrade.RenamedHelperBlocked -and $record.Upgrade.ActualPrestage.Passed -and
                    $record.Upgrade.ActualPrestage.First.RelayResult -ceq 'Unavailable' -and
                    $record.Upgrade.FirstTcpUdpBlocked -and $record.Upgrade.FallbackBlockedWithOldAdmission
                $record.Upgrade.RegisteredPackage=$package.PackageFullName
                $record.Upgrade.VerifiedUtc=[datetime]::UtcNow.ToString('o')
                Assert-DailyRevisionStoreUpgradeEvidence $record

                $record.Phase='CandidateController'
                Save-GuardAdministratorJson $receiptPath $record
                $scenarioPath=Join-Path $PSScriptRoot 'native-store-controller-scenarios.ps1'
                Assert-GuardSandboxieAdministratorPath $scenarioPath
                $results=@(. $scenarioPath)
                if($results.Count -ne 1){throw 'The candidate controller must return one scenario receipt.'}
                $record.CandidateController=$results[0]
                foreach($field in 'ProbeTimeoutNoExit','UpstreamFailureWhileAdapterUp','UpstreamClosedBeforeExit',
                    'BackendExitBlocksExistingAndNew','ManualRecovery','PausedExitConfirmed','PausedExitCleanupSignal',
                    'PausedExitClearedSandbox','PausedExitManualReopen'){
                    $value=$record.CandidateController.$field
                    if($value -isnot [bool] -or -not $value){throw "The candidate controller scenario failed: $field."}
                }
            }
        }
    }else{
        $echo.Paused=$true
        $record.OutageDetected=-not (Test-NormalRelay)
        $echo.Paused=$false
        $record.HealthyProxy=Test-NormalRelay
    }
    $record.Phase='Completed'
}catch{$record.Error=$_.Exception.Message}
finally{
    foreach($cleanup in @(
        {if($policy){$policy.Close()}},
        {Close-NormalFixture $session},
        {if($policy){$policy.Dispose()}},
        {if($prestageControl){Stop-GuardNativeStorePathBlocks $prestageControl}},
        {if($packagePrestage){Stop-GuardNativeStorePathBlocks $packagePrestage}},
        {if($leaseSignal){$leaseSignal.Dispose()}},
        {if($InstalledSandboxie){
            Restore-GuardInstalledSandboxieFixture $stage
            $record.SandboxieRestored=$true
        }},
        {if($null -ne $record.PersistentPolicy.AssignedWeight){
            if($InstalledSandboxie -and -not $record.SandboxieRestored){
                throw 'Sandboxie restoration has not been verified. The persistent test block was retained.'
            }
            if(@(Get-Process -Name fixture-desktop -ErrorAction SilentlyContinue | Where-Object {
                -not $_.HasExited -and (-not $_.Path -or $_.Path -iin $fixtureImages)
            }).Count){throw 'The test package is still running. The persistent block was retained.'}
            [ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($plan,[uint16]$record.PersistentPolicy.AssignedWeight)
            $record.PersistentPolicy.Removed=$true
        }},
        {if($replacementReceipt -and (Test-Path -LiteralPath $replacementReceipt)){
            if(-not $record.SandboxieRestored){throw 'Replacement protection was retained because the test sandbox was not cleanly restored.'}
            $null=Invoke-GuardNativeReplacementChild Remove
            Assert-GuardDailyStatePath $replacementReceipt
            $removed=Read-GuardDailyJsonFile $replacementReceipt
            if($removed.Removed -ne $true -or $removed.Phase -cne 'Removed'){
                throw 'The independently recovered replacement rules were not verified removed.'
            }
            if($record.Upgrade.InterruptedHandoff){$record.Upgrade.InterruptedHandoff.CleanupVerified=$true}
        }},
        {if($forward){$forward.Dispose()}},
        {if($echo){$echo.Dispose()}},
        {if($directTcp){$directTcp.Stop()}},
        {if($directUdp){$directUdp.Dispose()}},
        {if($dnsSocket){$dnsSocket.Dispose()}},
        {if($dnsPolicyTag){
            $owned=@(Get-DnsClientNrptRule | Where-Object {$_.DisplayName -ceq $dnsPolicyTag -and $_.Comment -ceq $dnsPolicyTag})
            foreach($rule in $owned){
                if(@($rule.Namespace).Count -ne $dnsPolicyNames.Count -or @($rule.Namespace | Where-Object {$_ -notin $dnsPolicyNames}).Count -or
                    @($rule.NameServers).Count -ne 1 -or @($rule.NameServers)[0] -ne $dnsAddress){
                    throw 'The temporary DNS rule changed scope.'
                }
                Remove-DnsClientNrptRule -Name $rule.Name -Force
            }
            foreach($name in $dnsPolicyNames){
                $until=[datetime]::UtcNow.AddSeconds(6)
                while(@(Get-NormalDnsPolicy $name).Count){
                    if([datetime]::UtcNow -ge $until){throw 'A synthetic DNS rule remains effective.'}
                    Start-Sleep -Milliseconds 150
                }
            }
        }},
        {if($fixtureName){
            foreach($p in @(Get-AppxPackage -Name $fixtureName -AllUsers)){
                if($p.Name -cne $fixtureName -or $p.Version.ToString() -cnotin '1.0.0.0','2.0.0.0'){throw 'Unexpected package during cleanup.'}
                Remove-AppxPackage -Package $p.PackageFullName -AllUsers
            }
            if(@(Get-AppxPackage -Name $fixtureName -AllUsers).Count){throw 'The test package remains registered.'}
        }},
        {if($ControlOnly){
            $target=[IO.Path]::GetFullPath($stage)
            if((Split-Path -Parent $target).TrimEnd('\') -ine $tempRoot.TrimEnd('\') -or
                (Split-Path -Leaf $target) -cnotmatch '^guard-normal-control-[a-f0-9]{32}$'){throw 'Invalid control cleanup location.'}
            [IO.Directory]::Delete($target,$true)
        }}
    )){try{& $cleanup}catch{$record.CleanupErrors+= $_.Exception.Message}}
    $record.Cleanup=$record.CleanupErrors.Count -eq 0
}
$initialClosed=if($InstalledSandboxie){$record.PersistentPolicy.ClosedBeforeContainment}else{$record.PersistentPolicy.ClosedBeforeDriver}
$record.Passed=-not $ControlOnly -and $record.NormalEntry -and $record.Control -and $record.HealthyProxy -and
    $record.ParentDirectBlocked -and $record.ChildDirectBlocked -and $record.DnsBlocked -and $record.OutageDetected -and
    $record.ExitedAfterBlock -and $record.ManualRecovery -and $record.Cleanup -and -not $record.Error -and
    (-not $Sandboxie -or ($record.SandboxiePolicyVerified -and $record.SandboxiePackageVerified -and $record.DnsPolicyBlocked -and $record.UpgradeVerified -and
        $initialClosed -and $record.PersistentPolicy.Removed)) -and (-not $InstalledSandboxie -or $record.SandboxieRestored)
$json=$record | ConvertTo-Json -Depth 5 -Compress
if(-not $ControlOnly){$json | Set-Content -LiteralPath $receiptPath -Encoding UTF8}
$json
if($ControlOnly){if(-not $record.Control -or -not $record.OutageDetected -or -not $record.HealthyProxy -or -not $record.Cleanup -or $record.Error){exit 1}}
elseif(-not $record.Passed){exit 1}
