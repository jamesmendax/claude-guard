#Requires -Version 5.1
$ErrorActionPreference='Stop'
$folder=Join-Path ([IO.Path]::GetTempPath()) ('guard-process-scope-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $folder
$image=Join-Path $folder 'fixture-parent.exe'
$moved=Join-Path $folder ('fixture-helper-'+[guid]::NewGuid().ToString('N')+'.exe')
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$tcp=$null
$udp=$null
$scope=$null

function Read-GuardWitness {
    $tcpBytes=@()
    $udpBytes=@()
    while($tcp.Pending()){
        $client=$tcp.AcceptTcpClient()
        try{
            $client.ReceiveTimeout=1000
            $tcpBytes+=,$client.GetStream().ReadByte()
        }finally{$client.Dispose()}
    }
    while($udp.Available -gt 0){
        $origin=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $bytes=$udp.Receive([ref]$origin)
        if([Net.IPAddress]::IsLoopback($origin.Address) -and $bytes.Length -eq 1){$udpBytes+=,$bytes[0]}
    }
    [pscustomobject]@{Tcp=($tcpBytes | Sort-Object) -join ',';Udp=($udpBytes | Sort-Object) -join ','}
}

function Invoke-GuardControl {
    $start=[Diagnostics.ProcessStartInfo]::new($image,('parent '+$port+' none "'+$moved+'"'))
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $process=[Diagnostics.Process]::Start($start)
    try{
        if(-not $process.WaitForExit(8000)){throw 'The unrestricted control did not finish.'}
        if($process.ExitCode -ne 0){throw "The unrestricted control returned $($process.ExitCode)."}
    }finally{
        try{if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(2000)}}finally{$process.Dispose()}
    }
    $seen=Read-GuardWitness
    if($seen.Tcp -ne '81,82' -or $seen.Udp -ne '81,82'){throw 'The TCP and UDP witnesses did not receive both control packets.'}
}

function Invoke-GuardContainer([bool]$LessPrivileged) {
    $code=$null
    $startError=$null
    try{
        $child=$scope.Start($image,('parent '+$port+' '+$scope.Identity.Value+' "'+$moved+'"'),$LessPrivileged)
        try{
            if($child.WaitForExit(12000)){$code=$child.ExitCode}
            else{$startError='The restricted fixture did not finish.'}
        }finally{$child.Dispose()}
    }catch [Management.Automation.MethodInvocationException]{
        $startError=$_.Exception.InnerException.Message
    }
    $seen=Read-GuardWitness
    [pscustomobject]@{
        LessPrivileged=$LessPrivileged;ExitCode=$code;StartError=$startError
        ParentAndHelperIdentityVerified=($null -ne $code -and $code -eq 0)
        TcpReached=[bool]$seen.Tcp;UdpReached=[bool]$seen.Udp
    }
}

function Test-GuardManualEntry([string]$Hash) {
    . (Join-Path $PSScriptRoot '..\package\guard-runtime.ps1')
    $entryProfile=[GuardFixtureAppContainer]::new($true)
    $entryEventName='Global\GuardFixture_Close_'+[guid]::NewGuid().ToString('N')
    $entryEvent=$null
    $previousScope=$env:GUARD_FIXTURE_EXPECTED_SCOPE
    $previousProxy=$env:GUARD_FIXTURE_EXPECTED_PROXY
    $previousMutex=$script:GuardDailyLaunchMutex
    try{
        $acl=Get-Acl -LiteralPath $folder
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($entryProfile.Identity,'ReadAndExecute',
            'ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $folder -AclObject $acl
        $entryEvent=[Threading.EventWaitHandle]::new($false,'ManualReset',$entryEventName)
        $entryGeneration='B'*64
        $script:GuardDailyLaunchMutex='Global\GuardFixture_Mutex_'+[guid]::NewGuid().ToString('N')
        $env:GUARD_FIXTURE_EXPECTED_SCOPE=$entryProfile.Identity.Value
        $env:GUARD_FIXTURE_EXPECTED_PROXY="--proxy-server=http://127.0.0.1:$port"
        function Get-GuardInventory { [pscustomobject]@{PreferredDesktop=$image;DesktopPaths=@($image)} }
        function Get-GuardDailyProcessEntries { @() }
        function Get-GuardDailyStatus {
            $ending=$entryEvent.WaitOne(0)
            [pscustomobject]@{CanLaunch=(-not $ending);Readiness='Fixture';Reason='Fixture';ProxyPort=$port
                ScopeName=$entryProfile.Name;ScopeSid=$entryProfile.Identity.Value;Generation=$entryGeneration
                DesktopHashes=@($Hash);CloseName=$entryEventName;Gate=$(if($ending){'Closed'}else{'Open'})
                Policy='Verified';RulesUtc=[datetime]::UtcNow}
        }
        Invoke-GuardDailyDesktop $false
        if(-not $entryEvent.WaitOne(0)){throw 'The manual entry did not request gate closure.'}
        return $true
    }finally{
        try{if($entryEvent){$entryEvent.Dispose()}}finally{
            $env:GUARD_FIXTURE_EXPECTED_SCOPE=$previousScope
            $env:GUARD_FIXTURE_EXPECTED_PROXY=$previousProxy
            $script:GuardDailyLaunchMutex=$previousMutex
            $entryProfile.Dispose()
        }
    }
}

function Test-GuardJobOwnerExit([string]$Hash) {
    $source=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\package\guard-app-container.cs')).Path
    $ownerCode=@'
$ErrorActionPreference='Stop'
Add-Type -Path '@SOURCE@'
$signal=[Threading.ManualResetEvent]::new($false)
$tree=[ClaudeGuard.Processes.GuardAppContainer]::StartVerified('@NAME@','@SID@','@IMAGE@','@HASH@','hold @SID@',$signal)
[Console]::WriteLine($tree.Id)
[Threading.Thread]::Sleep(15000)
'@
    $ownerCode=$ownerCode.Replace('@SOURCE@',$source.Replace("'","''")).Replace('@NAME@',$scope.Name).
        Replace('@SID@',$scope.Identity.Value).Replace('@IMAGE@',$image.Replace("'","''")).Replace('@HASH@',$Hash)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ownerCode))
    $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'powershell.exe'),
        ('-NoProfile -NonInteractive -EncodedCommand '+$encoded))
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $owner=[Diagnostics.Process]::Start($start)
    $worker=$null
    try{
        $line=$owner.StandardOutput.ReadLineAsync()
        $fixturePid=0
        if(-not $line.Wait(10000) -or -not [int]::TryParse($line.Result,[ref]$fixturePid) -or $fixturePid -le 0){
            throw 'The fixture launcher could not start its owned process.'
        }
        $worker=[Diagnostics.Process]::GetProcessById($fixturePid)
        if($worker.HasExited -or $worker.MainModule.FileName -ine $image){throw 'The fixture launcher did not own the expected live image.'}
        $owner.Kill()
        if(-not $owner.WaitForExit(3000) -or -not $worker.WaitForExit(3000)){
            throw 'The isolated process survived its launcher.'
        }
        return $true
    }finally{
        try{if(-not $owner.HasExited){$owner.Kill();$null=$owner.WaitForExit(3000)}}finally{
            $owner.Dispose()
            if($worker){$worker.Dispose()}
        }
    }
}

try{
    & $compiler /nologo /warnaserror+ /platform:x64 "/out:$image" (Join-Path $PSScriptRoot 'native-process-scope-client.cs')
    if($LASTEXITCODE -ne 0){throw 'Synthetic identity probe compilation failed.'}
    Add-Type -Path (Join-Path $PSScriptRoot '..\package\guard-app-container.cs'),(Join-Path $PSScriptRoot 'native-app-container.cs')
    $scope=[GuardFixtureAppContainer]::new()
    $acl=Get-Acl -LiteralPath $folder
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($scope.Identity,'ReadAndExecute',
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $folder -AclObject $acl
    [IO.File]::Copy($image,$moved)
    $tcp=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $tcp.ExclusiveAddressUse=$true
    $tcp.Start()
    $port=([Net.IPEndPoint]$tcp.LocalEndpoint).Port
    $udp=[Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    $udp.ExclusiveAddressUse=$true
    $udp.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,$port))
    Invoke-GuardControl
    $appContainer=Invoke-GuardContainer $false
    if(-not $appContainer.ParentAndHelperIdentityVerified -or $appContainer.TcpReached -or $appContainer.UdpReached){
        throw 'The contained parent or helper failed its identity or direct-traffic check.'
    }
    $lpac=Invoke-GuardContainer $true
    Invoke-GuardControl
    $hash=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash
    $signal=[Threading.ManualResetEvent]::new($false)
    $tree=$null
    try{
        $tree=[ClaudeGuard.Processes.GuardAppContainer]::StartVerified($scope.Name,$scope.Identity.Value,$image,$hash,
            ('park '+$scope.Identity.Value+' "'+$moved+'"'),$signal)
        if(-not $tree.WaitForExit(9000) -or $tree.ExitCode -ne 0 -or -not $tree.HasRunningProcesses){
            throw 'The new-path child did not outlive its parent within the job.'
        }
        $tree.StopTree(3000)
        if($tree.HasRunningProcesses){throw 'The recovered job was not empty.'}
        $null=$signal.Set()
        $closedLaunchRejected=$false
        try{
            $unexpected=[ClaudeGuard.Processes.GuardAppContainer]::StartVerified($scope.Name,$scope.Identity.Value,$image,$hash,
                ('park '+$scope.Identity.Value+' "'+$moved+'"'),$signal)
            $unexpected.Dispose()
        }catch [Management.Automation.MethodInvocationException]{
            $closedLaunchRejected=$_.Exception.InnerException.Message -like '*closed before launch*'
        }
        if(-not $closedLaunchRejected){throw 'A closed gate allowed a new contained launch.'}
        $entryVerified=Test-GuardManualEntry $hash
        $ownerExitVerified=Test-GuardJobOwnerExit $hash
        $result=[pscustomobject]@{Utc=[datetime]::UtcNow.ToString('o');Target='IPv4LoopbackOnly';
            ControlsBothPassed=$true;AppContainer=$appContainer;LessPrivilegedAppContainer=$lpac;
            OutlivingChildTerminated=$true;ClosedGateLaunchRejected=$true;ManualEntryVerified=$entryVerified;
            OwnerExitTerminatedJob=$ownerExitVerified}
    }finally{
        if($tree){$tree.Dispose()}
        $signal.Dispose()
    }
}finally{
    try{if($scope){$scope.Dispose()}}finally{
        if($tcp){$tcp.Stop()}
        if($udp){$udp.Dispose()}
        [IO.File]::Delete($moved)
        [IO.File]::Delete($image)
        [IO.Directory]::Delete($folder,$false)
    }
}
$result | ConvertTo-Json -Depth 4 -Compress
