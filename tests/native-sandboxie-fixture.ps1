$sandboxieBox='GuardNativeFixture'

function Invoke-GuardSandboxieTool([string]$File,[string]$Arguments) {
    $start=[Diagnostics.ProcessStartInfo]::new($File,$Arguments)
    $start.WorkingDirectory=Split-Path -Parent $File
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $process=[Diagnostics.Process]::Start($start)
    try{
        if(-not $process.WaitForExit(15000)){
            $process.Kill()
            $null=$process.WaitForExit(3000)
            throw "Timed out running $([IO.Path]::GetFileName($File)) $Arguments"
        }
        if($process.ExitCode -ne 0){
            throw "$([IO.Path]::GetFileName($File)) $Arguments exited with code $($process.ExitCode)."
        }
    }finally{$process.Dispose()}
}

function Get-GuardSandboxieService([string]$Directory,[string]$Name) {
    $key="HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if(-not (Test-Path -LiteralPath $key)){return}
    $image=(Get-ItemProperty -LiteralPath $key -Name ImagePath).ImagePath.Trim('"')
    if($image.StartsWith('\??\',[StringComparison]::Ordinal)){$image=$image.Substring(4)}
    $file=if($Name -ceq 'SbieDrv'){'SbieDrv.sys'}else{'SbieSvc.exe'}
    if($image -ine (Join-Path $Directory $file)){throw "Unexpected service image for $Name."}
    Get-Service -Name $Name
}

function Get-GuardRetiredSandboxieDirectory([string]$Operation) {
    if($Operation -cnotmatch '\A[a-f0-9]{32}\z'){throw 'Expected the exact prior acceptance operation.'}
    $guardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
    $oldStage=Join-Path $guardRoot "native-acceptance-$Operation"
    $directory=Join-Path $oldStage 'sandboxie'
    $receipt=Join-Path $oldStage 'normal-package-receipt.json'
    $trusted=@('S-1-5-18','S-1-5-32-544')
    $write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach($path in $guardRoot,$oldStage,$directory,$receipt){
        $item=Get-Item -LiteralPath $path -Force
        $acl=Get-Acl -LiteralPath $path
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
            @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
                $_.IdentityReference.Value -notin $trusted -and
                    $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $write)
            }).Count){throw 'The prior Sandboxie stage is not administrator controlled.'}
    }
    $prior=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
    if($prior.Sandboxie -ne $true -or $prior.SandboxieRemoved -ne $false){
        throw 'The prior receipt does not identify a residual Sandboxie fixture.'
    }
    if(-not @(Get-ChildItem -LiteralPath $directory -Force).Count){
        foreach($name in 'SbieSvc','SbieDrv'){
            if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name") -or
                (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$name")){
                throw 'An empty retired staging directory cannot own a registered Sandboxie component.'
            }
        }
        return $directory
    }
    $driver=Get-Item -LiteralPath (Join-Path $directory 'SbieDrv.sys') -Force
    $tool=Get-Item -LiteralPath (Join-Path $directory 'KmdUtil.exe') -Force
    if(($driver.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($tool.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        (Get-FileHash -LiteralPath $driver.FullName).Hash -cne '4BCA736871ACFDBA6B4AD54A0CCE2A99B953A87E43270644E5992D564685CCA0' -or
        (Get-FileHash -LiteralPath $tool.FullName).Hash -cne 'EA863504C41BA1F2FCB98D42E01F9CA5C60E1E4268111CD1BFB55342A6605502'){
        throw 'The retired driver or its vendor cleanup utility changed.'
    }
    foreach($name in 'SbieSvc','SbieDrv'){
        $service=Get-GuardSandboxieService $directory $name
        if($service){$service.Dispose()}
        $key="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$name"
        if((Test-Path -LiteralPath $key) -and
            (Get-ItemProperty -LiteralPath $key -Name EventMessageFile).EventMessageFile -ine (Join-Path $directory 'SbieMsg.dll')){
            throw "The event source for $name belongs to another installation."
        }
    }
    $driverKey='HKLM:\SYSTEM\CurrentControlSet\Services\SbieDrv'
    if(Test-Path -LiteralPath $driverKey){
        $identity=Get-ItemProperty -LiteralPath $driverKey
        if($identity.Start -ne 3 -or $identity.IniPath -ine (Join-Path $directory 'Sandboxie.ini')){
            throw 'The driver no longer belongs to the retired test configuration.'
        }
    }
    $directory
}

function Wait-GuardSandboxieSettings([scriptblock]$Read,[int]$TimeoutMilliseconds=20000) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    do {
        $last=& $Read
        if($last.ApiStatus -eq 0 -and -not @($last.Missing).Count){return}
        if($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds){break}
        Start-Sleep -Milliseconds 100
    }while($true)
    throw ('Sandboxie did not become ready. Driver readback 0x{0:X8}, settings {1}.' -f
        [uint32]$last.ApiStatus,($last.Missing -join ', '))
}

function Start-GuardSandboxieFixture([string]$Directory,[string]$FixturePath,[int]$RelayPort) {
    $kmd=Join-Path $Directory 'KmdUtil.exe'
    $dll=Join-Path $Directory 'SbieDll.dll'
    $ini=Join-Path $Directory 'Sandboxie.ini'
    $templates=Join-Path $Directory 'Templates.ini'
    $windowsConfig=Join-Path ([Environment]::GetFolderPath('Windows')) 'Sandboxie.ini'
    if((Test-Path -LiteralPath $windowsConfig) -or (Get-Service -Name SbieDrv,SbieSvc -ErrorAction SilentlyContinue)){
        throw 'A pre-existing Sandboxie installation or system configuration was found.'
    }
    foreach($path in $kmd,$dll,(Join-Path $Directory 'SbieDrv.sys'),(Join-Path $Directory 'SbieSvc.exe'),(Join-Path $Directory 'Start.exe')){
        if((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid'){throw "Untrusted fixture file $path."}
    }
    $rules=@(& (Join-Path $PSScriptRoot 'new-native-sandbox-policy.ps1') -FixturePath $FixturePath -RelayPort $RelayPort)
    $rules+="FileRootPath=$(Join-Path $Directory 'fixture-root')"
    [IO.File]::WriteAllLines($ini,$rules,[Text.Encoding]::Unicode)
    $source=[IO.File]::ReadAllText($templates)
    $dnsException='(?im)^OpenIpcPath=\\RPC Control\\DNSResolver[ \t]*\r?$'
    if([regex]::Matches($source,$dnsException).Count -ne 1){throw 'The vendor DNS template exception changed.'}
    [IO.File]::WriteAllText($templates,([regex]::Replace($source,$dnsException,'')),[Text.Encoding]::Unicode)

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class GuardSandboxieFixtureReadback
{
    [DllImport(@"$dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SbieApi_QueryProcess(IntPtr pid, StringBuilder box, IntPtr image, IntPtr sid, IntPtr session);
    [DllImport(@"$dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SbieApi_QueryConf(string box, string setting, uint index, StringBuilder value, uint bytes);
    [DllImport(@"$dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SbieApi_EnumProcessEx(string box, byte all, uint session, [Out] uint[] pids, out uint count);
    [DllImport(@"$dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SbieApi_GetVersionEx(StringBuilder version, out uint abi);
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string drive, StringBuilder target, int capacity);
    public static string KernelPath(string path)
    {
        var target = new StringBuilder(32768);
        if (QueryDosDeviceW(path.Substring(0, 2), target, target.Capacity) == 0)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return target.ToString().Split('\0')[0] + path.Substring(2);
    }
    public static string Box(int pid)
    {
        var box = new StringBuilder(34);
        int status = SbieApi_QueryProcess((IntPtr)pid, box, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        return status == 0 ? box.ToString() : null;
    }
    public static uint DriverStatus()
    {
        var version = new StringBuilder(16);
        uint abi;
        return unchecked((uint)SbieApi_GetVersionEx(version, out abi));
    }
    public static string Setting(string box, string name, uint index)
    {
        var value = new StringBuilder(512);
        int status = SbieApi_QueryConf(box, name, index, value, 1024);
        return status == 0 ? value.ToString() : null;
    }
    public static uint ProcessCount(string box)
    {
        uint count;
        int status = SbieApi_EnumProcessEx(box, 1, UInt32.MaxValue, new uint[512], out count);
        if (status != 0) throw new InvalidOperationException("Cannot enumerate fixture processes: " + status.ToString("X8"));
        return count;
    }
}
"@

    $msg=Join-Path $Directory 'SbieMsg.dll'
    $driver=Join-Path $Directory 'SbieDrv.sys'
    $service=Join-Path $Directory 'SbieSvc.exe'
    Invoke-GuardSandboxieTool $kmd ('install SbieDrv "'+$driver+'" type=kernel start=demand msgfile="'+$msg+'" altitude=86900')
    $null=Get-GuardSandboxieService $Directory 'SbieDrv'
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieDrv' -Name IniPath -Value $ini -PropertyType String | Out-Null
    Invoke-GuardSandboxieTool $kmd ('install SbieSvc "'+$service+'" type=own start=demand msgfile="'+$msg+'" display="Sandboxie Test Service" group=UIGroup')
    $null=Get-GuardSandboxieService $Directory 'SbieSvc'
    Invoke-GuardSandboxieTool $kmd 'start SbieSvc'
    $instance=Get-GuardSandboxieService $Directory 'SbieSvc'
    try{$instance.WaitForStatus('Running',[TimeSpan]::FromSeconds(12))}finally{$instance.Dispose()}
    $route="Allow;Address=127.0.0.1;Port=$RelayPort;Protocol=TCP"
    $kernelFolder=[GuardSandboxieFixtureReadback]::KernelPath($FixturePath)
    # SbieSvc reports Running while StartDriverAsync is still starting the driver.
    Wait-GuardSandboxieSettings -Read {
        $apiStatus=[GuardSandboxieFixtureReadback]::DriverStatus()
        $loadedFolder=[GuardSandboxieFixtureReadback]::Setting($sandboxieBox,'ForceFolder',0)
        $checks=[ordered]@{
            NetworkEnableWFP=[GuardSandboxieFixtureReadback]::Setting('GlobalSettings','NetworkEnableWFP',0) -ceq 'y'
            ForceFolder=$loadedFolder -iin $FixturePath,"\??\$FixturePath",$kernelFolder
            ForceProcess=[GuardSandboxieFixtureReadback]::Setting($sandboxieBox,'ForceProcess',0) -ieq 'fixture-desktop.exe'
            ClosedIpcPath=[GuardSandboxieFixtureReadback]::Setting($sandboxieBox,'ClosedIpcPath',0) -ieq '\RPC Control\DNSResolver'
            DefaultBlock=[GuardSandboxieFixtureReadback]::Setting($sandboxieBox,'NetworkAccess',0) -ceq 'Block'
            RelayPermit=[GuardSandboxieFixtureReadback]::Setting($sandboxieBox,'NetworkAccess',1) -ceq $route
        }
        [pscustomobject]@{
            ApiStatus=$apiStatus
            Missing=@($checks.GetEnumerator() | Where-Object {-not $_.Value} | Select-Object -ExpandProperty Key)
        }
    }
}

function Stop-GuardSandboxieFixture([string]$Directory,[switch]$KeepFiles,[ValidateSet('GuardNativeFixture','GuardDesktop')][string]$BoxName='GuardNativeFixture') {
    # Run this after the acceptance process exits and releases its driver API handles.
    $kmd=Join-Path $Directory 'KmdUtil.exe'
    $start=Join-Path $Directory 'Start.exe'
    $failures=@()
    $service=Get-GuardSandboxieService $Directory 'SbieSvc'
    if($service){
        try{
            if($service.Status -eq 'Running'){
                Invoke-GuardSandboxieTool $start "/box:$BoxName /terminate"
                if('GuardSandboxieFixtureReadback' -as [type]){
                    $until=[datetime]::UtcNow.AddSeconds(8)
                    while([GuardSandboxieFixtureReadback]::ProcessCount($BoxName) -ne 0){
                        if([datetime]::UtcNow -ge $until){throw 'Sandboxie test processes remain.'}
                        Start-Sleep -Milliseconds 100
                    }
                }
            }
        }catch{$failures+= $_.Exception.Message}
        finally{$service.Dispose()}
    }
    $system=[Environment]::GetFolderPath('System')
    foreach($name in 'SbieSvc','SbieDrv'){
        try{
            $key="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$name"
            if((Test-Path -LiteralPath $key) -and
                (Get-ItemProperty -LiteralPath $key -Name EventMessageFile).EventMessageFile -ine (Join-Path $Directory 'SbieMsg.dll')){
                throw "Unexpected event source for $name."
            }
            $instance=Get-GuardSandboxieService $Directory $name
            if(-not $instance){
                if(Test-Path -LiteralPath $key){Invoke-GuardSandboxieTool $kmd "delete $name"}
                continue
            }
            try{
                if($instance.Status -ne 'Stopped'){
                    try{Invoke-GuardSandboxieTool $kmd "stop $name"}
                    catch{
                        $instance.Refresh()
                        if($instance.Status -notin 'Stopped','StopPending'){
                            try{Invoke-GuardSandboxieTool (Join-Path $system 'sc.exe') "stop $name"}
                            catch{
                                if($name -cne 'SbieDrv'){throw}
                                Invoke-GuardSandboxieTool (Join-Path $system 'fltmc.exe') 'unload SbieDrv'
                            }
                        }
                    }
                    $instance.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(12))
                }
            }finally{$instance.Dispose()}
            Invoke-GuardSandboxieTool $kmd "delete $name"
        }catch{$failures+= $_.Exception.Message}
    }
    foreach($name in 'SbieSvc','SbieDrv'){
        if(Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name"){$failures+="Fixture service remains registered: $name"}
        if(Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$name"){$failures+="Fixture event source remains registered: $name"}
    }
    $filters=& (Join-Path $system 'fltmc.exe') filters
    if($LASTEXITCODE -ne 0 -or @($filters | Where-Object {$_ -match '^\s*SbieDrv\s'}).Count){
        $failures+='Could not verify removal of the Sandboxie filesystem filter.'
    }
    if($failures){throw ($failures -join ' | ')}
    if(-not $KeepFiles -and (Test-Path -LiteralPath $Directory)){
        $guardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
        $stage=Split-Path -Parent $Directory
        if(([IO.Path]::GetFullPath($Directory) -ine $Directory) -or ((Split-Path -Leaf $Directory) -cne 'sandboxie') -or
            ((Split-Path -Parent $stage) -ine $guardRoot) -or ((Split-Path -Leaf $stage) -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z') -or
            @($guardRoot,$stage,$Directory | Where-Object {
                (Get-Item -LiteralPath $_ -Force).Attributes -band [IO.FileAttributes]::ReparsePoint
            }).Count -or @(Get-ChildItem -LiteralPath $Directory -Force -Recurse -Attributes ReparsePoint).Count){
            throw 'Unexpected sandbox work directory or junction.'
        }
        $fixtureData=Join-Path $Directory 'fixture-root'
        if(Test-Path -LiteralPath $fixtureData){
            # Sandboxie marks its disposable data root read-only, even when empty.
            $entries=@(Get-Item -LiteralPath $fixtureData -Force)
            $entries+=@(Get-ChildItem -LiteralPath $fixtureData -Force -Recurse)
            foreach($entry in $entries){
                if($entry.Attributes -band [IO.FileAttributes]::ReadOnly){
                    [IO.File]::SetAttributes($entry.FullName,$entry.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly))
                }
            }
        }
        [IO.Directory]::Delete($Directory,$true)
    }
}
