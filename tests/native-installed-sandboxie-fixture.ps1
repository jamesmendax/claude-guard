#Requires -Version 5.1

$installedFixturePackage = Join-Path (Split-Path -Parent $PSScriptRoot) 'package'
. (Join-Path $installedFixturePackage 'guard-common.ps1')
. (Join-Path $installedFixturePackage 'guard-sandboxie.ps1')
. (Join-Path $PSScriptRoot 'native-sandboxie-fixture.ps1')

function Get-GuardInstalledSandboxieFixturePaths([string]$Stage) {
    if ([IO.Path]::GetFullPath($Stage) -ine $Stage -or
        (Split-Path -Parent $Stage) -ine $script:GuardSandboxieHome -or
        (Split-Path -Leaf $Stage) -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z' -or
        $PSScriptRoot -ine (Join-Path $Stage 'tests')) {
        throw 'Expected the protected installed-driver fixture stage.'
    }
    foreach ($path in $script:GuardSandboxieHome,$Stage,$PSScriptRoot) {
        Assert-GuardSandboxieAdministratorPath $path
    }
    $driver = Join-Path $script:GuardSandboxieHome 'daily\sandboxie'
    [pscustomobject]@{
        Driver = $driver
        Ini = Join-Path $driver 'Sandboxie.ini'
        Backup = Join-Path $Stage 'sandboxie-production.ini.backup'
        Recovery = Join-Path $Stage 'sandboxie-fixture-recovery.json'
        Data = Join-Path $Stage 'sandboxie-fixture-data'
    }
}

function Get-GuardInstalledSandboxieConfigHash([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '') }
    finally { $hash.Dispose() }
}

function Get-GuardInstalledSandboxieFixtureNative([string]$Driver) {
    $native = Get-GuardSandboxieNative $Driver

    if (-not ('GuardInstalledSandboxieFixtureReadback' -as [type])) {
        $dll = Join-Path $Driver 'SbieDll.dll'
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class GuardInstalledSandboxieFixtureReadback {
    private static readonly string FixtureBox = "GuardNativeFixture".PadRight(34, '\0');

    [DllImport(@"$dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SbieApi_QueryProcess(IntPtr pid, StringBuilder box, IntPtr image, IntPtr sid, IntPtr session);
    [DllImport(@"$dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SbieApi_EnumProcessEx(string box, byte allSessions, uint session, [Out] uint[] pids, ref uint count);

    public static string Box(int pid) {
        var box = new StringBuilder(34);
        int status = SbieApi_QueryProcess((IntPtr)pid, box, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        return status == 0 ? box.ToString() : null;
    }

    public static uint[] ProcessIds() {
        var pids = new uint[512];
        uint count = (uint)pids.Length;
        int status = SbieApi_EnumProcessEx(FixtureBox, 1, UInt32.MaxValue, pids, ref count);
        if (status != 0 || count >= pids.Length)
            throw new InvalidOperationException("Cannot verify installed-driver fixture processes: " + status.ToString("X8"));
        Array.Resize(ref pids, (int)count);
        return pids;
    }

    public static uint ProcessCount() {
        return (uint)ProcessIds().Length;
    }
}
"@ -ErrorAction Stop
    }
    $native
}

function Set-GuardInstalledSandboxieFixtureConfiguration($Paths,[string]$ExpectedHash,[byte[]]$Bytes,[string]$ExpectedAcl) {
    Assert-GuardSandboxieAdministratorPath $Paths.Ini
    $acl = Get-Acl -LiteralPath $Paths.Ini
    if ($acl.Sddl -cne $ExpectedAcl -or
        (Get-FileHash -LiteralPath $Paths.Ini).Hash -cne $ExpectedHash) {
        throw 'The installed Sandboxie configuration changed during fixture maintenance.'
    }
    $temporary = "$($Paths.Ini).fixture-$([guid]::NewGuid().ToString('N')).tmp"
    $retired = "$temporary.retired"
    try {
        [IO.File]::WriteAllBytes($temporary,$Bytes)
        Set-Acl -LiteralPath $temporary -AclObject $acl
        [IO.File]::Replace($temporary,$Paths.Ini,$retired)
        if ((Get-Acl -LiteralPath $Paths.Ini).Sddl -cne $ExpectedAcl -or
            (Get-FileHash -LiteralPath $Paths.Ini).Hash -cne (Get-GuardInstalledSandboxieConfigHash $Bytes)) {
            throw 'The installed Sandboxie configuration replacement could not be verified.'
        }
    } finally {
        [IO.File]::Delete($temporary)
        [IO.File]::Delete($retired)
    }
}

function Start-GuardInstalledSandboxieFixture([string]$Stage,[string]$FixturePath,[ValidateRange(20000,47999)][int]$RelayPort) {
    $paths = Get-GuardInstalledSandboxieFixturePaths $Stage
    foreach ($path in $paths.Backup,$paths.Recovery,$paths.Data) {
        if (Test-Path -LiteralPath $path) { throw 'A previous installed-driver fixture still owns the stage.' }
    }
    $task = Get-ScheduledTask -TaskName 'ClaudeVPNGuard Daily Controller' -TaskPath '\' -ErrorAction Stop
    if ($task.State -notin 'Disabled','Ready') { throw 'Stop the production controller before adding the fixture box.' }

    $provisioned = Read-GuardDailyRecord 'daily-provisioned.json'
    $app = Get-GuardSandboxieApp
    if ($provisioned.Containment -cne 'Sandboxie' -or -not (Test-GuardDailyScopeBinding $provisioned) -or
        $provisioned.PackageRoot -ine $app.Root -or $provisioned.PackageFullName -cne $app.PackageFullName -or
        $provisioned.ScopeSid -cne $app.PackageSid -or $RelayPort -eq $provisioned.Port) {
        throw 'The production package or the isolated relay scope could not be verified.'
    }
    $null = Test-GuardSandboxieProtection $paths.Driver $app.Root $provisioned.Port
    $native = Get-GuardInstalledSandboxieFixtureNative $paths.Driver
    if ($native::ProcessIds().Count -ne 0 -or $null -ne $native::Setting('GuardNativeFixture','Enabled',0)) {
        throw 'The production sandbox must be empty and the fixture box must be absent.'
    }

    $fixturePolicy = @(& (Join-Path $PSScriptRoot 'new-native-sandbox-policy.ps1') -FixturePath $FixturePath -RelayPort $RelayPort)
    if ($fixturePolicy.Count -lt 5 -or $fixturePolicy[0] -cne '[GlobalSettings]' -or
        $fixturePolicy[1] -cne 'NetworkEnableWFP=y' -or $fixturePolicy[2] -cne '' -or
        $fixturePolicy[3] -cne '[GuardNativeFixture]') {
        throw 'The expected isolated Sandboxie test section could not be prepared.'
    }
    $section = @($fixturePolicy[3..($fixturePolicy.Count-1)]) + @("FileRootPath=$($paths.Data)")
    $original = [IO.File]::ReadAllBytes($paths.Ini)
    if ($original.Length -lt 2 -or $original[0] -ne 0xff -or $original[1] -ne 0xfe) {
        throw 'The installed Sandboxie configuration encoding is unexpected.'
    }
    $sddl = (Get-Acl -LiteralPath $paths.Ini).Sddl
    $newline = [string][char]13 + [char]10
    $append = [Text.Encoding]::Unicode.GetBytes($newline+$newline+($section -join $newline)+$newline)
    $combined = [byte[]]($original + $append)
    $receipt = [pscustomobject]@{
        ProductionRoot = $app.Root
        ProductionPort = [int]$provisioned.Port
        OriginalHash = Get-GuardInstalledSandboxieConfigHash $original
        FixtureHash = Get-GuardInstalledSandboxieConfigHash $combined
        OriginalAcl = $sddl
    }
    [IO.File]::WriteAllBytes($paths.Backup,$original)
    Set-Acl -LiteralPath $paths.Backup -AclObject (Get-Acl -LiteralPath $paths.Ini)
    [IO.File]::WriteAllText($paths.Recovery,($receipt | ConvertTo-Json -Compress))
    Set-Acl -LiteralPath $paths.Recovery -AclObject (Get-Acl -LiteralPath $paths.Ini)
    Assert-GuardSandboxieAdministratorPath $paths.Backup
    Assert-GuardSandboxieAdministratorPath $paths.Recovery

    Set-GuardInstalledSandboxieFixtureConfiguration $paths $receipt.OriginalHash $combined $receipt.OriginalAcl
    $native::Reload()
    $native::RequireReady()
    $fixture = 'GuardNativeFixture'
    $closeDns = '\RPC Control\DNSResolver'
    $relay = "Allow;Address=127.0.0.1;Port=$RelayPort;Protocol=TCP"
    if ($native::Setting($fixture,'Enabled',0) -cne 'y' -or
        $native::Setting($fixture,'ForceFolder',0) -notin $FixturePath,"\??\$FixturePath",$native::KernelPath($FixturePath) -or
        $null -ne $native::Setting($fixture,'ForceFolder',1) -or
        $native::Setting($fixture,'ForceProcess',0) -ine 'fixture-desktop.exe' -or
        $null -ne $native::Setting($fixture,'ForceProcess',1) -or
        $native::Setting($fixture,'OpenPipePath',0) -ine '\Device\NamedPipe\GuardNormalPackage-*' -or
        $native::Setting($fixture,'ClosedIpcPath',0) -ine $closeDns -or
        $native::Setting($fixture,'FileRootPath',0) -notin $paths.Data,"\??\$($paths.Data)",$native::KernelPath($paths.Data) -or
        $native::Setting($fixture,'NetworkAccess',0) -cne 'Block' -or
        $native::Setting($fixture,'NetworkAccess',1) -cne $relay -or
        $null -ne $native::Setting($fixture,'NetworkAccess',2)) {
        throw 'The loaded fixture policy does not match the isolated Sandboxie rules.'
    }
    for ($index = 0; $index -lt 512; $index++) {
        $open = $native::Setting($fixture,'OpenIpcPath',$index)
        if ($null -eq $open) { return }
        if ($open -ieq $closeDns) { throw 'Sandboxie loaded an opening for the fixture DNS resolver.' }
    }
    throw 'Could not verify the complete fixture IPC policy.'
}

function Restore-GuardInstalledSandboxieFixture([string]$Stage) {
    $paths = Get-GuardInstalledSandboxieFixturePaths $Stage
    if (-not (Test-Path -LiteralPath $paths.Recovery -PathType Leaf)) { return }
    foreach ($path in $paths.Backup,$paths.Recovery,$paths.Ini) {
        Assert-GuardSandboxieAdministratorPath $path
    }
    $receipt = [IO.File]::ReadAllText($paths.Recovery) | ConvertFrom-Json
    $original = [IO.File]::ReadAllBytes($paths.Backup)
    $currentHash = (Get-FileHash -LiteralPath $paths.Ini).Hash
    if ($receipt.OriginalHash -cne (Get-GuardInstalledSandboxieConfigHash $original) -or
        $receipt.FixtureHash -cnotmatch '\A[A-F0-9]{64}\z' -or
        $currentHash -cnotin $receipt.OriginalHash,$receipt.FixtureHash -or
        (Get-Acl -LiteralPath $paths.Ini).Sddl -cne $receipt.OriginalAcl -or
        (Get-Acl -LiteralPath $paths.Backup).Sddl -cne $receipt.OriginalAcl) {
        throw 'Rollback requires the verified original and installed Sandboxie configurations.'
    }

    $native = Get-GuardInstalledSandboxieFixtureNative $paths.Driver
    if ($null -ne $native::Setting('GuardNativeFixture','Enabled',0) -and
        [GuardInstalledSandboxieFixtureReadback]::ProcessCount() -ne 0) {
        $start = Join-Path $paths.Driver 'Start.exe'
        Assert-GuardSandboxieAdministratorPath $start
        if ((Get-FileHash -LiteralPath $start).Hash -cne '1711F06241B00E3C4450897A0D07198BBB564A7B3A5C99BD9F38E98426DAC413' -or
            (Get-AuthenticodeSignature -LiteralPath $start).Status -ne 'Valid') {
            throw 'The installed Sandboxie fixture termination tool changed.'
        }
        Invoke-GuardSandboxieTool $start '/box:GuardNativeFixture /terminate'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ([GuardInstalledSandboxieFixtureReadback]::ProcessCount() -ne 0) {
            if ($clock.Elapsed.TotalSeconds -ge 8) { throw 'Installed-driver fixture processes remain.' }
            Start-Sleep -Milliseconds 100
        }
    }
    if ($currentHash -ceq $receipt.FixtureHash) {
        Set-GuardInstalledSandboxieFixtureConfiguration $paths $receipt.FixtureHash $original $receipt.OriginalAcl
    }
    $native::Reload()
    $null = Test-GuardSandboxieProtection $paths.Driver $receipt.ProductionRoot $receipt.ProductionPort
    if ($null -ne $native::Setting('GuardNativeFixture','Enabled',0)) {
        throw 'The installed Sandboxie driver still reports the fixture box.'
    }
    if (Test-Path -LiteralPath $paths.Data) {
        $data = Get-Item -LiteralPath $paths.Data -Force
        if ($data.FullName -ine $paths.Data -or (Split-Path -Parent $data.FullName) -ine $Stage -or
            ($data.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            @(Get-ChildItem -LiteralPath $data.FullName -Force -Recurse -Attributes ReparsePoint).Count) {
            throw 'Unexpected installed-driver fixture data or junction.'
        }
        foreach ($entry in (@($data) + @(Get-ChildItem -LiteralPath $data.FullName -Force -Recurse))) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReadOnly) {
                [IO.File]::SetAttributes($entry.FullName,$entry.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly))
            }
        }
        [IO.Directory]::Delete($data.FullName,$true)
    }
    [IO.File]::Delete($paths.Recovery)
    [IO.File]::Delete($paths.Backup)
}
