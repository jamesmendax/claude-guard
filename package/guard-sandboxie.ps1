# Production Sandboxie policy and readback for the registered Claude Desktop package.
$script:GuardSandboxieBox = 'GuardDesktop'
$script:GuardSandboxieHome = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'

function Get-GuardSandboxiePackageRoot([string]$Path) {
    if ($Path -notmatch '\A[A-Z]:\\(?:Program Files\\)?WindowsApps\\AnthropicPBC\.Claude_(?:[0-9]{1,5}\.){3}[0-9]{1,5}_x64__fnn82j28hfe8t\z' -or
        [IO.Path]::GetFullPath($Path) -ine $Path) {
        throw 'Expected the exact WindowsApps path of the Anthropic Claude Store package.'
    }
    $Path
}

function Get-GuardSandboxieApp {
    $packages = @(Get-AppxPackage -Name 'AnthropicPBC.Claude' -ErrorAction Stop)
    if ($packages.Count -ne 1 -or $packages[0].Name -cne 'AnthropicPBC.Claude' -or
        $packages[0].PackageFamilyName -cne 'AnthropicPBC.Claude_fnn82j28hfe8t' -or
        $packages[0].SignatureKind -ne 'Store' -or $packages[0].Status -ne 'Ok') {
        throw 'Expected one healthy Claude Store package registered for this user.'
    }
    $package = $packages[0]
    $root = Get-GuardSandboxiePackageRoot $package.InstallLocation
    if ([IO.Path]::GetFileName($root) -cne $package.PackageFullName) {
        throw 'The Claude installation path does not match its registered package name.'
    }

    $manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction Stop
    $applications = @($manifest.SelectNodes("/*[local-name()='Package']/*[local-name()='Applications']/*[local-name()='Application']") |
        Where-Object {
            $_.GetAttribute('EntryPoint') -ceq 'Windows.FullTrustApplication' -and
            [IO.Path]::GetFileName($_.GetAttribute('Executable')) -ieq 'Claude.exe'
        })
    if ($applications.Count -ne 1) { throw 'The Claude package must register one full-trust Claude.exe application.' }
    $app = $applications[0]
    $id = $app.GetAttribute('Id')
    $executable = $app.GetAttribute('Executable')
    if ($id -cnotmatch '\A[A-Za-z0-9.]{1,64}\z' -or $executable -notmatch '\A(?:[A-Za-z0-9_-]+\\)*Claude\.exe\z') {
        throw 'The Claude package application ID or executable path is invalid.'
    }
    $desktop = Join-Path $root $executable
    if (-not (Test-Path -LiteralPath $desktop -PathType Leaf -ErrorAction Stop)) {
        throw 'The registered Claude Desktop executable is missing.'
    }
    [pscustomobject]@{
        Family = $package.PackageFamilyName
        PackageFullName = $package.PackageFullName
        PackageSid = Get-GuardPackageSid $package.PackageFamilyName
        Root = $root
        AppId = "$($package.PackageFamilyName)!$id"
        DesktopPath = $desktop
    }
}

function New-GuardSandboxiePolicy([string]$PackageRoot, [ValidateRange(1,65535)][int]$RelayPort, [string]$DataRoot) {
    $root = Get-GuardSandboxiePackageRoot $PackageRoot
    if ($DataRoot -ine (Join-Path $script:GuardSandboxieHome 'sandbox-data\GuardDesktop') -or $RelayPort -eq 0) {
        throw 'Expected the GuardDesktop data root and relay port.'
    }

    '[GlobalSettings]'
    'NetworkEnableWFP=y'
    'EditAdminOnly=y'
    'ForceDisableAdminOnly=y'
    ''
    "[$script:GuardSandboxieBox]"
    'Enabled=y'
    "ForceFolder=$root"
    'ForceProcess=Claude.exe'
    "FileRootPath=$DataRoot"
    'ClosedIpcPath=\RPC Control\DNSResolver'
    'NetworkAccess=Block'
    "NetworkAccess=Allow;Address=127.0.0.1;Port=$RelayPort;Protocol=TCP"
}

function Assert-GuardSandboxieAdministratorPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trusted = @('S-1-5-18','S-1-5-32-544')
    $write = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
        @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.IdentityReference.Value -notin $trusted -and $_.AccessControlType -eq 'Allow' -and
            ($_.FileSystemRights -band $write)
        }).Count) {
        throw "Sandboxie path is not administrator controlled: $Path"
    }
}

function Get-GuardSandboxieNative([string]$DriverRoot) {
    if ($DriverRoot -ine (Join-Path $script:GuardSandboxieHome 'daily\sandboxie')) {
        throw 'Expected the protected Guard Sandboxie installation directory.'
    }
    if (-not ('ClaudeGuard.SandboxieReadback' -as [type])) {
        if (-not [Environment]::Is64BitProcess) { throw 'Guard Sandboxie requires 64-bit PowerShell.' }
        foreach ($path in $script:GuardSandboxieHome,(Split-Path -Parent $DriverRoot),$DriverRoot) {
            Assert-GuardSandboxieAdministratorPath $path
        }

        $pins = @{
            'SbieDll.dll' = '7C0272E146DCD4162B40CD551CCABDE45EEB6F0031E8CDBB523C551900039FEF'
            'SbieDrv.sys' = '4BCA736871ACFDBA6B4AD54A0CCE2A99B953A87E43270644E5992D564685CCA0'
            'SbieSvc.exe' = '6BA437F8D45E1C0A0C54FEA39942431B4FEAC4B725AAE07DC6E527E3E57EF34D'
            # The pinned release template with its default DNS resolver opening removed.
            'Templates.ini' = 'B5258D4D6B881B29677336E166DD6494DD73A8171F67826318F4AB2243CC1736'
        }
        foreach ($name in $pins.Keys) {
            $path = Join-Path $DriverRoot $name
            Assert-GuardSandboxieAdministratorPath $path
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -cne $pins[$name] -or
                ($name -ne 'Templates.ini' -and (Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop).Status -ne 'Valid')) {
                throw "Unexpected Sandboxie release file: $name"
            }
        }
        $dll = Join-Path $DriverRoot 'SbieDll.dll'
        $source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32 | DllImportSearchPath.UseDllDirectoryForDependencies)]

namespace ClaudeGuard {
    public static class SandboxieReadback {
        private const string BoxName = "GuardDesktop";
        // The driver probes a fixed-width box name even when its value is shorter.
        private static readonly string Box = BoxName.PadRight(34, '\0');

        [DllImport(@"__SBIE_DLL__", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int SbieApi_GetVersionEx(StringBuilder version, out uint abi);
        [DllImport(@"__SBIE_DLL__", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int SbieApi_IsBoxEnabled(string box);
        [DllImport(@"__SBIE_DLL__", ExactSpelling = true)]
        private static extern int SbieApi_ReloadConf(uint session, uint flags);
        [DllImport(@"__SBIE_DLL__", ExactSpelling = true)]
        private static extern int SbieApi_DisableForceProcess(IntPtr newState, out uint oldState);
        [DllImport(@"__SBIE_DLL__", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int SbieApi_QueryConf(string box, string setting, uint index, StringBuilder value, uint bytes);
        [DllImport(@"__SBIE_DLL__", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int SbieApi_EnumProcessEx(string box, byte allSessions, uint session, [Out] uint[] pids, ref uint count);
        [DllImport(@"__SBIE_DLL__", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int SbieApi_QueryProcessEx2(IntPtr processId, uint imageLength, StringBuilder box,
            IntPtr image, IntPtr sid, IntPtr session, out long creationTime);
        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(string drive, StringBuilder target, int capacity);

        private static void RequireSuccess(int status, string action) {
            if (status != 0)
                throw new InvalidOperationException(action + " failed (0x" + status.ToString("X8") + ").");
        }

        public static void RequireReady() {
            var version = new StringBuilder(16);
            uint abi, paused;
            RequireSuccess(SbieApi_GetVersionEx(version, out abi), "Sandboxie driver version query");
            if (!String.Equals(version.ToString(), "5.74.1", StringComparison.Ordinal) || abi != 0x57230)
                throw new InvalidOperationException("The loaded Sandboxie driver version is unexpected.");
            RequireSuccess(SbieApi_IsBoxEnabled(Box), "GuardDesktop enablement query");
            RequireSuccess(SbieApi_DisableForceProcess(IntPtr.Zero, out paused), "Sandboxie forcing state query");
            if (paused != 0)
                throw new InvalidOperationException("Sandboxie folder forcing is paused for this session.");
        }

        public static void Reload() {
            RequireSuccess(SbieApi_ReloadConf(UInt32.MaxValue, 0), "Sandboxie configuration reload");
        }

        public static string Setting(string section, string name, uint index) {
            var value = new StringBuilder(1024);
            int status = SbieApi_QueryConf(section, name, index, value, 2048);
            if (status == unchecked((int)0xC000008B)) // STATUS_RESOURCE_NAME_NOT_FOUND
                return null;
            RequireSuccess(status, "Sandboxie configuration query for " + name);
            return value.ToString();
        }

        public static string KernelPath(string path) {
            var target = new StringBuilder(32768);
            if (QueryDosDeviceW(path.Substring(0, 2), target, target.Capacity) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return target.ToString().Split('\0')[0] + path.Substring(2);
        }

        public static int[] ProcessIds() {
            var pids = new uint[512];
            uint count = (uint)pids.Length;
            RequireSuccess(SbieApi_EnumProcessEx(Box, 1, UInt32.MaxValue, pids, ref count),
                "GuardDesktop process enumeration");
            if (count >= pids.Length)
                throw new InvalidOperationException("GuardDesktop process enumeration may be incomplete.");

            var result = new int[count];
            for (int i = 0; i < result.Length; i++) {
                result[i] = checked((int)pids[i]);
                if (result[i] <= 0)
                    throw new InvalidOperationException("GuardDesktop returned an invalid PID.");
            }
            return result;
        }

        public static long ProcessStart(int pid) {
            var box = new StringBuilder(34);
            long fileTime;
            int status = SbieApi_QueryProcessEx2((IntPtr)pid, 0, box, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out fileTime);
            if (status == unchecked((int)0xC000000B)) // STATUS_INVALID_CID
                return 0;
            RequireSuccess(status, "Sandboxie process query");
            if (!String.Equals(box.ToString(), BoxName, StringComparison.OrdinalIgnoreCase))
                return 0;
            if (fileTime <= 0)
                throw new InvalidOperationException("GuardDesktop returned an invalid creation time.");
            return DateTime.FromFileTimeUtc(fileTime).Ticks;
        }
    }
}
'@
        Add-Type -TypeDefinition $source.Replace('__SBIE_DLL__', $dll) -ErrorAction Stop
    }
    [ClaudeGuard.SandboxieReadback]
}

function Test-GuardSandboxieProtection([string]$DriverRoot, [string]$PackageRoot, [ValidateRange(1,65535)][int]$RelayPort) {
    $dataRoot = Join-Path $script:GuardSandboxieHome 'sandbox-data\GuardDesktop'
    $policy = @(New-GuardSandboxiePolicy $PackageRoot $RelayPort $dataRoot)
    $native = Get-GuardSandboxieNative $DriverRoot
    $ini = Join-Path $DriverRoot 'Sandboxie.ini'
    Assert-GuardSandboxieAdministratorPath $ini
    if (([IO.File]::ReadAllLines($ini) -join [char]10) -cne ($policy -join [char]10)) {
        throw 'The protected Sandboxie policy file has changed.'
    }
    foreach ($name in 'SbieDrv','SbieSvc') {
        $registration = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction Stop
        $file = if ($name -eq 'SbieDrv') { 'SbieDrv.sys' } else { 'SbieSvc.exe' }
        $image = ([string]$registration.ImagePath).Trim('"')
        if ($image.StartsWith('\??\', [StringComparison]::Ordinal)) { $image = $image.Substring(4) }
        if ($image -ine (Join-Path $DriverRoot $file) -or ($name -eq 'SbieDrv' -and $registration.IniPath -ine $ini)) {
            throw "The registered $name component does not belong to Guard."
        }
    }
    $service = Get-Service -Name 'SbieSvc' -ErrorAction Stop
    try {
        if ($service.Status -ne 'Running') { throw 'The Guard Sandboxie service is stopped.' }
    } finally { $service.Dispose() }

    $native::RequireReady()
    $section = $script:GuardSandboxieBox
    $relay = "Allow;Address=127.0.0.1;Port=$RelayPort;Protocol=TCP"
    $resolverPath = '\RPC Control\DNSResolver'
    $folder = $native::Setting($section,'ForceFolder',0)
    $data = $native::Setting($section,'FileRootPath',0)
    $iniLocation = $native::Setting('','IniLocation',0x20000000)
    $checks = [ordered]@{
        IniLocation = $iniLocation -iin $ini, "\??\$ini"
        NetworkEnableWFP = $native::Setting('GlobalSettings','NetworkEnableWFP',0) -ceq 'y'
        EditAdminOnly = $native::Setting('GlobalSettings','EditAdminOnly',0) -ceq 'y'
        ForceDisableAdminOnly = $native::Setting('GlobalSettings','ForceDisableAdminOnly',0) -ceq 'y'
        Enabled = $native::Setting($section,'Enabled',0) -ceq 'y'
        ForceFolder = ($folder -iin $PackageRoot, "\??\$PackageRoot", $native::KernelPath($PackageRoot)) -and
            $null -eq $native::Setting($section,'ForceFolder',1)
        ForceProcess = $native::Setting($section,'ForceProcess',0) -ieq 'Claude.exe' -and
            $null -eq $native::Setting($section,'ForceProcess',1)
        FileRootPath = $data -iin $dataRoot, "\??\$dataRoot", $native::KernelPath($dataRoot)
        ClosedIpcPath = $native::Setting($section,'ClosedIpcPath',0) -ieq $resolverPath
        NetworkAccess = ($native::Setting($section,'NetworkAccess',0) -ceq 'Block') -and
            ($native::Setting($section,'NetworkAccess',1) -ceq $relay) -and
            $null -eq $native::Setting($section,'NetworkAccess',2)
    }
    $failed = @($checks.GetEnumerator() | Where-Object { -not $_.Value } | Select-Object -ExpandProperty Key)
    if ($failed.Count) { throw ('Unexpected Sandboxie rule readback: ' + ($failed -join ', ')) }
    # An active vendor default could override the DNS closure after an incomplete reload.
    for ($index = 0; $index -lt 512; $index++) {
        $openPath = $native::Setting($section,'OpenIpcPath',$index)
        if ($null -eq $openPath) { return $true }
        if ($openPath -ieq $resolverPath) { throw 'Sandboxie still has the default DNS resolver opening loaded.' }
    }
    throw 'Could not verify all Sandboxie IPC openings.'
}

function Get-GuardSandboxieProcessEntries([string]$DriverRoot) {
    $native = Get-GuardSandboxieNative $DriverRoot
    $entries = [Collections.Generic.List[object]]::new()
    try {
        foreach ($processId in $native::ProcessIds()) {
            try { $process = [Diagnostics.Process]::GetProcessById($processId) }
            catch [ArgumentException] { continue }

            $keep = $false
            try {
                if ($process.HasExited) { continue }
                $start = $process.StartTime.ToUniversalTime().Ticks
                $confirmedStart = $native::ProcessStart($processId)
                if ($process.HasExited) { continue }
                if ($confirmedStart -ne $start) {
                    throw "Cannot confirm the identity of GuardDesktop PID $processId."
                }
                $entries.Add([pscustomobject]@{ Id = $processId; Start = $start; Process = $process })
                $keep = $true
            } catch {
                if (-not (Test-GuardProcessExited $process)) { throw }
            } finally {
                if (-not $keep) { $process.Dispose() }
            }
        }
    } catch {
        foreach ($entry in $entries) { $entry.Process.Dispose() }
        throw
    }
    $entries.ToArray()
}

function Test-GuardSandboxieProcess([string]$DriverRoot, [ValidateRange(1,2147483647)][int]$ProcessId, [long]$ExpectedStart=0) {
    $native = Get-GuardSandboxieNative $DriverRoot
    # The process enumeration excludes host-injected processes that have a box name.
    $start = $native::ProcessStart($ProcessId)
    $start -gt 0 -and (-not $ExpectedStart -or $start -eq $ExpectedStart) -and
        ($ProcessId -in $native::ProcessIds()) -and (-not $ExpectedStart -or $native::ProcessStart($ProcessId) -eq $ExpectedStart)
}

function Start-GuardWindowsApplication([string]$AppId, [string]$Arguments) {
    if ([string]::IsNullOrWhiteSpace($AppId)) { throw 'An application user model ID is required.' }
    if (-not ('ClaudeGuard.WindowsApplication' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace ClaudeGuard {
    public static class WindowsApplication {
        [ComImport, Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IApplicationActivationManager {
            [PreserveSig]
            int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appId,
                [MarshalAs(UnmanagedType.LPWStr)] string arguments, uint options, out uint pid);
        }

        public static int Start(string appId, string arguments) {
            var type = Type.GetTypeFromCLSID(new Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C"));
            object manager = Activator.CreateInstance(type);
            try {
                uint pid;
                const uint NoErrorUi = 2;
                Marshal.ThrowExceptionForHR(((IApplicationActivationManager)manager)
                    .ActivateApplication(appId, arguments, NoErrorUi, out pid));
                if (pid == 0)
                    throw new InvalidOperationException("Windows application activation returned no process ID.");
                return checked((int)pid);
            } finally {
                Marshal.FinalReleaseComObject(manager);
            }
        }
    }
}
'@
    }
    [ClaudeGuard.WindowsApplication]::Start($AppId,$Arguments)
}
