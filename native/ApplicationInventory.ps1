function Initialize-GuardApplicationInterop {
    if ('ClaudeGuardNative.ApplicationInterop' -as [type]) { return }
    $members = @'
        private const uint QueryProcess = 0x1000;
        private const uint Terminate = 0x0001;
        private const uint Synchronize = 0x00100000;

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct FileIdentity
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, AccessTime, WriteTime;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct FileTimes
        {
            public long CreationTime, AccessTime, WriteTime, ChangeTime;
            public uint Attributes;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(
            string path, uint access, uint share, System.IntPtr security, uint disposition, uint flags, System.IntPtr template);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            Microsoft.Win32.SafeHandles.SafeFileHandle file, System.Text.StringBuilder path, uint capacity, uint flags);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file, out FileIdentity identity);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            Microsoft.Win32.SafeHandles.SafeFileHandle file, int infoClass, out FileTimes times, uint size);

        [System.Runtime.InteropServices.DllImport("userenv.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling = true)]
        private static extern int DeriveAppContainerSidFromAppContainerName(string name, out System.IntPtr sid);

        [System.Runtime.InteropServices.DllImport("advapi32.dll")]
        private static extern System.IntPtr FreeSid(System.IntPtr sid);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern Microsoft.Win32.SafeHandles.SafeWaitHandle OpenProcess(uint access, bool inherit, int id);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(System.IntPtr process, uint flags, System.Text.StringBuilder path, ref int capacity);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(System.IntPtr process, out long created, out long exited, out long kernel, out long user);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(Microsoft.Win32.SafeHandles.SafeWaitHandle process, uint status);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(Microsoft.Win32.SafeHandles.SafeWaitHandle process, uint milliseconds);

        private static Microsoft.Win32.SafeHandles.SafeFileHandle OpenPath(string path)
        {
            // Open for attributes only and share deletes so inventory does not hold up Store updates.
            var handle = CreateFile(path, 0x80, 7, System.IntPtr.Zero, 3, 0x02000000, System.IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = new System.ComponentModel.Win32Exception();
                handle.Dispose();
                throw error;
            }
            return handle;
        }

        public static string FinalPath(string path)
        {
            using (var handle = OpenPath(path))
            {
                var resolved = new System.Text.StringBuilder(32768);
                uint length = GetFinalPathNameByHandle(handle, resolved, (uint)resolved.Capacity, 0);
                if (length == 0) throw new System.ComponentModel.Win32Exception();
                if (length >= resolved.Capacity) throw new System.IO.PathTooLongException();
                string name = resolved.ToString();
                if (name.StartsWith(@"\\?\", System.StringComparison.Ordinal)) name = name.Substring(4);
                if (name.Length < 3 || !char.IsLetter(name[0]) || name[1] != ':' || name[2] != '\\')
                    throw new System.InvalidOperationException("The application path did not resolve to a local volume.");
                return name;
            }
        }

        public static string FileRevision(string path)
        {
            using (var handle = OpenPath(path))
            {
                FileIdentity id;
                FileTimes times;
                if (!GetFileInformationByHandle(handle, out id) ||
                    !GetFileInformationByHandleEx(handle, 0, out times, (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(FileTimes))))
                    return null;
                return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}",
                    id.VolumeSerial, id.IndexHigh, id.IndexLow, id.SizeHigh, id.SizeLow, times.CreationTime, times.WriteTime, times.ChangeTime);
            }
        }

        public static string PackageSid(string family)
        {
            System.IntPtr sid;
            int result = DeriveAppContainerSidFromAppContainerName(family, out sid);
            if (result != 0) System.Runtime.InteropServices.Marshal.ThrowExceptionForHR(result);
            if (sid == System.IntPtr.Zero) throw new System.InvalidOperationException("Windows returned an empty application SID.");
            try { return new System.Security.Principal.SecurityIdentifier(sid).Value; }
            finally { FreeSid(sid); }
        }

        public static string ProcessPath(System.IntPtr process)
        {
            var path = new System.Text.StringBuilder(32768);
            int length = path.Capacity;
            return QueryFullProcessImageName(process, 0, path, ref length) ? path.ToString() : null;
        }

        public static string ProcessPath(int id)
        {
            using (var handle = OpenProcess(QueryProcess, false, id))
                return handle.IsInvalid ? null : ProcessPath(handle.DangerousGetHandle());
        }

        public static long ProcessCreation(System.IntPtr process)
        {
            long created, exited, kernel, user;
            if (!GetProcessTimes(process, out created, out exited, out kernel, out user))
                throw new System.ComponentModel.Win32Exception();
            return created;
        }

        public static Microsoft.Win32.SafeHandles.SafeWaitHandle OpenMatchingProcess(int id, long creation)
        {
            var handle = OpenProcess(QueryProcess | Terminate | Synchronize, false, id);
            try
            {
                if (handle.IsInvalid)
                {
                    int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                    if (error == 87 || error == 1168) return null; // The snapshot's process has gone.
                    throw new System.ComponentModel.Win32Exception(error);
                }
                // CIM rounds its creation timestamp to microseconds. Match it to the native time.
                if (System.Math.Abs(ProcessCreation(handle.DangerousGetHandle()) - creation) >= 10) return null;
                var matching = handle;
                handle = null;
                return matching;
            }
            finally { if (handle != null) handle.Dispose(); }
        }

        public static void StopProcess(Microsoft.Win32.SafeHandles.SafeWaitHandle handle)
        {
            if (WaitForSingleObject(handle, 0) == 0) return;
            if (!TerminateProcess(handle, 1) && WaitForSingleObject(handle, 0) != 0)
                throw new System.ComponentModel.Win32Exception();
            if (WaitForSingleObject(handle, 2000) != 0)
                throw new System.InvalidOperationException("Windows did not confirm that a guarded process stopped.");
        }
'@
    Add-Type -Namespace ClaudeGuardNative -Name ApplicationInterop -MemberDefinition $members -ErrorAction Stop
}

function Test-GuardPathWithin([string]$Path, [string]$Root) {
    $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-GuardAnthropicSignature([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetExtension($Path) -ine '.exe') { return $false }
    Initialize-GuardApplicationInterop
    if (-not $script:GuardSignatureCache) { $script:GuardSignatureCache = @{} }
    try {
        $revision = [ClaudeGuardNative.ApplicationInterop]::FileRevision($Path)
        $cached = $script:GuardSignatureCache[$Path]
        if ($revision -and $cached -and $cached.Revision -ceq $revision) { return $cached.Valid }
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $certificate = $signature.SignerCertificate
        $valid = $signature.Status -eq 'Valid' -and $certificate -and (
            $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ceq 'Anthropic, PBC'
        )
        if ($revision -and $revision -cne [ClaudeGuardNative.ApplicationInterop]::FileRevision($Path)) { return $false }
        if ($revision) {
            $script:GuardSignatureCache[$Path] = @{ Revision = $revision; Valid = $valid }
        }
        return $valid
    } catch {
        return $false
    }
}

function Get-GuardInstallationExecutables([string]$Root) {
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        foreach ($item in (Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($item.PSIsContainer) {
                $pending.Push($item.FullName)
            } elseif ($item.Extension -ieq '.exe') {
                $item.FullName
            }
        }
    }
}

function Add-GuardInstallInventory([string]$Root, $Programs, $Roots) {
    $canonical = [ClaudeGuardNative.ApplicationInterop]::FinalPath($Root)
    $null = $Roots.Add($Root)
    $null = $Roots.Add($canonical)
    foreach ($path in Get-GuardInstallationExecutables $Root) {
        $resolved = [ClaudeGuardNative.ApplicationInterop]::FinalPath($path)
        if (-not (Test-GuardPathWithin $resolved $canonical)) {
            throw 'An executable resolved outside its Claude installation.'
        }
        $null = $Programs.Add($path)
        $null = $Programs.Add($resolved)
    }
}

function Get-GuardRegisteredCoworkServices {
    $filter = "Name='CoworkVMServiceStore' OR Name='CoworkVMService'"
    foreach ($service in Get-CimInstance Win32_Service -Filter $filter -ErrorAction Stop) {
        if ($service.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) { continue }
        if ($service.PathName -notmatch '^\s*(?:"([^"]+)"|(.+?\.exe))(?=\s|$)') { continue }
        $path = [Environment]::ExpandEnvironmentVariables($Matches[1] + $Matches[2])
        if ([IO.Path]::GetFileName($path) -ine 'cowork-svc.exe' -or -not (Test-GuardAnthropicSignature $path)) { continue }
        [pscustomobject]@{
            Id = [int]$service.ProcessId
            Running = $service.State -eq 'Running'
            Path = $path
            ResolvedPath = [ClaudeGuardNative.ApplicationInterop]::FinalPath($path)
        }
    }
}

function Get-GuardInventory {
    Initialize-GuardApplicationInterop
    $programs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $roots = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $desktopPaths = [Collections.Generic.List[string]]::new()
    $packages = [Collections.Generic.List[object]]::new()
    $families = @('AnthropicPBC.Claude_fnn82j28hfe8t', 'Claude_pzs8sxrjxfjjc')
    foreach ($package in (Get-AppxPackage -ErrorAction Stop | Where-Object PackageFamilyName -In $families)) {
        if ([string]$package.SignatureKind -ne 'Store' -or $package.IsDevelopmentMode -or [string]$package.Status -ne 'Ok') {
            throw 'A known Claude package is missing a healthy Microsoft Store registration.'
        }
        $root = [IO.Path]::GetFullPath($package.InstallLocation).TrimEnd('\')
        Add-GuardInstallInventory $root $programs $roots
        $packages.Add([pscustomobject]@{
            Family = $package.PackageFamilyName
            Root = $root
            Sid = [ClaudeGuardNative.ApplicationInterop]::PackageSid($package.PackageFamilyName)
        })
        $manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction Stop
        foreach ($entry in $manifest.Package.Applications.Application) {
            if (!$entry.Executable -or [IO.Path]::GetFileName($entry.Executable) -ine 'Claude.exe') { continue }
            $path = [IO.Path]::GetFullPath((Join-Path $root $entry.Executable))
            if (Test-GuardPathWithin $path $root) {
                if (-not $programs.Contains($path)) { throw 'Windows did not expose the registered Claude Desktop executable.' }
                $desktopPaths.Add($path)
            }
        }
    }

    $local = [Environment]::GetFolderPath('LocalApplicationData')
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $programFiles86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $classicRoots = @(
        (Join-Path $local 'AnthropicClaude')
        (Join-Path $local 'Programs\Claude')
        (Join-Path $local 'Programs\Anthropic\Claude')
        (Join-Path $programFiles 'Claude')
        (Join-Path $programFiles86 'Claude')
    )
    foreach ($root in ($classicRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container -ErrorAction Stop)) { continue }
        Add-GuardInstallInventory $root $programs $roots
        $versions = @(Get-ChildItem -LiteralPath $root -Directory -Filter 'app-*' -ErrorAction Stop | Sort-Object LastWriteTimeUtc -Descending)
        foreach ($folder in (@($versions.FullName) + $root)) {
            if (!$folder) { continue }
            $path = Join-Path $folder 'Claude.exe'
            if ($programs.Contains($path)) { $desktopPaths.Add($path) }
        }
    }

    $cliPath = $null
    $command = Get-Command -Name 'claude.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and (Test-GuardAnthropicSignature $command.Path)) {
        $cliPath = [ClaudeGuardNative.ApplicationInterop]::FinalPath($command.Path)
        $null = $programs.Add($command.Path)
        $null = $programs.Add($cliPath)
    }
    $services = @(Get-GuardRegisteredCoworkServices)
    foreach ($service in $services) {
        $null = $programs.Add($service.Path)
        $null = $programs.Add($service.ResolvedPath)
    }
    [pscustomobject]@{
        Programs = @($programs | Sort-Object)
        DesktopPaths = $desktopPaths.ToArray()
        CliPath = $cliPath
        Packages = $packages.ToArray()
        InstallationRoots = @($roots | Sort-Object)
        Services = $services
    }
}

function Get-GuardProcessTable {
    Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,SessionId,CreationDate,ExecutablePath -ErrorAction Stop
}

function Get-GuardRunningProcesses($Inventory) {
    Initialize-GuardApplicationInterop
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $Inventory.Programs) {
        $null = $paths.Add($path)
        $null = $names.Add([IO.Path]::GetFileName($path))
    }
    foreach ($process in Get-GuardProcessTable) {
        $path = [string]$process.ExecutablePath
        if (!$path -and $names.Contains($process.Name)) {
            $path = [ClaudeGuardNative.ApplicationInterop]::ProcessPath([int]$process.ProcessId)
        }
        $knownService = $false
        if ($process.SessionId -eq 0 -and $process.Name -ieq 'cowork-svc.exe') {
            $registered = @($Inventory.Services | Where-Object { $_.Running -and $_.Id -eq $process.ProcessId })
            if ($registered.Count -eq 1 -and (!$path -or $path -iin @($registered[0].Path,$registered[0].ResolvedPath))) {
                $path = $registered[0].Path
                $knownService = $true
            }
        }
        $protected = $knownService -or $paths.Contains($path)
        if ($path -and !$protected) {
            foreach ($root in $Inventory.InstallationRoots) {
                if (Test-GuardPathWithin $path $root) { $protected = $true; break }
            }
        }
        if (!$path -and $process.Name -iin @('claude.exe','cowork-svc.exe') -and $names.Contains($process.Name)) {
            throw 'Windows could not verify the path of a running Claude process.'
        }
        if ($protected) {
            [pscustomobject]@{
                Id = [int]$process.ProcessId
                ProcessName = [IO.Path]::GetFileNameWithoutExtension($process.Name)
                SessionId = [int]$process.SessionId
                Path = $path
            }
        }
    }
}

function Get-GuardStartedProcessIdentity([Diagnostics.Process]$Process, [string]$ExpectedPath) {
    Initialize-GuardApplicationInterop
    try {
        # Keeping this Process object alive also keeps its handle pinned until the session ends.
        $handle = $Process.Handle
        $created = [ClaudeGuardNative.ApplicationInterop]::ProcessCreation($handle)
        $path = [ClaudeGuardNative.ApplicationInterop]::ProcessPath($handle)
    } catch {
        if ($Process.HasExited) { return $null }
        throw
    }
    if (!$path -and $Process.HasExited) { return $null }
    $actual = [ClaudeGuardNative.ApplicationInterop]::FinalPath($path)
    if (!$ExpectedPath -or $actual -ine [ClaudeGuardNative.ApplicationInterop]::FinalPath($ExpectedPath)) {
        throw 'Windows started a different application than the verified Claude executable.'
    }
    $session = [Diagnostics.Process]::GetCurrentProcess()
    try {
        if ($Process.SessionId -eq 0 -or $Process.SessionId -ne $session.SessionId) {
            throw 'Windows did not start Claude in the current interactive session.'
        }
        [pscustomobject]@{ Id = $Process.Id; SessionId = $Process.SessionId; Created = $created }
    } finally { $session.Dispose() }
}

function Stop-GuardRunningProcesses($Inventory, [Diagnostics.Process]$StartedProcess, $Identity) {
    if (!$Identity) {
        $startedPath = [ClaudeGuardNative.ApplicationInterop]::ProcessPath($StartedProcess.Handle)
        if (!$startedPath -and $StartedProcess.HasExited) { return }
        if ($Inventory.Programs -inotcontains $startedPath -or -not (Test-GuardAnthropicSignature $startedPath)) {
            throw 'The guarded process identity is unavailable.'
        }
        $Identity = Get-GuardStartedProcessIdentity $StartedProcess $startedPath
        if (!$Identity) { return }
    }
    $verified = [Collections.Generic.Dictionary[int,long]]::new()
    $verified.Add($Identity.Id, $Identity.Created)
    $handles = [Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeWaitHandle]]::new()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $root = [ClaudeGuardNative.ApplicationInterop]::OpenMatchingProcess($Identity.Id, $Identity.Created)
        if ($root) {
            $handles.Add($root)
            [ClaudeGuardNative.ApplicationInterop]::StopProcess($root)
        }
        do {
            $found = 0
            $rows = Get-GuardProcessTable | Where-Object {
                $_.SessionId -eq $Identity.SessionId -and $_.CreationDate
            } | Sort-Object CreationDate
            foreach ($row in $rows) {
                $id = [int]$row.ProcessId
                $parent = [int]$row.ParentProcessId
                $created = ([datetime]$row.CreationDate).ToFileTimeUtc()
                if ($verified.ContainsKey($id) -or !$verified.ContainsKey($parent) -or $created + 9 -lt $verified[$parent]) { continue }
                $handle = [ClaudeGuardNative.ApplicationInterop]::OpenMatchingProcess($id, $created)
                if (!$handle) { continue }
                $handles.Add($handle)
                $verified.Add($id, $created)
                [ClaudeGuardNative.ApplicationInterop]::StopProcess($handle)
                $found++
            }
            if ($found -eq 0) { return }
        } while ($watch.Elapsed.TotalSeconds -lt $script:GuardShutdownConfirmSeconds)
        throw 'Windows did not confirm that all guarded descendants stopped.'
    } finally {
        foreach ($handle in $handles) { $handle.Dispose() }
    }
}

function ConvertTo-GuardNativeArgument([string]$Argument) {
    if ($Argument.IndexOf([char]0) -ge 0) { throw 'A Windows command-line argument cannot contain a null character.' }
    $result = [Text.StringBuilder]::new()
    $null = $result.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            $null = $result.Append([char]'\', 2 * $backslashes + 1)
        } elseif ($backslashes -gt 0) {
            $null = $result.Append([char]'\', $backslashes)
        }
        $null = $result.Append($character)
        $backslashes = 0
    }
    $null = $result.Append([char]'\', 2 * $backslashes)
    $null = $result.Append('"')
    $result.ToString()
}
