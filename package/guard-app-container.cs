using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ClaudeGuard.Processes
{
    public static class GuardAppContainer
    {
        public static string DeriveSid(string name)
        {
            ValidateProfileName(name);
            IntPtr sid;
            Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(name, out sid));
            try { return new SecurityIdentifier(sid).Value; }
            finally { FreeSid(sid); }
        }

        public static SecurityIdentifier CreateProfile(string name)
        {
            ValidateProfileName(name);
            IntPtr sid;
            Marshal.ThrowExceptionForHR(CreateAppContainerProfile(name, name, "Guard process scope", IntPtr.Zero, 0, out sid));
            try { return new SecurityIdentifier(sid); }
            finally { FreeSid(sid); }
        }

        public static void RemoveProfile(string name)
        {
            ValidateProfileName(name);
            Marshal.ThrowExceptionForHR(DeleteAppContainerProfile(name));
        }

        public static GuardContainedProcess StartVerified(string profileName, string expectedSid, string executable,
            string expectedHash, string arguments, WaitHandle closeSignal)
        {
            RequireOpenGate(closeSignal);
            string derived = DeriveSid(profileName);
            if (!String.Equals(derived, expectedSid, StringComparison.Ordinal))
                throw new InvalidOperationException("The registered AppContainer identity changed.");
            IntPtr folder;
            Marshal.ThrowExceptionForHR(GetAppContainerFolderPath(derived, out folder));
            try
            {
                if (!Directory.Exists(Marshal.PtrToStringUni(folder)))
                    throw new InvalidOperationException("The guarded AppContainer profile has not been installed.");
            }
            finally { Marshal.FreeCoTaskMem(folder); }
            executable = LocalImage(executable);
            using (var file = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create())
            {
                string actual = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "");
                if (!String.Equals(actual, expectedHash, StringComparison.Ordinal))
                    throw new InvalidOperationException("The executable no longer matches the approved hash.");
                return Start(executable, arguments, new SecurityIdentifier(derived), closeSignal, false, false);
            }
        }

        internal static GuardContainedProcess StartFixture(string executable, string arguments,
            SecurityIdentifier sid, bool lessPrivileged)
        {
            return Start(LocalImage(executable), arguments, sid, null, true, lessPrivileged);
        }

        private static void RequireOpenGate(WaitHandle closeSignal)
        {
            if (closeSignal == null || closeSignal.WaitOne(0))
                throw new InvalidOperationException("The proxy gate closed before launch.");
        }

        private static void ValidateProfileName(string name)
        {
            if (name == null || !Regex.IsMatch(name, @"\A(claude-guard|guard-fixture)-[a-f0-9]{32}\z"))
                throw new ArgumentException("Invalid Guard AppContainer name.");
        }

        private static string LocalImage(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length < 4 || !Char.IsLetter(path[0]) ||
                path[1] != ':' || path[2] != '\\' || !String.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("An absolute local Windows executable is required.");
            return Path.GetFullPath(path);
        }

        private static GuardContainedProcess Start(string image, string arguments, SecurityIdentifier identity,
            WaitHandle closeSignal, bool noWindow, bool lessPrivileged)
        {
            const int securityCapabilities = 0x00020009;
            const int jobList = 0x0002000d;
            const int allApplicationPackagesPolicy = 0x0002000f;
            const uint extendedStartupInfoPresent = 0x00080000;
            const uint createSuspended = 0x00000004;
            const uint createNoWindow = 0x08000000;
            const uint killOnJobClose = 0x00002000;

            var size = IntPtr.Zero;
            int count = lessPrivileged ? 3 : 2;
            InitializeProcThreadAttributeList(IntPtr.Zero, count, 0, ref size);
            var attributes = IntPtr.Zero;
            var capabilities = IntPtr.Zero;
            var nativeSid = IntPtr.Zero;
            var optOut = IntPtr.Zero;
            var job = IntPtr.Zero;
            var jobHandles = IntPtr.Zero;
            var child = new ProcessInformation();
            bool initialized = false;
            try
            {
                attributes = Marshal.AllocHGlobal(size);
                capabilities = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityCapabilities)));
                byte[] sidBytes = new byte[identity.BinaryLength];
                identity.GetBinaryForm(sidBytes, 0);
                nativeSid = Marshal.AllocHGlobal(sidBytes.Length);
                Marshal.Copy(sidBytes, 0, nativeSid, sidBytes.Length);
                Check(InitializeProcThreadAttributeList(attributes, count, 0, ref size));
                initialized = true;
                Marshal.StructureToPtr(new SecurityCapabilities { Sid = nativeSid }, capabilities, false);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(securityCapabilities), capabilities,
                    new IntPtr(Marshal.SizeOf(typeof(SecurityCapabilities))), IntPtr.Zero, IntPtr.Zero));
                if (lessPrivileged)
                {
                    optOut = Marshal.AllocHGlobal(sizeof(uint));
                    Marshal.WriteInt32(optOut, 1); // PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
                    Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(allApplicationPackagesPolicy), optOut,
                        new IntPtr(sizeof(uint)), IntPtr.Zero, IntPtr.Zero));
                }

                job = CreateJobObjectW(IntPtr.Zero, null);
                Check(job != IntPtr.Zero);
                var limits = new ExtendedJobLimits();
                limits.Basic.LimitFlags = killOnJobClose;
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedJobLimits))));
                jobHandles = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobHandles, job);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(jobList), jobHandles,
                    new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
                var startup = new StartupInfoEx { AttributeList = attributes };
                startup.StartupInfo.Size = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
                var command = new StringBuilder("\"" + image + "\" " + arguments);
                uint flags = extendedStartupInfoPresent | createSuspended | (noWindow ? createNoWindow : 0);
                Check(CreateProcessW(image, command, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero,
                    Path.GetDirectoryName(image), ref startup, out child));
                VerifyToken(child.Process, identity);
                if (closeSignal != null) RequireOpenGate(closeSignal);
                Check(ResumeThread(child.Thread) != UInt32.MaxValue);

                var result = new GuardContainedProcess(child.Process, job, child.ProcessId);
                job = IntPtr.Zero;
                child.Process = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (child.Process != IntPtr.Zero)
                {
                    TerminateProcess(child.Process, 1);
                    CloseHandle(child.Process);
                }
                if (child.Thread != IntPtr.Zero) CloseHandle(child.Thread);
                if (job != IntPtr.Zero) CloseHandle(job);
                if (initialized) DeleteProcThreadAttributeList(attributes);
                Marshal.FreeHGlobal(jobHandles);
                Marshal.FreeHGlobal(optOut);
                Marshal.FreeHGlobal(nativeSid);
                Marshal.FreeHGlobal(capabilities);
                Marshal.FreeHGlobal(attributes);
            }
        }

        private static void VerifyToken(IntPtr process, SecurityIdentifier expected)
        {
            const int tokenIsAppContainer = 29;
            const int tokenCapabilities = 30;
            const int tokenAppContainerSid = 31;
            IntPtr token;
            Check(OpenProcessToken(process, 8 /* TOKEN_QUERY */, out token));
            try
            {
                if (ReadToken<int>(token, tokenIsAppContainer, Marshal.ReadInt32) != 1 ||
                    ReadToken<int>(token, tokenCapabilities, Marshal.ReadInt32) != 0 ||
                    !expected.Equals(ReadToken(token, tokenAppContainerSid, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)))))
                    throw new InvalidOperationException("Windows did not assign the expected AppContainer without capabilities.");
            }
            finally { CloseHandle(token); }
        }

        private static T ReadToken<T>(IntPtr token, int kind, Func<IntPtr, T> read)
        {
            uint size;
            GetTokenInformation(token, kind, IntPtr.Zero, 0, out size);
            if (size < sizeof(uint) || size > 65536)
                throw new InvalidOperationException("Windows returned an invalid process token size.");
            var buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                Check(GetTokenInformation(token, kind, buffer, size, out size));
                return read(buffer);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        internal static void Check(bool success)
        {
            if (!success) throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityCapabilities
        {
            public IntPtr Sid, Capabilities;
            public uint Count, Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfo
        {
            public uint Size;
            public IntPtr Reserved, Desktop, Title;
            public uint X, Y, Width, Height, Columns, Rows, Fill, Flags;
            public ushort ShowWindow, Reserved2Size;
            public IntPtr Reserved2, StandardInput, StandardOutput, StandardError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr AttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr Process, Thread;
            public uint ProcessId, ThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicJobLimits
        {
            public long ProcessTime, JobTime;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass, SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedJobLimits
        {
            public BasicJobLimits Basic;
            public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int CreateAppContainerProfile(string name, string displayName, string description,
            IntPtr capabilities, uint capabilityCount, out IntPtr sid);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int DeleteAppContainerProfile(string name);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int GetAppContainerFolderPath(string sid, out IntPtr path);
        [DllImport("advapi32.dll")]
        private static extern IntPtr FreeSid(IntPtr sid);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, uint size, out uint used);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list, int flags, IntPtr attribute, IntPtr value,
            IntPtr size, IntPtr previousValue, IntPtr returnSize);
        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
            IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup,
            out ProcessInformation child);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int kind, ref ExtendedJobLimits limits, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll")]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll")]
        internal static extern bool CloseHandle(IntPtr handle);
    }

    public sealed class GuardContainedProcess : IDisposable
    {
        private IntPtr process;
        private IntPtr job;
        public uint Id { get; private set; }

        internal GuardContainedProcess(IntPtr process, IntPtr job, uint id)
        {
            this.process = process;
            this.job = job;
            Id = id;
        }

        public bool WaitForExit(uint milliseconds)
        {
            uint status = WaitForSingleObject(process, milliseconds);
            if (status == 0 || status == 258) return status == 0;
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public uint ExitCode
        {
            get
            {
                uint code;
                GuardAppContainer.Check(GetExitCodeProcess(process, out code));
                return code;
            }
        }

        public bool HasRunningProcesses
        {
            get
            {
                JobAccounting accounting;
                uint written;
                GuardAppContainer.Check(QueryInformationJobObject(job, 1, out accounting,
                    (uint)Marshal.SizeOf(typeof(JobAccounting)), out written));
                return accounting.ActiveProcesses != 0;
            }
        }

        public void RequestClose()
        {
            if (WaitForExit(0)) return;
            try
            {
                using (var root = Process.GetProcessById((int)Id))
                    if (!root.HasExited) root.CloseMainWindow();
            }
            catch (ArgumentException) { if (!WaitForExit(0)) throw; }
        }

        public void StopTree(int milliseconds)
        {
            if (!HasRunningProcesses) return;
            GuardAppContainer.Check(TerminateJobObject(job, 1));
            var timer = Stopwatch.StartNew();
            while (HasRunningProcesses && timer.ElapsedMilliseconds < milliseconds) Thread.Sleep(25);
            if (HasRunningProcesses) throw new TimeoutException("The guarded process tree did not terminate.");
        }

        public void Dispose()
        {
            if (job == IntPtr.Zero) return;
            try { StopTree(2000); }
            finally
            {
                GuardAppContainer.CloseHandle(job);
                GuardAppContainer.CloseHandle(process);
                job = IntPtr.Zero;
                process = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobAccounting
        {
            public long TotalUserTime, TotalKernelTime, PeriodUserTime, PeriodKernelTime;
            public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int kind, out JobAccounting data,
            uint capacity, out uint written);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    }
}
