using System;
using System.Collections;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal interface IGuardSetupActions
{
    IDictionary Home();
    IDictionary Probe(string node, CancellationToken token);
    IDictionary ProbeCurrentNode(CancellationToken token);
    IDictionary Region(string zoneId, string localeName);
    IDictionary Update();
    IDictionary Apply(string zoneId, string localeName);
    IDictionary ApplyCurrentNode(string country, string ipv4, bool retirePrevious);
    IDictionary Recover();
    IDictionary CheckManualSetting(string setting, string target, bool confirmEdge, string operation);
    void OpenManualSetting(string settingId);
    IDictionary StartUserRegion(string country, string ipv4);
    IDictionary Progress();
    void ClearPreview();
}

internal sealed class GuardSetupActions : IGuardSetupActions, IDisposable
{
    private const string Failure = "操作未完成。请检查 Bettbox 连接和安装条件，再重试。";
    private readonly object gate = new object();
    private readonly object progressGate = new object();
    private readonly string bridge;
    private Runspace runspace;
    private IDictionary progress = new Hashtable();

    internal GuardSetupActions(string bridge)
    {
        this.bridge = bridge;
    }

    private void Initialize()
    {
        if (runspace != null) return;
        InitialSessionState state = InitialSessionState.CreateDefault2();
        state.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;
        state.ThrowOnRunspaceOpenError = true;
        Runspace session = RunspaceFactory.CreateRunspace(state);
        try
        {
            session.ApartmentState = ApartmentState.STA;
            session.ThreadOptions = PSThreadOptions.ReuseThread;
            session.Open();
            session.SessionStateProxy.Path.SetLocation(Environment.SystemDirectory);
            session.SessionStateProxy.SetVariable("GuardWindowProgress", new Action<string, int, int, string, string, int, int>(ReportProgress));
            using (PowerShell command = PowerShell.Create())
            {
                command.Runspace = session;
                command.AddScript("param($BridgePath) . $BridgePath").AddParameter("BridgePath", bridge);
                command.Invoke();
                if (command.Streams.Error.Count != 0) throw new InvalidOperationException("The verified setup actions could not be initialized.");
            }
            runspace = session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    private IDictionary Invoke(string name, params object[] arguments)
    {
        lock (gate)
        {
            Initialize();
            using (PowerShell command = PowerShell.Create())
            {
                command.Runspace = runspace;
                command.AddCommand(name);
                for (int i = 0; i < arguments.Length; i += 2)
                    command.AddParameter((string)arguments[i], arguments[i + 1]);

                Collection<PSObject> output = command.Invoke();
                if (command.Streams.Error.Count != 0 || output.Count != 1)
                    throw new InvalidOperationException(Failure);
                IDictionary result = output[0].BaseObject as IDictionary;
                if (result == null) throw new InvalidOperationException(Failure);
                return result;
            }
        }
    }

    private IDictionary Change(string command, params object[] arguments)
    {
        string phase = command == "Set-GuardWindowCurrentNode" ? "CheckingCurrentNode" : "Preparing";
        ReportProgress(phase, 0, command == "Restore-GuardWindow" ? 2 : 6, null, null, 0, 0);
        try { return Invoke(command, arguments); }
        catch (Exception) { return new Hashtable { { "Success", false }, { "Restored", false }, { "Message", Failure } }; }
    }

    public IDictionary Home()
    {
        IDictionary home = Invoke("Get-GuardWindowHome");
        home["Version"] = GuardSetup.ReleaseVersion;
        return home;
    }

    public IDictionary Probe(string node, CancellationToken token)
    {
        try { return Invoke("Get-GuardWindowProbe", "Node", node, "Token", token); }
        catch (Exception) { return new Hashtable { { "Ok", false }, { "Message", Failure } }; }
    }

    public IDictionary ProbeCurrentNode(CancellationToken token)
    {
        try { return Invoke("Get-GuardWindowProbe", "CurrentBettbox", true, "Token", token); }
        catch (Exception) { return new Hashtable { { "Ok", false }, { "Message", Failure } }; }
    }

    public IDictionary Region(string zoneId, string localeName)
    {
        try { return Invoke("Get-GuardWindowRegion", "ZoneId", zoneId, "LocaleName", localeName); }
        catch (Exception) { return new Hashtable { { "RequiresChoice", true }, { "Message", Failure } }; }
    }

    public IDictionary Update() { return Change("Update-GuardWindow"); }
    public IDictionary Apply(string zoneId, string localeName)
    {
        return Change("Set-GuardWindowNode", "ZoneId", zoneId, "LocaleName", localeName);
    }
    public IDictionary ApplyCurrentNode(string country, string ipv4, bool retirePrevious)
    {
        return Change("Set-GuardWindowCurrentNode", "CountryCode", country, "ExitIpv4", ipv4, "RetirePrevious", retirePrevious);
    }
    public IDictionary Recover() { return Change("Restore-GuardWindow"); }

    public IDictionary CheckManualSetting(string setting, string target, bool confirmEdge, string operation)
    {
        return Invoke("Get-GuardWindowManualCheck", "Setting", setting, "Target", target, "ConfirmEdge", confirmEdge, "Operation", operation);
    }

    public void OpenManualSetting(string settingId) { ClaudeGuard.SiteLanguage.OpenManualSetting(settingId); }

    public IDictionary StartUserRegion(string country, string ipv4) { return GuardSetup.StartUserRegion(country, ipv4); }

    private void ReportProgress(string phase, int proofs, int required, string status, string worker, int elapsed, int timeout)
    {
        lock (progressGate)
        {
            progress = new Hashtable
            {
                { "Phase", phase }, { "FreshProofs", proofs }, { "RequiredProofs", required },
                { "Status", status }, { "WorkerStatus", worker }, { "ElapsedSeconds", elapsed }, { "TimeoutSeconds", timeout }
            };
        }
    }

    public IDictionary Progress()
    {
        lock (progressGate) { return new Hashtable(progress); }
    }

    public void ClearPreview()
    {
        lock (gate) { if (runspace != null) Invoke("Clear-GuardWindowPreview"); }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (runspace == null) return;
            try { ClearPreview(); }
            finally { runspace.Dispose(); runspace = null; }
        }
    }
}

internal static class GuardBackgroundProcess
{
    private const uint NoWindow = 0x08000000;
    private const uint Suspended = 0x00000004;
    private const uint KillOnJobClose = 0x00002000;

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public uint Size;
        public IntPtr Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, Columns, Rows, FillAttribute, Flags;
        public ushort ShowWindow, ReservedCount;
        public IntPtr ReservedData, StandardInput, StandardOutput, StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process, Thread;
        public uint ProcessId, ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobLimits
    {
        public long ProcessUserTime, JobUserTime;
        public uint Flags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
        public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processSecurity,
        IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref StartupInfo startup, out ProcessInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool SetInformationJobObject(IntPtr job, int kind, ref JobLimits limits, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint status);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool TerminateProcess(IntPtr process, uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CloseHandle(IntPtr handle);

    internal static int Run(string executable, string arguments)
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var limits = new JobLimits { Flags = KillOnJobClose };
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(JobLimits))))
                throw new Win32Exception();
            var startup = new StartupInfo { Size = (uint)Marshal.SizeOf(typeof(StartupInfo)) };
            var command = new StringBuilder("\"" + executable + "\" " + arguments);
            ProcessInformation child;
            if (!CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, false, NoWindow | Suspended,
                IntPtr.Zero, Environment.SystemDirectory, ref startup, out child)) throw new Win32Exception();
            try
            {
                if (!AssignProcessToJobObject(job, child.Process))
                {
                    var error = new Win32Exception();
                    TerminateProcess(child.Process, 1);
                    throw error;
                }
                if (ResumeThread(child.Thread) == UInt32.MaxValue) throw new Win32Exception();
                uint status;
                if (WaitForSingleObject(child.Process, UInt32.MaxValue) != 0 || !GetExitCodeProcess(child.Process, out status))
                    throw new Win32Exception();
                return unchecked((int)status);
            }
            finally { CloseHandle(child.Thread); CloseHandle(child.Process); }
        }
        finally { CloseHandle(job); }
    }
}
