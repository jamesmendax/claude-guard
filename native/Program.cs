using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("Claude Guard Native")]
[assembly: AssemblyProduct("Claude Guard Native")]
[assembly: AssemblyDescription("Local Windows VPN and firewall launch guard")]
[assembly: AssemblyVersion("1.0.9.0")]
[assembly: AssemblyFileVersion("1.0.9.0")]

namespace ClaudeGuardNative
{
    internal sealed class GuardResult
    {
        public bool Ok;
        public bool Ready;
        public bool CanConfigure;
        public string Route;
        public string Firewall;
        public string Claude;
        public string Message;
        public int ExitCode;

        internal static GuardResult Failure(string message)
        {
            return new GuardResult
            {
                Route = "Unverified",
                Firewall = "Unverified",
                Claude = "Not checked",
                Message = message,
                ExitCode = 1
            };
        }
    }

    internal static class GuardEngine
    {
        internal static string ReadResource(string name)
        {
            Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
            if (stream == null)
                throw new InvalidOperationException("A packaged Native Guard resource is missing.");
            using (var reader = new StreamReader(stream))
                return reader.ReadToEnd();
        }

        internal static InitialSessionState CreateSessionState(params string[] names)
        {
            string moduleRoot = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "Modules");
            var state = InitialSessionState.CreateDefault();
            state.Variables.Add(new SessionStateVariableEntry(
                "PSModuleAutoLoadingPreference", "None", "Load only the Windows inbox modules."));
            var modules = new string[names.Length];
            for (int i = 0; i < names.Length; i++)
            {
                modules[i] = Path.Combine(moduleRoot, names[i], names[i] + ".psd1");
                if (!File.Exists(modules[i]))
                    throw new InvalidOperationException("This Windows installation lacks the " + names[i] + " module.");
            }
            if (modules.Length != 0)
                state.ImportPSModule(modules);
            return state;
        }

        internal static Collection<PSObject> Invoke(PowerShell shell)
        {
            Collection<PSObject> result = shell.Invoke();
            if (shell.Streams.Error.Count != 0)
                throw new InvalidOperationException(shell.Streams.Error[0].Exception.Message);
            return result;
        }

        private static T ReadProperty<T>(PSObject value, string name)
        {
            PSPropertyInfo property = value.Properties[name];
            if (property == null)
                throw new InvalidOperationException("The network check returned an incomplete result.");
            return LanguagePrimitives.ConvertTo<T>(property.Value);
        }

        internal static bool IsElevated()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        internal static GuardResult Run(string mode)
        {
            return Run(mode, null, null);
        }

        internal static GuardResult Run(string mode, string timeZone, string[] cliArguments)
        {
            GuardResult result = RunWindowsChecks(mode, timeZone, cliArguments);
            GuardDiagnostics.Record(mode, result);
            return result;
        }

        private static GuardResult RunWindowsChecks(string mode, string timeZone, string[] cliArguments)
        {
            Mutex launchLock = null;
            bool lockAcquired = false;
            try
            {
                bool launching = mode == "Launch" || mode == "LaunchCli";
                bool maintenance = mode == "Refresh" || mode == "RemoveRules";
                if (launching && IsElevated())
                    return GuardResult.Failure("Open the guard normally before starting Claude.");
                if ((mode == "Configure" || maintenance) && !IsElevated())
                    return GuardResult.Failure("Firewall setup requires administrator approval.");
                if (maintenance && !IsInstalledConsole())
                    return GuardResult.Failure("Run this action through the installed Native Guard 1.0.9 console.");
                if (launching || mode == "RemoveRules")
                {
                    launchLock = new Mutex(false, @"Global\ClaudeGuardNativeFirewallSetup");
                    try { lockAcquired = launchLock.WaitOne(0); }
                    catch (AbandonedMutexException) { lockAcquired = true; }
                    if (!lockAcquired)
                        return GuardResult.Failure("A guarded session or firewall setup is already running.");
                }
                using (Runspace session = RunspaceFactory.CreateRunspace(
                    CreateSessionState("CimCmdlets", "NetAdapter", "NetTCPIP", "NetSecurity", "Appx")))
                {
                    session.Open();
                    using (PowerShell shell = PowerShell.Create())
                    {
                        shell.Runspace = session;
                        shell.AddScript(ReadResource("NetworkCore.ps1"), false);
                        Invoke(shell);
                        shell.Commands.Clear();
                        shell.AddScript(ReadResource("NativeSession.ps1"), false);
                        Invoke(shell);
                        shell.Commands.Clear();
                        shell.AddScript(ReadResource("NativeGuard.ps1"), false).AddParameter("Mode", mode);
                        if (!String.IsNullOrEmpty(timeZone))
                            shell.AddParameter("TimeZoneId", timeZone);
                        if (cliArguments != null)
                            shell.AddParameter("CliArguments", cliArguments);
                        Collection<PSObject> values = Invoke(shell);
                        if (values.Count != 1)
                            return GuardResult.Failure("The network check did not return one status result.");
                        PSObject result = values[0];
                        return new GuardResult
                        {
                            Ok = ReadProperty<bool>(result, "Ok"),
                            Ready = ReadProperty<bool>(result, "Ready"),
                            CanConfigure = ReadProperty<bool>(result, "CanConfigure"),
                            Route = ReadProperty<string>(result, "Route"),
                            Firewall = ReadProperty<string>(result, "Firewall"),
                            Claude = ReadProperty<string>(result, "Claude"),
                            Message = ReadProperty<string>(result, "Message"),
                            ExitCode = ReadProperty<int>(result, "ExitCode")
                        };
                    }
                }
            }
            catch (Exception error)
            {
                return GuardResult.Failure(error.Message);
            }
            finally
            {
                if (lockAcquired)
                    launchLock.ReleaseMutex();
                if (launchLock != null)
                    launchLock.Dispose();
            }
        }

        private static bool IsInstalledConsole()
        {
            string installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Claude Guard Native", "1.0.9", "ClaudeGuardNativeConsole.exe");
            return String.Equals(Application.ExecutablePath, installed, StringComparison.OrdinalIgnoreCase);
        }

        internal static GuardResult RequestConfiguration(string statusMode = "Status")
        {
            try
            {
                if (IsElevated())
                    return Run("Configure");
                string sid;
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    sid = identity.User.Value;
                var start = new ProcessStartInfo(Application.ExecutablePath, "--configure-admin " + sid)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WorkingDirectory = Environment.SystemDirectory
                };
                using (Process worker = Process.Start(start))
                {
                    if (worker == null)
                        return GuardResult.Failure("Windows did not start firewall setup.");
                    worker.WaitForExit();
                    if (worker.ExitCode != 0)
                        return GuardResult.Failure("Firewall setup did not complete. Check local protection again.");
                }
                return Run(statusMode);
            }
            catch (System.ComponentModel.Win32Exception error)
            {
                return GuardResult.Failure(error.NativeErrorCode == 1223
                    ? "Firewall setup was cancelled." : error.Message);
            }
            catch (Exception error)
            {
                return GuardResult.Failure(error.Message);
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 2 && args[0] == "--status-json")
            {
                GuardResult result = GuardEngine.Run("Status");
                try
                {
                    using (var file = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write))
                    using (var writer = new StreamWriter(file, new UTF8Encoding(false)))
                        writer.Write(new JavaScriptSerializer().Serialize(result));
                    return result.Ok ? 0 : 1;
                }
                catch (IOException) { return 2; }
                catch (UnauthorizedAccessException) { return 2; }
            }
            if (args.Length == 2 && args[0] == "--configure-admin")
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    if (!GuardEngine.IsElevated() || identity.User.Value != args[1])
                    {
                        MessageBox.Show("Approve setup using the same Windows account that runs Claude.",
                            "Claude Guard Native", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return 1;
                    }
                }
                GuardResult result = GuardEngine.Run("Configure");
#if GUARD_CONSOLE
                Console.Error.WriteLine(result.Message);
#else
                MessageBox.Show(result.Message, "Claude Guard Native", MessageBoxButtons.OK,
                    result.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
#endif
                return result.Ok ? 0 : 1;
            }
            if (args.Length > 0 && args[0] == "--dns-admin")
                return DnsSettingsWindow.RunAdmin(args);
#if GUARD_CONSOLE
            return RunConsole(args);
#else
            bool regional = args.Length == 1 && args[0] == "--region";
            if (args.Length != 0 && !regional)
                return 2;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (Form window = regional ? (Form)new RegionalSettingsWindow() : new GuardWindow())
            {
                if (regional)
                {
                    window.StartPosition = FormStartPosition.CenterScreen;
                    window.ShowInTaskbar = true;
                }
                Application.Run(window);
            }
            return 0;
#endif
        }

#if GUARD_CONSOLE
        private static int RunConsole(string[] args)
        {
            if (args.Length == 0 || (args.Length == 1 && args[0] == "--help"))
                return PrintUsage(0);
            if (args[0] == "--status" && (args.Length == 1 || (args.Length == 2 && args[1] == "--cli")))
            {
                GuardResult result = GuardEngine.Run(args.Length == 2 ? "StatusCli" : "Status");
                Console.WriteLine(new JavaScriptSerializer().Serialize(result));
                return result.Ready ? 0 : 1;
            }
            if (args[0] == "--configure" && (args.Length == 1 || (args.Length == 2 && args[1] == "--cli")))
                return Report(GuardEngine.RequestConfiguration(args.Length == 2 ? "StatusCli" : "Status"));
            if (args[0] == "--refresh" && args.Length == 1)
                return Report(GuardEngine.Run("Refresh"));
            if (args[0] == "--remove-rules" && args.Length == 1)
                return Report(GuardEngine.Run("RemoveRules"));
            if (args[0] == "--verify-package" && args.Length == 1)
                return RunMaintenance("ValidatePackage", false, false);
            if (args[0] == "--install" && (args.Length == 1 || (args.Length == 2 && args[1] == "--enable-refresh")))
                return RunMaintenance("Install", args.Length == 2, false);
            if (args[0] == "--disable-refresh" && args.Length == 1)
                return RunMaintenance("DisableRefresh", false, false);
            if (args[0] == "--uninstall" && (args.Length == 1 || (args.Length == 2 && args[1] == "--remove-rules")))
                return RunMaintenance("Remove", false, args.Length == 2);
            if (args[0] != "--desktop" && args[0] != "--cli")
                return PrintUsage(2);

            bool cli = args[0] == "--cli";
            string zone = null;
            int next = 1;
            if (next < args.Length && args[next] == "--time-zone")
            {
                if (next + 1 == args.Length || String.IsNullOrWhiteSpace(args[next + 1]))
                    return PrintUsage(2);
                zone = args[next + 1];
                next += 2;
            }
            string[] childArguments = new string[0];
            if (cli && next < args.Length && args[next] == "--")
            {
                next += 1;
                childArguments = new string[args.Length - next];
                Array.Copy(args, next, childArguments, 0, childArguments.Length);
                next = args.Length;
            }
            if (next != args.Length)
                return PrintUsage(2);

            // The child receives console control signals. Keep the guard alive for cleanup.
            ConsoleCancelEventHandler keepGuardOpen = delegate(object sender, ConsoleCancelEventArgs e)
            {
                if (e.SpecialKey == ConsoleSpecialKey.ControlC)
                    e.Cancel = true;
            };
            Console.CancelKeyPress += keepGuardOpen;
            try { return Report(GuardEngine.Run(cli ? "LaunchCli" : "Launch", zone, childArguments)); }
            finally { Console.CancelKeyPress -= keepGuardOpen; }
        }

        private static int Report(GuardResult result)
        {
            Console.Error.WriteLine(result.Message);
            return result.Ok ? result.ExitCode : 1;
        }

        private static int RunMaintenance(string action, bool enableRefresh, bool removeRules)
        {
            try
            {
                bool verifying = action == "ValidatePackage";
                if (!verifying && !GuardEngine.IsElevated())
                    throw new InvalidOperationException("Open Windows Terminal as administrator under the Windows account that will use Native Guard.");
                if (action == "Remove" &&
                    Application.ExecutablePath.EndsWith("\\ClaudeGuardNativeConsole.exe", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Run uninstall from the portable console in the extracted package.");
                string[] modules = verifying ? new string[0] : new[] { "CimCmdlets", "ScheduledTasks" };
                using (Runspace session = RunspaceFactory.CreateRunspace(GuardEngine.CreateSessionState(modules)))
                {
                    session.Open();
                    using (PowerShell shell = PowerShell.Create())
                    {
                        shell.Runspace = session;
                        shell.AddScript(GuardEngine.ReadResource("Manage-NativeGuard.ps1"))
                            .AddParameter("Action", action)
                            .AddParameter("PackageDirectory", Path.GetDirectoryName(Application.ExecutablePath));
                        if (enableRefresh)
                            shell.AddParameter("EnableRefresh");
                        if (removeRules)
                            shell.AddParameter("RemoveRules");
                        foreach (PSObject item in GuardEngine.Invoke(shell))
                            Console.WriteLine(item.ToString());
                    }
                }
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine(error.Message);
                return 1;
            }
        }

        private static int PrintUsage(int exitCode)
        {
            TextWriter writer = exitCode == 0 ? Console.Out : Console.Error;
            writer.WriteLine("Claude Guard Native 1.0.9");
            writer.WriteLine("  --status [--cli]");
            writer.WriteLine("  --configure [--cli]");
            writer.WriteLine("  --desktop [--time-zone ID]");
            writer.WriteLine("  --cli [--time-zone ID] [-- CLAUDE_ARGUMENTS...]");
            writer.WriteLine("  --verify-package");
            writer.WriteLine("  --install [--enable-refresh]");
            writer.WriteLine("  --disable-refresh");
            writer.WriteLine("  --uninstall [--remove-rules]");
            return exitCode;
        }
#endif
    }
}
