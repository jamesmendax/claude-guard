using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;

[assembly: AssemblyTitle("Claude Guard Setup")]
[assembly: AssemblyProduct("Claude Guard")]
[assembly: AssemblyVersion("1.0.4.0")]
[assembly: AssemblyFileVersion("1.0.4.0")]
[assembly: AssemblyInformationalVersion("1.0.4")]

internal static partial class GuardSetup
{
    private const string SetupName = "Claude Guard Setup";
    private const string Launcher = "ClaudeGuardSetup.exe";
    internal const string ReleaseVersion = "1.0.4";
    private const string ApplyCurrentNode = "--apply-current-node";
    private const string RetirePrevious = "--retire-previous";
    private const string ActionsPath = "release/guard-window-actions.ps1";
    private static readonly Assembly Image = Assembly.GetExecutingAssembly();
    private static readonly SecurityIdentifier Administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemAccount = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    private static readonly Regex SafePart = new Regex(@"\A[A-Za-z0-9][A-Za-z0-9._-]*\z", RegexOptions.CultureInvariant);
    private static readonly Regex TestFolder = new Regex(@"\Aguard-setup-test-[a-f0-9]{32}\z", RegexOptions.CultureInvariant);
    private static readonly Regex DosDevice = new Regex(@"\A(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|\z)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

    [STAThread]
    internal static int Main(string[] args)
    {
        bool consoleOnly = args.Length > 0 && (args[0] == "--verify" || args[0] == "--extract-test" ||
            args[0] == "--background-controller" || args[0] == "--background-notifier" || args[0] == "--apply-user-region" || args[0] == "--user-region-settings");
        try
        {
            if(args.Length>0 && (args[0]=="--apply-user-region" || args[0]=="--user-region-settings"))
                return RunUserRegionMode(args);
            if (args.Length == 1 && args[0] == "--verify")
            {
                Bundle bundle = new Bundle();
                bundle.ReadArchive(null);
                using (FileStream own = OpenImage()) ReadBoundImage(own);
                Console.WriteLine("Verified " + bundle.Count + " files. Manifest SHA-256 " + bundle.ManifestHash + ".");
                return 0;
            }
            if (args.Length == 2 && args[0] == "--extract-test")
            {
                string path = Path.GetFullPath(args[1]);
                string temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
                if (!String.Equals(Path.GetDirectoryName(path), temp, StringComparison.OrdinalIgnoreCase) ||
                    !TestFolder.IsMatch(Path.GetFileName(path)) || Directory.Exists(path) || File.Exists(path))
                    throw new InvalidOperationException("Use a new guard-setup-test-<32 lowercase hex> directory under your Windows TEMP directory.");
                AssertNotLink(temp);
                Bundle bundle = new Bundle();
                Directory.CreateDirectory(path);
                AssertNotLink(path);
                bundle.ReadArchive(path);
                bundle.VerifyTree(path, false, null);
                Console.WriteLine("Extracted and verified " + bundle.Count + " files without installing.");
                return 0;
            }

            RequireNativeAmd64();
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                string sid = identity.User.Value;
                bool elevated = new WindowsPrincipal(identity).IsInRole(Administrators);
                if (args.Length == 1 && (args[0] == "--background-controller" || args[0] == "--background-notifier"))
                    return RunBackground(args[0] == "--background-controller", elevated);

                bool approved = args.Length >= 2 && args[0] == "--approved";
                int offset = approved ? 2 : 0;
                string mode = args.Length > offset ? args[offset] : "";
                string country = null;
                string ipv4 = null;
                bool retirePrevious = false;
                if (mode == ApplyCurrentNode)
                {
                    retirePrevious = args.Length == offset + 4 && args[offset + 3] == RetirePrevious;
                    if ((args.Length != offset + 3 && !retirePrevious) || !IsCurrentNodeTarget(args[offset + 1], args[offset + 2]))
                        throw new InvalidOperationException("用法：--apply-current-node 国家代码 公网 IPv4 [--retire-previous]。");
                    country = args[offset + 1];
                    ipv4 = args[offset + 2];
                }
                else if (args.Length != offset && (args.Length != offset + 1 || !IsWindowMode(mode)))
                {
                    consoleOnly = true;
                    throw new InvalidOperationException("Unknown setup arguments.");
                }

                string windowArguments = country == null ? mode : mode + " " + country + " " + ipv4;
                if (retirePrevious) windowArguments += " " + RetirePrevious;
                if (approved)
                {
                    consoleOnly = !elevated;
                    if (!elevated || args[1] != sid)
                        throw new InvalidOperationException("Approve setup as the same Windows account that opened it.");
                }
                else if (!elevated)
                {
                    var start = new ProcessStartInfo(Image.Location, "--approved " + sid + " " + windowArguments);
                    start.UseShellExecute = true;
                    start.Verb = "runas";
                    start.WorkingDirectory = Environment.SystemDirectory;
                    // Keep the reviewed executable pinned against replacement while UAC opens it.
                    using (FileStream own = OpenImage())
                    {
                        ReadBoundImage(own);
                        using (Process child = Process.Start(start))
                        {
                            if (child == null) throw new InvalidOperationException("Windows did not start the approved setup process.");
                            child.WaitForExit();
                            return child.ExitCode;
                        }
                    }
                }

                return RunApproved(mode, windowArguments, sid, country, ipv4, retirePrevious);
            }
        }
        catch (Win32Exception error)
        {
            if (error.NativeErrorCode == 1223) return 1223;
            return ReportFailure(error, consoleOnly);
        }
        catch (Exception error) { return ReportFailure(error, consoleOnly); }
    }

    private static int ReportFailure(Exception error, bool consoleOnly)
    {
        if (consoleOnly) Console.Error.WriteLine(error.Message);
        else MessageBox.Show(error.Message, SetupName, MessageBoxButton.OK, MessageBoxImage.Error);
        return 1;
    }

    private static bool IsWindowMode(string mode) { return mode == "--settings" || mode == "--update"; }

    internal static bool IsCurrentNodeTarget(string country, string ipv4)
    {
        IPAddress address;
        return country.Length == 2 && country[0] >= 'A' && country[0] <= 'Z' &&
            country[1] >= 'A' && country[1] <= 'Z' &&
            IPAddress.TryParse(ipv4, out address) && address.AddressFamily == AddressFamily.InterNetwork &&
            String.Equals(address.ToString(), ipv4, StringComparison.Ordinal);
    }

    private static void RequireNativeAmd64()
    {
        try
        {
            ushort processMachine, nativeMachine;
            using (Process process = Process.GetCurrentProcess())
                if (Environment.Is64BitProcess && IsWow64Process2(process.Handle, out processMachine, out nativeMachine) &&
                    processMachine == 0 && nativeMachine == 0x8664) return;
        }
        catch (EntryPointNotFoundException) { }
        throw new PlatformNotSupportedException("This Sandboxie driver requires native x64 Windows.");
    }

    private static int RunApproved(string mode, string windowArguments, string sid, string country, string ipv4, bool retirePrevious)
    {
        if (!Environment.Is64BitProcess || !Environment.UserInteractive)
            throw new InvalidOperationException("Setup requires a 64-bit interactive Windows session.");

        byte[] executable;
        using (FileStream own = OpenImage()) executable = ReadBoundImage(own);
        string imageHash;
        using (var imageData = new MemoryStream(executable, false)) imageHash = Hash(imageData);
        Bundle bundle = new Bundle();
        string root = GetDataRoot();
        CreateProtectedDirectory(root);
        string stage = GetStage(root, imageHash);

        if (!Directory.Exists(stage))
        {
            string pending = Path.Combine(root, "release-install-" + Guid.NewGuid().ToString("N"));
            CreateProtectedDirectory(pending);
            bundle.ReadArchive(pending, true);
            string copied = Path.Combine(pending, Launcher);
            using (Stream to = new FileStream(copied, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                to.Write(executable, 0, executable.Length);
            SetProtectedFileOwner(copied);
            bundle.VerifyTree(pending, true, imageHash);
            try { Directory.Move(pending, stage); }
            catch (IOException) { if (!Directory.Exists(stage)) throw; }
        }
        bundle.VerifyTree(stage, true, imageHash);

        string launcher = Path.Combine(stage, Launcher);
        if (!String.Equals(Image.Location, launcher, StringComparison.OrdinalIgnoreCase))
        {
            var start = new ProcessStartInfo(launcher, "--approved " + sid + " " + windowArguments);
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.WorkingDirectory = Environment.SystemDirectory;
            using (Process child = Process.Start(start))
            {
                if (child == null) throw new InvalidOperationException("Windows did not start the verified setup window.");
                child.WaitForExit();
                return child.ExitCode;
            }
        }

        SetTrustedProcessEnvironment();
        UnhandledExceptionEventHandler terminal = delegate(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.IsTerminating) RecordWindowFailure(root, e.ExceptionObject as Exception);
        };
        AppDomain.CurrentDomain.UnhandledException += terminal;
        try
        {
            using (var actions = new GuardSetupActions(Destination(stage, ActionsPath)))
                return GuardSetupWindow.Run(actions, mode == "--settings", mode == "--update", country, ipv4, retirePrevious);
        }
        catch (Exception error)
        {
            bool saved = RecordWindowFailure(root, error);
            string next = saved ? "重新打开后，可在首页的停止详情中查看这条记录。" : "这次未能保存错误记录。";
            throw new InvalidOperationException(String.Format(CultureInfo.InvariantCulture,
                "Guard 设置窗口意外关闭。错误代码 0x{0:X8}。{1}", unchecked((uint)error.HResult), next), error);
        }
        finally { AppDomain.CurrentDomain.UnhandledException -= terminal; }
    }

    private static string WindowFailureRecord(Exception error, DateTime utc)
    {
        string kind = error is UnauthorizedAccessException ? "WindowsAccess" :
            error is IOException ? "FileAccess" :
            error is Win32Exception || error is COMException ? "WindowsError" : "RuntimeError";
        return String.Format(CultureInfo.InvariantCulture,
            "{{\"Schema\":1,\"Component\":\"GuardSettingsWindow\",\"TimeUtc\":\"{0:o}\",\"Kind\":\"{1}\",\"HResult\":\"0x{2:X8}\"}}",
            utc.ToUniversalTime(), kind, unchecked((uint)error.HResult));
    }

    private static bool RecordWindowFailure(string root, Exception error)
    {
        if (error == null) return false;
        string temporary = null;
        try
        {
            AssertProtected(root, true);
            string receipt = Path.Combine(root, "setup-last-window-error.json");
            string name = Path.Combine(root, "setup-window-error-" + Guid.NewGuid().ToString("N") + ".tmp");
            using (var stream = new FileStream(name, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                temporary = name;
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                    writer.Write(WindowFailureRecord(error, DateTime.UtcNow));
            }
            SetProtectedFileOwner(temporary);
            if (!File.Exists(receipt))
            {
                try { File.Move(temporary, receipt); temporary = null; return true; }
                catch (IOException) { if (!File.Exists(receipt)) throw; }
            }
            AssertProtected(receipt, false);
            File.Replace(temporary, receipt, null);
            temporary = null;
            return true;
        }
        // Diagnostic persistence must never replace the original failure or affect enforcement.
        catch (Exception) { return false; }
        finally
        {
            if (temporary != null) try { File.Delete(temporary); } catch (Exception) { }
        }
    }

    private static int RunBackground(bool controller, bool elevated)
    {
        if (controller && !elevated)
            throw new InvalidOperationException("The installed Guard controller requires its approved administrator account.");
        string root = GetDataRoot();
        string imageHash;
        using (FileStream own = OpenImage())
        using (var imageData = new MemoryStream(ReadBoundImage(own), false)) imageHash = Hash(imageData);
        string stage = GetStage(root, imageHash);
        if (!String.Equals(Image.Location, Path.Combine(stage, Launcher), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Use the protected Guard background launcher.");
        AssertProtected(root, true);
        AssertProtected(stage, true);
        AssertProtected(Image.Location, false);
        string daily = Path.Combine(root, "daily");
        string script = Path.Combine(daily, controller ? "guard-daily-supervisor.ps1" : "guard-daily-notifier.ps1");
        AssertProtected(daily, true);
        AssertProtected(script, false);
        string powershellHome = SetTrustedProcessEnvironment();
        string executable = Path.Combine(powershellHome, "powershell.exe");
        string arguments = "-NoProfile -NonInteractive " + (controller ? "" : "-STA ") +
            "-ExecutionPolicy Bypass -File \"" + script + "\"" + (controller ? " -Run" : "");
        return GuardBackgroundProcess.Run(executable, arguments);
    }

    private static string GetDataRoot()
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (String.IsNullOrEmpty(programData)) throw new InvalidOperationException("Windows did not identify ProgramData.");
        AssertNotLink(programData);
        return Path.Combine(programData, "ClaudeVPNGuard");
    }

    private static string GetStage(string root, string imageHash)
    {
        return Path.Combine(root, "release-install-" + imageHash.Substring(0, 32).ToLowerInvariant());
    }

    private static string SetTrustedProcessEnvironment()
    {
        string system = Environment.SystemDirectory;
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string powershellHome = Path.Combine(system, @"WindowsPowerShell\v1.0");
        Environment.CurrentDirectory = system;
        Environment.SetEnvironmentVariable("PATH", system + ";" + windows + ";" + powershellHome);
        Environment.SetEnvironmentVariable("PSModulePath", Path.Combine(powershellHome, "Modules"));
        Environment.SetEnvironmentVariable("ComSpec", Path.Combine(system, "cmd.exe"));
        return powershellHome;
    }

    private static FileStream OpenImage()
    {
        return new FileStream(Image.Location, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    private static byte[] ReadBoundImage(FileStream stream)
    {
        if (stream.Length < 512 || stream.Length > 256 * 1024 * 1024)
            throw new InvalidOperationException("The setup executable has an invalid length.");
        var bytes = new byte[(int)stream.Length];
        for (int offset = 0; offset < bytes.Length;)
        {
            int count = stream.Read(bytes, offset, bytes.Length - offset);
            if (count == 0) throw new EndOfStreamException("The setup executable was truncated.");
            offset += count;
        }
        int pe = BitConverter.ToInt32(bytes, 60);
        if (pe < 64 || pe > bytes.Length - 92 || BitConverter.ToUInt32(bytes, pe) != 0x4550 ||
            BitConverter.ToUInt16(bytes, pe + 4) != 0x8664 || BitConverter.ToUInt32(bytes, pe + 8) != 0 ||
            BitConverter.ToUInt32(bytes, pe + 88) != 0)
            throw new InvalidOperationException("The setup executable no longer has its verified image header.");

        // The build derives the managed module GUID from the full unsigned image
        // with its GUID bytes cleared. Match the file against the loaded module.
        byte[] module = Image.ManifestModule.ModuleVersionId.ToByteArray();
        int found = -1;
        for (int i = 0; i <= bytes.Length - module.Length; i++)
        {
            int j = 0;
            while (j < module.Length && bytes[i + j] == module[j]) j++;
            if (j != module.Length) continue;
            if (found != -1) throw new InvalidOperationException("The setup image identity is ambiguous.");
            found = i;
        }
        if (found == -1) throw new InvalidOperationException("The setup file differs from the loaded executable.");
        Array.Clear(bytes, found, module.Length);
        byte[] digest;
        using (SHA256 sha = SHA256.Create()) digest = sha.ComputeHash(bytes);
        for (int i = 0; i < module.Length; i++)
            if (digest[i] != module[i]) throw new InvalidOperationException("The setup file failed its loaded-image identity check.");
        Array.Copy(module, 0, bytes, found, module.Length);
        return bytes;
    }

    private static void CreateProtectedDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            var acl = new DirectorySecurity();
            acl.SetOwner(Administrators);
            acl.SetAccessRuleProtection(true, false);
            InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            acl.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(SystemAccount, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            acl.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(path, acl);
        }
        AssertProtected(path, true);
    }

    private static void AssertNotLink(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("An installer path is redirected by a link or junction.");
    }

    private static void SetProtectedFileOwner(string path)
    {
        FileSecurity security = File.GetAccessControl(path);
        security.SetOwner(Administrators);
        File.SetAccessControl(path, security);
    }

    private static void AssertProtected(string path, bool directory)
    {
        AssertNotLink(path);
        if (((File.GetAttributes(path) & FileAttributes.Directory) != 0) != directory)
            throw new InvalidOperationException("An installer path has the wrong type.");
        FileSystemSecurity security = directory ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
        var owner = (SecurityIdentifier)security.GetOwner(typeof(SecurityIdentifier));
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if ((!owner.Equals(Administrators) && !owner.Equals(SystemAccount)) || descriptor.DiscretionaryAcl == null)
            throw new InvalidOperationException("An installer path is not owned and protected by administrators.");
        const FileSystemRights writable = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | (FileSystemRights)0x50000000;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & writable) != 0 &&
                !rule.IdentityReference.Equals(Administrators) && !rule.IdentityReference.Equals(SystemAccount))
                throw new InvalidOperationException("An installer path can be changed outside the administrators group.");
        }
    }

    private static string Destination(string root, string name)
    {
        return Path.Combine(root, name.Replace('/', Path.DirectorySeparatorChar));
    }

    private static string HashFile(string path)
    {
        using (Stream stream = File.OpenRead(path)) return Hash(stream);
    }

    private static string Hash(Stream stream)
    {
        using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
    }

    private static Stream Resource(string name)
    {
        Stream stream = Image.GetManifestResourceStream(name);
        if (stream == null) throw new InvalidOperationException("An embedded installer resource is missing.");
        return stream;
    }

    private sealed class Bundle
    {
        private sealed class Item
        {
            internal string Name;
            internal string Sha;
            internal long Length;
        }

        private readonly Dictionary<string, Item> items = new Dictionary<string, Item>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> stageFiles = new HashSet<string>(new[] { Launcher, "install-result.json" }, StringComparer.OrdinalIgnoreCase);
        private static readonly HashSet<string> stageDirectories = new HashSet<string>(new[] { "operations", "previous", "retired-daily" }, StringComparer.OrdinalIgnoreCase);
        internal readonly string ManifestHash;
        internal int Count { get { return items.Count; } }

        internal Bundle()
        {
            using (Stream manifest = Resource("Guard.Manifest"))
            {
                if (manifest.Length > 128 * 1024) throw new InvalidOperationException("The installer manifest is too large.");
                ManifestHash = Hash(manifest);
                manifest.Position = 0;
                using (var reader = new StreamReader(manifest, new UTF8Encoding(false, true), false))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] fields = line.Split('\t');
                        long length;
                        if (fields.Length != 3 || !Regex.IsMatch(fields[0], @"\A[A-F0-9]{64}\z") ||
                            !Int64.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out length) ||
                            length < 0 || length > 256 * 1024 * 1024 || !ValidName(fields[2]))
                            throw new InvalidOperationException("An installer manifest entry is invalid.");
                        string name = fields[2];
                        items.Add(name, new Item { Name = name, Sha = fields[0], Length = length });
                        for (int index = name.LastIndexOf('/'); index >= 0; index = name.LastIndexOf('/', index - 1))
                        {
                            directories.Add(name.Substring(0, index));
                            if (index == 0) break;
                        }
                    }
                }
            }
            if (!items.ContainsKey(ActionsPath) || items.Count > 256)
                throw new InvalidOperationException("The installer manifest does not identify the setup application.");
            foreach (string directory in directories)
                if (items.ContainsKey(directory)) throw new InvalidOperationException("An installer file conflicts with a directory.");
        }

        private static bool ValidName(string name)
        {
            if (name.Length > 180 || name.IndexOf('/') < 0) return false;
            foreach (string part in name.Split('/'))
                if (!SafePart.IsMatch(part) || part.EndsWith(".", StringComparison.Ordinal) || DosDevice.IsMatch(part)) return false;
            return true;
        }

        internal void ReadArchive(string output, bool protectedStage = false)
        {
            using (Stream content = Resource("Guard.Payload"))
            using (var archive = new ZipArchive(content, ZipArchiveMode.Read, false))
            {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    Item item;
                    if (!items.TryGetValue(entry.FullName, out item) || entry.FullName != item.Name ||
                        !seen.Add(entry.FullName) || entry.Length != item.Length)
                        throw new InvalidOperationException("The embedded archive differs from the installer manifest.");
                    using (Stream stream = entry.Open())
                    using (SHA256 sha = SHA256.Create())
                    {
                        var bytes = new byte[64 * 1024];
                        long length = 0;
                        FileStream target = null;
                        try
                        {
                            if (output != null)
                            {
                                string path = Destination(output, item.Name);
                                if (protectedStage)
                                {
                                    string parent = output;
                                    string[] parts = item.Name.Split('/');
                                    for (int i = 0; i < parts.Length - 1; i++)
                                    {
                                        parent = Path.Combine(parent, parts[i]);
                                        CreateProtectedDirectory(parent);
                                    }
                                }
                                else Directory.CreateDirectory(Path.GetDirectoryName(path));
                                target = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                            }
                            int read;
                            while ((read = stream.Read(bytes, 0, bytes.Length)) != 0)
                            {
                                length += read;
                                if (length > item.Length) throw new InvalidOperationException("An embedded file exceeds its verified length.");
                                sha.TransformBlock(bytes, 0, read, null, 0);
                                if (target != null) target.Write(bytes, 0, read);
                            }
                            sha.TransformFinalBlock(new byte[0], 0, 0);
                            if (length != item.Length || BitConverter.ToString(sha.Hash).Replace("-", "") != item.Sha)
                                throw new InvalidOperationException("An embedded file failed its SHA-256 check.");
                        }
                        finally { if (target != null) target.Dispose(); }
                    }
                    if (protectedStage) SetProtectedFileOwner(Destination(output, item.Name));
                }
                if (seen.Count != items.Count) throw new InvalidOperationException("The embedded archive is incomplete.");
            }
        }

        internal void VerifyTree(string root, bool protectedStage, string imageHash)
        {
            CheckDirectory(root, "", protectedStage);
            foreach (Item item in items.Values)
            {
                string path = Destination(root, item.Name);
                if (protectedStage) AssertProtected(path, false);
                else AssertNotLink(path);
                if (new FileInfo(path).Length != item.Length || HashFile(path) != item.Sha)
                    throw new InvalidOperationException("A staged installer file differs from its embedded SHA-256.");
            }
            if (protectedStage)
            {
                string path = Path.Combine(root, Launcher);
                AssertProtected(path, false);
                if (HashFile(path) != imageHash) throw new InvalidOperationException("The staged settings launcher differs from this verified setup executable.");
            }
        }

        private void CheckDirectory(string path, string prefix, bool protectedStage)
        {
            if (protectedStage) AssertProtected(path, true);
            else AssertNotLink(path);
            foreach (string entry in Directory.GetFileSystemEntries(path))
            {
                string leaf = Path.GetFileName(entry);
                string name = prefix + leaf;
                AssertNotLink(entry);
                bool directory = (File.GetAttributes(entry) & FileAttributes.Directory) != 0;
                if (directory && directories.Contains(name)) CheckDirectory(entry, name + "/", protectedStage);
                else if (!directory && items.ContainsKey(name)) continue;
                else if (protectedStage && prefix.Length == 0 && (directory ? stageDirectories.Contains(leaf) : stageFiles.Contains(leaf)))
                    AssertProtected(entry, directory);
                else throw new InvalidOperationException("The staged installer contains an unexpected file or directory.");
            }
        }
    }
}
