using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace ClaudeGuardNative
{
    public sealed class DesktopDataLocation
    {
        public string Kind = "";
        public string RootPath = "";
        public bool Exists;
        public bool HasMcpConfig;
        public string McpConfigPath = "";
        public long CleanableBytes;
        public string[] CleanableItems = new string[0];
        public string[] ProtectedItems = new string[0];
    }

    public sealed class DesktopStartupEntry
    {
        public string Source = "";
        public string Name = "";
        public string Detail = "";
        public bool Enabled;
    }

    public sealed class DesktopHygieneReport
    {
        public DesktopDataLocation[] Locations = new DesktopDataLocation[0];
        public DesktopStartupEntry[] StartupEntries = new DesktopStartupEntry[0];
        public bool HasAutoStartEnabled;
        public long TotalCleanableBytes;
        public string QuarantineRoot = "";
        public string[] Backups = new string[0];
    }

    public sealed class QuarantineItem
    {
        public string OriginalPath = "";
        public string BackupRelativePath = "";
        public bool IsDirectory;
    }

    public sealed class QuarantineManifest
    {
        public int Version = 1;
        public string CreatedUtc = "";
        public QuarantineItem[] Items = new QuarantineItem[0];
    }

    public sealed class QuarantineResult
    {
        public string BackupDirectory = "";
        public int MovedCount;
        public int PreservedMcpCount;
        public long MovedBytes;
        public string Message = "";
    }

    public static class DesktopHygiene
    {
        private static readonly Encoding Utf8 = new UTF8Encoding(false);
        private static readonly string[] StorePackageFamilies = new[]
        {
            "AnthropicPBC.Claude_fnn82j28hfe8t",
            "Claude_pzs8sxrjxfjjc"
        };

        // Explicitly protected user MCP configuration files that quarantine MUST NEVER move or delete.
        private static readonly HashSet<string> ProtectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "claude_desktop_config.json",
            "claude_desktop_config.json.bak"
        };

        // Curated Electron / Claude Desktop cache, session, cookie, and log entries eligible for safe quarantine.
        private static readonly HashSet<string> CleanableNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Cache",
            "Code Cache",
            "GPUCache",
            "DawnCache",
            "DawnGraphiteCache",
            "DawnWebGPUCache",
            "Network",
            "Cookies",
            "Cookies-journal",
            "Local Storage",
            "Session Storage",
            "IndexedDB",
            "Service Worker",
            "blob_storage",
            "Shared Dictionary",
            "SessionData",
            "logs",
            "Sentry",
            "Crashpad",
            "Local State",
            "Preferences",
            "window-state.json",
            "config.json"
        };

        public static string DefaultQuarantineRoot
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "ClaudeGuardNative",
                    "quarantine");
            }
        }

        public static DesktopHygieneReport Scan()
        {
            string roamingClaude = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Claude");
            string[] storeDirs = DiscoverStoreDataDirectories();
            return Scan(roamingClaude, storeDirs, null, DefaultQuarantineRoot);
        }

        public static DesktopHygieneReport Scan(
            string classicRoamingClaudeDir,
            string[] storeRoamingClaudeDirs,
            DesktopStartupEntry[] startupOverride,
            string quarantineRoot)
        {
            var locations = new List<DesktopDataLocation>();
            if (!String.IsNullOrWhiteSpace(classicRoamingClaudeDir))
                locations.Add(InspectLocation("Classic", classicRoamingClaudeDir));

            if (storeRoamingClaudeDirs != null)
            {
                foreach (string dir in storeRoamingClaudeDirs)
                {
                    if (!String.IsNullOrWhiteSpace(dir))
                        locations.Add(InspectLocation("StoreMsix", dir));
                }
            }

            DesktopStartupEntry[] startupEntries = startupOverride != null
                ? startupOverride
                : DetectStartupEntries();

            bool autoStart = false;
            foreach (DesktopStartupEntry entry in startupEntries)
            {
                if (entry != null && entry.Enabled)
                {
                    autoStart = true;
                    break;
                }
            }

            long totalBytes = 0;
            foreach (DesktopDataLocation loc in locations)
                totalBytes += loc.CleanableBytes;

            string qRoot = String.IsNullOrWhiteSpace(quarantineRoot) ? DefaultQuarantineRoot : quarantineRoot;
            return new DesktopHygieneReport
            {
                Locations = locations.ToArray(),
                StartupEntries = startupEntries,
                HasAutoStartEnabled = autoStart,
                TotalCleanableBytes = totalBytes,
                QuarantineRoot = qRoot,
                Backups = ListBackups(qRoot)
            };
        }

        public static bool HasAutoStartWarning()
        {
            try
            {
                foreach (DesktopStartupEntry entry in DetectStartupEntries())
                {
                    if (entry.Enabled)
                        return true;
                }
            }
            catch (Exception) { }
            return false;
        }

        public static QuarantineResult Quarantine(DesktopHygieneReport report)
        {
            if (report == null)
                throw new ArgumentNullException("report");
            return Quarantine(report, report.QuarantineRoot);
        }

        public static QuarantineResult Quarantine(DesktopHygieneReport report, string quarantineRoot)
        {
            if (report == null)
                throw new ArgumentNullException("report");
            string root = String.IsNullOrWhiteSpace(quarantineRoot) ? DefaultQuarantineRoot : quarantineRoot;
            DirectoryInfo rootInfo = Directory.CreateDirectory(root);
            if ((rootInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("The quarantine folder is not a regular directory.");

            string stamp = "desktop-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) +
                "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string backupDir = Path.Combine(root, stamp);
            var movedItems = new List<QuarantineItem>();
            int preservedMcp = 0;
            long movedBytes = 0;
            int locIndex = 0;

            foreach (DesktopDataLocation loc in report.Locations)
            {
                locIndex++;
                if (loc == null || !loc.Exists || String.IsNullOrWhiteSpace(loc.RootPath) || !Directory.Exists(loc.RootPath))
                    continue;
                if (IsReparsePoint(loc.RootPath))
                    continue;
                if (loc.HasMcpConfig)
                    preservedMcp++;

                string locTag = loc.Kind + "-" + locIndex.ToString(CultureInfo.InvariantCulture);
                foreach (string relName in loc.CleanableItems)
                {
                    if (String.IsNullOrWhiteSpace(relName) || ProtectedNames.Contains(relName) || !CleanableNames.Contains(relName))
                        continue;

                    string sourcePath = Path.Combine(loc.RootPath, relName);
                    if (!File.Exists(sourcePath) && !Directory.Exists(sourcePath))
                        continue;
                    if (IsReparsePoint(sourcePath))
                        continue;

                    bool isDir = Directory.Exists(sourcePath);
                    long itemBytes = isDir ? MeasureDirectoryBytes(sourcePath) : new FileInfo(sourcePath).Length;

                    if (!Directory.Exists(backupDir))
                        Directory.CreateDirectory(backupDir);
                    string targetSub = Path.Combine(locTag, relName);
                    string destPath = Path.Combine(backupDir, targetSub);
                    string destParent = Path.GetDirectoryName(destPath);
                    if (!Directory.Exists(destParent))
                        Directory.CreateDirectory(destParent);

                    MoveFileOrDirectory(sourcePath, destPath, isDir);
                    movedItems.Add(new QuarantineItem
                    {
                        OriginalPath = sourcePath,
                        BackupRelativePath = targetSub,
                        IsDirectory = isDir
                    });
                    movedBytes += itemBytes;
                }
            }

            if (movedItems.Count == 0)
            {
                return new QuarantineResult
                {
                    BackupDirectory = "",
                    MovedCount = 0,
                    PreservedMcpCount = preservedMcp,
                    MovedBytes = 0,
                    Message = "No cleanable Claude Desktop cache or session items were found."
                };
            }

            var manifest = new QuarantineManifest
            {
                Version = 1,
                CreatedUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                Items = movedItems.ToArray()
            };
            File.WriteAllText(Path.Combine(backupDir, "manifest.json"), new JavaScriptSerializer().Serialize(manifest), Utf8);

            return new QuarantineResult
            {
                BackupDirectory = backupDir,
                MovedCount = movedItems.Count,
                PreservedMcpCount = preservedMcp,
                MovedBytes = movedBytes,
                Message = "Quarantined " + movedItems.Count + " item(s) (" + FormatBytes(movedBytes) + "). " +
                    (preservedMcp > 0 ? "MCP configuration (claude_desktop_config.json) preserved untouched." : "Backup saved for restore.")
            };
        }

        public static int Restore(string backupDirectory)
        {
            if (String.IsNullOrWhiteSpace(backupDirectory) || !Directory.Exists(backupDirectory))
                throw new DirectoryNotFoundException("Backup directory not found.");
            if (IsReparsePoint(backupDirectory))
                throw new IOException("Backup directory is not a regular directory.");

            string manifestPath = Path.Combine(backupDirectory, "manifest.json");
            if (!File.Exists(manifestPath) || IsReparsePoint(manifestPath))
                throw new FileNotFoundException("Backup manifest.json is missing or invalid.");

            string json = File.ReadAllText(manifestPath, Utf8);
            QuarantineManifest manifest = new JavaScriptSerializer().Deserialize<QuarantineManifest>(json);
            if (manifest == null || manifest.Version != 1 || manifest.Items == null)
                throw new InvalidOperationException("Backup manifest is invalid.");

            string fullBackupRoot = Path.GetFullPath(backupDirectory).TrimEnd('\\') + "\\";
            int restored = 0;

            foreach (QuarantineItem item in manifest.Items)
            {
                if (item == null || String.IsNullOrWhiteSpace(item.OriginalPath) || String.IsNullOrWhiteSpace(item.BackupRelativePath))
                    continue;
                string leaf = Path.GetFileName(item.OriginalPath);
                if (ProtectedNames.Contains(leaf) || !CleanableNames.Contains(leaf))
                    throw new InvalidOperationException("Refused to restore an unrecognized path from manifest: " + leaf);

                string sourcePath = Path.GetFullPath(Path.Combine(backupDirectory, item.BackupRelativePath));
                if (!sourcePath.StartsWith(fullBackupRoot, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Manifest path escapes backup directory.");
                if (IsReparsePoint(sourcePath))
                    continue;

                bool exists = item.IsDirectory ? Directory.Exists(sourcePath) : File.Exists(sourcePath);
                if (!exists)
                    continue;

                string destParent = Path.GetDirectoryName(item.OriginalPath);
                if (!String.IsNullOrEmpty(destParent) && !Directory.Exists(destParent))
                    Directory.CreateDirectory(destParent);
                if (IsReparsePoint(destParent))
                    throw new IOException("Target restore directory is not a regular directory.");

                if (item.IsDirectory && Directory.Exists(item.OriginalPath))
                    Directory.Delete(item.OriginalPath, true);
                else if (!item.IsDirectory && File.Exists(item.OriginalPath))
                    File.Delete(item.OriginalPath);

                MoveFileOrDirectory(sourcePath, item.OriginalPath, item.IsDirectory);
                restored++;
            }

            try
            {
                File.Delete(manifestPath);
                Directory.Delete(backupDirectory, true);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }

            return restored;
        }

        public static string CreateGuardedDesktopShortcut(string targetExePath)
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string linkPath = Path.Combine(desktop, "Claude (Native Guard).lnk");
            return CreateGuardedShortcut(targetExePath, linkPath);
        }

        public static string CreateGuardedShortcut(string targetExePath, string shortcutPath)
        {
            if (String.IsNullOrWhiteSpace(targetExePath) || !File.Exists(targetExePath))
                throw new FileNotFoundException("Native Guard executable not found: " + targetExePath);
            if (String.IsNullOrWhiteSpace(shortcutPath))
                throw new ArgumentException("Shortcut path is required.");

            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null)
                throw new InvalidOperationException("Windows Script Host (WScript.Shell) is unavailable.");

            object shell = null;
            object shortcut = null;
            try
            {
                shell = Activator.CreateInstance(shellType);
                shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { shortcutPath });
                Type scType = shortcut.GetType();
                scType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { targetExePath });
                scType.InvokeMember("Arguments", BindingFlags.SetProperty, null, shortcut, new object[] { "--launch-desktop" });
                scType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { Path.GetDirectoryName(targetExePath) });
                scType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { "Launch Claude Desktop through Claude Guard Native" });
                scType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { targetExePath + ",0" });
                scType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
                return shortcutPath;
            }
            finally
            {
                if (shortcut != null && Marshal.IsComObject(shortcut))
                    Marshal.ReleaseComObject(shortcut);
                if (shell != null && Marshal.IsComObject(shell))
                    Marshal.ReleaseComObject(shell);
            }
        }

        public static string FormatBytes(long bytes)
        {
            if (bytes < 1024)
                return bytes.ToString(CultureInfo.InvariantCulture) + " B";
            double kb = bytes / 1024.0;
            if (kb < 1024.0)
                return kb.ToString("F1", CultureInfo.InvariantCulture) + " KB";
            double mb = kb / 1024.0;
            return mb.ToString("F2", CultureInfo.InvariantCulture) + " MB";
        }

        private static string[] DiscoverStoreDataDirectories()
        {
            var list = new List<string>();
            string packagesRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Packages");
            if (!Directory.Exists(packagesRoot))
                return list.ToArray();

            foreach (string family in StorePackageFamilies)
            {
                string candidate = Path.Combine(packagesRoot, family, @"LocalCache\Roaming\Claude");
                if (Directory.Exists(candidate))
                    list.Add(candidate);
            }
            return list.ToArray();
        }

        private static DesktopDataLocation InspectLocation(string kind, string rootPath)
        {
            var loc = new DesktopDataLocation
            {
                Kind = kind,
                RootPath = rootPath,
                Exists = Directory.Exists(rootPath) && !IsReparsePoint(rootPath)
            };
            if (!loc.Exists)
                return loc;

            var cleanable = new List<string>();
            var protectedList = new List<string>();
            long bytes = 0;

            foreach (string entry in Directory.GetFileSystemEntries(rootPath))
            {
                if (IsReparsePoint(entry))
                    continue;
                string name = Path.GetFileName(entry);
                if (ProtectedNames.Contains(name))
                {
                    protectedList.Add(name);
                    if (String.Equals(name, "claude_desktop_config.json", StringComparison.OrdinalIgnoreCase))
                    {
                        loc.HasMcpConfig = true;
                        loc.McpConfigPath = entry;
                    }
                    continue;
                }
                if (CleanableNames.Contains(name))
                {
                    cleanable.Add(name);
                    bytes += Directory.Exists(entry) ? MeasureDirectoryBytes(entry) : new FileInfo(entry).Length;
                }
            }

            cleanable.Sort(StringComparer.OrdinalIgnoreCase);
            protectedList.Sort(StringComparer.OrdinalIgnoreCase);
            loc.CleanableItems = cleanable.ToArray();
            loc.ProtectedItems = protectedList.ToArray();
            loc.CleanableBytes = bytes;
            return loc;
        }

        private static DesktopStartupEntry[] DetectStartupEntries()
        {
            var entries = new List<DesktopStartupEntry>();

            // 1. Classic HKCU Run entries
            try
            {
                using (RegistryKey runKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false))
                {
                    if (runKey != null)
                    {
                        foreach (string valueName in runKey.GetValueNames())
                        {
                            string val = Convert.ToString(runKey.GetValue(valueName), CultureInfo.InvariantCulture) ?? "";
                            if (valueName.IndexOf("Claude", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                val.IndexOf("Claude.exe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                val.IndexOf("AnthropicClaude", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                entries.Add(new DesktopStartupEntry
                                {
                                    Source = "RegistryRun",
                                    Name = valueName,
                                    Detail = val,
                                    Enabled = true
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception) { }

            // 2. Microsoft Store MSIX StartupTask state (2 = Enabled, 4 = EnabledByPolicy)
            foreach (string family in StorePackageFamilies)
            {
                try
                {
                    string basePath = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\" + family;
                    using (RegistryKey familyKey = Registry.CurrentUser.OpenSubKey(basePath, false))
                    {
                        if (familyKey == null)
                            continue;
                        foreach (string subName in familyKey.GetSubKeyNames())
                        {
                            using (RegistryKey sub = familyKey.OpenSubKey(subName, false))
                            {
                                if (sub == null)
                                    continue;
                                object rawState = sub.GetValue("State");
                                if (rawState == null)
                                    continue;
                                int state = Convert.ToInt32(rawState, CultureInfo.InvariantCulture);
                                bool enabled = state == 2 || state == 4;
                                entries.Add(new DesktopStartupEntry
                                {
                                    Source = "StoreStartupTask",
                                    Name = family + "\\" + subName,
                                    Detail = enabled ? "Enabled (State=" + state + ")" : "Disabled (State=" + state + ")",
                                    Enabled = enabled
                                });
                            }
                        }
                    }
                }
                catch (Exception) { }
            }

            return entries.ToArray();
        }

        private static string[] ListBackups(string quarantineRoot)
        {
            if (String.IsNullOrWhiteSpace(quarantineRoot) || !Directory.Exists(quarantineRoot) || IsReparsePoint(quarantineRoot))
                return new string[0];
            var list = new List<string>();
            foreach (string dir in Directory.GetDirectories(quarantineRoot, "desktop-*"))
            {
                if (!IsReparsePoint(dir) && File.Exists(Path.Combine(dir, "manifest.json")))
                    list.Add(dir);
            }
            list.Sort(StringComparer.OrdinalIgnoreCase);
            list.Reverse();
            return list.ToArray();
        }

        private static bool IsReparsePoint(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
                return false;
            try
            {
                FileAttributes attrs = File.GetAttributes(path);
                return (attrs & FileAttributes.ReparsePoint) != 0;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static long MeasureDirectoryBytes(string dir)
        {
            long total = 0;
            var stack = new Stack<string>();
            stack.Push(dir);
            while (stack.Count > 0)
            {
                string current = stack.Pop();
                if (IsReparsePoint(current))
                    continue;
                try
                {
                    foreach (string file in Directory.GetFiles(current))
                    {
                        if (!IsReparsePoint(file))
                            total += new FileInfo(file).Length;
                    }
                    foreach (string sub in Directory.GetDirectories(current))
                    {
                        if (!IsReparsePoint(sub))
                            stack.Push(sub);
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            return total;
        }

        private static void MoveFileOrDirectory(string source, string destination, bool isDir)
        {
            if (!isDir)
            {
                File.Move(source, destination);
                return;
            }
            try
            {
                Directory.Move(source, destination);
            }
            catch (IOException)
            {
                CopyDirectoryRecursive(source, destination);
                Directory.Delete(source, true);
            }
        }

        private static void CopyDirectoryRecursive(string sourceDir, string destDir)
        {
            Directory.CreateDirectory(destDir);
            foreach (string file in Directory.GetFiles(sourceDir))
            {
                if (!IsReparsePoint(file))
                    File.Copy(file, Path.Combine(destDir, Path.GetFileName(file)), true);
            }
            foreach (string sub in Directory.GetDirectories(sourceDir))
            {
                if (!IsReparsePoint(sub))
                    CopyDirectoryRecursive(sub, Path.Combine(destDir, Path.GetFileName(sub)));
            }
        }
    }
}
