using System;
using System.Collections.Generic;
using System.ComponentModel;
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
        public QuarantineItem PendingItem;
    }

    public sealed class QuarantineResult
    {
        public string BackupDirectory = "";
        public int MovedCount;
        public int PreservedMcpCount;
        public long MovedBytes;
        public string Message = "";
    }

    public sealed class QuarantineInterruptedException : IOException
    {
        public readonly string BackupDirectory;

        public QuarantineInterruptedException(string backupDirectory, Exception cause)
            : base("Quarantine stopped. " + (String.IsNullOrEmpty(backupDirectory)
                ? "No items were saved. " : "Saved items are available in the restore list. ") + cause.Message, cause)
        {
            BackupDirectory = backupDirectory;
        }
    }

    public sealed class RestoreConflictException : IOException
    {
        public readonly string DestinationPath;
        public readonly int RestoredCount;

        public RestoreConflictException(string destinationPath, int restoredCount)
            : base("Restore stopped because the destination already exists.\n" + destinationPath +
                "\nRestored " + restoredCount + " item(s) in this attempt. The remaining items are still in the backup.")
        {
            DestinationPath = destinationPath;
            RestoredCount = restoredCount;
        }
    }

    public static class DesktopHygiene
    {
        private const int ErrorNotSameDevice = 17;
        private const int ErrorFileExists = 80;
        private const int ErrorAlreadyExists = 183;
        private const string QuarantineMarker = ".quarantine-in-progress";

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

            DateTime created = DateTime.UtcNow;
            string stamp = "desktop-" + created.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) +
                "-" + Guid.NewGuid().ToString("N");
            string backupDir = Path.Combine(rootInfo.FullName, stamp);
            string manifestPath = Path.Combine(backupDir, "manifest.json");
            // Version 2 is an interrupted or in-progress backup. Older builds must not consume it.
            var manifest = new QuarantineManifest
            {
                Version = 2,
                CreatedUtc = created.ToString("O", CultureInfo.InvariantCulture)
            };
            var movedItems = new List<QuarantineItem>();
            int preservedMcp = 0;
            long movedBytes = 0;
            int locIndex = 0;
            FileStream marker = null;

            try
            {
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
                        if (marker == null)
                        {
                            Directory.CreateDirectory(backupDir);
                            marker = new FileStream(Path.Combine(backupDir, QuarantineMarker), FileMode.CreateNew,
                                FileAccess.Write, FileShare.None, 4096, FileOptions.DeleteOnClose);
                        }
                        var item = new QuarantineItem
                        {
                            OriginalPath = sourcePath,
                            BackupRelativePath = Path.Combine(locTag, relName),
                            IsDirectory = isDir
                        };
                        string destination = ResolveBackupItemPath(backupDir, item.BackupRelativePath);
                        Directory.CreateDirectory(Path.GetDirectoryName(destination));

                        manifest.Items = movedItems.ToArray();
                        manifest.PendingItem = item;
                        WriteQuarantineManifest(manifestPath, manifest);
                        MoveIntoQuarantine(sourcePath, destination, isDir);
                        movedItems.Add(item);
                        movedBytes += itemBytes;
                        manifest.PendingItem = null;
                    }
                }

                if (movedItems.Count != 0)
                {
                    manifest.Version = 1;
                    manifest.Items = movedItems.ToArray();
                    WriteQuarantineManifest(manifestPath, manifest);
                }
            }
            catch (IOException error)
            {
                throw QuarantineFailure(backupDir, movedItems.Count, manifest.PendingItem, error);
            }
            catch (UnauthorizedAccessException error)
            {
                throw QuarantineFailure(backupDir, movedItems.Count, manifest.PendingItem, error);
            }
            finally
            {
                if (marker != null)
                    marker.Dispose();
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
            if (IsQuarantineActive(backupDirectory))
                throw new IOException("Quarantine is still running for this backup.");

            QuarantineManifest manifest = ReadQuarantineManifest(manifestPath);
            if (manifest == null || (manifest.Version != 1 && manifest.Version != 2) || manifest.Items == null)
                throw new InvalidOperationException("Backup manifest is invalid.");

            var savedItems = new List<QuarantineItem>(manifest.Items);
            if (manifest.Version == 2 && HasBackupPayload(backupDirectory, manifest.PendingItem))
                savedItems.Add(manifest.PendingItem);
            var pending = new List<QuarantineItem>();

            // Check all destinations before changing either the profile or the backup.
            foreach (QuarantineItem item in savedItems)
            {
                if (item == null || String.IsNullOrWhiteSpace(item.OriginalPath) || String.IsNullOrWhiteSpace(item.BackupRelativePath))
                    throw new InvalidOperationException("Backup manifest contains an invalid item.");
                string leaf = Path.GetFileName(item.OriginalPath);
                if (ProtectedNames.Contains(leaf) || !CleanableNames.Contains(leaf))
                    throw new InvalidOperationException("Refused to restore an unrecognized path from manifest: " + leaf);

                string sourcePath = ResolveBackupItemPath(backupDirectory, item.BackupRelativePath);
                FileAttributes? attributes = GetExistingAttributes(sourcePath);
                FileAttributes? destinationAttributes = GetExistingAttributes(item.OriginalPath);
                if (!attributes.HasValue)
                {
                    if (!destinationAttributes.HasValue)
                        throw new IOException("A backup item is missing from both the backup and its expected destination: " + sourcePath);
                    if ((destinationAttributes.Value & FileAttributes.ReparsePoint) != 0 ||
                        ((destinationAttributes.Value & FileAttributes.Directory) != 0) != item.IsDirectory)
                        throw new IOException("A backup item is missing and its destination has an unexpected type: " + item.OriginalPath);
                    continue;
                }
                if ((attributes.Value & FileAttributes.ReparsePoint) != 0 ||
                    ((attributes.Value & FileAttributes.Directory) != 0) != item.IsDirectory)
                    throw new IOException("A backup item has an unexpected type: " + sourcePath);
                if (destinationAttributes.HasValue)
                    throw new RestoreConflictException(item.OriginalPath, 0);
                pending.Add(item);
            }

            int restored = 0;
            foreach (QuarantineItem item in pending)
            {
                string sourcePath = ResolveBackupItemPath(backupDirectory, item.BackupRelativePath);
                try
                {
                    string destParent = Path.GetDirectoryName(item.OriginalPath);
                    if (!String.IsNullOrEmpty(destParent) && !Directory.Exists(destParent))
                        Directory.CreateDirectory(destParent);
                    if (IsReparsePoint(destParent))
                        throw new IOException("Target restore directory is not a regular directory.");

                    bool moved = TryMoveIntoRestoreDestination(sourcePath, item.OriginalPath, restored);
                    if (!moved)
                        CopyIntoRestoreDestination(sourcePath, item, restored);
                    restored++;

                    if (!moved)
                    {
                        // Rename the copied backup item so a retry skips it. Keep its bytes until
                        // the remaining items are restored and the entire backup can be removed.
                        string consumedPath = Path.Combine(Path.GetDirectoryName(sourcePath), ".restored-" + Guid.NewGuid().ToString("N"));
                        if (item.IsDirectory)
                            Directory.Move(sourcePath, consumedPath);
                        else
                            File.Move(sourcePath, consumedPath);
                    }
                }
                catch (RestoreConflictException) { throw; }
                catch (Exception error)
                {
                    if (!(error is IOException) && !(error is UnauthorizedAccessException))
                        throw;
                    throw new IOException("Restore stopped after restoring " + restored + " item(s). " +
                        "The unfinished backup is still available. " + error.Message, error);
                }
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
                string manifestPath = Path.Combine(dir, "manifest.json");
                if (IsReparsePoint(dir) || !File.Exists(manifestPath) || IsReparsePoint(manifestPath) || IsQuarantineActive(dir))
                    continue;
                try
                {
                    QuarantineManifest manifest = ReadQuarantineManifest(manifestPath);
                    if (manifest != null && manifest.Version == 2 && manifest.Items != null &&
                        manifest.Items.Length == 0 && !HasBackupPayload(dir, manifest.PendingItem))
                        continue;
                }
                // Keep unreadable backups visible so the user can see the error on restore.
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (ArgumentException) { }
                catch (InvalidOperationException) { }
                list.Add(dir);
            }
            list.Sort(StringComparer.OrdinalIgnoreCase);
            list.Reverse();
            return list.ToArray();
        }

        private static bool IsQuarantineActive(string backupDirectory)
        {
            try
            {
                using (File.Open(Path.Combine(backupDirectory, QuarantineMarker), FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete))
                    return false;
            }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
            catch (IOException) { return true; }
            catch (UnauthorizedAccessException) { return true; }
        }

        private static string ResolveBackupItemPath(string backupDirectory, string relativePath)
        {
            string root = Path.GetFullPath(backupDirectory).TrimEnd('\\') + "\\";
            string path = Path.GetFullPath(Path.Combine(root, relativePath));
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Manifest path escapes backup directory.");
            return path;
        }

        private static bool HasBackupPayload(string backupDirectory, QuarantineItem item)
        {
            if (item == null || String.IsNullOrWhiteSpace(item.BackupRelativePath))
                return false;
            string path = ResolveBackupItemPath(backupDirectory, item.BackupRelativePath);
            return File.Exists(path) || Directory.Exists(path);
        }

        private static QuarantineInterruptedException QuarantineFailure(string backupDirectory, int movedCount,
            QuarantineItem pendingItem, Exception error)
        {
            bool hasBackup = movedCount > 0 || HasBackupPayload(backupDirectory, pendingItem);
            return new QuarantineInterruptedException(hasBackup ? backupDirectory : "", error);
        }

        private static QuarantineManifest ReadQuarantineManifest(string path)
        {
            return new JavaScriptSerializer().Deserialize<QuarantineManifest>(File.ReadAllText(path, Utf8));
        }

        private static void WriteQuarantineManifest(string path, QuarantineManifest manifest)
        {
            string temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            byte[] contents = Utf8.GetBytes(new JavaScriptSerializer().Serialize(manifest));
            try
            {
                using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(contents, 0, contents.Length);
                    stream.Flush(true);
                }
                if (File.Exists(path))
                    File.Replace(temporaryPath, path, null);
                else
                    File.Move(temporaryPath, path);
            }
            finally
            {
                try { File.Delete(temporaryPath); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
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

        private static FileAttributes? GetExistingAttributes(string path)
        {
            try { return File.GetAttributes(path); }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
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

        private static void MoveIntoQuarantine(string source, string destination, bool isDirectory)
        {
            if (MoveFileEx(source, destination, 0))
                return;
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorNotSameDevice)
                throw new IOException("Could not move " + source + " to quarantine. " + new Win32Exception(error).Message);

            string temporaryDirectory = Path.Combine(Path.GetDirectoryName(destination),
                ".quarantine-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temporaryDirectory);
            try
            {
                // Only the completed copy is published at the path recorded in the manifest.
                string stagedPath = Path.Combine(temporaryDirectory, "item");
                if (isDirectory)
                    CopyDirectoryRecursive(source, stagedPath);
                else
                    File.Copy(source, stagedPath);
                if (!MoveFileEx(stagedPath, destination, 0))
                    throw new IOException("Could not publish the backup. " +
                        new Win32Exception(Marshal.GetLastWin32Error()).Message);
                if (isDirectory)
                    Directory.Delete(source, true);
                else
                    File.Delete(source);
            }
            finally
            {
                try { Directory.Delete(temporaryDirectory, true); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }

        private static bool TryMoveIntoRestoreDestination(string source, string destination, int restored)
        {
            // Zero flags allow neither replacement nor a copy directly into the destination.
            if (MoveFileEx(source, destination, 0))
                return true;
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorFileExists || error == ErrorAlreadyExists || GetExistingAttributes(destination).HasValue)
                throw new RestoreConflictException(destination, restored);
            if (error == ErrorNotSameDevice)
                return false;
            throw new IOException("Could not move the backup item to " + destination + ". " + new Win32Exception(error).Message);
        }

        private static void CopyIntoRestoreDestination(string source, QuarantineItem item, int restored)
        {
            string destination = item.OriginalPath;
            string tempDir = Path.Combine(Path.GetDirectoryName(destination), ".restore-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                // Complete the cross-volume copy on the destination volume before exposing it.
                string stagedPath = Path.Combine(tempDir, "item");
                if (item.IsDirectory)
                    CopyDirectoryRecursive(source, stagedPath);
                else
                    File.Copy(source, stagedPath);
                if (!TryMoveIntoRestoreDestination(stagedPath, destination, restored))
                    throw new IOException("The restore destination changed volumes: " + destination);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);

        private static void CopyDirectoryRecursive(string sourceDir, string destDir)
        {
            Directory.CreateDirectory(destDir);
            foreach (string file in Directory.GetFiles(sourceDir))
            {
                if (IsReparsePoint(file))
                    throw new IOException("Cannot copy a linked item: " + file);
                File.Copy(file, Path.Combine(destDir, Path.GetFileName(file)));
            }
            foreach (string sub in Directory.GetDirectories(sourceDir))
            {
                if (IsReparsePoint(sub))
                    throw new IOException("Cannot copy a linked item: " + sub);
                CopyDirectoryRecursive(sub, Path.Combine(destDir, Path.GetFileName(sub)));
            }
        }
    }
}
