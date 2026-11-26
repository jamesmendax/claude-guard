using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace ClaudeGuardNative
{
    internal static class GuardDiagnostics
    {
        private const int MaxBytes = 65536;
        private static readonly Encoding Utf8 = new UTF8Encoding(false);
        internal static readonly string LogFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClaudeGuardNative");

        internal static void Record(string action, GuardResult result)
        {
            try
            {
                // Background maintenance runs elevated and reports on its own output stream.
                if (GuardEngine.IsElevated())
                    return;
                DirectoryInfo directory = Directory.CreateDirectory(LogFolder);
                if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
                    return;
                string path = Path.Combine(LogFolder, "events.log");
                string previous = Path.Combine(LogFolder, "events.previous.log");
                string outcome = !result.Ok ? "failed" : result.Ready ? "ready" : "completed";
                string line = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)
                    + " " + action + " " + outcome
                    + (String.IsNullOrEmpty(result.ExitStatus) || result.ExitStatus == "Not checked" ? "" : " exit=" + result.ExitStatus)
                    + (String.IsNullOrEmpty(result.ProxyIssue) || result.ProxyIssue == "None" ? "" : " proxy=" + result.ProxyIssue)
                    + Environment.NewLine;

                using (var guard = new FileStream(Path.Combine(LogFolder, "events.lock"),
                    FileMode.OpenOrCreate, FileAccess.Write, FileShare.None))
                {
                    if (LogLength(path) + Utf8.GetByteCount(line) > MaxBytes)
                    {
                        LogLength(previous);
                        File.Delete(previous);
                        File.Move(path, previous);
                    }
                    File.AppendAllText(path, line, Utf8);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static long LogLength(string path)
        {
            if (!File.Exists(path))
                return 0;
            var file = new FileInfo(path);
            if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("The diagnostic log is not a regular file.");
            return file.Length;
        }

        internal static void Export(string path, GuardResult last)
        {
            using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(output, Utf8))
            {
                writer.WriteLine("Claude Guard Native " + GuardEngine.VersionText);
                writer.WriteLine("Created " + DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
                if (last != null)
                {
                    writer.WriteLine("Route: " + last.Route + (String.IsNullOrEmpty(last.VpnName) ? "" : " (" + last.VpnName + ")"));
                    writer.WriteLine("Firewall: " + last.Firewall + " (targets=" + last.ProtectedTargetCount + ", blockedAdapters=" + last.BlockedAdapterCount + ")");
                    writer.WriteLine("Claude: " + last.Claude + " (desktop=" + last.DesktopReady + ", cli=" + last.CliReady + ")");
                    writer.WriteLine("ProxyIssue: " + (String.IsNullOrEmpty(last.ProxyIssue) ? "None" : last.ProxyIssue));
                    writer.WriteLine("Exit: " + (String.IsNullOrEmpty(last.ExitStatus) ? "Not checked" : last.ExitStatus) +
                        (String.IsNullOrEmpty(last.ExitMaskedIp) ? "" : " " + last.ExitMaskedIp) +
                        (String.IsNullOrEmpty(last.ExitCountry) ? "" : " " + last.ExitCountry) +
                        (String.IsNullOrEmpty(last.ExitColo) ? "" : "/" + last.ExitColo));
                    writer.WriteLine("AutoRefresh: " + (String.IsNullOrEmpty(last.RefreshTaskState) ? "Not checked" : last.RefreshTaskState));
                }
                writer.WriteLine();
                writer.WriteLine("Recent local events");
                foreach (string name in new[] { "events.previous.log", "events.log" })
                {
                    string source = Path.Combine(LogFolder, name);
                    long length = LogLength(source);
                    if (length > 0 && length <= MaxBytes)
                        writer.Write(File.ReadAllText(source, Utf8));
                }
            }
        }
    }
}
