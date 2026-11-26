using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace ClaudeGuardNative
{
    internal sealed class UiPreferences
    {
        public int Version = 1;
        public string Language = "auto";
        public bool AutoMinimizeToTray = true;
    }

    internal static class UiStrings
    {
        private const int MaxPrefsBytes = 4096;
        private static readonly Encoding Utf8 = new UTF8Encoding(false);
        private static UiPreferences cachedPrefs = LoadPreferences();

        internal static string Preference
        {
            get { return cachedPrefs.Language; }
        }

        internal static bool AutoMinimizeToTray
        {
            get { return cachedPrefs.AutoMinimizeToTray; }
            set
            {
                cachedPrefs.AutoMinimizeToTray = value;
                SavePreferences(cachedPrefs);
            }
        }

        internal static bool IsChinese
        {
            get
            {
                if (String.Equals(cachedPrefs.Language, "zh", StringComparison.OrdinalIgnoreCase))
                    return true;
                if (String.Equals(cachedPrefs.Language, "en", StringComparison.OrdinalIgnoreCase))
                    return false;
                return CultureInfo.CurrentUICulture.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase);
            }
        }

        internal static string T(string english, string chinese)
        {
            return IsChinese ? chinese : english;
        }

        internal static void SetPreference(string value)
        {
            string normalized = "auto";
            if (String.Equals(value, "zh", StringComparison.OrdinalIgnoreCase))
                normalized = "zh";
            else if (String.Equals(value, "en", StringComparison.OrdinalIgnoreCase))
                normalized = "en";
            cachedPrefs.Language = normalized;
            SavePreferences(cachedPrefs);
        }

        internal static string TranslateStatus(string value)
        {
            if (String.IsNullOrWhiteSpace(value))
                return T("Unverified", "未验证");
            if (!IsChinese)
                return value;

            switch (value)
            {
                case "Not checked": return "未检查";
                case "Unchecked": return "未检查";
                case "Unverified": return "未验证";
                case "VPN route verified": return "VPN 路由已验证";
                case "Effective blocks verified": return "防火墙有效阻断已验证";
                case "Setup required": return "需要配置防火墙";
                case "Rules applied": return "规则已应用";
                case "Desktop verified": return "Claude Desktop 已验证";
                case "Claude Code verified": return "Claude Code CLI 已验证";
                case "Already running": return "Claude 已在运行";
                case "Disabled": return "未启用（仅检查本地路由）";
                case "Verified": return "已验证通过";
                case "Policy mismatch": return "出口不匹配策略";
                case "Probe failed": return "探测失败";
                case "Not installed": return "未安装";
                case "Unavailable": return "不可用";
                case "Ready": return "已启用（就绪）";
                case "Running": return "运行中";
                default: return value;
            }
        }

        private static string PrefsPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ClaudeGuardNative",
                "ui-prefs.json");
        }

        private static UiPreferences LoadPreferences()
        {
            try
            {
                string path = PrefsPath();
                if (!File.Exists(path))
                    return new UiPreferences();
                var info = new FileInfo(path);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length > MaxPrefsBytes)
                    return new UiPreferences();
                string json = File.ReadAllText(path, Utf8);
                UiPreferences parsed = new JavaScriptSerializer().Deserialize<UiPreferences>(json);
                if (parsed == null)
                    return new UiPreferences();
                string lang = String.IsNullOrWhiteSpace(parsed.Language) ? "auto" : parsed.Language.Trim().ToLowerInvariant();
                if (lang != "zh" && lang != "en" && lang != "auto")
                    lang = "auto";
                return new UiPreferences
                {
                    Version = 1,
                    Language = lang,
                    AutoMinimizeToTray = parsed.AutoMinimizeToTray
                };
            }
            catch (Exception)
            {
                return new UiPreferences();
            }
        }

        private static void SavePreferences(UiPreferences prefs)
        {
            try
            {
                string path = PrefsPath();
                string folder = Path.GetDirectoryName(path);
                DirectoryInfo dir = Directory.CreateDirectory(folder);
                if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                    return;
                if (File.Exists(path) && (new FileInfo(path).Attributes & FileAttributes.ReparsePoint) != 0)
                    return;
                string json = new JavaScriptSerializer().Serialize(prefs);
                string temp = Path.Combine(folder, "ui-prefs-" + Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    File.WriteAllText(temp, json, Utf8);
                    if (File.Exists(path))
                        File.Replace(temp, path, null);
                    else
                        File.Move(temp, path);
                }
                finally
                {
                    if (File.Exists(temp))
                        File.Delete(temp);
                }
            }
            catch (Exception) { }
        }
    }
}
