using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ClaudeGuardNative
{
    internal sealed class RegionalSettingsWindow : Form
    {
        private const uint GetDefaultInputLanguage = 0x0059;
        private readonly TextBox overview = new TextBox
        {
            AccessibleName = "Current Windows regional settings",
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical
        };
        private readonly ComboBox keyboards = new ComboBox
        {
            AccessibleName = "Default input method",
            Dock = DockStyle.Fill,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        private readonly Button apply = MakeButton("&Apply default input");
        private readonly Button refresh = MakeButton("&Refresh");
        private readonly Label message = new Label
        {
            AccessibleName = "Regional settings status",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft
        };
        private string currentOverride;
        private bool busy;

        public RegionalSettingsWindow()
        {
            Text = "Windows regional settings";
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(574, 350);
            MinimumSize = SizeFromClientSize(new Size(520, 320));
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            MaximizeBox = false;
            MinimizeBox = false;

            var content = new TableLayoutPanel
            {
                Padding = new Padding(16),
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 5
            };
            content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            content.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            content.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            content.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            content.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            content.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
            content.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            AddFullRow(content, overview, 0);
            AddFullRow(content, new Label { AutoSize = true, Text = "Default input method", Margin = new Padding(3, 12, 0, 4) }, 1);
            content.Controls.Add(keyboards, 0, 2);
            content.Controls.Add(apply, 1, 2);
            AddFullRow(content, message, 3);

            var links = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = Padding.Empty };
            links.Controls.Add(refresh);
            links.Controls.Add(MakeLink("Region and &language", delegate { OpenSettings("ms-settings:regionlanguage"); }));
            links.Controls.Add(MakeLink("Date and &time", delegate { OpenSettings("ms-settings:dateandtime"); }));
            string edge = FindEdge();
            if (edge != null)
                links.Controls.Add(MakeLink("&Edge languages", delegate { OpenSettings(edge, "edge://settings/languages"); }));
            AddFullRow(content, links, 4);
            Controls.Add(content);

            refresh.Click += async delegate { await UpdateSettings(null, false); };
            keyboards.SelectedIndexChanged += delegate { UpdateButtons(); };
            apply.Click += async delegate
            {
                var choice = keyboards.SelectedItem as KeyboardChoice;
                if (choice != null && apply.Enabled)
                    await UpdateSettings(choice.Tip, true);
            };
            UpdateButtons();
        }

        protected override async void OnShown(EventArgs e)
        {
            base.OnShown(e);
            await UpdateSettings(null, false);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);
            if (busy && e.CloseReason == CloseReason.UserClosing)
                e.Cancel = true;
        }

        private static void AddFullRow(TableLayoutPanel panel, Control control, int row)
        {
            panel.Controls.Add(control, 0, row);
            panel.SetColumnSpan(control, 2);
        }

        private static Button MakeButton(string caption)
        {
            return new Button { Text = caption, AutoSize = true, MinimumSize = new Size(0, 29) };
        }

        private static Button MakeLink(string caption, EventHandler click)
        {
            Button button = MakeButton(caption);
            button.Click += click;
            return button;
        }

        private void OpenSettings(string target, string arguments = "")
        {
            try
            {
                using (Process process = Process.Start(new ProcessStartInfo(target, arguments) { UseShellExecute = true }))
                {
                }
            }
            catch (Win32Exception)
            {
                message.Text = "Could not open the settings page.";
            }
        }

        private void UpdateButtons()
        {
            var selection = keyboards.SelectedItem as KeyboardChoice;
            keyboards.Enabled = !busy && keyboards.Items.Count > 0;
            apply.Enabled = !busy && selection != null &&
                !String.Equals(selection.Tip, currentOverride, StringComparison.OrdinalIgnoreCase);
            refresh.Enabled = !busy;
        }

        private async Task UpdateSettings(string requestedTip, bool changeDefault)
        {
            if (busy)
                return;
            busy = true;
            UpdateButtons();
            message.Text = changeDefault ? "Saving and checking the default input method." : "Reading the current Windows settings.";
            try
            {
                RegionalSnapshot snapshot = await Task.Run(() => ReadSettings(requestedTip, changeDefault));
                if (IsDisposed)
                    return;
                currentOverride = snapshot.Override;
                overview.Text = snapshot.Summary;
                keyboards.Items.Clear();
                foreach (KeyboardChoice choice in snapshot.Keyboards)
                {
                    int index = keyboards.Items.Add(choice);
                    if (String.Equals(choice.Tip, currentOverride, StringComparison.OrdinalIgnoreCase))
                        keyboards.SelectedIndex = index;
                }
                message.Text = snapshot.Message;
            }
            catch (Exception)
            {
                if (!IsDisposed)
                {
                    currentOverride = null;
                    overview.Clear();
                    keyboards.Items.Clear();
                    message.Text = "Windows settings could not be verified. Use Refresh or open Windows Settings.";
                }
            }
            finally
            {
                busy = false;
                if (!IsDisposed)
                    UpdateButtons();
            }
        }

        private static RegionalSnapshot ReadSettings(string requestedTip, bool changeDefault)
        {
            string inboxModule = Path.Combine(Environment.SystemDirectory,
                @"WindowsPowerShell\v1.0\Modules\International\International.psd1");
            var session = InitialSessionState.CreateDefault();
            session.ImportPSModule(new[] { inboxModule });
            using (Runspace runspace = RunspaceFactory.CreateRunspace(session))
            {
                runspace.Open();
                using (PowerShell shell = PowerShell.Create())
                {
                    shell.Runspace = runspace;
                    RegionalSnapshot snapshot = ReadSnapshot(shell);
                    if (!changeDefault)
                        return snapshot;

                    if (snapshot.Keyboards.Find(choice => String.Equals(choice.Tip, requestedTip,
                        StringComparison.OrdinalIgnoreCase)) == null)
                    {
                        snapshot.Message = "That keyboard is no longer available. Select a current keyboard and try again.";
                        return snapshot;
                    }

                    bool writeFailed = false;
                    try
                    {
                        shell.Commands.Clear();
                        shell.AddCommand("International\\Set-WinDefaultInputMethodOverride").AddParameter("ErrorAction", "Stop");
                        if (!String.IsNullOrEmpty(requestedTip))
                            shell.AddParameter("InputTip", requestedTip);
                        shell.Invoke();
                        writeFailed = shell.HadErrors;
                    }
                    catch (RuntimeException)
                    {
                        writeFailed = true;
                    }

                    snapshot = ReadSnapshot(shell);
                    snapshot.Message = !writeFailed && String.Equals(snapshot.Override, requestedTip, StringComparison.OrdinalIgnoreCase)
                        ? "Windows saved the default. If an open app still uses the prior keyboard, switch input there or reopen it."
                        : "Windows did not confirm the requested default. The current settings are shown above.";
                    return snapshot;
                }
            }
        }

        private static RegionalSnapshot ReadSnapshot(PowerShell shell)
        {
            var snapshot = new RegionalSnapshot();
            snapshot.Keyboards.Add(new KeyboardChoice("", "Let Windows choose from the language list"));
            var languages = new List<string>();
            var tips = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (PSObject result in Read(shell, "Get-WinUserLanguageList"))
            {
                var languageList = result == null ? null : result.BaseObject as IEnumerable;
                if (languageList == null)
                    continue;
                foreach (object item in languageList)
                {
                    PSObject language = PSObject.AsPSObject(item);
                    string tag = PropertyText(language, "LanguageTag");
                    if (!String.IsNullOrEmpty(tag))
                        languages.Add(tag);
                    PSPropertyInfo property = language.Properties["InputMethodTips"];
                    IEnumerable inputMethods = property == null ? null : property.Value as IEnumerable;
                    if (inputMethods == null)
                        continue;
                    foreach (object inputMethod in inputMethods)
                    {
                        string tip = Convert.ToString(inputMethod, CultureInfo.InvariantCulture);
                        if (!String.IsNullOrWhiteSpace(tip) && tips.Add(tip))
                            snapshot.Keyboards.Add(new KeyboardChoice(tip, LanguageName(tag) + "  (" + tip + ")"));
                    }
                }
            }

            var home = Read(shell, "Get-WinHomeLocation");
            var defaults = Read(shell, "Get-WinDefaultInputMethodOverride");
            snapshot.Override = defaults.Count == 0 ? "" : PropertyText(defaults[0], "InputMethodTip");
            if (defaults.Count > 0 && defaults[0] != null && snapshot.Override.Length == 0)
                throw new InvalidOperationException("Windows returned a default input method without its identifier.");
            string region = home.Count == 0 ? "" : PropertyText(home[0], "HomeLocation");
            CultureInfo format = ReadRegionalFormat();
            TimeZoneInfo.ClearCachedData();
            var selected = snapshot.Keyboards.Find(choice => String.Equals(choice.Tip, snapshot.Override,
                StringComparison.OrdinalIgnoreCase));
            snapshot.Summary = String.Join(Environment.NewLine, new[]
            {
                "Country or region   " + (region.Length == 0 ? "Unavailable" : region),
                "Regional format   " + (format == null ? "Unavailable" : format.DisplayName + "  (" + format.Name + ")"),
                "Date and time pattern   " + (format == null ? "Unavailable" :
                    format.DateTimeFormat.ShortDatePattern + "  " + format.DateTimeFormat.ShortTimePattern),
                "Time zone   " + TimeZoneInfo.Local.DisplayName,
                "Preferred languages   " + (languages.Count == 0 ? "Unavailable" : String.Join(", ", languages)),
                "Default input override   " + (selected == null ? snapshot.Override : selected.Caption),
                "Windows default keyboard language   " + ReadDefaultKeyboardLanguage()
            });
            snapshot.Message = "Change language order in Windows Settings. Applying an input choice keeps the existing languages and keyboards.";
            return snapshot;
        }

        private static IList<PSObject> Read(PowerShell shell, string command)
        {
            shell.Commands.Clear();
            shell.Streams.Error.Clear();
            shell.AddCommand("International\\" + command).AddParameter("ErrorAction", "Stop");
            var values = shell.Invoke();
            if (shell.HadErrors)
                throw new InvalidOperationException("Windows could not read an international setting.");
            return values;
        }

        private static string PropertyText(PSObject value, string name)
        {
            PSPropertyInfo property = value == null ? null : value.Properties[name];
            return property == null ? "" : Convert.ToString(property.Value, CultureInfo.InvariantCulture) ?? "";
        }

        private static string LanguageName(string tag)
        {
            try { return CultureInfo.GetCultureInfo(tag).DisplayName; }
            catch (CultureNotFoundException) { return tag; }
        }

        private static string ReadDefaultKeyboardLanguage()
        {
            IntPtr layout = IntPtr.Zero;
            if (!SystemParametersInfo(GetDefaultInputLanguage, 0, ref layout, 0) || layout == IntPtr.Zero)
                return "Unavailable";
            int languageId = (int)(layout.ToInt64() & 0xffff);
            try { return CultureInfo.GetCultureInfo(languageId).DisplayName; }
            catch (CultureNotFoundException) { return "Windows keyboard language " + languageId.ToString("X4"); }
        }

        private static CultureInfo ReadRegionalFormat()
        {
            var localeName = new StringBuilder(85);
            return GetUserDefaultLocaleName(localeName, localeName.Capacity) > 0
                ? new CultureInfo(localeName.ToString())
                : null;
        }

        private static string FindEdge()
        {
            foreach (Environment.SpecialFolder folder in new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles })
            {
                string root = Environment.GetFolderPath(folder);
                if (String.IsNullOrWhiteSpace(root))
                    continue;
                string path = Path.Combine(root, @"Microsoft\Edge\Application\msedge.exe");
                if (File.Exists(path))
                    return path;
            }
            return null;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SystemParametersInfo(uint action, uint argument, ref IntPtr value, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetUserDefaultLocaleName(StringBuilder localeName, int size);

        private sealed class KeyboardChoice
        {
            internal readonly string Tip;
            internal readonly string Caption;

            internal KeyboardChoice(string tip, string caption)
            {
                Tip = tip;
                Caption = caption;
            }

            public override string ToString()
            {
                return Caption;
            }
        }

        private sealed class RegionalSnapshot
        {
            internal readonly List<KeyboardChoice> Keyboards = new List<KeyboardChoice>();
            internal string Override;
            internal string Summary;
            internal string Message;
        }
    }
}
