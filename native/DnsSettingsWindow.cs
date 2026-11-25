using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace ClaudeGuardNative
{
    internal sealed class DnsSettingsWindow : Form
    {
        private const string Title = "Encrypted DNS";
        private const string AdminCommand = "--dns-admin";
        private const string ResourceName = "NativeDns.ps1";

        private sealed class Resolver
        {
            internal string Address;
            internal string Interfaces;
            internal string Template;
            internal bool AutoUpgrade;
            internal bool AllowFallback;

            public override string ToString()
            {
                return Address + "  (" + Interfaces + ")";
            }
        }

        private readonly ComboBox resolvers = new ComboBox();
        private readonly CheckBox fallback = new CheckBox();
        private readonly Label detail = new Label();
        private readonly Label status = new Label();
        private readonly Button apply = new Button();
        private readonly Button restore = new Button();
        private readonly Button refresh = new Button();
        private readonly Button networkSettings = new Button();
        private string backupAddress;
        private bool busy;

        internal DnsSettingsWindow()
        {
            Text = Title;
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Font;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(580, 306);
            MinimumSize = new Size(520, 320);
            MaximizeBox = false;
            MinimizeBox = false;

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(16),
                ColumnCount = 1,
                RowCount = 7
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            var intro = new Label
            {
                Dock = DockStyle.Fill,
                Text = "Use DNS-over-HTTPS for a resolver already assigned to a Windows network adapter. " +
                    "The change applies wherever Windows uses that resolver."
            };
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 47));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 49));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            layout.Controls.Add(intro, 0, 0);
            layout.Controls.Add(new Label { Text = "Windows &resolver", AutoSize = true }, 0, 1);

            resolvers.Dock = DockStyle.Fill;
            resolvers.DropDownStyle = ComboBoxStyle.DropDownList;
            resolvers.AccessibleName = "Windows resolver";
            resolvers.SelectedIndexChanged += delegate
            {
                var resolver = resolvers.SelectedItem as Resolver;
                fallback.Checked = resolver != null && resolver.AllowFallback;
                UpdateControls();
            };
            layout.Controls.Add(resolvers, 0, 2);
            detail.Dock = DockStyle.Fill;
            detail.AutoEllipsis = true;
            layout.Controls.Add(detail, 0, 3);
            fallback.Text = "Allow &unencrypted DNS if HTTPS fails";
            fallback.AutoSize = true;
            layout.Controls.Add(fallback, 0, 4);
            status.Dock = DockStyle.Fill;
            status.AutoEllipsis = true;
            layout.Controls.Add(status, 0, 5);

            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            ConfigureButton(apply, "&Apply", delegate { Apply(); });
            ConfigureButton(restore, "R&estore", delegate { Restore(); });
            ConfigureButton(refresh, "Re&fresh", delegate { RefreshSettings(null); });
            ConfigureButton(networkSettings, "Open Windows &network settings", delegate { OpenNetworkSettings(); });
            buttons.Controls.AddRange(new Control[] { apply, restore, refresh, networkSettings });
            layout.Controls.Add(buttons, 0, 6);
            Controls.Add(layout);
            UpdateControls();
            Shown += delegate { RefreshSettings(null); };
        }

        private static void ConfigureButton(Button button, string text, EventHandler onClick)
        {
            button.Text = text;
            button.AutoSize = true;
            button.MinimumSize = new Size(75, 28);
            button.Click += onClick;
        }

        private void UpdateControls()
        {
            var resolver = resolvers.SelectedItem as Resolver;
            resolvers.Enabled = !busy && resolvers.Items.Count > 0;
            refresh.Enabled = !busy;
            restore.Enabled = !busy && !String.IsNullOrEmpty(backupAddress);
            apply.Enabled = !busy && resolver != null && String.IsNullOrEmpty(backupAddress);
            fallback.Enabled = apply.Enabled;
            if (resolver == null)
            {
                detail.Text = "";
                return;
            }
            string mode = resolver.AutoUpgrade
                ? (resolver.AllowFallback ? "HTTPS with unencrypted fallback" : "HTTPS only")
                : "Automatic HTTPS upgrade is off";
            detail.Text = resolver.Template + Environment.NewLine + mode;
        }

        private void RefreshSettings(string preferredAddress)
        {
            if (preferredAddress == null && resolvers.SelectedItem != null)
                preferredAddress = ((Resolver)resolvers.SelectedItem).Address;
            status.Text = "Reading Windows DNS settings...";
            RunBackground(delegate { return RunDns("Read", null, null); }, delegate(Collection<PSObject> rows)
            {
                resolvers.Items.Clear();
                backupAddress = null;
                int selected = -1;
                foreach (PSObject row in rows)
                {
                    string address = GetProperty<string>(row, "Address");
                    if (GetProperty<string>(row, "Kind") == "Backup")
                    {
                        backupAddress = address;
                        continue;
                    }
                    var resolver = new Resolver
                    {
                        Address = address,
                        Interfaces = GetProperty<string>(row, "Interfaces"),
                        Template = GetProperty<string>(row, "Template"),
                        AutoUpgrade = GetProperty<bool>(row, "AutoUpgrade"),
                        AllowFallback = GetProperty<bool>(row, "AllowFallback")
                    };
                    int index = resolvers.Items.Add(resolver);
                    if (address == preferredAddress)
                        selected = index;
                }
                resolvers.SelectedIndex = selected;
                status.Text = !String.IsNullOrEmpty(backupAddress)
                    ? "Original settings saved for " + backupAddress + "."
                    : (resolvers.Items.Count > 0
                        ? "Select a resolver to review its settings."
                        : "No assigned Windows resolver has a known HTTPS template. Choose a resolver in Windows network settings.");
            });
        }

        private void RunBackground<T>(Func<T> work, Action<T> completed)
        {
            busy = true;
            UpdateControls();
            var worker = new BackgroundWorker();
            worker.DoWork += delegate(object sender, DoWorkEventArgs e) { e.Result = work(); };
            worker.RunWorkerCompleted += delegate(object sender, RunWorkerCompletedEventArgs e)
            {
                worker.Dispose();
                if (IsDisposed || Disposing)
                    return;
                busy = false;
                try
                {
                    if (e.Error != null)
                        throw e.Error;
                    completed((T)e.Result);
                }
                catch (Exception error)
                {
                    resolvers.Items.Clear();
                    backupAddress = null;
                    status.Text = error.Message;
                }
                UpdateControls();
            };
            worker.RunWorkerAsync();
        }

        private void Apply()
        {
            var resolver = resolvers.SelectedItem as Resolver;
            if (resolver == null || !IsCanonicalAddress(resolver.Address))
                return;
            string message = "Enable DNS-over-HTTPS for " + resolver.Address + "?" + Environment.NewLine +
                (fallback.Checked ? "Windows can use unencrypted DNS if HTTPS fails."
                    : "DNS queries to this resolver can fail if its HTTPS service is unavailable.");
            if (MessageBox.Show(this, message, Title, MessageBoxButtons.OKCancel, MessageBoxIcon.Question)
                != DialogResult.OK)
                return;
            RequestAdmin("apply " + resolver.Address + (fallback.Checked ? " fallback" : " strict"));
        }

        private void Restore()
        {
            if (MessageBox.Show(this, "Restore the original encryption settings for " + backupAddress + "?",
                Title, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK)
                RequestAdmin("restore");
        }

        private void RequestAdmin(string operation)
        {
            string address = resolvers.SelectedItem == null ? null : ((Resolver)resolvers.SelectedItem).Address;
            status.Text = "Waiting for Windows administrator approval and DNS verification...";
            RunBackground(delegate
            {
                var start = new ProcessStartInfo(Application.ExecutablePath, AdminCommand + " " + operation)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WorkingDirectory = Environment.SystemDirectory
                };
                try
                {
                    using (Process child = Process.Start(start))
                    {
                        if (child == null)
                            throw new InvalidOperationException("Windows could not start the DNS confirmation.");
                        child.WaitForExit();
                        return true;
                    }
                }
                catch (Win32Exception error)
                {
                    if (error.NativeErrorCode == 1223)
                        return false;
                    throw;
                }
            }, delegate(bool approved)
            {
                if (approved)
                    RefreshSettings(address);
                else
                    status.Text = "Windows administrator approval was canceled.";
            });
        }

        private void OpenNetworkSettings()
        {
            try
            {
                using (Process settings = Process.Start(new ProcessStartInfo("ms-settings:network")
                    { UseShellExecute = true }))
                {
                }
            }
            catch (Exception error) { status.Text = error.Message; }
        }

        private static bool IsCanonicalAddress(string address)
        {
            IPAddress ip;
            return address.IndexOf('%') < 0 && IPAddress.TryParse(address, out ip) &&
                String.Equals(ip.ToString(), address, StringComparison.Ordinal);
        }

        private static T GetProperty<T>(PSObject value, string name)
        {
            PSPropertyInfo property = value.Properties[name];
            if (property == null)
                throw new InvalidOperationException("Windows returned incomplete DNS settings.");
            return LanguagePrimitives.ConvertTo<T>(property.Value);
        }

        private static Collection<PSObject> RunDns(string mode, string address, string fallbackMode)
        {
            string script;
            using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName))
            {
                if (resource == null)
                    throw new InvalidOperationException("The packaged DNS control is missing.");
                using (var reader = new StreamReader(resource))
                    script = reader.ReadToEnd();
            }

            string root = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "Modules");
            string cim = Path.Combine(root, "CimCmdlets", "CimCmdlets.psd1");
            string dns = Path.Combine(root, "DnsClient", "DnsClient.psd1");
            if (!File.Exists(cim) || !File.Exists(dns))
                throw new InvalidOperationException("This Windows installation does not provide the DNS-over-HTTPS commands.");
            InitialSessionState state = InitialSessionState.CreateDefault();
            state.Variables.Add(new SessionStateVariableEntry("PSModuleAutoLoadingPreference", "None",
                "Load only the specified inbox modules."));
            state.ImportPSModule(new[] { cim, dns });
            using (Runspace runspace = RunspaceFactory.CreateRunspace(state))
            {
                runspace.Open();
                using (PowerShell shell = PowerShell.Create())
                {
                    shell.Runspace = runspace;
                    shell.AddScript(script).AddParameter("Mode", mode);
                    if (address != null)
                        shell.AddParameter("Address", address).AddParameter("Fallback", fallbackMode);
                    Collection<PSObject> rows = shell.Invoke();
                    if (shell.Streams.Error.Count != 0)
                        throw new InvalidOperationException(shell.Streams.Error[0].Exception.Message);
                    return rows;
                }
            }
        }

        internal static int RunAdmin(string[] args)
        {
            if (args.Length < 2 || args[0] != AdminCommand ||
                !((args.Length == 2 && args[1] == "restore") ||
                    (args.Length == 4 && args[1] == "apply" && IsCanonicalAddress(args[2]) &&
                    (args[3] == "strict" || args[3] == "fallback"))))
                return 2;
            if (!GuardEngine.IsElevated())
                return 3;

            try
            {
                using (var mutex = new Mutex(false, @"Global\ClaudeGuardNativeEncryptedDns"))
                {
                    bool held;
                    try { held = mutex.WaitOne(0); }
                    catch (AbandonedMutexException) { held = true; }
                    if (!held)
                        throw new InvalidOperationException("Another DNS change is already running.");
                    Collection<PSObject> result;
                    try
                    {
                        result = args[1] == "apply"
                            ? RunDns("Apply", args[2], args[3])
                            : RunDns("Restore", null, null);
                    }
                    finally { mutex.ReleaseMutex(); }
                    if (result.Count != 1)
                        throw new InvalidOperationException("Windows did not return a DNS verification result.");
                    MessageBox.Show(result[0].ToString(), Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 0;
                }
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }
    }
}
