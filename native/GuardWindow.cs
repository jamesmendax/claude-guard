using System;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace ClaudeGuardNative
{
    internal sealed class GuardWindow : Form
    {
        private readonly Label route = MakeValue();
        private readonly Label firewall = MakeValue();
        private readonly Label claude = MakeValue();
        private readonly TextBox message = new TextBox
        {
            AccessibleName = "Guard status",
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical
        };
        private readonly Button check = MakeButton("&Check");
        private readonly Button configure = MakeButton("&Set up firewall");
        private readonly Button open = MakeButton("&Open Claude");
        private readonly BackgroundWorker worker = new BackgroundWorker();
        private readonly ToolStripMenuItem openFromTray = new ToolStripMenuItem("Open Claude");
        private readonly ToolStripMenuItem checkFromTray = new ToolStripMenuItem("Check protection");
        private readonly ToolStripMenuItem zoneMenu = new ToolStripMenuItem();
        private readonly NotifyIcon tray;
        private string activeMode;
        private string sessionZone;
        private GuardResult lastResult;

        public GuardWindow()
        {
            Text = "Claude Guard Native";
            Font = SystemFonts.MessageBoxFont;
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(504, 268);
            MinimumSize = SizeFromClientSize(new Size(440, 244));
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;

            var layout = new TableLayoutPanel
            {
                ColumnCount = 2,
                RowCount = 5,
                Dock = DockStyle.Fill,
                Padding = new Padding(16)
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 84));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            AddStatusRow(layout, 0, "Route", route);
            AddStatusRow(layout, 1, "Firewall", firewall);
            AddStatusRow(layout, 2, "Claude", claude);

            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            message.Margin = new Padding(0, 8, 0, 10);
            layout.Controls.Add(message, 0, 3);
            layout.SetColumnSpan(message, 2);

            var buttons = new FlowLayoutPanel
            {
                AutoSize = true,
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                Margin = Padding.Empty,
                WrapContents = false
            };
            open.TabIndex = 2;
            configure.TabIndex = 1;
            check.TabIndex = 0;
            buttons.Controls.AddRange(new Control[] { open, configure, check });
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(buttons, 0, 4);
            layout.SetColumnSpan(buttons, 2);
            Controls.Add(layout);

            var options = new ToolStripMenuItem("&Settings");
            options.DropDownItems.Add("Windows &region and language", null, OpenRegionalSettings);
            options.DropDownItems.Add("Encrypted &DNS", null, OpenDnsSettings);
            zoneMenu.Text = "Session &time zone…";
            zoneMenu.Click += ChooseSessionZone;
            options.DropDownItems.Add(zoneMenu);
            var support = new ToolStripMenuItem("&Diagnostics");
            support.DropDownItems.Add("&Save report…", null, SaveDiagnostics);
            MainMenuStrip = new MenuStrip();
            MainMenuStrip.Items.AddRange(new ToolStripItem[] { options, support });
            Controls.Add(MainMenuStrip);

            var trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("Show Native Guard", null, delegate { RestoreWindow(); });
            trayMenu.Items.Add(checkFromTray);
            trayMenu.Items.Add(openFromTray);
            trayMenu.Items.Add("Windows region and language", null, OpenRegionalSettings);
            trayMenu.Items.Add("Exit", null, delegate { Close(); });
            tray = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = Text,
                ContextMenuStrip = trayMenu,
                Visible = true
            };
            tray.DoubleClick += delegate { RestoreWindow(); };
            checkFromTray.Click += delegate { check.PerformClick(); };
            openFromTray.Click += delegate { open.PerformClick(); };

            worker.DoWork += RunAction;
            worker.RunWorkerCompleted += ActionCompleted;
            check.Click += delegate { StartAction("Status", "Checking route, firewall, and Claude Desktop."); };
            configure.Click += ConfirmConfiguration;
            open.Click += delegate
            {
                StartAction("Launch", "Starting or monitoring Claude Desktop. Keep this window open until the session ends.");
            };
            SetButtons(null);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            StartAction("Status", "Checking route, firewall, and Claude Desktop.");
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);
            if (activeMode == "Launch" && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                MessageBox.Show(this, "Keep Claude Guard open while it monitors the session. Close Claude Desktop first.",
                    Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !IsDisposed)
            {
                tray.Visible = false;
                tray.ContextMenuStrip.Dispose();
                tray.Dispose();
                worker.Dispose();
            }
            base.Dispose(disposing);
        }

        private void RestoreWindow()
        {
            Show();
            if (WindowState == FormWindowState.Minimized)
                WindowState = FormWindowState.Normal;
            Activate();
        }

        private void OpenRegionalSettings(object sender, EventArgs e)
        {
            RestoreWindow();
            using (var window = new RegionalSettingsWindow())
                window.ShowDialog(this);
        }

        private void OpenDnsSettings(object sender, EventArgs e)
        {
            using (var window = new DnsSettingsWindow())
                window.ShowDialog(this);
        }

        private void ChooseSessionZone(object sender, EventArgs e)
        {
            using (var dialog = new Form())
            {
                dialog.Text = "Session time zone";
                dialog.StartPosition = FormStartPosition.CenterParent;
                dialog.ClientSize = new Size(460, 140);
                dialog.FormBorderStyle = FormBorderStyle.FixedDialog;
                dialog.MaximizeBox = false;
                dialog.MinimizeBox = false;
                dialog.ShowInTaskbar = false;
                dialog.Font = Font;
                dialog.AutoScaleMode = AutoScaleMode.Font;
                var description = new Label
                {
                    Text = "Choose the Windows time zone for the next guarded session.",
                    AutoSize = true,
                    Location = new Point(16, 18)
                };
                var zones = new ComboBox
                {
                    DropDownStyle = ComboBoxStyle.DropDownList,
                    Location = new Point(16, 46),
                    Width = 428,
                    AccessibleName = "Session time zone"
                };
                zones.Items.Add("Keep current Windows time zone");
                zones.SelectedIndex = 0;
                foreach (TimeZoneInfo zone in TimeZoneInfo.GetSystemTimeZones())
                {
                    int index = zones.Items.Add(zone);
                    if (zone.Id == sessionZone)
                        zones.SelectedIndex = index;
                }
                var use = new Button { Text = "Use", Location = new Point(277, 94), DialogResult = DialogResult.OK };
                var cancel = new Button { Text = "Cancel", Location = new Point(367, 94), DialogResult = DialogResult.Cancel };
                dialog.AcceptButton = use;
                dialog.CancelButton = cancel;
                dialog.Controls.AddRange(new Control[] { description, zones, use, cancel });
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    var choice = zones.SelectedItem as TimeZoneInfo;
                    sessionZone = choice == null ? null : choice.Id;
                    zoneMenu.Checked = sessionZone != null;
                }
            }
        }

        private void SaveDiagnostics(object sender, EventArgs e)
        {
            using (var picker = new SaveFileDialog
            {
                FileName = "ClaudeGuardNative-diagnostics.txt",
                Filter = "Text report (*.txt)|*.txt",
                AddExtension = true
            })
            {
                if (picker.ShowDialog(this) != DialogResult.OK)
                    return;
                try
                {
                    GuardDiagnostics.Export(picker.FileName, lastResult);
                    MessageBox.Show(this, "The local diagnostic report was saved.", Text);
                }
                catch (IOException error)
                {
                    MessageBox.Show(this, error.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                catch (UnauthorizedAccessException error)
                {
                    MessageBox.Show(this, error.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        private static Label MakeValue()
        {
            return new Label
            {
                AutoEllipsis = true,
                Dock = DockStyle.Fill,
                Text = "Unchecked",
                TextAlign = ContentAlignment.MiddleLeft
            };
        }

        private static Button MakeButton(string text)
        {
            return new Button
            {
                AutoSize = true,
                MinimumSize = new Size(82, 30),
                Padding = new Padding(7, 0, 7, 0),
                Text = text,
                UseVisualStyleBackColor = true
            };
        }

        private static void AddStatusRow(TableLayoutPanel layout, int row, string name, Label value)
        {
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
            layout.Controls.Add(new Label
            {
                Dock = DockStyle.Fill,
                Text = name,
                TextAlign = ContentAlignment.MiddleLeft
            }, 0, row);
            layout.Controls.Add(value, 1, row);
        }

        private void ConfirmConfiguration(object sender, EventArgs e)
        {
            DialogResult choice = MessageBox.Show(this,
                "Apply the Windows Firewall rules that restrict Claude Desktop to the approved VPN route? Windows will ask for administrator permission.",
                "Set up firewall", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
            if (choice == DialogResult.Yes)
                StartAction("Configure", "Waiting for Windows administrator approval and checking the firewall.");
        }

        private void StartAction(string mode, string description)
        {
            if (activeMode != null)
                return;
            activeMode = mode;
            SetButtons(null);
            message.Text = description;
            worker.RunWorkerAsync(Tuple.Create(mode, mode == "Launch" ? sessionZone : null));
        }

        private static void RunAction(object sender, DoWorkEventArgs e)
        {
            var request = (Tuple<string, string>)e.Argument;
            e.Result = request.Item1 == "Configure"
                ? GuardEngine.RequestConfiguration()
                : GuardEngine.Run(request.Item1, request.Item2, null);
        }

        private void ActionCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            if (IsDisposed || Disposing)
                return;
            activeMode = null;
            GuardResult result = e.Error == null ? e.Result as GuardResult : null;
            lastResult = result;
            route.Text = ResultText(result == null ? null : result.Route);
            firewall.Text = ResultText(result == null ? null : result.Firewall);
            claude.Text = ResultText(result == null ? null : result.Claude);
            message.Text = result == null
                ? "The action stopped before Guard could verify its status. Click Check to try again."
                : string.IsNullOrWhiteSpace(result.Message)
                    ? (result.Ready ? "Ready to open Claude Desktop." : "Claude Desktop is unavailable. Review the checks above.")
                    : result.Message;
            SetButtons(result);
        }

        private void SetButtons(GuardResult result)
        {
            check.Enabled = activeMode == null;
            configure.Enabled = activeMode == null && result != null && result.CanConfigure;
            open.Enabled = activeMode == null && result != null && result.Ready;
            openFromTray.Enabled = open.Enabled;
            checkFromTray.Enabled = check.Enabled;
            zoneMenu.Enabled = activeMode == null;
            AcceptButton = open.Enabled ? open : check.Enabled ? check : null;
        }

        private static string ResultText(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "Unverified" : value;
        }
    }
}
