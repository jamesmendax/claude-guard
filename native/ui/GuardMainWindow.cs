using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Shell;
using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace ClaudeGuardNative
{
    internal sealed class GuardMainWindow : Window
    {
        private const int DwmwaWindowCornerPreference = 33;
        private const int DwmwcpRound = 2;

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        private readonly Ellipse titleLedDot;
        private readonly TextBlock navOverviewText = new TextBlock();
        private readonly TextBlock navExitText = new TextBlock();
        private readonly TextBlock navHygieneText = new TextBlock();
        private readonly TextBlock navSystemText = new TextBlock();

        private readonly RadioButton navOverviewBtn = new RadioButton();
        private readonly RadioButton navExitBtn = new RadioButton();
        private readonly RadioButton navHygieneBtn = new RadioButton();
        private readonly RadioButton navSystemBtn = new RadioButton();

        private readonly TextBlock railRefreshCaption = new TextBlock();
        private readonly TextBlock railRefreshValue = new TextBlock();
        private readonly TextBlock railLangCaption = new TextBlock();
        private readonly RadioButton langZhBtn = new RadioButton();
        private readonly RadioButton langEnBtn = new RadioButton();

        private readonly ContentControl pageHost = new ContentControl();
        private readonly OverviewPage overviewPage;
        private readonly ExitPolicyPage exitPolicyPage;
        private readonly DesktopHygienePage hygienePage;
        private readonly SystemMaintenancePage systemPage;

        private readonly Forms.NotifyIcon tray;
        private readonly Forms.ContextMenuStrip trayMenu = new Forms.ContextMenuStrip();
        private readonly Forms.ToolStripMenuItem trayShowItem = new Forms.ToolStripMenuItem();
        private readonly Forms.ToolStripMenuItem trayCheckItem = new Forms.ToolStripMenuItem();
        private readonly Forms.ToolStripMenuItem trayOpenDesktopItem = new Forms.ToolStripMenuItem();
        private readonly Forms.ToolStripMenuItem trayOpenCliItem = new Forms.ToolStripMenuItem();
        private readonly Forms.ToolStripMenuItem trayStopClaudeItem = new Forms.ToolStripMenuItem();
        private readonly Forms.ToolStripMenuItem trayHygieneItem = new Forms.ToolStripMenuItem();
        private readonly Forms.ToolStripMenuItem trayExitItem = new Forms.ToolStripMenuItem();

        private System.Drawing.Icon trayIconOk;
        private System.Drawing.Icon trayIconWarn;
        private System.Drawing.Icon trayIconBlocked;
        private bool suppressLangEvents;
        private string activeMode;
        private string sessionZone;
        private GuardResult lastResult;
        private bool pendingAutoLaunch;

        internal GuardMainWindow(bool autoLaunchDesktop)
        {
            pendingAutoLaunch = autoLaunchDesktop;

            LoadThemeDictionary();

            Title = "Claude Guard " + GuardEngine.VersionText;
            Width = 868;
            Height = 560;
            MinWidth = 840;
            MinHeight = 544;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.None;
            ResizeMode = ResizeMode.CanResize;
            Background = BrushFrom("#F7F7F8");
            FontFamily = new FontFamily("Segoe UI, Microsoft YaHei UI");
            UseLayoutRounding = true;
            SnapsToDevicePixels = true;
            TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);
            Icon = AppIcons.CreateWindowIconSource(GuardIconState.Ready);

            WindowChrome.SetWindowChrome(this, new WindowChrome
            {
                CaptionHeight = 40,
                ResizeBorderThickness = new Thickness(6),
                GlassFrameThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10)
            });

            // Initialize modular pages
            overviewPage = new OverviewPage();
            exitPolicyPage = new ExitPolicyPage();
            hygienePage = new DesktopHygienePage();
            systemPage = new SystemMaintenancePage();

            WirePageEvents();

            // Build shell visual tree
            var outer = new Border
            {
                Background = BrushFrom("#F7F7F8"),
                BorderBrush = BrushFrom("#C8CDD6"),
                BorderThickness = new Thickness(1)
            };

            var rootGrid = new Grid();
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(40) });
            rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            UIElement titleBar = BuildTitleBar(out titleLedDot);
            Grid.SetRow(titleBar, 0);
            rootGrid.Children.Add(titleBar);

            var bodyGrid = new Grid();
            bodyGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(184) });
            bodyGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            UIElement rail = BuildLeftRail();
            Grid.SetColumn(rail, 0);
            bodyGrid.Children.Add(rail);

            pageHost.Content = overviewPage;
            Grid.SetColumn(pageHost, 1);
            bodyGrid.Children.Add(pageHost);

            Grid.SetRow(bodyGrid, 1);
            rootGrid.Children.Add(bodyGrid);

            outer.Child = rootGrid;
            Content = outer;

            // System tray setup (3-state Option A icons)
            trayIconOk = AppIcons.CreateTrayIcon(GuardIconState.Ready);
            trayIconWarn = AppIcons.CreateTrayIcon(GuardIconState.Warning);
            trayIconBlocked = AppIcons.CreateTrayIcon(GuardIconState.Blocked);

            trayShowItem.Click += delegate { RestoreWindow(); };
            trayCheckItem.Click += delegate { TriggerStatusCheck(); };
            trayOpenDesktopItem.Click += delegate { StartGuardedDesktopLaunch(); };
            trayOpenCliItem.Click += delegate { LaunchGuardedCliTerminal(); };
            trayStopClaudeItem.Click += delegate { ConfirmStopClaude(); };
            trayHygieneItem.Click += delegate { RestoreWindow(); SelectTab(2); };
            trayExitItem.Click += delegate { Close(); };

            trayMenu.Items.AddRange(new Forms.ToolStripItem[]
            {
                trayShowItem, trayCheckItem, trayOpenDesktopItem, trayOpenCliItem, trayStopClaudeItem,
                new Forms.ToolStripSeparator(), trayHygieneItem,
                new Forms.ToolStripSeparator(), trayExitItem
            });

            tray = new Forms.NotifyIcon
            {
                Icon = trayIconOk,
                ContextMenuStrip = trayMenu,
                Visible = true
            };
            tray.DoubleClick += delegate { RestoreWindow(); };

            SourceInitialized += OnSourceInitialized;
            Loaded += delegate { TriggerStatusCheck(); };
            Closing += OnWindowClosing;
            Closed += OnWindowClosed;

            ApplyLocalization();
            SyncVisualState();
        }

        private void LoadThemeDictionary()
        {
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("Theme.xaml"))
            {
                if (stream == null)
                    throw new InvalidOperationException("Embedded WPF Theme.xaml resource is missing.");
                var dict = (ResourceDictionary)XamlReader.Load(stream);
                Resources.MergedDictionaries.Add(dict);
            }
        }

        private void OnSourceInitialized(object sender, EventArgs e)
        {
            try
            {
                IntPtr hwnd = new WindowInteropHelper(this).Handle;
                int preference = DwmwcpRound;
                DwmSetWindowAttribute(hwnd, DwmwaWindowCornerPreference, ref preference, sizeof(int));
            }
            catch (Exception)
            {
                // Older Windows 10 builds ignore DWMWA_WINDOW_CORNER_PREFERENCE safely.
            }
        }

        private UIElement BuildTitleBar(out Ellipse ledDot)
        {
            var bar = new Border
            {
                Background = BrushFrom("#EFEFF2"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(0, 0, 0, 1)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var left = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(14, 0, 0, 0)
            };

            Viewbox mark = AppIcons.CreateBrandMark(18, GuardIconState.Ready, out ledDot);
            mark.Margin = new Thickness(0, 0, 9, 0);
            left.Children.Add(mark);

            left.Children.Add(new TextBlock
            {
                Text = "Claude Guard",
                FontSize = 12.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = BrushFrom("#121418"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            });

            left.Children.Add(new TextBlock
            {
                Text = GuardEngine.VersionText,
                FontSize = 11,
                FontFamily = new FontFamily("Cascadia Mono, Consolas"),
                Foreground = BrushFrom("#7A8194"),
                VerticalAlignment = VerticalAlignment.Center
            });

            Grid.SetColumn(left, 0);
            grid.Children.Add(left);

            var controls = new StackPanel { Orientation = Orientation.Horizontal };

            var minBtn = new Button
            {
                Content = new Line
                {
                    X1 = 0, Y1 = 0, X2 = 10, Y2 = 0,
                    Stroke = BrushFrom("#4A505E"),
                    StrokeThickness = 1.2
                }
            };
            minBtn.SetResourceReference(StyleProperty, "TitleBarMinButtonStyle");
            WindowChrome.SetIsHitTestVisibleInChrome(minBtn, true);
            minBtn.Click += delegate { WindowState = WindowState.Minimized; };

            var closePath = new System.Windows.Shapes.Path
            {
                Data = Geometry.Parse("M 0,0 L 8.5,8.5 M 8.5,0 L 0,8.5"),
                StrokeThickness = 1.25
            };
            closePath.SetBinding(Shape.StrokeProperty, new System.Windows.Data.Binding("Foreground")
            {
                RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.FindAncestor, typeof(Button), 1)
            });
            var closeBtn = new Button { Content = closePath };
            closeBtn.SetResourceReference(StyleProperty, "TitleBarCloseButtonStyle");
            WindowChrome.SetIsHitTestVisibleInChrome(closeBtn, true);
            closeBtn.Click += delegate { Close(); };

            controls.Children.Add(minBtn);
            controls.Children.Add(closeBtn);
            Grid.SetColumn(controls, 1);
            grid.Children.Add(controls);

            bar.Child = grid;
            return bar;
        }

        private UIElement BuildLeftRail()
        {
            var railBorder = new Border
            {
                Background = BrushFrom("#EFEFF2"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(0, 0, 1, 0),
                Padding = new Thickness(10, 14, 10, 12)
            };

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var navStack = new StackPanel();
            SetupNavButton(navOverviewBtn, "overview", navOverviewText, 0, true);
            SetupNavButton(navExitBtn, "exit", navExitText, 1, false);
            SetupNavButton(navHygieneBtn, "hygiene", navHygieneText, 2, false);
            SetupNavButton(navSystemBtn, "system", navSystemText, 3, false);

            navStack.Children.Add(navOverviewBtn);
            navStack.Children.Add(navExitBtn);
            navStack.Children.Add(navHygieneBtn);
            navStack.Children.Add(navSystemBtn);
            Grid.SetRow(navStack, 0);
            grid.Children.Add(navStack);

            // Rail footer: background refresh status + segmented language toggle
            var foot = new Border
            {
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(4, 10, 4, 0)
            };
            var footStack = new StackPanel();

            var refreshRow = new Grid { Margin = new Thickness(2, 0, 2, 8) };
            refreshRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            refreshRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            railRefreshCaption.FontSize = 11.5;
            railRefreshCaption.Foreground = BrushFrom("#7A8194");
            railRefreshValue.FontSize = 11.5;
            railRefreshValue.FontWeight = FontWeights.SemiBold;
            Grid.SetColumn(railRefreshCaption, 0);
            Grid.SetColumn(railRefreshValue, 1);
            refreshRow.Children.Add(railRefreshCaption);
            refreshRow.Children.Add(railRefreshValue);
            footStack.Children.Add(refreshRow);

            var langRow = new Grid { Margin = new Thickness(2, 0, 2, 0) };
            langRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            langRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            railLangCaption.FontSize = 11.5;
            railLangCaption.Foreground = BrushFrom("#7A8194");
            railLangCaption.VerticalAlignment = VerticalAlignment.Center;

            var segOuter = new Border
            {
                Background = BrushFrom("#E2E4EB"),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(2)
            };
            var segInner = new StackPanel { Orientation = Orientation.Horizontal };
            langZhBtn.GroupName = "UiLang";
            langZhBtn.Content = "中";
            langZhBtn.SetResourceReference(StyleProperty, "SegLangRadioStyle");
            langZhBtn.Checked += delegate { if (!suppressLangEvents) SwitchLanguage("zh"); };

            langEnBtn.GroupName = "UiLang";
            langEnBtn.Content = "EN";
            langEnBtn.SetResourceReference(StyleProperty, "SegLangRadioStyle");
            langEnBtn.Checked += delegate { if (!suppressLangEvents) SwitchLanguage("en"); };

            segInner.Children.Add(langZhBtn);
            segInner.Children.Add(langEnBtn);
            segOuter.Child = segInner;

            Grid.SetColumn(railLangCaption, 0);
            Grid.SetColumn(segOuter, 1);
            langRow.Children.Add(railLangCaption);
            langRow.Children.Add(segOuter);
            footStack.Children.Add(langRow);

            foot.Child = footStack;
            Grid.SetRow(foot, 1);
            grid.Children.Add(foot);

            railBorder.Child = grid;
            return railBorder;
        }

        private void SetupNavButton(RadioButton btn, string iconKind, TextBlock label, int tabIndex, bool isDefault)
        {
            btn.GroupName = "MainNav";
            btn.IsChecked = isDefault;
            btn.SetResourceReference(StyleProperty, "NavRadioButtonStyle");

            var inner = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            UIElement icon = AppIcons.CreateNavIcon(iconKind);
            var iconHost = new ContentPresenter { Content = icon, Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center };
            label.VerticalAlignment = VerticalAlignment.Center;
            inner.Children.Add(iconHost);
            inner.Children.Add(label);
            btn.Content = inner;

            btn.Checked += delegate { ShowPageIndex(tabIndex); };
        }

        private void SelectTab(int tabIndex)
        {
            switch (tabIndex)
            {
                case 1: navExitBtn.IsChecked = true; break;
                case 2: navHygieneBtn.IsChecked = true; break;
                case 3: navSystemBtn.IsChecked = true; break;
                default: navOverviewBtn.IsChecked = true; break;
            }
        }

        private void ShowPageIndex(int tabIndex)
        {
            switch (tabIndex)
            {
                case 1:
                    exitPolicyPage.LoadCurrentPolicy();
                    pageHost.Content = exitPolicyPage;
                    break;
                case 2:
                    hygienePage.RefreshScan();
                    pageHost.Content = hygienePage;
                    break;
                case 3:
                    systemPage.UpdateStatus(lastResult);
                    pageHost.Content = systemPage;
                    break;
                default:
                    pageHost.Content = overviewPage;
                    break;
            }
        }

        private void WirePageEvents()
        {
            // Overview page
            overviewPage.CheckRequested += TriggerStatusCheck;
            overviewPage.StopClaudeRequested += ConfirmStopClaude;
            overviewPage.ConfigureFirewallRequested += ConfirmConfiguration;
            overviewPage.LaunchCliRequested += LaunchGuardedCliTerminal;
            overviewPage.LaunchDesktopRequested += StartGuardedDesktopLaunch;
            overviewPage.OpenProxySettingsRequested += OpenWindowsProxySettings;
            overviewPage.NavigateToTabRequested += SelectTab;
            overviewPage.ShowFullIpChanged += delegate(bool show) { exitPolicyPage.ShowFullIp = show; };

            // Exit Policy page
            exitPolicyPage.ShowFullIpChanged += delegate(bool show) { overviewPage.ShowFullIp = show; };
            exitPolicyPage.PolicySaved += delegate
            {
                if (activeMode == null)
                    TriggerStatusCheck();
            };

            // Desktop Hygiene page
            hygienePage.HygieneChanged += delegate
            {
                if (activeMode == null)
                    TriggerStatusCheck();
            };

            // System & Maintenance page
            systemPage.RefreshFirewallRequested += ConfirmConfiguration;
            systemPage.RemoveFirewallRulesRequested += delegate
            {
                RunGuiMaintenance("--remove-rules",
                    UiStrings.T("Remove Native Guard Windows Firewall rules? Ensure Claude is closed first.",
                        "确定移除 Native Guard 的 Windows 防火墙规则？请先关闭 Claude。"));
            };
            systemPage.CreateShortcutRequested += CreateDesktopShortcut;
            systemPage.InstallRefreshTaskRequested += delegate
            {
                RunGuiMaintenance("--install --enable-refresh",
                    UiStrings.T("Install Native Guard " + GuardEngine.VersionText + " to Program Files and enable 5-minute background firewall refresh?",
                        "确定将 Native Guard " + GuardEngine.VersionText + " 安装到 Program Files 并启用 5 分钟后台自动刷新计划任务？"));
            };
            systemPage.DisableRefreshTaskRequested += delegate
            {
                RunGuiMaintenance("--disable-refresh",
                    UiStrings.T("Disable the Native Guard auto-refresh scheduled task?",
                        "确定关闭 Native Guard 后台自动刷新计划任务？"));
            };
            systemPage.SessionTimeZoneChanged += delegate(string tz)
            {
                sessionZone = tz;
                SyncVisualState();
            };
            systemPage.OpenRegionalRequested += OpenRegionalSettings;
            systemPage.OpenDnsRequested += OpenDnsSettings;
            systemPage.VerifyPackageRequested += VerifyPackage;
            systemPage.OpenLogsFolderRequested += OpenLogsFolder;
            systemPage.ExportDiagnosticsRequested += ExportDiagnostics;
            systemPage.UninstallRequested += delegate
            {
                RunGuiMaintenance("--uninstall --remove-rules",
                    UiStrings.T("Uninstall Native Guard " + GuardEngine.VersionText + " from Program Files and remove its firewall rules?",
                        "确定从 Program Files 卸载 Native Guard " + GuardEngine.VersionText + " 并同时移除其防火墙规则？"));
            };
            systemPage.ShowLimitationsRequested += ShowLimitations;
        }

        private void SwitchLanguage(string lang)
        {
            UiStrings.SetPreference(lang);
            ApplyLocalization();
        }

        private void ApplyLocalization()
        {
            suppressLangEvents = true;
            langZhBtn.IsChecked = UiStrings.IsChinese;
            langEnBtn.IsChecked = !UiStrings.IsChinese;
            suppressLangEvents = false;

            navOverviewText.Text = UiStrings.T("Overview", "总览守卫");
            navExitText.Text = UiStrings.T("Exit Policy", "出口策略");
            navHygieneText.Text = UiStrings.T("Desktop Hygiene", "桌面卫生");
            navSystemText.Text = UiStrings.T("System", "系统与维护");

            railRefreshCaption.Text = UiStrings.T("Auto refresh", "后台自动刷新");
            railLangCaption.Text = UiStrings.T("Language", "界面语言");

            trayShowItem.Text = UiStrings.T("Show Claude Guard", "显示主窗口");
            trayCheckItem.Text = UiStrings.T("Check protection", "重新检查状态");
            trayOpenDesktopItem.Text = UiStrings.T("Launch Claude Desktop", "启动 Claude Desktop");
            trayOpenCliItem.Text = UiStrings.T("Launch Claude CLI", "启动 Claude CLI");
            trayStopClaudeItem.Text = UiStrings.T("Stop Claude processes", "停止 Claude 进程树");
            trayHygieneItem.Text = UiStrings.T("Desktop hygiene", "桌面卫生与清理");
            trayExitItem.Text = UiStrings.T("Exit", "退出");

            overviewPage.ApplyLocalization();
            exitPolicyPage.ApplyLocalization();
            hygienePage.ApplyLocalization();
            systemPage.ApplyLocalization();

            SyncVisualState();
        }

        private void TriggerStatusCheck()
        {
            StartAction("Status");
        }

        private void StartAction(string mode)
        {
            if (activeMode != null)
                return;
            activeMode = mode;
            string requestedZone = mode == "Launch" ? sessionZone : null;
            SyncVisualState();

            Task.Factory.StartNew(delegate
            {
                GuardResult result;
                try
                {
                    result = mode == "Configure"
                        ? GuardEngine.RequestConfiguration()
                        : GuardEngine.Run(mode, requestedZone, null);
                }
                catch (Exception ex)
                {
                    result = GuardResult.Failure(ex.Message);
                }

                Dispatcher.BeginInvoke(new Action(delegate { ActionCompleted(mode, result); }));
            });
        }

        private void ActionCompleted(string finishedMode, GuardResult result)
        {
            if (!IsLoaded)
                return;
            activeMode = null;
            SetTrayText("Claude Guard " + GuardEngine.VersionText);

            lastResult = result;
            SyncVisualState();

            if (finishedMode == "Launch")
            {
                if (result == null || !result.Ok)
                {
                    RestoreWindow();
                    tray.ShowBalloonTip(5000,
                        UiStrings.T("Claude Guard Protection Triggered", "Claude Guard 已触发熔断保护"),
                        result == null ? UiStrings.T("Guard session ended.", "守卫会话已中断。") : result.Message,
                        Forms.ToolTipIcon.Warning);
                }
                else if (!IsVisible)
                {
                    RestoreWindow();
                }
            }

            if (finishedMode == "Status" && pendingAutoLaunch)
            {
                pendingAutoLaunch = false;
                if (result != null && (result.Ready || result.CanRepair))
                    StartGuardedDesktopLaunch();
            }
        }

        private void SyncVisualState()
        {
            bool hasConsole = GuardEngine.FindSiblingConsole() != null;
            overviewPage.UpdateState(lastResult, activeMode, sessionZone, hasConsole);
            systemPage.UpdateStatus(lastResult);
            systemPage.SetBusy(activeMode != null);

            // Rail background refresh badge
            string taskState = lastResult == null ? null : lastResult.RefreshTaskState;
            bool taskRunning = !String.IsNullOrEmpty(taskState) &&
                (taskState.StartsWith("Ready", StringComparison.OrdinalIgnoreCase) ||
                 taskState.StartsWith("Running", StringComparison.OrdinalIgnoreCase));
            if (taskRunning)
            {
                railRefreshValue.Text = UiStrings.T("Active", "运行中");
                railRefreshValue.Foreground = BrushFrom("#15803D");
            }
            else if (String.Equals(taskState, "Not installed", StringComparison.OrdinalIgnoreCase))
            {
                railRefreshValue.Text = UiStrings.T("Not set", "未安装");
                railRefreshValue.Foreground = BrushFrom("#7A8194");
            }
            else
            {
                railRefreshValue.Text = UiStrings.TranslateStatus(taskState ?? "Not checked");
                railRefreshValue.Foreground = BrushFrom("#7A8194");
            }

            // Live Option A brand icon state (Title bar + Taskbar + System Tray)
            GuardIconState iconState = ComputeIconState(lastResult, activeMode);
            AppIcons.UpdateBrandLed(titleLedDot, iconState);
            tray.Icon = iconState == GuardIconState.Ready ? trayIconOk :
                        iconState == GuardIconState.Warning ? trayIconWarn : trayIconBlocked;
            Icon = AppIcons.CreateWindowIconSource(iconState);

            // Tray menu item enablement
            bool idle = activeMode == null;
            trayCheckItem.Enabled = idle;
            trayOpenDesktopItem.Enabled = idle && lastResult != null && (lastResult.Ready || lastResult.CanRepair);
            trayOpenCliItem.Enabled = idle && lastResult != null && lastResult.CliReady &&
                (lastResult.CanRepair || String.Equals(lastResult.Firewall, "Effective blocks verified", StringComparison.OrdinalIgnoreCase)) &&
                String.Equals(lastResult.Route, "VPN route verified", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(lastResult.ExitStatus, "Policy mismatch", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(lastResult.ExitStatus, "Probe failed", StringComparison.OrdinalIgnoreCase) &&
                hasConsole;
            trayStopClaudeItem.Enabled = idle;
        }

        private static GuardIconState ComputeIconState(GuardResult r, string mode)
        {
            if (mode == "Launch")
                return GuardIconState.Ready;
            if (r == null)
                return GuardIconState.Warning;
            if (r.Ready)
                return r.DesktopAutoStart ? GuardIconState.Warning : GuardIconState.Ready;
            bool proxyConflict = !String.IsNullOrWhiteSpace(r.ProxyIssue) &&
                !String.Equals(r.ProxyIssue, "None", StringComparison.OrdinalIgnoreCase);
            bool routeBad = !String.Equals(r.Route, "VPN route verified", StringComparison.OrdinalIgnoreCase);
            bool exitBad = String.Equals(r.ExitStatus, "Policy mismatch", StringComparison.OrdinalIgnoreCase) ||
                           String.Equals(r.ExitStatus, "Probe failed", StringComparison.OrdinalIgnoreCase);
            if (proxyConflict || routeBad || exitBad)
                return GuardIconState.Blocked;
            return GuardIconState.Warning;
        }

        private void StartGuardedDesktopLaunch()
        {
            if (activeMode != null)
                return;
            string vpnTag = (lastResult != null && !String.IsNullOrWhiteSpace(lastResult.VpnName)) ? lastResult.VpnName : "VPN";
            string exitTag = (lastResult != null && !String.IsNullOrWhiteSpace(lastResult.ExitMaskedIp))
                ? (" " + lastResult.ExitMaskedIp + (String.IsNullOrWhiteSpace(lastResult.ExitCountry) ? "" : " " + lastResult.ExitCountry))
                : "";
            SetTrayText("Guarding Claude via " + vpnTag + exitTag);

            StartAction("Launch");

            if (UiStrings.AutoMinimizeToTray)
            {
                Hide();
                tray.ShowBalloonTip(3000,
                    UiStrings.T("Guarding Claude Desktop", "正在守卫 Claude Desktop"),
                    UiStrings.T("Monitoring via " + vpnTag + exitTag + ". Double-click tray icon to restore.",
                        "已通过 " + vpnTag + exitTag + " 静默守卫运行，双击托盘图标可随时恢复主窗口。"),
                    Forms.ToolTipIcon.Info);
            }
        }

        private void ConfirmConfiguration()
        {
            if (activeMode != null)
                return;
            MessageBoxResult choice = MessageBox.Show(this,
                UiStrings.T(
                    "Apply Windows Firewall rules that lock Claude to the verified VPN/TUN adapter? Windows will ask for administrator permission.",
                    "确定应用 Windows 防火墙规则，将 Claude 锁定在已核验的 VPN/TUN 网卡上？Windows 将请求管理员权限。"),
                "Claude Guard",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (choice == MessageBoxResult.Yes)
                StartAction("Configure");
        }

        private void ConfirmStopClaude()
        {
            if (activeMode != null)
                return;
            MessageBoxResult choice = MessageBox.Show(this,
                UiStrings.T(
                    "Stop all running Claude Desktop / CLI processes and their child processes (preserving system services)?",
                    "确定安全结束当前运行的全部 Claude Desktop / CLI 进程及其子进程（不会影响无关程序和系统服务）？"),
                UiStrings.T("Stop Claude", "停止 Claude"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (choice == MessageBoxResult.Yes)
                StartAction("StopClaude");
        }

        private void LaunchGuardedCliTerminal()
        {
            string console = GuardEngine.FindSiblingConsole();
            if (console == null)
            {
                MessageBox.Show(this,
                    UiStrings.T(
                        "Could not find ClaudeGuardNativeConsole executable beside this app.",
                        "未在同目录找到 ClaudeGuardNativeConsole 可执行文件，无法从窗口拉起 CLI。"),
                    "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            string args = "--cli";
            if (!String.IsNullOrEmpty(sessionZone))
                args += " --time-zone \"" + sessionZone.Replace("\"", "\\\"") + "\"";
            try
            {
                using (Process process = Process.Start(new ProcessStartInfo(console, args)
                {
                    UseShellExecute = true,
                    WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                }))
                {
                }
            }
            catch (Exception error)
            {
                MessageBox.Show(this, error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void OpenWindowsProxySettings()
        {
            try
            {
                using (Process process = Process.Start(new ProcessStartInfo("ms-settings:network-proxy") { UseShellExecute = true }))
                {
                }
            }
            catch (Exception error)
            {
                MessageBox.Show(this, error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void CreateDesktopShortcut()
        {
            try
            {
                string path = DesktopHygiene.CreateGuardedDesktopShortcut(Forms.Application.ExecutablePath);
                MessageBox.Show(this,
                    UiStrings.T(
                        "Created guarded shortcut:\n" + path + "\n\nDouble-clicking it verifies your VPN/exit policy and launches Claude Desktop automatically.",
                        "已创建桌面受保护快捷方式：\n" + path + "\n\n以后直接双击该图标，即可自动核验 VPN/出口策略并拉起 Claude Desktop。"),
                    "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception error)
            {
                MessageBox.Show(this, error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RunGuiMaintenance(string consoleArguments, string confirmText)
        {
            if (activeMode != null)
                return;
            if (MessageBox.Show(this, confirmText, "Claude Guard", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
                return;
            string console = GuardEngine.FindSiblingConsole();
            if (console == null)
            {
                MessageBox.Show(this,
                    UiStrings.T(
                        "Could not find ClaudeGuardNativeConsole beside this app.",
                        "未在同目录找到配套的控制台程序（ClaudeGuardNativeConsole），无法执行维护操作。"),
                    "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            string statusMsg = GuardEngine.RunElevatedConsoleMaintenance(console, consoleArguments);
            MessageBox.Show(this, statusMsg, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Information);
            TriggerStatusCheck();
        }

        private void VerifyPackage()
        {
            string console = GuardEngine.FindSiblingConsole();
            if (console == null)
            {
                MessageBox.Show(this,
                    UiStrings.T("No portable console executable was found beside this app.", "未在同目录找到便携控制台程序。"),
                    "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            string output = GuardEngine.RunConsoleReadOnly(console, "--verify-package");
            MessageBox.Show(this, output, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void OpenLogsFolder()
        {
            try
            {
                Directory.CreateDirectory(GuardDiagnostics.LogFolder);
                using (Process p = Process.Start(new ProcessStartInfo(GuardDiagnostics.LogFolder) { UseShellExecute = true }))
                {
                }
            }
            catch (Exception error)
            {
                MessageBox.Show(this, error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void ExportDiagnostics()
        {
            var picker = new SaveFileDialog
            {
                FileName = "ClaudeGuardNative-diagnostics.txt",
                Filter = "Text report (*.txt)|*.txt",
                AddExtension = true
            };
            if (picker.ShowDialog(this) != true)
                return;
            try
            {
                GuardDiagnostics.Export(picker.FileName, lastResult);
                MessageBox.Show(this,
                    UiStrings.T("The local diagnostic report was saved (IPv4 masked).", "本地诊断报告已保存（公网 IPv4 已默认脱敏）。"),
                    "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception error)
            {
                MessageBox.Show(this, error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void OpenRegionalSettings()
        {
            using (var win = new RegionalSettingsWindow())
            {
                win.Icon = trayIconOk;
                win.ShowDialog();
            }
        }

        private void OpenDnsSettings()
        {
            using (var win = new DnsSettingsWindow())
            {
                win.Icon = trayIconOk;
                win.ShowDialog();
            }
        }

        private void ShowLimitations()
        {
            string body = UiStrings.T(
                "Scope and known limitations:\n\n" +
                "1. Local guard tools do not change Anthropic's Supported Regions policy and cannot guarantee against account restrictions.\n" +
                "2. Native Guard enforces Windows full-tunnel VPN / TUN routing and blocks non-VPN interfaces + IPv6 for discovered Anthropic-signed apps and Store packages.\n" +
                "3. Enable Exit Verification (Exit Policy tab) if your Wintun client (e.g., Bettbox / Clash TUN) splits domains in user space.\n" +
                "4. Generic child tools (git, node, curl) and Hyper-V NAT guest traffic are outside per-app firewall scope.\n" +
                "5. See native/LIMITATIONS.md for full details.",
                "范围与已知边界：\n\n" +
                "1. 本工具仅做本机路由、防火墙、出口与桌面卫生核验，不能改变 Anthropic 地区政策，也不保证账号不被限制。\n" +
                "2. Native Guard 校验 Windows 全隧道 VPN / TUN 路由，并为已识别的 Anthropic 签名程序及 Store 包阻断非 VPN 网卡与 IPv6。\n" +
                "3. 若使用支持用户态分流的 Wintun 客户端（如 Bettbox / Clash TUN），请务必在「出口策略」页锁定独享出口 IPv4 或国家。\n" +
                "4. 通用子进程（git/node/curl 等）与 Hyper-V NAT 流量不在按程序防火墙覆盖范围内。\n" +
                "5. 完整说明请查看仓库中的 native/LIMITATIONS.md。");
            MessageBox.Show(this, body, UiStrings.T("Known scope and limitations", "已知边界与限制"),
                MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void RestoreWindow()
        {
            Show();
            if (WindowState == WindowState.Minimized)
                WindowState = WindowState.Normal;
            Activate();
        }

        private void SetTrayText(string text)
        {
            if (String.IsNullOrEmpty(text))
                text = "Claude Guard";
            tray.Text = text.Length <= 63 ? text : text.Substring(0, 60) + "...";
        }

        private void OnWindowClosing(object sender, CancelEventArgs e)
        {
            if (activeMode == "Launch")
            {
                e.Cancel = true;
                Hide();
                tray.ShowBalloonTip(3000,
                    UiStrings.T("Claude Guard", "Claude Guard 守卫中"),
                    UiStrings.T("Minimized to system tray while guarding Claude Desktop. Double-click the tray icon to restore.",
                        "已最小化到系统托盘继续静默守卫 Claude Desktop，双击托盘图标可恢复主窗口。"),
                    Forms.ToolTipIcon.Info);
            }
        }

        private void OnWindowClosed(object sender, EventArgs e)
        {
            tray.Visible = false;
            trayMenu.Dispose();
            tray.Dispose();
            if (trayIconOk != null) trayIconOk.Dispose();
            if (trayIconWarn != null) trayIconWarn.Dispose();
            if (trayIconBlocked != null) trayIconBlocked.Dispose();
        }

        private static SolidColorBrush BrushFrom(string hex)
        {
            return (SolidColorBrush)new BrushConverter().ConvertFromString(hex);
        }
    }
}
