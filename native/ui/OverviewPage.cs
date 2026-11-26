using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace ClaudeGuardNative
{
    internal sealed class OverviewPage : Grid
    {
        private enum NodeTone { Ok, Warn, Danger, Idle }
        private enum RailKind { Ok, Warn, Broken, Muted }

        private sealed class SchematicColumn
        {
            internal Border Halo;
            internal Ellipse Led;
            internal Grid RailHost;
            internal TextBlock Title;
            internal TextBlock Sub;
        }

        private readonly TextBlock headline = new TextBlock();
        private readonly TextBlock subtitle = new TextBlock();
        private readonly Border statusChip = new Border();
        private readonly Ellipse statusChipLed = new Ellipse();
        private readonly TextBlock statusChipText = new TextBlock();

        private readonly SchematicColumn[] nodes = new SchematicColumn[4];

        private readonly Border alertStrip = new Border();
        private readonly TextBlock alertText = new TextBlock();
        private readonly Button alertButton = new Button();
        private Action alertButtonHandler;

        private readonly TextBlock keyAdapter = new TextBlock();
        private readonly TextBlock valAdapterMain = new TextBlock();
        private readonly TextBlock valAdapterSub = new TextBlock();

        private readonly TextBlock keyExit = new TextBlock();
        private readonly TextBlock valExitMain = new TextBlock();
        private readonly TextBlock valExitSub = new TextBlock();

        private readonly TextBlock keyEvent = new TextBlock();
        private readonly TextBlock valEventMain = new TextBlock();
        private readonly TextBlock valEventSub = new TextBlock();

        private readonly TextBlock keyHygiene = new TextBlock();
        private readonly TextBlock valHygieneMain = new TextBlock();
        private readonly TextBlock valHygieneSub = new TextBlock();

        private readonly CheckBox autoMinimizeToggle = new CheckBox();
        private readonly CheckBox showFullIpToggle = new CheckBox();
        private readonly TextBlock lastCheckedText = new TextBlock();

        private readonly Button checkBtn = new Button();
        private readonly Button stopClaudeBtn = new Button();
        private readonly Button configureBtn = new Button();
        private readonly Button openCliBtn = new Button();
        private readonly Button openDesktopBtn = new Button();

        private bool suppressToggleEvents;
        private DateTime? lastCheckedUtc;
        private GuardResult currentResult;
        private string currentActiveMode;
        private string currentSessionZone;
        private bool hasSiblingConsole;

        internal event Action CheckRequested;
        internal event Action StopClaudeRequested;
        internal event Action ConfigureFirewallRequested;
        internal event Action LaunchCliRequested;
        internal event Action LaunchDesktopRequested;
        internal event Action OpenProxySettingsRequested;
        internal event Action<int> NavigateToTabRequested;
        internal event Action<bool> ShowFullIpChanged;

        internal bool ShowFullIp
        {
            get { return showFullIpToggle.IsChecked == true; }
            set
            {
                suppressToggleEvents = true;
                showFullIpToggle.IsChecked = value;
                suppressToggleEvents = false;
                RenderState();
            }
        }

        internal OverviewPage()
        {
            Margin = new Thickness(24, 20, 24, 18);
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0: Header
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 1: Conduit Card
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 2: Telemetry Table
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 3: Switches
            RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 4: Air
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 5: Action Dock

            BuildHeader();
            BuildConduitCard();
            BuildTelemetryCard();
            BuildSwitchRow();
            BuildActionDock();

            ApplyLocalization();
            RenderState();
        }

        private void BuildHeader()
        {
            var header = new Grid { Margin = new Thickness(0, 0, 0, 14) };
            header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var titleStack = new StackPanel();
            headline.FontSize = 17.5;
            headline.FontWeight = FontWeights.SemiBold;
            headline.Foreground = BrushFrom("#121418");
            headline.TextTrimming = TextTrimming.CharacterEllipsis;
            titleStack.Children.Add(headline);

            subtitle.FontSize = 12.5;
            subtitle.Foreground = BrushFrom("#7A8194");
            subtitle.Margin = new Thickness(0, 3, 0, 0);
            subtitle.TextTrimming = TextTrimming.CharacterEllipsis;
            titleStack.Children.Add(subtitle);
            Grid.SetColumn(titleStack, 0);
            header.Children.Add(titleStack);

            statusChip.CornerRadius = new CornerRadius(12);
            statusChip.BorderThickness = new Thickness(1);
            statusChip.Padding = new Thickness(10, 4, 10, 4);
            statusChip.VerticalAlignment = VerticalAlignment.Top;
            statusChip.Margin = new Thickness(12, 2, 0, 0);

            var chipInner = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            statusChipLed.Width = 7;
            statusChipLed.Height = 7;
            statusChipLed.VerticalAlignment = VerticalAlignment.Center;
            statusChipLed.Margin = new Thickness(0, 0, 6, 0);
            statusChipText.FontSize = 12;
            statusChipText.FontWeight = FontWeights.SemiBold;
            statusChipText.VerticalAlignment = VerticalAlignment.Center;
            chipInner.Children.Add(statusChipLed);
            chipInner.Children.Add(statusChipText);
            statusChip.Child = chipInner;
            Grid.SetColumn(statusChip, 1);
            header.Children.Add(statusChip);

            Grid.SetRow(header, 0);
            Children.Add(header);
        }

        private void BuildConduitCard()
        {
            var card = new Border
            {
                Background = BrushFrom("#FFFFFF"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(20, 18, 20, 16),
                Margin = new Thickness(0, 0, 0, 14)
            };

            var stack = new StackPanel();

            var schematic = new Grid();
            for (int i = 0; i < 4; i++)
                schematic.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            for (int i = 0; i < 4; i++)
            {
                var col = new StackPanel();

                var railRow = new Grid { Height = 22, Margin = new Thickness(0, 0, 0, 10) };
                railRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                railRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                var halo = new Border
                {
                    Width = 18,
                    Height = 18,
                    CornerRadius = new CornerRadius(9),
                    BorderThickness = new Thickness(1),
                    VerticalAlignment = VerticalAlignment.Center
                };
                var led = new Ellipse { Width = 7, Height = 7, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                halo.Child = led;
                Grid.SetColumn(halo, 0);
                railRow.Children.Add(halo);

                Grid railHost = null;
                if (i < 3)
                {
                    railHost = new Grid { Margin = new Thickness(8, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center, Height = 18 };
                    Grid.SetColumn(railHost, 1);
                    railRow.Children.Add(railHost);
                }

                col.Children.Add(railRow);

                var title = new TextBlock
                {
                    FontSize = 12.5,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = BrushFrom("#121418"),
                    Margin = new Thickness(0, 0, 8, 0),
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                var sub = new TextBlock
                {
                    FontSize = 11.5,
                    Foreground = BrushFrom("#7A8194"),
                    Margin = new Thickness(0, 2, 8, 0),
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                if (i == 3)
                    sub.FontFamily = new FontFamily("Cascadia Mono, Consolas, Segoe UI");

                col.Children.Add(title);
                col.Children.Add(sub);

                Grid.SetColumn(col, i);
                schematic.Children.Add(col);

                nodes[i] = new SchematicColumn
                {
                    Halo = halo,
                    Led = led,
                    RailHost = railHost,
                    Title = title,
                    Sub = sub
                };
            }
            stack.Children.Add(schematic);

            // Inline recovery alert strip (shown dynamically on block/warning)
            alertStrip.Margin = new Thickness(0, 14, 0, 0);
            alertStrip.Padding = new Thickness(14, 10, 14, 10);
            alertStrip.CornerRadius = new CornerRadius(8);
            alertStrip.BorderThickness = new Thickness(1);
            alertStrip.Visibility = Visibility.Collapsed;

            var alertGrid = new Grid();
            alertGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            alertGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            alertText.FontSize = 12;
            alertText.TextWrapping = TextWrapping.Wrap;
            alertText.VerticalAlignment = VerticalAlignment.Center;
            alertText.LineHeight = 18;
            Grid.SetColumn(alertText, 0);
            alertGrid.Children.Add(alertText);

            alertButton.Margin = new Thickness(12, 0, 0, 0);
            alertButton.VerticalAlignment = VerticalAlignment.Center;
            alertButton.Click += delegate
            {
                if (alertButtonHandler != null)
                    alertButtonHandler();
            };
            Grid.SetColumn(alertButton, 1);
            alertGrid.Children.Add(alertButton);

            alertStrip.Child = alertGrid;
            stack.Children.Add(alertStrip);

            card.Child = stack;
            Grid.SetRow(card, 1);
            Children.Add(card);
        }

        private void BuildTelemetryCard()
        {
            var card = new Border
            {
                Background = BrushFrom("#FFFFFF"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Margin = new Thickness(0, 0, 0, 14)
            };

            var stack = new StackPanel();
            stack.Children.Add(CreateSpecRow(keyAdapter, valAdapterMain, valAdapterSub, false, false));
            stack.Children.Add(CreateSpecRow(keyExit, valExitMain, valExitSub, true, false));
            stack.Children.Add(CreateSpecRow(keyEvent, valEventMain, valEventSub, false, false));
            stack.Children.Add(CreateSpecRow(keyHygiene, valHygieneMain, valHygieneSub, false, true));

            card.Child = stack;
            Grid.SetRow(card, 2);
            Children.Add(card);
        }

        private static Border CreateSpecRow(TextBlock keyBlock, TextBlock mainVal, TextBlock subVal, bool monoMain, bool isLast)
        {
            var border = new Border
            {
                Padding = new Thickness(16, 10, 16, 10),
                BorderBrush = BrushFrom("#EFF1F4"),
                BorderThickness = isLast ? new Thickness(0) : new Thickness(0, 0, 0, 1)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            keyBlock.FontSize = 12.5;
            keyBlock.Foreground = BrushFrom("#4B5162");
            keyBlock.VerticalAlignment = VerticalAlignment.Center;
            keyBlock.Margin = new Thickness(0, 0, 16, 0);
            Grid.SetColumn(keyBlock, 0);
            grid.Children.Add(keyBlock);

            var right = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center
            };
            mainVal.FontSize = 12.5;
            mainVal.FontWeight = FontWeights.Medium;
            mainVal.Foreground = BrushFrom("#121418");
            if (monoMain)
                mainVal.FontFamily = new FontFamily("Cascadia Mono, Consolas, Segoe UI");
            subVal.FontSize = 12;
            subVal.Foreground = BrushFrom("#7A8194");
            subVal.Margin = new Thickness(7, 0, 0, 0);
            subVal.TextTrimming = TextTrimming.CharacterEllipsis;
            subVal.MaxWidth = 340;
            right.Children.Add(mainVal);
            right.Children.Add(subVal);

            Grid.SetColumn(right, 1);
            grid.Children.Add(right);

            border.Child = grid;
            return border;
        }

        private void BuildSwitchRow()
        {
            var row = new Grid { Margin = new Thickness(2, 0, 2, 0) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var left = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            autoMinimizeToggle.SetResourceReference(StyleProperty, "HardwareToggleStyle");
            autoMinimizeToggle.IsChecked = UiStrings.AutoMinimizeToTray;
            autoMinimizeToggle.Margin = new Thickness(0, 0, 20, 0);
            autoMinimizeToggle.Checked += delegate { if (!suppressToggleEvents) UiStrings.AutoMinimizeToTray = true; };
            autoMinimizeToggle.Unchecked += delegate { if (!suppressToggleEvents) UiStrings.AutoMinimizeToTray = false; };

            showFullIpToggle.SetResourceReference(StyleProperty, "HardwareToggleStyle");
            showFullIpToggle.Checked += delegate
            {
                if (!suppressToggleEvents)
                {
                    RenderState();
                    if (ShowFullIpChanged != null) ShowFullIpChanged(true);
                }
            };
            showFullIpToggle.Unchecked += delegate
            {
                if (!suppressToggleEvents)
                {
                    RenderState();
                    if (ShowFullIpChanged != null) ShowFullIpChanged(false);
                }
            };

            left.Children.Add(autoMinimizeToggle);
            left.Children.Add(showFullIpToggle);
            Grid.SetColumn(left, 0);
            row.Children.Add(left);

            lastCheckedText.FontSize = 12;
            lastCheckedText.Foreground = BrushFrom("#7A8194");
            lastCheckedText.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(lastCheckedText, 1);
            row.Children.Add(lastCheckedText);

            Grid.SetRow(row, 3);
            Children.Add(row);
        }

        private void BuildActionDock()
        {
            var dock = new Border
            {
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(0, 12, 0, 0)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var leftBtns = new StackPanel { Orientation = Orientation.Horizontal };
            checkBtn.SetResourceReference(StyleProperty, "SecondaryButtonStyle");
            checkBtn.Margin = new Thickness(0, 0, 8, 0);
            checkBtn.Click += delegate { if (CheckRequested != null) CheckRequested(); };

            stopClaudeBtn.SetResourceReference(StyleProperty, "DangerOutlineButtonStyle");
            stopClaudeBtn.Click += delegate { if (StopClaudeRequested != null) StopClaudeRequested(); };

            leftBtns.Children.Add(checkBtn);
            leftBtns.Children.Add(stopClaudeBtn);
            Grid.SetColumn(leftBtns, 0);
            grid.Children.Add(leftBtns);

            var rightBtns = new StackPanel { Orientation = Orientation.Horizontal };
            configureBtn.SetResourceReference(StyleProperty, "GhostButtonStyle");
            configureBtn.Margin = new Thickness(0, 0, 8, 0);
            configureBtn.Click += delegate { if (ConfigureFirewallRequested != null) ConfigureFirewallRequested(); };

            openCliBtn.SetResourceReference(StyleProperty, "SecondaryButtonStyle");
            openCliBtn.Margin = new Thickness(0, 0, 8, 0);
            openCliBtn.Click += delegate { if (LaunchCliRequested != null) LaunchCliRequested(); };

            openDesktopBtn.SetResourceReference(StyleProperty, "PrimaryButtonStyle");
            openDesktopBtn.Click += delegate { if (LaunchDesktopRequested != null) LaunchDesktopRequested(); };

            rightBtns.Children.Add(configureBtn);
            rightBtns.Children.Add(openCliBtn);
            rightBtns.Children.Add(openDesktopBtn);
            Grid.SetColumn(rightBtns, 2);
            grid.Children.Add(rightBtns);

            dock.Child = grid;
            Grid.SetRow(dock, 5);
            Children.Add(dock);
        }

        internal void ApplyLocalization()
        {
            keyAdapter.Text = UiStrings.T("Locked VPN adapter", "当前锁定网卡");
            keyExit.Text = UiStrings.T("Public exit allowlist", "出口白名单核验");
            keyEvent.Text = UiStrings.T("Event watcher & timezone", "事件监听与会话时区");
            keyHygiene.Text = UiStrings.T("Desktop hygiene status", "桌面端卫生状态");

            autoMinimizeToggle.Content = UiStrings.T("Minimize to tray while guarding", "启动后最小化到托盘静默守卫");
            showFullIpToggle.Content = UiStrings.T("Show full IPv4", "显示完整 IPv4");

            checkBtn.Content = UiStrings.T("Re-check", "重新检查");
            configureBtn.Content = UiStrings.T("Configure firewall", "配置防火墙");
            openCliBtn.Content = UiStrings.T("Launch CLI", "启动 CLI");
            openDesktopBtn.Content = UiStrings.T("Launch Claude Desktop", "启动 Claude Desktop");

            RenderState();
        }

        internal void UpdateState(GuardResult result, string activeMode, string sessionZone, bool siblingConsolePresent)
        {
            currentResult = result;
            currentActiveMode = activeMode;
            currentSessionZone = sessionZone;
            hasSiblingConsole = siblingConsolePresent;
            if (activeMode == null && result != null)
                lastCheckedUtc = DateTime.Now;
            RenderState();
        }

        private void RenderState()
        {
            bool idle = currentActiveMode == null;
            GuardResult r = currentResult;

            // Update timestamp
            if (!idle)
            {
                lastCheckedText.Text = currentActiveMode == "Launch"
                    ? UiStrings.T("Active monitoring", "实时守卫中")
                    : UiStrings.T("Checking...", "正在校验...");
            }
            else if (lastCheckedUtc.HasValue)
            {
                lastCheckedText.Text = UiStrings.T("Last check: ", "上次校验：") + lastCheckedUtc.Value.ToString("HH:mm:ss");
            }
            else
            {
                lastCheckedText.Text = UiStrings.T("Not checked yet", "尚未校验");
            }

            // Stop button label + running count
            int runningCount = r != null ? r.RunningClaudeCount : 0;
            bool claudeRunning = r != null && (runningCount > 0 || String.Equals(r.Claude, "Already running", StringComparison.OrdinalIgnoreCase));
            stopClaudeBtn.Content = runningCount > 0
                ? UiStrings.T("Stop Claude (" + runningCount + ")", "停止 Claude (" + runningCount + ")")
                : UiStrings.T("Stop Claude", "停止 Claude");

            // Buttons enabled state
            checkBtn.IsEnabled = idle;
            stopClaudeBtn.IsEnabled = idle && claudeRunning;
            configureBtn.IsEnabled = idle && r != null && r.CanConfigure;
            configureBtn.SetResourceReference(StyleProperty,
                (r != null && r.CanConfigure && !r.Ready) ? "SecondaryButtonStyle" : "GhostButtonStyle");
            openDesktopBtn.IsEnabled = idle && r != null && r.Ready;

            bool cliLaunchable = idle && r != null && r.CliReady &&
                String.Equals(r.Firewall, "Effective blocks verified", StringComparison.OrdinalIgnoreCase) &&
                String.Equals(r.Route, "VPN route verified", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(r.ExitStatus, "Policy mismatch", StringComparison.OrdinalIgnoreCase) &&
                !String.Equals(r.ExitStatus, "Probe failed", StringComparison.OrdinalIgnoreCase) &&
                hasSiblingConsole;
            openCliBtn.IsEnabled = cliLaunchable;

            // Loading / Guarding state
            if (!idle)
            {
                if (currentActiveMode == "Launch")
                {
                    headline.Text = UiStrings.T("Guarding Claude Desktop session", "正在静默守卫 Claude Desktop 会话");
                    subtitle.Text = UiStrings.T("Windows IP Helper event watcher and exit checks are active.", "Windows IP Helper 路由变更实时监听与公网出口核验已激活");
                    SetChip(NodeTone.Ok, UiStrings.T("Guarding", "守卫运行中"));
                }
                else
                {
                    headline.Text = UiStrings.T("Verifying local tunnel, firewall, and exit...", "正在核验本地隧道、防火墙与公网出口...");
                    subtitle.Text = UiStrings.T("Inspecting Windows network interfaces, proxy state, and Anthropic app signatures.", "正在检查 Windows 网卡路由、系统代理状态与签名应用");
                    SetChip(NodeTone.Idle, UiStrings.T("Checking...", "检查中..."));
                }
                if (r == null)
                {
                    SetNode(0, NodeTone.Idle, "Claude Desktop", UiStrings.T("Scanning...", "扫描中..."), RailKind.Muted, false);
                    SetNode(1, NodeTone.Idle, UiStrings.T("Firewall lock", "防火墙锁"), UiStrings.T("Checking...", "检查中..."), RailKind.Muted, false);
                    SetNode(2, NodeTone.Idle, "VPN / TUN", UiStrings.T("Checking...", "检查中..."), RailKind.Muted, false);
                    SetNode(3, NodeTone.Idle, UiStrings.T("Public exit", "独享 VPS 出口"), UiStrings.T("Waiting...", "等待核验"), RailKind.Muted, false);
                    alertStrip.Visibility = Visibility.Collapsed;
                    RenderTelemetryFallback();
                    return;
                }
            }

            if (r == null)
            {
                headline.Text = UiStrings.T("Waiting for protection check", "等待执行本地安全核验");
                subtitle.Text = UiStrings.T("Click Re-check to inspect VPN route, firewall lock, and exit policy.", "点击「重新检查」验证 VPN 路由、防火墙锁定与出口策略");
                SetChip(NodeTone.Idle, UiStrings.T("Unchecked", "未检查"));
                SetNode(0, NodeTone.Idle, "Claude Desktop", UiStrings.T("Unchecked", "未检查"), RailKind.Muted, false);
                SetNode(1, NodeTone.Idle, UiStrings.T("Firewall lock", "防火墙锁"), UiStrings.T("Unchecked", "未检查"), RailKind.Muted, false);
                SetNode(2, NodeTone.Idle, "VPN / TUN", UiStrings.T("Unchecked", "未检查"), RailKind.Muted, false);
                SetNode(3, NodeTone.Idle, UiStrings.T("Public exit", "独享 VPS 出口"), UiStrings.T("Unchecked", "未检查"), RailKind.Muted, false);
                alertStrip.Visibility = Visibility.Collapsed;
                RenderTelemetryFallback();
                return;
            }

            bool proxyConflict = !String.IsNullOrWhiteSpace(r.ProxyIssue) && !String.Equals(r.ProxyIssue, "None", StringComparison.OrdinalIgnoreCase);
            bool routeOk = String.Equals(r.Route, "VPN route verified", StringComparison.OrdinalIgnoreCase);
            bool fwOk = String.Equals(r.Firewall, "Effective blocks verified", StringComparison.OrdinalIgnoreCase);
            bool fwNeedSetup = String.Equals(r.Firewall, "Setup required", StringComparison.OrdinalIgnoreCase);
            bool exitOk = String.Equals(r.ExitStatus, "Verified", StringComparison.OrdinalIgnoreCase);
            bool exitDisabled = String.Equals(r.ExitStatus, "Disabled", StringComparison.OrdinalIgnoreCase);
            bool exitFailed = String.Equals(r.ExitStatus, "Policy mismatch", StringComparison.OrdinalIgnoreCase) ||
                              String.Equals(r.ExitStatus, "Probe failed", StringComparison.OrdinalIgnoreCase);
            bool desktopFound = r.DesktopReady || String.Equals(r.Claude, "Desktop verified", StringComparison.OrdinalIgnoreCase) ||
                                String.Equals(r.Claude, "Already running", StringComparison.OrdinalIgnoreCase);

            string vpnLabel = String.IsNullOrWhiteSpace(r.VpnName) ? "VPN / TUN" : r.VpnName;
            string shownIp = ShowFullIp ? r.ExitIp : r.ExitMaskedIp;

            // --- Header & Chip ---
            if (idle)
            {
                if (r.Ready)
                {
                    headline.Text = UiStrings.T("Conduit ready — launch Claude Desktop", "通道就绪，可以启动 Claude Desktop");
                    subtitle.Text = UiStrings.T(
                        "Public IPv4 traffic is locked to " + vpnLabel + "; non-VPN adapters and IPv6 are blocked.",
                        "所有公网 IPv4 流量已锁定经由 " + vpnLabel + " 出口，非 VPN 网卡与 IPv6 已封锁");
                    SetChip(NodeTone.Ok, UiStrings.T("All checks passed", "全部核验通过"));
                }
                else if (proxyConflict)
                {
                    headline.Text = UiStrings.T("Launch blocked — Windows system proxy conflict", "已拦截启动 — 检测到 Windows 系统代理冲突");
                    subtitle.Text = UiStrings.T(
                        "Disable system proxy so traffic cannot loop back around adapter firewall rules.",
                        "为避免流量经回环端口绕过网卡防火墙，请先关闭代理软件中的系统代理开关");
                    SetChip(NodeTone.Danger, UiStrings.T("Blocked", "已阻止放行"));
                }
                else if (!routeOk)
                {
                    headline.Text = UiStrings.T("Launch blocked — no active full-tunnel VPN / TUN", "已拦截启动 — 未检测到全隧道 VPN / TUN 路由");
                    subtitle.Text = UiStrings.T(
                        "Start your TUN adapter (e.g., Bettbox TUN) before launching Claude.",
                        "请先开启 Bettbox 等全隧道 TUN 虚拟网卡，再点击「重新检查」");
                    SetChip(NodeTone.Danger, UiStrings.T("Blocked", "已阻止放行"));
                }
                else if (fwNeedSetup || r.CanConfigure)
                {
                    headline.Text = UiStrings.T("Firewall lock setup required", "待配置 Windows 防火墙出站锁定");
                    subtitle.Text = UiStrings.T(
                        "VPN route is verified; apply per-app outbound firewall rules to lock Claude to " + vpnLabel + ".",
                        "已检测到 " + vpnLabel + " 隧道；请应用出站防火墙规则以封锁非 VPN 网卡与 IPv6");
                    SetChip(NodeTone.Warn, UiStrings.T("Setup needed", "待配置防火墙"));
                }
                else if (exitFailed)
                {
                    headline.Text = UiStrings.T("Launch blocked — public exit policy mismatch", "已拦截启动 — 公网出口核验未通过");
                    subtitle.Text = !String.IsNullOrWhiteSpace(r.Message)
                        ? r.Message
                        : UiStrings.T("Public IPv4 exit did not match your configured allowlist.", "当前公网出口未命中你设定的独享 IPv4 或国家白名单");
                    SetChip(NodeTone.Danger, UiStrings.T("Exit blocked", "出口已熔断"));
                }
                else if (claudeRunning)
                {
                    headline.Text = UiStrings.T("Claude is already running", "检测到 Claude 正在运行");
                    subtitle.Text = UiStrings.T(
                        "Stop existing Claude processes first so Native Guard can start a clean guarded session.",
                        "请先安全停止现有 Claude 进程树，再通过本守卫重新拉起受保护会话");
                    SetChip(NodeTone.Warn, UiStrings.T("Already running", "进程已运行"));
                }
                else
                {
                    headline.Text = !desktopFound
                        ? UiStrings.T("Claude Desktop not found on this PC", "未在本机检测到 Claude Desktop")
                        : UiStrings.T("Launch blocked — review checks below", "已拦截启动 — 请查看下方核验详情");
                    subtitle.Text = !desktopFound
                        ? UiStrings.T(
                            "VPN route (" + vpnLabel + ") is verified; install official signed Claude Desktop to configure firewall and launch.",
                            "已核验 " + vpnLabel + " 全隧道；安装官方签名版 Claude Desktop 后即可配置防火墙并启动")
                        : (!String.IsNullOrWhiteSpace(r.Message)
                            ? r.Message
                            : UiStrings.T("Review the diagnostic details below.", "请查看下方详细核验状态"));
                    SetChip(NodeTone.Warn, UiStrings.T("Action needed", "需处理"));
                }
            }

            // --- 4-Node Connected-Rail Conduit Schematic ---
            NodeTone n0Tone = desktopFound ? (claudeRunning ? NodeTone.Warn : NodeTone.Ok) : NodeTone.Idle;
            string n0Sub = claudeRunning
                ? UiStrings.T("Running (" + (runningCount > 0 ? runningCount.ToString() : "1") + ")", "运行中 (" + (runningCount > 0 ? runningCount.ToString() : "1") + ")")
                : (desktopFound
                    ? (r.CliReady ? UiStrings.T("Desktop + CLI signed", "桌面端 + CLI 已签名") : UiStrings.T("Signed Desktop ready", "官方签名已核验"))
                    : (r.CliReady ? UiStrings.T("CLI only (Desktop missing)", "仅 CLI（未装桌面端）") : UiStrings.T("Not installed", "未检测到安装")));

            NodeTone n1Tone;
            string n1Title;
            string n1Sub;
            RailKind r01;
            if (proxyConflict)
            {
                n1Tone = NodeTone.Danger;
                n1Title = UiStrings.T("System proxy conflict", "系统代理冲突");
                n1Sub = r.ProxyIssue + UiStrings.T(" active", " 已开启");
                r01 = RailKind.Broken;
            }
            else if (fwOk)
            {
                n1Tone = NodeTone.Ok;
                n1Title = UiStrings.T("Firewall lock", "防火墙锁");
                n1Sub = UiStrings.T(r.BlockedAdapterCount + " NICs + IPv6 blocked", "已封锁 " + r.BlockedAdapterCount + " 网卡 + IPv6");
                r01 = desktopFound ? RailKind.Ok : RailKind.Muted;
            }
            else if (fwNeedSetup || r.CanConfigure)
            {
                n1Tone = NodeTone.Warn;
                n1Title = UiStrings.T("Firewall lock", "防火墙待配置");
                n1Sub = UiStrings.T("Setup required", "需应用出站规则");
                r01 = RailKind.Warn;
            }
            else if (!desktopFound && String.Equals(r.Firewall, "Unverified", StringComparison.OrdinalIgnoreCase))
            {
                n1Tone = NodeTone.Idle;
                n1Title = UiStrings.T("Firewall lock", "防火墙锁");
                n1Sub = UiStrings.T("Waiting for Desktop", "等待安装桌面端");
                r01 = RailKind.Muted;
            }
            else
            {
                n1Tone = NodeTone.Danger;
                n1Title = UiStrings.T("Firewall lock", "防火墙锁");
                n1Sub = UiStrings.TranslateStatus(r.Firewall);
                r01 = RailKind.Broken;
            }

            NodeTone n2Tone = routeOk ? NodeTone.Ok : (proxyConflict && !String.IsNullOrWhiteSpace(r.VpnName) ? NodeTone.Ok : NodeTone.Danger);
            string n2Title = String.IsNullOrWhiteSpace(r.VpnName) ? "VPN / TUN" : r.VpnName + " TUN";
            string n2Sub = routeOk
                ? UiStrings.T("Full tunnel verified", "全隧道已核验")
                : (!String.IsNullOrWhiteSpace(r.VpnName)
                    ? UiStrings.T("Online (blocked by proxy)", "已在线（被代理阻断）")
                    : UiStrings.T("Not connected", "未连接全隧道"));
            RailKind r12 = (r01 == RailKind.Ok && routeOk) ? RailKind.Ok : (routeOk ? RailKind.Muted : RailKind.Broken);

            NodeTone n3Tone;
            string n3Sub;
            RailKind r23;
            if (!routeOk || proxyConflict)
            {
                n3Tone = NodeTone.Idle;
                n3Sub = UiStrings.T("Waiting for route", "等待前序通过");
                r23 = RailKind.Muted;
            }
            else if (exitOk)
            {
                n3Tone = NodeTone.Ok;
                string geo = String.IsNullOrWhiteSpace(r.ExitCountry)
                    ? ""
                    : (" · " + r.ExitCountry + (String.IsNullOrWhiteSpace(r.ExitColo) ? "" : "/" + r.ExitColo));
                n3Sub = (String.IsNullOrWhiteSpace(shownIp) ? "Verified" : shownIp) + geo;
                r23 = (r12 == RailKind.Ok) ? RailKind.Ok : RailKind.Muted;
            }
            else if (exitFailed)
            {
                n3Tone = NodeTone.Danger;
                n3Sub = String.IsNullOrWhiteSpace(shownIp) ? UiStrings.TranslateStatus(r.ExitStatus) : shownIp + " ×";
                r23 = RailKind.Broken;
            }
            else if (exitDisabled)
            {
                n3Tone = NodeTone.Idle;
                n3Sub = UiStrings.T("Policy off (optional)", "策略未启用（可选）");
                r23 = (r12 == RailKind.Ok) ? RailKind.Ok : RailKind.Muted;
            }
            else
            {
                n3Tone = NodeTone.Idle;
                n3Sub = UiStrings.TranslateStatus(r.ExitStatus);
                r23 = RailKind.Muted;
            }

            SetNode(0, n0Tone, "Claude Desktop", n0Sub, r01, false);
            SetNode(1, n1Tone, n1Title, n1Sub, r12, proxyConflict);
            SetNode(2, n2Tone, n2Title, n2Sub, r23, !routeOk && !proxyConflict);
            SetNode(3, n3Tone, UiStrings.T("Public exit", "独享 VPS 出口"), n3Sub, RailKind.Muted, exitFailed);

            // --- Inline Contextual Recovery Alert Strip ---
            if (proxyConflict)
            {
                ShowAlert(
                    true,
                    UiStrings.T(
                        "Fix: Your TUN adapter handles routing directly — Windows manual/PAC proxy (" + r.ProxyIssue + ") must be turned off so traffic cannot bypass firewall rules.",
                        "修复指引：已启用 TUN 虚拟网卡，无需同时开启 Windows 系统代理（" + r.ProxyIssue + "）。关闭后点击「重新检查」即可放行。"),
                    UiStrings.T("Open proxy settings", "打开系统代理设置"),
                    delegate { if (OpenProxySettingsRequested != null) OpenProxySettingsRequested(); });
            }
            else if (fwNeedSetup || (r.CanConfigure && !fwOk))
            {
                ShowAlert(
                    false,
                    UiStrings.T(
                        "Next step: Apply Windows Firewall rules to lock Claude to " + vpnLabel + " and block all non-VPN adapters + IPv6.",
                        "下一步：点击右侧按钮一键配置 Windows 防火墙规则，将 Claude 锁定在 " + vpnLabel + " 并封锁非 VPN 网卡与 IPv6。"),
                    UiStrings.T("Configure firewall", "立即配置防火墙"),
                    delegate { if (ConfigureFirewallRequested != null) ConfigureFirewallRequested(); });
            }
            else if (exitFailed)
            {
                ShowAlert(
                    true,
                    UiStrings.T("Exit check failed: ", "出口核验拦截：") + r.Message,
                    UiStrings.T("Open exit policy", "调整出口策略"),
                    delegate { if (NavigateToTabRequested != null) NavigateToTabRequested(1); });
            }
            else if (r.DesktopAutoStart)
            {
                ShowAlert(
                    false,
                    UiStrings.T(
                        "Auto-start risk: Claude Desktop is set to start at Windows logon and may connect before your VPN/TUN is up.",
                        "开机自启提醒：检测到 Claude Desktop 已启用 Windows 开机自启，可能在 Bettbox TUN 就绪前抢跑联网，建议关闭。"),
                    UiStrings.T("Open Desktop hygiene", "前往桌面卫生"),
                    delegate { if (NavigateToTabRequested != null) NavigateToTabRequested(2); });
            }
            else if (!r.Ready && !String.IsNullOrWhiteSpace(r.Message))
            {
                string alertBody = (!desktopFound && routeOk)
                    ? UiStrings.T(
                        "Install official Anthropic-signed Claude Desktop (Microsoft Store or installer), then click Re-check to configure firewall rules and launch safely.",
                        "请先安装官方签名版 Claude Desktop（Microsoft Store 或官网安装程序），安装完成后点击「重新检查」即可一键配置防火墙并受守卫启动。")
                    : r.Message;
                ShowAlert(
                    !routeOk,
                    alertBody,
                    claudeRunning ? UiStrings.T("Stop Claude", "停止 Claude") : UiStrings.T("Re-check", "重新检查"),
                    delegate
                    {
                        if (claudeRunning) { if (StopClaudeRequested != null) StopClaudeRequested(); }
                        else { if (CheckRequested != null) CheckRequested(); }
                    });
            }
            else
            {
                alertStrip.Visibility = Visibility.Collapsed;
            }

            // --- 4-Row Hairline Telemetry Table ---
            if (proxyConflict)
            {
                valAdapterMain.Text = r.ProxyIssue;
                valAdapterMain.Foreground = BrushFrom("#B91C1C");
                valAdapterSub.Text = UiStrings.T("Windows system proxy conflict", "Windows 系统代理冲突（请关闭）");
            }
            else if (routeOk)
            {
                valAdapterMain.Text = vpnLabel;
                valAdapterMain.Foreground = BrushFrom("#121418");
                valAdapterSub.Text = UiStrings.T("(Full tunnel · No system proxy conflict)", "(全隧道已核验 · 无系统代理冲突)");
            }
            else
            {
                valAdapterMain.Text = UiStrings.TranslateStatus(r.Route);
                valAdapterMain.Foreground = BrushFrom("#B91C1C");
                valAdapterSub.Text = "";
            }

            if (exitOk)
            {
                valExitMain.Text = String.IsNullOrWhiteSpace(shownIp) ? UiStrings.T("Verified", "已通过") : shownIp;
                valExitMain.Foreground = BrushFrom("#121418");
                ExitPolicy p = SafeLoadExitPolicy();
                string geo = String.IsNullOrWhiteSpace(r.ExitCountry) ? "" : (r.ExitCountry + (String.IsNullOrWhiteSpace(r.ExitColo) ? "" : "/" + r.ExitColo));
                valExitSub.Text = (String.IsNullOrEmpty(geo) ? "" : geo + " · ") + p.TargetHost +
                    UiStrings.T(" · retry " + p.TransientFailureTolerance + "x", " · 弱网容忍 " + p.TransientFailureTolerance + " 次");
            }
            else if (exitFailed)
            {
                valExitMain.Text = UiStrings.TranslateStatus(r.ExitStatus);
                valExitMain.Foreground = BrushFrom("#B91C1C");
                valExitSub.Text = String.IsNullOrWhiteSpace(shownIp) ? "" : shownIp;
            }
            else if (exitDisabled)
            {
                valExitMain.Text = UiStrings.T("Disabled", "未启用");
                valExitMain.Foreground = BrushFrom("#4B5162");
                valExitSub.Text = UiStrings.T("Configure in Exit Policy to lock your VPS IPv4", "建议在「出口策略」锁定独享 VPS IPv4");
            }
            else
            {
                valExitMain.Text = UiStrings.TranslateStatus(r.ExitStatus);
                valExitMain.Foreground = BrushFrom("#7A8194");
                valExitSub.Text = "";
            }

            valEventMain.Text = UiStrings.T("Windows IP Helper active", "Windows IP Helper 实时唤醒");
            valEventMain.Foreground = BrushFrom("#121418");
            valEventSub.Text = String.IsNullOrEmpty(currentSessionZone)
                ? UiStrings.T("· Time zone: keep current", "· 时区保持当前")
                : UiStrings.T("· Session TZ: ", "· 会话时区：") + currentSessionZone;

            if (r.DesktopAutoStart)
            {
                valHygieneMain.Text = UiStrings.T("Auto-start ON (warning)", "已启用开机自启");
                valHygieneMain.Foreground = BrushFrom("#B45309");
                valHygieneSub.Text = UiStrings.T("· Disable in Desktop Hygiene", "· 建议在「桌面卫生」中关闭");
            }
            else
            {
                valHygieneMain.Text = UiStrings.T("Auto-start OFF", "开机自启已关闭");
                valHygieneMain.Foreground = BrushFrom("#121418");
                valHygieneSub.Text = UiStrings.T("· MCP config protected", "· MCP 配置受保护");
            }

            SyncSubVisibility(valAdapterSub);
            SyncSubVisibility(valExitSub);
            SyncSubVisibility(valEventSub);
            SyncSubVisibility(valHygieneSub);
        }

        private static void SyncSubVisibility(TextBlock tb)
        {
            tb.Visibility = String.IsNullOrEmpty(tb.Text) ? Visibility.Collapsed : Visibility.Visible;
        }

        private void RenderTelemetryFallback()
        {
            string dash = "—";
            valAdapterMain.Text = dash; valAdapterMain.Foreground = BrushFrom("#7A8194"); valAdapterSub.Text = "";
            valExitMain.Text = dash; valExitMain.Foreground = BrushFrom("#7A8194"); valExitSub.Text = "";
            valEventMain.Text = UiStrings.T("Windows IP Helper ready", "Windows IP Helper 就绪");
            valEventMain.Foreground = BrushFrom("#121418");
            valEventSub.Text = "";
            valHygieneMain.Text = dash; valHygieneMain.Foreground = BrushFrom("#7A8194"); valHygieneSub.Text = "";
            SyncSubVisibility(valAdapterSub);
            SyncSubVisibility(valExitSub);
            SyncSubVisibility(valEventSub);
            SyncSubVisibility(valHygieneSub);
        }

        private void ShowAlert(bool danger, string text, string btnLabel, Action handler)
        {
            alertStrip.Visibility = Visibility.Visible;
            alertStrip.Background = BrushFrom(danger ? "#FEF2F2" : "#FFFBEB");
            alertStrip.BorderBrush = BrushFrom(danger ? "#FECACA" : "#FDE68A");
            alertText.Foreground = BrushFrom(danger ? "#7F1D1D" : "#92400E");
            alertText.Text = text;
            alertButton.Content = btnLabel;
            alertButton.SetResourceReference(StyleProperty, danger ? "SmallDangerOutlineButtonStyle" : "SmallSecondaryButtonStyle");
            alertButtonHandler = handler;
        }

        private void SetChip(NodeTone tone, string text)
        {
            statusChipText.Text = text;
            switch (tone)
            {
                case NodeTone.Ok:
                    statusChip.Background = BrushFrom("#ECFDF3");
                    statusChip.BorderBrush = BrushFrom("#BBF7D0");
                    statusChipLed.Fill = BrushFrom("#16A34A");
                    statusChipText.Foreground = BrushFrom("#15803D");
                    break;
                case NodeTone.Warn:
                    statusChip.Background = BrushFrom("#FFFBEB");
                    statusChip.BorderBrush = BrushFrom("#FDE68A");
                    statusChipLed.Fill = BrushFrom("#D97706");
                    statusChipText.Foreground = BrushFrom("#B45309");
                    break;
                case NodeTone.Danger:
                    statusChip.Background = BrushFrom("#FEF2F2");
                    statusChip.BorderBrush = BrushFrom("#FECACA");
                    statusChipLed.Fill = BrushFrom("#DC2626");
                    statusChipText.Foreground = BrushFrom("#B91C1C");
                    break;
                default:
                    statusChip.Background = BrushFrom("#F1F5F9");
                    statusChip.BorderBrush = BrushFrom("#E2E8F0");
                    statusChipLed.Fill = BrushFrom("#9CA3AF");
                    statusChipText.Foreground = BrushFrom("#4B5162");
                    break;
            }
        }

        private void SetNode(int index, NodeTone tone, string title, string sub, RailKind rail, bool dangerTitle)
        {
            SchematicColumn c = nodes[index];
            c.Title.Text = title;
            c.Title.Foreground = BrushFrom(dangerTitle ? "#B91C1C" : "#121418");
            c.Sub.Text = sub;
            c.Sub.Foreground = BrushFrom(dangerTitle ? "#B91C1C" : "#7A8194");

            switch (tone)
            {
                case NodeTone.Ok:
                    c.Halo.Background = BrushFrom("#DCFCE7");
                    c.Halo.BorderBrush = BrushFrom("#86EFAC");
                    c.Led.Fill = BrushFrom("#16A34A");
                    break;
                case NodeTone.Warn:
                    c.Halo.Background = BrushFrom("#FEF3C7");
                    c.Halo.BorderBrush = BrushFrom("#FCD34D");
                    c.Led.Fill = BrushFrom("#D97706");
                    break;
                case NodeTone.Danger:
                    c.Halo.Background = BrushFrom("#FEE2E2");
                    c.Halo.BorderBrush = BrushFrom("#FCA5A5");
                    c.Led.Fill = BrushFrom("#DC2626");
                    break;
                default:
                    c.Halo.Background = BrushFrom("#F1F5F9");
                    c.Halo.BorderBrush = BrushFrom("#CBD5E1");
                    c.Led.Fill = BrushFrom("#9CA3AF");
                    break;
            }

            if (c.RailHost == null)
                return;
            c.RailHost.Children.Clear();

            if (rail == RailKind.Ok)
            {
                var track = new Border
                {
                    Height = 2,
                    Background = BrushFrom("#22C55E"),
                    CornerRadius = new CornerRadius(1),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 2, 0)
                };
                var arrow = new Path
                {
                    Data = Geometry.Parse("M 0,0 L 4.5,4 L 0,8"),
                    Stroke = BrushFrom("#16A34A"),
                    StrokeThickness = 1.8,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round,
                    StrokeLineJoin = PenLineJoin.Round,
                    HorizontalAlignment = HorizontalAlignment.Right,
                    VerticalAlignment = VerticalAlignment.Center
                };
                c.RailHost.Children.Add(track);
                c.RailHost.Children.Add(arrow);
            }
            else if (rail == RailKind.Broken)
            {
                Line dash = CreateDashedRailLine(c.RailHost, "#DC2626");
                var badge = new Border
                {
                    Width = 18,
                    Height = 18,
                    CornerRadius = new CornerRadius(9),
                    Background = BrushFrom("#FEF2F2"),
                    BorderBrush = BrushFrom("#DC2626"),
                    BorderThickness = new Thickness(1.5),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                badge.Child = new Path
                {
                    Data = Geometry.Parse("M 0,0 L 6,6 M 6,0 L 0,6"),
                    Stroke = BrushFrom("#DC2626"),
                    StrokeThickness = 1.6,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                c.RailHost.Children.Add(dash);
                c.RailHost.Children.Add(badge);
            }
            else if (rail == RailKind.Warn)
            {
                c.RailHost.Children.Add(CreateDashedRailLine(c.RailHost, "#D97706"));
            }
            else
            {
                c.RailHost.Children.Add(CreateDashedRailLine(c.RailHost, "#CBD5E1"));
            }
        }

        private static Line CreateDashedRailLine(Grid host, string hex)
        {
            var line = new Line
            {
                X1 = 0,
                Y1 = 9,
                Y2 = 9,
                Stroke = BrushFrom(hex),
                StrokeThickness = 1.8,
                StrokeDashArray = new DoubleCollection { 2.5, 2.2 },
                VerticalAlignment = VerticalAlignment.Center
            };
            line.SetBinding(Line.X2Property, new System.Windows.Data.Binding("ActualWidth") { Source = host });
            return line;
        }

        private static ExitPolicy SafeLoadExitPolicy()
        {
            try { return ExitPolicyStore.Load(); }
            catch (Exception) { return ExitPolicy.CreateDefault(); }
        }

        private static SolidColorBrush BrushFrom(string hex)
        {
            return (SolidColorBrush)new BrushConverter().ConvertFromString(hex);
        }
    }
}
