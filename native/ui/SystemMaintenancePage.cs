using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ClaudeGuardNative
{
    internal sealed class SystemMaintenancePage : Grid
    {
        private sealed class ZoneChoice
        {
            internal readonly string Id;
            private readonly string label;

            internal ZoneChoice(string id, string label)
            {
                Id = id;
                this.label = label;
            }

            public override string ToString()
            {
                return label;
            }
        }

        private readonly TextBlock titleText = new TextBlock();
        private readonly TextBlock subtitleText = new TextBlock();

        private readonly TextBlock fwTitle = new TextBlock();
        private readonly TextBlock fwSub = new TextBlock();
        private readonly Button fwRefreshBtn = new Button();
        private readonly Button fwRemoveBtn = new Button();

        private readonly TextBlock shortcutTitle = new TextBlock();
        private readonly TextBlock shortcutSub = new TextBlock();
        private readonly Button shortcutBtn = new Button();

        private readonly TextBlock taskTitle = new TextBlock();
        private readonly TextBlock taskSub = new TextBlock();
        private readonly Button taskInstallBtn = new Button();
        private readonly Button taskDisableBtn = new Button();

        private readonly TextBlock netTitle = new TextBlock();
        private readonly TextBlock netSub = new TextBlock();
        private readonly ComboBox zoneCombo = new ComboBox();
        private readonly Button regionBtn = new Button();
        private readonly Button dnsBtn = new Button();

        private readonly TextBlock diagTitle = new TextBlock();
        private readonly TextBlock diagSub = new TextBlock();
        private readonly Button verifyPkgBtn = new Button();
        private readonly Button openLogsBtn = new Button();
        private readonly Button exportDiagBtn = new Button();

        private readonly TextBlock footerMeta = new TextBlock();
        private readonly Button uninstallBtn = new Button();
        private readonly Button limitationsBtn = new Button();

        private bool suppressZoneEvent;
        private string selectedZoneId;
        private GuardResult lastResult;

        internal event Action RefreshFirewallRequested;
        internal event Action RemoveFirewallRulesRequested;
        internal event Action CreateShortcutRequested;
        internal event Action InstallRefreshTaskRequested;
        internal event Action DisableRefreshTaskRequested;
        internal event Action<string> SessionTimeZoneChanged;
        internal event Action OpenRegionalRequested;
        internal event Action OpenDnsRequested;
        internal event Action VerifyPackageRequested;
        internal event Action OpenLogsFolderRequested;
        internal event Action ExportDiagnosticsRequested;
        internal event Action UninstallRequested;
        internal event Action ShowLimitationsRequested;

        internal SystemMaintenancePage()
        {
            Margin = new Thickness(24, 20, 24, 18);
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0: Header
            RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 1: Spec Card
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 2: Dock

            BuildHeader();
            BuildMaintenanceCard();
            BuildDock();

            PopulateTimeZones();
            ApplyLocalization();
        }

        private void BuildHeader()
        {
            var stack = new StackPanel { Margin = new Thickness(0, 0, 0, 14) };
            titleText.FontSize = 17.5;
            titleText.FontWeight = FontWeights.SemiBold;
            titleText.Foreground = BrushFrom("#121418");
            subtitleText.FontSize = 12.5;
            subtitleText.Foreground = BrushFrom("#7A8194");
            subtitleText.Margin = new Thickness(0, 3, 0, 0);
            stack.Children.Add(titleText);
            stack.Children.Add(subtitleText);
            Grid.SetRow(stack, 0);
            Children.Add(stack);
        }

        private void BuildMaintenanceCard()
        {
            var card = new Border
            {
                Background = BrushFrom("#FFFFFF"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                VerticalAlignment = VerticalAlignment.Top
            };

            var stack = new StackPanel();

            // Row 1: Firewall rules
            var fwBtns = new StackPanel { Orientation = Orientation.Horizontal };
            fwRefreshBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            fwRefreshBtn.Margin = new Thickness(0, 0, 8, 0);
            fwRefreshBtn.Click += delegate { if (RefreshFirewallRequested != null) RefreshFirewallRequested(); };
            fwRemoveBtn.SetResourceReference(StyleProperty, "SmallDangerOutlineButtonStyle");
            fwRemoveBtn.Click += delegate { if (RemoveFirewallRulesRequested != null) RemoveFirewallRulesRequested(); };
            fwBtns.Children.Add(fwRefreshBtn);
            fwBtns.Children.Add(fwRemoveBtn);
            stack.Children.Add(BuildActionRow(fwTitle, fwSub, fwBtns, false));

            // Row 2: Guarded Desktop shortcut
            shortcutBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            shortcutBtn.Click += delegate { if (CreateShortcutRequested != null) CreateShortcutRequested(); };
            stack.Children.Add(BuildActionRow(shortcutTitle, shortcutSub, shortcutBtn, false));

            // Row 3: Scheduled refresh task
            var taskBtns = new StackPanel { Orientation = Orientation.Horizontal };
            taskInstallBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            taskInstallBtn.Margin = new Thickness(0, 0, 8, 0);
            taskInstallBtn.Click += delegate { if (InstallRefreshTaskRequested != null) InstallRefreshTaskRequested(); };
            taskDisableBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            taskDisableBtn.Click += delegate { if (DisableRefreshTaskRequested != null) DisableRefreshTaskRequested(); };
            taskBtns.Children.Add(taskInstallBtn);
            taskBtns.Children.Add(taskDisableBtn);
            stack.Children.Add(BuildActionRow(taskTitle, taskSub, taskBtns, false));

            // Row 4: Session timezone + Region + Encrypted DNS
            var netControls = new StackPanel { Orientation = Orientation.Horizontal };
            zoneCombo.SetResourceReference(StyleProperty, "CleanComboBoxStyle");
            zoneCombo.Width = 152;
            zoneCombo.Margin = new Thickness(0, 0, 8, 0);
            zoneCombo.SelectionChanged += delegate
            {
                if (suppressZoneEvent)
                    return;
                var choice = zoneCombo.SelectedItem as ZoneChoice;
                selectedZoneId = choice == null ? null : choice.Id;
                if (SessionTimeZoneChanged != null)
                    SessionTimeZoneChanged(selectedZoneId);
            };
            regionBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            regionBtn.Margin = new Thickness(0, 0, 8, 0);
            regionBtn.Click += delegate { if (OpenRegionalRequested != null) OpenRegionalRequested(); };
            dnsBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            dnsBtn.Click += delegate { if (OpenDnsRequested != null) OpenDnsRequested(); };
            netControls.Children.Add(zoneCombo);
            netControls.Children.Add(regionBtn);
            netControls.Children.Add(dnsBtn);
            stack.Children.Add(BuildActionRow(netTitle, netSub, netControls, false));

            // Row 5: Diagnostics & Package verification
            var diagBtns = new StackPanel { Orientation = Orientation.Horizontal };
            verifyPkgBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            verifyPkgBtn.Margin = new Thickness(0, 0, 8, 0);
            verifyPkgBtn.Click += delegate { if (VerifyPackageRequested != null) VerifyPackageRequested(); };
            openLogsBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            openLogsBtn.Margin = new Thickness(0, 0, 8, 0);
            openLogsBtn.Click += delegate { if (OpenLogsFolderRequested != null) OpenLogsFolderRequested(); };
            exportDiagBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            exportDiagBtn.Click += delegate { if (ExportDiagnosticsRequested != null) ExportDiagnosticsRequested(); };
            diagBtns.Children.Add(verifyPkgBtn);
            diagBtns.Children.Add(openLogsBtn);
            diagBtns.Children.Add(exportDiagBtn);
            stack.Children.Add(BuildActionRow(diagTitle, diagSub, diagBtns, true));

            card.Child = stack;

            var scroller = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Content = card
            };
            Grid.SetRow(scroller, 1);
            Children.Add(scroller);
        }

        private static Border BuildActionRow(TextBlock title, TextBlock sub, UIElement rightActions, bool isLast)
        {
            var border = new Border
            {
                Padding = new Thickness(16, 10, 16, 10),
                BorderBrush = BrushFrom("#EFF1F4"),
                BorderThickness = isLast ? new Thickness(0) : new Thickness(0, 0, 0, 1)
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var left = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 14, 0) };
            title.FontSize = 12.5;
            title.FontWeight = FontWeights.Medium;
            title.Foreground = BrushFrom("#121418");
            sub.FontSize = 11.5;
            sub.Foreground = BrushFrom("#7A8194");
            sub.Margin = new Thickness(0, 2, 0, 0);
            sub.TextTrimming = TextTrimming.CharacterEllipsis;
            left.Children.Add(title);
            left.Children.Add(sub);
            Grid.SetColumn(left, 0);
            grid.Children.Add(left);

            var wrap = new ContentPresenter { Content = rightActions, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetColumn(wrap, 1);
            grid.Children.Add(wrap);

            border.Child = grid;
            return border;
        }

        private void BuildDock()
        {
            var dock = new Border
            {
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(0, 12, 0, 0)
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            footerMeta.FontSize = 11.5;
            footerMeta.Foreground = BrushFrom("#7A8194");
            footerMeta.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(footerMeta, 0);
            grid.Children.Add(footerMeta);

            var right = new StackPanel { Orientation = Orientation.Horizontal };
            uninstallBtn.SetResourceReference(StyleProperty, "GhostButtonStyle");
            uninstallBtn.Margin = new Thickness(0, 0, 6, 0);
            uninstallBtn.Click += delegate { if (UninstallRequested != null) UninstallRequested(); };

            limitationsBtn.SetResourceReference(StyleProperty, "SecondaryButtonStyle");
            limitationsBtn.Click += delegate { if (ShowLimitationsRequested != null) ShowLimitationsRequested(); };

            right.Children.Add(uninstallBtn);
            right.Children.Add(limitationsBtn);
            Grid.SetColumn(right, 1);
            grid.Children.Add(right);

            dock.Child = grid;
            Grid.SetRow(dock, 2);
            Children.Add(dock);
        }

        private void PopulateTimeZones()
        {
            suppressZoneEvent = true;
            zoneCombo.Items.Clear();
            zoneCombo.Items.Add(new ZoneChoice(null, UiStrings.T("Keep current TZ", "时区保持当前")));
            int selectedIdx = 0;
            foreach (TimeZoneInfo tz in TimeZoneInfo.GetSystemTimeZones())
            {
                int idx = zoneCombo.Items.Add(new ZoneChoice(tz.Id, tz.DisplayName));
                if (tz.Id == selectedZoneId)
                    selectedIdx = idx;
            }
            zoneCombo.SelectedIndex = selectedIdx;
            suppressZoneEvent = false;
        }

        internal void SetBusy(bool busy)
        {
            fwRefreshBtn.IsEnabled = !busy;
            fwRemoveBtn.IsEnabled = !busy;
            shortcutBtn.IsEnabled = !busy;
            taskInstallBtn.IsEnabled = !busy;
            taskDisableBtn.IsEnabled = !busy;
            zoneCombo.IsEnabled = !busy;
            uninstallBtn.IsEnabled = !busy;
        }

        internal void UpdateStatus(GuardResult result)
        {
            lastResult = result;
            RefreshDynamicSubtitles();
        }

        internal void ApplyLocalization()
        {
            titleText.Text = UiStrings.T("System firewall & daily maintenance", "系统防火墙与日常维护");
            subtitleText.Text = UiStrings.T(
                "Manage Windows Firewall rules, guarded desktop shortcut, scheduled refresh, and sanitized diagnostics.",
                "集中管理 Windows 防火墙锁定规则、受守卫快捷方式、计划任务与脱敏诊断报告");

            fwTitle.Text = UiStrings.T("Windows Firewall outbound lock", "Windows 防火墙出站锁定");
            fwRefreshBtn.Content = UiStrings.T("Apply / Refresh", "配置 / 刷新");
            fwRemoveBtn.Content = UiStrings.T("Remove rules", "卸载规则");

            shortcutTitle.Text = UiStrings.T("Guarded Desktop shortcut", "受守卫桌面快捷方式");
            shortcutSub.Text = UiStrings.T(
                "Create 'Claude (Native Guard).lnk' to verify route & exit before opening Desktop.",
                "创建「Claude (Native Guard).lnk」，双击自动先核验再启动 Claude Desktop");
            shortcutBtn.Content = UiStrings.T("Create shortcut", "创建桌面快捷方式");

            taskTitle.Text = UiStrings.T("Scheduled background refresh", "后台计划任务自动刷新");
            taskInstallBtn.Content = UiStrings.T("Install & enable", "安装并启用");
            taskDisableBtn.Content = UiStrings.T("Disable task", "关闭任务");

            netTitle.Text = UiStrings.T("Session time zone & system network", "会话临时时区与系统网络");
            netSub.Text = UiStrings.T(
                "Optional temporary session time zone, Windows region/language, and Encrypted DNS (DoH).",
                "可选会话期临时时区（退出自动恢复），及 Windows 区域语言 / 加密 DNS");
            regionBtn.Content = UiStrings.T("Region", "区域语言");
            dnsBtn.Content = UiStrings.T("DoH DNS", "加密 DNS");

            diagTitle.Text = UiStrings.T("Package verification & sanitized report", "安装包校验与脱敏诊断报告");
            diagSub.Text = UiStrings.T(
                "Verify SHA-256 checksums, inspect local event logs, or export an IPv4-masked report.",
                "校验安装包 SHA-256，或导出已隐藏完整 IPv4 的环境与策略诊断快照");
            verifyPkgBtn.Content = UiStrings.T("Verify SHA-256", "校验安装包");
            openLogsBtn.Content = UiStrings.T("Logs folder", "日志目录");
            exportDiagBtn.Content = UiStrings.T("Export report", "导出诊断报告");

            footerMeta.Text = UiStrings.T(
                "Claude Guard Native " + GuardEngine.VersionText + " · Zero-SDK Windows Inbox WPF",
                "Claude Guard Native " + GuardEngine.VersionText + " · 零外部运行库依赖 (Windows Inbox WPF)");
            uninstallBtn.Content = UiStrings.T("Uninstall...", "卸载程序");
            limitationsBtn.Content = UiStrings.T("Known scope & limits", "查看安全边界说明");

            PopulateTimeZones();
            RefreshDynamicSubtitles();
        }

        private void RefreshDynamicSubtitles()
        {
            if (lastResult == null)
            {
                fwSub.Text = UiStrings.T("Blocks non-VPN adapters and public IPv6 for signed Claude binaries.", "为官方签名 Claude 程序封锁非 VPN 网卡 IPv4 及全部公网 IPv6");
                taskSub.Text = UiStrings.T("Syncs newly connected adapters every 5 minutes in background.", "开机及网络变更时自动同步新网卡封锁列表");
                return;
            }

            if (String.Equals(lastResult.Firewall, "Effective blocks verified", StringComparison.OrdinalIgnoreCase))
            {
                fwSub.Text = UiStrings.T(
                    "Active · covering " + lastResult.BlockedAdapterCount + " non-VPN adapters + IPv6 (" + lastResult.ProtectedTargetCount + " targets).",
                    "已生效 · 覆盖 " + lastResult.BlockedAdapterCount + " 个非 VPN 网卡 IPv4 及全部公网 IPv6（" + lastResult.ProtectedTargetCount + " 个目标）");
            }
            else
            {
                fwSub.Text = UiStrings.TranslateStatus(lastResult.Firewall);
            }

            string taskStatus = UiStrings.TranslateStatus(lastResult.RefreshTaskState);
            taskSub.Text = UiStrings.T(
                "Syncs adapter blocklists automatically in background (Current: " + taskStatus + ").",
                "开机及网络变更时自动同步新网卡封锁列表（当前：" + taskStatus + "）");
        }

        private static SolidColorBrush BrushFrom(string hex)
        {
            return (SolidColorBrush)new BrushConverter().ConvertFromString(hex);
        }
    }
}
