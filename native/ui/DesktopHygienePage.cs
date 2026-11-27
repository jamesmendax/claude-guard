using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ClaudeGuardNative
{
    internal sealed class DesktopHygienePage : Grid
    {
        private readonly TextBlock titleText = new TextBlock();
        private readonly TextBlock subtitleText = new TextBlock();
        private readonly TextBlock mcpBadgeText = new TextBlock();

        private readonly TextBlock keyDataDir = new TextBlock();
        private readonly TextBlock valDataDirMain = new TextBlock();
        private readonly TextBlock valDataDirSub = new TextBlock();

        private readonly TextBlock keyMcp = new TextBlock();
        private readonly TextBlock valMcp = new TextBlock();

        private readonly TextBlock keyStartup = new TextBlock();
        private readonly TextBlock valStartup = new TextBlock();

        private readonly TextBlock keyBackup = new TextBlock();
        private readonly ComboBox backupCombo = new ComboBox();
        private readonly Button restoreBtn = new Button();

        private readonly TextBlock oauthTipTitle = new TextBlock();
        private readonly TextBlock oauthTipBody = new TextBlock();

        private readonly Button refreshBtn = new Button();
        private readonly Button startupBtn = new Button();
        private readonly Button openFolderBtn = new Button();
        private readonly Button quarantineBtn = new Button();

        private DesktopHygieneReport currentReport;

        internal event Action HygieneChanged;

        internal DesktopHygienePage()
        {
            Margin = new Thickness(24, 20, 24, 18);
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0: Header
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 1: Spec card
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 2: OAuth tip
            RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 3: Air
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 4: Dock

            BuildHeader();
            BuildSpecCard();
            BuildTipBox();
            BuildDock();

            ApplyLocalization();
            RefreshScan();
        }

        private void BuildHeader()
        {
            var header = new Grid { Margin = new Thickness(0, 0, 0, 14) };
            header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var left = new StackPanel();
            titleText.FontSize = 17.5;
            titleText.FontWeight = FontWeights.SemiBold;
            titleText.Foreground = BrushFrom("#121418");
            subtitleText.FontSize = 12.5;
            subtitleText.Foreground = BrushFrom("#7A8194");
            subtitleText.Margin = new Thickness(0, 3, 0, 0);
            subtitleText.TextWrapping = TextWrapping.Wrap;
            left.Children.Add(titleText);
            left.Children.Add(subtitleText);
            Grid.SetColumn(left, 0);
            header.Children.Add(left);

            var badge = new Border
            {
                Background = BrushFrom("#ECFDF3"),
                BorderBrush = BrushFrom("#BBF7D0"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(10, 3, 10, 3),
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(12, 2, 0, 0)
            };
            mcpBadgeText.FontSize = 11.5;
            mcpBadgeText.FontWeight = FontWeights.SemiBold;
            mcpBadgeText.Foreground = BrushFrom("#15803D");
            badge.Child = mcpBadgeText;
            Grid.SetColumn(badge, 1);
            header.Children.Add(badge);

            Grid.SetRow(header, 0);
            Children.Add(header);
        }

        private void BuildSpecCard()
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

            // Row 1: Data directories
            var r1Val = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };
            valDataDirMain.FontSize = 12.5;
            valDataDirMain.FontWeight = FontWeights.Medium;
            valDataDirMain.Foreground = BrushFrom("#121418");
            valDataDirSub.FontSize = 12;
            valDataDirSub.Foreground = BrushFrom("#7A8194");
            valDataDirSub.Margin = new Thickness(7, 0, 0, 0);
            r1Val.Children.Add(valDataDirMain);
            r1Val.Children.Add(valDataDirSub);
            stack.Children.Add(WrapRow(keyDataDir, r1Val, false));

            // Row 2: MCP config
            valMcp.FontSize = 12.5;
            valMcp.FontWeight = FontWeights.Medium;
            valMcp.HorizontalAlignment = HorizontalAlignment.Right;
            valMcp.VerticalAlignment = VerticalAlignment.Center;
            stack.Children.Add(WrapRow(keyMcp, valMcp, false));

            // Row 3: Startup check
            valStartup.FontSize = 12.5;
            valStartup.FontWeight = FontWeights.Medium;
            valStartup.HorizontalAlignment = HorizontalAlignment.Right;
            valStartup.VerticalAlignment = VerticalAlignment.Center;
            stack.Children.Add(WrapRow(keyStartup, valStartup, false));

            // Row 4: Restorable backup picker + Restore button
            var backupRight = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };
            backupCombo.SetResourceReference(StyleProperty, "CleanComboBoxStyle");
            backupCombo.Width = 220;
            backupCombo.FontFamily = new FontFamily("Cascadia Mono, Consolas, Segoe UI");
            backupCombo.Margin = new Thickness(0, 0, 8, 0);

            restoreBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            restoreBtn.Click += delegate { RestoreSelected(); };

            backupRight.Children.Add(backupCombo);
            backupRight.Children.Add(restoreBtn);
            stack.Children.Add(WrapRow(keyBackup, backupRight, true));

            card.Child = stack;
            Grid.SetRow(card, 1);
            Children.Add(card);
        }

        private static Border WrapRow(TextBlock keyBlock, UIElement rightElement, bool isLast)
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
            keyBlock.Margin = new Thickness(0, 0, 14, 0);
            Grid.SetColumn(keyBlock, 0);
            grid.Children.Add(keyBlock);

            Grid.SetColumn(rightElement, 1);
            grid.Children.Add(rightElement);

            border.Child = grid;
            return border;
        }

        private void BuildTipBox()
        {
            var box = new Border
            {
                Background = BrushFrom("#F8F9FB"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(14, 11, 14, 11)
            };
            var stack = new StackPanel();
            oauthTipTitle.FontSize = 12;
            oauthTipTitle.FontWeight = FontWeights.SemiBold;
            oauthTipTitle.Foreground = BrushFrom("#121418");
            oauthTipBody.FontSize = 12;
            oauthTipBody.Foreground = BrushFrom("#4B5162");
            oauthTipBody.TextWrapping = TextWrapping.Wrap;
            oauthTipBody.LineHeight = 18;
            oauthTipBody.Margin = new Thickness(0, 3, 0, 0);
            stack.Children.Add(oauthTipTitle);
            stack.Children.Add(oauthTipBody);
            box.Child = stack;

            Grid.SetRow(box, 2);
            Children.Add(box);
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
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var left = new StackPanel { Orientation = Orientation.Horizontal };
            refreshBtn.SetResourceReference(StyleProperty, "SecondaryButtonStyle");
            refreshBtn.Margin = new Thickness(0, 0, 8, 0);
            refreshBtn.Click += delegate { RefreshScan(); };

            startupBtn.SetResourceReference(StyleProperty, "SecondaryButtonStyle");
            startupBtn.Margin = new Thickness(0, 0, 8, 0);
            startupBtn.Click += delegate { OpenTarget("ms-settings:startupapps"); };

            openFolderBtn.SetResourceReference(StyleProperty, "SecondaryButtonStyle");
            openFolderBtn.Click += delegate { OpenBackupFolder(); };

            left.Children.Add(refreshBtn);
            left.Children.Add(startupBtn);
            left.Children.Add(openFolderBtn);
            Grid.SetColumn(left, 0);
            grid.Children.Add(left);

            quarantineBtn.SetResourceReference(StyleProperty, "PrimaryButtonStyle");
            quarantineBtn.Click += delegate { RunQuarantine(); };
            Grid.SetColumn(quarantineBtn, 2);
            grid.Children.Add(quarantineBtn);

            dock.Child = grid;
            Grid.SetRow(dock, 4);
            Children.Add(dock);
        }

        internal void ApplyLocalization()
        {
            titleText.Text = UiStrings.T("Claude Desktop hygiene & restorable quarantine", "Claude Desktop 卫生与可恢复清理");
            subtitleText.Text = UiStrings.T(
                "Archive old cache, cookies, and session logs; MCP configuration is strictly preserved with 1-click restore.",
                "归档旧缓存、Cookie 与会话日志；强制跳过并保护 MCP 配置，随时可一键还原");
            mcpBadgeText.Text = UiStrings.T("MCP config locked & safe", "MCP 配置已锁定保护");

            keyDataDir.Text = UiStrings.T("Claude Desktop data directories", "Desktop 数据目录");
            keyMcp.Text = "claude_desktop_config.json";
            keyStartup.Text = UiStrings.T("Windows auto-start check", "Windows 开机自启检查");
            keyBackup.Text = UiStrings.T("Restorable quarantine backups", "历史归档备份");

            restoreBtn.Content = UiStrings.T("Restore", "一键还原");
            oauthTipTitle.Text = UiStrings.T("Fingerprint browser OAuth login tip", "指纹浏览器登录提示");
            oauthTipBody.Text = UiStrings.T(
                "Clicking Log in inside Claude Desktop opens your Windows default browser. Copy the OAuth URL into your fingerprint browser to authorize cleanly, then allow the callback back to Claude Desktop.",
                "桌面端点击 Log in 会默认唤起系统浏览器。如需在指纹浏览器中完成授权，可复制登录链接贴入指纹浏览器后再回调回桌面端。");

            refreshBtn.Content = UiStrings.T("Rescan", "刷新扫描");
            startupBtn.Content = UiStrings.T("Startup settings", "开机自启设置");
            openFolderBtn.Content = UiStrings.T("Backup folder", "打开备份目录");
            quarantineBtn.Content = UiStrings.T("Quarantine cache (keep MCP)", "归档清理（保留 MCP）");

            RenderReport();
        }

        internal void RefreshScan()
        {
            try
            {
                currentReport = DesktopHygiene.Scan();
                RenderReport();
            }
            catch (Exception error)
            {
                currentReport = null;
                valDataDirMain.Text = error.Message;
                valDataDirMain.Foreground = BrushFrom("#B91C1C");
                valDataDirSub.Text = "";
                quarantineBtn.IsEnabled = false;
                restoreBtn.IsEnabled = false;
            }
        }

        private void RenderReport()
        {
            if (currentReport == null)
                return;

            int existingDirs = 0;
            int cleanableCount = 0;
            bool anyMcp = false;
            string dirKinds = "";
            foreach (DesktopDataLocation loc in currentReport.Locations)
            {
                if (loc.Exists)
                {
                    existingDirs++;
                    if (dirKinds.Length > 0) dirKinds += " + ";
                    dirKinds += loc.Kind;
                    cleanableCount += loc.CleanableItems.Length;
                    if (loc.HasMcpConfig) anyMcp = true;
                }
            }

            if (existingDirs == 0)
            {
                valDataDirMain.Text = UiStrings.T("Not detected", "未检测到安装目录");
                valDataDirMain.Foreground = BrushFrom("#7A8194");
                valDataDirSub.Text = UiStrings.T("(Classic & Store MSIX checked)", "(已扫描 Classic 与 Store MSIX)");
            }
            else if (cleanableCount == 0)
            {
                valDataDirMain.Text = UiStrings.T("Clean (0 items)", "已洁净（0 项残留）");
                valDataDirMain.Foreground = BrushFrom("#15803D");
                valDataDirSub.Text = "(" + dirKinds + ")";
            }
            else
            {
                valDataDirMain.Text = UiStrings.T(cleanableCount + " cleanable items", cleanableCount + " 项可清理");
                valDataDirMain.Foreground = BrushFrom("#121418");
                valDataDirSub.Text = "(" + DesktopHygiene.FormatBytes(currentReport.TotalCleanableBytes) + " · " + dirKinds + ")";
            }

            if (anyMcp)
            {
                valMcp.Text = UiStrings.T("Detected · strictly preserved", "已检测到 · 强制保留不移动");
                valMcp.Foreground = BrushFrom("#15803D");
            }
            else
            {
                valMcp.Text = UiStrings.T("Not present (always protected if created)", "未检测到（始终强制跳过保护）");
                valMcp.Foreground = BrushFrom("#7A8194");
            }

            if (currentReport.HasAutoStartEnabled)
            {
                valStartup.Text = UiStrings.T("Active — recommend disabling in Startup apps", "已启用开机自启 · 建议立即关闭");
                valStartup.Foreground = BrushFrom("#B45309");
            }
            else
            {
                valStartup.Text = UiStrings.T("Disabled (won't race ahead of TUN)", "未启用（不会在 Bettbox 前抢跑）");
                valStartup.Foreground = BrushFrom("#15803D");
            }

            backupCombo.Items.Clear();
            foreach (string backupPath in currentReport.Backups)
                backupCombo.Items.Add(new BackupDisplayItem(backupPath));

            if (backupCombo.Items.Count > 0)
            {
                backupCombo.FontFamily = new FontFamily("Cascadia Mono, Consolas, Segoe UI");
                backupCombo.SelectedIndex = 0;
                backupCombo.IsEnabled = true;
                restoreBtn.IsEnabled = true;
            }
            else
            {
                backupCombo.FontFamily = new FontFamily("Segoe UI, Microsoft YaHei UI");
                backupCombo.Items.Add(UiStrings.T("No backups yet", "暂无归档备份"));
                backupCombo.SelectedIndex = 0;
                backupCombo.IsEnabled = false;
                restoreBtn.IsEnabled = false;
            }

            quarantineBtn.IsEnabled = cleanableCount > 0;
        }

        private void RunQuarantine()
        {
            if (currentReport == null)
                return;

            MessageBoxResult confirm = MessageBox.Show(
                UiStrings.T(
                    "Move Claude Desktop cache, cookies, sessions, and logs into a restorable quarantine backup?\n\n" +
                    "- Make sure Claude Desktop is fully closed first.\n" +
                    "- claude_desktop_config.json (MCP settings) will NOT be touched.",
                    "确定将 Claude Desktop 的缓存、Cookie、会话与日志移入可还原的备份区？\n\n" +
                    "- 请先确保 Claude Desktop 已完全关闭。\n" +
                    "- claude_desktop_config.json（MCP 配置）将强制保留，不会被修改或移动。"),
                "Claude Guard",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes)
                return;

            try
            {
                Process[] running = Process.GetProcessesByName("Claude");
                try
                {
                    if (running.Length > 0)
                    {
                        MessageBox.Show(
                            UiStrings.T(
                                "Claude Desktop appears to be running. Stop Claude Desktop first before quarantining data.",
                                "检测到 Claude 进程仍在运行，请先关闭 Claude Desktop（或在总览页点击「停止 Claude」）后再清理。"),
                            "Claude Guard",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);
                        return;
                    }
                }
                finally
                {
                    foreach (Process p in running) p.Dispose();
                }

                QuarantineResult result = DesktopHygiene.Quarantine(currentReport);
                MessageBox.Show(result.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Information);
                RefreshScan();
                if (HygieneChanged != null) HygieneChanged();
            }
            catch (QuarantineInterruptedException error)
            {
                bool hasBackup = !String.IsNullOrEmpty(error.BackupDirectory);
                string message = hasBackup
                    ? UiStrings.T("Quarantine stopped. Items already saved are available in the restore list.",
                        "隔离已停止。已保存的项目仍可从恢复列表找回。")
                    : UiStrings.T("Quarantine stopped before any items were saved.", "隔离已停止，尚未保存任何项目。");
                RefreshScan();
                if (hasBackup && HygieneChanged != null) HygieneChanged();
                MessageBox.Show(message + "\n\n" + error.InnerException.Message,
                    "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
                RefreshScan();
            }
        }

        private void RestoreSelected()
        {
            var item = backupCombo.SelectedItem as BackupDisplayItem;
            if (item == null)
                return;

            MessageBoxResult confirm = MessageBox.Show(
                UiStrings.T(
                    "Restore quarantined Claude Desktop items from this backup?\n" + item.FullPath + "\n\nClose Claude Desktop first. Restore stops if an item already exists.",
                    "确定从以下备份还原 Claude Desktop 缓存与会话？\n" + item.FullPath + "\n\n请先关闭 Claude Desktop。若目标位置已有同名文件或文件夹，还原会停止。"),
                "Claude Guard",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes)
                return;

            try
            {
                int count = DesktopHygiene.Restore(item.FullPath);
                MessageBox.Show(
                    UiStrings.T("Restored " + count + " item(s) cleanly.", "已成功还原 " + count + " 个文件/目录。"),
                    "Claude Guard",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                RefreshScan();
                if (HygieneChanged != null) HygieneChanged();
            }
            catch (RestoreConflictException error)
            {
                MessageBox.Show(
                    UiStrings.T(
                        error.Message + "\n\nMove the existing item to a safe location before retrying.",
                        "目标位置已有同名文件或文件夹，还原已停止。\n" + error.DestinationPath +
                        "\n本次已还原 " + error.RestoredCount + " 项。其余内容仍保存在备份中。" +
                        "\n\n请将现有项目移到安全的位置，再试一次。"),
                    "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
                RefreshScan();
                if (error.RestoredCount > 0 && HygieneChanged != null) HygieneChanged();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
                RefreshScan();
            }
        }

        private static void OpenBackupFolder()
        {
            string root = DesktopHygiene.DefaultQuarantineRoot;
            try
            {
                Directory.CreateDirectory(root);
                OpenTarget(root);
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private static void OpenTarget(string target)
        {
            try
            {
                using (Process p = Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }))
                {
                }
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private sealed class BackupDisplayItem
        {
            internal readonly string FullPath;
            private readonly string displayName;

            internal BackupDisplayItem(string fullPath)
            {
                FullPath = fullPath;
                displayName = Path.GetFileName(fullPath);
            }

            public override string ToString()
            {
                return displayName;
            }
        }

        private static SolidColorBrush BrushFrom(string hex)
        {
            return (SolidColorBrush)new BrushConverter().ConvertFromString(hex);
        }
    }
}
