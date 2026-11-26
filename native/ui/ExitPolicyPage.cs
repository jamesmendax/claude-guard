using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace ClaudeGuardNative
{
    internal sealed class ExitPolicyPage : Grid
    {
        private readonly TextBlock titleText = new TextBlock();
        private readonly TextBlock subtitleText = new TextBlock();
        private readonly CheckBox enabledToggle = new CheckBox();

        private readonly TextBlock hostLabel = new TextBlock();
        private readonly TextBox hostBox = new TextBox();

        private readonly TextBlock countriesLabel = new TextBlock();
        private readonly TextBox countriesBox = new TextBox();

        private readonly TextBlock ipv4Label = new TextBlock();
        private readonly TextBox ipv4Box = new TextBox();
        private readonly TextBlock ipv4CountBadge = new TextBlock();

        private readonly TextBlock timingLabel = new TextBlock();
        private readonly TextBlock intervalPrefix = new TextBlock();
        private readonly TextBox intervalBox = new TextBox();
        private readonly TextBlock intervalHint = new TextBlock();

        private readonly TextBlock tolerancePrefix = new TextBlock();
        private readonly TextBox toleranceBox = new TextBox();
        private readonly TextBlock toleranceHint = new TextBlock();

        private readonly Ellipse probeLed = new Ellipse();
        private readonly TextBlock probeTitle = new TextBlock();
        private readonly TextBlock probeDetail = new TextBlock();
        private readonly Button addIpBtn = new Button();
        private readonly Button testBtn = new Button();

        private readonly CheckBox showFullIpToggle = new CheckBox();
        private readonly Button resetBtn = new Button();
        private readonly Button saveBtn = new Button();

        private string rawIpv4Input = "";
        private bool ipv4FieldFocused;
        private bool suppressEvents;
        private bool testing;
        private ExitProbeResult lastProbe;

        internal event Action PolicySaved;
        internal event Action<bool> ShowFullIpChanged;

        internal bool ShowFullIp
        {
            get { return showFullIpToggle.IsChecked == true; }
            set
            {
                suppressEvents = true;
                showFullIpToggle.IsChecked = value;
                suppressEvents = false;
                SyncIpv4Display();
                RenderProbeBox();
            }
        }

        internal ExitPolicyPage()
        {
            Margin = new Thickness(24, 20, 24, 18);
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0: Header
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 1: Form card
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 2: Live probe box
            RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 3: Air
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 4: Dock

            BuildHeader();
            BuildFormCard();
            BuildProbeCard();
            BuildDock();

            LoadCurrentPolicy();
            ApplyLocalization();
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

            enabledToggle.SetResourceReference(StyleProperty, "HardwareToggleStyle");
            enabledToggle.FontWeight = FontWeights.SemiBold;
            enabledToggle.Foreground = BrushFrom("#121418");
            enabledToggle.VerticalAlignment = VerticalAlignment.Top;
            enabledToggle.Margin = new Thickness(12, 4, 0, 0);
            enabledToggle.Checked += delegate { UpdateEnableLabel(); };
            enabledToggle.Unchecked += delegate { UpdateEnableLabel(); };
            Grid.SetColumn(enabledToggle, 1);
            header.Children.Add(enabledToggle);

            Grid.SetRow(header, 0);
            Children.Add(header);
        }

        private void BuildFormCard()
        {
            var card = new Border
            {
                Background = BrushFrom("#FFFFFF"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(16, 14, 16, 14),
                Margin = new Thickness(0, 0, 0, 14)
            };

            var mono = new FontFamily("Cascadia Mono, Consolas, Segoe UI");
            var stack = new StackPanel();

            hostBox.SetResourceReference(StyleProperty, "CleanTextBoxStyle");
            hostBox.FontFamily = mono;
            stack.Children.Add(BuildFieldRow(hostLabel, hostBox, 11));

            countriesBox.SetResourceReference(StyleProperty, "CleanTextBoxStyle");
            countriesBox.FontFamily = mono;
            stack.Children.Add(BuildFieldRow(countriesLabel, countriesBox, 11));

            // IPv4 row with live lock count badge overlaid neatly on the right
            var ipv4Wrap = new Grid();
            ipv4Box.SetResourceReference(StyleProperty, "CleanTextBoxStyle");
            ipv4Box.FontFamily = mono;
            ipv4Box.Padding = new Thickness(9, 0, 108, 0);
            ipv4Box.GotKeyboardFocus += delegate
            {
                ipv4FieldFocused = true;
                suppressEvents = true;
                ipv4Box.Text = rawIpv4Input;
                suppressEvents = false;
            };
            ipv4Box.LostKeyboardFocus += delegate
            {
                ipv4FieldFocused = false;
                rawIpv4Input = ipv4Box.Text;
                SyncIpv4Display();
            };
            ipv4Box.TextChanged += delegate
            {
                if (!suppressEvents && (ipv4FieldFocused || ShowFullIp))
                {
                    rawIpv4Input = ipv4Box.Text;
                    UpdateIpv4CountBadge();
                }
            };
            ipv4CountBadge.FontSize = 11.5;
            ipv4CountBadge.Foreground = BrushFrom("#7A8194");
            ipv4CountBadge.HorizontalAlignment = HorizontalAlignment.Right;
            ipv4CountBadge.VerticalAlignment = VerticalAlignment.Center;
            ipv4CountBadge.Margin = new Thickness(0, 0, 10, 0);
            ipv4CountBadge.IsHitTestVisible = false;
            ipv4Wrap.Children.Add(ipv4Box);
            ipv4Wrap.Children.Add(ipv4CountBadge);
            stack.Children.Add(BuildFieldRow(ipv4Label, ipv4Wrap, 11));

            // Split timing & retry tolerance row
            var split = new Grid();
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var leftCell = BuildInlineMetricInput(intervalPrefix, intervalBox, intervalHint);
            Grid.SetColumn(leftCell, 0);
            split.Children.Add(leftCell);

            var rightCell = BuildInlineMetricInput(tolerancePrefix, toleranceBox, toleranceHint);
            Grid.SetColumn(rightCell, 2);
            split.Children.Add(rightCell);

            stack.Children.Add(BuildFieldRow(timingLabel, split, 0));

            card.Child = stack;
            Grid.SetRow(card, 1);
            Children.Add(card);
        }

        private static Grid BuildFieldRow(TextBlock label, UIElement input, double bottomMargin)
        {
            var grid = new Grid { Margin = new Thickness(0, 0, 0, bottomMargin) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(154) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            label.FontSize = 12.5;
            label.Foreground = BrushFrom("#4B5162");
            label.VerticalAlignment = VerticalAlignment.Center;
            label.Margin = new Thickness(0, 0, 10, 0);
            Grid.SetColumn(label, 0);
            grid.Children.Add(label);

            Grid.SetColumn(input, 1);
            grid.Children.Add(input);
            return grid;
        }

        private static Border BuildInlineMetricInput(TextBlock prefix, TextBox box, TextBlock hint)
        {
            var border = new Border
            {
                Height = 32,
                Background = BrushFrom("#FFFFFF"),
                BorderBrush = BrushFrom("#CFD3DC"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(9, 0, 9, 0)
            };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(46) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            prefix.FontSize = 12;
            prefix.Foreground = BrushFrom("#4B5162");
            prefix.VerticalAlignment = VerticalAlignment.Center;
            prefix.Margin = new Thickness(0, 0, 6, 0);
            Grid.SetColumn(prefix, 0);
            grid.Children.Add(prefix);

            box.BorderThickness = new Thickness(0);
            box.Background = Brushes.Transparent;
            box.FontSize = 12.5;
            box.FontFamily = new FontFamily("Cascadia Mono, Consolas, Segoe UI");
            box.FontWeight = FontWeights.SemiBold;
            box.Foreground = BrushFrom("#121418");
            box.VerticalContentAlignment = VerticalAlignment.Center;
            Grid.SetColumn(box, 1);
            grid.Children.Add(box);

            hint.FontSize = 11.5;
            hint.Foreground = BrushFrom("#7A8194");
            hint.HorizontalAlignment = HorizontalAlignment.Right;
            hint.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(hint, 2);
            grid.Children.Add(hint);

            border.Child = grid;
            return border;
        }

        private void BuildProbeCard()
        {
            var box = new Border
            {
                Background = BrushFrom("#F8F9FB"),
                BorderBrush = BrushFrom("#E2E4E9"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(14, 11, 14, 11)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var left = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var head = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            probeLed.Width = 7;
            probeLed.Height = 7;
            probeLed.Margin = new Thickness(0, 0, 7, 0);
            probeLed.VerticalAlignment = VerticalAlignment.Center;
            probeTitle.FontSize = 12.5;
            probeTitle.FontWeight = FontWeights.SemiBold;
            probeTitle.VerticalAlignment = VerticalAlignment.Center;
            head.Children.Add(probeLed);
            head.Children.Add(probeTitle);

            probeDetail.FontSize = 11.5;
            probeDetail.Foreground = BrushFrom("#7A8194");
            probeDetail.Margin = new Thickness(0, 3, 12, 0);
            probeDetail.TextWrapping = TextWrapping.Wrap;

            left.Children.Add(head);
            left.Children.Add(probeDetail);
            Grid.SetColumn(left, 0);
            grid.Children.Add(left);

            var btns = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            addIpBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            addIpBtn.Margin = new Thickness(0, 0, 8, 0);
            addIpBtn.IsEnabled = false;
            addIpBtn.Click += delegate { AddObservedIp(); };

            testBtn.SetResourceReference(StyleProperty, "SmallSecondaryButtonStyle");
            testBtn.Click += delegate { RunLiveProbe(); };

            btns.Children.Add(addIpBtn);
            btns.Children.Add(testBtn);
            Grid.SetColumn(btns, 1);
            grid.Children.Add(btns);

            box.Child = grid;
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

            showFullIpToggle.SetResourceReference(StyleProperty, "HardwareToggleStyle");
            showFullIpToggle.VerticalAlignment = VerticalAlignment.Center;
            showFullIpToggle.Checked += delegate
            {
                if (!suppressEvents)
                {
                    SyncIpv4Display();
                    RenderProbeBox();
                    if (ShowFullIpChanged != null) ShowFullIpChanged(true);
                }
            };
            showFullIpToggle.Unchecked += delegate
            {
                if (!suppressEvents)
                {
                    SyncIpv4Display();
                    RenderProbeBox();
                    if (ShowFullIpChanged != null) ShowFullIpChanged(false);
                }
            };
            Grid.SetColumn(showFullIpToggle, 0);
            grid.Children.Add(showFullIpToggle);

            var right = new StackPanel { Orientation = Orientation.Horizontal };
            resetBtn.SetResourceReference(StyleProperty, "SecondaryButtonStyle");
            resetBtn.Margin = new Thickness(0, 0, 8, 0);
            resetBtn.Click += delegate { ResetToDefaults(); };

            saveBtn.SetResourceReference(StyleProperty, "PrimaryButtonStyle");
            saveBtn.Click += delegate { SavePolicy(); };

            right.Children.Add(resetBtn);
            right.Children.Add(saveBtn);
            Grid.SetColumn(right, 2);
            grid.Children.Add(right);

            dock.Child = grid;
            Grid.SetRow(dock, 4);
            Children.Add(dock);
        }

        internal void ApplyLocalization()
        {
            titleText.Text = UiStrings.T("Public exit verification policy", "公网出口核验策略");
            subtitleText.Text = UiStrings.T(
                "Direct IPv4 TLS probe to claude.ai (bypasses system proxy) to detect TUN split-routing drift.",
                "直连 IPv4 TLS 探测 claude.ai，防止 Bettbox 内部分流漂移或误切节点");
            UpdateEnableLabel();

            hostLabel.Text = UiStrings.T("Probe target host", "探测目标域名");
            countriesLabel.Text = UiStrings.T("Allowed countries (ISO)", "允许国家码 (ISO)");
            ipv4Label.Text = UiStrings.T("Dedicated IPv4 allowlist", "独享 VPS IPv4 白名单");
            timingLabel.Text = UiStrings.T("Recheck & jitter tolerance", "复核与弱网容忍");

            intervalPrefix.Text = UiStrings.T("Every", "间隔");
            intervalHint.Text = UiStrings.T("sec (15-300)", "秒 · 15-300");
            tolerancePrefix.Text = UiStrings.T("Retry", "丢包重试");
            toleranceHint.Text = UiStrings.T("0x on mismatch", "次 · 越界 0 容忍");

            addIpBtn.Content = UiStrings.T("Add current IPv4", "加入当前 IPv4");
            testBtn.Content = UiStrings.T("Probe now", "立即探测");
            showFullIpToggle.Content = UiStrings.T("Show full IPv4", "显示完整 IPv4");
            resetBtn.Content = UiStrings.T("Reset defaults", "恢复默认");
            saveBtn.Content = UiStrings.T("Save policy", "保存策略");

            UpdateIpv4CountBadge();
            RenderProbeBox();
        }

        private void UpdateEnableLabel()
        {
            enabledToggle.Content = enabledToggle.IsChecked == true
                ? UiStrings.T("Enabled", "已启用")
                : UiStrings.T("Disabled", "未启用");
        }

        internal void LoadCurrentPolicy()
        {
            try
            {
                ExitPolicy policy = ExitPolicyStore.Load();
                suppressEvents = true;
                enabledToggle.IsChecked = policy.Enabled;
                hostBox.Text = policy.TargetHost;
                countriesBox.Text = String.Join(", ", policy.AllowedCountries);
                rawIpv4Input = String.Join(", ", policy.AllowedIpv4s);
                intervalBox.Text = policy.MonitorIntervalSeconds.ToString();
                toleranceBox.Text = policy.TransientFailureTolerance.ToString();
                suppressEvents = false;
                SyncIpv4Display();
                UpdateEnableLabel();
            }
            catch (Exception error)
            {
                SetProbeBanner("#DC2626", UiStrings.T("Failed to load policy", "加载策略失败"), error.Message);
            }
        }

        private void SyncIpv4Display()
        {
            suppressEvents = true;
            if (ipv4FieldFocused || ShowFullIp)
            {
                ipv4Box.Text = rawIpv4Input;
            }
            else
            {
                string[] tokens = ExitPolicyStore.ParseCsvTokens(rawIpv4Input);
                var masked = new List<string>();
                foreach (string token in tokens)
                    masked.Add(ExitPolicyStore.MaskIpv4(token));
                ipv4Box.Text = String.Join(", ", masked.ToArray());
            }
            suppressEvents = false;
            UpdateIpv4CountBadge();
        }

        private void UpdateIpv4CountBadge()
        {
            string[] tokens = ExitPolicyStore.ParseCsvTokens(rawIpv4Input);
            ipv4CountBadge.Text = tokens.Length == 0
                ? UiStrings.T("Optional", "可选")
                : UiStrings.T(tokens.Length + " locked", "已锁定 " + tokens.Length + " 个地址");
        }

        private ExitPolicy BuildDraftPolicy()
        {
            int interval;
            if (!Int32.TryParse((intervalBox.Text ?? "").Trim(), out interval))
                throw new InvalidOperationException(UiStrings.T("Recheck interval must be a number between 15 and 300.", "复核间隔必须是 15 到 300 之间的整数。"));
            int tol;
            if (!Int32.TryParse((toleranceBox.Text ?? "").Trim(), out tol))
                throw new InvalidOperationException(UiStrings.T("Retry tolerance must be a number between 1 and 5.", "丢包重试次数必须是 1 到 5 之间的整数。"));

            string ipSource = (ipv4FieldFocused || ShowFullIp) ? ipv4Box.Text : rawIpv4Input;
            var draft = new ExitPolicy
            {
                Version = 1,
                Enabled = enabledToggle.IsChecked == true,
                TargetHost = hostBox.Text,
                AllowedCountries = ExitPolicyStore.ParseCsvTokens(countriesBox.Text),
                AllowedIpv4s = ExitPolicyStore.ParseCsvTokens(ipSource),
                MonitorIntervalSeconds = interval,
                TransientFailureTolerance = tol
            };
            return ExitPolicyStore.NormalizeAndValidate(draft);
        }

        private void ResetToDefaults()
        {
            ExitPolicy def = ExitPolicy.CreateDefault();
            suppressEvents = true;
            enabledToggle.IsChecked = def.Enabled;
            hostBox.Text = def.TargetHost;
            countriesBox.Text = "";
            rawIpv4Input = "";
            intervalBox.Text = def.MonitorIntervalSeconds.ToString();
            toleranceBox.Text = def.TransientFailureTolerance.ToString();
            suppressEvents = false;
            SyncIpv4Display();
            UpdateEnableLabel();
        }

        private void SavePolicy()
        {
            try
            {
                ExitPolicy clean = BuildDraftPolicy();
                if (clean.Enabled && clean.AllowedCountries.Length == 0 && clean.AllowedIpv4s.Length == 0)
                {
                    MessageBox.Show(
                        UiStrings.T(
                            "When exit verification is enabled, configure at least one allowed country code or IPv4 address.",
                            "启用出口核验时，请至少填写一个允许的国家码或独享 IPv4 地址。"),
                        "Claude Guard",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }
                ExitPolicyStore.Save(clean);
                rawIpv4Input = String.Join(", ", clean.AllowedIpv4s);
                SyncIpv4Display();
                SetProbeBanner(
                    "#16A34A",
                    UiStrings.T("Policy saved", "出口策略已保存"),
                    UiStrings.T("Main guard status is being re-verified against your updated policy.", "正在按最新策略重新核验主窗口通道状态。"));
                if (PolicySaved != null)
                    PolicySaved();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RunLiveProbe()
        {
            if (testing)
                return;
            ExitPolicy draft;
            try { draft = BuildDraftPolicy(); }
            catch (Exception error)
            {
                SetProbeBanner("#DC2626", UiStrings.T("Invalid policy input", "策略参数格式有误"), error.Message);
                return;
            }

            testing = true;
            testBtn.IsEnabled = false;
            saveBtn.IsEnabled = false;
            addIpBtn.IsEnabled = false;
            SetProbeBanner("#D97706", UiStrings.T("Probing IPv4 TLS exit...", "正在通过 IPv4 TLS 直连探测出口..."), "https://" + draft.TargetHost + "/cdn-cgi/trace");

            Task.Factory.StartNew(delegate
            {
                ExitProbeResult probe = null;
                Exception error = null;
                try { probe = ExitProbe.CheckWithPolicy(draft, 6000, false, null); }
                catch (Exception ex) { error = ex; }

                Dispatcher.BeginInvoke(new Action(delegate
                {
                    testing = false;
                    testBtn.IsEnabled = true;
                    saveBtn.IsEnabled = true;
                    if (error != null)
                    {
                        lastProbe = null;
                        SetProbeBanner("#DC2626", UiStrings.T("Probe failed", "出口探测失败"), error.Message);
                    }
                    else
                    {
                        lastProbe = probe;
                        RenderProbeBox();
                    }
                }));
            });
        }

        private void RenderProbeBox()
        {
            addIpBtn.IsEnabled = !testing && lastProbe != null && lastProbe.Ok && !String.IsNullOrEmpty(lastProbe.Ip);
            if (lastProbe == null)
            {
                SetProbeBanner(
                    "#9CA3AF",
                    UiStrings.T("Ready for live IPv4 TLS probe", "就绪 · 点击「立即探测」实测当前出口"),
                    UiStrings.T("Read-only request directly over IPv4 TLS (no system proxy).", "直接经由 TUN 发起只读 IPv4 TLS 探测，不走系统代理，不发送账号信息。"));
                return;
            }
            if (!lastProbe.Ok)
            {
                SetProbeBanner("#DC2626", UiStrings.T("Probe failed", "出口探测失败"), lastProbe.Message);
                return;
            }

            string ipText = ShowFullIp ? lastProbe.Ip : lastProbe.MaskedIp;
            string geo = String.IsNullOrEmpty(lastProbe.Country)
                ? ""
                : (" (" + lastProbe.Country + (String.IsNullOrEmpty(lastProbe.Colo) ? ")" : " / " + lastProbe.Colo + ")"));
            string head = (lastProbe.PolicyAllowed ? UiStrings.T("Passed · ", "实测通过 · ") : UiStrings.T("Blocked · ", "策略拦截 · ")) + ipText + geo;
            string detail = UiStrings.T("TLS 1.2 verified · ", "TLS 1.2 证书校验通过 · ") + lastProbe.LatencyMs + " ms · " + lastProbe.Message;
            SetProbeBanner(lastProbe.PolicyAllowed ? "#16A34A" : "#DC2626", head, detail);
        }

        private void AddObservedIp()
        {
            if (lastProbe == null || !lastProbe.Ok || String.IsNullOrEmpty(lastProbe.Ip))
                return;
            try
            {
                var list = new List<string>(ExitPolicyStore.NormalizeIpv4s(ExitPolicyStore.ParseCsvTokens(rawIpv4Input)));
                if (!list.Contains(lastProbe.Ip))
                    list.Add(lastProbe.Ip);
                list.Sort(StringComparer.Ordinal);
                rawIpv4Input = String.Join(", ", list.ToArray());
                SyncIpv4Display();
            }
            catch (Exception error)
            {
                MessageBox.Show(error.Message, "Claude Guard", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void SetProbeBanner(string dotHex, string title, string detail)
        {
            probeLed.Fill = BrushFrom(dotHex);
            probeTitle.Text = title;
            probeTitle.Foreground = dotHex == "#16A34A" ? BrushFrom("#15803D") : (dotHex == "#DC2626" ? BrushFrom("#B91C1C") : BrushFrom("#121418"));
            probeDetail.Text = detail;
        }

        private static SolidColorBrush BrushFrom(string hex)
        {
            return (SolidColorBrush)new BrushConverter().ConvertFromString(hex);
        }
    }
}
