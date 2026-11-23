using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;

internal sealed class GuardUserRegionWindow : Window
{
    private static readonly Brush Paper = Color("#F8F6F0");
    private static readonly Brush Sheet = Color("#FFFEFB");
    private static readonly Brush Ink = Color("#302E29");
    private static readonly Brush Muted = Color("#646056");
    private static readonly Brush Line = Color("#DEDACF");
    private static readonly Brush Clay = Color("#A85138");
    private static readonly Brush Good = Color("#365E47");
    private static readonly Brush Attention = Color("#795018");
    private static readonly Brush Problem = Color("#914431");

    private readonly Func<IDictionary> read;
    private readonly Func<string, string, IDictionary> apply;
    private readonly Func<string> confirmSite;
    private readonly Action<string> openSetting;
    private readonly TextBlock guard = Text("", 14);
    private readonly TextBlock route = Text("", 18);
    private readonly TextBlock edge = Text("", 13);
    private readonly TextBlock status = Text("", 14);
    private readonly TextBlock failureDetail = Text("", 13, Problem);
    private readonly TextBlock windowsLanguageLabel = Text("Windows 首选语言", 13, Muted);
    private readonly TextBlock windowsLanguageGuidance = Text("请打开“Windows 首选语言”，将目标语言移到列表第一位，然后刷新当前状态。", 13, Attention);
    private readonly TextBlock[] current = new TextBlock[6];
    private readonly TextBlock[] target = new TextBlock[6];
    private readonly Button applyButton;
    private readonly Button confirmButton;
    private readonly List<Button> availableWhileIdle = new List<Button>();
    private IDictionary receipt;
    private bool busy;

    internal static int Run(Func<IDictionary> read, Func<string, string, IDictionary> apply,
        Func<string> confirmSite, Action<string> openSetting)
    {
        var window = new GuardUserRegionWindow(read, apply, confirmSite, openSetting);
        if (Application.Current != null)
        {
            window.ShowDialog();
            return 0;
        }
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        return app.Run(window);
    }

    private GuardUserRegionWindow(Func<IDictionary> read, Func<string, string, IDictionary> apply,
        Func<string> confirmSite, Action<string> openSetting)
    {
        this.read = read;
        this.apply = apply;
        this.confirmSite = confirmSite;
        this.openSetting = openSetting;

        Title = "Claude Guard · 地区和语言";
        Width = 780;
        Height = 700;
        MinWidth = 590;
        MinHeight = 460;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Paper;
        Foreground = Ink;
        FontFamily = new FontFamily("Segoe UI, Microsoft YaHei UI");
        FontSize = 14;
        Language = XmlLanguage.GetLanguage("zh-CN");
        UseLayoutRounding = true;
        TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);

        var body = new StackPanel { Margin = new Thickness(32, 25, 32, 26) };
        Content = new ScrollViewer { Content = body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        var heading = Text("地区和语言", 31);
        heading.FontFamily = new FontFamily("Georgia, SimSun");
        body.Children.Add(heading);
        var scope = Text("仅调整本用户的 Windows 地区和语言、Edge 网站语言。", 14, Muted);
        scope.Margin = new Thickness(0, 6, 0, 16);
        body.Children.Add(scope);

        AutomationProperties.SetLiveSetting(guard, AutomationLiveSetting.Polite);
        guard.FontWeight = FontWeights.SemiBold;
        var guardPanel = Panel(guard, new Thickness(14, 9, 14, 9));
        body.Children.Add(guardPanel);

        var routeLabel = Text("当前节点", 13, Muted);
        routeLabel.Margin = new Thickness(0, 16, 0, 2);
        body.Children.Add(routeLabel);
        route.Margin = new Thickness(0, 0, 0, 10);
        body.Children.Add(route);
        body.Children.Add(Panel(BuildComparison(), new Thickness(14, 4, 14, 4)));
        edge.Foreground = Muted;
        edge.Margin = new Thickness(0, 7, 0, 9);
        body.Children.Add(edge);

        var actions = new WrapPanel();
        applyButton = ActionButton("应用当前节点的地区和语言", true);
        applyButton.Click += async (sender, args) =>
        {
            string country = Value(receipt, "CountryCode");
            string ip = Value(receipt, "ExpectedIpv4");
            if (CanApply(receipt))
                await Perform("正在应用地区和语言…", "应用未完成。请刷新状态后重试。",
                    () => this.apply(country, ip), Present);
        };
        actions.Children.Add(applyButton);

        confirmButton = ActionButton("核对网站实际收到的语言", false);
        confirmButton.Click += async (sender, args) =>
        {
            string request = Value(receipt, "RequestId");
            if (CanConfirm(receipt))
                await Perform("正在核对网站收到的语言…", "未能核对。请确认 Edge 网站首选语言后再试。", () =>
                {
                    string header = this.confirmSite();
                    if (Header(header).Length == 0) throw new InvalidOperationException();
                    IDictionary latest = null;
                    try { latest = this.read(); }
                    catch (Exception) { }
                    return Tuple.Create(header, latest);
                }, result =>
                {
                    if (result.Item2 != null)
                    {
                        Present(result.Item2);
                        if (Value(result.Item2, "RequestId") != request)
                        {
                            Announce("当前设置记录已更新，可核对新记录。", Attention);
                            return;
                        }
                    }
                    current[5].Text = result.Item1;
                    Announce("已核对网站实际收到的语言。", Good);
                });
        };
        actions.Children.Add(confirmButton);

        var refresh = ActionButton("刷新当前状态", false);
        refresh.Click += async (sender, args) => await Refresh();
        availableWhileIdle.Add(refresh);
        actions.Children.Add(refresh);
        body.Children.Add(actions);

        AutomationProperties.SetLiveSetting(status, AutomationLiveSetting.Polite);
        AutomationProperties.SetLiveSetting(failureDetail, AutomationLiveSetting.Polite);
        AutomationProperties.SetLiveSetting(windowsLanguageGuidance, AutomationLiveSetting.Polite);
        var feedbackContent = new StackPanel();
        feedbackContent.Children.Add(status);
        windowsLanguageGuidance.Margin = new Thickness(0, 5, 0, 0);
        feedbackContent.Children.Add(windowsLanguageGuidance);
        failureDetail.Margin = new Thickness(0, 5, 0, 0);
        feedbackContent.Children.Add(failureDetail);
        var feedback = Panel(feedbackContent, new Thickness(14, 10, 14, 10));
        feedback.Margin = new Thickness(0, 2, 0, 13);
        body.Children.Add(feedback);

        var links = new WrapPanel();
        AddSettingLink(links, "打开 Edge 网站语言设置", "edge-website-languages");
        AddSettingLink(links, "Windows 时区", "windows-time-zone");
        AddSettingLink(links, "Windows 国家或地区", "windows-home-region");
        AddSettingLink(links, "Windows 区域格式", "windows-regional-format");
        AddSettingLink(links, "Windows 首选语言", "windows-preferred-languages");
        body.Children.Add(links);

        Present(null);
        Loaded += async (sender, args) => await Refresh();
        Closing += (sender, args) =>
        {
            if (!busy) return;
            args.Cancel = true;
            Announce("当前操作正在完成。", Muted);
        };
    }

    private static Brush Color(string hex)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromInvariantString(hex);
        brush.Freeze();
        return brush;
    }

    private static TextBlock Text(string content, double size, Brush brush = null)
    {
        return new TextBlock { Text = content, FontSize = size, TextWrapping = TextWrapping.Wrap, Foreground = brush ?? Ink };
    }

    private static Border Panel(UIElement content, Thickness padding)
    {
        return new Border
        {
            Child = content, Padding = padding, Background = Sheet, BorderBrush = Line,
            BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(9)
        };
    }

    private static Button ActionButton(string caption, bool primary, bool link = false)
    {
        var button = new Button
        {
            Content = caption, MinHeight = link ? 32 : 37, Margin = new Thickness(0, 0, 8, 7),
            Padding = link ? new Thickness(7, 4, 7, 4) : new Thickness(12, 6, 12, 6),
            Background = primary ? Clay : link ? Brushes.Transparent : Sheet,
            Foreground = primary ? Sheet : link ? Clay : Ink,
            BorderBrush = primary ? Clay : Line, BorderThickness = new Thickness(link ? 0 : 1),
            FontWeight = primary ? FontWeights.SemiBold : FontWeights.Normal,
            Cursor = System.Windows.Input.Cursors.Hand,
            Template = ButtonTemplate()
        };
        return button;
    }

    private static ControlTemplate ButtonTemplate()
    {
        var surface = new FrameworkElementFactory(typeof(Border), "Surface");
        surface.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
        surface.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
        surface.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));
        surface.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
        surface.SetValue(Border.CornerRadiusProperty, new CornerRadius(6));
        var content = new FrameworkElementFactory(typeof(ContentPresenter));
        content.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        content.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        surface.AppendChild(content);
        var template = new ControlTemplate(typeof(Button)) { VisualTree = surface };
        var hover = new Trigger { Property = IsMouseOverProperty, Value = true };
        hover.Setters.Add(new Setter(UIElement.OpacityProperty, 0.78, "Surface"));
        template.Triggers.Add(hover);
        var disabled = new Trigger { Property = IsEnabledProperty, Value = false };
        disabled.Setters.Add(new Setter(UIElement.OpacityProperty, 0.45, "Surface"));
        template.Triggers.Add(disabled);
        return template;
    }

    private Grid BuildComparison()
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(143) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Cell(grid, 0, 1, Text("当前", 13, Muted));
        Cell(grid, 0, 2, Text("目标", 13, Muted));
        string[] rows = { "Windows 国家或地区", "Windows 时区", "Windows 区域格式", "Windows 首选语言", "Edge 网站首选语言", "网站实际收到的语言" };
        for (int i = 0; i < rows.Length; i++)
        {
            current[i] = Text("", 13);
            target[i] = Text("", 13);
            Cell(grid, i + 1, 0, i == 3 ? windowsLanguageLabel : Text(rows[i], 13, Muted));
            Cell(grid, i + 1, 1, current[i]);
            Cell(grid, i + 1, 2, target[i]);
        }
        return grid;
    }

    private static void Cell(Grid grid, int row, int column, TextBlock text)
    {
        while (grid.RowDefinitions.Count <= row) grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var cell = new Border { Child = text, Padding = new Thickness(0, 6, 12, 6) };
        if (row > 0)
        {
            cell.BorderBrush = Line;
            cell.BorderThickness = new Thickness(0, 1, 0, 0);
        }
        Grid.SetRow(cell, row);
        Grid.SetColumn(cell, column);
        grid.Children.Add(cell);
    }

    private void AddSettingLink(Panel links, string caption, string setting)
    {
        var button = ActionButton(caption, false, true);
        button.Click += async (sender, args) =>
        {
            await Perform("正在打开设置…", "无法打开设置。请在系统或浏览器中打开对应页面。",
                () => { openSetting(setting); return true; },
                done => Announce(setting == "edge-website-languages"
                    ? "请在 Edge 网站首选语言中将目标语言移到最上方。"
                    : "设置已打开。完成后可刷新当前状态。", Muted));
        };
        availableWhileIdle.Add(button);
        links.Children.Add(button);
    }

    private async Task Refresh()
    {
        await Perform("正在读取当前状态…", "无法读取当前状态。请刷新后重试。", read, Present);
    }

    private async Task Perform<T>(string working, string failure, Func<T> operation, Action<T> complete)
    {
        if (busy) return;
        busy = true;
        UpdateButtons();
        Announce(working, Muted);
        try { complete(await Task.Run(operation)); }
        catch (Exception) { Announce(failure, Problem); }
        finally
        {
            busy = false;
            UpdateButtons();
        }
    }

    private void Announce(string message, Brush tone)
    {
        status.Text = message;
        status.Foreground = tone;
    }

    private void UpdateButtons()
    {
        applyButton.IsEnabled = !busy && CanApply(receipt);
        confirmButton.IsEnabled = !busy && CanConfirm(receipt);
        foreach (Button button in availableWhileIdle) button.IsEnabled = !busy;
    }

    private void Present(IDictionary data)
    {
        receipt = data;
        var health = Map(data, "GuardHealth");
        string healthStatus = Value(health, "Readiness");
        switch (healthStatus)
        {
            case "Ready": guard.Text = "Guard 防护正常"; guard.Foreground = Good; break;
            case "Locked": guard.Text = "Guard 防护已锁定"; guard.Foreground = Problem; break;
            case "Emergency": guard.Text = "Guard 防护处于紧急模式"; guard.Foreground = Problem; break;
            case "WaitingForProxy": guard.Text = "Guard 正在等待代理"; guard.Foreground = Attention; break;
            case "Rechecking": guard.Text = "Guard 正在重新核验防护"; guard.Foreground = Attention; break;
            case "Unverified": guard.Text = "Guard 防护尚未核验"; guard.Foreground = Attention; break;
            default: guard.Text = "Guard 防护状态未知"; guard.Foreground = Muted; break;
        }
        DateTimeOffset checkedAt;
        if (DateTimeOffset.TryParse(Value(health, "CheckedUtc"), CultureInfo.InvariantCulture,
            DateTimeStyles.None, out checkedAt))
            guard.Text += "　上次核对 " + checkedAt.ToLocalTime().ToString("MM-dd HH:mm", CultureInfo.InvariantCulture);

        string country = Value(data, "CountryCode");
        string ip = Value(data, "ExpectedIpv4");
        string observed = Value(data, "ObservedIpv4");
        route.Text = CanApply(data) ? Country(country) + "　" + ip : "暂无可用的当前节点核对记录";
        if (CanApply(data) && Ipv4(observed) && observed != ip)
            route.Text += "　实测 " + observed;
        Fill(current, Map(data, "Current") ?? Map(data, "After") ?? Map(data, "Before"));
        Fill(target, Map(data, "Targets"));
        string website = Value(data, "WebsiteStatus");
        string header = website == "Verified" ? Header(Value(data, "SiteAcceptLanguage")) : "";
        current[5].Text = header.Length > 0 ? header : website == "AwaitingBrowser" ? "等待手动核对" : "尚未核对";
        target[5].Text = Or(Value(data, "PrimaryLanguage"), "等待核对");

        string edgeStatus = Value(data, "EdgeStatus");
        bool windowsLanguageManual = Value(data, "WindowsLanguageStatus") == "ManualRequired";
        windowsLanguageLabel.Text = windowsLanguageManual ? "Windows 首选语言（需手动）" : "Windows 首选语言";
        windowsLanguageLabel.Foreground = windowsLanguageManual ? Attention : Muted;
        windowsLanguageGuidance.Visibility = windowsLanguageManual ? Visibility.Visible : Visibility.Collapsed;
        edge.Text = edgeStatus == "PreferencesVerified" ? "Edge 首选语言已核对。"
            : edgeStatus == "ManualRequired" ? "请在 Edge 设置中完成网站首选语言。"
            : "Edge 网站首选语言尚未核对。";
        string outcome = Value(data, "Outcome");
        string supplied = FriendlyMessage(Value(data, "Message"));
        string message;
        Brush tone = Muted;
        switch (outcome)
        {
            case "Applied":
                message = header.Length == 0 ? "地区和语言已应用。网站实际收到的语言可单独核对。" : "地区和语言已应用，网站语言已核对。";
                tone = Good;
                break;
            case "ManualRequired":
                message = header.Length == 0 ? "请完成 Edge 网站首选语言，再核对网站实际收到的语言。" : "地区和语言已应用，网站语言已核对。";
                tone = header.Length == 0 ? Attention : Good;
                break;
            case "Failed": message = "地区和语言应用未完成。请刷新当前状态。"; tone = Problem; break;
            case "RecoveryRequired": message = "地区和语言设置需要恢复。请刷新状态查看当前值。"; tone = Problem; break;
            case "Busy": message = "已有地区和语言操作在进行。完成后可刷新当前状态。"; tone = Attention; break;
            default: message = CanApply(data) ? "可以应用当前节点的地区和语言。" : "请先在 Guard 核对当前节点，再刷新此处的状态。"; break;
        }
        if (windowsLanguageManual && (outcome == "Applied" || outcome == "ManualRequired"))
        {
            supplied = "";
            message = header.Length > 0 ? "网站实际收到的语言已核对。"
                : edgeStatus == "ManualRequired" ? "请完成 Edge 网站首选语言，再核对网站实际收到的语言。"
                : "网站实际收到的语言仍待核对。";
            tone = Attention;
        }
        failureDetail.Text = outcome == "Failed" || outcome == "RecoveryRequired" ? ExplainFailure(Map(data, "Diagnostics")) : "";
        failureDetail.Visibility = failureDetail.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
        Announce(Or(supplied, message), tone);
        UpdateButtons();
    }

    private static void Fill(TextBlock[] fields, IDictionary state)
    {
        fields[0].Text = Country(Value(state, "CountryCode"));
        fields[1].Text = TimeZone(Value(state, "TimeZone"));
        fields[2].Text = Or(Join("  ", Value(state, "LocaleName"), Value(state, "ShortDate"), Value(state, "ShortTime")), "暂无记录");
        fields[3].Text = Or(Languages(Get(state, "PreferredLanguages")), "暂无记录");
        fields[4].Text = Or(Languages(Get(state, "EdgeLanguages")), "暂无记录");
    }

    private static object Get(IDictionary data, string name) { return data == null ? null : data[name]; }
    private static IDictionary Map(IDictionary data, string name) { return Get(data, name) as IDictionary; }
    private static string Value(IDictionary data, string name)
    {
        return Convert.ToString(Get(data, name), CultureInfo.InvariantCulture) ?? "";
    }
    private static string Or(string value, string fallback) { return string.IsNullOrWhiteSpace(value) ? fallback : value; }

    private static string Join(string separator, params string[] parts)
    {
        return string.Join(separator, Array.FindAll(parts, part => !string.IsNullOrWhiteSpace(part)));
    }

    private static string Languages(object value)
    {
        var csv = value as string;
        if (csv != null) return csv.Replace(",", "、");
        var items = value as IEnumerable;
        if (items == null) return "";
        var result = new List<string>();
        foreach (object item in items) result.Add(Convert.ToString(item, CultureInfo.InvariantCulture));
        return Join("、", result.ToArray());
    }

    private static string Country(string country)
    {
        switch (country)
        {
            case "JP": return "日本";
            case "US": return "美国";
            case "GB": return "英国";
            case "CA": return "加拿大";
            case "AU": return "澳大利亚";
            case "CN": return "中国";
            case "HK": return "中国香港";
            case "TW": return "中国台湾";
            case "SG": return "新加坡";
            case "KR": return "韩国";
            case "DE": return "德国";
            case "FR": return "法国";
            default: return Regex.IsMatch(country, @"\A[A-Z]{2}\z") ? country : "暂无记录";
        }
    }

    private static string TimeZone(string value)
    {
        switch (value)
        {
            case "Tokyo Standard Time": return "东京（UTC+09:00）";
            case "China Standard Time": return "北京（UTC+08:00）";
            case "Pacific Standard Time": return "美国太平洋时间";
            case "Eastern Standard Time": return "美国东部时间";
            default: return Or(value, "暂无记录");
        }
    }

    private static bool Ipv4(string value)
    {
        IPAddress address;
        return IPAddress.TryParse(value, out address) && address.AddressFamily == AddressFamily.InterNetwork && address.ToString() == value;
    }

    private static bool CanApply(IDictionary data)
    {
        return Regex.IsMatch(Value(data, "CountryCode"), @"\A[A-Z]{2}\z") && Ipv4(Value(data, "ExpectedIpv4"));
    }

    private static bool CanConfirm(IDictionary data)
    {
        string outcome = Value(data, "Outcome");
        return (outcome == "Applied" || outcome == "ManualRequired") &&
            Regex.IsMatch(Value(data, "RequestId"), @"\A[a-f0-9]{32}\z") &&
            Regex.IsMatch(Value(data, "BrowserProfile"), @"\A(?:Default|Profile [1-9][0-9]*)\z") &&
            Regex.IsMatch(Value(data, "PrimaryLanguage"), @"\A[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*\z");
    }

    private static string Header(string value)
    {
        return !string.IsNullOrWhiteSpace(value) && Regex.IsMatch(value, @"\A[A-Za-z0-9,;=. \-]{1,512}\z") ? value : "";
    }

    private static string ExplainFailure(IDictionary diagnostics)
    {
        string step = Value(diagnostics, "Step");
        string stage = FailureStep(step);
        if (stage.Length == 0) return "";
        var lines = new List<string> { "操作停在“" + stage + "”。" };
        if (step == "WindowsLocaleApply" || step == "WindowsLocaleVerification")
        {
            string detail = WindowsFailureStage(Value(diagnostics, "WindowsStage"));
            if (detail.Length > 0) lines.Add(detail);
            string setting = WindowsSettingLabel(Value(diagnostics, "WindowsSetting"));
            if (setting.Length > 0) lines.Add("涉及" + setting + "。");

            var differenceLabels = new List<string>();
            object differences = Get(diagnostics, "WindowsDifferences");
            var fields = differences is string ? new[] { differences } : differences as IEnumerable;
            if (fields != null)
            {
                foreach (object field in fields)
                {
                    string label = WindowsSettingLabel(field as string);
                    if (label.Length > 0 && !differenceLabels.Contains(label)) differenceLabels.Add(label);
                }
            }
            if (differenceLabels.Count > 0) lines.Add("涉及的具体项目有" + string.Join("、", differenceLabels) + "。");
        }
        return string.Join(Environment.NewLine, lines);
    }

    private static string FailureStep(string step)
    {
        switch (step)
        {
            case "PriorRecovery": return "恢复上一次地区和语言设置";
            case "InitialRouteBinding": return "核对 Guard 已保存的节点和出口";
            case "ExitProbe": return "试测当前节点的出口";
            case "Plan": return "准备目标地区和语言";
            case "PreApplyRouteBinding": return "应用前再次核对节点和出口";
            case "UserRecoveryJournal": return "保存用于恢复的设置";
            case "WindowsTimeZoneApply": return "应用 Windows 时区";
            case "WindowsTimeZoneVerification": return "核对 Windows 时区";
            case "WindowsLocaleApply": return "应用 Windows 地区和语言";
            case "WindowsLocaleVerification": return "核对 Windows 地区和语言";
            case "EdgeAvailability": return "检查 Edge 网站语言设置能否调整";
            case "EdgeApply": return "应用 Edge 网站首选语言";
            case "EdgeVerification": return "核对 Edge 保存的网站首选语言";
            case "FinalRouteBinding": return "应用后再次核对节点和出口";
            case "FinalSettingsRead": return "读取应用后的设置";
            case "ResultPublication": return "保存本次操作结果";
            default: return "";
        }
    }

    private static string WindowsFailureStage(string stage)
    {
        switch (stage)
        {
            case "PlanValidation": return "无法确认要应用哪些 Windows 设置。";
            case "PreviewRead": case "PreWriteRead": return "无法读取更改前的 Windows 设置。";
            case "PreviewMismatch": case "PreWriteMismatch": return "Windows 设置在预览后发生了变化。";
            case "JournalWrite": return "无法保存更改前的设置。";
            case "NativeWrite": return "Windows 未能写入这项设置。";
            case "SettingReadback": case "FinalReadback": return "无法读取应用后的 Windows 设置。";
            case "SettingMismatch": case "FinalMismatch": return "读到的 Windows 设置与目标不同。";
            case "JournalClear": return "无法清除本次操作的恢复记录。";
            default: return "";
        }
    }

    private static string WindowsSettingLabel(string field)
    {
        switch (field)
        {
            case "OwnerSid": return "当前 Windows 账户";
            case "EffectiveUiLanguage": case "UiLanguageOverride": return "Windows 显示语言";
            case "EffectiveInputMethod": case "DefaultInputLocale": case "InputMethodOverride":
            case "InputMethodOverrideAvailable": return "默认输入法";
            case "HomeLocation": case "CountryCode": case "GeoId": return "Windows 国家或地区";
            case "RegionalFormat": case "LocaleName": case "CultureFromLanguageListOptOut": return "Windows 区域格式";
            case "Languages": case "Languages.Count": return "Windows 首选语言列表";
            case "Format.Calendar": return "日历";
            case "Format.ShortDate": return "短日期格式";
            case "Format.LongDate": return "长日期格式";
            case "Format.YearMonth": return "年月格式";
            case "Format.ShortTime": return "短时间格式";
            case "Format.LongTime": return "长时间格式";
            case "Format.AM": case "Format.PM": return "上午和下午的显示方式";
            case "Format.FirstDayOfWeek": case "Format.FirstWeekOfYear": return "每周和每年的起始规则";
            case "Format.Decimal": case "Format.Thousands": case "Format.Grouping": case "Format.Digits":
            case "Format.LeadingZero": case "Format.NativeDigits": case "Format.DigitSubstitution":
            case "Format.NegativeNumber": case "Format.PositiveSign": case "Format.NegativeSign": return "数字格式";
            case "Format.Currency": case "Format.CurrencyDecimal": case "Format.CurrencyThousands":
            case "Format.CurrencyGrouping": case "Format.CurrencyDigits": case "Format.CurrencyFormat":
            case "Format.NegativeCurrencyFormat": return "货币格式";
            case "Format.ListSeparator": return "列表分隔符";
            case "Format.Measurement": return "度量单位";
            case "Format.Paper": return "默认纸张尺寸";
        }
        if (field != null && Regex.IsMatch(field, @"\ALanguages\.[0-9]{1,3}\.(?:LanguageTag|Handwriting|Spellchecking|InputMethodTips)\z"))
        {
            if (field.EndsWith(".Handwriting", StringComparison.Ordinal)) return "手写输入";
            if (field.EndsWith(".Spellchecking", StringComparison.Ordinal)) return "拼写检查";
            if (field.EndsWith(".InputMethodTips", StringComparison.Ordinal)) return "首选语言的输入法";
            return "首选语言或顺序";
        }
        return "";
    }

    private static string FriendlyMessage(string value)
    {
        switch (value)
        {
            case "Prior regional settings need review before another change.":
                return "请先核对上一次的地区和语言设置。";
            case "The current Bettbox selection and pinned IPv4 must match the existing Guard record.":
                return "当前 Bettbox 节点或 IPv4 与 Guard 的记录不同。";
            case "The observed exit did not match the requested country and IPv4, or could not be verified.":
                return "未能核对当前出口的国家和 IPv4。";
            case "Windows could not prepare a matching regional settings change while preserving the current menu and keyboard.":
                return "Windows 无法在保留显示语言和输入法的同时应用目标地区格式。";
            case "The regional change failed. The prior settings were verified.":
                return "地区和语言应用失败，已核对原有设置。";
        }
        return value.Length <= 220 && Regex.IsMatch(value, @"[\u3400-\u9fff]") ? value.Trim() : "";
    }
}
