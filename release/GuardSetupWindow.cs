using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Controls.Primitives;
using System.Windows.Threading;
using Ellipse = System.Windows.Shapes.Ellipse;

internal static class GuardSetupWindow
{
    internal static int Run(IGuardSetupActions actions, bool settings, bool startUpdate)
    {
        var view = new View(actions, settings, startUpdate);
        view.Window.ShowDialog();
        view.WaitForPreviewClear();
        return view.ExitCode;
    }

    internal sealed class View
    {
        private enum Page { Home, Nodes, Prerequisites, Plan, Audit, Work, Result, Stop }
        private enum CheckFilter { All, Issue, Change }
        private enum Operation { None, Load, Probe, Region, Update, Apply, Recover }
        private enum ResultAction { Home, Nodes, Recover, Reload }

        private sealed class Zone
        {
            public string Id { get; private set; }
            public string Label { get; private set; }

            internal Zone(string id, string label)
            {
                Id = id;
                Label = label;
            }
        }

        private readonly IGuardSetupActions actions;
        private readonly bool settings;
        private bool startUpdate;
        private readonly Button homeNav;
        private readonly Button nodesNav;
        private readonly Button auditNav;
        private readonly Button backButton;
        private readonly Button homePrimary;
        private readonly Button leaveButton;
        private readonly Button primaryButton;
        private readonly Button probeButton;
        private readonly Button cancelProbeButton;
        private readonly PasswordBox maskedNode;
        private readonly TextBox visibleNode;
        private readonly CheckBox revealNode;
        private readonly ComboBox zones;
        private readonly DispatcherTimer progressTimer;
        private readonly DispatcherTimer proofTimer;
        private IDictionary homeSnapshot;
        private IDictionary regionSnapshot;
        private IList<IDictionary> displayedChecks = new List<IDictionary>();
        private CheckFilter checkFilter;
        private string reviewedZoneChoice;
        private DateTimeOffset? proofExpiry;
        private Page page;
        private Operation work;
        private ResultAction resultAction;
        private bool homeLoaded;
        private bool recoveryPending;
        private bool installed;
        private bool changingText;
        private bool settingZones;
        private bool regionReady;
        private bool closeAfterProbe;
        private bool progressRead;
        private bool updateNeedsInstallation;
        private int displayedStage = -2;
        private int operationId;
        private string exitIpv4;
        private string country;
        private CancellationTokenSource probeCancellation;
        private Task clearingPreview = Task.FromResult(0);

        internal Window Window { get; private set; }
        internal int ExitCode { get; private set; }

        internal View(IGuardSetupActions actions, bool settings, bool startUpdate)
        {
            this.actions = actions;
            this.settings = settings;
            this.startUpdate = startUpdate;
            using (Stream stream = typeof(GuardSetupWindow).Assembly.GetManifestResourceStream("Guard.SetupWindow"))
                Window = (Window)XamlReader.Load(stream);

            homeNav = Find<Button>("HomeNav");
            nodesNav = Find<Button>("NodesNav");
            auditNav = Find<Button>("AuditNav");
            backButton = Find<Button>("BackButton");
            homePrimary = Find<Button>("HomePrimary");
            leaveButton = Find<Button>("LeaveButton");
            primaryButton = Find<Button>("PrimaryButton");
            probeButton = Find<Button>("ProbeButton");
            cancelProbeButton = Find<Button>("CancelProbeButton");
            maskedNode = Find<PasswordBox>("MaskedNode");
            visibleNode = Find<TextBox>("VisibleNode");
            revealNode = Find<CheckBox>("RevealNode");
            zones = Find<ComboBox>("Zones");

            homeNav.Click += delegate { ShowHome(); };
            nodesNav.Click += delegate { NavigateNodes(); };
            auditNav.Click += delegate { ShowAudit(); };
            backButton.Click += delegate { Back(); };
            Find<Button>("HomeNodes").Click += delegate { ShowNodes(); };
            Find<Button>("HomeAudit").Click += delegate { ShowAudit(); };
            Find<Button>("HomeStopDetails").Click += delegate { ShowStop(); };
            Find<Button>("AllChecks").Click += delegate { SetCheckFilter(CheckFilter.All); };
            Find<Button>("IssueChecks").Click += delegate { SetCheckFilter(CheckFilter.Issue); };
            Find<Button>("ChangeChecks").Click += delegate { SetCheckFilter(CheckFilter.Change); };
            homePrimary.Click += async delegate { await Primary(); };
            leaveButton.Click += delegate { Window.Close(); };
            probeButton.Click += async delegate { await Probe(); };
            cancelProbeButton.Click += delegate { CancelProbe(); };
            primaryButton.Click += async delegate { await Primary(); };
            maskedNode.PasswordChanged += delegate { NodeEdited(); };
            visibleNode.TextChanged += delegate { NodeEdited(); };
            revealNode.Checked += delegate { Reveal(true); };
            revealNode.Unchecked += delegate { Reveal(false); };
            zones.SelectionChanged += async delegate
            {
                if (!settingZones && work == Operation.None && !String.IsNullOrEmpty(exitIpv4))
                    await RefreshRegion();
            };
            Window.PreviewKeyDown += NavigateByKey;
            Window.Closing += Closing;
            Window.Closed += delegate
            {
                progressTimer.Stop();
                proofTimer.Stop();
                ClearNode();
                ClearPreview();
            };
            progressTimer = new DispatcherTimer(DispatcherPriority.Background, Window.Dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(300)
            };
            progressTimer.Tick += async delegate { await ReadProgress(); };
            proofTimer = new DispatcherTimer(DispatcherPriority.Background, Window.Dispatcher)
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            proofTimer.Tick += delegate { CheckProofExpiry(); };
            Window.Loaded += Loaded;
            ShowWork("正在读取安装状态", "正在检查此电脑上的 Guard 配置。", "正在读取 Windows 时区和防护出口。", "");
            RenderButtons();
        }

        private T Find<T>(string name) where T : FrameworkElement
        {
            return (T)Window.FindName(name);
        }

        internal void WaitForPreviewClear()
        {
            clearingPreview.GetAwaiter().GetResult();
        }

        private static string Read(IDictionary values, string key)
        {
            return values == null ? String.Empty : Convert.ToString(values[key], CultureInfo.InvariantCulture) ?? String.Empty;
        }

        private static bool Flag(IDictionary values, string key)
        {
            return values != null && Object.Equals(values[key], true);
        }

        private static int Count(IDictionary values, string key)
        {
            int number;
            return Int32.TryParse(Read(values, key), NumberStyles.None, CultureInfo.InvariantCulture, out number) ? number : 0;
        }

        private static string Or(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }

        private static Visibility Visible(bool shown)
        {
            return shown ? Visibility.Visible : Visibility.Collapsed;
        }

        private void Text(string name, string value)
        {
            Find<TextBlock>(name).Text = value;
        }

        private void Announce(string name, string value)
        {
            var element = Find<TextBlock>(name);
            if (element.Text == value) return;
            element.Text = value;
            if (AutomationPeer.ListenerExists(AutomationEvents.LiveRegionChanged))
            {
                AutomationPeer peer = UIElementAutomationPeer.CreatePeerForElement(element);
                if (peer != null) peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
            }
        }

        private Brush BrushResource(string key)
        {
            return (Brush)Window.Resources[key];
        }

        private static DateTimeOffset? ReadTime(IDictionary values, string key)
        {
            DateTimeOffset time;
            return DateTimeOffset.TryParse(Read(values, key), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out time) ? time : (DateTimeOffset?)null;
        }

        private static string LocalTime(DateTimeOffset? time)
        {
            return time.HasValue ? time.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "时间未知";
        }

        private void Show(Page next, string title, string description)
        {
            if (page == Page.Nodes && next != Page.Nodes && revealNode.IsChecked == true)
                revealNode.IsChecked = false;
            bool changedPage = page != next;
            page = next;
            Find<FrameworkElement>("HomePage").Visibility = Visible(page == Page.Home);
            Find<FrameworkElement>("NodesPage").Visibility = Visible(page == Page.Nodes);
            Find<FrameworkElement>("ChecksPage").Visibility = Visible(page == Page.Prerequisites || page == Page.Plan || page == Page.Audit);
            Find<FrameworkElement>("WorkPage").Visibility = Visible(page == Page.Work);
            Find<FrameworkElement>("ResultPage").Visibility = Visible(page == Page.Result);
            Find<FrameworkElement>("StopPage").Visibility = Visible(page == Page.Stop);
            Find<FrameworkElement>("PageContent").MaxWidth = page == Page.Stop || page == Page.Work || page == Page.Result ? 754 : 948;
            var heading = Find<TextBlock>("PageTitle");
            heading.Text = title;
            heading.FontSize = page == Page.Home ? 49 : 42;
            heading.TextAlignment = page == Page.Home ? TextAlignment.Center : TextAlignment.Left;
            heading.Margin = new Thickness(0, page == Page.Home ? 13 : 0, 0, 0);
            var lead = Find<TextBlock>("PageDescription");
            lead.Text = description;
            lead.TextAlignment = heading.TextAlignment;
            lead.Visibility = Visible(!String.IsNullOrEmpty(description));
            var steps = Find<TextBlock>("PageStep");
            steps.Visibility = Visible(page == Page.Nodes || page == Page.Plan);
            steps.Inlines.Clear();
            if (steps.Visibility == Visibility.Visible)
            {
                steps.Inlines.Add(new Run("填写与试测") { Foreground = BrushResource(page == Page.Nodes ? "Clay" : "Muted") });
                steps.Inlines.Add(new Run("  ›  "));
                steps.Inlines.Add(new Run("核对变更") { Foreground = BrushResource(page == Page.Plan ? "Clay" : "Muted") });
                steps.Inlines.Add(new Run("  ›  应用与验收"));
            }
            Find<ScrollViewer>("ContentScroll").ScrollToTop();
            RenderButtons();
            if (changedPage && Window.IsLoaded) heading.Focus();
        }

        private void ShowHome()
        {
            if (!homeLoaded || work != Operation.None) return;
            if (recoveryPending)
            {
                ShowRecovery();
                return;
            }
            bool ready = installed && Flag(homeSnapshot, "Ready");
            string title = ready ? "防护已就绪" : installed ? "防护待核对" : "安装 Claude Guard";
            string description = ready ? "Claude Desktop 只允许通过已确认的 IPv4 出口联网。"
                : installed ? Or(Read(homeSnapshot, "StatusMessage"), "查看核对清单，了解哪些防护项目需要处理。")
                : "配置专用出口后，即可为 Claude Desktop 安装防护。";
            Text("HomeActionDescription", installed ? "更新会沿用此节点、出口和时区。"
                : updateNeedsInstallation ? "这台电脑尚未安装 Guard。" : "先查看安装条件，再试测节点。");
            Text("HomeEntry", GuardedEntry(Read(homeSnapshot, "GuardedEntry")));
            IDictionary stop = SnapshotPart(homeSnapshot, "LastStop");
            Text("HomeStopSummary", StopBrief(stop));
            IDictionary windowError = SnapshotPart(homeSnapshot, "LastWindowError");
            bool hasWindowError = HasWindowError(windowError);
            Text("HomeWindowError", hasWindowError ? "设置窗口  ·  " + LocalTime(ReadTime(windowError, "TimeUtc")) +
                "  ·  " + Or(Read(windowError, "Title"), "意外退出") : "");
            Find<TextBlock>("HomeWindowError").Visibility = Visible(hasWindowError);
            Show(Page.Home, title, description);
        }

        private void NavigateNodes()
        {
            if (page == Page.Nodes) return;
            if (!installed && (page == Page.Home || page == Page.Audit || page == Page.Stop))
                ShowPrerequisites();
            else ShowNodes();
        }

        private void ShowNodes()
        {
            if (!homeLoaded || recoveryPending || work != Operation.None) return;
            CheckProofExpiry();
            Show(Page.Nodes, installed ? "更换节点" : "配置安装节点",
                "填写节点链接并试测。Guard 会用测得的公网 IPv4 作为允许的出口。");
        }

        private void ShowPrerequisites()
        {
            if (!homeLoaded || recoveryPending || work != Operation.None) return;
            List<IDictionary> prerequisites = Checks(homeSnapshot);
            prerequisites.RemoveAll(row => Read(row, "Key") != "bettbox" && Read(row, "Key") != "store-desktop" && Read(row, "Key") != "closed-desktop");
            Show(Page.Prerequisites, installed ? "保留配置并更新" : "安装前检查",
                "运行安装或更新时，Guard 会核对所需条件。");
            SetChecks(prerequisites, installed ? "沿用现有设置" : "开始前",
                (installed ? "更新 Guard 文件，沿用当前节点、出口和 Windows 时区。 " : "") +
                "请连接 Bettbox 并开启 TUN 模式，确认已安装 Microsoft 商店版 Claude Desktop，并保存 Claude 中的工作。");
        }

        private void ShowPlan()
        {
            if (work != Operation.None || !CanReview() || CheckProofExpiry()) return;
            List<IDictionary> plan = Checks(regionSnapshot);
            int changes = plan.FindAll(row => Flag(row, "Change")).Count;
            Show(Page.Plan, "核对本次变更", "展开任意一行查看原因和处理方法。");
            string heading = !regionReady ? "暂不能应用" : changes > 0
                ? String.Format(CultureInfo.CurrentCulture, "{0} 项设置拟更新", changes) : "核对拟应用的设置";
            SetChecks(plan, heading, regionReady ? "确认节点、允许的出口和 Windows 时区后，再应用变更。"
                : "查看问题项，按说明处理后重新核对。");
        }

        private bool CanReview()
        {
            return !String.IsNullOrEmpty(Read(regionSnapshot, "TimeZone")) && !Flag(regionSnapshot, "RequiresChoice");
        }

        private void ShowAudit()
        {
            if (!homeLoaded || recoveryPending || work != Operation.None) return;
            Show(Page.Audit, "核对清单", "查看当前设置、应有值和状态。展开任意一行查看说明。");
            SetChecks(Checks(homeSnapshot), "", "");
        }

        private void Back()
        {
            if (work != Operation.None) return;
            if (page == Page.Plan) ShowNodes();
            else ShowHome();
        }

        private static IDictionary SnapshotPart(IDictionary snapshot, string key)
        {
            return snapshot == null ? null : snapshot[key] as IDictionary;
        }

        private static string StopBrief(IDictionary stop)
        {
            if (Flag(stop, "HasRecord"))
            {
                string reason = Read(stop, "SourceKind") == "GuardConfirmed" ? Read(stop, "Summary") : Read(stop, "Title");
                return LocalTime(ReadTime(stop, "TimeUtc")) + "  ·  " + Or(reason, "停止原因未知");
            }
            string state = Read(stop, "ReadState");
            return state == "Missing" || state == "Empty" ? "暂无停止记录" : "暂时无法读取停止记录";
        }

        private static bool HasWindowError(IDictionary error)
        {
            return Flag(error, "HasRecord") || ReadTime(error, "TimeUtc").HasValue;
        }

        private static string StopTime(IDictionary record)
        {
            DateTimeOffset? time = ReadTime(record, "TimeUtc");
            return time.HasValue ? LocalTime(time) + "（本地时间）" : "时间未知";
        }

        private void ShowStop()
        {
            if (!homeLoaded || work != Operation.None) return;
            IDictionary stop = SnapshotPart(homeSnapshot, "LastStop");
            bool recorded = Flag(stop, "HasRecord");
            Text("StopTitle", recorded ? Or(Read(stop, "Title"), "停止原因未知") : StopBrief(stop));
            Text("StopSummary", Or(Read(stop, "Summary"), recorded ? "现有记录未说明停止原因。"
                : "此页会显示 Guard 能读取到的最近一次停止记录。"));
            var facts = Find<StackPanel>("StopFacts");
            facts.Children.Clear();
            AddFact(facts, "停止时间", recorded ? StopTime(stop) : "未知");
            string network = Read(stop, "Network");
            string sourceKind = Read(stop, "SourceKind");
            if (sourceKind == "GuardConfirmed") network = "是。Guard 先确认联网许可已关闭，再发起关闭。";
            else if (sourceKind == "LauncherObserved") network = ("先后顺序未知。 " + network).TrimEnd();
            AddFact(facts, "Guard 是否先断网", Or(network, "未知"));
            AddFact(facts, "下一步", Or(Read(stop, "Action"), "如再次停止，请重新打开 Guard 查看记录。"));
            AddFact(facts, "记录来源", Or(Read(stop, "Source"), "暂无可显示的来源"));
            AddFact(facts, "退出代码", Read(stop, "ExitCode"));
            Text("StopExtraText", Read(stop, "Details"));
            var extra = Find<Expander>("StopExtra");
            extra.IsExpanded = false;
            extra.Visibility = Visible(!String.IsNullOrWhiteSpace(Read(stop, "Details")));
            IDictionary windowError = SnapshotPart(homeSnapshot, "LastWindowError");
            bool hasWindowError = HasWindowError(windowError);
            Find<Border>("WindowErrorCard").Visibility = Visible(hasWindowError);
            if (hasWindowError)
            {
                Text("WindowErrorTitle", Or(Read(windowError, "Title"), "意外退出"));
                Text("WindowErrorSummary", Or(Read(windowError, "Summary"), Read(windowError, "Detail")));
                var errorFacts = Find<StackPanel>("WindowErrorFacts");
                errorFacts.Children.Clear();
                AddFact(errorFacts, "停止时间", StopTime(windowError));
                AddFact(errorFacts, "下一步", Read(windowError, "Action"));
                AddFact(errorFacts, "记录来源", Read(windowError, "Source"));
                AddFact(errorFacts, "错误代码", Or(Read(windowError, "ExitCode"), Read(windowError, "HResult")));
                AddFact(errorFacts, "记录详情", Read(windowError, "Details"));
            }
            Show(Page.Stop, "最近一次停止", "查看受防护的 Claude 会话和设置窗口的停止记录。");
        }

        private void AddFact(Panel panel, string label, string value)
        {
            if (String.IsNullOrWhiteSpace(value)) return;
            var row = new Grid { Margin = new Thickness(0, 7, 0, 7) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(144) });
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.Children.Add(new TextBlock { Text = label, Style = (Style)Window.Resources["Label"], Margin = new Thickness(0, 1, 10, 0) });
            var content = new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap };
            Grid.SetColumn(content, 1);
            row.Children.Add(content);
            panel.Children.Add(new Border { Height = 1, Background = BrushResource("Line") });
            panel.Children.Add(row);
        }

        private static List<IDictionary> Checks(IDictionary snapshot)
        {
            var rows = new List<IDictionary>();
            var data = snapshot == null ? null : snapshot["Checks"] as IEnumerable;
            if (data != null)
            {
                foreach (object item in data)
                {
                    var row = item as IDictionary;
                    if (row != null) rows.Add(row);
                }
            }
            return rows;
        }

        private void SetChecks(IList<IDictionary> rows, string title, string description)
        {
            displayedChecks = rows;
            Text("ChecksLeadTitle", title);
            Text("ChecksLeadDetail", description);
            Find<Border>("ChecksLead").Visibility = Visible(title.Length > 0);
            SetCheckFilter(CheckFilter.All);
        }

        private void SetCheckFilter(CheckFilter filter)
        {
            checkFilter = filter;
            Find<Button>("AllChecks").Tag = filter == CheckFilter.All ? "Selected" : null;
            Find<Button>("IssueChecks").Tag = filter == CheckFilter.Issue ? "Selected" : null;
            Find<Button>("ChangeChecks").Tag = filter == CheckFilter.Change ? "Selected" : null;
            var rows = Find<StackPanel>("CheckRows");
            rows.Children.Clear();
            AddCheckGroup(rows, "settings", "配置与改动");
            AddCheckGroup(rows, "protection", "防护核对");
            AddCheckGroup(rows, "environment", "环境参考");
            if (rows.Children.Count == 0)
            {
                rows.Children.Add(new TextBlock
                {
                    Text = filter == CheckFilter.Issue ? "当前清单里没有标出问题。" : filter == CheckFilter.Change
                        ? "当前清单里没有拟应用的改动。" : "暂未读取到核对项。",
                    Style = (Style)Window.Resources["Body"],
                    Margin = new Thickness(8, 12, 8, 12)
                });
            }
        }

        private void AddCheckGroup(Panel panel, string group, string title)
        {
            var groupRows = new List<IDictionary>();
            int issues = 0;
            foreach (IDictionary row in displayedChecks)
            {
                if (Read(row, "Group") != group) continue;
                bool issue = Flag(row, "Issue");
                if (checkFilter == CheckFilter.Issue && !issue || checkFilter == CheckFilter.Change && !Flag(row, "Change")) continue;
                groupRows.Add(row);
                if (issue) issues++;
            }
            if (groupRows.Count == 0) return;

            var detail = new StackPanel { Margin = new Thickness(0, 0, 0, 6) };
            var columns = CheckColumns("项目", "当前值", page == Page.Plan ? "拟用或应有值" : "应有值", "状态", "");
            columns.Background = BrushResource("QuietPaper");
            columns.Margin = new Thickness(0, 0, 0, 4);
            detail.Children.Add(columns);
            foreach (IDictionary row in groupRows)
            {
                string label = Read(row, "Label");
                string status = Read(row, "Status");
                string current = Or(Read(row, "Current"), "未知");
                string expected = Or(Read(row, "Expected"), "未提供");
                string explanation = Or(Read(row, "Detail"), "此项暂无更多说明。");
                detail.Children.Add(new Border { Background = BrushResource("Line"), Height = 1 });
                detail.Children.Add(CheckExpander(CheckColumns(label, current, expected, CheckStatus(status), status),
                    new TextBlock
                    {
                        Text = explanation, Style = (Style)Window.Resources["Body"],
                        Margin = new Thickness(9, 0, 27, 11)
                    }, label + "。当前值 " + current + "，应有值 " + expected + "，状态 " + CheckStatus(status), false));
            }

            var heading = new DockPanel { Margin = new Thickness(8, 9, 4, 9) };
            if (issues > 0)
            {
                var tally = new TextBlock { Text = issues + " 项需关注", FontSize = 12, Foreground = BrushResource("Clay"), Margin = new Thickness(6, 0, 0, 0) };
                DockPanel.SetDock(tally, Dock.Right);
                heading.Children.Add(tally);
            }
            heading.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold });
            panel.Children.Add(new Border { Background = BrushResource("Line"), Height = 1 });
            bool expanded = group == "settings" || page == Page.Prerequisites || checkFilter != CheckFilter.All;
            panel.Children.Add(CheckExpander(heading, detail, title, expanded));
        }

        private Expander CheckExpander(object heading, object content, string name, bool expanded)
        {
            var expander = new Expander
            {
                Header = heading, Content = content, IsExpanded = expanded,
                Style = (Style)Window.Resources["CheckExpander"]
            };
            System.Windows.Automation.AutomationProperties.SetName(expander, name);
            return expander;
        }

        private Grid CheckColumns(string label, string current, string expected, string state, string status)
        {
            bool head = status.Length == 0;
            var grid = new Grid { Margin = new Thickness(0, 0, head ? 24 : 0, 0) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.08, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.15, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(104) });
            string[] values = { label, current, expected, state };
            for (int i = 0; i < values.Length; i++)
            {
                var cell = new TextBlock
                {
                    Text = values[i], FontSize = head || i == 3 ? 12 : 13,
                    TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center,
                    Foreground = BrushResource(head ? "Muted" : "Ink"),
                    Margin = new Thickness(i == 0 ? 9 : 4, head ? 6 : 8, 6, head ? 6 : 8)
                };
                if (i == 0 && !head) cell.FontWeight = FontWeights.SemiBold;
                if (!head && i == 3)
                {
                    string color = CheckColor(status);
                    cell.Foreground = BrushResource(color);
                    cell.Margin = new Thickness(6, 3, 6, 3);
                    var chip = new Border
                    {
                        Background = BrushResource(color == "Green" ? "GoodPaper" : color == "Red" ? "RedPaper"
                            : color == "Amber" ? "AmberPaper" : "QuietPaper"),
                        CornerRadius = new CornerRadius(4), Child = cell, HorizontalAlignment = HorizontalAlignment.Left,
                        VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 5, 2, 5)
                    };
                    Grid.SetColumn(chip, i);
                    grid.Children.Add(chip);
                }
                else
                {
                    Grid.SetColumn(cell, i);
                    grid.Children.Add(cell);
                }
            }
            return grid;
        }

        private static string CheckStatus(string status)
        {
            switch (status)
            {
                case "change": return "拟写入";
                case "follows": return "随时区生效";
                case "applied": return "已生效";
                case "kept": return "保留";
                case "ok": return "已确认";
                case "blocked": return "待处理";
                case "stale": return "凭证已过期";
                case "failed": return "未通过";
                case "paused": return "已暂停";
                case "attention": return "需关注";
                case "review": return "需核对";
                case "choice": return "待选择";
                case "restored": return "已恢复";
                case "withdrawn": return "已撤回";
                case "reference": return "仅供参考";
                case "waiting": return "待核对";
                case "uncollected": return "未读取";
                case "missing": return "未取得";
                case "pending": return "待验证";
                default: return "未知";
            }
        }

        private static string CheckColor(string status)
        {
            switch (status)
            {
                case "applied": case "ok": case "restored": case "withdrawn": return "Green";
                case "blocked": case "stale": case "failed": case "paused": return "Red";
                case "change": case "attention": case "review": case "choice": return "Amber";
                default: return "Muted";
            }
        }

        private void ShowRecovery()
        {
            ShowResult("恢复上次操作", "上次变更尚未完成", "恢复之前的配置后，可以继续安装、更新或试测节点。",
                "", false, ResultAction.Recover, true);
            RenderReceipt(SnapshotPart(homeSnapshot, "Receipt"), false, false);
        }

        private void ShowWork(string title, string phase, string detail, string note)
        {
            var progress = Find<ProgressBar>("WorkProgress");
            progress.IsIndeterminate = true;
            progress.Value = 0;
            Text("WorkPhase", phase);
            Text("WorkDetail", detail);
            Text("WorkNote", note);
            var summary = Find<TextBlock>("WorkProofSummary");
            summary.Visibility = Visibility.Collapsed;
            Find<UniformGrid>("WorkProofs").Visibility = Visibility.Collapsed;
            RenderStages(work == Operation.Update || work == Operation.Apply ? 0 : -1);
            Show(Page.Work, title, "此窗口会显示当前阶段和验收进度。");
        }

        private void ShowResult(string title, string heading, string message, string entry, bool success, ResultAction next, bool warning = false)
        {
            resultAction = next;
            Brush accent = BrushResource(success ? "Green" : warning ? "Amber" : "Red");
            Find<Border>("ResultMarkSurface").Background = BrushResource(success ? "GoodPaper" : warning ? "AmberPaper" : "RedPaper");
            Find<StackPanel>("ResultFacts").Children.Clear();
            Find<StackPanel>("ResultFacts").Visibility = Visibility.Collapsed;
            var mark = Find<TextBlock>("ResultMark");
            mark.Foreground = accent;
            mark.Text = success ? "✓" : "!";
            Text("ResultTitle", heading);
            Text("ResultMessage", message);
            Find<TextBlock>("ResultMessage").Visibility = Visible(!String.IsNullOrEmpty(message));
            Text("ResultEntry", entry);
            Find<TextBlock>("ResultEntry").Visibility = Visible(!String.IsNullOrEmpty(entry));
            Show(Page.Result, title, "");
        }

        private void RenderButtons()
        {
            bool idle = work == Operation.None;
            homeNav.IsEnabled = homeLoaded && idle && !recoveryPending;
            nodesNav.IsEnabled = homeNav.IsEnabled;
            auditNav.IsEnabled = homeNav.IsEnabled;
            homeNav.Tag = page == Page.Home || page == Page.Stop || page == Page.Prerequisites ? "Selected" : null;
            nodesNav.Tag = page == Page.Nodes || page == Page.Plan ? "Selected" : null;
            auditNav.Tag = page == Page.Audit ? "Selected" : null;
            homePrimary.Content = installed ? "保留配置并更新" : "查看安装条件";
            Find<Button>("HomeNodes").Visibility = Visible(installed);
            leaveButton.IsEnabled = idle;
            leaveButton.Visibility = Visible(work != Operation.Probe);
            backButton.Visibility = Visible(page == Page.Prerequisites || page == Page.Plan || page == Page.Audit || page == Page.Stop);
            backButton.Content = page == Page.Plan ? "‹ 返回节点设置" : "‹ 返回总览";
            probeButton.Visibility = Visible(page == Page.Nodes && work != Operation.Probe);
            probeButton.Content = String.IsNullOrEmpty(exitIpv4) ? "试测出口" : "重新试测";
            probeButton.IsEnabled = idle;
            cancelProbeButton.Visibility = Visible(work == Operation.Probe);
            cancelProbeButton.IsEnabled = probeCancellation != null && !probeCancellation.IsCancellationRequested;
            maskedNode.IsEnabled = idle;
            visibleNode.IsEnabled = idle;
            revealNode.IsEnabled = idle;
            zones.IsEnabled = idle;
            primaryButton.Visibility = Visible(page == Page.Nodes || page == Page.Plan || page == Page.Prerequisites || page == Page.Result);
            primaryButton.IsEnabled = idle && (page != Page.Nodes || CanReview()) && (page != Page.Plan || regionReady);
            if (page == Page.Nodes) primaryButton.Content = "查看变更清单 ›";
            else if (page == Page.Plan) primaryButton.Content = installed ? "应用这些变更" : "安装并应用";
            else if (page == Page.Prerequisites) primaryButton.Content = installed ? "开始更新" : "配置节点 ›";
            else if (page == Page.Result)
            {
                if (resultAction == ResultAction.Recover) primaryButton.Content = "恢复上次操作";
                else if (resultAction == ResultAction.Reload) primaryButton.Content = "重新读取状态";
                else if (resultAction == ResultAction.Nodes) primaryButton.Content = "返回节点设置";
                else primaryButton.Content = "返回总览";
            }
            string footer = page == Page.Nodes && idle ? regionReady ? "核对变更后，再决定是否应用。" : "先试测出口，再核对变更。" : "";
            Text("FooterText", footer);
            Find<TextBlock>("FooterText").Visibility = Visible(footer.Length > 0);
        }

        private async void Loaded(object sender, RoutedEventArgs args)
        {
            Window.Loaded -= Loaded;
            await LoadHome();
        }

        private async Task LoadHome()
        {
            work = Operation.Load;
            ShowWork("正在读取安装状态", "正在检查此电脑上的 Guard 配置", "读取 Windows 时区和防护出口。", "");
            bool loaded = await ReadHome();
            work = Operation.None;
            if (!loaded)
            {
                homeLoaded = false;
                ExitCode = 1;
                ShowResult("读取安装状态", "暂时无法读取安装状态", "请重新读取状态。", "", false, ResultAction.Reload);
                return;
            }
            bool update = startUpdate && installed && !recoveryPending;
            updateNeedsInstallation = startUpdate && !installed;
            ExitCode = startUpdate && !update ? 1 : 0;
            startUpdate = false;
            if (update) await Change(Operation.Update);
            else if (recoveryPending) ShowRecovery();
            else if (settings) ShowNodes();
            else ShowHome();
        }

        private async Task<bool> ReadHome()
        {
            IDictionary snapshot;
            await clearingPreview;
            try { snapshot = await Task.Run(() => actions.Home()); }
            catch (Exception) { return false; }
            if (snapshot == null) return false;

            homeLoaded = true;
            homeSnapshot = snapshot;
            installed = Read(snapshot, "Mode") == "Update";
            recoveryPending = Flag(snapshot, "RecoveryPending");
            bool ready = installed && Flag(snapshot, "Ready");
            Text("HomeState", ready ? "防护就绪" : installed ? "待核对" : "未安装");
            Text("HomeIpLabel", installed ? "已配置的唯一出口 IPv4" : "防护出口 IPv4");
            Text("HomeIp", Or(Read(snapshot, "ExitIpv4"), installed ? "暂未核对" : "待试测"));
            Text("HomeZone", Or(Read(snapshot, "TimeZone"), "暂不可用"));
            Text("HomeNode", Or(Read(snapshot, "NodeLabel"), installed ? "已保存" : "未配置"));
            Text("Version", "Claude Guard " + Or(Read(snapshot, "Version"), "1.0.1"));
            Brush stateColor = BrushResource(ready ? "Green" : installed ? "Amber" : "Muted");
            Find<TextBlock>("HomeState").Foreground = stateColor;
            Find<Ellipse>("HomeStateDot").Fill = stateColor;
            Find<Border>("HomeStateBadge").Background = BrushResource(ready ? "GoodPaper" : installed ? "AmberPaper" : "QuietPaper");
            LoadZones(snapshot["Zones"] as IEnumerable);
            if (String.IsNullOrEmpty(exitIpv4)) ResetProofText();
            return true;
        }

        private void LoadZones(IEnumerable catalog)
        {
            string selected = ZoneId();
            var items = new List<Zone>
            {
                new Zone("Automatic", "根据出口国家建议"),
                new Zone("Keep", "保留当前 Windows 时区"),
                new Zone("UsPacific", "美国西部 · 洛杉矶"),
                new Zone("Japan", "日本 · 东京")
            };
            var ids = new HashSet<string>(StringComparer.Ordinal) { "Automatic", "Keep", "UsPacific", "Japan" };
            if (catalog != null)
            {
                foreach (object item in catalog)
                {
                    var zone = item as IDictionary;
                    string id = Read(zone, "Id");
                    string label = Read(zone, "Label");
                    if (!String.IsNullOrEmpty(id) && !String.IsNullOrEmpty(label) && ids.Add(id))
                        items.Add(new Zone(id, label));
                }
            }
            settingZones = true;
            zones.ItemsSource = items;
            zones.SelectedValue = ids.Contains(selected) ? selected : "Automatic";
            settingZones = false;
        }

        private string ZoneId()
        {
            var zone = zones.SelectedItem as Zone;
            return zone == null ? "Automatic" : zone.Id;
        }

        private string NodeText()
        {
            return revealNode.IsChecked == true ? visibleNode.Text : maskedNode.Password;
        }

        private void Reveal(bool show)
        {
            changingText = true;
            if (show)
            {
                visibleNode.Text = maskedNode.Password;
                maskedNode.Clear();
            }
            else
            {
                maskedNode.Password = visibleNode.Text;
                visibleNode.Clear();
            }
            maskedNode.Visibility = Visible(!show);
            visibleNode.Visibility = Visible(show);
            changingText = false;
        }

        private void ClearNode()
        {
            changingText = true;
            maskedNode.Clear();
            visibleNode.Clear();
            changingText = false;
            revealNode.IsChecked = false;
        }

        private void ClearPreview(bool force = false)
        {
            bool hadPreview = !String.IsNullOrEmpty(exitIpv4);
            proofTimer.Stop();
            proofExpiry = null;
            regionSnapshot = null;
            reviewedZoneChoice = null;
            regionReady = false;
            exitIpv4 = null;
            country = null;
            if (!hadPreview && !force) return;
            Task priorClear = clearingPreview;
            clearingPreview = Task.Run(async () =>
            {
                await priorClear.ConfigureAwait(false);
                try { actions.ClearPreview(); }
                catch (Exception) { }
            });
        }

        private void NodeEdited()
        {
            if (changingText) return;
            ClearPreview();
            ResetProofText();
            RenderButtons();
        }

        private void ResetProofText()
        {
            Find<FrameworkElement>("ProofFacts").Visibility = Visibility.Collapsed;
            Find<TextBlock>("ProofExpiry").Visibility = Visibility.Collapsed;
            ShowProof("等待试测出口", "试测会用这条线路查询公网 IPv4。", false, false);
        }

        private void ShowProof(string title, string message, bool good, bool error)
        {
            Find<Border>("ProofCard").Background = BrushResource(good ? "GoodPaper" : error ? "RedPaper" : "QuietPaper");
            Find<TextBlock>("ProofTitle").Foreground = BrushResource(good ? "Green" : error ? "Red" : "Ink");
            Announce("ProofTitle", title);
            Announce("ProofDetail", message);
        }

        private async Task Probe()
        {
            if (work != Operation.None || page != Page.Nodes) return;
            string node = NodeText().Trim();
            ClearPreview();
            ResetProofText();
            if (!node.StartsWith("vless://", StringComparison.OrdinalIgnoreCase) || node.Length <= 8)
            {
                ShowProof("请填写 VLESS 节点链接", "从 Bettbox 复制完整链接，再试测出口。", false, true);
                RenderButtons();
                return;
            }

            work = Operation.Probe;
            probeCancellation = new CancellationTokenSource();
            CancellationToken token = probeCancellation.Token;
            ShowProof("正在试测出口", "正在通过这条线路查询公网 IPv4。", false, false);
            RenderButtons();
            try
            {
                await clearingPreview;
                IDictionary proof = await Task.Run(() => actions.Probe(node, token));
                token.ThrowIfCancellationRequested();
                if (!Flag(proof, "Ok") || String.IsNullOrEmpty(Read(proof, "ExitIpv4")))
                {
                    ClearPreview(true);
                    ShowProof("出口尚未核对", Or(Read(proof, "Message"), "请检查节点链接和 Bettbox 连接，再试测。"), false, true);
                }
                else
                {
                    exitIpv4 = Read(proof, "ExitIpv4");
                    country = Read(proof, "CountryCode");
                    proofExpiry = ReadTime(proof, "ExpiresUtc");
                    if (proofExpiry.HasValue) proofTimer.Start();
                    await ResolveRegion(token);
                }
            }
            catch (OperationCanceledException)
            {
                ClearPreview(true);
                ResetProofText();
                ShowProof("试测已取消", "可以重新试测这条线路。", false, false);
            }
            catch (Exception)
            {
                ClearPreview(true);
                ResetProofText();
                ShowProof("试测未完成", "请确认 Bettbox 已连接，再试测出口。", false, true);
            }
            finally
            {
                probeCancellation.Dispose();
                probeCancellation = null;
                work = Operation.None;
                RenderButtons();
                if (closeAfterProbe) Window.Close();
                else CheckProofExpiry();
            }
        }

        private void CancelProbe()
        {
            if (probeCancellation == null || probeCancellation.IsCancellationRequested) return;
            probeCancellation.Cancel();
            ShowProof("正在取消试测", "正在结束这次出口查询。", false, false);
            RenderButtons();
        }

        private async Task RefreshRegion()
        {
            work = Operation.Region;
            regionReady = false;
            ShowProof(ProofHeading(), "正在检查所选时区。", true, false);
            RenderButtons();
            try { await ResolveRegion(CancellationToken.None); }
            finally
            {
                work = Operation.None;
                RenderButtons();
                CheckProofExpiry();
            }
        }

        private bool CheckProofExpiry()
        {
            if (work != Operation.None || !proofExpiry.HasValue || DateTimeOffset.UtcNow < proofExpiry.Value) return false;
            ClearPreview();
            ResetProofText();
            ShowProof("试测结果已过期", "请重新试测出口，再核对变更。", false, true);
            if (page == Page.Plan)
            {
                var rows = Find<StackPanel>("CheckRows");
                rows.Children.Clear();
                rows.Children.Add(new TextBlock { Text = "试测结果已过期。返回节点设置重新试测。", Margin = new Thickness(8, 12, 8, 12) });
                displayedChecks = new List<IDictionary>();
                Text("ChecksLeadTitle", "试测结果已过期");
                Text("ChecksLeadDetail", "返回节点设置重新试测后，再核对本次变更。");
            }
            RenderButtons();
            return true;
        }

        private string ProofHeading()
        {
            return "出口已核对  " + exitIpv4 + (String.IsNullOrEmpty(country) ? "" : "（" + country + "）");
        }

        private async Task ResolveRegion(CancellationToken token)
        {
            string choice = ZoneId();
            IDictionary region;
            try { region = await Task.Run(() => actions.Region(choice)); }
            catch (Exception) { region = null; }
            token.ThrowIfCancellationRequested();
            string timeZone = Read(region, "TimeZone");
            regionSnapshot = region;
            reviewedZoneChoice = choice;
            proofExpiry = ReadTime(region, "ExpiresUtc") ?? proofExpiry;
            if (proofExpiry.HasValue) proofTimer.Start();
            List<IDictionary> checks = Checks(region);
            regionReady = CanReview() && !checks.Exists(row => Flag(row, "Blocks"));
            Text("ProofIp", exitIpv4);
            Text("ProofCountry", Or(Read(checks.Find(row => Read(row, "Key") == "country"), "Current"), Or(country, "未知")));
            Text("ProofZone", Or(timeZone, "待确认"));
            Find<FrameworkElement>("ProofFacts").Visibility = Visible(!String.IsNullOrEmpty(exitIpv4));
            Text("ProofExpiry", proofExpiry.HasValue ? "试测有效至 " + proofExpiry.Value.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture) : "");
            Find<TextBlock>("ProofExpiry").Visibility = Visible(proofExpiry.HasValue);
            if (CanReview())
            {
                string message = "应用后的 Windows 时区为 " + timeZone + "。";
                string note = Read(region, "Message");
                if (!String.IsNullOrEmpty(note)) message += "\n" + note;
                if (!regionReady) message += "\n变更暂不能应用。请在清单中查看待处理项。";
                ShowProof(ProofHeading(), message, regionReady, !regionReady);
            }
            else
            {
                string message = region == null ? "无法检查时区。请重新试测出口。" : "请选择城市，或保留当前 Windows 时区。";
                ShowProof(ProofHeading(), Or(Read(region, "Message"), message), false, region == null);
            }
        }

        private async Task Primary()
        {
            if (work != Operation.None) return;
            if (page == Page.Home) ShowPrerequisites();
            else if (page == Page.Prerequisites)
            {
                if (installed) await Change(Operation.Update);
                else
                {
                    ShowNodes();
                    maskedNode.Focus();
                }
            }
            else if (page == Page.Nodes) ShowPlan();
            else if (page == Page.Plan && regionReady && !CheckProofExpiry() && reviewedZoneChoice == ZoneId())
                await Change(Operation.Apply);
            else if (page == Page.Result)
            {
                if (resultAction == ResultAction.Recover) await Change(Operation.Recover);
                else if (resultAction == ResultAction.Reload) await LoadHome();
                else if (resultAction == ResultAction.Nodes) ShowNodes();
                else ShowHome();
            }
        }

        private async Task Change(Operation operation)
        {
            work = operation;
            operationId++;
            string choice = reviewedZoneChoice;
            bool firstInstall = !installed;
            string title = operation == Operation.Recover ? "恢复上次操作" : operation == Operation.Update
                ? "更新 Claude Guard" : firstInstall ? "安装 Claude Guard" : "应用节点";
            ShowWork(title, operation == Operation.Recover ? "正在恢复之前的配置" : "正在检查安装条件",
                operation == Operation.Update ? "沿用现有节点和 Windows 时区。" : "完成后会显示操作结果。",
                "操作完成后可以关闭此窗口。");
            progressTimer.Start();

            IDictionary result = null;
            try
            {
                await clearingPreview;
                result = await Task.Run(() => operation == Operation.Update ? actions.Update()
                    : operation == Operation.Recover ? actions.Recover() : actions.Apply(choice));
            }
            catch (Exception) { }
            progressTimer.Stop();
            operationId++;
            bool success = Flag(result, "Success");
            if (operation == Operation.Apply || success)
            {
                if (success) ClearNode();
                ClearPreview();
                ResetProofText();
            }
            Text("WorkPhase", "正在读取操作后的防护状态");
            Find<ProgressBar>("WorkProgress").IsIndeterminate = true;
            bool refreshed = await ReadHome();
            work = Operation.None;
            ExitCode = success ? 0 : 1;
            if (!refreshed) homeLoaded = false;
            ResultAction next = !refreshed ? ResultAction.Reload : recoveryPending ? ResultAction.Recover
                : settings || (!success && operation == Operation.Apply) ? ResultAction.Nodes : ResultAction.Home;
            if (success)
            {
                string entry = GuardedEntry(Read(result, "GuardedEntry"));
                string message = operation == Operation.Recover ? "可以继续安装、更新或更换节点。"
                    : String.IsNullOrEmpty(entry) ? Read(result, "Message") : "";
                if (!refreshed) message = (message + " 暂时无法刷新当前防护状态。").TrimStart();
                string heading = operation == Operation.Recover ? "恢复完成" :
                    refreshed && Flag(homeSnapshot, "Ready") ? "防护已就绪" : firstInstall ? "安装完成" :
                    operation == Operation.Apply ? "节点已应用" : "更新完成";
                ShowResult(title, heading, message, entry, true, next);
                RenderReceipt(result, true, refreshed && operation != Operation.Recover);
            }
            else
            {
                string message = Or(Read(result, "Message"), "请检查 Bettbox 连接和安装条件，再重试。");
                bool restored = Flag(result, "Restored") && operation != Operation.Recover;
                if (restored && Object.Equals(result["HadPrior"], false) && !message.Contains("已撤回"))
                    message += " 首次安装已撤回。";
                else if (restored && !Object.Equals(result["HadPrior"], false) && !message.Contains("已恢复"))
                    message += " 上一次配置已恢复。";
                ShowResult(restored ? "恢复回执" : title, operation == Operation.Recover ? "恢复未完成" :
                    restored ? "变更未生效" : "操作未完成", message, "", false, next, restored);
                RenderReceipt(result, false, refreshed && restored);
            }
        }

        private void RenderReceipt(IDictionary result, bool success, bool showConfiguration)
        {
            var facts = Find<StackPanel>("ResultFacts");
            if (showConfiguration)
            {
                AddFact(facts, "Guard 节点", Read(homeSnapshot, "NodeLabel"));
                AddFact(facts, "允许的出口 IPv4", Read(homeSnapshot, "ExitIpv4"));
                AddFact(facts, "Windows 时区", Read(homeSnapshot, "TimeZone"));
            }
            int proofs = Count(result, "RequiredProofs");
            if (proofs > 0)
                AddFact(facts, "连续核对", String.Format(CultureInfo.CurrentCulture, "{0} / {1} 次通过", Count(result, "FreshProofs"), proofs));
            if (Flag(result, "Restored"))
                AddFact(facts, "恢复状态", Object.Equals(result["HadPrior"], false) ? "首次安装已撤回" : "已恢复上一次配置");
            AddFact(facts, success ? "记录详情" : "处理详情", Read(result, "Details"));
            facts.Visibility = Visible(facts.Children.Count > 0);
        }

        private static string GuardedEntry(string entry)
        {
            if (entry == "Desktop") return "请从桌面的 Claude Desktop - Guarded 打开。";
            if (entry == "StartMenu") return "请从开始菜单的 Claude Desktop - Guarded 打开。";
            if (entry == "File") return "手动入口为 " + Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                @"ClaudeVPNGuard\daily\open-claude-daily.cmd");
            return "";
        }

        private async Task ReadProgress()
        {
            if (progressRead || work == Operation.None) return;
            int id = operationId;
            progressRead = true;
            IDictionary status = null;
            try { status = await Task.Run(() => actions.Progress()); }
            catch (Exception) { }
            finally { progressRead = false; }
            if (id != operationId || status == null) return;

            string phase = Read(status, "Phase");
            string title = null;
            string detail = null;
            switch (phase)
            {
                case "Preparing":
                case "Preflight":
                    if (work == Operation.Recover) break;
                    title = "正在检查安装条件"; detail = "检查 Guard 配置、Bettbox 连接和 Claude Desktop。"; break;
                case "Backup": title = "正在备份现有配置"; detail = "备份用于恢复节点和防护设置。"; break;
                case "Close": title = "正在准备防护切换"; detail = "等待现有防护退出后再应用变更。"; break;
                case "Install": title = "正在应用 Guard 防护"; detail = "正在写入文件和防护配置。"; break;
                case "Publish": title = "正在准备防护规则"; detail = "正在发布本次防护所需的规则。"; break;
                case "Start": title = "正在启动 Guard 防护"; detail = "启动防护后会检查实际出口和防火墙。"; break;
                case "Verify": title = "正在核对公网出口和防火墙"; detail = "等待防护连续通过检查。"; break;
                case "Commit":
                case "Completed": title = "正在确认最终状态"; detail = "正在完成本次操作。"; break;
                case "RollingBack": title = "正在恢复原设置"; detail = "正在用保存的记录恢复变更。"; break;
                case "RolledBack":
                case "RollbackIncomplete": title = "正在核对恢复结果"; detail = "正在检查当前防护配置。"; break;
            }
            if (work != Operation.Recover)
            {
                switch (phase)
                {
                    case "Preparing": case "Preflight": RenderStages(0); break;
                    case "Backup": RenderStages(1); break;
                    case "Close": RenderStages(2); break;
                    case "Install": case "Publish": case "Start": RenderStages(3); break;
                    case "Verify": case "Commit": case "Completed": RenderStages(4); break;
                }
            }
            int needed = Count(status, "RequiredProofs");
            int observed = Math.Min(Count(status, "FreshProofs"), needed);
            var progress = Find<ProgressBar>("WorkProgress");
            if (phase == "Verify" && needed > 0)
            {
                progress.IsIndeterminate = false;
                progress.Maximum = needed;
                progress.Value = observed;
                Find<TextBlock>("WorkProofSummary").Visibility = Visibility.Visible;
                Find<UniformGrid>("WorkProofs").Visibility = Visibility.Visible;
                Announce("WorkProofSummary", String.Format(CultureInfo.CurrentCulture, "连续通过  {0} / {1}", observed, needed));
                RenderProofSlots(observed, needed);
                detail = "核对唯一出口、防火墙规则和应用监控。";
                if (Read(status, "Status") == "WaitingForStoreWorker")
                    detail += " 正在确认 Claude Desktop 监控已启动。";
                int timeout = Count(status, "TimeoutSeconds");
                if (timeout > 0)
                    detail += String.Format(CultureInfo.CurrentCulture, " 已用时 {0} 秒，最长等待 {1} 秒。", Count(status, "ElapsedSeconds"), timeout);
            }
            else
            {
                progress.IsIndeterminate = true;
                Find<TextBlock>("WorkProofSummary").Visibility = Visibility.Collapsed;
                Find<UniformGrid>("WorkProofs").Visibility = Visibility.Collapsed;
            }
            if (title != null) Announce("WorkPhase", title);
            if (detail != null) Text("WorkDetail", detail);
        }

        private void RenderStages(int active)
        {
            if (displayedStage == active) return;
            displayedStage = active;
            var stages = Find<UniformGrid>("WorkStages");
            stages.Children.Clear();
            stages.Visibility = Visible(active >= 0);
            if (active < 0) return;
            string[] labels = { "检查条件", "保存恢复记录", "准备防护切换", "应用变更", "核对出口与防火墙" };
            for (int i = 0; i < labels.Length; i++)
            {
                var stage = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 0, 8, 0) };
                var mark = new Border
                {
                    Width = 22, Height = 22, CornerRadius = new CornerRadius(11), VerticalAlignment = VerticalAlignment.Top,
                    Background = BrushResource(i < active ? "GoodPaper" : i == active ? "Clay" : "QuietPaper"),
                    Margin = new Thickness(0, 0, 5, 0),
                    Child = new TextBlock
                    {
                        Text = i < active ? "✓" : (i + 1).ToString(CultureInfo.InvariantCulture), FontSize = 12,
                        HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                        Foreground = BrushResource(i < active ? "Green" : i == active ? "Sheet" : "Muted")
                    }
                };
                DockPanel.SetDock(mark, Dock.Left);
                stage.Children.Add(mark);
                stage.Children.Add(new TextBlock
                {
                    Text = labels[i], FontSize = 12, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center,
                    Foreground = BrushResource(i == active ? "Ink" : "Muted"),
                    FontWeight = i == active ? FontWeights.SemiBold : FontWeights.Normal
                });
                stages.Children.Add(stage);
            }
        }

        private void RenderProofSlots(int passed, int required)
        {
            var proofs = Find<UniformGrid>("WorkProofs");
            if (proofs.Children.Count != required)
            {
                proofs.Children.Clear();
                for (int i = 1; i <= required; i++)
                {
                    proofs.Children.Add(new Border
                    {
                        Margin = new Thickness(0, 0, i < required ? 5 : 0, 8), Padding = new Thickness(2, 3, 2, 3),
                        CornerRadius = new CornerRadius(4),
                        Child = new TextBlock { Text = i.ToString(CultureInfo.InvariantCulture), TextAlignment = TextAlignment.Center, FontSize = 12 }
                    });
                }
            }
            for (int i = 0; i < required; i++)
            {
                var slot = (Border)proofs.Children[i];
                slot.Background = BrushResource(i < passed ? "Clay" : "Sheet");
                ((TextBlock)slot.Child).Foreground = BrushResource(i < passed ? "Sheet" : "Muted");
            }
        }

        private void NavigateByKey(object sender, KeyEventArgs args)
        {
            if ((Keyboard.Modifiers & ModifierKeys.Alt) == 0) return;
            if (args.SystemKey == Key.D1 && homeNav.IsEnabled) { ShowHome(); homeNav.Focus(); args.Handled = true; }
            if (args.SystemKey == Key.D2 && nodesNav.IsEnabled) { NavigateNodes(); nodesNav.Focus(); args.Handled = true; }
            if (args.SystemKey == Key.D3 && auditNav.IsEnabled) { ShowAudit(); auditNav.Focus(); args.Handled = true; }
        }

        private void Closing(object sender, CancelEventArgs args)
        {
            if (work == Operation.None) return;
            args.Cancel = true;
            if (work == Operation.Probe)
            {
                closeAfterProbe = true;
                CancelProbe();
            }
            else if (page == Page.Work)
                Announce("WorkNote", "当前操作仍在进行，请等到此窗口显示结果后再关闭。");
            else ShowProof(ProofHeading(), "时区检查完成后可以关闭窗口。", false, false);
        }
    }
}
