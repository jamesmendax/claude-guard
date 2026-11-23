#Requires -Version 5.1
[CmdletBinding()]
param([string]$PreviewDirectory)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$wpf = Join-Path $framework 'WPF'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('guard-native-window-test-'+[guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($scratch)
if($PreviewDirectory){
    $PreviewDirectory = [IO.Path]::GetFullPath($PreviewDirectory)
    $null = [IO.Directory]::CreateDirectory($PreviewDirectory)
}

$fixture = @'
using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

internal interface IGuardSetupActions
{
    IDictionary Home(); IDictionary Probe(string node, CancellationToken token); IDictionary Region(string zoneId);
    IDictionary Update(); IDictionary Apply(string zoneId); IDictionary Recover(); IDictionary Progress(); void ClearPreview();
}

internal sealed class FakeSetup : IGuardSetupActions
{
    internal bool Installed, Pending, FailUpdate, FailApply, SlowProbe, WindowError, Expired, BlockApply;
    internal volatile int Updates, Probes, Clears, Recoveries;
    internal readonly ManualResetEventSlim PermitUpdate = new ManualResetEventSlim();
    internal string AppliedZone;
    internal string StopKind;
    private readonly int ui = Thread.CurrentThread.ManagedThreadId;

    private void AssertWorker()
    {
        if (Thread.CurrentThread.ManagedThreadId == ui) throw new Exception("Called on UI thread.");
    }

    public IDictionary Home()
    {
        AssertWorker();
        return new Hashtable { { "Mode", Installed ? "Update" : "Fresh" }, { "RecoveryPending", Pending }, { "Ready", Installed },
            { "NodeLabel", Installed ? "Bettbox · 美国西部" : "" }, { "ExitIpv4", Installed ? "198.51.100.17" : "" },
            { "TimeZone", "美国西部 · 洛杉矶" }, { "Version", "1.0.1" }, { "GuardedEntry", Installed ? "Desktop" : "" },
            { "LastStop", StopRecord() }, { "LastWindowError", WindowError ? new Hashtable {
                { "HasRecord", true }, { "TimeUtc", "2026-11-23T09:07:02Z" }, { "Title", "设置窗口意外退出" },
                { "Summary", "上次打开设置时发生错误。" }, { "Source", "Guard 设置窗口错误记录" }, { "HResult", "0x80004005" }
            } : null }, { "Checks", new[] {
                Check("zone", "settings", "Windows 时区", "洛杉矶", "洛杉矶", "ok", "Guard 会沿用此时区。", false, false),
                Check("worker", "protection", "商店版监控", "待核对", "持续守护", "attention", "Guard 正在等待商店版监控确认启动。", true, false),
                Check("bettbox", "protection", "Bettbox", "等待核对", "开启 TUN 模式", "pending", "Guard 会在开始后检查连接。", false, false),
                Check("store-desktop", "protection", "商店版 Claude Desktop", "等待核对", "已安装", "pending", "请先保存正在进行的工作。", false, false),
                Check("closed-desktop", "protection", "关闭 Claude Desktop", "等待核对", "可安全关闭", "pending", "Guard 会检查相关进程。", false, false),
                Check("display", "environment", "Claude 偏好", "只能手动查看", "按需设置", "reference", "此项由用户手动查看。", false, false)
            } }, { "Zones", new[] {
                new Hashtable { { "Id", "Japan" }, { "Label", "日本 · 东京" } },
                new Hashtable { { "Id", "Europe/Paris" }, { "Label", "法国 · 巴黎" } }
            } } };
    }

    private IDictionary StopRecord()
    {
        if (StopKind == null) return new Hashtable { { "HasRecord", false }, { "ReadState", "Missing" } };
        if (StopKind == "Unavailable") return new Hashtable { { "HasRecord", false }, { "ReadState", "Unreadable" } };
        if (StopKind == "Nonzero") return new Hashtable {
            { "HasRecord", true }, { "TimeUtc", "2026-11-23T04:17:31Z" }, { "ReadState", "Readable" },
            { "Title", "Claude 退出时返回了非零退出码" },
            { "Summary", "启动器记录了此次启动的 Claude 主进程返回的退出码，具体原因无法确认。" },
            { "Action", "防护已就绪。请从原入口手动打开 Claude。" },
            { "Network", "本次记录没有联网许可已关闭的确认。" }, { "Source", "防护入口记录" },
            { "SourceKind", "LauncherObserved" }, { "ExitCode", "0xC0000005" },
            { "Details", "由当前 Windows 用户下的 Guard 启动器记录。" }
        };
        bool guard = StopKind == "Guard";
        return new Hashtable {
            { "HasRecord", true }, { "TimeUtc", "2026-11-23T04:17:31Z" },
            { "Title", guard ? "防护关闭了 Claude" : "Claude Desktop 已退出，原因未知" },
            { "Summary", guard ? "公网 IPv4 与设置中允许的出口不符。" : "启动器记录到进程退出，无法判断为何退出。" },
            { "Action", guard ? "确认 Bettbox 连接，然后重新核对出口。" : "如果反复退出，先查看 Claude Desktop 的帮助。" },
            { "Network", guard ? "防护已确认断开联网，Claude 已退出。" : "本次记录没有联网许可已关闭的确认。" },
            { "Source", guard ? "Guard 防护停止记录" : "Guard 启动器退出记录" },
            { "SourceKind", guard ? "GuardConfirmed" : "LauncherObserved" },
            { "ExitCode", guard ? "" : "1" }, { "Details", guard ? "记录中的检查项为公网出口 IPv4。" : "" }
        };
    }

    private static Hashtable Check(string key, string group, string label, string current, string expected,
        string status, string detail, bool issue, bool change)
    {
        return new Hashtable { { "Key", key }, { "Group", group }, { "Label", label }, { "Current", current },
            { "Expected", expected }, { "Status", status }, { "Detail", detail }, { "Issue", issue }, { "Change", change },
            { "Blocks", false } };
    }

    public IDictionary Probe(string node, CancellationToken token)
    {
        AssertWorker();
        Probes++;
        if (SlowProbe) token.WaitHandle.WaitOne(12000);
        token.ThrowIfCancellationRequested();
        if (node != "vless://synthetic") return new Hashtable { { "Ok", false }, { "Message", "测试节点不可用。" } };
        return new Hashtable { { "Ok", true }, { "ExitIpv4", "203.0.113.28" }, { "CountryCode", "JP" },
            { "ExpiresUtc", DateTimeOffset.UtcNow.AddSeconds(Expired ? -1 : 300).ToString("o") } };
    }

    public IDictionary Region(string zoneId)
    {
        AssertWorker();
        if (zoneId == "Automatic") return new Hashtable { { "RequiresChoice", true }, { "Message", "请选择城市。" } };
        var exit = Check("exit", "settings", "允许的出口 IPv4", "198.51.100.17", "203.0.113.28", "change",
            "Guard 会用本次试测的出口。", false, true);
        var worker = Check("worker", "protection", "商店版监控", "待核对", "持续守护", "attention",
            "应用变更后核对。", true, false);
        worker["Blocks"] = BlockApply;
        return new Hashtable { { "RequiresChoice", false }, { "TimeZone", zoneId == "Japan" ? "日本 · 东京" : "美国西部 · 洛杉矶" },
            { "Checks", new[] { exit, worker } } };
    }

    public IDictionary Update()
    {
        AssertWorker();
        Updates++;
        if (!PermitUpdate.Wait(TimeSpan.FromSeconds(12))) throw new TimeoutException();
        return FailUpdate
            ? new Hashtable { { "Success", false }, { "Restored", true }, { "Message", "测试更新失败。" } }
            : new Hashtable { { "Success", true }, { "GuardedEntry", "Desktop" } };
    }

    public IDictionary Apply(string zoneId)
    {
        AssertWorker();
        AppliedZone = zoneId;
        if (FailApply)
            return new Hashtable { { "Success", false }, { "Restored", true }, { "HadPrior", false }, { "Message", "测试安装失败。" } };
        Installed = true;
        return new Hashtable { { "Success", true }, { "GuardedEntry", "StartMenu" } };
    }

    public IDictionary Recover()
    {
        AssertWorker();
        Recoveries++;
        Pending = false;
        return new Hashtable { { "Success", true }, { "Restored", true } };
    }

    public IDictionary Progress()
    {
        AssertWorker();
        return new Hashtable { { "Phase", "Verify" }, { "FreshProofs", 3 }, { "RequiredProofs", 6 } };
    }

    public void ClearPreview() { AssertWorker(); Clears++; }
}

internal static class WindowTests
{
    [STAThread]
    private static int Main(string[] args)
    {
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
        try { Test(args.Length == 0 ? "" : args[0]); return 0; }
        catch (Exception error) { Console.Error.WriteLine(error.GetType().FullName + ": " + error.Message); return 1; }
    }

    private static T Find<T>(Window window, string name) where T : FrameworkElement { return (T) window.FindName(name); }
    private static string Text(Window window, string name) { return Find<TextBlock>(window, name).Text; }
    private static bool Shown(Window window, string name) { return Find<FrameworkElement>(window, name).IsVisible; }

    private static bool ContainsText(DependencyObject root, string value)
    {
        var text = root as TextBlock;
        if (text != null && text.Text.Contains(value)) return true;
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            if (ContainsText(VisualTreeHelper.GetChild(root, i), value)) return true;
        return false;
    }

    private static void Pump()
    {
        var frame = new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }

    private static void Assert(bool passed, string label)
    {
        if (!passed) throw new InvalidOperationException(label);
        Console.WriteLine("PASS " + label);
    }

    private static void Until(Func<bool> condition, string label)
    {
        Stopwatch time = Stopwatch.StartNew();
        while (!condition() && time.Elapsed.TotalSeconds < 10) { Pump(); Thread.Sleep(15); }
        if (!condition()) throw new TimeoutException(label);
    }

    private static Window Show(FakeSetup fake, bool settings, bool autoUpdate)
    {
        Window window = new GuardSetupWindow.View(fake, settings, autoUpdate).Window;
        window.WindowStartupLocation = WindowStartupLocation.Manual;
        window.ShowInTaskbar = false;
        window.ShowActivated = false;
        window.Left = -10000;
        window.Top = -10000;
        window.Show();
        Pump();
        return window;
    }

    private static void Click(Window window, string name)
    {
        var button = Find<Button>(window, name);
        if (!button.IsEnabled || !button.IsVisible) throw new InvalidOperationException(name + " is unavailable.");
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Pump();
    }

    private static void Capture(Window window, string directory, string name)
    {
        if (String.IsNullOrEmpty(directory)) return;
        var content = (FrameworkElement)window.Content;
        window.UpdateLayout();
        Pump();
        var image = new RenderTargetBitmap((int)Math.Ceiling(content.ActualWidth), (int)Math.Ceiling(content.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        image.Render(content);
        var png = new PngBitmapEncoder();
        png.Frames.Add(BitmapFrame.Create(image));
        using (var file = File.Create(Path.Combine(directory, name + ".png"))) png.Save(file);
    }

    private static void Test(string preview)
    {
        var existing = new FakeSetup { Installed = true, StopKind = "Guard" };
        var window = Show(existing, false, false);
        Until(() => Shown(window, "HomePage"), "Existing landing page");
        Assert(Text(window, "HomeIp") == "198.51.100.17" && Text(window, "HomeZone").Contains("洛杉矶") &&
            (string)Find<Button>(window, "HomePrimary").Content == "保留配置并更新", "Existing status and preserve-update action");
        Assert(((SolidColorBrush)window.Background).Color == Color.FromRgb(248, 246, 240) &&
            ((SolidColorBrush)Find<Button>(window, "HomePrimary").Background).Color == Color.FromRgb(168, 81, 56),
            "Native overview uses the approved cream and terracotta palette");
        Assert(Text(window, "HomeStopSummary").Contains("公网 IPv4 与设置中允许的出口不符") &&
            Text(window, "HomeStopSummary").Contains(DateTimeOffset.Parse("2026-11-23T04:17:31Z").ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")),
            "Overview surfaces the latest reason and local time");
        Capture(window, preview, "setup-home");
        Click(window, "HomeStopDetails");
        Assert(Shown(window, "StopPage") && Text(window, "StopTitle") == "防护关闭了 Claude" &&
            ContainsText(Find<StackPanel>(window, "StopFacts"), "先确认联网许可已关闭") &&
            ContainsText(Find<StackPanel>(window, "StopFacts"), "Guard 防护停止记录") &&
            !Shown(window, "WindowErrorCard"), "Guard-confirmed stop has reason, network, action and source");
        Capture(window, preview, "setup-last-stop");
        Click(window, "BackButton");
        Click(window, "HomeAudit");
        Assert(Shown(window, "ChecksPage") && ContainsText(Find<StackPanel>(window, "CheckRows"), "Windows 时区") &&
            ContainsText(Find<StackPanel>(window, "CheckRows"), "应有值"), "Audit displays actual rows and comparison columns");
        Click(window, "IssueChecks");
        Assert(!ContainsText(Find<StackPanel>(window, "CheckRows"), "Windows 时区") &&
            ContainsText(Find<StackPanel>(window, "CheckRows"), "商店版监控"), "Issue filter keeps only flagged rows");
        var auditRows = Find<StackPanel>(window, "CheckRows");
        var group = (Expander)auditRows.Children[1];
        var detail = (StackPanel)group.Content;
        var issue = (Expander)detail.Children[2];
        issue.IsExpanded = true;
        Pump();
        Assert(ContainsText(issue, "等待商店版监控确认启动"), "Audit row can expand to show its reason");
        Capture(window, preview, "setup-audit");
        Click(window, "BackButton");
        Click(window, "HomePrimary");
        Assert(Shown(window, "ChecksPage") && Text(window, "PageTitle") == "保留配置并更新" && existing.Updates == 0,
            "Manual update shows preflight conditions before making any change");
        Click(window, "PrimaryButton");
        Until(() => Find<ProgressBar>(window, "WorkProgress").Value == 3, "Live update progress");
        window.Close();
        Assert(window.IsVisible && Text(window, "WorkNote").Contains("显示结果") &&
            Find<UniformGrid>(window, "WorkProofs").Children.Count == 6, "Update keeps progress visible and renders six proof slots");
        Capture(window, preview, "setup-progress");
        existing.PermitUpdate.Set();
        Until(() => Shown(window, "ResultPage"), "Update result");
        Assert(existing.Updates == 1 && existing.Probes == 0 && Text(window, "ResultEntry").Contains("Claude Desktop - Guarded"), "Update leaves the node alone and returns the protected shortcut");
        Capture(window, preview, "setup-result");
        window.Close();

        var fresh = new FakeSetup();
        window = Show(fresh, false, true);
        Until(() => Shown(window, "HomePage"), "Fresh first page");
        Assert(fresh.Updates == 0, "Automatic update never starts a fresh install");
        Assert(Text(window, "HomeStopSummary") == "暂无停止记录" && !Shown(window, "HomeWindowError"), "An empty stop history is labelled accurately");
        Click(window, "HomeStopDetails");
        Assert(Text(window, "StopTitle") == "暂无停止记录" && !Shown(window, "WindowErrorCard"), "Empty history details stay readable");
        Click(window, "BackButton");
        Click(window, "HomePrimary");
        Assert(Text(window, "PageTitle") == "安装前检查" && ContainsText(Find<StackPanel>(window, "CheckRows"), "商店版 Claude Desktop"),
            "Fresh installation shows its prerequisites");
        Capture(window, preview, "setup-install-prerequisites");
        Click(window, "PrimaryButton");
        var password = Find<PasswordBox>(window, "MaskedNode");
        var zones = Find<ComboBox>(window, "Zones");
        var apply = Find<Button>(window, "PrimaryButton");
        Assert(password.IsVisible && !Shown(window, "VisibleNode") && !apply.IsEnabled && zones.Items.Count == 5, "Node starts masked with deduplicated presets and optional catalog choices");
        password.Password = "invalid";
        Click(window, "ProbeButton");
        Assert(fresh.Probes == 0 && Text(window, "ProofTitle").Contains("VLESS"), "Incomplete link stops before the background call");
        password.Password = "vless://synthetic";
        Click(window, "ProbeButton");
        Until(() => Text(window, "ProofDetail") == "请选择城市。", "Automatic region requires a choice");
        Assert(!apply.IsEnabled && Text(window, "ProofTitle").Contains("203.0.113.28"), "Verified exit is shown while apply waits for a time zone");
        zones.SelectedValue = "Japan";
        Until(() => apply.IsEnabled, "Explicit time zone resolves");
        Assert(fresh.Probes == 1 && Text(window, "ProofDetail").Contains("东京"), "Tokyo preview reuses the same verified exit");
        Capture(window, preview, "setup-node-settings");
        var reveal = Find<CheckBox>(window, "RevealNode");
        reveal.IsChecked = true;
        var visible = Find<TextBox>(window, "VisibleNode");
        Assert(visible.IsVisible && !password.IsVisible && apply.IsEnabled, "Explicit reveal retains the existing preview");
        int clears = fresh.Clears;
        visible.Text += "x";
        Assert(!apply.IsEnabled, "Editing the visible link immediately disables apply");
        Until(() => fresh.Clears > clears, "Background cleanup after editing the link");
        reveal.IsChecked = false;
        Assert(password.Password.EndsWith("x") && visible.Text.Length == 0, "Masking removes the clear-text field contents");
        password.Password = "vless://synthetic";
        fresh.SlowProbe = true;
        Click(window, "ProbeButton");
        Click(window, "CancelProbeButton");
        Until(() => Text(window, "ProofTitle") == "试测已取消", "Cancelable probe");
        Assert(!apply.IsEnabled, "Canceled probe leaves apply disabled");
        fresh.SlowProbe = false;
        Click(window, "ProbeButton");
        Until(() => apply.IsEnabled, "Repeat probe");
        Click(window, "PrimaryButton");
        Assert(Shown(window, "ChecksPage") && Text(window, "PageTitle") == "核对本次变更" && fresh.AppliedZone == null &&
            ContainsText(Find<StackPanel>(window, "CheckRows"), "203.0.113.28"), "Review presents the measured target before applying");
        Click(window, "ChangeChecks");
        Assert(!ContainsText(Find<StackPanel>(window, "CheckRows"), "商店版监控") &&
            ContainsText(Find<StackPanel>(window, "CheckRows"), "允许的出口 IPv4"), "Change filter shows only proposed changes");
        Click(window, "AllChecks");
        Capture(window, preview, "setup-change-review");
        Click(window, "BackButton");
        password.Password = "vless://synthetic2";
        Assert(!apply.IsEnabled && fresh.AppliedZone == null, "Editing after reviewing invalidates the proof and confirmation");
        password.Password = "vless://synthetic";
        fresh.Expired = true;
        Click(window, "ProbeButton");
        Until(() => Text(window, "ProofTitle") == "试测结果已过期", "Expired proof is invalidated");
        Assert(!apply.IsEnabled, "Expired proof cannot open a confirmation");
        fresh.Expired = false;
        fresh.BlockApply = true;
        Click(window, "ProbeButton");
        Until(() => Shown(window, "ProbeButton"), "Blocked plan returns to idle");
        Click(window, "PrimaryButton");
        Click(window, "IssueChecks");
        Assert(!apply.IsEnabled && Text(window, "ChecksLeadTitle") == "暂不能应用" &&
            ContainsText(Find<StackPanel>(window, "CheckRows"), "商店版监控"), "Backend blocker can be reviewed and prevents applying");
        Click(window, "BackButton");
        fresh.BlockApply = false;
        Click(window, "ProbeButton");
        Until(() => apply.IsEnabled, "Probe before final confirmation");
        Click(window, "PrimaryButton");
        Click(window, "PrimaryButton");
        Until(() => Shown(window, "ResultPage"), "Fresh result");
        Assert(fresh.AppliedZone == "Japan" && password.Password.Length == 0 && Text(window, "ResultEntry").Contains("开始菜单"), "Fresh install applies the selected time zone and clears the link");
        window.Close();

        var recovery = new FakeSetup { Installed = true, Pending = true };
        window = Show(recovery, true, true);
        Until(() => Shown(window, "ResultPage"), "Recovery entry");
        Assert(!Find<Button>(window, "NodesNav").IsEnabled && recovery.Updates == 0 && Text(window, "ResultTitle").Contains("尚未完成"), "Pending recovery prevents update and probe");
        Capture(window, preview, "setup-recovery");
        Click(window, "PrimaryButton");
        Until(() => Text(window, "ResultTitle") == "恢复完成", "Recovery result");
        Click(window, "PrimaryButton");
        Assert(recovery.Recoveries == 1 && Shown(window, "NodesPage"), "Recovery restores the settings entry within the same window");
        window.Close();

        var retry = new FakeSetup { Installed = true, FailUpdate = true };
        retry.PermitUpdate.Set();
        window = Show(retry, false, true);
        Until(() => Shown(window, "ResultPage"), "Automatic update failure");
        Assert(retry.Updates == 1 && Text(window, "ResultMessage").Contains("上一次配置已恢复"), "Automatic update surfaces rollback details in the same window");
        window.Close();

        window = Show(new FakeSetup { Installed = true, StopKind = "Exit" }, false, false);
        Until(() => Shown(window, "HomePage"), "Observed app exit");
        Click(window, "HomeStopDetails");
        Assert(Text(window, "StopTitle").Contains("原因未知") && ContainsText(Find<StackPanel>(window, "StopFacts"), "先后顺序未知") &&
            ContainsText(Find<StackPanel>(window, "StopFacts"), "Guard 启动器退出记录"),
            "App exit without a cause does not imply Guard stopped it");
        window.Close();

        window = Show(new FakeSetup { Installed = true, StopKind = "Nonzero" }, false, false);
        Until(() => Shown(window, "HomePage"), "Exit code readback");
        Click(window, "HomeStopDetails");
        Assert(Text(window, "StopSummary").Contains("具体原因无法确认") &&
            ContainsText(Find<StackPanel>(window, "StopFacts"), "0xC0000005") &&
            ContainsText(Find<StackPanel>(window, "StopFacts"), "先后顺序未知"),
            "An observed nonzero exit retains its hexadecimal code without attributing a root cause");
        Capture(window, preview, "setup-observed-exit");
        window.Close();

        window = Show(new FakeSetup { Installed = true, StopKind = "Unavailable", WindowError = true }, false, false);
        Until(() => Shown(window, "HomePage"), "Settings window error");
        Assert(Text(window, "HomeStopSummary") == "暂时无法读取停止记录" && Shown(window, "HomeWindowError"),
            "Unavailable session history and a settings-window crash are separate on the overview");
        Click(window, "HomeStopDetails");
        Assert(Shown(window, "WindowErrorCard") && Text(window, "WindowErrorTitle") == "设置窗口意外退出" &&
            ContainsText(Find<StackPanel>(window, "WindowErrorFacts"), "0x80004005"),
            "Settings-window crash details can be reached without a session-stop record");
        Capture(window, preview, "setup-window-error");
        window.Close();

        window = Show(new FakeSetup { FailApply = true }, true, false);
        Until(() => Shown(window, "NodesPage"), "Fresh installation rollback");
        Find<ComboBox>(window, "Zones").SelectedValue = "Japan";
        Find<PasswordBox>(window, "MaskedNode").Password = "vless://synthetic";
        Click(window, "ProbeButton");
        Until(() => Find<Button>(window, "PrimaryButton").IsEnabled, "Fresh installation ready to review");
        Click(window, "PrimaryButton");
        Click(window, "PrimaryButton");
        Until(() => Shown(window, "ResultPage"), "Fresh rollback receipt");
        Assert(Text(window, "ResultMessage").Contains("首次安装已撤回") &&
            !Text(window, "ResultMessage").Contains("上一次配置"), "Fresh install rollback reports withdrawal without claiming a previous configuration");
        Capture(window, preview, "setup-rollback-receipt");
        window.Close();
    }
}
'@

try {
    $test = Join-Path $scratch 'WindowTests.cs'
    $exe = Join-Path $scratch 'WindowTests.exe'
    [IO.File]::WriteAllText($test, $fixture, [Text.UTF8Encoding]::new($true))
    $references = @('WindowsBase.dll','PresentationCore.dll','PresentationFramework.dll','UIAutomationTypes.dll' | ForEach-Object { '/reference:'+(Join-Path $wpf $_) })
    $references += '/reference:'+(Join-Path $framework 'System.Xaml.dll')
    $xaml = Join-Path $project 'release\GuardSetupWindow.xaml'
    $source = Join-Path $project 'release\GuardSetupWindow.cs'
    & (Join-Path $framework 'csc.exe') /nologo /target:exe /platform:x64 /langversion:5 /codepage:65001 @references "/resource:$xaml,Guard.SetupWindow" "/out:$exe" $source $test
    if($LASTEXITCODE -ne 0){throw 'WPF test fixture compilation failed.'}
    if($PreviewDirectory){& $exe $PreviewDirectory}else{& $exe}
    if($LASTEXITCODE -ne 0){throw 'Native WPF window tests failed.'}
} finally {
    if([IO.Path]::GetDirectoryName($scratch) -ieq [IO.Path]::GetTempPath().TrimEnd('\') -and
        [IO.Path]::GetFileName($scratch) -cmatch '\Aguard-native-window-test-[0-9a-f]{32}\z'){
        foreach($name in 'WindowTests.cs','WindowTests.exe'){
            $file = Join-Path $scratch $name
            if([IO.File]::Exists($file)){[IO.File]::Delete($file)}
        }
        [IO.Directory]::Delete($scratch)
    }
}
