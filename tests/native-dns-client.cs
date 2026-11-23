using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using ClaudeGuard.Network;

public static class GuardNativeDnsFixture
{
    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr extra,
        out IntPtr records, IntPtr reserved);
    [DllImport("dnsapi.dll")]
    private static extern void DnsFree(IntPtr records, int freeType);

    public static IDisposable CloseOnlyFixtureImage(string image)
    {
        string path = Path.GetFullPath(image);
        var template = GuardPolicy.Create(new[] {path}, new[] {path}, null, null,
            Path.Combine(Path.GetDirectoryName(path), "unused-relay.exe"), 18793, "127.0.0.1", 53);
        var deny = Array.FindAll(template.Baseline, r => !r.Permit && r.Conditions.Length == 1 &&
            r.Conditions[0].Field == GuardPolicy.AppId &&
            String.Equals((string)r.Conditions[0].Data, path, StringComparison.OrdinalIgnoreCase));
        if (deny.Length != 4 || deny.Select(r => r.Layer).Distinct().Count() != 4)
            throw new InvalidOperationException("Unexpected application block policy.");
        return new WindowsPolicySession(new PolicyPlan(deny, new Rule[0]));
    }

    public static int Main(string[] args)
    {
        if ((args.Length != 1 && args.Length != 2) || !Regex.IsMatch(args[0], @"\A(before|blocked|after)\.g[a-f0-9]{32}\.test\.\z")) return 87;
        string expectedIdentity = args.Length == 2 ? args[1] : "none";
        if (GuardFixtureClient.GetAppContainerIdentity() != expectedIdentity) return 9;
        IntPtr records;
        // Fully qualified unicast A query through Windows' configured resolver and NRPT.
        int result = DnsQuery_W(args[0], 1, 0x800 /* DNS_QUERY_NO_MULTICAST */, IntPtr.Zero, out records, IntPtr.Zero);
        if (records != IntPtr.Zero) DnsFree(records, 1);
        return result;
    }
}
