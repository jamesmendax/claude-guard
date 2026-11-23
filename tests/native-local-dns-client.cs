using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

internal static class GuardLocalDnsClient
{
    [StructLayout(LayoutKind.Sequential)]
    private struct CustomServer
    {
        public uint Kind;
        public ulong Flags;
        public IntPtr Template;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] SocketAddress;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct QueryRequest
    {
        public uint Version;
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        public ushort Type;
        public ulong Options;
        public IntPtr ServerList;
        public uint InterfaceIndex;
        public IntPtr Completion, Context;
        public int NetworkQueryRequired;
        public uint NetworkIndex, CustomServerCount;
        public IntPtr CustomServers;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryResult
    {
        public uint Version;
        public int Status;
        public ulong Options;
        public IntPtr Records, Reserved;
    }

    public static int Main(string[] args)
    {
        SetErrorMode(3);
        try
        {
            if (args.Length != 3) return 87;
            bool policy = args[1] == "WindowsPolicy";
            string labels = policy ? "policybefore|policyblocked|upgraded" : "before|container|after";
            if (!Regex.IsMatch(args[0], @"\A(" + labels + @")\.g[a-f0-9]{32}\.test\.\z")) return 87;
            if (GuardFixtureClient.GetAppContainerIdentity() != args[2]) return 9;

            if (policy)
            {
                var request = new QueryRequest { Version = 1, Name = args[0], Type = 1,
                    Options = 0x808 /* DNS_QUERY_NO_MULTICAST | DNS_QUERY_BYPASS_CACHE */ };
                return Query(ref request);
            }
            IPAddress local;
            if (!IPAddress.TryParse(args[1], out local) || local.AddressFamily != AddressFamily.InterNetwork ||
                !IPAddress.IsLoopback(local) || local.ToString() != args[1]) return 87;
            var server = new CustomServer { Kind = 1, SocketAddress = new byte[32] };
            server.SocketAddress[0] = 2; // AF_INET, default DNS port
            local.GetAddressBytes().CopyTo(server.SocketAddress, 4);
            var buffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CustomServer)));
            try
            {
                Marshal.StructureToPtr(server, buffer, false);
                var request = new QueryRequest { Version = 3, Name = args[0], Type = 1,
                    Options = 0x800 /* DNS_QUERY_NO_MULTICAST */, CustomServerCount = 1, CustomServers = buffer };
                return Query(ref request);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 13;
        }
    }

    private static int Query(ref QueryRequest request)
    {
        var result = new QueryResult { Version = 1 };
        int status = DnsQueryEx(ref request, ref result, IntPtr.Zero);
        if (result.Records != IntPtr.Zero) DnsFree(result.Records, 1);
        return status;
    }

    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);
    [DllImport("dnsapi.dll")]
    private static extern int DnsQueryEx(ref QueryRequest request, ref QueryResult result, IntPtr cancel);
    [DllImport("dnsapi.dll")]
    private static extern void DnsFree(IntPtr records, int freeType);
}
