#Requires -Version 5.1
$ErrorActionPreference='Stop'
$folder=Join-Path ([IO.Path]::GetTempPath()) ('guard-dns-scope-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $folder
$image=Join-Path $folder 'dns-scope-probe.exe'
try{
    Add-Type -OutputAssembly $image -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

static class DnsScopeProbe
{
    private const uint SuppressFaultDialogs = 0x0001 | 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    private struct Settings
    {
        public uint Version;
        public ulong Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Server
    {
        public uint Kind;
        public ulong Flags;
        public IntPtr Template;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Address;
    }

    [DllImport("dnsapi.dll")]
    private static extern uint DnsSetApplicationSettings(uint count, ref Server server, ref Settings settings);

    [DllImport("dnsapi.dll")]
    private static extern uint DnsGetApplicationSettings(out uint count, out IntPtr servers, ref Settings settings);

    [DllImport("dnsapi.dll")]
    private static extern void DnsFreeCustomServers(ref uint count, ref IntPtr servers);

    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);

    private static uint Read(out ulong flags)
    {
        uint count;
        IntPtr servers;
        var settings = new Settings { Version = 1 };
        uint status = DnsGetApplicationSettings(out count, out servers, ref settings);
        if (status != 0) throw new InvalidOperationException("DnsGetApplicationSettings error " + status);
        flags = settings.Flags;
        uint observed = count;
        if (servers != IntPtr.Zero) DnsFreeCustomServers(ref count, ref servers);
        return observed;
    }

    public static int Main(string[] args)
    {
        SetErrorMode(SuppressFaultDialogs);
        try { return Run(args); }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        ulong flags;
        uint before = Read(out flags);
        if (args.Length == 1 && args[0] == "child")
        {
            Console.WriteLine(before);
            return 0;
        }

        // SOCKADDR_IN for a reserved documentation address. This probe sends no query.
        var server = new Server { Kind = 1, Address = new byte[32] };
        server.Address[0] = 2;
        server.Address[4] = 192;
        server.Address[6] = 2;
        server.Address[7] = 53;
        var exclusive = new Settings { Version = 1, Flags = 1 };
        uint status = DnsSetApplicationSettings(1, ref server, ref exclusive);
        if (status != 0) throw new InvalidOperationException("DnsSetApplicationSettings error " + status);
        uint parent = Read(out flags);
        if (before != 0 || parent != 1 || (flags & 1) == 0)
            throw new InvalidOperationException("The positive control could not read back the exclusive server.");
        string executable;
        using (var self = Process.GetCurrentProcess()) executable = self.MainModule.FileName;
        var start = new ProcessStartInfo(executable, "child") {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
        };
        using (var child = Process.Start(start))
        {
            if (!child.WaitForExit(5000))
            {
                child.Kill();
                child.WaitForExit(1000);
                throw new TimeoutException("The synthetic DNS child did not finish.");
            }
            if (child.ExitCode != 0) throw new InvalidOperationException("The DNS child failed.");
            uint inherited = UInt32.Parse(child.StandardOutput.ReadToEnd(), CultureInfo.InvariantCulture);
            Console.WriteLine("{{\"Before\":{0},\"Parent\":{1},\"Child\":{2},\"QueriedNetwork\":false}}", before, parent, inherited);
        }
        return 0;
    }
}
'@
    $result=& $image
    if($LASTEXITCODE -ne 0){throw 'Windows application-specific DNS probe failed.'}
    $result | ConvertFrom-Json | Add-Member -NotePropertyName Utc -NotePropertyValue ([datetime]::UtcNow.ToString('o')) -PassThru |
        ConvertTo-Json -Compress
}finally{
    [IO.File]::Delete($image)
    [IO.Directory]::Delete($folder,$false)
}
