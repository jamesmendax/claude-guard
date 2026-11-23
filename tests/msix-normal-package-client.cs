using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class GuardNormalPackageClient
{
    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "observer") return TryEcho(Port(args[1])) ? 0 : 1;
        if (args.Length == 5 && args[0] == "upgrade-first")
        {
            DateTime started = DateTime.UtcNow;
            string package = GuardMsixProbe.CurrentPackageName();
            if (package != args[2] || GuardFixtureClient.GetAppContainerIdentity() != "none") return 9;
            DateTime firstDirect = DateTime.UtcNow;
            AttemptDirect(Port(args[3]));
            DateTime firstRelay = DateTime.UtcNow;
            bool relay = TryEcho(Port(args[4]));
            using (var pipe = OpenPipe(args[1]))
            {
                using (var report = new StreamWriter(pipe, new UTF8Encoding(false), 1024, true))
                    report.WriteLine(String.Join("|", args[1], package, started.ToString("o"), firstDirect.ToString("o"),
                        firstRelay.ToString("o"), relay ? "Echo" : "Unavailable"));
                using (var acknowledgement = new StreamReader(pipe))
                {
                    Task<string> verified = acknowledgement.ReadLineAsync();
                    if (Task.WhenAny(verified, Task.Delay(7000)).GetAwaiter().GetResult() != verified ||
                        verified.Status != TaskStatus.RanToCompletion) return 9;
                    return verified.Result == args[1] ? 0 : 9;
                }
            }
        }
        if (args.Length == 1 && args[0] == "linger")
        {
            Thread.Sleep(TimeSpan.FromMinutes(2));
            return 0;
        }
        if (args.Length == 3 && args[0] == "child")
        {
            using (var pipe = OpenPipe(args[1], PipeDirection.Out))
            using (var report = new StreamWriter(pipe) { AutoFlush = true })
            {
                AttemptDirect(Port(args[2]));
                report.WriteLine("ChildAttempted|" + (GuardMsixProbe.CurrentPackageName() ?? "Unpackaged"));
                return 0;
            }
        }
        if (args.Length != 3 || args[0] != "session") return 87;
        using (var pipe = OpenPipe(args[1]))
        using (var commands = new StreamReader(pipe))
        using (var report = new StreamWriter(pipe) { AutoFlush = true })
        {
            string package = GuardMsixProbe.CurrentPackageName();
            if ((package ?? "Unpackaged") != args[2] || GuardFixtureClient.GetAppContainerIdentity() != "none")
            {
                report.WriteLine("ERROR|UnexpectedPackageIdentity");
                return 9;
            }
            report.WriteLine("READY|" + (package ?? "Unpackaged"));
            TcpClient existing = null;
            NetworkStream existingStream = null;
            try
            {
                for (string line = commands.ReadLine(); line != null; line = commands.ReadLine())
                {
                    var fields = line.Split('|');
                    try
                    {
                        switch (fields[0])
                        {
                            case "open":
                                if (existing != null) existing.Dispose();
                                existing = null;
                                existingStream = null;
                                existing = Connect(Port(fields[1]));
                                existingStream = existing.GetStream();
                                report.WriteLine(Echo(existingStream) ? "Echo" : "Unavailable");
                                break;
                            case "existing":
                                report.WriteLine(existingStream != null && Echo(existingStream) ? "Echo" : "Unavailable");
                                break;
                            case "new":
                                report.WriteLine(TryEcho(Port(fields[1])) ? "Echo" : "Unavailable");
                                break;
                            case "download":
                                using (TcpClient download = Connect(Port(fields[1])))
                                    report.WriteLine(ReadDownload(download) ? "Downloaded|65536" : "Unavailable");
                                break;
                            case "direct":
                                AttemptDirect(Port(fields[1]));
                                report.WriteLine("Attempted");
                                break;
                            case "child":
                                report.WriteLine(RunChild(fields[1], Port(fields[2])));
                                break;
                            case "linger":
                                using (var child = StartCopiedFixture(fields[1], "linger"))
                                    report.WriteLine("LingerStarted|" + child.Id);
                                break;
                            case "dns":
                                report.WriteLine(GuardLocalDnsClient.Main(new[] { fields[1], fields[2], "none" }));
                                break;
                            case "quit-confirmed":
                                report.WriteLine("Quitting");
                                return 0;
                            case "quit":
                                return 0;
                            default:
                                report.WriteLine("ERROR|UnknownCommand");
                                break;
                        }
                    }
                    catch (SocketException) { report.WriteLine("Unavailable"); }
                    catch (IOException) { report.WriteLine("Unavailable"); }
                    catch (Exception error) { report.WriteLine("ERROR|" + fields[0] + "|" + error.GetType().Name); }
                }
            }
            finally { if (existing != null) existing.Dispose(); }
        }
        return 0;
    }

    private static string PipeName(string id)
    {
        Guid parsed;
        if (!Guid.TryParseExact(id, "N", out parsed)) throw new ArgumentException("Invalid fixture identifier.");
        return "GuardNormalPackage-" + id;
    }

    private static NamedPipeClientStream OpenPipe(string id, PipeDirection direction = PipeDirection.InOut)
    {
        var pipe = new NamedPipeClientStream(".", PipeName(id), direction);
        try { pipe.Connect(4000); return pipe; }
        catch { pipe.Dispose(); throw; }
    }

    private static int Port(string value)
    {
        ushort port;
        if (!UInt16.TryParse(value, out port) || port < 1024) throw new ArgumentException("Invalid fixture port.");
        return port;
    }

    private static TcpClient Connect(int port)
    {
        var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            IAsyncResult pending = client.BeginConnect(IPAddress.Loopback, port, null, null);
            using (WaitHandle finished = pending.AsyncWaitHandle)
            {
                if (!finished.WaitOne(750)) throw new SocketException((int)SocketError.TimedOut);
                client.EndConnect(pending);
            }
            client.ReceiveTimeout = 750;
            client.SendTimeout = 750;
            return client;
        }
        catch { client.Dispose(); throw; }
    }

    private static bool Echo(NetworkStream stream)
    {
        stream.WriteByte(0x53);
        return stream.ReadByte() == 0x53;
    }

    private static bool TryEcho(int port)
    {
        try { using (var client = Connect(port)) return Echo(client.GetStream()); }
        catch (SocketException) { return false; }
        catch (IOException) { return false; }
    }

    private static bool ReadDownload(TcpClient client)
    {
        NetworkStream stream = client.GetStream();
        stream.WriteByte(0x42);
        byte[] buffer = new byte[4096];
        int total = 0;
        while (total < 65536)
        {
            int count = stream.Read(buffer, 0, Math.Min(buffer.Length, 65536 - total));
            if (count == 0) return false;
            for (int i = 0; i < count; i++)
                if (buffer[i] != (byte)((total + i) & 255)) return false;
            total += count;
        }
        return true;
    }

    private static void AttemptDirect(int port)
    {
        try { using (var tcp = Connect(port)) tcp.GetStream().WriteByte(0x44); }
        catch (SocketException) { }
        catch (IOException) { }
        try { using (var udp = new UdpClient()) udp.Send(new byte[] { 0x44 }, 1, new IPEndPoint(IPAddress.Loopback, port)); }
        catch (SocketException) { }
    }

    private static Process StartCopiedFixture(string image, string arguments)
    {
        if (!Path.IsPathRooted(image) || !String.Equals(Path.GetExtension(image), ".exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid fixture helper path.");
        var name = Path.GetFileName(image);
        var localUpgradeHelper = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "fixture-helper-v2.exe");
        if (!name.StartsWith("guard-new-helper-", StringComparison.Ordinal) &&
            !String.Equals(Path.GetFullPath(image), localUpgradeHelper, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid copied fixture path.");
        var start = new ProcessStartInfo(image, arguments) { UseShellExecute = false, CreateNoWindow = true };
        return Process.Start(start);
    }

    private static string RunChild(string image, int port)
    {
        string id = Guid.NewGuid().ToString("N");
        using (var pipe = new NamedPipeServerStream(PipeName(id), PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
        {
            IAsyncResult before = pipe.BeginWaitForConnection(null, null);
            using (var child = StartCopiedFixture(image, "child " + id + " " + port))
            {
                try
                {
                    using (WaitHandle connected = before.AsyncWaitHandle)
                    {
                        if (!connected.WaitOne(5000)) throw new TimeoutException();
                        pipe.EndWaitForConnection(before);
                    }
                    using (var reader = new StreamReader(pipe))
                    {
                        Task<string> line = reader.ReadLineAsync();
                        if (!line.Wait(3000) || String.IsNullOrEmpty(line.Result) || !child.WaitForExit(3000) || child.ExitCode != 0)
                            throw new InvalidOperationException("The copied fixture did not finish.");
                        return line.Result;
                    }
                }
                finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(2000); } }
            }
        }
    }
}

public sealed class GuardNormalEchoWitness : IDisposable
{
    private readonly TcpListener listener;
    private readonly ConcurrentDictionary<TcpClient, byte> clients = new ConcurrentDictionary<TcpClient, byte>();
    private readonly Thread receiver;
    private volatile bool rejectTransport;
    public volatile bool Paused;
    public volatile int ConnectWitnessPort;
    private readonly byte[] downloadBytes = new byte[65536];

    public GuardNormalEchoWitness()
    {
        for (int i = 0; i < downloadBytes.Length; i++) downloadBytes[i] = (byte)(i & 255);
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.ExclusiveAddressUse = true;
        listener.Start();
        receiver = new Thread(Receive) { IsBackground = true };
        receiver.Start();
    }

    public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }

    public bool RejectTransport
    {
        get { return rejectTransport; }
        set
        {
            rejectTransport = value;
            if (value)
                foreach (TcpClient client in clients.Keys) client.Dispose();
        }
    }

    private void Receive()
    {
        try
        {
            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();
                client.LingerState = new LingerOption(true, 0);
                clients.TryAdd(client, 0);
                Task.Run(() => Serve(client));
            }
        }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    private void Serve(TcpClient client)
    {
        try
        {
            using (client)
            {
                if (rejectTransport) return;
                NetworkStream stream = client.GetStream();
                for (int value = stream.ReadByte(); value >= 0; value = stream.ReadByte())
                {
                    if (Paused) continue;
                    if (value == 0x43 && ConnectWitnessPort != 0)
                    {
                        using (var witness = new TcpClient(AddressFamily.InterNetwork))
                        {
                            witness.Connect(IPAddress.Loopback, ConnectWitnessPort);
                            NetworkStream target = witness.GetStream();
                            target.WriteByte((byte)value);
                            Task.WaitAny(stream.CopyToAsync(target), target.CopyToAsync(stream));
                        }
                        return;
                    }
                    if (value == 0x42) stream.Write(downloadBytes, 0, downloadBytes.Length);
                    else stream.WriteByte((byte)value);
                }
            }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
        finally { byte unused; clients.TryRemove(client, out unused); }
    }

    public void Dispose()
    {
        listener.Stop();
        receiver.Join(2000);
        foreach (TcpClient client in clients.Keys) client.Dispose();
    }
}
