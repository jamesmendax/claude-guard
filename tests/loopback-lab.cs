using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ClaudeGuard.Network;

public static class GuardLoopbackLab
{
    public static PolicyPlan CreateNormalPackagePlan(string image, string familySid, string relay, ushort relayPort,
        ushort upstreamPort, string observer = null)
    {
        var family = new System.Security.Principal.SecurityIdentifier(familySid);
        if (!family.Value.StartsWith("S-1-15-2-", StringComparison.Ordinal) || family.BinaryLength != 40 ||
            relayPort < 1024 || upstreamPort < 1024 || relayPort == upstreamPort ||
            String.Equals(Path.GetFullPath(image), Path.GetFullPath(relay), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid normal package fixture scope.");
        var package = new Condition(GuardPolicy.PackageId, family);
        var relayImage = new Condition(GuardPolicy.AppId, Path.GetFullPath(relay));
        var blocks = new List<Rule>();
        foreach (Condition target in new[] { package, new Condition(GuardPolicy.AppId, Path.GetFullPath(image)) })
        {
            foreach (Guid layer in new[] { GuardPolicy.Connect4, GuardPolicy.Connect6, GuardPolicy.Accept4, GuardPolicy.Accept6 })
                blocks.Add(new Rule(layer, false, target));
        }
        blocks.Add(new Rule(GuardPolicy.Connect4, false, relayImage));
        blocks.Add(new Rule(GuardPolicy.Connect6, false, relayImage));
        blocks.Add(new Rule(GuardPolicy.Connect4, true, relayImage,
            new Condition(GuardPolicy.RemoteIp, IPAddress.Loopback), new Condition(GuardPolicy.RemotePort, upstreamPort),
            new Condition(GuardPolicy.Protocol, (byte)ProtocolType.Tcp)));
        if (observer != null)
        {
            // Closing this test port also rejects copied helpers that carry no package identity.
            blocks.Add(new Rule(GuardPolicy.Connect4, false,
                new Condition(GuardPolicy.RemoteIp, IPAddress.Loopback), new Condition(GuardPolicy.RemotePort, relayPort)));
            blocks.Add(new Rule(GuardPolicy.Connect4, true,
                new Condition(GuardPolicy.AppId, Path.GetFullPath(observer)),
                new Condition(GuardPolicy.RemoteIp, IPAddress.Loopback), new Condition(GuardPolicy.RemotePort, relayPort),
                new Condition(GuardPolicy.Protocol, (byte)ProtocolType.Tcp)));
        }
        var allowed = new Rule(GuardPolicy.Connect4, true,
            package,
            new Condition(GuardPolicy.RemoteIp, IPAddress.Loopback), new Condition(GuardPolicy.RemotePort, relayPort),
            new Condition(GuardPolicy.Protocol, (byte)ProtocolType.Tcp));
        return new PolicyPlan(blocks.ToArray(), new[] { allowed });
    }

    public static PolicyPlan CreateStartupPlan(string image, Guid deployment)
    {
        if (String.IsNullOrEmpty(image) || !Path.IsPathRooted(image) ||
            !String.Equals(Path.GetFileName(image), "guard-boot-client.exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The startup plan must identify the synthetic boot client.");
        Condition app = new Condition(GuardPolicy.AppId, Path.GetFullPath(image));
        Rule[] blocks = new[] {
            new Rule(GuardPolicy.Connect4, false, app), new Rule(GuardPolicy.Connect6, false, app),
            new Rule(GuardPolicy.Accept4, false, app), new Rule(GuardPolicy.Accept6, false, app)
        };
        return new PolicyPlan(blocks, new Rule[0]).WithEarlyBootBlocks().ForPersistentUse(deployment);
    }

    public static bool StartupDatagramReceived(string executable, string family)
    {
        IPAddress address = family == "4" ? IPAddress.Loopback : family == "6" ? IPAddress.IPv6Loopback : null;
        if (address == null) throw new ArgumentException("Expected a loopback address family.");
        using (var listener = new UdpClient(address.AddressFamily))
        {
            listener.ExclusiveAddressUse = true;
            listener.Client.Bind(new IPEndPoint(address, 0));
            string token = Guid.NewGuid().ToString("N");
            int port = ((IPEndPoint)listener.Client.LocalEndPoint).Port;
            using (Child child = Child.Start(executable, "udp " + family + " " + port + " " + token))
            {
                if (!child.Process.WaitForExit(4000)) throw new TimeoutException("The startup probe did not exit.");
                if (child.Process.ExitCode != 0 &&
                    (child.Process.ExitCode != 1 || child.Read() != "REJECT SocketException"))
                    throw new InvalidOperationException("The startup probe did not attempt the expected datagram.");
            }
            if (!listener.Client.Poll(500000, SelectMode.SelectRead)) return false;
            IPEndPoint sender = new IPEndPoint(address, 0);
            string received = Encoding.ASCII.GetString(listener.Receive(ref sender));
            if (!IPAddress.IsLoopback(sender.Address) || received != token)
                throw new InvalidOperationException("The startup witness received an unexpected datagram.");
            return true;
        }
    }

    public static bool RejectsUnexpectedFilter(PolicyPlan plan, ushort assignedWeight, string client, ushort port)
    {
        WindowsPolicySession attached = null;
        bool rejected = false;
        using (NativeSession extra = new NativeSession(true))
        {
            Rule permit = new Rule(GuardPolicy.Connect4, true,
                new Condition(GuardPolicy.AppId, client), new Condition(GuardPolicy.RemoteIp, IPAddress.Loopback),
                new Condition(GuardPolicy.RemotePort, port), new Condition(GuardPolicy.Protocol, (byte)ProtocolType.Tcp));
            extra.Transaction(delegate { extra.AddRules(plan.PersistentSublayer, new Rule[] { permit }); });
            try { attached = WindowsPolicySession.AttachPersistent(plan, assignedWeight); }
            catch (InvalidOperationException error)
            {
                rejected = error.Message == "An unexpected filter remains in the Guard sublayer.";
            }
        }
        if (attached != null) attached.Dispose();
        return rejected;
    }

    public static int Run(string directory, X509Certificate2 certificate, bool kernel, int durationSeconds)
    {
        if (durationSeconds < 1 || durationSeconds > 120)
            throw new ArgumentOutOfRangeException("durationSeconds");

        string client = Path.Combine(directory, "guard-lab-client.exe");
        string relay = Path.Combine(directory, "guard-lab-relay.exe");
        string control = Path.Combine(directory, "guard-lab-control.exe");
        string alias = Path.Combine(directory, "guard-lab-alias.exe");
        int relayPort = FindPrivatePort();
        using (TlsWitness upstream = new TlsWitness(IPAddress.Loopback, certificate))
        using (TlsWitness direct = new TlsWitness(IPAddress.Loopback, certificate))
        using (TlsWitness ipv6 = new TlsWitness(IPAddress.IPv6Loopback, certificate))
        using (UdpClient dns = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
        {
            int dnsPort = ((IPEndPoint)dns.Client.LocalEndPoint).Port;
            Require(Echo(control, "4", direct.Port, certificate), "IPv4 direct witness control");
            Require(Echo(control, "6", ipv6.Port, certificate), "IPv6 witness control");
            string udpToken = Guid.NewGuid().ToString("N");
            RunUdp(control, dnsPort, udpToken);
            dns.Client.ReceiveTimeout = 2000;
            IPEndPoint sender = null;
            Require(Encoding.ASCII.GetString(dns.Receive(ref sender)) == udpToken, "UDP/DNS witness control");
            Require(Echo(control, "4", upstream.Port, certificate), "Proxy-side witness control");

            // A mixed-port forwarding fixture validates traffic observation and
            // the native policy, without invoking Bettbox or any real service.
            if (!kernel)
            {
                using (Child forwarding = StartRelay(relay, relayPort, upstream.Port))
                    Require(Echo(client, "4", relayPort, certificate), "Unfiltered TLS relay fixture");
                Console.WriteLine("RESULT Fixture=Passed Kernel=NotRun");
                return 0;
            }

            PolicyPlan plan = GuardPolicy.Create(new string[] { client, alias }, new string[] { client, alias },
                new string[0], null, relay, (ushort)relayPort, "127.0.0.1", (ushort)upstream.Port);
            using (Child oldDirect = StartTls(client, "4", direct.Port, certificate))
            {
                Require(oldDirect.Read() == "READY" && oldDirect.Push(Guid.NewGuid().ToString("N")), "Established direct flow control");
                using (WindowsPolicySession policy = new WindowsPolicySession(plan))
                {
                    Require(!oldDirect.Push(Guid.NewGuid().ToString("N")), "Established direct flow revoked");
                    Require(!Echo(client, "4", direct.Port, certificate), "Startup closed before admission");
                    Require(!Echo(client, "4", upstream.Port, certificate), "Client cannot bypass relay to upstream port");
                    Require(!Echo(client, "6", ipv6.Port, certificate), "IPv6 denied");
                    string deniedUdp = Guid.NewGuid().ToString("N");
                    RunUdp(client, dnsPort, deniedUdp);
                    Require(!dns.Client.Poll(450000, SelectMode.SelectRead), "Direct synthetic DNS/UDP denied");

                    using (Child rogue = Child.Start(control, "relay " + relayPort + " " + direct.Port))
                        Require(rogue.Read() != "READY", "Replacement listener denied");
                    using (Child forwarding = StartRelay(relay, relayPort, upstream.Port))
                    {
                        Require(!Echo(client, "4", relayPort, certificate), "Proxy cannot be used while gate closed");
                        policy.Open();
                        policy.Open();
                        int upstreamBefore = upstream.Received;
                        int directBefore = direct.Accepted;
                        Require(Echo(client, "4", relayPort, certificate), "Healthy HTTPS attempt 1");
                        Require(Echo(client, "4", relayPort, certificate), "Healthy HTTPS attempt 2");
                        Require(Echo(alias, "4", relayPort, certificate), "Healthy HTTPS attempt 3 from enrolled alias");
                        Require(upstream.Received == upstreamBefore + 3, "Only the approved witness received the healthy payloads");
                        Require(!Echo(client, "4", direct.Port, certificate), "Direct TCP denied with admission open");
                        Require(!Echo(relay, "4", direct.Port, certificate), "Relay fallback direct denied with admission open");
                        Require(direct.Accepted == directBefore, "Direct witness received no protected connection");
                        using (Child active = StartTls(client, "4", relayPort, certificate))
                        {
                            Require(active.Read() == "READY", "Long TLS connection started");
                            Stopwatch watch = Stopwatch.StartNew();
                            do
                            {
                                if (!active.Push(Guid.NewGuid().ToString("N"))) throw new InvalidOperationException("Long TLS echo failed.");
                                Thread.Sleep(300);
                            } while (watch.Elapsed.TotalSeconds < durationSeconds);
                            Console.WriteLine("PASS Healthy TLS stream duration=" + watch.Elapsed.TotalSeconds.ToString("F1") + "s");

                            // Deleting the dynamic permits models the policy
                            // owner's WFP session ending while relay stays up.
                            policy.Close();
                            policy.Close();
                            int last = upstream.Received;
                            Require(!active.Push(Guid.NewGuid().ToString("N")), "Existing TLS flow closed after gate revocation");
                            Require(upstream.Received == last, "No post-revocation payload at approved witness");
                            Require(!Echo(client, "4", relayPort, certificate), "New TLS flow denied after gate revocation");
                            Require(!Echo(client, "4", direct.Port, certificate), "No fallback after gate revocation");
                        }

                        policy.Open();
                        Require(Echo(client, "4", relayPort, certificate), "Manual restart through same relay succeeded");
                        using (Child active = StartTls(client, "4", relayPort, certificate))
                        {
                            Require(active.Read() == "READY", "Active TLS flow before simulated node failure");
                            upstream.Pause();
                            Require(!active.Push(Guid.NewGuid().ToString("N")), "Upstream loss stopped active traffic");
                            Require(!Echo(client, "4", relayPort, certificate), "Upstream loss rejected new traffic");
                            Require(!Echo(relay, "4", direct.Port, certificate), "Upstream loss cannot switch destination");
                            policy.Close();
                            upstream.Resume();
                            policy.Open();
                            Require(Echo(client, "4", relayPort, certificate), "Original upstream recovered");
                        }

                        forwarding.Dispose();
                        Require(!Echo(client, "4", relayPort, certificate), "Relay process exit stops new traffic");
                        Require(!Echo(client, "4", direct.Port, certificate), "Relay process exit cannot fall back to direct");
                        using (Child rogue = Child.Start(control, "relay " + relayPort + " " + direct.Port))
                            Require(rogue.Read() != "READY", "Relay replacement remains blocked after process exit");
                        Require(direct.Accepted == directBefore, "Direct witness received zero protected connections during failures");
                    }
                }
            }
            Require(Echo(client, "4", direct.Port, certificate), "Scoped WFP lab filters removed");
            Console.WriteLine("RESULT Fixture=Passed Kernel=Passed");
            return 0;
        }
    }

    public static int FindPrivatePort()
    {
        Random random = new Random();
        for (int index = 0; index < 30; index++)
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, random.Next(20000, 48000));
            listener.ExclusiveAddressUse = true;
            try
            {
                listener.Start();
                return ((IPEndPoint)listener.LocalEndpoint).Port;
            }
            catch (SocketException) { }
            finally { listener.Stop(); }
        }
        throw new InvalidOperationException("No unused loopback port for the fixture.");
    }

    public static Child StartTls(string path, string family, int port, X509Certificate2 certificate)
    {
        return Child.Start(path, "tls " + family + " " + port + " " + certificate.Thumbprint);
    }
    public static bool Echo(string path, string family, int port, X509Certificate2 certificate)
    {
        using (Child probe = StartTls(path, family, port, certificate))
        {
            string banner = probe.Read();
            if (banner == "READY") return probe.Push(Guid.NewGuid().ToString("N"));
            if (Path.GetFileName(path) == "guard-lab-control.exe") Console.WriteLine("CONTROL " + banner);
            return false;
        }
    }
    private static void RunUdp(string path, int port, string token)
    {
        using (Child probe = Child.Start(path, "udp 4 " + port + " " + token))
            if (!probe.Process.WaitForExit(3000)) throw new TimeoutException("UDP probe hung.");
    }
    public static Child StartRelay(string path, int port, int upstream)
    {
        Child child = Child.Start(path, "relay " + port + " " + upstream);
        if (child.Read() == "READY") return child;
        child.Dispose();
        throw new InvalidOperationException("Loopback relay did not bind.");
    }
    private static void Require(bool result, string message)
    {
        if (!result) throw new InvalidOperationException(message);
        Console.WriteLine("PASS " + message);
    }

    public sealed class Child : IDisposable
    {
        public readonly Process Process;
        private bool disposed;
        private Child(Process process) { Process = process; }
        internal static Child Start(string executable, string arguments)
        {
            ProcessStartInfo options = new ProcessStartInfo(executable, arguments);
            options.UseShellExecute = false;
            options.CreateNoWindow = true;
            options.RedirectStandardInput = true;
            options.RedirectStandardOutput = true;
            return new Child(Process.Start(options));
        }
        public string Read()
        {
            Task<string> line = Process.StandardOutput.ReadLineAsync();
            if (!line.Wait(4500)) throw new TimeoutException("Loopback probe response timeout.");
            return line.Result;
        }
        public bool Push(string token)
        {
            try
            {
                Process.StandardInput.WriteLine(token);
                Process.StandardInput.Flush();
                return Read() == "OK";
            }
            catch (IOException) { return false; }
        }
        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            try
            {
                if (!Process.HasExited)
                {
                    Process.Kill();
                    if (!Process.WaitForExit(5000)) throw new TimeoutException("Loopback probe did not stop.");
                }
            }
            finally { Process.Dispose(); }
        }
    }

    public sealed class TlsWitness : IDisposable
    {
        private readonly TcpListener listener;
        private readonly X509Certificate2 certificate;
        private readonly ConcurrentDictionary<TcpClient, byte> active = new ConcurrentDictionary<TcpClient, byte>();
        private int received;
        private int accepted;
        private volatile bool paused;

        public TlsWitness(IPAddress source, X509Certificate2 certificate)
        {
            this.certificate = certificate;
            listener = new TcpListener(source, 0);
            listener.ExclusiveAddressUse = true;
            listener.Start();
            Task.Run((Action)Listen);
        }
        public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
        public int Accepted { get { return Volatile.Read(ref accepted); } }
        public int Received { get { return Volatile.Read(ref received); } }

        public void Pause()
        {
            paused = true;
            foreach (TcpClient socket in active.Keys) socket.Dispose();
        }
        public void Resume() { paused = false; }
        private void Listen()
        {
            try
            {
                while (true)
                {
                    TcpClient socket = listener.AcceptTcpClient();
                    active.TryAdd(socket, 0);
                    Interlocked.Increment(ref accepted);
                    Task.Run(() => Reply(socket));
                }
            }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
        }
        private void Reply(TcpClient socket)
        {
            try
            {
                using (socket)
                {
                    if (paused) return;
                    using (SslStream stream = new SslStream(socket.GetStream(), false))
                    {
                        stream.AuthenticateAsServer(certificate, false, SslProtocols.Tls12, false);
                        using (StreamReader reader = new StreamReader(stream, Encoding.ASCII))
                        using (StreamWriter writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true, NewLine = "\r\n" })
                        {
                            string request;
                            while (!paused && (request = reader.ReadLine()) != null)
                            {
                                string[] parts = request.Split(' ');
                                Guid id;
                                if (parts.Length != 3 || parts[0] != "GET" || parts[2] != "HTTP/1.1" ||
                                    !parts[1].StartsWith("/") || !Guid.TryParseExact(parts[1].Substring(1), "N", out id))
                                    return;
                                string header;
                                while (!String.IsNullOrEmpty(header = reader.ReadLine())) { }
                                string token = id.ToString("N");
                                Interlocked.Increment(ref received);
                                writer.Write("HTTP/1.1 200 OK\r\nContent-Length: " + token.Length +
                                    "\r\nConnection: keep-alive\r\n\r\n" + token);
                            }
                        }
                    }
                }
            }
            catch (IOException) { }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
            catch (AuthenticationException error) { Console.WriteLine("TLS witness handshake: " + error.Message); }
            finally
            {
                byte marker;
                active.TryRemove(socket, out marker);
            }
        }
        public void Dispose()
        {
            Pause();
            listener.Stop();
        }
    }
}

