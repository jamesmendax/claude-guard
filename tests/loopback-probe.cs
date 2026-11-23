using System;
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

internal static class Probe
{
    // This executable accepts only loopback ports. It has no DNS, proxy
    // discovery, service endpoints, application data or filesystem inputs.
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 3 && args[0] == "relay")
            {
                RunRelay(Port(args[1]), Port(args[2]));
                return 0;
            }
            if (args.Length != 4) throw new ArgumentException();
            IPAddress address =
                args[1] == "4" ? IPAddress.Loopback :
                args[1] == "6" ? IPAddress.IPv6Loopback : null;
            if (address == null) throw new ArgumentException();
            int port = Port(args[2]);
            if (args[0] == "udp")
            {
                using (UdpClient socket = new UdpClient(address.AddressFamily))
                {
                    byte[] token = Encoding.ASCII.GetBytes(args[3]);
                    socket.Send(token, token.Length, new IPEndPoint(address, port));
                }
                return 0;
            }
            if (args[0] != "tls") throw new ArgumentException();
            using (TcpClient socket = Connect(address, port))
            using (SslStream stream = new SslStream(socket.GetStream(), false,
                (sender, cert, chain, errors) => cert != null && cert.GetCertHashString() == args[3]))
            {
                stream.AuthenticateAsClient("guard-lab.invalid", new X509CertificateCollection(), SslProtocols.Tls12, false);
                using (StreamReader reader = new StreamReader(stream, Encoding.ASCII))
                    using (StreamWriter writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true, NewLine = "\r\n" })
                {
                    Console.WriteLine("READY");
                    for (string token = Console.ReadLine(); token != null; token = Console.ReadLine())
                    {
                        writer.Write("GET /" + token + " HTTP/1.1\r\nHost: guard-lab.invalid\r\nConnection: keep-alive\r\n\r\n");
                        string status = reader.ReadLine();
                        string header;
                        while (!String.IsNullOrEmpty(header = reader.ReadLine())) { }
                        char[] response = new char[token.Length];
                        int length = reader.ReadBlock(response, 0, response.Length);
                        Console.WriteLine(status == "HTTP/1.1 200 OK" && length == token.Length && new string(response) == token ? "OK" : "REJECT");
                    }
                }
            }
            return 0;
        }
        catch (Exception error)
        {
            Console.WriteLine("REJECT " + error.GetType().Name);
            return 1;
        }
    }

    private static int Port(string value)
    {
        int port = Int32.Parse(value);
        if (port < 1024 || port > 65535) throw new ArgumentException();
        return port;
    }
    private static TcpClient Connect(IPAddress address, int port)
    {
        TcpClient socket = new TcpClient(address.AddressFamily);
        try
        {
            IAsyncResult pending = socket.BeginConnect(address, port, null, null);
            using (pending.AsyncWaitHandle)
                if (!pending.AsyncWaitHandle.WaitOne(1500)) throw new TimeoutException();
            socket.EndConnect(pending);
            socket.ReceiveTimeout = 2000;
            socket.SendTimeout = 2000;
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
    private static void RunRelay(int localPort, int upstreamPort)
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, localPort);
        listener.ExclusiveAddressUse = true;
        listener.Start();
        Console.WriteLine("READY");
        while (true)
        {
            TcpClient client = listener.AcceptTcpClient();
            Task.Run(() => Forward(client, upstreamPort));
        }
    }
    private static void Forward(TcpClient client, int upstreamPort)
    {
        try
        {
            using (client)
            using (TcpClient upstream = Connect(IPAddress.Loopback, upstreamPort))
            {
                Task toUpstream = client.GetStream().CopyToAsync(upstream.GetStream());
                Task toClient = upstream.GetStream().CopyToAsync(client.GetStream());
                Task.WaitAny(toUpstream, toClient);
            }
        }
        catch (SocketException) { }
        catch (IOException) { }
    }
}

