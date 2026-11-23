using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

internal static class GuardFixtureClient
{
    private const int TokenIsAppContainer = 29;
    private const int TokenAppContainerSid = 31;

    internal static string GetAppContainerIdentity()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 8 /* TOKEN_QUERY */, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr buffer = IntPtr.Zero;
        try
        {
            uint used;
            buffer = Marshal.AllocHGlobal(IntPtr.Size);
            if (!GetTokenInformation(token, TokenIsAppContainer, buffer, (uint)IntPtr.Size, out used))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (Marshal.ReadInt32(buffer) == 0) return "none";
            if (!GetTokenInformation(token, TokenAppContainerSid, buffer, (uint)IntPtr.Size, out used))
            {
                int error = Marshal.GetLastWin32Error();
                if (error != 122 || used <= IntPtr.Size) throw new Win32Exception(error);
                buffer = Marshal.ReAllocHGlobal(buffer, new IntPtr(used));
                if (!GetTokenInformation(token, TokenAppContainerSid, buffer, used, out used))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseHandle(token);
        }
    }

    private static void TrySend(IPEndPoint endpoint, SocketType type, ProtocolType protocol, byte marker, bool isolated)
    {
        try
        {
            using (var socket = new Socket(endpoint.AddressFamily, type, protocol))
            {
                socket.SendTimeout = 1000;
                IAsyncResult connection = socket.BeginConnect(endpoint, null, null);
                using (var finished = connection.AsyncWaitHandle)
                {
                    if (!finished.WaitOne(1000))
                    {
                        if (isolated) return;
                        throw new TimeoutException("The loopback control did not connect.");
                    }
                    socket.EndConnect(connection);
                }
                socket.Send(new[] { marker });
            }
        }
        catch (SocketException error)
        {
            if (!isolated || (error.SocketErrorCode != SocketError.AccessDenied &&
                error.SocketErrorCode != SocketError.NetworkUnreachable &&
                error.SocketErrorCode != SocketError.TimedOut)) throw;
        }
    }

    public static int Main(string[] args)
    {
        SetErrorMode(3);
        try
        {
            if (args.Length == 2 && args[0].StartsWith("--proxy-server=http://127.0.0.1:", StringComparison.Ordinal))
            {
                string scope = Environment.GetEnvironmentVariable("GUARD_FIXTURE_EXPECTED_SCOPE");
                string proxy = Environment.GetEnvironmentVariable("GUARD_FIXTURE_EXPECTED_PROXY");
                return scope != null && scope != "none" && scope == GetAppContainerIdentity() &&
                    args[0] == proxy && args[1] == "--proxy-bypass-list=<-loopback>" ? 0 : 14;
            }
            if (args.Length == 2 && args[0] == "hold")
            {
                if (GetAppContainerIdentity() != args[1]) return 9;
                Thread.Sleep(30000);
                return 0;
            }
            if (args.Length == 3 && args[0] == "park")
            {
                if (GetAppContainerIdentity() != args[1]) return 9;
                var parked = new ProcessStartInfo(args[2], "hold " + args[1]) {
                    UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(args[2])
                };
                using (var child = Process.Start(parked)) return 0;
            }
            bool isParent = (args.Length == 4 || args.Length == 5) && args[0] == "parent";
            if (!isParent && ((args.Length != 3 && args.Length != 4) || args[0] != "child")) return 87;
            if (GetAppContainerIdentity() != args[2]) return 9;
            var endpoint = new IPEndPoint(IPAddress.Loopback, UInt16.Parse(args[1]));
            byte marker = isParent ? (byte)0x51 : (byte)0x52;
            TrySend(endpoint, SocketType.Stream, ProtocolType.Tcp, marker, args[2] != "none");
            TrySend(endpoint, SocketType.Dgram, ProtocolType.Udp, marker, args[2] != "none");
            int proxyArgument = isParent ? 4 : 3;
            string proxyPort = args.Length > proxyArgument ? args[proxyArgument] : null;
            if (proxyPort != null)
                TrySend(new IPEndPoint(IPAddress.Loopback, UInt16.Parse(proxyPort)),
                    SocketType.Stream, ProtocolType.Tcp, marker, args[2] != "none");
            if (!isParent) return 0;

            string childArgs = "child " + args[1] + " " + args[2];
            if (proxyPort != null) childArgs += " " + proxyPort;
            var start = new ProcessStartInfo(args[3], childArgs) {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(args[3])
            };
            using (var child = Process.Start(start))
            {
                if (child.WaitForExit(5000)) return child.ExitCode == 0 ? 0 : 32 + child.ExitCode;
                child.Kill();
                child.WaitForExit(2000);
                return 11;
            }
        }
        catch (Win32Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return error.NativeErrorCode;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 13;
        }
    }

    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, uint size, out uint used);
}
