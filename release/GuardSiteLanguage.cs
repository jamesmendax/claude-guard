using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ClaudeGuard
{
    public static class SiteLanguage
    {
        private const uint QueryLimitedInformation = 0x1000;
        private const int TokenQuery = 8, TokenElevation = 20;
        private static readonly Regex Profile = new Regex(@"\A(?:Default|Profile [1-9][0-9]{0,5})\z");
        private static readonly Regex ProbeUrl = new Regex(@"\Ahttp://127\.0\.0\.1:[0-9]{4,5}/guard-language/[a-f0-9]{32}\z");
        private static readonly Regex Language = new Regex(@"\A[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*\z");
        private static readonly object ReceiptLock = new object();
        private static string lastEdge, lastProfile, lastPreferences, lastRequested, lastHeader;
        private static long lastTick;
        private static int checking;

        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool GetTokenInformation(IntPtr token, int kind, out int data, int length, out int required);
        [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int pid);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder image, ref int length);
        [DllImport("iphlpapi.dll")]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool ordered, int family, int kind, uint reserved);

        private static string CheckEdge(string executable, string profile)
        {
            if (String.IsNullOrEmpty(profile) || !Profile.IsMatch(profile) || String.IsNullOrEmpty(executable))
                throw new InvalidOperationException("The selected Edge profile could not be verified.");
            string path = Path.GetFullPath(executable);
            foreach (Environment.SpecialFolder folder in new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles })
            {
                string parent = Environment.GetFolderPath(folder);
                string expected = Path.Combine(parent, @"Microsoft\Edge\Application\msedge.exe");
                if (!String.Equals(path, expected, StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) continue;
                for (FileSystemInfo item = new FileInfo(path); item != null; item = new DirectoryInfo(Path.GetDirectoryName(item.FullName)))
                {
                    if ((item.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("The Edge installation path is redirected.");
                    if (String.Equals(item.FullName, parent, StringComparison.OrdinalIgnoreCase)) return path;
                }
            }
            throw new InvalidOperationException("The installed Microsoft Edge executable could not be verified.");
        }

        // Use the ordinary signed-in desktop to open Edge from an elevated installer.
        private static void OpenFromDesktop(string target, string args, string directory)
        {
            int pid;
            IntPtr hwnd=GetShellWindow();
            if (hwnd == IntPtr.Zero || GetWindowThreadProcessId(hwnd,out pid) == 0)
                throw new InvalidOperationException("The original Windows desktop is unavailable for Edge.");
            IntPtr explorer=OpenProcess(QueryLimitedInformation,false,pid), token=IntPtr.Zero;
            try
            {
                int max=32767, elevated, required;
                var path=new StringBuilder(max);
                string expected=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe");
                if (explorer == IntPtr.Zero || !QueryFullProcessImageName(explorer,0,path,ref max) ||
                    !String.Equals(path.ToString(),expected,StringComparison.OrdinalIgnoreCase) ||
                    !OpenProcessToken(explorer,TokenQuery,out token) ||
                    !GetTokenInformation(token,TokenElevation,out elevated,sizeof(int),out required) || elevated != 0)
                    throw new InvalidOperationException("The ordinary Windows desktop could not be verified for Edge.");
                using (var shellUser = new WindowsIdentity(token))
                using (var user = WindowsIdentity.GetCurrent())
                    if (!user.User.Equals(shellUser.User)) throw new InvalidOperationException("Edge belongs to a different Windows desktop user.");
            }
            finally { if (token!=IntPtr.Zero) CloseHandle(token); if (explorer!=IntPtr.Zero) CloseHandle(explorer); }

            object windows=null, desktop=null, document=null, application=null;
            try
            {
                windows=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("9BA05972-F6A8-11CF-A442-00A0C90A8F39"),true));
                object[] query={0,0,8,0,1}; // SWC_DESKTOP with SWFO_NEEDDISPATCH
                var refs=new ParameterModifier(5); refs[0]=true; refs[1]=true; refs[3]=true;
                desktop=windows.GetType().InvokeMember("FindWindowSW",BindingFlags.InvokeMethod,null,windows,query,
                    new[]{refs},CultureInfo.InvariantCulture,null);
                if (desktop==null || Convert.ToInt32(query[3],CultureInfo.InvariantCulture)!=hwnd.ToInt32())
                    throw new InvalidOperationException("The original Windows desktop changed while opening Edge.");
                document=desktop.GetType().InvokeMember("Document",BindingFlags.GetProperty,null,desktop,null);
                application=document.GetType().InvokeMember("Application",BindingFlags.GetProperty,null,document,null);
                application.GetType().InvokeMember("ShellExecute",BindingFlags.InvokeMethod,null,application,
                    new object[]{target,args,directory,"open",1});
            }
            finally
            {
                foreach(object value in new[]{application,document,desktop,windows})
                    if(value!=null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value);
            }
        }

        private static void OpenEdge(string executable, string profile, string parameters)
        {
            string edge = CheckEdge(executable, profile);
            string args = "--profile-directory=\"" + profile + "\" " + parameters;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                {
                    using (Process child = Process.Start(new ProcessStartInfo(edge, args) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(edge) }))
                        if (child == null) throw new InvalidOperationException("The normal Edge profile could not be opened.");
                    return;
                }
                OpenFromDesktop(edge,args,Path.GetDirectoryName(edge));
            }
        }

        private static void CheckLocalUrl(string url)
        {
            Uri parsed;
            if (url == null || !ProbeUrl.IsMatch(url) || !Uri.TryCreate(url, UriKind.Absolute, out parsed) || parsed.Port < 1024)
                throw new InvalidOperationException("The language check requires a local, one-time Guard URL.");
        }

        public static string GetManualDestination(string setting)
        {
            switch(setting)
            {
                case "windows-time-zone": return "ms-settings:dateandtime";
                case "windows-home-region":
                case "windows-regional-format":
                case "windows-preferred-languages": return "ms-settings:regionlanguage";
                case "edge-website-languages": return "microsoft-edge:edge://settings/languages";
                default: throw new ArgumentException("Unknown settings entry.");
            }
        }

        public static void OpenManualSetting(string setting)
        {
            string target=GetManualDestination(setting);
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent())
            {
                if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    OpenFromDesktop(target,"",Environment.SystemDirectory);
                else
                    using(Process process=Process.Start(new ProcessStartInfo(target){UseShellExecute=true,WorkingDirectory=Environment.SystemDirectory})) { }
            }
        }

        internal static void StartUserRegionHelper(string country,string ipv4,string requestId)
        {
            IPAddress address;
            if(country==null || !Regex.IsMatch(country,@"\A[A-Z]{2}\z") || !IPAddress.TryParse(ipv4,out address) ||
                address.AddressFamily!=AddressFamily.InterNetwork || address.ToString()!=ipv4 || requestId==null || !Regex.IsMatch(requestId,@"\A[a-f0-9]{32}\z"))
                throw new ArgumentException("Invalid regional target.");
            string path=Assembly.GetExecutingAssembly().Location;
            OpenFromDesktop(path,"--apply-user-region "+country+" "+ipv4+" "+requestId,Path.GetDirectoryName(path));
        }

        public static void OpenEdgeDocument(string executable, string profile, string url)
        {
            CheckLocalUrl(url);
            OpenEdge(executable, profile, url);
        }

        private static bool IsBrowserConnection(TcpClient request, string executable)
        {
            int remotePort = ((IPEndPoint)request.Client.RemoteEndPoint).Port;
            int localPort = ((IPEndPoint)request.Client.LocalEndPoint).Port;
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 4, 0);
            for (int attempt = 0; attempt < 3 && size >= 4 && size <= 16 * 1024 * 1024; attempt++)
            {
                int allocated = size;
                IntPtr data = Marshal.AllocHGlobal(allocated);
                try
                {
                    uint status = GetExtendedTcpTable(data, ref size, false, 2, 4, 0);
                    if (status == 122) continue;
                    if (status != 0) return false;
                    int count = Marshal.ReadInt32(data);
                    if (count < 0 || count > (allocated - 4) / 24) return false;
                    for (int i = 0; i < count; i++)
                    {
                        int row = 4 + 24 * i;
                        if (Marshal.ReadInt32(data, row + 4) != 0x0100007f || Marshal.ReadInt32(data, row + 12) != 0x0100007f) continue;
                        int local = Marshal.ReadByte(data,row+8)*256 + Marshal.ReadByte(data,row+9);
                        int peer = Marshal.ReadByte(data,row+16)*256 + Marshal.ReadByte(data,row+17);
                        if (local != remotePort || peer != localPort) continue;
                        IntPtr owner = OpenProcess(QueryLimitedInformation, false, Marshal.ReadInt32(data,row+20));
                        if (owner == IntPtr.Zero) return false;
                        try
                        {
                            int max = 32767; var path = new StringBuilder(max);
                            return QueryFullProcessImageName(owner, 0, path, ref max) && String.Equals(executable,path.ToString(),StringComparison.OrdinalIgnoreCase);
                        }
                        finally { CloseHandle(owner); }
                    }
                    return false;
                }
                finally { Marshal.FreeHGlobal(data); }
            }
            return false;
        }

        public static bool MatchesFirstLanguage(string value, string requested)
        {
            if (String.IsNullOrEmpty(value) || value.Length > 512 || String.IsNullOrEmpty(requested) || !Language.IsMatch(requested)) return false;
            string first = null;
            double firstQuality = 0;
            foreach (string piece in value.Split(','))
            {
                Match match = Regex.Match(piece.Trim(), @"\A([A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*|\*)(?:\s*;\s*q=(0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?))?\z", RegexOptions.IgnoreCase);
                if (!match.Success) return false;
                double weight = match.Groups[2].Success ? Double.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture) : 1;
                if (first == null) { first = match.Groups[1].Value; firstQuality = weight; }
                else if (weight > firstQuality) return false;
            }
            if (firstQuality <= 0 || first == "*") return false;
            return String.Equals(first, requested, StringComparison.OrdinalIgnoreCase) ||
                requested.StartsWith(first + "-", StringComparison.OrdinalIgnoreCase) ||
                first.StartsWith(requested + "-", StringComparison.OrdinalIgnoreCase);
        }

        private static string ReadHeader(NetworkStream stream, string target, int port)
        {
            byte[] bytes = new byte[16384]; int total = 0;
            while (total < bytes.Length)
            {
                int add = stream.Read(bytes, total, bytes.Length - total);
                if (add == 0) return null;
                total += add;
                string raw = Encoding.ASCII.GetString(bytes,0,total);
                int end = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (end < 0) continue;
                string[] lines = raw.Substring(0,end).Split(new[] {"\r\n"},StringSplitOptions.None);
                if (lines[0] != "GET " + target + " HTTP/1.1") return null;
                string found = null, host = null;
                foreach (string line in lines)
                {
                    if (line.StartsWith("Host:",StringComparison.OrdinalIgnoreCase))
                    { if (host != null) return null; host = line.Substring(5).Trim(); }
                    if (line.StartsWith("Accept-Language:",StringComparison.OrdinalIgnoreCase))
                    { if (found != null) return null; found = line.Substring(16).Trim(); }
                }
                return host == "127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture) && found != null && found.Length <= 512 &&
                    Regex.IsMatch(found, @"\A[A-Za-z0-9.,;= \t*-]+\z") ? found : null;
            }
            return null;
        }

        private static string ReadRecent(string executable, string profile, string requested, string preferences)
        {
            lock(ReceiptLock)
            {
                double age=(Stopwatch.GetTimestamp()-lastTick)/(double)Stopwatch.Frequency;
                if(lastHeader!=null && age>=0 && age<=300 && lastProfile==profile && lastRequested==requested &&
                    String.Equals(lastEdge,executable,StringComparison.OrdinalIgnoreCase) && lastPreferences==preferences)
                    return lastHeader;
            }
            return null;
        }

        public static string Recent(string executable, string profile, string requested, string preferences)
        {
            string header=ReadRecent(executable,profile,requested,preferences);
            if(header!=null && !MatchesFirstLanguage(header,requested))
                throw new InvalidOperationException("The local website received a different preferred language from Edge.");
            return header;
        }

        public static string Confirm(string executable, string profile, string requested, string preferences)
        {
            string edge=CheckEdge(executable,profile);
            if(String.IsNullOrEmpty(preferences) || preferences.Length>4096 || !MatchesFirstLanguage(preferences.Split(',')[0],requested))
                throw new InvalidOperationException("The selected Edge profile has not saved the requested first language.");
            string cached=ReadRecent(edge,profile,requested,preferences);
            if(cached!=null && MatchesFirstLanguage(cached,requested)) return cached;
            if(Interlocked.CompareExchange(ref checking,1,0)!=0)
                throw new InvalidOperationException("A website language check is already open.");
            try { return Receive(edge,profile,requested,preferences); }
            finally { Interlocked.Exchange(ref checking,0); }
        }

        // The caller must explicitly request a browser tab. Automatic checks use Recent.
        private static string Receive(string edge, string profile, string requested, string preferences)
        {
            if (requested == null || !Language.IsMatch(requested)) throw new InvalidOperationException("Invalid expected website language.");
            var server = new TcpListener(IPAddress.Loopback, 0);
            server.ExclusiveAddressUse = true;
            server.Start(8);
            try
            {
                int port = ((IPEndPoint)server.LocalEndpoint).Port;
                string path = "/guard-language/" + Guid.NewGuid().ToString("N");
                OpenEdgeDocument(edge, profile, "http://127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture) + path);
                var watch = Stopwatch.StartNew(); string observed = null;
                while (watch.ElapsedMilliseconds < 30000)
                {
                    if (!server.Pending()) { Thread.Sleep(35); continue; }
                    using (TcpClient peer = server.AcceptTcpClient())
                    {
                        peer.ReceiveTimeout = 1800; peer.SendTimeout = 1800;
                        if (!IsBrowserConnection(peer, edge)) continue;
                        try
                        {
                            NetworkStream stream = peer.GetStream();
                            string header = ReadHeader(stream,path,port);
                            if (String.IsNullOrEmpty(header)) continue;
                            observed = header;
                            bool passed = MatchesFirstLanguage(header, requested);
                            string page = "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>Guard 网站语言核对</title>" +
                                "<link rel=\"icon\" href=\"data:,\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
                                "<style>body{margin:12vh auto;padding:0 24px;max-width:640px;font:17px/1.6 'Segoe UI',sans-serif;background:#faf8f4;color:#302d29}h1{font-size:27px}code{overflow-wrap:anywhere}</style>" +
                                "<h1>" + (passed ? "网站语言已核对" : "网站收到的首选语言与目标不符") + "</h1><p>这台电脑的 Edge 向本页实际发送了</p><code>" +
                                WebUtility.HtmlEncode(header) + "</code><p>结果已传回 Guard，可以关闭此标签页。</p></html>";
                            byte[] body = Encoding.UTF8.GetBytes(page);
                            byte[] headers = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n" +
                                "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'\r\n" +
                                "Content-Length: " + body.Length.ToString(CultureInfo.InvariantCulture) + "\r\nConnection: close\r\n\r\n");
                            stream.Write(headers,0,headers.Length); stream.Write(body,0,body.Length); stream.Flush();
                            lock(ReceiptLock)
                            {
                                lastEdge=edge; lastProfile=profile; lastRequested=requested;
                                lastPreferences=preferences; lastHeader=header; lastTick=Stopwatch.GetTimestamp();
                            }
                            if (passed) return header;
                            throw new InvalidOperationException("The local website received a different preferred language from Edge.");
                        }
                        catch (IOException) { }
                    }
                }
                throw new InvalidOperationException(observed == null ? "The local website received no verifiable request from the selected Edge browser." :
                    "The local website received a different preferred language from Edge.");
            }
            finally { server.Stop(); }
        }
    }
}
