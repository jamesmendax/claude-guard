using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ClaudeGuard.Network
{
    public sealed class StoreDeploymentEvent
    {
        private static readonly Regex EventId = new Regex(@"<EventID(?:\s[^>]*)?>([0-9]+)</EventID>");
        private static readonly Regex EventRecordId = new Regex(@"<EventRecordID>([0-9]+)</EventRecordID>");
        private static readonly Regex EventTime = new Regex(@"<TimeCreated\s+SystemTime=['""]([^'""]+)['""]");
        public int Id { get; private set; }
        public long RecordId { get; private set; }
        public DateTime TimeCreated { get; private set; }
        public DateTime ReceivedUtc { get; private set; }
        public string Delivery { get; private set; }
        private readonly string xml;

        internal StoreDeploymentEvent(string payload, DateTime receivedUtc, string delivery)
        {
            Id = Int32.Parse(EventId.Match(payload).Groups[1].Value, CultureInfo.InvariantCulture);
            RecordId = Int64.Parse(EventRecordId.Match(payload).Groups[1].Value, CultureInfo.InvariantCulture);
            TimeCreated = DateTime.Parse(EventTime.Match(payload).Groups[1].Value,
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();
            ReceivedUtc = receivedUtc;
            Delivery = delivery;
            xml = payload;
        }

        public string ToXml() { return xml; }
    }

    public sealed class StoreDirectoryNotice
    {
        public string Package { get; private set; }
        public string WindowsAppsRoot { get; private set; }
        public DateTime ReceivedUtc { get; private set; }
        public string Action { get; private set; }

        internal StoreDirectoryNotice(string package, string windowsAppsRoot, DateTime receivedUtc, string action)
        {
            Package = package;
            WindowsAppsRoot = windowsAppsRoot;
            ReceivedUtc = receivedUtc;
            Action = action;
        }
    }

    public sealed class StoreDeploymentWake : IDisposable
    {
        private const string Channel = "Microsoft-Windows-AppXDeploymentServer/Operational";
        private const string Filter = "*[System[Provider[@Name='Microsoft-Windows-AppXDeployment-Server'] and " +
            "(EventID=574 or EventID=855 or EventID=617 or EventID=400)]]";
        private const int QueueLimit = 128;
        private static readonly Regex PackageName = new Regex(
            @"\A(?<name>[A-Za-z0-9.-]{3,50})_(?<version>[0-9]{1,5}(?:\.[0-9]{1,5}){3})_x64__(?<publisher>[a-z0-9]{13})\z");
        private static readonly Regex StoreRoot = new Regex(@"\A[A-Z]:\\(?:Program Files\\)?WindowsApps\z", RegexOptions.IgnoreCase);
        private readonly object gate = new object();
        private readonly Queue<StoreDeploymentEvent> queued = new Queue<StoreDeploymentEvent>();
        private readonly Queue<StoreDirectoryNotice> directories = new Queue<StoreDirectoryNotice>();
        private readonly AutoResetEvent wake = new AutoResetEvent(false);
        private readonly SubscribeCallback callback;
        private readonly IntPtr subscription;
        private FileSystemWatcher directoryWatcher;
        private string directoryRoot;
        private string familyName;
        private string publisher;
        private Version installedVersion;
        private bool directoryFailed;
        private bool overflow;
        private bool failed;
        private bool disposed;

        public StoreDeploymentWake()
        {
            callback = Receive;
            subscription = EvtSubscribe(IntPtr.Zero, IntPtr.Zero, Channel, Filter, IntPtr.Zero, IntPtr.Zero,
                callback, 1 | 0x10000 /* EvtSubscribeToFutureEvents | EvtSubscribeStrict */);
            if (subscription == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                wake.Dispose();
                throw new System.ComponentModel.Win32Exception(error, "Could not subscribe to Store deployment events.");
            }
        }

        private uint Receive(int action, IntPtr context, IntPtr eventHandle)
        {
            StoreDeploymentEvent item = null;
            DateTime received = DateTime.UtcNow;
            try
            {
                if (action == 1) // The subscription owns this handle until the callback returns.
                    item = new StoreDeploymentEvent(RenderXml(eventHandle), received, "Subscription");
            }
            catch (Exception) { }

            lock (gate)
            {
                if (disposed) return 0;
                if (action == 0) failed = true;
                if (item == null || queued.Count >= QueueLimit) overflow = true;
                else queued.Enqueue(item);
                wake.Set();
            }
            return 0;
        }

        public bool WatchDirectory(string verifiedWindowsAppsRoot, string installedPackageFullName)
        {
            Version version;
            if (String.IsNullOrEmpty(verifiedWindowsAppsRoot) || !StoreRoot.IsMatch(verifiedWindowsAppsRoot) ||
                String.IsNullOrEmpty(installedPackageFullName)) return false;
            Match installed = PackageName.Match(installedPackageFullName);
            if (!TryPackageVersion(installed, out version)) return false;
            FileSystemWatcher previous;
            lock (gate)
            {
                if (disposed) return false;
                if (directoryWatcher != null && !directoryFailed)
                    return String.Equals(directoryRoot, verifiedWindowsAppsRoot, StringComparison.OrdinalIgnoreCase) &&
                        installedVersion == version && familyName == installed.Groups["name"].Value &&
                        publisher == installed.Groups["publisher"].Value;
                previous = directoryWatcher;
                directoryWatcher = null;
                directories.Clear();
            }
            if (previous != null) previous.Dispose();

            FileSystemWatcher next = null;
            try
            {
                FileAttributes attributes = File.GetAttributes(verifiedWindowsAppsRoot);
                if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
                    return false;
                next = new FileSystemWatcher(verifiedWindowsAppsRoot);
                next.NotifyFilter = NotifyFilters.DirectoryName;
                next.Created += OnDirectoryCreated;
                next.Renamed += OnDirectoryRenamed;
                next.Error += OnDirectoryError;
                lock (gate)
                {
                    if (disposed) return false;
                    directoryRoot = verifiedWindowsAppsRoot;
                    familyName = installed.Groups["name"].Value;
                    publisher = installed.Groups["publisher"].Value;
                    installedVersion = version;
                    directoryFailed = false;
                    directoryWatcher = next;
                    try { next.EnableRaisingEvents = true; }
                    catch { directoryWatcher = null; throw; }
                    next = null;
                    return true;
                }
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (ArgumentException) { return false; }
            catch (System.ComponentModel.Win32Exception) { return false; }
            finally { if (next != null) next.Dispose(); }
        }

        private static bool TryPackageVersion(Match package, out Version version)
        {
            version = null;
            if (!package.Success) return false;
            string text = package.Groups["version"].Value;
            return Version.TryParse(text, out version) && version.ToString() == text &&
                version.Major <= UInt16.MaxValue && version.Minor <= UInt16.MaxValue &&
                version.Build <= UInt16.MaxValue && version.Revision <= UInt16.MaxValue;
        }

        private bool IsNewerPackage(string name)
        {
            if (String.IsNullOrEmpty(name) || installedVersion == null) return false;
            Match match = PackageName.Match(name);
            Version version;
            return TryPackageVersion(match, out version) && version > installedVersion &&
                match.Groups["name"].Value == familyName && match.Groups["publisher"].Value == publisher;
        }

        private void OnDirectoryCreated(object sender, FileSystemEventArgs change)
        {
            ReceiveDirectory(sender, change.Name, "Created");
        }

        private void OnDirectoryRenamed(object sender, RenamedEventArgs change)
        {
            ReceiveDirectory(sender, change.Name, "Renamed");
        }

        private void ReceiveDirectory(object sender, string name, string action)
        {
            DateTime received = DateTime.UtcNow;
            lock (gate)
            {
                if (disposed || directoryFailed || !Object.ReferenceEquals(sender, directoryWatcher) || !IsNewerPackage(name))
                    return;
                if (directories.Count >= QueueLimit) overflow = true;
                else directories.Enqueue(new StoreDirectoryNotice(name, directoryRoot, received, action));
                wake.Set();
            }
        }

        private void OnDirectoryError(object sender, ErrorEventArgs args)
        {
            lock (gate)
            {
                if (disposed || !Object.ReferenceEquals(sender, directoryWatcher)) return;
                directoryFailed = true;
                overflow = true;
                wake.Set();
            }
        }

        public StoreDirectoryNotice[] DrainDirectoryNotices()
        {
            lock (gate)
            {
                StoreDirectoryNotice[] batch = directories.ToArray();
                directories.Clear();
                return batch;
            }
        }

        public StoreDeploymentEvent QueryPreparation(string exactNewPackage)
        {
            lock (gate) { if (disposed || !IsNewerPackage(exactNewPackage)) return null; }
            // Exact package identity is validated above before embedding it in this XPath.
            string query = "*[System[Provider[@Name='Microsoft-Windows-AppXDeployment-Server'] and EventID=574" +
                " and TimeCreated[timediff(@SystemTime) <= 5000]] and " +
                "EventData[Data[@Name='PackageMoniker']='" + exactNewPackage + "']]";
            IntPtr result = EvtQuery(IntPtr.Zero, Channel, query, 0x201); // Channel path, newest first.
            if (result == IntPtr.Zero) return null;
            try
            {
                IntPtr item;
                int count;
                if (!EvtNext(result, 1, out item, 20, 0, out count) || count != 1) return null;
                try { return new StoreDeploymentEvent(RenderXml(item), DateTime.UtcNow, "Query"); }
                finally { EvtClose(item); }
            }
            finally { EvtClose(result); }
        }

        private static string RenderXml(IntPtr eventHandle)
        {
            int size, count;
            if (EvtRender(IntPtr.Zero, eventHandle, 1, 0, IntPtr.Zero, out size, out count) ||
                Marshal.GetLastWin32Error() != 122 || size < 2 || size > 262144)
                throw new InvalidOperationException("The Store event XML size could not be read.");
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!EvtRender(IntPtr.Zero, eventHandle, 1, size, buffer, out size, out count))
                    throw new InvalidOperationException("The Store event XML could not be read.");
                return Marshal.PtrToStringUni(buffer, size / 2 - 1);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public StoreDeploymentEvent[] Drain()
        {
            lock (gate)
            {
                StoreDeploymentEvent[] batch = queued.ToArray();
                queued.Clear();
                return batch;
            }
        }

        public bool TakeReplayRequest()
        {
            lock (gate)
            {
                bool value = overflow;
                overflow = false;
                return value;
            }
        }

        public bool Failed { get { lock (gate) return failed; } }
        public bool DirectoryWatching { get { lock (gate) return directoryWatcher != null && !directoryFailed; } }
        public bool Wait(int milliseconds) { return wake.WaitOne(milliseconds); }

        public void Dispose()
        {
            FileSystemWatcher directory;
            lock (gate)
            {
                if (disposed) return;
                disposed = true;
                directory = directoryWatcher;
                directoryWatcher = null;
            }
            try { if (directory != null) directory.Dispose(); }
            finally
            {
                try { EvtClose(subscription); }
                finally { wake.Dispose(); }
            }
            GC.KeepAlive(callback);
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint SubscribeCallback(int action, IntPtr context, IntPtr eventHandle);
        [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr EvtSubscribe(IntPtr session, IntPtr signal, string channel, string query,
            IntPtr bookmark, IntPtr context, SubscribeCallback callback, int flags);
        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern bool EvtRender(IntPtr context, IntPtr eventHandle, int flags, int size, IntPtr buffer,
            out int bytesUsed, out int propertyCount);
        [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr EvtQuery(IntPtr session, string path, string query, int flags);
        [DllImport("wevtapi.dll", SetLastError = true)]
        private static extern bool EvtNext(IntPtr resultSet, int eventSize, out IntPtr eventHandle, int timeout,
            int flags, out int returned);
        [DllImport("wevtapi.dll")]
        private static extern bool EvtClose(IntPtr handle);
    }

    // Windows Filtering Platform ALE layers authorize both the first packet and
    // reauthorized flows. The filter weights apply only in this sublayer.
    // A permitted tuple does not override other Windows security providers.
    public static class GuardPolicy
    {
        internal static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        internal static readonly Guid Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        internal static readonly Guid Listen4 = new Guid("88bb5dad-76d7-4227-9c71-df0a3ed7be7e");
        internal static readonly Guid Listen6 = new Guid("7ac9de24-17dd-4814-b4bd-a9fbc95a321b");
        internal static readonly Guid Accept4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
        internal static readonly Guid Accept6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
        internal static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        internal static readonly Guid PackageId = new Guid("71bc78fa-f17c-4997-a602-6abb261f351c");
        internal static readonly Guid UserId = new Guid("af043a0a-b34d-4f86-979c-c90371af6e66");
        internal static readonly Guid LocalIp = new Guid("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
        internal static readonly Guid RemoteIp = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        internal static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        internal static readonly Guid LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
        internal static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");

        public static string ReadVerifiedAppDevice(string existingImage)
        {
            return NativeSession.ReadVerifiedAppDevice(NormalizePath(existingImage));
        }

        public static PolicyPlan CreateStorePathBlocks(string[] paths, string device, Guid deploymentId)
        {
            if (String.IsNullOrEmpty(device) ||
                !device.StartsWith(@"\device\", StringComparison.Ordinal) ||
                device.IndexOfAny(new[] { '\0', '/', ':', '*', '?' }) >= 0 ||
                device.IndexOf('\\', 8) >= 0)
                throw new ArgumentException("A verified local WFP device is required.");
            var baseline = new List<Rule>();
            foreach (string path in NormalizePaths(paths))
            {
                var identity = new Condition(AppId, new StoreAppIdentity(path, device));
                baseline.Add(new Rule(Connect4, false, identity));
                baseline.Add(new Rule(Connect6, false, identity));
            }
            if (baseline.Count == 0) throw new ArgumentException("At least one exact update image is required.");
            return new PolicyPlan(baseline.ToArray(), new Rule[0]).WithEarlyBootBlocks().ForPersistentUse(deploymentId);
        }

        public static void VerifyStorePathIdentity(string existingImage, string device)
        {
            NativeSession.VerifyStorePathIdentity(new StoreAppIdentity(NormalizePath(existingImage), device), false);
        }

        public static void ValidateProposedStorePath(string image, string device)
        {
            NativeSession.VerifyStorePathIdentity(new StoreAppIdentity(NormalizePath(image), device), true);
        }

        public static PolicyPlan Create(
            string[] protectedPaths, string[] desktopPaths, string[] packageSids, string serviceSid,
            string relayPath, ushort relayPort, string upstreamAddress, ushort upstreamPort)
        {
            return Create(protectedPaths, desktopPaths, packageSids, serviceSid, relayPath, relayPort, upstreamAddress, upstreamPort, null);
        }

        public static PolicyPlan Create(
            string[] protectedPaths, string[] desktopPaths, string[] packageSids, string serviceSid,
            string relayPath, ushort relayPort, string upstreamAddress, ushort upstreamPort, string healthProbePath)
        {
            return CreateWithServices(protectedPaths, desktopPaths, packageSids,
                String.IsNullOrEmpty(serviceSid) ? null : new[] { serviceSid },
                relayPath, relayPort, upstreamAddress, upstreamPort, healthProbePath);
        }

        public static PolicyPlan CreateWithServices(
            string[] protectedPaths, string[] desktopPaths, string[] packageSids, string[] serviceSids,
            string relayPath, ushort relayPort, string upstreamAddress, ushort upstreamPort, string healthProbePath)
        {
            if (protectedPaths == null || protectedPaths.Length == 0 ||
                desktopPaths == null || desktopPaths.Length == 0 ||
                relayPort < 1024 || relayPort >= 49152 || upstreamPort == 0)
                throw new ArgumentException("Invalid application or port scope.");

            SortedSet<string> applications = NormalizePaths(protectedPaths);
            SortedSet<string> permitted = NormalizePaths(desktopPaths);
            relayPath = NormalizePath(relayPath);
            if (!permitted.IsSubsetOf(applications) || applications.Contains(relayPath))
                throw new ArgumentException("The relay and protected process scopes must be disjoint.");
            IPAddress upstream;
            if (!IPAddress.TryParse(upstreamAddress, out upstream) || upstream.AddressFamily != AddressFamily.InterNetwork ||
                !String.Equals(upstream.ToString(), upstreamAddress, StringComparison.Ordinal) ||
                IPAddress.Any.Equals(upstream) || upstream.GetAddressBytes()[0] >= 224 ||
                (IPAddress.IsLoopback(upstream) && upstreamPort == relayPort))
                throw new ArgumentException("The upstream must be one literal IPv4 endpoint.");

            List<Rule> baseline = new List<Rule>();
            List<Rule> admission = new List<Rule>();
            Condition relay = new Condition(AppId, relayPath);
            foreach (string path in applications)
                DenyIdentity(baseline, new Condition(AppId, path));
            foreach (string packageSid in new SortedSet<string>(packageSids ?? new string[0], StringComparer.OrdinalIgnoreCase))
            {
                SecurityIdentifier sid = new SecurityIdentifier(packageSid);
                if (!sid.Value.StartsWith("S-1-15-2-", StringComparison.Ordinal) || sid.BinaryLength != 40)
                    throw new ArgumentException("A package-specific AppContainer SID is required.");
                DenyIdentity(baseline, new Condition(PackageId, sid));
            }
            foreach (string serviceSid in new SortedSet<string>(serviceSids ?? new string[0], StringComparer.OrdinalIgnoreCase))
            {
                SecurityIdentifier sid = new SecurityIdentifier(serviceSid);
                if (!sid.Value.StartsWith("S-1-5-80-", StringComparison.Ordinal) || sid.BinaryLength != 32)
                    throw new ArgumentException("A dedicated service SID is required.");
                DenyIdentity(baseline, new Condition(UserId, sid));
            }
            DenyIdentity(baseline, relay);
            baseline.Add(new Rule(Connect4, false, new Condition(RemoteIp, IPAddress.Loopback),
                new Condition(RemotePort, relayPort)));
            foreach (Guid layer in new Guid[] { Listen4, Listen6, Accept4, Accept6 })
                baseline.Add(new Rule(layer, false, new Condition(LocalPort, relayPort)));

            // Only this executable may accept on the dedicated port, even if
            // another program binds it during a relay restart.
            baseline.Add(new Rule(Listen4, true, relay, new Condition(LocalIp, IPAddress.Loopback),
                new Condition(LocalPort, relayPort)));
            baseline.Add(new Rule(Accept4, true, relay, new Condition(LocalIp, IPAddress.Loopback),
                new Condition(RemoteIp, IPAddress.Loopback), new Condition(LocalPort, relayPort),
                new Condition(Protocol, (byte)ProtocolType.Tcp)));
            baseline.Add(AllowConnect(relay, upstream, upstreamPort));
            if (!String.IsNullOrEmpty(healthProbePath))
            {
                string observer = NormalizePath(healthProbePath);
                if (applications.Contains(observer) || String.Equals(relayPath, observer, StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("The health probe requires its own restricted executable.");
                Condition healthProbe = new Condition(AppId, observer);
                DenyIdentity(baseline, healthProbe);
                baseline.Add(AllowConnect(healthProbe, IPAddress.Loopback, relayPort));
            }
            foreach (string path in permitted)
                admission.Add(AllowConnect(new Condition(AppId, path), IPAddress.Loopback, relayPort));
            return new PolicyPlan(baseline.ToArray(), admission.ToArray());
        }

        public static PolicyPlan CreateForPackage(
            string[] protectedPaths, string[] desktopPaths, string[] packageSids, string[] serviceSids,
            string desktopPackageSid, string relayPath, ushort relayPort, string upstreamAddress, ushort upstreamPort,
            string healthProbePath)
        {
            var desktop = new SecurityIdentifier(desktopPackageSid);
            PolicyPlan closed = CreateWithServices(protectedPaths, desktopPaths, packageSids, serviceSids,
                relayPath, relayPort, upstreamAddress, upstreamPort, healthProbePath);
            Rule block = Array.Find(closed.Baseline, rule => !rule.Permit && rule.Layer == Connect4 &&
                rule.Conditions.Length == 1 && rule.Conditions[0].Field == PackageId &&
                desktop.Equals(rule.Conditions[0].Data));
            if (block == null)
                throw new ArgumentException("The Desktop package must be in the blocked package scope.", "desktopPackageSid");

            return new PolicyPlan(closed.Baseline, new[] {
                AllowConnect(block.Conditions[0], IPAddress.Loopback, relayPort)
            });
        }

        public static PolicyPlan CreateForAppContainer(
            string[] protectedPaths, string[] desktopPaths, string[] packageSids, string[] serviceSids,
            string appContainerSid, string relayPath, ushort relayPort, string upstreamAddress, ushort upstreamPort,
            string healthProbePath)
        {
            var container = new SecurityIdentifier(appContainerSid);
            var protectedPackages = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string sid in packageSids ?? new string[0])
                protectedPackages.Add(new SecurityIdentifier(sid).Value);
            if (!protectedPackages.Add(container.Value))
                throw new ArgumentException("The guarded AppContainer must be distinct from the original package identity.");
            var scopedPackageSids = new string[protectedPackages.Count];
            protectedPackages.CopyTo(scopedPackageSids);
            PolicyPlan closed = CreateWithServices(protectedPaths, desktopPaths, scopedPackageSids, serviceSids,
                relayPath, relayPort, upstreamAddress, upstreamPort, healthProbePath);

            // One lease applies to the whole isolated process tree. The regular
            // package and executable identities never receive the proxy permit.
            return new PolicyPlan(closed.Baseline, new[] {
                AllowConnect(new Condition(PackageId, container), IPAddress.Loopback, relayPort)
            });
        }

        internal static SortedSet<string> NormalizePaths(IEnumerable<string> paths)
        {
            SortedSet<string> normalized = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in paths)
                normalized.Add(NormalizePath(path));
            return normalized;
        }

        private static string NormalizePath(string path)
        {
            if (String.IsNullOrEmpty(path) || path.Length < 4 || path[1] != ':' || path[2] != '\\' ||
                !String.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("An absolute local executable path is required.");
            return Path.GetFullPath(path);
        }

        private static void DenyIdentity(List<Rule> rules, Condition identity)
        {
            foreach (Guid layer in new Guid[] { Connect4, Connect6, Accept4, Accept6 })
                rules.Add(new Rule(layer, false, identity));
        }

        private static Rule AllowConnect(Condition subject, IPAddress address, ushort port)
        {
            return new Rule(Connect4, true, subject, new Condition(RemoteIp, address),
                new Condition(RemotePort, port), new Condition(Protocol, (byte)ProtocolType.Tcp));
        }
    }

    internal sealed class StoreAppIdentity
    {
        internal readonly string Path;
        internal readonly string Device;
        internal StoreAppIdentity(string path, string device)
        {
            Path = path;
            Device = device;
        }
        public override string ToString()
        {
            return Device + Path.Substring(2).ToLowerInvariant() + "|" + Path;
        }
    }

    public sealed class PolicyPlan
    {
        internal readonly Rule[] Baseline;
        internal readonly Rule[] Admission;
        internal readonly Rule[] Boot;
        internal PolicyPlan(Rule[] baseline, Rule[] admission, Guid persistentSublayer = default(Guid), Rule[] boot = null)
        {
            Baseline = baseline;
            Admission = admission;
            Boot = boot ?? new Rule[0];
            PersistentSublayer = persistentSublayer;
        }
        public int BaseCount { get { return Baseline.Length; } }
        public int AdmissionCount { get { return Admission.Length; } }
        public int BootCount { get { return Boot.Length; } }
        public Guid PersistentSublayer { get; private set; }

        public Guid[] GetBaselineKeys()
        {
            return Array.ConvertAll(Baseline, rule => rule.Key);
        }

        public Guid[] GetBootKeys()
        {
            return Array.ConvertAll(Boot, rule => rule.Key);
        }

        public PolicyPlan WithRegisteredPackageAdmission(string[] approvedPaths)
        {
            if (PersistentSublayer == Guid.Empty || Admission.Length != 1 || !Admission[0].Permit ||
                Admission[0].Layer != GuardPolicy.Connect4 || Admission[0].Conditions.Length != 4 ||
                Admission[0].Conditions[0].Field != GuardPolicy.PackageId || approvedPaths == null)
                throw new InvalidOperationException("An installed package relay policy is required.");

            var images = GuardPolicy.NormalizePaths(approvedPaths);
            var baselineImages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Rule rule in Baseline)
            {
                if (!rule.Permit && rule.Layer == GuardPolicy.Connect4 && rule.Conditions.Length == 1 &&
                    rule.Conditions[0].Field == GuardPolicy.AppId && rule.Conditions[0].Data is string)
                    baselineImages.Add((string)rule.Conditions[0].Data);
            }
            if (images.Count == 0 || !images.IsSubsetOf(baselineImages))
                throw new ArgumentException("The registered package images must already be protected by this policy.");

            // Keep all installed persistent and boot filter identities. Refine only the
            // short-lived permit with the registered image so v2 cannot use v1's lease.
            var rules = new List<Rule>();
            foreach (string image in images)
            {
                var conditions = new List<Condition> { new Condition(GuardPolicy.AppId, image) };
                conditions.AddRange(Admission[0].Conditions);
                rules.Add(new Rule(GuardPolicy.Connect4, true, conditions.ToArray()));
            }
            using (SHA256 hash = SHA256.Create())
                return new PolicyPlan(Baseline, BindRuleKeys(hash, PersistentSublayer, rules.ToArray(), 1),
                    PersistentSublayer, Boot);
        }

        public PolicyPlan WithEarlyBootBlocks()
        {
            if (PersistentSublayer != Guid.Empty)
                throw new InvalidOperationException("Select the boot rules before binding the persistent policy.");
            // Only the application, package and service connection blocks have
            // boot-time counterparts. No early permit or machine-wide rule is added.
            Rule[] blocks = Array.FindAll(Baseline, rule => !rule.Permit &&
                (rule.Layer == GuardPolicy.Connect4 || rule.Layer == GuardPolicy.Connect6) &&
                rule.Conditions.Length == 1 &&
                (rule.Conditions[0].Field == GuardPolicy.AppId || rule.Conditions[0].Field == GuardPolicy.PackageId ||
                 rule.Conditions[0].Field == GuardPolicy.UserId));
            return new PolicyPlan(Baseline, Admission, Guid.Empty,
                Array.ConvertAll(blocks, rule => new Rule(rule.Layer, false, rule.Conditions)));
        }

        public PolicyPlan ForPersistentUse(Guid deploymentId)
        {
            if (deploymentId == Guid.Empty)
                throw new ArgumentException("A saved deployment identity is required.");

            using (SHA256 hash = SHA256.Create())
            using (MemoryStream stream = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                writer.Write("Claude Guard network policy version 1");
                writer.Write(deploymentId.ToByteArray());
                WriteRules(writer, Baseline);
                WriteRules(writer, Admission);
                if (Boot.Length != 0)
                    WriteRules(writer, Boot);
                writer.Flush();
                Guid sublayer = HashGuid(hash, stream.ToArray());
                return new PolicyPlan(
                    BindRuleKeys(hash, sublayer, Baseline, 0),
                    BindRuleKeys(hash, sublayer, Admission, 1), sublayer,
                    BindRuleKeys(hash, sublayer, Boot, 2));
            }
        }

        private static void WriteRules(BinaryWriter writer, Rule[] rules)
        {
            writer.Write(rules.Length);
            foreach (Rule rule in rules)
            {
                writer.Write(rule.Layer.ToByteArray());
                writer.Write(rule.Permit);
                writer.Write(rule.Conditions.Length);
                foreach (Condition condition in rule.Conditions)
                {
                    writer.Write(condition.Field.ToByteArray());
                    string value = Convert.ToString(condition.Data, CultureInfo.InvariantCulture);
                    writer.Write(value.ToUpperInvariant());
                }
            }
        }

        private static Rule[] BindRuleKeys(SHA256 hash, Guid sublayer, Rule[] rules, byte group)
        {
            byte[] keyData = new byte[21];
            sublayer.ToByteArray().CopyTo(keyData, 0);
            keyData[16] = group;
            Rule[] bound = new Rule[rules.Length];
            for (int index = 0; index < rules.Length; index++)
            {
                BitConverter.GetBytes(index).CopyTo(keyData, 17);
                Rule rule = rules[index];
                bound[index] = new Rule(HashGuid(hash, keyData), rule.Layer, rule.Permit, rule.Conditions);
            }
            return bound;
        }

        private static Guid HashGuid(SHA256 hash, byte[] data)
        {
            byte[] digest = hash.ComputeHash(data);
            byte[] key = new byte[16];
            Array.Copy(digest, key, key.Length);
            return new Guid(key);
        }
    }

    internal sealed class Rule
    {
        internal readonly Guid Key;
        internal readonly Guid Layer;
        internal readonly bool Permit;
        internal readonly Condition[] Conditions;
        internal Rule(Guid layer, bool permit, params Condition[] conditions)
            : this(Guid.NewGuid(), layer, permit, conditions) {}

        internal Rule(Guid key, Guid layer, bool permit, params Condition[] conditions)
        {
            Key = key;
            Layer = layer;
            Permit = permit;
            Conditions = conditions;
        }
    }

    internal sealed class Condition
    {
        internal readonly Guid Field;
        internal readonly object Data;
        internal Condition(Guid field, object data)
        {
            Field = field;
            Data = data;
        }
    }

    public sealed class AdmissionRenewal
    {
        public long Period { get; private set; }
        public DateTime RenewedUtc { get; private set; }
        public double? PreviousOverlapMilliseconds { get; private set; }

        internal AdmissionRenewal(long period, DateTime renewedUtc, double? previousOverlapMilliseconds)
        {
            Period = period;
            RenewedUtc = renewedUtc;
            PreviousOverlapMilliseconds = previousOverlapMilliseconds;
        }
    }

    // A separate dynamic session owns the desktop permits. An installed
    // baseline remains in force across controller restarts.
    public sealed class WindowsPolicySession : IDisposable
    {
        private readonly PolicyPlan plan;
        private readonly Guid sublayer;
        private readonly bool persistent;
        private readonly object admissionLock = new object();
        private NativeSession baseline;
        private NativeSession admission;
        private ushort assignedSublayerWeight;
        private bool baselineInstalled;
        private Timer admissionTimer;
        private RegisteredWaitHandle closeWait;
        private long admissionDeadline;
        private long admissionPeriod;
        private DateTime admissionProofExpiryUtc;
        private AdmissionRenewal admissionRenewal;
        private EventWaitHandle expirySignal;
        private bool notifyOnExpiry;

        public const ushort RequestedSublayerWeight = UInt16.MaxValue;
        public ushort AssignedSublayerWeight { get { return assignedSublayerWeight; } }

        public WindowsPolicySession(PolicyPlan plan) : this(plan, false, 0) {}

        private WindowsPolicySession(PolicyPlan plan, bool persistent, ushort recordedWeight)
        {
            if (plan == null) throw new ArgumentNullException("plan");
            if (persistent != (plan.PersistentSublayer != Guid.Empty))
                throw new ArgumentException("The policy plan must match the requested lifetime.");
            if (!persistent && plan.BootCount != 0)
                throw new ArgumentException("Boot rules require an installed policy.");
            this.plan = plan;
            this.persistent = persistent;
            assignedSublayerWeight = recordedWeight;
            sublayer = persistent ? plan.PersistentSublayer : Guid.NewGuid();
            baseline = new NativeSession(false);
            try
            {
                if (!persistent)
                {
                    baseline.Transaction(delegate
                    {
                        assignedSublayerWeight = baseline.CreateSublayer(sublayer);
                        baseline.AddRules(sublayer, plan.Baseline);
                    });
                    baselineInstalled = true;
                }
                VerifyBaseline();
                baseline.VerifyAbsent(plan.Admission);
                if (persistent) baseline.VerifyScope(sublayer, plan.Baseline, plan.Boot);
                baselineInstalled = true;
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public static ushort InstallPersistent(PolicyPlan plan)
        {
            return InstallPersistent(plan, null);
        }

        public static ushort InstallPersistent(PolicyPlan plan, Action<ushort> recordBeforeCommit)
        {
            Guid key = RequirePersistentKey(plan);
            ushort weight = 0;
            using (NativeSession session = new NativeSession(false))
            {
                session.Transaction(delegate
                {
                    weight = session.CreateSublayer(key, true);
                    session.AddRules(key, plan.Baseline, true);
                    session.AddRules(key, plan.Boot, bootTime: true);
                    session.VerifySublayer(key, true, weight);
                    session.VerifyRules(key, plan.Baseline, true);
                    session.VerifyRules(key, plan.Boot, bootTime: true);
                    session.VerifyScope(key, plan.Baseline, plan.Boot);
                    if (recordBeforeCommit != null) recordBeforeCommit(weight);
                });
            }
            return weight;
        }

        public static WindowsPolicySession AttachPersistent(PolicyPlan plan, ushort recordedWeight)
        {
            return new WindowsPolicySession(plan, true, recordedWeight);
        }

        public static int ReadBootFilterCount(PolicyPlan plan, ushort recordedWeight)
        {
            return ReadBootFilterCount(plan, recordedWeight, false);
        }

        public static int ReadBootFilterCount(PolicyPlan plan, ushort recordedWeight, bool allowMissing)
        {
            Guid key = RequirePersistentKey(plan);
            using (NativeSession session = new NativeSession(false))
            {
                if (!session.VerifySublayer(key, true, recordedWeight, allowMissing))
                {
                    session.VerifyAbsent(plan.Baseline);
                    session.VerifyAbsent(plan.Boot);
                    session.VerifyAbsent(plan.Admission);
                    return 0;
                }
                session.VerifyRules(key, plan.Baseline, true);
                session.VerifyRules(key, plan.Boot, bootTime: true);
                session.VerifyAbsent(plan.Admission);
                session.VerifyScope(key, plan.Baseline, plan.Boot);
                return plan.BootCount;
            }
        }

        public static void VerifyNoPersistentAdmission(PolicyPlan plan, ushort recordedWeight)
        {
            Guid key = RequirePersistentKey(plan);
            using (NativeSession session = new NativeSession(false))
            {
                session.VerifyAbsent(plan.Admission);
                if (session.VerifySublayer(key, true, recordedWeight, allowMissing: true))
                    session.VerifyScope(key, plan.Baseline, plan.Boot);
                else
                {
                    session.VerifyAbsent(plan.Baseline);
                    session.VerifyAbsent(plan.Boot);
                }
            }
        }

        public static void RemovePersistent(PolicyPlan plan, ushort recordedWeight)
        {
            Guid key = RequirePersistentKey(plan);
            using (NativeSession session = new NativeSession(false))
            {
                session.Transaction(delegate
                {
                    session.VerifyAbsent(plan.Admission);
                    if (!session.VerifySublayer(key, true, recordedWeight, allowMissing: true)) return;
                    // Rollback uses the committed rule identities even if an
                    // update has removed an executable on which they were based.
                    session.RemoveOwnedRules(key, plan.Boot, bootTime: true);
                    session.RemoveOwnedRules(key, plan.Baseline, persistent: true);
                    // BFE refuses to remove a sublayer referenced by an
                    // unexpected filter. The transaction then restores our rules.
                    session.RemoveSublayer(key);
                });
                session.VerifyAbsent(plan.Baseline);
                session.VerifyAbsent(plan.Boot);
                if (session.VerifySublayer(key, true, recordedWeight, allowMissing: true))
                    throw new InvalidOperationException("The removed policy sublayer remains installed.");
            }
        }

        private static Guid RequirePersistentKey(PolicyPlan plan)
        {
            if (plan == null || plan.PersistentSublayer == Guid.Empty)
                throw new ArgumentException("The persistent rules require a bound policy plan.");
            return plan.PersistentSublayer;
        }

        private void VerifyBaseline()
        {
            baseline.VerifySublayer(sublayer, persistent, assignedSublayerWeight);
            baseline.VerifyRules(sublayer, plan.Baseline, persistent);
            if (persistent) baseline.VerifyRules(sublayer, plan.Boot, bootTime: true);
        }

        public void Open()
        {
            if (persistent)
                throw new InvalidOperationException("The installed policy requires a bounded lease.");
            lock (admissionLock) OpenAdmission();
        }
        public void OpenUntil(DateTime deadlineUtc, EventWaitHandle closeSignal)
        {
            OpenUntil(deadlineUtc, closeSignal, true);
        }
        public void OpenUntil(DateTime deadlineUtc, EventWaitHandle closeSignal, bool closeOnProofExpiry)
        {
            OpenUntilWithReceipt(deadlineUtc, closeSignal, closeOnProofExpiry);
        }
        public AdmissionRenewal OpenUntilWithReceipt(DateTime deadlineUtc, EventWaitHandle closeSignal, bool closeOnProofExpiry)
        {
            if (deadlineUtc.Kind != DateTimeKind.Utc) throw new ArgumentException("UTC lease required.", "deadlineUtc");
            if (closeSignal == null) throw new ArgumentNullException("closeSignal");
            lock (admissionLock)
            {
                long now = Stopwatch.GetTimestamp();
                double seconds = (deadlineUtc - DateTime.UtcNow).TotalSeconds;
                if (seconds <= 0 || seconds > 15 || closeSignal.WaitOne(0))
                    throw new InvalidOperationException("Admission requires a live lease and close event.");
                if (admissionDeadline != 0 && admissionDeadline <= now)
                {
                    ExpireAdmission(null);
                    throw new InvalidOperationException("The previous admission already expired.");
                }
                long previousDeadline = admissionDeadline;
                bool continuous = admission != null && previousDeadline > now &&
                    Object.ReferenceEquals(expirySignal, closeSignal);
                // A repeat readback of the same proof keeps its original renewal time and deadline.
                bool sameProof = continuous && admissionRenewal != null && admissionProofExpiryUtc == deadlineUtc;
                try
                {
                    if (!sameProof) admissionDeadline = now + (long)(seconds * Stopwatch.Frequency);
                    DateTime renewedUtc = DateTime.UtcNow;
                    long renewedAt = Stopwatch.GetTimestamp();
                    if (previousDeadline != 0 && previousDeadline <= renewedAt)
                        throw new InvalidOperationException("The previous admission already expired.");
                    notifyOnExpiry = closeOnProofExpiry;
                    if (admissionTimer == null) admissionTimer = new Timer(ExpireAdmission);
                    if (!Object.ReferenceEquals(expirySignal, closeSignal))
                    {
                        if (closeWait != null) closeWait.Unregister(null);
                        expirySignal = closeSignal;
                        closeWait = ThreadPool.RegisterWaitForSingleObject(closeSignal, CloseOnSignal,
                            closeSignal, Timeout.Infinite, true);
                    }
                    ScheduleExpiry();
                    OpenAdmission();
                    if (admissionDeadline <= Stopwatch.GetTimestamp() || closeSignal.WaitOne(0))
                        throw new InvalidOperationException("Admission expired before verification finished.");
                    if (!sameProof)
                    {
                        if (!continuous) admissionPeriod = checked(admissionPeriod + 1);
                        double? overlap = continuous ? (double?)(1000.0 * (previousDeadline - renewedAt) / Stopwatch.Frequency) : null;
                        admissionRenewal = new AdmissionRenewal(admissionPeriod, renewedUtc, overlap);
                        admissionProofExpiryUtc = deadlineUtc;
                    }
                    return admissionRenewal;
                }
                catch
                {
                    DropAdmission();
                    ClearAdmissionLease();
                    throw;
                }
            }
        }
        private void OpenAdmission()
        {
            if (!baselineInstalled) throw new InvalidOperationException("No verified baseline.");
            try
            {
                VerifyBaseline();
                if (admission == null)
                {
                    admission = new NativeSession(true);
                    admission.Transaction(delegate { admission.AddRules(sublayer, plan.Admission); });
                }
                admission.VerifyRules(sublayer, plan.Admission);
                if (persistent) admission.VerifyScope(sublayer, plan.Baseline, plan.Boot, plan.Admission);
            }
            catch
            {
                DropAdmission();
                throw;
            }
        }
        public int ReadLiveAdmissionCount()
        {
            lock (admissionLock)
            {
                if (!persistent || admission == null || admissionDeadline <= Stopwatch.GetTimestamp() ||
                    expirySignal == null || expirySignal.WaitOne(0)) return 0;
                // These keys and conditions were read back on open. Query the
                // live filter set even if Windows has since uninstalled v1.
                admission.VerifyScope(sublayer, plan.Baseline, plan.Boot, plan.Admission);
                return admissionDeadline > Stopwatch.GetTimestamp() && !expirySignal.WaitOne(0)
                    ? plan.AdmissionCount : 0;
            }
        }

        public void Close()
        {
            lock (admissionLock)
            {
                DropAdmission();
                ClearAdmissionLease();
                if (baselineInstalled)
                {
                    VerifyBaseline();
                    baseline.VerifyAbsent(plan.Admission);
                    if (persistent) baseline.VerifyScope(sublayer, plan.Baseline, plan.Boot);
                }
            }
        }
        private void DropAdmission()
        {
            if (admission == null) return;
            admission.Dispose();
            admission = null;
        }
        private void ScheduleExpiry()
        {
            double remaining = (admissionDeadline - Stopwatch.GetTimestamp()) * 1000.0 / Stopwatch.Frequency;
            admissionTimer.Change(Math.Max(1, (int)Math.Ceiling(remaining)), Timeout.Infinite);
        }
        private void ClearAdmissionLease()
        {
            admissionDeadline = 0;
            admissionRenewal = null;
            expirySignal = null;
            notifyOnExpiry = false;
            if (closeWait != null)
            {
                closeWait.Unregister(null);
                closeWait = null;
            }
            if (admissionTimer != null) admissionTimer.Change(Timeout.Infinite, Timeout.Infinite);
        }
        private void CloseOnSignal(object signal, bool timedOut)
        {
            lock (admissionLock)
            {
                if (Object.ReferenceEquals(signal, expirySignal)) RevokeAdmission(false);
            }
        }
        private void ExpireAdmission(object ignored)
        {
            lock (admissionLock)
            {
                if (admissionDeadline == 0) return;
                if (admissionDeadline > Stopwatch.GetTimestamp())
                {
                    ScheduleExpiry();
                    return;
                }
                RevokeAdmission(notifyOnExpiry);
            }
        }
        private void RevokeAdmission(bool notify)
        {
            EventWaitHandle signal = notify ? expirySignal : null;
            try
            {
                DropAdmission();
                ClearAdmissionLease();
            }
            catch (InvalidOperationException)
            {
                admissionDeadline = Stopwatch.GetTimestamp();
                admissionTimer.Change(100, Timeout.Infinite);
            }
            // Only the controller's filter readback produces a closed receipt.
            try { if (signal != null) signal.Set(); }
            catch (ObjectDisposedException) { }
        }
        public void Dispose()
        {
            try { Close(); }
            finally
            {
                lock (admissionLock)
                {
                    ClearAdmissionLease();
                    if (admissionTimer != null)
                    {
                        admissionTimer.Dispose();
                        admissionTimer = null;
                    }
                }
                if (baseline != null)
                {
                    try
                    {
                        if (baselineInstalled && !persistent)
                            baseline.Transaction(delegate
                            {
                                baseline.RemoveRules(plan.Baseline);
                                baseline.RemoveSublayer(sublayer);
                            });
                    }
                    finally
                    {
                        baselineInstalled = false;
                        baseline.Dispose();
                        baseline = null;
                    }
                }
            }
        }
    }

    internal sealed class NativeSession : IDisposable
    {
        private IntPtr engine;
        private const uint Block = 0x1001;
        private const uint Permit = 0x1002;
        private const uint Persistent = 1;
        private const uint BootTime = 2;
        private const uint ClearActionRight = 8;
        private const uint Disabled = 0x20;
        private const string PolicyName = "Claude Guard network policy";
        private const uint FilterNotFound = 0x80320003;
        private const uint SublayerNotFound = 0x80320007;

        internal NativeSession(bool dynamic)
        {
            if (IntPtr.Size != 8 || Marshal.SizeOf(typeof(NativeFilter)) != 200 ||
                Marshal.SizeOf(typeof(NativeCondition)) != 40 || Marshal.SizeOf(typeof(NativeSublayer)) != 72)
                throw new PlatformNotSupportedException("Windows PowerShell x64 is required for these WFP layouts.");
            NativeSessionData session = new NativeSessionData();
            session.Description.Name = PolicyName;
            session.Flags = dynamic ? 1U : 0U;
            session.WaitMilliseconds = 5000;
            Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out engine), "open engine");
        }
        internal void Transaction(Action write)
        {
            Check(FwpmTransactionBegin0(engine, 0), "begin transaction");
            try
            {
                write();
                Check(FwpmTransactionCommit0(engine), "commit transaction");
            }
            catch
            {
                FwpmTransactionAbort0(engine);
                throw;
            }
        }
        internal ushort CreateSublayer(Guid id, bool persistent = false)
        {
            NativeSublayer sublayer = new NativeSublayer();
            sublayer.Key = id;
            sublayer.Description.Name = PolicyName;
            sublayer.Flags = persistent ? Persistent : 0;
            sublayer.Weight = WindowsPolicySession.RequestedSublayerWeight;
            Check(FwpmSubLayerAdd0(engine, ref sublayer, IntPtr.Zero), "add sublayer");
            // BFE can allocate the nearest free weight. Bind subsequent verification
            // to the value actually assigned to this newly created key.
            return ReadSublayerWeight(id, persistent).Value;
        }
        internal bool VerifySublayer(Guid id, bool persistent, ushort recordedWeight, bool allowMissing = false)
        {
            ushort? weight = ReadSublayerWeight(id, persistent, allowMissing);
            if (!weight.HasValue) return false;
            if (weight.Value != recordedWeight)
                throw new InvalidOperationException(String.Format(CultureInfo.InvariantCulture,
                    "Sublayer weight changed. Assigned={0}; Recorded={1}.", weight.Value, recordedWeight));
            return true;
        }
        private ushort? ReadSublayerWeight(Guid id, bool persistent, bool allowMissing = false)
        {
            IntPtr pointer;
            uint result = FwpmSubLayerGetByKey0(engine, ref id, out pointer);
            if (allowMissing && result == SublayerNotFound) return null;
            Check(result, "read sublayer");
            try
            {
                NativeSublayer actual = (NativeSublayer)Marshal.PtrToStructure(pointer, typeof(NativeSublayer));
                if (actual.Key != id || actual.Description.Name != PolicyName ||
                    actual.Flags != (persistent ? Persistent : 0) || actual.Provider != IntPtr.Zero)
                    throw new InvalidOperationException(String.Format(CultureInfo.InvariantCulture,
                        "Sublayer readback disagrees. KeyMatches={0}; NameMatches={1}; Flags=0x{2:X8} (expected 0x{3:X8}); Weight={4}; Provider={5}.",
                        actual.Key == id, actual.Description.Name == PolicyName, actual.Flags, persistent ? Persistent : 0,
                        actual.Weight, actual.Provider == IntPtr.Zero ? "none" :
                            ((Guid)Marshal.PtrToStructure(actual.Provider, typeof(Guid))).ToString("D")));
                return actual.Weight;
            }
            finally { FwpmFreeMemory0(ref pointer); }
        }
        internal void RemoveSublayer(Guid id)
        {
            Check(FwpmSubLayerDeleteByKey0(engine, ref id), "remove sublayer");
        }
        internal void AddRules(Guid sublayer, Rule[] rules, bool persistent = false, bool bootTime = false)
        {
            foreach (Rule rule in rules)
            {
                using (NativeMemory memory = new NativeMemory())
                {
                    NativeFilter filter = new NativeFilter();
                    filter.Key = rule.Key;
                    filter.Description.Name = PolicyName;
                    filter.Layer = rule.Layer;
                    filter.Sublayer = sublayer;
                    filter.Flags = RuleFlags(rule, persistent, bootTime);
                    filter.Action.Kind = rule.Permit ? Permit : Block;
                    filter.Weight = new NativeValue(1, new IntPtr(rule.Permit ? 15 : 1));
                    filter.ConditionCount = (uint)rule.Conditions.Length;
                    int size = Marshal.SizeOf(typeof(NativeCondition));
                    filter.Conditions = memory.Allocate(size * rule.Conditions.Length);
                    for (int index = 0; index < rule.Conditions.Length; index++)
                    {
                        NativeCondition condition = MakeCondition(rule.Conditions[index], memory);
                        Marshal.StructureToPtr(condition, IntPtr.Add(filter.Conditions, index * size), false);
                    }
                    ulong id;
                    Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id), "add filter");
                }
            }
        }
        internal void VerifyRules(Guid sublayer, Rule[] rules, bool persistent = false, bool bootTime = false)
        {
            foreach (Rule rule in rules)
            {
                Guid key = rule.Key;
                IntPtr pointer;
                Check(FwpmFilterGetByKey0(engine, ref key, out pointer), "read filter");
                try
                {
                    NativeFilter actual = (NativeFilter)Marshal.PtrToStructure(pointer, typeof(NativeFilter));
                    VerifyRuleIdentity(actual, sublayer, rule, persistent, bootTime);
                    uint flagsToCompare = ClearActionRight;
                    if (!bootTime) flagsToCompare |= Disabled;
                    if ((actual.Flags & flagsToCompare) != (RuleFlags(rule, persistent, bootTime) & flagsToCompare) ||
                        actual.Weight.Type != 1 || actual.Weight.Data.ToInt64() != (rule.Permit ? 15 : 1) ||
                        actual.ConditionCount != rule.Conditions.Length)
                        throw new InvalidOperationException("Filter readback disagrees with the requested policy.");
                    using (NativeMemory memory = new NativeMemory())
                    {
                        int size = Marshal.SizeOf(typeof(NativeCondition));
                        List<NativeCondition> expected = new List<NativeCondition>();
                        foreach (Condition field in rule.Conditions)
                            expected.Add(MakeCondition(field, memory));
                        for (int index = 0; index < actual.ConditionCount; index++)
                        {
                            NativeCondition found = (NativeCondition)Marshal.PtrToStructure(
                                IntPtr.Add(actual.Conditions, size * index), typeof(NativeCondition));
                            int match = expected.FindIndex(x => SameCondition(x, found));
                            if (match < 0) throw new InvalidOperationException("Filter condition readback disagrees.");
                            expected.RemoveAt(match);
                        }
                    }
                }
                finally { FwpmFreeMemory0(ref pointer); }
            }
        }
        private static uint RuleFlags(Rule rule, bool persistent, bool bootTime)
        {
            if (bootTime)
            {
                if (persistent || rule.Permit)
                    throw new ArgumentException("Boot rules must be standalone blocks.");
                return BootTime | ClearActionRight;
            }
            return (rule.Permit ? 0 : ClearActionRight) | (persistent ? Persistent : 0);
        }
        private static void VerifyRuleIdentity(NativeFilter actual, Guid sublayer, Rule rule, bool persistent, bool bootTime)
        {
            const uint lifetime = Persistent | BootTime;
            if (actual.Key != rule.Key || actual.Layer != rule.Layer || actual.Sublayer != sublayer ||
                actual.Action.Kind != (rule.Permit ? Permit : Block) ||
                (actual.Flags & lifetime) != (RuleFlags(rule, persistent, bootTime) & lifetime))
                throw new InvalidOperationException("A rule identity does not match the saved Guard policy.");
        }
        private static readonly int FilterSublayerOffset = Marshal.OffsetOf(typeof(NativeFilter), "Sublayer").ToInt32();

        private static void VerifyScopePage(IntPtr page, uint count, Guid sublayer, HashSet<Guid> keys, HashSet<Guid> bootKeys)
        {
            for (int index = 0; index < count; index++)
            {
                IntPtr entry = Marshal.ReadIntPtr(page, index * IntPtr.Size);
                if (entry == IntPtr.Zero) throw new InvalidOperationException("Filter enumeration returned an empty entry.");
                // Enumeration spans every WFP layer. Skip unrelated rows without
                // marshaling their display strings or other filter fields.
                if (Marshal.PtrToStructure<Guid>(IntPtr.Add(entry, FilterSublayerOffset)) != sublayer) continue;
                NativeFilter filter = (NativeFilter)Marshal.PtrToStructure(entry, typeof(NativeFilter));
                if ((filter.Flags & BootTime) != 0 && bootKeys.Remove(filter.Key)) continue;
                if (!keys.Remove(filter.Key))
                    throw new InvalidOperationException("An unexpected filter remains in the Guard sublayer.");
            }
        }

        internal void VerifyScope(Guid sublayer, Rule[] runtime, Rule[] boot, Rule[] admission = null)
        {
            HashSet<Guid> keys = new HashSet<Guid>(Array.ConvertAll(runtime, rule => rule.Key));
            if (admission != null)
                foreach (Rule rule in admission) keys.Add(rule.Key);
            // Boot filters are already verified by their exact keys. BFE's
            // ordinary enumeration can omit them once runtime rules take over.
            HashSet<Guid> bootKeys = new HashSet<Guid>(Array.ConvertAll(boot, rule => rule.Key));

            IntPtr enumerator;
            Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out enumerator), "create filter enumeration");
            try
            {
                const uint pageSize = 128;
                uint count;
                do
                {
                    IntPtr page;
                    Check(FwpmFilterEnum0(engine, enumerator, pageSize, out page, out count), "enumerate filter scope");
                    try
                    {
                        VerifyScopePage(page, count, sublayer, keys, bootKeys);
                    }
                    finally { FwpmFreeMemory0(ref page); }
                } while (count == pageSize);
                if (keys.Count != 0)
                    throw new InvalidOperationException("The Guard sublayer has missing filters.");
            }
            finally { Check(FwpmFilterDestroyEnumHandle0(engine, enumerator), "close filter enumeration"); }
        }
        internal void VerifyAbsent(Rule[] rules)
        {
            foreach (Rule rule in rules)
            {
                Guid key = rule.Key;
                IntPtr pointer;
                uint result = FwpmFilterGetByKey0(engine, ref key, out pointer);
                if (result == FilterNotFound) continue;
                if (result == 0)
                {
                    FwpmFreeMemory0(ref pointer);
                    throw new InvalidOperationException("A revoked admission filter remains installed.");
                }
                Check(result, "verify revoked filter");
            }
        }
        internal void RemoveRules(Rule[] rules)
        {
            foreach (Rule rule in rules)
                RemoveRule(rule.Key);
        }
        internal void RemoveOwnedRules(Guid sublayer, Rule[] rules, bool persistent = false, bool bootTime = false)
        {
            foreach (Rule rule in rules)
            {
                Guid key = rule.Key;
                IntPtr pointer;
                uint result = FwpmFilterGetByKey0(engine, ref key, out pointer);
                if (result == FilterNotFound) continue;
                Check(result, "read filter for removal");
                try
                {
                    NativeFilter actual = (NativeFilter)Marshal.PtrToStructure(pointer, typeof(NativeFilter));
                    VerifyRuleIdentity(actual, sublayer, rule, persistent, bootTime);
                }
                finally { FwpmFreeMemory0(ref pointer); }
                RemoveRule(key);
            }
        }
        private void RemoveRule(Guid key)
        {
            uint result = FwpmFilterDeleteByKey0(engine, ref key);
            if (result != FilterNotFound) Check(result, "remove filter");
        }

        private NativeCondition MakeCondition(Condition condition, NativeMemory memory)
        {
            NativeCondition native = new NativeCondition();
            native.Field = condition.Field;
            if (condition.Field == GuardPolicy.AppId)
            {
                StoreAppIdentity future = condition.Data as StoreAppIdentity;
                if (future != null)
                    native.Value = new NativeValue(12, memory.Blob(StorePathBytes(future)));
                else
                {
                    IntPtr identity;
                    Check(FwpmGetAppIdFromFileName0((string)condition.Data, out identity), "resolve executable identity");
                    memory.AppIds.Add(identity);
                    native.Value = new NativeValue(12, identity);
                }
            }
            else if (condition.Field == GuardPolicy.UserId)
            {
                RawSecurityDescriptor sd = new RawSecurityDescriptor("D:(A;;0x1;;;" + condition.Data + ")");
                byte[] bytes = new byte[sd.BinaryLength];
                sd.GetBinaryForm(bytes, 0);
                native.Value = new NativeValue(14, memory.Blob(bytes));
            }
            else if (condition.Field == GuardPolicy.PackageId)
            {
                SecurityIdentifier sid = (SecurityIdentifier)condition.Data;
                byte[] bytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(bytes, 0);
                native.Value = new NativeValue(13, memory.Copy(bytes));
            }
            else if (condition.Data is IPAddress)
            {
                byte[] address = ((IPAddress)condition.Data).GetAddressBytes();
                uint hostOrder = ((uint)address[0] << 24) | ((uint)address[1] << 16) | ((uint)address[2] << 8) | address[3];
                native.Value = new NativeValue(3, new IntPtr((long)hostOrder));
            }
            else if (condition.Data is ushort)
                native.Value = new NativeValue(2, new IntPtr((ushort)condition.Data));
            else
                native.Value = new NativeValue(1, new IntPtr((byte)condition.Data));
            return native;
        }

        private static byte[] ReadNativeAppId(string path, bool allowMissing)
        {
            IntPtr identity;
            uint error = FwpmGetAppIdFromFileName0(path, out identity);
            if (allowMissing && (error == 2 || error == 3 || error == 0x80070002 || error == 0x80070003))
                return null;
            Check(error, "resolve executable identity");
            try
            {
                NativeBlob blob = (NativeBlob)Marshal.PtrToStructure(identity, typeof(NativeBlob));
                if (blob.Size < 4 || blob.Size > 65536 || (blob.Size & 1) != 0)
                    throw new InvalidOperationException("The Windows application identity has an unexpected size.");
                var bytes = new byte[blob.Size];
                Marshal.Copy(blob.Data, bytes, 0, bytes.Length);
                return bytes;
            }
            finally { FwpmFreeMemory0(ref identity); }
        }

        internal static string ReadVerifiedAppDevice(string path)
        {
            var target = new StringBuilder(4096);
            if (QueryDosDeviceW(path.Substring(0, 2), target, target.Capacity) == 0)
                throw new InvalidOperationException("The installed package drive could not be resolved.");
            string device = target.ToString().Split('\0')[0].ToLowerInvariant();
            VerifyStorePathIdentity(new StoreAppIdentity(path, device), false);
            return device;
        }

        private static byte[] StorePathBytes(StoreAppIdentity identity)
        {
            return Encoding.Unicode.GetBytes(identity.Device + identity.Path.Substring(2).ToLowerInvariant() + "\0");
        }

        internal static void VerifyStorePathIdentity(StoreAppIdentity identity, bool allowMissing)
        {
            byte[] expected = StorePathBytes(identity);
            byte[] native = ReadNativeAppId(identity.Path, allowMissing);
            if (native == null) return;
            if (expected.Length == native.Length)
            {
                int index = 0;
                while (index < native.Length && expected[index] == native[index]) index++;
                if (index == native.Length) return;
            }
            throw new InvalidOperationException("The exact update executable identity disagrees with Windows.");
        }
        private static bool SameCondition(NativeCondition a, NativeCondition b)
        {
            if (a.Field != b.Field || a.Match != b.Match || a.Value.Type != b.Value.Type)
                return false;
            if (a.Value.Type == 12 || a.Value.Type == 14)
            {
                NativeBlob first = (NativeBlob)Marshal.PtrToStructure(a.Value.Data, typeof(NativeBlob));
                NativeBlob second = (NativeBlob)Marshal.PtrToStructure(b.Value.Data, typeof(NativeBlob));
                if (first.Size != second.Size) return false;
                for (int index = 0; index < first.Size; index++)
                    if (Marshal.ReadByte(first.Data, index) != Marshal.ReadByte(second.Data, index)) return false;
                return true;
            }
            if (a.Value.Type == 13)
                return new SecurityIdentifier(a.Value.Data).Equals(new SecurityIdentifier(b.Value.Data));
            long mask = a.Value.Type == 1 ? 0xffL : (a.Value.Type == 2 ? 0xffffL : 0xffffffffL);
            return (a.Value.Data.ToInt64() & mask) == (b.Value.Data.ToInt64() & mask);
        }
        public void Dispose()
        {
            if (engine == IntPtr.Zero) return;
            Check(FwpmEngineClose0(engine), "close filter engine");
            engine = IntPtr.Zero;
        }
        private static void Check(uint result, string operation)
        {
            if (result != 0)
                throw new InvalidOperationException("WFP " + operation + " failed (0x" + result.ToString("X8") + ").");
        }

        private sealed class NativeMemory : IDisposable
        {
            private readonly List<IntPtr> allocations = new List<IntPtr>();
            internal readonly List<IntPtr> AppIds = new List<IntPtr>();

            internal IntPtr Allocate(int size)
            {
                IntPtr pointer = Marshal.AllocHGlobal(size);
                allocations.Add(pointer);
                return pointer;
            }
            internal IntPtr Blob(byte[] bytes)
            {
                IntPtr data = Copy(bytes);
                IntPtr ptr = Allocate(Marshal.SizeOf(typeof(NativeBlob)));
                Marshal.StructureToPtr(new NativeBlob { Size = (uint)bytes.Length, Data = data }, ptr, false);
                return ptr;
            }
            internal IntPtr Copy(byte[] bytes)
            {
                IntPtr ptr = Allocate(bytes.Length);
                Marshal.Copy(bytes, 0, ptr, bytes.Length);
                return ptr;
            }
            public void Dispose()
            {
                foreach (IntPtr appId in AppIds)
                {
                    IntPtr ptr = appId;
                    FwpmFreeMemory0(ref ptr);
                }
                foreach (IntPtr ptr in allocations) Marshal.FreeHGlobal(ptr);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NativeDisplay { public string Name; public string Details; }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeBlob { public uint Size; public IntPtr Data; }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeValue
        {
            public int Type;
            public IntPtr Data;
            public NativeValue(int type, IntPtr data) { Type = type; Data = data; }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeCondition { public Guid Field; public int Match; public NativeValue Value; }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeAction { public uint Kind; public Guid Key; }
        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct NativeContext
        {
            [FieldOffset(0)] public Guid Provider;
            [FieldOffset(0)] public ulong Raw;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeFilter
        {
            public Guid Key;
            public NativeDisplay Description;
            public uint Flags;
            public IntPtr Provider;
            public NativeBlob ProviderData;
            public Guid Layer;
            public Guid Sublayer;
            public NativeValue Weight;
            public uint ConditionCount;
            public IntPtr Conditions;
            public NativeAction Action;
            public NativeContext Context;
            public IntPtr Reserved;
            public ulong Id;
            public NativeValue EffectiveWeight;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeSessionData
        {
            public Guid Key;
            public NativeDisplay Description;
            public uint Flags;
            public uint WaitMilliseconds;
            public uint ProcessId;
            public IntPtr Sid;
            public IntPtr Username;
            public int KernelMode;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeSublayer
        {
            public Guid Key;
            public NativeDisplay Description;
            public uint Flags;
            public IntPtr Provider;
            public NativeBlob ProviderData;
            public ushort Weight;
        }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmEngineOpen0(string server, uint authentication, IntPtr identity, ref NativeSessionData session, out IntPtr handle);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionCommit0(IntPtr engine);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmTransactionAbort0(IntPtr engine);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerAdd0(IntPtr engine, ref NativeSublayer sublayer, IntPtr security);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr sublayer);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterAdd0(IntPtr engine, ref NativeFilter filter, IntPtr security, out ulong id);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr handle);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr handle, uint requested, out IntPtr entries, out uint returned);
        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr handle);
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmGetAppIdFromFileName0(string filename, out IntPtr appId);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint QueryDosDeviceW(string deviceName, StringBuilder target, int capacity);
        [DllImport("fwpuclnt.dll")]
        private static extern void FwpmFreeMemory0(ref IntPtr pointer);
    }
}

