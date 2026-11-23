using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace ClaudeGuard.Network
{
    public static class RelayListener
    {
        private const uint InsufficientBuffer = 122;
        private const int OwnerPidListenerTable = 3;
        private const int ListenState = 2;
        private const int Ipv4Loopback = 0x0100007f; // 127.0.0.1 in Windows table byte order.
        private const uint NoSuchInterface = 2; // ERROR_FILE_NOT_FOUND
        private const uint InvalidParameter = 87;
        private const uint NotFound = 1168;
        private const int InterfaceUp = 1;
        private const int InterfaceStateWithoutStatistics = 2; // MibIfEntryNormalWithoutStatistics

        // Windows MIB_IF_ROW2. The eight status flags share a single BOOLEAN.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct InterfaceRow
        {
            public ulong InterfaceLuid;
            public uint InterfaceIndex;
            public Guid InterfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
            public string Alias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
            public string Description;
            public uint PhysicalAddressLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] PhysicalAddress;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] PermanentPhysicalAddress;
            public uint Mtu;
            public uint Type;
            public int TunnelType;
            public int MediaType;
            public int PhysicalMediumType;
            public int AccessType;
            public int DirectionType;
            public byte InterfaceAndOperStatusFlags;
            public int OperStatus;
            public int AdminStatus;
            public int MediaConnectState;
            public Guid NetworkGuid;
            public int ConnectionType;
            public ulong TransmitLinkSpeed;
            public ulong ReceiveLinkSpeed;
            public ulong InOctets;
            public ulong InUcastPkts;
            public ulong InNUcastPkts;
            public ulong InDiscards;
            public ulong InErrors;
            public ulong InUnknownProtos;
            public ulong InUcastOctets;
            public ulong InMulticastOctets;
            public ulong InBroadcastOctets;
            public ulong OutOctets;
            public ulong OutUcastPkts;
            public ulong OutNUcastPkts;
            public ulong OutDiscards;
            public ulong OutErrors;
            public ulong OutUcastOctets;
            public ulong OutMulticastOctets;
            public ulong OutBroadcastOctets;
            public ulong OutQLen;
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size,
            [MarshalAs(UnmanagedType.Bool)] bool sorted, AddressFamily family, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint ConvertInterfaceGuidToLuid([In] ref Guid interfaceGuid, out ulong interfaceLuid);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint GetIfEntry2Ex(int level, ref InterfaceRow row);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint GetIfEntry2(ref InterfaceRow row);

        public static bool IsAdapterUp(Guid interfaceGuid, string alias)
        {
            if (interfaceGuid == Guid.Empty || String.IsNullOrEmpty(alias)) return false;

            ulong luid;
            uint result = ConvertInterfaceGuidToLuid(ref interfaceGuid, out luid);
            // Conversion uses ERROR_INVALID_PARAMETER for a GUID Windows cannot resolve.
            if (result == InvalidParameter || result == NoSuchInterface || result == NotFound) return false;
            if (result != 0) throw new Win32Exception((int)result);
            if (luid == 0) throw new InvalidOperationException("Windows returned no network interface identity.");

            var row = new InterfaceRow {
                InterfaceLuid = luid,
                PhysicalAddress = new byte[32],
                PermanentPhysicalAddress = new byte[32]
            };
            try { result = GetIfEntry2Ex(InterfaceStateWithoutStatistics, ref row); }
            catch (EntryPointNotFoundException) { result = GetIfEntry2(ref row); }
            if (result == NoSuchInterface || result == NotFound) return false;
            if (result != 0) throw new Win32Exception((int)result);

            return row.InterfaceLuid == luid && row.InterfaceGuid == interfaceGuid &&
                String.Equals(row.Alias, alias, StringComparison.Ordinal) &&
                row.AdminStatus == InterfaceUp && row.OperStatus == InterfaceUp;
        }

        public static bool IsExclusiveLoopback(int port, int ownerId)
        {
            if (port < 1 || port > UInt16.MaxValue || ownerId <= 0) return false;
            return MatchesTable(AddressFamily.InterNetworkV6, port, ownerId) &&
                MatchesTable(AddressFamily.InterNetwork, port, ownerId);
        }

        private static bool MatchesTable(AddressFamily family, int port, int ownerId)
        {
            int capacity = 4096;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                IntPtr table = Marshal.AllocHGlobal(capacity);
                try
                {
                    int size = capacity;
                    Marshal.WriteInt32(table, -1);
                    uint result = GetExtendedTcpTable(table, ref size, false, family, OwnerPidListenerTable, 0);
                    if (result == InsufficientBuffer && size > capacity)
                    {
                        capacity = size;
                        continue;
                    }
                    return result == 0 && size <= capacity &&
                        MatchesRows(table, size, family == AddressFamily.InterNetwork, port, ownerId);
                }
                finally { Marshal.FreeHGlobal(table); }
            }
            return false;
        }

        private static bool MatchesRows(IntPtr table, int size, bool ipv4, int port, int ownerId)
        {
            // The Windows MIB_TCP[6]ROW_OWNER_PID layouts have DWORD fields
            // and, for IPv6, two 16-byte addresses aligned on DWORD boundaries.
            const int headerSize = sizeof(int);
            int rowSize = ipv4 ? 24 : 56;
            int localPortOffset = ipv4 ? 8 : 20;
            int stateOffset = ipv4 ? 0 : 48;
            if (size < headerSize || size % sizeof(int) != 0) return false;

            int count = Marshal.ReadInt32(table);
            if (count != (size - headerSize) / rowSize) return false;
            bool matched = false;
            for (int index = 0; index < count; index++)
            {
                IntPtr row = IntPtr.Add(table, headerSize + index * rowSize);
                if (Marshal.ReadInt32(row, stateOffset) != ListenState) return false;

                // The first two bytes are the port in network byte order.
                int localPort = (Marshal.ReadByte(row, localPortOffset) << 8) |
                    Marshal.ReadByte(row, localPortOffset + 1);
                if (localPort == 0) return false;
                if (localPort != port) continue;

                if (!ipv4 || matched || Marshal.ReadInt32(row, sizeof(int)) != Ipv4Loopback ||
                    Marshal.ReadInt32(row, rowSize - sizeof(int)) != ownerId) return false;
                matched = true;
            }
            return !ipv4 || matched;
        }
    }

    public enum RelayAttemptState
    {
        Unconfirmed,
        SetupReached,
        FirstHopDown
    }

    // The only input is the stdout pipe of the dedicated, pinned Mihomo child.
    // Keep port, timestamp and result, never the log line. Unknown formats
    // cannot turn a probe failure into a confirmed transport failure.
    public sealed class RelayEvidence
    {
        private const int Capacity = 256;
        private const int PinnedMihomoRetryCount = 10;
        private static readonly TimeSpan PinnedMihomoDialBudget = TimeSpan.FromSeconds(5);
        private const string ProbeFlow = @"127\.0\.0\.1:(?<port>[0-9]{1,5}) --> (?<destination>1\.1\.1\.1:443|api\.ipify\.org:443)";
        private const string OptionalDialSource = @"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}->)?";
        private static readonly Regex Envelope = new Regex(
            @"\Atime=""(?<time>[0-9T:.+Z-]+)"" level=(?<level>warning|info) msg=""(?<message>[^""\r\n]+)""\z",
            RegexOptions.CultureInvariant);
        private static readonly Regex Nanoseconds = new Regex(@"(\.[0-9]{7})[0-9]{1,2}(?=Z|[+-][0-9]{2}:[0-9]{2}\z)",
            RegexOptions.CultureInvariant);
        private static readonly Regex Setup = new Regex(@"\A\[TCP\] " + ProbeFlow + @" match Match using guard-pinned\z",
            RegexOptions.CultureInvariant);

        private readonly object gate = new object();
        private readonly Queue<Record> records = new Queue<Record>();
        private readonly Regex failedDial;
        private DateTime discardedThroughUtc = DateTime.MinValue;

        public int ProcessId { get; private set; }
        public DateTime StartedUtc { get; private set; }

        internal enum RecordKind { DialFailure, DialDeadline, Setup }

        private sealed class Record
        {
            internal int Port;
            internal string Destination;
            internal DateTime Utc;
            internal RecordKind Kind;
        }

        public RelayEvidence(Process child, string endpoint)
        {
            if (child == null) throw new ArgumentNullException("child");
            if (!IsIpv4Endpoint(endpoint)) throw new ArgumentException("Expected a literal IPv4 upstream endpoint.", "endpoint");
            ProcessId = child.Id;
            StartedUtc = child.StartTime.ToUniversalTime();
            string target = Regex.Escape(endpoint);
            failedDial = new Regex(@"\A\[TCP\] dial guard-pinned \(match Match/\) " + ProbeFlow +
                " error: " + target + @" connect error: dial tcp(?:4)? " + OptionalDialSource + target +
                @": (?<error>[^\r\n]+)\z", RegexOptions.CultureInvariant);
            child.OutputDataReceived += ReceiveOutput;
            child.BeginOutputReadLine();
        }

        private static bool IsIpv4Endpoint(string endpoint)
        {
            if (String.IsNullOrEmpty(endpoint)) return false;
            int separator = endpoint.LastIndexOf(':');
            if (separator < 1) return false;
            IPAddress address;
            ushort port;
            return IPAddress.TryParse(endpoint.Substring(0, separator), out address) &&
                address.AddressFamily == AddressFamily.InterNetwork &&
                UInt16.TryParse(endpoint.Substring(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) &&
                port != 0 && endpoint.Equals(address.ToString() + ":" + port.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
        }

        private void ReceiveOutput(object sender, DataReceivedEventArgs args)
        {
            string line = args.Data;
            if (line == null || line.Length > 2048) return;
            Match envelope = Envelope.Match(line);
            if (!envelope.Success) return;
            bool isSetup = envelope.Groups["level"].Value == "info";
            Match message = (isSetup ? Setup : failedDial).Match(envelope.Groups["message"].Value);
            if (!message.Success) return;
            int port;
            DateTimeOffset stamp;
            if (!Int32.TryParse(message.Groups["port"].Value, out port) || port < 1 || port > 65535 ||
                !DateTimeOffset.TryParse(Nanoseconds.Replace(envelope.Groups["time"].Value, "$1"),
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out stamp))
                return;
            string reason = message.Groups["error"].Value;
            RecordKind kind = isSetup ? RecordKind.Setup :
                (reason == "i/o timeout" || reason == "context deadline exceeded" ? RecordKind.DialDeadline : RecordKind.DialFailure);
            lock (gate)
            {
                if (records.Count == Capacity)
                {
                    DateTime discarded = records.Dequeue().Utc;
                    if (discarded > discardedThroughUtc) discardedThroughUtc = discarded;
                }
                records.Enqueue(new Record {
                    Port = port, Destination = message.Groups["destination"].Value,
                    Utc = stamp.UtcDateTime, Kind = kind
                });
            }
        }

        public RelayAttemptState ReadAttempt(int sourcePort, DateTime connectedUtc, DateTime endedUtc)
        {
            return ReadAttempt(sourcePort, connectedUtc, endedUtc, "1.1.1.1:443");
        }

        public RelayAttemptState ReadAttempt(int sourcePort, DateTime connectedUtc, DateTime endedUtc, string destination)
        {
            if (sourcePort < 1 || sourcePort > 65535 || connectedUtc.Kind != DateTimeKind.Utc ||
                endedUtc.Kind != DateTimeKind.Utc || connectedUtc < StartedUtc || endedUtc < connectedUtc ||
                (destination != "1.1.1.1:443" && destination != "api.ipify.org:443"))
                return RelayAttemptState.Unconfirmed;
            lock (gate)
            {
                if (discardedThroughUtc >= connectedUtc) return RelayAttemptState.Unconfirmed;
                int dialFailures = 0;
                DateTime lastFailedDial = DateTime.MinValue;
                bool lastDialReachedDeadline = false;
                foreach (Record item in records)
                {
                    if (item.Port != sourcePort || item.Destination != destination ||
                        item.Utc < connectedUtc || item.Utc > endedUtc) continue;
                    if (item.Kind == RecordKind.Setup) return RelayAttemptState.SetupReached;
                    if (item.Utc <= lastFailedDial) return RelayAttemptState.Unconfirmed;
                    lastFailedDial = item.Utc;
                    dialFailures++;
                    lastDialReachedDeadline =
                        item.Kind == RecordKind.DialDeadline && item.Utc - connectedUtc >= PinnedMihomoDialBudget;
                }
                // Up to ten retries share the one five-second context in the
                // pinned release. One failed sub-attempt is not terminal.
                return dialFailures == PinnedMihomoRetryCount ||
                    (dialFailures > 0 && dialFailures < PinnedMihomoRetryCount && lastDialReachedDeadline)
                    ? RelayAttemptState.FirstHopDown : RelayAttemptState.Unconfirmed;
            }
        }
    }
}
