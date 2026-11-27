using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace ClaudeGuardNative
{
    public sealed class ExitPolicy
    {
        public int Version = 1;
        public bool Enabled = false;
        public string TargetHost = "claude.ai";
        public string[] AllowedCountries = new string[0];
        public string[] AllowedIpv4s = new string[0];
        public int MonitorIntervalSeconds = 45;
        public int TransientFailureTolerance = 3;

        public static ExitPolicy CreateDefault()
        {
            return new ExitPolicy
            {
                Version = 1,
                Enabled = false,
                TargetHost = "claude.ai",
                AllowedCountries = new string[0],
                AllowedIpv4s = new string[0],
                MonitorIntervalSeconds = 45,
                TransientFailureTolerance = 3
            };
        }
    }

    public sealed class ExitProbeResult
    {
        public bool Ok;
        public bool PolicyAllowed;
        public bool TransientFailure;
        public string Host;
        public string Ip;
        public string MaskedIp;
        public string Country;
        public string Colo;
        public int LatencyMs;
        public string CheckedUtc;
        public string Message;

        public ExitProbeResult()
        {
            Host = "";
            Ip = "";
            MaskedIp = "";
            Country = "";
            Colo = "";
            CheckedUtc = "";
            Message = "";
        }
    }

    public static class ExitPolicyStore
    {
        private const int MaxPolicyBytes = 65536;
        private static readonly Encoding Utf8 = new UTF8Encoding(false);
        private static readonly Regex HostPattern = new Regex(
            @"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$",
            RegexOptions.Compiled);
        private static readonly Regex CountryPattern = new Regex(@"^[A-Z]{2}$", RegexOptions.Compiled);

        public static string DefaultPath
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "ClaudeGuardNative",
                    "exit-policy.json");
            }
        }

        public static ExitPolicy Load()
        {
            return Load(DefaultPath);
        }

        public static ExitPolicy Load(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return ExitPolicy.CreateDefault();

            string folder = Path.GetDirectoryName(path);
            if (!String.IsNullOrEmpty(folder) && Directory.Exists(folder))
            {
                var dirInfo = new DirectoryInfo(folder);
                if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("The exit policy directory is not a regular directory.");
            }
            var info = new FileInfo(path);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length > MaxPolicyBytes)
                throw new IOException("The exit policy file could not be trusted.");

            string json = File.ReadAllText(path, Utf8);
            var serializer = new JavaScriptSerializer();
            ExitPolicy parsed = serializer.Deserialize<ExitPolicy>(json);
            if (parsed == null)
                throw new InvalidOperationException("The exit policy file is empty or malformed.");
            return NormalizeAndValidate(parsed);
        }

        public static void Save(ExitPolicy policy)
        {
            Save(policy, DefaultPath);
        }

        public static void Save(ExitPolicy policy, string path)
        {
            ExitPolicy clean = NormalizeAndValidate(policy);
            string folder = Path.GetDirectoryName(path);
            if (String.IsNullOrWhiteSpace(folder))
                throw new InvalidOperationException("Invalid exit policy path.");

            DirectoryInfo dir = Directory.CreateDirectory(folder);
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("The exit policy directory is not a regular directory.");

            if (File.Exists(path))
            {
                var existing = new FileInfo(path);
                if ((existing.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("The exit policy file is not a regular file.");
            }

            string json = new JavaScriptSerializer().Serialize(clean);
            string temp = Path.Combine(folder, "exit-policy-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                File.WriteAllText(temp, json, Utf8);
                if (File.Exists(path))
                    File.Replace(temp, path, null);
                else
                    File.Move(temp, path);
            }
            finally
            {
                if (File.Exists(temp))
                    File.Delete(temp);
            }
        }

        public static ExitPolicy NormalizeAndValidate(ExitPolicy policy)
        {
            if (policy == null)
                return ExitPolicy.CreateDefault();
            if (policy.Version != 1)
                throw new InvalidOperationException("Unsupported exit policy version.");

            string host = NormalizeHost(policy.TargetHost);
            string[] countries = NormalizeCountries(policy.AllowedCountries);
            string[] ipv4s = NormalizeIpv4s(policy.AllowedIpv4s);
            int interval = policy.MonitorIntervalSeconds;
            if (interval < 15)
                interval = 15;
            if (interval > 300)
                interval = 300;

            int tolerance = policy.TransientFailureTolerance;
            if (tolerance <= 0)
                tolerance = 3;
            if (tolerance > 5)
                tolerance = 5;

            return new ExitPolicy
            {
                Version = 1,
                Enabled = policy.Enabled,
                TargetHost = host,
                AllowedCountries = countries,
                AllowedIpv4s = ipv4s,
                MonitorIntervalSeconds = interval,
                TransientFailureTolerance = tolerance
            };
        }

        public static string NormalizeHost(string host)
        {
            string trimmed = host == null ? "" : host.Trim().ToLowerInvariant();
            if (trimmed.Length == 0)
                return "claude.ai";
            if (trimmed.Length > 253 || !HostPattern.IsMatch(trimmed))
                throw new InvalidOperationException("Invalid exit probe host name: " + host);
            return trimmed;
        }

        public static string[] NormalizeCountries(IEnumerable<string> raw)
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            var list = new List<string>();
            if (raw != null)
            {
                foreach (string item in raw)
                {
                    if (String.IsNullOrWhiteSpace(item))
                        continue;
                    string code = item.Trim().ToUpperInvariant();
                    if (!CountryPattern.IsMatch(code) || code == "XX" || code == "T1")
                        throw new InvalidOperationException("Invalid ISO 3166-1 alpha-2 country code: " + item);
                    if (set.Add(code))
                        list.Add(code);
                }
            }
            list.Sort(StringComparer.Ordinal);
            return list.ToArray();
        }

        public static string[] ParseCsvTokens(string text)
        {
            if (String.IsNullOrWhiteSpace(text))
                return new string[0];
            string[] parts = text.Split(new[] { ',', ';', '\r', '\n', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            return parts;
        }

        public static string[] NormalizeIpv4s(IEnumerable<string> raw)
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            var list = new List<string>();
            if (raw != null)
            {
                foreach (string item in raw)
                {
                    if (String.IsNullOrWhiteSpace(item))
                        continue;
                    string trimmed = item.Trim();
                    IPAddress ip;
                    if (!IPAddress.TryParse(trimmed, out ip) ||
                        ip.AddressFamily != AddressFamily.InterNetwork ||
                        !String.Equals(ip.ToString(), trimmed, StringComparison.Ordinal))
                        throw new InvalidOperationException("Invalid canonical IPv4 address: " + item);
                    if (set.Add(trimmed))
                        list.Add(trimmed);
                }
            }
            list.Sort(StringComparer.Ordinal);
            return list.ToArray();
        }

        public static string MaskIpv4(string ip)
        {
            if (String.IsNullOrWhiteSpace(ip))
                return "";
            IPAddress parsed;
            if (!IPAddress.TryParse(ip, out parsed) || parsed.AddressFamily != AddressFamily.InterNetwork)
                return "***";
            byte[] octets = parsed.GetAddressBytes();
            return octets[0].ToString(CultureInfo.InvariantCulture) + "." +
                octets[1].ToString(CultureInfo.InvariantCulture) + ".*.*";
        }
    }

    public static class ExitProbe
    {
        private const int MaxResponseBytes = 16384;
        private static readonly Regex CountryPattern = new Regex(@"^[A-Z]{2}$", RegexOptions.Compiled);

        public static ExitProbeResult ParseTrace(string host, string body, int latencyMs)
        {
            var result = new ExitProbeResult
            {
                Host = host ?? "",
                LatencyMs = latencyMs < 0 ? 0 : latencyMs,
                CheckedUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture)
            };

            if (String.IsNullOrWhiteSpace(body))
            {
                result.Ok = false;
                result.TransientFailure = true;
                result.Message = "Exit probe returned an empty trace response.";
                return result;
            }

            string rawIp = "";
            string rawLoc = "";
            string rawColo = "";

            string[] lines = body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                int eq = line.IndexOf('=');
                if (eq <= 0)
                    continue;
                string key = line.Substring(0, eq).Trim();
                string val = line.Substring(eq + 1).Trim();
                if (String.Equals(key, "ip", StringComparison.OrdinalIgnoreCase))
                    rawIp = val;
                else if (String.Equals(key, "loc", StringComparison.OrdinalIgnoreCase))
                    rawLoc = val.ToUpperInvariant();
                else if (String.Equals(key, "colo", StringComparison.OrdinalIgnoreCase))
                    rawColo = val.ToUpperInvariant();
            }

            IPAddress parsedIp;
            if (String.IsNullOrEmpty(rawIp) ||
                !IPAddress.TryParse(rawIp, out parsedIp) ||
                parsedIp.AddressFamily != AddressFamily.InterNetwork ||
                !String.Equals(parsedIp.ToString(), rawIp, StringComparison.Ordinal))
            {
                result.Ok = false;
                result.TransientFailure = false;
                result.Message = String.IsNullOrEmpty(rawIp)
                    ? "Exit probe response did not include an IPv4 address."
                    : "Exit probe returned a non-IPv4 or malformed address.";
                return result;
            }

            result.Ip = rawIp;
            result.MaskedIp = ExitPolicyStore.MaskIpv4(rawIp);
            if (CountryPattern.IsMatch(rawLoc) && rawLoc != "XX" && rawLoc != "T1")
                result.Country = rawLoc;
            if (rawColo.Length > 0 && rawColo.Length <= 16)
                result.Colo = rawColo;

            result.Ok = true;
            result.PolicyAllowed = true;
            result.Message = BuildSummaryMessage(result, "Observed IPv4 exit");
            return result;
        }

        public static ExitProbeResult Evaluate(ExitProbeResult sample, ExitPolicy policy)
        {
            if (sample == null)
            {
                return new ExitProbeResult
                {
                    Ok = false,
                    PolicyAllowed = false,
                    TransientFailure = true,
                    CheckedUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    Message = "Exit probe did not return a sample."
                };
            }

            if (!sample.Ok)
            {
                sample.PolicyAllowed = false;
                return sample;
            }

            if (policy == null || !policy.Enabled)
            {
                sample.PolicyAllowed = true;
                sample.Message = BuildSummaryMessage(sample, "Exit observed (policy enforcement off)");
                return sample;
            }

            ExitPolicy clean = ExitPolicyStore.NormalizeAndValidate(policy);
            bool hasCountries = clean.AllowedCountries != null && clean.AllowedCountries.Length > 0;
            bool hasIps = clean.AllowedIpv4s != null && clean.AllowedIpv4s.Length > 0;

            if (!hasCountries && !hasIps)
            {
                sample.PolicyAllowed = false;
                sample.TransientFailure = false;
                sample.Message = "Exit verification is enabled, but no allowed country codes or IPv4 addresses are configured.";
                return sample;
            }

            if (hasIps)
            {
                bool ipMatched = false;
                foreach (string allowed in clean.AllowedIpv4s)
                {
                    if (String.Equals(allowed, sample.Ip, StringComparison.Ordinal))
                    {
                        ipMatched = true;
                        break;
                    }
                }
                if (!ipMatched)
                {
                    sample.PolicyAllowed = false;
                    sample.TransientFailure = false;
                    sample.Message = BuildSummaryMessage(sample, "Blocked: observed IPv4 is not in the allowlist");
                    return sample;
                }
            }

            if (hasCountries)
            {
                bool countryMatched = false;
                if (!String.IsNullOrEmpty(sample.Country))
                {
                    foreach (string allowed in clean.AllowedCountries)
                    {
                        if (String.Equals(allowed, sample.Country, StringComparison.Ordinal))
                        {
                            countryMatched = true;
                            break;
                        }
                    }
                }
                if (!countryMatched)
                {
                    sample.PolicyAllowed = false;
                    sample.TransientFailure = false;
                    string expected = String.Join(", ", clean.AllowedCountries);
                    string observed = String.IsNullOrEmpty(sample.Country) ? "unknown" : sample.Country;
                    sample.Message = "Blocked: observed country '" + observed + "' is outside allowed countries (" +
                        expected + ") [" + sample.MaskedIp + "].";
                    return sample;
                }
            }

            sample.PolicyAllowed = true;
            sample.TransientFailure = false;
            sample.Message = BuildSummaryMessage(sample, "Exit verified");
            return sample;
        }

        public static ExitProbeResult CheckWithPolicy(ExitPolicy policy, int timeoutMs, bool allowRetryOnTransient, string localBindIpv4)
        {
            return CheckWithPolicyCore(policy, timeoutMs, allowRetryOnTransient, localBindIpv4, 2000, null);
        }

        public static ExitProbeResult CheckWithProbe(
            ExitPolicy policy,
            bool allowRetryOnTransient,
            int retryDelayMs,
            Func<int, ExitProbeResult> probeAttempt)
        {
            if (probeAttempt == null)
                throw new ArgumentNullException("probeAttempt");
            return CheckWithPolicyCore(policy, 6000, allowRetryOnTransient, null, retryDelayMs, probeAttempt);
        }

        private static ExitProbeResult CheckWithPolicyCore(
            ExitPolicy policy,
            int timeoutMs,
            bool allowRetryOnTransient,
            string localBindIpv4,
            int retryDelayMs,
            Func<int, ExitProbeResult> customProbe)
        {
            ExitPolicy clean = policy == null ? ExitPolicy.CreateDefault() : ExitPolicyStore.NormalizeAndValidate(policy);
            IPAddress bindIp = ParseOptionalIpv4(localBindIpv4);
            int maxAttempts = allowRetryOnTransient ? clean.TransientFailureTolerance : 1;
            if (maxAttempts < 1)
                maxAttempts = 1;
            if (retryDelayMs < 0)
                retryDelayMs = 0;

            ExitProbeResult last = null;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                ExitProbeResult sample = customProbe != null
                    ? customProbe(attempt)
                    : Probe(clean.TargetHost, timeoutMs, bindIp);
                last = Evaluate(sample, clean);

                // Explicit policy verdict (allowed or disallowed) and non-transient failures (e.g., TLS errors)
                // never retry: only transient network timeouts/packet loss consume jitter tolerance.
                if (last.Ok || !last.TransientFailure)
                    return last;

                if (attempt < maxAttempts && retryDelayMs > 0)
                    Thread.Sleep(retryDelayMs);
            }

            if (last != null && maxAttempts > 1 && !String.IsNullOrEmpty(last.Message))
                last.Message = last.Message + " (confirmed after " + maxAttempts + " attempts)";
            return last;
        }

        public static ExitProbeResult Probe(string host, int timeoutMs)
        {
            return Probe(host, timeoutMs, null);
        }

        public static ExitProbeResult Probe(string host, int timeoutMs, IPAddress localBindIpv4)
        {
            string targetHost;
            try { targetHost = ExitPolicyStore.NormalizeHost(host); }
            catch (Exception error)
            {
                return new ExitProbeResult
                {
                    Ok = false,
                    PolicyAllowed = false,
                    TransientFailure = false,
                    Host = host ?? "",
                    CheckedUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    Message = error.Message
                };
            }

            if (timeoutMs < 1000)
                timeoutMs = 1000;
            if (timeoutMs > 15000)
                timeoutMs = 15000;

            var sw = Stopwatch.StartNew();
            try
            {
                IPAddress remoteIp = ResolveIpv4(targetHost, timeoutMs);
                int remaining = timeoutMs - (int)sw.ElapsedMilliseconds;
                if (remaining < 500)
                    throw new TimeoutException("Exit probe timed out during IPv4 name resolution.");

                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    socket.ReceiveTimeout = remaining;
                    socket.SendTimeout = remaining;
                    if (localBindIpv4 != null && localBindIpv4.AddressFamily == AddressFamily.InterNetwork)
                        socket.Bind(new IPEndPoint(localBindIpv4, 0));

                    IAsyncResult connect = socket.BeginConnect(remoteIp, 443, null, null);
                    if (!connect.AsyncWaitHandle.WaitOne(remaining, false))
                    {
                        socket.Close();
                        throw new TimeoutException("Exit probe timed out connecting over IPv4 to " + targetHost + ".");
                    }
                    socket.EndConnect(connect);

                    using (var network = new NetworkStream(socket, false))
                    using (var tls = new SslStream(network, false, ValidateCertificate))
                    {
                        tls.ReadTimeout = Math.Max(500, timeoutMs - (int)sw.ElapsedMilliseconds);
                        tls.WriteTimeout = tls.ReadTimeout;
                        tls.AuthenticateAsClient(targetHost, null, SslProtocols.Tls12, true);

                        string request = "GET /cdn-cgi/trace HTTP/1.1\r\n" +
                            "Host: " + targetHost + "\r\n" +
                            "User-Agent: ClaudeGuardNative/2.0.1\r\n" +
                            "Accept: text/plain\r\n" +
                            "Connection: close\r\n\r\n";
                        byte[] payload = Encoding.ASCII.GetBytes(request);
                        tls.Write(payload, 0, payload.Length);
                        tls.Flush();

                        string rawHttp = ReadBoundedAscii(tls, MaxResponseBytes);
                        string body = ExtractHttp200Body(rawHttp);
                        sw.Stop();
                        return ParseTrace(targetHost, body, (int)sw.ElapsedMilliseconds);
                    }
                }
            }
            catch (AuthenticationException error)
            {
                sw.Stop();
                return new ExitProbeResult
                {
                    Ok = false,
                    PolicyAllowed = false,
                    TransientFailure = false,
                    Host = targetHost,
                    LatencyMs = (int)sw.ElapsedMilliseconds,
                    CheckedUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    Message = "Exit probe TLS verification failed (possible certificate mismatch or proxy interception): " + error.Message
                };
            }
            catch (Exception error)
            {
                sw.Stop();
                return new ExitProbeResult
                {
                    Ok = false,
                    PolicyAllowed = false,
                    TransientFailure = true,
                    Host = targetHost,
                    LatencyMs = (int)sw.ElapsedMilliseconds,
                    CheckedUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    Message = "Exit probe failed for " + targetHost + ": " + error.Message
                };
            }
        }

        private static IPAddress ParseOptionalIpv4(string text)
        {
            if (String.IsNullOrWhiteSpace(text))
                return null;
            IPAddress ip;
            if (IPAddress.TryParse(text.Trim(), out ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                return ip;
            return null;
        }

        private static IPAddress ResolveIpv4(string host, int timeoutMs)
        {
            IPAddress literal;
            if (IPAddress.TryParse(host, out literal))
            {
                if (literal.AddressFamily != AddressFamily.InterNetwork)
                    throw new InvalidOperationException("Only IPv4 hosts are supported for exit probing.");
                return literal;
            }

            IAsyncResult lookup = Dns.BeginGetHostAddresses(host, null, null);
            if (!lookup.AsyncWaitHandle.WaitOne(timeoutMs, false))
                throw new TimeoutException("DNS lookup timed out for " + host + ".");
            IPAddress[] addresses = Dns.EndGetHostAddresses(lookup);
            foreach (IPAddress address in addresses)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                    return address;
            }
            throw new InvalidOperationException("No IPv4 address resolved for " + host + ".");
        }

        private static bool ValidateCertificate(
            object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return sslPolicyErrors == SslPolicyErrors.None;
        }

        private static string ReadBoundedAscii(Stream stream, int maxBytes)
        {
            using (var memory = new MemoryStream())
            {
                var buffer = new byte[2048];
                while (memory.Length < maxBytes)
                {
                    int toRead = Math.Min(buffer.Length, maxBytes - (int)memory.Length);
                    int count = stream.Read(buffer, 0, toRead);
                    if (count <= 0)
                        break;
                    memory.Write(buffer, 0, count);
                }
                return Encoding.UTF8.GetString(memory.ToArray());
            }
        }

        public static string ExtractHttp200Body(string rawHttp)
        {
            if (String.IsNullOrEmpty(rawHttp))
                throw new IOException("Empty HTTP response.");
            int separator = rawHttp.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (separator < 0)
                throw new IOException("Incomplete HTTP response headers.");

            string headerBlock = rawHttp.Substring(0, separator);
            string body = rawHttp.Substring(separator + 4);
            string[] headerLines = headerBlock.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (headerLines.Length == 0 ||
                !(headerLines[0].StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase) ||
                  headerLines[0].StartsWith("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase)))
            {
                string status = headerLines.Length > 0 ? headerLines[0] : "unknown";
                throw new IOException("Unexpected HTTP status: " + status);
            }

            bool chunked = false;
            for (int i = 1; i < headerLines.Length; i++)
            {
                if (headerLines[i].StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase) &&
                    headerLines[i].IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    chunked = true;
                    break;
                }
            }
            return chunked ? DecodeChunkedBody(body) : body;
        }

        private static string DecodeChunkedBody(string encoded)
        {
            var sb = new StringBuilder();
            int pos = 0;
            while (pos < encoded.Length)
            {
                int crlf = encoded.IndexOf("\r\n", pos, StringComparison.Ordinal);
                if (crlf < 0)
                    break;
                string sizeHex = encoded.Substring(pos, crlf - pos).Trim();
                int semi = sizeHex.IndexOf(';');
                if (semi >= 0)
                    sizeHex = sizeHex.Substring(0, semi).Trim();
                int size;
                if (!Int32.TryParse(sizeHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out size) || size < 0)
                    throw new IOException("Malformed chunked response.");
                if (size == 0)
                    break;
                pos = crlf + 2;
                if (pos + size > encoded.Length)
                    throw new IOException("Truncated chunked response.");
                sb.Append(encoded, pos, size);
                pos += size + 2;
            }
            return sb.ToString();
        }

        private static string BuildSummaryMessage(ExitProbeResult sample, string prefix)
        {
            var sb = new StringBuilder(prefix);
            sb.Append(": ");
            sb.Append(sample.MaskedIp);
            if (!String.IsNullOrEmpty(sample.Country))
                sb.Append(" (").Append(sample.Country).Append(String.IsNullOrEmpty(sample.Colo) ? ")" : "/" + sample.Colo + ")");
            else if (!String.IsNullOrEmpty(sample.Colo))
                sb.Append(" (").Append(sample.Colo).Append(")");
            sb.Append(" via ").Append(sample.Host);
            return sb.ToString();
        }
    }
}
