# Read the Windows route table without contacting any remote host.
function Get-GuardNetworkSnapshot {
    $ipInterfaces = @(Get-NetIPInterface -PolicyStore ActiveStore -ErrorAction Stop)
    $byIndex = @{}
    $ipv4 = @{}
    foreach ($ipInterface in $ipInterfaces) {
        $index = [int]$ipInterface.InterfaceIndex
        if ($byIndex.ContainsKey($index) -and $byIndex[$index] -ine $ipInterface.InterfaceAlias) {
            throw 'Windows reported conflicting names for a network interface.'
        }
        $byIndex[$index] = [string]$ipInterface.InterfaceAlias
        if ([string]$ipInterface.AddressFamily -eq 'IPv4') {
            if ($ipv4.ContainsKey($index)) { throw 'Windows reported duplicate IPv4 interface settings.' }
            $ipv4[$index] = $ipInterface
        }
    }

    $known = [Collections.Generic.HashSet[int]]::new()
    $adapters = @(foreach ($device in Get-NetAdapter -IncludeHidden -ErrorAction Stop) {
        $index = [int]$device.ifIndex
        if ($index -le 0 -or [int]$device.InterfaceType -eq 24) { continue }
        if (-not $known.Add($index)) { throw 'Windows reported a duplicate network adapter index.' }
        if ($byIndex.ContainsKey($index) -and $byIndex[$index] -ine $device.Name) {
            throw 'A network interface changed while Windows was reading its settings.'
        }
        [pscustomobject]@{
            InterfaceGuid = [string]$device.InterfaceGuid
            Name = [string]$device.Name
            Status = [string]$device.Status
            ifIndex = $index
            HardwareInterface = $device.HardwareInterface
            InterfaceDescription = [string]$device.InterfaceDescription
            DriverDescription = [string]$device.DriverDescription
            DriverProvider = [string]$device.DriverProvider
            IpBound = $byIndex.ContainsKey($index)
            Ipv4Present = $ipv4.ContainsKey($index)
        }
    })

    $unmatched = @($ipv4.Keys | Where-Object { -not $known.Contains($_) })
    if ($unmatched.Count) {
        $loopbacks = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object NetworkInterfaceType -eq 'Loopback' | Select-Object -ExpandProperty Name)
        foreach ($index in $unmatched) {
            if ($loopbacks -notcontains $byIndex[$index]) {
                throw 'Windows exposed an IPv4 interface without a corresponding firewall adapter identity.'
            }
        }
    }

    [pscustomobject]@{ Adapters = $adapters; Ipv4Interfaces = $ipv4 }
}

function ConvertTo-GuardIpv4Interval([string]$Prefix) {
    $parts = $Prefix.Split('/')
    if ($parts.Count -ne 2 -or $parts[1] -notmatch '^(?:[0-9]|[12][0-9]|3[0-2])$') {
        throw 'Windows returned an invalid IPv4 route prefix.'
    }
    $address = [Net.IPAddress]::Parse($parts[0])
    $octets = $address.GetAddressBytes()
    if ($octets.Length -ne 4) { throw 'Windows returned an IPv6 prefix in the IPv4 route table.' }
    $length = [int]$parts[1]
    $number = [long]$octets[0] * 16777216 + [long]$octets[1] * 65536 + [long]$octets[2] * 256 + $octets[3]
    $size = [long]1 -shl (32 - $length)
    $start = $number - ($number % $size)
    [pscustomobject]@{ Start = $start; End = $start + $size; Length = $length }
}

function Get-GuardPublicRouteIndex([object[]]$Routes, [hashtable]$Ipv4Interfaces) {
    $candidates = @(foreach ($route in $Routes) {
        $index = [int]$route.InterfaceIndex
        if ([string]$route.State -eq 'Dead') { continue }
        $interface = $Ipv4Interfaces[$index]
        if (-not $interface) { throw 'An IPv4 route appeared on an unverified network interface.' }
        if ([string]$interface.ConnectionState -ne 'Connected') { continue }
        $interval = ConvertTo-GuardIpv4Interval ([string]$route.DestinationPrefix)
        [pscustomobject]@{
            Index = $index
            Start = $interval.Start
            End = $interval.End
            Length = $interval.Length
            State = [string]$route.State
            Metric = if ($null -ne $interface.InterfaceMetric -and $null -ne $route.RouteMetric) {
                [long]$interface.InterfaceMetric + [long]$route.RouteMetric
            }
        }
    })
    $candidates = @($candidates | Sort-Object -Property @{ Expression = 'Length'; Descending = $true }, 'Metric')

    # Locally scoped and reserved addresses can legitimately bypass a full-tunnel VPN.
    $localOnly = @(foreach ($prefix in @(
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
        '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3'
    )) { ConvertTo-GuardIpv4Interval $prefix })

    # The candidate routes can only change at a prefix boundary. Checking each
    # interval detects a partial tunnel without probing arbitrary remote hosts.
    $boundaries = [Collections.Generic.SortedSet[long]]::new()
    foreach ($interval in $candidates + $localOnly) {
        $null = $boundaries.Add($interval.Start)
        $null = $boundaries.Add($interval.End)
    }
    $routeIndex = 0
    foreach ($point in $boundaries) {
        if ($point -ge 4294967296L) { continue }
        $local = $false
        foreach ($interval in $localOnly) {
            if ($point -ge $interval.Start -and $point -lt $interval.End) {
                $local = $true
                break
            }
        }
        if ($local) { continue }

        $best = $null
        foreach ($route in $candidates) {
            if ($best -and $route.Length -lt $best.Length) { break }
            if ($point -lt $route.Start -or $point -ge $route.End) { continue }
            if (-not $best) {
                $best = $route
                continue
            }
            if ($best.Index -ne $route.Index -and
                ($null -eq $best.Metric -or $null -eq $route.Metric -or $best.Metric -eq $route.Metric)) {
                throw 'The best Internet route is ambiguous across network interfaces.'
            }
        }
        if (-not $best -or $best.State -ne 'Alive') { throw 'An active route to the full Internet address range could not be verified.' }
        if ($routeIndex -ne 0 -and $routeIndex -ne $best.Index) {
            throw 'Internet routes use different interfaces. A full-tunnel VPN is required.'
        }
        $routeIndex = $best.Index
    }
    if ($routeIndex -eq 0) { throw 'Windows did not report an active IPv4 Internet route.' }
    $routeIndex
}

function Test-GuardVpnDriver($Adapter) {
    if ($Adapter.HardwareInterface -ne $false) { return $false }
    if ($Adapter.DriverDescription -ieq 'Wintun Userspace Tunnel') {
        return $Adapter.DriverProvider -ieq 'WireGuard LLC'
    }
    $Adapter.InterfaceDescription -imatch '^(?:WireGuard(?: Tunnel)?|TAP-Windows Adapter(?: V9)?|OpenVPN (?:Data Channel Offload|DCO) Adapter|Tailscale Tunnel|WAN Miniport \((?:IKEv2|L2TP|PPTP|SSTP)\))(?: #\d+)?$'
}

function Find-GuardPinnedAdapter($Snapshot, [string]$Pin) {
    $id = [guid]::Empty
    if (-not [guid]::TryParse($Pin, [ref]$id) -or $id -eq [guid]::Empty) {
        throw 'The saved VPN adapter identity is invalid.'
    }
    $matches = @($Snapshot.Adapters | Where-Object { $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq $id })
    if ($matches.Count -ne 1) { throw 'Windows could not find the saved VPN adapter.' }
    $matches[0]
}

function New-GuardVpnSelection($Snapshot, $Adapter) {
    [pscustomobject]@{
        InterfaceGuid = $Adapter.InterfaceGuid
        Name = $Adapter.Name
        Status = $Adapter.Status
        ifIndex = $Adapter.ifIndex
        OtherAdapters = @($Snapshot.Adapters | Where-Object ifIndex -NE $Adapter.ifIndex)
    }
}

function Get-GuardVpnAdapter([string]$Pin) {
    $snapshot = Get-GuardNetworkSnapshot
    $routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
    $index = Get-GuardPublicRouteIndex $routes $snapshot.Ipv4Interfaces
    $matches = @($snapshot.Adapters | Where-Object ifIndex -EQ $index)
    if ($matches.Count -ne 1 -or $matches[0].Status -ne 'Up' -or $matches[0].HardwareInterface -ne $false) {
        throw 'No active VPN tunnel owns the IPv4 Internet routes.'
    }
    $adapter = $matches[0]
    if (-not (Test-GuardVpnDriver $adapter)) { throw 'The active VPN type is not recognized.' }
    $id = [guid]::Empty
    if (-not [guid]::TryParse($adapter.InterfaceGuid, [ref]$id) -or $id -eq [guid]::Empty) {
        throw 'The active VPN adapter does not have a valid Windows identity.'
    }
    if ($Pin -and (Find-GuardPinnedAdapter $snapshot $Pin).ifIndex -ne $index) {
        throw 'The Internet route no longer uses the saved VPN.'
    }
    New-GuardVpnSelection $snapshot $adapter
}

function Get-GuardPinnedVpnAdapter([string]$Pin) {
    $snapshot = Get-GuardNetworkSnapshot
    $adapter = Find-GuardPinnedAdapter $snapshot $Pin
    if (-not (Test-GuardVpnDriver $adapter)) { throw 'The saved VPN type is not recognized.' }
    New-GuardVpnSelection $snapshot $adapter
}

function Get-GuardBlockedAdapters($Vpn, [switch]$AllowVpnDown) {
    if (-not $AllowVpnDown -and $Vpn.Status -ne 'Up') {
        throw 'The selected VPN adapter is disconnected.'
    }
    $aliases = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($adapter in $Vpn.OtherAdapters) {
        if (-not $adapter.IpBound) { continue }
        $id = [guid]::Empty
        if (-not [guid]::TryParse($adapter.InterfaceGuid, [ref]$id) -or $id -eq [guid]::Empty -or
            [string]::IsNullOrWhiteSpace($adapter.Name) -or -not $aliases.Add($adapter.Name)) {
            throw 'A non-VPN interface does not have a unique Windows firewall identity.'
        }
        $adapter
    }
}

function Test-GuardSystemProxy {
    if (-not ('ClaudeGuardWindowsProxy' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class ClaudeGuardWindowsProxy
{
    [StructLayout(LayoutKind.Sequential)]
    private struct UserSettings
    {
        [MarshalAs(UnmanagedType.Bool)] public bool AutoDetect;
        public IntPtr AutoConfigUrl;
        public IntPtr Proxy;
        public IntPtr Bypass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MachineSettings
    {
        public uint AccessType;
        public IntPtr Proxy;
        public IntPtr Bypass;
    }

    [DllImport("winhttp.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetIEProxyConfigForCurrentUser(out UserSettings settings);

    [DllImport("winhttp.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(out MachineSettings settings);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GlobalFree(IntPtr memory);

    private static bool HasText(IntPtr value)
    {
        return value != IntPtr.Zero && !String.IsNullOrWhiteSpace(Marshal.PtrToStringUni(value));
    }

    public static string Describe()
    {
        UserSettings user;
        bool userFound = WinHttpGetIEProxyConfigForCurrentUser(out user);
        int userError = Marshal.GetLastWin32Error();
        try
        {
            const int FileNotFound = 2;
            if (!userFound && userError != FileNotFound)
                throw new Win32Exception(userError, "Windows could not read the current user's proxy settings.");
            if (userFound)
            {
                if (HasText(user.Proxy))
                    return "ManualProxy";
                if (HasText(user.AutoConfigUrl))
                    return "AutoConfig";
                if (user.AutoDetect)
                    return "AutoDetect";
            }
        }
        finally
        {
            if (user.AutoConfigUrl != IntPtr.Zero) GlobalFree(user.AutoConfigUrl);
            if (user.Proxy != IntPtr.Zero) GlobalFree(user.Proxy);
            if (user.Bypass != IntPtr.Zero) GlobalFree(user.Bypass);
        }

        MachineSettings machine;
        bool machineFound = WinHttpGetDefaultProxyConfiguration(out machine);
        int machineError = Marshal.GetLastWin32Error();
        try
        {
            if (!machineFound)
                throw new Win32Exception(machineError, "Windows could not read the default WinHTTP proxy.");
            const uint NoProxy = 1;
            if (machine.AccessType != NoProxy || HasText(machine.Proxy))
                return "WinHttp";
            return "None";
        }
        finally
        {
            if (machine.Proxy != IntPtr.Zero) GlobalFree(machine.Proxy);
            if (machine.Bypass != IntPtr.Zero) GlobalFree(machine.Bypass);
        }
    }

    public static bool Configured()
    {
        return Describe() != "None";
    }
}
'@ -ErrorAction Stop
    }
    [ClaudeGuardWindowsProxy]::Configured()
}

function Get-GuardProxyDetail {
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'GLOBAL_AGENT_HTTP_PROXY')) {
        if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
            return [pscustomobject]@{
                Kind = 'EnvVar'
                Source = $name
                Message = "Process proxy environment variable '$name' is configured. Clear it so Claude routes directly through the VPN adapter."
            }
        }
    }
    $configured = Test-GuardSystemProxy
    if (-not $configured) {
        return [pscustomobject]@{ Kind = 'None'; Source = ''; Message = '' }
    }
    $kind = 'SystemProxy'
    if ('ClaudeGuardWindowsProxy' -as [type]) {
        $described = [ClaudeGuardWindowsProxy]::Describe()
        if ($described -and $described -ne 'None') { $kind = $described }
    }
    $message = switch ($kind) {
        'ManualProxy' {
            'Windows manual proxy is enabled (Settings -> Network & internet -> Proxy). Turn it off so Claude routes directly through the VPN adapter.'
        }
        'AutoConfig' {
            'A Windows proxy auto-configuration script (PAC) is enabled (Settings -> Network & internet -> Proxy). Turn it off so Claude routes directly through the VPN adapter.'
        }
        'AutoDetect' {
            'Windows automatic proxy discovery (WPAD / "Automatically detect settings") is enabled. Turn it off in Windows Settings -> Network & internet -> Proxy so Claude routes directly through the VPN adapter.'
        }
        'WinHttp' {
            'A machine-wide WinHTTP proxy is configured (check "netsh winhttp show proxy"). Clear it so Claude routes directly through the VPN adapter.'
        }
        default {
            'A Windows proxy or automatic proxy discovery is configured. The guard requires direct routing through the VPN adapter.'
        }
    }
    [pscustomobject]@{ Kind = $kind; Source = $kind; Message = $message }
}

function Assert-GuardNoProxy {
    $detail = Get-GuardProxyDetail
    if ($detail.Kind -ne 'None') {
        $error = [InvalidOperationException]::new($detail.Message)
        $error.Data['ProxyIssue'] = $detail.Kind
        throw $error
    }
}
