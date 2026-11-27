#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()][string]$AlternateProfile,
    [ValidateNotNullOrEmpty()][string]$AlternateSsid,
    [ValidateNotNullOrEmpty()][string]$InterfaceAlias
)

$ErrorActionPreference = 'Stop'
# Inspect netsh and curl exit codes explicitly in both Windows PowerShell and PowerShell 7.
$PSNativeCommandUseErrorActionPreference = $false

if (-not ('ClaudeGuardNative.WifiTest' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace ClaudeGuardNative
{
    public static class WifiTest
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Dot11Ssid
        {
            public uint Length;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] Bytes;
        }

        // The prefix of WLAN_CONNECTION_ATTRIBUTES through its associated SSID.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ConnectionAttributes
        {
            public uint State;
            public uint Mode;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string Profile;
            public Dot11Ssid Ssid;
        }

        public sealed class Connection
        {
            public string Profile;
            public byte[] Ssid;
        }

        [DllImport("wlanapi.dll")]
        private static extern uint WlanOpenHandle(uint version, IntPtr reserved, out uint negotiated, out IntPtr handle);
        [DllImport("wlanapi.dll")]
        private static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);
        [DllImport("wlanapi.dll")]
        private static extern uint WlanQueryInterface(IntPtr handle, ref Guid adapter, int opcode, IntPtr reserved,
            out uint size, out IntPtr data, IntPtr valueType);
        [DllImport("wlanapi.dll")]
        private static extern void WlanFreeMemory(IntPtr data);
        [DllImport("wlanapi.dll", EntryPoint = "WlanScan")]
        private static extern uint ScanAll(IntPtr handle, ref Guid adapter, IntPtr ssid, IntPtr data, IntPtr reserved);
        [DllImport("wlanapi.dll", EntryPoint = "WlanScan")]
        private static extern uint ScanSsid(IntPtr handle, ref Guid adapter, ref Dot11Ssid ssid, IntPtr data, IntPtr reserved);

        private static IntPtr Open()
        {
            IntPtr handle;
            uint version;
            uint error = WlanOpenHandle(2, IntPtr.Zero, out version, out handle);
            if (error != 0) throw new Win32Exception((int)error);
            return handle;
        }

        public static Connection Current(Guid adapter)
        {
            const int CurrentConnection = 7;
            const int InvalidState = 5023;
            const uint Connected = 1;
            IntPtr handle = Open();
            IntPtr data = IntPtr.Zero;
            try
            {
                uint size;
                uint error = WlanQueryInterface(handle, ref adapter, CurrentConnection, IntPtr.Zero,
                    out size, out data, IntPtr.Zero);
                if (error == InvalidState) return null;
                if (error != 0) throw new Win32Exception((int)error);
                if (size < Marshal.SizeOf(typeof(ConnectionAttributes)))
                    throw new InvalidOperationException("Windows returned incomplete Wi-Fi connection attributes.");

                var connection = (ConnectionAttributes)Marshal.PtrToStructure(data, typeof(ConnectionAttributes));
                if (connection.State != Connected) return null;
                if (connection.Ssid.Length == 0 || connection.Ssid.Length > 32)
                    throw new InvalidOperationException("Windows returned an invalid associated SSID.");
                var bytes = new byte[connection.Ssid.Length];
                Array.Copy(connection.Ssid.Bytes, bytes, bytes.Length);
                return new Connection { Profile = connection.Profile, Ssid = bytes };
            }
            finally
            {
                if (data != IntPtr.Zero) WlanFreeMemory(data);
                WlanCloseHandle(handle, IntPtr.Zero);
            }
        }

        public static void Scan(Guid adapter, byte[] bytes)
        {
            IntPtr handle = Open();
            try
            {
                uint error;
                if (bytes == null || bytes.Length == 0)
                    error = ScanAll(handle, ref adapter, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                else
                {
                    var ssid = new Dot11Ssid { Length = (uint)bytes.Length, Bytes = new byte[32] };
                    Array.Copy(bytes, ssid.Bytes, bytes.Length);
                    error = ScanSsid(handle, ref adapter, ref ssid, IntPtr.Zero, IntPtr.Zero);
                }
                if (error != 0) throw new Win32Exception((int)error);
                // WlanScan queues a request. The WLAN service allows up to four seconds for completion.
                Thread.Sleep(4200);
            }
            finally { WlanCloseHandle(handle, IntPtr.Zero); }
        }
    }
}
'@
}

function Get-WifiConnection([guid]$Adapter) {
    [ClaudeGuardNative.WifiTest]::Current($Adapter)
}

function Test-WifiConnection($Current, $Expected) {
    $null -ne $Current -and $Current.Profile -ceq $Expected.Profile -and
        [Convert]::ToBase64String($Current.Ssid) -ceq [Convert]::ToBase64String($Expected.Ssid)
}

function Get-WifiIpv4([int]$InterfaceIndex) {
    $addresses = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue |
        Where-Object IPAddress -NotLike '169.254.*' | Select-Object -ExpandProperty IPAddress)
    $gateways = @(Get-NetRoute -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object NextHop -NotIn @('', '0.0.0.0') | Select-Object -ExpandProperty NextHop)
    if ($addresses.Count -and $gateways.Count) {
        [pscustomobject]@{ Key = (($addresses | Sort-Object) -join ',') + '|' + (($gateways | Sort-Object) -join ',') }
    }
}

function Get-WifiTestSettings {
    $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    [pscustomobject]@{
        BettboxProcessIds = (@(Get-Process -Name BettboxCore -ErrorAction SilentlyContinue | Sort-Object Id |
            Select-Object -ExpandProperty Id) -join ',')
        ProxyEnabled = [bool]$proxy.ProxyEnable
        ProxyServer = [string]$proxy.ProxyServer
        ProxyScript = [string]$proxy.AutoConfigURL
        ProxyConfigured = Test-GuardSystemProxy
    }
}

function Connect-SavedWifi($Test, $Target, [switch]$Restoring) {
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            if ($attempt) { [ClaudeGuardNative.WifiTest]::Scan($Test.AdapterId, $null) }
            [ClaudeGuardNative.WifiTest]::Scan($Test.AdapterId, $Target.Ssid)
        } catch {
            if (!$Restoring) { throw }
            Write-Warning "Scanning before restoration failed. Requesting the original profile directly. $($_.Exception.Message)"
        }
        $Test.ConnectionPending = $true
        $reply = @(& $Test.Netsh wlan connect "name=$($Target.Profile)" "ssid=$($Target.SsidText)" "interface=$($Test.Alias)")
        if ($LASTEXITCODE -eq 0) { break }
    }
    if ($LASTEXITCODE -ne 0) { throw "Windows rejected the connection to $($Target.Label). $($reply -join ' ')" }

    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (Test-WifiConnection (Get-WifiConnection $Test.AdapterId) $Target) {
            $Test.ConnectionPending = $false
            return
        }
        Start-Sleep -Milliseconds 450
    } while ($clock.Elapsed.TotalSeconds -lt 20)
    throw "Windows did not finish connecting to $($Target.Label)."
}

function Confirm-WifiLeg($Test, $Target, [string]$PreviousAddress) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (!(Test-WifiConnection (Get-WifiConnection $Test.AdapterId) $Target)) {
            throw "Wi-Fi changed while waiting for IPv4 settings on $($Target.Label)."
        }
        $address = Get-WifiIpv4 $Test.InterfaceIndex
        if ($address -and (!$PreviousAddress -or $address.Key -cne $PreviousAddress)) { break }
        Start-Sleep -Milliseconds 500
    } while ($clock.Elapsed.TotalSeconds -lt 20)
    if (!$address -or ($PreviousAddress -and $address.Key -ceq $PreviousAddress)) {
        throw "$($Target.Label) did not obtain an updated IPv4 address and default gateway."
    }

    $endpoints = @('https://example.com/', 'https://www.microsoft.com/favicon.ico')
    $response = $null
    $attempt = 0
    do {
        if (!(Test-WifiConnection (Get-WifiConnection $Test.AdapterId) $Target)) {
            throw "Wi-Fi changed during the HTTPS check on $($Target.Label)."
        }
        try { $vpn = Get-GuardVpnAdapter ([string]$Test.Policy.VpnGuid) } catch { $vpn = $null }
        if ($vpn) {
            $endpoint = $endpoints[$attempt % $endpoints.Count]
            $attempt++
            $received = & $Test.Curl --disable --ipv4 --noproxy '*' --connect-timeout 5 --max-time 8 --silent --output NUL --write-out '%{http_code} %{size_download}' $endpoint
            if ($LASTEXITCODE -eq 0 -and $received -match '^200 ([1-9][0-9]*)$') {
                $response = [long]$Matches[1]
                break
            }
        }
        Start-Sleep -Milliseconds 500
    } while ($clock.Elapsed.TotalSeconds -lt 42)
    if ($null -eq $response) { throw "$($Target.Label) did not return HTTPS data through the saved VPN." }

    $vpn = Get-GuardVpnAdapter ([string]$Test.Policy.VpnGuid)
    $specifications = @(Get-GuardSpecifications (Get-GuardInventory) @(Get-GuardBlockedAdapters $vpn))
    Assert-GuardProfiles
    Assert-GuardCoverage $specifications @($Test.Policy.Rules)
    if (!(Test-WifiConnection (Get-WifiConnection $Test.AdapterId) $Target)) {
        throw "Wi-Fi changed during the policy check on $($Target.Label)."
    }
    $settings = Get-WifiTestSettings
    if ((Get-FileHash -LiteralPath $Test.PolicyPath -Algorithm SHA256).Hash -cne $Test.PolicyHash -or
        $settings.BettboxProcessIds -cne $Test.Settings.BettboxProcessIds -or
        $settings.ProxyEnabled -ne $Test.Settings.ProxyEnabled -or $settings.ProxyServer -cne $Test.Settings.ProxyServer -or
        $settings.ProxyScript -cne $Test.Settings.ProxyScript -or $settings.ProxyConfigured -ne $Test.Settings.ProxyConfigured) {
        throw "The saved firewall policy, Bettbox processes, or system proxy changed on $($Target.Label)."
    }

    [pscustomobject]@{
        Network = $Target.Label
        HttpsStatus = 200
        BytesReceived = $response
        HttpsAttempts = $attempt
        VerifiedRules = @($Test.Policy.Rules).Count
    }
}

function Invoke-WifiRoundTrip($Test) {
    $testError = $null
    $restoreError = $null
    try {
        Connect-SavedWifi $Test $Test.Alternate
        Confirm-WifiLeg $Test $Test.Alternate $Test.InitialAddress
    } catch {
        $testError = $_
    } finally {
        try {
            $current = try { Get-WifiConnection $Test.AdapterId } catch {
                Write-Verbose "Could not read the connection before restoration. $($_.Exception.Message)"
            }
            $previousAddress = $null
            if ($Test.ConnectionPending -or !(Test-WifiConnection $current $Test.Original)) {
                if (Test-WifiConnection $current $Test.Alternate) {
                    $alternateAddress = try { Get-WifiIpv4 $Test.InterfaceIndex } catch {
                        Write-Verbose "Could not read the alternate IPv4 settings before restoration. $($_.Exception.Message)"
                    }
                    if ($alternateAddress -and $alternateAddress.Key -cne $Test.InitialAddress) {
                        $previousAddress = $alternateAddress.Key
                    }
                }
                Connect-SavedWifi $Test $Test.Original -Restoring
            }
            Confirm-WifiLeg $Test $Test.Original $previousAddress
        } catch { $restoreError = $_ }
    }
    if ($testError -and $restoreError) {
        throw "Wi-Fi test failed. $($testError.Exception.Message) Restoration check failed. $($restoreError.Exception.Message)"
    }
    if ($restoreError) { throw $restoreError }
    if ($testError) { throw $testError }
}

# NdisPhysicalMediumWirelessLan (1) and NdisPhysicalMediumNative802_11 (9).
$wireless = @(Get-NetAdapter -Physical | Where-Object {
    $_.Status -eq 'Up' -and $_.NdisPhysicalMedium -in @(1, 9) -and (!$InterfaceAlias -or $_.Name -eq $InterfaceAlias)
})
if ($wireless.Count -ne 1) { throw 'Select one connected wireless adapter with -InterfaceAlias.' }
$adapter = $wireless[0]
$original = Get-WifiConnection ([guid]$adapter.InterfaceGuid)
if (!$original -or !$original.Profile) { throw 'Connect to the original saved Wi-Fi before running this test.' }
if ($original.Profile -ceq $AlternateProfile) { throw 'Choose a saved profile different from the current Wi-Fi.' }

$ssidEncoding = [Text.UTF8Encoding]::new($false, $true)
$startSsid = $ssidEncoding.GetString($original.Ssid)
if (!$AlternateSsid) { $AlternateSsid = $AlternateProfile }
$alternateBytes = $ssidEncoding.GetBytes($AlternateSsid)
if ($alternateBytes.Length -gt 32) { throw 'The alternate SSID has more than 32 UTF-8 bytes. Specify its exact name with -AlternateSsid.' }
$netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
foreach ($profile in @($original.Profile, $AlternateProfile)) {
    $null = & $netsh wlan show profile "name=$profile" "interface=$($adapter.Name)"
    if ($LASTEXITCODE -ne 0) { throw "Windows has no saved profile named '$profile' on the selected adapter." }
}
if (!$PSCmdlet.ShouldProcess($adapter.Name, "Connect to '$AlternateProfile', verify HTTPS, and return to '$($original.Profile)'")) { return }

. (Join-Path $PSScriptRoot 'NetworkAdapters.ps1')
. (Join-Path $PSScriptRoot 'ApplicationInventory.ps1')
. (Join-Path $PSScriptRoot 'FirewallPolicy.ps1')
$statePath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeGuardNative\firewall.json'
$policy = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($policy.Version -ne 1 -or !$policy.VpnGuid -or !@($policy.Rules).Count) {
    throw 'Set up a saved Native Guard firewall policy before this test.'
}
$null = Get-GuardVpnAdapter ([string]$policy.VpnGuid)
$initialAddress = Get-WifiIpv4 $adapter.ifIndex
if (!$initialAddress) { throw 'The original Wi-Fi needs a preferred IPv4 address and default gateway.' }

$test = [pscustomobject]@{
    AdapterId = [guid]$adapter.InterfaceGuid
    InterfaceIndex = [int]$adapter.ifIndex
    Alias = [string]$adapter.Name
    Netsh = $netsh
    Curl = (Get-Command curl.exe -CommandType Application | Select-Object -First 1).Path
    Original = [pscustomobject]@{ Label = 'original Wi-Fi'; Profile = $original.Profile; Ssid = $original.Ssid; SsidText = $startSsid }
    Alternate = [pscustomobject]@{ Label = 'alternate Wi-Fi'; Profile = $AlternateProfile; Ssid = $alternateBytes; SsidText = $AlternateSsid }
    InitialAddress = $initialAddress.Key
    Policy = $policy
    PolicyPath = $statePath
    PolicyHash = (Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
    Settings = Get-WifiTestSettings
    ConnectionPending = $false
}
if (!(Test-WifiConnection (Get-WifiConnection $test.AdapterId) $test.Original)) {
    throw 'The original Wi-Fi changed during preflight.'
}
Invoke-WifiRoundTrip $test
