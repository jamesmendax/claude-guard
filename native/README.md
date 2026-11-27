# Claude Guard Native 2.0.0

This folder contains the complete source for Windows x64 **Native Guard 2.0.0**. A local build produces a native WPF graphical app (`ClaudeGuardNative-2.0.0-x64.exe`, ~313 KB) and a console executable (`ClaudeGuardNativeConsole-2.0.0-x64.exe`) using only Windows inbox tools — zero external SDKs or runtimes required.

> Read [LIMITATIONS.md](LIMITATIONS.md) for scope boundaries, policy caveats, and the distinction between offline-verified checks and live-environment verification.

## What's new in 2.0.0

- **Complete Native WPF UI & Custom Identity**: Replaces the legacy WinForms interface with a modular, zero-SDK Windows inbox WPF shell (`ui/Theme.xaml`, `ui/GuardMainWindow.cs`, `ui/OverviewPage.cs`, `ui/ExitPolicyPage.cs`, `ui/DesktopHygienePage.cs`, `ui/SystemMaintenancePage.cs`) featuring a custom frameless rounded window, a live **4-node Conduit Schematic**, live `中 | EN` language switching, and the multi-resolution **Aperture Gate** `.ico` + 3-state tray LED (`assets/ClaudeGuard.ico`, `ui/AppIcons.cs`).
- **Granular proxy / WPAD diagnostics**: Identifies the exact proxy source blocking launch (`EnvVar`, `ManualProxy`, `AutoConfig`, `AutoDetect` WPAD, or `WinHttp`) and displays an inline recovery card with a one-click **Open Windows proxy settings** button.
- **Optional fail-closed IPv4 TLS exit verification (with weak-network jitter tolerance)**: Direct IPv4 TLS `/cdn-cgi/trace` check (default host `claude.ai`, bypassing system proxies) against user-configured allowed country codes and/or IPv4 allowlists, before launch and during guarded sessions. Explicit IP/country mismatch blocks immediately (0 retries), while transient timeouts/packet loss (e.g., HY2/CDN jitter) support configurable retry tolerance (default 3 attempts). IPv4 addresses are masked (`203.0.*.*`) by default in the UI and diagnostic reports.
- **Event-driven + tiered session monitoring**: Registers Windows IP Helper notifications (`NotifyRouteChange2` / `NotifyIpInterfaceChange`) to wake verification immediately on route or interface changes while caching expensive disk/Store inventory scans across quiet ticks.
- **Claude Desktop hygiene, MCP-safe quarantine & daily guardian UX**: Scans Classic and Microsoft Store MSIX Claude Desktop data directories and Windows auto-start entries (`HKCU\...\Run` and Store `StartupTask`), quarantines cache/cookies/session/logs to a 1-click restorable backup while strictly protecting `claude_desktop_config.json` (MCP config), adds auto-minimize-to-tray guarding with balloon alerts, one-click safe Claude process-tree stop (`--stop-claude`), and guarded Desktop shortcut creation (`--launch-desktop`).
- **Live acceptance helper & optional Inno Setup script**: Adds `Verify-LiveGuard.ps1` (read-only host diagnostics + manual live-test checklist) and `installer/ClaudeGuardNative.iss`.

## Unified 4-tab desktop interface

| Tab | Capabilities |
| --- | --- |
| **Overview (`总览守卫`)** | Live 4-node Conduit Schematic (`Claude Desktop → Firewall Lock → VPN/TUN → Public Exit`), inline failure recovery guidance, hairline telemetry table, auto-minimize & IP reveal switches, one-click **Launch Claude Desktop**, **Launch CLI**, **Stop Claude**, and **Configure firewall**. |
| **Exit Policy (`出口策略`)** | Enable/disable fail-closed IPv4 TLS exit checks (`claude.ai`, ISO country allowlist, dedicated VPS IPv4 allowlist with automatic masking, recheck interval, weak-network retry tolerance) plus live **Probe now** & **Add current IPv4**. |
| **Desktop Hygiene (`桌面卫生`)** | Scan Classic & Store MSIX Claude Desktop folders, inspect Windows auto-start race risks, archive old cache/cookies/logs with strict `claude_desktop_config.json` (MCP) protection, 1-click restore from timestamped backups, and fingerprint-browser OAuth login tip. |
| **System (`系统与维护`)** | Apply/refresh or remove Windows Firewall rules, create a guarded Desktop shortcut (`--launch-desktop`), install/disable the 5-minute background refresh task, configure optional temporary session time zone, open Windows Region/Input (`--region`) and Encrypted DNS (DoH) tools, verify SHA-256 checksums, open logs, export masked diagnostics, or uninstall. |

The standalone region and input window also launches directly with `ClaudeGuardNative-2.0.0-x64.exe --region`, and guarded Desktop auto-launch works via `ClaudeGuardNative-2.0.0-x64.exe --launch-desktop`.

## Portable and console use

Keep the two executables and `SHA256SUMS.txt` together in the download folder or `native/.build/`. Double-click `ClaudeGuardNative-2.0.0-x64.exe` for the main window, or use the console:

```powershell
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --verify-package
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --status
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --status --cli
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --check-exit
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --check-exit --host claude.ai --allow-country US,JP
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --desktop
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --cli
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --cli --time-zone "Tokyo Standard Time" -- --help
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --stop-claude
```

A guarded Desktop or native CLI launch can request administrator approval to repair incomplete firewall coverage for the saved VPN. The guard verifies the rules and reruns the launch checks, including any enabled exit policy, before opening Claude.

## Optional installation and upkeep

Run from an elevated Windows Terminal under the Windows account that uses Claude (or trigger directly from the GUI **System** tab):

```powershell
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --install
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --install --enable-refresh
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --disable-refresh
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --remove-rules
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --uninstall
.\ClaudeGuardNativeConsole-2.0.0-x64.exe --uninstall --remove-rules
```

Installed files live in `%ProgramFiles%\Claude Guard Native\2.0.0` with administrator-only write ACLs.

## Build and verification

On Windows x64 with Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\native\Build-NativeGuard.ps1
.\native\Test-NetworkAdapters.ps1
.\native\Test-FirewallPolicy.ps1
.\native\Test-NativeGuard.ps1
.\native\Test-ExitAndMonitor.ps1
```

For live host read-only diagnostics and the manual live-acceptance checklist:

```powershell
.\native\Verify-LiveGuard.ps1
.\native\Verify-LiveGuard.ps1 -CheckExit -ReportPath .\live-check.txt
```

### Live Wi-Fi switching test

With Native Guard configured and its saved VPN connected, use an alternate Wi-Fi profile already saved in Windows. Run the preview first, then run the test when a brief interruption is acceptable.

```powershell
.\native\Test-WifiSwitch.ps1 -AlternateProfile 'Phone Hotspot' -WhatIf
.\native\Test-WifiSwitch.ps1 -AlternateProfile 'Phone Hotspot'
```

Use `-AlternateSsid` if the broadcast network name differs from the saved profile name, or `-InterfaceAlias` if more than one Wi-Fi adapter is active. The test switches networks and attempts to reconnect to the original profile even if a check fails. On both networks it checks IPv4 and the default gateway, requests HTTPS through the saved VPN, and reads back the effective firewall rules. The address and gateway together must differ between the two networks. The VPN and Bettbox stay running throughout.

The built executables are unsigned. Source is licensed under [GPL-3.0](../LICENSE).
