# Claude Guard

[English](README.md) · [简体中文](README.zh-CN.md)

**Claude Guard Native** is an open-source, zero-external-SDK Windows x64 launch guard for **Claude Desktop** and native **Claude Code CLI**. It verifies that Windows routes public IPv4 traffic through a single recognized full-tunnel VPN/TUN adapter, enforces scoped Windows Defender Firewall outbound blocks on non-VPN interfaces and IPv6 for discovered Anthropic-signed binaries and Store packages, monitors sessions via Windows IP Helper change notifications, and provides optional fail-closed IPv4 TLS exit verification, MCP-safe Claude Desktop hygiene, and reversible Windows locale/timezone/DoH controls.

> **Important scope note**: Claude Guard is a local Windows routing, firewall, and settings hygiene tool. It does **not** change Anthropic's [Supported Regions policy](https://www.anthropic.com/legal/supported-regions) and does **not** guarantee against account restrictions. Read [Known Limitations](native/LIMITATIONS.md) before use.

<p align="center">
  <img src="docs/preview-overview.png" alt="Claude Guard Native 2.0.0 WPF Interface" width="760" />
</p>

## Major Release: Native Guard 2.0.0

- **Redesigned Native WPF Desktop UI (~313 KB, Zero External SDK)**: Built directly with Windows inbox `.NET Framework` WPF (`PresentationFramework.dll` + `WindowChrome`), featuring a custom frameless rounded window, a slim 4-tab navigation rail (**Overview / Exit Policy / Desktop Hygiene / System**), a live **4-node Conduit Schematic** that pinpoints exact route or proxy breaks, modular XAML styling (`native/ui/Theme.xaml`), and a custom multi-resolution **Aperture Gate** `.ico` + 3-state system tray LED (Ready / Warning / Blocked).
- **Optional Fail-Closed Public Exit Verification (with Weak-Network Jitter Tolerance)**: Directly probes `https://<host>/cdn-cgi/trace` (default `claude.ai`) over IPv4 TLS (bypassing system proxies) against user-configured allowed ISO country codes and/or dedicated VPS IPv4 allowlists, before launch and during sessions. Explicit IP/country mismatch blocks immediately (0 retries), while transient packet loss/timeouts (e.g., HY2/CDN jitter) support configurable retry tolerance (default 3 attempts). IPv4 addresses are masked (`203.0.*.*`) by default.
- **Event-Driven + Tiered Session Monitor**: Registers Windows IP Helper notifications (`NotifyRouteChange2` / `NotifyIpInterfaceChange`) to wake verification immediately on route or interface changes while caching expensive disk/Store inventory scans across quiet ticks.
- **Claude Desktop Hygiene, MCP-Safe Quarantine & Daily Guardian UX**: Audits Classic and Microsoft Store MSIX Claude Desktop data directories plus Windows auto-start entries (`HKCU\...\Run` / Store `StartupTask`), archives old cache/cookies/session/logs to a 1-click restorable backup while **strictly protecting `claude_desktop_config.json` (MCP config)**, and supports auto-minimize-to-tray guarding with balloon alerts, safe Claude process-tree stop (`--stop-claude`), and guarded Desktop shortcut creation (`--launch-desktop`).
- **Granular Proxy / WPAD Diagnostics**: Distinguishes process proxy environment variables, Windows manual proxy, PAC scripts, Windows WPAD (`Automatically detect settings`), and WinHTTP proxy, with an inline repair prompt and one-click link to Windows Proxy Settings.
- **Bilingual UI (English / 简体中文) & Full Console Companion**: Live segmented `中 | EN` language switcher, Windows region/input tool (`--region`), session time-zone rollback, encrypted DNS (DoH) controls, SHA-256 package verification (`--verify-package`), and masked diagnostic report export.

👉 **[Native Guard 2.0.0 documentation, CLI reference, build & verification steps](native/README.md)** · **[Known limitations](native/LIMITATIONS.md)** · **[Releases](https://github.com/jamesmendax/claude-guard/releases)**

### Quick build and offline verification (Windows x64)

```powershell
.\native\Build-NativeGuard.ps1
.\native\Test-NetworkAdapters.ps1
.\native\Test-FirewallPolicy.ps1
.\native\Test-NativeGuard.ps1
.\native\Test-ExitAndMonitor.ps1
```

For read-only live host diagnostics and the manual live-acceptance checklist:

```powershell
.\native\Verify-LiveGuard.ps1
```

---

## Historical Public Source Archive: Claude Guard 1.0.1–1.0.4 (Bettbox / WFP)

The directories `package/`, `release/`, `runtime/`, `tests/`, and `tools/` preserve the original public source components and test fixtures for the earlier **Claude Guard 1.0.4** Bettbox/WFP/AppContainer architecture.

- Because the complete 1.0.4 installer depended on eight inherited scripts from `gruskry/claude-vpn-guard` (whose pinned revision lacks a published redistribution license), those omitted scripts and the full 1.0.4 installer remain private. Building the full 1.0.4 installer from this public checkout is **not** supported; use **Native Guard 2.0.0** in [`native/`](native/) for a complete, self-contained public build.
- See [Third-party notices](NOTICE.md), [1.0.4 checksums](checksums/ClaudeGuardSetup-1.0.4-SHA256.txt), and [legacy test instructions](tests/README.md).

## Repository layout

- `native/` — **Active mainline**: complete source (`ui/`, `assets/`, `ExitProbe.cs`, `NetworkMonitor.cs`, `DesktopHygiene.cs`), 107 offline tests, live verification helper, Inno Setup script, and limitations doc for **Native Guard 2.0.0**.
- `.github/workflows/native-guard-ci.yml` — Automated Windows CI building and testing Native Guard under both Windows PowerShell 5.1 and PowerShell 7.
- `package/`, `release/`, `runtime/`, `tests/`, `tools/` — Historical 1.0.4 Bettbox/WFP public source snapshot and fixtures.

Original project components are licensed under [GPL-3.0](LICENSE). Third-party notices are documented in [NOTICE.md](NOTICE.md).
