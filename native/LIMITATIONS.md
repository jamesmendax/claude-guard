# Known Limitations and Scope Boundaries (Native Guard 2.0.2)

This document records what **Claude Guard Native** verifies, what it does **not** cover, and which scenarios require live testing on your own Windows environment.

## 1. Service Terms and Region Policy

- Native Guard is a local Windows routing, firewall, and settings hygiene tool.
- Anthropic's [Supported Regions policy](https://www.anthropic.com/legal/supported-regions) applies based on the user's actual location and terms of service.
- Checking exit IP, Windows time zone, regional settings, or DNS-over-HTTPS **cannot** change policy applicability and does **not** guarantee against account restrictions or suspension.

## 2. Full-Tunnel Routing vs. Local Split-Tunnel Proxies

- Native Guard requires all public IPv4 routes (outside standard local/private ranges such as `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `127.0.0.0/8`, `224.0.0.0/3`) to resolve to one recognized virtual VPN adapter (`Wintun`, `WireGuard`, `OpenVPN TAP/DCO`, `Tailscale`, or Windows `WAN Miniport`).
- **Host `/32` bypass routes**: VPN clients that install a public `/32` host route via the physical NIC to reach their own VPN server (instead of socket interface binding such as `IP_UNICAST_IF`) will fail the strict full-tunnel check.
- **System proxy / WPAD**: System proxies, PAC scripts, process proxy environment variables, and Windows WPAD (`Automatically detect settings`) are rejected because Windows Firewall does not block loopback traffic to a local proxy listener.
- **User-space TUN split routing**: If you use a TUN-mode proxy client (such as Mihomo/Clash/sing-box TUN) that owns the Windows Wintun route while splitting domains internally in user space, the Windows route check alone cannot see whether `claude.ai` is routed to a remote node or `DIRECT`. Enabling **Exit Verification** (`Settings -> Exit verification`) with target `claude.ai` adds a direct IPv4 TLS probe for that domain, but note:
  - A probe proves only the exit observed for that probe connection at that moment, not a cryptographic proof over every future packet inside the TUN daemon.
  - Keeping your TUN client's rules pinned to the approved node remains essential.

## 3. Process, Service, and Child-Process Coverage

- Firewall rules cover discovered Anthropic-signed executables (`Claude.exe`, `claude.exe`, `cowork-svc.exe`, etc.) and recognized Microsoft Store package identities (`AppContainer SID`).
- **Generic child processes**: Tools spawned by Claude Code (such as `git.exe`, `node.exe`, `python.exe`, `curl.exe`, `pwsh.exe`) are **not** signed by Anthropic and are **not** individually blocked by Native Guard's firewall rules (blocking them would break unrelated work on the same machine).
- **npm-installed Claude Code**: Native Guard's CLI mode targets the standalone Anthropic-signed native `claude.exe` on `PATH`, not `node.exe`-hosted npm wrappers.
- **Hyper-V / Cowork VM NAT**: While the host-side signed `cowork-svc.exe` service binary is included in firewall rules, any VM traffic forwarded by Windows Hyper-V NAT does not carry a per-application process identity in Windows Defender Firewall.

## 4. Monitoring and Recovery Semantics

- Native Guard combines Windows IP Helper notifications (`NotifyRouteChange2` / `NotifyIpInterfaceChange`) with tiered periodic checks so route/interface changes wake verification promptly instead of waiting for a full sleep cycle.
- Even with event-driven wakeup, process termination after a fault is best-effort and asynchronous; if a process cannot be terminated, Native Guard surfaces an explicit error rather than claiming cleanup succeeded.
- **Session time zone recovery**: If Native Guard changes the Windows time zone for a guarded session and the machine loses power or Guard is forcibly killed before exit, the pending journal (`%LOCALAPPDATA%\ClaudeGuardNative\session-zone.json`) is recovered on the **next** guarded launch (and preserves any later manual change by the user).

## 5. Build Signing and Smart App Control

- Locally built and GitHub Release binaries are **unsigned**.
- Windows SmartScreen may display an unknown-publisher warning, and Windows 11 systems with **Smart App Control** set to Enforcement mode may block unsigned executables.

## 6. Verification Status Distinction

- **Offline test suite**: Verifies route interval math, proxy/WPAD classification, firewall rule coverage and reuse, exit trace parsing and allowlist policy evaluation, monitor event signaling, and session time-zone rollback using deterministic fixtures.
- **Live acceptance**: Real VPN disconnect/reconnect behavior, packet-level leak verification, and production Microsoft Store / Claude Code updates must be verified on a real Windows host or disposable VM using `native/Verify-LiveGuard.ps1`.
