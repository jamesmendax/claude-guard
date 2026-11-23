# Claude Guard

Claude Guard is a Windows x64 tool for keeping the Microsoft Store edition of Claude Desktop on one approved Bettbox IPv4 exit. A single health-check timeout triggers another check. When Guard confirms that the channel has failed, it closes the protected application's network access before stopping it. The user reopens Claude Desktop after restoring the proxy.

![Claude Guard overview with sample data](docs/images/overview.png)

## Source availability

This repository includes the original Claude Guard interface, Windows protection components, and test fixtures prepared for public release. The 1.0.1 installer and complete source archive also include eight scripts derived from gruskry/claude-vpn-guard. The pinned upstream version has no published license declaration. Distribution of those scripts and the two complete artifacts is awaiting confirmation of the applicable terms. [Upstream v1.4.4](https://github.com/gruskry/claude-vpn-guard/releases/tag/v1.4.4)

The SHA-256 file identifies the exact installer and source ZIP built for the original 1.0.1 release. [Original artifact checksums](checksums/ClaudeGuardSetup-1.0.1-SHA256.txt)

## Try the interface

On Windows x64 with the .NET Framework WPF components and 64-bit Windows PowerShell 5.1, run the native window fixture from the checkout root.

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./tests/setup-native-window-tests.ps1
~~~

The fixture runs the actual WPF window with sample data. It exercises node changes, verification progress, recovery, and stop details. Its mock actions use no live Claude Desktop session or proxy. The overview's recent-stop entry distinguishes a Guard-initiated stop from a launcher-observed exit and a settings-window error. A nonzero exit code is shown alongside what Guard could confirm. [Example exit details](docs/images/observed-exit.png)

## Repository layout

- `package/` contains the Windows protection components included in the public snapshot.
- `release/` contains the WPF host, setup actions, build logic, and region catalog.
- `runtime/` contains the exit observer.
- `tests/` contains fixtures and their dependencies. Some integration suites require the full runtime. [Test instructions](tests/README.md)
- `tools/` contains optional local diagnostics.

The project's original components are distributed under GPL-3.0. Third-party components retain their respective terms. [Project license](LICENSE) · [Third-party notices](NOTICE.md)
