# Claude Guard tests

Run these commands from the checkout root, which contains `package/`, `release/`, and `tests/`. Use 64-bit Windows PowerShell 5.1 for the PowerShell fixtures. Run each PowerShell command in a fresh process so its fixture functions and compiled types are isolated.

## Offline checks

These fixtures run from the public checkout. They use test data and mocked operations. The Node.js observer test uses a local loopback server and a self-signed test certificate. The matching PEM key is deliberately public and belongs only to that fixture.

```powershell
powershell.exe -NoProfile -File ./tests/bettbox-profile-tests.ps1
powershell.exe -NoProfile -File ./tests/browser-language-tests.ps1
powershell.exe -NoProfile -File ./tests/daily-notifier-task-tests.ps1
powershell.exe -NoProfile -File ./tests/daily-revision-baseline-tests.ps1
powershell.exe -NoProfile -File ./tests/daily-revision-evidence-tests.ps1
powershell.exe -NoProfile -File ./tests/daily-store-stage-tests.ps1
powershell.exe -NoProfile -File ./tests/node-locale-and-site-header-tests.ps1
powershell.exe -NoProfile -File ./tests/region-profile-tests.ps1
powershell.exe -NoProfile -File ./tests/release-install-tests.ps1
powershell.exe -NoProfile -File ./tests/setup-transaction-integration.ps1
powershell.exe -NoProfile -File ./tests/user-region-tests.ps1
powershell.exe -NoProfile -File ./tests/windows-locale-tests.ps1
powershell.exe -NoProfile -File ./tests/wfp-scope-readback.tests.ps1
powershell.exe -NoProfile -File ./tests/renewal-scheduling-replay.ps1 -ControllerPath ./package/guard-daily-controller.ps1
node.exe --test ./tests/exit-observer.test.mjs
```

The user-region fixture checks an unshown window. In an interactive Windows desktop session, `-PrivateDesktop` runs the 1.0.4 setup window fixture off the active desktop. Omit it to see the setup window with sample data.

```powershell
powershell.exe -NoProfile -STA -File ./tests/user-region-window-tests.ps1
powershell.exe -NoProfile -STA -File ./tests/setup-native-window-tests.ps1 -PrivateDesktop
```

## Relay, observer, and setup package

Use the release's Windows x64 Mihomo v1.19.30 binary and Node.js v24.22.3. The relay and node profile tests use synthetic local receivers. `test-mihomo-config.ps1` verifies the original Mihomo release binary ZIP before extracting a temporary copy and checking a synthetic configuration. The production observer source exists under `runtime/` in the released source archive. The identical copy beside the tests is used by the Node fixtures.

Set `$mihomoExe`, `$mihomoZip`, and `$nodeExe` to your local dependency paths. If you have the original local 1.0.4 EXE, set `$setupExe` to its path. The setup test uses the EXE's `--verify` and `--extract-test` modes. [Versions and sources](../NOTICE.md)

```powershell
powershell.exe -NoProfile -File ./tests/guard-relay-listener.tests.ps1
powershell.exe -NoProfile -File ./tests/guard-relay-evidence.tests.ps1 -MihomoPath $mihomoExe -NodePath $nodeExe
powershell.exe -NoProfile -File ./tests/node-profile-tests.ps1 -MihomoPath $mihomoExe -NodePath $nodeExe
powershell.exe -NoProfile -File ./tests/test-mihomo-config.ps1 -MihomoArchive $mihomoZip
powershell.exe -NoProfile -File ./tests/setup-package-tests.ps1 -SetupPath $setupExe
powershell.exe -NoProfile -File ./tests/run-loopback-lab.ps1 -DurationSeconds 3
```

The optional `observer-endurance.ps1` loopback test runs for at least one hour, or four hours with `-WithTraffic`. It writes its generated results to a unique directory under Windows TEMP by default. Pass `-OutputDirectory` to keep the results elsewhere.

## Native Windows labs and local diagnostics

`offline-tests.ps1`, `daily-controller-tests.ps1`, `daily-notification-tests.ps1`, `daily-record-publication-tests.ps1`, `daily-use-tests.ps1`, `setup-profile-actions-tests.ps1`, `setup-window-evidence-tests.ps1`, and the legacy WinForms fixture require inherited scripts from the complete runtime. The loopback lab's `-Monitor` mode also needs those scripts.

Use a disposable Windows VM for the protected native and Store labs. The full workflow needs the complete runtime, protected staging directories, pinned SDK and Sandboxie files, and an authorized Guard installation. The prior-hour verifier also needs independently pinned receipts and the reviewed input manifest. The public checkout contains the lab source. Historical receipts, provisioning drafts, and production cutover commands stay local.

`tools/inspect-bettbox-route.ps1` reads a local saved Bettbox selection, the listener and adapter and returns a summary. `tools/snapshot-live-guard.ps1` reads an existing Guard deployment and writes a local snapshot. Use `-DeployedPackageDirectory` and `-OutputPath` for the snapshot, with `-AdditionalRulePrefix` only for a legacy isolation deployment you administer. Keep diagnostic output local because it can contain paths, account identifiers, firewall addresses, and scheduled task arguments.
