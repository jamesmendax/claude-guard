; Optional Inno Setup script for Claude Guard Native 2.0.1 (Windows x64)
; Build prerequisites:
;   1. Run .\native\Build-NativeGuard.ps1 to generate native\.build\*.exe and SHA256SUMS.txt
;   2. Compile with Inno Setup 6: iscc native\installer\ClaudeGuardNative.iss
;
; Note: Unsigned builds may trigger Windows SmartScreen or Smart App Control in Enforcement mode.

#define MyAppName "Claude Guard Native"
#define MyAppVersion "2.0.1"
#define MyAppPublisher "Claude Guard Contributors"
#define MyAppURL "https://github.com/jamesmendax/claude-guard"
#define MyAppExeName "ClaudeGuardNative.exe"
#define MyConsoleExeName "ClaudeGuardNativeConsole.exe"

[Setup]
AppId={{8E92D67B-4C7A-4F84-A985-3D4A1F9C8E12}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
DefaultDirName={autopf}\Claude Guard Native\{#MyAppVersion}
DisableDirPage=yes
DefaultGroupName={#MyAppName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir=..\.build
OutputBaseFilename=ClaudeGuardNative-{#MyAppVersion}-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\..\LICENSE
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "enablerefresh"; Description: "Register 5-minute background firewall rule auto-refresh (uses Native Guard SHA-256 verified installer)"; GroupDescription: "Background maintenance:"; Flags: unchecked

[Files]
Source: "..\.build\ClaudeGuardNative-{#MyAppVersion}-x64.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
Source: "..\.build\ClaudeGuardNativeConsole-{#MyAppVersion}-x64.exe"; DestDir: "{app}"; DestName: "{#MyConsoleExeName}"; Flags: ignoreversion
Source: "..\.build\SHA256SUMS.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LIMITATIONS.md"; DestDir: "{app}"; Flags: ignoreversion
; Staged portable package in {tmp} for optional S4U scheduled-task registration via Manage-NativeGuard.ps1
Source: "..\.build\ClaudeGuardNative-{#MyAppVersion}-x64.exe"; DestDir: "{tmp}\ngstage"; Flags: deleteafterinstall; Tasks: enablerefresh
Source: "..\.build\ClaudeGuardNativeConsole-{#MyAppVersion}-x64.exe"; DestDir: "{tmp}\ngstage"; Flags: deleteafterinstall; Tasks: enablerefresh
Source: "..\.build\SHA256SUMS.txt"; DestDir: "{tmp}\ngstage"; Flags: deleteafterinstall; Tasks: enablerefresh

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Windows Region and Language"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--region"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{tmp}\ngstage\ClaudeGuardNativeConsole-{#MyAppVersion}-x64.exe"; Parameters: "--install --enable-refresh"; WorkingDir: "{tmp}\ngstage"; Flags: runhidden waituntilterminated; Tasks: enablerefresh
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\{#MyConsoleExeName}"; Parameters: "--disable-refresh"; Flags: runhidden waituntilterminated; RunOnceId: "DisableNativeRefresh"
