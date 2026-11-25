#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$buildFolder = Join-Path $PSScriptRoot '.build'
$corePath = Join-Path $buildFolder 'NetworkCore.ps1'
$coreFiles = @(
    'NetworkAdapters.ps1'
    'ApplicationInventory.ps1'
    'FirewallPolicy.ps1'
    'WindowsApplication.ps1'
)
$core = foreach ($file in $coreFiles) {
    [IO.File]::ReadAllText((Join-Path $PSScriptRoot $file))
}
$null = [IO.Directory]::CreateDirectory($buildFolder)
$separator = [Environment]::NewLine + [Environment]::NewLine
[IO.File]::WriteAllText($corePath, ($core -join $separator), [Text.UTF8Encoding]::new($false))

$framework = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319'
$automation = Join-Path $env:windir 'Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll'
$compilerArguments = @(
    '/nologo', '/platform:x64', '/optimize+', '/warnaserror+',
    "/reference:$automation", '/reference:System.Windows.Forms.dll',
    '/reference:System.Drawing.dll', '/reference:System.Web.Extensions.dll',
    "/win32manifest:$(Join-Path $PSScriptRoot 'GuardNative.manifest')",
    "/resource:$($corePath),NetworkCore.ps1",
    "/resource:$(Join-Path $PSScriptRoot 'NativeGuard.ps1'),NativeGuard.ps1",
    "/resource:$(Join-Path $PSScriptRoot 'NativeSession.ps1'),NativeSession.ps1",
    "/resource:$(Join-Path $PSScriptRoot 'NativeDns.ps1'),NativeDns.ps1",
    (Join-Path $PSScriptRoot 'Program.cs'), (Join-Path $PSScriptRoot 'GuardWindow.cs'),
    (Join-Path $PSScriptRoot 'RegionalSettingsWindow.cs'), (Join-Path $PSScriptRoot 'DnsSettingsWindow.cs'),
    (Join-Path $PSScriptRoot 'GuardDiagnostics.cs')
)
$appName = 'ClaudeGuardNative-1.0.11-x64.exe'
$consoleName = 'ClaudeGuardNativeConsole-1.0.11-x64.exe'
$app = Join-Path $buildFolder $appName
$console = Join-Path $buildFolder $consoleName
$compiler = Join-Path $framework 'csc.exe'
& $compiler '/target:winexe' "/out:$app" @compilerArguments
if ($LASTEXITCODE -ne 0) { throw 'The native guard window build failed.' }
$management = "/resource:$(Join-Path $PSScriptRoot 'Manage-NativeGuard.ps1'),Manage-NativeGuard.ps1"
& $compiler '/target:exe' '/define:GUARD_CONSOLE' "$management" "/out:$console" @compilerArguments
if ($LASTEXITCODE -ne 0) { throw 'The native guard console build failed.' }
$hashes = @(Get-FileHash -LiteralPath $app,$console -Algorithm SHA256)
$lines = @($hashes | ForEach-Object { '{0}  {1}' -f $_.Hash, (Split-Path -Leaf $_.Path) })
[IO.File]::WriteAllLines((Join-Path $buildFolder 'SHA256SUMS.txt'), $lines, [Text.Encoding]::ASCII)
$hashes
