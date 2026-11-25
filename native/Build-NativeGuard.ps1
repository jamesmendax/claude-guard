[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UpstreamArchive
)

$ErrorActionPreference = 'Stop'
$buildFolder = Join-Path $PSScriptRoot '.build'
$corePath = Join-Path $buildFolder 'NetworkCore.ps1'
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Read-ZipScript($archive, [string]$pattern) {
    $matches = @($archive.Entries | Where-Object FullName -like $pattern)
    if ($matches.Count -ne 1) { throw "Expected one archived file matching $pattern." }
    $reader = [IO.StreamReader]::new($matches[0].Open())
    try { $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Get-NamedFunctions([string]$content, [string[]]$names) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($content, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw $errors[0].Message }
    $functions = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $false))
    foreach ($functionName in $names) {
        $entry = @($functions | Where-Object Name -ceq $functionName)
        if ($entry.Count -ne 1) { throw "Expected one implementation of $functionName." }
        $entry[0].Extent.Text
    }
}

$expectedArchiveHash = 'D8B8E1E7E0F1D5F4B376333D341B293FDA8DBD288923D31D3E9E8792E13FE14D'
$archivePath = (Resolve-Path -LiteralPath $UpstreamArchive).ProviderPath
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -cne $expectedArchiveHash) {
    throw 'The input does not match the pinned gruskry Claude VPN Guard v1.4.4 source ZIP.'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$activation = [IO.File]::ReadAllText((Join-Path $repoRoot 'package\guard-sandboxie.ps1'))
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $network = Read-ZipScript $archive '*/guard-network.ps1'
    $common = Read-ZipScript $archive '*/guard-common.ps1'
    $runtime = Read-ZipScript $archive '*/guard-runtime.ps1'
} finally { $archive.Dispose() }

# Some Wintun clients advertise a custom adapter description. Use the driver
# metadata for these adapters after the existing full-tunnel and virtual checks.
$oldVpnCheck = 'elseif ($vpn.InterfaceDescription -notmatch'
$newVpnCheck = @'
elseif (-not ($vpn.DriverDescription -eq 'Wintun Userspace Tunnel' -and $vpn.DriverProvider -eq 'WireGuard LLC') -and
        $vpn.InterfaceDescription -notmatch
'@
if (-not $network.Contains($oldVpnCheck)) { throw 'The archived VPN adapter check changed.' }
$network = $network.Replace($oldVpnCheck, $newVpnCheck)

# Reuse the existing rule matching and program discovery. Recognize both Store identities.
$oldFilter = "-eq 'Claude_pzs8sxrjxfjjc'"
$newFilter = "-in @('Claude_pzs8sxrjxfjjc','AnthropicPBC.Claude_fnn82j28hfe8t')"
if (-not $common.Contains($oldFilter)) { throw 'The archived Store inventory filter changed.' }
$common = $common.Replace($oldFilter, $newFilter)
$functions = @(
    Get-NamedFunctions $network @('Get-GuardNetworkAdapters','Get-GuardRouteIndex','Get-GuardVpnAdapter',
        'Get-GuardPinnedVpnAdapter','Get-GuardBlockedAdapters','Assert-GuardNoProxy')
    Get-NamedFunctions $common @('Throw-GuardCoverageChanged','Get-GuardRules','Get-GuardPackageSid',
        'Get-GuardFinalPath','Assert-GuardInstallationPath','Test-GuardProcessExited','Get-GuardProcessSnapshot',
        'Get-GuardRunningProcesses','Test-GuardAnthropicSignature','Get-GuardRunningClaudePaths',
        'Get-GuardServicePaths','Get-GuardInventory','Assert-GuardProfiles','Get-GuardSpecifications',
        'Get-GuardRuleFilter','Test-GuardRule','Assert-GuardCoverage','Initialize-GuardAdministratorDirectory')
    Get-NamedFunctions $runtime @('ConvertTo-GuardNativeArgument','Stop-GuardProcessTree','Stop-GuardRunningProcesses')
    Get-NamedFunctions $activation @('Start-GuardWindowsApplication')
)
$separator = [Environment]::NewLine + [Environment]::NewLine
$null = [IO.Directory]::CreateDirectory($buildFolder)
[IO.File]::WriteAllText($corePath, ($functions -join $separator), [Text.UTF8Encoding]::new($false))

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
$appName = 'ClaudeGuardNative-1.0.10-x64.exe'
$consoleName = 'ClaudeGuardNativeConsole-1.0.10-x64.exe'
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
