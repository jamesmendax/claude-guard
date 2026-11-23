#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixturePath,
    [ValidateRange(20000,47999)][int]$RelayPort
)

$ErrorActionPreference='Stop'
$fullPath=[IO.Path]::GetFullPath($FixturePath)
if($fullPath -ine $FixturePath -or
    $fullPath -cnotmatch '\A[A-Za-z]:\\(?:[A-Za-z0-9 ._-]+\\)*WindowsApps\\GuardMsixFixture\.[0-9a-f]{32}_(?:[0-9]{1,5}\.){3}[0-9]{1,5}_x64__[a-z0-9]{13}\z'){
    throw 'Expected the exact installed location of a generated Guard MSIX fixture.'
}

# Emit a test configuration only. The caller must verify the bound synthetic relay.
'[GlobalSettings]'
'NetworkEnableWFP=y'
''
'[GuardNativeFixture]'
'Enabled=y'
"ForceFolder=$fullPath"
'ForceProcess=fixture-desktop.exe'
'OpenPipePath=\Device\NamedPipe\GuardNormalPackage-*'
'ClosedIpcPath=\RPC Control\DNSResolver'
'NetworkAccess=Block'
if($PSBoundParameters.ContainsKey('RelayPort')){
    "NetworkAccess=Allow;Address=127.0.0.1;Port=$RelayPort;Protocol=TCP"
}
