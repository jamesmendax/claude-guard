#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$source = Join-Path $PSScriptRoot 'NativeGuard.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($definition in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:GuardRulePrefix = 'ClaudeGuardNative-Block'
$script:ProgramDataRoot = 'C:\NativeGuardFixture'
$script:GuardFolder = Join-Path $script:ProgramDataRoot 'ClaudeGuardNative'
$script:GuardState = Join-Path $script:GuardFolder 'firewall.json'
$script:DailyState = Join-Path $script:ProgramDataRoot 'ClaudeVPNGuard\daily-mode.json'
$script:Pin = '019e0648-36ea-4cc5-8798-81934eb2be65'
$script:AdapterId = '40ebca6a-6a6c-4d4a-88ed-e14653444da6'
$script:OldRule = 'ClaudeGuardNative-Block-078fdcfdbecb4a8fb046212ccb9cd232-0'
$script:FixtureExe = 'C:\NativeGuardFixture\Claude.exe'
$script:Passed = 0

function Reset-Fixture {
    $script:FixtureState = [pscustomobject]@{
        Version = 1
        OwnerSid = Get-GuardNativeOwner
        VpnGuid = $script:Pin
        Rules = @($script:OldRule)
        Adapters = @([pscustomobject]@{ Guid = $script:AdapterId; Alias = 'Fixture Ethernet' })
    }
    $script:Rules = @{}
    $script:Rules[$script:OldRule] = 'Outbound Block'
    $script:DailyPresent = $false
    $script:Started = $false
    $script:StopRequested = $false
    $script:SleepCount = 0
    $script:WriteCount = 0
    $script:CreateCount = 0
    $script:FailSecondCreate = $false
    $script:FailDuringSession = $false
    $script:ProxyPresent = $false
    $script:DesktopPresent = $true
    $script:RefreshChecked = $false
    $script:NewProgram = $null
    $script:ObservedArgs = $null
    $script:RemovedRules = [Collections.Generic.List[string]]::new()
}

function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    switch ($LiteralPath) {
        $script:GuardState { return $null -ne $script:FixtureState }
        $script:DailyState { return $script:DailyPresent }
        default { throw "Unexpected fixture path check: $LiteralPath" }
    }
}

function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)
    switch ($LiteralPath) {
        $script:GuardFolder { return [pscustomobject]@{ PSIsContainer = $true; Attributes = 0 } }
        $script:GuardState { return [pscustomobject]@{ FullName = $LiteralPath; Attributes = 0; Length = 512 } }
        $script:SessionJournal { return Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force }
        default { throw "Unexpected fixture file read: $LiteralPath" }
    }
}

function Get-Content {
    param([string]$LiteralPath, [switch]$Raw)
    if ($LiteralPath -ne $script:GuardState -or -not $Raw) { throw 'Unexpected fixture state read.' }
    $script:FixtureState | ConvertTo-Json -Depth 5 -Compress
}

function Assert-GuardNoProxy {
    if ($script:ProxyPresent) { throw 'Fixture proxy configured.' }
}
function Assert-GuardAdministratorDirectory([string]$Path) {}
function Assert-GuardProfiles {}

function Get-GuardVpnAdapter([string]$Pin) {
    if ($Pin -and $Pin -ne $script:Pin) { throw 'Unexpected fixture VPN pin.' }
    [pscustomobject]@{ InterfaceGuid = $script:Pin }
}

function Get-GuardPinnedVpnAdapter([string]$Pin) {
    if ($Pin -ne $script:Pin) { throw 'Unexpected fixture VPN pin during refresh.' }
    $script:RefreshChecked = $true
    [pscustomobject]@{ InterfaceGuid = $script:Pin }
}

function Get-GuardBlockedAdapters($Vpn, [switch]$AllowVpnDown) {
    [pscustomobject]@{ InterfaceGuid = $script:AdapterId; Name = 'Fixture Ethernet'; Status = 'Up'; Ipv4Present = $true }
}

function Get-GuardInventory {
    [pscustomobject]@{
        DesktopPaths = if ($script:DesktopPresent) { @($script:FixtureExe) } else { @() }
        Packages = @()
        Programs = @($script:FixtureExe)
        CliPath = $script:FixtureExe
    }
}

function Test-GuardAnthropicSignature([string]$Path) { $Path -eq $script:FixtureExe }

function Get-GuardFirewallKey([string]$Alias, [string]$Program, [string]$Package, [string]$RemoteAddress) {
    "$Alias|$Program|$Package|$RemoteAddress"
}

function Get-GuardReusableRules($Specifications, [string[]]$CandidateNames) {
    if ($script:NewProgram -and $CandidateNames -contains $script:OldRule) {
        [pscustomobject]@{
            Name = $script:OldRule
            Key = Get-GuardFirewallKey 'Fixture Ethernet' $script:FixtureExe '' 'Any'
        }
    }
}

function Get-GuardSpecifications($Inventory, $Adapters) {
    [pscustomobject]@{ Alias = 'Fixture Ethernet'; Program = $script:FixtureExe }
    if ($script:NewProgram) {
        [pscustomobject]@{ Alias = 'Fixture Ethernet'; Program = $script:NewProgram }
    }
    if ($script:FailSecondCreate) {
        [pscustomobject]@{ Alias = 'Any'; Program = $script:FixtureExe; RemoteAddress = '::/0' }
    }
}

function Assert-GuardCoverage($Specifications, [string[]]$RuleNames, [switch]$DuringRefresh) {
    if (@($Specifications).Count -ne $RuleNames.Count) { throw 'Fixture rule count changed.' }
    foreach ($name in $RuleNames) {
        if ($script:Rules[$name] -ne 'Outbound Block') { throw 'Fixture effective rule missing or altered.' }
    }
}

function Get-GuardRunningProcesses($Inventory) {
    if ($script:Started) { [pscustomobject]@{ Id = 42 } }
}

function Start-Process {
    [CmdletBinding()]
    param([string]$FilePath, [switch]$PassThru)
    if ($FilePath -ne $script:FixtureExe -or -not $PassThru) { throw 'Unexpected fixture process launch.' }
    $script:Started = $true
    $process = [pscustomobject]@{ Id = 42; HasExited = $false }
    Add-Member -InputObject $process -MemberType ScriptMethod -Name Dispose -Value {}
    $process
}

function Start-GuardWindowsApplication { throw 'Unexpected Store activation in the native executable fixture.' }
function Get-Process { throw 'Unexpected process enumeration in the test fixture.' }
function Get-AppxPackage { throw 'Unexpected Store discovery in the native executable fixture.' }

function Start-GuardSessionZone([string]$Zone) {}
function Restore-GuardSessionZone {}
function Start-GuardNativeCli([string]$Path, [string[]]$Arguments) {
    if ($Path -ne $script:FixtureExe) { throw 'Unexpected fixture CLI launch.' }
    $script:ObservedArgs = $Arguments
    $process = [pscustomobject]@{ Id = 42; HasExited = $true; ExitCode = 17 }
    Add-Member -InputObject $process -MemberType ScriptMethod -Name Dispose -Value {}
    $process
}

function Get-GuardStartedProcessIdentity($StartedProcess, [string]$ExpectedPath) { $null }
function Stop-GuardRunningProcesses($Inventory, $StartedProcess, $StartedIdentity) {
    if ($StartedProcess.Id -ne 42) { throw 'Wrong fixture process selected for shutdown.' }
    $script:StopRequested = $true
    $StartedProcess.HasExited = $true
}

function Start-Sleep {
    param([int]$Milliseconds)
    $script:SleepCount++
    if (-not $script:FailDuringSession -or $script:SleepCount -gt 1) {
        throw 'Fixture monitor did not stop on the missing rule.'
    }
    $script:Rules.Remove($script:OldRule)
}

function New-NetFirewallRule {
    [CmdletBinding()]
    param($Name, $DisplayName, $PolicyStore, $Direction, $Action, $Profile, $Enabled, $InterfaceAlias, $RemoteAddress, $Program, $Package)
    $script:CreateCount++
    if ($script:NewProgram -and $Program -eq $script:FixtureExe) { throw 'Fixture refused a duplicate rule for the existing program.' }
    if ($script:FailSecondCreate -and $script:CreateCount -eq 2) { throw 'Fixture failure creating the second rule.' }
    $script:Rules[$Name] = "$Direction $Action"
}

function Get-NetFirewallRule {
    [CmdletBinding()]
    param($PolicyStore, $Name)
    if ($script:Rules.ContainsKey($Name)) { [pscustomobject]@{ Name = $Name } }
}

function Get-GuardRules {
    foreach ($name in $script:Rules.Keys) { [pscustomobject]@{ Name = $name } }
}

function Remove-NetFirewallRule {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        $script:RemovedRules.Add($InputObject.Name)
        $script:Rules.Remove($InputObject.Name)
    }
}

function Save-GuardNativeState($State) {
    $script:WriteCount++
    $script:FixtureState = $State
}

function Assert-Check([bool]$Condition, [string]$Description) {
    if (-not $Condition) { throw "FAIL: $Description" }
    $script:Passed++
    Write-Output "PASS: $Description"
}

function Assert-Throws([scriptblock]$Action, [string]$Expected) {
    try { $null = & $Action }
    catch {
        if ($_.Exception.Message -like "*$Expected*") { return }
        throw
    }
    throw "Expected failure containing '$Expected'."
}

Reset-Fixture
$status = Get-GuardNativeStatus
Assert-Check ($status.Ready -and $status.CanConfigure) 'Verified local state enables guarded launch.'

Reset-Fixture
$script:FixtureState = $null
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.CanConfigure) 'Missing state requires setup before launch.'

Reset-Fixture
$script:Rules.Remove($script:OldRule)
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.Message -like '*effective rule missing*') 'Missing effective rules disable launch.'

Reset-Fixture
$script:Rules[$script:OldRule] = 'Outbound Allow'
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.Message -like '*missing or altered*') 'An altered effective rule disables launch.'

Reset-Fixture
$script:FixtureState.Adapters[0].Alias = 'Old adapter name'
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.Message -like '*interface changed*') 'A changed adapter invalidates saved coverage.'

Reset-Fixture
$script:FixtureState.Version = 0
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.Message -like '*incomplete or invalid*') 'An unsupported state version is rejected.'

Reset-Fixture
$script:FixtureState.Rules = @('Claude-VPN-Guard-Block-legacy')
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.Message -like '*incomplete or invalid*') 'Legacy upstream rule names are rejected.'

Reset-Fixture
$script:DailyPresent = $true
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.Message -like '*Daily Guard*') 'Existing Daily Guard policy prevents native readiness.'

Reset-Fixture
$script:Rules.Remove($script:OldRule)
Assert-Throws { Invoke-GuardNativeDesktop } 'effective rule missing'
Assert-Check (-not $script:Started -and -not $script:StopRequested) 'Launch refuses unverified coverage before creating a process.'

Reset-Fixture
$script:FailDuringSession = $true
Assert-Throws { Invoke-GuardNativeDesktop } 'effective rule missing'
Assert-Check ($script:Started -and $script:SleepCount -eq 1 -and $script:StopRequested) 'Losing a verified rule during a session requests shutdown.'

Reset-Fixture
$script:FailSecondCreate = $true
Assert-Throws { Set-GuardNativeProtection } 'failure creating the second rule'
Assert-Check (
    $script:CreateCount -eq 2 -and $script:RemovedRules.Count -eq 1 -and
    $script:RemovedRules[0] -ne $script:OldRule -and $script:Rules.Count -eq 1 -and
    $script:Rules.ContainsKey($script:OldRule) -and $script:WriteCount -eq 0
) 'Partial setup removes its staged rule and preserves the prior generation.'

Reset-Fixture
$script:DesktopPresent = $false
$status = Get-GuardNativeStatus -Cli
Assert-Check ($status.Ready -and $status.Claude -eq 'Claude Code verified') 'CLI-only installations can be checked independently.'
$cli = Invoke-GuardNativeDesktop -Cli -Arguments @('--print', '', 'two words', 'a"b')
Assert-Check (
    $cli.Ok -and $cli.ExitCode -eq 17 -and $script:ObservedArgs.Count -eq 4 -and
    $script:ObservedArgs[1] -ceq '' -and $script:ObservedArgs[2] -ceq 'two words' -and
    $script:ObservedArgs[3] -ceq 'a"b'
) 'Guarded CLI forwards arguments and preserves the child exit code.'

Reset-Fixture
$script:ProxyPresent = $true
$status = Get-GuardNativeStatus
Assert-Check (-not $status.Ready -and $status.Message -like '*proxy configured*') 'A configured proxy blocks launch readiness.'

$core = Join-Path $PSScriptRoot '.build\NetworkCore.ps1'
$coreErrors = $null
$coreAst = [System.Management.Automation.Language.Parser]::ParseFile($core, [ref]$tokens, [ref]$coreErrors)
if ($coreErrors.Count) { throw ($coreErrors | Out-String) }
$escaping = $coreAst.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'ConvertTo-GuardNativeArgument'
}, $false)
. ([scriptblock]::Create($escaping.Extent.Text))
$quoted = Get-GuardNativeCliCommandLine @('', 'two words', 'a"b', 'C:\a\')
Assert-Check ($quoted -ceq '"" "two words" "a\"b" "C:\a\\"') 'Native argument quoting preserves empty values, quotes and trailing separators.'

Reset-Fixture
$script:ProxyPresent = $true
$unchanged = Set-GuardNativeProtection -Refresh
Assert-Check (
    $unchanged.Ok -and $script:RefreshChecked -and $script:WriteCount -eq 0 -and
    $script:CreateCount -eq 0 -and $script:FixtureState.VpnGuid -eq $script:Pin
) 'Healthy background refresh keeps the pinned VPN and performs no policy write.'

Reset-Fixture
$script:ProxyPresent = $true
$script:Rules.Remove($script:OldRule)
$refreshed = Set-GuardNativeProtection -Refresh
Assert-Check (
    $refreshed.Ok -and $script:RefreshChecked -and $script:WriteCount -eq 1 -and
    $script:CreateCount -eq 1 -and $script:FixtureState.VpnGuid -eq $script:Pin -and
    $script:Rules.ContainsKey($script:FixtureState.Rules[0])
) 'Refresh repairs coverage without relying on a connected VPN or repinning.'

Reset-Fixture
$script:NewProgram = 'C:\NativeGuardFixture\Updated\Claude.exe'
$obsoleteRule = 'ClaudeGuardNative-Block-0451a40d99f34ef6892ad8aea82474bd-0'
$script:Rules[$obsoleteRule] = 'Outbound Block'
$retained = Set-GuardNativeProtection -Refresh
Assert-Check (
    $retained.Ok -and $script:WriteCount -eq 1 -and $script:CreateCount -eq 1 -and
    $script:FixtureState.Rules.Count -eq 2 -and $script:FixtureState.Rules -contains $script:OldRule -and
    $script:Rules.ContainsKey($script:OldRule) -and $script:RemovedRules.Count -eq 1 -and
    $script:RemovedRules[0] -eq $obsoleteRule
) 'Adding an updated program keeps its previously enforced rules and replaces only obsolete coverage.'

Reset-Fixture
$script:FixtureState.OwnerSid = 'S-1-5-18'
Assert-Throws { Set-GuardNativeProtection -Refresh } 'another Windows user'
Assert-Check ($script:CreateCount -eq 0 -and $script:WriteCount -eq 0) 'Refresh rejects a different policy owner before writing.'

& {
    $servicePath = 'C:\NativeGuardFixture\Store\cowork-svc.exe'
    $desktopProcess = [pscustomobject]@{ SessionId = 1; ProcessName = 'Claude'; Id = 43; Path = $script:FixtureExe }
    $serviceProcess = [pscustomobject]@{ SessionId = 0; ProcessName = 'cowork-svc'; Id = 44; Path = $servicePath }
    $service = [pscustomobject]@{ State = 'Running'; StartName = 'LocalSystem'; ProcessId = 44; PathName = ('"' + $servicePath + '"') }
    $inventory = [pscustomobject]@{
        Programs = @($script:FixtureExe, $servicePath)
        Packages = @([pscustomobject]@{ Family = 'AnthropicPBC.Claude_fnn82j28hfe8t'; Root = 'C:\NativeGuardFixture\Store' })
    }
    function Get-GuardRunningProcesses($Inventory) { @($serviceProcess, $desktopProcess) }
    function Get-CimInstance($ClassName, $Filter) {
        if ($ClassName -ne 'Win32_Service' -or $Filter -cne "Name='CoworkVMServiceStore'") { throw 'Unexpected service query.' }
        $service
    }
    function Test-GuardAnthropicSignature([string]$Path) { $Path -ieq $servicePath }
    $clients = @(Get-GuardNativeClientProcesses $inventory)
    Assert-Check ($clients.Count -eq 1 -and $clients[0].Id -eq 43 -and $servicePath -in $inventory.Programs) 'The signed Store service retains firewall coverage without counting as an open Claude session.'
    $service.ProcessId = 45
    Assert-Check (@(Get-GuardNativeClientProcesses $inventory).Count -eq 2) 'A process that does not match the registered service still blocks rule replacement.'
}

. (Join-Path $PSScriptRoot 'NativeSession.ps1')
$script:SessionJournal = Join-Path (Split-Path $core -Parent) ("zone-fixture-{0}.json" -f [guid]::NewGuid().ToString('N'))
$script:CurrentZone = 'UTC'
function Get-GuardSessionZoneJournal { $script:SessionJournal }
function Get-GuardSessionZone { $script:CurrentZone }
function Set-GuardSessionZone([string]$Id) { $script:CurrentZone = $Id }

try {
    Start-GuardSessionZone ''
    Assert-Check ($script:CurrentZone -eq 'UTC' -and -not [IO.File]::Exists($script:SessionJournal)) 'Default session start leaves Windows time zone alone.'
    Start-GuardSessionZone 'Tokyo Standard Time'
    Assert-Check (
        $script:CurrentZone -eq 'Tokyo Standard Time' -and [IO.File]::Exists($script:SessionJournal)
    ) 'Opt-in session time zone creates a recovery journal before applying.'
    Restore-GuardSessionZone
    Assert-Check ($script:CurrentZone -eq 'UTC' -and -not [IO.File]::Exists($script:SessionJournal)) 'Session time zone restores and clears the journal.'
    Start-GuardSessionZone 'Tokyo Standard Time'
    $script:CurrentZone = 'Pacific Standard Time'
    Restore-GuardSessionZone
    Assert-Check (
        $script:CurrentZone -eq 'Pacific Standard Time' -and -not [IO.File]::Exists($script:SessionJournal)
    ) 'Session recovery preserves a later user change.'
} finally {
    [IO.File]::Delete($script:SessionJournal)
}

& {
    $writer = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Save-GuardNativeState'
    }, $false)
    . ([scriptblock]::Create($writer.Extent.Text))
    function Assert-GuardNativeFolder {}
    function Initialize-GuardAdministratorDirectory([string]$Path) {}

    $folder = Join-Path ([IO.Path]::GetTempPath()) ('native-state-fixture-' + [guid]::NewGuid().ToString('N'))
    $priorFolder = $script:GuardFolder
    $priorFile = $script:GuardState
    try {
        $null = [IO.Directory]::CreateDirectory($folder)
        $script:GuardFolder = $folder
        $script:GuardState = Join-Path $folder 'firewall.json'
        Save-GuardNativeState ([pscustomobject]@{ Generation = 'first' })
        Save-GuardNativeState ([pscustomobject]@{ Generation = 'second' })
        $saved = [IO.File]::ReadAllText($script:GuardState) | ConvertFrom-Json
        Assert-Check ($saved.Generation -ceq 'second' -and [IO.Directory]::GetFiles($folder).Length -eq 1) 'Replacing saved rule state works in Windows PowerShell without a backup path.'
    } finally {
        [IO.File]::Delete((Join-Path $folder 'firewall.json'))
        if ([IO.Directory]::Exists($folder)) { [IO.Directory]::Delete($folder) }
        $script:GuardFolder = $priorFolder
        $script:GuardState = $priorFile
    }
}

Write-Output "$script:Passed offline Native Guard checks passed."
