#Requires -Version 5.1
#Requires -PSEdition Desktop
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('ValidatePackage', 'Install', 'Remove', 'DisableRefresh')]
    [string]$Action,
    [switch]$EnableRefresh,
    [switch]$RemoveRules,
    [string]$PackageDirectory = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$version = '2.0.0'
$taskName = 'Claude Guard Native Refresh'
$taskPath = '\'
$files = [ordered]@{
    "ClaudeGuardNative-$version-x64.exe" = 'ClaudeGuardNative.exe'
    "ClaudeGuardNativeConsole-$version-x64.exe" = 'ClaudeGuardNativeConsole.exe'
}
$administrators = 'S-1-5-32-544'
$system = 'S-1-5-18'
$trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

function Get-PackageHashes([string]$Directory, $Payload) {
    $manifest = Join-Path $Directory 'SHA256SUMS.txt'
    $hashes = @{}
    foreach ($line in [IO.File]::ReadAllLines($manifest)) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?([a-zA-Z0-9._-]+)\s*$') {
            $digest = $Matches[1]
            $fileName = $Matches[2]
            if (-not $Payload.Contains($fileName)) { continue }
            if ($hashes.ContainsKey($fileName)) { throw "Duplicate checksum for $fileName." }
            $hashes[$fileName] = $digest
        }
    }
    foreach ($fileName in $Payload.Keys) {
        if (-not $hashes.ContainsKey($fileName)) { throw "Missing checksum for $fileName." }
        Assert-FileHash (Join-Path $Directory $fileName) $hashes[$fileName]
    }
    $hashes
}

function Assert-FileHash([string]$Path, [string]$Expected) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($Path)
        try { $actual = [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '') }
        finally { $stream.Dispose() }
    } finally { $algorithm.Dispose() }
    if ($actual -ine $Expected) {
        throw "SHA-256 mismatch for $Path."
    }
}

function Get-InstallerIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this action in an elevated Windows PowerShell as the Windows user who will use Native Guard.'
    }
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $shells = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe' AND SessionId=$session")
    $owners = @($shells | ForEach-Object {
        $result = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid
        if ($result.ReturnValue -eq 0) { $result.Sid }
    } | Sort-Object -Unique)
    if ($session -eq 0 -or $owners.Count -ne 1 -or $owners[0] -ne $identity.User.Value) {
        throw 'Use the signed-in Windows desktop account to approve elevation. A different administrator or a background session cannot manage this installation.'
    }
    $identity
}

function Assert-ProtectedItem([string]$Path, [bool]$Directory, [switch]$WindowsProgramFiles) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unexpected installation path type at $Path."
    }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $trustedOwners = @($administrators, $system)
    if ($WindowsProgramFiles) { $trustedOwners += $trustedInstaller }
    if ($owner -notin $trustedOwners) { throw "The owner of $Path is not trusted." }
    $allowedRead = [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    foreach ($access in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($access.AccessControlType -ne 'Allow') { continue }
        if ($access.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($access.IdentityReference.Value -in $trustedOwners) { continue }
        if (($access.FileSystemRights -band (-bnot $allowedRead)) -ne 0) {
            throw "Someone other than an administrator or SYSTEM can modify $Path."
        }
    }
}

function New-ProtectedDirectory([string]$Path) {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
    $null = [IO.Directory]::CreateDirectory($Path, $security)
    Assert-ProtectedItem $Path $true
}

function Get-OwnedRefreshTask([string]$InstallRoot, [string]$UserSid) {
    $task = Get-ScheduledTask -TaskPath $taskPath | Where-Object TaskName -eq $taskName
    if (-not $task) { return }
    $actions = @($task.Actions)
    $identity = [string]$task.Principal.UserId
    if ($identity -notmatch '^S-1-') {
        $identity = ([Security.Principal.NTAccount]::new($identity)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    $consolePattern = '^' + [regex]::Escape($InstallRoot + '\') + '\d+\.\d+\.\d+\\ClaudeGuardNativeConsole\.exe$'
    if ($identity -ne $UserSid -or $actions.Count -ne 1 -or
        $actions[0].Execute -notmatch $consolePattern -or $actions[0].Arguments -cne '--refresh') {
        throw 'An existing refresh task belongs to another user or points outside this product. It was left alone.'
    }
    $task
}

function Register-NativeRefresh([string]$ConsolePath, [string]$InstallRoot, [string]$UserSid) {
    $directory = Split-Path -Parent $ConsolePath
    Assert-ProtectedItem $directory $true
    Assert-ProtectedItem $ConsolePath $false
    $taskAction = New-ScheduledTaskAction -Execute $ConsolePath -Argument '--refresh' -WorkingDirectory $directory
    $triggers = @(
        New-ScheduledTaskTrigger -AtLogOn -User $UserSid
        New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5)
    )
    # S4U uses the same local account without a password or an interactive console.
    $principal = New-ScheduledTaskPrincipal -UserId $UserSid -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $null = Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $taskAction -Trigger $triggers -Principal $principal -Settings $settings -Force
    $registered = Get-OwnedRefreshTask $InstallRoot $UserSid
    if (-not $registered -or $registered.Actions.Execute -ine $ConsolePath -or
        $registered.Principal.LogonType -ne 'S4U' -or $registered.Principal.RunLevel -ne 'Highest') {
        throw 'The scheduled action could not be verified.'
    }
}

function Remove-NativeRefresh {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Out-Null
    if ($task.State -eq 'Running' -or (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath).State -eq 'Running') {
        throw 'Refresh is disabled and its current run may still be finishing. Retry this action after it finishes.'
    }
    Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
}

if ($EnableRefresh -and $Action -ne 'Install') { throw '-EnableRefresh requires -Action Install.' }
if ($RemoveRules -and $Action -ne 'Remove') { throw '-RemoveRules requires -Action Remove.' }
if ($Action -in @('ValidatePackage', 'Install')) {
    $hashes = Get-PackageHashes $PackageDirectory $files
}
if ($Action -eq 'ValidatePackage') {
    Write-Output "Native Guard $version payload checksums verified."
    return
}

if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
$identity = Get-InstallerIdentity
$userSid = $identity.User.Value
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
Assert-ProtectedItem $programFiles $true -WindowsProgramFiles
$installRoot = Join-Path $programFiles 'Claude Guard Native'
$installDirectory = Join-Path $installRoot $version
$consolePath = Join-Path $installDirectory 'ClaudeGuardNativeConsole.exe'

$mutex = [Threading.Mutex]::new($false, 'Global\ClaudeGuardNativeInstallation')
$ownsMutex = $false
try {
    try { $ownsMutex = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
    if (-not $ownsMutex) { throw 'Another Native Guard installation action is running.' }

    if (Test-Path -LiteralPath $installRoot) { Assert-ProtectedItem $installRoot $true }
    elseif ($Action -eq 'Install') { New-ProtectedDirectory $installRoot }

    $task = $null
    if ($EnableRefresh -or $Action -in @('Remove', 'DisableRefresh')) {
        $task = Get-OwnedRefreshTask $installRoot $userSid
    }
    if ($Action -eq 'DisableRefresh') {
        if ($task) { Remove-NativeRefresh }
        Write-Output 'The Native Guard refresh task is disabled.'
        return
    }

    if ($Action -eq 'Install') {
        if ($EnableRefresh -and $task -and $task.State -eq 'Running') {
            throw 'The previous refresh is running. Let it finish before enabling refresh for this version.'
        }
        if (Test-Path -LiteralPath $installDirectory) {
            Assert-ProtectedItem $installDirectory $true
            foreach ($fileName in $files.Keys) {
                $installed = Join-Path $installDirectory $files[$fileName]
                Assert-ProtectedItem $installed $false
                Assert-FileHash $installed $hashes[$fileName]
            }
        } else {
            $stage = Join-Path $installRoot ('.stage-' + [guid]::NewGuid().ToString('N'))
            try {
                New-ProtectedDirectory $stage
                $fileSecurity = [Security.AccessControl.FileSecurity]::new()
                $fileSecurity.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)')
                foreach ($fileName in $files.Keys) {
                    $destination = Join-Path $stage $files[$fileName]
                    $inputFile = [IO.File]::OpenRead((Join-Path $PackageDirectory $fileName))
                    try {
                        $outputFile = [IO.FileStream]::new(
                            $destination, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write,
                            [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $fileSecurity
                        )
                        try { $inputFile.CopyTo($outputFile) } finally { $outputFile.Dispose() }
                    } finally { $inputFile.Dispose() }
                    Assert-ProtectedItem $destination $false
                    Assert-FileHash $destination $hashes[$fileName]
                }
                [IO.Directory]::Move($stage, $installDirectory)
            } finally {
                if ([IO.Directory]::Exists($stage)) {
                    Assert-ProtectedItem $stage $true
                    foreach ($fileName in $files.Values) { [IO.File]::Delete((Join-Path $stage $fileName)) }
                    [IO.Directory]::Delete($stage)
                }
            }
        }
        if ($EnableRefresh) {
            try { Register-NativeRefresh $consolePath $installRoot $userSid }
            catch { throw "Native Guard files are installed at $installDirectory. Refresh registration could not be confirmed. $($_.Exception.Message)" }
        }
        Write-Output "Native Guard $version is installed at $installDirectory."
        return
    }

    if (-not (Test-Path -LiteralPath $installDirectory)) {
        if ($RemoveRules) { throw 'The trusted console executable is required to remove the Native Guard rules.' }
        Write-Output "Native Guard $version is already absent."
        return
    }
    Assert-ProtectedItem $installDirectory $true
    $contents = @(Get-ChildItem -LiteralPath $installDirectory -Force)
    if (@($contents | Where-Object { $_.Name -cnotin $files.Values }).Count) {
        throw "Unexpected files in $installDirectory. No files were removed."
    }
    foreach ($item in $contents) { Assert-ProtectedItem $item.FullName $false }
    if ($task -and $task.Actions.Execute -ieq $consolePath) {
        Remove-NativeRefresh
    } elseif ($task -and $RemoveRules) {
        throw 'Another version owns the refresh task. Disable it explicitly before removing the shared Native Guard rules.'
    }
    if ($RemoveRules) {
        Assert-ProtectedItem $consolePath $false
        & $consolePath '--remove-rules'
        if ($LASTEXITCODE -ne 0) { throw 'Native Guard rule removal failed. Installed files were retained for retry.' }
    }
    foreach ($item in $contents) { [IO.File]::Delete($item.FullName) }
    [IO.Directory]::Delete($installDirectory)
    Write-Output "Native Guard $version files were removed."
} finally {
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
