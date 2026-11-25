# A timezone change is a choice for an individual guarded session.
function Get-GuardSessionZone {
    $tool = Join-Path ([Environment]::SystemDirectory) 'tzutil.exe'
    $value = (& $tool /g | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $value) { throw 'Windows could not read the current time zone.' }
    $value
}

function Assert-GuardSessionZone([string]$Id) {
    $baseId = $Id -replace '_dstoff$', ''
    if (-not @([TimeZoneInfo]::GetSystemTimeZones() | Where-Object Id -ceq $baseId).Count) {
        throw 'Select a Windows time zone from the installed list.'
    }
}

function Set-GuardSessionZone([string]$Id) {
    Assert-GuardSessionZone $Id
    $tool = Join-Path ([Environment]::SystemDirectory) 'tzutil.exe'
    & $tool /s $Id | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Get-GuardSessionZone) -cne $Id) {
        throw 'The time-zone change could not be verified.'
    }
}

function Get-GuardSessionZoneJournal {
    Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ClaudeGuardNative\session-zone.json'
}

function Restore-GuardSessionZone {
    $path = Get-GuardSessionZoneJournal
    if (-not [IO.File]::Exists($path)) { return }
    $file = Get-Item -LiteralPath $path -Force
    if ($file.Length -gt 4096 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The pending time-zone recovery file could not be read safely.'
    }
    $saved = [IO.File]::ReadAllText($path) | ConvertFrom-Json
    if ($saved.Version -ne 1 -or -not $saved.Previous -or -not $saved.Applied) {
        throw 'The pending time-zone recovery file is incomplete.'
    }
    Assert-GuardSessionZone ([string]$saved.Previous)
    Assert-GuardSessionZone ([string]$saved.Applied)
    if ((Get-GuardSessionZone) -ceq [string]$saved.Applied) {
        Set-GuardSessionZone ([string]$saved.Previous)
    }
    [IO.File]::Delete($path)
}

function Start-GuardSessionZone([string]$Id) {
    Restore-GuardSessionZone
    if (-not $Id) { return }
    Assert-GuardSessionZone $Id
    $previous = Get-GuardSessionZone
    if ($previous -ceq $Id) { return }
    $path = Get-GuardSessionZoneJournal
    $folder = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    if ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The session time-zone folder could not be used.'
    }
    $record = [pscustomobject]@{ Version = 1; Previous = $previous; Applied = $Id }
    $serialized = $record | ConvertTo-Json -Compress
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($serialized)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Set-GuardSessionZone $Id
}
