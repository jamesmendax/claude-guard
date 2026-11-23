# Only a completed native update may retire its immediate predecessor.
. (Join-Path $PSScriptRoot 'install-guard-helpers.ps1')

function Get-GuardRetirementPayload([string]$Folder,[string]$Manifest) {
    $files=[Collections.Generic.List[string]]::new()
    $directories=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $root=[IO.Path]::GetFullPath($Folder).TrimEnd('\')
    $rows=@($Manifest.TrimEnd([char]10).Split([char]10))
    if($rows.Count -lt 1 -or $rows.Count -gt 256){throw 'Invalid package manifest length.'}
    foreach($row in $rows){
        $parts=$row.TrimEnd([char]13).Split([char]9)
        if($parts.Count -ne 3 -or $parts[0] -cnotmatch '^[A-F0-9]{64}$' -or $parts[1] -cnotmatch '^[0-9]{1,10}$' -or
            $parts[2] -cnotmatch '\A(?:package|release|runtime|licenses|vendor/sandboxie)/(?:[A-Za-z0-9][A-Za-z0-9_.-]*/)*[A-Za-z0-9][A-Za-z0-9_.-]*\z'){
            throw 'Invalid package manifest entry.'
        }
        $path=[IO.Path]::GetFullPath((Join-Path $root $parts[2].Replace('/','\')))
        if(-not $path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or -not $seen.Add($path)){
            throw 'Unexpected package manifest path.'
        }
        $parent=[IO.Path]::GetDirectoryName($path)
        while($parent -ine $root){
            if(-not $directories.Add($parent)){break}
            if([IO.Directory]::Exists($parent)){Assert-GuardReleaseOwnedPath $parent -Directory}
            $parent=[IO.Path]::GetDirectoryName($parent)
        }
        if([IO.File]::Exists($path)){
            Assert-GuardReleaseOwnedPath $path
            if((Get-Item -LiteralPath $path).Length -ne [long]$parts[1] -or (Get-FileHash -LiteralPath $path).Hash -cne $parts[0]){
                throw 'A file in the old package has changed.'
            }
            $files.Add($path)
        }
    }
    # Inspect every known directory before the first deletion. Extra files are never removed.
    foreach($dir in $directories){
        if(-not [IO.Directory]::Exists($dir)){continue}
        foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($dir)){
            if(-not $seen.Contains($entry) -and -not $directories.Contains($entry)){throw 'The old package contains an additional file.'}
            if(([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint)){throw 'The old package contains a redirected path.'}
        }
    }
    [pscustomobject]@{Files=$files;Directories=@($directories | Sort-Object Length -Descending)}
}

function Remove-GuardSupersededSetup([string]$Stage,$Result) {
    $report=[ordered]@{Status='Retained';Reason='UpdateNotVerified';RemovedFiles=0;PreviousStage=$null}
    $mutex=$null
    $held=$false
    $reportPath=$null
    try{
        if($Result.Installed -ne $true -or $Result.Phase -cne 'Completed' -or $Result.Operation -cnotmatch '\A[a-f0-9]{32}\z'){return $report}
        $root=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath((Get-GuardDataPath 'daily')))
        $stagePath=[IO.Path]::GetFullPath($Stage).TrimEnd('\')
        if([IO.Path]::GetDirectoryName($stagePath) -ine $root -or [IO.Path]::GetFileName($stagePath) -cnotmatch '\Arelease-install-[a-f0-9]{32}\z'){return $report}
        $currentExe=Join-Path $stagePath 'ClaudeGuardSetup.exe'
        if([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -ine $currentExe){return $report}
        $mutex=[Threading.Mutex]::new($false,'Global\ClaudeVPNGuard_ReleaseInstall')
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){$report.Reason='MaintenanceBusy';return $report}
        $ops=Join-Path $stagePath 'operations'
        $op=Join-Path $ops $Result.Operation
        $backup=Join-Path $op 'previous'
        foreach($dir in $root,$stagePath,$ops,$op,$backup){Assert-GuardReleaseOwnedPath $dir -Directory}
        $receiptPath=Join-Path $op 'result.json'
        Assert-GuardReleaseOwnedPath $receiptPath
        $receipt=Read-GuardDailyJsonFile $receiptPath
        $current=Read-GuardDailyRecord 'daily-provisioned.json'
        if($receipt.Operation -cne $Result.Operation -or $receipt.Phase -cne 'Completed' -or $receipt.Installed -ne $true -or
            $receipt.Generation -cne $current.Generation -or $receipt.FreshProofs -lt 6 -or $receipt.Verification.Status -cne 'Verified' -or
            $receipt.Verification.WorkerStatus -cne 'Ready' -or [IO.File]::Exists((Join-Path $root 'release-install-pending.json')) -or
            [IO.File]::Exists((Join-Path $root 'daily-package-pending.json'))){return $report}
        if($receipt.Mode -cne 'Update'){$report.Status='NoChange';$report.Reason='SameSetup';return $report}
        $reportPath=Join-Path $op 'retirement.json'
        $report.Reason='CurrentEntryUnconfirmed'
        $tasks=@{'ClaudeVPNGuard Daily Controller'='--background-controller';'ClaudeVPNGuard Daily Notifications'='--background-notifier'}
        foreach($name in $tasks.Keys){
            $task=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
            if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ine $currentExe -or $task.Actions[0].Arguments -cne $tasks[$name]){return $report}
        }
        $taskBackup=Join-Path $backup 'tasks.json'
        Assert-GuardReleaseOwnedPath $taskBackup
        $prior=(Read-GuardDailyJsonFile $taskBackup).ControllerAction
        if($prior.Arguments -cne '--background-controller'){$report.Status='NoChange';$report.Reason='NoPredecessorPackage';return $report}
        $oldExe=[IO.Path]::GetFullPath([string]$prior.Execute)
        if($oldExe -ieq $currentExe){$report.Status='NoChange';$report.Reason='SameSetup';return $report}
        $oldDir=[IO.Path]::GetDirectoryName($oldExe)
        $leaf=[IO.Path]::GetFileName($oldDir)
        if([IO.Path]::GetDirectoryName($oldDir) -ine $root -or [IO.Path]::GetFileName($oldExe) -cne 'ClaudeGuardSetup.exe' -or
            $leaf -cnotmatch '\Arelease-install-[a-f0-9]{32}\z'){return $report}
        $report.PreviousStage=$leaf
        $report.Reason='PreviousIdentityUnconfirmed'
        Assert-GuardReleaseOwnedPath $oldDir -Directory
        Assert-GuardReleaseOwnedPath $oldExe
        $oldReceipt=Join-Path $oldDir 'install-result.json'
        Assert-GuardReleaseOwnedPath $oldReceipt
        $oldResult=Read-GuardDailyJsonFile $oldReceipt
        if($oldResult.Installed -ne $true -or $oldResult.Phase -cne 'Completed' -or $oldResult.Generation -cne $receipt.PriorGeneration){return $report}
        if(@($current.Assets | Where-Object {([string]$_.Source).StartsWith($oldDir+'\',[StringComparison]::OrdinalIgnoreCase)}).Count){return $report}
        $oldBytes=[IO.File]::ReadAllBytes($oldExe)
        $oldDigest=Get-FileHash -LiteralPath $oldExe
        if($leaf -cne ('release-install-'+$oldDigest.Hash.Substring(0,32).ToLowerInvariant())){return $report}
        $assembly=[Reflection.Assembly]::ReflectionOnlyLoad($oldBytes)
        if($assembly.GetName().Version -ge [Reflection.AssemblyName]::GetAssemblyName($currentExe).Version){return $report}
        $resource=$assembly.GetManifestResourceStream('Guard.Manifest')
        if(-not $resource -or $resource.Length -gt 131072){return $report}
        $reader=[IO.StreamReader]::new($resource)
        try{$manifest=$reader.ReadToEnd()}finally{$reader.Dispose()}
        $plan=Get-GuardRetirementPayload $oldDir $manifest
        $report.Reason='ShortcutStillUsesPreviousSetup'
        foreach($folder in 'Programs','CommonPrograms','DesktopDirectory','CommonDesktopDirectory'){
            foreach($linkName in 'Claude Guard Settings.lnk','Claude Desktop - Guarded.lnk'){
                $link=Join-Path ([Environment]::GetFolderPath($folder)) $linkName
                if([IO.File]::Exists($link)){
                    $shell=New-Object -ComObject WScript.Shell
                    try{
                        $entry=$shell.CreateShortcut($link)
                        if($entry.TargetPath -ieq $oldExe){return $report}
                    }finally{if($entry){$null=[Runtime.InteropServices.Marshal]::ReleaseComObject($entry)};$null=[Runtime.InteropServices.Marshal]::ReleaseComObject($shell)}
                }
            }
        }
        $report.Reason='PreviousWindowBusy'
        $previousProcesses=@([Diagnostics.Process]::GetProcessesByName('ClaudeGuardSetup') | Where-Object {
            try{$_.MainModule.FileName -ieq $oldExe}catch{$false}
        })
        foreach($process in $previousProcesses){
            if(-not $process.HasExited -and $process.MainWindowHandle -ne [IntPtr]::Zero -and $process.MainWindowTitle -ceq 'Claude Guard'){
                $null=$process.CloseMainWindow()
            }
        }
        foreach($process in $previousProcesses){
            try{if(-not $process.WaitForExit(6000)){return $report}}finally{$process.Dispose()}
        }
        $report.Reason='PreviousFilesInUse'
        foreach($file in $plan.Files){
            [IO.File]::Delete($file)
            $report.RemovedFiles++
        }
        foreach($dir in $plan.Directories){
            if([IO.Directory]::Exists($dir)){[IO.Directory]::Delete($dir,$false)}
        }
        [IO.File]::Delete($oldExe)
        $report.RemovedFiles++
        $report.Status='Removed'
        $report.Reason='Verified'
    }catch{
        # Keep the independent installation receipt authoritative even if a prior file is locked.
    }finally{
        if($reportPath){try{Save-GuardAdministratorJson $reportPath ([pscustomobject]$report)}catch{}}
        if($held){$mutex.ReleaseMutex()}
        if($mutex){$mutex.Dispose()}
    }
    $report
}
