function Set-GuardDailySandboxieRoot([string]$DriverRoot,[string]$PreviousRoot,[string]$NewRoot,[int]$Port) {
    try{if(Test-GuardSandboxieProtection $DriverRoot $NewRoot $Port){return}}catch{}
    $ini=Join-Path $DriverRoot 'Sandboxie.ini'
    Assert-GuardSandboxieAdministratorPath $ini
    $dataRoot=Get-GuardDataPath 'sandbox-data\GuardDesktop'
    $prior=@(New-GuardSandboxiePolicy $PreviousRoot $Port $dataRoot)
    $next=@(New-GuardSandboxiePolicy $NewRoot $Port $dataRoot)
    $current=[IO.File]::ReadAllLines($ini) -join [char]10
    if($current -cne ($prior -join [char]10) -and $current -cne ($next -join [char]10)){
        throw 'The protected sandbox configuration differs from both approved versions.'
    }
    $native=Get-GuardSandboxieNative $DriverRoot
    if($current -ceq ($prior -join [char]10)){
        $null=Test-GuardSandboxieProtection $DriverRoot $PreviousRoot $Port
        $temp="$ini.$([guid]::NewGuid().ToString('N')).tmp"
        $backup="$temp.backup"
        try{
            [IO.File]::WriteAllLines($temp,$next,[Text.Encoding]::Unicode)
            Set-Acl -LiteralPath $temp -AclObject (Get-Acl -LiteralPath $ini)
            [IO.File]::Replace($temp,$ini,$backup)
        }finally{
            [IO.File]::Delete($temp)
            [IO.File]::Delete($backup)
        }
    }
    $native::Reload()
    $null=Test-GuardSandboxieProtection $DriverRoot $NewRoot $Port
}

function Update-GuardDailyPackage($Active,$App,$Route) {
    $mutex=[Threading.Mutex]::new($false,'Global\ClaudeVPNGuard_FirewallSetup')
    $held=$false
    $phase='VerifyingStoreUpdate'
    $next=$null
    $pendingPath=Get-GuardDataPath 'daily-package-pending.json'
    $resultPath=Get-GuardDataPath 'daily-package-result.json'
    $backupPath=Get-GuardDataPath 'daily-package-backup.json'
    try{
        try{$held=$mutex.WaitOne(15000)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'Another Guard rule change is still running.'}
        if((Read-GuardDailyRecord 'daily-provisioned.json').Generation -cne $Active.Generation){
            throw 'The active deployment changed before package maintenance.'
        }
        $previous=$Active
        if(Test-Path -LiteralPath $pendingPath){
            $next=Read-GuardDailyRecord 'daily-package-pending.json'
            $previous=Read-GuardDailyRecord 'daily-package-backup.json'
            if($next.UpgradeSource -cne $previous.Generation -or
                $Active.Generation -cnotin $previous.Generation,$next.Generation -or
                $next.PackageFullName -cne $App.PackageFullName){
                throw 'The interrupted package maintenance does not match the registered update.'
            }
        }
        if(-not (Test-GuardDailyStoreUpgrade $previous $App) -or $previous.RouteHash -cne $Route.Hash -or
            (Get-GuardIsolationMode) -cne 'Off' -or (Get-GuardVpnAdapter $previous.VpnGuid).Name -cne 'Bettbox'){
            throw 'The signed Store update and unchanged Bettbox route could not be confirmed.'
        }
        $current=Get-GuardInventory -LocalOnly
        if($App.DesktopPath -notin @($current.DesktopPaths) -or $App.PackageSid -notin @($current.Packages | ForEach-Object Sid)){
            throw 'The registered update is not in the protected inventory.'
        }
        $oldInventory=Get-GuardDailyRecordedInventory $previous $current $App
        $oldPlan=New-GuardInstalledPolicy $Route $previous.Port ([guid]$previous.DeploymentId) $oldInventory $previous.ScopeSid 'Sandboxie'
        if(-not (Test-GuardDailyPolicyBinding $previous $oldPlan)){
            throw 'The original firewall policy cannot be matched to its saved rule keys.'
        }
        [ClaudeGuard.Network.WindowsPolicySession]::VerifyNoPersistentAdmission($oldPlan,[uint16]$previous.AssignedSublayerWeight)

        $boundInventory=[pscustomobject]@{
            Programs=@($current.Programs);DesktopPaths=@($current.DesktopPaths)
            Packages=@($current.Packages | ForEach-Object {[pscustomobject]@{Sid=$_.Sid}})
            ServiceSids=@(Get-GuardDailyServiceSids)
        }
        $images=@(Read-GuardDailyDesktopImages $current)
        $deployment=if($next){[guid]$next.DeploymentId}else{[guid]::NewGuid()}
        $plan=New-GuardInstalledPolicy $Route $previous.Port $deployment $boundInventory $previous.ScopeSid 'Sandboxie'
        if($next){
            if(-not (Test-GuardDailyPolicyBinding $next $plan) -or -not (Test-GuardDailyDesktopImages $next.DesktopImages $images) -or
                $next.RouteHash -cne $previous.RouteHash -or $next.PackageRoot -ine $App.Root -or $next.DesktopPath -ine $App.DesktopPath){
                throw 'The pending policy disagrees with the confirmed package or route.'
            }
        }else{
            $next=$previous | ConvertTo-Json -Depth 8 | ConvertFrom-Json
            $next.DeploymentId=$deployment
            $next.Sublayer=$plan.PersistentSublayer
            $next.AssignedSublayerWeight=$null
            $next.PackageFullName=$App.PackageFullName
            $next.PackageRoot=$App.Root
            $next.DesktopPath=$App.DesktopPath
            $next.DesktopImages=$images
            $next.DesktopHashes=@($images | ForEach-Object Hash)
            $next.BaselineKeys=$plan.GetBaselineKeys()
            $next.BootKeys=$plan.GetBootKeys()
            $next | Add-Member -NotePropertyName PolicyInventory -NotePropertyValue $boundInventory -Force
            $next | Add-Member -NotePropertyName UpgradeSource -NotePropertyValue $previous.Generation -Force
            $sha=[Security.Cryptography.SHA256]::Create()
            try{
                $binding=@($previous.Generation,$deployment,$plan.PersistentSublayer,$App.PackageFullName)+$next.DesktopHashes
                $next.Generation=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($binding -join '|')))).Replace('-','')
            }finally{$sha.Dispose()}
            Save-GuardAdministratorJson $backupPath $previous
            Save-GuardAdministratorJson $pendingPath $next
        }

        $phase='InstallingClosedRules'
        $native=[ClaudeGuard.Network.WindowsPolicySession]
        $bootCount=if($null -ne $next.AssignedSublayerWeight){
            $native::ReadBootFilterCount($plan,[uint16]$next.AssignedSublayerWeight,$true)
        }else{0}
        if($bootCount -eq 0){
            $beforeCommit=[Action[uint16]]{
                param([uint16]$Weight)
                $next.AssignedSublayerWeight=$Weight
                Save-GuardAdministratorJson $pendingPath $next
            }
            $next.AssignedSublayerWeight=$native::InstallPersistent($plan,$beforeCommit)
            $bootCount=$native::ReadBootFilterCount($plan,[uint16]$next.AssignedSublayerWeight)
        }
        if($bootCount -ne $plan.BootCount -or $bootCount -le 0){throw 'The replacement boot rules could not be verified.'}

        $phase='ClosingPreviousSession'
        $driverRoot=Get-GuardDataPath 'daily\sandboxie'
        $closeAction=@{Issued=$false}
        $shutdown=Stop-GuardDailySession @{
            CloseGate={
                $native::VerifyNoPersistentAdmission($oldPlan,[uint16]$previous.AssignedSublayerWeight)
                $native::ReadBootFilterCount($plan,[uint16]$next.AssignedSublayerWeight) -eq $plan.BootCount
            }
            Snapshot={Get-GuardDailySandboxedEntries $current $driverRoot (Get-GuardDailyStoreService $current $App.Root)}
            RequestClose={param($entry)
                if(-not $entry.Process.HasExited -and $entry.Process.StartTime.ToUniversalTime().Ticks -eq $entry.Start -and
                    $entry.Process.CloseMainWindow()){$closeAction.Issued=$true}
            }
            Wait={param($ms) Start-Sleep -Milliseconds $ms}
            ForceStop={param($entry)
                if(-not $entry.Process.HasExited -and $entry.Process.StartTime.ToUniversalTime().Ticks -eq $entry.Start){
                    $entry.Process.Kill()
                    $closeAction.Issued=$true
                    $null=$entry.Process.WaitForExit(2000)
                }
            }
        }
        if(-not $shutdown.NetworkBlocked -or -not $shutdown.Exited){
            throw 'The closed rules or shutdown of the previous protected session could not be verified.'
        }

        try{
            Publish-GuardDailyStoreStopNotice $shutdown $closeAction.Issued {
                param($name,$value) Save-GuardAdministratorJson (Get-GuardDataPath $name) $value
            } -PreviousGeneration $previous.Generation
        }catch{}

        $phase='VerifyingUpdatedSandbox'
        Set-GuardDailySandboxieRoot $driverRoot $previous.PackageRoot $App.Root $previous.Port
        $null=Confirm-GuardDailySandboxieApp $next
        if((Read-GuardDailyRelayConfig $next.Port).Hash -cne $next.RouteHash){throw 'The selected proxy changed during maintenance.'}
        if(-not (Test-GuardDailyDesktopImages $next.DesktopImages @(Read-GuardDailyDesktopImages (Get-GuardInventory -LocalOnly)))){
            throw 'The Store image changed again during package maintenance.'
        }

        $phase='RetiringStorePreprotection'
        Complete-GuardDailyStoreStage $previous $next
        $phase='RetiringOldRules'
        $native::RemovePersistent($oldPlan,[uint16]$previous.AssignedSublayerWeight)
        Save-GuardAdministratorJson (Get-GuardDataPath 'daily-provisioned.json') $next
        Save-GuardAdministratorJson $resultPath ([pscustomobject]@{
            Status='Updated';Package=$next.PackageFullName;BootRuleCount=$bootCount;Utc=[datetime]::UtcNow.ToString('o')
        })
        [IO.File]::Delete($pendingPath)
        $next
    }catch{
        $errorText=$_.Exception.Message -replace '(?i)https?://[^\s"]+','[link]' -replace '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b','[address]'
        if($held){Save-GuardAdministratorJson $resultPath ([pscustomobject]@{
            Status='Blocked';Phase=$phase;Error=$errorText;Utc=[datetime]::UtcNow.ToString('o')
        })}
        throw
    }finally{
        if($held){$mutex.ReleaseMutex()}
        $mutex.Dispose()
    }
}
