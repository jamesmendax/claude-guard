# A deployment event is a hint to deny exact future paths. Only registered
# package maintenance can grant an admission, after verifying the new policy.
$script:GuardStoreEventChannel='Microsoft-Windows-AppXDeploymentServer/Operational'
$script:GuardStoreEventProvider='Microsoft-Windows-AppXDeployment-Server'
$script:GuardStoreStageName='daily-store-stage.json'
$script:GuardStoreInventoryName='daily-store-inventory.json'

function ConvertFrom-GuardStoreEvent([xml]$Event,[string]$UserSid,
    [scriptblock]$IsPackage={param($name) Get-GuardDailyStoreVersion $name}) {
    $system=$Event.Event.System
    if($system.Provider.Name -cne $script:GuardStoreEventProvider -or
        $system.Channel -cne $script:GuardStoreEventChannel){return}
    $fields=@{}
    foreach($entry in $Event.Event.EventData.Data){
        $name=$entry.GetAttribute('Name')
        if($fields.ContainsKey($name)){return}
        $fields[$name]=$entry.InnerText
    }
    $id=[int]$system.EventID
    if($id -eq 617){
        if($fields.userSid -ceq $UserSid -and (& $IsPackage $fields.PackageFullName)){
            [pscustomobject]@{Package=$fields.PackageFullName;Prepare=$false}
        }
        return
    }
    if($id -ne 574 -and $id -ne 855){return}
    if($id -eq 574){
        if(& $IsPackage $fields.PackageMoniker){
            [pscustomobject]@{Package=$fields.PackageMoniker;Prepare=$true}
        }
        return
    }
    $pattern='(?<![\w.])[A-Za-z0-9.-]+_(?:[0-9]{1,5}\.){3}[0-9]{1,5}_x64__[a-z0-9]{13}(?![\w.])'
    foreach($match in [regex]::Matches([string]$fields.PackageMoniker,$pattern)){
        if(& $IsPackage $match.Value){[pscustomobject]@{Package=$match.Value;Prepare=$true}}
    }
}

function Read-GuardStoreDeploymentEvents([long]$Cursor) {
    $channel=$script:GuardStoreEventChannel
    $latest=Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop
    try{if($latest.RecordId -lt $Cursor){$Cursor=0}}
    finally{$latest.Dispose()}
    # Read forward in bounded batches. The time bound also applies after a log
    # reset so obsolete signals cannot cause an unlimited startup replay.
    $criteria="*[System[Provider[@Name='$script:GuardStoreEventProvider'] and " +
        "(EventID=574 or EventID=855 or EventID=617) and EventRecordID &gt; $Cursor and " +
        'TimeCreated[timediff(@SystemTime) &lt;= 172800000]]]'
    $query="<QueryList><Query Id='0' Path='$channel'><Select Path='$channel'>$criteria</Select></Query></QueryList>"
    try{Get-WinEvent -FilterXml $query -Oldest -MaxEvents 64 -ErrorAction Stop}
    catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
}

function Get-GuardStoreStagePaths([string]$WindowsAppsRoot,[string]$Package,[string[]]$RelativePaths,[switch]$VerifiedParent) {
    if(-not (Get-GuardDailyStoreVersion $Package) -or
        @($RelativePaths).Count -lt 1 -or @($RelativePaths).Count -gt 64){
        throw 'The future Store package or its path list is invalid.'
    }
    $root=Get-GuardSandboxiePackageRoot (Join-Path $WindowsAppsRoot $Package)
    if(-not $VerifiedParent){Assert-GuardInstallationPath $WindowsAppsRoot}
    foreach($path in $RelativePaths){
        if($path -notmatch '\A(?:[A-Za-z0-9_. ()-]+\\)*[A-Za-z0-9_. ()-]+\.exe\z' -or
            @($path.Split('\') | Where-Object {$_ -in '.','..' -or $_ -ne $_.Trim(' ','.')}).Count){
            throw 'A future Store program is not a safe relative path.'
        }
        $image=Join-Path $root $path
        if($VerifiedParent){$image; continue}
        # Check every existing parent after staging as well as the package
        # volume. A missing folder is acceptable; an existing junction is not.
        $existing=$image
        while(-not (Test-Path -LiteralPath $existing -ErrorAction Stop)){
            $existing=Split-Path -Parent $existing
            if([string]::IsNullOrEmpty($existing)){throw 'The Store package volume is missing.'}
        }
        Assert-GuardInstallationPath $existing
        $image
    }
}

function Get-GuardStoreRelativePaths($Record,$Inventory) {
    $prefix=(Get-GuardSandboxiePackageRoot $Record.PackageRoot)+'\'
    if(-not $Record.DesktopPath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
        $Record.DesktopPath -notin @($Inventory.Programs)){throw 'The older Store image is outside the approved program list.'}
    @($Inventory.Programs | Where-Object {$_.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)} |
        ForEach-Object {$_.Substring($prefix.Length)} | Sort-Object -Unique)
}

function Get-GuardStoreSavedInventory($Record,[switch]$IncludeReceipt) {
    if(-not (Test-Path -LiteralPath (Get-GuardDataPath $script:GuardStoreInventoryName) -ErrorAction Stop)){return}
    $saved=Read-GuardDailyRecord $script:GuardStoreInventoryName
    if($saved.Version -eq 1 -and $saved.Generation -ceq $Record.Generation -and $saved.Package -ceq $Record.PackageFullName){
        if($IncludeReceipt){$saved}else{$saved.Inventory}
    }
}

function Read-GuardStoreStage {
    if(-not (Test-Path -LiteralPath (Get-GuardDataPath $script:GuardStoreStageName) -ErrorAction Stop)){
        return [pscustomobject]@{Version=1;Cursor=0;Candidates=@();Status='Waiting'}
    }
    $stage=Read-GuardDailyRecord $script:GuardStoreStageName
    if($stage.Version -ne 1 -or [long]$stage.Cursor -lt 0 -or @($stage.Candidates).Count -gt 3){
        throw 'The Store preprotection record is invalid.'
    }
    $stage
}

function Get-GuardStoreCandidateWindowsAppsRoot($Record,$Candidate) {
    if($Candidate.PSObject.Properties['WindowsAppsRoot'] -and $Candidate.WindowsAppsRoot){
        if($Candidate.WindowsAppsRoot -notmatch '\A[A-Z]:\\(?:Program Files\\)?WindowsApps\z'){
            throw 'The Store preprotection record has an invalid package volume.'
        }
        return $Candidate.WindowsAppsRoot
    }
    Split-Path -Parent $Record.PackageRoot
}

function New-GuardStoreCandidatePlan($Record,$Candidate,[switch]$VerifyProposed,[switch]$VerifiedParent) {
    $store=Get-GuardStoreCandidateWindowsAppsRoot $Record $Candidate
    $paths=@(Get-GuardStoreStagePaths $store $Candidate.Package $Candidate.Paths -VerifiedParent:$VerifiedParent)
    if($VerifyProposed){
        foreach($image in $paths){[ClaudeGuard.Network.GuardPolicy]::ValidateProposedStorePath($image,$Candidate.Device)}
    }
    [ClaudeGuard.Network.GuardPolicy]::CreateStorePathBlocks([string[]]$paths,$Candidate.Device,[guid]$Candidate.Deployment)
}

function Remove-GuardStoreCandidate($Record,$Candidate) {
    if($null -eq $Candidate.Weight){return}
    $plan=New-GuardStoreCandidatePlan $Record $Candidate
    [ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($plan,[uint16]$Candidate.Weight)
}

function New-GuardStoreSetupMutex {
    [Threading.Mutex]::new($false,'Global\ClaudeVPNGuard_FirewallSetup')
}

function Install-GuardStoreCandidateFilters($Plan,$Candidate,[Action[uint16]]$RecordWeight) {
    $native=[ClaudeGuard.Network.WindowsPolicySession]
    $count=if($null -ne $Candidate.Weight){$native::ReadBootFilterCount($Plan,[uint16]$Candidate.Weight,$true)}else{0}
    if($count -eq 0){
        $Candidate.Weight=$native::InstallPersistent($Plan,$RecordWeight)
        $Candidate.RulesUtc=[datetime]::UtcNow.ToString('o')
        $count=$native::ReadBootFilterCount($Plan,[uint16]$Candidate.Weight)
    }
    $count
}

function Complete-GuardDailyStoreStage($Previous,$Next) {
    # Called with the shared rule-change lock, after the signed package, new
    # closed WFP baseline and Sandboxie rules have all been read back.
    $stage=Read-GuardStoreStage
    $ready=@($stage.Candidates | Where-Object Package -CEQ $Next.PackageFullName)
    $carried=@($stage.Candidates | Where-Object {
        $_.Generation -ceq $Previous.Generation -and $_.Package -cne $Next.PackageFullName -and
            (Get-GuardDailyStoreVersion $_.Package)
    })
    if(-not $ready.Count -and -not $carried.Count){return}
    $previousRoot=Get-GuardSandboxiePackageRoot $Previous.PackageRoot
    $nextRoot=Get-GuardSandboxiePackageRoot $Next.PackageRoot
    if($Next.UpgradeSource -cne $Previous.Generation -or $Next.Generation -ceq $Previous.Generation -or
        -not (Test-GuardDailyStoreUpgrade $Previous @{
            PackageFullName=$Next.PackageFullName;PackageSid=$Next.ScopeSid;AppId=$Next.AppId
        }) -or (Split-Path -Leaf $previousRoot) -cne $Previous.PackageFullName -or
        (Split-Path -Leaf $nextRoot) -cne $Next.PackageFullName -or
        (Split-Path -Parent $previousRoot) -ine (Split-Path -Parent $nextRoot)){
        throw 'The replacement Store package does not match the approved handoff.'
    }
    foreach($candidate in $ready){
        if($null -ne $candidate.Weight){
            $store=Get-GuardStoreCandidateWindowsAppsRoot $Previous $candidate
            if($candidate.PSObject.Properties['WindowsAppsRoot'] -and $candidate.WindowsAppsRoot -and
                (Split-Path -Parent (Get-GuardStorePhysicalPackageRoot $nextRoot)) -ine $store){
                throw 'The replacement Store package is on a different physical volume.'
            }
            foreach($path in @(Get-GuardStoreStagePaths $store $candidate.Package $candidate.Paths)){
                if(Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop){
                    [ClaudeGuard.Network.GuardPolicy]::VerifyStorePathIdentity($path,$candidate.Device)
                }
            }
        }
        Remove-GuardStoreCandidate $Previous $candidate
    }
    $stage.Candidates=@($stage.Candidates | Where-Object Package -CNE $Next.PackageFullName)
    foreach($candidate in $carried){
        # The deployment, device and path still describe the installed deny.
        # Superseded paths retain their deny until the usual expiry and absence checks.
        $candidate.Generation=$Next.Generation
        $candidate.CheckedUtc=$null
    }
    $stage.Status=if(@($stage.Candidates | Where-Object {-not $_.Verified}).Count){'Pending'}
        elseif($stage.Candidates.Count){'Protected'}else{'Waiting'}
    Save-GuardAdministratorJson (Get-GuardDataPath $script:GuardStoreStageName) $stage
}

function Undo-GuardDailyStoreStage($Record) {
    # Revision rollback calls this only when the previous deployment did not
    # already own a Store preprotection journal and its supervisor is stopped.
    $path=Get-GuardDataPath $script:GuardStoreStageName
    if(-not (Test-Path -LiteralPath $path -ErrorAction Stop)){return}
    $mutex=New-GuardStoreSetupMutex
    $held=$false
    try{
        try{$held=$mutex.WaitOne(10000)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'The Store preprotection worker has not released its lock.'}
        $stage=Read-GuardStoreStage
        foreach($candidate in $stage.Candidates){Remove-GuardStoreCandidate $Record $candidate}
        [IO.File]::Delete($path)
    }finally{
        if($held){$mutex.ReleaseMutex()}
        $mutex.Dispose()
    }
}

function ConvertTo-GuardStoreUtc($Time) {
    $instant=if($Time -is [datetime]){$Time}else{
        [datetime]::ParseExact([string]$Time,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
    }
    if($instant.Kind -eq 'Unspecified'){throw 'The Store time is missing its time zone.'}
    $instant.ToUniversalTime()
}

function Get-GuardStoreCandidateLastHint($Candidate) {
    if($Candidate.LastSeenUtc){ConvertTo-GuardStoreUtc $Candidate.LastSeenUtc}else{ConvertTo-GuardStoreUtc $Candidate.SeenUtc}
}

function Remove-GuardExpiredStoreCandidates($Stage,$Record,[datetime]$Expired) {
    $changed=$false
    foreach($candidate in @($Stage.Candidates)){
        if($candidate.Generation -cne $Record.Generation -or (Get-GuardStoreCandidateLastHint $candidate) -ge $Expired){continue}
        $parent=Get-GuardStoreCandidateWindowsAppsRoot $Record $candidate
        $candidateRoot=Get-GuardSandboxiePackageRoot (Join-Path $parent $candidate.Package)
        if(-not (Test-Path -LiteralPath $candidateRoot -ErrorAction Stop)){
            Remove-GuardStoreCandidate $Record $candidate
            $Stage.Candidates=@($Stage.Candidates | Where-Object Deployment -CNE $candidate.Deployment)
            $changed=$true
        }
    }
    $changed
}

function Update-GuardStoreHints($Stage,$Record,$Inventory,$Events,$ApprovedPaths,[switch]$PreserveCursor,[string]$WindowsAppsRoot,$DirectoryNotices) {
    $oldVersion=Get-GuardDailyStoreVersion $Record.PackageFullName
    $changed=$false
    $hints=@(
        foreach($notice in $DirectoryNotices){
            if(-not $PreserveCursor -or -not $ApprovedPaths -or -not $oldVersion -or
                $notice -isnot [ClaudeGuard.Network.StoreDirectoryNotice] -or $notice.Action -cnotin 'Created','Renamed' -or
                $WindowsAppsRoot -notmatch '\A[A-Z]:\\(?:Program Files\\)?WindowsApps\z' -or $notice.WindowsAppsRoot -ine $WindowsAppsRoot -or
                $notice.ReceivedUtc.Kind -ne 'Utc' -or $notice.ReceivedUtc -gt [datetime]::UtcNow -or
                $notice.ReceivedUtc -lt [datetime]::UtcNow.AddDays(-2) -or (Get-GuardDailyStoreVersion $notice.Package) -le $oldVersion){continue}
            [pscustomobject]@{Package=$notice.Package;Prepare=$true;Seen=$notice.ReceivedUtc;Kind='Directory';RecordId=0;EventId=0}
        }
        foreach($event in $Events){
            if(-not $event){continue}
            if(-not $PreserveCursor){$Stage.Cursor=[long]$event.RecordId; $changed=$true}
            foreach($entry in @(ConvertFrom-GuardStoreEvent ([xml]$event.ToXml()) $Record.LaunchUserSid)){
                [pscustomobject]@{Package=$entry.Package;Prepare=$entry.Prepare;Seen=([datetime]$event.TimeCreated).ToUniversalTime()
                    Kind='Event';RecordId=[long]$event.RecordId;EventId=[int]$event.Id}
            }
        }
    )
    foreach($hint in $hints){
        $seen=$hint.Seen
        $existing=$Stage.Candidates | Where-Object Package -CEQ $hint.Package | Select-Object -First 1
        if($existing){
            if($hint.Kind -ceq 'Directory' -and $existing.DirectoryNoticeUtc -isnot [string] -and $existing.DirectoryNoticeUtc -isnot [datetime]){
                $existing | Add-Member -NotePropertyName DirectoryNoticeUtc -NotePropertyValue $seen.ToString('o') -Force
                $changed=$true
            }
            if($hint.EventId -eq 574 -and $hint.RecordId -gt 0 -and
                ($existing.EventRecordId -lt 1 -or ($existing.FirstHintEventId -eq 855 -and
                    $existing.PreparationEventUtc -isnot [string] -and $existing.PreparationEventUtc -isnot [datetime]))){
                $existing.EventRecordId=$hint.RecordId
                $existing | Add-Member -NotePropertyName PreparationEventUtc -NotePropertyValue $seen.ToString('o') -Force
                $changed=$true
            }
            if($hint.Prepare -and $seen -gt (Get-GuardStoreCandidateLastHint $existing)){
                $existing | Add-Member -NotePropertyName LastSeenUtc -NotePropertyValue $seen.ToString('o') -Force
                $changed=$true
            }elseif(-not $hint.Prepare -and $existing.CheckedUtc){$existing.CheckedUtc=$null; $changed=$true}
            continue
        }
        if(-not $hint.Prepare -or (Get-GuardDailyStoreVersion $hint.Package) -le $oldVersion -or @($Stage.Candidates).Count -ge 3){continue}
        $paths=if($ApprovedPaths){$ApprovedPaths}else{@(Get-GuardStoreRelativePaths $Record $Inventory)}
        $candidate=[pscustomobject]@{
            Package=$hint.Package;Paths=$paths;Device=$null;Deployment=[guid]::NewGuid().ToString();WindowsAppsRoot=$WindowsAppsRoot
            Generation=$Record.Generation;Weight=$null;SeenUtc=$seen.ToString('o');LastSeenUtc=$seen.ToString('o');Verified=$false
            CheckedUtc=$null;RulesUtc=$null;EventRecordId=$hint.RecordId;FirstHintEventId=$hint.EventId
            DirectoryNoticeUtc=$null;PreparationEventUtc=$null
        }
        if($hint.Kind -ceq 'Directory'){$candidate.DirectoryNoticeUtc=$seen.ToString('o')}
        if($hint.EventId -eq 574){$candidate.PreparationEventUtc=$seen.ToString('o')}
        $Stage.Candidates=@($Stage.Candidates)+$candidate
        $changed=$true
    }
    $changed
}

function Invoke-GuardDailyStoreStage($Record,$App,$Route,$Worker,$Cache,$DeliveredEvents,[switch]$Fast,$DirectoryNotices) {
    $statePath=Get-GuardDataPath $script:GuardStoreStageName
    $saveInventory=$false
    $saved=$Cache.Inventory
    $events=@($DeliveredEvents)
    if($Fast){
        if(-not $Cache.Device -or -not $Cache.Paths -or -not $Cache.WindowsAppsRoot){return $false}
        $events=@($events | Where-Object Id -In 574,855)
        if(-not $events.Count -and -not $DirectoryNotices){return $true}
    }else{
        $stage=Read-GuardStoreStage
        $readCursor=[long]$stage.Cursor
        $receipt=Get-GuardStoreSavedInventory $Record -IncludeReceipt
        $events=@()
        $eventLogReadable=$false
        try{
            $events=@(Read-GuardStoreDeploymentEvents $readCursor)
            $eventLogReadable=$true
        }catch{ }
        $saveInventory=-not $saved -or ($Worker -and (
            $receipt.Worker.Pid -ne $Worker.Pid -or $receipt.Worker.StartedUtc -cne $Worker.StartedUtc -or
            $receipt.Worker.EventLogReadable -ne $eventLogReadable -or
            $receipt.Worker.WatcherSubscribed -ne $Worker.WatcherSubscribed -or
            $receipt.Worker.DirectoryWatching -ne $Worker.DirectoryWatching))
    }
    if($saveInventory){
        $current=Get-GuardInventory -LocalOnly
        $saved=[pscustomobject]@{
            Programs=@($current.Programs);DesktopPaths=@($current.DesktopPaths)
            Packages=@($current.Packages | ForEach-Object {[pscustomobject]@{Sid=$_.Sid}})
            ServiceSids=@(Get-GuardDailyServiceSids)
        }
        $plan=New-GuardInstalledPolicy $Route $Record.Port ([guid]$Record.DeploymentId) $saved $Record.ScopeSid 'Sandboxie'
        if(-not (Test-GuardDailyPolicyBinding $Record $plan) -or
            -not (Test-GuardDailyDesktopImages $Record.DesktopImages @(Read-GuardDailyDesktopImages $current))){
            throw 'The current Store program list disagrees with the approved WFP rules.'
        }
        $physicalRoot=Get-GuardStorePhysicalPackageRoot $App.Root
        $physicalImage=Get-GuardStorePhysicalImage $App.Root $physicalRoot $App.DesktopPath
        $Cache.Paths=@(Get-GuardStoreRelativePaths $Record $saved)
        $Cache.WindowsAppsRoot=Split-Path -Parent $physicalRoot
        try{$Cache.Device=[ClaudeGuard.Network.GuardPolicy]::ReadVerifiedAppDevice($physicalImage)}
        catch{$Cache.Device=$null}
        $Cache.Inventory=$saved
    }
    $expired=[datetime]::UtcNow.AddDays(-2)
    $checkBefore=[datetime]::UtcNow.AddMinutes(-1)
    if(-not $Fast -and -not $saveInventory -and -not $events.Count -and
        -not @($stage.Candidates | Where-Object {
            -not $_.CheckedUtc -or (ConvertTo-GuardStoreUtc $_.CheckedUtc) -lt $checkBefore -or
                ($_.Generation -ceq $Record.Generation -and (Get-GuardStoreCandidateLastHint $_) -lt $expired)
        }).Count){return $true}

    $mutex=New-GuardStoreSetupMutex
    $held=$false
    try{
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held -or
            (Read-GuardDailyRecord 'daily-provisioned.json').Generation -cne $Record.Generation -or
            (Test-Path -LiteralPath (Get-GuardDataPath 'daily-package-pending.json') -ErrorAction Stop)){return $false}
        if($saveInventory){
            Save-GuardAdministratorJson (Get-GuardDataPath $script:GuardStoreInventoryName) ([pscustomobject]@{
                Version=1;Generation=$Record.Generation;Package=$Record.PackageFullName;Inventory=$saved
                Worker=$(if($Worker){
                    [pscustomobject]@{
                        Pid=$Worker.Pid;ParentPid=$Worker.ParentPid;StartedUtc=$Worker.StartedUtc
                        ParentStartedUtc=$Worker.ParentStartedUtc;VerifiedUtc=[datetime]::UtcNow.ToString('o')
                        EventLogReadable=$eventLogReadable;WatcherSubscribed=$Worker.WatcherSubscribed
                        DirectoryWatching=[bool]$Worker.DirectoryWatching
                    }
                })
            })
        }
        $stage=Read-GuardStoreStage
        if(-not $Fast -and [long]$stage.Cursor -ne $readCursor){return $false}
        $changed=$false
        if($events.Count -or $DirectoryNotices){
            $changed=Update-GuardStoreHints $stage $Record $saved $events $Cache.Paths -PreserveCursor:$Fast -WindowsAppsRoot $Cache.WindowsAppsRoot -DirectoryNotices $DirectoryNotices
        }
        if(-not $Fast -and (Remove-GuardExpiredStoreCandidates $stage $Record $expired)){$changed=$true}
        if($changed -and -not $Fast){Save-GuardAdministratorJson $statePath $stage}
        # Process at most one rule transaction per pass. A contested lock or
        # failure retries from the admin-owned journal without changing v1.
        $candidate=if($Fast){
            $ids=@($events | ForEach-Object RecordId | Where-Object {$_ -gt 0})
            $packages=@($DirectoryNotices | Where-Object {$_ -is [ClaudeGuard.Network.StoreDirectoryNotice] -and $_.WindowsAppsRoot -ieq $Cache.WindowsAppsRoot} | ForEach-Object Package)
            $stage.Candidates | Where-Object {-not $_.Verified -and
                ($_.EventRecordId -in $ids -or ($_.DirectoryNoticeUtc -and $_.Package -cin $packages))} |
                Sort-Object SeenUtc -Descending | Select-Object -First 1
        }else{
            $stage.Candidates | Where-Object {-not $_.CheckedUtc -or (ConvertTo-GuardStoreUtc $_.CheckedUtc) -lt $checkBefore} |
                Sort-Object CheckedUtc | Select-Object -First 1
        }
        if($candidate){
            $candidate.CheckedUtc=[datetime]::UtcNow.ToString('o')
            try{
                if($null -eq $candidate.Weight -and -not $candidate.WindowsAppsRoot){
                    $candidate | Add-Member -NotePropertyName WindowsAppsRoot -NotePropertyValue $Cache.WindowsAppsRoot -Force
                    $candidate.Device=$null
                }
                if(-not $candidate.Device){
                    if(-not $Cache.Device){
                        $physicalRoot=Get-GuardStorePhysicalPackageRoot $App.Root
                        $physicalImage=Get-GuardStorePhysicalImage $App.Root $physicalRoot $App.DesktopPath
                        $Cache.Device=[ClaudeGuard.Network.GuardPolicy]::ReadVerifiedAppDevice($physicalImage)
                        $Cache.WindowsAppsRoot=Split-Path -Parent $physicalRoot
                    }
                    $candidateStore=Get-GuardStoreCandidateWindowsAppsRoot $Record $candidate
                    if($candidateStore -ine $Cache.WindowsAppsRoot){
                        throw 'The cached Store package volume disagrees with the proposed rule volume.'
                    }
                    $candidate.Device=$Cache.Device
                }
                $plan=New-GuardStoreCandidatePlan $Record $candidate -VerifyProposed:(-not $Fast) -VerifiedParent:$Fast
                $beforeCommit=[Action[uint16]]{
                    param([uint16]$Weight)
                    $candidate.Weight=$Weight
                    Save-GuardAdministratorJson $statePath $stage
                }
                $count=Install-GuardStoreCandidateFilters $plan $candidate $beforeCommit
                if($count -ne $plan.BootCount -or $count -lt 2){
                    throw 'The future Store program blocks were not verified.'
                }
                $candidate.Verified=$true
            }catch{
                $candidate.Verified=$false
                $stage.Status='Pending'
                Save-GuardAdministratorJson $statePath $stage
                return (-not $Fast)
            }
        }
        $stage.Status=if(@($stage.Candidates | Where-Object {-not $_.Verified}).Count){'Pending'}
            elseif($stage.Candidates.Count){'Protected'}else{'Waiting'}
        if($changed -or $candidate){Save-GuardAdministratorJson $statePath $stage}
        if($Fast){
            return -not @($stage.Candidates | Where-Object {-not $_.Verified -and
                ($_.EventRecordId -in $ids -or ($_.DirectoryNoticeUtc -and $_.Package -cin $packages))}).Count
        }
        $true
    }finally{
        if($held){$mutex.ReleaseMutex()}
        $mutex.Dispose()
        if(-not $Fast){foreach($event in $events){$event.Dispose()}}
    }
}
