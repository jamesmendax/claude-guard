#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'package\guard-daily-plan.ps1')
. (Join-Path $root 'package\guard-sandboxie.ps1')
. (Join-Path $root 'package\guard-daily-store-stage.ps1')
Add-Type -Path (Join-Path $root 'package\guard-wfp.cs')

function Assert-Store($Condition,[string]$Case) {
    if(-not $Condition){throw $Case}
    Write-Output "PASS $Case"
}

function New-StoreTestEvent([int]$Id,[long]$Cursor,[string]$Data,
    [string]$Provider='Microsoft-Windows-AppXDeployment-Server') {
    $xml=@"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="$Provider" /><EventID>$Id</EventID><Channel>Microsoft-Windows-AppXDeploymentServer/Operational</Channel></System><EventData>$Data</EventData></Event>
"@
    $event=[pscustomobject]@{Id=$Id;RecordId=$Cursor;TimeCreated=[datetime]::UtcNow;FixtureXml=$xml}
    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {$this.FixtureXml}
    $event
}

$package='AnthropicPBC.Claude_1.2.3.0_x64__fnn82j28hfe8t'
$future='AnthropicPBC.Claude_1.2.4.0_x64__fnn82j28hfe8t'
$other='Other.App_1.2.4.0_x64__fnn82j28hfe8t'
$sid='S-1-5-21-31-41-51-1001'
$parent='C:\Program Files\WindowsApps'
$record=[pscustomobject]@{Generation='ApprovedCurrent';PackageFullName=$package;PackageRoot="$parent\$package";LaunchUserSid=$sid}
$record | Add-Member -NotePropertyName DesktopPath -NotePropertyValue ($record.PackageRoot+'\app\Claude.exe')
$inventory=[pscustomobject]@{Programs=@($record.DesktopPath,($record.PackageRoot+'\app\resources\cowork-svc.exe'),'C:\Apps\claude.exe')}

$osTime=[datetime]::new(2026,11,22,20,0,4,[DateTimeKind]::Utc).AddTicks(1826629)
$precise='2026-11-22T20:00:04.1826629Z'
$last=Get-GuardStoreCandidateLastHint ([pscustomobject]@{SeenUtc=$precise})
Assert-Store ($last.Kind -eq 'Utc' -and $last.Ticks -eq $osTime.Ticks -and
    (ConvertTo-GuardStoreUtc $osTime.ToLocalTime()) -eq $osTime) 'persisted timestamps and Windows events share an exact UTC instant on a non-UTC host'
$recent=Get-GuardStoreCandidateLastHint ([pscustomobject]@{SeenUtc=$precise;LastSeenUtc=$osTime.AddSeconds(45).ToString('o')})
Assert-Store ($recent -ge $osTime.AddSeconds(44) -and $recent -lt $osTime.AddSeconds(46)) 'repeat hints and the next native readback use elapsed time across local time zones'

$early=New-StoreTestEvent 574 81 ('<Data Name="PackageMoniker">{0}</Data><Data Name="PackageMoniker2">{1}</Data>' -f $future,$package)
$tokens=New-StoreTestEvent 855 82 ('<Data Name="PackageMoniker">Pending {0}: install {1}; make bogus K{1}</Data>' -f $other,$future)
$change=New-StoreTestEvent 617 83 ('<Data Name="PackageFullName">{0}</Data><Data Name="userSid">{1}</Data>' -f $future,$sid)
$otherUser=New-StoreTestEvent 617 84 ('<Data Name="PackageFullName">{0}</Data><Data Name="userSid">{1}-2</Data>' -f $future,$sid)
$old=New-StoreTestEvent 574 85 ('<Data Name="PackageMoniker">{0}</Data>' -f $package)
$wrongProvider=New-StoreTestEvent 574 86 ('<Data Name="PackageMoniker">{0}</Data>' -f $future) 'Unrelated'

$parsed=@(ConvertFrom-GuardStoreEvent ([xml]$early.ToXml()) $sid)
Assert-Store ($parsed.Count -eq 1 -and $parsed[0].Package -ceq $future -and $parsed[0].Prepare) '574 only uses new PackageMoniker'
$parsed=@(ConvertFrom-GuardStoreEvent ([xml]$tokens.ToXml()) $sid)
Assert-Store ($parsed.Count -eq 1 -and $parsed[0].Package -ceq $future -and $parsed[0].Prepare) '855 requires a complete token for the same package'
$parsed=@(ConvertFrom-GuardStoreEvent ([xml]$change.ToXml()) $sid)
Assert-Store ($parsed.Count -eq 1 -and -not $parsed[0].Prepare) '617 is only a reconciliation hint'
Assert-Store (@(ConvertFrom-GuardStoreEvent ([xml]$otherUser.ToXml()) $sid).Count -eq 0) 'another user 617 is ignored'
Assert-Store (@(ConvertFrom-GuardStoreEvent ([xml]$wrongProvider.ToXml()) $sid).Count -eq 0) 'wrong event provider is ignored'
Assert-Store (-not (Get-GuardDailyStoreVersion 'AnthropicPBC.Claude_1.2.65536.0_x64__fnn82j28hfe8t')) 'invalid MSIX version is rejected'

$state=[pscustomobject]@{Cursor=0;Candidates=@()}
$null=Update-GuardStoreHints $state $record $inventory @($change,$otherUser,$old,$wrongProvider)
Assert-Store ($state.Cursor -eq 86 -and -not $state.Candidates.Count) 'missing early hint never stages an update'
$null=Update-GuardStoreHints $state $record $inventory @($early,$tokens)
Assert-Store ($state.Cursor -eq 82 -and $state.Candidates.Count -eq 1) 'duplicate early hints reuse one candidate'
Assert-Store (($state.Candidates[0].Paths -join ',') -ceq 'app\Claude.exe,app\resources\cowork-svc.exe') 'only the approved old package layout becomes future paths'
$deployment=$state.Candidates[0].Deployment
$state.Candidates[0].CheckedUtc=[datetime]::UtcNow.ToString('o')
$null=Update-GuardStoreHints $state $record $inventory @($change)
Assert-Store ($state.Cursor -eq 83 -and $state.Candidates[0].Deployment -ceq $deployment -and -not $state.Candidates[0].CheckedUtc) 'completion hint rereads the same rule identity'
$fastState=[pscustomobject]@{Cursor=77;Candidates=@()}
$null=Update-GuardStoreHints $fastState $record $null @($early,$tokens) @('app\Claude.exe') -PreserveCursor
Assert-Store ($fastState.Cursor -eq 77 -and $fastState.Candidates.Count -eq 1 -and $fastState.Candidates[0].EventRecordId -eq 81 -and
    $fastState.Candidates[0].Paths -join ',' -ceq 'app\Claude.exe') 'live delivery uses cached exact paths without advancing the historical replay cursor'

$parser=[ClaudeGuard.Network.StoreDeploymentEvent].GetConstructor([Reflection.BindingFlags]'NonPublic,Instance',$null,
    [type[]]@([string],[datetime],[string]),$null)
$received=[datetime]::UtcNow
$rendering="<Event><System><EventID Qualifiers='0'>574</EventID><TimeCreated SystemTime='2026-11-22T20:00:04.1820000Z'/><EventRecordID>81</EventRecordID></System></Event>"
$notice=$parser.Invoke(@($rendering,$received,'Subscription'))
Assert-Store ($notice.Id -eq 574 -and $notice.RecordId -eq 81 -and $notice.ReceivedUtc -eq $received -and
    $notice.TimeCreated.ToString('o') -ceq '2026-11-22T20:00:04.1820000Z') 'listener retains separate source and delivery timestamps'

& {
    $create=[ClaudeGuard.Network.StoreDirectoryNotice].GetConstructor([Reflection.BindingFlags]'NonPublic,Instance',$null,
        [type[]]@([string],[string],[datetime],[string]),$null)
    $seen=[datetime]::UtcNow.AddSeconds(-1)
    $paths=@('app\Claude.exe')
    $directory=$create.Invoke(@($future,$parent,$seen,'Created'))
    $dirState=[pscustomobject]@{Cursor=76;Candidates=@()}
    $null=Update-GuardStoreHints $dirState $record $null @() $paths -PreserveCursor -WindowsAppsRoot $parent -DirectoryNotices @($directory)
    $serialized=$dirState | ConvertTo-Json -Compress -Depth 8
    if($serialized -cnotmatch '"PreparationEventUtc":null'){throw 'An absent preparation time did not survive journal serialization as null.'}
    $dirState=if($PSVersionTable.PSVersion -ge [version]'7.5'){$serialized | ConvertFrom-Json -DateKind String}else{$serialized | ConvertFrom-Json}
    $candidate=$dirState.Candidates[0]
    Assert-Store ($dirState.Candidates.Count -eq 1 -and $candidate.EventRecordId -eq 0 -and -not $candidate.PreparationEventUtc -and
        $candidate.DirectoryNoticeUtc -ceq $seen.ToString('o') -and $candidate.WindowsAppsRoot -ieq $parent -and $dirState.Cursor -eq 76) 'a native directory notice stages exact future paths without inventing an event-log record'
    $id=$candidate.Deployment
    $candidate.Verified=$true
    $candidate.RulesUtc=$seen.AddMilliseconds(100).ToString('o')
    $null=Update-GuardStoreHints $dirState $record $null @($early) $paths -PreserveCursor -WindowsAppsRoot $parent
    Assert-Store ($dirState.Candidates.Count -eq 1 -and $candidate.Deployment -ceq $id -and $candidate.Verified -and
        $candidate.EventRecordId -eq $early.RecordId -and $candidate.PreparationEventUtc -ceq $early.TimeCreated.ToString('o') -and
        $candidate.RulesUtc -ceq $seen.AddMilliseconds(100).ToString('o')) 'the real 574 later binds to the same already-armed directory candidate after journal readback'
    $wrongNotices=@(
        $create.Invoke(@($other,$parent,$seen,'Created'))
        $create.Invoke(@($package,$parent,$seen,'Created'))
        $create.Invoke(@($future,'D:\WindowsApps',$seen,'Created'))
        $create.Invoke(@($future,$parent,$seen,'Deleted'))
        $create.Invoke(@($future,$parent,$seen.AddDays(-3),'Created'))
        [pscustomobject]@{Package=$future;WindowsAppsRoot=$parent;ReceivedUtc=$seen;Action='Created'}
    )
    $empty=[pscustomobject]@{Cursor=0;Candidates=@()}
    $null=Update-GuardStoreHints $empty $record $null @() $paths -PreserveCursor -WindowsAppsRoot $parent -DirectoryNotices $wrongNotices
    Assert-Store ($empty.Candidates.Count -eq 0) 'untrusted objects, wrong roots, stale notices, old versions and other families never stage directory rules'
    $null=Update-GuardStoreHints $empty $record $null @() $paths -WindowsAppsRoot $parent -DirectoryNotices @($directory)
    Assert-Store ($empty.Candidates.Count -eq 0) 'a directory notice cannot enter the historical event replay'
}

function Assert-GuardInstallationPath($Path) {}
function Test-Path {param($LiteralPath,$ErrorAction) $LiteralPath -ieq $parent}
$paths=@(Get-GuardStoreStagePaths $parent $future $state.Candidates[0].Paths)
Assert-Store ($paths.Count -eq 2 -and $paths[0] -ceq "$parent\$future\app\Claude.exe") 'future exact paths are derived beneath the validated package sibling'
$rejected=$false
try{$null=Get-GuardStoreStagePaths $parent $future @('..\outside.exe')}catch{$rejected=$true}
Assert-Store $rejected 'relative path traversal is rejected'
$rejected=$false
try{$null=Get-GuardStoreStagePaths $parent $other @('app\Claude.exe')}catch{$rejected=$true}
Assert-Store $rejected 'other package cannot supply a future path'

$device='\device\harddiskvolume71'
$plan=[ClaudeGuard.Network.GuardPolicy]::CreateStorePathBlocks([string[]]$paths,$device,[guid]$deployment)
$again=[ClaudeGuard.Network.GuardPolicy]::CreateStorePathBlocks([string[]]$paths,$device,[guid]$deployment)
Assert-Store ($plan.AdmissionCount -eq 0 -and $plan.BaseCount -eq 4 -and $plan.BootCount -eq 4) 'future path policy has only IPv4/IPv6 runtime and boot denies'
Assert-Store ($plan.PersistentSublayer -eq $again.PersistentSublayer -and
    ($plan.GetBaselineKeys() -join ',') -ceq ($again.GetBaselineKeys() -join ',')) 'journal can reproduce identical native rule identities after restart'

& {
    $older=[datetime]::UtcNow.AddDays(-3)
    $deadline=[datetime]::UtcNow.AddDays(-2)
    $delayed='AnthropicPBC.Claude_1.2.5.0_x64__fnn82j28hfe8t'
    $canceled='AnthropicPBC.Claude_1.2.6.0_x64__fnn82j28hfe8t'
    $anotherGeneration='AnthropicPBC.Claude_1.2.7.0_x64__fnn82j28hfe8t'
    $olderHints=@(foreach($item in @($future,$delayed,$canceled,$anotherGeneration)){
        $notice=New-StoreTestEvent 574 100 ('<Data Name="PackageMoniker">{0}</Data>' -f $item)
        $notice.TimeCreated=$older
        $notice
    })
    $later=New-StoreTestEvent 855 101 ('<Data Name="PackageMoniker">Renew {0}</Data>' -f $future)
    $requestedRemoval=[Collections.Generic.List[string]]::new()
    function Test-Path {
        param($LiteralPath,$ErrorAction)
        $LiteralPath -ieq "$parent\$delayed"
    }
    function Remove-GuardStoreCandidate($Record,$Candidate) {
        $requestedRemoval.Add([string]$Candidate.Deployment)
    }
    # Use a second journal for the unrelated generation. It must survive even
    # when the current-generation sweep sees its files are absent.
    $candidates=[pscustomobject]@{Cursor=0;Candidates=@()}
    $null=Update-GuardStoreHints $candidates $record $inventory ($olderHints | Select-Object -First 3)
    $other=[pscustomobject]@{Cursor=0;Candidates=@()}
    $otherRecord=[pscustomobject]@{Generation='OlderApproval';PackageFullName=$package;PackageRoot=$record.PackageRoot
        DesktopPath=$record.DesktopPath;LaunchUserSid=$sid}
    $null=Update-GuardStoreHints $other $otherRecord $inventory @($olderHints[3])
    $currentFuture=$candidates.Candidates | Where-Object Package -CEQ $future
    $first=$currentFuture.SeenUtc
    $firstId=$currentFuture.EventRecordId
    $canceledId=($candidates.Candidates | Where-Object Package -CEQ $canceled).Deployment
    $null=Update-GuardStoreHints $candidates $record $inventory @($later)
    Assert-Store ((Get-GuardStoreCandidateLastHint $currentFuture) -gt $deadline -and
        $currentFuture.SeenUtc -ceq $first -and $currentFuture.EventRecordId -eq $firstId) 'duplicate hint extends a missing candidate without altering the original event receipt'
    $removed=Remove-GuardExpiredStoreCandidates $candidates $record $deadline
    $removedOther=Remove-GuardExpiredStoreCandidates $other $record $deadline
    Assert-Store ($removed -and -not $removedOther -and $requestedRemoval.Count -eq 1 -and $requestedRemoval[0] -ceq $canceledId) 'cancellation reaps only the expired absent candidate from this approval'
    Assert-Store ($delayed -in @($candidates.Candidates.Package) -and $future -in @($candidates.Candidates.Package) -and
        $anotherGeneration -in @($other.Candidates.Package)) 'existing deferred path, renewed hint, and different approval retain their denies'
}

& {
    $laterPackage='AnthropicPBC.Claude_1.2.5.0_x64__fnn82j28hfe8t'
    $scopeSid='S-1-15-2-100-200-300-400-500-600-700'
    $appId='AnthropicPBC.Claude_fnn82j28hfe8t!Claude'
    $v1=[pscustomobject]@{
        Generation='FirstApproval';Containment='Sandboxie';ScopeSid=$scopeSid;AppId=$appId
        PackageRoot="$parent\$package";PackageFullName=$package
    }
    $v2=[pscustomobject]@{
        Generation='SecondApproval';UpgradeSource=$v1.Generation;ScopeSid=$scopeSid;AppId=$appId
        PackageRoot="$parent\$future";PackageFullName=$future
    }
    $v3=[pscustomobject]@{
        Generation='ThirdApproval';UpgradeSource=$v1.Generation;ScopeSid=$scopeSid;AppId=$appId
        PackageRoot="$parent\$laterPackage";PackageFullName=$laterPackage
    }
    $first=[datetime]::UtcNow.AddDays(-3).ToString('o')
    $target=[pscustomobject]@{
        Generation=$v1.Generation;Package=$future;Deployment=[guid]::NewGuid().ToString()
        Weight=$null;Verified=$false;CheckedUtc=$null
    }
    $upcoming=[pscustomobject]@{
        Generation=$v1.Generation;Package=$laterPackage;Deployment=[guid]::NewGuid().ToString();Weight=151;Verified=$true
        Paths=@('app\Claude.exe');Device=$device;SeenUtc=$first;LastSeenUtc=$first;RulesUtc=$first;CheckedUtc=$first;EventRecordId=501
    }
    $unrelated=[pscustomobject]@{
        Generation='DifferentApproval';Package='AnthropicPBC.Claude_1.2.6.0_x64__fnn82j28hfe8t';Deployment=[guid]::NewGuid().ToString()
        Weight=150;Verified=$true;SeenUtc=$first
    }
    $existing=[pscustomobject]@{Candidates=@($target,$upcoming,$unrelated);Status='Pending';Cursor=501}
    $disk=@{State=($existing | ConvertTo-Json -Depth 8);Saves=0;Interrupt=$true;Present=$false}
    $removed=[Collections.Generic.HashSet[string]]::new()
    function Read-GuardStoreStage {
        if($PSVersionTable.PSVersion -ge [version]'7.5'){return ($disk.State | ConvertFrom-Json -DateKind String)}
        $disk.State | ConvertFrom-Json
    }
    function Get-GuardDataPath([string]$Name) {$Name}
    function Save-GuardAdministratorJson($Path,$Data) {
        if($disk.Interrupt){throw 'Synthetic interruption before publishing the new stage owner.'}
        $disk.State=$Data | ConvertTo-Json -Depth 8
        $disk.Saves++
    }
    function Remove-GuardStoreCandidate($Record,$Candidate) {$null=$removed.Add([string]$Candidate.Deployment)}
    function Test-Path {param($LiteralPath,$ErrorAction) $disk.Present}
    $oldPlan=New-GuardStoreCandidatePlan $v1 $upcoming -VerifiedParent
    $interrupted=$false
    try{Complete-GuardDailyStoreStage $v1 $v2}catch{$interrupted=$true}
    Assert-Store ($interrupted -and (Read-GuardStoreStage).Candidates.Count -eq 3 -and $removed.Count -eq 1) 'an interrupted handoff leaves the previous journal available for retry'
    $disk.Interrupt=$false
    Complete-GuardDailyStoreStage $v1 $v2
    Complete-GuardDailyStoreStage $v1 $v2
    $resumed=Read-GuardStoreStage
    $carried=$resumed.Candidates | Where-Object Package -CEQ $laterPackage
    $newPlan=New-GuardStoreCandidatePlan $v2 $carried -VerifiedParent
    Assert-Store ($resumed.Candidates.Count -eq 2 -and $disk.Saves -eq 1 -and $removed.Count -eq 1 -and
        $carried.Generation -ceq $v2.Generation -and $carried.Verified -eq $true -and $carried.Weight -eq $upcoming.Weight -and
        $carried.SeenUtc -ceq $first -and $carried.LastSeenUtc -ceq $first -and $carried.RulesUtc -ceq $upcoming.RulesUtc -and
        $carried.EventRecordId -eq 501 -and -not $carried.CheckedUtc -and
        $newPlan.PersistentSublayer -eq $oldPlan.PersistentSublayer -and
        ($newPlan.GetBaselineKeys() -join ',') -ceq ($oldPlan.GetBaselineKeys() -join ',') -and
        ($newPlan.GetBootKeys() -join ',') -ceq ($oldPlan.GetBootKeys() -join ',')) 'the next approval carries the exact future deny and original times once, with fresh verification due'
    $expired=Remove-GuardExpiredStoreCandidates $resumed $v2 ([datetime]::UtcNow.AddDays(-2))
    Assert-Store ($expired -and $removed.Contains($upcoming.Deployment) -and -not $removed.Contains($unrelated.Deployment) -and
        $resumed.Candidates.Count -eq 1 -and $resumed.Candidates[0].Generation -ceq $unrelated.Generation) 'a canceled future candidate frees its slot under the next approval without affecting unrelated ownership'

    $target | Add-Member -NotePropertyName SeenUtc -NotePropertyValue $first
    $disk.State=[pscustomobject]@{Candidates=@($target);Status='Pending';Cursor=501} | ConvertTo-Json -Depth 8
    Complete-GuardDailyStoreStage $v1 $v3
    $skipped=Read-GuardStoreStage
    $disk.Present=$true
    $retained=-not (Remove-GuardExpiredStoreCandidates $skipped $v3 ([datetime]::UtcNow.AddDays(-2)))
    $disk.Present=$false
    $expired=Remove-GuardExpiredStoreCandidates $skipped $v3 ([datetime]::UtcNow.AddDays(-2))
    Assert-Store ($retained -and $expired -and -not $skipped.Candidates.Count) 'handoff without a matching hint retains superseded paths while present and reaps them after absence'
}

& {
    . (Join-Path $PSScriptRoot 'native-store-prestage-fixture.ps1')
    $name='GuardMsixFixture.'+[guid]::NewGuid().ToString('N')
    $familySuffix='_x64__8689sk8k9f0by'
    $oldPackage=$name+'_1.0.0.0'+$familySuffix
    $newPackage=$name+'_2.0.0.0'+$familySuffix
    $activation=[guid]::NewGuid()
    $otherActivation=[guid]::NewGuid()
    $completion="<Event><System><EventID>400</EventID><Correlation ActivityID='{0}'/></System><EventData><Data Name='DeploymentOperation'>{1}</Data><Data Name='PackageFullName'>{2}</Data></EventData></Event>"
    Assert-Store (Test-GuardNativeStoreAddCompletion ([xml]($completion -f $activation,'1',$newPackage)) $newPackage $activation) 'native receipt pairs only the same-activity Add completion'
    Assert-Store (-not (Test-GuardNativeStoreAddCompletion ([xml]($completion -f $activation,'2',$newPackage)) $newPackage $activation)) 'native receipt rejects a package removal event'
    Assert-Store (-not (Test-GuardNativeStoreAddCompletion ([xml]($completion -f $otherActivation,'1',$newPackage)) $newPackage $activation)) 'native receipt rejects an Add with a different deployment activity'
    $fixtureStage=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) (
        'ClaudeVPNGuard\native-acceptance-'+[guid]::NewGuid().ToString('N'))
    $physicalStore='C:\WindowsApps'
    $scope=[pscustomobject]@{
        OldPackage=$oldPackage;Package=$newPackage;OldRoot="$physicalStore\$oldPackage"
        FutureRoot="$physicalStore\$newPackage";State=(Join-Path $fixtureStage 'store-upgrade-state')
    }
    $stored=@{}
    $kernel=@{Calls=0}
    $fixtureLock='Local\GuardStoreOfflineTest_'+[guid]::NewGuid().ToString('N')
    function New-GuardStoreSetupMutex {[Threading.Mutex]::new($false,$fixtureLock)}
    function Test-Path {
        param($LiteralPath,$ErrorAction)
        $stored.ContainsKey($LiteralPath)
    }
    function Read-GuardDailyRecord($Name) {
        $stored[(Get-GuardDataPath $Name)] | ConvertFrom-Json
    }
    function Save-GuardAdministratorJson($Path,$Data) {
        if((Split-Path -Parent $Path) -ine $scope.State){throw 'Offline fixture path escaped its protected scope.'}
        $stored[$Path]=$Data | ConvertTo-Json -Depth 8
    }
    function Install-GuardStoreCandidateFilters($Plan,$Candidate,[Action[uint16]]$RecordWeight) {
        $kernel.Calls++
        if($kernel.Calls -eq 1){throw 'Synthetic WFP busy before the test commit.'}
        $RecordWeight.Invoke([uint16]100)
        $Candidate.RulesUtc=[datetime]::UtcNow.ToString('o')
        $Plan.BootCount
    }
    $ready=[Threading.ManualResetEvent]::new($false)
    $release=[Threading.ManualResetEvent]::new($false)
    $background=[PowerShell]::Create()
    try{
        $null=$background.AddScript({
            param($Name,$Ready,$Release)
            $lock=[Threading.Mutex]::new($false,$Name)
            try{
                if(-not $lock.WaitOne(2000)){throw 'Failed to take the isolated offline lock.'}
                try{$null=$Ready.Set();$null=$Release.WaitOne(7000)}finally{$lock.ReleaseMutex()}
            }finally{$lock.Dispose()}
        }).AddArgument($fixtureLock).AddArgument($ready).AddArgument($release)
        $held=$background.BeginInvoke()
        if(-not $ready.WaitOne(4000)){throw 'Offline fixture holder did not acquire its local mutex.'}
        Invoke-WithGuardNativeStoreFixtureState $scope {
            $bound=[pscustomobject]@{Generation='OfflineGeneration';PackageFullName=$scope.OldPackage
                PackageRoot=(Join-Path $parent $oldPackage);LaunchUserSid=$sid}
            $app=[pscustomobject]@{Root=$scope.OldRoot}
            $cache=@{Inventory=$null;Paths=@('fixture-desktop.exe','fixture-helper.exe');Device=$device;WindowsAppsRoot=$physicalStore}
            $notice=New-StoreTestEvent 574 101 ('<Data Name="PackageMoniker">{0}</Data>' -f $scope.Package)
            Save-GuardAdministratorJson (Get-GuardDataPath 'daily-provisioned.json') $bound
            $first=Invoke-GuardDailyStoreStage $bound $app $null $null $cache @($notice) -Fast
            Assert-Store (-not $first -and $kernel.Calls -eq 0 -and $stored.Count -eq 1) 'busy mutex defers the original 574 without touching the journal'
            $null=$release.Set()
            $null=$background.EndInvoke($held)
            $second=Invoke-GuardDailyStoreStage $bound $app $null $null $cache @($notice) -Fast
            $pending=Read-GuardStoreStage
            Assert-Store (-not $second -and $pending.Status -ceq 'Pending' -and $pending.Candidates[0].EventRecordId -eq 101) 'transient WFP failure keeps that event pending for the fast retry'
            $last=Invoke-GuardDailyStoreStage $bound $app $null $null $cache @($notice) -Fast
            $protected=Read-GuardStoreStage
            Assert-Store ($last -and $protected.Status -ceq 'Protected' -and $protected.Candidates[0].Verified -eq $true -and
                $protected.Candidates[0].RulesUtc -and $protected.Candidates[0].EventRecordId -eq 101 -and
                $protected.Candidates[0].Deployment -ceq $pending.Candidates[0].Deployment -and $protected.Cursor -eq 0) 'same production fast entry commits a protected matching receipt after retry'
            $savedCandidate=$protected.Candidates[0]
            $paths=@(Get-GuardStoreStagePaths (Get-GuardStoreCandidateWindowsAppsRoot $bound $savedCandidate) $newPackage $savedCandidate.Paths -VerifiedParent)
            Assert-Store ($savedCandidate.WindowsAppsRoot -ceq $physicalStore -and $savedCandidate.Device -ceq $device -and
                $paths.Count -eq 2 -and $paths[0] -ceq "$physicalStore\$newPackage\fixture-desktop.exe") 'journal reconstructs the physical filter paths after a restart with a registered alias'
        }
        Assert-Store (-not (Get-GuardDailyStoreVersion $newPackage)) 'fixture package validation does not escape its test scope'
    }finally{
        $null=$release.Set()
        $background.Dispose()
        $ready.Dispose()
        $release.Dispose()
    }
}

& {
    . (Join-Path $PSScriptRoot 'native-store-replacement-worker.ps1')
    $fixture='GuardMsixFixture.'+[guid]::NewGuid().ToString('N')
    $oldName=$fixture+'_1.0.0.0_x64__8689sk8k9f0by'
    $newName=$fixture+'_2.0.0.0_x64__8689sk8k9f0by'
    $family=$fixture+'_8689sk8k9f0by'
    $fixtureSid='S-1-15-2-100-200-300-400-500-600-700'
    function Get-GuardPackageSid([string]$Name) {
        if($Name -cne $family){throw 'Unexpected staged test package family.'}
        $fixtureSid
    }
    $stage=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) (
        'ClaudeVPNGuard\native-acceptance-'+[guid]::NewGuid().ToString('N'))
    $oldImage=Join-Path (Join-Path $parent $oldName) 'fixture-desktop.exe'
    $newRoot=Join-Path $parent $newName
    $images=@((Join-Path $newRoot 'fixture-desktop.exe'),(Join-Path $newRoot 'fixture-helper-v2.exe'))
    $relay=Join-Path $stage 'normal-fixture-relay.exe'
    $observer=Join-Path $stage 'normal-fixture-observer.exe'
    $oldDeployment=[guid]::NewGuid()
    $newDeployment=[guid]::NewGuid()
    $oldPlan=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage(
        [string[]]@($oldImage),[string[]]@($oldImage),[string[]]@($fixtureSid),$null,$fixtureSid,
        $relay,23001,'127.0.0.1',23002,$observer
    ).WithEarlyBootBlocks().ForPersistentUse($oldDeployment).WithRegisteredPackageAdmission([string[]]@($oldImage))
    $newPlan=[ClaudeGuard.Network.GuardPolicy]::CreateForPackage(
        [string[]]$images,[string[]]@($images[0]),[string[]]@($fixtureSid),$null,$fixtureSid,
        $relay,23001,'127.0.0.1',23002,$observer
    ).WithEarlyBootBlocks().ForPersistentUse($newDeployment).WithRegisteredPackageAdmission([string[]]$images)
    $receipt=[ordered]@{
        Version=1;Package=$newName;OldPackage=$oldName;PackageRoot=$newRoot;Family=$family;PackageSid=$fixtureSid
        Images=$images;ImageSha256=('A'*64);Deployment=$newDeployment;Sublayer=$newPlan.PersistentSublayer
        BaselineKeys=$newPlan.GetBaselineKeys();BootKeys=$newPlan.GetBootKeys();Weight=170;Phase='InstallingClosed';InstallPid=42
        OldPolicy=[ordered]@{
            Deployment=$oldDeployment;Sublayer=$oldPlan.PersistentSublayer;BaselineKeys=$oldPlan.GetBaselineKeys();BootKeys=$oldPlan.GetBootKeys()
            AssignedWeight=165;Image=$oldImage;PackageSid=$fixtureSid;Relay=$relay;RelayPort=23001
            Upstream='127.0.0.1';UpstreamPort=23002;Observer=$observer
        }
    }
    $disk=$receipt | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $rebuilt=New-GuardNativeReplacementPlans $disk $stage
    Assert-Store ($disk.Phase -ceq 'InstallingClosed' -and $disk.Weight -eq 170 -and
        $rebuilt.Old.PersistentSublayer -eq $oldPlan.PersistentSublayer -and $rebuilt.New.PersistentSublayer -eq $newPlan.PersistentSublayer -and
        $rebuilt.New.BaseCount -eq $newPlan.BaseCount -and $rebuilt.New.AdmissionCount -eq $newPlan.AdmissionCount) 'replacement weight and exact old/new identities survive journal serialization'

    $disk.Images[1]='C:\Windows\System32\notepad.exe'
    $blocked=$false
    try{$null=New-GuardNativeReplacementPlans $disk $stage}catch{$blocked=$true}
    Assert-Store $blocked 'replacement recovery rejects an unrelated executable from its journal'
    $disk=$receipt | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $disk.BootKeys[0]=[guid]::NewGuid().ToString()
    $blocked=$false
    try{$null=New-GuardNativeReplacementPlans $disk $stage}catch{$blocked=$true}
    Assert-Store $blocked 'replacement recovery rejects a changed Windows rule identity'
}
