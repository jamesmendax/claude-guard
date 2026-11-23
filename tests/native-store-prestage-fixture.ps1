# The Store package test runs in a fresh Windows PowerShell process.
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'package\guard-daily-plan.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'package\guard-daily-store-stage.ps1')
. (Join-Path $PSScriptRoot 'daily-revision-evidence.ps1')

function Start-GuardNativeStorePathBlocks([string[]]$Paths,[string]$InstalledImage,[string]$Receipt,[string]$Device) {
    if(-not $Device){
        $Device=[ClaudeGuard.Network.GuardPolicy]::ReadVerifiedAppDevice($InstalledImage)
        foreach($path in $Paths){[ClaudeGuard.Network.GuardPolicy]::ValidateProposedStorePath($path,$Device)}
    }
    $deployment=[guid]::NewGuid()
    $plan=[ClaudeGuard.Network.GuardPolicy]::CreateStorePathBlocks($Paths,$Device,$deployment)
    $journal=[ordered]@{
        Deployment=$deployment;Device=$Device;Paths=$Paths;Sublayer=$plan.PersistentSublayer;Weight=$null
        BaselineKeys=$plan.GetBaselineKeys();BootKeys=$plan.GetBootKeys();Verified=$false;Removed=$false;RulesUtc=$null
    }
    $entry=[pscustomobject]@{Plan=$plan;Journal=$journal;Receipt=$Receipt}
    $native=[ClaudeGuard.Network.WindowsPolicySession]
    try{
        $beforeCommit=[Action[uint16]]{
            param([uint16]$Weight)
            $journal.Weight=$Weight
            Save-GuardAdministratorJson $Receipt $journal
        }
        $journal.Weight=$native::InstallPersistent($plan,$beforeCommit)
        $journal.RulesUtc=[datetime]::UtcNow.ToString('o')
        if($native::ReadBootFilterCount($plan,[uint16]$journal.Weight) -ne $plan.BootCount -or
            $plan.AdmissionCount -ne 0 -or $plan.BaseCount -ne 2*$Paths.Count){
            throw 'The future fixture path blocks did not read back as deny-only.'
        }
        $journal.Verified=$true
        Save-GuardAdministratorJson $Receipt $journal
        $entry
    }catch{
        Stop-GuardNativeStorePathBlocks $entry
        throw
    }
}

function Stop-GuardNativeStorePathBlocks($Entry) {
    if(-not $Entry -or $null -eq $Entry.Journal.Weight -or $Entry.Journal.Removed){return}
    [ClaudeGuard.Network.WindowsPolicySession]::RemovePersistent($Entry.Plan,[uint16]$Entry.Journal.Weight)
    $Entry.Journal.Removed=$true
    Save-GuardAdministratorJson $Entry.Receipt $Entry.Journal
}

function Get-GuardNativeStorePackagePrestage($Installed,$Packed,[string]$Stage) {
    if($Installed.Name -cne $Packed.Name -or $Installed.Version.ToString() -cne '1.0.0.0' -or
        $Installed.PackageFullName -cnotmatch '\AGuardMsixFixture\.[0-9a-f]{32}_1\.0\.0\.0_x64__[a-z0-9]{13}\z'){
        throw 'Only the generated native test package can be prearmed.'
    }
    Assert-GuardSandboxieAdministratorPath $Packed.UpgradeFile
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive=[IO.Compression.ZipFile]::OpenRead($Packed.UpgradeFile)
    try{
        $reader=[IO.StreamReader]::new($archive.GetEntry('AppxManifest.xml').Open())
        try{$manifest=[xml]$reader.ReadToEnd()}finally{$reader.Dispose()}
    }finally{$archive.Dispose()}
    $identity=$manifest.Package.Identity
    if($identity.Name -cne $Installed.Name -or $identity.Publisher -cne $Installed.Publisher -or
        $identity.Version -cne '2.0.0.0' -or $identity.ProcessorArchitecture -cne 'x64'){
        throw 'The generated replacement manifest disagrees with the installed fixture family.'
    }
    $nextPackage=$Installed.PackageFullName.Replace('_1.0.0.0_','_2.0.0.0_')
    $registeredRoot=$Installed.InstallLocation
    $registeredStore=Split-Path -Parent $registeredRoot
    if([IO.Path]::GetFileName($registeredRoot) -cne $Installed.PackageFullName -or
        [IO.Path]::GetFileName($registeredStore) -ine 'WindowsApps'){
        throw 'The installed fixture is not in its exact versioned WindowsApps folder.'
    }
    $oldRoot=Get-GuardStorePhysicalPackageRoot $registeredRoot
    $future=Join-Path (Split-Path -Parent $oldRoot) $nextPackage
    $relative=@('fixture-desktop.exe','fixture-helper.exe')
    $old=@($relative | ForEach-Object {Get-GuardStorePhysicalImage $registeredRoot $oldRoot (Join-Path $registeredRoot $_)})
    $images=@($relative | ForEach-Object {Join-Path $future $_})
    if((Test-Path -LiteralPath $future -ErrorAction Stop) -or
        (Test-Path -LiteralPath (Join-Path $registeredStore $nextPackage) -ErrorAction Stop)){
        throw 'A replacement package image is already present.'
    }
    [pscustomobject]@{
        Package=$nextPackage;Paths=$images;RelativePaths=$relative;OldPackage=$Installed.PackageFullName
        OldRoot=$oldRoot;FutureRoot=$future
        Device=[ClaudeGuard.Network.GuardPolicy]::ReadVerifiedAppDevice($old[0])
        File=$Packed.UpgradeFile;Receipt=(Join-Path $Stage 'store-package-prestage.json')
        State=(Join-Path $Stage 'store-upgrade-state')
    }
}

function Invoke-WithGuardNativeStoreFixtureState($Scope,[scriptblock]$Operation) {
    # Deliberately local. Production callers retain the actual Anthropic pkg
    # validators and ProgramData locations. WFP/locking/receipts are unchanged.
    $nativeStage=Split-Path -Parent $Scope.State
    $guardRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard'
    if($Scope.OldPackage -cnotmatch '\AGuardMsixFixture\.[a-f0-9]{32}_1\.0\.0\.0_x64__[a-z0-9]{13}\z' -or
        $Scope.Package -cne $Scope.OldPackage.Replace('_1.0.0.0_','_2.0.0.0_') -or
        (Split-Path -Leaf $Scope.OldRoot) -cne $Scope.OldPackage -or (Split-Path -Leaf $Scope.FutureRoot) -cne $Scope.Package -or
        (Split-Path -Parent $Scope.OldRoot) -ine (Split-Path -Parent $Scope.FutureRoot) -or
        (Split-Path -Leaf (Split-Path -Parent $Scope.OldRoot)) -ine 'WindowsApps' -or
        (Split-Path -Parent $nativeStage) -ine $guardRoot -or (Split-Path -Leaf $nativeStage) -cnotmatch '\Anative-acceptance-[a-f0-9]{32}\z' -or
        (Split-Path -Leaf $Scope.State) -cne 'store-upgrade-state'){
        throw 'The native Store fixture scope is invalid.'
    }
    function local:Get-GuardDailyStoreVersion([string]$Package) {
        if($Package -ceq $Scope.OldPackage){[version]'1.0.0.0'}
        elseif($Package -ceq $Scope.Package){[version]'2.0.0.0'}
    }
    function local:Get-GuardSandboxiePackageRoot([string]$Path) {
        if($Path -cnotin $Scope.OldRoot,$Scope.FutureRoot -or [IO.Path]::GetFullPath($Path) -cne $Path){
            throw 'The observed Store update escaped the isolated fixture paths.'
        }
        $Path
    }
    function local:Get-GuardDataPath([string]$Name) {
        if($Name -cnotin 'daily-provisioned.json','daily-package-pending.json','daily-store-stage.json'){
            throw 'Store preprotection addressed an unrelated state file in the fixture.'
        }
        Join-Path $Scope.State $Name
    }
    & $Operation
}

function Get-GuardNativeLivePrestageEntry($Scope,$Record,$Candidate) {
    if(-not $Candidate -or $null -eq $Candidate.Weight){return}
    $store=Get-GuardStoreCandidateWindowsAppsRoot $Record $Candidate
    $paths=@(Get-GuardStoreStagePaths $store $Candidate.Package $Candidate.Paths -VerifiedParent)
    if(($paths -join '|') -cne ($Scope.Paths -join '|')){
        throw 'The production stage journal does not match the exact fixture path inventory.'
    }
    $plan=New-GuardStoreCandidatePlan $Record $Candidate -VerifiedParent
    $journal=[ordered]@{
        Deployment=$Candidate.Deployment;Device=$Candidate.Device;Paths=$Scope.Paths;Sublayer=$plan.PersistentSublayer
        Weight=$Candidate.Weight;BaselineKeys=$plan.GetBaselineKeys();BootKeys=$plan.GetBootKeys()
        Verified=($Candidate.Verified -eq $true);RulesUtc=$Candidate.RulesUtc
        EventRecordId=$Candidate.EventRecordId;Removed=$false
    }
    [pscustomobject]@{Plan=$plan;Journal=$journal;Receipt=$Scope.Receipt}
}

function Test-GuardNativeStoreAddCompletion([xml]$Event,[string]$Package,[guid]$Activity) {
    $system=$Event.Event.System
    $eventActivity=[guid]::Empty
    if($Activity -eq [guid]::Empty -or [int]$system.EventID -ne 400 -or
        -not [guid]::TryParse([string]$system.Correlation.ActivityID,[ref]$eventActivity) -or $eventActivity -ne $Activity){
        return $false
    }
    $name=@($Event.Event.EventData.Data | Where-Object {$_.GetAttribute('Name') -ceq 'PackageFullName'})
    $operation=@($Event.Event.EventData.Data | Where-Object {$_.GetAttribute('Name') -ceq 'DeploymentOperation'})
    $name.Count -eq 1 -and $name[0].InnerText -ceq $Package -and
        $operation.Count -eq 1 -and $operation[0].InnerText -ceq '1'
}

function Start-GuardNativeStoreUpgradeTrigger($Scope,[int]$DirectPort,[int]$RelayPort,[switch]$ActivateOnly) {
    $trigger=Join-Path $PSScriptRoot 'native-store-upgrade-trigger.ps1'
    Assert-GuardSandboxieAdministratorPath $trigger
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -UpgradeFile "{1}" -Package "{2}" -DirectPort {3} -RelayPort {4}' -f
        $trigger,$Scope.File,$Scope.Package,$DirectPort,$RelayPort
    if($ActivateOnly){$arguments+=' -ActivateOnly'}
    Start-GuardDailyChild (Join-Path $PSHOME 'powershell.exe') $arguments ''
}

function Read-GuardNativeStoreUpgradeTrigger($Child) {
    if($Child.Process.ExitCode -ne 0){
        throw ('The independently launched Store upgrade failed. '+$Child.ErrorOutput.GetAwaiter().GetResult().Trim())
    }
    $Child.Output.GetAwaiter().GetResult().Trim() | ConvertFrom-Json
}

function Invoke-GuardNativeStoreUpgradeObservation($Scope,[int]$DirectPort,[int]$RelayPort,[ref]$Prestage) {
    Invoke-WithGuardNativeStoreFixtureState $Scope {
        if(Test-Path -LiteralPath $Scope.State){throw 'Unexpected pre-existing state in the Store timing fixture.'}
        Initialize-GuardAdministratorDirectory $Scope.State
        $userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $fixtureRecord=[pscustomobject]@{
            Generation=[guid]::NewGuid().ToString('N').ToUpperInvariant()+[guid]::NewGuid().ToString('N').ToUpperInvariant()
            PackageFullName=$Scope.OldPackage;PackageRoot=$Scope.OldRoot;LaunchUserSid=$userSid
        }
        Save-GuardAdministratorJson (Get-GuardDataPath 'daily-provisioned.json') $fixtureRecord
        $cache=@{Inventory=$null;Paths=$Scope.RelativePaths;Device=$Scope.Device;WindowsAppsRoot=(Split-Path -Parent $Scope.OldRoot)}
        $app=[pscustomobject]@{Root=$Scope.OldRoot}
        $listener=[ClaudeGuard.Network.StoreDeploymentWake]::new()
        $child=$null
        $directoryNotice=$null
        $event574=$null
        $callback574=$null
        $event617=$null
        $event400=$null
        $deployEvents=@()
        $deployActivity=[guid]::Empty
        $candidate=$null
        $nativeCount=0
        $status=$null
        $attempts=0
        $nextRetry=[datetime]::MinValue
        $prepareError=$null
        try{
        $directoryWatching=$listener.WatchDirectory($cache.WindowsAppsRoot,$Scope.OldPackage)
        $observationStarted=[datetime]::UtcNow
        $child=Start-GuardNativeStoreUpgradeTrigger $Scope $DirectPort $RelayPort
        $until=[datetime]::UtcNow.AddSeconds(30)
        $result=$null
        do{
            $events=@($listener.Drain())
            foreach($notice in $listener.DrainDirectoryNotices()){
                if($directoryNotice -or $notice.Package -cne $Scope.Package -or
                    $notice.WindowsAppsRoot -ine $cache.WindowsAppsRoot -or $notice.ReceivedUtc -lt $observationStarted){continue}
                $directoryNotice=$notice
                if(-not $event574){
                    $queried=$listener.QueryPreparation($Scope.Package)
                    if($queried){$events+=,$queried}
                }
            }
            foreach($event in $events){
                if($event.TimeCreated -lt $observationStarted){continue}
                $xml=[xml]$event.ToXml()
                if($event.Id -eq 400){
                    $deployEvents=@($deployEvents)+$event
                    if($deployEvents.Count -gt 128){$deployEvents=@($deployEvents | Select-Object -Last 128)}
                    continue
                }
                $hint=@(ConvertFrom-GuardStoreEvent $xml $userSid)
                if($event.Id -eq 617 -and $hint.Count -eq 1 -and -not $event617){$event617=$event}
                if($event.Id -ne 574 -or $hint.Count -ne 1 -or -not $hint[0].Prepare -or
                    $hint[0].Package -cne $Scope.Package){continue}
                if(-not $event574){
                    $event574=$event
                    $null=[guid]::TryParse([string]$xml.Event.System.Correlation.ActivityID,[ref]$deployActivity)
                }
                if(-not $callback574 -and $event.Delivery -ceq 'Subscription' -and $event.RecordId -eq $event574.RecordId){
                    $callback574=$event
                }
            }
            $eventBound=$event574 -and $candidate.EventRecordId -eq $event574.RecordId
            if(($event574 -or $directoryNotice) -and ($nativeCount -eq 0 -or ($event574 -and -not $eventBound)) -and
                [datetime]::UtcNow -ge $nextRetry){
                $attempts++
                $nextRetry=[datetime]::UtcNow.AddMilliseconds(35)
                try{
                    $realEvents=@(if($event574){$event574})
                    $directoryNotices=@(if($directoryNotice){$directoryNotice})
                    $handled=Invoke-GuardDailyStoreStage $fixtureRecord $app $null $null $cache $realEvents -Fast -DirectoryNotices $directoryNotices
                    if($handled){
                        $storeStage=Read-GuardStoreStage
                        $status=$storeStage.Status
                        $candidate=$storeStage.Candidates | Where-Object Package -CEQ $Scope.Package | Select-Object -First 1
                        $Prestage.Value=Get-GuardNativeLivePrestageEntry $Scope $fixtureRecord $candidate
                        if($status -ceq 'Protected' -and $candidate.Verified -eq $true -and $candidate.RulesUtc -and $Prestage.Value){
                            $plan=$Prestage.Value.Plan
                            $count=[ClaudeGuard.Network.WindowsPolicySession]::ReadBootFilterCount($plan,[uint16]$candidate.Weight)
                            if($count -ne $plan.BootCount -or $plan.AdmissionCount -ne 0 -or $plan.BaseCount -ne 2*$Scope.Paths.Count){
                                throw 'The future package did not have the expected exact-path deny rules.'
                            }
                            $nativeCount=$count
                            $prepareError=$null
                        }
                    }
                }catch{$prepareError=$_.Exception.Message}
            }
            if($event574 -and -not $event400 -and $deployEvents.Count){
                $event400=$deployEvents | Where-Object {
                    Test-GuardNativeStoreAddCompletion ([xml]$_.ToXml()) $Scope.Package $deployActivity
                } | Select-Object -First 1
                $deployEvents=@()
            }
            if(-not $result -and $child.Process.HasExited){
                $result=Read-GuardNativeStoreUpgradeTrigger $child
                $until=[datetime]::UtcNow.AddSeconds(2)
            }
            if($result -and $event574 -and $callback574 -and $event400 -and $nativeCount -gt 0 -and
                $candidate.EventRecordId -eq $event574.RecordId){break}
            $null=$listener.Wait(35)
        }while([datetime]::UtcNow -lt $until)
        if(-not $result){throw 'The independent Store update did not finish before the test deadline.'}
        if(($event574 -or $directoryNotice) -and -not $candidate){
            $finalStage=Read-GuardStoreStage
            $status=$finalStage.Status
            $candidate=$finalStage.Candidates | Where-Object Package -CEQ $Scope.Package | Select-Object -First 1
        }
        $armedUtc=$candidate.RulesUtc
        $armed=if($armedUtc){Read-DailyRevisionUtc $armedUtc}
        $directoryUtc=if($directoryNotice){$directoryNotice.ReceivedUtc.ToString('o')}
        $checked=if($candidate.CheckedUtc){Read-DailyRevisionUtc $candidate.CheckedUtc}
        $directoryVerified=$directoryNotice -and $checked -and $armed -and $candidate.DirectoryNoticeUtc -ceq $directoryUtc -and
            $candidate.Package -ceq $directoryNotice.Package -and $candidate.WindowsAppsRoot -ieq $directoryNotice.WindowsAppsRoot -and
            $directoryNotice.ReceivedUtc -ge (Read-DailyRevisionUtc $result.InstallStartedUtc) -and
            $directoryNotice.ReceivedUtc -le $checked -and $checked -le $armed
        $failedBoundary=if(-not $event574){'MissingMatching574'}
            elseif(-not $event400){'MissingMatching400'}
            elseif($candidate.EventRecordId -ne $event574.RecordId){'Unbound574'}
            elseif(-not $armedUtc -or $nativeCount -le 0){'MissingVerifiedRules'}
            elseif($armed -lt $event574.TimeCreated -and -not $directoryVerified){'MissingVerifiedDirectoryNotice'}
            elseif($armed -ge $event400.TimeCreated){'RulesAtOrAfterRegistration'}
            elseif($armed -ge (Read-DailyRevisionUtc $result.AddReturnedUtc)){'RulesAtOrAfterAddReturn'}
            elseif($armed -ge (Read-DailyRevisionUtc $result.FirstTcpUdpUtc)){'RulesAtOrAfterFirstTraffic'}
        [pscustomobject]@{
            Passed=-not $failedBoundary
            FailedBoundary=$failedBoundary
            DirectoryWatching=$directoryWatching
            DirectoryNoticeUtc=$directoryUtc
            DirectoryNoticePackage=$directoryNotice.Package
            DirectoryNoticeRoot=$(if($directoryNotice){Join-Path $directoryNotice.WindowsAppsRoot $directoryNotice.Package})
            DirectoryNoticeVerified=[bool]$directoryVerified
            StagingStartedUtc=$candidate.CheckedUtc
            Actual574=$(if($event574){$event574.TimeCreated.ToString('o')})
            Received574=$(if($event574){$event574.ReceivedUtc.ToString('o')})
            Delivery574=$event574.Delivery
            Callback574Utc=$(if($callback574){$callback574.ReceivedUtc.ToString('o')})
            RecordId574=$(if($event574){$event574.RecordId})
            ActivityId574=$(if($deployActivity -ne [guid]::Empty){$deployActivity.ToString('D')})
            RulesUtc=$armedUtc
            StateStatus=$status;CandidateVerified=($candidate.Verified -eq $true)
            StateRecordId=$candidate.EventRecordId;NativeBootRules=$nativeCount;FastAttempts=$attempts
            StateReceipt=(Get-GuardDataPath 'daily-store-stage.json')
            Status617=$(if($event617){$event617.TimeCreated.ToString('o')})
            Registered400=$(if($event400){$event400.TimeCreated.ToString('o')})
            RecordId400=$(if($event400){$event400.RecordId})
            MatchedAdd400=($null -ne $event400)
            First=$result;PrepareError=$prepareError
        }
        }finally{
            try{
                if(-not $Prestage.Value -and ($event574 -or $directoryNotice)){
                    # The before-commit journal may be present even after a
                    # failed readback. Remember owned keys for lab cleanup.
                    $interrupted=(Read-GuardStoreStage).Candidates | Where-Object Package -CEQ $Scope.Package | Select-Object -First 1
                    $Prestage.Value=Get-GuardNativeLivePrestageEntry $Scope $fixtureRecord $interrupted
                }
            }finally{
                try{Stop-GuardDailyChild $child}
                finally{$listener.Dispose()}
            }
        }
    }
}

function Invoke-GuardNativeStoreUpgradeWithoutPrestage($Scope,[int]$DirectPort,[int]$RelayPort) {
    $child=$null
    try{
        $child=Start-GuardNativeStoreUpgradeTrigger $Scope $DirectPort $RelayPort -ActivateOnly
        if(-not $child.Process.WaitForExit(11000)){throw 'The replacement fallback control did not finish.'}
        Read-GuardNativeStoreUpgradeTrigger $child
    }finally{Stop-GuardDailyChild $child}
}

function Test-GuardNativeStorePrestage([string]$Stage,[string]$MakeAppx,$Installed,[int]$DirectPort,[int]$RelayPort) {
    Assert-GuardSandboxieAdministratorPath $Stage
    $receipt=Join-Path $Stage 'store-prestage-result.json'
    $record=[ordered]@{
        Passed=$false;ManualExactPathAttribution=$false;AbsentAtArm=$false;OldConnected=$false
        FirstTcpBlocked=$false;FirstUdpBlocked=$false;FirstRelayBlocked=$false;NativeIdentityMatched=$false
        RealPackageFirstActivation=$false;OriginalV1ConnectedWhileArmed=$false
        SameRegisteredPackageUnblocked=$false;IndependentCleanupVerified=$false;RollbackRestored=$false
        OriginalPackage=$Installed.PackageFullName;RegisteredRoot=$null;FinalRoot=$null;RootLinkType=$null
        FuturePackage=$null;FuturePath=$null;RulesUtc=$null;First=$null;Unblocked=$null
        OriginalV1Packets=$null;OriginalV1Relay=$null;FirstPackets=$null;UnblockedPackets=$null
        RuleRemovalReadback=$false;PackageRemovalReadback=$false;Error=$null
    }
    $entry=$null
    $child=$null
    $scope=$null
    $ownedName=$null
    try{
        $issuer=[string]$Installed.PublisherId
        $oldRoot=[string]$Installed.InstallLocation
        $windowsApps=Split-Path -Parent $oldRoot
        $oldReg=@(Get-AppxPackage -Name $Installed.Name | Where-Object Name -CEQ $Installed.Name)
        if($issuer -cnotmatch '\A[a-z0-9]{13}\z' -or
            $Installed.Name -cnotmatch '\AGuardMsixFixture\.[a-f0-9]{32}\z' -or $oldReg.Count -ne 1 -or
            $Installed.PackageFullName -cne "$($Installed.Name)_1.0.0.0_x64__$issuer" -or
            $oldReg[0].PackageFullName -cne $Installed.PackageFullName -or
            $oldReg[0].InstallLocation -ine $oldRoot -or (Split-Path -Leaf $oldRoot) -cne $Installed.PackageFullName -or
            (Split-Path -Leaf $windowsApps) -ine 'WindowsApps'){
            throw 'A verified and uniquely registered version 1 Store fixture is required.'
        }
        $record.RegisteredRoot=$oldRoot
        $record.FinalRoot=Get-GuardFinalPath $oldRoot
        $record.RootLinkType=(Get-Item -LiteralPath $oldRoot -Force -ErrorAction Stop).LinkType
        $physicalOldRoot=Get-GuardStorePhysicalPackageRoot $oldRoot
        $old=Get-GuardStorePhysicalImage $oldRoot $physicalOldRoot (Join-Path $oldRoot 'fixture-desktop.exe')

        $packed=& (Join-Path $PSScriptRoot 'native-msix-upgrade-lab.ps1') -MakeAppx $MakeAppx -Directory $Stage -PackOnly -NormalRelayVariant -IncludeUpgrade
        if($packed.Name -cnotmatch '\AGuardMsixFixture\.[a-f0-9]{32}\z' -or $packed.Name -ceq $Installed.Name){
            throw 'A separate generated fixture identity is required.'
        }
        Assert-GuardSandboxieAdministratorPath $packed.UpgradeFile
        Assert-GuardSandboxieAdministratorPath $packed.Image
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive=[IO.Compression.ZipFile]::OpenRead($packed.UpgradeFile)
        try{
            $reader=[IO.StreamReader]::new($archive.GetEntry('AppxManifest.xml').Open())
            try{$manifest=[xml]$reader.ReadToEnd()}finally{$reader.Dispose()}
        }finally{$archive.Dispose()}
        $identity=$manifest.Package.Identity
        $application=@($manifest.Package.Applications.Application | Where-Object Id -CEQ 'Desktop')
        if($identity.Name -cne $packed.Name -or $identity.Publisher -cne $Installed.Publisher -or
            $identity.Version -cne '2.0.0.0' -or $identity.ProcessorArchitecture -cne 'x64' -or
            $application.Count -ne 1 -or $application[0].Executable -cne 'fixture-desktop.exe' -or
            $application[0].EntryPoint -cne 'Windows.FullTrustApplication'){
            throw 'The generated package manifest disagrees with the verified fixture publisher or application.'
        }
        $fullName="$($packed.Name)_2.0.0.0_x64__$issuer"
        $family="$($packed.Name)_$issuer"
        $registeredFutureRoot=Join-Path $windowsApps $fullName
        $futureRoot=Join-Path (Split-Path -Parent $physicalOldRoot) $fullName
        $future=Join-Path $futureRoot 'fixture-desktop.exe'
        if(@(Get-AppxPackage -Name $packed.Name -AllUsers | Where-Object Name -CEQ $packed.Name).Count -or
            (Test-Path -LiteralPath $registeredFutureRoot -ErrorAction Stop) -or
            (Test-Path -LiteralPath $futureRoot -ErrorAction Stop) -or (Test-Path -LiteralPath $future -ErrorAction Stop)){
            throw 'The fresh version 2 family or future path is already present.'
        }
        $ownedName=$packed.Name
        $scope=[pscustomobject]@{File=$packed.UpgradeFile;Package=$fullName}
        $record.FuturePackage=$fullName
        $record.FuturePath=$future
        $record.AbsentAtArm=$true
        $entry=Start-GuardNativeStorePathBlocks @($future) $old (Join-Path $Stage 'store-standalone-path-rule.json')
        $record.RulesUtc=$entry.Journal.RulesUtc

        $null=Read-DirectPackets
        if((Invoke-NormalCommand "direct|$DirectPort") -cne 'Attempted'){throw 'The original v1 control did not probe while the future deny was armed.'}
        $record.OriginalV1Packets=Read-DirectPackets
        $record.OriginalV1Relay=Invoke-NormalCommand "open|$RelayPort"
        $record.OriginalV1ConnectedWhileArmed=$record.OriginalV1Packets.TcpCount -gt 0 -and
            $record.OriginalV1Packets.UdpCount -gt 0 -and $record.OriginalV1Relay -ceq 'Echo'
        $record.OldConnected=$record.OriginalV1ConnectedWhileArmed
        if(-not $record.OriginalV1ConnectedWhileArmed){throw 'The future deny affected the distinct installed v1.'}

        $child=Start-GuardNativeStoreUpgradeTrigger $scope $DirectPort $RelayPort
        if(-not $child.Process.WaitForExit(30000)){throw 'The fresh package did not report its first real activation.'}
        $record.First=Read-GuardNativeStoreUpgradeTrigger $child
        Stop-GuardDailyChild $child
        $child=$null
        $record.FirstPackets=Read-DirectPackets
        $record.FirstTcpBlocked=$record.FirstPackets.TcpCount -eq 0
        $record.FirstUdpBlocked=$record.FirstPackets.UdpCount -eq 0
        $record.FirstRelayBlocked=$record.First.RelayResult -ceq 'Unavailable'
        $registered=@(Get-AppxPackage -Name $ownedName | Where-Object Name -CEQ $ownedName)
        if($registered.Count -ne 1 -or $registered[0].PackageFullName -cne $fullName -or
            $registered[0].PackageFamilyName -cne $family -or $registered[0].PublisherId -cne $issuer -or
            $registered[0].InstallLocation -ine $registeredFutureRoot -or
            (Get-GuardStorePhysicalPackageRoot $registered[0].InstallLocation) -ine $futureRoot -or
            (Get-GuardStorePhysicalImage $registeredFutureRoot $futureRoot (Join-Path $registeredFutureRoot 'fixture-desktop.exe')) -ine $future){
            throw 'The newly activated package is not the independently derived registration.'
        }
        [ClaudeGuard.Network.GuardPolicy]::VerifyStorePathIdentity($future,$entry.Journal.Device)
        $record.NativeIdentityMatched=(Get-FileHash -LiteralPath $future).Hash -ceq (Get-FileHash -LiteralPath $packed.Image).Hash
        $record.RealPackageFirstActivation=$record.NativeIdentityMatched -and $record.First.Package -ceq $fullName -and
            $record.First.Pid -gt 0 -and (Read-DailyRevisionUtc $record.RulesUtc) -le (Read-DailyRevisionUtc $record.First.InstallStartedUtc) -and
            (Read-DailyRevisionUtc $record.First.InstallStartedUtc) -le (Read-DailyRevisionUtc $record.First.AddReturnedUtc) -and
            (Read-DailyRevisionUtc $record.First.AddReturnedUtc) -le (Read-DailyRevisionUtc $record.First.ActivationCalledUtc) -and
            (Read-DailyRevisionUtc $record.First.ActivationCalledUtc) -le (Read-DailyRevisionUtc $record.First.FirstProcessUtc) -and
            (Read-DailyRevisionUtc $record.First.FirstProcessUtc) -le (Read-DailyRevisionUtc $record.First.FirstTcpUdpUtc) -and
            (Read-DailyRevisionUtc $record.First.FirstTcpUdpUtc) -le (Read-DailyRevisionUtc $record.First.FirstRelayUtc)
        if(-not ($record.RealPackageFirstActivation -and $record.FirstTcpBlocked -and $record.FirstUdpBlocked -and $record.FirstRelayBlocked)){
            throw 'The first real Store activation did not prove exact-path blocking of TCP, UDP and relay connections.'
        }

        Stop-GuardNativeStorePathBlocks $entry
        $record.RuleRemovalReadback=$entry.Journal.Removed -eq $true
        $record.Unblocked=Invoke-GuardNativeStoreUpgradeWithoutPrestage $scope $DirectPort $RelayPort
        $record.UnblockedPackets=Read-DirectPackets
        $same=@(Get-AppxPackage -Name $ownedName | Where-Object Name -CEQ $ownedName)
        $record.SameRegisteredPackageUnblocked=$same.Count -eq 1 -and $same[0].PackageFullName -ceq $fullName -and
            $same[0].InstallLocation -ieq $registeredFutureRoot -and (Get-GuardStorePhysicalPackageRoot $same[0].InstallLocation) -ieq $futureRoot -and
            $record.Unblocked.Package -ceq $fullName -and $record.Unblocked.RelayResult -ceq 'Echo' -and
            $record.UnblockedPackets.TcpCount -gt 0 -and $record.UnblockedPackets.UdpCount -gt 0
        $record.RollbackRestored=$record.RuleRemovalReadback -and $record.SameRegisteredPackageUnblocked
        if(-not $record.RollbackRestored){throw 'Removing only the independent future deny did not restore the same registered v2.'}
        $record.ManualExactPathAttribution=$true
    }catch{
        $record.Error=$_.Exception.Message
        $record.ErrorLine=$_.InvocationInfo.ScriptLineNumber
        $record.ErrorSource=$_.InvocationInfo.ScriptName
        throw
    }finally{
        try{
            try{Stop-GuardDailyChild $child}
            finally{
                if($entry){
                    Stop-GuardNativeStorePathBlocks $entry
                    $record.RuleRemovalReadback=$entry.Journal.Removed -eq $true
                }
            }
        }finally{
            try{
                if($ownedName -and $scope){
                    $cleanup=@(Get-AppxPackage -Name $ownedName -AllUsers | Where-Object Name -CEQ $ownedName)
                    if(@($cleanup | Where-Object PackageFullName -CNE $scope.Package).Count){
                        throw 'Unexpected identity in the independent fixture family. No packages were removed.'
                    }
                    foreach($pkg in $cleanup){Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers}
                    $record.PackageRemovalReadback=@(Get-AppxPackage -Name $ownedName -AllUsers |
                        Where-Object Name -CEQ $ownedName).Count -eq 0
                    if(-not $record.PackageRemovalReadback){throw 'The isolated Store registration remains after cleanup.'}
                }
            }finally{
                $record.IndependentCleanupVerified=$record.RuleRemovalReadback -and $record.PackageRemovalReadback
                $record.Passed=$record.ManualExactPathAttribution -and $record.IndependentCleanupVerified -and -not $record.Error
                Save-GuardAdministratorJson $receipt $record
            }
        }
    }
    [pscustomobject]$record
}
