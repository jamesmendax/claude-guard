# Fixed operations for the in-process setup runspace. No action runs on import.
. (Join-Path $PSScriptRoot 'guard-profile-actions.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'package\guard-daily-notifications.ps1')
. (Join-Path $PSScriptRoot 'guard-window-evidence.ps1')
$ErrorActionPreference='Stop'
$script:GuardWindowStage=Split-Path -Parent $PSScriptRoot
$script:GuardWindowLauncher=Join-Path $script:GuardWindowStage 'ClaudeGuardSetup.exe'
$script:GuardWindowInstaller=Join-Path $PSScriptRoot 'install-guard.ps1'
$script:GuardWindowProfile=$null
$script:GuardWindowProof=$null
$script:GuardWindowFromBettbox=$false
$script:GuardWindowCatalog=$null
$script:GuardWindowRegionPreview=$null
$script:GuardWindowLastOperation=$null
$progressDelegate=$GuardWindowProgress
$script:GuardWindowProgressCallback={
    param($Progress)
    $progressDelegate.Invoke([string]$Progress.Phase,[int]$Progress.Proofs,[int]$Progress.RequiredProofs,
        [string]$Progress.Status,[string]$Progress.WorkerStatus,[int]$Progress.ElapsedSeconds,[int]$Progress.TimeoutSeconds)
}.GetNewClosure()

function Get-GuardWindowError([string]$Message,[string]$Code){
    if($Code -ceq 'ProbeCancelled'){return '试测已取消。'}
    if($Code -ceq 'ProbeTimedOut'){return '出口查询超时。确认 Bettbox 已连接，再试测一次。'}
    if($Code -ceq 'ProbeExitUnverified'){return '这个节点没有返回可核实的公网 IPv4。请核对链接和 Bettbox 连接。'}
    if($Code -ceq 'InvalidNode'){return '请粘贴一条完整的 VLESS 节点链接。'}
    if($Message -match 'expired|since the exit check|Verify the node'){return '试测已过期或节点已变更，请重新试测。'}
    if($Message -match 'Edge website|Accept-Language'){return '未能核对或应用 Edge 网站语言。请确认 Edge 可用后重新核对。'}
    if($Message -match 'Windows locale'){return '未能核对或应用 Windows 地区、区域格式或首选语言。请重新核对变更。'}
    if($Message -match 'does not match the observed country'){return '所选时区和实测出口国家不一致。请选择对应时区，或保留当前时区。'}
    if($Message -match 'time zone changed after the preview'){return 'Windows 时区已变更。请重新生成预览并确认。'}
    if($Message -match 'time zone|country|region'){return '时区预览已失效或 Windows 未能应用它。请重新选择并试测。'}
    if($Message -match 'Sandboxie protection|firewall scope|firewall plan|firewall policy|readback'){return 'Sandboxie 隔离范围或 Windows 防火墙规则未通过核对。'}
    if($Message -match 'publish fresh, continuous|exit and firewall proofs'){return '在规定时间内没有完成防护验证。'}
    if($Message -match 'current Bettbox selection changed'){return 'Bettbox 节点在核对期间发生变化。请确认当前节点后再试。'}
    if($Message -match 'current Bettbox selection could not be verified'){return '无法确认 Bettbox 当前选中的节点。请在 Bettbox 核对后再试。'}
    if($Message -match 'registered|Store (Desktop|app)|Claude must|protected .*running|close.*desktop|desktop.*(closed|process started)|guarded desktop session'){
        return '请确认已经安装 Microsoft 商店版 Claude Desktop，并手动关闭它，再重试。'
    }
    if($Message -match 'Bettbox|tunnel'){return '请先连接 Bettbox，并确认 TUN 模式已开启。'}
    if($Message -match 'pending|recovery|unfinished'){return '发现上一次未完成的变更。请先恢复该次操作。'}
    if($Message -match 'administrator|permission|access'){return 'Windows 未授予所需权限。请使用安装 Guard 的管理员账户打开。'}
    if($Message -match 'node|VLESS|link|Reality|WebSocket|credential|TLS|IPv4|query parameter' -or $Code){
        return '无法核实这个节点。请核对完整链接后重试。'
    }
    '操作未完成。请检查 Bettbox 连接和安装条件，再重试。'
}

function Get-GuardWindowCatalog {
    if($null -eq $script:GuardWindowCatalog){$script:GuardWindowCatalog=Get-GuardSettingsTimeZones $script:GuardWindowStage}
    $script:GuardWindowCatalog
}

function Get-GuardWindowHome {
    $snapshot=Get-GuardWindowSnapshot
    $catalog=Get-GuardWindowCatalog
    $zones=@(
        @{Id='Automatic';Label='根据出口国家建议'}
        @{Id='Keep';Label='保留当前时区'}
        @{Id='Japan';Label='日本 · 东京'}
        @{Id='UsPacific';Label='美国西部 · 洛杉矶'}
        foreach($zone in $catalog.Items){@{Id=$zone.Id;Label=$zone.Label}}
    )
    $installed=$snapshot.Installed
    $lastStop=try{Get-GuardDailyLastStopView -Status $snapshot.Status}catch{$null}
    if(-not $lastStop){$lastStop=@{HasRecord=$false;ReadState='Unreadable';Summary='暂时无法读取最近停用记录。'}}
    if($lastStop.Source){
        $lastStop.SourceKind=$lastStop.Source
        $lastStop.Source=switch -CaseSensitive ($lastStop.SourceKind){
            'GuardConfirmed' {'Guard 停用回执'}
            'LauncherObserved' {'防护入口记录'}
            default {'Guard 记录'}
        }
    }
    $message=if($snapshot.RecoveryPending){'发现上一次未完成的变更。请先完成恢复。'}
        elseif($snapshot.Mode -ceq 'Update'){Get-GuardWindowAdmissionText $snapshot.Status}
    @{
        Mode=$snapshot.Mode;RecoveryPending=$snapshot.RecoveryPending;Ready=($snapshot.Status.CanLaunch -eq $true)
        ExitIpv4=$snapshot.ExitIpv4;GuardedEntry=$snapshot.GuardedEntry;StatusMessage=$message
        NodeLabel=$(if($installed.ProxyMode -ceq 'Manual'){'已保存的节点'}elseif($installed){'当前 Guard 节点'})
        TimeZone=(Get-GuardWindowTimeZone $snapshot.Zone.Id).DisplayName;Zones=$zones
        WindowsHomeRegion=$snapshot.WindowsLocale.CountryCode;WindowsRegionalFormat=$snapshot.WindowsLocale.LocaleName
        WindowsPreferredLanguages=(@($snapshot.WindowsLocale.Languages | ForEach-Object LanguageTag) -join ', ')
        EdgePreferredLanguages=[string]$snapshot.BrowserLocale.AcceptLanguages
        Checks=@(Get-GuardWindowChecks $snapshot);LastStop=$lastStop;LastWindowError=(Get-GuardWindowLastError)
        Receipt=$(if($snapshot.Receipt){ConvertTo-GuardWindowResult $snapshot.Receipt})
    }
}

function Clear-GuardWindowPreview {
    if($script:GuardWindowProfile){$script:GuardWindowProfile.Password.Dispose()}
    $script:GuardWindowProfile=$null
    $script:GuardWindowProof=$null
    $script:GuardWindowFromBettbox=$false
    $script:GuardWindowRegionPreview=$null
    @{}
}

function Get-GuardWindowProbe([string]$Node,[Threading.CancellationToken]$Token,[bool]$CurrentBettbox){
    $null=Clear-GuardWindowPreview
    if(-not $CurrentBettbox -and ([string]::IsNullOrWhiteSpace($Node) -or $Node.Length -gt 4096)){
        return @{Ok=$false;ErrorCode='InvalidNode';Message=(Get-GuardWindowError '' 'InvalidNode')}
    }
    $profile=$null
    try{
        if($CurrentBettbox){$profile=Get-GuardCurrentBettboxProfile}
        else{
            try{$profile=New-GuardNodeProfile -Text $Node}catch{
                return @{Ok=$false;ErrorCode='InvalidNode';Message=(Get-GuardWindowError '' 'InvalidNode')}
            }finally{$Node=$null}
        }
        $proof=Get-GuardSettingsNodePreview $script:GuardWindowStage $profile $Token
        if(-not $proof.Passed){return @{Ok=$false;ErrorCode=$proof.ErrorCode;Message=(Get-GuardWindowError '' $proof.ErrorCode)}}
        Assert-GuardSettingsPreview $profile $proof
        $script:GuardWindowProfile=$profile
        $script:GuardWindowProof=$proof
        $script:GuardWindowFromBettbox=$CurrentBettbox
        $profile=$null
        $result=Get-GuardWindowProofTimes $proof
        $result.Ok=$true
        $result.ExitIpv4=$proof.ExitIpv4
        $result.CountryCode=$proof.CountryCode
        $result
    }catch{@{Ok=$false;Message=(Get-GuardWindowError $_.Exception.Message)}}
    finally{
        if($profile){$profile.Password.Dispose()}
        $Error.Clear()
    }
}

function Get-GuardWindowProofTimes($Proof){
    $checked=[datetimeoffset]::Parse($Proof.CheckedUtc).ToUniversalTime()
    @{
        CheckedUtc=$checked.UtcDateTime.ToString('o');ExpiresUtc=$checked.AddMinutes(5).UtcDateTime.ToString('o')
    }
}

function New-GuardWindowBrowserTarget($LocaleTarget,$State,$Plan){
    $language=if($Plan.PrimaryLanguage){$Plan.PrimaryLanguage}else{
        try{Resolve-GuardEdgeLanguage $LocaleTarget.LanguageTag @(([string]$State.AcceptLanguages).Split(','))}
        catch{$LocaleTarget.LanguageTag}
    }
    @{PrimaryLanguage=$language;Profile=$(if($Plan.Profile){$Plan.Profile}else{$State.Profile})}
}

function Get-GuardWindowRegion([string]$ZoneId,[string]$LocaleName){
    $script:GuardWindowRegionPreview=$null
    $snapshot=Get-GuardWindowSnapshot -ConfigOnly -ReadLocales
    $result=@{RequiresChoice=$true}
    $candidate=@{RequiresChoice=$true}
    try{
        Assert-GuardSettingsPreview $script:GuardWindowProfile $script:GuardWindowProof
        $proof=$script:GuardWindowProof
        $candidate.Proof=$proof
        $result=Get-GuardWindowProofTimes $proof
        $result.RequiresChoice=$true
        $result.ExitIpv4=$proof.ExitIpv4
        $result.CountryCode=$proof.CountryCode
        if($snapshot.Installed.RouteHash -cmatch '\A[A-F0-9]{64}\z' -and $snapshot.Installed.Port -ge 1024 -and $snapshot.Installed.Port -lt 49152){
            $candidate.SameRoute=(Get-GuardNodeProfileRoute $script:GuardWindowProfile $snapshot.Installed.Port).Hash -ceq $snapshot.Installed.RouteHash
        }
        $choice=Get-GuardSettingsRegionChoice (Get-GuardWindowCatalog) $ZoneId $proof.CountryCode
        if($choice.RequiresChoice){
            $candidate.ZoneStatus='choice'
            $result.Message=if($choice.TimeZoneCount -gt 1){'出口国家有多个时区。请选择城市，或保留当前时区。'}
                else{'本次查询没有确定时区。请选择城市，或保留当前时区。'}
        }else{
            $zoneState=$snapshot.Zone
            $plan=New-GuardRegionProfilePlan -ProfileId $choice.Id -ObservedCountryCode $proof.CountryCode `
                -Operations @{Read={$zoneState}.GetNewClosure()}
            $result.TimeZone=if($choice.Id -ceq 'Keep'){'保留当前时区'}elseif($choice.Id -ceq 'Japan'){'日本 · 东京'}
                elseif($choice.Id -ceq 'UsPacific'){'美国西部 · 洛杉矶'}else{(Get-GuardWindowTimeZone $choice.TimeZoneId).DisplayName}
            $result.ZoneId=$choice.Id
            $result.RequiresChoice=$false
            if($plan.AutomaticTimeZoneEnabled -eq $true -and $plan.Changes.Count){
                $result.Message='Windows 自动时区已开启，系统稍后可能自行调整。'
            }
            $candidate.Plan=$plan
            $candidate.TimeZone=$result.TimeZone
            $candidate.RequiresChoice=$false
        }
    }catch{
        $result.Message=Get-GuardWindowError $_.Exception.Message
        if($candidate.Proof){
            $candidate.ZoneStatus='blocked'
            $candidate.CountryMismatch=$_.Exception.Message -match 'does not match the observed country'
        }else{
            $candidate.ZoneStatus='pending'
            $candidate.ProofStatus=if($script:GuardWindowProof){'stale'}else{'pending'}
            if(-not $script:GuardWindowProof){$result.Message='请先试测选定节点。'}
        }
    }
    $candidate.Message=$result.Message
    if($candidate.Proof){
        if($candidate.Proof.CountryCode -cnotmatch '\A[A-Z]{2}\z'){
            $candidate.LocaleStatus='blocked'
            $candidate.LocaleMessage='本次试测只确认了 IPv4。请取得出口国家后，再应用地区和语言。'
        }else{
            try{
                $target=Get-GuardNodeLocaleTarget -CountryCode $candidate.Proof.CountryCode -LocaleName $LocaleName
                if(@($target.Choices).Count -gt 1){$result.LocaleChoices=@($target.Choices)}
                if($target.RequiresChoice){
                    $candidate.LocaleStatus='choice'
                    $candidate.LocaleMessage='这个国家有多个可用的语言和区域格式，请选择一项。'
                }else{
                    $candidate.LocaleTarget=$target
                    try{$candidate.WindowsLocalePlan=New-GuardWindowsLocalePlan -Target $target -State $snapshot.WindowsLocale}
                    catch{$candidate.LocaleMessage='无法读取或使用 Windows 地区、区域格式和首选语言。'}
                    try{
                        $candidate.BrowserLocalePlan=New-GuardBrowserLanguagePlan -Target $target.LanguageTag -State $snapshot.BrowserLocale
                        if((Get-GuardBrowserLanguageApplyMode -Plan $candidate.BrowserLocalePlan) -ceq 'ManualRequired'){
                            $candidate.BrowserMessage='Edge 正在使用。Guard 可以先完成其余设置，稍后在结果页手动调整 Edge 网站语言。'
                        }
                    }
                    catch{
                        $candidate.BrowserMessage=if($_.Exception.Message -match 'selected website language is not supported'){
                            'Guard 无法自动设置此 Edge 网站语言。您可以在 Edge 设置中手动选择。'
                        }else{'当前 Edge 用户配置需要手动调整网站语言。其余设置仍可应用。'}
                    }
                    $candidate.BrowserTarget=New-GuardWindowBrowserTarget $target $snapshot.BrowserLocale $candidate.BrowserLocalePlan
                }
            }catch{
                $candidate.LocaleStatus='blocked'
                $candidate.LocaleMessage='无法为本次出口国家确定可用的 Windows 地区和语言。'
            }
        }
        $result.Message=(@($result.Message,$candidate.LocaleMessage,$candidate.BrowserMessage) | Where-Object {$_}) -join [Environment]::NewLine
        if($candidate.Plan -and $candidate.WindowsLocalePlan){
            $script:GuardWindowRegionPreview=@{
                ZoneId=$ZoneId;Plan=$candidate.Plan;ZoneState=$zoneState;Mode=$snapshot.Mode;Generation=$snapshot.Installed.Generation
                LocaleName=$LocaleName;WindowsLocalePlan=$candidate.WindowsLocalePlan;BrowserLocalePlan=$candidate.BrowserLocalePlan
                BrowserTarget=$candidate.BrowserTarget
            }
        }
    }
    $result.Checks=@(Get-GuardWindowChecks $snapshot $candidate)
    $result
}

function ConvertTo-GuardWindowResult($Result,[switch]$Recovery,[string]$SelectionError){
    $verified=$Result.Verification
    $restored=$Result.Restored -eq $true
    $restoredClosed=$restored -and $Result.RestoredClosed -eq $true
    $success=$Result.Installed -eq $true -or ($Recovery -and $restored)
    $waitingBrowser=$Result.Installed -eq $true -and $Result.WebsiteStatus -ceq 'AwaitingBrowser'
    $windowsLanguageStatus=$Result.LocaleVerification.WindowsLanguageStatus
    $waitingWindows=$Result.Installed -eq $true -and $windowsLanguageStatus -ceq 'ManualRequired'
    $worker=Get-GuardWindowWorkerText $verified.WorkerStatus
    $verification=Get-GuardWindowVerificationText $verified.Status
    $storeFailed=$verified.Status -ceq 'WaitingForStoreWorker' -or
        ($verified.Status -ceq 'Ready' -and $verified.RequiredProofs -eq 6 -and $verified.Proofs -ge 6)
    $failure=if($Result.FailedPhase -ceq 'Verify' -and $storeFailed -and $worker -and $verified.WorkerStatus -cne 'Ready'){$worker+'。'}
        elseif($Result.FailedPhase -ceq 'Verify' -and $verification){$verification}
        elseif($Result.Error){Get-GuardWindowError $Result.Error}
    $message=if($waitingWindows -or $waitingBrowser){
        $notes=@('本次防护验收通过。'
            if($waitingWindows){'Windows 首选语言需手动调整。请打开「Windows 首选语言」，把目标语言移到首位。'}
            if($waitingBrowser){
                if($Result.BrowserStatus -ceq 'ManualRequired'){'请手动调整 Edge 网站首选语言，再核对网站实际收到的语言。'}
                else{'Edge 首选语言已读回，网站实际收到的语言仍待核对。'}
            }
        )
        $notes -join [Environment]::NewLine
    }elseif($Result.Installed){'本次防护验收通过。请从防护入口手动打开 Claude Desktop。'}
        elseif($Recovery -and $restored){
            if($restoredClosed){'上一次配置已恢复，Guard 联网仍关闭。'}
            elseif($Result.HadPrior -eq $false){'首次安装已撤回。'}else{'上次变更已恢复。'}
        }elseif($Result.Phase -ceq 'RollbackIncomplete'){'恢复未完成。请先完成恢复，再尝试变更。'}
        elseif($failure){$failure}else{Get-GuardWindowError ''}
    if($restored -and -not $Recovery){
        $message+=if($restoredClosed){' 原配置已恢复，Guard 联网仍关闭。'}
            elseif($Result.HadPrior -eq $false){' 首次安装已撤回。'}else{' 原配置已恢复。'}
    }
    if($SelectionError -and -not $success){$message=(Get-GuardWindowError $SelectionError)+' '+$message}
    $restore=$Result.RestoreVerification
    $localeFailure=Get-GuardWindowLocaleFailureText $Result.LocaleFailure
    $manualKeys=@(
        if($waitingWindows){'windows-preferred-languages'}
        if($waitingBrowser){'edge-website-languages'}
        if(-not $success -and -not $Recovery){
        if($SelectionError){'node'}
        if($localeFailure){
            switch -CaseSensitive ($Result.LocaleFailure){
                'WindowsTimeZone' {'windows-zone'}
                'WindowsHomeLocation' {'windows-home-region'}
                {$_.StartsWith('WindowsRegionalFormat') -or $_ -ceq 'WindowsCultureFromLanguageListOptOut'} {'windows-regional-format'}
                {$_ -cin 'WindowsLanguages','WindowsUiLanguageOverride','WindowsInputMethodOverride'} {'windows-preferred-languages'}
                {$_ -cin 'WindowsPreviewChanged','WindowsReadback'} {'windows-home-region';'windows-regional-format';'windows-preferred-languages'}
                {$_ -clike 'Edge*'} {'edge-website-languages'}
            }
        }elseif($Result.Error -match 'time zone'){'windows-zone'}
        elseif($Result.FailedPhase -ceq 'Verify' -and -not $storeFailed -and $verified.Proofs -lt 6){'allowed-ip'}
        }
    )
    $manualTargets=@{}
    if($waitingWindows){
        $language=$Result.LocaleVerification.ExpectedWindowsLanguage
        $manualTargets['windows-preferred-languages']=@{Expected=$language;VerificationTarget=$language
            Current=(@($Result.LocaleVerification.PreferredLanguages) -join ', ')}
    }
    if($waitingBrowser){
        $language=$Result.LocaleVerification.ExpectedBrowserLanguage
        $manualTargets['edge-website-languages']=@{Expected=$language;VerificationTarget=$language}
    }
    $siteLanguage=if($Result.Installed -eq $true -and [string]$Result.SiteAcceptLanguage -cmatch '\A[A-Za-z0-9,;= .\-]{1,512}\z'){
        [string]$Result.SiteAcceptLanguage
    }
    $details=@(
        if($Result.FailedPhase){
            $phase=Get-GuardWindowPhaseText $Result.FailedPhase
            if($phase){"停止于「$phase」。"}
        }
        if($failure -and -not $message.StartsWith($failure,[StringComparison]::Ordinal)){$failure}
        if($localeFailure){$localeFailure}
        if($verified.RequiredProofs -eq 6 -and $null -ne $verified.Proofs -and [int]$verified.Proofs -ge 0){
            "变更验收记录 $($verified.Proofs) / 6 份连续新结果。"
            if($worker -and $failure -ne ($worker+'。')){$worker+'。'}
        }
        if($restore.RequiredProofs -eq 2 -and $null -ne $restore.Proofs -and [int]$restore.Proofs -ge 0){
            "恢复验收记录 $($restore.Proofs) / 2 份连续新结果。本次恢复未验收商店监听。"
        }
        if($Result.RestoreError){
            $restoreFailure=Get-GuardWindowVerificationText $restore.Status
            if($restoreFailure){$restoreFailure}else{Get-GuardWindowError $Result.RestoreError}
        }
        if($restored -and $Result.LocaleRollback -ceq 'PreservedManualChange'){'部分 Windows 设置与备份不同，恢复时保留了当前值。'}
    )
    @{
        Success=$success;Restored=$restored;RestoredClosed=$restoredClosed;Message=$message;Details=($details -join [Environment]::NewLine)
        GuardedEntry=$Result.GuardedEntry;Phase=$Result.Phase;FailedPhase=$Result.FailedPhase;HadPrior=$Result.HadPrior
        FreshProofs=$verified.Proofs;RequiredProofs=$verified.RequiredProofs;Status=$verified.Status;WorkerStatus=$verified.WorkerStatus
        RestoreProofs=$restore.Proofs;RestoreRequiredProofs=$restore.RequiredProofs;RestoreStatus=$restore.Status
        SiteAcceptLanguage=$siteLanguage;LocaleVerification=$Result.LocaleVerification;Operation=$Result.Operation
        BrowserStatus=$Result.BrowserStatus;WebsiteStatus=$Result.WebsiteStatus;WindowsLanguageStatus=$windowsLanguageStatus
        AllSettingsVerified=($Result.AllSettingsVerified -eq $true -and -not $waitingWindows)
        ManualKeys=$manualKeys;ManualReason=$(if($localeFailure){$localeFailure}else{$failure})
        ManualTargets=$manualTargets
    }
}

function New-GuardWindowManualFailure([string]$Message,[string[]]$Keys,[hashtable]$Targets){
    @{Success=$false;Restored=$false;Message=$Message;ManualKeys=$Keys;ManualReason=$Message;ManualTargets=$Targets}
}

function Save-GuardWindowWebsiteReadback([string]$Operation,[string]$Target,$Plan,[string]$Header){
    if($Operation -cnotmatch '\A[a-f0-9]{32}\z' -or $Target -cnotmatch '\A[A-Za-z0-9-]{1,45}\z' -or
        $Plan.Profile -cnotmatch '\A(?:Default|Profile [1-9][0-9]*)\z' -or $Header -cnotmatch '\A[A-Za-z0-9,;= .\-]{1,512}\z'){
        return $false
    }
    $mutex=[Threading.Mutex]::new($false,'Global\ClaudeVPNGuard_ReleaseInstall')
    $held=$false
    try{
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held -or [IO.File]::Exists((Get-GuardDataPath 'release-install-pending.json')) -or
            [IO.File]::Exists((Get-GuardDataPath 'daily-package-pending.json'))){return $false}
        $installed=Read-GuardDailyRecord 'daily-provisioned.json'
        if($installed.Generation -cnotmatch '\A[A-F0-9]{64}\z' -or
            $installed.LaunchUserSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){return $false}
        $operationFolder=Join-Path $script:GuardWindowStage ('operations\'+$Operation)
        Assert-GuardDailyStatePath $script:GuardWindowStage
        Assert-GuardDailyStatePath (Split-Path -Parent $operationFolder)
        Assert-GuardDailyStatePath $operationFolder
        $latest=Read-GuardDailyJsonFile (Join-Path $script:GuardWindowStage 'install-result.json') -VerifyStatePath
        $saved=Read-GuardDailyJsonFile (Join-Path $operationFolder 'result.json') -VerifyStatePath
        foreach($receipt in $latest,$saved){
            if($receipt.Installed -ne $true -or $receipt.Operation -cne $Operation -or
                $receipt.Generation -cne $installed.Generation -or $receipt.WebsiteStatus -cne 'AwaitingBrowser' -or
                $receipt.LocaleVerification.BrowserProfile -cne $Plan.Profile -or
                $receipt.LocaleVerification.ExpectedBrowserLanguage -cne $Target){return $false}
        }
        $current=Get-GuardBrowserLanguageState
        if($current.Available -ne $true -or $current.Profile -cne $Plan.Profile -or $current.Executable -ine $Plan.Executable -or
            ([string]$current.AcceptLanguages).Split(',')[0] -ine $Plan.PrimaryLanguage){return $false}
        Save-GuardAdministratorJson (Join-Path $operationFolder 'website-readback.json') ([pscustomobject]@{
            Version=1;Operation=$Operation;Generation=$installed.Generation;Profile=$Plan.Profile;PrimaryLanguage=$Target
            SiteAcceptLanguage=$Header;CheckedUtc=[datetime]::UtcNow.ToString('o')
        })
        $true
    }catch{$false}finally{
        if($held){$mutex.ReleaseMutex()}
        $mutex.Dispose()
    }
}

function Get-GuardWindowManualCheck([string]$Setting,[string]$Target,[bool]$ConfirmEdge,[string]$Operation){
    if([string]::IsNullOrWhiteSpace($Target)){
        return @{Verified=$false;Message='请先回到节点设置试测出口，并在变更清单中确认目标。'}
    }
    try{
        $verified=$false
        if($Setting -ceq 'windows-zone'){
            $state=Get-GuardWindowRegionState
            $current=(Get-GuardWindowTimeZone $state.Id).DisplayName
            $verified=$state.Id -ceq $Target
        }elseif($Setting -ceq 'edge-website-languages'){
            $state=Get-GuardBrowserLanguageState
            $current=[string]$state.AcceptLanguages
            if(-not $current){return @{Verified=$false;Message='暂时无法读取 Edge 网站首选语言。'}}
            $expected=try{Resolve-GuardEdgeLanguage $Target @($current.Split(','))}catch{$Target}
            if($current.Split(',')[0] -ieq $expected){
                if($state.Available -eq $true){
                    $plan=@{Browser='Edge';Executable=$state.Executable;Profile=$state.Profile;PrimaryLanguage=$expected;After=$state}
                    try{
                        $header=if($ConfirmEdge){Confirm-GuardBrowserSiteLanguage -Plan $plan}else{Test-GuardBrowserSiteLanguageQuiet -Plan $plan}
                    }catch{
                        if($ConfirmEdge -or $_.Exception.Message -cne 'A recent website-language check from this Edge profile is required.'){
                            $code=Get-GuardSettingsBrowserFailure $_.Exception 'EdgeSiteReadback'
                            return @{Verified=$false;Current=$current;Message=(Get-GuardWindowLocaleFailureText $code)}
                        }
                    }
                    if($header -is [string] -and $header -cmatch '\A[A-Za-z0-9,;= .\-]{1,512}\z'){
                        $updated=$ConfirmEdge -and $Operation -and (Save-GuardWindowWebsiteReadback $Operation $Target $plan $header)
                        $message="网站收到的 Accept-Language：$header"
                        if($ConfirmEdge -and $Operation -and -not $updated){$message+='。本次核对未写入原操作回执。'}
                        return @{Verified=$true;Current=$current;Message=$message;OperationVerified=[bool]$updated;SiteAcceptLanguage=$header}
                    }
                }
                return @{Verified=$false;Current=$current;Message='读取到的 Edge 首选网站语言已匹配目标，网站实际收到的语言尚未核实。'}
            }
        }elseif($Setting -cin 'windows-home-region','windows-regional-format','windows-preferred-languages'){
            $state=Get-GuardWindowsLocaleState
            switch -CaseSensitive ($Setting){
                'windows-home-region' {$current=$state.CountryCode;$verified=$current -ceq $Target}
                'windows-regional-format' {
                    $current=$state.LocaleName
                    if($state.Format.ShortDate){$current+=" · $($state.Format.ShortDate) $($state.Format.ShortTime)"}
                    if($state.LocaleName -ceq $Target){
                        $expected=& (New-GuardWindowsLocaleOperations).DefaultFormat $Target
                        $verified=Test-GuardWindowsLocaleSetting $state @{LocaleName=$Target;Format=$expected} 'RegionalFormat'
                    }
                }
                'windows-preferred-languages' {
                    $current=@($state.Languages | ForEach-Object LanguageTag) -join ', '
                    if(Test-GuardWindowsPreferredLanguage $state.Languages[0].LanguageTag $Target){
                        $operations=New-GuardWindowsLocaleOperations
                        $independent=& $operations.ReadIndependentLanguages 0
                        $verified=Test-GuardWindowsIndependentLanguageOrder $independent $state $Target
                    }
                }
            }
        }else{return @{Verified=$false;Message='此设置在节点页核对。'}}
        $message=if($verified){'刚读到的设置与目标一致。'}else{'刚读到的设置与目标还有差异。'}
        @{Verified=$verified;Current=$current;Message=$message}
    }catch{@{Verified=$false;Message='暂时无法读取这项设置。'}}
}

function Update-GuardWindow {
    try{
        $plan=& $script:GuardWindowInstaller -Plan
        if($plan.RecoveryPending){return @{Success=$false;Restored=$false;Message=(Get-GuardWindowError 'pending')}}
        if($plan.Mode -cne 'Update'){return @{Success=$false;Restored=$false;Message='本机尚未安装 Claude Guard，请先完成安装。'}}
        $null=Clear-GuardWindowPreview
        $result=Invoke-GuardSettingsInstall $script:GuardWindowStage $script:GuardWindowLauncher `
            -ProgressCallback $script:GuardWindowProgressCallback
        $script:GuardWindowLastOperation=$result
        ConvertTo-GuardWindowResult $result
    }catch{@{Success=$false;Restored=$false;Message=(Get-GuardWindowError $_.Exception.Message)}}
}

function Add-GuardWindowUserRegionFallback($View,$Result,$Snapshot,[pscredential]$Profile,$Proof){
    if($Result.Installed -ne $false -or $Result.Phase -cne 'Rejected' -or $Result.FailedPhase -cne 'Preflight' -or
        $Result.Error -cne 'Expected one healthy Claude Store package registered for this user.' -or
        $Snapshot.Mode -cne 'Update' -or $Snapshot.RecoveryPending -or $Proof.CountryCode -cne 'JP'){return}
    $installed=$Snapshot.Installed
    if($installed.Version -ne 2 -or $installed.Containment -cne 'Sandboxie' -or
        $installed.LaunchUserSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
        $installed.RouteHash -cnotmatch '\A[A-F0-9]{64}\z' -or $installed.Generation -cnotmatch '\A[A-F0-9]{64}\z' -or
        $installed.Port -lt 1024 -or $installed.Port -ge 49152 -or $installed.ExpectedIpv4 -cne $Proof.ExitIpv4){return}
    try{
        Assert-GuardSettingsPreview $Profile $Proof
        if((Get-GuardNodeProfileRoute $Profile $installed.Port).Hash -cne $installed.RouteHash){return}
        $View.UserRegionCountry=$Proof.CountryCode
        $View.UserRegionIpv4=$Proof.ExitIpv4
    }catch{}
}

function Set-GuardWindowNode([string]$ZoneId,[string]$LocaleName){
    try{
        Assert-GuardSettingsPreview $script:GuardWindowProfile $script:GuardWindowProof
        $preview=$script:GuardWindowRegionPreview
        if(-not $preview -or $preview.ZoneId -cne $ZoneId -or $preview.LocaleName -cne $LocaleName){
            return @{Success=$false;Restored=$false;Message='请查看并确认当前设置预览。'}
        }
        $snapshot=Get-GuardWindowSnapshot -ConfigOnly
        if($snapshot.RecoveryPending){return @{Success=$false;Restored=$false;Message=(Get-GuardWindowError 'pending')}}
        if($snapshot.Mode -cne $preview.Mode -or $snapshot.Installed.Generation -cne $preview.Generation){
            return @{Success=$false;Restored=$false;Message='当前防护配置已变更。请重新生成预览并确认。'}
        }
        if($preview.Plan.ProfileId -cne 'Keep' -and (-not (Test-GuardRegionTimeZone $preview.ZoneState $snapshot.Zone) -or
            $preview.ZoneState.AutomaticTimeZoneEnabled -ne $snapshot.Zone.AutomaticTimeZoneEnabled)){
            return (New-GuardWindowManualFailure (Get-GuardWindowError 'time zone changed after the preview') @('windows-zone'))
        }
        $script:GuardWindowRegionPreview=$null
        $state=@{SelectionError=$null}
        $options=@{}
        if($snapshot.Mode -ceq 'Update'){$options.RequirePriorGeneration=$preview.Generation}
        if($script:GuardWindowFromBettbox){
            $options.BeforeApply=New-GuardWindowBettboxRecheck $script:GuardWindowProfile $script:GuardWindowProof $state
        }
        $result=Invoke-GuardSettingsInstall $script:GuardWindowStage $script:GuardWindowLauncher `
            $script:GuardWindowProfile $script:GuardWindowProof $preview.Plan -ProgressCallback $script:GuardWindowProgressCallback `
            -WindowsLocalePlan $preview.WindowsLocalePlan -BrowserLocalePlan $preview.BrowserLocalePlan -BrowserTarget $preview.BrowserTarget @options
        $script:GuardWindowLastOperation=$result
        $view=ConvertTo-GuardWindowResult $result -SelectionError $state.SelectionError
        if($result.Installed){$null=Clear-GuardWindowPreview}
        else{Add-GuardWindowUserRegionFallback $view $result $snapshot $script:GuardWindowProfile $script:GuardWindowProof}
        $view
    }catch{@{Success=$false;Restored=$false;Message=(Get-GuardWindowError $_.Exception.Message)}}
}

function New-GuardWindowBettboxRecheck([pscredential]$Profile,$Proof,$State){
    {
        try{Assert-GuardSettingsCurrentBettbox $Profile $Proof}
        catch{$State.SelectionError=$_.Exception.Message;throw}
    }.GetNewClosure()
}

function Set-GuardWindowCurrentNode([string]$CountryCode,[string]$ExitIpv4,[bool]$RetirePrevious){
    $profile=$null
    $manualKeys=@('node')
    $manualTargets=@{node=@{Expected='Bettbox 当前节点'}}
    try{
        if($CountryCode -cnotmatch '\A[A-Z]{2}\z' -or -not (ConvertTo-GuardWindowIpv4 $ExitIpv4)){
            return (New-GuardWindowManualFailure '请提供两位大写国家代码和完整的 IPv4 地址。' $manualKeys $manualTargets)
        }
        $manualTargets['allowed-ip']=@{Expected=$ExitIpv4}
        $snapshot=Get-GuardWindowSnapshot -ConfigOnly
        if($snapshot.RecoveryPending -or [IO.File]::Exists((Get-GuardDataPath 'daily-package-pending.json'))){
            return @{Success=$false;Message=(Get-GuardWindowError 'pending')}
        }
        $installed=$snapshot.Installed
        if($snapshot.Mode -cne 'Update' -or $installed.Version -ne 2 -or $installed.Containment -cne 'Sandboxie' -or
            $installed.Generation -cnotmatch '\A[A-F0-9]{64}\z' -or
            $installed.LaunchUserSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){
            return @{Success=$false;Message='请使用已安装 Claude Guard 的原 Windows 账户打开。'}
        }
        $profile=Get-GuardCurrentBettboxProfile
        $manualKeys=@('allowed-ip')
        $proof=Get-GuardSettingsNodePreview $script:GuardWindowStage $profile ([Threading.CancellationToken]::None)
        if(-not $proof.Passed){return (New-GuardWindowManualFailure (Get-GuardWindowError '' $proof.ErrorCode) $manualKeys $manualTargets)}
        Assert-GuardSettingsPreview $profile $proof
        if($proof.ExitIpv4 -cne $ExitIpv4 -or $proof.CountryCode -cne $CountryCode){
            $manualTargets['allowed-ip'].Current=$proof.ExitIpv4
            return (New-GuardWindowManualFailure "当前节点的实测出口与指定的 $CountryCode $ExitIpv4 不符，或无法核实其国家。" $manualKeys $manualTargets)
        }
        $manualKeys=@('windows-zone')
        $choice=Get-GuardSettingsRegionChoice (Get-GuardWindowCatalog) 'Automatic' $proof.CountryCode
        if($choice.RequiresChoice){
            return (New-GuardWindowManualFailure '此出口国家无法自动确定唯一的 Windows 时区。请在节点设置中选择时区。' $manualKeys $manualTargets)
        }
        $manualTargets['windows-zone']=@{Expected=(Get-GuardWindowTimeZone $choice.TimeZoneId).DisplayName;VerificationTarget=$choice.TimeZoneId}
        $region=New-GuardRegionProfilePlan -ProfileId $choice.Id -ObservedCountryCode $proof.CountryCode `
            -Operations (New-GuardWindowsRegionOperations)
        $manualKeys=@('windows-home-region','windows-regional-format','windows-preferred-languages')
        $manualTargets['windows-home-region']=@{Expected=$CountryCode;VerificationTarget=$CountryCode}
        $target=Get-GuardNodeLocaleTarget -CountryCode $proof.CountryCode
        if($target.RequiresChoice){
            return (New-GuardWindowManualFailure '这个国家有多个可用的语言和区域格式。请在节点设置中选择一项。' $manualKeys $manualTargets)
        }
        $manualTargets['windows-regional-format']=@{Expected=$target.LocaleName;VerificationTarget=$target.LocaleName}
        $manualTargets['windows-preferred-languages']=@{Expected=$target.LanguageTag;VerificationTarget=$target.LanguageTag}
        $windowsLocale=New-GuardWindowsLocalePlan -Target $target -State (Get-GuardWindowsLocaleState)
        $edgeState=try{Get-GuardBrowserLanguageState}catch{}
        $browserLocale=try{New-GuardBrowserLanguagePlan -Target $target.LanguageTag -State $edgeState}catch{}
        $browserTarget=New-GuardWindowBrowserTarget $target $edgeState $browserLocale
        $manualTargets['edge-website-languages']=@{Expected=$browserTarget.PrimaryLanguage;VerificationTarget=$browserTarget.PrimaryLanguage}
        $manualKeys=@()
        $state=@{SelectionError=$null}
        $recheck=New-GuardWindowBettboxRecheck $profile $proof $state
        $result=Invoke-GuardSettingsInstall $script:GuardWindowStage $script:GuardWindowLauncher $profile $proof $region `
            -ProgressCallback $script:GuardWindowProgressCallback -RequirePriorGeneration $installed.Generation -BeforeApply $recheck `
            -WindowsLocalePlan $windowsLocale -BrowserLocalePlan $browserLocale -BrowserTarget $browserTarget
        $script:GuardWindowLastOperation=$result
        $view=ConvertTo-GuardWindowResult $result -SelectionError $state.SelectionError
        foreach($key in $manualTargets.Keys){
            if(-not $view.ManualTargets.ContainsKey($key)){$view.ManualTargets[$key]=$manualTargets[$key]}
        }
        Add-GuardWindowUserRegionFallback $view $result $snapshot $profile $proof
        if($RetirePrevious -and $result.Installed -eq $true -and
            ($result.WebsiteStatus -ceq 'AwaitingBrowser' -or $result.LocaleVerification.WindowsLanguageStatus -ceq 'ManualRequired')){
            $view.Details=(@($view.Details,'仍有语言设置待核对，旧版安装文件暂时保留。') | Where-Object {$_}) -join [Environment]::NewLine
        }elseif($RetirePrevious -and $result.Installed -eq $true){
            $retirement=try{
                & $script:GuardWindowProgressCallback @{Phase='RetirePrevious';Proofs=6;RequiredProofs=6}
                . (Join-Path (Join-Path $script:GuardWindowStage 'release') 'guard-release-retirement.ps1')
                Remove-GuardSupersededSetup -Stage $script:GuardWindowStage -Result $result
            }catch{@{Status='Retained'}}
            $line=switch -CaseSensitive ($retirement.Status){
                'Removed' {'旧版安装文件已清理。'}
                'NoChange' {'没有需要清理的旧版安装文件。'}
                default {'旧版安装文件仍保留。'}
            }
            $view.Details=(@($view.Details,$line) | Where-Object {$_}) -join [Environment]::NewLine
        }
        $view
    }catch{New-GuardWindowManualFailure (Get-GuardWindowError $_.Exception.Message) $manualKeys $manualTargets}
    finally{
        if($profile){$profile.Password.Dispose()}
        $Error.Clear()
    }
}

function Restore-GuardWindow {
    try{
        $result=Invoke-GuardSettingsRecovery -ProgressCallback $script:GuardWindowProgressCallback
        $script:GuardWindowLastOperation=$result
        ConvertTo-GuardWindowResult $result -Recovery
    }catch{@{Success=$false;Restored=$false;Message=(Get-GuardWindowError $_.Exception.Message)}}
}
