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
    if($Message -match 'does not match the observed country'){return '所选时区和实测出口国家不一致。请选择对应时区，或保留当前时区。'}
    if($Message -match 'time zone changed after the preview'){return 'Windows 时区已变更。请重新生成预览并确认。'}
    if($Message -match 'time zone|country|region'){return '时区预览已失效或 Windows 未能应用它。请重新选择并试测。'}
    if($Message -match 'Sandboxie protection|firewall scope|firewall plan|firewall policy|readback'){return 'Sandboxie 隔离范围或 Windows 防火墙规则未通过核对。'}
    if($Message -match 'publish fresh, continuous|exit and firewall proofs'){return '在规定时间内没有完成防护验证。'}
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
        Checks=@(Get-GuardWindowChecks $snapshot);LastStop=$lastStop;LastWindowError=(Get-GuardWindowLastError)
        Receipt=$(if($snapshot.Receipt){ConvertTo-GuardWindowResult $snapshot.Receipt})
    }
}

function Clear-GuardWindowPreview {
    if($script:GuardWindowProfile){$script:GuardWindowProfile.Password.Dispose()}
    $script:GuardWindowProfile=$null
    $script:GuardWindowProof=$null
    $script:GuardWindowRegionPreview=$null
    @{}
}

function Get-GuardWindowProbe([string]$Node,[Threading.CancellationToken]$Token){
    $null=Clear-GuardWindowPreview
    if([string]::IsNullOrWhiteSpace($Node) -or $Node.Length -gt 4096){
        return @{Ok=$false;ErrorCode='InvalidNode';Message=(Get-GuardWindowError '' 'InvalidNode')}
    }
    $profile=$null
    try{
        try{$profile=New-GuardNodeProfile -Text $Node}catch{
            return @{Ok=$false;ErrorCode='InvalidNode';Message=(Get-GuardWindowError '' 'InvalidNode')}
        }finally{$Node=$null}
        $proof=Get-GuardSettingsNodePreview $script:GuardWindowStage $profile $Token
        if(-not $proof.Passed){return @{Ok=$false;ErrorCode=$proof.ErrorCode;Message=(Get-GuardWindowError '' $proof.ErrorCode)}}
        Assert-GuardSettingsPreview $profile $proof
        $script:GuardWindowProfile=$profile
        $script:GuardWindowProof=$proof
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

function Get-GuardWindowRegion([string]$ZoneId){
    $script:GuardWindowRegionPreview=$null
    $snapshot=Get-GuardWindowSnapshot -ConfigOnly
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
            $script:GuardWindowRegionPreview=@{
                ZoneId=$ZoneId;Plan=$plan;ZoneState=$zoneState;Mode=$snapshot.Mode;Generation=$snapshot.Installed.Generation
            }
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
    $result.Checks=@(Get-GuardWindowChecks $snapshot $candidate)
    $result
}

function ConvertTo-GuardWindowResult($Result,[switch]$Recovery){
    $verified=$Result.Verification
    $restored=$Result.Restored -eq $true
    $success=$Result.Installed -eq $true -or ($Recovery -and $restored)
    $worker=Get-GuardWindowWorkerText $verified.WorkerStatus
    $verification=Get-GuardWindowVerificationText $verified.Status
    $storeFailed=$verified.Status -ceq 'WaitingForStoreWorker' -or
        ($verified.Status -ceq 'Ready' -and $verified.RequiredProofs -eq 6 -and $verified.Proofs -ge 6)
    $failure=if($Result.FailedPhase -ceq 'Verify' -and $storeFailed -and $worker -and $verified.WorkerStatus -cne 'Ready'){$worker+'。'}
        elseif($Result.FailedPhase -ceq 'Verify' -and $verification){$verification}
        elseif($Result.Error){Get-GuardWindowError $Result.Error}
    $message=if($Result.Installed){'本次防护验收通过。请从防护入口手动打开 Claude Desktop。'}
        elseif($Recovery -and $restored){
            if($Result.HadPrior -eq $false){'首次安装已撤回。'}else{'上次变更已恢复。'}
        }elseif($Result.Phase -ceq 'RollbackIncomplete'){'恢复未完成。请先完成恢复，再尝试变更。'}
        elseif($failure){$failure}else{Get-GuardWindowError ''}
    if($restored -and -not $Recovery){
        $message+=if($Result.HadPrior -eq $false){' 首次安装已撤回。'}else{' 原配置已恢复。'}
    }
    $restore=$Result.RestoreVerification
    $details=@(
        if($Result.FailedPhase){
            $phase=Get-GuardWindowPhaseText $Result.FailedPhase
            if($phase){"停止于「$phase」。"}
        }
        if($failure -and -not $message.StartsWith($failure,[StringComparison]::Ordinal)){$failure}
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
    )
    @{
        Success=$success;Restored=$restored;Message=$message;Details=($details -join [Environment]::NewLine)
        GuardedEntry=$Result.GuardedEntry;Phase=$Result.Phase;FailedPhase=$Result.FailedPhase;HadPrior=$Result.HadPrior
        FreshProofs=$verified.Proofs;RequiredProofs=$verified.RequiredProofs;Status=$verified.Status;WorkerStatus=$verified.WorkerStatus
        RestoreProofs=$restore.Proofs;RestoreRequiredProofs=$restore.RequiredProofs;RestoreStatus=$restore.Status
    }
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

function Set-GuardWindowNode([string]$ZoneId){
    try{
        Assert-GuardSettingsPreview $script:GuardWindowProfile $script:GuardWindowProof
        $preview=$script:GuardWindowRegionPreview
        if(-not $preview -or $preview.ZoneId -cne $ZoneId){
            return @{Success=$false;Restored=$false;Message='请查看并确认当前设置预览。'}
        }
        $snapshot=Get-GuardWindowSnapshot -ConfigOnly
        if($snapshot.RecoveryPending){return @{Success=$false;Restored=$false;Message=(Get-GuardWindowError 'pending')}}
        if($snapshot.Mode -cne $preview.Mode -or $snapshot.Installed.Generation -cne $preview.Generation){
            return @{Success=$false;Restored=$false;Message='当前防护配置已变更。请重新生成预览并确认。'}
        }
        if($preview.Plan.ProfileId -cne 'Keep' -and (-not (Test-GuardRegionTimeZone $preview.ZoneState $snapshot.Zone) -or
            $preview.ZoneState.AutomaticTimeZoneEnabled -ne $snapshot.Zone.AutomaticTimeZoneEnabled)){
            return @{Success=$false;Restored=$false;Message=(Get-GuardWindowError 'time zone changed after the preview')}
        }
        $script:GuardWindowRegionPreview=$null
        $result=Invoke-GuardSettingsInstall $script:GuardWindowStage $script:GuardWindowLauncher `
            $script:GuardWindowProfile $script:GuardWindowProof $preview.Plan -ProgressCallback $script:GuardWindowProgressCallback
        $script:GuardWindowLastOperation=$result
        if($result.Installed){$null=Clear-GuardWindowPreview}
        ConvertTo-GuardWindowResult $result
    }catch{@{Success=$false;Restored=$false;Message=(Get-GuardWindowError $_.Exception.Message)}}
}

function Restore-GuardWindow {
    try{
        $result=Invoke-GuardSettingsRecovery -ProgressCallback $script:GuardWindowProgressCallback
        $script:GuardWindowLastOperation=$result
        ConvertTo-GuardWindowResult $result -Recovery
    }catch{@{Success=$false;Restored=$false;Message=(Get-GuardWindowError $_.Exception.Message)}}
}
