# Read-only facts and display rows for the setup window. No probes run here.
function ConvertTo-GuardWindowIpv4($Value){
    $ip=$null
    if($Value -is [string] -and [ipaddress]::TryParse($Value,[ref]$ip) -and
        $ip.AddressFamily -eq 'InterNetwork' -and $ip.ToString() -ceq $Value){$Value}
}

function Get-GuardWindowTimeZone([string]$Id){
    if($Id){try{[TimeZoneInfo]::FindSystemTimeZoneById($Id)}catch{}}
}

function Get-GuardWindowOffset($Zone,$DaylightDisabled,[datetimeoffset]$Now){
    if(-not $Zone){return '未读取'}
    $offset=if($DaylightDisabled -eq $true){$Zone.BaseUtcOffset}
        elseif($DaylightDisabled -eq $false -or -not $Zone.SupportsDaylightSavingTime){$Zone.GetUtcOffset($Now)}
    if($null -eq $offset){return '夏令时设置未读取'}
    $sign=if($offset.TotalMinutes -lt 0){'-'}else{'+'}
    'UTC'+$sign+$offset.Duration().ToString('hh\:mm')
}

function Get-GuardWindowDaylight($Zone,$Disabled){
    if(-not $Zone){return '未读取'}
    if(-not $Zone.SupportsDaylightSavingTime){return '本时区无夏令时'}
    if($Disabled -eq $true){return '已关闭切换'}
    if($Disabled -eq $false){return '按时区规则切换'}
    '开关未读取'
}

function Get-GuardWindowRegionState {
    try{& (New-GuardWindowsRegionOperations).Read}catch{$null}
}

function Get-GuardWindowEntry {
    $target=Get-GuardDataPath 'daily\open-claude-daily.cmd'
    if(-not [IO.File]::Exists($target)){return}
    try{Assert-GuardSandboxieAdministratorPath $target}catch{return}
    foreach($folder in 'DesktopDirectory','CommonDesktopDirectory','CommonPrograms'){
        try{
            $path=[Environment]::GetFolderPath($folder)
            if($path -and (Test-GuardSetupShortcut (Join-Path $path 'Claude Desktop - Guarded.lnk') $target '')){
                if($folder -ceq 'CommonPrograms'){return 'StartMenu'}
                return 'Desktop'
            }
        }catch{}
    }
    'File'
}

function Get-GuardWindowStoreState($Installed,$Status){
    if(-not $Status.SupervisorId -or $Status.Generation -cne $Installed.Generation){return}
    try{
        $store=Read-GuardDailyRecord 'daily-store-inventory.json'
        $worker=$store.Worker
        if($store.Generation -cne $Installed.Generation -or $store.Package -cne $Installed.PackageFullName -or
            $worker.ParentPid -ne $Status.SupervisorId -or $worker.ParentStartedUtc -cne $Status.SupervisorStartUtc){return}
        $published=[datetimeoffset]::Parse($worker.VerifiedUtc)
        $started=[datetimeoffset]::Parse($Status.SupervisorStartUtc)
        if($published -lt $started -or $published -gt [datetimeoffset]::UtcNow){return}
        $process=Get-Process -Id ([int]$worker.Pid) -ErrorAction Stop
        try{
            if($process.ProcessName -cne 'powershell' -or $process.HasExited -or
                $process.StartTime.ToUniversalTime().ToString('o') -cne $worker.StartedUtc){return}
            if($worker.EventLogReadable -ne $true){return 'EventLogUnreadable'}
            if($worker.WatcherSubscribed -ne $true){return 'EventWatcherUnavailable'}
            if($worker.DirectoryWatching -ne $true){return 'DirectoryWatcherUnavailable'}
            'Ready'
        }finally{$process.Dispose()}
    }catch{}
}

function Get-GuardWindowReceipt($Installed,[bool]$RecoveryPending){
    $receipt=$script:GuardWindowLastOperation
    if(-not $receipt){
        try{
            $file=Join-Path $script:GuardWindowStage 'install-result.json'
            Assert-GuardDailyStatePath $script:GuardWindowStage
            $receipt=Read-GuardDailyJsonFile $file -VerifyStatePath
        }catch{return}
    }
    if([string]$receipt.Operation -cnotmatch '\A[a-f0-9]{32}\z'){return}
    if($RecoveryPending){
        try{$pending=Read-GuardDailyRecord 'release-install-pending.json'}catch{return}
        if($pending.Operation -ceq $receipt.Operation){return $receipt}
    }elseif($Installed.Generation -cmatch '\A[A-F0-9]{64}\z'){
        if(($receipt.Installed -eq $true -and $receipt.Generation -ceq $Installed.Generation) -or
            ($receipt.Restored -eq $true -and $receipt.PriorGeneration -ceq $Installed.Generation)){return $receipt}
    }elseif(-not $Installed -and $receipt.HadPrior -eq $false -and $receipt.Restored -eq $true){$receipt}
}

function Get-GuardWindowLastError {
    $name='setup-last-window-error.json'
    try{$null=Get-Item -LiteralPath (Get-GuardDataPath $name) -Force -ErrorAction Stop}
    catch{
        if($_.CategoryInfo.Category -eq 'ObjectNotFound'){return}
        return @{ReadState='Unreadable'}
    }
    try{$record=Read-GuardDailyRecord $name}catch{return @{ReadState='Unreadable'}}
    $when=[datetime]::MinValue
    if($record.Schema -ne 1 -or $record.Component -cne 'GuardSettingsWindow' -or
        [string]$record.HResult -cnotmatch '\A0x[0-9A-Fa-f]{8}\z' -or
        -not [datetime]::TryParseExact([string]$record.TimeUtc,'o',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,[ref]$when) -or
        $when.Kind -ne 'Utc' -or $when -gt [datetime]::UtcNow){return @{ReadState='Unreadable'}}
    $detail=switch -CaseSensitive ($record.Kind){
        'WindowsAccess' {'Windows 拒绝 Guard 设置窗口所需的访问。'}
        'FileAccess' {'Guard 设置窗口无法访问所需的文件。'}
        'WindowsError' {'Guard 设置窗口遇到 Windows 错误。'}
        'RuntimeError' {'Guard 设置窗口遇到运行错误。'}
        default {return @{ReadState='Unreadable'}}
    }
    @{
        HasRecord=$true;ReadState='Readable';TimeUtc=$when.ToString('o');Title='最近一次 Guard 设置窗口错误'
        Detail=$detail;Kind=$record.Kind;HResult=$record.HResult;Component='GuardSettingsWindow';Source='Guard 设置窗口'
    }
}

function Get-GuardWindowPhaseText([string]$Phase){
    switch -CaseSensitive ($Phase){
        'Preparing' {'准备'}
        'Preflight' {'安装条件检查'}
        'Backup' {'保存原配置'}
        'Close' {'关闭旧联网许可'}
        'Install' {'写入配置'}
        'Publish' {'准备防护规则'}
        'Start' {'启动防护'}
        'Verify' {'防护验收'}
        'Commit' {'提交变更'}
        'RollingBack' {'恢复原设置'}
        'Completed' {'变更完成'}
        'RolledBack' {'恢复完成'}
        'RollbackIncomplete' {'恢复未完成'}
        'Rejected' {'变更未执行'}
    }
}

function Get-GuardWindowWorkerText([string]$Code){
    switch -CaseSensitive ($Code){
        'Ready' {'Windows 更新事件和安装目录监听均已验证'}
        'NotRequired' {'本次恢复未验收商店监听'}
        'DirectoryWatcherUnavailable' {'已核对更新事件，未能确认新版安装目录监听'}
        'EventLogUnreadable' {'无法读取 Windows 商店更新事件'}
        'EventWatcherUnavailable' {'无法确认 Windows 商店更新事件监听'}
        'IdentityPending' {'监听记录尚未与当前防护匹配'}
        'ReceiptTimeInvalid' {'监听记录的时间未通过核对'}
        'ProcessUnavailable' {'监听进程未通过核对'}
        'ReceiptUnavailable' {'未读到商店监听记录'}
        'WaitingForController' {'等待防护发布监听记录'}
    }
}

function Get-GuardWindowVerificationText([string]$Code){
    switch -CaseSensitive ($Code){
        'WaitingForGeneration' {'尚未收到与这次变更相符的防护记录。'}
        'WaitingForProof' {'尚未取得有效的出口和联网许可核对结果。'}
        'ProofExpired' {'上一份出口核对在验收完成前已过期。'}
        'ProofInvalid' {'取得的出口核对未通过完整性或时效检查。'}
        'ProofChangedDuringCheck' {'检查过程中出口或联网许可记录发生变化。'}
        'StatusNotReady' {'联网许可读回未能与出口核对结果匹配。'}
        'ReceiptUnavailable' {'尚未读取到可验证的防护记录。'}
    }
}

function Get-GuardWindowAdmissionText($Status){
    if($Status.CanLaunch -eq $true){return '防护已就绪。请从防护入口手动打开 Claude Desktop。'}
    switch -CaseSensitive ($Status.Reason){
        'UpstreamTransportDown' {'专用转发与上游的连接中断。请检查 Bettbox 连接和 TUN 模式。'}
        'ExitChanged' {'实测出口 IPv4 与已允许的出口不同。请核对 Bettbox 连接和选定节点。'}
        'CoverageUnverified' {'应用身份或 Windows 防火墙规则尚未通过核对。'}
        'ProofPending' {'正在重新核对代理出口。'}
        'ExitUnverified' {'尚未取得可用的出口结果。'}
        'HealthLeaseInvalid' {'上一份防火墙联网许可已失效，正在等待新的核对结果。'}
        'ShutdownPending' {'防护正在关闭上一会话。'}
        'RevisionInProgress' {'防护正在变更。'}
        'IsolationActive' {'紧急隔离已开启。'}
        'RelayIdentityChanged' {'专用转发已更换，需重新核对。'}
        'ProxyNotReady' {'专用转发暂不可用。'}
        'NetworkGateClosed' {'防火墙联网许可已关闭。'}
        default {'暂时无法确认防护已就绪。'}
    }
}

function Get-GuardWindowSnapshot([switch]$ConfigOnly){
    $plan=& $script:GuardWindowInstaller -Plan
    $installed=if($plan.Mode -ceq 'Update'){try{Read-GuardDailyRecord 'daily-provisioned.json'}catch{}}
    $status=if(-not $ConfigOnly -and $installed -and -not $plan.RecoveryPending){try{Get-GuardDailyStatus}catch{}}
    if($status.Generation -and $status.Generation -cne $installed.Generation){$status=$null}
    $zone=Get-GuardWindowRegionState
    $entry=if(-not $ConfigOnly -and $installed){Get-GuardWindowEntry}
    @{
        Mode=$plan.Mode;RecoveryPending=($plan.RecoveryPending -eq $true);Installed=$installed;Status=$status;Zone=$zone
        ExitIpv4=(ConvertTo-GuardWindowIpv4 $installed.ExpectedIpv4);GuardedEntry=$entry
        Receipt=$(if(-not $ConfigOnly){Get-GuardWindowReceipt $installed $plan.RecoveryPending})
        Worker=$(if(-not $ConfigOnly -and -not $plan.RecoveryPending){Get-GuardWindowStoreState $installed $status})
        Backup=$(if($installed){Test-GuardDailyBackupLookupEnabled $installed})
    }
}

function New-GuardWindowCheck([string]$Key,[string]$Group,[string]$Label,[string]$Current,
    [string]$Expected,[string]$Status,[string]$Detail,[switch]$Change,[switch]$Blocks){
    @{
        Key=$Key;Group=$Group;Label=$Label;Current=$Current;Expected=$Expected;Status=$Status;Detail=$Detail
        Issue=$Status -cin 'blocked','choice','stale','failed','review','attention','paused'
        Change=($Change.IsPresent -or $Status -cin 'change','applied');Blocks=$Blocks.IsPresent
    }
}

function Get-GuardWindowChecks($Snapshot,$Candidate){
    $isPlan=$null -ne $Candidate
    $proof=$Candidate.Proof
    $region=$Candidate.Plan
    $installed=$Snapshot.Mode -ceq 'Update'
    $status=$Snapshot.Status
    $ready=$status.CanLaunch -eq $true
    $pending=$Snapshot.RecoveryPending
    $receipt=$Snapshot.Receipt
    $restored=$receipt.Restored -eq $true
    $zone=Get-GuardWindowTimeZone $Snapshot.Zone.Id
    $beforeZone=if($zone){$zone.DisplayName}else{'未读取'}
    $afterZone=$beforeZone
    $zoneChange=($null -ne $region -and $region.Changes.Count -gt 0)
    $zoneStatus=if($Candidate.ZoneStatus){$Candidate.ZoneStatus}elseif($zoneChange){'change'}elseif($zone){'kept'}else{'uncollected'}
    $targetZone=$zone
    if($zoneChange){
        $targetZone=Get-GuardWindowTimeZone $region.WindowsTimeZoneId
        $afterZone=$Candidate.TimeZone
    }elseif($isPlan -and $region.ProfileId -ceq 'Keep'){$afterZone='保留当前时区'}
    elseif($isPlan -and $Candidate.RequiresChoice){$afterZone='待选择'}

    $node=if($Snapshot.Installed.ProxyMode -ceq 'Manual'){'已保存的节点'}elseif($Snapshot.Installed){'当前 Guard 节点'}else{'未读取已保存的节点'}
    $expectedNode=$node
    $nodeStatus=if($Snapshot.Installed){'kept'}else{'pending'}
    if($isPlan){
        $expectedNode='本次提交的节点'
        $nodeStatus=if(-not $proof){'pending'}elseif($Candidate.SameRoute -eq $true){'kept'}else{'change'}
    }
    New-GuardWindowCheck 'node' 'settings' 'Guard 选定节点' $node $expectedNode $nodeStatus `
        'Guard 用当前 Windows 账户加密保存选定的节点，供专用转发使用。'

    $allowed=if($Snapshot.ExitIpv4){$Snapshot.ExitIpv4}else{'未读取'}
    $targetIp=if($proof){$proof.ExitIpv4}elseif($isPlan){'由试测确定'}else{$allowed}
    $ipStatus=if($proof -and $Snapshot.ExitIpv4 -cne $proof.ExitIpv4){'change'}elseif($Snapshot.ExitIpv4){'kept'}else{'pending'}
    New-GuardWindowCheck 'allowed-ip' 'settings' '允许的出口 IPv4' $allowed $targetIp $ipStatus `
        '这是 Guard 配置中唯一允许的公网 IPv4。实际出口在防护核对中另行显示。'

    $zoneDetail=if($Candidate.RequiresChoice){$Candidate.Message}else{'时区设置影响整台电脑。选择保留或当前时区时，沿用现有设置。'}
    New-GuardWindowCheck 'windows-zone' 'settings' 'Windows 时区' $beforeZone $afterZone $zoneStatus $zoneDetail `
        -Blocks:($isPlan -and $Candidate.RequiresChoice -and $null -ne $proof)

    $daylightNow=Get-GuardWindowDaylight $zone $Snapshot.Zone.DaylightDisabled
    $daylightThen=if($zoneChange){Get-GuardWindowDaylight $targetZone $false}elseif($Candidate.RequiresChoice){'随所选时区确定'}else{$daylightNow}
    $daylightStatus=if($zoneChange){'follows'}elseif($Candidate.RequiresChoice){'pending'}elseif($daylightNow -in '未读取','开关未读取'){'uncollected'}else{'kept'}
    New-GuardWindowCheck 'daylight' 'settings' '夏令时规则' $daylightNow $daylightThen $daylightStatus `
        '写入新时区时会采用目标时区的夏令时规则。' -Change:$zoneChange
    $auto=$Snapshot.Zone.AutomaticTimeZoneEnabled
    $autoText=if($auto -eq $true){'已开启'}elseif($auto -eq $false){'已关闭'}else{'未读取'}
    $autoStatus=if($auto -eq $true -and $zoneChange){'attention'}elseif($null -eq $auto){'uncollected'}else{'reference'}
    New-GuardWindowCheck 'automatic-zone' 'settings' 'Windows 自动时区' $autoText '沿用 Windows 设置' $autoStatus `
        '开启时，Windows 之后仍可能自行调整时区。'

    if($pending -or $restored){
        $opText=if($pending){'上次操作未完成'}elseif($receipt.HadPrior -eq $false){'首次安装已撤回'}else{'原配置已恢复'}
        $opStatus=if($pending){'blocked'}elseif($receipt.HadPrior -eq $false){'withdrawn'}else{'restored'}
        $opNote=if($pending){'先用现有恢复记录完成恢复。'}else{'恢复时实际核对的结果见防火墙联网许可。'}
        New-GuardWindowCheck 'previous-operation' 'protection' '上次变更' $opText '完成恢复' $opStatus $opNote -Blocks:($pending -and $isPlan)
    }

    $transportDown=$status.Reason -ceq 'UpstreamTransportDown'
    $tunnelText=if($transportDown){'上游连接中断'}elseif($proof){'节点试测已通过隧道'}elseif($ready){'当前专用线路可用'}else{'待核对'}
    $tunnelStatus=if($transportDown){'failed'}elseif($proof -or $ready){'ok'}else{'waiting'}
    New-GuardWindowCheck 'bettbox' 'protection' 'Bettbox 隧道' $tunnelText '已登记的 Bettbox 网卡和路由可用' $tunnelStatus `
        '使用节点时核对 Bettbox 网卡和路由。连接中断时请查看 Bettbox 和 TUN 模式。'
    New-GuardWindowCheck 'store-desktop' 'protection' 'Microsoft 商店版 Claude Desktop' `
        $(if($status.Inventory -ceq 'Verified'){'当前受保护程序身份已核对'}else{'安装时检查'}) '商店版已注册' `
        $(if($status.Inventory -ceq 'Verified'){'ok'}else{'waiting'}) '应用前由安装程序核对商店版注册及受保护程序身份。'
    New-GuardWindowCheck 'closed-desktop' 'protection' 'Claude Desktop 窗口' '应用前检查' '手动关闭所有 Claude Desktop 窗口' 'waiting' `
        '安装、更新和恢复都会检查桌面程序是否已关闭。'

    $relayStatus=if($isPlan){'waiting'}elseif($status.Proxy -ceq 'Ready'){'ok'}elseif($status.Proxy -ceq 'Down'){'failed'}else{'waiting'}
    $relayText=if($status.Proxy -ceq 'Ready'){'专用转发已报告可用'}elseif($status.Proxy -ceq 'Down'){'专用转发不可用'}else{'待读回'}
    New-GuardWindowCheck 'relay' 'protection' 'Guard 专用转发' $relayText '转发与选定节点一致' $relayStatus `
        'Guard 使用本窗口保存的节点建立专用转发。Bettbox 的整机代理由 Bettbox 管理。'

    $firewallText=if($status.Policy -ceq 'Verified'){'已读回当前防火墙规则'}else{'待读回'}
    $binding=if(-not $isPlan){'规则与当前线路一致'}elseif(-not $installed){'建立拟用线路的规则'}
        elseif($Candidate.SameRoute -eq $true){'线路校验值相同，沿用原规则绑定'}
        elseif($Candidate.SameRoute -eq $false){'线路校验值不同，重新绑定规则'}else{'应用时核对线路校验值'}
    New-GuardWindowCheck 'firewall-binding' 'protection' 'Guard 防火墙策略绑定' $firewallText $binding `
        $(if($isPlan){'waiting'}elseif($status.Policy -ceq 'Verified'){'ok'}else{'waiting'}) `
        '同一个公网 IPv4 可能来自不同线路。Guard 使用线路校验值决定是否重绑。' `
        -Change:($isPlan -and $installed -and $Candidate.SameRoute -eq $false)

    $scopeReady=$status.Containment -ceq 'Sandboxie' -and $status.Inventory -ceq 'Verified' -and $status.Policy -ceq 'Verified'
    New-GuardWindowCheck 'sandboxie' 'protection' 'Sandboxie 与受保护程序' `
        $(if($scopeReady){'隔离范围及规则覆盖已核对'}else{'待核对'}) '受保护程序均在防护范围内' `
        $(if($isPlan){'waiting'}elseif($scopeReady){'ok'}elseif($status.Reason -ceq 'CoverageUnverified'){'failed'}else{'waiting'}) `
        '验收会核对 Sandboxie 隔离范围、受保护程序身份和防火墙规则覆盖。'

    $backup=if($Snapshot.Backup -eq $true){'已允许'}elseif($Snapshot.Backup -eq $false){'已禁用'}else{'未读取'}
    New-GuardWindowCheck 'backup-lookup' 'protection' '备用 IP 查询来源' $backup `
        $(if($installed){'沿用已有查询偏好'}else{'首次安装允许使用，遵循当前账户的查询偏好'}) 'reference' `
        '主查询使用 Cloudflare。允许备用查询时，Ipify 会通过同一条专用线路核对公网 IPv4。'

    $observedIp='待核对';$observedStatus='pending';$observedNote='Guard 通过专用线路核对公网 IPv4。'
    if($isPlan){
        if($proof){$observedIp=$proof.ExitIpv4;$observedStatus='ok';$observedNote='这是本次节点试测读取的出口。应用后 Guard 会重新核对。'}
        elseif($Candidate.ProofStatus){$observedIp=$Candidate.Message;$observedStatus=$Candidate.ProofStatus}
    }elseif($status.Exit -ceq 'Mismatch'){
        $observedIp='与允许的 IPv4 不同，当前记录未保存所测地址';$observedStatus='failed';$observedNote=Get-GuardWindowAdmissionText $status
    }elseif($ready -and $Snapshot.ExitIpv4){
        $observedIp=$Snapshot.ExitIpv4;$observedStatus='ok';$observedNote='当前有效的出口核对结果与配置中的 IPv4 一致。'
    }elseif($status.Readiness -ceq 'Rechecking'){
        $observedIp='等待新的出口结果';$observedStatus='review'
    }elseif($transportDown){
        $observedIp='上游连接中断，暂不可核对';$observedStatus='failed';$observedNote=Get-GuardWindowAdmissionText $status
    }
    New-GuardWindowCheck 'actual-ip' 'protection' $(if($isPlan){'节点试测 · 公网 IPv4'}else{'实际公网 IPv4'}) `
        $observedIp $targetIp $observedStatus $observedNote -Blocks:($isPlan -and -not $proof)

    $country=if($proof.CountryCode -cmatch '\A[A-Z]{2}\z'){
        switch -CaseSensitive ($proof.CountryCode){'JP' {'日本（JP）'} 'US' {'美国（US）'} default {$proof.CountryCode}}
    }elseif($isPlan -and -not $proof){'待试测'}else{'未读取'}
    $countryStatus=if($Candidate.CountryMismatch){'failed'}elseif($proof.CountryCode){'ok'}elseif($isPlan -and -not $proof){'pending'}else{'missing'}
    New-GuardWindowCheck 'country' 'protection' '出口国家' $country '用于时区选择' $countryStatus `
        '部分查询只返回公网 IPv4。缺少国家时，可手选 Windows 时区或保留当前时区。' -Blocks:($Candidate.CountryMismatch -eq $true)

    $permitText=if($pending){'等待恢复，暂不可从防护入口打开'}elseif($ready){'当前联网许可有效'}
        elseif($status.Gate -ceq 'Closed'){'联网许可已关闭'}elseif($status.Gate -ceq 'Closing'){'正在关闭联网许可'}else{'待核对'}
    $permitStatus=if($isPlan){'waiting'}elseif($pending -or $status.Gate -ceq 'Closed'){'paused'}
        elseif($ready){'ok'}elseif($status.Readiness -ceq 'Rechecking'){'review'}else{'waiting'}
    $permitExpected='连续 6 份新结果，每份许可最长 15 秒'
    $permitNote='安装、更新或应用新配置时，在 120 秒内核对 6 份连续新结果。'
    if(-not $isPlan -and $restored -and $receipt.RestoreVerification.RequiredProofs -eq 2){
        $permitExpected='恢复原防护须连续核对 2 份'
        $permitNote="恢复回执记录 $($receipt.RestoreVerification.Proofs) / 2 份新结果。"
    }elseif(-not $isPlan -and $receipt.Installed -eq $true -and $receipt.FreshProofs -ge 6){
        $permitNote="安装回执记录 $($receipt.FreshProofs) / 6 份连续新结果。"
    }
    New-GuardWindowCheck 'firewall' 'protection' '防火墙联网许可' $permitText $permitExpected $permitStatus $permitNote

    $worker=$Snapshot.Worker
    $storeText=Get-GuardWindowWorkerText $worker
    if(-not $storeText){$storeText=if($restored){'恢复回执未验收商店监听'}else{'待检查当前监听记录'}}
    New-GuardWindowCheck 'store' 'protection' '商店更新监听' $storeText '事件和目录监听均就绪' `
        $(if($isPlan){'waiting'}elseif($worker -ceq 'Ready'){'ok'}elseif($worker){'failed'}else{'waiting'}) `
        '验收核对 Windows 商店更新事件及安装目录监听。恢复旧配置所需的两份联网结果不含这两项。'
    $entry=switch -CaseSensitive ($Snapshot.GuardedEntry){'Desktop' {'桌面 · Claude Desktop - Guarded'} 'StartMenu' {'开始菜单 · Claude Desktop - Guarded'} 'File' {'已找到防护启动文件'} default {'未核对入口'}}
    New-GuardWindowCheck 'entry' 'protection' '防护桌面入口' $entry 'Claude Desktop - Guarded' `
        $(if($Snapshot.GuardedEntry){'kept'}else{'waiting'}) '防护就绪后，由你从防护入口手动打开。'

    $targetDisabled=if($zoneChange){$false}else{$Snapshot.Zone.DaylightDisabled}
    $now=[datetimeoffset]::UtcNow
    New-GuardWindowCheck 'environment-zone' 'environment' '系统时区' $beforeZone $afterZone `
        $(if($zone){'reference'}else{'uncollected'}) '当前值来自 Windows。浏览器时区可在网页中单独核对。'
    $offset=Get-GuardWindowOffset $zone $Snapshot.Zone.DaylightDisabled $now
    New-GuardWindowCheck 'offset' 'environment' '时区偏移' $offset `
        $(if($Candidate.RequiresChoice){'按所选时区确定'}else{Get-GuardWindowOffset $targetZone $targetDisabled $now}) `
        $(if($offset.StartsWith('UTC')){'derived'}else{'uncollected'}) '按当前日期、Windows 时区和夏令时设置计算。'
    New-GuardWindowCheck 'windows-locale' 'environment' 'Windows 语言、键盘和区域格式' '未采集' '沿用 Windows 设置' 'uncollected' `
        '系统显示语言、键盘和区域格式由 Windows 单独管理。'
    $browserItems=[ordered]@{
        language='浏览器语言';fonts='浏览器可用字体';intl='Intl 区域格式';emoji='Emoji 渲染'
        'claude-exits'='Claude 域名出口';dns='DNS 解析出口';webrtc='WebRTC 浏览器通道'
    }
    foreach($key in $browserItems.Keys){
        New-GuardWindowCheck $key 'environment' $browserItems[$key] '未采集' '浏览器单独核对' 'uncollected' `
            '这是 IPPure 网页的参考项目。Guard 会单独核对自己的专用线路。'
    }
}
