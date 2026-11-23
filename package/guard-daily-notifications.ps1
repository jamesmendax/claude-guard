function New-GuardDailyNotice([string]$Phase,[string]$Reason,[string]$Id) {
    if(-not $Id){$Id=[guid]::NewGuid().ToString('n')}
    [pscustomobject]@{Version=1;Id=$Id;Phase=$Phase;Reason=$Reason;Utc=[datetime]::UtcNow.ToString('o')}
}

function Get-GuardDailyNoticeReasonText([string]$Reason) {
    switch -CaseSensitive ($Reason) {
        'ProofPending' {'正在重新核对代理出口'}
        'ProxyNotReady' {'专用代理暂不可用'}
        'UpstreamTransportDown' {'专用代理与上游的连接已中断'}
        'RelayIdentityChanged' {'专用代理进程已更换，需要重新核对'}
        'ExitChanged' {'代理出口 IPv4 与已批准的地址不一致'}
        'CoverageUnverified' {'应用身份或防护规则未通过核对'}
        'IsolationActive' {'已启用紧急隔离'}
        'ControllerStopped' {'防护后台已停止'}
        'StoreUpdateHandoff' {'检测到 Microsoft Store 更新，防护需要重新核对新版 Claude'}
        'StateUnknown' {'暂时无法确认防护状态'}
        default {'暂时无法确认防护状态'}
    }
}

function Read-GuardDailyNotice([switch]$LastStop,[ref]$ReadState) {
    $file=if($LastStop){'daily-last-guard-stop.json'}else{'daily-notice.json'}
    if($ReadState){$ReadState.Value='Unreadable'}
    try{
        $record=Read-GuardDailyRecord $file
        if($null -eq $record){if($ReadState){$ReadState.Value='Missing'};return}
        if($record.Version -cne 1 -or [string]$record.Id -cnotmatch '^[a-f0-9]{32}$' -or
            $record.Phase -cnotin 'Paused','Resumed','Closing','StoppingUnverified','Stopped','Ready','Idle' -or
            $record.Reason -cnotin 'ProofPending','ProxyNotReady','UpstreamTransportDown','RelayIdentityChanged',
                'ExitChanged','CoverageUnverified','IsolationActive','ControllerStopped','StoreUpdateHandoff','StateUnknown' -or
            ($record.Generation -and [string]$record.Generation -cnotmatch '^[A-F0-9]{64}$') -or
            ($LastStop -and ($record.Phase -cne 'Stopped' -or $record.Reason -ceq 'ProofPending'))){return}
        $when=[datetime]::MinValue
        if(-not [datetime]::TryParseExact([string]$record.Utc,'o',[Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,[ref]$when) -or $when.Kind -ne 'Utc' -or
            $when -gt [datetime]::UtcNow.AddSeconds(5)){return}
        if($ReadState){$ReadState.Value='Readable'}
        [pscustomobject]@{Version=1;Id=$record.Id;Phase=$record.Phase;Reason=$record.Reason;Utc=$when;Generation=$record.Generation}
    }catch{
        if($ReadState -and ($_.CategoryInfo.Category -eq 'ObjectNotFound' -or
            $_.Exception.GetBaseException() -is [IO.FileNotFoundException])){
            $ReadState.Value='Missing'
        }
    }
}

function Read-GuardDailyPendingStopNotice {
    $notice=Read-GuardDailyNotice
    if($notice.Phase -cne 'Stopped'){return}
    $lastStop=Read-GuardDailyNotice -LastStop
    if($lastStop.Id -ceq $notice.Id -and $lastStop.Reason -ceq $notice.Reason -and
        $lastStop.Utc -eq $notice.Utc -and $lastStop.Generation -ceq $notice.Generation){
        $notice
    }
}

function Initialize-GuardDailyNotice($Controller,$Operations) {
    if($Operations.WriteNotice -and $Operations.ReadPendingStopNotice){
        try{$Controller.Notice=& $Operations.ReadPendingStopNotice}catch{}
    }
}

function Publish-GuardDailyStoreStopNotice($Shutdown,[bool]$Acted,[scriptblock]$WriteNotice,[string]$PreviousGeneration) {
    if(-not ($Acted -and $Shutdown.NetworkBlocked -and $Shutdown.ObservedProcess -and $Shutdown.Exited)){return}
    $current=Read-GuardDailyNotice
    $prior=if($current.Reason -ceq 'StoreUpdateHandoff' -and
        $current.Phase -cin @('Closing','StoppingUnverified') -and
        $PreviousGeneration -cmatch '^[A-F0-9]{64}$' -and $current.Generation -ceq $PreviousGeneration){$current}
    $publisher=[pscustomobject]@{Notice=$prior;Mode=@{Generation=$PreviousGeneration}}
    Publish-GuardDailyNotice $publisher @{WriteNotice=$WriteNotice} 'Stopped' 'StoreUpdateHandoff'
}

function Open-GuardDailyObservedExitKey([switch]$Writable) {
    $path='Software\ClaudeVPNGuard'
    if($Writable){return [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($path)}
    [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path)
}

function Save-GuardDailyObservedExit([datetime]$TimeUtc,$ExitCode,[bool]$NetworkClosed) {
    if($null -ne $ExitCode -and $ExitCode -eq 0){return}
    $code=$null
    if($null -ne $ExitCode){$code='0x{0:X8}' -f [uint32]$ExitCode}
    $record=@{Version=1;Id=[guid]::NewGuid().ToString('n');Utc=$TimeUtc.ToString('o')
        ExitCode=$code;NetworkClosed=$NetworkClosed}
    # One atomic current-user value for display only. The launch mutex
    # serializes the launcher writes. The controller never reads this value.
    $key=Open-GuardDailyObservedExitKey -Writable
    try{
        $json=ConvertTo-Json -InputObject $record -Compress
        $key.SetValue('LastObservedDesktopExit',$json,[Microsoft.Win32.RegistryValueKind]::String)
    }finally{$key.Dispose()}
}

function Read-GuardDailyObservedExit([ref]$ReadState) {
    $ReadState.Value='Unreadable'
    $key=$null
    try{
        $key=Open-GuardDailyObservedExitKey
        $json=if($key){$key.GetValue('LastObservedDesktopExit',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
        if($null -eq $json){$ReadState.Value='Missing';return}
        if($json -isnot [string] -or $json.Length -gt 1024 -or
            $key.GetValueKind('LastObservedDesktopExit') -ne [Microsoft.Win32.RegistryValueKind]::String){return}
        $record=if($PSVersionTable.PSVersion -ge [version]'7.5'){ConvertFrom-Json -InputObject $json -DateKind String -ErrorAction Stop}
            else{ConvertFrom-Json -InputObject $json -ErrorAction Stop}
        $when=[datetime]::MinValue
        if(($record.Version -isnot [int] -and $record.Version -isnot [long]) -or $record.Version -ne 1 -or
            $record.Id -isnot [string] -or $record.Id -cnotmatch '\A[a-f0-9]{32}\z' -or
            $record.NetworkClosed -isnot [bool] -or
            ($null -ne $record.ExitCode -and ($record.ExitCode -isnot [string] -or
                $record.ExitCode -cnotmatch '\A0x[0-9A-F]{8}\z' -or $record.ExitCode -ceq '0x00000000')) -or
            -not [datetime]::TryParseExact([string]$record.Utc,'o',[Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,[ref]$when) -or $when.Kind -ne 'Utc' -or
            $when -gt [datetime]::UtcNow.AddSeconds(5)){return}
        $ReadState.Value='Readable'
        [pscustomobject]@{Id=$record.Id;Utc=$when;ExitCode=$record.ExitCode;NetworkClosed=$record.NetworkClosed}
    }catch{}finally{if($key){$key.Dispose()}}
}

function Get-GuardDailyLastStopView($Status) {
    $guardState='Missing'
    $observedState='Missing'
    $guard=Read-GuardDailyNotice -LastStop -ReadState ([ref]$guardState)
    $observed=Read-GuardDailyObservedExit ([ref]$observedState)
    if(-not $guard -and -not $observed){
        $unreadable='Unreadable' -cin @($guardState,$observedState)
        return @{
            HasRecord=$false;ReadState=$(if($unreadable){'Unreadable'}else{'Missing'})
            TimeUtc='';Title=$(if($unreadable){'无法读取上次结束记录'}else{'暂无结束记录'})
            Summary=$(if($unreadable){'保存的记录无法读取或验证。'}else{'目前没有可显示的防护关闭或异常退出记录。'})
            Action='';Network='';Source='';ExitCode='';Details=''
        }
    }
    if(-not $PSBoundParameters.ContainsKey('Status')){$Status=try{Get-GuardDailyStatus}catch{$null}}
    $partial=if('Unreadable' -cin @($guardState,$observedState)){' 另一种结束记录暂时无法读取或验证。'}
    $next=if($status.CanLaunch){'防护已就绪。请从原入口手动打开 Claude。'}
        else{'请等防护就绪后，再从原入口手动打开 Claude。'}
    if($guard -and (-not $observed -or $guard.Utc -ge $observed.Utc)){
        return @{
            HasRecord=$true;ReadState='Readable';Id=$guard.Id;TimeUtc=$guard.Utc.ToString('o')
            Title='防护关闭了 Claude';Summary="$(Get-GuardDailyNoticeReasonText $guard.Reason)。"
            Action=$next;Network='防护已确认断开联网，Claude 已退出。';Source='GuardConfirmed'
            ExitCode='';Details="防护后台记录了关停原因，并确认 Claude 已退出。$partial"
        }
    }
    @{
        HasRecord=$true;ReadState='Readable';Id=$observed.Id;TimeUtc=$observed.Utc.ToString('o')
        Title=$(if($observed.ExitCode){'Claude 退出时返回了非零退出码'}else{'Claude 会话结束，原因未知'})
        Summary=$(if($observed.ExitCode){'启动器记录了此次启动的 Claude 主进程返回的退出码，具体原因无法确认。'}
            else{'启动器发现此次受保护的会话已经结束，未取得可确认的退出码。'})
        Action=$next;Network=$(if($observed.NetworkClosed){'防护已确认关闭本次会话的联网许可。'}
            else{'本次记录没有联网许可已关闭的确认。'})
        Source='LauncherObserved';ExitCode=[string]$observed.ExitCode;Details="由当前 Windows 用户下的 Guard 启动器记录。$partial"
    }
}

function Get-GuardDailyLastStopText {
    $view=Get-GuardDailyLastStopView
    if(-not $view.HasRecord){return $view.Summary}
    $when=[datetime]::Parse($view.TimeUtc,[Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $code=if($view.ExitCode){"退出码 $($view.ExitCode)"}
    (@("$($view.Title) · $when（本机时间）",$view.Summary,$code,$view.Network,$view.Action) |
        Where-Object { $_ }) -join [Environment]::NewLine
}

function Get-GuardDailyObservedExitPresentation([string[]]$Seen) {
    $readState='Missing'
    $observed=Read-GuardDailyObservedExit ([ref]$readState)
    if(-not $observed.ExitCode -or $observed.Utc -lt [datetime]::UtcNow.AddMinutes(-2)){return}
    $key="$($observed.Id):exit"
    if($key -cin $Seen){return}
    $guard=Read-GuardDailyNotice -LastStop
    if($guard -and $guard.Utc -ge $observed.Utc){return}
    [pscustomobject]@{
        Key=$key;Text="Claude 退出时返回了非零退出码 $($observed.ExitCode)。可在防护窗口查看记录。"
    }
}

function Get-GuardDailyUnavailableText($Status) {
    $reason=[string]$Status.Reason
    if($reason -ceq 'RevisionInProgress'){return '防护正在更新。完成后可以从原入口手动打开 Claude。'}
    if($reason -ceq 'ShutdownPending'){return '上一会话正在关闭。请等防护就绪后，再从原入口打开 Claude。'}
    if($reason -ceq 'ProofPending' -or $reason -ceq 'ExitUnverified'){
        return '正在核对代理出口。请等防护就绪后，再从原入口打开 Claude。'
    }
    $summary=Get-GuardDailyNoticeReasonText $reason
    "$summary。请等防护就绪后，再从原入口打开 Claude。"
}

function Get-GuardDailyPresentation($Notice,$Status,[string[]]$Seen,[scriptblock]$ReadStatus) {
    if(-not $Notice){return}
    $faultKey="$($Notice.Id):fault"
    $kind=switch -CaseSensitive ($Notice.Phase) {
        'Paused' {'pause'}
        'Resumed' {if("$($Notice.Id):pause" -cin $Seen){'recovery'}}
        'Closing' {'fault'}
        'StoppingUnverified' {'fault'}
        'Stopped' {'fault'}
        'Ready' {'recovery'}
    }
    if(-not $kind){return}
    $key="$($Notice.Id):$kind"
    if($key -cin $Seen){return}

    # A Stopped receipt already verifies that blocking and exit completed.
    if($ReadStatus -and $Notice.Phase -cne 'Stopped'){$Status=& $ReadStatus}
    $reason=Get-GuardDailyNoticeReasonText $Notice.Reason
    $message=switch -CaseSensitive ($Notice.Phase) {
        'Paused' {
            if($Status.Readiness -ceq 'Rechecking' -and $Status.Gate -ceq 'Closed'){
                '正在重新核对代理出口。Claude 已暂停联网，窗口仍保留。'
            }
        }
        'Resumed' {
            if($Status.CanLaunch){'代理出口核对通过，Claude 已恢复联网。'}
        }
        'Closing' {
            if(-not $Status.CanLaunch){"$reason。防护正在关闭 Claude，尚未确认已退出。"}
        }
        'StoppingUnverified' {
            if(-not $Status.CanLaunch){"$reason。暂未确认拦网或 Claude 退出。"}
        }
        'Stopped' {"$reason。防护已断开联网，Claude 已退出。"}
        'Ready' {
            if($Status.CanLaunch -and (-not $Notice.Generation -or $Status.Generation -ceq $Notice.Generation)){
                if($faultKey -cin $Seen){'防护已就绪。请从原入口手动打开 Claude。'}
                else{"$reason。Claude 已由防护关闭。防护现已就绪，请从原入口手动打开 Claude。"}
            }
        }
    }
    if($message){[pscustomobject]@{Key=$key;Text=$message}}
}
function Publish-GuardDailyNotice($Controller,$Operations,[string]$Phase,[string]$Reason) {
    $last=$Controller.Notice
    if($last.Phase -ceq $Phase -and $last.Reason -ceq $Reason){return}
    $id=if($last.Phase -cin @('Paused','Closing','StoppingUnverified','Stopped')){$last.Id}
    $receipt=New-GuardDailyNotice $Phase $Reason $id
    if([string]$Controller.Mode.Generation -cmatch '^[A-F0-9]{64}$'){
        $receipt | Add-Member -NotePropertyName Generation -NotePropertyValue $Controller.Mode.Generation
    }
    try{
        if($Phase -ceq 'Stopped'){& $Operations.WriteNotice 'daily-last-guard-stop.json' $receipt | Out-Null}
        & $Operations.WriteNotice 'daily-notice.json' $receipt | Out-Null
        $Controller.Notice=$receipt
    }catch{}
}


function Update-GuardDailyNotice($Controller,$Operations,$State) {
    if($Controller.NoticeStopped){
        Publish-GuardDailyNotice $Controller $Operations 'Stopped' $Controller.NoticeCause
        if($Controller.Notice.Phase -cne 'Stopped'){return}
        $Controller.NoticeStopped=$false
        $Controller.NoticeCause=$null
        $Controller.NoticeProcess=$false
        $Controller.NoticeCloseAction=$false
    }
    if($Controller.NoticeCause -and $Controller.NoticeProcess){
        $phase=if($State.Gate -ceq 'Closed'){'Closing'}else{'StoppingUnverified'}
        Publish-GuardDailyNotice $Controller $Operations $phase $Controller.NoticeCause
    }elseif($Controller.Rechecking -and $Controller.ObservedSession){
        Publish-GuardDailyNotice $Controller $Operations 'Paused' 'ProofPending'
    }elseif(-not $Controller.NoticeCause -and $Controller.Notice.Phase -cin @('Closing','StoppingUnverified')){
        Publish-GuardDailyNotice $Controller $Operations 'Idle' 'StateUnknown'
    }elseif($State.Gate -ceq 'Open' -and $Controller.Decision.CanLaunch){
        if($Controller.Notice.Phase -ceq 'Stopped'){
            Publish-GuardDailyNotice $Controller $Operations 'Ready' $Controller.Notice.Reason
        }elseif($Controller.Notice.Phase -ceq 'Paused' -and $Controller.ObservedSession){
            Publish-GuardDailyNotice $Controller $Operations 'Resumed' 'ProofPending'
        }
    }elseif($Controller.Notice.Phase -ceq 'Paused' -and -not $Controller.ObservedSession){
        Publish-GuardDailyNotice $Controller $Operations 'Idle' 'StateUnknown'
    }
}


function Get-GuardDailyBackupLookupView {
    $record=try{Read-GuardDailyRecord 'daily-provisioned.json'}catch{$null}
    $available=$record.BackupExitLookup -is [bool] -and $record.BackupExitLookup -eq $true
    $preferred=Get-GuardDailyBackupLookupPreference
    $details='主查询未取得可信 IPv4 时，部分情况下会用同一代理再核对一次。'
    $text=if($available){'备用出口核对'}
        elseif($preferred){'关闭备用核对偏好（部署未开放）'}
        else{'备用出口核对（部署未开放）'}
    [pscustomobject]@{
        Available=$available;Preferred=$preferred
        Checked=$available -and $preferred;CanChange=$available -or $preferred
        Text=$text;Details=$details
    }
}
