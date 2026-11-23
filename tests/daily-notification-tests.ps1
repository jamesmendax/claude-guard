#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot/../package/guard-runtime.ps1"
. "$PSScriptRoot/../package/guard-daily-controller.ps1"

function Assert-Equal($expected,$actual) {
    if($expected -cne $actual){throw "Expected [$expected], received [$actual]."}
}

function New-NoticeFixture {
    $test=@{Proxy='Ready';Exit='Match';Failure=$null;Process=$false;CloseVerified=$true;Stubborn=$false
        NoticeError=$false;Records=@{};Events=[Collections.Generic.List[string]]::new()}
    $operations=@{
        ReadIsolation={'Off'}
        VerifyInventory={$true}
        ReadPath={
            $now=[datetime]::UtcNow
            @{Proxy=$test.Proxy;Exit=$test.Exit;Failure=$test.Failure
                Lease=@{Generation=('F'*64);CheckedUtc=$now.ToString('o');ExpiresUtc=$now.AddSeconds(5).ToString('o')}}
        }.GetNewClosure()
        OpenVerified={$true}
        CloseVerified={$test.Events.Add('block');$test.CloseVerified}.GetNewClosure()
        WriteRecord={}
        WriteNotice={
            param($name,$receipt)
            if($test.NoticeError){throw 'Presentation storage failure'}
            $test.Events.Add($receipt.Phase)
            $test.Records[$name]=$receipt
        }.GetNewClosure()
        Snapshot={if($test.Process){[pscustomobject]@{Id=17;Start=25}}}.GetNewClosure()
        RequestClose={$test.Events.Add('request-exit')}.GetNewClosure()
        ForceStop={$test.Events.Add('force-exit');if(-not $test.Stubborn){$test.Process=$false;$true}}.GetNewClosure()
        Wait={}
    }
    $profile=@{Generation=('F'*64);Port=18793;DesktopHashes=@('D'*64)
        ScopeName=('claude-guard-'+('1'*32));ScopeSid='S-1-15-2-21-22-23-24-25-26-27'}
    [pscustomobject]@{Data=$test;Ops=$operations;Profile=$profile;Controller=(New-GuardDailyController $profile)}
}

function Invoke-NoticeCycle($Fixture) {
    $null=Invoke-GuardDailyControllerCycle $Fixture.Controller $Fixture.Ops
}

function Test-Notice([string]$Name,[scriptblock]$Body) {
    $f=New-NoticeFixture
    try{
        Invoke-NoticeCycle $f
        & $Body $f
        "PASS $Name"
    }finally{$f.Controller.Signal.Dispose()}
}

Test-Notice 'The status reader and the launcher open the same test signal with their required access' {
    param($f)
    $name=Get-GuardDailyCloseName $f.Controller.Mode.CloseId
    $readOnly=[Security.AccessControl.EventWaitHandleRights]::Synchronize
    $reader=Open-GuardDailyCloseSignal $name $readOnly
    $writer=$null
    try{
        $writer=Open-GuardDailyCloseSignal $name ($readOnly -bor [Security.AccessControl.EventWaitHandleRights]::Modify)
        Assert-Equal $false $reader.WaitOne(0)
        $null=$writer.Set()
        Assert-Equal $true $reader.WaitOne(0)
        Assert-Equal $true $f.Controller.Signal.WaitOne(0)
    }finally{if($writer){$writer.Dispose()};$reader.Dispose()}
}

Test-Notice 'Quiet startup, unavailable idle proxy, and ordinary user exit' {
    param($f)
    Assert-Equal 0 $f.Data.Records.Count
    $f.Data.Proxy='Down'
    Invoke-NoticeCycle $f
    Assert-Equal 0 $f.Data.Records.Count
    $f.Data.Proxy='Ready'
    Invoke-NoticeCycle $f
    $f.Data.Process=$true
    Invoke-NoticeCycle $f
    $f.Data.Process=$false
    $null=$f.Controller.Signal.Set()
    Invoke-NoticeCycle $f
    Assert-Equal 0 $f.Data.Records.Count
}

Test-Notice 'Short proof outage keeps the same process and never becomes stop history' {
    param($f)
    $f.Data.Process=$true
    Invoke-NoticeCycle $f
    $f.Data.Proxy='Unknown'
    Invoke-NoticeCycle $f
    $notice=$f.Data.Records['daily-notice.json']
    Assert-Equal 'Paused' $notice.Phase
    Assert-Equal $true $f.Data.Process
    $state=@{Readiness='Rechecking';Gate='Closed'}
    $pause=Get-GuardDailyPresentation $notice $state
    Assert-Equal "$($notice.Id):pause" $pause.Key
    Assert-Equal $null (Get-GuardDailyPresentation $notice $state @($pause.Key))
    Invoke-NoticeCycle $f
    Assert-Equal $notice.Utc $f.Data.Records['daily-notice.json'].Utc
    $f.Data.Proxy='Ready'
    Invoke-NoticeCycle $f
    $resumed=$f.Data.Records['daily-notice.json']
    Assert-Equal 'Resumed' $resumed.Phase
    Assert-Equal $notice.Id $resumed.Id
    Assert-Equal $true $f.Data.Process
    Assert-Equal $null $f.Data.Records['daily-last-guard-stop.json']
    Assert-Equal $null (Get-GuardDailyPresentation $resumed @{CanLaunch=$true})
    Assert-Equal "$($notice.Id):recovery" (Get-GuardDailyPresentation $resumed @{CanLaunch=$true} @($pause.Key)).Key
}

Test-Notice 'Definitive outage after recheck confirms the actual reason and exit before recording' {
    param($f)
    $f.Data.Process=$true
    Invoke-NoticeCycle $f
    $f.Data.Proxy='Unknown'
    Invoke-NoticeCycle $f
    $notice=$f.Data.Records['daily-notice.json']
    $f.Data.Proxy='Down'
    $f.Data.Failure='UpstreamTransportDown'
    $f.Data.Events.Clear()
    Invoke-NoticeCycle $f
    Assert-Equal 'block,request-exit,force-exit,Stopped,Stopped' ($f.Data.Events -join ',')
    $stop=$f.Data.Records['daily-last-guard-stop.json']
    Assert-Equal 'UpstreamTransportDown' $stop.Reason
    Assert-Equal $notice.Id $stop.Id
    Assert-Equal $false $f.Data.Process
    $f.Data.Proxy='Ready'
    Invoke-NoticeCycle $f
    $ready=$f.Data.Records['daily-notice.json']
    Assert-Equal 'Ready' $ready.Phase
    Assert-Equal $stop.Id $ready.Id
    Assert-Equal $false $f.Data.Process
    $key="$($stop.Id):recovery"
    Assert-Equal $key (Get-GuardDailyPresentation $ready @{CanLaunch=$true;Generation=$f.Profile.Generation}).Key
    Assert-Equal $null (Get-GuardDailyPresentation $ready @{CanLaunch=$true;Generation=$f.Profile.Generation} @($key))
    Assert-Equal $null (Get-GuardDailyPresentation $ready @{CanLaunch=$false})
    $f.Data.Process=$true
    Invoke-NoticeCycle $f
    $f.Data.Process=$false
    $null=$f.Controller.Signal.Set()
    Invoke-NoticeCycle $f
    Assert-Equal $stop.Utc $f.Data.Records['daily-last-guard-stop.json'].Utc
}

Test-Notice 'Unknown block and unsuccessful exit never get a confirmed history entry' {
    param($f)
    $f.Data.Process=$true
    $f.Data.Proxy='Down'
    $f.Data.Failure='RelayIdentityChanged'
    $f.Data.CloseVerified=$false
    Invoke-NoticeCycle $f
    $unknown=$f.Data.Records['daily-notice.json']
    Assert-Equal 'StoppingUnverified' $unknown.Phase
    Assert-Equal $null $f.Data.Records['daily-last-guard-stop.json']
    Assert-Equal $true $f.Data.Process
    $f.Data.CloseVerified=$true
    $f.Data.Stubborn=$true
    Invoke-NoticeCycle $f
    Assert-Equal 'Closing' $f.Data.Records['daily-notice.json'].Phase
    Assert-Equal $null $f.Data.Records['daily-last-guard-stop.json']
    $f.Data.Stubborn=$false
    Invoke-NoticeCycle $f
    Assert-Equal 'RelayIdentityChanged' $f.Data.Records['daily-last-guard-stop.json'].Reason
    Assert-Equal $unknown.Id $f.Data.Records['daily-last-guard-stop.json'].Id
}

Test-Notice 'Receipt failure cannot interrupt close and a later write retains the fault' {
    param($f)
    $f.Data.Process=$true
    $f.Data.Proxy='Down'
    $f.Data.NoticeError=$true
    $f.Data.Events.Clear()
    Invoke-NoticeCycle $f
    Assert-Equal $false $f.Data.Process
    Assert-Equal 'block,request-exit,force-exit' ($f.Data.Events -join ',')
    Assert-Equal $null $f.Data.Records['daily-last-guard-stop.json']
    $f.Data.Proxy='Ready'
    $f.Data.NoticeError=$false
    Invoke-NoticeCycle $f
    Assert-Equal 'ProxyNotReady' $f.Data.Records['daily-last-guard-stop.json'].Reason
}

& {
    function Read-GuardDailyRecord {
        [pscustomobject]@{Version=1;Id=('a'*32);Phase='Stopped';Reason='ignored sensitive text'
            Utc=[datetime]::UtcNow.ToString('o')}
    }
    Assert-Equal $null (Read-GuardDailyNotice -LastStop)
}
& {
    function Read-GuardDailyRecord {throw 'unavailable'}
    Assert-Equal $null (Read-GuardDailyNotice -LastStop)
}
'PASS protected receipt validation rejects missing and unrecognized reasons'

& {
    $fixtureKey=[pscustomobject]@{Text=$null;Writes=0;StatusReads=0;Kind=[Microsoft.Win32.RegistryValueKind]::String}
    $fixtureKey | Add-Member ScriptMethod GetValue {param($name,$fallback,$options) $this.Text}
    $fixtureKey | Add-Member ScriptMethod GetValueKind {param($name) $this.Kind}
    $fixtureKey | Add-Member ScriptMethod SetValue {param($name,$text,$kind) $this.Text=$text;$this.Kind=$kind;$this.Writes++}
    $fixtureKey | Add-Member ScriptMethod Dispose {}
    function Open-GuardDailyObservedExitKey {param([switch]$Writable) $fixtureKey}
    function Read-GuardDailyRecord($Name) {
        if($Name -cne 'daily-last-guard-stop.json'){throw 'Unexpected protected record read'}
        $confirmed
    }
    function Get-GuardDailyStatus {$fixtureKey.StatusReads++;@{CanLaunch=$false}}
    $confirmed=$null
    $when=[datetime]::UtcNow.AddSeconds(-5)
    Assert-Equal 'Missing' (Get-GuardDailyLastStopView -Status $null).ReadState
    Save-GuardDailyObservedExit $when 0 $true
    Assert-Equal 0 $fixtureKey.Writes
    Assert-Equal $null (Get-GuardDailyObservedExitPresentation)

    Save-GuardDailyObservedExit $when ([uint32]3221225477) $true
    $view=Get-GuardDailyLastStopView -Status @{CanLaunch=$true}
    Assert-Equal 'LauncherObserved' $view.Source
    Assert-Equal '0xC0000005' $view.ExitCode
    Assert-Equal 'Readable' $view.ReadState
    Assert-Equal $true $view.HasRecord
    Assert-Equal $when.ToString('o') $view.TimeUtc
    Assert-Equal $true ($view.Action -like '*已就绪*')
    Assert-Equal $true ($view.Network -like '*已确认*')
    $seen=Get-GuardDailyObservedExitPresentation
    Assert-Equal "$($view.Id):exit" $seen.Key
    Assert-Equal $null (Get-GuardDailyObservedExitPresentation -Seen $seen.Key)

    $confirmed=New-GuardDailyNotice 'Stopped' 'ExitChanged' ('a'*32)
    $confirmed.Utc=$when.AddSeconds(-1).ToString('o')
    Assert-Equal 'LauncherObserved' (Get-GuardDailyLastStopView -Status $null).Source
    $confirmed.Utc=$when.ToString('o')
    $view=Get-GuardDailyLastStopView -Status $null
    Assert-Equal 'GuardConfirmed' $view.Source
    Assert-Equal '' $view.ExitCode
    Assert-Equal $true ($view.Summary -like '*IPv4*')
    Assert-Equal $null (Get-GuardDailyObservedExitPresentation)

    $confirmed=$null
    Save-GuardDailyObservedExit $when $null $false
    $view=Get-GuardDailyLastStopView -Status $null
    Assert-Equal 'LauncherObserved' $view.Source
    Assert-Equal '' $view.ExitCode
    Assert-Equal $true ($view.Title -like '*原因未知*')
    Assert-Equal $true ($view.Network -like '*没有*确认*')
    Assert-Equal $null (Get-GuardDailyObservedExitPresentation)

    Save-GuardDailyObservedExit ([datetime]::UtcNow.AddMinutes(-3)) 1 $false
    Assert-Equal $null (Get-GuardDailyObservedExitPresentation)
    $fixtureKey.Text=$fixtureKey.Text.Replace('0x00000001','invalid diagnostic payload')
    $view=Get-GuardDailyLastStopView -Status $null
    Assert-Equal $false $view.HasRecord
    Assert-Equal 'Unreadable' $view.ReadState
    Assert-Equal $false ($view.Summary -like '*invalid diagnostic payload*')
    $confirmed=New-GuardDailyNotice 'Stopped' 'ControllerStopped' ('b'*32)
    Assert-Equal 'GuardConfirmed' (Get-GuardDailyLastStopView -Status $null).Source
    Assert-Equal 0 $fixtureKey.StatusReads
}
'PASS last-stop selection separates protected receipts, app exit codes, unavailable codes and invalid data'

& {
    $controller=@{HasExited=$false}
    $event=[pscustomobject]@{Set=$false}
    $event | Add-Member ScriptMethod WaitOne {param($ms) $this.Set}
    $desktop=[pscustomobject]@{Event=$event;SignalOnExit=$false;Reads=0;Reported=[int]-1073741819}
    $desktop | Add-Member ScriptMethod WaitForExit {param($ms) if($this.SignalOnExit){$this.Event.Set=$true};$true}
    $desktop | Add-Member ScriptProperty ExitCode {$this.Reads++;$this.Reported}

    Assert-Equal ([uint32]3221225477) (Wait-GuardDailyDesktopExit $desktop $controller $event)
    $desktop.Reported=0
    Assert-Equal 0 (Wait-GuardDailyDesktopExit $desktop $controller $event)
    $desktop.Reported=$null
    Assert-Equal $null (Wait-GuardDailyDesktopExit $desktop $controller $event)
    $reads=$desktop.Reads
    function Start-Sleep {param($Milliseconds) Assert-Equal 500 $Milliseconds}
    $membership=[Collections.Generic.Queue[bool]]::new()
    $membership.Enqueue($true)
    $membership.Enqueue($false)
    Assert-Equal $null (Wait-GuardDailyDesktopExit $desktop $controller $event {$membership.Dequeue()})
    Assert-Equal 0 $membership.Count
    Assert-Equal $reads $desktop.Reads

    $desktop.SignalOnExit=$true
    $reason=try{Wait-GuardDailyDesktopExit $desktop $controller $event}catch{$_.Exception.Message}
    Assert-Equal $true ($reason -like '*requested Desktop shutdown*')
    Assert-Equal $reads $desktop.Reads
    $controller.HasExited=$true
    $reason=try{Wait-GuardDailyDesktopExit $desktop $controller $event}catch{$_.Exception.Message}
    Assert-Equal 'The network controller has exited.' $reason
    Assert-Equal $reads $desktop.Reads
}
'PASS guarded wait only reads the bound desktop code and excludes near-simultaneous controller shutdown'

& {
    function Read-GuardDailyRecord($Name) {
        Assert-Equal 'daily-provisioned.json' $Name
        switch($deployment){
            'On'{[pscustomobject]@{BackupExitLookup=$true}}
            'Off'{[pscustomobject]@{BackupExitLookup=$false}}
            'Legacy'{[pscustomobject]@{Version=2}}
            'Malformed'{[pscustomobject]@{BackupExitLookup='true'}}
            default{throw 'The protected record could not be read'}
        }
    }
    function Get-GuardDailyBackupLookupPreference {$preference}
    $preference=$true
    foreach($deployment in 'Off','Legacy','Malformed','Unreadable'){
        $view=Get-GuardDailyBackupLookupView
        Assert-Equal $false $view.Checked
        Assert-Equal $true $view.CanChange
        Assert-Equal $true ($view.Text -like '*部署未开放*')
    }
    $deployment='On'
    $view=Get-GuardDailyBackupLookupView
    Assert-Equal $true $view.Checked
    Assert-Equal $true ($view.Details -like '*同一代理*')
    Assert-Equal $false ($view.Details -like '*超时*')
    $preference=$false
    $view=Get-GuardDailyBackupLookupView
    Assert-Equal $false $view.Checked
    Assert-Equal $true $view.CanChange
    $deployment='Off'
    Assert-Equal $false (Get-GuardDailyBackupLookupView).CanChange
}
'PASS tray preference view distinguishes administrator capability and opt-out'

$fixtureDirectory=Join-Path ([IO.Path]::GetTempPath()) ('claude-guard-notice-test-'+[guid]::NewGuid().ToString('n'))
[void][IO.Directory]::CreateDirectory($fixtureDirectory)
$files=@('open-claude-daily.ps1','guard-daily-notifications.ps1','guard-runtime.ps1')
try{
    foreach($file in $files[0..1]){
        Copy-Item -LiteralPath (Join-Path "$PSScriptRoot/../package" $file) -Destination $fixtureDirectory
    }
    $runtime=@'
. "$PSScriptRoot\guard-daily-notifications.ps1"
function Open-GuardDailyObservedExitKey {throw 'The fixture does not read the real user registry'}
function Get-GuardDailyStatus {
    [pscustomobject]@{Readiness='Ready';CanLaunch=$true;Reason='Verified';Policy='Verified';Internal='private'}
}
function Read-GuardDailyRecord($Name) {
    if($Name -ceq 'daily-provisioned.json'){
        switch($fixtureDeployMode){
            'On'{return [pscustomobject]@{BackupExitLookup=$true}}
            'Off'{return [pscustomobject]@{BackupExitLookup=$false}}
            'Legacy'{return [pscustomobject]@{Version=2}}
            default{throw 'Unreadable configuration'}
        }
    }
    if($Name -cne 'daily-last-guard-stop.json'){throw 'Unexpected file read'}
    [pscustomobject]@{Version=1;Id=('a'*32);Phase='Stopped';Reason='ExitChanged';Utc=[datetime]::UtcNow.ToString('o')}
}
function Set-GuardDailyBackupLookupPreference([bool]$Enabled) {$script:noticeTestPreference=$Enabled}
function Get-GuardDailyBackupLookupPreference {$script:noticeTestPreference}
function Invoke-GuardDailyDesktop {throw 'Read-only and preference commands may never launch the app'}
'@
    [IO.File]::WriteAllText((Join-Path $fixtureDirectory $files[2]),$runtime)
    $launcher=Join-Path $fixtureDirectory $files[0]
    $status=& $launcher -Status
    Assert-Equal '{"Readiness":"Ready","CanLaunch":true,"Reason":"Verified","Policy":"Verified"}' $status
    $history=& $launcher -LastStop
    Assert-Equal $true ($history -match '[0-9]{4}-[0-9]{2}-[0-9]{2}')
    Assert-Equal $true ($history -match 'IPv4' -and $history -match 'Claude')
    foreach($fixtureDeployMode in 'Off','Legacy','Unreadable'){
        $message=& $launcher -BackupLookup On
        Assert-Equal $true ($message -like '*已保存*未开放*')
        Assert-Equal $false ($message -like '*已启用*')
        Assert-Equal '已关闭备用出口核对。' (& $launcher -BackupLookup Off)
    }
    $fixtureDeployMode='On'
    $message=& $launcher -BackupLookup On
    Assert-Equal $true ($message -like '*已启用*同一代理*')
    Assert-Equal $false ($message -like '*超时*')
    Assert-Equal '已关闭备用出口核对。' (& $launcher -BackupLookup Off)
    'PASS launcher status contract, read-only history, and preference arguments with stubbed runtime'
}finally{
    foreach($file in $files){[IO.File]::Delete((Join-Path $fixtureDirectory $file))}
    [IO.Directory]::Delete($fixtureDirectory)
}

& {
    $counter=[pscustomobject]@{Reads=0;Status=@{CanLaunch=$true}}
    $readStatus={$counter.Reads++;$counter.Status}
    $id='a'*32
    $faultKey="$($id):fault"
    $recoveryKey="$($id):recovery"
    $pauseKey="$($id):pause"
    $notice=@{Id=$id;Reason='ProxyNotReady';Phase='Idle'}
    Assert-Equal $null (Get-GuardDailyPresentation $notice -ReadStatus $readStatus)
    $notice.Phase='Resumed'
    Assert-Equal $null (Get-GuardDailyPresentation $notice -ReadStatus $readStatus)
    $notice.Phase='Closing'
    Assert-Equal $null (Get-GuardDailyPresentation $notice -Seen @($faultKey) -ReadStatus $readStatus)
    Assert-Equal 0 $counter.Reads

    Assert-Equal $null (Get-GuardDailyPresentation $notice -ReadStatus $readStatus)
    Assert-Equal 1 $counter.Reads
    $counter.Status=@{CanLaunch=$false}
    Assert-Equal $faultKey (Get-GuardDailyPresentation $notice -ReadStatus $readStatus).Key
    Assert-Equal 2 $counter.Reads

    $notice.Phase='Stopped'
    Assert-Equal $null (Get-GuardDailyPresentation $notice -Seen @($faultKey) -ReadStatus $readStatus)
    Assert-Equal $faultKey (Get-GuardDailyPresentation $notice -ReadStatus $readStatus).Key
    Assert-Equal 2 $counter.Reads

    $notice.Phase='Ready'
    Assert-Equal $null (Get-GuardDailyPresentation $notice -Seen @($faultKey) -ReadStatus $readStatus)
    Assert-Equal 3 $counter.Reads
    $counter.Status.CanLaunch=$true
    Assert-Equal $recoveryKey (Get-GuardDailyPresentation $notice -Seen @($faultKey) -ReadStatus $readStatus).Key
    Assert-Equal 4 $counter.Reads

    foreach($phase in 'Ready','Idle','Stopped','Closing','StoppingUnverified','Paused','Resumed'){
        $notice.Phase=$phase
        Assert-Equal $null (Get-GuardDailyPresentation $notice -Seen @($faultKey,$recoveryKey,$pauseKey) -ReadStatus $readStatus)
    }
    Assert-Equal 4 $counter.Reads
}
'PASS reads live status only for unseen notifications that need it'

Test-Notice 'Fresh controller only reports recovery after current proof, preserving the confirmed incident' {
    param($f)
    $f.Data.Process=$true
    $f.Data.Proxy='Down'
    $f.Data.Failure='UpstreamTransportDown'
    Invoke-NoticeCycle $f
    $stop=$f.Data.Records['daily-last-guard-stop.json']
    $oldController=$f.Controller
    $f.Controller=New-GuardDailyController $f.Profile
    $oldController.Signal.Dispose()
    $f.Ops.ReadPendingStopNotice={Read-GuardDailyPendingStopNotice}
    function Read-GuardDailyRecord($Name) {$f.Data.Records[$Name]}
    $f.Data.Events.Clear()
    Initialize-GuardDailyNotice $f.Controller $f.Ops
    Assert-Equal $stop.Id $f.Controller.Notice.Id
    Assert-Equal 0 $f.Data.Events.Count

    $f.Data.Proxy='Unknown'
    Invoke-NoticeCycle $f
    Assert-Equal 'Stopped' $f.Data.Records['daily-notice.json'].Phase
    Assert-Equal $false $f.Controller.Decision.CanLaunch
    $f.Data.Proxy='Ready'
    Invoke-NoticeCycle $f
    $ready=$f.Data.Records['daily-notice.json']
    Assert-Equal 'Ready' $ready.Phase
    Assert-Equal $stop.Id $ready.Id
    Assert-Equal 'UpstreamTransportDown' $ready.Reason
    Assert-Equal $stop.Utc $f.Data.Records['daily-last-guard-stop.json'].Utc
    Assert-Equal $false $f.Data.Process
    Assert-Equal $null (Get-GuardDailyPresentation $ready @{CanLaunch=$true;Generation=('A'*64)})
    $shown=Get-GuardDailyPresentation $ready @{CanLaunch=$true;Generation=$f.Profile.Generation} @("$($stop.Id):fault")
    Assert-Equal "$($stop.Id):recovery" $shown.Key
    Assert-Equal $null (Get-GuardDailyPresentation $ready @{CanLaunch=$true;Generation=$f.Profile.Generation} @($shown.Key))
    Invoke-NoticeCycle $f
    Assert-Equal $ready.Utc $f.Data.Records['daily-notice.json'].Utc
}

& {
    function Read-GuardDailyRecord($Name) {$records[$Name]}
    $stopped=New-GuardDailyNotice 'Stopped' 'ExitChanged' ('a'*32)
    $records=@{'daily-last-guard-stop.json'=$stopped}
    Assert-Equal $null (Read-GuardDailyPendingStopNotice)
    foreach($phase in 'Resumed','Ready','Closing','Idle'){
        $records['daily-notice.json']=New-GuardDailyNotice $phase 'ExitChanged' $stopped.Id
        Assert-Equal $null (Read-GuardDailyPendingStopNotice)
    }
    $records['daily-notice.json']=New-GuardDailyNotice 'Stopped' 'ExitChanged' ('b'*32)
    Assert-Equal $null (Read-GuardDailyPendingStopNotice)
    $records['daily-notice.json']=$stopped.PSObject.Copy()
    $records['daily-notice.json'].Reason='ProxyNotReady'
    Assert-Equal $null (Read-GuardDailyPendingStopNotice)
    $records['daily-notice.json']=$stopped.PSObject.Copy()
    $records['daily-notice.json'].Utc=[datetime]::UtcNow.AddSeconds(-1).ToString('o')
    Assert-Equal $null (Read-GuardDailyPendingStopNotice)
    $records['daily-notice.json']=$stopped
    Assert-Equal $stopped.Id (Read-GuardDailyPendingStopNotice).Id
}
'PASS stale, mismatched, and incomplete recovery receipts are ignored'

& {
    $history=@{}
    function Read-GuardDailyRecord($Name) {$history[$Name]}
    $writer={param($name,$value) $history[$name]=$value}
    $verified=@{NetworkBlocked=$true;ObservedProcess=$true;Exited=$true}
    $oldStop=New-GuardDailyNotice 'Stopped' 'UpstreamTransportDown' ''
    $history['daily-last-guard-stop.json']=$oldStop
    foreach($property in 'NetworkBlocked','ObservedProcess','Exited'){
        $invalid=$verified.Clone()
        $invalid[$property]=$false
        Publish-GuardDailyStoreStopNotice $invalid $true $writer
        Assert-Equal $oldStop.Id $history['daily-last-guard-stop.json'].Id
    }
    Publish-GuardDailyStoreStopNotice $verified $false $writer
    Assert-Equal $oldStop.Id $history['daily-last-guard-stop.json'].Id
    Publish-GuardDailyStoreStopNotice $verified $true $writer
    $receipt=$history['daily-last-guard-stop.json']
    Assert-Equal 'StoreUpdateHandoff' $receipt.Reason
    Assert-Equal 'Stopped' $receipt.Phase
    Assert-Equal $false ($receipt.Id -ceq $oldStop.Id)
    Assert-Equal $receipt.Id (Read-GuardDailyPendingStopNotice).Id
    Assert-Equal $true ((Get-GuardDailyNoticeReasonText $receipt.Reason) -match 'Microsoft Store')
}
'PASS Store reason requires verified block, identified process, real stop action, and confirmed exit'


Test-Notice 'Store takeover reuses the prior generation incident without repeating its fault alert' {
    param($f)
    $f.Ops.StoreUpdateDetected=@{Value=$true}
    $f.Ops.VerifyInventory={$false}
    $f.Data.Process=$true
    $f.Data.Stubborn=$true
    Invoke-NoticeCycle $f
    $closing=$f.Data.Records['daily-notice.json']
    Assert-Equal 'Closing' $closing.Phase
    Assert-Equal 'StoreUpdateHandoff' $closing.Reason
    Assert-Equal $f.Profile.Generation $closing.Generation
    Assert-Equal $null $f.Data.Records['daily-last-guard-stop.json']

    function Read-GuardDailyRecord($Name) {$f.Data.Records[$Name]}
    $verified=@{NetworkBlocked=$true;ObservedProcess=$true;Exited=$true}
    Publish-GuardDailyStoreStopNotice $verified $true $f.Ops.WriteNotice -PreviousGeneration $f.Profile.Generation
    $stop=$f.Data.Records['daily-last-guard-stop.json']
    Assert-Equal $closing.Id $stop.Id
    Assert-Equal 'Stopped' $stop.Phase
    Assert-Equal $null (Get-GuardDailyPresentation $stop $null @("$($closing.Id):fault"))
}


Test-Notice 'An independent window exit between snapshot and close never replaces guard stop history' {
    param($f)
    $data=$f.Data
    $prior=New-GuardDailyNotice 'Stopped' 'ExitChanged' ('b'*32)
    $data.Records['daily-last-guard-stop.json']=$prior
    $data.Process=$true
    $data.Proxy='Down'
    $f.Ops.RequestClose={
        # The window already closed on its own after the snapshot.
        $data.Process=$false
        $false
    }.GetNewClosure()
    $f.Ops.ForceStop={throw 'Force stop must never act on an already exited fixture process'}
    Invoke-NoticeCycle $f
    Assert-Equal $true $f.Controller.Shutdown.NetworkBlocked
    Assert-Equal $true $f.Controller.Shutdown.Exited
    Assert-Equal $true $f.Controller.Shutdown.ObservedProcess
    Assert-Equal $prior.Id $data.Records['daily-last-guard-stop.json'].Id
    Assert-Equal $null $data.Records['daily-notice.json']
}


Test-Notice 'A delivered graceful close records the confirmed guard stop without a force stop' {
    param($f)
    $data=$f.Data
    $data.Process=$true
    $data.Proxy='Down'
    $f.Ops.RequestClose={param($entry)
        if($entry.Id -ne 17 -or $entry.Start -ne 25){throw 'Unexpected close identity'}
        $data.Process=$false
        $true
    }.GetNewClosure()
    $f.Ops.ForceStop={throw 'Graceful exit already completed'}
    Invoke-NoticeCycle $f
    Assert-Equal $true $f.Controller.Shutdown.ConfirmedCloseAction
    Assert-Equal 'ProxyNotReady' $data.Records['daily-last-guard-stop.json'].Reason
}

& {
    $snapshots=[Collections.Generic.Queue[object]]::new()
    $snapshots.Enqueue([pscustomobject]@{Id=17;Start=25})
    $snapshots.Enqueue([pscustomobject]@{Id=17;Start=35})
    $snapshots.Enqueue($null)
    $result=@(Stop-GuardDailySession @{
        CloseGate={$true}
        Snapshot={$item=$snapshots.Dequeue(); if($item){$item}}
        NotifyClosure={$true}
        RequestClose={'true'}
        Wait={$true}
        ForceStop={throw 'Unexpected stop on a reused PID'}
    })
    Assert-Equal 1 $result.Count
    Assert-Equal $true $result[0].Exited
    Assert-Equal $false $result[0].ConfirmedCloseAction
    Assert-Equal 0 $result[0].StopErrors
}
'PASS the stop returns one result and ignores unbound signals, non-boolean acknowledgments and reused PIDs'
