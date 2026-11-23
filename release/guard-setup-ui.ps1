#Requires -Version 5.1
[CmdletBinding()]
param([string]$Stage=(Split-Path -Parent $PSScriptRoot),[string]$BootstrapPath,[switch]$Settings,[switch]$DefineOnly)

$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
. (Join-Path $PSScriptRoot 'guard-profile-actions.ps1')

function Get-GuardSettingsErrorText([string]$Message,[string]$Code){
    if($Code -ceq 'ProbeCancelled'){return '试测已取消。'}
    if($Code -ceq 'ProbeTimedOut'){return '出口查询超时。确认 Bettbox 已连接，再点一次“试测出口”。'}
    if($Code -ceq 'ProbeExitUnverified'){return '这个节点没有返回可核实的公网 IPv4。请核对链接和 Bettbox 连接。'}
    if($Message -match 'expired|since the exit check'){return '试测已过期或节点已变更，请重新试测。'}
    if($Message -match 'time zone|country|region'){return '时区预览已失效或 Windows 未能应用它。请重新选择并试测。'}
    if($Message -match 'registered|Store (Desktop|app)|Claude must|protected .*running|closed.*Desktop'){
        return '请确认已经安装 Microsoft 商店版 Claude Desktop，并手动关闭它，再重试。'
    }
    if($Message -match 'Bettbox|tunnel'){return '请先连接 Bettbox，并确认 TUN 模式已开启。'}
    if($Message -match 'node|VLESS|link|Reality|WebSocket|credential|TLS|IPv4|query parameter'){
        return '请粘贴一条完整的 VLESS 节点链接。支持数字 IPv4 上游的 Reality TCP 和 WebSocket TLS。'
    }
    if($Message -match 'pending|recovery|unfinished'){return '发现上一次未完成的变更。请先恢复该次操作。'}
    if($Message -match 'administrator|permission|access'){return 'Windows 未授予所需权限。请使用安装 Guard 的管理员账户打开。'}
    if($Code){return '这个节点的出口尚未核实。请核对节点链接后重试。'}
    '操作未完成。请检查 Bettbox 连接和安装条件，再重试。'
}

function New-GuardSettingsWindow([string]$Stage,[string]$BootstrapPath,[string]$Mode,[switch]$Settings,[switch]$RecoveryPending){
    [Windows.Forms.Application]::EnableVisualStyles()
    $ink=[Drawing.ColorTranslator]::FromHtml('#15352C')
    $accent=[Drawing.ColorTranslator]::FromHtml('#17624D')
    $muted=[Drawing.ColorTranslator]::FromHtml('#4A635C')
    $surface=[Drawing.ColorTranslator]::FromHtml('#F3F7F5')
    $form=[Windows.Forms.Form]::new()
    $form.Text=if($Settings){'Claude Guard · 节点设置'}else{'Claude Guard · 安装与更新'}
    $form.StartPosition='CenterScreen'
    $form.AutoScaleMode='Dpi';$form.AutoScaleDimensions=[Drawing.SizeF]::new(96,96)
    $form.Font=[Drawing.Font]::new('Microsoft YaHei UI',10)
    $form.ClientSize=[Drawing.Size]::new(608,542);$form.MinimumSize=[Drawing.Size]::new(560,570)
    $form.BackColor=[Drawing.Color]::White;$form.ForeColor=$ink
    $layout=[Windows.Forms.TableLayoutPanel]::new()
    $layout.Dock='Fill';$layout.Padding=[Windows.Forms.Padding]::new(28,22,28,20)
    $layout.ColumnCount=1;$layout.RowCount=12
    $layout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent',100))|Out-Null
    foreach($height in 39,48,30,36,30,30,38,32,88,12){
        $layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute',$height))|Out-Null
    }
    $layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent',100))|Out-Null
    $layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute',44))|Out-Null
    $form.Controls.Add($layout)
    function New-Caption([string]$Text,[int]$Row){
        $label=[Windows.Forms.Label]::new();$label.AutoEllipsis=$false;$label.Dock='Fill'
        $label.TextAlign='MiddleLeft';$label.Margin=[Windows.Forms.Padding]::new(0);$label.Text=$Text
        $layout.Controls.Add($label,0,$Row)
        $label
    }
    function New-ActionButton([string]$Text,[int]$Width,[bool]$Primary){
        $b=[Windows.Forms.Button]::new()
        $b.Text=$Text;$b.Width=$Width;$b.Height=36;$b.Cursor=[Windows.Forms.Cursors]::Hand;$b.FlatStyle='Flat'
        $b.Margin=[Windows.Forms.Padding]::new(6,2,0,2);$b.UseVisualStyleBackColor=$false
        if($Primary){$b.BackColor=$accent;$b.ForeColor=[Drawing.Color]::White;$b.FlatAppearance.BorderSize=0}
        else{$b.BackColor=[Drawing.Color]::White;$b.ForeColor=$ink;$b.FlatAppearance.BorderColor=[Drawing.Color]::Silver}
        $b
    }
    $titleText=if($Settings){'节点与出口'}elseif($Mode -ceq 'Update'){'更新 Claude Guard'}else{'安装 Claude Guard'}
    $heading=New-Caption $titleText 0
    $heading.Font=[Drawing.Font]::new('Microsoft YaHei UI',19,[Drawing.FontStyle]::Bold)
    $description=if($Mode -ceq 'Fresh'){'先连接 Bettbox TUN，并安装商店版 Claude Desktop。填入节点后，Guard 会从这条线路实测出口。'}
        elseif($Settings){'换节点时，先试测它的公网 IPv4，再应用节点和时区。'}
        else{'可以直接更新现有防护。想换节点时，请先试测新线路的公网 IPv4。'}
    $sub=New-Caption $description 1;$sub.ForeColor=$muted
    $null=New-Caption 'Bettbox 节点链接' 2
    $node=[Windows.Forms.TextBox]::new();$node.Dock='Top';$node.MaxLength=4096
    $node.UseSystemPasswordChar=$true;$node.AccessibleName='VLESS 节点链接';$node.Margin=[Windows.Forms.Padding]::new(0,3,0,0)
    $layout.Controls.Add($node,0,3)
    $show=[Windows.Forms.CheckBox]::new();$show.AutoSize=$true;$show.Text='显示链接';$show.Margin=[Windows.Forms.Padding]::new(0,0,0,3)
    $layout.Controls.Add($show,0,4)
    $null=New-Caption '应用后的 Windows 时区' 5
    $region=[Windows.Forms.ComboBox]::new();$region.DropDownStyle='DropDownList';$region.Dock='Top';$region.Margin=[Windows.Forms.Padding]::new(0,3,0,0)
    $catalog=Get-GuardSettingsTimeZones $Stage
    $regionIds=@('Automatic','Keep','Japan','UsPacific')+@($catalog.Items | ForEach-Object Id)
    $choices=@('根据出口国家建议','保留当前时区','日本 · 东京','美国西部 · 洛杉矶')+@($catalog.Items | ForEach-Object Label)
    $region.MaxDropDownItems=12
    $null=$region.Items.AddRange([object[]]$choices)
    $region.SelectedIndex=0;$region.AccessibleName='应用后的 Windows 时区';$layout.Controls.Add($region,0,6)
    $hint=New-Caption '出口国家有多个时区时，请手动选择。' 7;$hint.ForeColor=$muted
    $status=New-Caption '等待试测出口。' 8
    $status.BackColor=$surface;$status.Padding=[Windows.Forms.Padding]::new(14,6,14,6);$status.AccessibleName='操作结果'
    $buttons=[Windows.Forms.FlowLayoutPanel]::new();$buttons.Dock='Fill';$buttons.WrapContents=$false
    $buttons.FlowDirection='RightToLeft';$buttons.Margin=[Windows.Forms.Padding]::new(0)
    $layout.Controls.Add($buttons,0,11)
    $applyText=if($Mode -ceq 'Fresh'){'安装并应用'}else{'应用节点'}
    $apply=New-ActionButton $applyText 106 $true;$apply.Enabled=$false;$buttons.Controls.Add($apply)
    $probe=New-ActionButton '试测出口' 95 $false;$buttons.Controls.Add($probe)
    $update=New-ActionButton '保留配置并更新' 143 $false;$update.Visible=$Mode -ceq 'Update' -and -not $Settings;$buttons.Controls.Add($update)
    $cancel=New-ActionButton '取消试测' 95 $false;$cancel.Visible=$false;$buttons.Controls.Add($cancel)
    $recover=New-ActionButton '恢复上次操作' 134 $true;$recover.Visible=$RecoveryPending.IsPresent;$buttons.Controls.Add($recover)
    if($RecoveryPending){
        $probe.Visible=$false;$apply.Visible=$false;$update.Visible=$false;$node.Enabled=$false;$region.Enabled=$false
        $status.Text='上次变更中途停止。先恢复它，再选择要使用的节点。'
    }
    $timer=[Windows.Forms.Timer]::new();$timer.Interval=180
    $state=@{Mode=$Mode;Profile=$null;Proof=$null;RegionPlan=$null;Work=$null;CloseAfter=$false;Applied=$false}
    $clearProof={
        if($state.Profile){$state.Profile.Password.Dispose()}
        $state.Profile=$null;$state.Proof=$null;$state.RegionPlan=$null;$apply.Enabled=$false
    }.GetNewClosure()
    $drawProof={
        if(-not $state.Profile -or -not $state.Proof){return}
        try{
            Assert-GuardSettingsPreview $state.Profile $state.Proof
            $choice=Get-GuardSettingsRegionChoice $catalog $regionIds[$region.SelectedIndex] $state.Proof.CountryCode
            $country=if($state.Proof.CountryCode){'  ·  '+$state.Proof.CountryCode}else{''}
            $status.Text="允许出口 IPv4  $($state.Proof.ExitIpv4)$country"
            if($choice.RequiresChoice){
                $state.RegionPlan=$null;$apply.Enabled=$false
                $status.Text+=[Environment]::NewLine+$(if($choice.TimeZoneCount -gt 1){'这个国家有多个时区。请选择城市，或保留当前时区。'}else{'本次查询没有确定时区。请选择城市，或保留当前时区。'})
                return
            }
            $state.RegionPlan=New-GuardRegionProfilePlan -ProfileId $choice.Id -ObservedCountryCode $state.Proof.CountryCode -Operations (New-GuardWindowsRegionOperations)
            $zone=if($choice.Id -ceq 'Keep'){'保留当前时区'}elseif($choice.Id -ceq 'Japan'){'日本 · 东京'}
                elseif($choice.Id -ceq 'UsPacific'){'美国西部 · 洛杉矶'}else{[TimeZoneInfo]::FindSystemTimeZoneById($choice.TimeZoneId).DisplayName}
            $status.Text+=[Environment]::NewLine+"应用后  $zone"
            if($state.RegionPlan.AutomaticTimeZoneEnabled -eq $true -and $state.RegionPlan.Changes.Count){
                $status.Text+=[Environment]::NewLine+'Windows 自动时区已开启，系统稍后可能自行调整。'
            }
            $apply.Enabled=$true
        }catch{$apply.Enabled=$false;$status.Text=Get-GuardSettingsErrorText $_.Exception.Message}
    }.GetNewClosure()
    $actionsPath=Join-Path $Stage 'release\guard-profile-actions.ps1'
    $startWork={
        param([string]$Kind)
        if($state.Work){return}
        if($Kind -ceq 'Probe'){
            & $clearProof
            try{$state.Profile=New-GuardNodeProfile -Text $node.Text}
            catch{$status.Text=Get-GuardSettingsErrorText $_.Exception.Message 'InvalidNode';return}
        }
        if($Kind -ceq 'Apply'){
            try{Assert-GuardSettingsPreview $state.Profile $state.Proof}
            catch{$status.Text=Get-GuardSettingsErrorText $_.Exception.Message;$apply.Enabled=$false;return}
        }
        $cts=[Threading.CancellationTokenSource]::new()
        $engine=[Management.Automation.PowerShell]::Create()
        $scriptText=@'
param($actions,$kind,$stage,$bootstrap,$profile,$proof,$plan,$token)
$ErrorActionPreference='Stop'
. $actions
if($kind -ceq 'Probe'){Get-GuardSettingsNodePreview $stage $profile $token}
elseif($kind -ceq 'Recover'){Invoke-GuardSettingsRecovery}
elseif($kind -ceq 'Update'){Invoke-GuardSettingsInstall $stage $bootstrap}
else{Invoke-GuardSettingsInstall $stage $bootstrap $profile $proof $plan}
'@
        $null=$engine.AddScript($scriptText)
        foreach($arg in @($actionsPath,$Kind,$Stage,$BootstrapPath,$state.Profile,$state.Proof,$state.RegionPlan,$cts.Token)){
            $null=$engine.AddArgument($arg)
        }
        try{$async=$engine.BeginInvoke()}catch{$engine.Dispose();$cts.Dispose();$status.Text='Windows 未能启动此操作。';return}
        $state.Work=@{Kind=$Kind;Engine=$engine;Token=$cts;Async=$async}
        $node.Enabled=$false;$show.Enabled=$false;$region.Enabled=$false
        $probe.Enabled=$false;$apply.Enabled=$false;$update.Enabled=$false;$recover.Enabled=$false;$cancel.Visible=$Kind -ceq 'Probe'
        $status.Text=if($Kind -ceq 'Probe'){'正在通过填写的节点核对公网 IPv4…'}else{'正在应用防护并核对后台状态。完成后会在这里显示结果。'}
        $timer.Start()
    }.GetNewClosure()
    $show.Add_CheckedChanged({$node.UseSystemPasswordChar=-not $show.Checked}.GetNewClosure())
    $node.Add_TextChanged({& $clearProof;$state.Applied=$false;$status.Text='等待试测出口。'}.GetNewClosure())
    $region.Add_SelectedIndexChanged({& $drawProof}.GetNewClosure())
    $probe.Add_Click({& $startWork 'Probe'}.GetNewClosure())
    $apply.Add_Click({& $startWork 'Apply'}.GetNewClosure())
    $update.Add_Click({& $startWork 'Update'}.GetNewClosure())
    $recover.Add_Click({& $startWork 'Recover'}.GetNewClosure())
    $cancel.Add_Click({if($state.Work.Kind -ceq 'Probe'){$state.Work.Token.Cancel();$status.Text='正在结束这次试测…'}}.GetNewClosure())
    $timer.Add_Tick({
        $work=$state.Work
        if(-not $work -or -not $work.Async.IsCompleted){return}
        $timer.Stop()
        try{
            $values=@($work.Engine.EndInvoke($work.Async))
            if($values.Count -ne 1){throw 'No valid operation result.'}
            $result=$values[0]
            if($work.Kind -ceq 'Probe'){
                if($result.Passed){$state.Proof=$result;& $drawProof}
                else{& $clearProof;$status.Text=Get-GuardSettingsErrorText '' $result.ErrorCode}
            }elseif($work.Kind -ceq 'Recover' -and $result.Restored){
                $recover.Visible=$false;$probe.Visible=$true;$apply.Visible=$true;$update.Visible=($state.Mode -ceq 'Update' -and -not $Settings)
                $status.Text='上次变更已恢复。可以继续安装或试测节点。'
            }elseif($result.Installed){
                $state.Applied=$true;$state.Mode='Update'
                $apply.Text='应用节点';$heading.Text='节点与出口'
                $node.Clear();& $clearProof
                $status.Text=if($result.GuardedEntry -ceq 'StartMenu'){'防护已就绪。请从开始菜单的 Claude Desktop - Guarded 手动打开。'}
                    elseif($result.GuardedEntry -ceq 'File'){'防护已就绪。手动入口为 '+(Get-GuardDataPath 'daily\open-claude-daily.cmd')}
                    else{'防护已就绪。请从桌面的 Claude Desktop - Guarded 手动打开。'}
                if($result.SettingsShortcut){$status.Text+=[Environment]::NewLine+'以后可从开始菜单的 Claude Guard Settings 更换节点。'}
                else{$status.Text+=[Environment]::NewLine+'要再次换节点，请重新打开此安装程序。'}
                $update.Visible=$false
            }else{
                $status.Text=Get-GuardSettingsErrorText ([string]$result.Error)
                if($result.Restored){$status.Text+=[Environment]::NewLine+'上一份配置已恢复。'}
            }
        }catch{$status.Text=Get-GuardSettingsErrorText $_.Exception.GetBaseException().Message}
        finally{
            $work.Engine.Dispose();$work.Token.Dispose();$state.Work=$null
            $node.Enabled=$true;$show.Enabled=$true;$region.Enabled=$true;$probe.Enabled=$true;$update.Enabled=$true;$cancel.Visible=$false
            $recover.Enabled=$true
            if($recover.Visible){$node.Enabled=$false;$region.Enabled=$false}
            if($state.CloseAfter){$form.Close()}
        }
    }.GetNewClosure())
    $form.Add_FormClosing({
        param($sender,$eventArgs)
        if($state.Work){
            $eventArgs.Cancel=$true
            if($state.Work.Kind -ceq 'Probe'){$state.CloseAfter=$true;$state.Work.Token.Cancel()}
            else{$status.Text='正在完成防护切换。核对完成后可以关闭窗口。'}
        }
    }.GetNewClosure())
    $form.Add_FormClosed({$timer.Dispose();& $clearProof}.GetNewClosure())
    [pscustomobject]@{Form=$form;Input=$node;Regions=$region;Preview=$probe;Confirm=$apply;Update=$update;Output=$status;State=$state}
}

if(-not $DefineOnly){
    $plan=& (Join-Path $Stage 'release\install-guard.ps1') -Plan
    $view=New-GuardSettingsWindow -Stage $Stage -BootstrapPath $BootstrapPath -Mode $plan.Mode -Settings:$Settings -RecoveryPending:$plan.RecoveryPending
    try{[Windows.Forms.Application]::Run($view.Form)}finally{$view.Form.Dispose()}
}
