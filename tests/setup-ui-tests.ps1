#Requires -Version 5.1
param([string]$PreviewPath)
$ErrorActionPreference='Stop'
$project=Split-Path -Parent $PSScriptRoot
. "$project\release\guard-setup-ui.ps1" -DefineOnly
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('guard-settings-view-'+[guid]::NewGuid().ToString('N'))
$testRelease=Join-Path $scratch 'release'
$null=[IO.Directory]::CreateDirectory($testRelease)
[IO.File]::Copy((Join-Path $project 'release\guard-region-zones.json'),(Join-Path $testRelease 'guard-region-zones.json'))
$realActions=(Join-Path $project 'release\guard-profile-actions.ps1').Replace("'","''")
$fixture=@'
. '__ACTIONS__'
function Get-GuardSettingsNodePreview($stage,$profile,$token){
    $token.ThrowIfCancellationRequested()
    $route=Get-GuardNodeProfileRoute $profile 18881
    [pscustomobject]@{Passed=$true;State='Completed';Provider='CloudflareTrace';ExitIpv4='198.51.100.17';CountryCode='JP'
        CheckedUtc=[datetime]::UtcNow.ToString('o');ProfileFingerprint=$route.ProfileFingerprint}
}
function Invoke-GuardSettingsInstall($stage,$bootstrap,$profile,$proof,$plan){
    if($profile){Assert-GuardSettingsPreview $profile $proof;if($plan.ProfileId -cne 'Japan'){throw 'Incorrect display selection.'}}
    [pscustomobject]@{Installed=$true;SettingsShortcut=$true}
}
'@
[IO.File]::WriteAllText((Join-Path $testRelease 'guard-profile-actions.ps1'),$fixture.Replace('__ACTIONS__',$realActions),[Text.UTF8Encoding]::new($true))
function Assert-View([bool]$Condition,[string]$Name){if(-not $Condition){throw $Name};"PASS $Name"}
function Show-TestForm($View){
    $View.Form.ShowInTaskbar=$false;$View.Form.StartPosition='Manual';$View.Form.Location=[Drawing.Point]::new(-10000,-10000)
    $View.Form.Show();[Windows.Forms.Application]::DoEvents()
}
function Wait-TestOperation($View){
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do{[Windows.Forms.Application]::DoEvents();[Threading.Thread]::Sleep(20)}while($View.State.Work -and $watch.Elapsed.TotalSeconds -lt 15)
    if($View.State.Work){throw 'The settings window remained busy.'}
}
$views=@()
try{
    $view=New-GuardSettingsWindow $scratch 'synthetic.exe' 'Fresh';$views+=$view;Show-TestForm $view
    Assert-View ($view.Input.UseSystemPasswordChar -and -not $view.Confirm.Enabled -and -not $view.Update.Visible) 'Fresh install masks credentials and awaits a verified exit'
    $view.Input.Text='invalid';$view.Preview.PerformClick();[Windows.Forms.Application]::DoEvents()
    Assert-View (-not $view.State.Work -and $view.Output.Text -like '*VLESS*' -and -not $view.Confirm.Enabled) 'Malformed pasted nodes stay local and cannot be applied'
    $view.Input.Text='vless://c2c36769-368d-4aec-b542-ec19b777521f@198.51.100.65:443?type=ws&security=tls&sni=example.test&host=example.test&path=%2Fguard&encryption=none'
    $view.Preview.PerformClick();Wait-TestOperation $view
    Assert-View ($view.Confirm.Enabled -and $view.Output.Text -like '*198.51.100.17*' -and $view.State.RegionPlan.ProfileId -ceq 'Japan') 'A verified Japanese exit suggests Tokyo in the asynchronous window without a second lookup'
    $view.Regions.SelectedIndex=1;[Windows.Forms.Application]::DoEvents()
    Assert-View ($view.State.RegionPlan.ProfileId -ceq 'Keep' -and $view.Confirm.Enabled) 'The user can keep the current time zone after an automatic suggestion'
    $view.Regions.SelectedIndex=2;[Windows.Forms.Application]::DoEvents()
    Assert-View ($view.State.RegionPlan.ProfileId -ceq 'Japan' -and $view.Output.Text -like '*东京*' -and $view.Output.Text -notlike '*vless*') 'Explicitly selecting Tokyo does not issue another network request'
    if($PreviewPath){
        $image=[Drawing.Bitmap]::new($view.Form.Width,$view.Form.Height)
        try{$view.Form.DrawToBitmap($image,[Drawing.Rectangle]::new(0,0,$image.Width,$image.Height));$image.Save($PreviewPath,[Drawing.Imaging.ImageFormat]::Png)}
        finally{$image.Dispose()}
    }
    $view.Confirm.PerformClick();Wait-TestOperation $view
    Assert-View ($view.Output.Text -like '*防护已就绪*' -and -not $view.Input.Text -and -not $view.Confirm.Enabled) 'Confirm submits the reviewed node and clears its secret after success'
    $existing=New-GuardSettingsWindow $scratch 'synthetic.exe' 'Update';$views+=$existing;Show-TestForm $existing
    Assert-View ($existing.Update.Visible -and $existing.Update.Enabled) 'An existing installation offers an update without a new node'
    $existing.Update.PerformClick();Wait-TestOperation $existing
    Assert-View ($existing.Output.Text -like '*防护已就绪*') 'The file update completes without changing the selected node'
    $recovery=New-GuardSettingsWindow $scratch 'synthetic.exe' 'Update' -Settings -RecoveryPending;$views+=$recovery;Show-TestForm $recovery
    Assert-View (-not $recovery.Input.Enabled -and -not $recovery.Preview.Visible -and $recovery.Output.Text -like '*先恢复*') 'Interrupted installations expose recovery before another node can be applied'
}finally{
    foreach($item in $views){$item.Form.Close();$item.Form.Dispose()}
    $full=[IO.Path]::GetFullPath($scratch)
    if([IO.Path]::GetDirectoryName($full).TrimEnd('\') -eq [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -and
        [IO.Path]::GetFileName($full) -cmatch '^guard-settings-view-[a-f0-9]{32}$'){
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}
