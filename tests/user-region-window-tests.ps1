#Requires -Version 5.1
$ErrorActionPreference='Stop'
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { throw 'Run this source fixture in Windows PowerShell STA.' }
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Xaml
$source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\release\GuardUserRegionWindow.cs'))
$compiler = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
$references = @([Windows.Window],[Windows.Media.Visual],[Windows.DependencyObject],[Xaml.XamlReader]) |
    ForEach-Object {'/reference:'+$_.Assembly.Location}
$output = Join-Path ([IO.Path]::GetTempPath()) ('guard-user-region-window-'+[Guid]::NewGuid().ToString('N')+'.dll')

function Assert-WindowFixture([bool]$Condition,[string]$Name) {
    if (!$Condition) { throw "FAIL: $Name" }
    "PASS: $Name"
}

try {
    & $compiler '/nologo' '/target:library' '/langversion:5' '/codepage:65001' @references ('/out:'+$output) $source
    if ($LASTEXITCODE -ne 0) { throw 'The ordinary-user region window did not compile.' }
    $type = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($output)).GetType('GuardUserRegionWindow',$true)
    $instance = [Reflection.BindingFlags]'NonPublic,Instance'
    $ctor = $type.GetConstructors($instance)[0]
    $read = [Func[Collections.IDictionary]] { throw 'Opening source fixture must never start callbacks.' }
    $apply = [Func[string,string,Collections.IDictionary]] { throw 'Fixture must never apply settings.' }
    $confirm = [Func[string]] { throw 'Fixture must never check a browser.' }
    $open = [Action[string]] { throw 'Fixture must never open external settings.' }
    $window = $ctor.Invoke(@($read,$apply,$confirm,$open))
    $present = $type.GetMethod('Present',$instance)
    $applyButton = $type.GetField('applyButton',$instance).GetValue($window)
    $confirmButton = $type.GetField('confirmButton',$instance).GetValue($window)
    $status = $type.GetField('status',$instance).GetValue($window)
    $failureDetail = $type.GetField('failureDetail',$instance).GetValue($window)
    $windowsLanguageLabel = $type.GetField('windowsLanguageLabel',$instance).GetValue($window)
    $windowsLanguageGuidance = $type.GetField('windowsLanguageGuidance',$instance).GetValue($window)
    $guard = $type.GetField('guard',$instance).GetValue($window)
    $current = $type.GetField('current',$instance).GetValue($window)
    $target = $type.GetField('target',$instance).GetValue($window)
    $window.Content.Measure([Windows.Size]::new(590,460))
    $window.Content.Arrange([Windows.Rect]::new(0,0,590,460))
    $window.Content.UpdateLayout()
    Assert-WindowFixture (!$window.IsVisible -and !$applyButton.IsEnabled -and !$confirmButton.IsEnabled) 'the unshown window cannot apply or confirm without an authenticated receipt'
    Assert-WindowFixture ($status.Text -match '\p{IsCJKUnifiedIdeographs}' -and $guard.Text -match '\p{IsCJKUnifiedIdeographs}') 'empty status and protection are explained in Chinese'

    $receipt = @{
        RequestId='11223344556677889900aabbccddeeff'; Outcome='ManualRequired'; CountryCode='JP'; ExpectedIpv4='192.0.2.12'
        ObservedIpv4='192.0.2.12'; PrimaryLanguage='ja'; BrowserProfile='Default'; EdgeStatus='ManualRequired'
        WebsiteStatus='AwaitingBrowser'; SiteAcceptLanguage='ja'; GuardHealth=@{Readiness='Locked';CheckedUtc='2026-01-01T01:00:00Z'}
        After=@{CountryCode='JP';TimeZone='Tokyo Standard Time';LocaleName='ja-JP';ShortDate='yyyy/MM/dd';ShortTime='HH:mm';PreferredLanguages=@('ja-JP','en-US');EdgeLanguages='en-US,ja'}
        Targets=@{CountryCode='JP';TimeZone='Tokyo Standard Time';LocaleName='ja-JP';EdgeLanguages='ja,en-US'}
        Message='Windows regional settings were verified. Edge website languages need attention.'
    }
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($applyButton.IsEnabled -and $confirmButton.IsEnabled) 'a manual Edge receipt permits an explicit website verification'
    Assert-WindowFixture ($current[2].Text.Contains('ja-JP') -and $current[3].Text.Contains('en-US') -and
        $target[4].Text.StartsWith('ja') -and $current[5].Text -cne 'ja') 'the comparison shows actual settings and never treats a pending header as verified'
    $locked = $guard.Text
    $receipt.GuardHealth.Readiness = 'Ready'
    $receipt.WebsiteStatus = 'Verified'
    $receipt.EdgeStatus = 'PreferencesVerified'
    $receipt.SiteAcceptLanguage = 'ja,en-US;q=0.9'
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($guard.Text -cne $locked -and $current[5].Text -ceq $receipt.SiteAcceptLanguage -and !$window.IsVisible) 'protection and confirmed website evidence update independently in the same unshown window'
    Assert-WindowFixture ($status.Text -match '\p{IsCJKUnifiedIdeographs}' -and $status.Text -notmatch 'Windows regional') 'an English backend message is rendered with a Chinese status'

    $receipt.Outcome = 'Failed'
    $receipt.WebsiteStatus = 'NotChecked'
    $receipt.Message = 'The regional change failed. The prior settings were verified.'
    $receipt.Diagnostics = @{
        Step='WindowsLocaleApply'; WindowsStage='SettingMismatch'; WindowsSetting='RegionalFormat'
        WindowsDifferences=@('Format.ShortDate','EffectiveInputMethod','DefaultInputLocale','Languages.0.LanguageTag','fixture-private-path')
    }
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($failureDetail.Visibility -eq [Windows.Visibility]::Visible -and -not $confirmButton.IsEnabled -and
        $failureDetail.Text.Contains('应用 Windows 地区和语言') -and $failureDetail.Text.Contains('与目标不同') -and
        $failureDetail.Text.Contains('Windows 区域格式') -and $failureDetail.Text.Contains('短日期格式') -and
        $failureDetail.Text.Contains('首选语言或顺序') -and ([regex]::Matches($failureDetail.Text,'默认输入法')).Count -eq 1 -and
        $failureDetail.Text -notmatch 'fixture-private-path|SettingMismatch|Format.ShortDate' -and !$window.IsVisible) `
        'the same unshown failure view explains the Windows step, setting, and distinct differences in plain Chinese'

    $receipt.Diagnostics = @{Step='WindowsLocaleVerification';WindowsStage='FinalMismatch';WindowsDifferences=@('GeoId','CountryCode')}
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($failureDetail.Text.Contains('核对 Windows 地区和语言') -and
        ([regex]::Matches($failureDetail.Text,'Windows 国家或地区')).Count -eq 1) `
        'final verification maps two internal country fields to one useful affected setting'

    $receipt.Outcome = 'RecoveryRequired'
    $receipt.Diagnostics = @{Step='FinalRouteBinding';WindowsStage='NativeWrite';WindowsSetting='UiLanguageOverride'}
    $null = $present.Invoke($window,@($receipt))
    $available = $type.GetField('availableWhileIdle',$instance).GetValue($window)
    Assert-WindowFixture ($failureDetail.Text.Contains('应用后再次核对节点和出口') -and
        -not $failureDetail.Text.Contains('显示语言') -and @($available | Where-Object {$_.IsEnabled}).Count -eq 6) `
        'recovery identifies its own failed step and leaves deliberate manual-setting actions available'

    $receipt.Diagnostics = @{Step='EdgeAvailability'}
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($failureDetail.Text.Contains('检查 Edge 网站语言设置能否调整')) 'Edge availability failure is named directly'
    $receipt.Diagnostics = @{Step='fixture-unknown-step';WindowsSetting='fixture-sensitive-field'}
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($failureDetail.Visibility -eq [Windows.Visibility]::Collapsed -and $failureDetail.Text.Length -eq 0) `
        'unknown diagnostic values do not appear in the result'

    $receipt.Outcome = 'Applied'
    $receipt.Diagnostics = @{Step='ExitProbe'}
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($failureDetail.Visibility -eq [Windows.Visibility]::Collapsed -and $failureDetail.Text.Length -eq 0) `
        'a successful result clears the prior failure details'

    $receipt.Outcome = 'ManualRequired'
    $receipt.WindowsLanguageStatus = 'ManualRequired'
    $receipt.EdgeStatus = 'ManualRequired'
    $receipt.WebsiteStatus = 'AwaitingBrowser'
    $receipt.After.PreferredLanguages = @('en-US','ja')
    $receipt.Targets.PreferredLanguages = @('ja','en-US')
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($windowsLanguageLabel.Text.Contains('需手动') -and $windowsLanguageGuidance.Visibility -eq [Windows.Visibility]::Visible -and
        $windowsLanguageGuidance.Text.Contains('打开“Windows 首选语言”') -and $current[3].Text.StartsWith('en-US') -and $target[3].Text.StartsWith('ja') -and
        $status.Text.Contains('Edge 网站首选语言') -and $confirmButton.IsEnabled) `
        'simultaneous Windows and Edge manual work keeps the live language comparison and both next steps visible'

    $receipt.Outcome = 'Applied'
    $receipt.EdgeStatus = 'PreferencesVerified'
    $receipt.WebsiteStatus = 'Verified'
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($current[5].Text -ceq $receipt.SiteAcceptLanguage -and $windowsLanguageLabel.Text.Contains('需手动') -and
        $windowsLanguageGuidance.Visibility -eq [Windows.Visibility]::Visible -and $status.Text -notmatch '地区和语言已应用') `
        'verified website readback does not claim the Windows preferred-language change is finished'

    $receipt.WindowsLanguageStatus = 'Verified'
    $receipt.After.PreferredLanguages = @('ja','en-US')
    $null = $present.Invoke($window,@($receipt))
    Assert-WindowFixture ($windowsLanguageGuidance.Visibility -eq [Windows.Visibility]::Collapsed -and $current[3].Text.StartsWith('ja') -and
        $windowsLanguageLabel.Text -ceq 'Windows 首选语言') 'Windows manual guidance clears when fresh readback verifies the target language'
} finally {
    if ([IO.File]::Exists($output)) { [IO.File]::Delete($output) }
}
