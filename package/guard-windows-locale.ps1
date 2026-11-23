# These settings belong to the current Windows user. The caller saves the plan
# before applying it, and can use that same plan to recover in a later session.
function Get-GuardWindowsLocaleFields {
    # Values accepted by both GetLocaleInfoEx and SetLocaleInfo. Write the
    # calendar before date formats, and long time before short time.
    [ordered]@{
        Calendar=0x1009;ShortDate=0x1f;LongDate=0x20;YearMonth=0x1006
        LongTime=0x1003;ShortTime=0x79;AM=0x28;PM=0x29
        FirstDayOfWeek=0x100c;FirstWeekOfYear=0x100d
        Decimal=0x0e;Thousands=0x0f;Grouping=0x10;Digits=0x11;LeadingZero=0x12
        NativeDigits=0x13;DigitSubstitution=0x1014;NegativeNumber=0x1010
        Currency=0x14;CurrencyDecimal=0x16;CurrencyThousands=0x17;CurrencyGrouping=0x18
        CurrencyDigits=0x19;CurrencyFormat=0x1b;NegativeCurrencyFormat=0x1c
        PositiveSign=0x50;NegativeSign=0x51;ListSeparator=0x0c;Measurement=0x0d;Paper=0x100a
    }
}

function Initialize-GuardWindowsLocaleApi {
    if('Guard.WindowsLocaleApi' -as [type]){return}
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Guard {
    public static class WindowsLocaleApi {
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetGeoInfo(int geoId, uint type, StringBuilder output, int size, ushort language);
        [DllImport("kernel32", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern int GetUserDefaultGeoName(StringBuilder output, int size);
        [DllImport("kernel32", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool SetUserGeoName(string name);
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetUserDefaultLocaleName(StringBuilder output, int size);
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int GetLocaleInfoEx(string locale, uint type, StringBuilder output, int size);
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool GetUserPreferredUILanguages(uint flags, out uint count, [Out] char[] output, ref uint size);
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool SetLocaleInfo(uint locale, uint type, string value);
        [DllImport("user32", CharSet = CharSet.Unicode)]
        static extern bool SendNotifyMessage(IntPtr window, uint message, IntPtr wParam, string lParam);
        [DllImport("user32", ExactSpelling = true, EntryPoint = "SystemParametersInfoW", SetLastError = true)]
        static extern bool GetSystemParameter(uint action, uint param, out IntPtr value, uint update);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winlangdb.dll", CharSet = CharSet.Unicode)]
        static extern int SetUserLanguages(char delimiter, IntPtr languages);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("bcp47langs.dll", CharSet = CharSet.Unicode)]
        static extern int GetUserLanguageInputMethods(string language, char delimiter, out IntPtr inputs);
        [DllImport("ext-ms-win-globalization-input-l1-1-3.dll", CharSet = CharSet.Unicode)]
        static extern int WGIGetUserLanguageInputMethods(string language, out IntPtr inputs);
        [DllImport("ext-ms-win-globalization-input-l1-1-2.dll", CharSet = CharSet.Unicode)]
        static extern int WGIIsImeInputMethod(IntPtr input, out int isIme);
        [DllImport("combase.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern int WindowsCreateString(string source, int length, out IntPtr value);
        [DllImport("combase.dll", ExactSpelling = true)]
        static extern int WindowsDeleteString(IntPtr value);
        [DllImport("combase.dll", ExactSpelling = true)]
        static extern IntPtr WindowsGetStringRawBuffer(IntPtr value, out uint length);

        public static string UserCountry(int geoId) {
            var buffer = new StringBuilder(8);
            try {
                if (GetUserDefaultGeoName(buffer, buffer.Capacity) == 0)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            } catch (EntryPointNotFoundException) {
                if (GetGeoInfo(geoId, 4, buffer, buffer.Capacity, 0) == 0)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return buffer.ToString();
        }

        public static void EnsureUserCountry(int geoId, string name) {
            if (UserCountry(geoId) != name && !SetUserGeoName(name))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public static string UserLocale() {
            var buffer = new StringBuilder(85);
            if (GetUserDefaultLocaleName(buffer, buffer.Capacity) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return buffer.ToString();
        }

        public static string LocaleValue(string locale, uint field) {
            var buffer = new StringBuilder(128);
            if (GetLocaleInfoEx(locale, field, buffer, buffer.Capacity) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return buffer.ToString();
        }

        public static string UserLocaleValue(uint field) {
            return LocaleValue(null, field);
        }

        public static string UserUiLanguage() {
            const uint MUI_LANGUAGE_NAME = 8;
            uint count;
            uint size = 0;
            if (!GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, out count, null, ref size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var buffer = new char[size];
            if (!GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, out count, buffer, ref size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new string(buffer, 0, Array.IndexOf(buffer, '\0'));
        }

        public static void SetLocaleValue(uint field, string value) {
            const uint LOCALE_USER_DEFAULT = 0x0400;
            if (!SetLocaleInfo(LOCALE_USER_DEFAULT, field, value))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public static void NotifyLocaleChange() {
            SendNotifyMessage(new IntPtr(0xffff), 0x001a, IntPtr.Zero, "intl");
        }

        public static string DefaultInputLocale() {
            const uint SPI_GETDEFAULTINPUTLANG = 0x0059;
            IntPtr result;
            if (!GetSystemParameter(SPI_GETDEFAULTINPUTLANG, 0, out result, 0) || result == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return unchecked((uint)result.ToInt64()).ToString("X8");
        }

        public static void SetPreferredLanguages(string[] tags) {
            // The International module uses this operation before its
            // separate keyboard installation and removal steps.
            var list = String.Join(";", tags);
            IntPtr value;
            Marshal.ThrowExceptionForHR(WindowsCreateString(list, list.Length, out value));
            try {
                Marshal.ThrowExceptionForHR(SetUserLanguages(';', value));
            } finally {
                WindowsDeleteString(value);
            }
        }

        public static string[] LanguageInputs(string tag) {
            const int NotImplemented = unchecked((int)0x80004001);
            IntPtr value;
            var result = GetUserLanguageInputMethods(tag, ';', out value);
            if (result == NotImplemented)
                result = WGIGetUserLanguageInputMethods(tag, out value);
            try {
                Marshal.ThrowExceptionForHR(result);
                uint length;
                var buffer = WindowsGetStringRawBuffer(value, out length);
                if (length == 0) return new string[0];
                return Marshal.PtrToStringUni(buffer, (int)length).Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            } finally {
                WindowsDeleteString(value);
            }
        }

        public static bool IsIme(string input) {
            IntPtr value;
            Marshal.ThrowExceptionForHR(WindowsCreateString(input, input.Length, out value));
            try {
                int isIme;
                return WGIIsImeInputMethod(value, out isIme) >= 0 && isIme != 0;
            } finally {
                WindowsDeleteString(value);
            }
        }
    }
}
'@
}

function ConvertTo-GuardWindowsLanguage($Language) {
    [pscustomobject][ordered]@{
        LanguageTag=[string]$Language.LanguageTag
        InputMethodTips=@($Language.InputMethodTips | ForEach-Object { [string]$_ })
        Spellchecking=[bool]$Language.Spellchecking
        Handwriting=[bool]$Language.Handwriting
    }
}

function Get-GuardWindowsRegionalFormat([string]$LocaleName) {
    # A null locale reads the current user's effective overrides. A named
    # locale with LOCALE_NOUSEROVERRIDE reads the Windows defaults for it.
    $fields=Get-GuardWindowsLocaleFields
    $format=[ordered]@{}
    foreach($field in $fields.Keys){
        $format[$field]=if($LocaleName){
            [Guard.WindowsLocaleApi]::LocaleValue($LocaleName,[uint32]($fields[$field] -bor 2147483648L))
        }else{
            [Guard.WindowsLocaleApi]::UserLocaleValue([uint32]$fields[$field])
        }
    }
    [pscustomobject]$format
}

function Get-GuardWindowsEffectiveInput($Languages,[string]$InputLocale,[string]$AvailableOverride) {
    $languageId=$InputLocale.Substring(4)
    $regularTip="${languageId}:0000"+$InputLocale.Substring(0,4)
    $candidateTips=@($Languages.InputMethodTips | Where-Object {$_ -like "${languageId}:*"} | Sort-Object -Unique)
    if($regularTip -in $candidateTips){return $regularTip}
    if($AvailableOverride -in $candidateTips){return $AvailableOverride}
    if($candidateTips.Count -eq 1){return $candidateTips[0]}
    'HKL:'+$InputLocale
}

function Get-GuardWindowsIndependentLanguages([int]$DelaySeconds) {
    # Read in a fresh Windows PowerShell process and use the Windows Runtime
    # preference list as well as the International cmdlet and saved list.
    $scriptText=@'
$ErrorActionPreference='Stop'
Start-Sleep -Seconds DELAY_SECONDS
$saved=[Microsoft.Win32.Registry]::GetValue('HKEY_CURRENT_USER\Control Panel\International\User Profile','Languages',$null)
$native=Get-WinUserLanguageList -WarningAction SilentlyContinue
$winRt=[Windows.System.UserProfile.GlobalizationPreferences,Windows.System.UserProfile,ContentType=WindowsRuntime]::Languages
[pscustomobject]@{
    OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Saved=@($saved | ForEach-Object {[string]$_})
    Native=@($native | ForEach-Object LanguageTag)
    WinRt=@($winRt | ForEach-Object {[string]$_})
} | ConvertTo-Json -Compress
'@
    $scriptText=$scriptText.Replace('DELAY_SECONDS',$DelaySeconds.ToString([Globalization.CultureInfo]::InvariantCulture))
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptText))
    $image=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'WindowsPowerShell\v1.0\powershell.exe'
    $start=[Diagnostics.ProcessStartInfo]::new($image,('-NoLogo -NoProfile -NonInteractive -EncodedCommand '+$encoded))
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start)
    try{
        $output=$process.StandardOutput.ReadToEndAsync()
        $errorOutput=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(1000*($DelaySeconds+12))){
            try{$process.Kill()}catch{}
            throw 'Windows preferred-language verification timed out.'
        }
        $text=$output.GetAwaiter().GetResult()
        $null=$errorOutput.GetAwaiter().GetResult()
        if($process.ExitCode -ne 0 -or $text.Length -gt 32KB){throw 'The independent Windows language list could not be read.'}
        ConvertFrom-Json -InputObject $text -ErrorAction Stop
    }finally{$process.Dispose()}
}

function New-GuardWindowsLocaleOperations {
    Initialize-GuardWindowsLocaleApi
    @{
        Read={
            $geoId=[int](Get-WinHomeLocation -ErrorAction Stop).GeoId
            $languages=@(foreach($entry in (Get-WinUserLanguageList -ErrorAction Stop)){
                ConvertTo-GuardWindowsLanguage $entry
            })
            $uiOverride=Get-WinUILanguageOverride -ErrorAction Stop
            # Preserve the saved preference exactly, including a stale IME.
            # The default keyboard's input locale comes independently from Windows.
            $inputOverride=[string][Microsoft.Win32.Registry]::GetValue(
                'HKEY_CURRENT_USER\Control Panel\International\User Profile','InputMethodOverride','')
            $inputLocale=[Guard.WindowsLocaleApi]::DefaultInputLocale()
            $availableOverride=''
            if($inputOverride){
                try{
                    $configured=Get-WinDefaultInputMethodOverride -ErrorAction Stop
                    if($configured -and $configured.InputMethodTip){
                        $availableOverride=[string]$configured.InputMethodTip
                    }
                }catch{
                    if($_.CategoryInfo.Category -ne 'InvalidResult'){throw}
                }
            }
            [pscustomobject][ordered]@{
                OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                GeoId=$geoId
                CountryCode=[Guard.WindowsLocaleApi]::UserCountry($geoId)
                LocaleName=[Guard.WindowsLocaleApi]::UserLocale()
                Format=(Get-GuardWindowsRegionalFormat)
                CultureFromLanguageListOptOut=[bool](Get-WinCultureFromLanguageListOptOut -ErrorAction Stop)
                Languages=$languages
                UiLanguageOverride=$(if($uiOverride){[string]$uiOverride.Name}else{''})
                EffectiveUiLanguage=[Guard.WindowsLocaleApi]::UserUiLanguage()
                InputMethodOverride=$inputOverride
                InputMethodOverrideAvailable=[bool]$availableOverride
                DefaultInputLocale=$inputLocale
                EffectiveInputMethod=(Get-GuardWindowsEffectiveInput $languages $inputLocale $availableOverride)
            }
        }
        DefaultFormat={
            param($LocaleName)
            Get-GuardWindowsRegionalFormat $LocaleName
        }
        DefaultLanguage={
            param($LocaleName)
            # Read existing input and writing preferences for the target
            # language, including an empty input list. Add no keyboard.
            $tips=@([Guard.WindowsLocaleApi]::LanguageInputs($LocaleName))
            $spell=[Microsoft.Win32.Registry]::GetValue(
                'HKEY_CURRENT_USER\Software\Microsoft\Spelling\Spellers\Disabled',$LocaleName,$null)
            $isoCode=[Globalization.CultureInfo]::GetCultureInfo($LocaleName).TwoLetterISOLanguageName
            $page=[Microsoft.Win32.Registry]::GetValue(
                'HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7\PagePreference',$isoCode,$null)
            $handwriting=if($page -is [byte[]]){
                [byte]0 -in $page
            }else{
                @($tips | Where-Object {[Guard.WindowsLocaleApi]::IsIme($_)}).Count -gt 0
            }
            [pscustomobject]@{
                LanguageTag=$LocaleName;InputMethodTips=$tips;Spellchecking=(-not ($spell -is [int] -and $spell))
                Handwriting=$handwriting
            }
        }
        ReadIndependentLanguages={param($delay) Get-GuardWindowsIndependentLanguages $delay}
        Write={
            param($Setting,$State,[switch]$PublishLanguage)
            switch -Exact ($Setting){
                'UiLanguageOverride' {
                    if($State.UiLanguageOverride){
                        Set-WinUILanguageOverride -Language $State.UiLanguageOverride -ErrorAction Stop
                    }else{
                        Set-WinUILanguageOverride -ErrorAction Stop
                    }
                }
                'CultureFromLanguageListOptOut' {
                    Set-WinCultureFromLanguageListOptOut -OptOut $State.CultureFromLanguageListOptOut -ErrorAction Stop
                }
                'Languages' {
                    [Guard.WindowsLocaleApi]::SetPreferredLanguages([string[]]$State.Languages.LanguageTag)
                    if($PublishLanguage){
                        # The supported International cmdlet submits the same
                        # language profile as Set-WinUserLanguageList, without
                        # removing or installing any keyboard layouts.
                        Set-WinCultureFromLanguageListOptOut -OptOut $State.CultureFromLanguageListOptOut -ErrorAction Stop
                    }
                }
                'HomeLocation' {
                    Set-WinHomeLocation -GeoId $State.GeoId -ErrorAction Stop
                    [Guard.WindowsLocaleApi]::EnsureUserCountry($State.GeoId,$State.CountryCode)
                }
                'RegionalFormat' {
                    Set-Culture -CultureInfo $State.LocaleName -ErrorAction Stop
                    $fields=Get-GuardWindowsLocaleFields
                    foreach($field in $fields.Keys){
                        try{
                            $value=[string]$State.Format.$field
                            if([Guard.WindowsLocaleApi]::UserLocaleValue([uint32]$fields[$field]) -cne $value){
                                [Guard.WindowsLocaleApi]::SetLocaleValue([uint32]$fields[$field],$value)
                            }
                        }catch{
                            $_.Exception.Data['GuardWindowsLocaleField']='Format.'+$field
                            throw
                        }
                    }
                    [Guard.WindowsLocaleApi]::NotifyLocaleChange()
                }
                default {throw 'An unknown Windows locale setting was requested.'}
            }
        }
    }
}

function Get-GuardWindowsLocaleState($Operations) {
    if(-not $Operations){$Operations=New-GuardWindowsLocaleOperations}
    & $Operations.Read
}

function Get-GuardWindowsLocaleSettings {
    'UiLanguageOverride','CultureFromLanguageListOptOut','HomeLocation','RegionalFormat','Languages'
}

function Test-GuardWindowsPreferredLanguage([string]$LanguageTag,[string]$Target) {
    $LanguageTag -ieq $Target -or ($Target -ieq 'ja-JP' -and $LanguageTag -ieq 'ja')
}

function Test-GuardWindowsLanguageOrder($Actual,$Expected,[string]$LocaleName) {
    if($Actual.Count -ne $Expected.Count){return $false}
    for($index=0;$index -lt $Expected.Count;$index++){
        if($Actual[$index] -ieq $Expected[$index]){continue}
        if($index -eq 0 -and $LocaleName -and (Test-GuardWindowsPreferredLanguage $Actual[0] $LocaleName) -and
            (Test-GuardWindowsPreferredLanguage $Expected[0] $LocaleName)){continue}
        return $false
    }
    $true
}

function Test-GuardWindowsIndependentLanguageOrder($State,$Expected,[string]$LocaleName) {
    if($State.OwnerSid -cne $Expected.OwnerSid){return $false}
    foreach($source in 'Saved','Native','WinRt'){
        if(-not (Test-GuardWindowsLanguageOrder $State.$source $Expected.Languages.LanguageTag $LocaleName)){return $false}
    }
    $true
}

function Test-GuardWindowsLanguageRecord($Left,$Right) {
    $Left.LanguageTag -ieq $Right.LanguageTag -and $Left.Spellchecking -eq $Right.Spellchecking -and
        $Left.Handwriting -eq $Right.Handwriting -and ($Left.InputMethodTips -join '|') -ieq ($Right.InputMethodTips -join '|')
}

function Test-GuardWindowsLocaleSetting($Left,$Right,[string]$Setting) {
    switch -Exact ($Setting){
        'HomeLocation' { return $Left.GeoId -eq $Right.GeoId -and $Left.CountryCode -ceq $Right.CountryCode }
        'InputMethodOverride' { return $Left.InputMethodOverride -ceq $Right.InputMethodOverride }
        'RegionalFormat' {
            if($Left.LocaleName -cne $Right.LocaleName){return $false}
            foreach($field in (Get-GuardWindowsLocaleFields).Keys){
                if($Left.Format.$field -cne $Right.Format.$field){return $false}
            }
            return $true
        }
        'Languages' {
            if($Left.Languages.Count -ne $Right.Languages.Count){return $false}
            for($index=0;$index -lt $Left.Languages.Count;$index++){
                if(-not (Test-GuardWindowsLanguageRecord $Left.Languages[$index] $Right.Languages[$index])){return $false}
            }
            return $true
        }
        default { return $Left.$Setting -eq $Right.$Setting }
    }
}

function Test-GuardWindowsLocalePlanSetting($Current,$Plan,[string]$Setting) {
    if(Test-GuardWindowsLocaleSetting $Current $Plan.After $Setting){return $true}
    # The Windows language-order API can save an added Japanese preference
    # as ja and supply its writing defaults. Preserve existing records and
    # require the same keyboard list, including for the new preference.
    if($Setting -cne 'Languages' -or $Plan.LocaleName -cne 'ja-JP' -or
        $Plan.After.Languages.Count -ne ($Plan.Before.Languages.Count+1) -or
        $Current.Languages.Count -ne $Plan.After.Languages.Count -or
        @($Plan.Before.Languages | Where-Object {Test-GuardWindowsPreferredLanguage $_.LanguageTag $Plan.LocaleName}).Count -or
        -not (Test-GuardWindowsPreferredLanguage $Current.Languages[0].LanguageTag $Plan.LocaleName) -or
        $Current.Languages[0].Spellchecking -isnot [bool] -or $Current.Languages[0].Handwriting -isnot [bool] -or
        ($Current.Languages[0].InputMethodTips -join '|') -ine ($Plan.After.Languages[0].InputMethodTips -join '|') -or
        $Current.InputMethodOverride -cne $Plan.After.InputMethodOverride -or
        $Current.InputMethodOverrideAvailable -ne $Plan.After.InputMethodOverrideAvailable -or
        $Current.DefaultInputLocale -cne $Plan.After.DefaultInputLocale -or
        $Current.EffectiveInputMethod -ine $Plan.After.EffectiveInputMethod -or
        $Current.EffectiveUiLanguage -ine $Plan.After.EffectiveUiLanguage){
        return $false
    }
    for($index=1;$index -lt $Current.Languages.Count;$index++){
        if(-not (Test-GuardWindowsLanguageRecord $Current.Languages[$index] $Plan.After.Languages[$index])){return $false}
    }
    $true
}

function Test-GuardWindowsLocaleState($Left,$Right,$Plan) {
    if($Left.OwnerSid -cne $Right.OwnerSid -or $Left.EffectiveUiLanguage -ne $Right.EffectiveUiLanguage -or
        $Left.EffectiveInputMethod -ne $Right.EffectiveInputMethod -or $Left.DefaultInputLocale -cne $Right.DefaultInputLocale -or
        $Left.InputMethodOverride -cne $Right.InputMethodOverride -or
        $Left.InputMethodOverrideAvailable -ne $Right.InputMethodOverrideAvailable){return $false}
    foreach($setting in (Get-GuardWindowsLocaleSettings)){
        $matched=if($Plan){Test-GuardWindowsLocalePlanSetting $Left $Plan $setting}
            else{Test-GuardWindowsLocaleSetting $Left $Right $setting}
        if(-not $matched){return $false}
    }
    $true
}

function Assert-GuardWindowsLocaleState($State) {
    $tag='\A[A-Za-z0-9]{1,8}(?:-[A-Za-z0-9]{1,8}){0,12}\z'
    $guid='\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}'
    $tip="\A[0-9a-f]{4}:(?:[0-9a-f]{8}|$guid$guid)\z"
    if($State.OwnerSid -cnotmatch '\AS-1-\d+(?:-\d+)+\z' -or $State.GeoId -le 0 -or
        $State.CountryCode -cnotmatch '\A(?:[A-Z]{2}|[0-9]{3})\z' -or $State.LocaleName -notmatch $tag -or
        $State.EffectiveUiLanguage -notmatch $tag -or ($State.UiLanguageOverride -and $State.UiLanguageOverride -notmatch $tag) -or
        ($State.EffectiveInputMethod -notmatch $tip -and $State.EffectiveInputMethod -cne ('HKL:'+$State.DefaultInputLocale)) -or
        $State.DefaultInputLocale -cnotmatch '\A[0-9A-F]{8}\z' -or $State.InputMethodOverride -isnot [string] -or
        $State.InputMethodOverrideAvailable -isnot [bool] -or $State.CultureFromLanguageListOptOut -isnot [bool] -or
        -not $State.Languages.Count){
        throw 'Windows did not return a usable current-user regional or language setting.'
    }
    $seen=@{}
    foreach($language in $State.Languages){
        if($language.LanguageTag -notmatch $tag -or $seen.ContainsKey($language.LanguageTag) -or
            $language.Spellchecking -isnot [bool] -or $language.Handwriting -isnot [bool] -or
            $language.InputMethodTips -isnot [array] -or @($language.InputMethodTips | Where-Object {$_ -notmatch $tip}).Count){
            throw 'Windows did not return a usable preferred language and keyboard list.'
        }
        $seen[$language.LanguageTag]=$true
    }
    foreach($field in (Get-GuardWindowsLocaleFields).Keys){
        $value=$State.Format.$field
        if($value -isnot [string] -or $value.Length -gt 127 -or $value.Contains([char]0)){
            throw 'Windows did not return a usable regional format.'
        }
    }
}

function Get-GuardWindowsLocaleTarget($Target) {
    try{
        $culture=[Globalization.CultureInfo]::GetCultureInfo([string]$Target.LocaleName)
        $region=[Globalization.RegionInfo]::new($culture.Name)
    }
    catch{throw 'Select a supported Windows regional format.'}
    if($culture.IsNeutralCulture -or $Target.CountryCode -cne $region.TwoLetterISORegionName -or
        $Target.GeoId -ne $region.GeoId -or $Target.LocaleName -cne $culture.Name){
        throw 'The Windows home location and regional format must match the selected country.'
    }
    $region
}

function New-GuardWindowsLocalePlan($Target,$State,$Operations) {
    $null=Get-GuardWindowsLocaleTarget $Target
    if(-not $Operations){$Operations=New-GuardWindowsLocaleOperations}
    if(-not $State){$State=Get-GuardWindowsLocaleState $Operations}
    Assert-GuardWindowsLocaleState $State
    $before=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $State -Depth 8 -Compress)
    $after=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $before -Depth 8 -Compress)
    $after.CountryCode=[string]$Target.CountryCode
    $after.GeoId=[int]$Target.GeoId
    $after.LocaleName=[string]$Target.LocaleName
    $after.Format=& $Operations.DefaultFormat $after.LocaleName
    if($after.LocaleName -ne $before.EffectiveUiLanguage -or
        ($before.UiLanguageOverride -and $after.LocaleName -ne $before.UiLanguageOverride)){
        $after.CultureFromLanguageListOptOut=$true
    }
    if(-not (Test-GuardWindowsPreferredLanguage $before.Languages[0].LanguageTag $after.LocaleName)){
        $targetLanguage=$after.Languages | Where-Object {Test-GuardWindowsPreferredLanguage $_.LanguageTag $after.LocaleName} | Select-Object -First 1
        if(-not $targetLanguage){$targetLanguage=& $Operations.DefaultLanguage $after.LocaleName}
        if(-not $before.InputMethodOverrideAvailable -and $targetLanguage.InputMethodTips.Count -and
            $targetLanguage.InputMethodTips[0] -ne $before.EffectiveInputMethod){
            throw 'Moving this language first could change the automatic default input method.'
        }
        $after.Languages=@($targetLanguage)+@($after.Languages | Where-Object LanguageTag -NE $targetLanguage.LanguageTag)
        if(-not $before.UiLanguageOverride -and -not (Test-GuardWindowsPreferredLanguage $before.EffectiveUiLanguage $after.LocaleName)){
            $after.UiLanguageOverride=$before.EffectiveUiLanguage
        }
    }
    Assert-GuardWindowsLocaleState $after
    $changes=@(foreach($setting in (Get-GuardWindowsLocaleSettings)){
        if(-not (Test-GuardWindowsLocaleSetting $before $after $setting)){$setting}
    })
    [pscustomobject]@{
        Version=1; CountryCode=$after.CountryCode; GeoId=$after.GeoId; LocaleName=$after.LocaleName
        Before=$before; After=$after; Changes=$changes
    }
}

function Assert-GuardWindowsLocalePlan($Plan) {
    $null=Get-GuardWindowsLocaleTarget $Plan
    Assert-GuardWindowsLocaleState $Plan.Before
    Assert-GuardWindowsLocaleState $Plan.After
    $changes=@(foreach($setting in (Get-GuardWindowsLocaleSettings)){
        if(-not (Test-GuardWindowsLocaleSetting $Plan.Before $Plan.After $setting)){$setting}
    })
    if($Plan.Version -ne 1 -or $Plan.Before.OwnerSid -cne $Plan.After.OwnerSid -or
        $Plan.CountryCode -cne $Plan.After.CountryCode -or $Plan.GeoId -ne $Plan.After.GeoId -or
        $Plan.LocaleName -cne $Plan.After.LocaleName -or
        -not (Test-GuardWindowsPreferredLanguage $Plan.After.Languages[0].LanguageTag $Plan.LocaleName) -or
        $Plan.Before.EffectiveUiLanguage -ne $Plan.After.EffectiveUiLanguage -or
        $Plan.Before.EffectiveInputMethod -ne $Plan.After.EffectiveInputMethod -or $Plan.Before.DefaultInputLocale -cne $Plan.After.DefaultInputLocale -or
        $Plan.Before.InputMethodOverride -cne $Plan.After.InputMethodOverride -or
        $Plan.Before.InputMethodOverrideAvailable -ne $Plan.After.InputMethodOverrideAvailable -or
        ($Plan.Changes -join '|') -cne ($changes -join '|')){
        throw 'The Windows locale plan is invalid.'
    }
}

function Test-GuardWindowsLocalePlan($Plan,[switch]$Before,[switch]$AllowOriginalLanguages,$Operations) {
    Assert-GuardWindowsLocalePlan $Plan
    $current=Get-GuardWindowsLocaleState $Operations
    if($Before){return (Test-GuardWindowsLocaleState $current $Plan.Before)}
    if($AllowOriginalLanguages){
        $expected=$Plan.After.PSObject.Copy()
        $expected.Languages=$Plan.Before.Languages
        return (Test-GuardWindowsLocaleState $current $expected)
    }
    Test-GuardWindowsLocaleState $current $Plan.After $Plan
}

function Test-GuardWindowsPartialWrite($Plan,$Current,[string]$Setting,[switch]$Immediate) {
    switch -Exact ($Setting){
        'Languages' {
            # An unverified write can be reversed while it is in progress.
            # A later recovery cannot attribute changed keyboards to that write.
            $tags=$Current.Languages.LanguageTag -join '|'
            return $Immediate -and $tags -in (($Plan.Before.Languages.LanguageTag -join '|'),($Plan.After.Languages.LanguageTag -join '|'))
        }
        'RegionalFormat' {
            if($Current.LocaleName -notin $Plan.Before.LocaleName,$Plan.After.LocaleName){return $false}
            if($Immediate){return $true}
            foreach($field in (Get-GuardWindowsLocaleFields).Keys){
                if($Current.Format.$field -cnotin $Plan.Before.Format.$field,$Plan.After.Format.$field){return $false}
            }
            return $true
        }
        'HomeLocation' { return $Current.GeoId -eq $Plan.After.GeoId }
        default { return $false }
    }
}

function Restore-GuardWindowsLocaleSettings($Plan,$Operations,[string[]]$Settings,[string]$FailedWrite,[string]$PendingWrite) {
    $preserved=$false
    $restored=$false
    $failed=@()
    for($index=$Settings.Count-1;$index -ge 0;$index--){
        $setting=$Settings[$index]
        try{
            $current=Get-GuardWindowsLocaleState $Operations
            if($current.OwnerSid -cne $Plan.Before.OwnerSid){throw 'The plan belongs to a different Windows user.'}
            if(Test-GuardWindowsLocaleSetting $current $Plan.Before $setting){continue}

            $canRestore=Test-GuardWindowsLocalePlanSetting $current $Plan $setting
            if(-not $canRestore -and $setting -cin $FailedWrite,$PendingWrite){
                # A saved marker may outlive an independent settings edit.
                # Outside this write attempt, require evidence of a partial write.
                $canRestore=Test-GuardWindowsPartialWrite $Plan $current $setting -Immediate:($setting -ceq $FailedWrite)
            }
            if($setting -ceq 'Languages'){
                # A newly chosen display language or keyboard may depend on
                # the target language that this operation added.
                foreach($other in 'UiLanguageOverride','InputMethodOverride'){
                    if(-not (Test-GuardWindowsLocaleSetting $current $Plan.After $other) -and
                        -not (Test-GuardWindowsLocaleSetting $current $Plan.Before $other)){$canRestore=$false}
                }
            }elseif($setting -ceq 'UiLanguageOverride' -and -not $Plan.Before.UiLanguageOverride){
                if(-not (Test-GuardWindowsLocaleSetting $current $Plan.Before 'Languages')){$canRestore=$false}
            }elseif($setting -ceq 'CultureFromLanguageListOptOut' -and
                -not (Test-GuardWindowsLocaleSetting $current $Plan.Before 'RegionalFormat')){
                $canRestore=$false
            }
            if(-not $canRestore){$preserved=$true; continue}

            $null=& $Operations.Write $setting $Plan.Before -PublishLanguage:($setting -ceq 'Languages')
            $verified=Get-GuardWindowsLocaleState $Operations
            if(-not (Test-GuardWindowsLocaleSetting $verified $Plan.Before $setting)){throw 'Windows did not restore the saved setting.'}
            if($setting -ceq 'Languages' -and $Operations.ReadIndependentLanguages){
                $independent=& $Operations.ReadIndependentLanguages 0
                if(-not (Test-GuardWindowsIndependentLanguageOrder $independent $Plan.Before '')){
                    throw 'The restored preferred-language order could not be verified independently.'
                }
            }
            $restored=$true
        }catch{
            $failed+=$setting
        }
    }
    if($failed.Count){throw "Windows regional rollback could not be verified for $($failed -join ', '). Keep the rollback journal."}
    if($preserved){return 'PreservedManualChange'}
    if(-not (Test-GuardWindowsLocalePlan -Plan $Plan -Before -Operations $Operations)){return 'PreservedManualChange'}
    if($restored){return 'Restored'}
    'Unchanged'
}

function Restore-GuardWindowsLocalePlan($Plan,[string]$PendingWrite,$Operations) {
    $ErrorActionPreference='Stop'
    Assert-GuardWindowsLocalePlan $Plan
    if($PendingWrite -and $PendingWrite -cnotin $Plan.Changes){throw 'The saved Windows locale write marker is invalid.'}
    if(-not $Operations){$Operations=New-GuardWindowsLocaleOperations}
    $current=Get-GuardWindowsLocaleState $Operations
    if($current.OwnerSid -cne $Plan.Before.OwnerSid){throw 'The plan belongs to a different Windows user.'}
    Restore-GuardWindowsLocaleSettings $Plan $Operations @($Plan.Changes) -PendingWrite $PendingWrite
}

function Get-GuardWindowsLocaleDifferences($Current,$Expected,$Plan,[string]$Setting) {
    if(-not $Setting){
        foreach($property in 'OwnerSid','EffectiveUiLanguage','EffectiveInputMethod','DefaultInputLocale','InputMethodOverride','InputMethodOverrideAvailable'){
            if($Current.$property -cne $Expected.$property){$property}
        }
    }
    $settings=if($Setting){@($Setting)}else{@(Get-GuardWindowsLocaleSettings)}
    foreach($name in $settings){
        $match=if($Plan){Test-GuardWindowsLocalePlanSetting $Current $Plan $name}
            else{Test-GuardWindowsLocaleSetting $Current $Expected $name}
        if($match){continue}
        switch -Exact ($name){
            'HomeLocation' {
                if($Current.GeoId -ne $Expected.GeoId){'GeoId'}
                if($Current.CountryCode -cne $Expected.CountryCode){'CountryCode'}
            }
            'RegionalFormat' {
                if($Current.LocaleName -cne $Expected.LocaleName){'LocaleName'}
                foreach($field in (Get-GuardWindowsLocaleFields).Keys){
                    if($Current.Format.$field -cne $Expected.Format.$field){'Format.'+$field}
                }
            }
            'Languages' {
                if($Current.Languages.Count -ne $Expected.Languages.Count){'Languages.Count'}
                for($index=0;$index -lt [math]::Min($Current.Languages.Count,$Expected.Languages.Count);$index++){
                    $actual=$Current.Languages[$index]
                    $wanted=$Expected.Languages[$index]
                    foreach($field in 'LanguageTag','Handwriting','Spellchecking','InputMethodTips'){
                        if(($actual.$field -join '|') -cne ($wanted.$field -join '|')){"Languages.$index.$field"}
                    }
                }
                foreach($property in 'EffectiveUiLanguage','EffectiveInputMethod','DefaultInputLocale','InputMethodOverride','InputMethodOverrideAvailable'){
                    if($Current.$property -cne $Expected.$property){$property}
                }
            }
            default {$name}
        }
    }
}

function New-GuardWindowsLocaleException([string]$Message,[Exception]$Cause,[string]$Stage,[string]$Setting,[string[]]$Differences,[string]$Rollback) {
    $failure=[InvalidOperationException]::new($Message,$Cause)
    $failure.Data['GuardWindowsLocaleStage']=$Stage
    $failure.Data['GuardWindowsLocaleSetting']=$Setting
    $failure.Data['GuardWindowsLocaleDifferences']=@($Differences | Select-Object -Unique)
    $failure.Data['GuardWindowsLocaleRollback']=$Rollback
    $failure
}

function Set-GuardWindowsLocalePlan($Plan,[scriptblock]$PersistWrite,[switch]$AllowManualPreferredLanguage,$Operations) {
    $ErrorActionPreference='Stop'
    $stage='PlanValidation'
    try{
        Assert-GuardWindowsLocalePlan $Plan
        $stage='PreviewRead'
        if(-not $Operations){$Operations=New-GuardWindowsLocaleOperations}
        $current=Get-GuardWindowsLocaleState $Operations
        if(-not (Test-GuardWindowsLocaleState $current $Plan.Before)){
            $stage='PreviewMismatch'
            $fields=@(Get-GuardWindowsLocaleDifferences $current $Plan.Before)
            throw 'The Windows regional settings changed after the preview. Preview the change again.'
        }
    }catch{
        throw (New-GuardWindowsLocaleException $_.Exception.Message $_.Exception $stage '' $fields 'NotRequired')
    }
    $attempted=@()
    $pending=$null
    $fields=@()
    $manualLanguages=$false
    try{
        foreach($setting in $Plan.Changes){
            $stage='JournalWrite'
            if($PersistWrite){$null=& $PersistWrite $setting}
            $stage='PreWriteRead'
            $current=Get-GuardWindowsLocaleState $Operations
            if($current.OwnerSid -cne $Plan.Before.OwnerSid -or -not (Test-GuardWindowsLocaleSetting $current $Plan.Before $setting)){
                $stage='PreWriteMismatch'
                $fields=@(Get-GuardWindowsLocaleDifferences $current $Plan.Before -Setting $setting)
                if($current.OwnerSid -cne $Plan.Before.OwnerSid){$fields+=@('OwnerSid')}
                throw 'A Windows regional setting changed while applying the preview.'
            }
            $attempted+=$setting
            $pending=$setting
            $stage='NativeWrite'
            $null=& $Operations.Write $setting $Plan.After -PublishLanguage:($setting -ceq 'Languages')
            $stage='SettingReadback'
            $verified=Get-GuardWindowsLocaleState $Operations
            if(-not (Test-GuardWindowsLocalePlanSetting $verified $Plan $setting)){
                if($setting -ceq 'Languages' -and $AllowManualPreferredLanguage -and
                    (Test-GuardWindowsLocaleSetting $verified $Plan.Before 'Languages')){
                    $manualLanguages=$true
                }else{
                    $stage='SettingMismatch'
                    $fields=@(Get-GuardWindowsLocaleDifferences $verified $Plan.After $Plan $setting)
                    throw "Windows did not apply the requested setting ($setting)."
                }
            }
            $pending=$null
        }
        if($Operations.ReadIndependentLanguages){
            # A transient list on Windows 11 reverted within 38 seconds.
            # Unchanged preferences only need a fresh read.
            $stepDelay=if(-not $manualLanguages -and 'Languages' -cin $attempted){40}else{0}
            $stage='IndependentLanguageRead'
            $setting='Languages'
            $independent=& $Operations.ReadIndependentLanguages $stepDelay
            $durable=if($manualLanguages){Test-GuardWindowsIndependentLanguageOrder $independent $Plan.Before ''}
                else{Test-GuardWindowsIndependentLanguageOrder $independent $Plan.After $Plan.LocaleName}
            if(-not $durable){
                if($AllowManualPreferredLanguage -and (Test-GuardWindowsIndependentLanguageOrder $independent $Plan.Before '')){
                    $manualLanguages=$true
                }else{
                    $stage='IndependentLanguageMismatch'
                    $fields=@('Languages.Order')
                    throw 'The saved and independent Windows preferred-language lists did not match the request.'
                }
            }
        }
        $setting=''
        $stage='FinalReadback'
        $verified=Get-GuardWindowsLocaleState $Operations
        $expected=$Plan.After
        $comparisonPlan=$Plan
        if($manualLanguages){
            $expected=$Plan.After.PSObject.Copy()
            $expected.Languages=$Plan.Before.Languages
            $comparisonPlan=$null
        }
        if(-not (Test-GuardWindowsLocaleState $verified $expected $comparisonPlan)){
            $stage='FinalMismatch'
            $fields=@(Get-GuardWindowsLocaleDifferences $verified $expected $comparisonPlan)
            throw 'The final Windows regional settings or the preserved menu language and keyboard could not be verified.'
        }
        $stage='JournalClear'
        if($PersistWrite -and $attempted.Count){$null=& $PersistWrite $null}
    }catch{
        $failure=$_.Exception
        if($failure.Data['GuardWindowsLocaleField']){$fields+=@($failure.Data['GuardWindowsLocaleField'])}
        try{$rollback=Restore-GuardWindowsLocaleSettings $Plan $Operations $attempted $pending}
        catch{
            throw (New-GuardWindowsLocaleException $_.Exception.Message $failure $stage $setting $fields 'Unverified')
        }
        $message=if($rollback -ceq 'PreservedManualChange'){
            'Windows regional changes failed. Settings differ from the preview. Keep the rollback journal.'
        }else{
            'Windows regional changes failed and the previous settings were verified.'
        }
        throw (New-GuardWindowsLocaleException ($message+' '+$failure.Message) $failure $stage $setting $fields $rollback)
    }
    if($manualLanguages){return 'ManualRequired'}
    if($attempted.Count){return 'Applied'}
    'Unchanged'
}
