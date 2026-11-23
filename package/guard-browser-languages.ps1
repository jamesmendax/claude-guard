# Edge language preferences can only be written while the browser is closed.
function Test-GuardEdgeLanguageList($Value) {
    if ($Value -isnot [string] -or $Value.Length -gt 4096 -or
        $Value -cnotmatch '\A[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*(?:,[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*)*\z') { return $false }
    $parts = $Value.Split(',')
    return @($parts | Select-Object -Unique).Count -eq $parts.Count
}

function Resolve-GuardEdgeLanguage([string]$Target,[string[]]$Current) {
    if ($Target -ieq 'JP') { $Target = 'ja-JP' }
    elseif ($Target -ieq 'US') { $Target = 'en-US' }
    elseif ($Target -ieq 'ja' -and $Current -inotcontains 'ja' -and $Current -icontains 'ja-JP') { $Target = 'ja-JP' }
    $Target = $Target -replace '^zh-Hans-CN$','zh-CN' -replace '^zh-Hant-(HK|TW)$','zh-$1'
    if (!(Test-GuardEdgeLanguageList $Target) -or $Target.Contains(',')) {
        throw 'The selected website language is not supported.'
    }
    try { $culture = [Globalization.CultureInfo]::GetCultureInfo($Target) }
    catch { throw 'The selected website language is not supported.' }
    foreach ($item in $Current) {
        if ($item -ieq $Target) { return $item }
    }
    # Chromium's accepted tags plus regional options exposed by the Edge
    # language chooser. The selected tag is also checked in the actual picker.
    $known = ('af ak am an ar as ast ay az be bg bho bm bn br bs ca ceb chr ckb co cs cy da de de-AT de-CH de-DE de-LI ' +
        'doi dv ee el en en-AU en-CA en-GB en-GB-oxendict en-IE en-IN en-NZ en-US en-ZA eo es es-419 es-AR es-CL es-CO ' +
        'es-CR es-ES es-HN es-MX es-PE es-US es-UY es-VE et eu fa fa-AF fi fil fo fr fr-BE fr-CA fr-CH fr-FR fy ga gd ' +
        'gl gn gu ha haw he hi hmn hr ht hu hy ia id ig ilo is it it-CH it-IT ja jv ka kk km kn ko kok kri ku ky la lb ' +
        'lg ln lo lt lus lv mai mg mi mk ml mn mni-Mtei mr ms mt my nb ne nl nl-BE nn no nso ny oc om or pa pl ps pt pt-BR ' +
        'pt-PT qu rm ro ro-MD ru rw sa sd sh si sk sl sm sn so sq sr sr-Cyrl-RS sr-Latn-RS st su sv sw ta te tg th ti tk tn ' +
        'to tr ts tt ug uk ur uz vi wa wo xh yi yo zh zh-CN zh-HK zh-TW zu').Split(' ')
    $tag = $Target
    if ($tag -inotin $known -and !$culture.IsNeutralCulture) {
        # Keep an explicitly selected script. Falling back to the same
        # language without a country must never select a different script.
        $tag = $tag -replace '-(?:[A-Za-z]{2}|[0-9]{3})$',''
        if ($tag -ieq 'zh' -and $culture.Parent.Name -match '^zh-Han[st]$') { $tag = $culture.Parent.Name }
    }
    foreach ($item in $known) {
        if ($item -ieq $tag) { return $item }
    }
    throw 'Edge does not offer the selected website language or its same-script neutral form.'
}

function Get-GuardEdgeLanguagePolicy {
    foreach ($hive in @('CurrentUser','LocalMachine')) {
        foreach ($view in @('Registry64','Registry32')) {
            $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            try {
                foreach ($path in @('SOFTWARE\Policies\Microsoft\Edge','SOFTWARE\Policies\Microsoft\Edge\Recommended')) {
                    $key = $root.OpenSubKey($path)
                    if (!$key) { continue }
                    try {
                        foreach ($name in @('DefinePreferredLanguages','UserDataDir','ApplicationLocaleValue')) {
                            if ($name -in $key.GetValueNames()) { [pscustomobject]@{Name=$name;Value=$key.GetValue($name)} }
                        }
                    } finally { $key.Dispose() }
                }
            } finally { $root.Dispose() }
        }
    }
}

function Get-GuardEdgeLanguageData {
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\Edge\User Data'
}

function Get-GuardEdgePreferenceFile([string]$DataRoot,[string]$Profile) {
    if ($Profile -cnotmatch '\A(?:Default|Profile [1-9][0-9]*)\z') {
        throw 'The selected Edge profile could not be verified.'
    }
    $data = Get-Item -LiteralPath $DataRoot -ErrorAction Stop
    $directory = Get-Item -LiteralPath (Join-Path $DataRoot $Profile) -ErrorAction Stop
    $preferences = Get-Item -LiteralPath (Join-Path $directory.FullName 'Preferences') -ErrorAction Stop
    if (!$data.PSIsContainer -or !$directory.PSIsContainer -or $preferences.PSIsContainer -or
        (($data.Attributes -bor $directory.Attributes -bor $preferences.Attributes) -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The Edge profile folder or its settings is redirected.'
    }
    return $preferences
}

function Get-GuardEdgeLanguageSnapshot([string]$DataRoot,[string]$Profile,[string]$DisplayLocale) {
    $data = Get-Item -LiteralPath $DataRoot -ErrorAction Stop
    $localFile = Get-Item -LiteralPath (Join-Path $DataRoot 'Local State') -ErrorAction Stop
    if (($data.Attributes -bor $localFile.Attributes) -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The Edge profile folder or its settings is redirected.'
    }
    $local = [IO.File]::ReadAllText($localFile.FullName) | ConvertFrom-Json -ErrorAction Stop
    if (!$Profile) { $Profile = $local.profile.last_used }
    if ($Profile -cnotmatch '\A(?:Default|Profile [1-9][0-9]*)\z' -or !$local.profile.info_cache.PSObject.Properties[$Profile]) {
        throw 'The last-used Edge profile is unavailable or unsupported.'
    }
    $preferences = Get-GuardEdgePreferenceFile $DataRoot $Profile
    $pref = [IO.File]::ReadAllText($preferences.FullName) | ConvertFrom-Json -ErrorAction Stop
    if (!$DisplayLocale) { $DisplayLocale = $local.intl.app_locale }
    return [pscustomobject]@{
        Profile=$Profile; AcceptLanguages=$pref.intl.accept_languages
        SelectedLanguages=$pref.intl.selected_languages; DisplayLocale=$DisplayLocale
    }
}

function Get-GuardBrowserLanguageState([string]$Profile) {
    $result = [pscustomobject]@{
        Browser='Edge'; Profile=$null; Executable=$null; AcceptLanguages=$null
        SelectedLanguages=$null; DisplayLocale=$null; Available=$false; Reason=$null
    }
    try {
        foreach ($scheme in @('http','https')) {
            $path = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$scheme\UserChoice"
            if ((Get-ItemProperty -LiteralPath $path -Name ProgId -ErrorAction Stop).ProgId -cne 'MSEdgeHTM') {
                $result.Reason = 'Microsoft Edge must be the default browser for both HTTP and HTTPS.'
                return $result
            }
        }
        foreach ($folder in @([Environment]::GetFolderPath('ProgramFilesX86'),[Environment]::GetFolderPath('ProgramFiles'))) {
            if (!$folder) { continue }
            $path = Join-Path $folder 'Microsoft\Edge\Application\msedge.exe'
            if ([IO.File]::Exists($path)) { $result.Executable = $path; break }
        }
        if (!$result.Executable) { $result.Reason = 'The installed Microsoft Edge application is unavailable.'; return $result }
        $policies = @(Get-GuardEdgeLanguagePolicy)
        if ($policies.Name -contains 'DefinePreferredLanguages' -or $policies.Name -contains 'UserDataDir') {
            $result.Reason = 'An existing Edge policy manages website languages or the profile location.'
            return $result
        }
        $locales = @($policies | Where-Object Name -eq 'ApplicationLocaleValue' | ForEach-Object Value | Select-Object -Unique)
        if ($locales.Count -gt 1) { $result.Reason = 'Edge has conflicting menu-language policies.'; return $result }
        $snapshot = Get-GuardEdgeLanguageSnapshot -DataRoot (Get-GuardEdgeLanguageData) -Profile $Profile -DisplayLocale ($locales -join '')
        $result.Profile = $snapshot.Profile
        $result.AcceptLanguages = $snapshot.AcceptLanguages
        $result.SelectedLanguages = $snapshot.SelectedLanguages
        $result.DisplayLocale = $snapshot.DisplayLocale
        if (!(Test-GuardEdgeLanguageList $result.SelectedLanguages) -or $result.AcceptLanguages -cne $result.SelectedLanguages) {
            $result.Reason = 'Edge did not report a consistent preferred-language list.'
            return $result
        }
        if ($result.DisplayLocale -isnot [string] -or !(Test-GuardEdgeLanguageList $result.DisplayLocale) -or $result.DisplayLocale.Contains(',')) {
            $result.Reason = 'Edge did not report a menu language.'
            return $result
        }
        $result.Available = $true
    } catch {
        $result.Reason = 'Edge browser language preferences could not be read safely.'
    }
    return $result
}

function New-GuardBrowserLanguagePlan([Parameter(Mandatory)][string]$Target,[Parameter(Mandatory)]$State) {
    if ($State.Available -ne $true -or $State.Browser -cne 'Edge' -or
        $State.Profile -cnotmatch '\A(?:Default|Profile [1-9][0-9]*)\z' -or
        $State.Executable -isnot [string] -or [IO.Path]::GetFileName($State.Executable) -ine 'msedge.exe' -or
        !(Test-GuardEdgeLanguageList $State.SelectedLanguages) -or $State.AcceptLanguages -cne $State.SelectedLanguages -or
        $State.DisplayLocale -isnot [string] -or !(Test-GuardEdgeLanguageList $State.DisplayLocale) -or $State.DisplayLocale.Contains(',')) {
        throw 'Edge website language settings are unavailable or unsupported.'
    }
    $languages = $State.SelectedLanguages.Split(',')
    $primary = Resolve-GuardEdgeLanguage $Target $languages
    foreach ($language in $languages) {
        if ($language -ieq $primary) { $primary = $language; break }
    }
    $updated = (@($primary) + @($languages | Where-Object {$_ -ine $primary})) -join ','
    $before = [pscustomobject]@{
        Browser='Edge'; Profile=$State.Profile; Executable=$State.Executable; Available=$true; Reason=$null
        SelectedLanguages=$State.SelectedLanguages; AcceptLanguages=$State.AcceptLanguages; DisplayLocale=$State.DisplayLocale
    }
    $after = $before.PSObject.Copy()
    $after.AcceptLanguages = $updated
    $after.SelectedLanguages = $updated
    return [pscustomobject]@{
        Version=1; Browser='Edge'; Profile=$before.Profile; Executable=$before.Executable; PrimaryLanguage=$primary
        Changed=($updated -cne $before.SelectedLanguages); Before=$before; After=$after
    }
}

function Test-GuardBrowserLanguageStateEqual($Left,$Right) {
    return $Left.Available -eq $true -and $Right.Available -eq $true -and
        $Left.Browser -ceq $Right.Browser -and $Left.Profile -ceq $Right.Profile -and
        $Left.Executable -ieq $Right.Executable -and $Left.DisplayLocale -ceq $Right.DisplayLocale -and
        $Left.AcceptLanguages -ceq $Right.AcceptLanguages -and $Left.SelectedLanguages -ceq $Right.SelectedLanguages
}

function Assert-GuardBrowserLanguagePlan($Plan) {
    if (!$Plan -or $Plan.Version -ne 1 -or $Plan.Changed -isnot [bool] -or $Plan.PrimaryLanguage -isnot [string]) {
        throw 'The recorded Edge website-language plan is invalid.'
    }
    $expected = New-GuardBrowserLanguagePlan -Target $Plan.PrimaryLanguage -State $Plan.Before
    if ($Plan.Browser -cne $expected.Browser -or $Plan.Profile -cne $expected.Profile -or
        $Plan.Executable -ine $expected.Executable -or $Plan.Changed -ne $expected.Changed -or
        $Plan.PrimaryLanguage -cne $expected.PrimaryLanguage -or !(Test-GuardBrowserLanguageStateEqual $Plan.After $expected.After)) {
        throw 'The recorded Edge website-language plan is invalid.'
    }
}

function Test-GuardEdgeIsRunning {
    $session = [Diagnostics.Process]::GetCurrentProcess()
    $processes = [Diagnostics.Process]::GetProcessesByName('msedge')
    try {
        foreach ($process in $processes) {
            try { if ($process.SessionId -eq $session.SessionId) { return $true } }
            catch [InvalidOperationException] {}
        }
        return $false
    } finally {
        foreach ($process in $processes) { $process.Dispose() }
        $session.Dispose()
    }
}

function New-GuardEdgeLanguageManualRequired {
    $exception = [InvalidOperationException]::new('Edge is open or its profile is busy. Change the website language in Edge, or close Edge and check again.')
    $exception.Data['GuardBrowserFailure'] = 'EdgeLanguageManualRequired'
    return $exception
}

function Get-GuardEdgeLanguageOperations {
    return @{
        Read={param($Profile) Get-GuardBrowserLanguageState -Profile $Profile}
        IsRunning={Test-GuardEdgeIsRunning}
        IsBusy={
            (Test-GuardEdgeIsRunning) -or [IO.File]::Exists((Join-Path (Get-GuardEdgeLanguageData) 'lockfile'))
        }
        Write={
            param($Plan,$Current,$Target,$Operations,$Restore)
            $arguments = @{
                DataRoot=(Get-GuardEdgeLanguageData); Profile=$Plan.Profile; Current=$Current; Target=$Target
                IsRunning=$Operations.IsRunning; Read=$Operations.Read; Restore=$Restore
            }
            Set-GuardEdgeOfflineLanguagePreferences @arguments
        }
    }
}

function Test-GuardBrowserLanguagePlan([Parameter(Mandatory)]$Plan,$Operations=(Get-GuardEdgeLanguageOperations),[switch]$Before) {
    Assert-GuardBrowserLanguagePlan $Plan
    if ($Before) { return Test-GuardBrowserLanguageStateEqual (& $Operations.Read) $Plan.Before }
    return Test-GuardBrowserLanguageStateEqual (& $Operations.Read $Plan.Profile) $Plan.After
}

function Get-GuardBrowserLanguageApplyMode([Parameter(Mandatory)]$Plan,$Operations=(Get-GuardEdgeLanguageOperations)) {
    Assert-GuardBrowserLanguagePlan $Plan
    if (!$Plan.Changed) { return 'Unchanged' }
    $isBusy = if ($Operations.IsBusy) {$Operations.IsBusy} else {$Operations.IsRunning}
    if (& $isBusy) { return 'ManualRequired' }
    return 'Offline'
}

function Set-GuardBrowserLanguagePlan([Parameter(Mandatory)]$Plan,$Operations=(Get-GuardEdgeLanguageOperations)) {
    Assert-GuardBrowserLanguagePlan $Plan
    $current = & $Operations.Read
    if (!(Test-GuardBrowserLanguageStateEqual $current $Plan.Before)) {
        throw 'Edge or its website language preferences changed after the preview.'
    }
    if (!$Plan.Changed) { return 'Unchanged' }
    if (& $Operations.IsRunning) { throw (New-GuardEdgeLanguageManualRequired) }
    $null = & $Operations.Write $Plan $current $Plan.After $Operations $false
    if (!(Test-GuardBrowserLanguagePlan $Plan $Operations)) { throw 'Edge did not save the requested website language change.' }
    return 'Applied'
}

function Restore-GuardBrowserLanguagePlan([Parameter(Mandatory)]$Plan,$Operations=(Get-GuardEdgeLanguageOperations)) {
    Assert-GuardBrowserLanguagePlan $Plan
    $current = & $Operations.Read $Plan.Profile
    if (Test-GuardBrowserLanguageStateEqual $current $Plan.Before) { return 'Unchanged' }
    if (!$Plan.Changed -or !(Test-GuardBrowserLanguageStateEqual $current $Plan.After)) {
        throw 'Edge website languages changed independently. Undo has been kept for review.'
    }
    if (& $Operations.IsRunning) { throw (New-GuardEdgeLanguageManualRequired) }
    $null = & $Operations.Write $Plan $current $Plan.Before $Operations $true
    if (!(Test-GuardBrowserLanguageStateEqual (& $Operations.Read $Plan.Profile) $Plan.Before)) {
        throw 'Edge did not save the original website languages.'
    }
    return 'Restored'
}

function Initialize-GuardEdgePreferenceEditor {
    if ('ClaudeGuard.EdgePreferenceEditor' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ClaudeGuard {
    public static class EdgePreferenceEditor {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int kind, out IntPtr value, int length, out int needed);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static IDisposable UseRegularUser() {
            using (WindowsIdentity current = WindowsIdentity.GetCurrent()) {
                if (!new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator)) return null;
                IntPtr token = IntPtr.Zero, limited = IntPtr.Zero;
                try {
                    int length;
                    using (Process process = Process.GetCurrentProcess())
                        if (!OpenProcessToken(process.Handle, 8, out token) ||
                            !GetTokenInformation(token, 19, out limited, IntPtr.Size, out length) || limited == IntPtr.Zero)
                            throw new InvalidOperationException("The regular Windows user token is unavailable for the Edge edit.");
                    using (var user = new WindowsIdentity(limited)) {
                        if (!current.User.Equals(user.User) || new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))
                            throw new InvalidOperationException("The Edge edit requires the original user's regular Windows token.");
                        return user.Impersonate();
                    }
                }
                finally {
                    if (limited != IntPtr.Zero) CloseHandle(limited);
                    if (token != IntPtr.Zero) CloseHandle(token);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EntryInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out EntryInformation info);

        private sealed class DirectoryPin : IDisposable {
            internal readonly List<SafeFileHandle> Handles = new List<SafeFileHandle>();
            public void Dispose() {
                foreach (SafeFileHandle handle in Handles) handle.Dispose();
            }
        }

        public static IDisposable PinDirectories(string profile) {
            var paths = new Stack<string>();
            for (var folder = new DirectoryInfo(profile); folder != null; folder = folder.Parent) paths.Push(folder.FullName);
            var pin = new DirectoryPin();
            try {
                while (paths.Count > 0) {
                    // Open the directory itself and deny deletion/rename while it is in use.
                    SafeFileHandle handle = CreateFile(paths.Pop(), 0x81, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                    pin.Handles.Add(handle);
                    EntryInformation info;
                    if (handle.IsInvalid || !GetFileInformationByHandle(handle, out info))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "The Edge profile directory could not be locked.");
                    if ((info.Attributes & 0x410) != 0x10)
                        throw new InvalidOperationException("The Edge profile folder or its settings is redirected.");
                }
                return pin;
            }
            catch { pin.Dispose(); throw; }
        }

        private sealed class Document {
            private readonly string text;
            private readonly JavaScriptSerializer json = new JavaScriptSerializer();
            private int next;

            internal Document(string value) { text = value; }
            private void Space() {
                while (next < text.Length && " \t\r\n".IndexOf(text[next]) >= 0) next++;
            }
            private char Peek() {
                if (next < text.Length) return text[next];
                throw new FormatException("The Edge preferences file ended unexpectedly.");
            }
            private void Take(char expected) {
                Space();
                if (Peek() != expected) throw new FormatException("The Edge preferences structure changed.");
                next++;
            }
            private void SkipString() {
                Take('"');
                while (Peek() != '"') {
                    if (text[next++] == '\\') next++;
                }
                next++;
            }
            private void SkipValue() {
                Space();
                char first = Peek();
                if (first == '"') { SkipString(); return; }
                if (first != '{' && first != '[') {
                    while (next < text.Length && ",}] \t\r\n".IndexOf(text[next]) < 0) next++;
                    return;
                }
                var stack = new Stack<char>();
                stack.Push(first == '{' ? '}' : ']');
                next++;
                while (stack.Count > 0) {
                    char current = Peek();
                    if (current == '"') { SkipString(); continue; }
                    next++;
                    if (current == '{' || current == '[') stack.Push(current == '{' ? '}' : ']');
                    else if ((current == '}' || current == ']') && current != stack.Pop())
                        throw new FormatException("The Edge preferences structure changed.");
                }
            }
            internal Tuple<int,int> Member(int start, string name) {
                next = start;
                Take('{');
                Tuple<int,int> match = null;
                Space();
                while (Peek() != '}') {
                    int key = next;
                    SkipString();
                    string property = json.Deserialize<string>(text.Substring(key, next - key));
                    Take(':');
                    Space();
                    int value = next;
                    SkipValue();
                    if (property.Equals(name, StringComparison.OrdinalIgnoreCase)) {
                        if (match != null || property != name)
                            throw new FormatException("The Edge preferences contain ambiguous language settings.");
                        match = Tuple.Create(value, next - value);
                    }
                    Space();
                    if (Peek() == '}') break;
                    Take(',');
                    Space();
                }
                if (match == null) throw new FormatException("An Edge language preference is missing.");
                return match;
            }
            internal string Rewrite(string expected, string desired) {
                var intl = Member(text.Length > 0 && text[0] == '\uFEFF' ? 1 : 0, "intl");
                var accept = Member(intl.Item1, "accept_languages");
                var selected = Member(intl.Item1, "selected_languages");
                foreach (var value in new[] { accept, selected }) {
                    if (json.Deserialize<string>(text.Substring(value.Item1, value.Item2)) != expected)
                        throw new InvalidOperationException("Edge or its website language preferences changed after the preview.");
                }
                var first = accept.Item1 < selected.Item1 ? accept : selected;
                var second = first == accept ? selected : accept;
                string literal = json.Serialize(desired);
                return text.Substring(0, first.Item1) + literal +
                    text.Substring(first.Item1 + first.Item2, second.Item1 - first.Item1 - first.Item2) + literal +
                    text.Substring(second.Item1 + second.Item2);
            }
        }

        public static string Rewrite(string document, string expected, string desired) {
            return new Document(document).Rewrite(expected, desired);
        }
    }
}
'@ -ReferencedAssemblies 'System.Web.Extensions' -ErrorAction Stop
}

function Set-GuardEdgeOfflineLanguagePreferences([string]$DataRoot,[string]$Profile,$Current,$Target,
    [scriptblock]$IsRunning,[scriptblock]$Read,[switch]$Restore) {
    Initialize-GuardEdgePreferenceEditor
    if (& $IsRunning) { throw (New-GuardEdgeLanguageManualRequired) }
    if ($Profile -cnotmatch '\A(?:Default|Profile [1-9][0-9]*)\z') { throw 'The selected Edge profile could not be verified.' }
    $token = $null
    $directories = $null
    $lock = $null
    $pending = $null
    $backup = $null
    $keepBackup = $false
    $utf8 = [Text.UTF8Encoding]::new($false,$true)
    $readProfile = if ($Restore) {$Profile}
    try {
        $token = [ClaudeGuard.EdgePreferenceEditor]::UseRegularUser()
        $directories = [ClaudeGuard.EdgePreferenceEditor]::PinDirectories((Join-Path $DataRoot $Profile))
        $preference = Get-GuardEdgePreferenceFile $DataRoot $Profile
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            foreach ($item in @($preference,$preference.Directory,$preference.Directory.Parent)) {
                $owner = $item.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner).GetOwner([Security.Principal.SecurityIdentifier])
                if (!$identity.User.Equals($owner)) { throw 'The Edge profile is not owned by the current Windows user.' }
            }
        } finally { $identity.Dispose() }
        # Chromium takes this user-data-level lock before opening profiles.
        # CreateNew leaves another owner's lock alone.
        try {
            $lock = [IO.FileStream]::new((Join-Path $DataRoot 'lockfile'),[IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite,[IO.FileShare]::Read,4096,[IO.FileOptions]::DeleteOnClose)
        } catch [IO.IOException] { throw (New-GuardEdgeLanguageManualRequired) }
        if (& $IsRunning) { throw (New-GuardEdgeLanguageManualRequired) }
        if (!(Test-GuardBrowserLanguageStateEqual (& $Read $readProfile) $Current)) {
            throw 'Edge or its website language preferences changed after the preview.'
        }
        $preference = Get-GuardEdgePreferenceFile $DataRoot $Profile
        if ($preference.Length -gt 32MB) { throw 'The Edge preferences file is too large to update safely.' }
        $file = $preference.FullName
        $original = $utf8.GetString([IO.File]::ReadAllBytes($file))
        $replacement = [ClaudeGuard.EdgePreferenceEditor]::Rewrite($original,$Current.SelectedLanguages,$Target.SelectedLanguages)
        $tag = 'Preferences.guard-' + [Guid]::NewGuid().ToString('N')
        $pending = Join-Path $preference.DirectoryName ($tag + '.pending')
        $backup = Join-Path $preference.DirectoryName ($tag + '.previous')
        $bytes = $utf8.GetBytes($replacement)
        $stream = [IO.FileStream]::new($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,
            [IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if (& $IsRunning) { throw (New-GuardEdgeLanguageManualRequired) }
        if (!(Test-GuardBrowserLanguageStateEqual (& $Read $readProfile) $Current) -or
            $utf8.GetString([IO.File]::ReadAllBytes($file)) -cne $original) {
            throw 'Edge language preferences changed during the operation.'
        }
        $null = Get-GuardEdgePreferenceFile $DataRoot $Profile
        try {
            [IO.File]::Replace($pending,$file,$backup,$false)
            if (([IO.File]::GetAttributes($backup) -band [IO.FileAttributes]::ReparsePoint) -or
                $utf8.GetString([IO.File]::ReadAllBytes($backup)) -cne $original) {
                throw 'Edge language preferences changed during the operation.'
            }
            if ($utf8.GetString([IO.File]::ReadAllBytes($file)) -cne $replacement -or
                !(Test-GuardBrowserLanguageStateEqual (& $Read $Profile) $Target)) {
                throw 'Edge did not save the requested website language change.'
            }
        } catch {
            if ([IO.File]::Exists($backup)) {
                $keepBackup = $true
                try {
                    $disk = $utf8.GetString([IO.File]::ReadAllBytes($file))
                    if (!([IO.File]::GetAttributes($backup) -band [IO.FileAttributes]::ReparsePoint)) {
                        $preserved = $utf8.GetString([IO.File]::ReadAllBytes($backup))
                        if ($disk -ceq $preserved) { $keepBackup = $false }
                        elseif ($disk -ceq $replacement -and !(& $IsRunning)) {
                            $null = Get-GuardEdgePreferenceFile $DataRoot $Profile
                            [IO.File]::Replace($backup,$file,[NullString]::Value,$false)
                            $keepBackup = $false
                        }
                    }
                } catch {}
            }
            throw
        }
    } finally {
        try {
            if ($pending) { [IO.File]::Delete($pending) }
            if ($backup -and !$keepBackup) { [IO.File]::Delete($backup) }
        } finally {
            if ($lock) { $lock.Dispose() }
            if ($directories) { $directories.Dispose() }
            if ($token) { $token.Dispose() }
        }
    }
}

