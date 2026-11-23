#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\release\guard-profile-actions.ps1"
$area=Join-Path ([IO.Path]::GetTempPath()) ('guard-profile-store-tests-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($area)
function Get-GuardDataPath([string]$Name){Join-Path $area $Name}
function Require([bool]$Check,[string]$Text){if(-not $Check){throw $Text};"PASS $Text"}
function Reject([scriptblock]$Action,[string]$Text){$denied=$false;try{$null=& $Action}catch{$denied=$true};Require $denied $Text}
$link='vless://6b1f71fb-b22c-41b7-8fe7-ceccb87c2fa3@198.51.100.81:443?type=ws&security=tls&sni=example.test&host=example.test&path=%2Fsocket&encryption=none'
try{
    $profile=New-GuardNodeProfile -Text $link
    $route=Get-GuardNodeProfileRoute $profile 18881
    $now=[datetimeoffset]::UtcNow
    $proof=[pscustomobject]@{Passed=$true;State='Completed';Provider='CloudflareTrace';ExitIpv4='198.51.100.13'
        CheckedUtc=$now.UtcDateTime.ToString('o');ProfileFingerprint=$route.ProfileFingerprint}
    Assert-GuardSettingsPreview $profile $proof $now
    'PASS A verified manual exit is accepted without a second configured egress'
    $zones=Get-GuardSettingsTimeZones (Split-Path -Parent $PSScriptRoot)
    Require ((Get-GuardSettingsRegionChoice $zones 'Automatic' JP).Id -ceq 'Japan') 'A Japanese exit selects Tokyo using the bundled territory map'
    $regionRead=@{Read={[pscustomobject]@{Id='UTC';DaylightDisabled=$false;AutomaticTimeZoneEnabled=$false}}}
    foreach($example in @(
        @{Country='PW';Choice='Automatic';Zone='Tokyo Standard Time'},
        @{Country='TL';Choice='Automatic';Zone='Tokyo Standard Time'},
        @{Country='CA';Choice='UsPacific';Zone='Pacific Standard Time'},
        @{Country='ZZ';Choice='Japan';Zone='Tokyo Standard Time'}
    )){
        $choice=Get-GuardSettingsRegionChoice $zones $example.Choice $example.Country
        $plan=New-GuardRegionProfilePlan $choice.Id $example.Country $regionRead
        Require ($choice.Id -ceq ('Windows/'+$example.Zone) -and $plan.Changes[0].After.Id -ceq $example.Zone) `
            ("The selected Windows time zone applies to {0} independently of a city shortcut's country" -f $example.Country)
    }
    Require ((Get-GuardSettingsRegionChoice $zones 'Automatic' US).RequiresChoice) 'A United States exit asks for a city instead of assuming the West Coast'
    Require ((Get-GuardSettingsRegionChoice $zones 'Automatic' '').RequiresChoice) 'Missing geography requires a choice without another network lookup'
    Require ((Get-GuardSettingsRegionChoice $zones 'Windows/Eastern Standard Time' US).TimeZoneId -ceq 'Eastern Standard Time') 'Other installed Windows time zones can be selected'
    Reject {Get-GuardSettingsRegionChoice $zones 'UsPacific' JP} 'A verified Japanese exit does not silently select a conflicting country'
    Reject {Assert-GuardSettingsPreview $profile $proof $now.AddMinutes(6)} 'An expired node check cannot be applied'
    $proof.ProfileFingerprint='A'*64
    Reject {Assert-GuardSettingsPreview $profile $proof $now} 'A different node cannot inherit a successful check'
    $proof.ProfileFingerprint=$route.ProfileFingerprint
    Require (-not (Get-GuardNodeStoreSnapshot).Exists) 'An absent private directory selects the compatible legacy route'

    $storePath=Get-GuardNodeStorePath
    $dir=Split-Path -Parent $storePath
    $null=[IO.Directory]::CreateDirectory($dir)
    Reject {Get-GuardNodeStoreSnapshot} 'A user-owned private directory cannot silently select a different route'
    [IO.Directory]::Delete($dir)

    & {
        function Restore-GuardNodeStoreSnapshot($state){$script:encrypted=$state}
        Save-GuardNodeProfile $profile
        $serialized=$script:encrypted|ConvertTo-Json -Depth 6 -Compress
        Require ($script:encrypted.Exists -and $serialized -notlike '*example.test*' -and $serialized -notlike '*6b1f71fb*') 'The persistent snapshot contains only DPAPI ciphertext and account metadata'
        function Get-GuardNodeStoreSnapshot { $script:encrypted }
        $restored=Read-GuardSavedNodeRoute 18881
        Require ($restored.Hash -ceq $route.Hash -and $restored.ProfileFingerprint -ceq $route.ProfileFingerprint) 'The current Windows account decrypts the original exact route'
        $script:encrypted.Record.ProtectedValue='00'*100
        Reject {Read-GuardSavedNodeRoute 18881} 'Unreadable credentials stop the route reader'
    }
    $testState=@{Id='Pacific Standard Time';DaylightDisabled=$false;Store='previous';Writes=0}
    function Get-GuardNodeStoreSnapshot {[pscustomobject]@{Exists=$true;Value=$testState.Store}}
    function Save-GuardNodeProfile($inputProfile){$testState.Store=(Get-GuardNodeProfileRoute $inputProfile 18881).ProfileFingerprint}
    function Restore-GuardNodeStoreSnapshot($saved){$testState.Store=$saved.Value}
    $regionOps=@{Read={ [pscustomobject]@{Id=$testState.Id;DaylightDisabled=$testState.DaylightDisabled;AutomaticTimeZoneEnabled=$false} }
        Write={param($target)$testState.Id=$target.Id;$testState.DaylightDisabled=$target.DaylightDisabled;$testState.Writes++}}
    $plan=New-GuardRegionProfilePlan -ProfileId Japan -Operations $regionOps
    $ops=New-GuardSettingsNodeOperations $plan $regionOps $route.ProfileFingerprint
    Reject {& $ops.Apply $profile} 'The private node cannot change before a rollback snapshot exists'
    $saved=& $ops.Snapshot
    & $ops.Apply $profile
    Require ($testState.Store -ceq $route.ProfileFingerprint -and $testState.Id -ceq 'Tokyo Standard Time') 'The explicit Japan choice applies the checked route and time zone together'
    $copy=$saved | ConvertTo-Json -Depth 8 |ConvertFrom-Json
    & $ops.Restore $copy
    Require ($testState.Store -ceq 'previous' -and $testState.Id -ceq 'Pacific Standard Time') 'The serialized recovery snapshot restores the prior node and time zone'
    $keep=New-GuardRegionProfilePlan -ProfileId Keep -Operations $regionOps
    $unchanged=New-GuardSettingsNodeOperations $keep $regionOps $route.ProfileFingerprint
    $null=& $unchanged.Snapshot
    & $unchanged.Apply $profile
    Require ($testState.Writes -eq 2) 'Choosing the current time zone does not write Windows settings'

    $local=@([pscustomobject]@{Name='Teredo Tunneling Pseudo-Interface';InterfaceType=131;InterfaceGuid=[guid]::NewGuid();ifIndex=7;NetLuid=1402},
        [pscustomobject]@{Name='Bettbox';InterfaceGuid=[guid]::NewGuid();ifIndex=8;NetLuid=1102})
    $identity=[pscustomobject]@{SourceGuid=$local[0].InterfaceGuid;GuidRoundTrip=$local[0].InterfaceGuid;NetLuidDecimal='1402'
        IndexLuidDecimal='1402';InterfaceIndex=7}
    $checked=Assert-GuardTeredoIdentity $local $identity
    Require ($checked.Verified -and [guid]$checked.VpnGuid -eq $local[1].InterfaceGuid) 'Fresh Windows adapter identities resolve without a previous machine GUID'
    $identity.GuidRoundTrip=[guid]::NewGuid()
    Reject {Assert-GuardTeredoIdentity $local $identity} 'The wrong native tunnel identity is rejected on a fresh computer'

    & {
        # Only ACL mutation is substituted. Create, replace and read real Windows Shell links in this isolated directory.
        function Assert-GuardSandboxieAdministratorPath([string]$Path){
            $absolute=[IO.Path]::GetFullPath($Path)
            if($absolute -ine $area -and -not $absolute.StartsWith($area+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture shortcut path.'}
        }
        function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction) Assert-GuardSandboxieAdministratorPath $LiteralPath}
        $target=Join-Path $area 'synthetic-guarded.cmd'
        [IO.File]::WriteAllText($target,'@exit /b 0')
        Write-GuardSetupShortcut $area 'Guard Test.lnk' $target '' 'Guard fixture'
        $linkPath=Join-Path $area 'Guard Test.lnk'
        Require (Test-GuardSetupShortcut $linkPath $target '') 'A normal Windows shortcut reopens the exact guarded launcher on a clean install'
        Write-GuardSetupShortcut $area 'Guard Test.lnk' $target '--settings' 'Guard settings fixture'
        Require (Test-GuardSetupShortcut $linkPath $target '--settings') 'An update replaces and verifies an existing settings shortcut'
    }
}finally{
    if($profile){$profile.Password.Dispose()}
    $actual=[IO.Path]::GetFullPath($area);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if([IO.Path]::GetDirectoryName($actual).TrimEnd('\') -eq $base.TrimEnd('\') -and
        [IO.Path]::GetFileName($actual) -cmatch '^guard-profile-store-tests-[a-f0-9]{32}$' -and [IO.Directory]::Exists($actual)){
        Remove-Item -LiteralPath $actual -Recurse -Force
    }
}
