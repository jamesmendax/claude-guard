$script:GuardReleaseRuntimePins=[ordered]@{
    'guard-dedicated-relay.exe'='CF894375DBC00AB6708C1314AC35BBD29059F4C37F315353AACA7F1A9C566DE6'
    'guard-exit-observer.exe'='86FC4785327DB5F5C7558DC6156C543B433C313E813A222E088086222AB4AFA6'
    'cloudflare-exit-probe.mjs'='E586ED2C31398A9ACD43AB1E4374611F2C515BFDD24AEF4E0E7027F5D17C3C37'
}
$script:GuardReleaseVendorPins=[ordered]@{
    'SbieDrv.sys'='4BCA736871ACFDBA6B4AD54A0CCE2A99B953A87E43270644E5992D564685CCA0'
    'sbiedrv.cat'='94439DF493A5BD698AB5CBC9933BE9D7B5253B79925B6A9A48384E6EA05D959C'
    'SbieSvc.exe'='6BA437F8D45E1C0A0C54FEA39942431B4FEAC4B725AAE07DC6E527E3E57EF34D'
    'SbieSvc.exe.sig'='1337A49908134FDC6E85174A1597D726DCD011E2670305F8082FE3D9DB6E630A'
    'SbieDll.dll'='7C0272E146DCD4162B40CD551CCABDE45EEB6F0031E8CDBB523C551900039FEF'
    'SbieMsg.dll'='8FBD00797808EE165915BB1BACCF5F7E76ED7A62C782A34076B7D94241BB8280'
    'Start.exe'='1711F06241B00E3C4450897A0D07198BBB564A7B3A5C99BD9F38E98426DAC413'
    'Start.exe.sig'='F597797D9304A82C8EF275F3B5D68681C719ECE91820B187CFF3AEE35B87D727'
    'KmdUtil.exe'='EA863504C41BA1F2FCB98D42E01F9CA5C60E1E4268111CD1BFB55342A6605502'
    'Templates.ini'='527CFE01A3330FDB32C8757AAD22539C1EEB62806D3D662559ED19D7FBECF265'
    'SandboxieRpcSs.exe'='68E97B4FC95F43BD210D7F538B478E780A0276B779FFDE0FAA2B9932F3EF7C78'
    'SandboxieDcomLaunch.exe'='4E2C9FD765DE69FD0AA640F2670127A2498029B42B24357F3F4654F9E5BFBB4E'
    'SandboxieBITS.exe'='ECECA8E0E4F04ECA11EBA9A417B91BAEB2C818354FD7CD010029CBDEFB964290'
    'SandboxieCrypto.exe'='D4E14151EFF2ED58C4266488E9A20B60C4E5D6F16F4443B9848A9068078DE219'
    'SandboxieWUAU.exe'='C1C8052AEEDB2D3428C538A703646031F55C4A93089A7D67CE01DDF388F9B815'
    '32\SbieDll.dll'='A938B81BE83A13C4A239A19E5BAC2CB4137DAC3540BCB132920C5A045E631E9D'
    '32\SbieSvc.exe'='45D304D290F4A7D8ECA54FC2978D1ED2AFA4B624EDFD15F723E7FB92C1C38469'
}
$script:GuardReleasePackageFiles=@(
    'guard-runtime.ps1','guard-common.ps1','guard-privacy.ps1','guard-diagnostics.ps1','guard-isolation.ps1',
    'guard-network.ps1','guard-daily.ps1','guard-daily-controller.ps1','guard-daily-plan.ps1','guard-wfp.cs',
    'guard-app-container.cs','guard-lookup-preferences.ps1','guard-daily-notifications.ps1','guard-daily-notifier.ps1',
    'guard-daily-notifier-task.ps1','guard-daily-supervisor.ps1','guard-sandboxie.ps1','guard-daily-package.ps1',
    'guard-relay-evidence.cs','guard-daily-store-stage.ps1','guard-daily-store-worker.ps1',
    'check-protection.ps1','open-claude-daily.ps1','open-claude-daily.cmd'
)
function Assert-GuardReleaseOwnedPath([string]$Path,[switch]$Directory){
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trusted=@('S-1-5-18','S-1-5-32-544')
    $writes=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    if($item.PSIsContainer -ne [bool]$Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
        @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $writes) -and $_.IdentityReference.Value -notin $trusted
        }).Count){throw 'A deployment input or destination is outside administrator control.'}
}
function Get-GuardReleaseCanonicalIpv4([string]$Address) {
    $ipv4=$null
    if(-not [ipaddress]::TryParse($Address,[ref]$ipv4) -or $ipv4.AddressFamily -ne 'InterNetwork' -or $ipv4.ToString() -cne $Address){
        throw 'Provide the verified public IPv4 as four decimal numbers.'
    }
    $Address
}
function Get-GuardReleaseGeneration([string[]]$Values) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try{[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Values -join '|')))).Replace('-','')}
    finally{$hash.Dispose()}
}
function Get-GuardReleaseAsset($Source,$Target,[string]$Pin) {
    Assert-GuardReleaseOwnedPath $Source
    $digest=(Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
    if($Pin -and $digest -cne $Pin){throw "The pinned release input changed: $(Split-Path -Leaf $Source)."}
    [pscustomobject]@{Source=$Source;Target=$Target;Sha256=$digest}
}
function Set-GuardReleaseAsset($Asset){
    $source=Get-GuardReleaseAsset $Asset.Source $Asset.Target $Asset.Sha256
    $parent=Split-Path -Parent $source.Target
    Assert-GuardReleaseOwnedPath $parent -Directory
    $temporary=Join-Path $parent ('guard-install-'+[guid]::NewGuid().ToString('N')+'.tmp')
    try{
        [IO.File]::Copy($source.Source,$temporary,$false)
        $acl=Get-Acl -LiteralPath $temporary
        $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
        Set-Acl -LiteralPath $temporary -AclObject $acl
        if([IO.File]::Exists($source.Target)){
            Assert-GuardReleaseOwnedPath $source.Target
            [IO.File]::Replace($temporary,$source.Target,$temporary+'.bak')
        }else{[IO.File]::Move($temporary,$source.Target)}
        $null=Get-GuardReleaseAsset $source.Target $source.Source $source.Sha256
    }finally{[IO.File]::Delete($temporary);[IO.File]::Delete($temporary+'.bak')}
}
function Invoke-GuardReleaseChange($Operation,$Result) {
    $changed=$false
    try{
        $Result.Phase='Preflight'
        if($Operation.Progress){& $Operation.Progress $Result.Phase}
        & $Operation.Preflight
        $Result.Phase='Backup'
        if($Operation.Progress){& $Operation.Progress $Result.Phase}
        & $Operation.Backup
        $changed=$true
        foreach($step in 'Close','Install','Verify'){
            $Result.Phase=$step
            if($Operation.Progress){& $Operation.Progress $Result.Phase}
            & $Operation.Publish
            & $Operation[$step]
        }
        $Result.Phase='Completed'
        if($null -ne $Result.PhaseTimes){$Result.PhaseTimes.Completed=[datetime]::UtcNow.ToString('o')}
        $Result.Installed=$true
        & $Operation.Publish
        $Result.Phase='Commit'
        if($Operation.Progress){& $Operation.Progress $Result.Phase}
        & $Operation.Commit
        $Result.Phase='Completed'
        if($Operation.Progress){& $Operation.Progress $Result.Phase}
    }catch{
        $Result.FailedPhase=$Result.Phase
        $Result.Error=$_.Exception.Message
        if($changed){
            try{
                $Result.Phase='RollingBack'
                if($Operation.Progress){& $Operation.Progress $Result.Phase}
                & $Operation.Restore
                $Result.Phase='RolledBack'
                $Result.Restored=$true
            }catch{
                $Result.Phase='RollbackIncomplete'
                $Result.RestoreError=$_.Exception.Message
            }
        }else{$Result.Phase='Rejected'}
        $Result.Installed=$false
        if($Operation.Progress){& $Operation.Progress $Result.Phase}
        & $Operation.Publish
    }
}
function Invoke-GuardReleaseDriverTool([string]$Tool,[string]$Arguments) {
    $child=Start-GuardDailyChild $Tool $Arguments ''
    try{
        if(-not $child.Process.WaitForExit(15000) -or $child.Process.ExitCode -ne 0){
            throw "Sandboxie service operation did not complete: $(($Arguments -split ' ')[0])."
        }
    }finally{Stop-GuardDailyChild $child}
}
function Install-GuardReleaseDriver([string]$Driver,[string]$ProgramRoot,[int]$Port,[string]$DataRoot) {
    $ini=Join-Path $Driver 'Sandboxie.ini'
    $templates=Join-Path $Driver 'Templates.ini'
    $dnsException='(?im)^OpenIpcPath=\\RPC Control\\DNSResolver[ \t]*\r?$'
    $original=[IO.File]::ReadAllText($templates)
    if([regex]::Matches($original,$dnsException).Count -ne 1){throw 'The pinned Sandboxie DNS template exception changed.'}
    [IO.File]::WriteAllText($templates,[regex]::Replace($original,$dnsException,''),[Text.Encoding]::Unicode)
    $null=Get-GuardReleaseAsset $templates $templates 'B5258D4D6B881B29677336E166DD6494DD73A8171F67826318F4AB2243CC1736'
    [IO.File]::WriteAllLines($ini,@(New-GuardSandboxiePolicy $ProgramRoot $Port $DataRoot),[Text.Encoding]::Unicode)
    $acl=Get-Acl -LiteralPath $ini
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    Set-Acl -LiteralPath $ini -AclObject $acl
    $kmd=Join-Path $Driver 'KmdUtil.exe'
    $sys=Join-Path $Driver 'SbieDrv.sys'
    $service=Join-Path $Driver 'SbieSvc.exe'
    $messages=Join-Path $Driver 'SbieMsg.dll'
    foreach($image in $kmd,$sys,$service){
        if((Get-AuthenticodeSignature -LiteralPath $image).Status -ne 'Valid'){throw 'A Sandboxie component signature is invalid.'}
    }
    Invoke-GuardReleaseDriverTool $kmd ('install SbieDrv "'+$sys+'" type=kernel start=demand msgfile="'+$messages+'" altitude=86900')
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SbieDrv' -Name IniPath -Value $ini -PropertyType String | Out-Null
    Invoke-GuardReleaseDriverTool $kmd ('install SbieSvc "'+$service+'" type=own start=auto msgfile="'+$messages+'" display="Sandboxie Guard Service" group=UIGroup')
    Invoke-GuardReleaseDriverTool $kmd 'start SbieSvc'
}
function Remove-GuardReleaseDriver([string]$Driver) {
    $kmd=Join-Path $Driver 'KmdUtil.exe'
    $null=Get-GuardReleaseAsset $kmd $kmd $script:GuardReleaseVendorPins['KmdUtil.exe']
    foreach($name in 'SbieSvc','SbieDrv'){
        $key="HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $messageKey="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\$name"
        if((Test-Path -LiteralPath $messageKey) -and
            [string](Get-ItemProperty -LiteralPath $messageKey -Name EventMessageFile).EventMessageFile -ine (Join-Path $Driver 'SbieMsg.dll')){
            throw 'Sandboxie event source belongs to another installation.'
        }
        if(Test-Path -LiteralPath $key){
            $raw=[string](Get-ItemProperty -LiteralPath $key -Name ImagePath).ImagePath
            $path=$raw.Trim('"')
            if($path.StartsWith('\??\',[StringComparison]::Ordinal)){$path=$path.Substring(4)}
            $binary=if($name -ceq 'SbieDrv'){'SbieDrv.sys'}else{'SbieSvc.exe'}
            if($path -ine (Join-Path $Driver $binary)){throw 'Sandboxie service belongs to another installation.'}
            $service=Get-Service -Name $name -ErrorAction Stop
            try{
                if($service.Status -ne 'Stopped'){
                    Invoke-GuardReleaseDriverTool $kmd "stop $name"
                    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(12))
                }
            }finally{$service.Dispose()}
        }
        if((Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $messageKey)){Invoke-GuardReleaseDriverTool $kmd "delete $name"}
        if((Test-Path -LiteralPath $key) -or (Test-Path -LiteralPath $messageKey)){throw 'A Guard Sandboxie service remains registered.'}
    }
}
