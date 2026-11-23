#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$NodePath,
    [string]$NodeLicense,
    [string]$MihomoPath,
    [string]$SandboxieDirectory,
    [string]$SandboxieTemplatesPath,
    [string]$GplLicense,
    [string]$DependencySourceDirectory
)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){
    throw 'Build this deterministic Windows artifact using 64-bit Windows PowerShell 5.1.'
}
Add-Type -AssemblyName System.IO.Compression

$root=Split-Path -Parent $PSScriptRoot
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root 'out'}
if(-not $NodePath){$NodePath=Join-Path $env:USERPROFILE '.codex\tools\node-v24.22.3\node.exe'}
if(-not $NodeLicense){$NodeLicense=Join-Path (Split-Path -Parent (Get-Item -LiteralPath $NodePath).FullName) 'LICENSE'}
if(-not $MihomoPath){$MihomoPath=Join-Path $root 'evidence\mihomo-syntax\mihomo\mihomo-windows-amd64-v1.exe'}
if(-not $SandboxieDirectory){$SandboxieDirectory=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ClaudeVPNGuard\daily\sandboxie'}
if(-not $GplLicense){$GplLicense=Join-Path $root '..\..\LICENSE'}
$windows=[Environment]::GetFolderPath('Windows')
$framework=Join-Path $windows 'Microsoft.NET\Framework64\v4.0.30319'
$compiler=Join-Path $framework 'csc.exe'
$curl=Join-Path ([Environment]::GetFolderPath('System')) 'curl.exe'
$utf8=[Text.UTF8Encoding]::new($false,$true)
$epoch=[DateTimeOffset]::new(1980,1,1,0,0,0,[TimeSpan]::Zero)
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('guard-setup-build-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($scratch)

function Read-SetupInput([string]$Path,[string]$Sha256){
    $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw "A release input is redirected or has the wrong type: $($file.Name)."
    }
    if($Sha256 -and (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $Sha256){
        throw "The pinned release input changed: $($file.Name)."
    }
    $file
}

function Get-SetupPublicInput([string]$Url,[string]$Name,[string]$Sha256){
    $target=Join-Path $scratch $Name
    & $curl --silent --show-error --fail --location --proto '=https' --proto-redir '=https' --max-time 120 --output $target $Url
    if($LASTEXITCODE -ne 0){throw "Official release input could not be downloaded: $Name."}
    Read-SetupInput $target $Sha256
}

function Find-SetupImageOffset([byte[]]$Bytes,[int]$Table,[int]$Sections,[long]$Address){
    for($i=0;$i -lt $Sections;$i++){
        $section=$Table+$i*40
        $virtual=[BitConverter]::ToUInt32($Bytes,$section+12)
        $length=[BitConverter]::ToUInt32($Bytes,$section+16)
        if($Address -ge $virtual -and $Address-$virtual -lt $length){
            return [int]([BitConverter]::ToUInt32($Bytes,$section+20)+$Address-$virtual)
        }
    }
    throw 'The compiler emitted an unmapped metadata address.'
}

function ConvertTo-DeterministicSetupImage([string]$Path){
    # The Framework compiler timestamps the PE and gives the module and its
    # optional private data type per-compilation identifiers.
    $bytes=[IO.File]::ReadAllBytes($Path)
    $header=[BitConverter]::ToInt32($bytes,60)
    if([BitConverter]::ToUInt32($bytes,$header) -ne 0x4550 -or [BitConverter]::ToUInt16($bytes,$header+4) -ne 0x8664){
        throw 'The compiler did not emit an x64 executable.'
    }
    $optional=$header+24
    if([BitConverter]::ToUInt16($bytes,$optional) -ne 0x20b){throw 'The installer requires PE32+ metadata.'}
    $sections=[BitConverter]::ToUInt16($bytes,$header+6)
    $table=$optional+[BitConverter]::ToUInt16($bytes,$header+20)
    $cli=Find-SetupImageOffset $bytes $table $sections ([BitConverter]::ToUInt32($bytes,$optional+112+14*8))
    $metadata=Find-SetupImageOffset $bytes $table $sections ([BitConverter]::ToUInt32($bytes,$cli+8))
    if([BitConverter]::ToUInt32($bytes,$metadata) -ne 0x424a5342){throw 'The installer CLR metadata is invalid.'}
    $start=$metadata+16+[BitConverter]::ToInt32($bytes,$metadata+12)
    $streamCount=[BitConverter]::ToUInt16($bytes,$start+2)
    $cursor=$start+4
    $guidOffset=-1
    $guidSize=0
    $stringOffset=-1
    $stringSize=0
    for($i=0;$i -lt $streamCount;$i++){
        $end=[Array]::IndexOf($bytes,[byte]0,$cursor+8,[Math]::Min(32,$bytes.Length-$cursor-8))
        if($end -lt 0){throw 'An installer metadata stream name is invalid.'}
        $name=[Text.Encoding]::ASCII.GetString($bytes,$cursor+8,$end-$cursor-8)
        if($name -ceq '#GUID'){
            $guidOffset=$metadata+[BitConverter]::ToInt32($bytes,$cursor)
            $guidSize=[BitConverter]::ToInt32($bytes,$cursor+4)
        }elseif($name -ceq '#Strings'){
            $stringOffset=$metadata+[BitConverter]::ToInt32($bytes,$cursor)
            $stringSize=[BitConverter]::ToInt32($bytes,$cursor+4)
        }
        $cursor=($end+4) -band -4
    }
    if($guidOffset -lt 0 -or $guidSize -lt 16){throw 'The installer is missing its CLR GUID heap.'}
    $module=[Reflection.Assembly]::ReflectionOnlyLoad($bytes).ManifestModule.ModuleVersionId.ToByteArray()
    $encoding=[Text.Encoding]::GetEncoding(28591)
    $heap=$encoding.GetString($bytes,$guidOffset,$guidSize)
    $needle=$encoding.GetString($module)
    $position=$heap.IndexOf($needle,[StringComparison]::Ordinal)
    if($position -lt 0 -or $position % 16 -ne 0 -or $heap.LastIndexOf($needle,[StringComparison]::Ordinal) -ne $position){
        throw 'The compiler emitted an unexpected module identifier layout.'
    }
    $position+=$guidOffset
    if($stringOffset -lt 0 -or $stringSize -lt 1){throw 'The installer is missing its CLR string heap.'}
    $strings=$encoding.GetString($bytes,$stringOffset,$stringSize)
    $privateIds=[regex]::Matches($strings,'(?<=<PrivateImplementationDetails>\{)[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}(?=\}\x00)')
    if($privateIds.Count -gt 1){throw 'The compiler emitted multiple private data types.'}
    if($privateIds.Count){
        # Only the metadata type name changes. IL references use its token.
        $stable=[Text.Encoding]::ASCII.GetBytes([guid]::Empty.ToString('D'))
        [Array]::Copy($stable,0,$bytes,($stringOffset+$privateIds[0].Index),$stable.Length)
    }
    [Array]::Clear($bytes,$header+8,4)
    [Array]::Clear($bytes,$header+88,4)
    [Array]::Clear($bytes,$position,16)
    $hash=[Security.Cryptography.SHA256]::Create()
    try{$value=$hash.ComputeHash($bytes)}finally{$hash.Dispose()}
    [Array]::Copy($value,0,$bytes,$position,16)
    [IO.File]::WriteAllBytes($Path,$bytes)
}

function Write-SetupArchive([string]$Path,[System.Collections.IDictionary]$Files,[string]$Manifest){
    [string[]]$names=@($Files.Keys)
    [Array]::Sort($names,[StringComparer]::Ordinal)
    $rows=[System.Collections.Generic.List[string]]::new()
    $output=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{
        $archive=[IO.Compression.ZipArchive]::new($output,[IO.Compression.ZipArchiveMode]::Create,$true)
        try{
            foreach($name in $names){
                $file=$Files[$name]
                $level=if($name.EndsWith('.zip')){[IO.Compression.CompressionLevel]::NoCompression}else{[IO.Compression.CompressionLevel]::Optimal}
                $entry=$archive.CreateEntry($name,$level)
                $entry.LastWriteTime=$epoch
                $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                try{
                    if($Manifest){
                        $hash=(Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
                        $rows.Add($hash+"`t"+$stream.Length.ToString([Globalization.CultureInfo]::InvariantCulture)+"`t"+$name)
                        $stream.Position=0
                    }
                    $target=$entry.Open()
                    try{$stream.CopyTo($target)}finally{$target.Dispose()}
                }finally{$stream.Dispose()}
            }
        }finally{$archive.Dispose()}
    }finally{$output.Dispose()}
    if($Manifest){[IO.File]::WriteAllText($Manifest,($rows -join "`n")+"`n",$utf8)}
}

try{
    $payload=@{}
    $packageNames=@(
        'check-protection.ps1','guard-app-container.cs','guard-autorefresh.ps1','guard-common.ps1',
        'guard-daily-controller.ps1','guard-daily-cutover.ps1','guard-daily-notifications.ps1','guard-daily-notifier-task.ps1',
        'guard-daily-notifier.ps1','guard-daily-package.ps1','guard-daily-plan.ps1','guard-daily-store-stage.ps1',
        'guard-daily-store-worker.ps1','guard-daily-supervisor.ps1','guard-daily.ps1','guard-diagnostics.ps1',
        'guard-isolation.ps1','guard-lookup-preferences.ps1','guard-network.ps1','guard-node-profile.ps1','guard-privacy.ps1',
        'guard-profile-store.ps1','guard-region-profile.ps1','guard-relay-evidence.cs','guard-runtime.ps1','guard-sandboxie.ps1',
        'guard-wfp.cs','open-claude-daily.cmd','open-claude-daily.ps1','setup-firewall.ps1'
    )
    foreach($name in $packageNames){$payload['package/'+$name]=Read-SetupInput (Join-Path $root ('package\'+$name))}
    foreach($name in 'install-guard.ps1','install-guard-helpers.ps1','guard-window-actions.ps1','guard-window-evidence.ps1','guard-profile-actions.ps1',
        'guard-region-zones.json','Unicode-Data-License.txt'){
        $payload['release/'+$name]=Read-SetupInput (Join-Path $PSScriptRoot $name)
    }
    $observer=Read-SetupInput $NodePath '86FC4785327DB5F5C7558DC6156C543B433C313E813A222E088086222AB4AFA6'
    $nodeSignature=Get-AuthenticodeSignature -LiteralPath $observer.FullName
    if($nodeSignature.Status -ne 'Valid' -or
        $nodeSignature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'OpenJS Foundation'){
        throw 'The official Node.js Authenticode signature is invalid.'
    }
    $payload['runtime/guard-exit-observer.exe']=$observer
    $payload['runtime/guard-dedicated-relay.exe']=Read-SetupInput $MihomoPath 'CF894375DBC00AB6708C1314AC35BBD29059F4C37F315353AACA7F1A9C566DE6'
    $probeSource=Join-Path $root 'tests\cloudflare-exit-probe.mjs'
    if(-not (Test-Path -LiteralPath $probeSource -PathType Leaf)){$probeSource=Join-Path $root 'runtime\cloudflare-exit-probe.mjs'}
    $payload['runtime/cloudflare-exit-probe.mjs']=Read-SetupInput $probeSource
    $payload['licenses/Node-LICENSE.txt']=Read-SetupInput $NodeLicense 'ED34DD8E3F0A78DBAF00D0444CE8E285B015B765379C2E17880455F70370F8E9'
    $payload['licenses/GPL-3.0.txt']=Read-SetupInput $GplLicense '3972DC9744F6499F0F9B2DBF76696F2AE7AD8AF9B23DDE66D6AF86C9DFB36986'
    $notices=Join-Path $PSScriptRoot 'THIRD-PARTY-NOTICES.md'
    if(-not (Test-Path -LiteralPath $notices -PathType Leaf)){$notices=Join-Path $root 'licenses\THIRD-PARTY-NOTICES.md'}
    $payload['licenses/THIRD-PARTY-NOTICES.md']=Read-SetupInput $notices

    $sandboxie=[ordered]@{
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
        '32/SbieDll.dll'='A938B81BE83A13C4A239A19E5BAC2CB4137DAC3540BCB132920C5A045E631E9D'
        '32/SbieSvc.exe'='45D304D290F4A7D8ECA54FC2978D1ED2AFA4B624EDFD15F723E7FB92C1C38469'
    }
    if(-not $SandboxieTemplatesPath){
        $raw=Get-SetupPublicInput 'https://raw.githubusercontent.com/sandboxie-plus/Sandboxie/v1.19.1/Sandboxie/install/Templates.ini' `
            'Sandboxie-Templates.ini' 'CB65ACA0D9F1091A61C849015314190A9F8B12B01B13DD3D77AF49517AE71393'
        $SandboxieTemplatesPath=Join-Path $scratch 'Templates.ini'
        [IO.File]::WriteAllText($SandboxieTemplatesPath,([IO.File]::ReadAllText($raw.FullName) -replace '\r?\n',"`r`n"),[Text.UTF8Encoding]::new($true))
    }
    foreach($name in $sandboxie.Keys){
        $path=if($name -ceq 'Templates.ini'){$SandboxieTemplatesPath}else{Join-Path $SandboxieDirectory ($name.Replace('/','\'))}
        $asset=Read-SetupInput $path $sandboxie[$name]
        if($name -cin 'SbieDrv.sys','SbieSvc.exe','SbieDll.dll','Start.exe','KmdUtil.exe'){
            $signature=Get-AuthenticodeSignature -LiteralPath $asset.FullName
            if($signature.Status -ne 'Valid'){throw "The public Sandboxie Authenticode signature is invalid: $name."}
        }
        $payload['vendor/sandboxie/'+$name]=$asset
    }

    foreach($name in $payload.Keys){
        if($name -notmatch '\.(?:ps1|cs|mjs|cmd)$'){continue}
        $source=[IO.File]::ReadAllText($payload[$name].FullName)
        if($source -match '(?i)(?:[a-z]:\\Users\\[^\\]+\\|[a-z]:\\appdata\\codex\\|(?:vless|trojan|vmess)://[A-Za-z0-9])'){
            throw "A candidate release source contains a private location or subscription literal: $name."
        }
    }

    $sources=@{}
    foreach($name in $payload.Keys){if($name -notmatch '\.(?:exe|sys|cat|dll|sig|ini)$'){$sources[$name]=$payload[$name]}}
    $sources['vendor/sandboxie/Templates.ini']=$payload['vendor/sandboxie/Templates.ini']
    foreach($name in 'GuardSetup.cs','GuardSetupActions.cs','GuardSetupWindow.cs','GuardSetupWindow.xaml','build-setup.ps1','guard-setup.manifest'){
        $sources['release/'+$name]=Read-SetupInput (Join-Path $PSScriptRoot $name)
    }
    $dependencies=@(
        @{Name='mihomo-v1.19.30.zip';Sha='6790545B467FD6E61B6610793F37B64FAC7F59B061F222501F6CC3A7A5DE7C8B';Url='https://codeload.github.com/MetaCubeX/mihomo/zip/refs/tags/v1.19.30'},
        @{Name='sandboxie-v1.19.1.zip';Sha='2A1A8DA626A478678FB89671546E2065B572976BF418272156F05685BF77726F';Url='https://codeload.github.com/sandboxie-plus/Sandboxie/zip/refs/tags/v1.19.1'},
        @{Name='claude-vpn-guard-v1.4.4.zip';Sha='D8B8E1E7E0F1D5F4B376333D341B293FDA8DBD288923D31D3E9E8792E13FE14D';Url='https://codeload.github.com/gruskry/claude-vpn-guard/zip/806d9489c8743363cbf64adf8f6284577adf13f8'}
    )
    foreach($dependency in $dependencies){
        $file=if($DependencySourceDirectory){Read-SetupInput (Join-Path $DependencySourceDirectory $dependency.Name) $dependency.Sha}
            else{Get-SetupPublicInput $dependency.Url $dependency.Name $dependency.Sha}
        $sources['upstream/'+$dependency.Name]=$file
    }

    $payloadZip=Join-Path $scratch 'payload.zip'
    $manifest=Join-Path $scratch 'payload.tsv'
    Write-SetupArchive $payloadZip $payload $manifest
    $version='1.0.1'
    $exeName="ClaudeGuardSetup-$version-x64.exe"
    $compiled=Join-Path $scratch $exeName
    $nativeSources=@('GuardSetup.cs','GuardSetupActions.cs','GuardSetupWindow.cs' | ForEach-Object {Join-Path $PSScriptRoot $_})
    $xaml=Join-Path $PSScriptRoot 'GuardSetupWindow.xaml'
    $win32=Join-Path $PSScriptRoot 'guard-setup.manifest'
    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Xaml
    $references=@(
        '/reference:System.IO.Compression.dll'
        foreach($type in [Management.Automation.PowerShell],[Windows.Window],[Windows.Media.Visual],[Windows.DependencyObject],[Xaml.XamlReader]){
            '/reference:'+$type.Assembly.Location
        }
    )
    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /debug- /langversion:5 /codepage:65001 @references `
        "/win32manifest:$win32" "/resource:$payloadZip,Guard.Payload" "/resource:$manifest,Guard.Manifest" `
        "/resource:$xaml,Guard.SetupWindow" "/out:$compiled" @nativeSources
    if($LASTEXITCODE -ne 0){throw 'The Windows installer compiler failed.'}
    ConvertTo-DeterministicSetupImage $compiled
    $verification=Start-Process -FilePath $compiled -ArgumentList '--verify' -Wait -PassThru -WindowStyle Hidden
    if($verification.ExitCode -ne 0){throw 'The compiled installer failed its read-only payload verification.'}

    $sourceName="ClaudeGuardSetup-$version-sources.zip"
    $sourceZip=Join-Path $scratch $sourceName
    Write-SetupArchive $sourceZip $sources
    $exeHash=(Get-FileHash -LiteralPath $compiled -Algorithm SHA256).Hash
    $sourceHash=(Get-FileHash -LiteralPath $sourceZip -Algorithm SHA256).Hash
    $summaryName="ClaudeGuardSetup-$version-SHA256.txt"
    $summary=Join-Path $scratch $summaryName
    [IO.File]::WriteAllText($summary,("$exeHash  $exeName`n$sourceHash  $sourceName`n"),$utf8)
    $output=[IO.Path]::GetFullPath($OutputDirectory)
    $null=[IO.Directory]::CreateDirectory($output)
    foreach($file in $sourceZip,$summary,$compiled){Copy-Item -LiteralPath $file -Destination (Join-Path $output (Split-Path -Leaf $file)) -Force}
    [pscustomobject]@{
        Setup=(Join-Path $output $exeName);SetupSha256=$exeHash;Sources=(Join-Path $output $sourceName);SourcesSha256=$sourceHash
        PayloadFiles=$payload.Count;Verified=$true;Signed=$false
    }
}finally{
    $storage=Get-Item -LiteralPath $scratch -Force
    $safe=$storage.FullName
    if(($storage.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Split-Path -Parent $safe) -ine ([IO.Path]::GetTempPath().TrimEnd('\')) -or
        (Split-Path -Leaf $safe) -cnotmatch '\Aguard-setup-build-[a-f0-9]{32}\z'){
        throw 'The scratch build directory changed.'
    }
    Remove-Item -LiteralPath $safe -Recurse -Force
}
