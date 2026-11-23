#Requires -Version 5.1
param([Parameter(Mandatory)][string]$SetupPath,[string]$ReferenceSetupPath)

$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Run the package tests in Windows PowerShell 5.1.'}
$setup=(Get-Item -LiteralPath $SetupPath -ErrorAction Stop).FullName
$temp=[IO.Path]::GetTempPath().TrimEnd('\')
$scratch=Join-Path $temp ('guard-setup-verification-'+[guid]::NewGuid().ToString('N'))
$extracted=Join-Path $temp ('guard-setup-test-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($scratch)

function Assert-SetupPackage([bool]$Condition,[string]$Message){
    if(-not $Condition){throw "FAIL: $Message"}
    "PASS: $Message"
}

function Invoke-SetupVerification([string]$Executable,[string]$Arguments){
    $start=[Diagnostics.ProcessStartInfo]::new($Executable,$Arguments)
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.WorkingDirectory=$scratch
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start)
    try{
        $text=$process.StandardOutput.ReadToEndAsync()
        $errorText=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(45000)){
            $process.Kill()
            throw 'The local read-only installer test did not finish.'
        }
        [pscustomobject]@{Code=$process.ExitCode;Output=$text.GetAwaiter().GetResult();Error=$errorText.GetAwaiter().GetResult()}
    }finally{$process.Dispose()}
}

try{
    $image=[IO.File]::ReadAllBytes($setup)
    $pe=[BitConverter]::ToInt32($image,60)
    Assert-SetupPackage ([BitConverter]::ToUInt16($image,$pe+4) -eq 0x8664 -and
        [BitConverter]::ToUInt16($image,$pe+24+68) -eq 2) 'the native executable is x64 with the GUI subsystem'
    $assembly=[Reflection.Assembly]::ReflectionOnlyLoad($image)
    Assert-SetupPackage ($assembly.GetName().Version -eq [version]'1.0.4.0' -and
        $assembly.GetManifestResourceNames() -ccontains 'Guard.SetupWindow' -and
        $assembly.GetReferencedAssemblies().Name -ccontains 'PresentationFramework' -and
        $assembly.GetReferencedAssemblies().Name -ccontains 'System.Management.Automation') 'the 1.0.4 host embeds WPF and uses the Windows PowerShell engine in-process'
    $hostType=[Reflection.Assembly]::Load($image).GetType('GuardSetup',$true)
    $flags=[Reflection.BindingFlags]'Static,NonPublic'
    $encode=$hostType.GetMethod('WindowFailureRecord',$flags)
    $when=[datetime]::UtcNow
    $cases=@(
        @{Error=[UnauthorizedAccessException]::new('private-fixture');Kind='WindowsAccess'}
        @{Error=[IO.IOException]::new('private-fixture');Kind='FileAccess'}
        @{Error=[ComponentModel.Win32Exception]::new(5,'private-fixture');Kind='WindowsError'}
        @{Error=[InvalidOperationException]::new('private-fixture');Kind='RuntimeError'}
    )
    foreach($case in $cases){
        $encoded=$encode.Invoke($null,[object[]]@($case.Error,$when))
        $issue=$encoded|ConvertFrom-Json
        if($issue.Schema -ne 1 -or $issue.Component -cne 'GuardSettingsWindow' -or $issue.Kind -cne $case.Kind -or
            $issue.TimeUtc -cne $when.ToString('o') -or $issue.HResult -cne ('0x{0:X8}' -f $case.Error.HResult) -or
            @($issue.PSObject.Properties).Count -ne 5 -or $encoded -like '*private-fixture*'){throw 'The setup failure receipt lost its source or exposed an exception message.'}
    }
    $missing=Join-Path $scratch 'missing-protected-root'
    $save=$hostType.GetMethod('RecordWindowFailure',$flags)
    Assert-SetupPackage (-not $save.Invoke($null,[object[]]@([string]$missing,$cases[0].Error)) -and -not [IO.Directory]::Exists($missing)) 'window error reporting keeps only the source, category, time and error code and leaves unavailable storage alone'
    $resource=$assembly.GetManifestResourceStream('Guard.Manifest')
    try{
        $reader=[IO.StreamReader]::new($resource,[Text.Encoding]::UTF8,$false)
        try{$manifest=$reader.ReadToEnd()}finally{$reader.Dispose()}
    }finally{$resource.Dispose()}
    $rows=@($manifest.TrimEnd("`n").Split("`n"))

    $verify=Invoke-SetupVerification $setup '--verify'
    Assert-SetupPackage ($verify.Code -eq 0 -and $verify.Output -like ('Verified '+$rows.Count+' files.*') -and
        -not @(Get-ChildItem -LiteralPath $scratch -Force).Count) 'verify checks all resources without writing to its working directory'
    $wrong=Join-Path $scratch 'outside-fixture'
    $invalid=Invoke-SetupVerification $setup ('--extract-test "'+$wrong+'"')
    Assert-SetupPackage ($invalid.Code -ne 0 -and -not (Test-Path -LiteralPath $wrong)) 'test extraction rejects paths outside its dedicated TEMP leaf'
    $extract=Invoke-SetupVerification $setup ('--extract-test "'+$extracted+'"')
    Assert-SetupPackage ($extract.Code -eq 0 -and $extract.Output -like ('Extracted and verified '+$rows.Count+' files*')) 'a safe temporary extraction verifies without installation or elevation'

    foreach($row in $rows){
        $fields=$row.Split("`t")
        $file=Get-Item -LiteralPath (Join-Path $extracted $fields[2])
        if($file.Length -ne [long]$fields[1] -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $fields[0]){
            throw 'An extracted file differs from the embedded manifest.'
        }
    }
    Assert-SetupPackage (@(Get-ChildItem -LiteralPath $extracted -File -Recurse -Force).Count -eq $rows.Count) 'every extracted file matches the embedded length, hash and exact file set'
    $vendor=Join-Path $extracted 'vendor\sandboxie'
    Assert-SetupPackage (@(Get-ChildItem -LiteralPath $vendor -File -Recurse -Force).Count -eq 17 -and
        -not @(Get-ChildItem -LiteralPath $extracted -Recurse -Force -File -Filter 'Sandboxie.ini').Count -and
        (Get-FileHash -LiteralPath (Join-Path $vendor 'Templates.ini')).Hash -ceq '527CFE01A3330FDB32C8757AAD22539C1EEB62806D3D662559ED19D7FBECF265') 'only the 17 public Sandboxie files and the original template are present'
    Assert-SetupPackage ((Get-FileHash -LiteralPath (Join-Path $extracted 'runtime/guard-dedicated-relay.exe')).Hash -ceq 'CF894375DBC00AB6708C1314AC35BBD29059F4C37F315353AACA7F1A9C566DE6' -and
        (Get-FileHash -LiteralPath (Join-Path $extracted 'runtime/guard-exit-observer.exe')).Hash -ceq '86FC4785327DB5F5C7558DC6156C543B433C313E813A222E088086222AB4AFA6') 'the embedded relay and Node executable match the selected vendor releases'
    $expected='release/guard-window-actions.ps1','release/guard-window-evidence.ps1','release/guard-profile-actions.ps1','release/install-guard.ps1',
        'release/guard-region-zones.json','release/guard-site-language.ps1','release/guard-user-region.ps1','release/Unicode-Data-License.txt',
        'package/guard-node-locale.ps1','package/guard-windows-locale.ps1','package/guard-browser-languages.ps1',
        'package/guard-region-profile.ps1','package/guard-node-profile.ps1','package/guard-profile-store.ps1',
        'runtime/cloudflare-exit-probe.mjs','licenses/Node-LICENSE.txt','licenses/GPL-3.0.txt','licenses/THIRD-PARTY-NOTICES.md'
    foreach($relative in $expected){if(-not (Test-Path -LiteralPath (Join-Path $extracted $relative) -PathType Leaf)){throw "Expected $relative."}}
    Assert-SetupPackage (-not (Test-Path -LiteralPath (Join-Path $extracted 'release/guard-setup-ui.ps1'))) 'the embedded actions, helpers, observer and notices are present and the previous UI script is absent'

    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{
        if(-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
            $denied=Invoke-SetupVerification $setup ('--approved '+$identity.User.Value)
            Assert-SetupPackage ($denied.Code -ne 0 -and $denied.Error -like '*same Windows account*') 'the native x64 check passes on this host and the internal argument cannot bypass the administrator token'
            $updateDenied=Invoke-SetupVerification $setup ('--approved '+$identity.User.Value+' --update')
            Assert-SetupPackage ($updateDenied.Code -ne 0 -and $updateDenied.Error -like '*same Windows account*') 'the elevated update argument requires the same approved administrator token'
        }
    }finally{$identity.Dispose()}
    $backgroundDenied=Invoke-SetupVerification $setup '--background-notifier'
    Assert-SetupPackage ($backgroundDenied.Code -ne 0 -and $backgroundDenied.Error -like '*protected Guard background launcher*') 'the background command only runs from the verified ProgramData stage'

    $latin=[Text.Encoding]::GetEncoding(28591)
    $payloadManifest=$latin.GetString([Text.Encoding]::UTF8.GetBytes($manifest))
    $raw=$latin.GetString($image)
    $position=$raw.IndexOf($payloadManifest,[StringComparison]::Ordinal)
    if($position -lt 0 -or $raw.LastIndexOf($payloadManifest,[StringComparison]::Ordinal) -ne $position){
        throw 'The test could not identify the unique embedded manifest.'
    }
    $original=$image[$position]
    $image[$position]=if($original -eq 48){49}else{48}
    $mutated=Join-Path $scratch 'TamperedSetup.exe'
    [IO.File]::WriteAllBytes($mutated,$image)
    $damaged=Invoke-SetupVerification $mutated '--verify'
    Assert-SetupPackage ($damaged.Code -ne 0 -and $damaged.Error -like '*failed its SHA-256*') 'verification rejects a modified embedded digest'

    $image[$position]=$original
    $image[$pe+8]=1
    [IO.File]::WriteAllBytes($mutated,$image)
    $changedImage=Invoke-SetupVerification $mutated '--verify'
    Assert-SetupPackage ($changedImage.Code -ne 0 -and $changedImage.Error -like '*verified image header*') 'verification rejects changed image bytes even when the payload and manifest still agree'

    if($ReferenceSetupPath){
        $reference=(Get-Item -LiteralPath $ReferenceSetupPath -ErrorAction Stop).FullName
        Assert-SetupPackage ((Get-FileHash -LiteralPath $reference).Hash -ceq (Get-FileHash -LiteralPath $setup).Hash) 'independent builds produce byte-identical installer executables'
        $sourceName='ClaudeGuardSetup-1.0.4-sources.zip'
        $sources=Join-Path (Split-Path -Parent $setup) $sourceName
        $referenceSources=Join-Path (Split-Path -Parent $reference) $sourceName
        Assert-SetupPackage ((Get-FileHash -LiteralPath $sources).Hash -ceq (Get-FileHash -LiteralPath $referenceSources).Hash) 'independent builds produce byte-identical source archives'
    }
}finally{
    foreach($path in $scratch,$extracted){
        if(-not (Test-Path -LiteralPath $path)){continue}
        $storage=Get-Item -LiteralPath $path -Force
        $safe=$storage.FullName
        if(($storage.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Split-Path -Parent $safe) -ine $temp -or
            (Split-Path -Leaf $safe) -cnotmatch '\Aguard-setup-(?:test|verification)-[a-f0-9]{32}\z'){
            throw 'The test storage has an unexpected location.'
        }
        Remove-Item -LiteralPath $safe -Recurse -Force
    }
}
