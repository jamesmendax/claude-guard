#Requires -Version 5.1
$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot '..\package\guard-wfp.cs')

$native=[ClaudeGuard.Network.WindowsPolicySession].Assembly.GetType('ClaudeGuard.Network.NativeSession',$true)
$filter=$native.GetNestedType('NativeFilter',[Reflection.BindingFlags]'NonPublic')
$privateStatic=[Reflection.BindingFlags]'NonPublic,Static'
$verifyPage=$native.GetMethod('VerifyScopePage',$privateStatic)
$offset=$native.GetField('FilterSublayerOffset',$privateStatic).GetValue($null)
$marshal=[Runtime.InteropServices.Marshal]
$readStructure=$marshal.GetMethod('PtrToStructure',[type[]]@([IntPtr],[type]))
$size=$marshal::SizeOf([Activator]::CreateInstance($filter))
$inScope=[guid]::NewGuid()
$outOfScope=[guid]::NewGuid()
$otherLayer=[guid]::NewGuid()
$runtimeKey=[guid]::NewGuid()
$bootKey=[guid]::NewGuid()
$unexpectedKey=[guid]::NewGuid()
$page=$marshal::AllocHGlobal(3*[IntPtr]::Size)
$rows=[Collections.Generic.List[IntPtr]]::new()

function Assert-ScopeReadback([bool]$Condition,[string]$Message){
    if(-not $Condition){throw "FAIL: $Message"}
    "PASS: $Message"
}

function Add-ScopeRow([int]$Index,[guid]$Key,[guid]$Layer,[guid]$Sublayer,[uint32]$Flags){
    $row=$marshal::AllocHGlobal($size)
    $rows.Add($row)
    $value=[Activator]::CreateInstance($filter)
    $filter.GetField('Key').SetValue($value,$Key)
    $filter.GetField('Layer').SetValue($value,$Layer)
    $filter.GetField('Sublayer').SetValue($value,$Sublayer)
    $filter.GetField('Flags').SetValue($value,$Flags)
    $marshal::StructureToPtr([object]$value,$row,$false)
    $marshal::WriteIntPtr($page,$Index*[IntPtr]::Size,$row)
}

function Test-ScopeRejection([uint32]$Count,$Expected,$Boot,[string]$Message){
    $rejected=$false
    try{$verifyPage.Invoke($null,[object[]]@($page,$Count,$inScope,$Expected,$Boot))}
    catch{
        if($_.Exception.GetBaseException().Message -ne 'An unexpected filter remains in the Guard sublayer.'){throw}
        $rejected=$true
    }
    Assert-ScopeReadback $rejected $Message
}

try{
    $expected=[Collections.Generic.HashSet[guid]]::new()
    $boot=[Collections.Generic.HashSet[guid]]::new()
    $null=$expected.Add($runtimeKey)
    $null=$boot.Add($bootKey)
    Add-ScopeRow 0 $runtimeKey $inScope $outOfScope 0
    Add-ScopeRow 1 $runtimeKey $otherLayer $inScope 0
    Add-ScopeRow 2 $bootKey $otherLayer $inScope 2

    $correctGuid=$true
    foreach($row in $rows){
        $full=$readStructure.Invoke($null,[object[]]@($row,$filter))
        $raw=$readStructure.Invoke($null,[object[]]@([IntPtr]::Add($row,$offset),[guid]))
        $correctGuid=$correctGuid -and $raw -eq $filter.GetField('Sublayer').GetValue($full)
    }
    Assert-ScopeReadback $correctGuid 'offset reads the same sublayer GUID as full native marshaling'
    $verifyPage.Invoke($null,[object[]]@($page,[uint32]3,$inScope,$expected,$boot))
    Assert-ScopeReadback ($expected.Count -eq 0 -and $boot.Count -eq 0) 'page verifies exact runtime and boot filters and ignores other sublayers'

    Add-ScopeRow 0 $runtimeKey $otherLayer $inScope 0
    Test-ScopeRejection 1 $expected $boot 'a duplicate runtime filter on a later page is rejected'
    Add-ScopeRow 0 $unexpectedKey $otherLayer $inScope 0
    Test-ScopeRejection 1 $expected $boot 'an unexpected filter in the guarded sublayer on another layer is rejected'
    $null=$boot.Add($bootKey)
    Add-ScopeRow 0 $bootKey $otherLayer $inScope 0
    Test-ScopeRejection 1 $expected $boot 'a boot key without the boot flag is rejected'
}finally{
    foreach($row in $rows){$marshal::FreeHGlobal($row)}
    $marshal::FreeHGlobal($page)
}
