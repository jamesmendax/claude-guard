# A manually selected node is private to the Windows account running Guard.
function Get-GuardNodeStorePath {
    Join-Path (Get-GuardDataPath 'node-private') 'selected-node.json'
}

function Test-GuardNodeStoreItem([string]$Path,[switch]$Directory) {
    try{$attributes=[IO.File]::GetAttributes($Path)}
    catch [IO.FileNotFoundException]{return $false}
    catch [IO.DirectoryNotFoundException]{return $false}
    if(($attributes -band [IO.FileAttributes]::ReparsePoint) -or
        [bool]($attributes -band [IO.FileAttributes]::Directory) -ne $Directory.IsPresent){
        throw 'The private node store has an unexpected path type.'
    }
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $trusted=@('S-1-5-18','S-1-5-32-544')
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted -or
        @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $trusted
        }).Count){throw 'The private node store has unexpected access permissions.'}
    $true
}

function Initialize-GuardNodeStore {
    $dir=Split-Path -Parent (Get-GuardNodeStorePath)
    Assert-GuardSandboxieAdministratorPath (Split-Path -Parent $dir)
    if(Test-GuardNodeStoreItem $dir -Directory){return}
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach($sid in 'S-1-5-18','S-1-5-32-544'){
        $rule=[Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]$sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    $null=[IO.Directory]::CreateDirectory($dir,$acl)
    if(-not (Test-GuardNodeStoreItem $dir -Directory)){throw 'Could not prepare the private node store.'}
}

function Get-GuardNodeStoreSnapshot {
    $path=Get-GuardNodeStorePath
    if(-not (Test-GuardNodeStoreItem (Split-Path -Parent $path) -Directory) -or -not (Test-GuardNodeStoreItem $path)){
        return [pscustomobject]@{Version=1;Exists=$false;Record=$null}
    }
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
    try{
        if($stream.Length -lt 1 -or $stream.Length -gt 48KB){throw 'Invalid private node record.'}
        $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true)
        try{$record=$reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop}finally{$reader.Dispose()}
    }finally{$stream.Dispose()}
    if($record.Version -ne 1 -or $record.UserName -cne 'GuardNodeProfile' -or
        [string]$record.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
        [string]$record.ProtectedValue -cnotmatch '\A[0-9a-fA-F]{64,40000}\z'){
        throw 'The selected node is invalid or belongs to a different Windows account.'
    }
    [pscustomobject]@{Version=1;Exists=$true;Record=$record}
}

function Restore-GuardNodeStoreSnapshot($Snapshot){
    if($Snapshot.Version -ne 1 -or $Snapshot.Exists -isnot [bool]){throw 'Invalid node recovery record.'}
    $path=Get-GuardNodeStorePath
    if(-not $Snapshot.Exists){
        if((Test-GuardNodeStoreItem (Split-Path -Parent $path) -Directory) -and (Test-GuardNodeStoreItem $path)){
            [IO.File]::Delete($path)
        }
        return
    }
    $record=$Snapshot.Record
    if($record.Version -ne 1 -or $record.UserName -cne 'GuardNodeProfile' -or
        $record.OwnerSid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or
        [string]$record.ProtectedValue -cnotmatch '\A[0-9a-fA-F]{64,40000}\z'){throw 'Invalid encrypted node recovery record.'}
    Initialize-GuardNodeStore
    $temporary=Join-Path (Split-Path -Parent $path) ([guid]::NewGuid().ToString('N')+'.tmp')
    try{
        $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Depth 3 -Compress))
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        # Files made by a split-token administrator may initially be owned by their user SID.
        $fileAcl=Get-Acl -LiteralPath $temporary -ErrorAction Stop
        $fileAcl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
        Set-Acl -LiteralPath $temporary -AclObject $fileAcl -ErrorAction Stop
        if(-not (Test-GuardNodeStoreItem $temporary)){throw 'The node recovery file could not be secured.'}
        if(Test-GuardNodeStoreItem $path){[IO.File]::Replace($temporary,$path,$temporary+'.bak')}
        else{[IO.File]::Move($temporary,$path)}
    }finally{[IO.File]::Delete($temporary);[IO.File]::Delete($temporary+'.bak')}
}

function Save-GuardNodeProfile([Management.Automation.PSCredential]$Profile){
    if($null -eq $Profile -or $Profile.UserName -cne 'GuardNodeProfile'){throw 'A validated node profile is required.'}
    $record=[pscustomobject]@{Version=1;UserName=$Profile.UserName;OwnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        ProtectedValue=(ConvertFrom-SecureString -SecureString $Profile.Password -ErrorAction Stop)}
    Restore-GuardNodeStoreSnapshot ([pscustomobject]@{Version=1;Exists=$true;Record=$record})
}

function Read-GuardSavedNodeRoute([int]$Port){
    $state=Get-GuardNodeStoreSnapshot
    if(-not $state.Exists){return}
    try{$secret=ConvertTo-SecureString -String $state.Record.ProtectedValue -ErrorAction Stop}
    catch{throw 'This Windows account could not decrypt the selected node.'}
    try{
        if(-not (Get-Command Get-GuardNodeProfileRoute -CommandType Function -ErrorAction SilentlyContinue)){
            . (Join-Path $PSScriptRoot 'guard-node-profile.ps1')
        }
        Get-GuardNodeProfileRoute -Profile ([Management.Automation.PSCredential]::new($state.Record.UserName,$secret)) -Port $Port
    }finally{$secret.Dispose()}
}
