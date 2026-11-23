#Requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\package\guard-common.ps1"
$target=Join-Path ([IO.Path]::GetTempPath()) ('guard-state-'+[guid]::NewGuid().ToString('N')+'.json')
$temporary="$target.next"

& {
    $folder=Join-Path ([IO.Path]::GetTempPath()) ('guard-directory-acl-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($folder)
    try{
        $applied=@{}
        function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction) $applied.Path=$LiteralPath;$applied.Acl=$AclObject}
        Initialize-GuardAdministratorDirectory $folder
        $sections=[Security.AccessControl.AccessControlSections]'Owner,Access'
        $expected=[Security.AccessControl.DirectorySecurity]::new()
        $expected.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
        $expected.SetAccessRuleProtection($true,$false)
        foreach($entry in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))){
            $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$entry[0],
                [Security.AccessControl.FileSystemRights]$entry[1],[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
            $expected.AddAccessRule($rule)
        }
        if($applied.Path -ine $folder -or
            $applied.Acl.GetSecurityDescriptorSddlForm($sections) -cne $expected.GetSecurityDescriptorSddlForm($sections)){
            throw 'A differently owned directory did not receive the original exact owner and protected ACL.'
        }
        'PASS A directory with different permissions receives the exact original administrator owner and three access rules'
    }finally{[IO.Directory]::Delete($folder)}
}

try{
    [IO.File]::WriteAllText($temporary,'{"Sequence":1}')
    Publish-GuardStateFile $temporary $target
    if((Read-GuardDailyJsonFile $target).Sequence -ne 1){throw 'Initial receipt publication failed.'}
    'PASS First publication can be read without administrator rights on the isolated test file'

    $reader=[IO.StreamReader]::new([IO.File]::Open($target,'Open','Read',[IO.FileShare]'Read,Delete'))
    try{
        [IO.File]::WriteAllText($temporary,'{"Sequence":2}')
        Publish-GuardStateFile $temporary $target
        if(($reader.ReadToEnd() | ConvertFrom-Json).Sequence -ne 1 -or (Read-GuardDailyJsonFile $target).Sequence -ne 2){
            throw 'A reader observed incomplete or mixed records.'
        }
        'PASS A reader can finish its prior record while a new reader sees the complete replacement'
    }finally{$reader.Dispose()}

    $ready=[Threading.ManualResetEvent]::new($false)
    $shortReader=[powershell]::Create()
    try{
        $null=$shortReader.AddScript({
            param($Path,$Ready)
            $held=[IO.File]::OpenRead($Path)
            try{$null=$Ready.Set();[Threading.Thread]::Sleep(75)}finally{$held.Dispose()}
        }).AddArgument($target).AddArgument($ready)
        $finished=$shortReader.BeginInvoke()
        if(-not $ready.WaitOne(5000)){throw 'The test reader did not open its file.'}
        [IO.File]::WriteAllText($temporary,'{"Sequence":3}')
        Publish-GuardStateFile $temporary $target
        $null=$shortReader.EndInvoke($finished)
        if((Read-GuardDailyJsonFile $target).Sequence -ne 3){throw 'A brief read prevented publication.'}
        'PASS A brief legacy reader lock is retried without losing the new receipt'
    }finally{$shortReader.Dispose();$ready.Dispose()}

    $held=[IO.File]::OpenRead($target)
    try{
        [IO.File]::WriteAllText($temporary,'{"Sequence":4}')
        $denied=$false
        try{Publish-GuardStateFile $temporary $target}catch{$denied=$true}
        if(-not $denied -or (Read-GuardDailyJsonFile $target).Sequence -ne 3 -or -not [IO.File]::Exists($temporary)){
            throw 'Persistent sharing failure did not preserve the last published receipt.'
        }
    }finally{$held.Dispose()}
    Publish-GuardStateFile $temporary $target
    if((Read-GuardDailyJsonFile $target).Sequence -ne 4){throw 'Retry after the external lock cleared failed.'}
    'PASS A persistent lock preserves the old receipt and recovery can publish a new one'

    $ready=[Threading.ManualResetEvent]::new($false)
    $writer=[powershell]::Create()
    try{
        $null=$writer.AddScript({
            param($Path,$Ready)
            $held=[IO.File]::Open($Path,'Open','ReadWrite','None')
            try{$null=$Ready.Set();[Threading.Thread]::Sleep(100)}finally{$held.Dispose()}
        }).AddArgument($target).AddArgument($ready)
        $finished=$writer.BeginInvoke()
        if(-not $ready.WaitOne(5000)){throw 'The isolated writer did not obtain its file lock.'}
        if((Read-GuardDailyJsonFile $target).Sequence -ne 4){throw 'A transient write lock lost the complete health record.'}
        $null=$writer.EndInvoke($finished)
        'PASS A health read survives a brief sharing violation during publication'
    }finally{$writer.Dispose();$ready.Dispose()}

    $exclusive=[IO.File]::Open($target,'Open','ReadWrite','None')
    try{
        $denied=$false
        $clock=[Diagnostics.Stopwatch]::StartNew()
        try{$null=Read-GuardDailyJsonFile $target}catch{$denied=$true}
        if(-not $denied -or $clock.Elapsed.TotalSeconds -gt 2){throw 'An unreadable health record did not fail closed promptly.'}
    }finally{$exclusive.Dispose()}
    'PASS A continuing write lock yields no usable health record and cannot consume a proof lifetime'

    [IO.File]::WriteAllText($temporary,'{"Sequence":0,"Copy":0}')
    Publish-GuardStateFile $temporary $target
    $publisher=[powershell]::Create()
    try{
        $null=$publisher.AddScript({
            param($Package,$Path,$Next)
            $ErrorActionPreference='Stop'
            . $Package
            foreach($number in 1..250){
                [IO.File]::WriteAllText($Next,('{"Sequence":'+$number+',"Copy":'+$number+'}'))
                Publish-GuardStateFile $Next $Path
                [Threading.Thread]::Sleep(2)
            }
        }).AddArgument((Join-Path $PSScriptRoot '..\package\guard-common.ps1')).AddArgument($target).AddArgument($temporary)
        $finished=$publisher.BeginInvoke()
        $previous=0
        $sawIntermediate=$false
        do {
            $sample=Read-GuardDailyJsonFile $target
            if($sample.Sequence -ne $sample.Copy -or $sample.Sequence -lt $previous){throw 'A health snapshot was mixed or went backwards.'}
            $previous=$sample.Sequence
            if($previous -gt 0 -and $previous -lt 250){$sawIntermediate=$true}
        }while(-not $finished.IsCompleted)
        $null=$publisher.EndInvoke($finished)
        if(-not $sawIntermediate -or (Read-GuardDailyJsonFile $target).Sequence -ne 250){throw 'The concurrent read/write trial did not complete.'}
        'PASS Continuous health reads see complete, ordered snapshots during 250 atomic replacements'
    }finally{$publisher.Dispose()}

    [IO.File]::WriteAllText($temporary,'{"Utc":"2026-11-22T03:00:00.1112223Z"}')
    Publish-GuardStateFile $temporary $target
    $stamp=(Read-GuardDailyJsonFile $target).Utc
    if($stamp -isnot [string] -or $stamp -cne '2026-11-22T03:00:00.1112223Z'){throw 'The reader changed a signed-off timestamp.'}
    'PASS The UTC receipt text keeps its original precision for health and stop-history checks'

    [IO.File]::WriteAllText($temporary,'x'*32769)
    Publish-GuardStateFile $temporary $target
    $denied=$false
    try{Read-GuardDailyJsonFile $target | Out-Null}catch{$denied=$true}
    if(-not $denied){throw 'An oversized state file was accepted.'}
    'PASS Size limits apply to the file handle actually opened by the reader'
}finally{[IO.File]::Delete($target);[IO.File]::Delete($temporary)}
