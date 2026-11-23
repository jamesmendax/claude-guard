#Requires -Version 5.1

. "$PSScriptRoot\guard-node-profile.ps1"

function Assert-GuardBettboxDirectory([string]$Path) {
    if($Path -cnotmatch '\A[A-Za-z]:\\' -or [IO.Path]::GetFullPath($Path) -ine $Path -or
        $Path.Substring(3) -match '[<>:"/|?*]|(?:[ .]\\|[ .]$)' -or
        [IO.DriveInfo]::new($Path.Substring(0,3)).DriveType -notin 'Fixed','Ram'){
        throw 'Invalid Bettbox directory.'
    }
    for($directory=[IO.DirectoryInfo]::new($Path);$directory;$directory=$directory.Parent){
        if(-not $directory.Exists -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){
            throw 'Invalid Bettbox directory.'
        }
    }
}

function Read-GuardBettboxFile([string]$Path,[int]$Limit) {
    $file=[IO.FileInfo]::new($Path)
    Assert-GuardBettboxDirectory $file.DirectoryName
    if(-not $file.Exists -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        throw 'Invalid Bettbox file.'
    }
    $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        $file.Refresh()
        Assert-GuardBettboxDirectory $file.DirectoryName
        if(-not $file.Exists -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $stream.Length -lt 1 -or $stream.Length -gt $Limit){throw 'Invalid Bettbox file.'}
        $bytes=[byte[]]::new([int]$stream.Length)
        $read=0
        while($read -lt $bytes.Length){
            $count=$stream.Read($bytes,$read,$bytes.Length-$read)
            if(-not $count){throw 'Invalid Bettbox file.'}
            $read+=$count
        }
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        if($text.StartsWith([string][char]0xFEFF,[StringComparison]::Ordinal)){$text=$text.Substring(1)}
        $text
    }finally{$stream.Dispose()}
}

function Assert-GuardBettboxJson([string]$Text) {
    # Windows PowerShell's JSON parser silently accepts repeated identical keys.
    $tokenPattern=[regex]'\G[ \t\r\n]*(?<token>"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|[{}\[\],:]|true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[Ee][+-]?[0-9]+)?)'
    $stack=[Collections.Generic.Stack[object]]::new()
    $stack.Push(@{State='value'})
    $offset=0
    while($offset -lt $Text.Length){
        $match=$tokenPattern.Match($Text,$offset)
        if(-not $match.Success){
            if($Text.Substring($offset) -cmatch '\A[ \t\r\n]*\z'){break}
            throw 'Invalid Bettbox settings.'
        }
        $offset+=$match.Length
        $token=$match.Groups['token'].Value
        $frame=$stack.Peek()
        switch($frame.State){
            'end' {throw 'Invalid Bettbox settings.'}
            'colon' {
                if($token -cne ':'){throw 'Invalid Bettbox settings.'}
                $frame.State='value'
                continue
            }
            {$_ -in 'object-start','key'} {
                if($token -ceq '}' -and $_ -ceq 'object-start'){$null=$stack.Pop();continue}
                if($token[0] -cne '"'){throw 'Invalid Bettbox settings.'}
                $key=if($token.Contains('\')){(ConvertFrom-Json -InputObject ('{"key":'+$token+'}') -ErrorAction Stop).key}
                    else{$token.Substring(1,$token.Length-2)}
                if(-not $frame.Keys.Add($key)){throw 'Invalid Bettbox settings.'}
                $frame.State='colon'
                continue
            }
            {$_ -in 'object-end','array-end'} {
                if($token -ceq $frame.Close){$null=$stack.Pop();continue}
                if($token -cne ','){throw 'Invalid Bettbox settings.'}
                $frame.State=if($frame.Close -ceq '}'){'key'}else{'value'}
                continue
            }
            default {
                if($token -ceq ']' -and $frame.State -ceq 'array-start'){$null=$stack.Pop();continue}
                if($token -cin '}',']',',',':'){throw 'Invalid Bettbox settings.'}
                $frame.State=if($frame.Close -ceq '}'){'object-end'}elseif($frame.Close -ceq ']'){'array-end'}else{'end'}
                if($token -ceq '{'){
                    $stack.Push(@{State='object-start';Close='}';Keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)})
                }elseif($token -ceq '['){$stack.Push(@{State='array-start';Close=']'})}
                if($stack.Count -gt 32){throw 'Invalid Bettbox settings.'}
            }
        }
    }
    if($stack.Count -ne 1 -or $stack.Peek().State -cne 'end'){throw 'Invalid Bettbox settings.'}
}

function Read-GuardBettboxSettings([string]$Directory) {
    Assert-GuardBettboxDirectory $Directory
    $text=Read-GuardBettboxFile (Join-Path $Directory 'config.json') 1MB
    if($text -cnotmatch '\A[ \t\r\n]*\{'){throw 'Invalid Bettbox settings.'}
    Assert-GuardBettboxJson $text
    $settings=ConvertFrom-Json -InputObject $text -ErrorAction Stop
    if('profiles' -cnotin $settings.PSObject.Properties.Name -or $settings.profiles -isnot [array] -or
        $settings.profiles.Count -lt 1 -or $settings.profiles.Count -gt 64){throw 'Invalid Bettbox settings.'}
    $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($profile in $settings.profiles){
        if($profile -isnot [pscustomobject] -or 'id' -cnotin $profile.PSObject.Properties.Name -or
            $profile.id -isnot [string] -or $profile.id -cnotmatch '\A[A-Za-z0-9_-]{1,128}\z' -or
            $profile.id -match '\A(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])\z' -or -not $ids.Add($profile.id)){
            throw 'Invalid Bettbox settings.'
        }
    }
    $settings
}

function ConvertFrom-GuardBettboxScalar([string]$Text) {
    $Text=$Text.Trim(' ')
    if($Text -cmatch '\A''(?:[^''\x00-\x1f\x7f]|'''')*''\z'){
        return $Text.Substring(1,$Text.Length-2).Replace("''", "'")
    }
    if($Text -cmatch '\A"[^"\\\x00-\x1f\x7f]*"\z'){return $Text.Substring(1,$Text.Length-2)}
    if(-not $Text -or $Text -match '\A(?:[!&*#{}\[\],>|%@`"'']|[-?:](?: |$))|[\x00-\x1f\x7f]| #|:(?: |$)'){
        throw 'Unsupported Bettbox scalar.'
    }
    $Text
}

function Read-GuardBettboxEntries([string]$Directory,[string]$ProfileId) {
    $path=Join-Path $Directory ('profiles\'+$ProfileId+'.yaml')
    $text=Read-GuardBettboxFile $path 2MB
    if($text -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85\u2028\u2029]|\r(?!\n)'){
        throw 'Unsupported Bettbox profile format.'
    }
    $entries=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $sections=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $section=$null
    $emptySection=$false
    $entry=$null
    foreach($line in ($text -split '\r?\n')){
        if($line -cmatch '\A *(?:#.*)?\z'){continue}
        if($line -cnotmatch '\A '){
            if($line.StartsWith('- ') -and $section -and $section -cnotin 'proxies','proxy-groups'){continue}
            $top=[regex]::Match($line,'\A(?<key>[a-z][a-z0-9-]*):(?<value> .*|)\z')
            if(-not $top.Success -or -not $sections.Add($top.Groups['key'].Value)){throw 'Unsupported Bettbox profile format.'}
            $section=$top.Groups['key'].Value
            $entry=$null
            $emptySection=$false
            if($section -cin 'proxies','proxy-groups' -and $top.Groups['value'].Value.Trim()){
                if($section -ceq 'proxy-groups' -and $top.Groups['value'].Value.Trim() -ceq '[]'){$emptySection=$true;continue}
                throw 'Unsupported Bettbox profile format.'
            }
            continue
        }
        if($section -cnotin 'proxies','proxy-groups'){continue}
        if($emptySection -or $line -match '\A *\t'){throw 'Unsupported Bettbox profile format.'}
        if($line.StartsWith('  - ',[StringComparison]::Ordinal)){
            $first=[regex]::Match($line,'\A  - name: (?<name>.+)\z')
            if(-not $first.Success){throw 'Unsupported Bettbox entry.'}
            $name=ConvertFrom-GuardBettboxScalar $first.Groups['name'].Value
            if(-not $name -or $name.Length -gt 512 -or $entries.ContainsKey($name) -or $entries.Count -ge 1024){
                throw 'Ambiguous Bettbox entry.'
            }
            $entry=@{Section=$section;Lines=[Collections.Generic.List[string]]::new()}
            $entries.Add($name,$entry)
        }else{
            if(-not $entry -or $line -cnotmatch '\A {4,}\S' -or $line -cmatch '\A {4}name:'){
                throw 'Unsupported Bettbox entry.'
            }
            # Index names from one unambiguous block mapping per entry.
            if($line -cmatch '\A {4}\S' -and $line -cnotmatch '\A {4}[a-z][a-z0-9-]*:(?: |\z)' -and
                -not ($section -ceq 'proxy-groups' -and $line.StartsWith('    - ',[StringComparison]::Ordinal))){
                throw 'Unsupported Bettbox entry.'
            }
            $entry.Lines.Add($line.TrimEnd(' '))
        }
    }
    if(-not $sections.Contains('proxies') -or -not $entries.Count){throw 'Missing Bettbox nodes.'}
    return ,$entries
}

function Get-GuardBettboxGroupChild($Entry) {
    $type=@($Entry.Lines | Where-Object {$_ -cmatch '\A {4}type: '})
    $children=@($Entry.Lines | Where-Object {$_ -cmatch '\A {4}proxies:(?: |\z)'})
    if($type.Count -ne 1 -or $children.Count -ne 1 -or (ConvertFrom-GuardBettboxScalar $type[0].Substring(10)) -cne 'select'){
        throw 'Unsupported Bettbox group.'
    }
    if($Entry.Lines.Count -eq 2){
        $inline=[regex]::Match($children[0],'\A {4}proxies: +\[(?<child>.+)\]\z')
        if($inline.Success){
            $child=$inline.Groups['child'].Value.Trim(' ')
            if($child -cmatch '\A["'']' -or $child -cnotmatch '[,\[\]{}]'){return ConvertFrom-GuardBettboxScalar $child}
        }
    }elseif($Entry.Lines.Count -eq 3 -and $children[0] -ceq '    proxies:'){
        $index=$Entry.Lines.IndexOf($children[0])+1
        if($index -lt $Entry.Lines.Count){
            $block=[regex]::Match($Entry.Lines[$index],'\A(?: {4}| {6})- (?<child>.+)\z')
            if($block.Success){return ConvertFrom-GuardBettboxScalar $block.Groups['child'].Value}
        }
    }
    throw 'Unsupported Bettbox group.'
}

function ConvertTo-GuardBettboxNodeProfile($Entry) {
    $fields=@{}
    $extra=@('ip-version','skip-cert-verify')
    $nested=[Collections.Generic.List[string]]::new()
    $legacy=[Collections.Generic.List[string]]::new()
    $parent=$null
    foreach($line in $Entry.Lines){
        $field=[regex]::Match($line,'\A {4}(?<key>[a-z][a-z0-9-]*):(?<value> .*|)\z')
        if(-not $field.Success){
            if($line -cnotmatch '\A {6,}\S' -or $parent -cnotin 'reality-opts','ws-opts' -or $fields[$parent] -cne ''){
                throw 'Unsupported nested Bettbox setting.'
            }
            $nested.Add($line)
            $legacy.Add($line)
            continue
        }
        $key=$field.Groups['key'].Value
        $parent=$key
        $value=$field.Groups['value'].Value.Trim(' ')
        if($fields.ContainsKey($key)){throw 'Duplicate Bettbox node setting.'}
        $fields[$key]=$value
        if($key -cnotin $extra){$legacy.Add($line)}
    }
    if((ConvertFrom-GuardBettboxScalar $fields.type) -cne 'vless' -or $fields.tls -cne 'true' -or
        ($fields.ContainsKey('skip-cert-verify') -and $fields.'skip-cert-verify' -cne 'false') -or
        ($fields.ContainsKey('ip-version') -and (ConvertFrom-GuardBettboxScalar $fields.'ip-version') -cne 'ipv4') -or
        ($fields.ContainsKey('udp') -and $fields.udp -cnotin 'true','false') -or
        $fields.port -cnotmatch '\A[1-9][0-9]{0,4}\z'){
        throw 'Unsupported Bettbox node.'
    }
    $network=ConvertFrom-GuardBettboxScalar $fields.network
    if($network -ceq 'tcp'){
        $node=Read-GuardBettboxVlessNode ("proxies:`n  - name: guard-selected`n"+($legacy -join "`n")) 'guard-selected'
        return New-GuardNodeProfile -Fields @{
            ServerIpv4=$node.server;ServerPort=$node.port;Uuid=$node.uuid;ServerName=$node.servername
            ClientFingerprint=$node.'client-fingerprint';Flow=$node.flow
            RealityPublicKey=$node.'reality-opts'.'public-key';RealityShortId=$node.'reality-opts'.'short-id'
        }
    }
    $allowed=@('type','network','server','port','uuid','tls','servername','client-fingerprint','udp','ws-opts')+$extra
    if($network -cne 'ws' -or $fields.'skip-cert-verify' -cne 'false' -or $fields.'ws-opts' -cne '' -or
        @($fields.Keys | Where-Object {$_ -cnotin $allowed}).Count -or $nested.Count -ne 3){throw 'Unsupported Bettbox node.'}
    $wsBlock=[regex]::Match(($Entry.Lines -join "`n"),'(?m)^ {4}ws-opts:\n(?<options>(?: {6,}[^\n]+(?:\n|\z)){3})(?= {4}\S|\z)')
    if(-not $wsBlock.Success){throw 'Unsupported Bettbox WebSocket settings.'}
    $options=$wsBlock.Groups['options'].Value.TrimEnd("`n")
    $ws=[regex]::Match($options,'\A(?: {6}path: (?<path>[^\n]+)\n {6}headers:\n {8}Host: (?<host>[^\n]+)| {6}headers:\n {8}Host: (?<host>[^\n]+)\n {6}path: (?<path>[^\n]+))\z')
    if(-not $ws.Success){throw 'Unsupported Bettbox WebSocket settings.'}
    $nodeFields=@{
        Transport='WebSocketTls';ServerIpv4=(ConvertFrom-GuardBettboxScalar $fields.server);ServerPort=$fields.port
        Uuid=(ConvertFrom-GuardBettboxScalar $fields.uuid);ServerName=(ConvertFrom-GuardBettboxScalar $fields.servername)
        WebSocketHost=(ConvertFrom-GuardBettboxScalar $ws.Groups['host'].Value)
        WebSocketPath=(ConvertFrom-GuardBettboxScalar $ws.Groups['path'].Value)
    }
    if($fields.ContainsKey('client-fingerprint')){$nodeFields.ClientFingerprint=ConvertFrom-GuardBettboxScalar $fields.'client-fingerprint'}
    New-GuardNodeProfile -Fields $nodeFields
}

function Get-GuardCurrentBettboxProfile([string]$BettboxDirectory) {
    try{
        if(-not $PSBoundParameters.ContainsKey('BettboxDirectory')){$BettboxDirectory=Join-Path $env:APPDATA 'com.appshub\Bettbox'}
        $settings=Read-GuardBettboxSettings $BettboxDirectory
        if('currentProfileId' -cnotin $settings.PSObject.Properties.Name -or $settings.currentProfileId -isnot [string] -or
            'patchClashConfig' -cnotin $settings.PSObject.Properties.Name -or $settings.patchClashConfig -isnot [pscustomobject] -or
            'mode' -cnotin $settings.patchClashConfig.PSObject.Properties.Name -or
            $settings.patchClashConfig.mode -isnot [string] -or $settings.patchClashConfig.mode -cne 'global'){
            throw 'Unsupported Bettbox selection.'
        }
        $profile=@($settings.profiles | Where-Object id -CEQ $settings.currentProfileId)
        if($profile.Count -ne 1 -or 'selectedMap' -cnotin $profile[0].PSObject.Properties.Name -or
            $profile[0].selectedMap -isnot [pscustomobject] -or 'GLOBAL' -cnotin $profile[0].selectedMap.PSObject.Properties.Name -or
            $profile[0].selectedMap.GLOBAL -isnot [string] -or -not $profile[0].selectedMap.GLOBAL){
            throw 'Missing Bettbox selection.'
        }
        # Resolve saved data only. Script overrides are never evaluated by the reader.
        $entries=Read-GuardBettboxEntries $BettboxDirectory $profile[0].id
        $name=$profile[0].selectedMap.GLOBAL
        $reserved=@('GLOBAL','DIRECT','REJECT','REJECT-DROP','PASS','COMPATIBLE')
        if($name -cin $reserved){throw 'Unsupported Bettbox selection.'}
        if($entries.ContainsKey($name) -and $entries[$name].Section -ceq 'proxy-groups'){
            $child=Get-GuardBettboxGroupChild $entries[$name]
            if($name -cin $profile[0].selectedMap.PSObject.Properties.Name){
                $explicit=$profile[0].selectedMap.PSObject.Properties[$name].Value
                if($explicit -isnot [string] -or $explicit -cne $child){throw 'Conflicting Bettbox selection.'}
            }
            $name=$child
        }
        if($name -cin $reserved -or -not $entries.ContainsKey($name) -or
            $entries[$name].Section -cne 'proxies'){throw 'Unsupported Bettbox selection.'}
        ConvertTo-GuardBettboxNodeProfile $entries[$name]
    }catch{throw 'The current Bettbox selection could not be verified.'}
}

function Find-GuardPriorBettboxRoute([string]$ExpectedHash,[int]$Port,[string]$BettboxDirectory) {
    try{
        if($ExpectedHash -cnotmatch '\A[A-F0-9]{64}\z' -or $Port -lt 1024 -or $Port -gt 49151){throw 'Invalid route pin.'}
        if(-not $PSBoundParameters.ContainsKey('BettboxDirectory')){$BettboxDirectory=Join-Path $env:APPDATA 'com.appshub\Bettbox'}
        $settings=Read-GuardBettboxSettings $BettboxDirectory
        $match=$null
        foreach($saved in $settings.profiles){
            try{$entries=Read-GuardBettboxEntries $BettboxDirectory $saved.id}catch{continue}
            foreach($entry in $entries.GetEnumerator()){
                if($entry.Value.Section -cne 'proxies' -or $entry.Key -cin 'GLOBAL','DIRECT','REJECT','REJECT-DROP','PASS','COMPATIBLE'){continue}
                try{$route=Get-GuardNodeProfileRoute (ConvertTo-GuardBettboxNodeProfile $entry.Value) $Port}catch{continue}
                if($route.Hash -cne $ExpectedHash){continue}
                if($match -and ($match.Json -cne $route.Json -or $match.ProfileFingerprint -cne $route.ProfileFingerprint)){
                    throw 'Ambiguous route pin.'
                }
                $match=$route
            }
        }
        if(-not $match){throw 'Missing route pin.'}
        $match
    }catch{throw 'The prior Bettbox route could not be verified.'}
}
