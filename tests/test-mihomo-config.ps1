#Requires -Version 5.1
param([Parameter(Mandatory)][string]$MihomoArchive)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. "$root\package\guard-daily.ps1"
$archive=(Get-Item -LiteralPath $MihomoArchive -ErrorAction Stop).FullName
$published='8B81FE2C5CD04CA6DEB61EEC6075150B44CC5AD13AB867750642E2422F7C1278'
if((Get-FileHash -LiteralPath $archive).Hash -cne $published){throw 'Mihomo release archive digest mismatch.'}
$work=Join-Path ([IO.Path]::GetTempPath()) ('guard-syntax-'+[guid]::NewGuid().ToString('N'))
$unpacked=Join-Path $work 'binary'
New-Item -ItemType Directory -Path $work | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $unpacked
$demo=@{
    type='vless';network='tcp';server='203.0.113.17';port=443
    uuid='d95bdb2e-9d99-4ee3-a1aa-841b1c976e89';tls=$true
    servername='synthetic.invalid';flow='xtls-rprx-vision';'client-fingerprint'='chrome'
    'reality-opts'=@{'public-key'='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';'short-id'='1234abcd'}
}
$dataPath=Join-Path $work 'synthetic-config.json'
$json=New-GuardDedicatedProxyConfig $demo 18793 | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($dataPath,$json,(New-Object Text.UTF8Encoding($false)))
$executable=Join-Path $unpacked 'mihomo-windows-amd64-v1.exe'
$lines=@(& $executable -t -d $work -f $dataPath 2>&1)
$result=$LASTEXITCODE
$lines | Out-String | Write-Host
if($result -ne 0){exit $result}
[pscustomobject]@{Mihomo='v1.19.30';ConfigParseSucceeded=$true;Input='synthetic';ReleaseArchiveSha256=$published;ExecutableSha256=(Get-FileHash -LiteralPath $executable).Hash} | ConvertTo-Json -Compress

