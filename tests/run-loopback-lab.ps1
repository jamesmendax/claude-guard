#Requires -Version 5.1
param([switch]$Kernel,[switch]$Monitor,[switch]$PersistentBaseline,[ValidateRange(1,120)][int]$DurationSeconds=60,
    [ValidateRange(0,600)][int]$ActiveSeconds=0,[string]$OutputDirectory=[IO.Path]::GetTempPath())
$ErrorActionPreference='Stop'
if($PersistentBaseline -and (-not $Kernel -or -not $Monitor)){
    throw 'The persistent test baseline requires the kernel monitor test.'
}
if($ActiveSeconds -and -not $Monitor){throw 'The active session check requires the controller monitor.'}
if ($Kernel) {
    $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The synthetic Windows Filtering Platform lab requires a native administrator token.'
    }
}
$root=Split-Path -Parent $PSScriptRoot
$directory=Join-Path $OutputDirectory ('loopback-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($directory)
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$client=Join-Path $directory 'guard-lab-client.exe'
& $compiler /nologo /warnaserror+ /platform:x64 "/out:$client" (Join-Path $PSScriptRoot 'loopback-probe.cs')
if ($LASTEXITCODE) { throw 'Loopback probe compilation failed.' }
foreach($file in 'guard-lab-relay.exe','guard-lab-alias.exe','guard-lab-control.exe') {
    Copy-Item -LiteralPath $client -Destination (Join-Path $directory $file)
}
if($Monitor){Copy-Item -LiteralPath $client -Destination (Join-Path $directory 'guard-lab-health.exe')}
Add-Type -Path (Join-Path $root 'package\guard-wfp.cs'),(Join-Path $PSScriptRoot 'loopback-lab.cs')
$key=[Security.Cryptography.RSA]::Create(2048)
$cert=$null
$pfx=$null
try {
    $request=New-Object Security.Cryptography.X509Certificates.CertificateRequest(
        'CN=guard-lab.invalid',$key,[Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $now=[datetimeoffset]::UtcNow
    $temporary=$request.CreateSelfSigned($now.AddMinutes(-1),$now.AddMinutes(10))
    $password=[guid]::NewGuid().ToString('N')
    try { $pfx=$temporary.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,$password) }
    finally { $temporary.Dispose() }
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $pfx,$password,[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
    if($Monitor){
        & "$PSScriptRoot\daily-controller-lab.ps1" -Directory $directory -Certificate $cert -Kernel:$Kernel `
            -PersistentBaseline:$PersistentBaseline -ActiveSeconds $ActiveSeconds
    }
    else{[GuardLoopbackLab]::Run($directory,$cert,[bool]$Kernel,$DurationSeconds)}
} finally {
    if($cert){$cert.Dispose()}
    if($pfx){[Array]::Clear($pfx,0,$pfx.Length)}
    $key.Dispose()
}

