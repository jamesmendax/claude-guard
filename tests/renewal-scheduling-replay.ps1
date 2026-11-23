#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ControllerPath)

$ErrorActionPreference='Stop'
$controllerFile=(Get-Item -LiteralPath $ControllerPath).FullName
. (Join-Path (Split-Path -Parent $controllerFile) 'guard-daily.ps1')
. $controllerFile

# Two identical slow local checks bracket a proof that is already available on time.
# The firewall boundary is a recorder. Nothing here starts a protected application or sends traffic.
$profile=@{Generation=('A'*64);Port=18793;DesktopHashes=@('B'*64)
    ScopeName=('claude-guard-'+('1'*32));ScopeSid='S-1-15-2-21-22-23-24-25-26-27'}
$halt=[Threading.ManualResetEvent]::new($false)
$controller=New-GuardDailyController $profile
$fixture=@{Checks=0;Arms=[Collections.Generic.List[datetime]]::new();NextProof=$null;PreviousExpiry=$null}
try{
    $operations=@{
        ReadIsolation={'Off'}
        VerifyInventory={
            if($fixture.Checks -lt 2){
                if($fixture.Checks -eq 0){
                    $now=[datetime]::UtcNow
                    $fixture.PreviousExpiry=$now.AddMilliseconds(3500)
                    $fixture.NextProof=$now.AddMilliseconds(1800)
                }
                $fixture.Checks++
                [Threading.Thread]::Sleep(1500)
            }elseif($fixture.Arms.Count -lt 2){$null=$halt.Set()}
            $true
        }
        ReadPath={
            $checked=if([datetime]::UtcNow -ge $fixture.NextProof){$fixture.NextProof}
                     else{$fixture.PreviousExpiry.AddSeconds(-15)}
            [pscustomobject]@{Proxy='Ready';Exit='Match';Lease=@{Generation=$profile.Generation
                CheckedUtc=$checked.ToString('o');ExpiresUtc=$checked.AddSeconds(15).ToString('o')}}
        }
        OpenVerified={
            param($deadline,$signal)
            $fixture.Arms.Add([datetime]::UtcNow)
            if($fixture.Arms.Count -eq 2){$null=$halt.Set()}
            $true
        }
        CloseVerified={$true}
        WriteRecord={param($name,$record)}
        Snapshot={}
        RequestClose={}
        Wait={}
        ForceStop={}
    }
    Start-GuardDailyController $controller $operations $halt -PollMilliseconds 1000
    if($fixture.Arms.Count -ne 2 -or $fixture.Arms[0] -ge $fixture.NextProof -or
        $fixture.NextProof -ge $fixture.PreviousExpiry){throw 'The short scheduling fixture missed its input timing.'}
    $margin=($fixture.PreviousExpiry-$fixture.Arms[1]).TotalMilliseconds
    [pscustomobject]@{ControllerSHA256=(Get-FileHash -LiteralPath $controllerFile).Hash
        InspectionMilliseconds=1500;PollMilliseconds=1000;ProofLifetimeSeconds=15
        ProofReadyBeforeOldExpiryMs=($fixture.PreviousExpiry-$fixture.NextProof).TotalMilliseconds
        FirstAppliedUtc=$fixture.Arms[0].ToString('o');NextProofUtc=$fixture.NextProof.ToString('o')
        OldExpiryUtc=$fixture.PreviousExpiry.ToString('o');SecondAppliedUtc=$fixture.Arms[1].ToString('o')
        RemainingAtSecondApplicationMs=$margin;RenewedBeforeExpiry=($margin -gt 0)}
}finally{$controller.Signal.Dispose();$halt.Dispose()}
