#Requires -Version 5.1
param([Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$DeployedPackageDirectory,
    [string[]]$AdditionalRulePrefix=@())
$ErrorActionPreference='Stop'
$deployed=(Resolve-Path -LiteralPath $DeployedPackageDirectory -ErrorAction Stop).ProviderPath
$runtime=Join-Path $env:ProgramData 'ClaudeVPNGuard\auto-refresh'
$stateDir=Split-Path $runtime -Parent
$taskName='ClaudeVPNGuard Auto Refresh'
$state=Get-Content -Raw -LiteralPath "$stateDir\firewall-state.json" | ConvertFrom-Json
$checked=Get-Content -Raw -LiteralPath "$stateDir\auto-refresh-status.json" | ConvertFrom-Json
$isolation=Get-Content -Raw -LiteralPath "$stateDir\privacy-isolation.json" | ConvertFrom-Json
$prefixes=@('ClaudeDesktopPrivacyIsolation-Managed-')+@($AdditionalRulePrefix | Where-Object {
    $_ -cmatch '\AClaudeDesktopPrivacyIsolation-[a-f0-9]{32}-\z'
})
if($prefixes.Count -ne $AdditionalRulePrefix.Count+1){
    throw 'Additional rule prefixes must identify a specific Guard isolation deployment.'
}
$files=@(
    foreach($dir in @($deployed,$runtime)){
        foreach($name in @('config.json','check-protection.ps1','guard-network.ps1','guard-runtime.ps1','guard-common.ps1','guard-autorefresh.ps1','guard-isolation.ps1','setup-firewall.ps1')){
            $path=Join-Path $dir $name
            if(Test-Path -LiteralPath $path -PathType Leaf){
                $item=Get-Item -LiteralPath $path
                [pscustomobject]@{Path=$path;Sha256=(Get-FileHash -LiteralPath $path).Hash;Acl=(Get-Acl -LiteralPath $path).Sddl;IsLink=([bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint))}
            }
        }
    }
)
$native={ param($value) $value | Select-Object -Property * -ExcludeProperty PSComputerName,RunspaceId,CimClass,CimInstanceProperties,CimSystemProperties | ConvertTo-Json -Depth 5 -Compress }
$policy=@(
    foreach($store in @('PersistentStore','ActiveStore')){
        try{
            $all=@(Get-NetFirewallRule -PolicyStore $store -ErrorAction Stop)
            $targets=@($all | Where-Object { 
                $id=$_.Name
                $id -cin $state.Rules -or @($prefixes | Where-Object {$id.StartsWith($_,[StringComparison]::Ordinal)}).Count
            })
            foreach($rule in $targets){
                [pscustomobject]@{
                    Store=$store;Name=$rule.Name;Rule=(&$native $rule)
                    Application=(&$native ($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop))
                    Address=(&$native ($rule | Get-NetFirewallAddressFilter -ErrorAction Stop))
                    Interface=(&$native ($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop))
                    Port=(&$native ($rule | Get-NetFirewallPortFilter -ErrorAction Stop))
                    InterfaceType=(&$native ($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop))
                    Service=(&$native ($rule | Get-NetFirewallServiceFilter -ErrorAction Stop))
                    Security=(&$native ($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop))
                }
            }
        }catch{
            [pscustomobject]@{Store=$store;Error=$_.FullyQualifiedErrorId}
        }
    }
)
$pkg=Get-AppxPackage -Name 'AnthropicPBC.Claude' | Select-Object Name,Version,PackageFamilyName,InstallLocation
$service=Get-CimInstance Win32_Service -Filter "Name='CoworkVMServiceStore'" | Select-Object Name,State,StartMode,ProcessId
$snapshot=[ordered]@{
    Utc=[datetime]::UtcNow.ToString('o')
    GuardFiles=$files
    Isolation=$isolation.Mode
    ReportedPolicy=$checked.Policy
    Package=$pkg
    Cowork=$service
    ProcessCount=@(Get-Process -Name 'Claude','cowork-svc' -ErrorAction SilentlyContinue).Count
    TaskXml=(Export-ScheduledTask -TaskName $taskName)
    FirewallState=$state
    Policy=$policy
}
$snapshot | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
[pscustomobject]@{
    RelatedFilters=@($policy | Where-Object Name).Count;IncompleteRecords=@($policy | Where-Object Error).Count
    ClaimedPolicy=$snapshot.ReportedPolicy;Isolation=$snapshot.Isolation;ProcessCount=$snapshot.ProcessCount;SourceFiles=$files.Count
} | ConvertTo-Json -Compress

