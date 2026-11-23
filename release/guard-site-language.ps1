# Only the explicit user action opens a tab. Repeated checks use the receipt.
function Get-GuardBrowserSiteLanguageInputs($Plan) {
    if($null -eq $Plan -or $Plan.Browser -cne 'Edge'){throw 'A verified Edge profile is required for the website language check.'}
    $current=Get-GuardBrowserLanguageState -Profile $Plan.Profile
    if(-not $current.Available -or $current.Executable -ine $Plan.Executable -or $current.Profile -cne $Plan.Profile -or
        $current.AcceptLanguages -cne $Plan.After.AcceptLanguages -or $current.SelectedLanguages -cne $Plan.After.SelectedLanguages){
        throw 'The selected Edge profile has not saved the requested first language.'
    }
    $current
}

function Test-GuardBrowserSiteLanguageQuiet($Plan) {
    $current=Get-GuardBrowserSiteLanguageInputs $Plan
    $header=[ClaudeGuard.SiteLanguage]::Recent($current.Executable,$current.Profile,[string]$Plan.PrimaryLanguage,$current.AcceptLanguages)
    if(-not $header){throw 'A recent website-language check from this Edge profile is required.'}
    $header
}

function Test-GuardBrowserSiteLanguage($Plan) {
    Test-GuardBrowserSiteLanguageQuiet $Plan
}

function Confirm-GuardBrowserSiteLanguage($Plan) {
    $current=Get-GuardBrowserSiteLanguageInputs $Plan
    $header=[ClaudeGuard.SiteLanguage]::Confirm($current.Executable,$current.Profile,[string]$Plan.PrimaryLanguage,$current.AcceptLanguages)
    $null=Get-GuardBrowserSiteLanguageInputs $Plan
    $header
}
