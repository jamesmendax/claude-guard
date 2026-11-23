# A territory can have more than one supported Windows language and format.
function Get-GuardNodeLocaleTarget([string]$CountryCode,[string]$LocaleName) {
    if($CountryCode -cnotmatch '\A[A-Z]{2}\z'){throw 'A verified two-letter exit country is required.'}
    $options=@(foreach($culture in [Globalization.CultureInfo]::GetCultures([Globalization.CultureTypes]::SpecificCultures)){
        if($culture.Name -notlike ('*-'+$CountryCode) -or $culture.Name -cnotmatch '\A[a-zA-Z]{2,8}(?:-[A-Za-z0-9]{2,8})+\z'){continue}
        $region=try{[Globalization.RegionInfo]::new($culture.Name)}catch{continue}
        if($region.TwoLetterISORegionName -ceq $CountryCode -and $region.GeoId -gt 0){$culture.Name}
    })
    [string[]]$choices=@($options | Sort-Object -Unique)
    if(-not $choices.Count){throw 'Windows has no supported regional format for this exit country.'}
    if($LocaleName -and $LocaleName -cnotin $choices){throw 'The selected language and format do not match the exit country.'}
    if(-not $LocaleName -and $choices.Count -eq 1){$LocaleName=$choices[0]}
    $selected=if($LocaleName){[Globalization.CultureInfo]::GetCultureInfo($LocaleName)}
    [pscustomobject]@{
        CountryCode=$CountryCode;GeoId=[Globalization.RegionInfo]::new($choices[0]).GeoId
        LocaleName=$LocaleName;LanguageTag=$(if($selected){$selected.IetfLanguageTag})
        RequiresChoice=(-not $selected);Choices=$choices
    }
}
