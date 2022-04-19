$CurrentSection = [PSCustomObject]@{   
    Name = 'Console'
    Description = "This section contains recommendations related to ESXi consoles."
}

#region 4.1 (L1) Ensure the DCUI timeout is set to 600 seconds or less (Automated)


if('5.1' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut
        $Pass = $Value.Value -le 600
        $CurrentTest = [PSCustomObject]@{
            Test = '5.1'
            Section = $CurrentSection.Name
            Name = 'Ensure the DCUI timeout is set to 600 seconds or less (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set DCUI timeout to 600 seconds')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvangedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set DCUI timeout to 600 seconds on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion