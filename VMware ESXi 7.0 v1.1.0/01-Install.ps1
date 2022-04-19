$CurrentSection = [PSCustomObject]@{   
    Name = 'Install'
    Description = 'This section contains recommendations related to ESXi communication.'
}

#region 1.1 (L1) Ensure ESXi is properly patched (Manual)
if('1.1' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $CurrentTest = [PSCustomObject]@{
            Test = '1.1'
            Section = $CurrentSection.Name
            Name = 'Ensure ESXi is properly patched (Manual)'
            Level = 1
            Item = $VMHost
            Value = ('{0} Build {1}' -f $VMHosts[$VMHost].VMHost.Version, $VMHosts[$VMHost].VMHost.Build)
            Pass = $null
            Remediated = $false
        }

        $CurrentTest

    }
}


#endregion

#region 1.2 (L1) Ensure the Image Profile VIB acceptance level is configured properly (Automated)

if('1.2' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].EsxCli.software.acceptance.get.Invoke()
        $Pass = $Value -in ('VMwareCertified','VMwareAccepted','PartnerSupported')
        $CurrentTest = [PSCustomObject]@{
            Test = '1.2'
            Section = $CurrentSection.Name
            Name = 'Ensure the Image Profile VIB acceptance level is configured properly (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set VIB acceptance level to PartnerSupported')) {
            try {
                $VMHosts[$VMHost].EsxCli.software.acceptance.set.Invoke(@{level='PartnerSupported'})
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to Set VIB acceptance level to PartnerSupported on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}

#endregion

#region 1.3 (L1) Ensure no unauthorized kernel modules are loaded on the host (Manual)

if('1.3' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].EsxCli.system.module.list.Invoke() | ForEach-Object -Process {
            try {
                if($null -ne $_.Name -and $_.Name -ne '') {
                    $VMHosts[$VMHost].EsxCli.system.module.get.Invoke(@{module=$_.Name}) | ForEach-Object -Process {
                        ('{0} (Signed: {1}, VIB: {2})' -f $_.Module, $_.SignedStatus, $_.ContainingVIB)
                    }
                }
            } catch {
                Write-Warning -Message ('Unable to get details for module [{0}] on host {1}' -f $_.Name, $VMHost)
            }
        }
        $Pass = $null
        $CurrentTest = [PSCustomObject]@{
            Test = '1.3'
            Section = $CurrentSection.Name
            Name = 'Ensure no unauthorized kernel modules are loaded on the host (Manual)'
            Level = 1
            Item = $VMHost
            Value = $Value | Join-String -Separator ', '
            Pass = $null
            Remediated = $false
        }

        $CurrentTest

    }
}
#endregion

#region 1.4 (L2) Ensure the default value of individual salt per vm is configured (Automated)

if($Level -eq 'L2' -and '1.4' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = ($VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name 'Mem.ShareForceSalting').Value
        $Pass = $Value -eq 2
        $CurrentTest = [PSCustomObject]@{
            Test = '1.4'
            Section = $CurrentSection.Name
            Name = 'Ensure the default value of individual salt per vm is configured (Automated)'
            Level = 2
            Item = $VMHost
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set VIB acceptance level to PartnerSupported')) {
            $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name 'Mem.ShareForceSalting' | Set-AdvancedSetting -Value 2
        }
        $CurrentTest

    }
}
#endregion