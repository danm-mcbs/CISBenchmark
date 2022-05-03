$CurrentSection = [PSCustomObject]@{   
    Name = 'Communication'
    Description = 'This section contains recommendations related to ESXi communication.'
}

#region 2.1 (L1) Ensure NTP time synchronization is configured properly (Automated)
if('2.1' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-VMHostNtpServer
        $Pass = $null -ne $Value
        $CurrentTest = [PSCustomObject]@{
            Test = '2.1'
            Section = $CurrentSection.Name
            Name = 'Ensure NTP time synchronization is configured properly (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value | Join-String -Separator ', '
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set NTP Servers')) {
            try {
                $VMHosts[$VMHost].VMHost | Add-VMHostNtpServer -NtpServer 'pool.ntp.org','pool2.ntp.org'
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set NTP Servers on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}


#endregion

#region 2.2 (L1) Ensure the ESXi host firewall is configured to restrict access to services running on the host (Manual)
if('2.2' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-VMHostFirewallException -Enabled $true | Where-Object -FilterScript {$_.ServiceRunning -and $_.ExtensionData.AllowedHosts.AllIP} | Select-Object -Property Name,Enabled,IncomingPorts,OutgoingPorts,Protocols,ServiceRunning,@{Label="AllowAllIPs";Expression={$_.ExtensionData.AllowedHosts.AllIP}}
        $Pass = $null

        $CurrentTest = [PSCustomObject]@{
            Test = '2.2'
            Section = $CurrentSection.Name
            Name = 'Ensure the ESXi host firewall is configured to restrict access to services running on the host (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value | ConvertTo-Json
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}


#endregion

#region 2.3 (L1) Ensure Managed Object Browser (MOB) is disabled (Automated)
if('2.3' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = ($VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob).Value
        $Pass = $Value -eq $false
        $CurrentTest = [PSCustomObject]@{
            Test = '2.3'
            Section = $CurrentSection.Name
            Name = 'Ensure Managed Object Browser (MOB) is disabled (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Disable MOB')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value $false
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to Disable MOB on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}


#endregion

#region 2.4 (L2) Ensure default self-signed certificate for ESXi communication is not used (Manual)

if('2.4' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = "N/A Manual Test Required"
        $Pass = $null

        $CurrentTest = [PSCustomObject]@{
            Test = '2.4'
            Section = $CurrentSection.Name
            Name = 'Ensure default self-signed certificate for ESXi communication is not used (Manual)'
            Level = 2
            Item = $VMHost
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}


#endregion

#region 2.5 (L1) Ensure SNMP is configured properly (Manual)

if('2.5' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].EsxCli.system.snmp.get.Invoke()
        $Pass = $Value.enable -eq $false

        $CurrentTest = [PSCustomObject]@{
            Test = '2.5'
            Section = $CurrentSection.Name
            Name = 'Ensure SNMP is configured properly (Manual)'
            Level = 1
            Item = $VMHost
            Value = ('Enabled: {0}' -f $Value.enable)
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}


#endregion

#region 2.6 (L1) Ensure dvfilter API is not configured if not used (Automated)
if('2.6' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = ($VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress).Value
        $Pass = $Value -eq ""
        $CurrentTest = [PSCustomObject]@{
            Test = '2.6'
            Section = $CurrentSection.Name
            Name = 'Ensure dvfilter API is not configured if not used (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Disable DVFilterBindIpAddress')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value ""
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to Disable DVFilterBindIpAddress on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 2.7 (L1) Ensure expired and revoked SSL certificates are removed from the ESXi server (Manual)
if('2.7' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = "N/A Manual Test Required"
        $Pass = $null

        $CurrentTest = [PSCustomObject]@{
            Test = '2.7'
            Section = $CurrentSection.Name
            Name = 'Ensure expired and revoked SSL certificates are removed from the ESXi server (Manual)'
            Level = 1
            Item = $VMHost
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}
#endregion

#region 2.8 (L1) Ensure vSphere Authentication Proxy is used when adding hosts to Active Directory (Automated)
if('2.8' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $VMHostAuthentication = $VMHosts[$VMHost].VMHost | Get-VMHostAuthentication 
        if($null -eq $VMHostAuthentication.Domain) {
            $Value = "Not Joined to AD"
            $Pass = $true
        } else {
            $Value = ("Manual Check Required Domain Joined to {0} Status {1}" -f $VMHostAuthentication.Domain, $VMHostAuthentication.DomainMembershipStatus)
            $Pass = $null
        }
        $CurrentTest = [PSCustomObject]@{
            Test = '2.8'
            Section = $CurrentSection.Name
            Name = 'Ensure vSphere Authentication Proxy is used when adding hosts to Active Directory (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}
#endregion

#region 2.9 (L2) Ensure VDS health check is disabled (Automated)

if('2.9' -like $Test) {        
    foreach($VDSwitch in $VDSwitches.Keys) {
        $Value = $false
        $VDSwitches[$VDSwitch].VDSwitch.ExtensionData.Config.HealthCheckConfig | Foreach-Object -Process {
            if($_.Enable) {
                $Value = $true
            }
        }
        $Pass = $Value -eq $false

        $CurrentTest = [PSCustomObject]@{
            Test = '2.9'
            Section = $CurrentSection.Name
            Name = 'Ensure VDS health check is disabled (Automated)'
            Level = 2
            Item = $VDSwitch
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VDSwitch,'Disable DVSwitch Health Check')) {
            try {
                ($VDSwitches[$VDSwitch].VDSwitch | Get-View).UpdateDVSHealthCheckConfig(@(
                    (New-Object -TypeName VMware.Vim.VMwareDVSVlanMtuHealthCheckConfig -Property @{enable=0}),
                    (New-Object -TypeName VMware.Vim.VMwareDVSTeamingHealthCheckConfig -Property @{enable=0})
                ))

                
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to Disable VDSwitch Health Check on switch {0}' -f $VDSwitch)
            }
        }
        $CurrentTest

    }
}


#endregion