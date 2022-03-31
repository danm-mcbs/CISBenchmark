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
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set NTP Servers')) {
            try {
                $VMHosts[$VMHost] | Add-VMHostNtpServer -NtpServer 'pool.ntp.org','pool2.ntp.org'
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
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}


#endregion