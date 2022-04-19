$CurrentSection = [PSCustomObject]@{   
    Name = 'vNetwork'
    Description = "This section contains recommendations related to configuring vNetwork."
}

#region 7.1 (L1) Ensure the vSwitch Forged Transmits policy is set to reject (Automated)

if('7.1' -like $Test) {
    foreach($vSwitch in $VSwitches) {
        $Value = $vSwitch.ExtensionData.Spec.Policy.Security.ForgedTransmits
        $Pass = $Value -eq $false
        $CurrentTest = [PSCustomObject]@{
            Test = '7.1'
            Section = $CurrentSection.Name
            Name = 'Ensure the vSwitch Forged Transmits policy is set to reject (Automated)'
            Level = 1
            Item = ('{0} vSwitch {1}' -f $vSwitch.VMHost, $vSwitch.Name)
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }
        
        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($CurrentTest.Item,'Disable Forged Transmits')) {
            try {
                $VMHosts[$vSwitch.VMHost].EsxCli.network.vswitch.standard.policy.security.set.Invoke(@{vswitchname=$vswitch.name; allowforgedtransmits=$false})                
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to disable Forged Transmits on {0}' -f $CurrentTest.Item)
            }
        }
        $CurrentTest
    }

}
#endregion

#region 7.2 (L1) Ensure the vSwitch MAC Address Change policy is set to reject (Automated)

if('7.2' -like $Test) {
    foreach($vSwitch in $VSwitches) {
        $Value = $vSwitch.ExtensionData.Spec.Policy.Security.MacChanges
        $Pass = $Value -eq $false
        $CurrentTest = [PSCustomObject]@{
            Test = '7.2'
            Section = $CurrentSection.Name
            Name = 'Ensure the vSwitch MAC Address Change policy is set to reject (Automated)'
            Level = 1
            Item = ('{0} vSwitch {1}' -f $vSwitch.VMHost, $vSwitch.Name)
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }
        
        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($CurrentTest.Item,'Disable Mac Address Changes')) {
            try {
                $VMHosts[$vSwitch.VMHost].EsxCli.network.vswitch.standard.policy.security.set.Invoke(@{vswitchname=$vswitch.name; allowmacchange=$false})                
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to disable Mac Address Changes on {0}' -f $CurrentTest.Item)
            }
        }
        $CurrentTest
    }

}
#endregion

#region 7.3 (L1) Ensure the vSwitch Promiscuous Mode policy is set to reject (Automated)

if('7.3' -like $Test) {
    foreach($vSwitch in $VSwitches) {
        $Value = $vSwitch.ExtensionData.Spec.Policy.Security.AllowPromiscuous
        $Pass = $Value -eq $false
        $CurrentTest = [PSCustomObject]@{
            Test = '7.3'
            Section = $CurrentSection.Name
            Name = 'Ensure the vSwitch Promiscuous Mode policy is set to reject (Automated)'
            Level = 1
            Item = ('{0} vSwitch {1}' -f $vSwitch.VMHost, $vSwitch.Name)
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }
        
        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($CurrentTest.Item,'Disable Promiscuous Mode')) {
            try {
                $VMHosts[$vSwitch.VMHost].EsxCli.network.vswitch.standard.policy.security.set.Invoke(@{vswitchname=$vswitch.name; allowpromiscuous=$false})                
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to Disable Promiscuous Mode on {0}' -f $CurrentTest.Item)
            }
        }
        $CurrentTest
    }

}
#endregion

#region 7.4 (L1) Ensure port groups are not configured to the value of the native VLAN (Manual)
if('7.4' -like $Test) {
    foreach($vSwitch in $VSwitches) {
        $vSwitch | Get-VirtualPortGroup -Standard | Foreach-Object -Process {
            $Value = $_.VLanId
            $Pass = $null -ne $Value 
            $CurrentTest = [PSCustomObject]@{
                Test = '7.4'
                Section = $CurrentSection.Name
                Name = 'Ensure port groups are not configured to the value of the native VLAN (Manual)'
                Level = 1
                Item = ('{0} vSwitch {1} Port Group {2}' -f $vSwitch.VMHost, $vSwitch.Name, $_.Name)
                Value = $Value
                Pass = $Pass
                Remediated = $false
            }
            
            $CurrentTest
        }

    }

}
#endregion

#region 7.5 (L1) Ensure port groups are not configured to VLAN values reserved by upstream physical switches (Manual)
if('7.5' -like $Test) {
    foreach($vSwitch in $VSwitches) {
        $vSwitch | Get-VirtualPortGroup -Standard | Foreach-Object -Process {
            $Value = ('Check with Vendor Documentation if Reserved VLANs exist. Check VLANs: {0}' -f $_.VLanId)
            $Pass = $null
            $CurrentTest = [PSCustomObject]@{
                Test = '7.5'
                Section = $CurrentSection.Name
                Name = 'Ensure port groups are not configured to VLAN values reserved by upstream physical switches (Manual)'
                Level = 1
                Item = ('{0} vSwitch {1} Port Group {2}' -f $vSwitch.VMHost, $vSwitch.Name, $_.Name)
                Value = $Value
                Pass = $Pass
                Remediated = $false
            }
            
            $CurrentTest
        }

    }

}
#endregion

#region 7.6 (L1) Ensure port groups are not configured to VLAN 4095 and 0 except for Virtual Guest Tagging (VGT) (Manual)
if('7.6' -like $Test) {
    foreach($vSwitch in $VSwitches) {
        $vSwitch | Get-VirtualPortGroup -Standard | Foreach-Object -Process {
            $Value = $_.VLanId
            $Pass = $Value -ne 0 -and $Value -ne 4095
            $CurrentTest = [PSCustomObject]@{
                Test = '7.6'
                Section = $CurrentSection.Name
                Name = 'Ensure port groups are not configured to VLAN 4095 and 0 except for Virtual Guest Tagging (VGT) (Manual)'
                Level = 1
                Item = ('{0} vSwitch {1} Port Group {2}' -f $vSwitch.VMHost, $vSwitch.Name, $_.Name)
                Value = $Value
                Pass = $Pass
                Remediated = $false
            }
            
            $CurrentTest
        }

    }

}
#endregion

#region 7.7 (L1) Ensure Virtual Distributed Switch Netflow traffic is sent to an authorized collector (Manual)

if('7.7' -like $Test) {
    foreach($VDSwitch in $VDSwitches.Keys) {
        $Value = $VDSwitches[$VDSwitch].VDSwitch.ExtensionData.Config.IpfixConfig.CollectorIpAddress
        $Pass = $null -ne $Value

        $CurrentTest = [PSCustomObject]@{
            Test = '7.7'
            Section = $CurrentSection.Name
            Name = 'Ensure Virtual Distributed Switch Netflow traffic is sent to an authorized collector (Manual)'
            Level = 1
            Item = $VDSwitch
            Value = $Value
            Pass = $Pass
            Remediated = $false
        }
        
        $CurrentTest
    }

}
#endregion

#region 7.8 (L1) Ensure port-level configuration overrides are disabled. (Automated)

if('7.8' -like $Test) {
    foreach($VDSwitch in $VDSwitches.Keys) {
        Get-VDPortgroup -VDSwitch $VDSwitch | Get-VDPortgroupOverridePolicy | Foreach-Object -Process {
            $Value = ('Security Override: {0}; Vlan Override: {1}; Traffic Shaping Override: {2}; Uplink Teaming Override: {3}' -f $_.SecurityOverrideAllowed, $_.VlanOverrideAllowed, $_.TrafficShapingOverrideAllowed, $_.UplinkTeamingOverrideAllowed)
            $Pass = $_.SecurityOverrideAllowed -eq $false -and $_.VlanOverrideAllowed -eq $false -and $_.TrafficShapingOverrideAllowed -eq $false -and $_.UplinkTeamingOverrideAllowed -eq $false
            
            $CurrentTest = [PSCustomObject]@{
                Test = '7.8'
                Section = $CurrentSection.Name
                Name = 'Ensure port-level configuration overrides are disabled. (Automated)'
                Level = 1
                Item = ('{0} Port Group {1}' -f $VDSwitch, $_.Name)
                Value = $Value
                Pass = $Pass
                Remediated = $false
            }
            
            if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($CurrentTest.Item,'Disable configuration overrides')) {
                try {
                    $_ | Set-VDPortgroupOverridePolicy -BlockOverrideAllowed $false -VlanOverrideAllowed $false -TrafficShapingOverrideAllowed $false -UplinkTeamingOverrideAllowed $false
                    $CurrentTest.Remediated = $true    
                } catch {
                    Write-Warning -Message ('Unable to Disable configuration overrides on {0}' -f $CurrentTest.Item)
                }
            }

            $CurrentTest
        }
    }

}
#endregion
