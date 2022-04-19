$CurrentSection = [PSCustomObject]@{   
    Name = 'Console'
    Description = "This section contains recommendations related to ESXi consoles."
}

#region 6.1 (L1) Ensure bidirectional CHAP authentication for iSCSI traffic is enabled (Manual)

if('6.1' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $VMHosts[$VMHost].VMHost | Get-VMHostHBA | Where-Object -FilterScript {$_.Type -eq 'IScsi'} | Foreach-Object -Process {
            $Value = ('Chap Type: {1}; Chap Name: {2}' -f $_.Name, $_.ChapType, $_.ChapName)
            $Pass = $null
            $CurrentTest = [PSCustomObject]@{
                Test = '6.1'
                Section = $CurrentSection.Name
                Name = 'Ensure bidirectional CHAP authentication for iSCSI traffic is enabled (Manual)'
                Level = 1
                Item = ('{0} HBA {1}' -f $VMHost, $_.Name)
                Value = $Value.Value
                Pass = $Pass
                Remediated = $false
            }
            
            $CurrentTest
            }

    }
}
#endregion

#region 6.2 (L2) Ensure the uniqueness of CHAP authentication secrets for iSCSI traffic (Manual)

if($Level -eq 'L2' -and '6.2' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $VMHosts[$VMHost].VMHost | Get-VMHostHBA | Where-Object -FilterScript {$_.Type -eq 'IScsi'} | Foreach-Object -Process {
            $Value = ('Chap Type: {1}; Chap Name: {2}' -f $_.Name, $_.ChapType, $_.ChapName)
            $Pass = $null
            $CurrentTest = [PSCustomObject]@{
                Test = '6.2'
                Section = $CurrentSection.Name
                Name = 'Ensure the uniqueness of CHAP authentication secrets for iSCSI traffic (Manual)'
                Level = 2
                Item = ('{0} HBA {1}' -f $VMHost, $_.Name)
                Value = $Value.Value
                Pass = $Pass
                Remediated = $false
            }
            
            $CurrentTest
            }

    }
}
#endregion

#region 6.3 (L1) Ensure storage area network (SAN) resources are segregated properly (Manual)

if('6.3' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = 'N/A - Manual review of the LUNs, SAN and Networks is required'
        $Pass = $null
        $CurrentTest = [PSCustomObject]@{
            Test = '6.3'
            Section = $CurrentSection.Name
            Name = 'Ensure storage area network (SAN) resources are segregated properly (Manual)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }
        
        $CurrentTest
    }
}
#endregion