$CurrentSection = [PSCustomObject]@{   
    Name = 'Logging'
    Description = "This section contains recommendations related to ESXi's logging capabilities."
}

#region 3.1 (L1) Ensure a centralized location is configured to collect ESXi host core dumps (Manual)
if('3.1' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].EsxCli.system.coredump.network.get.Invoke()
        $Pass = $Value.Enabled
        $CurrentTest = [PSCustomObject]@{
            Test = '3.1'
            Section = $CurrentSection.Name
            Name = 'Ensure a centralized location is configured to collect ESXi host core dumps (Manual)'
            Level = 1
            Item = $VMHost
            Value = ('Enabled: {0}, Location: {1}:{2}' -f $Value.Enabled, $Value.NetworkServerIP, $Value.NetworkServerPort)
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}
#endregion

#region 3.2 (L1) Ensure persistent logging is configured for all ESXi hosts (Manual)
if('3.2' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Syslog.global.logDir
        $Pass = $null -ne $Value.Value -and $Value.Value -ne '' -and $Value.Value -ne '[] /scratch/log'
        $CurrentTest = [PSCustomObject]@{
            Test = '3.2'
            Section = $CurrentSection.Name
            Name = 'Ensure persistent logging is configured for all ESXi hosts (Manual)'
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

#region 3.3 (L1) Ensure remote logging is configured for ESXi hosts (Manual)
if('3.3' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Syslog.global.logHost
        $Pass = $null -ne $Value.Value -and $Value.Value -ne ''
        $CurrentTest = [PSCustomObject]@{
            Test = '3.3'
            Section = $CurrentSection.Name
            Name = 'Ensure remote logging is configured for ESXi hosts (Manual)'
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