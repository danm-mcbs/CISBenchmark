$CurrentSection = [PSCustomObject]@{   
    Name = 'Console'
    Description = "This section contains recommendations related to ESXi consoles."
}

#region 5.1 (L1) Ensure the DCUI timeout is set to 600 seconds or less (Automated)

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
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set DCUI timeout to 600 seconds on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 5.2 (L1) Ensure the ESXi shell is disabled (Automated)

if('5.2' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-VMHostService | Where-Object -FilterScript {$_.Key -eq 'TSM'}
        $Pass = $Value.Policy -eq 'off'
        $CurrentTest = [PSCustomObject]@{
            Test = '5.2'
            Section = $CurrentSection.Name
            Name = 'Ensure the ESXi shell is disabled (Automated)'
            Level = 1
            Item = $VMHost
            Value = ('Service {0} ({1}); Startup Policy: {2}; Running: {3}' -f $Value.Key, $Value.Label, $Value.Policy, $Value.Running)
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Disable ESXi Shell')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-VMHostService | Where-Object -FilterScript {$_.Key -eq 'TSM'} | Set-VMHostService -Policy Off
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to disable ESXi Shell on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 5.3 (L1) Ensure SSH is disabled (Automated)

if('5.3' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-VMHostService | Where-Object -FilterScript {$_.Key -eq 'TSM-SSH'}
        $Pass = $Value.Policy -eq 'off'
        $CurrentTest = [PSCustomObject]@{
            Test = '5.3'
            Section = $CurrentSection.Name
            Name = 'Ensure SSH is disabled (Automated)'
            Level = 1
            Item = $VMHost
            Value = ('Service {0} ({1}); Startup Policy: {2}; Running: {3}' -f $Value.Key, $Value.Label, $Value.Policy, $Value.Running)
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Disable SSH')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-VMHostService | Where-Object -FilterScript {$_.Key -eq 'TSM-SSH'} | Set-VMHostService -Policy Off
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to disable SSH on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 5.5 (L1) Ensure Normal Lockdown mode is enabled (Automated)

if('5.5' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost.ExtensionData.Config.adminDisabled
        Switch($VMHosts[$VMHost].VMHost.ExtensionData.Config.LockdownMode) {
            'lockdownDisabled' { 
                $lockdownMode = 'Disabled'
            }
            'lockdownNormal' {
                $lockdownMode = 'Normal'
            }
            'lockdownStrict' {
                $lockdownMode = 'Strict'
            }
            default {
                $lockdownMode = 'Unknown Mode'
            }
        }
        $Pass = $Value -eq $true -and $lockdownMode -eq 'Normal'

        $CurrentTest = [PSCustomObject]@{
            Test = '5.5'
            Section = $CurrentSection.Name
            Name = 'Ensure Normal Lockdown mode is enabled (Automated)'
            Level = 1
            Item = $VMHost
            Value = ('Lockdown Mode Enabled: {0}; Lockdown Mode: {1}' -f $Value, $lockdownMode)
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Enable Lockdown Mode')) {
            try {
                if($Global:DefaultVIServer.ProductLine -eq 'embeddedEsx') {
                    Write-Warning -Message ('Not enabling Lockdown mode on host {0} as we are using ESXi connection' -f $VMHost)
                } else {
                    $VMHosts[$VMHost].VMHost | Get-VMHostService | Where-Object -FilterScript {$_.Key -eq 'TSM-SSH'} | Set-VMHostService -Policy Off
                    $CurrentTest.Remediated = $true    
    
                }
            } catch {
                Write-Warning -Message ('Unable to disable SSH on host {0}' -f $VMHost)
            }
        }

        $CurrentTest

    }
}
#endregion

#region 5.6 (L2) Ensure Strict Lockdown mode is enabled (Automated)

if($Level -eq 'L2' -and '5.6' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost.ExtensionData.Config.adminDisabled
        Switch($VMHosts[$VMHost].VMHost.ExtensionData.Config.LockdownMode) {
            'lockdownDisabled' { 
                $lockdownMode = 'Disabled'
            }
            'lockdownNormal' {
                $lockdownMode = 'Normal'
            }
            'lockdownStrict' {
                $lockdownMode = 'Strict'
            }
            default {
                $lockdownMode = 'Unknown Mode'
            }
        }
        $Pass = $Value -eq $true -and $lockdownMode -eq 'Strict'

        $CurrentTest = [PSCustomObject]@{
            Test = '5.6'
            Section = $CurrentSection.Name
            Name = 'Ensure Strict Lockdown mode is enabled (Automated)'
            Level = 2
            Item = $VMHost
            Value = ('Lockdown Mode Enabled: {0}; Lockdown Mode: {1}' -f $Value, $lockdownMode)
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Enable Lockdown Mode')) {
            try {
                if($Global:DefaultVIServer.ProductLine -eq 'embeddedEsx') {
                    Write-Warning -Message ('Not enabling Lockdown mode on host {0} as we are using ESXi connection' -f $VMHost)
                } else {
                    $lockdown = Get-View -Id $VMHosts[$VMHost].VMHost.ExtensionData.ConfigManager.HostAccessManager
                    $lockdown.ChangeLockdownMode('lockdownStrict')
                    $CurrentTest.Remediated = $true    
    
                }
            } catch {
                Write-Warning -Message ('Unable to disable SSH on host {0}' -f $VMHost)
            }
        }

        $CurrentTest

    }
}
#endregion

#region 5.7 (L2) Ensure the SSH authorized_keys file is empty (Manual)

if($Level -eq 'L2' -and '5.7' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = 'Manual Test - Check /etc/ssh/keys-root/authorized_keys and remove any keys'
        $Pass = $null

        $CurrentTest = [PSCustomObject]@{
            Test = '5.7'
            Section = $CurrentSection.Name
            Name = 'Ensure the SSH authorized_keys file is empty (Manual)'
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

#region 5.8 (L1) Ensure idle ESXi shell and SSH sessions time out after 300 seconds or less (Automated)

if('5.8' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut
        $Pass = $Value.Value -le 300 -and $Value.Value -ne 0
        $CurrentTest = [PSCustomObject]@{
            Test = '5.8'
            Section = $CurrentSection.Name
            Name = 'Ensure idle ESXi shell and SSH sessions time out after 300 seconds or less (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set ESXi shell & SSH idle timeout to 300 seconds')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 300
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set ESXi shell & SSH idle timeout to 300 seconds on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 5.9 (L1) Ensure the shell services timeout is set to 1 hour or less (Automated)

if('5.9' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut
        $Pass = $Value.Value -le 3600 -and $Value.Value -ne 0
        $CurrentTest = [PSCustomObject]@{
            Test = '5.9'
            Section = $CurrentSection.Name
            Name = 'Ensure the shell services timeout is set to 1 hour or less (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set shell services timeout to 1 hour')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 3600
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set shell services timeout to 1 hour on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 5.10 (L1) Ensure DCUI has a trusted users list for lockdown mode (Manual)

if('5.10' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name DCUI.Access
        $Pass = $null
        $CurrentTest = [PSCustomObject]@{
            Test = '5.10'
            Section = $CurrentSection.Name
            Name = 'Ensure DCUI has a trusted users list for lockdown mode (Manual)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value | Join-String -Separator ', '
            Pass = $Pass
            Remediated = $false
        }
        
        $CurrentTest

    }
}
#endregion

#region 5.11 (L2) Ensure contents of exposed configuration files have not been modified (Manual)


if('5.11' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {

        $Value = ('Manual Test: Log into https://{0}/host and review/backup files' -f $VMHost)
        $Pass = $null
        $CurrentTest = [PSCustomObject]@{
            Test = '5.11'
            Section = $CurrentSection.Name
            Name = 'Ensure contents of exposed configuration files have not been modified (Manual)'
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