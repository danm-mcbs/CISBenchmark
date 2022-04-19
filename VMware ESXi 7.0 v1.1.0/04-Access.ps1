$CurrentSection = [PSCustomObject]@{   
    Name = 'Access'
    Description = "This section contains recommendations related to ESXi access management."
}

#region 4.1 (L1) Ensure a non-root user account exists for local admin access (Manual)

if('4.1' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        if($Global:DefaultVIServer.ProductLine -eq 'embeddedEsx') {
            $Value = (Get-VMHostAccount).Name | Join-String -Separator ', '
            $Pass = $null
        } else {
            $Value = $VMHosts[$VMHost].EsxCli.system.account.list.Invoke().UserId | Join-String -Separator ', '
            $Pass = $null
        }
        $CurrentTest = [PSCustomObject]@{
            Test = '4.1'
            Section = $CurrentSection.Name
            Name = 'Ensure a non-root user account exists for local admin access (Manual)'
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

#region 4.2 (L1) Ensure passwords are required to be complex (Automated)

if('4.2' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl
        $Value -match 'min=(disabled|[0-9]+),(disabled|[0-9]+),(disabled|[0-9]+),(disabled|[0-9]+),(?<length>disabled|[0-9]+)' | Out-Null
        [int]$passwdLength = 0
        [int]::TryParse($Matches.length,[ref]$passwdLength) | Out-Null
        $Pass = $Value.Value -match 'retry=[1-5]' -and $Matches.length -ne 'disabled' -and [int]$passwdLength -ge 14
        $CurrentTest = [PSCustomObject]@{
            Test = '4.2'
            Section = $CurrentSection.Name
            Name = 'Ensure passwords are required to be complex (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set Password Complexity')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value 'retry=3 min=disabled,disabled,disabled,disabled,14'
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set Password Complexity on host {0}: {1}' -f $VMHost, $_.Exception.Message)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 4.3 (L1) Ensure the maximum failed login attempts is set to 5 (Automated)

if('4.3' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures
        $Pass = $Value.Value -ge 5
        $CurrentTest = [PSCustomObject]@{
            Test = '4.3'
            Section = $CurrentSection.Name
            Name = 'Ensure the maximum failed login attempts is set to 5 (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set Maximum failed login attempts to 5')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 5
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set maximum failed login attempts to 5 on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 4.4  (L1) Ensure account lockout is set to 15 minutes (Automated)

if('4.4' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime
        $Pass = $Value.Value -ge 900
        $CurrentTest = [PSCustomObject]@{
            Test = '4.4'
            Section = $CurrentSection.Name
            Name = 'Ensure account lockout is set to 15 minutes (Automated)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set account lockout is set to 15 minutes')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set account lockout to 15 minutes on host {0}' -f $VMHost)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 4.5 (L1) Ensure previous 5 passwords are prohibited (Manual)

if('4.5' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.PasswordHistory
        $Pass = $Value.Value -ge 5
        $CurrentTest = [PSCustomObject]@{
            Test = '4.5'
            Section = $CurrentSection.Name
            Name = 'Ensure previous 5 passwords are prohibited (Manual)'
            Level = 1
            Item = $VMHost
            Value = $Value.Value
            Pass = $Pass
            Remediated = $false
        }

        if($false -eq $Pass -and $true -eq $Remediate -and $PSCmdlet.ShouldProcess($VMHost,'Set password history to 5')) {
            try {
                $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 5
                $CurrentTest.Remediated = $true    
            } catch {
                Write-Warning -Message ('Unable to set account password history to 5 on host {0}: {1}' -f $VMHost, $_.Exception.Message)
            }
        }
        $CurrentTest

    }
}
#endregion

#region 4.6 (L1) Ensure Active Directory is used for local user authentication (Manual)

if('4.6' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $VMHostAuthentication = $VMHosts[$VMHost].VMHost | Get-VMHostAuthentication 
        if($null -eq $VMHostAuthentication.Domain) {
            $Value = "Not Joined to AD"
            $Pass = $false
        } else {
            $Value = ("Joined to {0} Status {1}" -f $VMHostAuthentication.Domain, $VMHostAuthentication.DomainMembershipStatus)
            $Pass = $true
        }

        $CurrentTest = [PSCustomObject]@{
            Test = '4.6'
            Section = $CurrentSection.Name
            Name = 'Ensure Active Directory is used for local user authentication (Manual)'
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

#region 4.7 (L1) Ensure only authorized users and groups belong to the esxAdminsGroup group (Manual)

if('4.7' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup
        $Pass = $null

        $CurrentTest = [PSCustomObject]@{
            Test = '4.7'
            Section = $CurrentSection.Name
            Name = 'Ensure only authorized users and groups belong to the esxAdminsGroup group (Manual)'
            Level = 1
            Item = $VMHost
            Value = ('Check users in AD Group "{0}"' -f $Value.Value)
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}
#endregion

#region 4.8 (L1) Ensure the Exception Users list is properly configured (Manual)

if('4.8' -like $Test) {
    foreach($VMHost in $VMHosts.Keys) {
        $Value = $VMHosts[$VMHost].VMHost.ExtensionData.Config.LockdownMode
        $lockdownView = Get-View -Id $VMHosts[$VMHost].VMHost.ExtensionData.ConfigManager.HostAccessManager
        $lockdownExceptions = $lockdownView.QueryLockdownExceptions() | Join-String -Separator ', '
        Switch($Value) {
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
        $Pass = $null

        $CurrentTest = [PSCustomObject]@{
            Test = '4.8'
            Section = $CurrentSection.Name
            Name = 'Ensure the Exception Users list is properly configured (Manual)'
            Level = 1
            Item = $VMHost
            Value = ('Lockdown Mode: {0}; Exception Users: {1}' -f $lockdownMode, $lockdownExceptions)
            Pass = $Pass
            Remediated = $false
        }

        $CurrentTest

    }
}
#endregion