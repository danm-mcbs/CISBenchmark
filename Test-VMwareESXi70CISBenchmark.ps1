<#
    .SYNOPSIS
        Using the PowerCLI modules run a simple assessment against CIS standards
#>


[CmdletBinding(SupportsShouldProcess=$True)]
Param(

    # The CIS Benchmark Level to Evaluate
    [ValidateSet('L1','L2')]
    [string]
    $Level = 'L1',

    # Should the CIS Profile automatic remediations be applied
    [switch]
    $Remediate,
    
    # Which Benchmark scripts should run, this folder should exist
    [string]
    $Benchmark = 'VMware ESXi 7.0 v1.1.0',

    # Which test to run
    [string]
    $Test = '*',

    # Which Host(s) to check
    [string[]]
    $VMHostName = @('*'), 

    # Which Cluster(s) to check
    [string[]]
    $ClusterName = @('*')
)

Begin {
    #region Check for PowerShell version and VMware.PowerCLI Modules
    if($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error -Message 'This script requires PowerShell 7 or higher. Visit https://aka.ms/powershell for details about downloading and deploying.' -Category NotInstalled
        exit 1
    }

    if($null -eq (Get-Module -Name VMware.PowerCLI -ListAvailable)) {
        Write-Error -Message 'This script requires the VMware.PowerCLI module. Use `Install-Module -Name VMware.PowerCLI` to install this.' -Category NotInstalled
        exit 1
    }
    #endregion

    #region Validate vCenter Connection
    if($Global:DefaultVIServer) {
        Write-Verbose -Message ('Connected to {0} version {1}' -f $Global:DefaultVIServer.Name, $Global:DefaultVIServer.Version, $Global:DefaultVIServer.Build)
    } else {
        Write-Error -Message 'You must be connected to a vCenter Server or ESXi Host to run this script. Use Connect-VIServer to connect (see Get-Help -name Connect-VIServer for details).' -Category ConnectionError
        exit 1
    }
    #endregion

}

Process {

    #region Get and Cache common Objects required in scripts - to avoid re-running multiple Get-xxx API Calls

    $VMHosts = @{}
    if($global:DefaultVIServer.ProductLine -eq 'vpx') {
        $VMHostList = Get-Cluster -Name $ClusterName | Get-VMHost -Name $VMHostName
    } else {
        $VMHostList = Get-VMHost -Name $VMHostName
    }
    $VMHostList | Foreach-Object -Process {
        $VMHosts[$_.Name] = [PSCustomObject]@{
            VMHost = $_
            EsxCli = $_ | Get-EsxCli -V2
        }
    }
    
    $VDSwitches = @{}
    Get-VDSwitch -VMHost $VMHostList | Foreach-Object -Process {
        $VDSwitches[$_.Name] = [PSCustomObject]@{
            VDSwitch = $_
        }
    }

    $VSwitches = Get-VirtualSwitch -Standard -VMHost $VMHostList

    #endregion

    #region Loop through scripts in the $BenchmarkFolder
    $BenchmarkPath = ('{0}\{1}' -f (Split-Path -Path $MyInvocation.MyCommand.Path), $Benchmark)
    if(Test-Path -Path $BenchmarkPath) {
        Get-ChildItem -Path $BenchmarkPath -Filter '*.ps1' | ForEach-Object -Process {
            . $_
        }
    } else {
        Write-Error -Message ('Unable to find Benchmark [{0}] in {1}' -f $Benchmark, $BenchmarkPath) -Category ObjectNotFound
    }
    #endregion
}