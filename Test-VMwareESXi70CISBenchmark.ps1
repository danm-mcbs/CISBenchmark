<#

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
    [string]
    $VMHostName = '*'
)

Begin {

    #region Validate vCenter Connection
    if($Global:DefaultVIServer) {
        Write-Verbose -Message ('Connected to {0} version {1}' -f $Global:DefaultVIServer.Name, $Global:DefaultVIServer.Version, $Global:DefaultVIServer.Build)
    } else {
        throw ('You must be connected to a vCenter Server or ESXi Host to run this script. Use Connect-VIServer to connect')
    }
    #endregion

}

Process {

    #region Get and Cache common Objects required in scripts - to avoid re-running multiple Get-xxx API Calls

    $VMHosts = @{}
    Get-VMHost -Name $VMHostName | Foreach-Object -Process {
        $VMHosts[$_.Name] = [PSCustomObject]@{
            VMHost = $_
            EsxCli = $_ | Get-EsxCli -V2
        }
    }
    
    $VDSwitches = @{}
    Get-VDSwitch | Foreach-Object -Process {
        $VDSwitches[$_.Name] = [PSCustomObject]@{
            VDSwitch = $_
        }
    }

    $VSwitches = Get-VirtualSwitch -Standard

    #endregion

    #region Loop through scripts in the $BenchmarkFolder
    $BenchmarkPath = ('{0}\{1}' -f (Split-Path -Path $MyInvocation.MyCommand.Path), $Benchmark)
    if(Test-Path -Path $BenchmarkPath) {
        Get-ChildItem -Path $BenchmarkPath -Filter '*.ps1' | ForEach-Object -Process {
            . $_
        }
    } else {
        throw ('Unable to find Benchmark [{0}] in {1}' -f $Benchmark, $BenchmarkPath)
    }
    #endregion
}