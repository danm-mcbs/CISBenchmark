<#

#>

[CmdletBinding()]
Param(

    #region Default Variables
    [string]
    $Benchmark = 'VMware ESXi 7.0 v1.1.0'
    #endregion
)

Begin {
    
}

Process {

    #region Loop through scripts in the $BenchmarkFolder
    $Section = @{}
    $BenchmarkPath = ('{0}\{1}' -f (Split-Path -Path $MyInvocation.MyCommand.Path), $Benchmark)
    if(Test-Path -Path $BenchmarkPath) {
        Get-ChildItem -Path $BenchmarkPath -Filter '*.ps1' | ForEach-Object -Process {
            . $_
        }
    } else {
        throw ('Unable to find Benchmark [{0}] in {1}' -f $Benchmark, $BenchmarkPath)
    }
    $Section.GetEnumerator() | Sort-Object -Property Key
    #endregion
}