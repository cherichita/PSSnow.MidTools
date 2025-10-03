[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingWriteHost', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingEmptyCatchBlock', '')]
param(
    [ValidateScript({ "snm::./build.tasks.ps1", "snm::./az.tasks.ps1", "snm::./snowmid.tasks.ps1" })]
    $Extends
)

task SnowMid {
    Write-PSFMessage "Starting SnowMid build process"
    # & "$PSScriptRoot/src/build/BuildHelper.build.ps1" -Extends $Extends -Force -ReloadModules -UpdateCredentials
    Write-PSFMessage "Completed SnowMid build process"
}