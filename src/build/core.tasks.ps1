[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingWriteHost', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingEmptyCatchBlock', '')]
param(
    [ValidateScript({ "snm::./build.tasks.ps1", "snm::./az.tasks.ps1", "snm::./snowmid.tasks.ps1" })]
    $Extends
)

Enter-Build {
    Write-Build Green "Loading PSSnow.MidTools InvokeBuild tasks from $PSScriptRoot"
}