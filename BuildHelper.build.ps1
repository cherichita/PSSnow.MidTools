[CmdletBinding()]
[System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingWriteHost', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingEmptyCatchBlock', '')]
param(
    [ValidateScript({"./src/build/build.tasks.ps1","./src/build/az.tasks.ps1","./src/build/snowmid.tasks.ps1"})]
    $Extends,
    $EnvironmentName = 'unts',
    $MidToolsPath = "$PSScriptRoot/src",
    $MidContext = 'azure',
    $MidBuildStrategy = 'acr',
    $SnowDataPath = $env:SNOW_DATA_PATH ?? "$PSScriptRoot/tests/testdeployment",
    [switch]$ReloadModules,
    [switch]$UpdateCredentials,
    [switch]$Force,
    $PodePort = 8099,
    [string]$TemplateOutputPath = $env:SN_TEMPLATE_OUTPUT_PATH ?? "$PSScriptRoot/src/arm_out",
    [string]$TemplateStorageAccount = "snowmiddeploy",
    [string]$TemplateStorageContainer = "snowmid-azure-templates"
)
begin {
    $ErrorActionPreference = 'Stop'
}
process {
    $env:SN_MID_ENVIRONMENT_NAME = $EnvironmentName
    $env:SN_MID_BUILD_STRATEGY = $MidBuildStrategy
    $env:SN_MID_CONTEXT = $MidContext
    $Script:BicepPath = Resolve-Path -Path "${MidToolsPath}/azure"
    $Script:SettingsFile = Resolve-Path -Path "${SnowDataPath}/settings.$($env:SN_MID_ENVIRONMENT_NAME).yml" -ErrorAction SilentlyContinue
    $Script:AcsBasePath = Resolve-Path -Path "${MidToolsPath}/azure"
    if( -not $Script:SettingsFile) {
        throw "Settings file not found: ${SnowDataPath}/settings.$($env:SN_MID_ENVIRONMENT_NAME).yml"
    }
    $Script:BuildSettings = Get-Content -Path $SettingsFile | ConvertFrom-Yaml
}

