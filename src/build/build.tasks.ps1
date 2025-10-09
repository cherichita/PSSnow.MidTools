if (-not(Get-Command -Name 'Initialize-WebServerEnvironment' -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot/WebServerHelper.ps1"
}

task DebugLoggingEnabled {
    Set-PSFConfig -FullName PSFramework.Message.Info.Maximum -Value 9
    Set-PSFConfig -FullName PSFramework.Message.Info.Minimum -Value 1
    Set-PSFConfig -FullName PSFramework.Message.Style.Breadcrumbs -Value $true
    Set-PSFConfig -FullName PSFramework.Message.Style.Level -Value $true
}

task DebugLoggingDisabled {
    Set-PSFConfig -FullName PSFramework.Message.Info.Maximum -Value 3
    Set-PSFConfig -FullName PSFramework.Message.Style.Breadcrumbs -Value $false
}

task CompileBicep {
    $BicepSources = @(
        @{
            Name          = "azure_servicenow_mid_acs_base"
            Description   = "Base ServiceNow MID Server deployment with ACS"
            Base          = 'azure_servicenow_mid_acs_base'
            UiDefType     = 'Microsoft_Azure_CreateUIDef'
            DeploymentUrl = "https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/CustomDeploymentBlade/uri/{0}/uiFormDefinitionUri/{1}"
            UiDefinition  = 'uiFormDefinition.mid_acs.json'
        },
        @{
            Name          = "azure_servicenow_mid_acs_full"
            Description   = "Full ServiceNow MID Server deployment with ACS + Optional Network Deployment"
            UiDefType     = 'Microsoft_Azure_CreateUIDef'
            DeploymentUrl = "https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/CustomDeploymentBlade/uri/{0}/uiFormDefinitionUri/{1}"
            Base          = 'azure_servicenow_mid_acs_full'
            UiDefinition  = 'uiFormDefinition.mid_acs.json'
        },
        @{
            Name          = "azure_servicenow_mid_server_single"
            Description   = "Single ServiceNow MID Server deployment"
            UiDefType     = 'Microsoft_Azure_CreateUIDef'
            DeploymentUrl = "https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/CustomDeploymentBlade/uri/{0}/uiFormDefinitionUri/{1}"
            Base          = 'servicenow_mid_server_single'
            UiDefinition  = 'uiFormDefinition.mid_server_single.json'
        },
        @{
            Name          = "azure_ui_def_debug"
            Description   = "Single ServiceNow MID Server deployment"
            UiDefType     = 'Microsoft_Azure_CreateUIDef'
            DeploymentUrl = "https://portal.azure.com/#view/Microsoft_Azure_CreateUIDef/CustomDeploymentBlade/uri/{0}/uiFormDefinitionUri/{1}"
            Base          = 'azure_servicenow_mid_acs_base'
            UiDefinition  = 'uiFormDefinition.debug.json'
        }
    )
    $Script:ArmOut = @()
    assert $TemplateOutputPath 'Template output path is not set'
    foreach ($bs in $BicepSources) {
        $BicepFile = "$($Script:BicepPath)/$($bs.Base).bicep"
        if (Test-Path $BicepFile) {
            # Create a subdirectory in output with name
            $OutputDir = "$TemplateOutputPath/$($bs.Name)"
            if (-not (Test-Path $OutputDir)) {
                New-Item -ItemType Directory -Path $OutputDir | Out-Null
            }
            $ArmFile = "$OutputDir/mainTemplate.json"
            if ((-not (Test-Path $ArmFile)) -or ((Get-Item $ArmFile).LastWriteTime -lt (Get-Item $BicepFile).LastWriteTime) -or ($Force.IsPresent)) {
                & bicep build $BicepFile --outfile $ArmFile
            }
            if (Test-Path $ArmFile) {
                Write-Build Green "$ArmFile compiled successfully"
                if (-not (Test-Path "$($Script:BicepPath)/uiDefinitions/$($bs.UiDefinition)")) {
                    Write-Error "UI definition file not found: $($bs.UiDefinition)"
                    continue
                }
                
                Copy-Item -Path "$($Script:BicepPath)/uiDefinitions/$($bs.UiDefinition)" -Destination "$OutputDir/createUiDefinition.json" -Force
                Write-Host "Copied UI definition to $OutputDir/createUiDefinition.json"
                $Script:ArmOut += ($bs + @{
                        Arm       = $ArmFile
                        OutputDir = $OutputDir
                    })
            }
            else {
                Write-Error "Failed to compile Bicep file: $BicepFile"
            }
        }
        else {
            Write-Error "Bicep file not found: $BicepFile"
        }
    }
    $Script:ArmGlobal = $Script:ArmOut 
}


task GenerateTemplateDocumentationDebug CompileBicep, TestPodeHookRoute, {
    $NgrokTunnel = $Script:NgrokTunnel
    if (-not $Script:ArmOut) {
        Write-Error "No compiled templates found. Run CompileBicep task first."
        return
    }
    foreach ($template in $Script:ArmOut) {
        $OutputDir = $template.OutputDir
        $ReadmePath = "$OutputDir/README.md"
                
        Write-Host "Generating documentation for template: $($template.Name)"
        $BaseUrl = "$($NgrokTunnel.public_url)/templates"
        Generate-TemplateMarkdown -TemplateInfo $template -OutputPath $ReadmePath -BaseUrl $BaseUrl
    }
}

task GenerateTemplateDocumentation CompileBicep, {
    if (-not $Script:ArmOut) {
        Write-Error "No compiled templates found. Run CompileBicep task first."
        return
    }
    foreach ($template in $Script:ArmOut) {
        $OutputDir = $template.OutputDir
        $ReadmePath = "$OutputDir/README.md"
                
        Write-Host "Generating documentation for template: $($template.Name)"
        Generate-TemplateMarkdown -TemplateInfo $template -OutputPath $ReadmePath -BaseUrl "https://raw.githubusercontent.com/cherichita/PSSnow.MidTools/refs/heads/development/src/arm_out"
    }
}

task GenerateTemplateDocumentationAzureStorage CompileBicep, GetTemplateStorageContext, {
    assert $TemplateStorageContainerRef 'Template storage container reference is not set'
    assert $TemplateStorageContext 'Template storage context is not set'
    if (-not $Script:ArmOut) {
        Write-Error "No compiled templates found. Run CompileBicep task first."
        return
    }
    $BaseUrl = $TemplateStorageContainerRef.BlobContainerClient.Uri.AbsoluteUri.TrimEnd('/')
    foreach ($template in $Script:ArmOut) {
        $OutputDir = $template.OutputDir
        $ReadmePath = "$OutputDir/README.md"
                
        Write-Host "Generating documentation for template: $($template.Name)"
        Generate-TemplateMarkdown -TemplateInfo $template -OutputPath $ReadmePath -BaseUrl $BaseUrl
    }
}

task UploadTemplates GenerateTemplateDocumentationAzureStorage, {
    assert $TemplateOutputPath 'Template output path is not set'
    assert $TemplateStorageContext 'Template storage context is not set'
    assert $TemplateStorageContainerRef 'Template storage container reference is not set'
    if (-not (Test-Path $TemplateOutputPath)) {
        Write-Error "Template output path does not exist: $TemplateOutputPath"
        return
    }
    $FilesToUpload = Get-ChildItem -Path $TemplateOutputPath -Recurse | Where-Object { -not $_.PSIsContainer }
    foreach ($file in $FilesToUpload) {
        $RelativePath = $file.FullName.Substring($TemplateOutputPath.Length).TrimStart('\', '/') -replace '\\', '/'
        Write-Host "Uploading file: $RelativePath"
        Set-AzStorageBlobContent -File $file.FullName -Container $TemplateStorageContainerRef.Name -Blob $RelativePath -Context $TemplateStorageContext -Force | Out-Null
        # Print the URL of the uploaded file
        $BlobUrl = ($TemplateStorageContainerRef.Context | Get-AzStorageBlob -Container $TemplateStorageContainerRef.Name -Blob $RelativePath).ICloudBlob.Uri.AbsoluteUri
        Write-Host "Uploaded to: $BlobUrl"
    }
}

task GetStorageContext SnowMidInitializeTools, {
    assert $SnowMidContext.StorageAccount
    
    if ($Script:SnowMidStorageContext = (Get-AzStorageAccount -ResourceGroupName $SnowMidContext.StorageAccount.resourceGroup -Name $SnowMidContext.StorageAccount.name).Context) {
        Write-Host "Retrieved storage context for account: $($SnowMidContext.StorageAccount)"
    }
    else {
        Write-Error "Failed to get storage context for account: $($SnowMidContext.StorageAccount)"
    }
}

task GetStorageShares GetStorageContext, {
    assert $Script:SnowMidStorageContext 'Storage context is not set'
    $Shares = Get-AzStorageShare -Context $Script:SnowMidStorageContext
    if ($Shares) {
        Write-Host "Retrieved storage shares:"
        $Shares | ForEach-Object { Write-Host "- $($_.Name)" }
        $Script:SnowMidStorageShares = $Shares
    }
    else {
        Write-Warning "No storage shares found in the storage account."
    }
}

task GetTemplateStorageContext {
    assert $TemplateStorageAccount 'Template storage account is not set'
    $StorageAccount = Search-AzGraph -UseTenantScope -Query "Resources | where type =~ 'Microsoft.Storage/storageAccounts' | where name =~ '$TemplateStorageAccount' | project name, resourceGroup, location, sku, tags, subscriptionId" | Select-Object -First 1
    if (-not $StorageAccount) {
        Write-Error "Storage account '$TemplateStorageAccount' not found in the current tenant."
        return
    }
    $CurrentContext = Get-AzContext
    try {
        if ($CurrentContext.Subscription.Id -ne $StorageAccount.subscriptionId) {
            Set-AzContext -Subscription $StorageAccount.subscriptionId -Scope Process | Out-Null
        }
        $StorageContext = (Get-AzStorageAccount -ResourceGroupName $StorageAccount.resourceGroup -Name $StorageAccount.name).Context
        $StorageAccountContainer = Get-AzStorageContainer -Name $TemplateStorageContainer -Context $StorageContext -ErrorAction SilentlyContinue
        if (-not $StorageAccountContainer) {
            Write-Host "Creating storage container: $TemplateStorageContainer"
            $StorageAccountContainer = New-AzStorageContainer -Name $TemplateStorageContainer -Context $StorageContext -PublicAccess Blob | Select-Object -First 1
        }
        $Script:TemplateStorageContext = $StorageContext
        $Script:TemplateStorageContainerRef = $StorageAccountContainer
    }
    catch {
        Write-Host "Error getting context: $_"
    }
    finally {
        Set-AzContext -Context $CurrentContext
    }
}


task ResolveModuleFiles {
    $Paths = @(
        'azure'
        'build'
    )
    $BasePath = (Resolve-Path "$PSScriptRoot/..").Path
    $BasePaths = foreach ($P in $Paths) {
        $ModuleFiles = Get-ChildItem -Path (Join-Path -Path $BasePath -ChildPath $P) -Recurse
        # Return the path of the file, relative to base
        $ModuleFiles | ForEach-Object {
            if ($_.PSIsContainer -eq $false) {
                $_.FullName.Substring($BasePath.Length + 1)
            }
        }
    }
    $BaseFiles = Get-ChildItem -Path "$BasePath" -File | ForEach-Object {
        $_.FullName.Substring($BasePath.Length + 1)
    }
    $Script:MidToolsBasePath = (Resolve-Path $BasePath).Path
    $Script:MidToolsModuleFiles = ($BasePaths + $BaseFiles)
    $Script:MidToolsContents = @(
        $BaseFiles
        $Paths
    )
    $ModuleFile = $BaseFiles | Where-Object { $_ -like 'PSSnow.MidTools.psd1' }
    if ($ModuleFile) {
        $ModuleManifest = Import-PowerShellDataFile -Path (Join-Path -Path $BasePath -ChildPath $ModuleFile)
        if ($ModuleManifest) {
            $Script:MidToolsVersion = $ModuleManifest.ModuleVersion
            Write-Host "PSSnow.MidTools version: $Script:MidToolsVersion"
        }
    }
}

task UploadModuleFilesToAzureStorage GetTemplateStorageContext, ResolveModuleFiles, {
    assert $TemplateStorageContainerRef 'Template storage container reference is not set'
    assert $TemplateStorageContext 'Template storage context is not set'
    if (-not $Script:MidToolsModuleFiles) {
        Write-Error "No module files found. Run GetMidToolsModuleFiles task first."
        return
    }
    $BasePath = (Resolve-Path "$PSScriptRoot/..").Path
    foreach ($file in $Script:MidToolsModuleFiles) {
        $LocalFilePath = Join-Path -Path $BasePath -ChildPath ($file -replace 'PSSnow.MidTools/', '')
        if (Test-Path $LocalFilePath) {
            Write-Host "Uploading file: $file"
            $BlobName = $file
            Set-AzStorageBlobContent -File $LocalFilePath -Container $TemplateStorageContainerRef.Name -Blob $BlobName -Context $TemplateStorageContext -Force | Out-Null
            # Print the URL of the uploaded file
            $BlobUrl = ($TemplateStorageContainerRef.Context | Get-AzStorageBlob -Container $TemplateStorageContainerRef.Name -Blob $BlobName).ICloudBlob.Uri.AbsoluteUri
            Write-Host "Uploaded to: $BlobUrl"
        }
        else {
            Write-Warning "Local file not found: $LocalFilePath"
        }
    }
}

task CompressModuleToTemplateOutput ResolveModuleFiles, {
    assert $TemplateOutputPath 'Template output path is not set'
    assert $MidToolsPath 'MidToolsPath is not set'
    
    $ZipFileName = "PSSnow.MidTools.zip"
    $ZipFilePath = Join-Path -Path $TemplateOutputPath -ChildPath $ZipFileName
    if (Test-Path $ZipFilePath) {
        Remove-Item -Path $ZipFilePath -Force
    }
    
    Write-Host "Creating zip file: $ZipFilePath"
    $Script:MidToolsModuleFiles
    try{
        $pwd = Get-Location
        Set-Location -Path $Script:MidToolsBasePath
        Compress-Archive -Path $MidToolsContents -DestinationPath $ZipFilePath -Force
    }catch{
        Write-Error "Error creating zip file: $_"
    }finally{
        Set-Location -Path $pwd
        Write-Host "Zip file created at: $ZipFilePath"
    }
    # if (Test-Path $ZipFilePath) {
    #     Write-Host "Module compressed successfully to $ZipFilePath"
    #     $Script:ZipFilePath = $ZipFilePath
    # }
    # else {
    #     Write-Error "Failed to create zip file: $ZipFilePath"
    # }
}

task UploadZipToAzureStorage CompressModuleToTemplateOutput, GetTemplateStorageContext, {
    assert $TemplateOutputPath 'Template output path is not set'
    assert $TemplateStorageContainerRef 'Template storage container reference is not set'
    assert $TemplateStorageContext 'Template storage context is not set'
    $ZipFileName = "PSSnow.MidTools.zip"
    $ZipFilePath = Join-Path -Path $TemplateOutputPath -ChildPath $ZipFileName
    Write-Host "Uploading zip file to Azure Storage: $ZipFileName"
    Set-AzStorageBlobContent -File $ZipFilePath -Container $TemplateStorageContainerRef.Name -Blob $ZipFileName -Context $TemplateStorageContext -Force | Out-Null
    # Print the URL of the uploaded file
    $BlobUrl = ($TemplateStorageContainerRef.Context | Get-AzStorageBlob -Container $TemplateStorageContainerRef.Name -Blob $ZipFileName).ICloudBlob.Uri.AbsoluteUri
    Write-Host "Uploaded to: $BlobUrl"
}

function Generate-TemplateMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$TemplateInfo,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://raw.githubusercontent.com/example/repo/master"
    )
    # \
    
    # Ensure required properties exist
    if (-not $TemplateInfo.Name -or -not $TemplateInfo.Description) {
        throw "TemplateInfo must contain Name and Description properties"
    }
    $mainTemplateUrl = "${BaseUrl}/$($TemplateInfo.Name)/mainTemplate.json"
    $uiDefinitionUrl = "${BaseUrl}/$($TemplateInfo.Name)/createUiDefinition.json"
    Write-Host "Main Template URL: $mainTemplateUrl"
    Write-Host "UI Definition URL: $uiDefinitionUrl"

    $mainTemplateUrlEncoded = [System.Web.HttpUtility]::UrlEncode($mainTemplateUrl)
    $uiDefinitionUrlEncoded = [System.Web.HttpUtility]::UrlEncode($uiDefinitionUrl)
    # Build the deployment URLs

    $deployToAzureUrl = $TemplateInfo.DeploymentUrl -f $mainTemplateUrlEncoded, $uiDefinitionUrlEncoded
    $deployToAzureGovUrl = $deployToAzureUrl -replace "portal\.azure\.com", "portal.azure.us"
    $visualizeUrl = "http://armviz.io/#/?load=${mainTemplateUrlEncoded}"

    # Generate the markdown content
    $markdownContent = @"
---
description: ${($TemplateInfo.Description)}
page_type: sample
products:
- azure
- azure-resource-manager
urlFragment: $($TemplateInfo.Name)
languages:
- json
- bicep
---
# $($TemplateInfo.Name)

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)]($deployToAzureUrl)
[![Deploy To Azure Gov](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazuregov.svg?sanitize=true)]($deployToAzureGovUrl)
[![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.svg?sanitize=true)]($visualizeUrl)

$($TemplateInfo.Description)

This template uses Azure Resource Manager (ARM) templates compiled from Bicep source files to deploy ServiceNow MID Server infrastructure components.

## Template Details

- **Template Type**: $($TemplateInfo.UiDefType)
- **Base Template**: $($TemplateInfo.Name)
- **UI Definition**: $($TemplateInfo.UiDefinition)

## Prerequisites

Before deploying this template, ensure you have:

- An active Azure subscription
- Appropriate permissions to create resources in the target resource group
- ServiceNow instance credentials (if required by the template)

## Deployment

### Azure Portal

Click the "Deploy to Azure" button above to deploy this template through the Azure Portal with a guided UI experience.

### Azure CLI

``````bash
az deployment group create \
  --resource-group myResourceGroup \
  --template-uri ${BaseUrl}/$($TemplateInfo.Name)/mainTemplate.json \
  --parameters @parameters.json
``````

### Azure PowerShell

``````powershell
New-AzResourceGroupDeployment \
  -ResourceGroupName "myResourceGroup" \
  -TemplateUri "${BaseUrl}/$($TemplateInfo.Name)/mainTemplate.json" \
  -TemplateParameterFile "parameters.json"
``````

## Parameters

Refer to the template's parameter file and UI definition for required and optional parameters.

## Resources Created

This template creates Azure resources as defined in the Bicep source file. Review the compiled ARM template for specific resource details.

``Tags: servicenow, mid-server, azure, infrastructure, bicep, arm-template``
"@

    # Output the content
    if ($OutputPath) {
        $markdownContent | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Generated markdown documentation: $OutputPath"
    }
    else {
        return $markdownContent
    }
}

### Web Related Tasks - Uses ngrok and Pode to expose local web server for hosting templates
### Should only be used ad-hoc during development.

task ResolveNgrok {
    $WebServerState = Initialize-NgrokEnvironment -PodePort $PodePort
    $Script:NgrokRunning = $WebServerState.NgrokRunning
    $Script:NgrokPath = $WebServerState.NgrokPath
    $Script:NgrokTunnel = $WebServerState.NgrokTunnel
}

task StartNgrokTunnel ResolveNgrok, {
    $NgrokState = Start-NgrokTunnel -NgrokPath $Script:NgrokPath -PodePort $PodePort -NgrokRunning $Script:NgrokRunning
    $Script:NgrokTunnel = $NgrokState.NgrokTunnel
    $Script:NgrokRunning = $NgrokState.NgrokRunning
}

task ShutdownNgrok ResolveNgrok, {
    Stop-NgrokTunnel -NgrokRunning $Script:NgrokRunning
    $Script:NgrokRunning = $false
}

task ResolvePodeServer {
    $PodeState = Get-PodeServerStatus -PodePort $PodePort
    $Script:PodeJob = $PodeState.PodeJob
}

task StartPodeServer ResolvePodeServer, {
    $ScriptTemplatePaths = @{
        'midtools'  = "$PSScriptRoot/.."
        'templates' = $TemplateOutputPath
    }
    if (-not $Script:PodeJob) {
        $Script:PodeJob = Start-PodeServer -ScriptTemplatePaths $ScriptTemplatePaths -PodePort $PodePort -PodeJob $Script:PodeJob
    }
}

task TestPodeHookRoute StartNgrokTunnel, StartPodeServer, {
    $TestResult = $null
    $timeout = 10
    $elapsed = 0
    do {
        $TestResult = Test-PodeHookRoute -NgrokTunnel $Script:NgrokTunnel -ErrorAction SilentlyContinue
        if ($TestResult) { break }
        Start-Sleep -Seconds 1
        $elapsed++
    } while (-not $TestResult -and $elapsed -lt $timeout)
    if (-not $TestResult) {
        Write-Error 'PODE hook route test failed'
    }else{
        Write-Build Green "PODE hook route test succeeded $($TestResult | ConvertTo-Json -Depth 5)"
    }
}

task ShutdownPodeServer {
    Stop-PodeServer
}