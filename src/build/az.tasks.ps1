task AzResolveContext {
    if (Get-Command -Name Resolve-SNOWMidBuildContext -ErrorAction SilentlyContinue) {
        $AzBuildCtx = Resolve-SNOWMidBuildContext -ErrorAction SilentlyContinue
    }
    $Script:AzureSettings = $BuildSettings.azure
    $SettingsKeys = @{
        subscription_id   = $AzBuildCtx.StorageAccount.subscriptionId
        subscription_name = $AzBuildCtx.SubscriptionName
        resource_group    = $AzBuildCtx.StorageAccount.resourceGroup
    }
    $SettingsState = @{
        Status = 'Unknown'
    }
    foreach ( $key in $SettingsKeys.Keys) {
        if ($Script:AzureSettings.$key -and ($Script:AzureSettings.$key -eq $SettingsKeys[$key])) {
            $SettingsState[$key] = 'OK'
        }
        elseif ($Script:AzureSettings.$key) {
            $SettingsState[$key] = "Mismatch (Expected: $($SettingsKeys[$key]), Found: $($Script:AzureSettings.$key))"
            Write-Warning "Azure setting '$key' mismatch. Expected: $($SettingsKeys[$key]), Found: $($Script:AzureSettings.$key). Using value from real context."
            $Script:AzureSettings.$key = $SettingsKeys[$key]
            $SettingsState.Status = 'Error'
        }
        else {
            $SettingsState[$key] = 'Missing'
            $SettingsState.Status = 'Error'
        }
    }
    $SettingsState.Status = if ($SettingsState.Values -notcontains 'Missing' -and $SettingsState.Values -notcontains 'Mismatch (Expected:') { 'OK' } else { 'Error' }
    Write-Build Blue "Settings state: $($SettingsState | ConvertTo-Json -Depth 5)"
    $AzCtx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $AzCtx) {
        Write-Error "No Azure context found. Please login to Azure using Connect-AzAccount."
        return
    }
    if ($AzCtx.Subscription.Id -ne $Script:AzureSettings.subscription_id) {
        Set-AzContext -SubscriptionId $Script:AzureSettings.subscription_id -ErrorAction Stop
    }
    else {
        Write-Build Green "Azure context already set to subscription: $($AzCtx.Subscription.Name) ($($AzCtx.Subscription.Id))"
    }
}

task AzDeployServicePrincipal AzResolveContext, {
    $BicepSource = Join-Path $BicepPath 'azuread_serviceprincipals.bicep'
    $ParameterFile = Join-Path $SnowDataPath "azuread_serviceprincipals.$($env:SN_MID_ENVIRONMENT_NAME).parameters.json"
    if (!(Test-Path $BicepSource)) {
        Write-Error "Bicep file not found: $BicepSource"
        return
    }
    if (!(Test-Path $ParameterFile)) {
        Write-Error "Parameter file not found: $ParameterFile"
        return
    }
    $SPDeployParams = @{
        Name                  = 'SSDServicePrincipals-' + $env:SN_MID_ENVIRONMENT_NAME
        ResourceGroupName     = $AzureSettings.resource_group
        TemplateFile          = $BicepSource
        TemplateParameterFile = $ParameterFile
    }
    $Global:LastAzDeployment = New-AzResourceGroupDeployment @SPDeployParams -ErrorAction Stop
    $Global:LastAzDeployment
}

task AzDeployServicePrincipalSecret AzResolveContext, {
    $ParameterFile = Join-Path $SnowDataPath "azuread_serviceprincipals.$($env:SN_MID_ENVIRONMENT_NAME).parameters.json"
    $Global:ArmParams = (Get-Content -Path $ParameterFile | ConvertFrom-Json)
    Write-Host "Using parameters file: $ParameterFile - $($ArmParams | ConvertTo-Json -Depth 5)"
    if (-not ($AppName = $ArmParams.parameters.applicationName.value)) {
        Write-Error "Application name not found in parameters file: $ParameterFile"
        return
    }
    $AzureApp = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue
    $AzureSP = Get-AzADServicePrincipal -ApplicationId $AzureApp.AppId -ErrorAction SilentlyContinue
    $NewSecret = newAzServicePrincipalCredential -AppId $AzureApp.AppId -SecretName 'MidServerSecret' -RemoveExisting
    $AzContext = Get-AzContext
    if ($NewSecret.SecretText) {
        Write-Host "New secret created: $($NewSecret.SecretText.Substring(0, 10)).... Sleeping for 20 seconds to allow Azure to propagate the secret."
        Start-Sleep -Seconds 20
        $ServicePrincipalConfig = @{
            ClientSecret         = ($NewSecret.SecretText | ConvertTo-SecureString -AsPlainText -Force)
            TenantId             = $AzContext.Tenant.Id
            SubscriptionId       = $AzContext.Subscription.Id
            ClientId             = $AzureApp.AppId
            PrincipalId          = $AzureSP.Id
            AzureEnvironmentName = "AzureCloud"
            Metadata             = @{}
        }
        Set-SNOWMidAzureEnvironmentSecret @ServicePrincipalConfig
    }
    else {
        Write-Error "Failed to create new secret for Service Principal $($AzureApp.DisplayName)"
    }
}

task AzResolveSnowConnection SnowMidInitializeTools, {
    $Global:SCO = Resolve-SNOWMidEnvironmentAuth -ErrorAction SilentlyContinue
    if ($SCO.Credential) {
        $SCO.Credential = @{
            UserName = $SCO.Credential.UserName
            Password = $SCO.Credential.GetNetworkCredential().Password
        }
    }
    if ($SCO.Expires) {
        $SCO.Expires = (Get-Date $SCO.Expires).ToString("o") # Convert to ISO 8601 format
    }
}

task ResolveCurrentAzParameters AzResolveContext, {
    $BC = Resolve-SNOWMidBuildContext -ErrorAction SilentlyContinue
    $Tags = $BC.StorageAccount.tags
    $Global:ArmParams = ConvertTo-AzureDeploymentParameters -Tags $Tags
    Write-Host ($ArmParams | ConvertTo-Json -Depth 10)
}

function ConvertTo-AzureDeploymentParameters {
    param(
        [Parameter(Mandatory = $true)]
        $Tags,
        
        [Parameter(Mandatory = $false)]
        [string]$Location = "canadacentral",
        
        [Parameter(Mandatory = $false)]
        [bool]$RunValidationScript = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$DeployPermissions = $true,
        
        [Parameter(Mandatory = $false)]
        [bool]$DeployNetwork = $false
    )
    $inputData = $Tags
    
    # Parse admin entities from the comma-separated string
    $adminEntities = @()
    if ($inputData.SnowAdminEntities) {
        $entities = $inputData.SnowAdminEntities -split ','
        foreach ($entity in $entities) {
            $parts = $entity -split ':'
            if ($parts.Length -eq 2) {
                $adminEntities += @{
                    principalId   = $parts[0].Trim()
                    principalType = $parts[1].Trim()
                }
            }
        }
    }
    
    # Extract container registry details from the registry ID
    $registryIdParts = $inputData.SnowContainerRegistryId -split '/'
    $containerRegistrySubscription = $registryIdParts[2]
    $containerRegistryResourceGroup = $registryIdParts[4]
    $containerRegistryName = $registryIdParts[8]
    
    # Build the deployment parameters object
    $deploymentParameters = @{
        '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
        contentVersion = "1.0.0.0"
        parameters     = @{
            devopsEnvironmentName          = @{ value = $inputData.SnowEnvironment }
            location                       = @{ value = $Location }
            runValidationScript            = @{ value = $RunValidationScript }
            adminEntraEntities             = @{ value = $adminEntities }
            deployPermissions              = @{ value = $DeployPermissions }
            deployNetwork                  = @{ value = $DeployNetwork }
            snowHost                       = @{ value = $inputData.SnowHost }
            containerSubnetId              = @{ value = $inputData.SnowContainerSubnetId }
            additionalStorageSubnetIds     = @{ value = @() }
            containerRegistrySubscription  = @{ value = $containerRegistrySubscription }
            containerRegistryResourceGroup = @{ value = $containerRegistryResourceGroup }
            containerRegistryName          = @{ value = $containerRegistryName }
        }
    }
    
    # Convert to JSON and return
    return $deploymentParameters
}

task AzDeployEnvironment AzResolveSnowConnection, AzResolveContext, {
    $BicepSource = Join-Path $BicepPath 'azure_servicenow_mid_acs_full.bicep'
    $ParameterFile = Join-Path $SnowDataPath "azure_servicenow_mid_acs_full.$($env:SN_MID_ENVIRONMENT_NAME).parameters.json"
    $Global:ArmParams = (Get-Content -Path $ParameterFile | ConvertFrom-Json)
    if (-not ($ResourceGroup = Get-AzResourceGroup -Name $AzureSettings.resource_group -ErrorAction SilentlyContinue)) {
        Write-Host "Resource group $($AzureSettings.resource_group) does not exist. Creating it..."
        $ResourceGroup = New-AzResourceGroup -Name $AzureSettings.resource_group -Location $Global:ArmParams.parameters.location.value -ErrorAction Stop
    }
    $DeployParams = @{
        Name                  = 'SSDServiceNowMidACS-' + $env:SN_MID_ENVIRONMENT_NAME
        TemplateFile          = $BicepSource
        TemplateParameterFile = $ParameterFile
        ResourceGroupName     = $ResourceGroup.ResourceGroupName
        Location              = $ArmParams.parameters.location.value
        deployCredentials     = $true
        snowCredentialsJson   = ($SCO | ConvertTo-Json -Depth 5 | ConvertTo-SecureString -AsPlainText -Force)
    }
    Write-Host ($DeployParams | ConvertTo-Json -Depth 5)
    New-AzResourceGroupDeployment @DeployParams -Confirm:$true -ErrorAction Stop -Verbose
}

task AzDeployEnvironmentNoCreds AzResolveContext, {
    $BicepSource = Join-Path $BicepPath 'azure_servicenow_mid_acs_full.bicep'
    $ParameterFile = Join-Path $SnowDataPath "azure_servicenow_mid_acs_full.$($env:SN_MID_ENVIRONMENT_NAME).parameters.json"
    $Global:ArmParams = (Get-Content -Path $ParameterFile | ConvertFrom-Json)
    if (-not ($ResourceGroup = Get-AzResourceGroup -Name $AzureSettings.resource_group -ErrorAction SilentlyContinue)) {
        Write-Host "Resource group $($AzureSettings.resource_group) does not exist. Creating it..."
        $ResourceGroup = New-AzResourceGroup -Name $AzureSettings.resource_group -Location $Global:ArmParams.parameters.location.value -ErrorAction Stop
    }
    $DeployParams = @{
        Name                  = 'SSDServiceNowMidACS-' + $env:SN_MID_ENVIRONMENT_NAME
        TemplateFile          = $BicepSource
        TemplateParameterFile = $ParameterFile
        ResourceGroupName     = $AzureSettings.resource_group
        Location              = $ArmParams.parameters.location.value
        deployCredentials     = $false
    }
    Write-Host ($DeployParams | ConvertTo-Json -Depth 5)
    New-AzResourceGroupDeployment @DeployParams
}

task AzResolveMidServer {
    $Script:ContainerResults = Get-SNOWMidAzContainerRecord -ContainerName $MidServerName
    if ($Script:ContainerResults.count -eq 0) {
        Write-Build Yellow "Container group '$MidServerName' not found."
        return
    }
}

task AzResolveMidServerContext AzResolveContext, {
    $Script:BicepSource = Join-Path $BicepPath 'servicenow_mid_server_multiple.bicep'
    $Script:ParameterFile = Join-Path $SnowDataPath "azure_mid_servers.$($env:SN_MID_ENVIRONMENT_NAME).parameters.json"
    $Script:MidServerParams = (Get-Content -Path $Script:ParameterFile | ConvertFrom-Json).parameters.midServers.value
}

task AzDeployMidServers AzResolveMidServerContext, {
    $DeployParams = @{
        Name                  = 'SSDMIDServerDeploy-' + $env:SN_MID_ENVIRONMENT_NAME
        ResourceGroupName     = $AzureSettings.resource_group
        TemplateFile          = $BicepSource
        TemplateParameterFile = $ParameterFile
    }
    Write-Host ($DeployParams | ConvertTo-Json -Depth 5)
    New-AzResourceGroupDeployment @DeployParams -ErrorAction Stop
}

function Enter-AzContainerShell {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )
    $Script:ContainerExecCommand = "az container exec --exec-command /bin/pwsh --name $ContainerName --resource-group $($ContainerResults.resourceGroup) --subscription $($ContainerResults.subscriptionId)"
    Write-Host "Executing command: $($Script:ContainerExecCommand)"
    $Script:ContainerExecCommand | Invoke-Expression
}

function Get-AzMidLogs {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerName,
        [switch]$Follow
    )
    $Logs = Get-AzContainerInstanceLog -ContainerGroupName $ContainerName -ContainerName $ContainerName -ResourceGroupName $ContainerResults.resourceGroup -Tail 100 -Timestamp 
    $StampedLogs = foreach ($l in $Logs) {
        $Time = ($l -split ' ')[0]
    }
    $Cmd = "az container logs --name $ContainerName --resource-group $($ContainerResults.resourceGroup) --subscription $($ContainerResults.subscriptionId)"
    if ($Follow) {
        $Cmd += " --follow"
    }
    Write-Host "Executing command: $Cmd"
    $Cmd | Invoke-Expression
}

task AzEnterShell AzResolveMidServer, {
    assert ($ContainerResults.count -gt 0)
    $c = $ContainerResults[0]
    Enter-AzContainerShell -ContainerName $c.name
}

task AzGetLogs AzResolveMidServer, {
    assert ($ContainerResults.count -gt 0)
    $c = $ContainerResults[0]
    Get-AzMidLogs -ContainerName $c.name -Follow
}

task AzAttach AzResolveMidServer, {
    assert ($ContainerResults.count -gt 0)
    $c = $ContainerResults[0]
    az container attach --name $c.name --resource-group $c.resourceGroup --subscription $c.subscriptionId
}





task AzInvokeMidEccCommandTestAzPs {
    $TestCommand = [scriptblock] {
        $AzSecretPath = "/run/secrets/snow-azure"
        if (Test-Path $AzSecretPath) {
            $AzSecretContent = Get-Content -Path $AzSecretPath | ConvertFrom-Json
            $AzConnectParams = @{
                TenantId       = $AzSecretContent.AZURE_TENANT_ID
                SubscriptionId = $AzSecretContent.AZURE_SUBSCRIPTION_ID
            }
            if ($AzSecretContent.AZURE_CLIENT_ID -and $AzSecretContent.AZURE_CLIENT_SECRET) {
                $AzConnectParams.Credential = [PSCredential]::new($AzSecretContent.AZURE_CLIENT_ID, ($AzSecretContent.AZURE_CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force))
                $AzConnectParams.ServicePrincipal = $true
            }
            Write-Host "Connecting to Azure with Service Principal: $($AzConnectParams.Credential.UserName) in Tenant: $($AzConnectParams.TenantId)"
            Connect-AzAccount @AzConnectParams -ErrorAction Stop
        }
        else {
            Write-Warning "Azure secret file not found at $AzSecretPath"
        }
        if ($env:IDENTITY_SERVER_THUMBPRINT) {
            Connect-AzAccount -Identity | Out-Null
        }
        $Output = [hashtable]@{}
        $Output.AzContext = Get-AzContext -ErrorAction SilentlyContinue
        $Output
    }
    $Global:PP = Invoke-SNOWMidPowerShellCommand -MidServerName $MidServerName -Command $TestCommand
    $PP.StdOut
}

task AzInvokeMidPodman {
    $Global:CCC = Invoke-SNOWMidPowerShellCommand -MidServerName $MidServerName -Command {
        Write-Host "Testing Podman Execution"
    } -UsePodmanExec
    $CCC
}

task AzClearPermissions AzResolveContext, SnowMidInitializeTools, {
    $Ctx = Resolve-SNOWMidBuildContext
    $Identities = Get-AzUserAssignedIdentity | Where-Object { $_.PrincipalId -in $Ctx.ManagedIdentities.properties.principalId }
    if ($Identities) {
        foreach ($Identity in $Identities) {
            Write-Host "Fixing permissions for identity $($Identity.Name)"
            $RoleAssignments = Get-AzRoleAssignment -ObjectId $Identity.PrincipalId -ErrorAction SilentlyContinue
            if ($RoleAssignments) {
                foreach ($RoleAssignment in $RoleAssignments) {
                    Write-Host "Removing role assignment: $($RoleAssignment.RoleDefinitionName) for $($RoleAssignment.Scope)"
                    $RoleAssignment | Remove-AzRoleAssignment -ErrorAction SilentlyContinue
                }
            }
        }
    }
    else {
        Write-Host 'No identities found to fix permissions'
    }
}

function newAzServicePrincipalCredential {
    param (
        [string]$AppId,
        [string]$SecretName,
        [switch]$RemoveExisting
    )
    $ExistingSecret = Get-AzADAppCredential -ApplicationId $AppId | Where-Object { $_.DisplayName -eq $SecretName }
    if ($ExistingSecret) {
        Write-Host "Secret $SecretName already exists - $($ExistingSecret.KeyId) - Clearing First"
        if ($RemoveExisting) {
            foreach ($cred in $ExistingSecret) {
                Remove-AzADAppCredential -ApplicationId $AppId -KeyId $cred.KeyId
            }
        }
    }
    $passwordStartDate = Get-Date
    $passwordEndDate = $passwordStartDate.AddMonths(36)
    $credentialProperties = New-Object Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential
    $credentialProperties.DisplayName = $SecretName
    $credentialProperties.StartDateTime = $passwordStartDate
    $credentialProperties.EndDateTime = $passwordEndDate
    $webApiSecret = New-AzADAppCredential -PasswordCredentials $credentialProperties -ApplicationId $AppId
    $webApiSecret
}