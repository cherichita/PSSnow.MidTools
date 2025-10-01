
# PSSnow.MidTools Module
$Script:ArmQueries = @{
    AllEnvironments = @"
        resources
| where type =~ "microsoft.storage/storageaccounts"
  and isnotempty(tags.SnowEnvironment)
| join kind=leftouter (
    resourcecontainers
    | where type == "microsoft.resources/subscriptions"
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project
   snowEnvironment = tags.SnowEnvironment,
    snowHost = tags.SnowHost,
    subscriptionName,
    subscriptionId,
    resourceGroup,
    location,
    id,
    tags
| order by tostring(snowEnvironment) asc, resourceGroup asc
"@
    Resources       = @"
        resources | where tags['SnowEnvironment'] == '{0}'
        | project resourceId=id, name, type, resourceGroup, tags, properties, subscriptionId, location
        | order by type asc, name asc
"@
}

# Initialization function for SNOWMidTools
function Initialize-SNOWMidTools {
    if (!(Get-Command -Name 'Write-PSFMessage' -ErrorAction SilentlyContinue)) {
        if (Get-Module -Name 'PSFramework' -ListAvailable -ErrorAction SilentlyContinue) {
            Import-Module -Name 'PSFramework' -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "PSFramework module not found. Installing..."
            Install-Module -Name PSFramework -Force -AllowClobber -Scope CurrentUser
            Import-Module -Name PSFramework -Force -ErrorAction SilentlyContinue
        }
        Write-Host 'PSFramework module was not found. Installing into CurrentUser scope.'
    }
    # When using this as a Module, you must use Import-Module with the -Force parameter,
    # to ensure the module is reloaded if changing any of the SN_MID_* environment variables.
    $DefaultEnv = @{
        SN_MID_ENVIRONMENT_NAME  = 'local'
        SN_MID_CONTEXT           = 'local'
        SN_MID_BUILD_STRATEGY    = 'podman'
        SN_MID_IMAGE_NAME        = 'snow_mid_base'
        SN_MID_CUSTOM_IMAGE_NAME = 'snow_mid_custom'
    }
    foreach ($key in $DefaultEnv.Keys) {
        $envValue = [Environment]::GetEnvironmentVariable($key, [System.EnvironmentVariableTarget]::Process)
        if ([string]::IsNullOrEmpty($envValue)) {
            Write-PSFMessage -Level Verbose "$key is not set. Defaulting to '$($DefaultEnv[$key])'."
            Set-Variable -Name $key -Scope Script -Value $DefaultEnv[$key]
        }
        else {
            Write-PSFMessage -Level Verbose "$key is set to '$envValue'."
            Set-Variable -Name $key -Scope Script -Value $envValue
        }
    }

    $Script:SN_MID_VAULT_NAME = "snmidvault-${SN_MID_ENVIRONMENT_NAME}-${SN_MID_CONTEXT}".ToLower()
    $Script:SN_CONNECTION_SECRET_NAME = "snow-connection-${SN_MID_ENVIRONMENT_NAME}-json".ToLower()
    $Script:AZ_CONNECTION_SECRET_NAME = "az-connection-${SN_MID_ENVIRONMENT_NAME}-json".ToLower()
    $Script:PSDependencies = @{
        'cherichita/PSSnow'                     = @{
            Source     = 'GitHubRepo'
            Repository = 'cherichita/PSSnow'
            Version    = '1.4.0'
            Target     = 'CurrentUser'
            Parameters = @{
                ExtractPath = 'src/'
                TargetType  = 'Parallel'
            }
        }
        'Microsoft.PowerShell.SecretManagement' = @{
            Target = 'CurrentUser'
        }
        'Microsoft.PowerShell.SecretStore'      = @{
            Target = 'CurrentUser'
        }
    }
    $Script:SnowEnvironmentAuth = $null
    $Script:SNMIDBuildContext = $null
    $Script:SnowAzContext = $null
    Write-PSFMessage -Level Important -Message "SNMIDBuildContext and SnowAzContext initialized. With parameters $(Get-SNOWMidToolsStatus | ConvertTo-Json -Depth 5)"
}

function Get-SNOWMidToolsStatus {
    $Status = [ordered]@{
        SN_MID_ENVIRONMENT_NAME  = $Script:SN_MID_ENVIRONMENT_NAME
        SN_MID_CONTEXT           = $Script:SN_MID_CONTEXT
        SN_MID_BUILD_STRATEGY    = $Script:SN_MID_BUILD_STRATEGY
        SN_MID_IMAGE_NAME        = $Script:SN_MID_IMAGE_NAME
        SN_MID_CUSTOM_IMAGE_NAME = $Script:SN_MID_CUSTOM_IMAGE_NAME
        SN_MID_VAULT_NAME        = $Script:SN_MID_VAULT_NAME
        BasePath                 = $PSScriptRoot
    }
    return $Status
}

# Section 1: Azure/Build Functions
function Assert-SNOWMIDAzCli {
    if (!(Get-Command -Name 'az' -ErrorAction SilentlyContinue)) {
        Write-PSFMessage -Level Warning -Message 'Azure CLI not found. Installing Azure CLI'
        Resolve-SNOWMIDAzureCli | Out-Null
        Connect-SNOWMIDAzureFromEnvironment | Out-Null
    }
}

function Resolve-SNOWMIDVault {
    switch ($Script:SN_MID_CONTEXT) {
        'local' {
            $VaultParameters = @{
                VaultName = $SN_MID_VAULT_NAME
            }
            Resolve-SNOWMidSecretManagementVault @VaultParameters -ErrorAction SilentlyContinue
        }
        'azure' {
            if (!$Script:SNMIDBuildContext.KeyVault.name) {
                Write-Error "Key Vault not found for environment $($env:SN_MID_ENVIRONMENT_NAME)"
                return $null
            }
            $VaultParameters = @{
                VaultName           = $SN_MID_VAULT_NAME
                AzureKeyVaultName   = $Script:SNMIDBuildContext.KeyVault.Name
                AzureSubscriptionId = $Script:SNMIDBuildContext.SubscriptionId
                UseAzureKeyVault    = $true
            }
            Resolve-SNOWMidSecretManagementVault @VaultParameters -ErrorAction SilentlyContinue
        }
        default {
            Write-Error "Unknown context type: $Script:SN_MID_CONTEXT. Use 'local' or 'azure'."
            return $null
        }
    }
}

function Resolve-SNOWMIDPrereqs {
    if (-not (Get-Command 'Install-Dependency' -ErrorAction SilentlyContinue)) {
        Write-PSFMessage -Level Important 'Installing PSDepend module'
        Install-Module -Name PSDepend -Force -AllowClobber -Scope CurrentUser
    }
    Import-Module -Name PSDepend -Force -ErrorAction SilentlyContinue -Scope Global
    Get-Dependency -InputObject $Script:PSDependencies | Install-Dependency
}

function Resolve-SNOWMIDAzureCli {
    if (-not (Get-Command 'az' -ErrorAction SilentlyContinue)) {
        Write-PSFMessage -Level Important 'Azure CLI not found. Installing Azure CLI'
        if ((Get-Command -Name apt -ErrorAction SilentlyContinue)) {
            Write-PSFMessage -Level Important 'Installing Azure CLI using apt'
            $InstallResults = (curl -sL https://aka.ms/InstallAzureCLIDeb | bash)
        }
    }
}

function Connect-SNOWMIDAzureFromEnvironment {
    param ([string]$Scope = 'Process', [switch]$Force)
    $AzCliExists = (Get-Command 'az' -ErrorAction SilentlyContinue)
    $Out = [ordered]@{ 
        TenantId    = $env:AZURE_TENANT_ID
        Environment = $env:SN_MID_ENVIRONMENT_NAME
        AzContext   = (Get-AzContext -ErrorAction SilentlyContinue)
        CliContext  = if ($AzCliExists) { (az account show -o json 2>&1 | ConvertFrom-Json) } else { $null }
    }
    if ( $Out.AzContext -and !$Force.IsPresent) {
        $Out.TenantId = $Out.AzContext.Tenant.Id
        Write-PSFMessage -Level Verbose "Using Existing Azure context: $($Out.AzContext.Name)`n CLI Context: $($Out.CliContext | ConvertTo-Json -Depth 5)"
        return $Out
    }
    if ($env:IDENTITY_HEADER) {
        if ($env:AZURE_CLIENT_ID -and $env:AZURE_CLIENT_SECRET -and $env:AZURE_TENANT_ID) { 
            Write-PSFMessage -Level Important 'Ignoring MSI. Using environment variables instead' 
        }
        else {
            if (($AzCliExists) -and !($Out.CliContext)) {
                $Out.CliContext = az login --identity | ConvertFrom-Json | Select-Object -First 1
                $Out.CliVersion = az version | ConvertFrom-Json
            }
            $Out.AzContext = Connect-AzAccount -Identity -Scope $Scope -ErrorAction SilentlyContinue
            $Script:SnowAzContext = $Out
            return $Out
        }
    }
    if (-not ($env:AZURE_CLIENT_ID -and $env:AZURE_CLIENT_SECRET -and $env:AZURE_TENANT_ID)) {
        if (!$Out.AzContext -and ($AzCliExists -and !($Out.CliContext))) {
            Write-PSFMessage -Level Warning 'No Azure context found. AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID must be set'
            return $null
        }
        else {
            Write-PSFMessage -Level Important "Using Existing Azure context: $($Out.AzContext.Name)`n CLI Context: $($Out.CliContext | ConvertTo-Json -Depth 5)"
            return $Out
        }
    }
    if ($AzCliExists -and !($Out.CliContext)) {
        $Out.CliContext = az login --service-principal --username $env:AZURE_CLIENT_ID --password $env:AZURE_CLIENT_SECRET --tenant $env:AZURE_TENANT_ID | ConvertFrom-Json | Select-Object -First 1
        $Out.CliVersion = az version | ConvertFrom-Json
    }
    $LoginParams = @{
        TenantId = $env:AZURE_TENANT_ID; ServicePrincipal = $true
        Credential = (New-Object PSCredential $env:AZURE_CLIENT_ID, ($env:AZURE_CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force))
        Scope = $Scope
    }
    if ($env:AZURE_SUBSCRIPTION_ID) { $LoginParams.Subscription = $env:AZURE_SUBSCRIPTION_ID }
    
    $Out.AzContext = Connect-AzAccount @LoginParams
    $Script:SnowAzContext = $Out
    return $Out
}

function Get-SNOWMidAllEnvironments {
    return Search-AzGraph -Query $Script:ArmQueries.AllEnvironments -UseTenantScope
}

function Resolve-SNOWMIDCustomResources {
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName = $env:AZURE_RESOURCE_GROUP_NAME
    )
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Write-PSFMessage -Level Warning 'No Azure context found. Please login to Azure'
        return $null
    }
    $SubscriptionId = if ($SubscriptionId) { $SubscriptionId } else { $ctx.Subscription.Id }
    if (-not $SubscriptionId) {
        Write-PSFMessage -Level Warning 'No Subscription ID found. Please login to Azure'
        return $null
    }

    $ResourceQuery = $Script:ArmQueries.Resources -f $Script:SN_MID_ENVIRONMENT_NAME

    Write-PSFMessage "Querying Azure Resource Graph with query: `n$ResourceQuery. First in active subscription only: $($SubscriptionId)" -Level Verbose
    $resources = Search-AzGraph -Query $ResourceQuery

    if ($resources.Count -eq 0) {
        Write-PSFMessage -Level Warning "No resources found for environment ${Script:SN_MID_ENVIRONMENT_NAME} in current subscription $SubscriptionId. Using  -UseTenantScope to search all subscriptions in tenant."
        $resources = Search-AzGraph -Query $ResourceQuery -UseTenantScope
        if ( $resources.Count -eq 0) {
            Write-Error "No resources found for environment ${Script:SN_MID_ENVIRONMENT_NAME} in any subscription in the current tenant."
            return $null
        }
    }

    $Outputs = [ordered]@{
        SubscriptionName = $ctx.Subscription.Name
        SubscriptionId   = $SubscriptionId
        ResourceGroup    = $ResourceGroupName
        EnvironmentName  = $Script:SN_MID_ENVIRONMENT_NAME
        StorageAccount   = $resources | Where-Object { $_.type -eq 'microsoft.storage/storageaccounts' } | Select-Object -First 1   
    }

    if (-not $Outputs.StorageAccount) {
        Write-Error "No Storage Account found for environment ${Script:SN_MID_ENVIRONMENT_NAME}. Has this environment been provisioned?" -ErrorAction Stop
    }
    else {
        if($Outputs.SubscriptionId -ne $Outputs.StorageAccount.subscriptionId) {
            Write-PSFMessage -Level Warning "Storage Account $($Outputs.StorageAccount.name) is in subscription $($Outputs.StorageAccount.subscriptionId), but current subscription is $($Outputs.SubscriptionId). Updating SubscriptionId to match Storage Account."
            $Outputs.SubscriptionName = (Get-AzSubscription -SubscriptionId $Outputs.StorageAccount.subscriptionId -ErrorAction SilentlyContinue).Name
            $Outputs.SubscriptionId = $Outputs.StorageAccount.subscriptionId
            Set-AzContext -SubscriptionId $Outputs.SubscriptionId | Out-Null
        }
        $Outputs.ResourceGroup = $Outputs.StorageAccount.resourceGroup
        $ContainerRegistryId = $Outputs.StorageAccount.tags.SnowContainerRegistryId
        $Outputs += @{
            KeyVault          = $resources | Where-Object { $_.type -eq 'microsoft.keyvault/vaults' -and $_.subscriptionId -eq $Outputs.SubscriptionId } | Select-Object -First 1
            ManagedIdentities = $resources | Where-Object { $_.type -eq 'microsoft.managedidentity/userassignedidentities' -and $_.subscriptionId -eq $Outputs.SubscriptionId }
            DevopsIdentity    = $resources | Where-Object { $_.type -eq 'microsoft.managedidentity/userassignedidentities' -and $_.name -like "*devops-${Script:SN_MID_ENVIRONMENT_NAME}*" -and $_.subscriptionId -eq $Outputs.SubscriptionId } | Select-Object -First 1
            MidIdentity       = $resources | Where-Object { $_.type -eq 'microsoft.managedidentity/userassignedidentities' -and $_.name -like "*midserver-${Script:SN_MID_ENVIRONMENT_NAME}*" -and $_.subscriptionId -eq $Outputs.SubscriptionId } | Select-Object -First 1
        }
        $Outputs.ContainerRegistry = if ($ContainerRegistryId) {
            Get-AzResource -ResourceId $ContainerRegistryId -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        else {
            Write-PSFMessage -Level Warning "No Container Registry found for $($Outputs.StorageAccount.name)"
        }
        $Outputs.ContainerSubnet = if ($Outputs.StorageAccount.tags.SnowContainerSubnetId) {
            Get-AzResource -ResourceId $Outputs.StorageAccount.tags.SnowContainerSubnetId -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        else {
            Write-PSFMessage -Level Warning "No Container Subnet found for $($Outputs.StorageAccount.name)"
        }
    }
    if (-not $Outputs.KeyVault) {
        Write-PSFMessage -Level Error "No Key Vault found for environment ${Script:SN_MID_ENVIRONMENT_NAME}" -ErrorAction Stop
    }
    if (-not $Outputs.ContainerRegistry) {
        Write-PSFMessage -Level Warning "No Container Registry found for environment ${Script:SN_MID_ENVIRONMENT_NAME}" -ErrorAction Stop
    }
    $Outputs.Raw = $resources
    $Outputs
}


function Resolve-SNOWMIDBuildContext {
    param (
        [string]$SubscriptionId,
        [string]$ResourceGroupName = $env:AZURE_RESOURCE_GROUP_NAME,
        [switch]$ReloadContext
    )
    if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue)) {
        Install-Module -Name Az -Force -AllowClobber -Scope CurrentUser
    }
    if ($Script:SNMIDBuildContext -and -not $ReloadContext.IsPresent) {
        Write-PSFMessage -Level Verbose -Message "Using cached build context for environment $($Script:SN_MID_ENVIRONMENT_NAME) from `$Script:SNMIDBuildContext"
        return $Script:SNMIDBuildContext
    }
    $Outputs = [ordered]@{
        EnvironmentName = $Script:SN_MID_ENVIRONMENT_NAME
        SubscriptionId  = $SubscriptionId
        BuildStrategy   = $Script:SN_MID_BUILD_STRATEGY 
        ImageName       = $Script:SN_MID_IMAGE_NAME
        CustomImageName = $Script:SN_MID_CUSTOM_IMAGE_NAME
        WorkDir         = ($env:AZ_SCRIPTS_PATH_OUTPUT_DIRECTORY ?? $env:TEMP ?? '/tmp')
    }
    switch ($Script:SN_MID_CONTEXT) {
        'local' {
            $Outputs.ContainerRegistry = @{
                name              = 'local'
                resourceGroupName = 'local'
                subscriptionId    = 'local'
            }
            $Outputs.ContainerSubnet = @{
                name              = 'local'
                resourceGroupName = 'local'
                subscriptionId    = 'local'
            }
        }
        'azure' {
            $ctx = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $ctx) {
                Write-PSFMessage -Level Warning 'No Azure context found. Please login to Azure'
            }
            $SubscriptionId = if ($SubscriptionId) { $SubscriptionId } else { $ctx.Subscription.Id }
            if (-not $SubscriptionId) {
                Write-PSFMessage -Level Warning 'No Subscription ID found. Please login to Azure'
                return $null
            }
            try {
                $ContextResources = Resolve-SNOWMIDCustomResources -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
                foreach ($k in $ContextResources.Keys) {
                    $Outputs[$k] = $ContextResources[$k]
                }
            }
            catch {
                Write-PSFMessage -Level Warning "Error Fetching AZ Resources${Script:SN_MID_ENVIRONMENT_NAME}. Error: $_"
            }
        }
        default {
            Write-Error "Unknown context type: $Script:SN_MID_CONTEXT. Use 'local' or 'azure'."
            return $null
        }
    }
    $Script:SNMIDBuildContext = $Outputs
    $Outputs.Vault = Resolve-SNOWMIDVault -ContextType $Script:SN_MID_CONTEXT
    $Outputs
}

function Get-SNOWMIDPfxCertificateAsPem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificateName
    )
    $KeyVaultName = $Script:SNMIDBuildContext.KeyVault.Name
    if (-not $KeyVaultName) {
        Write-Error 'KeyVaultName is required'
        return $null
    }
    if ($Cert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -ErrorAction SilentlyContinue) {
        $LeafCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $CertBytes = [Convert]::FromBase64String((Get-AzKeyVaultSecret -SecretId $Cert.SecretId -AsPlainText))
        # Must use Exportable flag to export the private key on Windows/MacOS
        $Pfx = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $LeafCollection.Add($Pfx) | Out-Null
        return @($LeafCollection.ExportCertificatePems(), $LeafCollection[0].PrivateKey.ExportPkcs8PrivateKeyPem()) -join "`n"
    }
    else {
        Write-PSFMessage -Level Warning "Certificate $CertificateName not found in Key Vault $KeyVaultName"
        $null
    }
}

function Resolve-SNOWMIDAcrImageState {
    $BuildContext = Resolve-SNOWMIDBuildContext
    if (-not $BuildContext.ContainerRegistry.ResourceGroupName) {
        Write-PSFMessage -Level Warning "No Container Registry found for ${Script:SN_MID_ENVIRONMENT_NAME}"
        return $null
    }
    $ContainerRegistry = $BuildContext.ContainerRegistry
    $Acr = Get-AzContainerRegistry -ResourceGroupName $ContainerRegistry.ResourceGroupName -Name $ContainerRegistry.name -SubscriptionId $ContainerRegistry.subscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if (-not $Acr) {
        Write-PSFMessage -Level Warning "No Container Registry found for ${Script:SN_MID_ENVIRONMENT_NAME}"
        return $null
    }
    $Images = Get-AzContainerRegistryRepository -RegistryName $ContainerRegistry.name
    $Images | ForEach-Object { Get-AzContainerRegistryTag -RegistryName $ContainerRegistry.name -RepositoryName $_ } `
    | ForEach-Object { 
        $its = @{
            Name     = $_.ImageName
            Tags     = [System.Collections.Generic.List[hashtable]]::new()
            Registry = $_.Registry
        }
        foreach ($t in $_.Tags) {
            $its.Tags.Add(@{Name = $t.Name; Digest = $t.Digest })
        }
        $its
    }
}

function Resolve-SNOWMIDImageState {
    param (
        [string]$BuildStrategy = $env:SN_MID_BUILD_STRATEGY
    )
    $BuildContext = Resolve-SNOWMIDBuildContext
    $images = switch ($BuildStrategy) {
        'acr' {
            $ImageRepo = "$($BuildContext.ContainerRegistry.properties.loginServer)/"
            Resolve-SNOWMIDAcrImageState -BuildContext $BuildContext
        }
        'podman' {
            $ImageRepo = 'localhost/'
            Get-DockerPodmanImageState -BuildContext $BuildContext
        }
        'docker' {
            $ImageRepo = ''
            Get-DockerPodmanImageState -BuildContext $BuildContext
        }
        default {
            throw "Unknown build strategy: $BuildStrategy"
        }
    }
    $midVersion = Get-SNOWMidVersion
    $BuildContext.ImageState = @{
        BuildStrategy             = $BuildStrategy
        AcrRepo                   = $BuildContext.ContainerRegistry.properties.loginServer
        ImageRepo                 = $ImageRepo
        Images                    = $images
        MidVersion                = $midVersion
        MidImageFacts             = (Get-SNOWMIDDownloadFacts -BuildTag $midVersion)
        DockerContext             = (Join-Path $BuildContext.WorkDir $midVersion)
        BaseImageUri              = "${ImageRepo}$($BuildContext.ImageName):$($midVersion)"
        CustomImageUri            = "${ImageRepo}$($BuildContext.CustomImageName):$($midVersion)"
        BaseImageEnvironmentUri   = "${ImageRepo}$($BuildContext.ImageName):$($BuildContext.EnvironmentName)"
        CustomImageEnvironmentUri = "${ImageRepo}$($BuildContext.CustomImageName):$($BuildContext.EnvironmentName)"
        BaseImage                 = ($images | Where-Object { $_.Name -eq $BuildContext.ImageName })
        CustomImage               = ($images | Where-Object { $_.Name -eq $BuildContext.CustomImageName })
    }
    $BuildContext.ImageState
}

function Get-SNOWMidVersion {
    (Get-SNOWObject -Table 'sys_properties' -Query 'name=mid.version' -Fields 'value' -ErrorAction SilentlyContinue)  | Select-Object -ExpandProperty value
}

function Build-SNOWMIDImageCommon {
    param(
        [string]$Strategy,
        [string]$ImageName,
        [string]$ImageTag,
        [string[]]$ImageAdditionalTags = @(),
        [hashtable]$BuildContext,
        [string]$DockerContext,
        [string]$DockerFile,
        [string]$PodmanIsolation = 'chroot'
    )
    switch ($Strategy) {
        'acr' {
            Assert-SNOWMIDAzCli
            $dockerFile = (Join-Path $DockerContext $DockerFile)
            $buildCommand = 'az'
            $buildParams = @(
                'acr', 'build', '--registry', $BuildContext.ContainerRegistry.name,
                '--image', "$($ImageName):$ImageTag", '--subscription', $BuildContext.ContainerRegistry.subscriptionId,
                '--file', $dockerFile, $DockerContext
            )
        }
        'podman' {
            $buildCommand = 'podman'
            $buildParams = @(
                'build', '--format', 'docker', "--isolation=${PodmanIsolation}", '--tag', "${ImageName}:${ImageTag}",
                '-f', $DockerFile, $DockerContext
            )
        }
        'docker' {
            $buildCommand = 'docker'
            $LocalImageName = $ImageName -split '/' | Select-Object -Last 1
            $buildParams = @(
                'build', '--tag', "${LocalImageName}:${ImageTag}",
                '-f', (Join-Path $DockerContext $DockerFile), $DockerContext
            )
        }
        default {
            throw "Unknown build strategy: $Strategy"
        }
    }
    Write-PSFMessage -Level Important "Executing $buildCommand $($buildParams -join ' ')"
    (& $buildCommand @buildParams | Tee-Object -Variable Result | Write-Verbose ) 
    if ($Result) {
        Write-PSFMessage -Level Important "Image $($ImageName):$ImageTag built successfully"
    }
    else {
        Write-Error "Failed to build image $($ImageName):$ImageTag"
    }
    $Result
}

function Expand-SNOWMIDArchive {
    param(
        [string]$Path,
        [string]$OutputPath
    )
    $ExpandCmd = Get-Command -Name 'Expand-Archive' -ErrorAction SilentlyContinue
    if (!$ExpandCmd) {
        Write-PSFMessage -Level Warning "Expand-Archive not found. Using unzip instead."
        apt update -y && apt install unzip -y | Write-Verbose
    }
    else {
        if ($ExpandCmd.Parameters.OutputPath) {
            # PSCX module
            Expand-Archive -Path $Path -OutputPath $OutputPath -Force
        }
        elseif ($ExpandCmd.Parameters.DestinationPath) {
            # PowerShell 5.1
            Expand-Archive -Path $Path -DestinationPath $OutputPath -Force
        }
    }
}

function Build-SNOWMidImage {
    param(
        [switch]$ForceBuildBase,
        [switch]$ForceBuildCustom,
        [string]$BuildStrategy = $env:SN_MID_BUILD_STRATEGY
    )
    $BuildContext = Resolve-SNOWMIDBuildContext
    $ImageState = Resolve-SNOWMIDImageState -BuildContext $BuildContext -BuildStrategy $BuildStrategy
    if ($env:SN_MID_FORCE_BUILD_BASE -eq 'true') {
        $ForceBuildBase = $true
    }
    if ($env:SN_MID_FORCE_BUILD_CUSTOM -eq 'true') {
        $ForceBuildCustom = $true
    }
    if ($ForceBuildBase -or (-not $ImageState.BaseImage -or (-not ($ImageState.BaseImage.Tags.Name.Contains($ImageState.MidVersion))))) {
        Write-PSFMessage -Level Important "Building $($BuildContext.ImageName) image with tag $($ImageState.MidVersion)"
        if (-not (Test-Path $ImageState.DockerContext)) {
            New-Item -Path $ImageState.DockerContext -ItemType Directory -Force | Out-Null
        }
        $BaseDockerFile = 'Dockerfile'
        if (-not (Test-Path ("$($ImageState.DockerContext)/$BaseDockerFile"))) {
            # Download file from ImageState facts
            $ArchivePath = "$($BuildContext.WorkDir)/$($ImageState.MidImageFacts.PackageFileName)"
            Invoke-WebRequest -Uri $ImageState.MidImageFacts.PackageUri -OutFile $ArchivePath
            Write-PSFMessage -Level Important "Extracting $($ImageState.MidImageFacts.PackageFileName) to $($ImageState.DockerContext)"
            Expand-SNOWMIDArchive -Path $ArchivePath -OutputPath $ImageState.DockerContext -Force
        }
        $BuildContext.BaseImageBuild = Build-SNOWMIDImageCommon -Strategy $BuildStrategy -ImageName $BuildContext.ImageName -ImageTag $ImageState.MidVersion -BuildContext $BuildContext -DockerContext $ImageState.DockerContext -DockerFile $BaseDockerFile
    }
    if ($ForceBuildCustom -or (-not $ImageState.CustomImage -or (-not ($ImageState.CustomImage.Tags.Name.Contains($ImageState.MidVersion))))) {
        $customDockerContent = Get-DockerPodmanDockerFileContent
        if ($customDockerContent) {
            $lines = $customDockerContent.Split("`n")
            $fromLineIndex = $lines.IndexOf(($lines | Where-Object { $_ -match '^FROM\s' }))
            $baseFirstLine = "FROM $($ImageState.BaseImageUri)"
            if ($BuildStrategy -eq 'docker') {
                # Docker requires the image name to not have a registry/repo prefix if it's localhost
                $baseFirstLine = ($baseFirstLine -replace 'FROM localhost/', 'FROM ')
            }
            if ($fromLineIndex -ge 0 -and $lines[$fromLineIndex] -ne $baseFirstLine) {
                Write-PSFMessage -Level Important "Updating custom Dockerfile with correct base Image $($ImageState.BaseImageUri)"
                $lines[$fromLineIndex] = $baseFirstLine
                $customDockerContent = $lines -join "`n"
            }
            Write-Host $customDockerContent
            if (-not (Test-Path $ImageState.DockerContext)) {
                New-Item -Path $ImageState.DockerContext -ItemType Directory -Force | Out-Null
            }
            $customDockerFilePath = (Join-Path $ImageState.DockerContext 'Dockerfile.midcustom')
            $customDockerContent | Out-File -FilePath $customDockerFilePath -Force -Encoding utf8
            $BuildContext.CustomImageBuild = Build-SNOWMIDImageCommon -Strategy $BuildStrategy -ImageName $BuildContext.CustomImageName -ImageTag $ImageState.MidVersion -BuildContext $BuildContext -DockerContext $ImageState.DockerContext -DockerFile 'Dockerfile.midcustom' -PodmanIsolation 'oci'
        }
        else {
            Write-PSFMessage -Level Warning 'No custom Dockerfile found. Skipping custom image build'
        }
    }
    $ImageState = Resolve-SNOWMIDImageState -BuildContext $BuildContext -BuildStrategy $BuildStrategy

    function TagImage($Source, $Dest) {
        $cmd = switch ($BuildStrategy) {
            'acr' { 
                Assert-SNOWMIDAzCli
                $dest = if ($dest -match '.*/') { $dest -replace '.*/', '' } else { $dest }
                "az acr import --name $($BuildContext.ContainerRegistry.name) --source $Source --image $Dest --force --subscription $($BuildContext.ContainerRegistry.subscriptionId)"
            }
            'podman' {
                "podman tag $Source $Dest"
            }
            'docker' {
                $Source = $Source -replace 'localhost/', ''
                $Dest = $Dest -replace 'localhost/', ''
                "docker tag $Source $Dest"
            }
            default {
                throw "Unknown build strategy: $($BuildStrategy)"
            }
        }
        Write-PSFMessage -Level Important "Tagging image $Source with tag $Dest - Command: $cmd"
        (Invoke-Expression $cmd) | Tee-Object -Variable Result | Write-Verbose
        $Result
    }
    $BaseImageTag = $ImageState.BaseImage.Tags | Where-Object { $_.Name -eq $imageState.MidVersion }
    $BaseImageEnvironmentTag = $ImageState.BaseImage.Tags | Where-Object { $_.Name -eq $BuildContext.EnvironmentName }
    if ($BaseImageTag -and $BaseImageEnvironmentTag -and ($BaseImageTag.Digest -eq $BaseImageEnvironmentTag.Digest)) {
        Write-PSFMessage -Level Important "Image $($BuildContext.ImageName):$($BuildContext.EnvironmentName) already exists. Skipping tagging."
    }
    else {
        $BuildContext.BaseTagResult = TagImage -Source $ImageState.BaseImageUri -Dest $ImageState.BaseImageEnvironmentUri
    }
    
    $CustomImageTag = $ImageState.CustomImage.Tags | Where-Object { $_.Name -eq $imageState.MidVersion }
    $CustomImageEnvironmentTag = $ImageState.CustomImage.Tags | Where-Object { $_.Name -eq $BuildContext.EnvironmentName }
    if ($CustomImageTag -and $CustomImageEnvironmentTag -and ($CustomImageTag.Digest -eq $CustomImageEnvironmentTag.Digest)) {
        Write-PSFMessage -Level Important "Image $($BuildContext.CustomImageName):$($BuildContext.EnvironmentName) already exists. Skipping tagging."
    }
    elseif ($CustomImageTag) {
        Write-PSFMessage -Level Important "Tagging image $($BuildContext.CustomImageName):$($BuildContext.EnvironmentName)"
        $BuildContext.CustomTagResult = TagImage -Source $ImageState.CustomImageUri -Dest $ImageState.CustomImageEnvironmentUri
    }

    [ordered]@{
        MidVersion                = $ImageState.MidVersion
        BaseImageEnvironmentUri   = $ImageState.BaseImageEnvironmentUri
        CustomImageEnvironmentUri = $ImageState.CustomImageEnvironmentUri
        BaseImageTagResult        = $BuildContext.BaseTagResult
        CustomImageTagResult      = $BuildContext.CustomTagResult
    }
}

# ============================
# Section 2: ServiceNow Functions
# ============================

function Get-SNOWCurrentUser {
    $CurrentUser = Get-SNOWObject -Table 'sys_user' -Query "user_name=javascript:gs.getUserName()" -ErrorAction SilentlyContinue
    if ($CurrentUser.Count -eq 0) {
        Write-PSFMessage -Level Important -Message "No current user found in ServiceNow. Please check your authentication."
        return $null
    }
    return $CurrentUser[0]
}
function Get-SNOWMIDRecordWithCreds {
    param (
        [pscredential]$Credential,
        [hashtable]$AuthObject = @{},
        [string]$Table = 'sys_user',
        [string]$Query = "user_name=javascript:gs.getUserName()"
    )
    $CurrentSnowAuth = Get-SNOWAuth -ErrorAction SilentlyContinue
    $Instance = $Script:SnowEnvironmentAuth.Instance ?? $CurrentSnowAuth.Instance
    if ( -not $Instance) {
        Write-Error "No ServiceNow instance found. Please set the SN_HOST environment variable."
        return $null
    }
    $AuthObject.Instance = $Instance
    if ($Credential) {
        $AuthObject.Credential = $Credential
    }
    $LoginMethod = if ($AuthObject.ClientId -and $AuthObject.ClientSecret -and $AuthObject.Credential) {
        'OAuth - password flow'
    }
    elseif ($AuthObject.ClientId -and $AuthObject.AccessToken) {
        'OAuth - access token: Expires: {0}' -f $($AuthObject.ExpiresInSeconds)
    }
    elseif ($AuthObject.ClientId -and $AuthObject.ClientSecret) {
        'OAuth - client credentials'
    }
    elseif ($AuthObject.Credential) {
        'Basic Auth'
    }
    else {
        'None'
    }
    if ( $LoginMethod -eq 'None') {
        Write-Error "No valid authentication method found. Please provide credentials or OAuth details."
        return $null
    }
    Write-PSFMessage -Level Important "Using ServiceNow instance $Instance - ${LoginMethod}"
    Set-SNOWAuth @AuthObject -ErrorAction SilentlyContinue
    $result = Get-SNOWObject -Table $Table -Query $Query -ErrorAction SilentlyContinue
    if (-not $result) {
        Write-PSFMessage -Level Warning "Failed to authenticate to ServiceNow -${LoginMethod}"
    }
    if ($CurrentSnowAuth) {
        Write-PSFMessage -Message "Restoring previous ServiceNow authentication $($CurrentSnowAuth.Credential.UserName)@$($CurrentSnowAuth.Instance)"
        Set-SNOWAuth -AuthObject $CurrentSnowAuth
    }
    return $result
}

function Get-SNOWMIDServerRecord {
    param(
        [string]$MidServerName
    )
    Get-SNOWObject -Table 'ecc_agent' -Query "name=$MidServerName"
}

function GenerateRandomPassword {
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(12, 42)]
        [int] 
        $Length = 24,
        [switch]$AsPlainText
    )
    $symbols = '!@#$*'.ToCharArray()
    $characterList = 'a'..'z' + 'A'..'Z' + '0'..'9' + $symbols
    do {
        $password = ''
        for ($i = 0; $i -lt $Length; $i++) {
            $randomIndex = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(0, $characterList.Length)
            $password += $characterList[$randomIndex]
        }

        [int]$hasLowerChar = $password -cmatch '[a-z]'
        [int]$hasUpperChar = $password -cmatch '[A-Z]'
        [int]$hasDigit = $password -match '[0-9]'
        [int]$hasSymbol = $password.IndexOfAny($symbols) -ne -1

    }
    until (($hasLowerChar + $hasUpperChar + $hasDigit + $hasSymbol) -ge 4)
    
    if ($AsPlainText) { 
        return $password
    }
    else {
        return $password | ConvertTo-SecureString -AsPlainText
    }
}

function Get-SNOWMIDUserRoles {
    param(
        [string]$Username,
        [switch]$IncludeInherited
    )
    $User = Get-SNOWObject -Table 'sys_user' -Query "user_name=$Username"
    $RoleQuery = "user=$($User.sys_id)^"
    if (-not $IncludeInherited) {
        $RoleQuery += 'inherited=false'
    }
    $UserRoles = Get-SNOWObject -Table 'sys_user_has_role' -Query $RoleQuery -DisplayValue 'true' -ErrorAction SilentlyContinue
    return $UserRoles
}

function Add-SNOWMIDUserRoles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserSysId,
        [Parameter(Mandatory = $true)]
        [string[]]$Roles
    )
    $RequestedRoles = Get-SNOWObject -Table 'sys_user_role' -Query "name=$($Roles -join ',')"
    $UserRoles = Get-SNOWObject -Table 'sys_user_has_role' -Query "user=$UserSysId"
    $RoleList = $UserRoles.role
    foreach ($Role in $RequestedRoles) {
        if ($RoleList.value -contains $Role.sys_id) {
            Write-PSFMessage "User [$UserSysId] already has role $($Role.name)"
            continue
        }
        $RoleProperties = @{
            user = $UserSysId
            role = $Role.sys_id
        }
        Write-PSFMessage -Level Significant "Adding role $($Role.name) to [$UserSysId]"
        $RoleList += New-SNOWObject -Table 'sys_user_has_role' -Properties $RoleProperties -PassThru
    }
    $RoleList
}

function Set-SNOWMIDServerUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MidServerName,
        [ValidatePattern('^[a-zA-Z0-9\-]+$')]
        [string]$MidServerUserName = "azmid-$MidServerName",
        [securestring]$Password,
        [string[]]$Roles = @('mid_server'),
        [string[]]$Capabilities = @('ALL'),
        [string]$MidServerCluster = 'azure',
        [hashtable]$UserValues = @{},
        [string]$DefaultEmailSuffix = 'example.com',
        [string]$Operation = 'deploy'
    )
    $MidSecretName = "${MidServerUserName}-password"
    $VaultSecret = Get-Secret -Name $MidSecretName -Vault $Script:SN_MID_VAULT_NAME -ErrorAction SilentlyContinue
    
    if ($VaultSecret) {
        Write-PSFMessage -Level Important "Using password from Vault $Script:SN_MID_VAULT_NAME"
        if ($VaultSecret -is [System.Security.SecureString]) {
            if (-not $Password) {
                $Password = $VaultSecret
            }
            else {
                Write-PSFMessage -Level Warning "Secret $MidSecretName is already set, but a new password was provided. Using the provided password instead."
            }
        }
        else {
            Write-PSFMessage -Level Warning "Secret $MidSecretName is not a valid SecureString"
        }
    }
    if ($env:MID_INSTANCE_USERNAME -and $env:MID_INSTANCE_PASSWORD) {
        Write-PSFMessage -Level Important "Using password MID_INSTANCE_USERNAME: $MidServerUserName and MID_INSTANCE_PASSWORD"
        $Password = $env:MID_INSTANCE_PASSWORD | ConvertTo-SecureString -AsPlainText -Force
        $MidServerUserName = $env:MID_INSTANCE_USERNAME
    }
    if (-not $Password) {
        $Password = GenerateRandomPassword -Length 19
    }
    $MidUserCredentials = [pscredential]::new($MidServerUserName, $Password)
    $MidMetadata = [ordered]@{
        Tag     = 'SNMID'
        Name    = $MidServerName
        Cluster = $MidServerCluster
        Status  = $Operation
    }

    $MidUser = [hashtable]@{
        user_name                 = $MidServerUserName
        user_password             = (ConvertFrom-SecureString -SecureString $Password -AsPlainText)
        active                    = $true
        email                     = "${MidServerUserName}@${DefaultEmailSuffix}"
        locked_out                = $false
        password_needs_reset      = $false
        first_name                = $MidServerName
        last_name                 = 'Mid Server'
        source                    = 'azuremid'
        internal_integration_user = $true
        web_services_access_only  = $true
        employee_number           = ($MidMetadata.Values -join '|')
    }
    $CurrentSnowAuth = Get-SNOWAuth -ErrorAction SilentlyContinue
    $UserIsAdmin = $false
    if ($CurrentSnowAuth) {
        $RoleRecords = Get-SNOWObject -Table 'sys_user_has_role' -Query "user_name=javascript:gs.getUserName()" -ErrorAction SilentlyContinue -ErrorVariable UserIsAdminError
        if ($UserIsAdminError) {
            Write-PSFMessage -Level Warning "Current user is not an admin. Cannot assign roles or create user. Proceeding with passthrough."
        }
        else {
            Write-PSFMessage -Level Important "Current user is an admin. Proceeding with role assignment."
            $UserIsAdmin = ($RoleRecords.Count -gt 0) 
        }
    }
    else {
        Write-PSFMessage -Level Error -Message "No ServiceNow authentication found in context"
    }
    $MidServerUser = Get-SNOWObject -Table 'sys_user' -Query "user_name=$MidServerUserName" -Verbose
    if ($MidServerUser) {
        if ($UserIsAdmin -and $MidServerUser.locked_out -eq 'true') {
            Write-PSFMessage -Level Warning "User $MidServerUserName is locked out. Unlocking user."
            $MidServerUser = Set-SNOWObject -Table 'sys_user' -SysId $MidServerUser.sys_id -Properties @{ locked_out = 'false' } -InputDisplayValue -PassThru
        }
        Write-PSFMessage -Level Important ('{0} already exists. [active: {1}] [locked_out: {2}] [password_needs_reset: {3}]' -f $MidServerUserName, $MidServerUser.active, $MidServerUser.locked_out, $MidServerUser.password_needs_reset)
        $MidUserValid = Get-SNOWMIDRecordWithCreds -Credential $MidUserCredentials
        if (-not $MidUserValid) {
            Write-PSFMessage -Level Warning "User $MidServerUserName password is invalid"
        }
        if ($UserIsAdmin) {
            Write-PSFMessage -Level Important "Updating user $MidServerUserName" 
            $MidServerUser = Set-SNOWObject -Table 'sys_user' -SysId $MidServerUser.sys_id -Properties $MidUser -InputDisplayValue -PassThru
        }
    }
    else {
        if ($UserIsAdmin) {
            Write-PSFMessage -Level Important "Creating user $MidServerUserName"
            $MidServerUser = New-SNOWObject -Table 'sys_user' -Properties $MidUser -InputDisplayValue -PassThru
        }
        else {
            Write-PSFMessage -Level Warning "Current user is not an admin. Using Existing SNOWAuth Credentials"
            $MidServerUserName = $CurrentSnowAuth.Credential.UserName
            $MidUserCredentials = $CurrentSnowAuth.Credential
            $MidSecretName = "${MidServerUserName}-password"
            $MidServerUser = Get-SNOWCurrentUser -ErrorAction SilentlyContinue
            if (-not $MidServerUser) {
                Write-PSFMessage -Level Warning "No user found with username $MidServerUserName. Cannot assign roles or capabilities."
                return $null
            }
        }
    }
    if ($UserIsAdmin) {
        $MidServerUserRoles = Add-SNOWMIDUserRoles -UserSysId $MidServerUser.sys_id -Roles $Roles
    }
    else {
        Write-PSFMessage -Level Warning "Current user is not an admin. Cannot assign roles to $MidServerUserName. Roles must be assigned manually."
    }
    $MidUserValid = Get-SNOWMIDRecordWithCreds -Credential $MidUserCredentials 
    if ($MidUserValid) {
        $CurrentSecret = Get-Secret -Name $MidSecretName -Vault $Script:SN_MID_VAULT_NAME -ErrorAction SilentlyContinue -AsPlainText
        if ($CurrentSecret -and $CurrentSecret -eq $MidUserCredentials.GetNetworkCredential().Password) {
            Write-PSFMessage "Secret $MidSecretName already exists and is the same as the new password. No need to update."
        }
        else {
            Write-PSFMessage -Level Important "Setting password for $MidServerUserName in Vault"
            Set-Secret -Name $MidSecretName -Secret $MidUserCredentials.Password -Vault $Script:SN_MID_VAULT_NAME -ErrorAction SilentlyContinue
        }
    }
    $Results = [ordered]@{
        MidServerName = $MidServerName
        User          = $MidServerUser
        Roles         = $MidServerUserRoles
        Credentials   = $MidUserCredentials
        MidVersion    = $MidUserValid.value
        VaultSecret   = $MidSecretName
        SnowAuth      = @{
            Instance   = $CurrentSnowAuth.Instance
            Credential = $MidUserCredentials
        }
    }
    if ($Results.MidVersion) {
        Write-PSFMessage -Level Important "User $MidServerUserName is valid"
        $Results.MidImageFacts = Get-SNOWMIDDownloadFacts -BuildTag $Results.MidVersion
    }
    return $Results   
}

function Start-SNOWMIDValidationScript {
    param(
        [string]$MidServerName,
        [string]$Operation,
        [int]$TimeoutMinutes = 45
    )
    $ScriptName = "AZURE_DEVOPS_MIDVALIDATE_$($MidServerName)"
    $AdminUser = Get-SNOWCurrentUser
    $EccAgent = Get-SNOWObject -Table 'ecc_agent' -Query "name=$MidServerName" | Select-Object -First 1
    if ($EccAgent -and $EccAgent.validated -eq 'true' -and $EccAgent.status -eq 'Down' -and ($EccAgent.is_using_custom_cert -eq 'false')) {
        Write-PSFMessage -Level Important 'ecc_agent is DOWN. Invalidating'
        $EccAgent = $EccAgent | Set-SNOWObject -Properties @{ validated = 'false'; validated_at = ''; validated_by = '' } -Table 'ecc_agent' -PassThru
    }
    $ExistingScript = Get-SNOWObject -Table 'sysauto_script' -Query "name=${ScriptName}"
    if ($ExistingScript.sys_id) {
        Write-PSFMessage -Level Important 'Script already exists, deleting'
        Remove-SNOWObject -Table 'sysauto_script' -Sys_ID $ExistingScript.sys_id -Confirm:$false | Out-Null
    }
    if ($Operation -eq 'remove') {
        Write-PSFMessage -Level Important 'Operation is remove. No need to create sysauto_script entry.'
        return $false
    }
    # Check the agent. If already validated, do nothing
    $sysScriptBody = @{
        'conditional'       = 'false'
        'business_calendar' = ''
        'entered_time'      = '1970-01-01 00:00:00'
        'run_as_tz'         = ''
        'run_as'            = $AdminUser.sys_id
        'run_type'          = 'periodically'
        'run_start'         = (Get-Date).AddMinutes(+1).ToString('yyyy-MM-dd HH:mm:ss')    
        'run_dayofmonth'    = '1'
        'sys_scope'         = 'global'
        'run_dayofweek'     = '1'
        'offset'            = ''
        'run_time'          = '1970-01-01 05:00:00'
        'active'            = 'true'
        'time_zone'         = ''
        'sys_package'       = 'global'
        'condition'         = ''
        'offset_type'       = '0'
        'name'              = $ScriptName
        'max_drift'         = ''
        'run_period'        = '1970-01-01 00:00:45' # every 45 seconds   
    }
    
    $scriptHeader = 'var SYS_AUTO_SCRIPT_NAME="AZURE_DEVOPS_MIDVALIDATE_{0}";var MID_SERVER_NAME="{0}";var SYS_AUTO_SCRIPT_EXPIRY_MINUTES={1};' -f $MidServerName, $TimeoutMinutes
    $scriptBase = 'function GetMidUserMetadata(midServerName){var user=new GlideRecord("sys_user");user.addQuery("employee_number","STARTSWITH","SNMID|"+midServerName);user.query();if(!user.next()){gs.info("User not found for MID Server "+midServerName);return null}var metaParts=user.employee_number.split("|");var outputs={user:user,midServerName:midServerName};if(metaParts.length>=3){outputs.midServerCluster=metaParts[2]}if(metaParts.length>=4){outputs.midServerCluster=metaParts[2];outputs.midServerStatus=metaParts[3]}var agent=new GlideRecord("ecc_agent");agent.addQuery("name",midServerName);agent.query();if(agent.next()){outputs.agent=agent}return outputs}function CheckCapabilities(midServerName,capabilities){if(!capabilities){capabilities=["ALL"]}var outputs={capabilities:[]};var agent=new GlideRecord("ecc_agent");agent.addQuery("name",midServerName);agent.query();if(!agent.next()){gs.info("MID Server "+midServerName+" not found");return}var agentCaps=capabilities.map(function(cap){var capQuery=new GlideRecord("ecc_agent_capability_m2m");capQuery.addEncodedQuery("agent="+agent.sys_id+"^capability.name="+cap);capQuery.query();if(capQuery.next()){gs.debug("Capability "+cap+" found for MID Server "+midServerName);outputs.capabilities.push(capQuery.sys_id.toString())}else{gs.info("Capability "+cap+" not found for MID Server "+midServerName);var newCap=new GlideRecord("ecc_agent_capability_m2m");newCap.initialize();newCap.capability.setDisplayValue(cap);newCap.agent=agent.sys_id;if(newCap.insert()){outputs.capabilities.push(newCap.sys_id)}else{gs.info("Failed to add capability "+cap+" to MID Server "+midServerName)}}return capQuery});return outputs}function CheckCluster(midServerName){var userMeta=GetMidUserMetadata(midServerName);if(userMeta===null){gs.info("User metadata not found for MID Server "+midServerName);return}var cluster=new GlideRecord("ecc_agent_cluster");cluster.addQuery("name",userMeta.midServerCluster);cluster.query();if(!cluster.next()){gs.info("Cluster "+userMeta.midServerCluster+" not found. Creating...");cluster=new GlideRecord("ecc_agent_cluster");cluster.initialize();cluster.name=userMeta.midServerCluster;cluster.active=true;cluster.insert()}var clusterMember=new GlideRecord("ecc_agent_cluster_member_m2m");clusterMember.addQuery("cluster.name",userMeta.midServerCluster);clusterMember.addQuery("agent.name",midServerName);clusterMember.query();if(!clusterMember.next()){gs.info("MID Server "+midServerName+" not found in cluster "+userMeta.midServerCluster);clusterMember=new GlideRecord("ecc_agent_cluster_member_m2m");clusterMember.initialize();clusterMember.cluster.setDisplayValue(userMeta.midServerCluster);clusterMember.agent.setDisplayValue(midServerName);clusterMember.insert()}return clusterMember.sys_id.toString()}function ValidateMidServer(midServerName){var outputs={success:false,status:"unknown",midServer:midServerName};var userMeta=GetMidUserMetadata(midServerName);if(userMeta===null){gs.info("User metadata not found for MID Server "+midServerName);outputs.status="not found";return outputs}if(gs.nil(userMeta.agent)){gs.info("Agent not found for MID Server "+midServerName);outputs.status="agent not found";return outputs}outputs.clusterMember=CheckCluster(midServerName);outputs.capabilities=CheckCapabilities(midServerName);var agent=userMeta.agent;outputs.agent_status=agent.status.toString();var mm=new global.MIDServerManage;var invalidateRequired=false;var errors=new global.GlideQuery("ecc_agent_issue").where("mid_server.name",midServerName).where("state","!=","resolved").where("source","UpdatePublicKey").select("sys_id","state","message").toArray(10);if(errors.length>0){invalidateRequired=true;if(agent.validated.toString()==="true"){if(agent.status=="Up"){gs.info("Agent re-validation required for MID Server "+midServerName);mm.invalidate(agent.name);outputs.status="invalidating"}}return outputs}if(agent.validated.toString()==="false"&&agent.status=="Up"){mm.validate(agent.name);outputs.status="validating";outputs.success=true}else{outputs.status=userMeta.agent.validated.toString();outputs.success=true}return outputs}function ClearAutoScript(name,forceDelete){var script=new GlideRecord("sysauto_script");script.addQuery("name",name);script.query();if(script.next()){if(forceDelete){script.deleteRecord();return"sysauto_script "+name+" deleted"}else{var lastModified=new GlideDateTime(script.sys_created_on);var now=new GlideDateTime;var mins=gs.dateDiff(lastModified,now,true)/60;if(mins>SYS_AUTO_SCRIPT_EXPIRY_MINUTES){script.deleteRecord();return"sysauto_script "+name+" deleted - Time Elapsed: "+mins}else{return"sysauto_script "+name+" not expired. Minutes Elapsed: "+mins}}}else{return"sysauto_script "+name+" not found"}}var results=ValidateMidServer(MID_SERVER_NAME);if(results.success){results.sys_script_auto=ClearAutoScript(SYS_AUTO_SCRIPT_NAME,false)}else{results.sys_script_auto=ClearAutoScript(SYS_AUTO_SCRIPT_NAME,false)}gs.info(JSON.stringify(results,null,2));'
    $sysScriptBody.script = $scriptHeader + $scriptBase
    Write-PSFMessage -Level Important "Creating sysauto_script record in SN name: $ScriptName. Expiry: $TimeoutMinutes minutes"
    $CreateRequest = @{
        Uri         = '/api/now/table/sysauto_script?sysparm_transaction_scope=global'
        Body        = ($sysScriptBody | ConvertTo-Json -Depth 3)
        ContentType = 'application/json'
        Method      = 'POST'
    }
    $CreateResponse = Invoke-SNOWWebRequest @CreateRequest -UseRestMethod
    return @{
        name   = $ScriptName
        sys_id = $CreateResponse.result.sys_id
    }
}

function Remove-SNOWMIDServerDeployment {
    param(
        [string]$MidServerName,
        [switch]$Force
    )
    $BuildContext = Resolve-SNOWMIDBuildContext -ReloadContext
    $ContainerGroup = $BuildContext.raw | Where-Object { $_.type -eq 'microsoft.containerinstance/containergroups' -and $_.name -eq $MidServerName } | Select-Object -First 1
    
    $sa = Get-AzStorageAccount -ResourceGroupName $BuildContext.StorageAccount.resourceGroup `
        -Name $BuildContext.StorageAccount.name `
        -ErrorAction Stop
    $sactx = New-AzStorageContext -StorageAccountName $sa.StorageAccountName -StorageAccountKey (Get-AzStorageAccountKey -ResourceGroupName $BuildContext.StorageAccount.resourceGroup -Name $BuildContext.StorageAccount.name)[0].Value `
        -ErrorAction Stop
    $shares = Get-AzStorageShare -Context $sactx -ErrorAction SilentlyContinue
    if ($ContainerGroup) {
        $ContainerGroup = Get-AzContainerGroup -ResourceGroupName $ContainerGroup.resourceGroup -Name $ContainerGroup.name -SubscriptionId $ContainerGroup.subscriptionId
        if ($Force.IsPresent) {
            $ContainerGroup | Remove-AzContainerGroup -ErrorAction SilentlyContinue -Confirm:$false
        }
        else {
            Write-PSFMessage -Level Important "Container group $($ContainerGroup.name) found, but not forcing removal."
        }
    }
    $ShareNames = @($MidServerName, "${MidServerName}keystore")
    foreach ( $ShareName in $ShareNames) {
        $Share = $shares | Where-Object { $_.Name -eq $ShareName }
        if ($Share) {
            Write-PSFMessage -Level Important "Removing storage share $($Share.Name)"
            if ($Force.IsPresent) {
                Write-PSFMessage -Level Important "Forcing removal of storage share $($Share.Name)"
                Remove-AzStorageShare -Context $sactx -Name $Share.Name -Force -ErrorAction SilentlyContinue -Confirm:$false
            }
            else {
                Write-PSFMessage -Level Warning "Storage share $($Share.Name) found, but not forcing removal."
            }
        }
        else {
            Write-PSFMessage -Level Warning "Storage share $($ShareName) not found"
        }
    }
    $EccAgent = Get-SNOWObject -Table 'ecc_agent' -Query "name=$MidServerName" | Select-Object -First 1
    if ($EccAgent) {
        Write-PSFMessage -Level Important "MID Server $MidServerName found"
        if ($EccAgent.user_name) {
            $EccAgentUser = Get-SNOWUser -Query "user_name=$($EccAgent.user_name)" | Select-Object -First 1
            if ($Force.IsPresent) {
                Write-PSFMessage -Level Important "Removing MID Server user $($EccAgent.user_name)"
                if ($EccAgentUser) {
                    Remove-SNOWObject -Table 'sys_user' -Sys_ID $EccAgentUser.sys_id -Confirm:$false | Out-Null
                }
            }
            else {
                Write-PSFMessage -Level Warning "MID Server user $($EccAgent.user_name) found, but not forcing removal."
            }
        }
        if ($Force.IsPresent) {
            Write-PSFMessage -Level Important "Removing MID Server $MidServerName"
            Remove-SNOWObject -Table 'ecc_agent' -Sys_ID $EccAgent.sys_id -Confirm:$false | Out-Null
        }
        else {
            Write-PSFMessage -Level Warning "MID Server $MidServerName found, but not forcing removal."
        }
    }
    @{
        EccAgent       = $EccAgent
        Shares         = $shares
        ContainerGroup = $ContainerGroup.id
        MidServerName  = $MidServerName
    }
}

function Invoke-SNOWMIDValidate {
    param(
        [string]$MidServerName
    )
    $MidServer = Get-SNOWObject -Table 'ecc_agent' -Query "name=$MidServerName" | Select-Object -First 1
    if ( -not $MidServer) {
        Write-PSFMessage -Level Warning "MID Server $MidServerName not found"
        return $null
    }
    if (-not $MidServer.public_key) {
        Write-PSFMessage -Level Warning "MID Server $MidServerName does not have a public key"
        return $null
    }
    $UserRecord = Get-SNOWUser -Query "user_name=javascript:gs.getUserName()" -Fields 'user_name'
    Set-SNOWObject -Table 'ecc_agent' -Sys_ID $MidServer.sys_id -Properties @{
        validated    = 'true'
        validated_by = $UserRecord.user_name
        # 2025-05-08 02:20:51
        validated_at = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss' -AsUTC)
    }
    $EccQueue = New-SNOWObject -Table 'ecc_queue' -Properties @{
        agent    = "mid.server.${MidServerName}"
        source   = 'restartService'
        sequence = [guid]::NewGuid().ToString('N')
        queue    = 'output'
        topic    = 'SystemCommand'
    } -PassThru
    if ($QueueSysId = $EccQueue.sys_id) {
        Write-PSFMessage -Level Important "Command sent to MID Server $MidServerName [sys_id: $QueueSysId]"
        $EccResponse = Wait-SNOWEccQueueResponse -QueueSysId $QueueSysId -TimeoutSeconds 120
        if ($EccResponse -and $EccResponse.state -eq 'ready') {
            Write-PSFMessage -Level Important "MID Server $MidServerName validated successfully"
            return $EccResponse
        }
        else {
            Write-PSFMessage -Level Warning "Failed to validate MID Server $MidServerName"
            return $null
        }
    }
}

function Invoke-SNOWMIDInvalidate { 
    param(
        [string]$MidServerName
    )
    $MidServer = Get-SNOWObject -Table 'ecc_agent' -Query "name=$MidServerName" | Select-Object -First 1
    if ( -not $MidServer) {
        Write-PSFMessage -Level Warning "MID Server $MidServerName not found"
        return $null
    }
    Set-SNOWObject -Table 'ecc_agent' -Sys_ID $MR.sys_id -Properties @{
        validated    = ''
        validated_by = ''
        # 2025-05-08 02:20:51
        validated_at = ''
        public_key   = ''
    }
    $EccQueue = New-SNOWObject -Table 'ecc_queue' -Properties @{
        agent    = "mid.server.${MidServerName}"
        name     = 'Invalidate'
        source   = 'delete_mid_keypair'
        sequence = [guid]::NewGuid().ToString('N')
        queue    = 'output'
        topic    = 'SystemCommand'
    } -PassThru
    if ($QueueSysId = $EccQueue.sys_id) {
        Write-PSFMessage -Level Important "Command sent to MID Server $MidServerName [sys_id: $QueueSysId]"
        $EccResponse = Wait-SNOWEccQueueResponse -QueueSysId $QueueSysId
        if ($EccResponse -and $EccResponse.state -eq 'ready') {
            Write-PSFMessage -Level Important "MID Server $MidServerName invalidated successfully"
            return $EccResponse
        }
        else {
            Write-PSFMessage -Level Warning "Failed to invalidate MID Server $MidServerName"
            return $null
        }
    }
}

function Wait-SNOWEccQueueResponse {
    param(
        [string]$QueueSysId,
        [int]$TimeoutSeconds = 360
    )
    $StartTime = Get-Date
    $EndTime = $StartTime.AddSeconds($TimeoutSeconds)
    $EccResponse = $null
    while ((Get-Date) -lt $EndTime) {
        $EccResponse = Get-SNOWObject -Table 'ecc_queue' -Query "response_to=$($QueueSysId)^queue=input"
        if ($EccResponse -and $EccResponse.state -eq 'ready') {
            return $EccResponse
        }
        Start-Sleep -Seconds 1
    }
    Write-PSFMessage -Level Warning "Timeout reached waiting for ecc_queue response $($QueueSysId)"
}

function Wait-SNOWTableRecord {
    param(
        [string]$Table,
        [string]$Query,
        [int]$TimeoutSeconds = 360
    )
    $StartTime = Get-Date
    $EndTime = $StartTime.AddSeconds($TimeoutSeconds)
    $Record = $null
    while ((Get-Date) -lt $EndTime) {
        $Record = Get-SNOWObject -Table $Table -Query $Query
        if ($Record) {
            return $Record
        }
        Write-PSFMessage -Level Important "Waiting for table record [$Table] with query [$Query]"
        Start-Sleep -Seconds 1
    }
    Write-PSFMessage -Level Warning "Timeout reached waiting for table record [$Table] with sys_id [$SysId]"
}

function Get-SNOWMidAzContainerRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )
    $ContainerResults = Search-AzGraph -Query "Resources | where type =~ 'Microsoft.ContainerInstance/containerGroups' | where name == '$ContainerName' | where tags['SnowEnvironment'] == '$($Script:SN_MID_ENVIRONMENT_NAME)'" -First 1 -UseTenantScope

    if ( -not $ContainerResults) {
        Write-Error "Container group '$ContainerName' not found."
        return
    }
    return $ContainerResults
}

function Invoke-SNOWMIDCommand {
    param(
        [string]$MidServerName,
        [string]$Command,
        [int]$TimeoutSeconds = 360
    )
    $MidServer = Get-SNOWObject -Table 'ecc_agent' -Query "name=$MidServerName" | Select-Object -First 1
    if ( -not $MidServer) {
        Write-PSFMessage -Level Warning "MID Server $MidServerName not found"
        return $null
    }
    Write-Host "Sending command to MID Server $Command"
    $Payload = [xml]"<?xml version='1.0' encoding='UTF-8'?><parameters><parameter name='name' value='id'/></parameters>"
    $Payload.parameters.parameter.value = $Command
    $EccQueue = New-SNOWObject -Table 'ecc_queue' -Properties @{
        agent   = "mid.server.${MidServerName}"
        name    = 'RunCommand'
        payload = $Payload.OuterXml
        queue   = 'output'
        topic   = 'Command'
    } -PassThru
    $StartTime = Get-Date
    if ($QueueSysId = $EccQueue.sys_id) {
        Write-PSFMessage -Level Important "Command sent to MID Server $MidServerName [sys_id: $QueueSysId]"
        $EccResponse = Wait-SNOWEccQueueResponse -QueueSysId $QueueSysId -TimeoutSeconds $TimeoutSeconds
        $ResponsePayload = [xml]$EccResponse.payload
        return [ordered]@{
            StdOut          = $ResponsePayload.results.result.stdout 
            StdErr          = $ResponsePayload.results.result.stderr
            Request         = $EccQueue
            Response        = $EccResponse
            Status          = $EccResponse.state
            Time            = $EccResponse.sys_updated_on
            Duration        = (Get-Date) - $StartTime
            DurationSeconds = (Get-Date) - $StartTime | Select-Object -ExpandProperty TotalSeconds
        }
    }
}

function Get-SNOWMIDDownloadFacts {
    param(
        # xanadu-07-02-2024__patch4b-01-15-2025_02-11-2025_1733
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9\-_]+$')]
        $BuildTag,
        [ValidateSet('mid-linux-container-recipe', 'mid-windows-installer', 'mid-linux-installer-rpm', 'mid-linux-installer-deb')]
        $Package = 'mid-linux-container-recipe',
        $Architecture = 'linux.x86-64'
    )
    $Parts = $BuildTag -split '_'
    $BuildDate = ($Parts | Select-Object -Last 2) -join '_'
    $BuildStamp = $BuildTag
    $Out = [ordered]@{
        Package      = $Package
        Architecture = $Architecture
        BuildDate    = $BuildDate
        BuildStamp   = $BuildStamp
    }
    $url_date = ($BuildDate -split '_')[0] -split '-' 
    $packageFolder = @(
        $url_date[2],
        $url_date[0],
        $url_date[1]
    ) -join '/'
    $PackageExtension = switch ($Package) {
        'mid-linux-container-recipe' { 'zip' }
        'mid-windows-installer' { 'exe' }
        'mid-linux-installer-rpm' { 'rpm' }
        'mid-linux-installer-deb' { 'deb' }
    }
    #Remove -deb and -rpm from package name
    $PackageName = $Package -replace '-(deb|rpm)$'
    $Out.PackageFileName = "$PackageName.$BuildStamp.$Architecture.$PackageExtension"
    $baseUri = 'https://install.service-now.com/glide/distribution/builds/package/app-signed/{0}' -f $PackageName
    $Out.PackageUri = "$baseUri/$packageFolder/$($Out.PackageFileName)"
    $Out
}

# ============================
# Private Functions (Docker/Podman)
# ============================

function Get-DockerPodmanCommand {
    if ($env:DOCKER_COMMAND) {
        $env:DOCKER_COMMAND
    }
    elseif ((Get-Command podman -ErrorAction SilentlyContinue)) {
        'podman'
    }
    elseif ((Get-Command docker -ErrorAction SilentlyContinue)) {
        'docker'
    }
    else {
        Write-PSFMessage -Level Warning 'No docker or podman command found. Cannot resolve local images'
        $null
    }
}

function Get-DockerPodmanImageState {
    $ImageTags = @()
    $DockerCommand = Get-DockerPodmanCommand
    $DockerParams = switch ($DockerCommand) {
        'docker' { @('image', 'ls', '--format', '{{.Repository}}||{{.Tag}}||{{.ID}}') }
        'podman' { @('images', 'ls', '--format', '{{.Repository}}||{{.Tag}}||{{.Digest}}') }
        default { return $null }
    }
    $Images = (& $DockerCommand $DockerParams) -replace '<none>', 'latest'
    foreach ($Image in $Images) {
        $NameRegex = '^(?<Repository>.+)\|\|(?<Tag>.+)\|\|(?<Digest>.+)$'
        if ($Image -match $NameRegex) {
            $P = $matches['Repository'] -split '/', 2
            if ($P.Count -eq 2) {
                $RegistryName = $P[0]
                $ImageName = $P[1]
            }elseif($P.Count -eq 1) {
                $RegistryName = ''
                $ImageName = $P[0]
            }
            $ImageTags += [PSCustomObject]@{
                Registry  = $RegistryName
                ImageName = $ImageName
                Name      = $Matches['Tag']
                Digest    = $matches['Digest']
            }  
        }
    } 
    $ImageTags | Group-Object -Property ImageName | ForEach-Object {
        [PSCustomObject]@{
            Name     = $_.Name
            Registry = $_.Group[0].Registry
            Tags     = @($_.Group | Select-Object -Property Name, Digest)
        }
    } | Sort-Object -Property Name
}

function Get-DockerPodmanDockerFileContent {
    if ($env:SN_MID_CUSTOM_DOCKERFILE_BASE64) {
        $dockerFile = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($env:SN_MID_CUSTOM_DOCKERFILE_BASE64))
    }
    elseif (Test-Path "$PSScriptRoot/azure/Dockerfile.midcustom") {
        $dockerFile = Get-Content -Path ("$PSScriptRoot/azure/Dockerfile.midcustom") -Raw
    }
    elseif ($env:SN_MID_CUSTOM_DOCKERFILE_PATH) {
        $dockerFile = Get-Content -Path $env:SN_MID_CUSTOM_DOCKERFILE_PATH -Raw
    }
    else {
        return $null
    }
    $dockerFile
}

function Merge-DockerPodmanHashTables {
    param(
        [hashtable] $default, # Your original set
        [hashtable] $uppend # The set you want to update/append to the original set
    )
    $default1 = $default.Clone()
    foreach ($key in $uppend.Keys) {
        if ($default1.ContainsKey($key)) {
            $default1.Remove($key)
        }
    }
    return $default1 + $uppend
}

#==============================================================================
# ServiceNow MID Tools - Vault Management Functions
#==============================================================================
# This script provides functions for managing secrets in PowerShell SecretStore
# or Azure Key Vault for use with ServiceNow and Azure environments.
#
# Functions:
# - Resolve-SNOWMidSecretManagementVault: Configure and register a secret vault
# - Set-JsonSecret / Get-JsonSecret: Store and retrieve JSON-formatted secrets
# - Set-SNOWMidEnvironmentSecret / Resolve-SNOWMIDEnvironmentAuth: Manage ServiceNow credentials
# - Set-SNOWMidAzureEnvironmentSecret / Resolve-SNOWMidAzureEnvironmentSecrets: Manage Azure credentials
#
#==============================================================================
# EXAMPLES
#==============================================================================
# Example 1: Register a vault
# --------------------------
# # Use PowerShell SecretStore (default)
# $DefaultVault = Resolve-SNOWMidSecretManagementVault -VaultName 'PSSnowTestVault' -UseAzureKeyVault:$false
#
# # Use Azure KeyVault with metadata
# Resolve-SNOWMidSecretManagementVault -VaultName 'PSSnowTestVault' -UpdateMetadata -VaultMetadata @{
#     EnvironmentName = 'Test'
#     SubscriptionId  = '12345678-1234-1234-1234-123456789012'
# }
#
# Example 2: ServiceNow Credentials Management
# ------------------------------------------
# # Store ServiceNow credentials
# Set-SNOWMidEnvironmentSecret -Username admin -Instance dev195226 -Password ($env:SN_PASSWORD | ConvertTo-SecureString -AsPlainText -Force) `
#     -SecretName 'snow-connection-unts-json' -VaultName 'PSSnowTestVault'
#
# # Retrieve ServiceNow credentials and set environment variables
# Resolve-SNOWMIDEnvironmentAuth -SecretName 'snow-connection-sbx-json' -VaultName 'PSSnowTestVault'
#
# Example 3: Azure Credentials Management
# -------------------------------------
# # Store Azure credentials
# $clientSecret = ConvertTo-SecureString -String "your-client-secret" -AsPlainText -Force
# Set-SNOWMidAzureEnvironmentSecret -TenantId "your-tenant-id" -SubscriptionId "your-subscription-id" `
#     -ClientId "your-client-id" -PrincipalId "your-principal-id" -ClientSecret $clientSecret `
#     -SecretName 'azure-connection-sbx-json' -VaultName 'PSSnowTestVault'
#
# # Retrieve and set Azure environment variables
# Resolve-SNOWMidAzureEnvironmentSecrets -SecretName 'azure-connection-sbx-json' -VaultName 'PSSnowTestVault'
#
# Example 4: Copy secrets between vaults
# ------------------------------------
# Resolve-SNOWMIDEnvironmentAuth -SecretName 'snow-connection-sbx-json' -VaultName 'PSSnowTestAzVault' | 
#     Set-JsonSecret -SecretName 'snow-connection-sbx-json' -VaultName 'PSSnowTestVault'
#
#==============================================================================

function Resolve-SNOWMidSecretManagementVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VaultName,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseAzureKeyVault,
        
        [Parameter(Mandatory = $false)]
        [string]$AzureKeyVaultName,
        
        [Parameter(Mandatory = $false)]
        [string]$AzureSubscriptionId,

        [Parameter(Mandatory = $false)]
        [hashtable]$VaultMetadata = @{},

        [Parameter(Mandatory = $false)]
        [switch]$UpdateMetadata
    )
    $VaultMetadata += [hashtable]@{
        VaultName           = $VaultName
        UseAzureKeyVault    = $UseAzureKeyVault
        AzureKeyVaultName   = $AzureKeyVaultName
        AzureSubscriptionId = $AzureSubscriptionId
        UpdateTimestamp     = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    }
    # Prepare vault configuration based on type
    if ($UseAzureKeyVault) {
        # Verify Azure context
        try {
            $context = Get-AzContext -ErrorAction Stop
            if (-not ($azKvModule = Get-Module -Name Az.KeyVault -ErrorAction SilentlyContinue)) {
                Import-Module -Name Az.KeyVault
                $azKvModule = Get-Module -Name Az.KeyVault -ErrorAction SilentlyContinue
            }
            $kvSecretVault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
            if ($kvSecretVault) {
                if (-not($azKvModule.ModuleBase.ToLower().StartsWith($kvSecretVault.ModulePath.ToLower()))) {
                    Write-PSFMessage -Level Warning "AZ Secret vault '$VaultName' exists but is not registered with the expected Az.KeyVault module. ModulePath: $($kvSecretVault.ModulePath), ModuleBase: $($azKvModule.ModuleBase)"
                    Unregister-SecretVault -Name $VaultName -ErrorAction Stop
                    Remove-Variable -Name kvSecretVault -ErrorAction SilentlyContinue
                }
                else {
                    Write-PSFMessage -Level Verbose "AZ Secret vault '$VaultName' already exists and is registered with the expected Az.KeyVault module."
                }
            }
            if (-not $context) {
                throw "No Azure context found. Please connect to Azure first with Connect-AzAccount."
            }
            
            # Use provided subscription ID or current one
            $subscriptionId = $AzureSubscriptionId ? $AzureSubscriptionId : $context.Subscription.Id
            
            # Use the provided KeyVault name or default to the VaultName parameter
            $keyVaultToUse = if ($AzureKeyVaultName) { $AzureKeyVaultName } else { $VaultName }
            
            # Prepare parameters for Azure KeyVault
            $vaultConfig = @{
                Name            = $VaultName
                ModuleName      = 'Az.KeyVault'
                VaultParameters = @{
                    AZKVaultName   = $keyVaultToUse
                    SubscriptionId = $subscriptionId
                }
            }
        }
        catch {
            Write-Error "Azure KeyVault configuration failed: $_"
            return
        }
    }
    else {
        # Setup for PowerShell SecretStore
        $RequiredModules = @(
            'Microsoft.PowerShell.SecretManagement',
            'Microsoft.PowerShell.SecretStore'
        )
        $RequiredModules | ForEach-Object {
            if (-not (Get-Module -Name $_ -ErrorAction SilentlyContinue -ListAvailable)) {
                Install-Module -Name $_ -Force -Scope CurrentUser
                if ($_ -eq 'Microsoft.PowerShell.SecretStore') {
                    Import-Module -Name $_ -Force -Scope CurrentUser
                    Reset-SecretStore -Confirm:$false -Authentication None
                    Set-SecretStoreConfiguration -Authentication None -Scope CurrentUser -Confirm:$false
                }
            }
        }
        
        # Configure SecretStore
        Set-SecretStoreConfiguration -Authentication None -Scope CurrentUser -Confirm:$false
        
        # Prepare parameters for PowerShell SecretStore
        $vaultConfig = @{
            Name         = $VaultName
            ModuleName   = 'Microsoft.PowerShell.SecretStore'
            DefaultVault = $true
        }
    }

    # Common functionality for both vault types
    $existingVault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    $VaultMetadata.VaultConfig = $vaultConfig
    $Metadata = (ConvertTo-Json -InputObject $VaultMetadata -Depth 4 -Compress)

    if (-not $existingVault) {
        # Register the vault using parameters
        Register-SecretVault @vaultConfig -ErrorAction Stop
        Write-PSFMessage -Level Important "Vault $VaultName registered as $($vaultConfig.ModuleName) with parameters $($vaultConfig.VaultParameters | ConvertTo-Json -Depth 3 -Compress)."
    }
    else {
        Write-PSFMessage "Secret vault '$VaultName' already exists. $($existingVault.ModulePath) is already registered."
    }
    $existingMetadata = Get-Secret -Name 'AzVaultMetadata' -Vault $VaultName -ErrorAction SilentlyContinue -AsPlainText
    if ($existingMetadata) {
        $CurrentMetadata = (ConvertFrom-Json -InputObject $existingMetadata -ErrorAction SilentlyContinue -AsHashtable) 
    }
    if ($UpdateMetadata) {
        Set-Secret -Name 'AzVaultMetadata' -Vault $VaultName -Secret $Metadata
    }
    
    # Return vault information
    $result = @{
        VaultName       = $VaultName
        Vault           = (Get-SecretVault -Name $VaultName)
        VaultParams     = $vaultConfig
        Metadata        = $VaultMetadata
        CurrentMetadata = $CurrentMetadata
    }
    
    
    return $result
}

function Set-JsonSecret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [hashtable]$SecretValue,
        
        [Parameter(Mandatory = $true)]
        [string]$SecretName,
        
        [Parameter(Mandatory = $true)]
        [string]$VaultName
    )
    process {
        $SecretValueOut = [ordered]@{}
        # Go through keys and check for PSCredential or securestring objects
        foreach ($skey in $SecretValue.Keys) {
            if ($SecretValue[$skey] -is [PSCredential]) {
                $SecretValueOut[$skey] = @{
                    UserName = $SecretValue[$skey].UserName
                    Password = $SecretValue[$skey].GetNetworkCredential().Password
                }
            }
            elseif ($SecretValue[$skey] -is [SecureString]) {
                $SecretValueOut[$skey] = $SecretValue[$skey] | ConvertFrom-SecureString -AsPlainText -ErrorAction SilentlyContinue
            }
            else {
                $SecretValueOut[$skey] = $SecretValue[$skey]
            }
        }
        Write-PSFMessage -Level Important "Storing secret '$SecretName' in vault '$VaultName'."
        $JsonSecretValue = $SecretValueOut | ConvertTo-Json -Depth 10 -Compress
        Set-Secret -Name $SecretName -Secret $JsonSecretValue -Vault $VaultName
    }
}

function Get-JsonSecret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SecretName,
        
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $false)]
        [string[]]$SecureVariables = @('ClientSecret', 'Password', 'ClientSecretValue'),

        [switch]$Raw
    )
    process {
        $JsonSecretValue = Get-Secret -Name $SecretName -Vault $VaultName -AsPlainText -ErrorAction SilentlyContinue
        if ($JsonSecretValue) {
            $SecretValueOut = @{}
            $SecretValue = $JsonSecretValue | ConvertFrom-Json -AsHashtable -ErrorAction Continue
            if ( $Raw.IsPresent) {
                return $SecretValue
            }
            foreach ($skey in $SecretValue.Keys) {
                if ($SecretValue[$skey] -is [hashtable] -and $SecretValue[$skey].Keys.Contains('UserName') -and $SecretValue[$skey].Keys.Contains('Password')) {
                    $SecretValueOut[$skey] = New-Object -TypeName PSCredential -ArgumentList $SecretValue[$skey].UserName, (ConvertTo-SecureString -String $SecretValue[$skey].Password -AsPlainText -Force)
                }
                elseif ($SecretValue[$skey] -is [string] -and $SecureVariables -contains $skey) {
                    $SecretValueOut[$skey] = ConvertTo-SecureString -String $SecretValue[$skey] -AsPlainText -Force
                }
                else {
                    $SecretValueOut[$skey] = $SecretValue[$skey]
                }
            }
        }
        else {
            Write-Error "Secret '$SecretName' not found in vault '$VaultName'."
        }
        return $SecretValueOut
    }
}

function New-SNOWMidEnvironmentPassword {
    param(
        [string]$SecretName = $Script:SN_CONNECTION_SECRET_NAME,
        [string]$VaultName = $Script:SN_MID_VAULT_NAME
    )
    $CurrentAuth = Resolve-SNOWMIDEnvironmentAuth -SecretName $SecretName -VaultName $VaultName
    if ($CurrentAuth -and ($CurrentUser = Get-SNOWCurrentUser) -and ($CurrentAuth.Credential)) {
        $Password = GenerateRandomPassword -Length 24 -AsPlainText
        Write-PSFMessage "Generated new password for ServiceNow MID environment: $($CurrentAuth.Instance)"
        $UserUpdate = Set-SNOWObject -Table 'sys_user' -Sys_ID $CurrentUser.sys_id -Properties @{
            locked_out           = $false
            password_needs_reset = $false
            user_password        = $Password
        } -InputDisplayValue -PassThru
        if ($UserUpdate) {
            Write-PSFMessage -Level Important "Password updated for user $($CurrentUser.user_name) in ServiceNow MID environment: $($CurrentAuth.Instance)"
            # Store the new password in the vault
            $SecretParams = @{
                Instance   = $CurrentAuth.Instance
                Credential = [pscredential]::new($CurrentUser.user_name, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
                VaultName  = $VaultName
                SecretName = $SecretName
            }
            Set-SNOWMidEnvironmentSecret @SecretParams
            return $SecretParams
        }
        else {
            Write-PSFMessage -Level Warning "Failed to update password for user $($CurrentUser.user_name) in ServiceNow MID environment: $($CurrentAuth.Instance)"
        }
    }
    else {
        Write-PSFMessage -Level Warning "No current ServiceNow MID environment found to generate a password."
    }

}

$Script:PSSnowParameters = @('Instance', 'Credential', 'ClientID', 'ClientSecret', 'ProxyURI', 'ProxyCredential', 'HandleRatelimiting', 'WebCallTimeoutSeconds', 'BypassDefaultProxy', 'UseWebSession', 'AccessToken', 'RefreshToken', 'ExpiresInSeconds')
function Set-SNOWMidEnvironmentSecret {
    [CmdletBinding(DefaultParameterSetName = 'Basic')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Basic')]
        [Parameter(Mandatory, ParameterSetName = 'OAuth')]
        [Parameter(Mandatory, ParameterSetName = 'OAuthToken')]
        [ValidateNotNullOrEmpty()]
        [string]
        #Instance name e.g dev123456
        $Instance,
        [Parameter(Mandatory, ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [PSCredential]
        #Basic Auth
        $Credential,
        [Parameter(Mandatory, ParameterSetName = 'OAuth')]
        [Parameter(Mandatory, ParameterSetName = 'OAuthToken')]
        [string]
        #OAuth ClientID
        $ClientID,
        [Parameter(Mandatory, ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [SecureString]
        #OAuth ClientSecret
        $ClientSecret,
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [string]
        #By default if this param is not used the system default proxy will be provided if configured. URI should include the port if used.
        $ProxyURI,
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [PSCredential]
        #Provide credentials if you do not want to use default auth for any existing proxy
        $ProxyCredential,
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        #Servicenow rate limit policies are per hour, this will cause commands to sleep and wait until those rate limits are refreshed, instead of returning an error.
        [switch]
        $HandleRatelimiting,
        #Default is no specified timeout
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [int]
        $WebCallTimeoutSeconds,
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [switch]
        #Only supported on PS Core. 5.1 users will need to add a bypass via device config.
        $BypassDefaultProxy,
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [switch]
        # Create a web session for the session context. This will store the cookies and X-UserToken in the session object.
        $UseWebSession,
        [Parameter(Mandatory, ParameterSetName = 'OAuthToken')]
        [string]
        # An existing OAuth Access Token
        $AccessToken,
        [Parameter(Mandatory, ParameterSetName = 'OAuthToken')]
        [string]
        #OAuth Refresh Token
        $RefreshToken,
        [Parameter(Mandatory, ParameterSetName = 'OAuthToken')]
        [datetime]
        #OAuth Refresh Token
        $Expires,
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [string]$SecretName = $Script:SN_CONNECTION_SECRET_NAME,
        [Parameter(ParameterSetName = 'Basic')]
        [Parameter(ParameterSetName = 'OAuth')]
        [Parameter(ParameterSetName = 'OAuthToken')]
        [string]$VaultName = $Script:SN_MID_VAULT_NAME
    )
    process {
        $SecretValue = [ordered]@{
            Instance = $Instance
        }
        foreach ($p in $Script:PSSnowParameters) {
            if ($PSBoundParameters.ContainsKey($p)) {
                $SecretValue[$p] = $PSBoundParameters[$p]
            }
        }
        if ($Expires) {
            $SecretValue.ExpiresInSeconds = ($Expires - (Get-Date)).TotalSeconds
        }
        try {
            $OldAuth = Get-SNOWAuth -ErrorAction SilentlyContinue
            Set-SNOWAuth @SecretValue -ErrorAction Stop
            # Test the connection with a simple API call
            $Self = Invoke-SNOWWebRequest -Method Get -URI '/api/now/table/sys_user?sysparm_fields=sys_id,name,user_name&sysparm_query=user_name=javascript:gs.getUserName()' -UseRestMethod -ErrorAction Stop
            if ($Self.result) {
                Write-PSFMessage "Successfully connected to ServiceNow [$($Instance)]: $($Self.result.user_name) ($($Self.result.sys_id))"
            }
            else {
                Write-PSFMessage -Level Warning "Failed to retrieve user information from ServiceNow instance. Check your credentials."
            }
        }
        catch {
            Write-PSFMessage -Level Warning "Could not verify ServiceNow credentials: $_"
            if ($OldAuth) {
                Set-SNOWAuth -AuthObject $OldAuth -ErrorAction SilentlyContinue | Out-Null
            }
        }
        if ($Expires) {
            $SecretValue.Expires = $Expires
        }
        Set-JsonSecret -SecretValue $SecretValue -SecretName $SecretName -VaultName $VaultName
        $VaultSecrets = switch ($PsCmdlet.ParameterSetName) {
            'Basic' {
                @{
                    'snow-api-username' = $Credential.UserName | ConvertTo-SecureString -AsPlainText -Force
                    'snow-api-password' = $Credential.Password
                }
            }
            default {
                @{}
            }
        }
        foreach ($key in $VaultSecrets.Keys) {
            Set-Secret -Name $key -SecureStringSecret $VaultSecrets[$key] -Vault $VaultName
        }
    }
}

function Get-SNOWMIDEnvironmentAuthSecret {
    param(
        [string]$SecretName = $Script:SN_CONNECTION_SECRET_NAME,
        [string]$VaultName = $Script:SN_MID_VAULT_NAME,
        [switch]$Raw
    )
    Get-JsonSecret -SecretName $SecretName -VaultName $VaultName -ErrorAction SilentlyContinue -Raw:$Raw
}

function Resolve-SNOWMIDEnvironmentAuth {
    param(
        [string]$SecretName = $Script:SN_CONNECTION_SECRET_NAME,
        [string]$VaultName = $Script:SN_MID_VAULT_NAME,
        [switch]$SkipTagUpdate
    )
    process {
        $SecretValue = Get-SNOWMIDEnvironmentAuthSecret -SecretName $SecretName -VaultName $VaultName
        if ($SecretValue.Username -and $SecretValue.Password) {
            $SecretValue.Credential = [pscredential]::new($SecretValue.Username, $SecretValue.Password)
        }
        # Attempt to Set-SNOWAuth with the retrieved secret and query the user
        if ($SecretValue) {
            Write-PSFMessage "Resolved ServiceNow credentials for $($SecretValue.Instance) in Environment $($Script:SN_MID_ENVIRONMENT_NAME)"
            # If the instance is not a proper URL, append .service-now.com
            if ($SecretValue.Instance -notmatch '^https.*$') {
                $SecretValue.Instance = "https://$($SecretValue.Instance).service-now.com"
            }
            $Script:SnowEnvironmentAuth = @{
                Instance = $SecretValue.Instance
            }
            foreach ($p in $Script:PSSnowParameters) {
                if ($SecretValue.Keys.Contains($p) -and $null -ne $SecretValue[$p]) {
                    $Script:SnowEnvironmentAuth[$p] = $SecretValue[$p]
                }
            }
            if ($SecretValue.Expires) {
                if ($SecretValue.Expires -is [string]) {
                    $SecretValue.Expires = [datetime]::Parse($SecretValue.Expires)
                }
                $Script:SnowEnvironmentAuth.ExpiresInSeconds = ($SecretValue.Expires - (Get-Date)).TotalSeconds
            }
            elseif ($SecretValue.AccessToken -and -not $SecretValue.Expires) {
                $Script:SnowEnvironmentAuth.ExpiresInSeconds = 30
            }
            Write-PSFMessage -Message "Using ServiceNow credentials for $($SecretValue.Instance) from Vault Secret" -Level Important
        }
        else {
            Write-PSFMessage -Level Warning -Message "Failed to retrieve secret '$($Script:SN_CONNECTION_SECRET_NAME)' from vault '$($Script:SN_MID_VAULT_NAME)'."
        }

        if (![string]::IsNullOrEmpty($env:MID_INSTANCE_URL) -and ![string]::IsNullOrEmpty($env:MID_INSTANCE_USERNAME) `
                -and ![string]::IsNullOrEmpty($env:MID_INSTANCE_PASSWORD)) {
            $Script:SnowEnvironmentAuth = @{
                Instance   = $env:MID_INSTANCE_URL
                Credential = [pscredential]::new($env:MID_INSTANCE_USERNAME, ($env:MID_INSTANCE_PASSWORD | ConvertTo-SecureString -AsPlainText -Force))
            }
            Write-PSFMessage -Message "Setting ServiceNow credentials for $($Script:SnowEnvironmentAuth.Instance) from MID_INSTANCE_ Environment" -Level Important
        }
        

        if ($Script:SnowEnvironmentAuth) {
            $CurrentUser = Get-SNOWMIDRecordWithCreds -AuthObject $Script:SnowEnvironmentAuth -ErrorAction SilentlyContinue
            if ($CurrentUser) {
                Set-SNOWAuth @SnowEnvironmentAuth -ErrorAction SilentlyContinue
                $MidVersion = Get-SNOWMidVersion -ErrorAction SilentlyContinue
                $NewSnowAuth = Get-SNOWAuth -ErrorAction SilentlyContinue
                # Handle OAuth token refresh if needed and store updated tokens back in the vault
                # TODO: Clean this up or break into smaller functions
                if ($NewSnowAuth -and $NewSnowAuth.Token.access_token) {
                    $Script:SnowEnvironmentAuth.Expires = $NewSnowAuth.Expires
                    $TokenUpdated = (-not $SecretValue.Expires)
                    if ($SecretValue.AccessToken -and $SecretValue.RefreshToken) {
                        $TokenUpdated = ($NewSnowAuth.Token.access_token -ne $SecretValue.AccessToken) -or ($NewSnowAuth.Token.refresh_token -ne $SecretValue.RefreshToken)                        
                        $TimeDelta = ($NewSnowAuth.Expires - ($SecretValue.Expires)).TotalSeconds
                        $TokenUpdated = ($TokenUpdated -or ($TimeDelta -gt 60) -or ($TimeDelta -lt -60))
                        Write-PSFMessage -Level Verbose "OAuth token updated: $TokenUpdated (Delta: $([math]::Round($TimeDelta,0)) seconds)"
                    }
                    if ( $TokenUpdated ) {
                        $Script:SnowEnvironmentAuth.ExpiresInSeconds = ($NewSnowAuth.Token.expires_in)  
                        Write-PSFMessage -Level Important "ServiceNow OAuth token refreshed for $($SecretValue.Instance). New expiry in $($NewSnowAuth.Token.expires_in) seconds."
                        Set-SNOWMidEnvironmentSecret -Instance $NewSnowAuth.Instance `
                            -ClientID $NewSnowAuth.ClientId `
                            -AccessToken $NewSnowAuth.Token.access_token `
                            -RefreshToken $NewSnowAuth.Token.refresh_token `
                            -Expires $NewSnowAuth.Expires `
                            -SecretName $SecretName `
                            -VaultName $VaultName
                    }
                    else {
                        Write-PSFMessage -Level Verbose "ServiceNow OAuth token not updated for $($SecretValue.Instance)."
                        $Script:SnowEnvironmentAuth.ExpiresInSeconds = ($NewSnowAuth.Expires - (Get-Date)).TotalSeconds
                    }
                }
                Write-PSFMessage -Level Important "Successfully connected to ServiceNow [$($SecretValue.Instance)]: $($MidVersion) ($($CurrentUser.user_name) - $($CurrentUser.sys_id))"
                if ($Script:SN_MID_CONTEXT -eq 'azure') {
                    try {
                        $BuildContext = Resolve-SNOWMIDBuildContext
                        $SnowAuthState = @{
                            User                 = ($CurrentUser.user_name)
                            Version              = $MidVersion
                            AuthenticationMethod = if ($Script:SnowEnvironmentAuth.Credential -and -not $Script:SnowEnvironmentAuth.ClientID) { 'Basic' } else { 'OAuth' }
                            LastVerified         = (Get-Date).ToString('o')
                        }
                        if ($LastState = $BuildContext.StorageAccount.Tags.SnowAuthState) {
                            $LastState = $LastState | ConvertFrom-Json -ErrorAction SilentlyContinue
                        }
                        if ($LastState -and $LastState.User -eq $SnowAuthState.User -and $LastState.Version -eq $SnowAuthState.Version -and $LastState.AuthenticationMethod -eq $SnowAuthState.AuthenticationMethod) {
                            $LastState.LastVerified = [datetime]::Parse($LastState.LastVerified)
                            $TimeSinceLastVerified = (Get-Date) - $LastState.LastVerified
                        }
                        if ($LastState.LastVerified -and $TimeSinceLastVerified.TotalMinutes -lt 30) {
                            Write-PSFMessage -Level Verbose "Last tag update was less than 30 minutes ago. Skipping tag update on Storage Account."
                        }
                        elseif ($SkipTagUpdate.IsPresent) {
                            Write-PSFMessage -Level Important "Skipping tag update on Storage Account as requested. Time since last update was $([math]::Round($TimeSinceLastVerified.TotalMinutes,1)) minutes."
                        }else{
                            Write-PSFMessage -Level Important "Updating Azure Storage Account tags with ServiceNow MID environment state: $($BuildContext.StorageAccount.Name)"
                            $NewState = ($SnowAuthState | ConvertTo-Json -Compress)
                            Update-AzTag -ResourceId $BuildContext.StorageAccount.resourceId -Tag @{SnowAuthState = $NewState } -Operation Merge -ErrorAction SilentlyContinue | Out-Null
                            if ($BuildContext.StorageAccount.Tags.SnowAuthState) {
                                $Script:SNMIDBuildContext.StorageAccount.Tags.SnowAuthState = $NewState
                            }
                            else {
                                Resolve-SNOWMIDBuildContext -ReloadContext | Out-Null
                            }
                        }                        
                    }
                    catch {
                        Write-PSFMessage -Level Warning "Failed to update Azure Storage Account tags with ServiceNow MID environment state: $_"
                    }
                }
            }
            else {
                Write-PSFMessage -Level Warning "Failed to retrieve MID version from ServiceNow instance. Check your credentials."
                $Script:SnowEnvironmentAuth = $null
            }
        }
        return $Script:SnowEnvironmentAuth
    }
}

function Set-SNOWMidAzureEnvironmentSecret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        
        [Parameter(Mandatory = $true)]
        [securestring]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Metadata = @{},
        
        [Parameter(Mandatory = $false)]
        [string]$AzureEnvironmentName = 'AzureCloud',
        
        [Parameter(Mandatory = $false)]
        [string]$SecretName = $Script:AZ_CONNECTION_SECRET_NAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VaultName = $Script:SN_MID_VAULT_NAME
    )
    process {
        $SecretValue = @{
            TenantId        = $TenantId
            SubscriptionId  = $SubscriptionId
            ClientId        = $ClientId
            PrincipalId     = $PrincipalId
            ClientSecret    = ($ClientSecret | ConvertFrom-SecureString -AsPlainText)
            EnvironmentName = $AzureEnvironmentName
            Metadata        = $Metadata
        }
        
        if ($Certificate) {
            $SecretValue.Certificate = @($Certificate.ExportCertificatePem(), $Certificate.PrivateKey.ExportPkcs8PrivateKeyPem()) -join "`n"
        }
        
        # Verify the credentials are valid if possible
        try {
            $context = Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId `
                -Credential (New-Object PSCredential($ClientId, $ClientSecret)) -Environment $AzureEnvironmentName `
                -ServicePrincipal -ErrorAction Stop -Scope Process
            # Disconnect if the connection was successful
            Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue 
        }
        catch {
            Write-PSFMessage -Level Warning "Could not verify Azure credentials: $_"
            # Continue anyway - the secret will still be stored
        }
        
        Set-JsonSecret -SecretValue $SecretValue -SecretName $SecretName -VaultName $VaultName
    }
}

function Resolve-SNOWMidAzureEnvironmentSecrets {
    [CmdletBinding()]
    param (
        [string]$SecretName = $Script:AZ_CONNECTION_SECRET_NAME,
        [string]$VaultName = $Script:SN_MID_VAULT_NAME,
        [switch]$SetEnvironmentVariables
    )
    process {
        $SecretValue = Get-JsonSecret -SecretName $SecretName -VaultName $VaultName
        $EnvVars = [ordered]@{
            AZURE_TENANT_ID        = $SecretValue.TenantId
            AZURE_SUBSCRIPTION_ID  = $SecretValue.SubscriptionId
            AZURE_CLIENT_ID        = $SecretValue.ClientId
            AZURE_CLIENT_SECRET    = $SecretValue.ClientSecret
            AZURE_ENVIRONMENT_NAME = $SecretValue.EnvironmentName
        }
        if ($EnvVars.AZURE_CLIENT_SECRET -and $EnvVars.AZURE_CLIENT_SECRET -is [securestring]) {
            $EnvVars.AZURE_CLIENT_SECRET = $EnvVars.AZURE_CLIENT_SECRET | ConvertFrom-SecureString -AsPlainText
        }
        if ($SecretValue.Certificate) {
            $certPath = [System.IO.Path]::GetTempFileName()
            $SecretValue.Certificate | Out-File -FilePath $certPath -Encoding utf8
            $EnvVars.AZURE_CERTIFICATE_PATH = $certPath
        }
        # Set environment variables if requested or by default
        if ($SecretValue -and ($SetEnvironmentVariables.IsPresent)) {
            foreach ($EnvVar in $EnvVars.Keys) {
                if ($EnvVars[$EnvVar]) {
                    $eVal = $EnvVars[$EnvVar]
                    [System.Environment]::SetEnvironmentVariable($EnvVar, $eVal, [System.EnvironmentVariableTarget]::Process)
                }
                else {
                    Write-PSFMessage -Level Verbose "Environment variable '$EnvVar' not set. Value is null or empty."
                }
            }
        }
        elseif (!$SecretValue) {
            Write-Error "Failed to retrieve secret '$SecretName' from vault '$VaultName'."
        }
        else {
            Write-PSFMessage -Level Verbose "Environment variables not set. Use -SetEnvironmentVariables to set them in the current process."
        }
        
        return $EnvVars
    }
}
Initialize-SNOWMidTools
foreach ($Script in (Get-ChildItem -Path $PSScriptRoot -Filter 'PSSNow.MidTools.*.ps1' -File)) {
    . $Script.FullName
}
# DO NOT REMOVE THIS LINE
### END PSSnow.MidTools.psm1 ###