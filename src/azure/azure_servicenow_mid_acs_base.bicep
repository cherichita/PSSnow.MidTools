@description('The name of the environment. This will be used to tag, and identify resources.')
@maxLength(5)
param devopsEnvironmentName string = 'dev'

@description('A unique string to append to some of the deployments.')
param deploymentKey string = utcNow()

@description('Deploy Permissions? This will deploy the necessary permissions for the DevOps identities to the resources. Requires OWNER permissions on the resource group.')
param deployPermissions bool = true

@description('Location for the resources')
param location string = resourceGroup().location

@description('Run the validation script to test connectivity to ServiceNow')
param runValidationScript bool = false

@description('Additional Azure AD Objects with principalId and principalType to be added to the Key Vault access policy, and admin role assignments.')
param adminEntraEntities array = []

// ServiceNow Parameters 
@description('ServiceNow Instance name (e.g., dev123456)')
param snowHost string

@description('Set to true and provide snowCredentials or snowCredentialsJson to deploy the ServiceNow credentials to Key Vault.')
param deployCredentials bool = true

@description('SNOW Credentials Object - Must match Set-SNOWMidEnvironmentSecret parameters')
@secure()
param snowCredentials object = {}

@description('The snowCredentials object in JSON format.')
@secure()
param snowCredentialsJson string = ''

var snowCredentialsParsed = empty(snowCredentialsJson) ? snowCredentials : json(snowCredentialsJson)

// Network parameters
@description('Subnet ID for the container. Must have access to ServiceNow instance, ACR, and ARM Services at a minimum.')
param containerSubnetId string

@description('Subnet IDs to allow access to the storage account')
param additionalStorageSubnetIds array = []

@description('The ID of the virtual network role. This is used to assign the role to the subnet. Default is Contributor on the virtual network.')
param virtualNetworkRoleId string = '9980e02c-c2be-4d73-94e8-173b1dc7cf3c'

@description('Key Vault Name')
@maxLength(24)
param keyVaultName string = 'snkv-${devopsEnvironmentName}-${uniqueString(resourceGroup().id)}'

@description('Key Vault Resource Group')
param keyVaultResourceGroup string = resourceGroup().name

@description('Key Vault Subscription')
param keyVaultSubscription string = subscription().subscriptionId

@description('ACR Subscription')
param containerRegistrySubscription string = subscription().subscriptionId

@description('ACR Resource Group')
param containerRegistryResourceGroup string = resourceGroup().name

@description('ACR Registry Name')
param containerRegistryName string

@description('Additional Resource Group Role Assignments')
param additionalResourceGroupRoleAssignments array = []

@description('Container Registry ID')
var containerRegistryId = '/subscriptions/${containerRegistrySubscription}/resourceGroups/${containerRegistryResourceGroup}/providers/Microsoft.ContainerRegistry/registries/${containerRegistryName}'

var keyVaultId = '/subscriptions/${keyVaultSubscription}/resourceGroups/${keyVaultResourceGroup}/providers/Microsoft.KeyVault/vaults/${keyVaultName}'

// IMPORTANT: The storage account name is unique, and automatically generated. 
//            Do not change this without updating the base template.
var storageAccountName = 'snst${devopsEnvironmentName}${uniqueString(resourceGroup().id)}'

@description('User Assigned Identity Name - DEVOPS. This will have Owner permissions on the ResourceGroup for self-management.')
var userAssignedIdentityName = 'snow-devops-${devopsEnvironmentName}-${uniqueString(resourceGroup().id)}'

@description('User Assigned Identity for MID Servers')
var midServerIdentityName = 'snow-midserver-${devopsEnvironmentName}-${uniqueString(resourceGroup().id)}'

var adminEntitiesTagArray = [
  for entity in adminEntraEntities: '${entity.principalId}:${entity.principalType}'
]
var adminEntitiesTag = join(adminEntitiesTagArray, ',')

var environmentTags = {
  SnowEnvironment: devopsEnvironmentName
  SnowStorageAccount: storageAccountName
  SnowContainerRegistry: '${containerRegistryName}.azurecr.io'
  SnowKeyVaultId: keyVaultId
  SnowContainerSubnetId: containerSubnetId
  SnowContainerRegistryId: containerRegistryId
  SnowDevopsIdentity: userAssignedIdentityName
  SnowMidServerIdentity: midServerIdentityName
  SnowHost: snowHost
  SnowAdminEntities: adminEntitiesTag
}

var storageAccountSubnets = union(
  [
    containerSubnetId
  ],
  additionalStorageSubnetIds
)

resource userAssignedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: userAssignedIdentityName
  location: location
  tags: union(environmentTags, {
    SnowIdentityType: 'DevOps'
  })
}

resource midServerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: midServerIdentityName
  location: location
  tags: union(environmentTags, {
    SnowIdentityType: 'MidServer'
  })
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: [
        for subnetId in storageAccountSubnets: {
          id: subnetId
          action: 'Allow'
          state: 'Succeeded'
        }
      ]
      defaultAction: 'Deny'
    }
  }
  tags: environmentTags
}

resource storageAccountTableServices 'Microsoft.Storage/storageAccounts/tableServices@2024-01-01' = {
  parent: storageAccount
  name: 'default'
}

resource storageAccountMidServersTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: storageAccountTableServices
  name: 'ServiceNowMidServers'
}

resource storageAccountConfigTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: storageAccountTableServices
  name: 'config'
}

module keyVault 'modules/keyvault.bicep' = {
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  name: keyVaultName
  params: {
    keyVaultName: keyVaultName
    location: location
    tenantId: subscription().tenantId
    objectIds: union(
      [
        userAssignedIdentity.properties.principalId
      ],
      map(adminEntraEntities, (entity) => entity.principalId)
    )
    secretsPermissions: ['all','purge']
    keysPermissions: ['all','purge']
    certificatePermissions: ['all','purge']
    enabledForDeployment: true
    enabledForTemplateDeployment: true
    enabledForDiskEncryption: true
    skuName: 'standard'
    secretsObject: {
      secrets: []
    }
    tags: environmentTags
  }
}

module keyVaultSecrets './azure_servicenow_mid_acs_credentials.bicep' = if(deployCredentials && !empty(snowCredentialsParsed)) {
  name: 'KeyVaultSecrets-${devopsEnvironmentName}-${deploymentKey}'
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  dependsOn: [
    keyVault
    userAssignedIdentity
    midServerIdentity
    storageAccount
    storageAccountMidServersTable
    storageAccountConfigTable
  ]
  params: {
    keyVaultName: keyVaultName
    snowConnectionSecretName: 'snow-connection-${toLower(devopsEnvironmentName)}-json'
    instance: snowHost
    credential: snowCredentialsParsed.?Credential ?? {}
    clientID: snowCredentialsParsed.?ClientID ?? ''
    clientSecret: snowCredentialsParsed.?ClientSecret ?? ''
    accessToken: snowCredentialsParsed.?AccessToken ?? ''
    refreshToken: snowCredentialsParsed.?RefreshToken ?? ''
    expires: snowCredentialsParsed.?Expires ?? ''
    proxyURI: snowCredentialsParsed.?ProxyURI ?? ''
    proxyCredential: snowCredentialsParsed.?ProxyCredential ?? {}
    handleRatelimiting: snowCredentialsParsed.?HandleRatelimiting ?? false
    webCallTimeoutSeconds: snowCredentialsParsed.?WebCallTimeoutSeconds
    bypassDefaultProxy: snowCredentialsParsed.?BypassDefaultProxy
    useWebSession: snowCredentialsParsed.?UseWebSession
  }
}

// Add Keyvault Secret permissions for the DevOps identity
module vaultAccessPolicies 'modules/vault-accesspolicies.bicep' = {
  name: 'DevopsVaultAccessPolicies'
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  params: {
    principalId: userAssignedIdentity.properties.principalId
    keyVaultName: keyVault.name
  }
}

// Add Container Registry Permissions for the identity
module containerRegistry 'modules/container-registry.bicep' = {
  name: 'containerRegistry'
  scope: resourceGroup(containerRegistrySubscription, containerRegistryResourceGroup)
  params: {
    registryName: containerRegistryName
  }
}

module assignPermissions './azure_servicenow_mid_acs_permissions.bicep' = if (deployPermissions) {
  name: 'AssignPermissions-${devopsEnvironmentName}'
  params: {
    devopsEnvironmentName: devopsEnvironmentName
    containerRegistrySubscription: containerRegistrySubscription
    containerRegistryResourceGroup: containerRegistryResourceGroup
    containerRegistryName: containerRegistryName
    keyVaultSubscription: keyVaultSubscription
    keyVaultResourceGroup: keyVaultResourceGroup
    keyVaultName: keyVaultName
    containerSubnetId: containerSubnetId
    virtualNetworkRoleId: virtualNetworkRoleId
    adminEntraEntities: adminEntraEntities
    additionalResourceGroupRoleAssignments: additionalResourceGroupRoleAssignments
  }
  dependsOn: [
    userAssignedIdentity
    midServerIdentity
    storageAccount
    storageAccountMidServersTable
    storageAccountConfigTable
    keyVault
  ]
}

// Optional: Validate the environment by running a deployment script with PSSnow.MidTools
module dsValidateEnvironment 'modules/servicenow.midtools.deploymentscript.bicep' = if (runValidationScript) {
  name: 'ValidateEnvironment-${devopsEnvironmentName}'
  params: {
    deploymentScriptName: 'ValidateEnvironment-${devopsEnvironmentName}'
    devopsEnvironmentName: devopsEnvironmentName
    userAssignedIdentityName: userAssignedIdentityName
    inlineScript: '''
      Resolve-SNOWMIDPrereqs
      $ctx = Resolve-SNOWMIDBuildContext
      $SnowConn = Resolve-SNOWMIDEnvironmentAuth
      foreach($key in $Ctx.Keys) {
        $DeploymentScriptOutputs[$key] = $Ctx[$key]
      }
      $ImageState = Resolve-SNOWMIDImageState
      foreach($key in $ImageState.Keys) {
        $DeploymentScriptOutputs[$key] = $ImageState[$key]
      }
    '''
  }
  dependsOn: [
    containerRegistry
    vaultAccessPolicies
    keyVault
    storageAccount
    storageAccountMidServersTable
    storageAccountConfigTable
  ]
}

module appendResourceGroupTags 'modules/append-resoure-group-tags.bicep' = {
  name: 'appendResourceGroupTags'
  params: {
    tags: {
      SnowEnvironments: devopsEnvironmentName
    }
  }
}

output resourceGroupId string = resourceGroup().id
output containerRegistry object = containerRegistry.outputs.containerRegistry
output keyVault object = keyVault.outputs.keyVault
output storageAccount object = storageAccount
output userAssignedIdentity object = userAssignedIdentity
output midServerIdentity object = midServerIdentity
