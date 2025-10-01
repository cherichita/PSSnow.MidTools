import { parseResourceId } from 'modules/common-functions.bicep'

@description('The name of the environment. This will be used to tag, and identify resources.')
@maxLength(5)
param devopsEnvironmentName string = 'dev'

// Network parameters
@description('Subnet ID for the container. Must have access to ServiceNow instance, ACR, and ARM Services at a minimum.')
param containerSubnetId string

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

@description('The Entra ID (Azure AD) objects with principalId and principalType to be added to the Key Vault access policy, and admin role assignments.')
param adminEntraEntities array = []

@description('Additional Resource Group Role Assignments')
param additionalResourceGroupRoleAssignments array = []

// IMPORTANT: The storage account name is unique, and automatically generated. 
//            Do not change this without updating the base template.
var storageAccountName = 'snst${devopsEnvironmentName}${uniqueString(resourceGroup().id)}'

@description('User Assigned Identity Name - DEVOPS. This will have Owner permissions on the ResourceGroup for self-management.')
var userAssignedIdentityName = 'snow-devops-${devopsEnvironmentName}-${uniqueString(resourceGroup().id)}'

@description('User Assigned Identity for MID Servers')
var midServerIdentityName = 'snow-midserver-${devopsEnvironmentName}-${uniqueString(resourceGroup().id)}'

resource userAssignedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: userAssignedIdentityName
}

resource midServerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: midServerIdentityName
}

var subnetParts = containerSubnetId != ''
  ? parseResourceId(containerSubnetId)
  : { ResourceGroup: resourceGroup().name, SubscriptionId: subscription().subscriptionId }

// DevOps Network Role Assignment
module roleAssignmentNetworkDevOps 'modules/roleassignment.subnet.bicep' = if (containerSubnetId != '') {
  name: 'roleAssignmentNetworkDevops'
  scope: resourceGroup(subnetParts.ResourceGroup)
  params: {
    subnetId: containerSubnetId
    roleDefinitionId: virtualNetworkRoleId
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

module roleAssignmentNetworkDevOpsReader 'modules/roleassignment.resourcegroup.bicep' = if (containerSubnetId != '') {
  name: 'roleAssignmentNetworkDevopsReader'
  scope: resourceGroup(subnetParts.ResourceGroup)
  params: {
    roleDefinitionId: readerRoleDefinition.id
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// MID Server Network Role Assignment
module roleAssignmentNetworkMidServer 'modules/roleassignment.subnet.bicep' = if (containerSubnetId != '') {
  name: 'roleAssignmentNetworkMid'
  scope: resourceGroup(subnetParts.ResourceGroup)
  params: {
    subnetId: containerSubnetId
    roleDefinitionId: virtualNetworkRoleId
    principalId: midServerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
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

resource storageFileDataPrivilegedContributor 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: '69566ab7-960f-475b-8e7c-b3118f30c6bd' // Storage File Data Privileged Contributor
  scope: tenant()
}

resource storageTableDataContributor 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3' // Storage Table Data Contributor
  scope: tenant()
}

@description('This is the built-in Key Vault Administrator role. See https://docs.microsoft.com/azure/role-based-access-control/built-in-roles#key-vault-administrator')
resource keyVaultAdministratorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2018-01-01-preview' existing = {
  name: '00482a5a-887f-4fb3-b363-3b7fe8e74483'
  scope: subscription()
}

resource keyvaultReaderRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Reader
  scope: subscription()
}

resource contributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: 'b24988ac-6180-42a0-ab88-20f7382dd24c' // Contributor
  scope: subscription()
}

resource readerRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: 'acdd72a7-3385-48ef-bd42-f606fba81ae7' // Reader
  scope: subscription()
}

resource acrPullRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: '7f951dda-4ed3-4680-a7ca-43fe172d538d' // AcrPull
  scope: subscription()
}
// End of Roles

resource keyVault 'Microsoft.KeyVault/vaults@2024-12-01-preview' existing = {
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  name: keyVaultName
}

// Storage File Data Privileged Contributor for DevOps identity
module roleAssignmentStorageFiles 'modules/roleassignment.storage.bicep' = {
  name: 'roleAssignmentStorageFiles'
  params: {
    storageAccountName: storageAccount.name
    roleDefinitionId: storageFileDataPrivilegedContributor.id
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage File Data Privileged Contributor for MidServer identity
module midRoleAssignmentStorageFiles 'modules/roleassignment.storage.bicep' = {
  name: 'midRoleAssignmentStorageFiles'
  params: {
    storageAccountName: storageAccount.name
    roleDefinitionId: storageFileDataPrivilegedContributor.id
    principalId: midServerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Table Data Contributor for DevOps identity
module roleAssignmentStorageTables 'modules/roleassignment.storage.bicep' = {
  name: 'roleAssignmentStorageTables'
  params: {
    storageAccountName: storageAccount.name
    roleDefinitionId: storageTableDataContributor.id
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Table Data Contributor for MidServer identity
module midRoleAssignmentStorageTables 'modules/roleassignment.storage.bicep' = {
  name: 'midRoleAssignmentStorageTables'
  params: {
    storageAccountName: storageAccount.name
    roleDefinitionId: storageTableDataContributor.id
    principalId: midServerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Contributor role for DevOps identity at resource group
module roleAssignmentResourceGroup 'modules/roleassignment.resourcegroup.bicep' = {
  name: 'roleAssignmentResourceGroup'
  params: {
    roleDefinitionId: contributorRoleDefinition.id
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Reader role for MidServer identity at resource group
module roleAssignmentResourceGroupMidServer 'modules/roleassignment.resourcegroup.bicep' = {
  name: 'roleAssignmentResourceGroupMidServer'
  params: {
    roleDefinitionId: readerRoleDefinition.id
    principalId: midServerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Assign Key Vault Administrator role to the DevOps identity
module roleAssignmentKeyVault 'modules/roleassignment.keyvault.bicep' = {
  name: 'roleAssignmentKeyVault'
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  params: {
    keyVaultName: keyVault.name
    roleDefinitionId: keyVaultAdministratorRoleDefinition.id
    principalId: userAssignedIdentity.properties.principalId
  }
}

// Assign Key Vault Reader role to the MidServer identity
module roleAssignmentKeyVaultReaderMid 'modules/roleassignment.keyvault.bicep' = {
  name: 'roleAssignmentKeyVaultReaderMid'
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  params: {
    keyVaultName: keyVault.name
    roleDefinitionId: keyvaultReaderRoleDefinition.id
    principalId: midServerIdentity.properties.principalId
  }
}

module acrDevopsContributor 'modules/roleassignment.containerregistry.bicep' = {
  name: 'acrDevopsContributor'
  scope: resourceGroup(containerRegistrySubscription, containerRegistryResourceGroup)
  params: {
    containerRegistryName: containerRegistryName
    roleDefinitionName: contributorRoleDefinition.name
    principalId: userAssignedIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

module acrMidServerContributor 'modules/roleassignment.containerregistry.bicep' = {
  name: 'acrMidServerContributor'
  scope: resourceGroup(containerRegistrySubscription, containerRegistryResourceGroup)
  params: {
    containerRegistryName: containerRegistryName
    roleDefinitionName: contributorRoleDefinition.name
    principalId: midServerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

module acrMidServerAcrPull 'modules/roleassignment.containerregistry.bicep' = {
  name: 'acrMidServerAcrPull'
  scope: resourceGroup(containerRegistrySubscription, containerRegistryResourceGroup)
  params: {
    containerRegistryName: containerRegistryName
    roleDefinitionName: acrPullRoleDefinition.name
    principalId: midServerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

module resourceGroupContributors 'modules/roleassignment.resourcegroup.bicep' = [
  for entity in adminEntraEntities: {
    name: 'roleAssignment-${uniqueString(devopsEnvironmentName, entity.principalId)}'
    params: {
      roleDefinitionId: contributorRoleDefinition.id
      principalId: entity.principalId
      principalType: entity.principalType ?? 'ServicePrincipal'
    }
  }
]

module acrContributors 'modules/roleassignment.resourcegroup.bicep' = [
  for entity in adminEntraEntities: {
    name: 'acrRoleAssignment-${uniqueString(devopsEnvironmentName, entity.principalId)}'
    scope: resourceGroup(containerRegistrySubscription, containerRegistryResourceGroup)
    params: {
      roleDefinitionId: contributorRoleDefinition.id
      principalId: entity.principalId
      principalType: entity.principalType ?? 'ServicePrincipal'
    }
  }
]


module networkAdditionalAssignments 'modules/roleassignment.subnet.bicep' = [
  for entity in adminEntraEntities: if (containerSubnetId != '') {
    name: 'networkRoleAssignment-${uniqueString(devopsEnvironmentName, entity.principalId)}'
    scope: resourceGroup(subnetParts.ResourceGroup)
    params: {
      subnetId: containerSubnetId
      roleDefinitionId: virtualNetworkRoleId
      principalId: entity.principalId
      principalType: entity.principalType ?? 'ServicePrincipal'
    }
  }
]

module additionalRoleAssignments 'modules/roleassignment.resourcegroup.bicep' = [
  for assignment in additionalResourceGroupRoleAssignments: {
    name: 'roleAssignment-${uniqueString(devopsEnvironmentName, assignment.roleDefinitionId, assignment.principalId)}'
    params: {
      roleDefinitionId: assignment.roleDefinitionId
      principalId: assignment.principalId
      principalType: assignment.principalType ?? 'ServicePrincipal'
    }
  }
]

output resourceGroupId string = resourceGroup().id
output userAssignedIdentity object = userAssignedIdentity
output midServerIdentity object = midServerIdentity
