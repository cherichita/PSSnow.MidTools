// Create an Azure Container environment for ServiceNow MID Servers. Optionally deploys network resources. 
// For production use, it is reccomended to leave network deployments out and use the base template
targetScope = 'resourceGroup'

@description('The name of the network resource group.')
param networkResourceGroupName string = ''

@description('Deploy the network resources?')
param deployNetwork bool = false

@description('The name of the virtual network')
param vnetName string = 'aci-vnet-default'

@description('The address prefixes for the virtual network')
param vnetAddressPrefixes array = [
  '10.112.0.0/16'
]

@description('The name of the subnet')
param subnetName string = 'aci-subnet-default'

@description('The name of the network security group')
param nsgName string = 'snowmid-nsg-default'

@description('The address prefix for the subnet')
param subnetAddressPrefix string = '10.112.0.0/24'

// Begin Parameters for the Workload Resource Group Deployment
@description('The name of the environment. This will be used to tag, and identify resources.')
@maxLength(5)
@minLength(1)
param devopsEnvironmentName string

@description('Deploy Permissions? Requires Owner permissions on the resource group.')
param deployPermissions bool = true

@description('Location for the resources')
param location string

@description('Run the validation script to test connectivity to ServiceNow')
param runValidationScript bool = false

@description('Additional Azure AD Objects with principalId and principalType to be added to the Key Vault access policy')
param adminEntraEntities array = []

// ServiceNow Parameters 
@description('ServiceNow Host. Will be stored as a tag on the storage account')
param snowHost string

@description('Set to true and provide snowCredentials or snowCredentialsJson to deploy the ServiceNow credentials to Key Vault.')
param deployCredentials bool = true

@description('SNOW Credentials Object - Must match Set-SNOWMidEnvironmentSecret parameters')
@secure()
param snowCredentials object = {}

@description('The snowCredentials object in JSON format.')
@secure()
param snowCredentialsJson string = ''

// Network parameters
@description('Subnet ID for the container. Must have access to ServiceNow instance, ACR, and ARM Services at a minimum.')
param containerSubnetId string = ''

@description('Subnet IDs to allow access to the storage account')
param additionalStorageSubnetIds array = []

@description('The ID of the virtual network role. This is used to assign the role to the subnet. Default is Contributor on the virtual network.')
param virtualNetworkRoleId string = '9980e02c-c2be-4d73-94e8-173b1dc7cf3c'

@description('ACR Subscription')
param containerRegistrySubscription string = subscription().subscriptionId

@description('ACR Resource Group')
param containerRegistryResourceGroup string

@description('ACR Registry Name')
param containerRegistryName string

type roleDefinition = {
  roleDefinitionId: string
  principalId: string
  principalType: string // 'ServicePrincipal', 'User', or 'Group'
}

@description('Must contain roleDefinitionId, principalId, and principalType. This is used to assign additional roles to the resource group.')
param additionalResourceGroupRoleAssignments array = []

module aciNetwork './network/default.virtualnetwork.bicep' = if (deployNetwork) {
  name: 'ServiceNow-MID-ACI-Network'
  scope: subscription()
  params: {
    resourceGroupName: networkResourceGroupName
    location: location
    vnetName: vnetName
    nsgName: nsgName
    vnetAddressPrefixes: vnetAddressPrefixes
    subnetName: subnetName
    subnetAddressPrefix: subnetAddressPrefix
  }
}

module midEnvironment './azure_servicenow_mid_acs_base.bicep' = {
  scope: resourceGroup()
  name: 'ServiceNow-MID-ACI-${devopsEnvironmentName}'
  params: {
    devopsEnvironmentName: devopsEnvironmentName
    deployPermissions: deployPermissions
    location: location
    runValidationScript: runValidationScript
    adminEntraEntities: adminEntraEntities
    snowHost: snowHost
    deployCredentials: deployCredentials
    snowCredentials: snowCredentials
    snowCredentialsJson: snowCredentialsJson
    containerSubnetId: deployNetwork ? aciNetwork!.outputs.subnetId : containerSubnetId
    additionalStorageSubnetIds: additionalStorageSubnetIds
    virtualNetworkRoleId: virtualNetworkRoleId
    containerRegistrySubscription: containerRegistrySubscription
    containerRegistryResourceGroup: containerRegistryResourceGroup
    containerRegistryName: containerRegistryName
    additionalResourceGroupRoleAssignments: additionalResourceGroupRoleAssignments
  }
}
