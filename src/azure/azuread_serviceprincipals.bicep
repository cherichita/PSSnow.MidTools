// azuread_serviceprincipals.bicep
// Deploy Azure AD Service Principals, including optional federated credentials.
// Default Permissions
// * Owner on Resource Group
// * Reader on Subscription
// * Contributor on Virtual Network if subnetId is provided

extension microsoftGraphV1

param applicationName string

param federated bool = false

param federatedCredentialName string = ''

param federatedCredentialIssuer string = ''

param federatedCredentialSubject string = ''

param federatedCredentialAudiences string[] = ['api://AzureADTokenExchange']

param subnetId string = ''

resource clientApp 'Microsoft.Graph/applications@v1.0' = {
  uniqueName: applicationName
  displayName: applicationName
  resource federatedCredential 'federatedIdentityCredentials@v1.0' = if (federated) {
    name: '${applicationName}/${federatedCredentialName}'
    issuer: federatedCredentialIssuer
    subject: federatedCredentialSubject
    audiences: federatedCredentialAudiences
  }
}

resource servicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: clientApp.appId
  displayName: applicationName
}

resource contributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: 'b24988ac-6180-42a0-ab88-20f7382dd24c' // Contributor
  scope: subscription()
}

resource readerRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: 'acdd72a7-3385-48ef-bd42-f606fba81ae7' // Reader
  scope: subscription()
}

// Reader on Sub
module roleAssignment 'modules/roleassignment.subscription.bicep' = {
  name: 'SubscriptionReader-${applicationName}'
  scope: subscription()
  params: {
    principalId: servicePrincipal.id
    roleDefinitionId: readerRoleDefinition.id
  }
}

// Contributor role for DevOps identity at resource group
module roleAssignmentResourceGroup 'modules/roleassignment.resourcegroup.bicep' = {
  name: 'roleAssignmentResourceGroup-${applicationName}'
  params: {
    roleDefinitionId: contributorRoleDefinition.id
    principalId: servicePrincipal.id
    principalType: 'ServicePrincipal'
  }
}

var networkResourceGroupName = (subnetId != '') ? split(subnetId, '/')[4] : ''

module subnetRoleAssignment 'modules/roleassignment.subnet.bicep' = if (subnetId != '') {
  name: 'SubnetRoleAssignment-${applicationName}'
  scope: resourceGroup(networkResourceGroupName)
  params: {
    subnetId: subnetId 
    roleDefinitionId: 'b24988ac-6180-42a0-ab88-20f7382dd24c' // Contributor on Subnet
    principalId: servicePrincipal.id
    principalType: 'ServicePrincipal'
  }
}

output appId string = clientApp.appId
output servicePrincipalId string = servicePrincipal.id
output spObject object = {
  app: clientApp
  sp: servicePrincipal
}
// output virtualNetwork object = (subnetId != '') ? subnetPermissions.outputs.virtualNetwork : {}
