param subnetId string
param roleDefinitionId string
param principalId string
param principalType string = 'ServicePrincipal'

var subnetParts = split(subnetId, '/')
var virtualNetworkName = subnetParts[8] // The 9th part is the virtual network name

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' existing = {
  name: virtualNetworkName
}

resource roleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: roleDefinitionId
  scope: subscription()
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(virtualNetworkName, roleDefinition.id, principalId)
  scope: virtualNetwork
  properties: {
    roleDefinitionId: roleDefinition.id
    principalId: principalId
    principalType: principalType
  }
  dependsOn: [
    roleDefinition
    virtualNetwork
  ]
}

output roleAssignment object = roleAssignment
