param subnetId string
param subnetRoleAssingments array = []
param virtualNetworkRoleId string = '9980e02c-c2be-4d73-94e8-173b1dc7cf3c' // Contributor on Virtual Network by Default

var subnetParts = split(subnetId, '/')
// var subnetName = last(subnetParts)
var virtualNetworkName = subnetParts[8]

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' existing = {
  name: virtualNetworkName
}

resource networkRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: virtualNetworkRoleId // Contributor on Subnet 
  scope: subscription()
}

resource networkContributorAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = [
  for ra in subnetRoleAssingments: {
    name: guid(virtualNetwork.id, networkRole.id, ra.principalId)
    scope: virtualNetwork
    properties: {
      roleDefinitionId: networkRole.id
      principalId: ra.principalId
      principalType: ra.principalType
    }
  }
]

output virtualNetwork object = virtualNetwork
