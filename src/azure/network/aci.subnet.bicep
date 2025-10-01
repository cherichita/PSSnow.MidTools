
param virtualNetworkName string 

param subnetName string
param subnetAddressPrefix string = '10.166.85.0/26'

param workloadNsgId string

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' existing = {
  name: virtualNetworkName
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  name: subnetName
  parent: virtualNetwork
  properties: {
    addressPrefix: subnetAddressPrefix
    networkSecurityGroup: {
      id: workloadNsgId
    }
    serviceEndpoints: [
      {
        service: 'Microsoft.Storage'
        locations: [
          'canadacentral'
          'canadaeast'
        ]
      }
    ]
    delegations: [
      {
        name: 'ACIDelegationService'
        properties: {
          serviceName: 'Microsoft.ContainerInstance/containerGroups'
        }
        type: 'Microsoft.Network/virtualNetworks/subnets/delegations'
      }
    ]
    privateEndpointNetworkPolicies: 'Enabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
  }
}

output subnetId string = subnet.id
output subnetName string = subnet.name
output subnetAddressPrefix string = subnet.properties.addressPrefix
output virtualNetworkId string = virtualNetwork.id
