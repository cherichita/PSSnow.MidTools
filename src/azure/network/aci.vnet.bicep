
param location string = resourceGroup().location
param vnetName string = 'aci-vnet-default'
param vnetAddressPrefixes string[]

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: vnetAddressPrefixes
    }
    privateEndpointVNetPolicies: 'Disabled'
    enableDdosProtection: false
  }
}

output virtualNetwork object = virtualNetwork
