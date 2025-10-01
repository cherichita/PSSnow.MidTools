param registryName string
param location string = resourceGroup().location

@allowed(['Basic', 'Standard', 'Premium'])
param sku string = 'Basic'
param tags object = {}

param identity object = {
  type: 'SystemAssigned'
}

resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: registryName
  identity: identity
  location: location
  properties: {
    adminUserEnabled: true
  }
  sku: {
    name: sku
  }
  tags: tags
}

output containerRegistry object = containerRegistry
output loginServer string = containerRegistry.properties.loginServer
