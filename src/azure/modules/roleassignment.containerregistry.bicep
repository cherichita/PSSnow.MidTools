targetScope = 'resourceGroup'

param containerRegistryName string
param roleDefinitionName string
param principalId string
param principalType string = 'ServicePrincipal'

resource containerRegistry 'Microsoft.ContainerRegistry/registries@2025-05-01-preview' existing = {
  name: containerRegistryName
}

resource roleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: roleDefinitionName // Contributor
  scope: subscription()
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(containerRegistryName, roleDefinition.name, principalId)
  scope: containerRegistry
  properties: {
    roleDefinitionId: roleDefinition.id
    principalId: principalId
    principalType: principalType
  }
}

output roleAssignment object = roleAssignment
