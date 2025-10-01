targetScope = 'resourceGroup'

param roleDefinitionId string
param principalId string
param principalType string = 'ServicePrincipal'

resource roleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: last(split(roleDefinitionId, '/'))
  scope: subscription()
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(resourceGroup().id, roleDefinition.name, principalId)
  scope: resourceGroup()
  properties: {
    roleDefinitionId: roleDefinition.id
    principalId: principalId
    principalType: principalType
  }
}

output roleAssignment object = roleAssignment
