targetScope = 'subscription'

param principalId string
param roleDefinitionId string
param principalType string = 'ServicePrincipal'

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(subscription().id, roleDefinitionId, principalId)
  scope: subscription()
  properties: {
    roleDefinitionId: roleDefinitionId
    principalId: principalId
    principalType: principalType
  }
}
