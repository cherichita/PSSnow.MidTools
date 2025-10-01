targetScope = 'resourceGroup'

param storageAccountName string
param roleDefinitionId string
param principalId string
param principalType string = 'ServicePrincipal'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(storageAccount.id, roleDefinitionId, principalId)
  scope: storageAccount
  properties: {
    roleDefinitionId: roleDefinitionId
    principalId: principalId
    principalType: principalType
  }
}

output roleAssignment object = roleAssignment
