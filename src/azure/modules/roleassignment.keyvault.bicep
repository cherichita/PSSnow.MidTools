targetScope = 'resourceGroup'

param keyVaultName string
param roleDefinitionId string
param principalId string
param principalType string = 'ServicePrincipal'

resource keyVault 'Microsoft.KeyVault/vaults@2021-10-01' existing = {
  name: keyVaultName
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(keyVault.id, roleDefinitionId, principalId)
  scope: keyVault
  properties: {
    roleDefinitionId: roleDefinitionId
    principalId: principalId
    principalType: principalType
  }
}

output roleAssignment object = roleAssignment
