targetScope = 'resourceGroup'

param keyVaultName string
param principalId string
param permissions object = {
  secrets: [
    'all'
  ]
}

resource keyVault 'Microsoft.KeyVault/vaults@2021-10-01' existing = {
  name: keyVaultName
}

resource accessPolicies 'Microsoft.KeyVault/vaults/accessPolicies@2019-09-01' = {
  parent: keyVault
  name: 'add'
  properties: {
    accessPolicies: [
      {
        objectId: principalId
        tenantId: subscription().tenantId
        permissions: permissions
      }
    ]
  }
}
