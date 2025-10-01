param storageAccountName string
param blobContainerName string = 'snow-ps'
param timeStamp string = utcNow('o')

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2021-09-01' existing = {
  parent: storageAccount
  name: 'default'
}

resource blobContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2021-09-01' existing = {
  parent: blobService
  name: blobContainerName
}

// Define account SAS properties for the function
var serviceSasProperties = {
  canonicalizedResource: '/blob/${storageAccount.name}/${blobContainerName}'
  signedStart: dateTimeAdd(timeStamp, '-PT5H')
  signedExpiry: dateTimeAdd(timeStamp, 'PT24H')
  signedProtocol: 'https'
  signedPermission: 'r' // Read permission
  signedResource: 'c' // Service, Container, and Object
  signedServices: 'b' // Blob service
}

// Generate the service SAS token

var storageSas = replace(replace(storageAccount.listServiceSas('2024-01-01', serviceSasProperties).serviceSasToken, '%3A', ':'), '%3D', '=')
var baseUrl = '${storageAccount.properties.primaryEndpoints.blob}${blobContainerName}'
output storageAccountId string = storageAccount.id
output storageAccountBlobServiceSas string = storageSas
output storageAccountBlobContainerUrl string = baseUrl
