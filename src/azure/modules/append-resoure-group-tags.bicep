@description('The tags to append to the resource group')
param tags object

var existingTags = resourceGroup().tags
var mergedTags = union(existingTags, tags)

resource appendTags 'Microsoft.Resources/tags@2021-01-01' = {
  name: 'default'
  properties: {
    tags: mergedTags
  }
}

output mergedTags object = mergedTags
