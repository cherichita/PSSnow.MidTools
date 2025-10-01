// BICEP Module for managing ServiceNow MID Servers, users, and images.
// Leverages PSSnow.MidTools.psm1 to manage the MID Server lifecycle.
// See: ../../PSSnow.MidTools.psm1

@description('The name of the environment. This will be used to tag, and identify resources.')
@maxLength(5)
param devopsEnvironmentName string = 'unts'

param deploymentScriptName string = 'SnowMidTools-${devopsEnvironmentName}'

param userAssignedIdentityName string

// By default - pull from GitHub. This can be overridden to point to a private repo or storage account for secure environments.
param midToolsRemoteUriBase string = 'https://raw.githubusercontent.com/cherichita/PSSnow.MidTools/refs/heads/development/src'

@secure()
param midToolsRemoteUriSas string = ''

param supportingScriptUris string[] = []

param inlineScript string = '''
Resolve-SNOWMIDPrereqs
$ctx = Resolve-SNOWMIDBuildContext
foreach($key in $Ctx.Keys) {
  $DeploymentScriptOutputs[$key] = $Ctx[$key]
}
$DeploymentScriptOutputs['ctxJson'] = ($ctx | ConvertTo-Json -Depth 10)
'''

param utcValue string = utcNow()

param scriptEnvironmentVariables array = []
param tags object = resourceGroup().tags

var psToolsSupportFiles = [
  'PSSnow.MidTools.psd1'
  'PSSnow.MidTools.psm1'
  'PSSnow.MidTools.CertTools.ps1'
  'PSSnow.MidTools.Extensions.ps1'
]
var psToolsSupportFileUris = [
  for file in psToolsSupportFiles: '${midToolsRemoteUriBase}/${file}?${midToolsRemoteUriSas}'
]

var storageAccountName = 'snst${devopsEnvironmentName}${uniqueString(resourceGroup().id)}'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource userAssignedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: userAssignedIdentityName
}

var dsEnv = union(
  [
    {
      name: 'SN_MID_ENVIRONMENT_NAME'
      value: devopsEnvironmentName
    }
    {
      name: 'SN_MID_CONTEXT'
      value: 'azure'
    }
    {
      name: 'SN_MID_BUILD_STRATEGY'
      value: 'acr'
    }
    {
      name: 'NO_COLOR'
      value: 'true'
    }
  ],
  scriptEnvironmentVariables
)

resource manageImageScript 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: deploymentScriptName
  location: resourceGroup().location
  identity: {
    type: 'userAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentity.id}': {}
    }
  }
  kind: 'AzurePowerShell'
  properties: {
    environmentVariables: dsEnv
    forceUpdateTag: utcValue
    azPowerShellVersion: '14.3'
    storageAccountSettings: {
      storageAccountName: storageAccount.name
    }
    containerSettings: {
      subnetIds: [
        {
          id: storageAccount.tags.SnowContainerSubnetId
        }
      ]
    }

    scriptContent: join(
      [
        '# GENERATED IN snow-mid-deplyoymentscript.mod.bicep'
        '# This function is called at the bottom of this script.'
        'function SnowMidDeploymentScript {'
              inlineScript
        '}'
        '$DeploymentScriptOutputs.DirContents = Get-ChildItem -Path $PSScriptRoot -Recurse'
        'Get-ChildItem -Path $PSScriptRoot -Recurse'
        'Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath "PSSnow.MidTools.psm1") -Force'
        'SnowMidDeploymentScript'
      ],
      '\n'
    )
    retentionInterval: 'PT1H'
    cleanupPreference: 'OnSuccess'
    supportingScriptUris: union(psToolsSupportFileUris, supportingScriptUris)
  }
  tags: tags
}

output scriptOutput object = manageImageScript.properties.outputs
