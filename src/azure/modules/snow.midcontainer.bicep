// Module to deploy a container group for a ServiceNow MID Server
// This module will deploy a container group with a single container running a ServiceNow MID Server

@description('The ServiceNow URL. Fully qualified. Example: https://<instance>.service-now.com')
param midInstanceUrl string

@description('The MID Server name')
param midServerName string

@description('The MID Server username. Must exist, and have the mid_server role')
param midInstanceUsername string
@secure()
param midInstancePassword string

@description('The fully qualified image path to use for the container. [registry].azurecr.io/snow_mid_custom:yokohama-12-18-2024__patch1-02-21-2025_03-05-2025_2133')
param imagePath string
param containerRegistryId string
param userAssignedIdentityName string
param containerSubnetId string
param storageAccountName string

@description('The number of CPU cores to allocate to the MID Server container')
@allowed([1, 2, 4, 8])
param numCpu int = 1

@description('The amount of memory in GB to allocate to the MID Server container')
@allowed([1, 2, 4, 8, 16])
param memoryInGB int = 4

@description('Whether to use certificates for MID Server authentication. If true, a root CA and server certificate will be created in Key Vault.')
param useCertificates bool = true

@secure()
param midServerCertificatePemBase64 string = ''

// The default below ensures that any custom JAR files are loaded before the default JAR files
// This ensures any custom JAR files supporting Azure integrations are loaded before out-of-date versions shipped with the agent.
// See: https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0862383
param additionalEnvironmentVariables array = [
  {
    name: 'MID_WRAPPER_wrapper__java__classpath__1'
    value: 'extlib/*.jar'
  }
  {
    name: 'MID_WRAPPER_wrapper__java__classpath__2'
    value: 'lib/*.jar'
  }
]
param location string

@description('Tags to apply to the executed deployment script')
param tags object = {}

param command string[] = [
  '/opt/snc_mid_server/init'
  'start'
]

var containerRegistryObject = parseResourceId(containerRegistryId)
resource containerRegistryExisting 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  scope: resourceGroup(containerRegistryObject.SubscriptionId, containerRegistryObject.ResourceGroup)
  name: containerRegistryObject.Name
}

resource userAssignedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: userAssignedIdentityName
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

var fileShareName = toLower(replace(midServerName, '-', ''))
resource midServerShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  name: toLower('${storageAccount.name}/default/${fileShareName}')
  properties: {
    shareQuota: 5
  }
}
resource midServerShareKeystore 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = if (!useCertificates) {
  name: toLower('${storageAccount.name}/default/${fileShareName}keystore')
  properties: {
    shareQuota: 1
  }
}

// Resolve Network
var subnetObject = parseResourceId(containerSubnetId)
var virtualNetworkName = split(containerSubnetId, '/')[8]

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-05-01' existing = {
  name: virtualNetworkName
  scope: resourceGroup(subnetObject.SubscriptionId, subnetObject.ResourceGroup)
}

resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: midServerName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentity.id}': {}
    }
  }
  properties: {
    containers: [
      {
        name: midServerName
        properties: {
          image: imagePath
          resources: {
            requests: {
              cpu: numCpu
              memoryInGB: memoryInGB
            }
          }
          command: command
          environmentVariables: union(
            [
              {
                name: 'HOSTNAME'
                value: midServerName
              }
              {
                name: 'MID_INSTANCE_URL'
                value: midInstanceUrl
              }
              {
                name: 'MID_SERVER_NAME'
                value: midServerName
              }
              {
                name: 'MID_INSTANCE_USERNAME'
                value: midInstanceUsername
              }
              {
                name: 'MID_INSTANCE_PASSWORD'
                secureValue: midInstancePassword
              }
              {
                name: 'MID_CONFIG_azure__client__id'
                value: userAssignedIdentity.properties.principalId
              }
              {
                name: 'MID_CONFIG_mid__ssl__bootstrap__default__check_cert_hostname'
                value: 'false'
              }
              {
                name: 'MID_CUSTOM_PEM_FILE'
                value: '/opt/snc_mid_server/current_cert.pem'
              }
              {
                name: 'MID_SERVER_PEM_BASE64'
                secureValue: useCertificates ? midServerCertificatePemBase64 : ''
              }
            ],
            additionalEnvironmentVariables
          )
          volumeMounts: !useCertificates
            ? [
                {
                  name: 'midserver'
                  mountPath: '/opt/snc_mid_server/mid_container'
                }
                {
                  name: 'keystore'
                  mountPath: '/opt/snc_mid_server/agent/security'
                }
              ]
            : []
        }
      }
    ]
    imageRegistryCredentials: [
      {
        server: containerRegistryExisting.properties.loginServer
        identity: userAssignedIdentity.id
      }
    ]
    dnsConfig: (!empty(virtualNetwork.properties.?dhcpOptions.?dnsServers))
      ? {
          nameServers: virtualNetwork.properties.dhcpOptions.dnsServers
        }
      : null
    osType: 'Linux'
    restartPolicy: 'Always'
    subnetIds: [
      { name: 'default', id: containerSubnetId }
    ]
    volumes: !useCertificates
      ? [
          {
            name: 'midserver'
            azureFile: {
              shareName: fileShareName
              storageAccountName: storageAccount.name
              storageAccountKey: storageAccount.listKeys().keys[0].value
            }
          }
          {
            name: 'keystore'
            azureFile: {
              shareName: '${fileShareName}keystore'
              storageAccountName: storageAccount.name
              storageAccountKey: storageAccount.listKeys().keys[0].value
            }
          }
        ]
      : []
  }
  tags: union(tags, {
    SnowMidServerName: midServerName
    SnowMidServerUser: midInstanceUsername
    SnowMidImage: imagePath
  })
}

output container object = containerGroup

func parseResourceId(resourceId string) object => {
  SubscriptionId: split(resourceId, '/')[2]
  ResourceGroup: split(resourceId, '/')[4]
  Name: last(split(resourceId, '/'))
}
