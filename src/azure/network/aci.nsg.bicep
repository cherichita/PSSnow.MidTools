
param nsgName string
param location string = resourceGroup().location

resource nsgName_resource 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowInbound-443'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound to destination port 443'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1001
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowInbound-dbports'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound to database ports'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1002
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '1433-1434'
            '2382-2383'
            '5432'
            '27016-27019'
            '3306'
            '33060'
            '6446-6449'
            '50000-50001'
            '1521-1525'
            '8000'
            '8200'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'Allow-AzureLoadBalancer-Inbound'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow AzureLoadBalancer inbound'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1003
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'fileshare-access'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound fileshare access'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1004
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '111'
            '139'
            '445'
            '2048'
            '2049'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'service_bus'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound service bus access'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1005
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '5671'
            '5672'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'event_hub'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound event hub access'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '9093'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1006
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'mongodb'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound mongodb access'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1007
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '1024-1030'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'elastic'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound elastic access'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '9243'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1008
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'redis'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound redis access'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1009
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '6379-6380'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'Deny-udp-Inbound'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Deny UDP inbound'
          protocol: 'Udp'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 4095
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'Deny-tcp-Inbound'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Deny TCP inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          priority: 4096
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowInbound-https-9443-9455'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound to destination port 9443-9455'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1000
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '9443-9455'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'Allow-BatchAccount-Inbound'
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          description: 'Allow inbound batch account access'
          protocol: '*'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1010
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '29876-29877'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
    ]
  }
}

output nsgId string = nsgName_resource.id
