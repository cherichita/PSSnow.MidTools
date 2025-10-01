targetScope = 'subscription'

param resourceGroupName string = 'snmid-rg-network-default'

param location string

@description('The name of the virtual network')
param vnetName string = 'aci-vnet-default'

@description('The address prefixes for the virtual network')
param vnetAddressPrefixes array = [
  '10.112.0.0/16'
]

@description('The name of the subnet')
param subnetName string = 'aci-subnet-default'

@description('The name of the network security group')
param nsgName string = 'snowmid-nsg-default'

@description('The address prefix for the subnet')
param subnetAddressPrefix string = '10.112.0.0/24'

resource resourceGroup 'Microsoft.Resources/resourceGroups@2024-11-01' existing = {
  name: resourceGroupName
}

module acsNsg 'aci.nsg.bicep' = {
  scope: resourceGroup
  name: 'aci-nsg-default'
  params: {
    nsgName: nsgName
    location: location
  }
}

module virtualNetwork 'aci.vnet.bicep' = {
  scope: resourceGroup
  name: 'aci-vnet-default'
  params: {
    vnetName: vnetName
    vnetAddressPrefixes: vnetAddressPrefixes
    location: location
  }
}


module aciSubnet 'aci.subnet.bicep' = {
  scope: resourceGroup
  name: 'aci-subnet-default'
  params: {
    subnetName: subnetName
    workloadNsgId: acsNsg.outputs.nsgId
    virtualNetworkName: vnetName
    subnetAddressPrefix: subnetAddressPrefix
  }
  dependsOn: [
    virtualNetwork
  ]
}

output subnetId string = aciSubnet.outputs.subnetId
