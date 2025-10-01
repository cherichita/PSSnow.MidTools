@description('Array of MID server definitions. Each object must contain midServerName, midServerCluster, devopsEnvironmentName, customImageName, and customDockerfileContent.')
param midServers array

// Deploy each MID server using the single-server module sequentially
// Note: This creates individual modules with dependencies to ensure sequential deployment
@batchSize(1)
module midServersModules 'servicenow_mid_server_single.bicep' = [for (mid, i) in midServers: {
  name: 'MidDeploy-${mid.devopsEnvironmentName}-${mid.midServerName}'
  params: {
    devopsEnvironmentName: mid.devopsEnvironmentName
    midServerName: mid.midServerName
    midServerCluster: mid.midServerCluster
    customImageName: mid.?customImageName
    customDockerfileContent: mid.?customDockerfileContent
    numCpu: mid.?numCpu
    memoryInGB: mid.?memoryInGB
  }
}]

output midServerOutputs array = [for (mid, i) in midServers: {
  outputs: midServersModules[i].outputs
}]
