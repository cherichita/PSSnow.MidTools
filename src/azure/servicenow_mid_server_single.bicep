param devopsEnvironmentName string

@minLength(3)
@maxLength(16)
param midServerName string

@minLength(3)
@maxLength(16)
param midServerCluster string

@description('The number of CPU cores to allocate to the MID Server container')
@allowed([1, 2, 4, 8])
param numCpu int = 1

@description('The amount of memory in GB to allocate to the MID Server container')
@allowed([1, 2, 4, 8, 16])
param memoryInGB int = 4

@description('Whether to use certificates for MID Server authentication. If true, a root CA and server certificate will be created in Key Vault.')
param useCertificates bool = true

param midToolsRemoteUriBase string = 'https://raw.githubusercontent.com/cherichita/PSSnow.MidTools/refs/heads/development/src'

@secure()
param midToolsRemoteUriSas string = ''

param customImageName string = 'snow_mid_custom'
param customDockerfileContent string = '''
FROM localhost/snow_mid_server:yokohama-12-18-2024__patch1-02-21-2025_03-05-2025_2133
ARG AZ_PWSH_VERSION="14.1.0"
ARG ANSIBLE_VERSION="9.13.0"
ARG AZ_CLI_VERSION="2.74.0"
ARG MID_USERNAME=mid

USER root

RUN dnf update -y && \
    dnf install -y  ca-certificates curl gnupg && \
    curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/pki/rpm-gpg/microsoft.asc.gpg > /dev/null && \
    curl -sL https://packages.microsoft.com/config/rhel/9/prod.repo | tee /etc/yum.repos.d/microsoft-prod.repo && \
    dnf check-update -y && \
    dnf install -y azure-cli-${AZ_CLI_VERSION}-1.el9 && \
    dnf install -y https://github.com/PowerShell/PowerShell/releases/download/v7.5.1/powershell-7.5.1-1.rh.x86_64.rpm && \
    dnf clean all -y

USER $MID_USERNAME

RUN pwsh -C "Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted" && \
    pwsh -C "Install-Module -Name Az -MinimumVersion ${AZ_PWSH_VERSION} -MaximumVersion ${AZ_PWSH_VERSION} -Force -AllowClobber -Scope CurrentUser -Repository PSGallery -AcceptLicense" && \
    pwsh -C "Install-Module -Name PSDepend -Force -AllowClobber -Scope CurrentUser -Repository PSGallery -AcceptLicense" && \
    pwsh -C "Install-Module -Name InvokeBuild -Force -AllowClobber -Scope CurrentUser -Repository PSGallery -AcceptLicense"

ENTRYPOINT ["/opt/snc_mid_server/init", "start"]
'''

param forceBuildCustomImage bool = false

var storageAccountName = 'snst${devopsEnvironmentName}${uniqueString(resourceGroup().id)}'
var keyVaultName = 'snkv-${devopsEnvironmentName}-${uniqueString(resourceGroup().id)}'
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' existing = {
  name: keyVaultName
}

module GetBuildContext 'modules/servicenow.midtools.deploymentscript.bicep' = {
  name: 'GetBuildContext-${midServerName}'
  params: {
    deploymentScriptName: 'SnowMidTools-${midServerName}'
    userAssignedIdentityName: storageAccount.tags.SnowDevopsIdentity
    midToolsRemoteUriBase: empty(midToolsRemoteUriBase) ? null : midToolsRemoteUriBase
    midToolsRemoteUriSas: empty(midToolsRemoteUriSas) ? null : midToolsRemoteUriSas
    inlineScript: '''
      Param(
          [string]$MidServerName = $env:MID_SERVER_NAME,
          [string]$MidServerCluster = $env:MID_SERVER_CLUSTER,
          [string]$RootCACommonName = $env:MID_SERVER_ROOT_CA ?? 'az-mid-ca',
          [string]$MidCertCommonName = $env:MID_SERVER_NAME,
          [System.Boolean]$UseCertificates = $env:SN_MID_USE_CERTIFICATES -eq 'true'
      )
      Resolve-SNOWMIDPrereqs
      $DeploymentScriptOutputs.EntryPoint = @('/opt/snc_mid_server/init')
      $DeploymentScriptOutputs.Cmd = @('start')
      $DeploymentScriptOutputs.EnvVars = @{
          MID_SERVER_NAME         = $MidServerName
          MID_SERVER_CLUSTER      = $MidServerCluster
          SN_MID_ENVIRONMENT_NAME = $env:SN_MID_ENVIRONMENT_NAME
          SN_MID_CONTEXT          = 'azure'
          SN_MID_BUILD_STRATEGY   = 'acr'
      }
      $DeploymentScriptOutputs.SecretEnvVars = @{}
      Connect-SNOWMIDAzureFromEnvironment | Out-Null
      if ($ctx = Resolve-SNOWMIDBuildContext) {
          $DeploymentScriptOutputs.BuildContext = $ctx
          $DeploymentScriptOutputs.VaultName = $ctx.Vault.VaultName
          $DeploymentScriptOutputs.EnvVars += @{
              MID_INSTANCE_URL = "$($ctx.StorageAccount.tags.SnowHost)"
              MID_WRAPPER_wrapper__java__classpath__1 = 'extlib/*.jar'
              MID_WRAPPER_wrapper__java__classpath__2 = 'lib/*.jar'
          }
      }
      else {
          throw "Failed to resolve build context for environment $($env:SN_MID_ENVIRONMENT_NAME). Ensure the environment name is correct and that you have access to it."
      }
      if ($UseCertificates) {
          $RootCA = Set-SNOWMidRootCertificate -VaultName $ctx.Vault.VaultName -RootCN $RootCACommonName -ErrorAction Stop
          $MidCert = Set-SNOWMidServerCertificate -VaultName $ctx.Vault.VaultName -LeafCN $MidCertCommonName -Signer $RootCA.Collection[0] -ErrorAction Stop
          $DeploymentScriptOutputs.MidCert = $MidCert
          $DeploymentScriptOutputs.SecretEnvVars.MID_SERVER_PEM_BASE64 = $MidCert.PemSecret.Name
          $DeploymentScriptOutputs.EntryPoint = @('/bin/bash')
          $DeploymentScriptOutputs.Cmd = @(
              '-c'
              'echo $MID_SERVER_PEM_BASE64 | base64 -d > /opt/snc_mid_server/current_cert.pem; cd /opt/snc_mid_server/agent && sh bin/scripts/manage-certificates.sh -a DefaultSecurityKeyPairHandle /opt/snc_mid_server/current_cert.pem; cd /opt/snc_mid_server/; ./init setup -f; ./init start'
          )
      }
      $SnowConn = Resolve-SNOWMIDEnvironmentAuth -SkipTagUpdate
      $DeploymentScriptOutputs.EnvVars.MID_CONFIG_mid__pinned__version = (Get-SNOWMidVersion)
      $BuildResults = Build-SNOWMidImage -Verbose
      $DeploymentScriptOutputs.ImageState = Resolve-SNOWMIDImageState
      $DeploymentScriptOutputs.Image = $DeploymentScriptOutputs.ImageState.CustomImageUri
      $UserResult = Set-SNOWMIDServerUser -MidServerName $MidServerName -MidServerCluster $MidServerCluster
      $DeploymentScriptOutputs.EnvVars.MID_INSTANCE_USERNAME = $UserResult.Credentials.UserName
      $DeploymentScriptOutputs.SecretEnvVars.MID_INSTANCE_PASSWORD = $UserResult.VaultSecret
      $DeploymentScriptOutputs['sysauto_script'] = try {
          Start-SNOWMIDValidationScript -MidServerName $MidServerName -ErrorAction Stop
      }
      catch {
          "Error: $_"
      }
      Write-PSFMessage "Deployment Script complete for MID Server $MidServerName"
'''
    devopsEnvironmentName: devopsEnvironmentName
    tags: storageAccount.tags
    scriptEnvironmentVariables: [
      {
        name: 'MID_SERVER_ROOT_CA'
        value: 'az-mid-ca-${devopsEnvironmentName}'
      }
      {
        name: 'SN_MID_CUSTOM_DOCKERFILE_BASE64'
        value: base64(customDockerfileContent)
      }
      {
        name: 'MID_SERVER_NAME'
        value: midServerName
      }
      {
        name: 'MID_SERVER_CLUSTER'
        value: midServerCluster
      }
      {
        name: 'SN_MID_CUSTOM_IMAGE_NAME'
        value: customImageName
      }
      {
        name: 'SN_MID_FORCE_BUILD_CUSTOM'
        value: forceBuildCustomImage ? 'true' : 'false'
      }
      {
        name: 'SN_MID_USE_CERTIFICATES'
        value: useCertificates
      }
    ]
  }
}

module midServerDeployment 'modules/snow.midcontainer.bicep' = {
  name: 'midServerDeployment-${midServerName}'
  params: {
    userAssignedIdentityName: storageAccount.tags.SnowMidServerIdentity
    location: resourceGroup().location
    midServerName: GetBuildContext.outputs.scriptOutput.EnvVars.MID_SERVER_NAME
    midInstanceUrl: storageAccount.tags.SnowHost
    midInstanceUsername: GetBuildContext.outputs.scriptOutput.EnvVars.MID_INSTANCE_USERNAME
    midInstancePassword: keyVault.getSecret(GetBuildContext.outputs.scriptOutput.SecretEnvVars.MID_INSTANCE_PASSWORD)
    containerRegistryId: storageAccount.tags.SnowContainerRegistryId
    containerSubnetId: storageAccount.tags.SnowContainerSubnetId
    imagePath: GetBuildContext.outputs.scriptOutput.Image
    storageAccountName: storageAccount.name
    numCpu: numCpu
    memoryInGB: memoryInGB
    useCertificates: useCertificates
    midServerCertificatePemBase64: useCertificates ? keyVault.getSecret(GetBuildContext.outputs.scriptOutput.SecretEnvVars.MID_SERVER_PEM_BASE64) : ''
    command: union(
      GetBuildContext.outputs.scriptOutput.EntryPoint,
      GetBuildContext.outputs.scriptOutput.Cmd
    )
    additionalEnvironmentVariables: [
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
        name: 'MID_WRAPPER_wrapper__java__classpath__1'
        value: 'extlib/*.jar'
      }
      {
        name: 'MID_WRAPPER_wrapper__java__classpath__2'
        value: 'lib/*.jar'
      }
      {
        name: 'MID_CONFIG_mid__pinned__version'
        value: GetBuildContext.outputs.scriptOutput.ImageState.MidVersion
      }
    ]
    tags: storageAccount.tags
  }
}

output storageAccountId string = storageAccount.id
output scriptOutputs object = GetBuildContext.outputs
