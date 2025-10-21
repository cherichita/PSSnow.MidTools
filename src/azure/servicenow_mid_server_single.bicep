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
FROM localhost/snow_mid_base:yokohama-12-18-2024__patch1-02-21-2025_03-05-2025_2133
ARG AZ_PWSH_VERSION="14.4.0"
ARG AZ_CLI_VERSION="2.77.0"
ARG PWSH_VERSION="7.5.3"
ARG MID_USERNAME=mid

USER root

RUN dnf update -y && \
    dnf install -y ca-certificates curl gnupg git wget && \
    curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/pki/rpm-gpg/microsoft.asc.gpg > /dev/null && \
    curl -sL https://packages.microsoft.com/config/rhel/9/prod.repo | tee /etc/yum.repos.d/microsoft-prod.repo && \
    dnf check-update -y && \
    dnf install -y azure-cli-${AZ_CLI_VERSION}-1.el9 && \
    dnf install -y https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-1.rh.x86_64.rpm && \
    dnf clean all -y

USER $MID_USERNAME

RUN pwsh -C "Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted" && \
    pwsh -C "Install-Module -Name Az -MinimumVersion ${AZ_PWSH_VERSION} -MaximumVersion ${AZ_PWSH_VERSION} -Force -AllowClobber -Scope CurrentUser -Repository PSGallery -AcceptLicense" && \
    pwsh -C "Install-Module -Name PSDepend -Force -AllowClobber -Scope CurrentUser -Repository PSGallery -AcceptLicense" && \
    pwsh -C "Install-Module -Name InvokeBuild -Force -AllowClobber -Scope CurrentUser -Repository PSGallery -AcceptLicense"

WORKDIR /opt/snc_mid_server/

# Check if the wrapper PID file exists and a HeartBeat is processed in the last 30 minutes
HEALTHCHECK --interval=5m --start-period=3m --retries=3 --timeout=15s \
    CMD bash check_health.sh || exit 1

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
  name: 'snow-get-midcontext-${midServerName}'
  params: {
    deploymentScriptName: 'snow-prepare-midserver-${midServerName}'
    userAssignedIdentityName: storageAccount.tags.SnowDevopsIdentity
    midToolsRemoteUriBase: empty(midToolsRemoteUriBase) ? null : midToolsRemoteUriBase
    midToolsRemoteUriSas: empty(midToolsRemoteUriSas) ? null : midToolsRemoteUriSas
    inlineScript: loadTextContent('../../scripts/prepare.ps1')
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
    midInstancePassword: GetBuildContext.outputs.scriptOutput.MutualAuthEnabled
      ? ''
      : keyVault.getSecret(GetBuildContext.outputs.scriptOutput.SecretEnvVars.MID_INSTANCE_PASSWORD)
    containerRegistryId: storageAccount.tags.SnowContainerRegistryId
    containerSubnetId: storageAccount.tags.SnowContainerSubnetId
    imagePath: GetBuildContext.outputs.scriptOutput.Image
    storageAccountName: storageAccount.name
    numCpu: numCpu
    memoryInGB: memoryInGB
    useCertificates: useCertificates
    mutualAuthEnabled: GetBuildContext.outputs.scriptOutput.MutualAuthEnabled
    midServerCertificatePemBase64: useCertificates
      ? keyVault.getSecret(GetBuildContext.outputs.scriptOutput.SecretEnvVars.MID_SERVER_PEM_BASE64)
      : ''
    command: union(GetBuildContext.outputs.scriptOutput.EntryPoint, GetBuildContext.outputs.scriptOutput.Cmd)
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
