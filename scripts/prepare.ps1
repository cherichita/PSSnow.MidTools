Param(
    [string]$MidServerName = $env:MID_SERVER_NAME,
    [string]$MidServerCluster = $env:MID_SERVER_CLUSTER,
    [string]$RootCACommonName = $env:MID_SERVER_ROOT_CA ?? 'az-mid-ca',
    [string]$MidCertCommonName = $env:MID_SERVER_NAME,
    [System.Boolean]$UseCertificates = $env:SN_MID_USE_CERTIFICATES -eq 'true',
    [string[]]$MidServerGroups = $env:MID_SERVER_GROUPS ? $env:MID_SERVER_GROUPS -split ',' : $null
)
Resolve-SNOWMIDPrereqs
$DeploymentScriptOutputs.MutualAuthEnabled = $false
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
        MID_INSTANCE_URL                        = "$($ctx.StorageAccount.tags.SnowHost)"
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
$SnowConn = Resolve-SNOWMIDEnvironmentAuth
$DeploymentScriptOutputs.EnvVars.MID_CONFIG_mid__pinned__version = (Get-SNOWMidVersion)
$BuildResults = Build-SNOWMidImage -Verbose
$DeploymentScriptOutputs.ImageState = Resolve-SNOWMIDImageState
$DeploymentScriptOutputs.Image = $DeploymentScriptOutputs.ImageState.CustomImageUri
$UserParams = @{
    MidServerName    = $MidServerName
    MidServerCluster = $MidServerCluster
    Roles            = @('mid_server')
    Groups           = $MidServerGroups
    Capabilities     = @('ALL')
    Operation        = 'deploy'
}
$UserResult = Set-SNOWMIDServerUser @UserParams
$DeploymentScriptOutputs.EnvVars.MID_INSTANCE_USERNAME = $UserResult.Credentials.UserName
$DeploymentScriptOutputs.SecretEnvVars.MID_INSTANCE_PASSWORD = $UserResult.VaultSecret
if ($UseCertificates -and $UserResult.User.user_name -and $MidCert) {
    $MutualAuthEnabled = Get-SNOWMidMutualAuthState -RootCN $RootCACommonName
    if ($MutualAuthEnabled.Valid) {
        Write-PSFMessage "Mutual Auth is available for instance root CA $RootCACommonName"
        try {
            $TempFile = New-TemporaryFile
            $TempFilePath = $TempFile.FullName
            if ($PemContent = $MidCert.Collection.ExportCertificatePems()) {
                $PemContent | Out-File -FilePath $TempFilePath -Encoding ascii
                Set-SNOWMidUserCertificate -UserName $UserResult.User.user_name -CertificatePemPath $TempFilePath -CertificateName $MidCertCommonName -ErrorAction Stop
                Write-PSFMessage "Mutual authentication enabled for user $($UserResult.User.user_name) with certificate $MidCertCommonName."
                $DeploymentScriptOutputs.EnvVars.MID_MUTUAL_AUTH_PEM_FILE = '/opt/snc_mid_server/current_cert.pem'
                $DeploymentScriptOutputs.EntryPoint = @('/bin/bash')
                $DeploymentScriptOutputs.SecretEnvVars.Remove('MID_INSTANCE_PASSWORD')
                $DeploymentScriptOutputs.MutualAuthEnabled = $true
                $DeploymentScriptOutputs.Cmd = @(
                    '-c'
                    'echo $MID_SERVER_PEM_BASE64 | base64 -d > $MID_MUTUAL_AUTH_PEM_FILE; /opt/snc_mid_server/init start'
                )
            }
        }
        catch {
            Write-PSFMessage -Level Warning "Failed to enable Mutual Auth for MID Server ${MidServerName}: $_"
        
        }
        finally {
            if (Test-Path $TempFilePath) {
                Remove-Item -Path $TempFilePath -Force -ErrorAction SilentlyContinue
            }
        }
        
    }
    else {
        Write-PSFMessage "Enabling Mutual Auth for MID Server $MidServerName"
        # Enable-SNOWMidUserMutualAuth -RootCN $RootCACommonName -MidServerName $MidServerName -ErrorAction Stop
    }
}

$DeploymentScriptOutputs['sysauto_script'] = try {
    Start-SNOWMIDValidationScript -MidServerName $MidServerName -ErrorAction Stop
}
catch {
    "Error: $_"
}
Write-PSFMessage "Deployment Script complete for MID Server $MidServerName"