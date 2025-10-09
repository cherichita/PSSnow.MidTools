$MidToolsPath = (Resolve-Path -Path "$PSScriptRoot/../" -ErrorAction Stop).Path

$Script:SMC ??= @{}
$Script:_SNB ??= @{}
$Script:_SNB.SMC = $Script:SMC
function SnowMidInitializeTools {
    if ($ResolveCommand = (Get-Command -Name 'Resolve-SNOWMIDBuildContext' -ErrorAction SilentlyContinue)) {
        if($ResolveCommand.Module.ModuleBase -ne $MidToolsPath) {
            Write-Build Yellow "Module path mismatch. Reloading module from $MidToolsPath"
            Import-Module "$MidToolsPath/PSSnow.MidTools.psd1" -Force
        }
        $CurrentContext = Resolve-SNOWMIDBuildContext 
        if ($CurrentContext.EnvironmentName -eq $EnvironmentName -and -not $ReloadModules.IsPresent) {
            Write-Build Green "Current context matches environment: $($CurrentContext.EnvironmentName), strategy: $($CurrentContext.BuildStrategy), mid context: $($CurrentContext.MidContext)"
        }
        else {
            Write-Build Yellow "Current context does not match environment. Resetting context."
            Import-Module "$MidToolsPath/PSSnow.MidTools.psd1" -Force
        }
    }
    else {
        Import-Module "$MidToolsPath/PSSnow.MidTools.psd1" -Force
    }
    if ($ReloadModules.IsPresent -or (-not (Get-Command -Name 'Get-SNOWAuth' -ErrorAction SilentlyContinue))) {
        Resolve-SNOWMIDPrereqs
    }
    $CurrentContext = Resolve-SNOWMIDBuildContext -ErrorAction SilentlyContinue
    $SnowAuth = Get-SNOWAuth -ErrorAction SilentlyContinue
    $CurrentState = Get-SNOWMIDEnvironmentAuthSecret -ErrorAction SilentlyContinue
    $StateInstance = $CurrentState.Instance
    if ($StateInstance -like "https://*") {
        $StateInstance = $StateInstance.replace('https://', '')
    }
    if ($StateInstance -like "*.service-now.com*") {
        $StateInstance = $StateInstance.split('.') | Select-Object -first 1
    }
    if (($CurrentUser = Get-SNOWCurrentUser) -and ($CurrentState.Instance -and $SnowAuth.Instance -and ($StateInstance -eq $SnowAuth.Instance)) -and !$ReloadModules.IsPresent) {
        Write-Build Green "Current user: $($CurrentUser.name) ($($CurrentUser.user_name))"
    }
    else {
        $CurrentAuth = Resolve-SNOWMIDEnvironmentAuth -ErrorAction SilentlyContinue
        if ($CurrentAuth) {
            Write-Build Green "ServiceNow auth found: $($CurrentAuth.Instance)"
        }
        if (-not $CurrentAuth -or $UpdateCredentials.IsPresent) {
            if (-not $CurrentContext.KeyVault) {
                Write-Build Red "No KeyVault found for environment $($CurrentContext.EnvironmentName). Please set up the KeyVault first."
            }
            else {
                # Prompt to skip setting credentils
                if ((Read-Host -Prompt "Do you want to set up ServiceNow credentials for environment $($CurrentContext.EnvironmentName)? (Y/N)") -eq 'N') {
                    Write-Build Green "Skipping ServiceNow credentials setup."
                }
                else {
                    $Instance = Read-Host -Prompt 'Enter ServiceNow instance URL (e.g. https://dev12345.service-now.com): '
                    $Username = Read-Host -Prompt 'Enter ServiceNow username: '
                    $Password = Read-Host -Prompt 'Enter ServiceNow password: ' -AsSecureString
                    $ServiceNowConfig = @{
                        Instance   = $Instance
                        Credential = [PSCredential]::new($Username, $Password)
                    }
                    Set-SNOWMidEnvironmentSecret @ServiceNowConfig
                }
                
            }
            
        }
    }
}

task SnowMidGetEnvironments {
    $envQuery = 'resources | where type =~ "microsoft.storage/storageaccounts" and tags.SnowEnvironment != "" | project label = strcat(tags.SnowEnvironment,"-",tags.SnowHost), description = location, value = pack("url", properties.primaryEndpoints.blob, "resourceId", id, "subscriptionId", subscriptionId, "resourceGroup", resourceGroup, "location", location, "subscriptionId", subscriptionId, "tags", tags, "resourceGroupId", strcat("/subscriptions/",subscriptionId,"/resourceGroups/",resourceGroup)) | order by label asc'
    $Environments = Search-AzGraph -Query $envQuery -ErrorAction Stop -UseTenantScope
    if ($Environments) {
        $Script:SMC.Environments = $Environments
    }
}

task SnowMidInitializeTools {
    SnowMidInitializeTools
    # $Script:SMC.BuildContext = Resolve-SNOWMIDBuildContext
}

task InitOAuthClient SnowMidInitializeTools, {
    $OAuthModulePath = if(Get-Module -Name 'PSSnow.OAuthClient' -ListAvailable -ErrorAction SilentlyContinue) {
        (Get-Module -Name 'PSSnow.OAuthClient' -ListAvailable).ModuleBase + '/PSSnow.OAuthClient.psd1'
    }
    else {
        "$PSScriptRoot/../../../PSSnow.OAuthClient/src/PSSnow.OAuthClient.psd1"
    }
    Import-Module $OAuthModulePath -Force -Scope Global -ErrorAction Stop
    $Script:OAuthBuildContext = Resolve-SNOWMIDBuildContext
    $Script:OAuthClient = Initialize-SNOWOauthClient -SnowHost $OAuthBuildContext.StorageAccount.tags.SnowHost `
        -ClientID "ff97fbb4da3313004591cc3a291b47fd" `
        -RedirectURI 'snappauth://' `
        -VaultName $OAuthBuildContext.Vault.VaultName `
        -VaultSecretName "snow-oauth-$($EnvironmentName.ToLower())"
    Clear-SNOWOAuthSecrets -SaveToken
}

task StartOAuthFlow InitOAuthClient, {
    $Script:SNOWOAUthToken = Start-SNOWOauthInteractive -SnowHost $OAuthBuildContext.StorageAccount.tags.SnowHost `
        -ClientID "ff97fbb4da3313004591cc3a291b47fd" `
        -VaultName $OAuthBuildContext.Vault.VaultName `
        -VaultSecretName "snow-oauth-$($EnvironmentName.ToLower())" -Force
    Set-SNOWMidEnvironmentSecret -Instance $OAuthBuildContext.StorageAccount.tags.SnowHost `
        -ClientID "ff97fbb4da3313004591cc3a291b47fd" `
        -AccessToken $Script:SNOWOAUthToken.AccessToken `
        -RefreshToken $Script:SNOWOAUthToken.RefreshToken `
        -Expires $Script:SNOWOAUthToken.Expires
    Test-SnowOAuthTokenExpiration
}

task SnowGetMidServers {
    $Script:MidServers = Get-SNOWObject -Table 'ecc_agent' `
        -ErrorAction Stop
    $Script:MidServers | Select-Object name, status, version, ip_address, os, sys_id, is_using_custom_cert, validated | ConvertTo-Yaml
}

task SnowGetMidServerClusters {
    Get-SNOWObject -Table 'ecc_agent_cluster_member_m2m' -DisplayValue 'true' -Fields 'sys_id,agent.name,agent.status', 'cluster.name' | Group-Object -Property 'cluster.name' -AsHashTable
}

task SnowCleanMidServerClusters {
    CleanMidServerClusters
}

function CleanMidServers {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param ()
    process {
        $Script:SMC.MidServers = Get-SNOWObject -Table 'ecc_agent' `
            -ErrorAction Stop
        foreach ($MidServer in $Script:SMC.MidServers) {
            if ($MidServer.status -ne 'down') {
                Write-Host "MID Server $($MidServer.name) is in status $($MidServer.status). Slipping clean up."
                continue
            }
            if ($PSCmdlet.ShouldProcess("MID Server: $($MidServer.name)", "Remove")) {
                # Logic to clean up the MID Server
                Write-Host "Cleaning up MID Server: $($MidServer.name)"
                Invoke-SNOWWebRequest -URI "/api/now/table/ecc_agent/$($MidServer.sys_id)" `
                    -Method 'DELETE' `
                    -ErrorAction Stop
            }
        }

        # Next - find any users that are part of the mid_server group and remove them if not in use
        $MidServerMembers = Get-SNOWObject -Table 'sys_user_has_role' `
            -Query "role.name=mid_server" `
            -ErrorAction Stop
        foreach ($Member in $MidServerMembers) {
            $User = Get-SNOWObject -Table 'sys_user' `
                -SysId $Member.user.value `
                -ErrorAction Stop
            
            Write-Host "Found user in mid_server group: $($User.name)"
            if ($User) {
                $MidServersRunning = Get-SNOWObject -Table 'ecc_agent' `
                    -Query "user_name=$($User.user_name)" `
                    -ErrorAction Stop
                if ($MidServersRunning) {
                    Write-Host "User $($User.name) is associated with running MID Servers. Skipping removal."
                    continue
                }
                else {
                    Write-Host "Removing user $($User.name) from mid_server group."
                    Invoke-SNOWWebRequest -URI "/api/now/table/sys_user_has_role/$($Member.sys_id)" `
                        -Method 'DELETE' `
                        -ErrorAction Stop | Out-Null
                    Write-Host "User $($User.name) removed from mid_server group."
                    $UserRemainingRoles = Get-SNOWObject -Table 'sys_user_has_role' `
                        -Query "user=$($User.sys_id)" `
                        -ErrorAction Stop
                    if ($UserRemainingRoles.Count -eq 0) {
                        Write-Host "User $($User.name) has no remaining roles. Deleting user."

                        Invoke-SNOWWebRequest -URI "/api/now/table/sys_user/$($User.sys_id)" `
                            -Method 'DELETE' `
                            -ErrorAction Stop | Out-Null
                        Write-Host "User $($User.name) deleted from sys_user table."
                    }
                }   
            }
            else {
                Write-Host "User not found for sys_id: $($Member.user). Skipping removal."
                continue
            }
        }

    }
}

function CleanMidServerClusters {
    $MidClusters = Get-SNOWObject -Table 'ecc_agent_cluster'
    foreach ($MidCluster in $MidClusters) {
        $ClusterMembers = Get-SNOWObject -Table 'ecc_agent_cluster_member_m2m' `
            -Query "cluster=$($MidCluster.sys_id)" `
            -ErrorAction Stop
        if ($ClusterMembers.Count -eq 0) {
            Write-Host "MID Server Cluster $($MidCluster.name) has no members. Removing cluster."
            Invoke-SNOWWebRequest -URI "/api/now/table/ecc_agent_cluster/$($MidCluster.sys_id)" `
                -Method 'DELETE' `
                -ErrorAction Stop | Out-Null
            Write-Host "MID Server Cluster $($MidCluster.name) removed."
        }
        else {
            Write-Host "MID Server Cluster $($MidCluster.name) has members. Skipping removal."
        }
    }
}

task SnowMidTestInvokeRemoteCommandAll {
    # assert $MidServerName
    $ThisGuid = [guid]::NewGuid().ToString()
    Write-Host "Generated GUID: $ThisGuid"
    $Command = "echo -n $ThisGuid"
    $TestPsCommand = "/usr/bin/pwsh -NonInteractive -OutputFormat XML -EncodedCommand DQAKACAAIAAgACAAIAAgACAAIABQAGEAcgBhAG0AKAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAWwBQAGEAcgBhAG0AZQB0AGUAcgAoAFYAYQBsAHUAZQBGAHIAbwBtAFAAaQBwAGUAbABpAG4AZQApAF0ADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFsAcwB0AHIAaQBuAGcAXQAkAEYAaQByAHMAdABQAGEAcgBhAG0ADQAKACAAIAAgACAAIAAgACAAIAApAA0ACgAgACAAIAAgACAAIAAgACAAVwByAGkAdABlAC0ASABvAHMAdAAgACQARgBpAHIAcwB0AFAAYQByAGEAbQANAAoAIAAgACAAIAAgACAAIAAgAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAtAE4AbwBOAGUAdwBsAGkAbgBlACAAKABbAGcAdQBpAGQAXQA6ADoATgBlAHcARwB1AGkAZAAoACkALgBUAG8AUwB0AHIAaQBuAGcAKAApACkADQAKACAAIAAgACAA"
    $PowerShellCommand = [scriptblock]{
        Param(
            [Parameter(ValueFromPipeline)]
            [string]$FirstParam
        )
        Write-Host $FirstParam
        Write-Host -NoNewline ([guid]::NewGuid().ToString())
    }
    $PodmanResult = Invoke-SNOWMidRemoteCommand -MidServerName "onptest02" -UsePodmanExec -Command $TestPsCommand
    # $PodmanPwshResult = Invoke-SNOWMidPowerShellCommand -MidServerName "onptest02" -UsePodmanExec -Command $PowerShellCommand
    Write-Host "Podman Result: $($PodmanResult | ConvertTo-Json -Depth 5)"
    # Write-Host "Podman PowerShell Result: $($PodmanPwshResult | ConvertTo-Json -Depth 5)"
}

task SnowCleanMidServers {
    CleanMidServers
}

task CleanEnvironment SnowMidInitializeTools, {
    $Proceed = $true
    $Script:_SNB['Context'] = Resolve-SNOWMIDBuildContext -ReloadContext
    Set-AzContext -SubscriptionId $Script:_SNB['Context'].StorageAccount.subscriptionId -ErrorAction Stop
    $MidToolsStatus = Get-SNOWMidToolsStatus
    if ($MidToolsStatus.SN_MID_VAULT_NAME -and (Get-SecretVault -Name $MidToolsStatus.SN_MID_VAULT_NAME -ErrorAction SilentlyContinue)) {
        $Proceed = Read-Host -Prompt "Do you want to clean up the vault '$($MidToolsStatus.SN_MID_VAULT_NAME)'? (Y/N)"
        if ($Proceed -ne 'Y') {
            Write-Build Green "Skipping vault cleanup."
        }
        else {
            Unregister-SecretVault -Name $MidToolsStatus.SN_MID_VAULT_NAME -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Build Green "No vault found to clean up."
    }
    if (-not $Script:_SNB['Context'].StorageAccount) {
        Write-Build Red "No context found to clean up."
        return
    }
    $Script:_SNB['Context'].ManagedIdentities | ForEach-Object {
        $ManagedIdentity = $_
        Write-Build Yellow "Searching for permissions for managed identity: $($ManagedIdentity.properties.principalId)"
        $Permissions = Get-AzRoleAssignment -ObjectId $ManagedIdentity.properties.principalId -ErrorAction SilentlyContinue
        if ($Permissions) {
            Write-Build Yellow "Found permissions for managed identity: $($ManagedIdentity.name)"
            $Permissions | ForEach-Object {
                if ($Proceed) {
                    Write-Build Yellow "Removing permission for identity $($ManagedIdentity.name): $($_.RoleDefinitionName) for $($_.Scope)"
                    Remove-AzRoleAssignment -ObjectId $ManagedIdentity.properties.principalId -RoleDefinitionName $_.RoleDefinitionName -Scope $_.Scope -ErrorAction SilentlyContinue
                }
                else {
                    Write-Build Yellow "Skipping removal of permission for identity $($ManagedIdentity.name): $($_.RoleDefinitionName) for $($_.Scope)"
                }
            }
        }
        else {
            Write-Build Green "No permissions found for managed identity: $($ManagedIdentity.properties.principalId)"
        }
    }

    # Clean up any MID Servers that are running
    $Containers = $Script:_SNB['Context'].Raw | Where-Object { $_.type -eq 'microsoft.containerinstance/containergroups' }
    if ($Containers) {
        $Containers | ForEach-Object {
            $ContainerName = $_.name
            Write-Build Yellow "Stopping container: $ContainerName"
            # Stop-AzContainerGroup -ResourceGroupName $_.resourceGroup -Name $ContainerName -ErrorAction SilentlyContinue
            # Write-Build Yellow "Removing container: $ContainerName"
            Remove-AzContainerGroup -ResourceGroupName $_.resourceGroup -Name $ContainerName -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Build Green "No containers found to clean up."
    }

    # Purge the KeyVault and prompt the user
    $KeyVaultName = $Script:_SNB['Context'].StorageAccount.tags.SnowKeyVaultId -split '/' | Select-Object -Last 1
    $Location = $Script:_SNB['Context'].StorageAccount.location
    if ($KeyVaultName) {
        Write-Host "Searching for KeyVault: $KeyVaultName in location: $Location"
        $ActiveKeyVault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction SilentlyContinue
        if (-not $ActiveKeyVault) {
            $PurgedVault = Get-AzKeyVault -VaultName $KeyVaultName -Location $Location -InRemovedState -ErrorAction SilentlyContinue
        }
        $RemoveParams = @{
            Name     = $KeyVaultName
            Force    = $true
            Location = $Location
        }
        $Proceed = if ($ActiveKeyVault) {
            Read-Host -Prompt "KeyVault '$KeyVaultName' exists. Do you want to purge it? (Y/N)"
        }
        else {
            $true
        }
        if ($Proceed -eq 'Y') {
            if ($ActiveKeyVault) {
                Write-Build Yellow "KeyVault '$KeyVaultName' exists. Proceeding to purge."
                Remove-AzKeyVault @RemoveParams -ErrorAction Stop
                $PurgedVault = Get-AzKeyVault -VaultName $KeyVaultName -Location $Location -InRemovedState -ErrorAction SilentlyContinue
            }
            if ($PurgedVault) {
                Write-Build Yellow "KeyVault '$KeyVaultName' is in removed state. Proceeding to purge."
                Remove-AzKeyVault @RemoveParams -InRemovedState -AsJob -ErrorAction Stop 
            }
            else {
                Write-Build Green "No KeyVault found in removed state with name '$KeyVaultName'."
            }
        }
        else {
            Write-Build Green "Skipping KeyVault purge."
        }
    }
    else {
        Write-Build Green "No KeyVault found to purge."
    }

    # Remove the managed identities
    $Script:_SNB['Context'].ManagedIdentities | ForEach-Object {
        $ManagedIdentity = $_
        Write-Build Yellow "Removing managed identity: $($ManagedIdentity.name)"
        Remove-AzUserAssignedIdentity -ResourceGroupName $ManagedIdentity.resourceGroup -Name $ManagedIdentity.name -ErrorAction SilentlyContinue
    }

    # # Remove the storage account
    $StorageAccountName = $Script:_SNB['Context'].StorageAccount.name
    Remove-AzStorageAccount -ResourceGroupName $Script:_SNB['Context'].StorageAccount.resourceGroup -Name $StorageAccountName
}

task CleanContainerRegistryPermissions {
    $RegistryNames = @(
        'opsssd',
        'csocregistrydev'
    )
    $ContainerRegistry = Search-AzGraph -Query "Resources | where type =~ 'microsoft.containerregistry/registries' | where name in ('$($RegistryNames -join "','")') | project id, name, resourceGroup, resourceGroupId=tolower(strcat('/subscriptions/', subscriptionId, '/resourceGroups/', resourceGroup))" -ErrorAction Stop -UseTenantScope
    if ($ContainerRegistry) {
        $ContainerRegistry | ForEach-Object {
            Write-Build Yellow ($_ | ConvertTo-Yaml)
            $RegistryName = $_.name
            $ResourceGroupId = $_.resourceGroupId
            Write-Build Yellow "Searching for role assignments for container registry: $RegistryName in resource group: $ResourceGroupId"
            $RoleAssignments = Get-AzRoleAssignment -Scope $_.id -ErrorAction SilentlyContinue
            $ResourceGroupAssignments = $RoleAssignments | Where-Object { $_.Scope -eq $ResourceGroupId }
            $ObjectAssignments = $RoleAssignments | Where-Object { $_.Scope -eq $_.id }
            $ResourceGroupAssignments | ForEach-Object {
                Write-Build Yellow "Removing role assignment for ServicePrincipal: $($_.DisplayName) with role: $($_.RoleDefinitionName) in resource group: $ResourceGroupId"
            }
        }
    }
    else {
        Write-Build Green "No container registries found to clean up."
    }
}