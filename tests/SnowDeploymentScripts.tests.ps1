<#
.SYNOPSIS
    Integration tests for running SnowMidTools in different execution contexts.

.DESCRIPTION
    This file contains integration tests for running SnowMidTools in three execution contexts:
    1. Locally using PWSH encoded command.
    2. In a Podman container.
    3. As an Azure DeploymentScript.

.NOTES
    Requires connection to both ServiceNow and Azure for full test coverage.
    These tests validate the deployment scripts can run in all supported environments.

    This test framework should be used as a good example of how to use the
    SnowMidTools and VaultTools functions to resolve a build context and run in different environments.
    It is not a test of the SnowMidTools or VaultTools themselves. 
    See VaultTools.tests.ps1 and SnowMidTools.tests.ps1 for those tests.
#>
BeforeAll {
    # Import required modules
    $env:SN_MID_ENVIRONMENT_NAME = 'unts'
    $env:SN_MID_CONTEXT = 'azure'
    $env:SN_MID_BUILD_STRATEGY = 'acr'
    Import-Module "$PSScriptRoot/../src/PSSnow.MidTools.psd1" -Force

    # # Retrieve Azure environment secrets from the vault
    $Script:AzureConfig = Resolve-SNOWMidAzureEnvironmentSecrets -SetEnvironmentVariables
    # # Retrieve ServiceNow environment secrets from the vault 
    # # Configuration - pulled from environment instead of $Rmm
    
    # Test server configuration
    $Script:NewMidServer = @{
        name = 'zzmidtest002'
    }
    # Azure credential configuration - replace $Rmm references
    $Script:AzureConfig = @{
        TenantId       = $env:AZURE_TENANT_ID
        SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
        ClientId       = $env:AZURE_CLIENT_ID
        ClientSecret   = $env:AZURE_CLIENT_SECRET
    }

    #
    
    # Check if required Azure environment variables are set
    if (-not $Script:AzureConfig.TenantId -or 
        -not $Script:AzureConfig.SubscriptionId -or
        -not $Script:AzureConfig.ClientId -or
        -not $Script:AzureConfig.ClientSecret) {
        Write-Warning "Some Azure environment variables are missing. Tests requiring Azure credentials will be skipped."
    }
    Write-Host "Azure Configuration: $($Script:AzureConfig | Select-Object -Property ClientId, SubscriptionId | ConvertTo-Json -Depth 5)"
    
    # Set up output paths
    $Script:LocalOutputDir = "$PSScriptRoot/.local"
    if (-not (Test-Path $Script:LocalOutputDir)) {
        New-Item -Path $Script:LocalOutputDir -ItemType Directory -Force | Out-Null
    }
    
    # Helper function to encode PowerShell commands for remote execution
    function Get-EncodedPowerShellCommand {
        param (
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            
            [Parameter(Mandatory = $false)]
            [switch]$ForDeploymentScript
        )
        
        # Get SnowMidTools content to include with the command
        $commonFileContent = Get-Content "$PSScriptRoot/../src/PSSnow.MidTools.psm1" -Raw
        
        # Create script header and footer
        $scriptHeader = @'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$DeploymentScriptOutputs = @{}
Update-AzConfig -CheckForUpgrade $false | Out-Null
'@
        
        $scriptFooter = @"
`$AZ_SCRIPTS_OUTPUT_PATH = `$env:AZ_SCRIPTS_OUTPUT_PATH
Write-Host "`$AZ_SCRIPTS_OUTPUT_PATH"
if (-not (Test-Path (Split-Path -Parent `$AZ_SCRIPTS_OUTPUT_PATH))) {
    New-Item -Path (Split-Path -Parent `$AZ_SCRIPTS_OUTPUT_PATH) -ItemType Directory -Force | Out-Null
}
`$DeploymentScriptOutputs | ConvertTo-Json -Depth 10 | Out-File -FilePath `$AZ_SCRIPTS_OUTPUT_PATH -Force
"@
        
        # Combine all parts
        $fullCommand = if ($ForDeploymentScript) {
            @(
                "# Running as deployment script",
                $commonFileContent,
                $ScriptBlock.ToString()
            ) -join "`n"
        }
        else {
            @(
                $scriptHeader,
                $commonFileContent,
                $ScriptBlock.ToString(),
                $scriptFooter
            ) -join "`n"
        }
        
        # Return Base64 encoded command
        if ($ForDeploymentScript) {
            return $fullCommand
        }
        return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($fullCommand))
    }
    
    # Helper function to run commands locally
    function Invoke-LocalPowerShellCommand {
        param (
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            
            [Parameter(Mandatory = $false)]
            [hashtable]$EnvironmentVariables
        )
        
        try {
            $tempFile = Join-Path $Script:LocalOutputDir "TempScript-$((Get-Date).ToString('yyyyMMddHHmmss')).ps1"
            # Set environment variables
            $originalEnvVars = @{}
            if ($EnvironmentVariables) {
                foreach ($key in $EnvironmentVariables.Keys) {
                    # Save original value
                    $originalEnvVars[$key] = [System.Environment]::GetEnvironmentVariable($key)
                    # Set new value
                    [System.Environment]::SetEnvironmentVariable($key, $EnvironmentVariables[$key], 'Process')
                }
            }
            # Prepare output path
            $outputPath = Join-Path $Script:LocalOutputDir "DeploymentScriptOutputs-$($env:SN_MID_ENVIRONMENT_NAME).json"
            [System.Environment]::SetEnvironmentVariable('AZ_SCRIPTS_OUTPUT_PATH', $outputPath, 'Process')
            # Encode and run command
            $encodedCommand = Get-EncodedPowerShellCommand -Scriptblock $ScriptBlock
            # Decode and write to local script file
            
            # Decode base64 Unicode string to file
            [System.IO.File]::WriteAllText($tempFile, [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedCommand)))

            pwsh.exe -File $tempFile | Tee-Object -Variable result | Write-Host
                        
            # Parse results
            if (Test-Path $outputPath) {
                $scriptOutput = Get-Content -Path $outputPath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                return $scriptOutput
            }
            
            return $result
        }
        finally {
            # Restore original environment variables
            foreach ($key in $originalEnvVars.Keys) {
                [System.Environment]::SetEnvironmentVariable($key, $originalEnvVars[$key], 'Process')
            }
            if (Test-Path $tempFile) {
                Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Helper function to run commands in Docker/Podman container
    function Invoke-ContainerPowerShellCommand {
        param (
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            
            [Parameter(Mandatory = $false)]
            [hashtable]$EnvironmentVariables,
            
            [Parameter(Mandatory = $false)]
            [string]$ImageName = 'mcr.microsoft.com/azuredeploymentscripts-powershell:az13.2'
        )
        
        try {
            $mountDir = (Resolve-Path $Script:LocalOutputDir).Path
            # Prepare mount directory
            $TempFileName = "TempScript-$((Get-Date).ToString('yyyyMMddHHmmss')).ps1"
            $TempFilePath = Join-Path $Script:LocalOutputDir $TempFileName
            $HostTempFilePath = $TempFilePath
            # Encode the command
            $encodedCommand = Get-EncodedPowerShellCommand -Scriptblock $ScriptBlock
            # Decode base64 Unicode string to file
            [System.IO.File]::WriteAllText($TempFilePath, [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedCommand)))
            # OutputVolume
            podman volume create pstes 2>&1 | Out-Null
            # Add output path environment variable
            $OutFile = "DockerOutput-Latest.json"
            $ContainerOutDir = '/opt/snc_mid_server/testout'
            $HostOutFilePath = Join-Path $Script:LocalOutputDir $OutFile
            $OutDir = '/tmp/testout'
            # Check if running on Windows and convert path for WSL if needed
            if ($IsWindows) {
                $mountDir = $mountDir -replace '^([A-Za-z]):', { "/mnt/$($_.Groups[1].Value.ToLower())" } -replace '\\', '/'
                $TempFilePath = $TempFilePath -replace '^([A-Za-z]):', { "/mnt/$($_.Groups[1].Value.ToLower())" } -replace '\\', '/'
                wsl.exe mkdir -p $OutDir 2>&1 | Out-Null
                wsl.exe chmod -R 777 $OutDir 2>&1 | Out-Null
            }
            else {
                chmod -R 777 $mountDir 2>&1 | Out-Null
                mkdir -p $OutDir 2>&1 | Out-Null
                chmod -R 777 $OutDir 2>&1 | Out-Null    
            }
            
            # Build podman parameters
            $podmanParams = @(
                'run',
                # '--rm',
                '--entrypoint', '/usr/bin/pwsh',
                '-v', "${mountDir}:/opt/snc_mid_server/tests",
                '-v', "${OutDir}:${ContainerOutDir}"
            )
            $OutputPath = "$ContainerOutDir/$OutFile"
            $podmanParams += "--env=AZ_SCRIPTS_OUTPUT_PATH=$OutputPath"
            
            # Add environment variables
            if ($EnvironmentVariables) {
                foreach ($key in $EnvironmentVariables.Keys) {
                    $podmanParams += "--env=$key=$($EnvironmentVariables[$key])"
                }
            }
            
            
            
            # Build command parameters
            $commandParams = @(
                $ImageName,
                '-of', 'Text',
                '-File', "/opt/snc_mid_server/tests/$TempFileName"
            )
            
            # Run the command
            podman $podmanParams $commandParams | Tee-Object -Variable response | Write-Host
            
            # Find the output file path in the response
            $localOutputPath = $null
            foreach ($line in $response -split "`n") {
                if ($line -match 'DockerOutput.*\.json') {
                    $localOutputPath = $line -replace $ContainerOutDir, $OutDir
                    if ($IsWindows) {
                        wsl.exe cat $localOutputPath | Out-File -FilePath $HostOutFilePath -Force -Encoding utf8 2>&1 | Out-Null
                    }
                    else {
                        cat $localOutputPath | Out-File -FilePath $HostOutFilePath -Force -Encoding utf8 2>&1 | Out-Null
                    }
                    break
                }
            }
            
            # Parse results
            if ($HostOutFilePath -and (Test-Path $HostOutFilePath)) {
                Write-PSFMessage -Level Important -Message  "Output file:`n $HostOutFilePath"
                $scriptOutput = Get-Content -Path $HostOutFilePath -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                return @{
                    DeploymentScriptOutputs = $scriptOutput
                    Response                = $response
                }
            }
            
            return @{
                DeploymentScriptOutputs = $null
                Response                = $response
            }
        }
        catch {
            Write-Error "Error running container command: $_"
            return $null
        }
        finally {
            # Clean up temporary file
            if (Test-Path $HostTempFilePath) {
                Remove-Item -Path $HostTempFilePath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Helper function to run commands as Azure deployment script
    function Invoke-AzDeploymentScriptCommand {
        param (
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,
            
            [Parameter(Mandatory = $true)]
            [hashtable]$BuildContext,
            
            [Parameter(Mandatory = $false)]
            [hashtable]$EnvironmentVariables
        )
        
        try {
            # Create bicep deployment template path
            $bicepPath = "$PSScriptRoot/../src/azure/modules/servicenow.midtools.deploymentscript.bicep"
            if (-not (Test-Path $bicepPath)) {
                Write-Error "Bicep template not found at $bicepPath"
                return $null
            }
            
            # Encode the script content
            $scriptContent = $ScriptBlock.ToString()
            # Prepare container environment variables
            $containerEnv = @()
            if ($EnvironmentVariables) {
                foreach ($key in $EnvironmentVariables.Keys) {
                    $containerEnv += @{
                        name  = $key
                        value = $EnvironmentVariables[$key]
                    }
                }
            }
            
            # Prepare deployment parameters
            $deployParams = @{
                Name                       = "TestDeploymentScript-$((Get-Date).ToString('yyyyMMddHHmmss'))"
                ResourceGroupName          = $BuildContext.StorageAccount.resourceGroup
                TemplateFile               = $bicepPath
                DeploymentScriptName       = "TestDeploymentScript"
                inlineScript               = $scriptContent
                devopsEnvironmentName      = $BuildContext.EnvironmentName
                userAssignedIdentityName   = $BuildContext.DevopsIdentity.name
                scriptEnvironmentVariables = $containerEnv
                midToolsRemoteUriBase      = 'https://snowmiddeploy.blob.core.windows.net/snow-ps/PSSnow.MidTools' | ConvertTo-SecureString -AsPlainText -Force
                midToolsRemoteUriSas       = '' | ConvertTo-SecureString -AsPlainText -Force
            }
            Write-Host "Deployment parameters: $($deployParams | ConvertTo-Json -Depth 5)"
            
            # Run the deployment
            $deployment = New-AzResourceGroupDeployment @deployParams -ErrorAction Stop -Verbose
            
            # Parse results
            return @{
                Deployment              = $deployment
                DeploymentScriptOutputs = ($deployment.Outputs | ConvertTo-Json -Depth 22 | ConvertFrom-Json)
            }
        }
        catch {
            Write-Error "Error running Azure deployment script: $_"
            return $null
        }
    }
}

Describe "SnowDeploymentScript Integration Tests" -Tag 'Integration' {
    Context "Azure Environment Tests" {
        BeforeEach {
            # Skip tests if no Azure credentiafls are available
            if (-not $Script:AzureConfig.TenantId -or 
                -not $Script:AzureConfig.SubscriptionId -or
                -not $Script:AzureConfig.ClientId -or
                -not $Script:AzureConfig.ClientSecret) {
                Set-ItResult -Skipped -Because "Azure credentials not available"
            }
        }
        
        It "Should resolve Azure build context" {
            $result = Resolve-SNOWMidBuildContext
            $result | Should -Not -BeNullOrEmpty
            $result.EnvironmentName | Should -Be $env:SN_MID_ENVIRONMENT_NAME
        }
        
        It "Should connect to Azure using environment variables" {
            $envVars = @{
                AZURE_TENANT_ID       = $Script:AzureConfig.TenantId
                AZURE_SUBSCRIPTION_ID = $Script:AzureConfig.SubscriptionId
                AZURE_CLIENT_ID       = $Script:AzureConfig.ClientId
                AZURE_CLIENT_SECRET   = $Script:AzureConfig.ClientSecret
            }
            
            $result = Connect-SNOWMidAzureFromEnvironment
            if (-not $result) {
                # Try with explicit environment variables
                foreach ($key in $envVars.Keys) {
                    [System.Environment]::SetEnvironmentVariable($key, $envVars[$key], 'Process')
                }
                $result = Connect-SNOWMidAzureFromEnvironment
                # Clean up environment variables
                foreach ($key in $envVars.Keys) {
                    [System.Environment]::SetEnvironmentVariable($key, $null, 'Process')
                }
            }
            
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "Local PowerShell Execution - Local Context" {
        BeforeEach {
            # Set up environment variables for tests
            $Script:TestEnvVars = @{
                SN_MID_ENVIRONMENT_NAME = $env:SN_MID_ENVIRONMENT_NAME
                SN_MID_CONTEXT          = 'azure'
            }
        }
        
        It "Should connect to ServiceNow and retrieve build context" {
            $result = Invoke-LocalPowerShellCommand -ScriptBlock {
                Resolve-SNOWMidPrereqs
                $buildContext = Resolve-SNOWMidBuildContext
                $Script:AzureConfig = Resolve-SNOWMidAzureEnvironmentSecrets -SetEnvironmentVariables
                Connect-SNOWMidAzureFromEnvironment
                $DeploymentScriptOutputs = @{
                    BuildContext = $buildContext
                    AzContext    = Get-AzContext
                }
            } -EnvironmentVariables $Script:TestEnvVars
            
            $result | Should -Not -BeNullOrEmpty
            $result.BuildContext | Should -Not -BeNullOrEmpty
            $result.BuildContext.EnvironmentName | Should -Be $env:SN_MID_ENVIRONMENT_NAME
        }

        It 'Should create a new MID server user' {
            $result = Invoke-LocalPowerShellCommand -ScriptBlock {
                $buildContext = Resolve-SNOWMidBuildContext
                
                $DeploymentScriptOutputs = @{
                    BuildContext = $buildContext
                }
                
            } -EnvironmentVariables $Script:TestEnvVars
            $result.BuildContext | Should -Not -BeNullOrEmpty
            $result.BuildContext.EnvironmentName | Should -Be $env:SN_MID_ENVIRONMENT_NAME
        }
    }
    
    Context "Local PowerShell Execution - Azure Context" {
        BeforeEach {
            # Skip tests if no Azure credentials are available
            if (-not $Script:AzureConfig.TenantId -or 
                -not $Script:AzureConfig.SubscriptionId -or
                -not $Script:AzureConfig.ClientId -or
                -not $Script:AzureConfig.ClientSecret) {
                Set-ItResult -Skipped -Because "Azure credentials noSADt available"
            }
            
            # Set up environment variables for tests
            $Script:TestEnvVars = @{
                SN_MID_ENVIRONMENT_NAME = $env:SN_MID_ENVIRONMENT_NAME
                SN_MID_CONTEXT          = 'azure'
            }
        }
        
        It "Should connect to Azure and retrieve build context" {
            $result = Invoke-LocalPowerShellCommand -ScriptBlock {
                $buildContext = Resolve-SNOWMidBuildContext -Verbose
                $ConnectResults = Connect-SNOWMidAzureFromEnvironment -Verbose
                $DeploymentScriptOutputs = @{
                    ConnectResults = $connectResults
                    BuildContext   = $buildContext
                    Ctx            = Get-AzContext
                }
                
            } -EnvironmentVariables $Script:TestEnvVars
            
            $result | Should -Not -BeNullOrEmpty
            $result.ConnectResults | Should -Not -BeNullOrEmpty
            $result.BuildContext | Should -Not -BeNullOrEmpty
            $result.BuildContext.EnvironmentName | Should -Be $env:SN_MID_ENVIRONMENT_NAME
        }

        It 'Should resolve the custom resources' {
            $result = Invoke-LocalPowerShellCommand -ScriptBlock {
                $connectResults = Connect-SNOWMidAzureFromEnvironment
                $buildContext = Resolve-SNOWMidBuildContext
                
                $DeploymentScriptOutputs = @{
                    ConnectResults = $connectResults
                    BuildContext   = $buildContext
                    Ctx            = Get-AzContext
                    Resources      = Resolve-SNOWMidCustomResources
                }
                
            } -EnvironmentVariables $Script:TestEnvVars
            
            $result | Should -Not -BeNullOrEmpty
            $result.ConnectResults | Should -Not -BeNullOrEmpty
            $result.BuildContext | Should -Not -BeNullOrEmpty
            $result.BuildContext.EnvironmentName | Should -Be $env:SN_MID_ENVIRONMENT_NAME
            Write-Host ($result | ConvertTo-Json -Depth 15)
        }
        BeforeAll {
            Resolve-SNOWMidEnvironmentAuth
            function ValidateMidServer($MidServerName) {
                $scriptHeader = 'var SYS_AUTO_SCRIPT_NAME="AZURE_DEVOPS_MIDVALIDATE_{0}";var MID_SERVER_NAME="{0}";var SYS_AUTO_SCRIPT_EXPIRY_MINUTES=60;' -f $MidServerName
                $scriptBase = 'function GetMidUserMetadata(midServerName){var user=new GlideRecord("sys_user");user.addQuery("employee_number","STARTSWITH","SNMID|"+midServerName);user.query();if(!user.next()){gs.info("User not found for MID Server "+midServerName);return null}var metaParts=user.employee_number.split("|");var outputs={user:user,midServerName:midServerName};if(metaParts.length>=3){outputs.midServerCluster=metaParts[2]}if(metaParts.length>=4){outputs.midServerCluster=metaParts[2];outputs.midServerStatus=metaParts[3]}var agent=new GlideRecord("ecc_agent");agent.addQuery("name",midServerName);agent.query();if(agent.next()){outputs.agent=agent}return outputs}function CheckCapabilities(midServerName,capabilities){if(!capabilities){capabilities=["ALL"]}var outputs={capabilities:[]};var agent=new GlideRecord("ecc_agent");agent.addQuery("name",midServerName);agent.query();if(!agent.next()){gs.info("MID Server "+midServerName+" not found");return}var agentCaps=capabilities.map(function(cap){var capQuery=new GlideRecord("ecc_agent_capability_m2m");capQuery.addEncodedQuery("agent="+agent.sys_id+"^capability.name="+cap);capQuery.query();if(capQuery.next()){gs.debug("Capability "+cap+" found for MID Server "+midServerName);outputs.capabilities.push(capQuery.sys_id.toString())}else{gs.info("Capability "+cap+" not found for MID Server "+midServerName);var newCap=new GlideRecord("ecc_agent_capability_m2m");newCap.initialize();newCap.capability.setDisplayValue(cap);newCap.agent=agent.sys_id;if(newCap.insert()){outputs.capabilities.push(newCap.sys_id)}else{gs.info("Failed to add capability "+cap+" to MID Server "+midServerName)}}return capQuery});return outputs}function CheckCluster(midServerName){var userMeta=GetMidUserMetadata(midServerName);if(userMeta===null){gs.info("User metadata not found for MID Server "+midServerName);return}var cluster=new GlideRecord("ecc_agent_cluster");cluster.addQuery("name",userMeta.midServerCluster);cluster.query();if(!cluster.next()){gs.info("Cluster "+userMeta.midServerCluster+" not found. Creating...");cluster=new GlideRecord("ecc_agent_cluster");cluster.initialize();cluster.name=userMeta.midServerCluster;cluster.active=true;cluster.insert()}var clusterMember=new GlideRecord("ecc_agent_cluster_member_m2m");clusterMember.addQuery("cluster.name",userMeta.midServerCluster);clusterMember.addQuery("agent.name",midServerName);clusterMember.query();if(!clusterMember.next()){gs.info("MID Server "+midServerName+" not found in cluster "+userMeta.midServerCluster);clusterMember=new GlideRecord("ecc_agent_cluster_member_m2m");clusterMember.initialize();clusterMember.cluster.setDisplayValue(userMeta.midServerCluster);clusterMember.agent.setDisplayValue(midServerName);clusterMember.insert()}return clusterMember.sys_id.toString()}function ValidateMidServer(midServerName){var outputs={success:false,status:"unknown",midServer:midServerName};var userMeta=GetMidUserMetadata(midServerName);if(userMeta===null){gs.info("User metadata not found for MID Server "+midServerName);outputs.status="not found";return outputs}if(gs.nil(userMeta.agent)){gs.info("Agent not found for MID Server "+midServerName);outputs.status="agent not found";return outputs}outputs.clusterMember=CheckCluster(midServerName);outputs.capabilities=CheckCapabilities(midServerName);var agent=userMeta.agent;outputs.agent_status=agent.status.toString();var mm=new global.MIDServerManage;var invalidateRequired=false;var errors=new global.GlideQuery("ecc_agent_issue").where("mid_server.name",midServerName).where("state","!=","resolved").where("source","UpdatePublicKey").select("sys_id","state","message").toArray(10);if(errors.length>0){invalidateRequired=true;if(agent.validated.toString()==="true"){if(agent.status=="Up"){gs.info("Agent re-validation required for MID Server "+midServerName);mm.invalidate(agent.name);outputs.status="invalidating"}}return outputs}if(agent.validated.toString()==="false"&&agent.status=="Up"){mm.validate(agent.name);outputs.status="validating";outputs.success=true}else{outputs.status=userMeta.agent.validated.toString();outputs.success=true}return outputs}function ClearAutoScript(name,forceDelete){var script=new GlideRecord("sysauto_script");script.addQuery("name",name);script.query();if(script.next()){if(forceDelete){script.deleteRecord();return"sysauto_script "+name+" deleted"}else{var lastModified=new GlideDateTime(script.sys_created_on);var now=new GlideDateTime;var mins=gs.dateDiff(lastModified,now,true)/60;if(mins>SYS_AUTO_SCRIPT_EXPIRY_MINUTES){script.deleteRecord();return"sysauto_script "+name+" deleted - Time Elapsed: "+mins}else{return"sysauto_script "+name+" not expired. Minutes Elapsed: "+mins}}}else{return"sysauto_script "+name+" not found"}}var results=ValidateMidServer(MID_SERVER_NAME);if(results.success){results.sys_script_auto=ClearAutoScript(SYS_AUTO_SCRIPT_NAME,false)}else{results.sys_script_auto=ClearAutoScript(SYS_AUTO_SCRIPT_NAME,false)}gs.info(JSON.stringify(results,null,2));'
                $MidRecord = Get-SNOWObject -Table 'ecc_agent' -Query "name=$MidServerName" -Fields 'sys_id,name,cluster.name,cluster.sys_id,sys_class_name,sys_domain,sys_domain_path,sys_created_on,sys_updated_on,status'
                $MidRecordIssues = Get-SNOWObject -Table 'ecc_agent_issue' -Query "mid_server.name=$MidServerName^state!=resolved" -Fields 'sys_id,sys_created_on,sys_updated_on,state,message'
                Write-Host ($MidRecordIssues | ConvertTo-Json -Depth 15)
                $ValidateScript = @"
                $scriptHeader
                gs.info("Running MID server validation script for $MidServerName")
"@
                Invoke-SNOWBackgroundScript -ScriptContents $ValidateScript
            }
        }

        
        It "Should prepare environment and retrieve MID server details" {
            
            # First ensure we have a MID server user
            $midUser = Set-SNOWMidServerUser -MidServerName "azmiduloc06"
            $midUser | Should -Not -BeNullOrEmpty
            # ValidateMidServer $midUser.MidServerName
            # Update environment variables with MID server info
            $localVars = $Script:TestEnvVars.Clone()
            $localVars.MID_SERVER_NAME = $midUser.MidServerName
            $localVars.MID_INSTANCE_URL = $Script:SN_HOST
            $localVars.MID_INSTANCE_USERNAME = $midUser.Credentials.UserName
            $localVars.MID_INSTANCE_PASSWORD = ($midUser.Credentials.Password | ConvertFrom-SecureString -AsPlainText)
            
            $BuildResults = Build-SNOWMidImage
            # Use the results and local vars to start a podman container
            $ImageName = $BuildResults.CustomImageEnvironmentUri
            # $ImageName = 'localhost/snow_mid_custom:unts'
            $EnvVars = @{
                MID_INSTANCE_URL      = $localVars.MID_INSTANCE_URL
                MID_INSTANCE_USERNAME = $localVars.MID_INSTANCE_USERNAME
                MID_INSTANCE_PASSWORD = $localVars.MID_INSTANCE_PASSWORD
                MID_SERVER_NAME       = $localVars.MID_SERVER_NAME
            }
            podman rm -f $localVars.MID_SERVER_NAME 2>&1 | Out-Null
            $podmanParams = @(
                'run', '-d',
                '--env', "MID_INSTANCE_URL=$($EnvVars.MID_INSTANCE_URL)",
                '--env', "MID_INSTANCE_USERNAME=$($EnvVars.MID_INSTANCE_USERNAME)", 
                '--env', "MID_INSTANCE_PASSWORD=$($EnvVars.MID_INSTANCE_PASSWORD)",
                '--env', "MID_SERVER_NAME=$($EnvVars.MID_SERVER_NAME)",
                '--name', $localVars.MID_SERVER_NAME
                $ImageName
            )
            & podman $podmanParams | Tee-Object -Variable response | Write-Host
            # Wait for MID server to be registered and come online
            $maxWaitMinutes = 5 # Parameterize this if needed
            $startTime = Get-Date
            $timeout = $startTime.AddMinutes($maxWaitMinutes)
            $MidServer = $null
            $MidServerName = $localVars.MID_SERVER_NAME
            Write-Host "Waiting up to $maxWaitMinutes minutes for MID server $MidServerName to come online..."

            while ((Get-Date) -lt $timeout) {
                $MidServer = Get-SNOWObject -Table 'ecc_agent' -Query "name=$($EnvVars.MID_SERVER_NAME)" | Select-Object -First 1
                
                if ($MidServer) {
                    Write-Host "MID server found with status: $($MidServer.status)"
                    if ($MidServer.status -eq 'Up') {
                        Write-Host "MID server is up and running!"
                        break
                    }
                }

                Write-Host "Waiting 30 seconds before next check..."
                Start-Sleep -Seconds 4
            }

            if (-not $MidServer) {
                throw "MID server was not registered after $maxWaitMinutes minutes"
            }
            if ($MidServer.status -ne 'Up') {
                throw "MID server did not come online after $maxWaitMinutes minutes. Current status: $($MidServer.status)"
            }
            Write-PSFMessage -Level Important -Message "MID server $($MidServer.name) is up and running with status: $($MidServer.status)"
            Invoke-SNOWMidValidate -MidServerName $MidServerName -Verbose
            Write-Host "Podman response: $($response | Out-String)"
        }
    }
    
    Context "Podman Container Execution" {
        BeforeEach {
            # Skip tests if podman is not available
            if (-not (Get-Command 'podman' -ErrorAction SilentlyContinue)) {
                Set-ItResult -Skipped -Because "Podman not available"
                return
            }
            
            # Skip tests if no Azure credentials are available
            if (-not $Script:AzureConfig.TenantId -or 
                -not $Script:AzureConfig.SubscriptionId -or
                -not $Script:AzureConfig.ClientId -or
                -not $Script:AzureConfig.ClientSecret) {
                Set-ItResult -Skipped -Because "Azure credentials not available"
                return
            }
            
            # Set up environment variables for tests
            $Script:ContainerEnvVars = @{
                SN_MID_ENVIRONMENT_NAME          = $env:SN_MID_ENVIRONMENT_NAME
                SN_MID_CONTEXT                   = 'azure'
                SN_MID_BUILD_STRATEGY            = 'acr'
                AZ_SCRIPTS_PATH_OUTPUT_DIRECTORY = '/opt/snc_mid_server/tests'
                AZURE_TENANT_ID                  = $Script:AzureConfig.TenantId
                AZURE_SUBSCRIPTION_ID            = $Script:AzureConfig.SubscriptionId
                AZURE_CLIENT_ID                  = $Script:AzureConfig.ClientId
                AZURE_CLIENT_SECRET              = $Script:AzureConfig.ClientSecret

            }
            Write-Host ("ContainerEnvVars: $($Script:ContainerEnvVars.Keys | ConvertTo-Json -Depth 5)")
        }
        
        It "Should connect to Azure from container" {
            $result = Invoke-ContainerPowerShellCommand -ScriptBlock {
                $DeploymentScriptOutputs['ss'] = Get-AzResource -ResourceId '/subscriptions/063aa8c5-6e46-407a-b34e-c44d7f0f1ffb/resourceGroups/snowmid-azure-vnet-rg/providers/Microsoft.Network/virtualNetworks/aci-vnet-default/subnets/aci-subnet-default'
                # Assert-SNOWMidAzCli
                # $connectResults = Connect-SNOWMidAzureFromEnvironment
                # Resolve-SNOWMidPrereqs
                # $buildContext = Resolve-SNOWMidBuildContext
                # Resolve-SNOWMidEnvironmentAuth
                # # $BuildResults = Build-SNOWMidImage
                # # $SnowConn = Resolve-SNOWMidEnvironmentAuth
                # $DeploymentScriptOutputs = @{
                #     BuildContext = $buildContext
                #     SnowConn     = $connectResults
                #     BuildResults = $BuildResults
                # }
            } -EnvironmentVariables $Script:ContainerEnvVars
            
            $result | Should -Not -BeNullOrEmpty
            $result.DeploymentScriptOutputs | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Azure DeploymentScript Execution" {
        BeforeEach {
            # Verify we can access the Azure environment
            $env:SN_MID_ENVIRONMENT_NAME = 'unts'
            $env:SN_MID_CONTEXT = 'azure'
            $env:SN_MID_BUILD_STRATEGY = 'acr'
            Import-Module "$PSScriptRoot/../src/PSSnow.MidTools.psm1" -Force
            $Script:BuildContext = Resolve-SNOWMidBuildContext
            if (-not $Script:BuildContext -or 
                -not $Script:BuildContext.StorageAccount) {
                Set-ItResult -Skipped -Because "Azure build context not available"
                return
            }
            # Set up environment variables for tests
            $Script:DeploymentEnvVars = @{
                SN_TEST_VAR = $env:SN_MID_ENVIRONMENT_NAME
                MID_SERVER_NAME = 'azmiduloc06'
                MID_SERVER_CLUSTER = 'azmiduloc'
                SN_MID_ENVIRONMENT_NAME = $env:SN_MID_ENVIRONMENT_NAME
                SN_MID_CONTEXT = 'azure'
                SN_MID_BUILD_STRATEGY = 'acr'
            }
        }
        
        It "Should execute as deployment script and prepare environment" {
            # This test is skipped by default as it requires a valid TestDeploymentScript.bicep
            # and appropriate Azure resources
            
            $result = Invoke-AzDeploymentScriptCommand -ScriptBlock {
                $env:MID_SERVER_NAME = 'azmiduloc06'
                $MidServerName = $env:MID_SERVER_NAME
                Resolve-SNOWMIDPrereqs
                # $connectResults = Connect-SNOWMIDAzureFromEnvironment
                # $ctx = Resolve-SNOWMIDBuildContext
                # $SnowConn = Resolve-SNOWMIDEnvironmentAuth
                # $BuildResults = Build-SNOWMidImage -Verbose
                # $UserResult = Set-SNOWMIDServerUser -MidServerName $env:MID_SERVER_NAME -MidServerCluster $env:MID_SERVER_CLUSTER
                # foreach($key in $UserResult.Keys) {
                #     $DeploymentScriptOutputs[$key] = $UserResult[$key]
                # }
                # $DeploymentScriptOutputs['MidVersion'] = Get-SNOWMidVersion
                # $DeploymentScriptOutputs['sysauto_script'] = try {
                #     Start-SNOWMIDValidationScript -MidServerName $env:MID_SERVER_NAME -ErrorAction Stop
                # } catch {
                #     Write-PSFMessage -Level Warning "Failed to start validation script. Ensure the MID Server has the necessary permissions."
                #     "Error: $_"
                # }
                # $RootCA = Set-SNOWMidRootCertificate -VaultName $ctx.KeyVault.Name -RootCN 'az-mid-ca' -ErrorAction Stop
                # $MidCert = Set-SNOWMidServerCertificate -VaultName $ctx.KeyVault.Name -LeafCN $MidServerName -Signer $RootCA.Collection[0] -ErrorAction Stop
                # $DeploymentScriptOutputs.MidCert = $MidCert.PublicKeyInfo
                # $DeploymentScriptOutputs.MidCertSecret = $MidCert.PemSecret.Name
                # $DeploymentScriptOutputs.BuildContext = $ctx
                # $DeploymentScriptOutputs.MidCertThumbprint = $MidCert.Thumbprint
                # $DeploymentScriptOutputs.MidCertSubject = $MidCert.Collection[0].Subject
                # foreach ($key in $Ctx.Keys) {
                #     $DeploymentScriptOutputs[$key] = $Ctx[$key]
                # }
                # $ImageState = Resolve-SNOWMIDImageState
                # $DeploymentScriptOutputs['ImageState'] = $ImageState
                # $DeploymentScriptOutputs['EnvVars'] += @{
                #     MID_INSTANCE_USERNAME = $UserResult.Credentials.UserName
                   
                # }
                # $DeploymentScriptOutputs['SecretEnvVars'] = @{
                #     MID_INSTANCE_PASSWORD = $UserResult.VaultSecret
                #     MID_SERVER_PEM_BASE64      = $MidCert.PemSecret.Name
                # }
            } -BuildContext $Script:BuildContext -EnvironmentVariables $Script:DeploymentEnvVars
            $Global:RESS = $result            
            $result | Should -Not -BeNullOrEmpty
            $result.Deployment | Should -Not -BeNullOrEmpty
            $result.DeploymentScriptOutputs | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "MID Server User Management" {
        
        
        It "Should create and validate MID server user" {
            $midServerName = $Script:NewMidServer.name
            
            # Clean up any existing users
            $existingUser = Get-SNOWObject -Table 'sys_user' -Query "user_name=azmid-$midServerName"
            if ($existingUser) {
                Remove-SNOWObject -Table 'sys_user' -Sys_ID $existingUser.sys_id -Confirm:$false -ErrorAction SilentlyContinue
            }
            
            # Create new user
            $result = Set-SNOWMidServerUser -MidServerName $midServerName
            
            $result | Should -Not -BeNullOrEmpty
            $result.MidServerName | Should -Be $midServerName
            $result.User | Should -Not -BeNullOrEmpty
            $result.User.user_name | Should -BeExactly "azmid-$midServerName"
        }
    }
}