<#
.SYNOPSIS
    Integration tests for PSSnow.MidTools.psm1 module.

.DESCRIPTION
    This file contains tests for the PSSnow.MidTools.psm1 script.
    It validates both Azure and ServiceNow integration functions.

.NOTES
    Requires connection to both ServiceNow and Azure for full test coverage.
#>

Describe 'SnowMidTools Integration Tests'  -Tag 'Integration' {
    BeforeAll {
        $env:SN_MID_CONTEXT = 'local'
        $env:SN_MID_ENVIRONMENT_NAME = 'unts'
        Import-Module "$PSScriptRoot/../src/PSSnow.MidTools.psm1" -Force
    }
    Context 'Azure Build Functions - Local Context' {
        
        It 'Should resolve the build context' {
            
            $result = Resolve-SNOWMIDBuildContext
            $result | Should -Not -BeNullOrEmpty
            $result.EnvironmentName | Should -Be 'unts'
            $result.Vault | Should -Not -BeNullOrEmpty

            $Vault = Resolve-SNOWMIDVault
            $Vault | Should -Not -BeNullOrEmpty
        } 

        It 'Should resolve a mid server user' {
            $SnowConn = Resolve-SNOWMIDEnvironmentAuth
            $SnowConn | Should -Not -BeNullOrEmpty
            $SnowConn.Instance | Should -BeLike 'https://*service-now.com'
            $SnowConn.Credential | Should -Not -BeNullOrEmpty
            Set-SNOWMIDServerUser -MidServerName "testmid1443" 
        }

        It 'Should resolve a mid server user - and then connect' {
            $SnowConn = Resolve-SNOWMIDEnvironmentAuth
            $SnowConn | Should -Not -BeNullOrEmpty
            $SnowConn.Instance | Should -BeLike 'https://*service-now.com'
            $SnowConn.Credential | Should -Not -BeNullOrEmpty
            
        }
    }

    Context 'Azure Build Functions - New Environment' {
        BeforeEach {
            $env:SN_MID_ENVIRONMENT_NAME = 'nonex'
            $env:SN_MID_CONTEXT = 'local'
            $env:SN_MID_BUILD_STRATEGY = 'acr'
            Import-Module "$PSScriptRoot/../src/PSSnow.MidTools.psd1" -Force
        }
        It 'Should resolve the build context' {
            $result = Resolve-SNOWMIDBuildContext
            $result | Should -Not -BeNullOrEmpty
            $result.EnvironmentName | Should -Be 'nonex'
            $result.Vault | Should -Not -BeNullOrEmpty

            $Vault = Resolve-SNOWMIDVault
            $Vault | Should -Not -BeNullOrEmpty
        } 
    }

    Context 'Azure Build Functions' {
        BeforeEach {
            $env:SN_MID_ENVIRONMENT_NAME = 'unts'
            $env:SN_MID_CONTEXT = 'azure'
            $env:SN_MID_BUILD_STRATEGY = 'acr'
            Import-Module "$PSScriptRoot/../src/PSSnow.MidTools.psm1" -Force
        }
        It 'Should install PSSnow module if not already installed' {
            Resolve-SNOWMIDPrereqs
            $result = Get-Module -Name PSSnow
            $result | Should -Not -BeNullOrEmpty
        }
        
        It 'Should connect to Azure from environment variables' -Skip {
            $result = Connect-SNOWMIDAzureFromEnvironment
            $result | Should -Not -BeNullOrEmpty
            $result.Environment | Should -Be $env:SN_MID_ENVIRONMENT_NAME
        }
        
        It 'Should resolve the build context' {
            $env:SN_MID_BUILD_STRATEGY = 'acr'
            $result = Resolve-SNOWMIDBuildContext
            $result | Should -Not -BeNullOrEmpty
            $imageState = Resolve-SNOWMIDImageState
            $result.EnvironmentName | Should -Be 'unts'
            $BuildResults = Build-SNOWMidImage
        }        

        It 'Should resolve the custom resources' {
            $result = Resolve-SNOWMIDCustomResources -EnvironmentName 'unts'
            $result | Should -Not -BeNullOrEmpty
            $result.ContainerRegistry | Should -Not -BeNullOrEmpty
            Write-Host ($result | ConvertTo-Json -Depth 15)
        }
    }
    
    Context 'ServiceNow Functions - MidServer' {
        BeforeAll {
            $Script:TestMidServer = @{
                name = "testmidserver01"
            }
        }
        It 'Should connect to ServiceNow with environment variables' {
            $result = Resolve-SNOWMIDEnvironmentAuth
            $result | Should -Not -BeNullOrEmpty
        }
        
        It 'Should create a MID Server user' {
            
            $params = @{
                MidServerName = $Script:TestMidServer.name
                Password      = (GenerateRandomPassword -Length 16)
            }
            $result = Set-SNOWMIDServerUser @params
            $result | Should -Not -BeNullOrEmpty
            $result.User.user_name | Should -Be "azmid-$($Script:TestMidServer.name)"
        }
        
        It 'Should create a new secure password' {
            $length = 16
            $result = GenerateRandomPassword -Length $length
            $result | Should -BeOfType [System.Security.SecureString]
            
            $plainText = GenerateRandomPassword -Length $length -AsPlainText
            $plainText | Should -BeOfType [System.String]
            $plainText.Length | Should -Be $length
        }
        
        It 'Should resolve download facts for MID server build tags' {
            $buildTags = @(
                @{
                    BuildTag   = 'xanadu-07-02-2024__patch7-02-27-2025_03-06-2025_0935'
                    PackageUri = 'https://install.service-now.com/glide/distribution/builds/package/app-signed/mid-linux-container-recipe/2025/03/06/mid-linux-container-recipe.xanadu-07-02-2024__patch7-02-27-2025_03-06-2025_0935.linux.x86-64.zip'
                },
                @{
                    BuildTag   = 'xanadu-07-02-2024__patch1-08-24-2024_09-01-2024_1853'
                    PackageUri = 'https://install.service-now.com/glide/distribution/builds/package/app-signed/mid-linux-container-recipe/2024/09/01/mid-linux-container-recipe.xanadu-07-02-2024__patch1-08-24-2024_09-01-2024_1853.linux.x86-64.zip'
                }
            )
            
            foreach ($fact in $buildTags) {
                $result = Get-SNOWMIDDownloadFacts -BuildTag $fact.BuildTag
                $result | Should -Not -BeNullOrEmpty
                $result.PackageUri | Should -Be $fact.PackageUri
            }
        }
    }
    
    # Context 'Docker/Podman Functions' {
    #     It 'Should get Docker/Podman command' {
    #         $result = Get-DockerPodmanCommand -ErrorAction SilentlyContinue
    #         # This might be null if Docker/Podman is not installed
    #         if ($result) {
    #             $result | Should -BeIn @('docker', 'podman')
    #         }
    #     }
        
    #     It 'Should handle Dockerfile content retrieval' {
    #         # This might return null if no Dockerfile is available
    #         $result = Get-DockerPodmanDockerFileContent -ErrorAction SilentlyContinue
    #         if ($result) {
    #             $result | Should -BeOfType [System.String]
    #             $result | Should -Match 'FROM'
    #         }
    #     }
        
    #     It 'Should merge hashtables correctly' {
    #         $default = @{
    #             Key1 = "Value1"
    #             Key2 = "Value2"
    #         }
            
    #         $uppend = @{
    #             Key2 = "NewValue2"
    #             Key3 = "Value3"
    #         }
            
    #         $result = Merge-DockerPodmanHashTables -default $default -uppend $uppend
    #         $result.Key1 | Should -Be "Value1"
    #         $result.Key2 | Should -Be "NewValue2"
    #         $result.Key3 | Should -Be "Value3"
    #         $result.Count | Should -Be 3
    #     }
    # }
    
    Context 'Comprehensive Workflows' {
        BeforeAll {
            $Script:NewMidServer = @{
                name = "testmidserver01"
            }
        }
        It 'Should set up a MID server user with roles' {
            $params = @{
                MidServerName    = $Script:NewMidServer.name
                Password         = GenerateRandomPassword
                Roles            = @('mid_server')
                MidServerCluster = 'test_cluster'
                Operation        = 'test'
            }
            
            $result = Set-SNOWMIDServerUser @params
            $result | Should -Not -BeNullOrEmpty
            $result.MidServerName | Should -Be $Script:NewMidServer.name
            $result.User | Should -Not -BeNullOrEmpty
            $result.Roles | Should -Not -BeNullOrEmpty
        }
        
        # Skip complex tests that require full environment setup
        It 'Should build MID server images' {
            $env:SN_MID_ENVIRONMENT_NAME = 'unts'
            $env:SN_MID_CONTEXT = 'local'
            $env:SN_MID_BUILD_STRATEGY = 'podman'
            Import-Module "$PSScriptRoot/../src/PSSnow.MidTools.psm1" -Force
            $buildContext = Resolve-SNOWMIDBuildContext
            $TestDockerContent = @'
FROM localhost/snow_mid_server:yokohama-12-18-2024__patch1-02-21-2025_03-05-2025_2133
ARG AZ_PWSH_VERSION="14.2.0"
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
'@
            $env:SN_MID_CUSTOM_DOCKERFILE_BASE64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($TestDockerContent))
            $env:PODMAN_CONNECTION = 'odev'
            $result = Build-SNOWMidImage -ForceBuildCustom
            $result | Should -Not -BeNullOrEmpty
        }
    }
}