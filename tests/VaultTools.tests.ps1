# Set up configuration objects - INITIALIZE EARLY
$script:localConfig = @{
    Name             = "LocalVault"
    VaultName        = "PSSnowTestVault"
    UseAzureKeyVault = $false
    Skip             = $false
    ModuleName       = "Microsoft.PowerShell.SecretStore"
}



# Store configurations for retrieval in tests - INITIALIZE EARLY
$global:VaultConfigs = @($script:localConfig)

# Create proper test cases array - INITIALIZE EARLY with script scope
$global:VaultTestCases = @(
    @{ Config = $script:localConfig }
)

BeforeAll {
    $env:SN_MID_ENVIRONMENT_NAME = 'vuts'
    # Import the module
    Import-Module "$PSScriptRoot/../PSSnow.MidTools.psm1"
    
    # Test data
    $script:TestMetadata = @{
        EnvironmentName = "TestEnvironment"
        SubscriptionId  = "12345678-1234-1234-1234-123456789012"
        TestDate        = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffff')
    }
    
    $script:TestComplexObject = @{
        ConnectionStrings = @{
            Default = "Server=myserver;Database=mydb;User Id=myuser;Password=mypassword;"
        }
        AppSettings       = @{
            Environment = "Development"
            LogLevel    = "Debug"
            Features    = @{
                EnableCache = $true
                MaxItems    = 100
            }
        }
        Array             = @("item1", "item2", @{SubItem = "value" })
    }

    $script:TestSNOWConnection = @{
        Instance      = "dev12345"
        Username      = "admin"
        Password      = "********"
        UseRestMethod = $true
    }

    # Debug output to verify test cases
    Write-Host "Test cases initialized:"
    $global:VaultTestCases | ForEach-Object { 
        Write-Host "  - $($_.Config.Name) (Skip: $($_.Config.Skip))"
    }

    Set-SecretStoreConfiguration -Authentication None -Scope CurrentUser -Confirm:$false

    # Helper function to initialize a vault with test data
    function Initialize-TestVault {
        param (
            [Parameter(Mandatory)]
            [hashtable]$VaultConfig
        )

        Write-Host "Initializing vault: $($VaultConfig.Name)"
        
        $resolveParams = @{
            VaultName      = $VaultConfig.VaultName
            UpdateMetadata = $true
            VaultMetadata  = $script:TestMetadata
        }

        if ($VaultConfig.UseAzureKeyVault) {
            $resolveParams.UseAzureKeyVault = $true
            $resolveParams.AzureKeyVaultName = $VaultConfig.AzureKeyVaultName
            $resolveParams.AzureSubscriptionId = $VaultConfig.AzureSubscriptionId
        }

        return Resolve-SNOWMidSecretManagementVault @resolveParams
    }
}

Describe "VaultTools Integration Tests" {
    BeforeAll {
        # Verify test cases are available in this scope
        Write-Host "VaultTestCases in Describe block:"
        $global:VaultTestCases | ForEach-Object { 
            Write-Host "  - $($_.Config.Name) (Skip: $($_.Config.Skip))"
        }
    }
    
    AfterAll {
        # Clean up test vaults
        foreach ($config in $global:VaultConfigs) {
            try {
                Unregister-SecretVault -Name $config.VaultName -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Failed to unregister vault $($config.VaultName): $_"
            }
        }
    }

    It 'Should register the test vaults' {
        foreach ($config in $global:VaultConfigs) {
            if (-not (Get-SecretVault -Name $config.VaultName -ErrorAction SilentlyContinue)) {
                $Vault = Initialize-TestVault -VaultConfig $config
                $Vault | Should -Not -BeNullOrEmpty
                $Vault.VaultName | Should -Be $config.VaultName
            }
        }
    }

    Context "Vault Operations" {
        # Verify test cases again in this scope
        BeforeAll {
            Write-Host "VaultTestCases in Context block:"
            $global:VaultTestCases | ForEach-Object { 
                Write-Host "  - $($_.Config.Name) (Skip: $($_.Config.Skip))"
            }
        }
        
        # Make sure param() is declared in all test blocks
        It "Should create and configure a <Config.Name> vault" -TestCases $global:VaultTestCases {
            param($Config)
            
            Write-Host "Running test for: $($Config.Name) - $($Config.VaultName) - $($Config.ModuleName)"
            
            if ($Config.Skip) {
                Set-ItResult -Skipped -Because "Vault type not available in this environment"
                return
            }

            $result = Initialize-TestVault -VaultConfig $Config
            
            $result | Should -Not -BeNullOrEmpty
            $result.VaultName | Should -Be $Config.VaultName
            $result.Vault.Name | Should -Be $Config.VaultName
            $result.VaultParams.ModuleName | Should -Be $Config.ModuleName
        }
        
        It "Should retrieve metadata from <Config.Name> vault" -TestCases $global:VaultTestCases {
            param($Config)
            
            Write-Host "Running test for: $($Config.Name) - $($Config.VaultName) - $($Config.ModuleName)"
            
            if ($Config.Skip) {
                Set-ItResult -Skipped -Because "Vault type not available in this environment"
                return
            }

            Initialize-TestVault -VaultConfig $Config | Out-Null
            
            $metadata = Get-JsonSecret -SecretName 'AzVaultMetadata' -VaultName $Config.VaultName
            
            $metadata | Should -Not -BeNullOrEmpty
            $metadata.EnvironmentName | Should -Be $script:TestMetadata.EnvironmentName
            $metadata.SubscriptionId | Should -Be $script:TestMetadata.SubscriptionId
            $metadata.TestDate | Should -Not -BeNullOrEmpty
        }
        
        # Rest of the tests...
        
        It "Should store and retrieve complex JSON objects in <Config.Name> vault" -TestCases $global:VaultTestCases {
            param($Config)
            
            Write-Host "Running test for: $($Config.Name)"
            
            if ($Config.Skip) {
                Set-ItResult -Skipped -Because "Vault type not available in this environment"
                return
            }

            Initialize-TestVault -VaultConfig $Config | Out-Null
            
            # Store the complex object
            Set-JsonSecret -SecretName "TestComplexObject" -SecretValue $script:TestComplexObject -VaultName $Config.VaultName
            
            # Retrieve it
            $retrieved = Get-JsonSecret -SecretName "TestComplexObject" -VaultName $Config.VaultName
            
            $retrieved | Should -Not -BeNullOrEmpty
            $retrieved.ConnectionStrings.Default | Should -Be $script:TestComplexObject.ConnectionStrings.Default
            $retrieved.AppSettings.Features.EnableCache | Should -Be $script:TestComplexObject.AppSettings.Features.EnableCache
            $retrieved.Array[2].SubItem | Should -Be $script:TestComplexObject.Array[2].SubItem
        }
        
        # Remaining tests follow same pattern...
    }
}