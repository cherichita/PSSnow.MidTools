# Azure ServiceNow MID Server Credentials Template

This Bicep template replicates the functionality of the PowerShell `Set-SNOWMidEnvironmentSecret` function from PSSnow.MidTools, providing a comprehensive solution for storing ServiceNow credentials in Azure Key Vault.

## Overview

The template automatically detects the authentication method based on provided parameters:

- **Basic Authentication**: Username/password credentials via `credential` object
- **OAuth**: Client ID/Secret with optional username/password
- **OAuth Token**: Access token, refresh token, and client credentials

## Features

### Authentication Methods

The template automatically determines the authentication method based on the parameters provided:

| Method       | Detection Logic                                   | Required Parameters                                   | Notes                                        |
| ------------ | ------------------------------------------------- | ----------------------------------------------------- | -------------------------------------------- |
| `OAuthToken` | Has `accessToken` and `refreshToken`              | `instance`, `accessToken`, `refreshToken`, `clientID` | OAuth with existing tokens                   |
| `OAuth`      | Has `clientID` and `clientSecret` (but no tokens) | `instance`, `clientID`, `clientSecret`                | OAuth client credentials                     |
| `Basic`      | Has `credential` object with UserName/Password    | `instance`, `credential`                              | Traditional username/password authentication |

### Parameter Requirements by Authentication Method

#### Basic Authentication

**Required:**

- `instance`: ServiceNow instance URL or name
- `credential`: Object with `UserName` and `Password` properties
- `snowConnectionSecretName`: Name for the connection JSON secret

#### OAuth Authentication  

**Required:**

- `instance`: ServiceNow instance URL or name
- `clientID`: OAuth client identifier
- `clientSecret`: OAuth client secret
- `snowConnectionSecretName`: Name for the connection JSON secret

**Optional:**

- `credential`: For hybrid authentication scenarios

#### OAuth Token Authentication

**Required:**

- `instance`: ServiceNow instance URL or name
- `clientID`: OAuth client identifier  
- `accessToken`: Current access token
- `refreshToken`: Token for refreshing access
- `snowConnectionSecretName`: Name for the connection JSON secret

**Optional:**

- `clientSecret`: May be required for confidential OAuth clients
- `expires`: Token expiration timestamp (ISO 8601 format)

### Secret Storage

The template creates a connection JSON secret using the `modules/keyvault-secrets.bicep` module. The module handles the actual secret creation and individual secret storage logic.

### Connection Object Structure

The JSON connection object includes all PSSnow parameters:

```json
{
  "Instance": "https://instance.service-now.com",
  "HandleRatelimiting": false,
  "WebCallTimeoutSeconds": 100,
  "BypassDefaultProxy": false,
  "UseWebSession": false,
  "Credential": {
    "UserName": "username",
    "Password": "password"
  },
  "ClientID": "oauth-client-id",
  "ClientSecret": "oauth-client-secret",
  "AccessToken": "oauth-access-token",
  "RefreshToken": "oauth-refresh-token",
  "Expires": "2025-12-31T23:59:59Z",
  "ProxyURI": "http://proxy:8080",
  "ProxyCredential": {
    "UserName": "proxy-user",
    "Password": "proxy-password"
  }
}
```

## Parameters

### Core Configuration

- `instance`: ServiceNow instance URL or name
- `snowConnectionSecretName`: Name for the main connection JSON secret
- `keyVaultName`: Target Key Vault name (max 24 characters)
- `keyVaultResourceGroup`: Key Vault resource group (defaults to current resource group)
- `keyVaultSubscription`: Key Vault subscription ID (defaults to current subscription)

### Authentication Parameters

- `credential`: Object with `UserName` and `Password` for basic authentication
- `clientID`: OAuth client identifier
- `clientSecret`: OAuth client secret
- `accessToken`: OAuth access token
- `refreshToken`: OAuth refresh token
- `expires`: OAuth token expiration (ISO 8601 format)

### Optional Configuration

- `proxyURI`: Proxy server URI
- `proxyCredential`: Object with proxy `UserName` and `Password`
- `handleRatelimiting`: Enable rate limit handling (boolean, default: false)
- `webCallTimeoutSeconds`: Request timeout in seconds (integer, optional)
- `bypassDefaultProxy`: Bypass system proxy (boolean, optional)
- `useWebSession`: Enable session state management (boolean, optional)

## Usage Examples

### Basic Authentication Parameters

```bicep
module snowCredentials 'azure_servicenow_mid_acs_credentials.bicep' = {
  name: 'snow-creds-basic'
  params: {
    instance: 'dev12345.service-now.com'
    snowConnectionSecretName: 'snow-connection-dev-json'
    keyVaultName: 'snkv-dev-abc123'
    credential: {
      UserName: 'midserver_user'
      Password: 'securePassword123!'
    }
    // Optional: keyVaultResourceGroup and keyVaultSubscription default to current scope
  }
}
```

### OAuth Authentication (Client Credentials)

```bicep
module snowCredentials 'azure_servicenow_mid_acs_credentials.bicep' = {
  name: 'snow-creds-oauth'
  params: {
    instance: 'https://company.service-now.com'
    snowConnectionSecretName: 'snow-connection-prod-json'
    keyVaultName: 'snkv-prod-xyz789'
    clientID: 'oauth-client-12345'
    clientSecret: 'oauth-secret-67890'
    keyVaultResourceGroup: 'rg-keyvault-prod'
  }
}
```

### OAuth Token Parameters

```bicep
module snowCredentials 'azure_servicenow_mid_acs_credentials.bicep' = {
  name: 'snow-creds-token'
  params: {
    instance: 'test.service-now.com'
    snowConnectionSecretName: 'snow-connection-test-json'
    keyVaultName: 'snkv-test-def456'
    clientID: 'oauth-client-12345'
    accessToken: 'access-token-abc123'
    refreshToken: 'refresh-token-xyz789'
    expires: '2025-12-31T23:59:59Z'
    // clientSecret is optional for public clients
  }
}
```

### Full Configuration with Proxy

```bicep
module snowCredentials 'azure_servicenow_mid_acs_credentials.bicep' = {
  name: 'snow-creds-full'
  params: {
    instance: 'https://company.service-now.com'
    snowConnectionSecretName: 'snow-connection-prod-json'
    keyVaultName: 'snkv-prod-xyz789'
    keyVaultResourceGroup: 'rg-keyvault-prod'
    keyVaultSubscription: '12345678-1234-1234-1234-123456789012'
    clientID: 'confidential-oauth-client'
    clientSecret: 'confidential-client-secret'
    accessToken: 'current-access-token'
    refreshToken: 'refresh-token'
    expires: '2025-12-31T23:59:59Z'
    // Proxy settings
    proxyURI: 'http://corporate-proxy:8080'
    proxyCredential: {
      UserName: 'proxy-user'
      Password: 'proxy-password'
    }
    // Connection behavior
    handleRatelimiting: true
    webCallTimeoutSeconds: 300
    useWebSession: true
    bypassDefaultProxy: false
  }
}
```

## Outputs

The template provides these outputs:

```bicep
// Key Vault and authentication info
output keyVaultName string          // Target Key Vault name
output authenticationMethod string  // Detected authentication method ('Basic', 'OAuth', or 'OAuthToken')

// Secret names for reference
output secretNames object = {
  connectionSecret: string    // Main JSON connection secret name
}

// Created secrets summary (from keyvault-secrets module)
output secretsCreated object       // Details of secrets created by the module
```

## Integration with PSSnow.MidTools

The stored secrets are fully compatible with PSSnow.MidTools functions:

```powershell
# Retrieve and use stored credentials
$auth = Resolve-SNOWMIDEnvironmentAuth -SecretName 'snow-connection-dev-json' -VaultName 'snkv-dev-abc123'

# Use with Set-SNOWAuth
Set-SNOWAuth @auth

# Test connection
Get-SNOWCurrentUser
```

## Security Considerations

- All sensitive parameters are marked as `@secure()`
- Secrets are stored via the `modules/keyvault-secrets.bicep` module
- Cross-subscription Key Vault access supported via module deployment
- Authentication method is automatically detected to prevent configuration errors

## Dependencies

- Target Key Vault must exist and be accessible
- Deploying identity requires Key Vault Secrets Officer role
- `modules/keyvault-secrets.bicep` module handles the actual secret creation
- The module supports cross-resource group and cross-subscription deployments
