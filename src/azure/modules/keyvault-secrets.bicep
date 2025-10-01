@description('Key Vault Name')
param keyVaultName string

@description('Authentication method to use for ServiceNow')
@allowed(['Basic', 'OAuth', 'OAuthToken'])
param authenticationMethod string

@description('ServiceNow Instance name (e.g., dev123456)')
param instance string

@description('ServiceNow Basic Authentication Credentials')
@secure()
param credential object = {}

@description('ServiceNow OAuth Client ID')
param clientID string = ''

@description('ServiceNow OAuth Client Secret')
@secure()
param clientSecret string = ''

@description('ServiceNow OAuth Access Token')
@secure()
param accessToken string = ''

@description('ServiceNow OAuth Refresh Token')
@secure()
param refreshToken string = ''

@description('OAuth Token Expiration Date/Time (ISO 8601 format)')
param expires string = ''

@description('Proxy URI for ServiceNow connections')
param proxyURI string = ''

@description('Proxy Authentication Credentials')
@secure()
param proxyCredential object = {}

@description('Handle rate limiting by waiting for limits to refresh')
param handleRatelimiting bool

@description('Web call timeout in seconds')
param webCallTimeoutSeconds int?

@description('Bypass default proxy settings')
param bypassDefaultProxy bool?

@description('Use web session for cookie and token storage')
param useWebSession bool?

@description('Name of the secret to store the full connection JSON object')
param snowConnectionSecretName string

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

// Build the connection object securely within the module

// Build the connection object with conditional spreads to omit null/empty values
var connectionObject = {
  Instance: instance
  ...(handleRatelimiting != null ? { HandleRatelimiting: handleRatelimiting } : {})
  ...(webCallTimeoutSeconds != null ? { WebCallTimeoutSeconds: webCallTimeoutSeconds } : {})
  ...(bypassDefaultProxy != null ? { BypassDefaultProxy: bypassDefaultProxy } : {})
  ...(useWebSession != null ? { UseWebSession: useWebSession } : {})
  ...(!empty(proxyURI) ? { ProxyURI: proxyURI } : {})
  ...(!empty(proxyCredential) && contains(proxyCredential, 'UserName') && contains(proxyCredential, 'Password') ? { ProxyCredential: proxyCredential } : {})
  ...(authenticationMethod == 'Basic' && !empty(credential) && contains(credential, 'UserName') && contains(credential, 'Password') ? { Credential: credential } : {})
  ...(authenticationMethod == 'OAuth' ? {
    ClientID: clientID
    ...(!empty(clientSecret) ? { ClientSecret: clientSecret } : {})
    ...(!empty(credential) && contains(credential, 'UserName') && contains(credential, 'Password') ? { Credential: credential } : {})
  } : {})
  ...(authenticationMethod == 'OAuthToken' ? {
    ClientID: clientID
    ...(!empty(clientSecret) ? { ClientSecret: clientSecret } : {})
    ...(!empty(accessToken) ? { AccessToken: accessToken } : {})
    ...(!empty(refreshToken) ? { RefreshToken: refreshToken } : {})
    ...(!empty(expires) ? { Expires: expires } : {})
  } : {})
}

// Create the main connection secret as JSON (replicating Set-JsonSecret functionality)
resource snowConnectionSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: snowConnectionSecretName
  properties: {
    value: string(connectionObject)
    contentType: 'application/json'
    attributes: {
      enabled: true
    }
  }
}

output secretsCreated object = {
  connectionSecret: snowConnectionSecret.name
  authenticationMethod: authenticationMethod
}
