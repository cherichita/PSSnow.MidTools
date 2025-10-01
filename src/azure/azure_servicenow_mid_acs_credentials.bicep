@description('ServiceNow Instance name (e.g., dev123456)')
param instance string

@description('Name of the secret to store the full connection JSON object')
param snowConnectionSecretName string

@description('Key Vault Name')
@maxLength(24)
param keyVaultName string

@description('Key Vault Resource Group')
param keyVaultResourceGroup string = resourceGroup().name

@description('Key Vault Subscription')
param keyVaultSubscription string = subscription().subscriptionId

// ServiceNow Credentials - Basic Auth (PSCredential equivalent)
@description('ServiceNow Basic Authentication Credentials')
@secure()
param credential object = {}

// OAuth Parameters
@description('ServiceNow OAuth Client ID')
param clientID string = ''

@description('ServiceNow OAuth Client Secret')
@secure()
param clientSecret string = ''

// OAuth Token Parameters
@description('ServiceNow OAuth Access Token')
@secure()
param accessToken string = ''

@description('ServiceNow OAuth Refresh Token')
@secure()
param refreshToken string = ''

@description('OAuth Token Expiration Date/Time (ISO 8601 format)')
param expires string = ''

// Optional Connection Parameters
@description('Proxy URI for ServiceNow connections')
param proxyURI string = ''

@description('Proxy Authentication Credentials')
@secure()
param proxyCredential object = {}

@description('Handle rate limiting by waiting for limits to refresh')
param handleRatelimiting bool = false

@description('Web call timeout in seconds')
param webCallTimeoutSeconds int?

@description('Bypass default proxy settings')
param bypassDefaultProxy bool?

@description('Use web session for cookie and token storage')
param useWebSession bool?

// Derived authentication method based on provided parameters
var hasCredential = !empty(credential) && contains(credential, 'UserName') && contains(credential, 'Password')
var hasOAuthToken = !empty(accessToken) && !empty(refreshToken)
var hasOAuthClient = !empty(clientID) && !empty(clientSecret)

var authenticationMethod = hasOAuthToken ? 'OAuthToken' : (hasOAuthClient ? 'OAuth' : (hasCredential ? 'Basic' : 'Basic'))

var snowInstance = toLower(replace(replace(instance, 'https://', ''), 'http://', ''))

// Use module to deploy secrets to the correct scope
module keyVaultSecrets 'modules/keyvault-secrets.bicep' = {
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  name: 'snowCredentials-${snowInstance}'
  params: {
    keyVaultName: keyVaultName
    authenticationMethod: authenticationMethod
    instance: instance
    credential: credential
    clientID: clientID
    clientSecret: clientSecret
    accessToken: accessToken
    refreshToken: refreshToken
    expires: expires
    proxyURI: proxyURI
    proxyCredential: proxyCredential
    handleRatelimiting: handleRatelimiting
    webCallTimeoutSeconds: webCallTimeoutSeconds
    bypassDefaultProxy: bypassDefaultProxy
    useWebSession: useWebSession
    snowConnectionSecretName: snowConnectionSecretName
  }
}

output keyVaultName string = keyVaultName
output authenticationMethod string = authenticationMethod
output secretNames object = {
  connectionSecret: snowConnectionSecretName
}
output secretsCreated object = keyVaultSecrets.outputs.secretsCreated

