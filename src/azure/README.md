# Azure ServiceNow MID Server Container Infrastructure

This repository contains Azure Bicep templates for deploying the infrastructure required to run ServiceNow MID Servers in containers on Azure Container Services (ACS). The templates create a complete, secure, and scalable environment for ServiceNow MID Server operations.

## Overview

The `azure_servicenow_mid_acs_base.bicep` template deploys a comprehensive infrastructure foundation that includes identity management, secure storage, networking controls, and container services integration. This base template is designed to support multiple MID Server deployments within the same environment.

## Infrastructure Components

| Resource Type | Resource Name Pattern | Purpose | Key Features |
|---------------|----------------------|---------|--------------|
| **User Assigned Identity** | `snow-devops-{env}-{uniqueId}` | DevOps automation identity | Owner permissions on resource group for self-management |
| **User Assigned Identity** | `snow-midserver-{env}-{uniqueId}` | MID Server runtime identity | Scoped permissions for container and storage access |
| **Storage Account** | `snst{env}{uniqueId}` | MID Server state and logging | Network-restricted access, table services enabled |
| **Storage Table** | `ServiceNowMidServers` | MID Server registration tracking | Stores MID Server instance metadata |
| **Storage Table** | `config` | Environment configuration | Stores deployment and runtime configuration |
| **Key Vault** | `snkv-{env}-{uniqueId}` | Secrets management | ServiceNow credentials, connection strings |
| **Role Assignments** | Various | Access control | Fine-grained permissions for identities |
| **Network Access Rules** | Applied to storage | Security controls | Subnet-based access restrictions |

## Key Features

### Security

- **Network Isolation**: Storage account access restricted to specified subnets
- **Identity-Based Access**: User-assigned managed identities for secure resource access
- **Secret Management**: Centralized credential storage in Azure Key Vault
- **Role-Based Access Control**: Granular permissions for different service components

### Scalability

- **Environment Tagging**: Consistent resource tagging for multi-environment support
- **Flexible Networking**: Support for multiple subnet configurations
- **Modular Design**: Separate modules for different infrastructure concerns

### Management

- **Infrastructure as Code**: Complete environment definition in Bicep templates
- **Validation Scripts**: Optional deployment validation using PSSnow.MidTools
- **Automated Permissions**: Optional automatic role assignment deployment

## Parameters

### Core Configuration

- `devopsEnvironmentName`: Environment identifier (max 5 characters, default: 'dev')
- `location`: Azure region for resource deployment
- `deployPermissions`: Enable automatic permission assignment (default: true)
- `runValidationScript`: Run post-deployment validation (default: false)

### ServiceNow Integration

- `snowCredentials`: ServiceNow credentials object (secure)
  - `snowHost`: ServiceNow instance URL
  - `snowUsername`: ServiceNow API username
  - `snowPassword`: ServiceNow API password (secure parameter)

#### ServiceNow Credentials

This deployment supports multiple authentication methods for ServiceNow (Basic, OAuth, OAuthToken). The required parameters and object structure for ServiceNow credentials are documented in detail in [azure_servicenow_mid_acs_credentials.md](./azure_servicenow_mid_acs_credentials.md).

See that file for:

- Supported authentication methods and required parameters
- Example Bicep usage for each method
- Security and Key Vault integration details

### Network Configuration

- `containerSubnetId`: Subnet for container instances (required)
- `additionalStorageSubnetIds`: Additional subnets for storage access
- `virtualNetworkRoleId`: Role ID for virtual network permissions

### Container Registry

- `containerRegistryName`: Azure Container Registry name
- `containerRegistrySubscription`: ACR subscription ID
- `containerRegistryResourceGroup`: ACR resource group name

### Access Control

- `adminEntraEntities`: Additional Entra ID objects for Key Vault access
- `additionalResourceGroupRoleAssignments`: Custom role assignments

## Outputs

The template provides comprehensive outputs for integration with other templates:

- `resourceGroupId`: Current resource group identifier
- `containerRegistry`: Container registry details and configuration
- `keyVault`: Key Vault configuration and access information
- `storageAccount`: Storage account details and connection information
- `userAssignedIdentity`: DevOps identity configuration
- `midServerIdentity`: MID Server runtime identity configuration

## Dependencies

### Required Resources

- Azure Container Registry (existing or created separately)
- Virtual Network with appropriate subnets
- Azure subscription with appropriate permissions

### Module Dependencies

- `modules/keyvault.bicep`: Key Vault creation and configuration
- `modules/vault-accesspolicies.bicep`: Key Vault access policy management
- `modules/container-registry.bicep`: Container registry configuration
- `azure_servicenow_mid_acs_permissions.bicep`: Permission assignments
- `modules/servicenow.midtools.deploymentscript.bicep`: Validation scripts
- `modules/append-resoure-group-tags.bicep`: Resource group tagging

## Deployment Notes

1. **Permissions Required**: The deploying identity needs Owner permissions on the target resource group
2. **Network Prerequisites**: Ensure container subnets have access to ServiceNow instance, ACR, and ARM services
3. **Naming Constraints**: Environment names are limited to 5 characters to accommodate Azure naming limits
4. **Security Consideration**: All secrets are stored in Key Vault and referenced securely

