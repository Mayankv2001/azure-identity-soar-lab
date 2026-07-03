// Log Analytics workspace for the identity SOAR lab.
// Lab-only: low retention default, immediate purge enabled to control cost.
// Requires tenant-specific review before any non-lab use.

@description('Azure region for the workspace.')
param location string

@description('Log Analytics workspace name (must be globally-unique within the subscription/region scope).')
param workspaceName string

@description('Data retention in days. Lab-safe low default to limit cost.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 30

@description('Resource tags.')
param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    features: {
      // Allow data to be purged sooner than 30 days if needed - lab cost control.
      immediatePurgeDataOn30Days: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

output workspaceId string = workspace.id
output workspaceName string = workspace.name
output workspaceResourceGroup string = resourceGroup().name
