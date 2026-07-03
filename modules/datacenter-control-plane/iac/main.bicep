// Illustrative only - not deployment-ready.
// Log Analytics workspace + Microsoft Sentinel onboarding for the control-plane
// module's Mode B. Placeholder values; review before any real use.

@description('Deployment location')
param location string = resourceGroup().location

@description('Log Analytics / Sentinel workspace name')
param workspaceName string = 'law-dc-controlplane'

@description('Data retention in days')
param retentionInDays int = 90

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
  }
}

// Onboard Microsoft Sentinel onto the workspace.
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2023-11-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

output workspaceId string = workspace.id
output workspaceResourceName string = workspace.name
