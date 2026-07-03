// Onboards Microsoft Sentinel onto an existing Log Analytics workspace.
// The onboarding state is an extension resource scoped to the workspace and is
// named 'default'. Enabling Sentinel is what activates SecurityInsights on the
// workspace; there is no separate cost for onboarding itself (analytics data
// ingestion is billed through the workspace).

@description('Name of the existing Log Analytics workspace to onboard.')
param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource onboarding 'Microsoft.SecurityInsights/onboardingStates@2023-11-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

output onboardingId string = onboarding.id
