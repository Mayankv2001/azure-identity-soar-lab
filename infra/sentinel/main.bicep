// ============================================================================
// Mode C: Live Microsoft Sentinel Deployment - main orchestration (LAB ONLY)
// ============================================================================
//
// Deploys a lab Sentinel workspace and sample detection-as-code artefacts:
//   1. Log Analytics workspace (low retention, cost-controlled)
//   2. Microsoft Sentinel onboarding
//   3. Sample scheduled analytics rule (DET-001, DISABLED by default)
//   4. Optional non-destructive automation rule (off by default)
//   5. Optional disabled Logic App playbook skeleton (off by default)
//
// This is NOT a production deployment. It is intended for a personal/test Azure
// subscription only. Review, tune, and cost-check before any real use. No real
// tenant IDs, subscription IDs, or secrets appear in this repository.
//
// Validate before deploying:
//   az deployment group validate --resource-group <rg> --template-file main.bicep \
//     --parameters workspaceName=<name> location=<region>

targetScope = 'resourceGroup'

@description('Azure region for all lab resources.')
param location string = resourceGroup().location

@description('Log Analytics / Sentinel workspace name.')
param workspaceName string

@description('Environment label. Kept as "lab" so resources are obviously test-scoped.')
param environmentName string = 'lab'

@description('Data retention (days) for the workspace. Lab-safe low default.')
@minValue(30)
@maxValue(730)
param retentionInDays int = 30

@description('Deploy the sample analytics rule(s).')
param deployAnalyticsRules bool = true

@description('Enable the analytics rule on deploy. Default false - review/tune first.')
param enableAnalyticsRule bool = false

@description('Deploy the illustrative (non-destructive) automation rule.')
param deployAutomationRules bool = false

@description('Deploy the disabled Logic App playbook skeleton.')
param deployPlaybook bool = false

@description('Resource tags applied to all resources.')
param tags object = {
  project: 'azure-identity-soar-lab'
  mode: 'lab-only'
  environment: 'lab'
}

// --- 1. Log Analytics workspace ---------------------------------------------
module workspace 'modules/log-analytics-workspace.bicep' = {
  name: 'deploy-log-analytics'
  params: {
    location: location
    workspaceName: workspaceName
    retentionInDays: retentionInDays
    tags: tags
  }
}

// --- 2. Microsoft Sentinel onboarding ---------------------------------------
module sentinel 'modules/sentinel-onboarding.bicep' = {
  name: 'deploy-sentinel-onboarding'
  params: {
    workspaceName: workspaceName
  }
  dependsOn: [
    workspace
  ]
}

// --- 3. Sample analytics rule (disabled by default) -------------------------
module analyticsRule 'modules/analytics-rule.bicep' = if (deployAnalyticsRules) {
  name: 'deploy-analytics-rule-det001'
  params: {
    workspaceName: workspaceName
    environmentName: environmentName
    enableRule: enableAnalyticsRule
  }
  dependsOn: [
    sentinel
  ]
}

// --- 4. Optional automation rule (non-destructive) --------------------------
module automationRule 'modules/automation-rule.bicep' = if (deployAutomationRules) {
  name: 'deploy-automation-rule'
  params: {
    workspaceName: workspaceName
    environmentName: environmentName
  }
  dependsOn: [
    sentinel
  ]
}

// --- 5. Optional Logic App playbook skeleton (disabled) ---------------------
module playbook 'modules/playbook-logic-app.bicep' = if (deployPlaybook) {
  name: 'deploy-playbook-skeleton'
  params: {
    location: location
    tags: tags
  }
  dependsOn: [
    sentinel
  ]
}

// --- Outputs ----------------------------------------------------------------
output workspaceName string = workspace.outputs.workspaceName
output workspaceId string = workspace.outputs.workspaceId
output resourceGroupName string = resourceGroup().name
output sentinelOnboarded bool = true
output analyticsRuleDeployed bool = deployAnalyticsRules
output analyticsRuleEnabled bool = deployAnalyticsRules ? enableAnalyticsRule : false
output automationRuleDeployed bool = deployAutomationRules
output playbookDeployed bool = deployPlaybook
