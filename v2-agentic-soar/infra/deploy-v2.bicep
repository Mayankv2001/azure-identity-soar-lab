// V2.0 detection-as-code deployment (LAB / illustrative).
//
// Deploys the CI/CD credential-bridging analytics rule (DET-CICD-001) to an
// existing Sentinel-enabled Log Analytics workspace, plus the watchlist the rule
// depends on. Rules ship DISABLED by default (enableRules=false) - enabling is a
// deliberate, approved change after tenant-specific validation.
//
// The Security Copilot custom agent and the MCP server are not Azure resources
// deployed here; they are registered in the Security Copilot / Foundry control
// plane. This template covers the analytics-rule side of detection-as-code, which
// is what a Bicep deployment owns. Validate with `az bicep build` (the CI does).

targetScope = 'resourceGroup'

@description('Existing Sentinel-enabled Log Analytics workspace name.')
param workspaceName string

@description('Enable the deployed rules. Default false - review and tune before enabling.')
param enableRules bool = false

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Watchlist the CI/CD rule joins against (approved repo:subject -> service principal).
resource approvedFederation 'Microsoft.SecurityInsights/watchlists@2023-11-01' = {
  scope: workspace
  name: 'ApprovedFederatedIdentities'
  properties: {
    displayName: 'ApprovedFederatedIdentities'
    provider: 'azure-identity-soar-lab'
    source: 'Local file'
    itemsSearchKey: 'Subject'
    description: 'Approved GitHub OIDC federated identities (repo:subject -> service principal). Lab placeholder - populate per tenant.'
    contentType: 'text/csv'
    rawContent: 'Subject,ServicePrincipalId\nrepo:contoso/app:ref:refs/heads/main,00000000-0000-0000-0000-000000000000\n'
  }
}

var cicdRuleId = guid(workspace.id, 'DET-CICD-001-credential-bridging')

resource cicdRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: workspace
  name: cicdRuleId
  kind: 'Scheduled'
  properties: {
    displayName: '[LAB] DET-CICD-001 Workload-identity credential bridging'
    description: 'GitHub OIDC federated service principal that extracts Key Vault secrets or escalates privilege within a short bridge window. Ships disabled; requires tenant validation.'
    severity: 'High'
    enabled: enableRules
    query: loadTextContent('../detections/DET-CICD-001-workload-identity-credential-bridging.kql')
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'PrivilegeEscalation'
      'LateralMovement'
    ]
    techniques: [
      'T1552'
      'T1550'
      'T1098'
    ]
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'ServicePrincipalName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddress'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
  }
  dependsOn: [
    approvedFederation
  ]
}

output cicdRuleResourceId string = cicdRule.id
output rulesEnabled bool = enableRules
output watchlistName string = approvedFederation.name
