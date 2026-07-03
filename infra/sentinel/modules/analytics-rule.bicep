// Sample scheduled analytics rule for the lab: DET-001 MFA Fatigue (Push Bombing).
//
// LAB-SAFE DESIGN CHOICES:
// - disabled by default (enableRule=false) so it cannot raise alerts in a real
//   tenant until it has been reviewed and tuned;
// - displayName is prefixed [LAB] so it is obviously test-scoped;
// - the KQL is a lab template. Column names (SigninLogs.ResultType 500121 for
//   failed strong-auth, UserPrincipalName, IPAddress) follow the documented
//   Microsoft schema, but thresholds and grouping REQUIRE tenant-specific
//   validation - a real MFA-fatigue rule should baseline per-user prompt volume.
//
// The rule is scoped to the workspace as an extension resource.

@description('Name of the existing Sentinel-enabled Log Analytics workspace.')
param workspaceName string

@description('Environment label (e.g. lab) used only in metadata/labels.')
param environmentName string = 'lab'

@description('Whether the rule is enabled. Default false - review and tune before enabling.')
param enableRule bool = false

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Deterministic rule id derived from the workspace so redeploys are idempotent.
var ruleId = guid(workspace.id, 'DET-001-mfa-fatigue')

resource mfaFatigueRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: workspace
  name: ruleId
  kind: 'Scheduled'
  properties: {
    displayName: '[LAB] DET-001 MFA Fatigue (Push Bombing)'
    description: 'LAB template. Detects five or more failed strong-authentication events (ResultType 500121) for a single user within a ten-minute window - a possible MFA fatigue / push-bombing attempt. Requires tenant-specific tuning before enabling.'
    severity: 'High'
    enabled: enableRule
    query: '''
SigninLogs
| where ResultType == 500121   // Authentication failed during strong authentication request
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| project TimeGenerated, UserPrincipalName, IPAddress, FailedAttempts
'''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1621'
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'UserPrincipalName'
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
}

output ruleId string = mfaFatigueRule.id
output ruleName string = mfaFatigueRule.properties.displayName
output ruleEnabled bool = enableRule
output environmentLabel string = environmentName
