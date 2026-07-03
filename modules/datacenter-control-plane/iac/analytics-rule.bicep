// Illustrative only - not deployment-ready.
// One scheduled analytics rule (CP-DET-006, NSG opened to the internet) as a
// placeholder, showing how a control-plane detection maps onto a Microsoft
// Sentinel scheduled alert rule. The KQL is inline and abbreviated.

@description('Existing Sentinel workspace name')
param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource nsgPublicRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: workspace
  name: 'CP-DET-006-nsg-public-rule'
  kind: 'Scheduled'
  properties: {
    displayName: 'NSG or firewall rule opened to the internet'
    description: 'Inbound allow rule created with an internet-wide source prefix.'
    severity: 'High'
    enabled: true
    query: '''
AzureActivity
| where OperationNameValue == "Microsoft.Network/networkSecurityGroups/securityRules/write"
| where ActivityStatusValue == "Success"
| extend SourcePrefix = tostring(Properties.sourceAddressPrefix), Access = tostring(Properties.access)
| where Access == "Allow" and SourcePrefix in ("0.0.0.0/0", "*", "Internet")
'''
    queryFrequency: 'PT15M'
    queryPeriod: 'P1D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'DefenseEvasion'
    ]
    techniques: [
      'T1562'
    ]
  }
}
