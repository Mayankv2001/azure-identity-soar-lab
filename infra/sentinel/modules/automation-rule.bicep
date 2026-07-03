// Illustrative, NON-DESTRUCTIVE automation rule.
//
// It only tags incidents (adds a label) so they can be routed/filtered. It does
// NOT disable users, revoke sessions, rotate credentials, change network rules,
// or run any destructive playbook. Destructive response in this project is
// always human-approved and is not automated here.

@description('Name of the existing Sentinel-enabled Log Analytics workspace.')
param workspaceName string

@description('Environment label used in the incident tag.')
param environmentName string = 'lab'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource tagIncidents 'Microsoft.SecurityInsights/automationRules@2023-11-01' = {
  scope: workspace
  name: guid(workspace.id, 'lab-tag-identity-incidents')
  properties: {
    displayName: '[LAB] Tag identity incidents for routing'
    order: 1
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: []
    }
    actions: [
      {
        order: 1
        actionType: 'ModifyProperties'
        actionConfiguration: {
          labels: [
            {
              labelName: 'identity-soar-${environmentName}'
            }
          ]
        }
      }
    ]
  }
}

output automationRuleId string = tagIncidents.id
