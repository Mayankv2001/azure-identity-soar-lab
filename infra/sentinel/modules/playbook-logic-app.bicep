// Illustrative Logic App playbook skeleton.
//
// LAB-SAFE DESIGN CHOICES:
// - state: 'Disabled' (off by default) - it will not run until explicitly enabled;
// - NO API connections, NO secrets, NO managed-identity credentials;
// - NO destructive action: it only composes a notification string and returns it.
//   It does NOT disable users, rotate credentials, or change firewall/NSG rules.
//
// A real Sentinel playbook would use the 'azuresentinel' connector trigger
// ("When a Microsoft Sentinel incident creation rule was triggered") and a
// Teams/Outlook action. Those require API connections that carry auth, so they
// are intentionally left out of the repo - documented in
// docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md instead.

@description('Azure region for the Logic App.')
param location string

@description('Logic App (playbook) name.')
param logicAppName string = 'la-identity-soar-lab-${uniqueString(resourceGroup().id)}'

@description('Resource tags.')
param tags object = {}

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  tags: tags
  properties: {
    // Off by default. Enable manually in the portal only after review.
    state: 'Disabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {
        manual: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {
              type: 'object'
              properties: {
                incidentTitle: {
                  type: 'string'
                }
                severity: {
                  type: 'string'
                }
              }
            }
          }
        }
      }
      actions: {
        Compose_notification: {
          type: 'Compose'
          inputs: 'LAB placeholder: a non-destructive incident notification would be composed and posted to a chat/ticket channel here. No secrets, no account changes, no network changes.'
        }
        Response: {
          type: 'Response'
          kind: 'Http'
          runAfter: {
            Compose_notification: [
              'Succeeded'
            ]
          }
          inputs: {
            statusCode: 200
            body: '@outputs(\'Compose_notification\')'
          }
        }
      }
      outputs: {}
    }
  }
}

output playbookId string = playbook.id
output playbookName string = playbook.name
output playbookState string = playbook.properties.state
