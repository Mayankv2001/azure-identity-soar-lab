// Illustrative only - not deployment-ready.
// NSG rule concept: the approved internal-only management access pattern that
// the deny-public-management-exposure policy leaves untouched. Management
// access comes from the corporate/bastion range, never the internet.

@description('Deployment location')
param location string = resourceGroup().location

@description('NSG name')
param nsgName string = 'nsg-prod-dc-mgmt'

@description('Approved internal management source range (corporate / bastion)')
param managementSourcePrefix string = '10.10.0.0/24'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-rdp-from-bastion-only'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: managementSourcePrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
      {
        name: 'deny-all-inbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

output nsgId string = nsg.id
