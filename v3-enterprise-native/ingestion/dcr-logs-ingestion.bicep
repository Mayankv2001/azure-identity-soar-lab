// V3.0 | Future-proofed telemetry ingestion via the Logs Ingestion API (LAB).
//
// Azure is retiring the legacy Log Analytics Data Collector API (HTTP Data
// Collector). This template provisions the modern path: a Data Collection
// Endpoint (DCE) + a Data Collection Rule (DCR) + a DCR-based custom table, so
// the lab's synthetic CyberArk telemetry is ingested through the supported Logs
// Ingestion API instead. Illustrative / lab-only - validate before real use.
//
// Flow: sender POSTs JSON to the DCE logsIngestion endpoint, targeting the DCR's
// immutable id and the input stream. The DCR applies transformKql and lands rows
// in the custom table CyberArk_EPV_CL.
//
// Validate offline: az bicep build --file dcr-logs-ingestion.bicep

targetScope = 'resourceGroup'

@description('Azure region.')
param location string = resourceGroup().location

@description('Existing Log Analytics workspace name (the ingestion destination).')
param workspaceName string

@description('Data Collection Endpoint name.')
param dceName string = 'dce-identity-soar-lab'

@description('Data Collection Rule name.')
param dcrName string = 'dcr-cyberark-epv-lab'

@description('Custom table name (must end with _CL).')
param customTableName string = 'CyberArk_EPV_CL'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// DCR-based custom table. Schema mirrors the lab's synthetic CyberArk events.
resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: customTableName
  properties: {
    schema: {
      name: customTableName
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'EventType', type: 'string' }
        { name: 'Username', type: 'string' }
        { name: 'SafeName', type: 'string' }
        { name: 'AccountName', type: 'string' }
        { name: 'TargetSystem', type: 'string' }
        { name: 'SourceIP', type: 'string' }
        { name: 'TicketId', type: 'string' }
        { name: 'Reason', type: 'string' }
      ]
    }
    retentionInDays: 30
    totalRetentionInDays: 30
  }
}

// Data Collection Endpoint - the ingestion front door.
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dceName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
    description: 'Lab DCE for Logs Ingestion API (synthetic CyberArk telemetry).'
  }
}

// Data Collection Rule - stream declaration, destination, and transform.
resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-CyberArkEPV': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'EventType', type: 'string' }
          { name: 'Username', type: 'string' }
          { name: 'SafeName', type: 'string' }
          { name: 'AccountName', type: 'string' }
          { name: 'TargetSystem', type: 'string' }
          { name: 'SourceIP', type: 'string' }
          { name: 'TicketId', type: 'string' }
          { name: 'Reason', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'laDestination'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-CyberArkEPV'
        ]
        destinations: [
          'laDestination'
        ]
        // Pass-through transform; refine per tenant (drop/rename/enrich here).
        transformKql: 'source'
        outputStream: 'Custom-${customTableName}'
      }
    ]
  }
  dependsOn: [
    customTable
  ]
}

// The immutable id and endpoint a sender needs (no secrets - callers use Entra ID
// tokens with the Monitoring Metrics Publisher role on the DCR).
output dceLogsIngestionEndpoint string = dce.properties.logsIngestion.endpoint
output dcrImmutableId string = dcr.properties.immutableId
output inputStreamName string = 'Custom-CyberArkEPV'
output customTable string = customTableName
