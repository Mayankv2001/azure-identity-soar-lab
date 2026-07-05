# Future-proofed ingestion — DCE + DCR + Logs Ingestion API

The legacy Log Analytics **Data Collector API** (HTTP Data Collector) is on the
retirement path. V3 moves the lab's synthetic telemetry onto the supported modern
pipeline: a **Data Collection Endpoint (DCE)** + a **Data Collection Rule (DCR)**
+ a **DCR-based custom table**, ingested through the **Logs Ingestion API**.

Template: [dcr-logs-ingestion.bicep](dcr-logs-ingestion.bicep) (compiles clean;
lab-only, validate before real use).

## What it deploys

| Resource | Purpose |
|----------|---------|
| `Microsoft.OperationalInsights/workspaces/tables` | The `CyberArk_EPV_CL` custom table with an explicit schema |
| `Microsoft.Insights/dataCollectionEndpoints` | The ingestion front door (DCE) |
| `Microsoft.Insights/dataCollectionRules` | Stream declaration, transform (`transformKql`), destination |

## How a sender uses it (no secrets)

Callers authenticate with an **Entra ID token** (the identity holds the
*Monitoring Metrics Publisher* role on the DCR) - there is no shared key. Then
they POST rows to the DCE:

```
POST {dceLogsIngestionEndpoint}/dataCollectionRules/{dcrImmutableId}/streams/Custom-CyberArkEPV?api-version=2023-01-01
Authorization: Bearer <entra-id-token>
Content-Type: application/json

[ { "TimeGenerated": "...", "EventType": "PasswordCheckout", "Username": "...", ... } ]
```

The three values a sender needs (`dceLogsIngestionEndpoint`, `dcrImmutableId`,
`Custom-CyberArkEPV`) are template outputs.

## Why this matters

- **Supported path** - not the retiring Data Collector API.
- **Schema-on-write with transform** - `transformKql` can drop, rename, or enrich
  at ingestion, controlling both quality and cost per table.
- **Token-based, keyless** - no workspace shared key to leak; least-privilege
  publisher role instead.

## Honest scope

Lab-only and illustrative. It compiles offline (`az bicep build`) and models the
correct resource graph, but it is not deployed and the transform/schema would be
tuned per real source before use.
