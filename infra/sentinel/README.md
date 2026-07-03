# infra/sentinel - Mode C: Live Sentinel Deployment (LAB ONLY)

Bicep infrastructure that provisions a **lab** Microsoft Sentinel workspace and a
sample detection-as-code path. This is **not** production infrastructure and is
intended for a **personal/test Azure subscription only**.

Full walkthrough: [docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md](../../docs/LIVE_SENTINEL_DEPLOYMENT_PATH.md).

## Files

| File | What it deploys |
|------|-----------------|
| `main.bicep` | Orchestrates the whole lab deployment (resource-group scope) |
| `modules/log-analytics-workspace.bicep` | Log Analytics workspace (30-day retention default) |
| `modules/sentinel-onboarding.bicep` | Enables Microsoft Sentinel on the workspace |
| `modules/analytics-rule.bicep` | Sample scheduled rule (DET-001), **disabled by default** |
| `modules/automation-rule.bicep` | Non-destructive tagging automation rule (optional, off by default) |
| `modules/playbook-logic-app.bicep` | Disabled Logic App skeleton (optional, off by default) |
| `parameters.example.json` | Placeholder parameters - copy, fill in, never commit real values |

## Parameters (main.bicep)

| Parameter | Default | Notes |
|-----------|---------|-------|
| `location` | resource group location | Azure region |
| `workspaceName` | (required) | Log Analytics / Sentinel workspace name |
| `environmentName` | `lab` | Kept as "lab" so resources are obviously test-scoped |
| `retentionInDays` | `30` | Low default to control cost |
| `deployAnalyticsRules` | `true` | Deploy the sample rule |
| `enableAnalyticsRule` | `false` | Rule ships **disabled** - review/tune before enabling |
| `deployAutomationRules` | `false` | Non-destructive tagging rule |
| `deployPlaybook` | `false` | Logic App skeleton (deployed disabled) |
| `tags` | lab tags | Applied to all resources |

## Safety design

- The analytics rule is **disabled by default** and prefixed `[LAB]` - it cannot
  raise alerts in a real tenant until you deliberately enable it.
- The automation rule only **adds a label** to incidents. It performs no account
  disablement, credential rotation, or network changes.
- The Logic App playbook is deployed with `state: 'Disabled'`, has **no API
  connections and no secrets**, and only composes a placeholder notification.
- No subscription IDs, tenant IDs, client secrets, or tokens appear in any file.

## Validate before deploying

```bash
export RESOURCE_GROUP="rg-sentinel-identity-lab"
export LOCATION="australiaeast"
bash ../../scripts/sentinel/validate_sentinel_templates.sh
```

`az deployment group validate` checks the template against Azure without creating
billable resources. The KQL and rule thresholds are **lab templates** and require
tenant-specific validation before they should be enabled.
