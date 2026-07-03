# Mode C: Live Microsoft Sentinel Deployment path (LAB ONLY)

> **Lab deployment only.** This optional mode provisions a lab Microsoft Sentinel
> workspace and a sample analytics-rule path in a **personal/test Azure
> subscription**. It is **not** a production deployment, and nothing here should
> be pointed at an employer/work tenant.

Offline mode remains the default and primary way to review and test this
project. This document describes the optional live path.

## 1. Purpose

To show, honestly, how the lab's KQL detections could be promoted into a real
Microsoft Sentinel workspace through infrastructure-as-code. It deploys a lab
workspace, enables Sentinel, and creates a **disabled** sample analytics rule.
It is a demonstration of the *promotion path*, not a production-ready detection
deployment.

## 2. What gets deployed

- A resource group (you name it)
- A Log Analytics workspace (30-day retention default, cost-controlled)
- Microsoft Sentinel onboarding on that workspace
- One sample scheduled analytics rule - **DET-001 MFA Fatigue**, **disabled by
  default**, prefixed `[LAB]`
- (optional) a non-destructive automation rule that only **tags** incidents
- (optional) a Logic App playbook **skeleton**, deployed **disabled**, with no
  connectors and no secrets

## 3. What does NOT get deployed

- No data-connector secrets, no API connection credentials
- No destructive playbooks (no user disablement, no session revocation, no
  credential rotation, no firewall/NSG changes)
- No employer data, no production tenant configuration
- No real subscription IDs, tenant IDs, client secrets, or tokens (none appear
  anywhere in this repository)

## 4. Prerequisites

- Azure CLI (`az`) with Bicep support (`az bicep version`)
- A **personal/test** Azure subscription (never a work tenant)
- Permission to create a resource group and the resources above
- Cost awareness: Log Analytics ingestion and Sentinel analytics are billable

## 5. Step-by-step deployment

```bash
cd "/Users/mayank/Microsoft sentinel project/azure-identity-soar-lab"

# Log in with your PERSONAL / TEST account
az login
az account show
az account set --subscription "<your personal subscription>"

# Set variables (edit these)
export RESOURCE_GROUP="rg-sentinel-identity-lab"
export LOCATION="australiaeast"
export WORKSPACE_NAME="law-identity-soar-lab-$RANDOM"
export I_UNDERSTAND_THIS_CREATES_AZURE_RESOURCES=yes

# Validate first (no resources created)
bash scripts/sentinel/validate_sentinel_templates.sh

# Deploy (prompts for confirmation, shows the active subscription)
bash scripts/sentinel/deploy_sentinel_lab.sh
```

The deploy script refuses to run unless `I_UNDERSTAND_THIS_CREATES_AZURE_RESOURCES=yes`
is set, prints the active subscription/tenant, and asks you to confirm it is your
personal/test subscription before creating anything.

## 6. Validation (after deploy)

In the Azure Portal:

- **Resource groups** > your resource group > confirm the workspace exists
- **Microsoft Sentinel** > select the workspace
- **Analytics** > confirm `[LAB] DET-001 MFA Fatigue (Push Bombing)` exists and
  is **Disabled** (unless you deployed with `ENABLE_ANALYTICS_RULE=true`)
- **Log Analytics workspace** > Usage and estimated costs > watch ingestion

Read-only CLI checks are documented in
`scripts/sentinel/test_sentinel_deployment.sh.example`.

## 7. Testing detections

- The **offline Python demo remains the primary deterministic test** -
  `python3 src/main.py --demo` and the pytest suite.
- Live Sentinel testing requires real logs or **controlled, authorised**
  synthetic ingestion into the workspace.
- **Do not test with real attacks. Do not generate malicious activity.** Never
  run attack tooling against any account or tenant. The point of the lab is safe,
  synthetic demonstration.

## 8. Cost controls

- Use a personal/test subscription
- Keep `retentionInDays` low (30)
- Keep the analytics rule **disabled** unless you are actively testing
- **Delete the resource group** when finished
- Monitor cost in the portal

## 9. Security controls

- No secrets in the repo (verified by a test)
- Personal/test subscription only - never an employer tenant
- Review RBAC on the resource group before granting access
- Keep rules disabled until reviewed and tuned
- The Logic App skeleton is disabled and has no credentials

## 10. Rollback / cleanup

```bash
az group delete --name "$RESOURCE_GROUP" --yes --no-wait
```

Deleting the resource group removes the workspace, Sentinel, and all rules. Note
that Log Analytics workspaces have a soft-delete window. See
`scripts/sentinel/destroy_sentinel_lab.sh.example`.

## 11. How to describe this honestly

> "The repo is offline-first by design, so it can be reviewed safely without a
> tenant. I added an optional live Sentinel deployment path using Bicep and Azure
> CLI that can provision a lab Log Analytics workspace, enable Sentinel and deploy
> sample analytics rules. I would not call it production-ready until the rules are
> tuned against real telemetry, reviewed for cost, and approved through normal
> change control."
