#!/usr/bin/env bash
# ============================================================================
# Deploy the LAB-ONLY Microsoft Sentinel environment.
# ============================================================================
#
# !!  COST WARNING  !!
# This script CREATES real Azure resources (a Log Analytics workspace and
# Sentinel). Log Analytics ingestion and Sentinel analytics are BILLABLE. Use a
# personal/test subscription only, keep retention low, and DELETE the resource
# group when you are finished (see destroy_sentinel_lab.sh.example).
#
# !!  DO NOT run this against an employer / work tenant.  !!
#
# Required environment variables:
#   I_UNDERSTAND_THIS_CREATES_AZURE_RESOURCES=yes
#   RESOURCE_GROUP    e.g. rg-sentinel-identity-lab
#   LOCATION          e.g. australiaeast
#   WORKSPACE_NAME    e.g. law-identity-soar-lab-12345
#
# Optional:
#   ENABLE_ANALYTICS_RULE=true   (default false - rule ships disabled for safety)
#   DEPLOY_AUTOMATION_RULE=true  (default false)
#   DEPLOY_PLAYBOOK=true         (default false; playbook is disabled even if deployed)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../../infra/sentinel/main.bicep"

# --- Guard rails ------------------------------------------------------------
command -v az >/dev/null 2>&1 || { echo "ERROR: Azure CLI (az) is required."; exit 1; }
az account show >/dev/null 2>&1 || { echo "ERROR: Not logged in. Run: az login (personal/test account)."; exit 1; }

if [[ "${I_UNDERSTAND_THIS_CREATES_AZURE_RESOURCES:-no}" != "yes" ]]; then
  echo "ERROR: Refusing to run. Set I_UNDERSTAND_THIS_CREATES_AZURE_RESOURCES=yes to acknowledge cost."
  exit 1
fi

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP}"
: "${LOCATION:?Set LOCATION}"
: "${WORKSPACE_NAME:?Set WORKSPACE_NAME}"

ENABLE_ANALYTICS_RULE="${ENABLE_ANALYTICS_RULE:-false}"
DEPLOY_AUTOMATION_RULE="${DEPLOY_AUTOMATION_RULE:-false}"
DEPLOY_PLAYBOOK="${DEPLOY_PLAYBOOK:-false}"

# --- Show context and confirm ----------------------------------------------
echo "=============================================================="
echo "  LAB SENTINEL DEPLOYMENT  (creates billable Azure resources)"
echo "=============================================================="
echo "Active Azure context:"
az account show --query "{subscription:name, subscriptionId:id, tenantId:tenantId, user:user.name, cloud:environmentName}" -o table
echo
echo "Resource group:  ${RESOURCE_GROUP}"
echo "Location:        ${LOCATION}"
echo "Workspace:       ${WORKSPACE_NAME}"
echo "Analytics rule:  deploy=true enabled=${ENABLE_ANALYTICS_RULE}"
echo "Automation rule: deploy=${DEPLOY_AUTOMATION_RULE}"
echo "Playbook:        deploy=${DEPLOY_PLAYBOOK} (disabled even if deployed)"
echo
echo "This will CREATE resources and may INCUR COST."
echo "Confirm the subscription above is your PERSONAL / TEST subscription (not employer/work)."
read -r -p "Type 'yes' to proceed: " CONFIRM
if [[ "${CONFIRM}" != "yes" ]]; then
  echo "Aborted. No resources created."
  exit 0
fi

# --- Create RG, validate, then deploy --------------------------------------
echo "== Creating resource group (if missing) =="
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" -o none

echo "== Validating template (no resources created yet) =="
az deployment group validate \
  --resource-group "${RESOURCE_GROUP}" \
  --template-file "${TEMPLATE}" \
  --parameters \
      workspaceName="${WORKSPACE_NAME}" \
      location="${LOCATION}" \
      enableAnalyticsRule="${ENABLE_ANALYTICS_RULE}" \
      deployAutomationRules="${DEPLOY_AUTOMATION_RULE}" \
      deployPlaybook="${DEPLOY_PLAYBOOK}" \
  -o none
echo "Validation passed."

echo "== Deploying =="
az deployment group create \
  --resource-group "${RESOURCE_GROUP}" \
  --name "sentinel-lab-$(date +%Y%m%d%H%M%S)" \
  --template-file "${TEMPLATE}" \
  --parameters \
      workspaceName="${WORKSPACE_NAME}" \
      location="${LOCATION}" \
      enableAnalyticsRule="${ENABLE_ANALYTICS_RULE}" \
      deployAutomationRules="${DEPLOY_AUTOMATION_RULE}" \
      deployPlaybook="${DEPLOY_PLAYBOOK}" \
  -o table

echo
echo "=============================================================="
echo "  DEPLOYMENT COMPLETE (lab)"
echo "=============================================================="
echo "Resource group:  ${RESOURCE_GROUP}"
echo "Workspace:       ${WORKSPACE_NAME}"
echo
echo "Next steps:"
echo "  - Azure Portal > Microsoft Sentinel > select the workspace"
echo "  - Analytics > confirm '[LAB] DET-001 ...' exists and is DISABLED"
echo "  - The analytics rule is disabled unless you set ENABLE_ANALYTICS_RULE=true"
echo
echo "COST CONTROL: delete everything when done:"
echo "  az group delete --name \"${RESOURCE_GROUP}\" --yes --no-wait"
