#!/usr/bin/env bash
# Validate the lab Sentinel Bicep templates WITHOUT creating billable resources.
#
# It builds the Bicep and runs `az deployment group validate`, which checks the
# template against Azure Resource Manager but does not deploy anything. An empty
# resource group is created if needed (resource groups themselves are free).
#
# Requires: Azure CLI (az), a logged-in personal/test account, and:
#   RESOURCE_GROUP, LOCATION   (WORKSPACE_NAME optional, defaults for validation)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../../infra/sentinel/main.bicep"

command -v az >/dev/null 2>&1 || {
  echo "ERROR: Azure CLI (az) is required. Install it, then 'az login' with your personal/test account."
  exit 1
}

az account show >/dev/null 2>&1 || {
  echo "ERROR: Not logged in. Run: az login   (use your personal/test Azure account, NOT a work tenant)."
  exit 1
}

: "${RESOURCE_GROUP:?Set RESOURCE_GROUP, e.g. export RESOURCE_GROUP=rg-sentinel-identity-lab}"
: "${LOCATION:?Set LOCATION, e.g. export LOCATION=australiaeast}"
WORKSPACE_NAME="${WORKSPACE_NAME:-law-identity-soar-lab-validate}"

echo "== Active Azure context =="
az account show --query "{subscription:name, subscriptionId:id, tenantId:tenantId, user:user.name}" -o table
echo
echo "Template:        ${TEMPLATE}"
echo "Resource group:  ${RESOURCE_GROUP}"
echo "Location:        ${LOCATION}"
echo "Workspace (val): ${WORKSPACE_NAME}"
echo

echo "== Building Bicep =="
az bicep build --file "${TEMPLATE}"

echo "== Ensuring resource group exists (free) =="
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" -o none

echo "== Validating deployment (no resources are created) =="
az deployment group validate \
  --resource-group "${RESOURCE_GROUP}" \
  --template-file "${TEMPLATE}" \
  --parameters workspaceName="${WORKSPACE_NAME}" location="${LOCATION}" \
  -o table

echo
echo "Validation complete. No billable resources were created by this script."
echo "To deploy for real, review and run: scripts/sentinel/deploy_sentinel_lab.sh"
