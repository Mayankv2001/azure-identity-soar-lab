# Infrastructure as Code (illustrative)

These templates are **illustrative, not deployment-ready**. They show how the
Mode B version of this module would be provisioned and how the key preventive
control - denying public exposure of management ports - would be expressed as
policy rather than caught only after the fact by a detection.

Nothing here needs to be deployed to run the lab; the whole module works
offline. Subscription IDs, workspace names and resource names are placeholders.

| File | Concept |
|------|---------|
| `main.bicep` | Log Analytics workspace + Microsoft Sentinel onboarding placeholder |
| `analytics-rule.bicep` | One scheduled analytics rule (CP-DET-006) as a placeholder |
| `deny-public-management-exposure.json` | Azure Policy denying internet-wide inbound on management ports |
| `nsg-baseline.bicep` | NSG rule concept showing an approved internal-only rule |

## The detection-to-prevention story

CP-DET-006 and CP-DET-007 *detect* a management port being opened to the
internet. `deny-public-management-exposure.json` *prevents* it - the Azure
Policy denies the NSG rule at write time. A mature control plane does both:
policy stops the common case, and the detection catches the exceptions
(policy exemptions, drift, resource types the policy does not cover). The RCA
in the demo output recommends exactly this pairing.

## How these would deploy in a real tenant

Through the same detection-as-code discipline as the parent lab: the Bicep and
policy files live in the repo, are reviewed in pull requests, validated in the
pipeline, and deployed through an approval-gated stage - never applied by hand.
See `.azure-pipelines/validate-control-plane-module.yml`.
