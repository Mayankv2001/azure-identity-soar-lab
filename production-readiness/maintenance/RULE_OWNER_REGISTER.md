# Rule owner register

Lab-safe, synthetic. Every detection mapped to an accountable owner, version, and
review dates. Machine-readable copy:
[sample-rule-owner-register.json](sample-rule-owner-register.json). No detection
is marked "production approved" - the repo detections sit at Draft/Simulated in
the [promotion pipeline](../tuning/DETECTION_PROMOTION_GATES.md).

## Identity Threat Detection & SOAR Lab

| Rule | Name | Owner | Version | Last reviewed | Next review | Promotion state |
|------|------|-------|---------|---------------|-------------|-----------------|
| DET-001 | MFA Fatigue (Push Bombing) | ravi.menon@contoso.com | 1.0.0 | 2026-07-01 | 2026-08-01 | Simulated |
| DET-002 | Impossible Travel Sign-in | ravi.menon@contoso.com | 1.1.0 | 2026-07-01 | 2026-08-01 | Simulated |
| DET-003 | Conditional Access Policy Modified/Deleted | ravi.menon@contoso.com | 1.0.0 | 2026-07-01 | 2026-08-01 | Draft |
| DET-004 | New Credential Added to Service Principal | ravi.menon@contoso.com | 1.0.0 | 2026-07-01 | 2026-08-01 | Draft |
| DET-005 | Account Added to Privileged Role or Group | ravi.menon@contoso.com | 1.0.0 | 2026-07-01 | 2026-08-01 | Draft |
| DET-006 | Anomalous CyberArk Privileged Checkout | ravi.menon@contoso.com | 1.0.0 | 2026-07-01 | 2026-08-01 | Draft |
| DET-007 | Stale or Orphaned Privileged Account | ravi.menon@contoso.com | 1.0.0 | 2026-07-01 | 2026-08-01 | Draft |

## Datacenter Control Plane Attack Path Lab

| Rule | Name | Owner | Version | Last reviewed | Next review | Promotion state |
|------|------|-------|---------|---------------|-------------|-----------------|
| CP-DET-001 | Risky sign-in from unusual location | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Simulated |
| CP-DET-002 | MFA fatigue leading to approval | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Simulated |
| CP-DET-003 | Privileged role activation without change record | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Draft |
| CP-DET-004 | Credential added to high-privilege service principal | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Draft |
| CP-DET-005 | Subscription or resource group permission change | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Draft |
| CP-DET-006 | NSG or firewall rule opened to the internet | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Draft |
| CP-DET-007 | VM management endpoint exposed | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Draft |
| CP-DET-008 | Correlated identity-to-control-plane chain | amara.okafor@contoso.com | 1.0.0 | 2026-07-04 | 2026-08-04 | Simulated |

## Live analytics rule (Mode C)

| Rule | Name | Owner | Version | State |
|------|------|-------|---------|-------|
| [LAB] DET-001 | MFA Fatigue (Push Bombing) - deployed | amara.okafor@contoso.com | 1.0.0 | Deployed **disabled** in lab subscription |

An owner-less rule is a liability: nobody notices when it drifts, floods, or goes
blind. The register makes ownership explicit and reviewable.
