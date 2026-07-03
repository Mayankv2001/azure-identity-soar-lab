# Prevention controls

Detection tells you an attack happened; prevention stops it. A mature control
plane does both - policy blocks the common case at write time, and detection
catches the exceptions (exemptions, drift, uncovered resource types). This
document maps each attack-chain stage to the preventive control that would have
broken it, with illustrative policy-as-code under
[policy-as-code/](policy-as-code/).

> **These are illustrative templates and require environment-specific testing
> before production.** Deploy any deny policy in Audit mode first, measure what
> it would have blocked, then tighten to Deny.

## Prevention mapped to the attack chain

| Chain stage | Detection | Preventive control | Policy-as-code |
|-------------|-----------|--------------------|----------------|
| NSG opens RDP/SSH to 0.0.0.0/0 | CP-DET-006/007 | Deny public inbound on management ports | [deny-public-management-ports.json](policy-as-code/deny-public-management-ports.json) |
| Privileged role activation | CP-DET-003 / DET-005 | Require approval + justification on PIM activation | [require-approval-privileged-role.md](policy-as-code/require-approval-privileged-role.md) |
| SP credential added | CP-DET-004 / DET-004 | Monitor + restrict app credential management; alert on every add | [monitor-sp-credentials.md](policy-as-code/monitor-sp-credentials.md) |
| SP standing privilege | CP-DET-004 | Require workload-identity credential rotation / managed identities | [require-workload-identity-rotation.md](policy-as-code/require-workload-identity-rotation.md) |
| CA policy tamper | DET-003 | Enforce Conditional Access protection for admin roles | [enforce-ca-admin-protection.md](policy-as-code/enforce-ca-admin-protection.md) |
| High-privilege app abuse | CP-DET-004 | Audit high-privilege app registrations | [audit-highpriv-app-registrations.json](policy-as-code/audit-highpriv-app-registrations.json) |
| Stale privileged identity | DET-007 | Detect and lifecycle stale privileged identities | [detect-stale-privileged-identity.md](policy-as-code/detect-stale-privileged-identity.md) |
| Untraceable sensitive resource | all | Require tagging/ownership for sensitive resources | [require-tagging-ownership.json](policy-as-code/require-tagging-ownership.json) |

## The eight controls

### 1. Deny public RDP/SSH from 0.0.0.0/0
Azure Policy denying inbound NSG Allow rules from the internet to ports
22/3389/5985/5986. This is the **earliest break point** in the attack-path graph:
it severs the last and most damaging edge before the management endpoint is ever
reachable. Deploy as Audit first to find existing exposure, then Deny.

### 2. Require approval for privileged role activation
PIM configured so protected roles (Global Administrator, Privileged Role
Administrator, Application Administrator) require approval and a justification on
activation. Turns CP-DET-003's ticketless activation into a blocked or
approver-visible event.

### 3. Monitor service principal credential changes
Alert on every `Add service principal credentials`, and restrict who may manage
app credentials. Prevention here is partly procedural (least privilege on the
directory role) and partly detective (DET-004 / CP-DET-004 as the safety net).

### 4. Require workload-identity credential rotation
Prefer managed identities (no secrets to steal); where secrets are unavoidable,
enforce short lifetimes and automated rotation from key vault. Removes the
durable-persistence value of a stolen SP secret.

### 5. Enforce Conditional Access protection for admin roles
Require phishing-resistant MFA and compliant device for privileged roles, and
alert on any change to those policies (DET-003). Directly counters the MFA
fatigue that started this chain.

### 6. Audit high-privilege app registrations
Regularly review app registrations holding directory-write or subscription-level
scopes. An unreviewed high-privilege app is exactly the sp-infra-deploy in this
scenario.

### 7. Detect stale privileged identities
DET-007 as a posture control: enabled privileged accounts unused for 60+ days, or
orphaned service accounts, are dormant attack surface. Lifecycle them via
access reviews and PIM-eligible-with-expiry.

### 8. Require tagging/ownership for sensitive resources
Azure Policy requiring an `owner` and `criticality` tag on sensitive resources.
You cannot enrich, prioritise or route an incident on an asset nobody owns -
tagging is a precondition for fast, correct response.

## Prevention-first philosophy

The scorecard, the purple-team pack and the detections all point the same
direction: the goal is not more alerts, it is fewer incidents. Every RCA in
these labs ends by asking "which control would have prevented this", and the
answer becomes a policy in this folder - so the system gets safer over time, not
just noisier.
