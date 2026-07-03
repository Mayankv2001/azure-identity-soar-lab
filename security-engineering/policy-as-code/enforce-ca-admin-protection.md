# Control: enforce Conditional Access protection for admin roles

**Illustrative concept - requires environment-specific configuration and testing.**

Counters: the MFA fatigue that starts the chain (**DET-001 / CP-DET-002**) and
CA tampering (**DET-003**).

## Intended Conditional Access policy (as reviewable config)

```yaml
policy: CA-Require-Phishing-Resistant-MFA-for-Admins
state: enabled
assignments:
  users_and_groups:
    include_roles:
      - Global Administrator
      - Privileged Role Administrator
      - Application Administrator
      - Cloud Operations (sg-cloud-ops)
  applications:
    include: All cloud apps
conditions:
  sign_in_risk: [medium, high]        # pair with Entra ID Protection
grant_controls:
  operator: AND
  require:
    - authenticationStrength: phishingResistantMfa   # FIDO2 / passkeys / CBA
    - compliantDevice
session_controls:
  sign_in_frequency_hours: 4
```

## How it breaks the attack chain

Push-approval MFA is what the fatigue attack defeats. Requiring
**phishing-resistant** authentication strength for operations and admin roles
removes the approve-a-prompt weakness entirely - there is no prompt to spam.
Enforcing a compliant device raises the bar further.

## Guardrails

- Exclude break-glass accounts, monitored separately and stored offline.
- Roll out in report-only first; watch for legitimate lockouts.
- Alert on any change to this policy (DET-003) - the policy that protects admins
  is itself a high-value target.
