# Control: detect and lifecycle stale privileged identities

**Illustrative concept - requires environment-specific configuration and testing.**

Counters: **DET-007** (stale or orphaned privileged account) - reducing standing
attack surface before it is ever abused.

## Principle

Dormant privileged accounts are the quiet entry points attackers prefer: nobody
notices when a long-unused admin account suddenly wakes up. Prevention is
lifecycle hygiene - find them, confirm ownership, and remove or time-box the
privilege.

## Governance query concept

```kusto
// Enabled privileged identities unused for 60+ days, or orphaned service accounts.
IdentityInfo
| where IsPrivileged == true and AccountEnabled == true
| where isempty(LastSignIn) or LastSignIn < ago(60d)
| extend Orphaned = IsServiceAccount and isempty(Owner)
| extend Severity = iff(Orphaned, "High", "Low")
| project Upn, LastSignIn, Orphaned, Severity
```

## Lifecycle workflow (as reviewable process)

```yaml
stale_privileged_identity_lifecycle:
  detect: DET-007 (daily posture run)
  triage:
    - confirm business owner
    - confirm no auth via paths not in sign-in logs
  action:
    - disable_or_strip_privilege        # disable-then-delete
    - convert_remaining_need_to: PIM_eligible_with_expiry
  feedback:
    - update joiner_mover_leaver_process   # stop the debt regenerating
  exclusions:
    - break_glass_accounts_by_naming_convention
```

## How it reduces risk

CP-INC-2001 used a live account, but the same estate typically carries dormant
privileged identities that would give an attacker an even quieter path. Running
DET-007 as a posture control with an SLA - not an annual audit - shrinks that
surface continuously.

## Validation before production

1. Confirm the identity snapshot source (Entra ID export / watchlist) is fresh.
2. Exclude intentionally dormant break-glass accounts by naming convention.
3. Map service-account dependencies before disabling (avoid breaking integrations).
