# Control: monitor service principal credential changes

**Illustrative concept - requires environment-specific configuration and testing.**

Counters: **CP-DET-004 / DET-004** (credential added to a service principal).

## Two layers

Prevention and detection work together here, because you cannot fully "deny"
credential management without breaking legitimate automation.

1. **Restrict who can manage app credentials.** Limit the Application
   Administrator / Cloud Application Administrator population and put those roles
   behind PIM with approval (see require-approval-privileged-role).
2. **Alert on every credential add**, and escalate for high-privilege targets -
   which is exactly what DET-004 / CP-DET-004 do.

## Detection-as-prevention query concept

```kusto
// Alert on every service-principal credential addition; enrich with privilege tier.
AuditLogs
| where OperationName == "Add service principal credentials"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         TargetSP = tostring(TargetResources[0].displayName)
| lookup kind=leftouter (_GetWatchlist('HighPrivilegeServicePrincipals')) on $left.TargetSP == $right.SearchKey
| extend Severity = iff(isnotempty(SearchKey), "Critical", "High")
```

## How it breaks the attack chain

Restricting credential management shrinks the population that can perform the
stage-4 move at all; alerting on every add ensures that when it does happen, it
is seen immediately rather than discovered during an incident.

## Validation before production

1. Baseline: how many credential adds per week are legitimate (pipeline rotation)?
2. Exclude approved rotation principals to keep the signal clean.
3. Confirm the high-privilege watchlist is complete and maintained by the SOC.
