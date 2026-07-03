# Control: require workload-identity credential rotation

**Illustrative concept - requires environment-specific configuration and testing.**

Counters: durable service-principal persistence (**CP-DET-004 / DET-004**).

## Principle

The most robust prevention is to have no secret to steal: prefer **managed
identities** for Azure workloads. Where a secret or certificate is unavoidable,
enforce short lifetimes and automated rotation from a key vault, so a stolen
credential is worth little and expires fast.

## Intended standard (as reviewable config)

```yaml
service_principal_standard:
  prefer: managed_identity            # first choice for anything running in Azure
  if_secret_required:
    max_credential_lifetime_days: 90
    rotation: automated_from_key_vault
    no_secrets_in_code_or_pipeline_variables: true
    alert_on_manual_credential_add: true   # DET-004 / CP-DET-004
governance_query_concept: |
  # Directory query concept (Graph): flag app credentials older than the standard
  applications
  | mv-expand cred = passwordCredentials
  | where cred.endDateTime > now() and datetime_diff('day', cred.endDateTime, cred.startDateTime) > 90
  | project appId, displayName, credentialAgeDays
```

## How it breaks the attack chain

In CP-INC-2001 the attacker's value came from adding a long-lived secret to a
high-privilege SP. A managed identity has no addable secret; a 90-day
auto-rotated secret from key vault sharply limits the persistence window and
makes a manual credential add an anomaly worth alerting on.

## Validation before production

1. Inventory which SPs can move to managed identity vs which genuinely need secrets.
2. Confirm rotation automation has a tested rollback (rotation that breaks an
   integration is its own incident).
3. Pair with DET-004 / CP-DET-004 so any manual add still detects.
