# KQL Test Harness

The labs execute the **Python mirrors** of every detection against synthetic
telemetry, with deterministic tests. This document describes how the **KQL
itself** would be validated before production in a Microsoft Sentinel staging
workspace - because a rule that has never been tested against real-shaped data
is a liability, not a control.

Machine-readable test cases: [kql-test-cases.json](kql-test-cases.json) - one
per detection, all 15.

> The goal here is not to execute live KQL locally. It is to document the
> validation discipline that turns a query into a production detection.

## What every KQL test case records

| Field | Purpose |
|-------|---------|
| positive_sample | Telemetry that must produce an alert |
| negative_sample | Look-alike that must stay silent |
| expected_alert_count | The exact count, so regressions are visible |
| false_positive_case | The realistic benign twin to review against real data |
| regression_case | The subtle edge that broke (or could break) the rule |
| tuning_variable | The knobs an environment will need to adjust |
| approval_checklist | What must be true before this rule is promoted |

## How validation runs in the labs today

The Python mirrors give a real, runnable proxy for KQL validation:

```bash
python3 src/main.py --demo                                   # identity lab
python3 modules/datacenter-control-plane/src/main.py --demo  # control-plane lab
python3 -m pytest -q                                         # asserts positives + negatives
```

Every positive/negative pair in `kql-test-cases.json` corresponds to an assertion
in the test suite. Running the tests *is* the offline validation run; the KQL
staging validation below is the production equivalent.

## Detection promotion checklist

No detection reaches a production workspace without clearing every gate. This is
the detection-as-code lifecycle in one list:

1. **Dev** - author the KQL and its Python mirror; thresholds documented in the
   query header.
2. **Peer review** - a second engineer reviews the logic, the MITRE mapping and
   the false-positive guidance in the pull request.
3. **Simulation validation** - run the positive and negative samples (purple-team
   pack) in a staging workspace; confirm the expected alert count.
4. **Test-case evidence** - attach the positive/negative results and query
   performance (scan volume, run time) to the PR.
5. **False-positive review** - run the query over a window of real historical
   telemetry; quantify the benign firings and tune exclusions.
6. **Rollback plan** - define how the rule is disabled or reverted if it
   misbehaves (version pin, feature flag, disable switch).
7. **Deployment approval** - the approval-gated pipeline stage promotes the rule
   to production (see the Azure DevOps pipelines in both labs).
8. **Post-deployment monitoring** - watch alert volume and precision for the
   first N days; an alert-volume canary pages if the rule floods the queue.

## Why this matters for the role

The difference between "I wrote some KQL" and "I engineer detections" is this
checklist. It is how a detection-as-code team keeps a large estate trustworthy:
every rule is reviewed, tested against positives *and* negatives, tuned against
real data, deployed through a gate, and monitored after. The labs demonstrate
steps 1-4 concretely and document 5-8 as the production path.
