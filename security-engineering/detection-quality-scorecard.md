# Detection Quality Scorecard

A transparent maturity assessment of all 15 detections across both labs. The
machine-readable source is
[detection-quality-scorecard.json](detection-quality-scorecard.json), regenerated
by [score_detections.py](score_detections.py) (stdlib only - runs with a bare
`python3`).

**Honest framing:** these scores measure **detection-as-code metadata quality**
- is the rule mapped, tested, documented and owned - not production readiness.
Every detection here is a **candidate that requires tenant-specific baselining
and tuning before deployment**. The scorecard is a maturity instrument, not a
certificate.

## Scoring rubric (100 points)

| Criterion | Weight | What it checks |
|-----------|--------|----------------|
| MITRE ATT&CK mapping | 14 | At least one technique id present |
| Data source listed | 8 | `data_source(s)` declared |
| Severity + rationale | 6 | Severity set and explained in the description |
| Version | 5 | Semantic version present |
| Named owner | 7 | An accountable owner is named |
| False-positive guidance | 12 | Benign causes documented |
| Response guidance | 12 | Explicit response steps (full) or SLA only (half) |
| Automated test coverage | 12 | Detection asserted in the test suite |
| Tuning notes | 10 | Structured tuning block (full) or prose FP notes (partial) |
| Known limitations | 8 | Limitations / references documented |
| Expected output contract | 6 | `test_expectation` or `entity_mappings` present |

## Maturity bands

| Score | Band |
|-------|------|
| 85-100 | Production candidate (strong) - requires tenant-specific tuning |
| 66-84 | Production candidate - requires tenant-specific tuning |
| 41-65 | Developing |
| 0-40 | Experimental |

No band is labelled "production ready". Even the strongest detections need
environment baselining, false-positive review against real telemetry, and a
deployment approval before they earn that description.

## Results (generated 2026-07)

**15 detections | average 91.8/100 | range 87-96**

### Datacenter Control Plane Attack Path Lab

| ID | Detection | Severity | Score | Maturity |
|----|-----------|----------|-------|----------|
| CP-DET-001 | Risky sign-in from unusual location | High | 96 | Strong candidate (tenant tuning) |
| CP-DET-002 | MFA fatigue leading to approval | Critical | 96 | Strong candidate (tenant tuning) |
| CP-DET-003 | Privileged role activation without change record | High | 96 | Strong candidate (tenant tuning) |
| CP-DET-004 | Credential added to high-privilege service principal | Critical | 96 | Strong candidate (tenant tuning) |
| CP-DET-005 | Subscription or resource group permission change | High | 96 | Strong candidate (tenant tuning) |
| CP-DET-006 | NSG or firewall rule opened to the internet | Critical | 96 | Strong candidate (tenant tuning) |
| CP-DET-007 | VM management endpoint exposed | Critical | 96 | Strong candidate (tenant tuning) |
| CP-DET-008 | Correlated identity-to-control-plane chain | Critical | 96 | Strong candidate (tenant tuning) |

### Identity Threat Detection & SOAR Lab

| ID | Detection | Severity | Score | Maturity |
|----|-----------|----------|-------|----------|
| DET-001 | MFA Fatigue (Push Bombing) | High | 87 | Strong candidate (tenant tuning) |
| DET-002 | Impossible Travel Sign-in | Medium | 87 | Strong candidate (tenant tuning) |
| DET-003 | Conditional Access Policy Modified or Deleted | High | 87 | Strong candidate (tenant tuning) |
| DET-004 | New Credential Added to Service Principal | High | 87 | Strong candidate (tenant tuning) |
| DET-005 | Account Added to Privileged Role or Group | High | 87 | Strong candidate (tenant tuning) |
| DET-006 | Anomalous CyberArk Privileged Credential Checkout | Medium | 87 | Strong candidate (tenant tuning) |
| DET-007 | Stale or Orphaned Privileged Account | Low | 87 | Strong candidate (tenant tuning) |

## Reading the spread

The 9-point gap between the two labs is real and instructive, not noise:

- The **control-plane detections (96)** carry explicit `owner`, `response_guidance`
  and `test_expectation` fields in every rule - metadata I added after learning
  from the parent lab.
- The **identity detections (87)** lose points for having no explicit owner field
  and expressing response guidance through SLA + engine triage steps rather than
  an inline field. Their tuning metadata is actually richer (structured
  `tuning` blocks with exclusions), which is why they still score highly.

That gap is the scorecard doing its job: it points at exactly what to improve
next (add owners and inline response guidance to the identity rules), which is
the kind of continuous-improvement signal a detection-engineering team runs on.

## How to regenerate

```bash
python3 security-engineering/score_detections.py
```

The script parses every `*.yaml` under `detections/` and
`modules/datacenter-control-plane/detections/`, so new detections are scored
automatically and the scorecard never drifts from the rules.
