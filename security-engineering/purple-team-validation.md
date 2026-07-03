# Purple-Team Validation Pack

> **This validation pack uses synthetic telemetry only and does not provide
> instructions to compromise real systems.** Every "attack" is a synthetic log
> event emitted by the labs' generators. The purpose is to prove that each
> detection fires on the behaviour it claims to catch, stays silent on the
> benign look-alike, and hands the analyst the right next question.

Purple teaming is the habit that keeps detection engineering honest: the red
idea (what would an attacker do) and the blue control (does my detection see it)
are validated together, continuously, rather than assumed. This pack maps every
detection across both labs to a safe, simulation-based behaviour.

Machine-readable source:
[atomic-scenarios.json](atomic-scenarios.json).

## How to read a scenario

Each scenario answers eight questions a detection engineer should be able to
answer before shipping a rule:

1. **Scenario / objective** - what is the adversary trying to achieve?
2. **MITRE technique** - how does that map to ATT&CK?
3. **Expected telemetry** - what synthetic events represent it?
4. **Expected detection** - which rule fires, at what severity?
5. **Expected analyst question** - the first thing triage should ask.
6. **Expected containment** - the response, with its approval class.
7. **False-positive scenario** - the benign look-alike that must *not* fire.
8. **Validation method** - how the test suite proves both halves.

## Coverage matrix

| Scenario | Detection | Technique | Fires | Benign look-alike suppressed |
|----------|-----------|-----------|-------|------------------------------|
| MFA fatigue push-bombing | DET-001 / CP-DET-002 | T1621 | Yes | Single missed prompt |
| Impossible travel | DET-002 | T1078.004 | Yes | Corporate VPN egress pair |
| Conditional Access tamper | DET-003 | T1556.009 | Yes | Approved change-window edit |
| SP credential addition | DET-004 / CP-DET-004 | T1098.001 | Yes | Low-privilege SP rotation |
| Privileged role activation | DET-005 / CP-DET-003 | T1098.003 | Yes | Ticketed break-glass |
| NSG public exposure | CP-DET-006 | T1562.007 | Yes | Internal 10.0.0.0/8 rule |
| VM management exposure | CP-DET-007 | T1133 | Yes | Open rule, no public IP |
| CyberArk checkout anomaly | DET-006 | T1078.002 | Yes | Ticketed daytime checkout |
| Stale privileged account | DET-007 | T1078 | Yes | Break-glass by naming convention |
| Full control-plane chain | CP-DET-008 | 6 techniques | Yes | 3 unrelated events (entity scoping) |

## Why the benign look-alikes matter most

Any rule can be made to fire; the engineering is in *not* firing on the benign
twin. This pack pairs every positive with a negative that the test suite
asserts:

- impossible travel must ignore VPN egress (the v1.1.0 tuning story);
- the SP credential rule must ignore low-privilege principals;
- the NSG rules must ignore internal-source and non-reachable changes;
- the CyberArk rule must ignore ticketed, in-hours checkouts.

Those negatives are what turn a noisy demo into a detection an on-call engineer
would actually trust at 3am.

## How this is exercised

The labs' generators emit the positive and negative telemetry deterministically
(fixed seeds). The test suites (`tests/` and
`modules/datacenter-control-plane/tests/`) assert the expected firing and the
expected suppression for every scenario. Running the demos and the tests *is*
the validation run:

```bash
python3 src/main.py --demo
python3 modules/datacenter-control-plane/src/main.py --demo
python3 -m pytest -q
```

In a real tenant, the same scenarios would be reproduced with a controlled,
authorised attack-simulation tool against a staging workspace before any rule
is promoted - see the promotion checklist in
[kql-test-harness.md](kql-test-harness.md).
