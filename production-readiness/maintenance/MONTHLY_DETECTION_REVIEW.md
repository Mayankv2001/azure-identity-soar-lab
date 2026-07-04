# Monthly detection review

Lab-safe, synthetic. Agenda and checklist for the monthly detection review. Owned
by the SecOps Lead (amara.okafor@contoso.com), attended by detection owners.

## Purpose

Keep the detection estate earning its alerts: cut noise, protect true positives,
and surface coverage gaps before an attacker finds them.

## Agenda (60 minutes)

1. **Metrics recap (10 min)** - alert volume, false-positive rate, MTTD/MTTR, SLA
   adherence from the daily reports and
   [../../security-engineering/detection-quality-scorecard.md](../../security-engineering/detection-quality-scorecard.md).
2. **False-positive review (20 min)** - walk the top FP contributors from
   [../tuning/noise-review-sample.json](../tuning/noise-review-sample.json); each
   recurring benign cause becomes a proposed, scoped, tested exclusion (never
   broad suppression). Use
   [../tuning/FALSE_POSITIVE_REVIEW_TEMPLATE.md](../tuning/FALSE_POSITIVE_REVIEW_TEMPLATE.md).
3. **Promotion decisions (10 min)** - which rules advance a promotion state
   ([../tuning/DETECTION_PROMOTION_GATES.md](../tuning/DETECTION_PROMOTION_GATES.md)),
   which get demoted, which stay put. Nothing is promoted to "production approved"
   without real-telemetry evidence.
4. **New/changed detections (10 min)** - review rules shipped since last month;
   confirm each has an owner, tests, MITRE mapping, and a version bump.
5. **Actions and owners (10 min)** - each item gets an owner and a due date.

## Checklist

- [ ] FP rate reviewed per detection; recurring causes have a tuning proposal
- [ ] No true positives lost to any exclusion (regression tests confirm)
- [ ] Every rule change is versioned and tested in CI
- [ ] Every noisy rule has an owner action or a documented reason to keep it
- [ ] Rules that stopped earning alerts flagged for
      [deprecation](DEPRECATION_PROCESS.md)
- [ ] Connector health checked - no rule running blind over a dead source
- [ ] [Rule owner register](RULE_OWNER_REGISTER.md) updated (last/next review)

## Output

A short minutes note: metrics, decisions, and actions with owners/dates. Actions
feed the [tuning backlog](../tuning/TUNING_BACKLOG_SAMPLE.md).
