# Change Risk Matrix

Part of the **Production Readiness & Operations Layer** for the AI-Assisted
Azure Identity Threat Detection & SOAR Lab.

> **Honest lab framing.** Synthetic, offline-first lab that mirrors Microsoft
> Sentinel and Azure concepts; nothing here is deployed to a production tenant.
> This matrix is the scoring instrument behind the
> [Change Approval Model](CHANGE_APPROVAL_MODEL.md). It assigns a risk level to
> each change type from **likelihood x impact**, and that level drives approval,
> test evidence, and change window. All personas are fictional `@contoso.com`
> accounts; no secrets or real identifiers appear.

## 1. How to score a change

1. Rate **likelihood** — how probable is it that this change causes harm
   (breaks a control, blocks legitimate activity, or opens exposure) given the
   test evidence available?
2. Rate **impact** — if it does go wrong, how wide and how reversible is the
   damage?
3. Read the risk level off the grid. The **default risk level** in the approval
   model is the starting assumption; a change's actual scope can move it up.

Likelihood and impact are each rated 1–3.

### Likelihood scale

| Score | Band | Meaning |
|-------|------|---------|
| 1 | Unlikely | Well-understood change, strong test coverage, deterministic behaviour verified |
| 2 | Possible | Partial coverage, some environment dependence, a plausible failure path |
| 3 | Likely | Novel or broad change, thin evidence, behaviour depends on real tenant data not yet seen |

### Impact scale

| Score | Band | Meaning |
|-------|------|---------|
| 1 | Contained | Reversible in seconds; no effect on live response, access, or network reachability |
| 2 | Significant | Reversible with effort; can degrade detection fidelity or a scoped control |
| 3 | Severe | Can lock users out, open network exposure, grant standing privilege, or block change estate-wide |

## 2. The matrix (likelihood x impact)

Cells give the resulting **risk level**. Read down = likelihood, across =
impact.

| Likelihood \ Impact | 1 — Contained | 2 — Significant | 3 — Severe |
|---------------------|---------------|-----------------|------------|
| **3 — Likely**   | Medium | High | **Critical** |
| **2 — Possible** | Low | Medium | High |
| **1 — Unlikely** | Low | Low | Medium |

Rationale for the corners: a severe-impact change is **never** below Medium even
when failure is unlikely (impact dominates — you cannot buy back a locked-out
tenant with a low probability), and a likely-but-contained change stays Medium
because it is cheap to reverse.

## 3. Risk level → approval path

Straight from the [Change Approval Model](CHANGE_APPROVAL_MODEL.md), so the
matrix output maps directly to an action.

| Risk level | Approval required | Change window | Test evidence bar |
|------------|-------------------|---------------|-------------------|
| **Low** | One peer review | Any time | Tests green |
| **Medium** | Detection reviewer *or* SOC DRI | Business hours | Tests green + before/after on affected control |
| **High** | Two-person (owner + DRI) | Scheduled, announced | Above + reachability/least-privilege proof |
| **Critical** | Change advisory (owner + DRI + peer) + explicit go/no-go | Scheduled, rollback rehearsed | Above + Audit/report-only dry run + rehearsed rollback |

## 4. Change types mapped

Default scoring for each change type from the approval model, with the scope
condition that escalates it. "L" = likelihood, "I" = impact.

| Change type | L | I | Default risk | Primary approver | Escalates to Critical when… |
|-------------|---|---|--------------|------------------|------------------------------|
| **Analytics rule** — edit/tune `DET-00X` / `CP-DET-00X` | 2 | 2 | Medium | Detection reviewer | (goes High, not Critical) disabling a Critical detection or widening an exclusion that could drop true positives |
| **Analytics rule** — disable / suppress a Critical detection | 2 | 3 | High | Detection reviewer + DRI | broad suppression across multiple Critical rules at once |
| **SOAR playbook** — `PB-01/02/03` (enrich/notify/ticket) | 2 | 1 | Medium | SOC DRI | n/a (informational, easily reversed) |
| **SOAR playbook** — `PB-04/05/06` (revoke/reset/disable) logic edit | 2 | 3 | High | SOC DRI + identity owner | promoting a destructive action to full-auto (unattended) |
| **Firewall / NSG response** — non-management subnet | 2 | 2 | High | Infra owner + DRI | rule governs a management port (22/3389/5985/5986) or prod-tier subnet |
| **Firewall / NSG response** — management endpoint | 2 | 3 | Critical | Change advisory | any change touching an internet-facing management endpoint (the CP-INC-2001 class) |
| **RBAC assignment** — scoped, time-bound (PIM-eligible) | 1 | 2 | Medium | Identity owner | permanent standing grant instead of PIM-eligible |
| **RBAC assignment** — Owner / Global Admin / subscription scope | 2 | 3 | Critical | Change advisory | Owner/Global Administrator, subscription scope, or any break-glass account change |
| **Azure Policy** — Audit / report-only mode | 1 | 1 | Medium | Infra owner | (stays Medium — observes only) |
| **Azure Policy** — Deny mode, management-group/subscription scope | 2 | 3 | Critical | Change advisory | any Deny-mode promotion at management-group or subscription scope |

## 5. Worked examples

- **Re-enabling a tuned `DET-002` (Impossible Travel) after adding the v1.1.0
  exclusion.** Likelihood 2 (behavioural rule, but tuning is tested on the
  deterministic dataset), impact 2 (a bad exclusion could drop true positives,
  but it is reversible through the pipeline) → **Medium**. Approval: detection
  reviewer, with the DRI informed because a re-enabled rule changes response
  volume. This is the change worked end-to-end in the
  [Sample Change Record](SAMPLE_CHANGE_RECORD.md).

- **Moving `deny-public-management-ports` from Audit to Deny at subscription
  scope.** Likelihood 2 (a legitimate deployment could be blocked), impact 3
  (blocks change across the subscription) → **Critical**. Requires the Audit-run
  compliance evidence and a rehearsed rollback (flip the effect parameter back
  to `Audit`) before go/no-go.

- **Reverting the CP-INC-2001 NSG rule that opened RDP to `0.0.0.0/0` on
  `nsg-prod-dc-mgmt`.** Likelihood 2, impact 3 (management endpoint) →
  **Critical** on paper — but this is *containment closing an active exposure*,
  so it is executed first under the DRI's authority and ratified with a change
  record immediately after. The matrix sets the evidence bar; it does not delay
  closing a live exposure.

- **Adding a read-only reviewer to a synthetic dashboard.** Likelihood 1, impact
  1 → **Low**. One peer review, any time.

## 6. Notes on using the matrix honestly

- **Impact wins ties.** When likelihood and impact disagree, size the risk to
  the impact — the whole point is to protect against the change you were sure
  would be fine.
- **Thin evidence raises likelihood.** If you cannot produce the test evidence
  the change type requires, likelihood is 3 by definition until you can.
- **The matrix does not approve anything.** It classifies. A human on the
  correct approval path still signs, and the requester is never that human for
  their own change.

## Related documents

- [Change Approval Model](CHANGE_APPROVAL_MODEL.md) — change types, roles,
  lifecycle
- [Sample Change Record](SAMPLE_CHANGE_RECORD.md) — a filled example
- [Rollback Plan Template](ROLLBACK_PLAN_TEMPLATE.md) — reusable rollback
