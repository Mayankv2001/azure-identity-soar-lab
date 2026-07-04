# Least-Privilege Review Checklist

The checklist a reviewer runs against the Sentinel detection estate — quarterly
for standing access, on-event for joiners/movers/leavers, and annually for a full
recertification. Pairs with [RBAC_REVIEW_MODEL.md](RBAC_REVIEW_MODEL.md) (why)
and [SENTINEL_RBAC_MATRIX.md](SENTINEL_RBAC_MATRIX.md) (what).

> **Honest lab framing.** This is an illustrative checklist for a synthetic,
> offline-first lab; there is no live tenant to review. It is written as a working
> reviewer's aid so the process is concrete and auditable, using fictional
> `@contoso.com` personas and placeholder scopes (`sub-lab` / all-zero GUID). No
> real GUIDs, subscriptions or secrets appear anywhere.

**How to use:** work top to bottom. Any **✗ (fail)** is an exception — record it,
assign an owner and a due date, and where the risk is material, **remove or
disable the access until it is re-justified**. The default answer to "should this
access still exist?" is *no* unless someone actively attests *yes*.

---

## A. Scope & preparation

- [ ] The review covers the **whole estate**: the Log Analytics workspace, the
      Sentinel workspace roles, the playbook resource group, the deployment
      identity, and any Entra/Defender-plane grants (Security Reader / Admin).
- [ ] The current assignment list is exported and diffed against
      [sample-rbac-assignments.json](sample-rbac-assignments.json) (the intended
      state). Every *actual* assignment maps to an *intended* one.
- [ ] The reviewer is **not** reviewing their own access — separation of duties
      applies to the review itself.
- [ ] The date, reviewer and scope are recorded before starting.

## B. Least privilege — role right-sizing

- [ ] Every persona holds the **narrowest built-in role** that lets them do their
      job (Reader < Responder < Contributor). No one is over-roled "to be safe".
- [ ] **No custom roles** are in use where a built-in role would do; any custom
      role has a documented justification and an explicit permission list.
- [ ] Nobody holds a role they have not exercised in the review period without a
      written reason (e.g. break-glass is *meant* to be unused).
- [ ] **Contributor is limited to detection engineers and the deployment
      identity.** No analyst holds Sentinel Contributor.
- [ ] Analysts (Readers) genuinely cannot run response actions or change incident
      ownership on their own — verify against the matrix, not assumptions.

## C. Least privilege — scope right-sizing

- [ ] **No assignment at subscription, management-group or tenant scope.** Every
      grant is workspace-, resource-group- or directory-scoped.
- [ ] Any subscription-level *placeholder* in the intended state is `sub-lab` or
      the all-zero GUID — a **real subscription ID would be a finding** (there is
      no real subscription in this lab).
- [ ] The deployment identity's scope is **workspace + playbook RG only** — no
      scope creep into other resource groups or the subscription.
- [ ] Broad-reach Entra roles (Security Reader / Security Admin) are held by the
      **fewest** people necessary and are directory-scoped, not global-by-habit.

## D. Separation of duties

- [ ] **Author ≠ deployer:** the person who authors/merges a detection is not the
      identity that writes it to the workspace.
- [ ] **Author ≠ change approver:** the playbook author does not approve their own
      playbook change.
- [ ] **Incident raiser ≠ destructive-run approver:** the analyst who raises an
      incident cannot self-approve a destructive playbook (disable user / reset /
      role removal) against that incident.
- [ ] **No single human holds two of {Deploy, Approve, Break-glass}.**
- [ ] The approval gates (pipeline change gate + run-time destructive gate) are
      still enforced and route to a *different* person than the requester.

## E. Automation / deployment identity

- [ ] `svc-sentinel-deploy` is **non-interactive** — it is not used as a person's
      login and has no interactive sign-in.
- [ ] Its role set is still the minimum (Sentinel Contributor + Logic App
      Contributor, workspace/RG scope) — nothing added "temporarily" and left.
- [ ] Its credential/secret is rotated on schedule; the rotation date is recorded.
      (No secret is stored in the repo — verify none has crept in.)
- [ ] It is the **only** principal that writes analytics rules to the workspace;
      no human has been granted an equivalent standing write path outside the
      pipeline.
- [ ] Pipeline deploy runs are logged and attributable to a specific change.

## F. Break-glass account

- [ ] `break-glass-01@contoso.com` is **currently disabled**.
- [ ] It is held by **no working human** as a day-to-day identity.
- [ ] Its Owner assignment is **workspace-scoped only** (all-zero GUID
      placeholder) — never subscription or tenant Owner.
- [ ] Its credential is intact/sealed (or was rotated on schedule); the custody
      record is verified. No credential material is in the repo.
- [ ] Its Conditional Access exclusion is still correct and still monitored
      (tampering would trip DET-003).
- [ ] **Every use since the last review has a completed blameless RCA**, a
      credential rotation, and a re-disable. Any un-RCA'd use is a Critical
      finding.
- [ ] Enable/sign-in alerting on the account is confirmed to still fire to the
      SecOps Manager and platform admin.

## G. Standing privilege & time-bounding

- [ ] Every assignment **above Reader** has a live business justification and a
      named owner.
- [ ] Elevations above read are **time-bound** (expiry set, ideally PIM-eligible
      rather than a permanent standing grant).
- [ ] No assignment is **past its `review_due`** without an attestation; any that
      is gets removed pending re-justification.
- [ ] Stale grants (role no longer matches the person's function) are removed, not
      "left in case".

## H. Joiner / mover / leaver hygiene

- [ ] **Joiners** received access starting at the floor (Reader) and were widened
      only with justification.
- [ ] **Movers** (role changes) had their old access **re-scoped**, not merely
      added to — no accumulation of privilege across roles.
- [ ] **Leavers** had access **fully revoked the same day** they left. Verify no
      orphaned assignment remains for anyone who has departed.
- [ ] No shared or generic human accounts exist (the deployment and break-glass
      identities are the only non-personal principals, and both are purpose-built).

## I. Evidence, logging & closure

- [ ] The workspace and directory activity logs show that privileged actions
      (rule deploys, destructive playbook runs, break-glass enables) are
      **attributable** to a specific principal.
- [ ] Read access to logs does not silently include write — Reader roles were
      confirmed read-only in practice, not just in name.
- [ ] Every ✗ finding from sections B–H has an **owner and a due date** and is
      tracked to closure at the weekly operations review.
- [ ] The completed checklist, the assignment diff, and the finding list are
      recorded, and the next `review_due` dates are set.

---

## Sign-off

| Field | Value |
|-------|-------|
| Review type | Quarterly / On-event (JML) / Annual recertification |
| Estate reviewed | Log Analytics workspace · Sentinel workspace · Playbook RG · Deploy identity · Entra grants |
| Reviewer | *(named security-team persona, not self-reviewing)* |
| Date | |
| Findings (✗) count | |
| All findings owned & dated | ☐ Yes ☐ No |
| Next review due | |

The point of the sign-off is accountability: a named person attests, on a date,
that the estate matches the least-privilege model in
[RBAC_REVIEW_MODEL.md](RBAC_REVIEW_MODEL.md) — or lists exactly where it does not
and who is fixing it.
