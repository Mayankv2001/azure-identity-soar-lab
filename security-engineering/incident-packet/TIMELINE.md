# Timeline - CP-INC-2001

Synthetic. All times UTC, 2026-06-30. Local time (Australia/Sydney) is UTC+10.

## Attack timeline (detection stages)

| Time (UTC) | Stage | Detection | Entity | What the attacker did |
|------------|-------|-----------|--------|-----------------------|
| 09:00 | 1 | CP-DET-001 | chris.walker@contoso.com | High-risk sign-in from Latvia (unusual country) succeeds |
| 09:02 | 2 | CP-DET-002 | chris.walker@contoso.com | First failed strong-auth prompt |
| 09:03-09:09 | 2 | CP-DET-002 | chris.walker@contoso.com | Four more failed prompts (MFA fatigue) |
| 09:11 | 2 | CP-DET-002 | chris.walker@contoso.com | User approves a prompt - account taken over |
| 09:25 | 3 | CP-DET-003 | chris.walker@contoso.com | Application Administrator activated via PIM, no ticket |
| 09:40 | 4 | CP-DET-004 | sp-infra-deploy | Client secret added to high-privilege service principal |
| 10:05 | 5 | CP-DET-005 | rg-prod-dc-mgmt | sp-infra-deploy granted Owner on the management RG |
| 10:20 | 6 | CP-DET-006 | nsg-prod-dc-mgmt | NSG rule opens RDP 3389 to 0.0.0.0/0 |
| 10:20 | 7 | CP-DET-007 | vm-dc-mgmt-01 | Management endpoint now reachable from the internet |
| 10:40 | 8 | Defender for Cloud | vm-dc-mgmt-01 | Unusual inbound traffic to the management port flagged |

## Response timeline (synthetic, illustrative)

| Time (UTC) | Actor | Action | Approval class |
|------------|-------|--------|----------------|
| 10:41 | SOAR (CP-PB-01/02/03) | Page DRI, open ticket, enrich + blast radius | automatic |
| 10:43 | SOAR (CP-PB-04) | Revoke sessions for chris.walker | automatic (Critical) |
| 10:52 | DRI + network on-call | Revert NSG rule (snapshot first) | human approval |
| 11:04 | DRI + app owner | Remove attacker SP credential, rotate secrets | human approval |
| 11:10 | DRI | Remove Owner assignment, deactivate PIM role | human approval |
| 11:20 | DRI + workload owner | Confirm no successful RDP login; JIT-lock the endpoint | human approval |
| 12:00 | DRI | Open blameless RCA task | manual |

## Time-to-detect and time-to-contain

- First malicious event: 09:00. Correlated Critical incident raised: 10:40.
- Sessions revoked: 10:43 (3 minutes after correlation).
- Full containment approved and applied: ~11:20.

The gap worth discussing in an RCA: the chain ran for 100 minutes before the
correlated incident fired, because the earlier single-stage alerts were
individually sub-Critical. The improvement is to raise correlation severity as
soon as stage 4 (SP credential on a high-privilege principal) chains with a
stage-1/2 identity compromise, rather than waiting for the exposure at stage 7.
