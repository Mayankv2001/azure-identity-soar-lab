# Root cause analysis - CP-INC-2001

Blameless RCA for the synthetic control-plane attack chain. Focus is on the controls that failed, not the person who clicked.

## What happened

A high-risk sign-in for chris.walker@contoso.com from an unusual country was followed by an MFA-fatigue approval, a ticketless privileged-role activation, a credential added to a high-privilege service principal, an Owner grant on a synthetic cloud-management resource group, and an NSG rule opening RDP to the internet on a reachable management jumpbox. Eight detections correlated into one Critical incident with a blast-radius score of 100/100.

## Root causes (controls that failed)

1. **Standing Contributor on sp-infra-deploy.** The service principal held broad standing rights, so a single added secret unlocked control-plane changes. Fix: least-privilege scoping and managed identities where possible.
2. **Ticketless PIM activation.** Application Administrator activated with no linked change record. Fix: require justification/ticket binding and approval on protected-role activation.
3. **No policy denying public management exposure.** An NSG rule exposing RDP to 0.0.0.0/0 was accepted. Fix: Azure Policy to deny or audit internet-wide inbound on management ports (see iac/).
4. **Phishing-vulnerable MFA.** MFA fatigue succeeded. Fix: phishing-resistant methods and risk-based Conditional Access.

## Hardening recommendations (advisory - require human approval to apply)

- Convert sp-infra-deploy to least-privilege, scoped, short-lived credentials.
- Enforce ticket-bound, approval-gated PIM activation for protected roles.
- Deploy Azure Policy denying public inbound on management ports across the subscription.
- Add alert-volume canaries so a new public NSG rule pages before it is exploited.
- Feed each root cause back as a versioned detection or policy change.

## Detection performance

- Stages detected: 7 of 7 telemetry stages, correlated into one incident.
- Time from first stage to correlated Critical incident: 2026-06-30T09:00:00Z -> 2026-06-30T10:20:00Z.
- Gap to close next: no detection yet for the actual RDP brute-force post-exposure; add a follow-on behavioural rule.
