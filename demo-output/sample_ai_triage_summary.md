# AI triage briefing - INC-1003 (offline deterministic mode)

Generated locally from the incident context; no data left this machine.

## a. Executive summary
Correlated identity attack (3 detections) - amelia.chen@contoso.com: 3 correlated alert(s) (AL-002-0002 (Impossible Travel Sign-in, Critical); AL-001-0001 (MFA Fatigue (Push Bombing), Critical); AL-002-0003 (Impossible Travel Sign-in, Critical)) affecting amelia.chen@contoso.com. Overall severity Critical. The activity maps to MITRE ATT&CK T1078.004, T1621. Containment and remediation guidance follows; disposition is pending analyst confirmation.

## b. Likely cause
An attacker holding a valid password generated repeated MFA push prompts until the user approved one (MFA fatigue). Confidence: high, given the deny burst followed by an approval from the same foreign IP.

Sign-ins from two locations faster than physical travel allows - either session/token use from attacker infrastructure or VPN egress. Confidence: medium until the second IP is attributed.

## c. Affected identities and assets
- Identity: amelia.chen@contoso.com
- Source IPs: 192.0.2.199, 203.0.113.21

## d. MITRE ATT&CK mapping
- DET-002 -> T1078.004 (InitialAccess, DefenseEvasion)
- DET-001 -> T1621 (CredentialAccess)
- DET-002 -> T1078.004 (InitialAccess, DefenseEvasion)

## e. Recommended containment (least destructive first)
- Revoke all refresh tokens and active sessions (approval: none needed)
- Disable the account if compromise is confirmed (approval: DRI)
- Block the attacker IP at Conditional Access named locations
- Revoke sessions if the foreign IP is not corporate egress
- Mark the account at-risk in Microsoft Entra ID Protection

## f. Recommended remediation and hardening
- Reset credentials and re-register MFA methods
- Move the user to phishing-resistant MFA (passkeys or FIDO2)
- Enable Entra ID Protection sign-in risk policies
- Add confirmed corporate VPN egress ranges to the rule exclusions
- Require compliant device for the affected application

## g. Root-cause analysis questions
- Which control should have prevented the initial access, and why did it not?
- Was detection latency acceptable (compare created vs acknowledged timestamps)?
- Do any of the triage steps need automation to reduce time-to-contain?
- What tuning or coverage gap did this incident expose?

## h. False-positive checks
- Did the user trigger the prompts themselves from a new device?
- Was there a helpdesk-driven re-enrolment at the same time?
- Are both IPs inside the corporate VPN egress range 198.51.100.0/24?
- Does the device fingerprint match the user's usual hardware?
