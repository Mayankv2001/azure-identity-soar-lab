# Executive summary - CP-INC-2001

Synthetic incident. One page for non-technical leadership.

## What happened, in plain terms

An attacker got hold of one engineer's login. Because that login could be
approved with a simple phone prompt, the attacker wore the engineer down with
repeated prompts until one was accepted. From there, they used the access to
give themselves broader permissions and briefly opened a remote-access door to a
sensitive datacenter management server - exposing it to the internet for about
twenty minutes before it was caught and closed.

## Why it matters

This is the pattern behind most serious cloud incidents: it starts with an
identity, not a firewall. One compromised login became infrastructure exposure.
The affected server manages datacenter operations, so the potential impact was
high even though no confirmed damage occurred in this (synthetic) exercise.

## How it was handled

- The suspicious activity was automatically detected and connected into a single
  high-priority incident, rather than sitting as scattered low-level alerts.
- The engineer's active sessions were cut off automatically within minutes.
- A human responder then approved each higher-risk step - closing the internet
  exposure, removing the extra permissions, and locking down the server -
  because those actions could themselves cause an outage if done carelessly.

## What we are changing to prevent a repeat

1. **Stronger sign-in** for operations staff, so a login cannot be approved by a
   simple prompt an attacker can spam.
2. **A guardrail** that automatically blocks anyone - including an attacker -
   from exposing management servers to the internet in the first place.
3. **Tighter permissions** so that a single compromised account cannot reach so
   far so fast.

## The one-line takeaway

We caught and contained a realistic identity-to-infrastructure attack, and we
are turning what we learned into automatic guardrails - so the next attempt is
stopped before it starts, not just detected after it happens.

## Measures of success (next 90 days)

- Management servers cannot be exposed to the internet by policy.
- Operations staff use phishing-resistant sign-in.
- Time from first suspicious event to a connected high-priority incident drops
  from ~100 minutes to under 30.
