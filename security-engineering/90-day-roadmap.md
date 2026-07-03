# 90-day improvement roadmap

How I would add value in the first 90 days - written against this project, and
directly transferable to a real Microsoft CO+I security operations team. The
shape is deliberate: earn context before opinions, take the pager with a safety
net, then own end-to-end improvements.

## Days 1-30: learn the environment, earn trust

- **Learn the estate.** Map the detection inventory: which rules earn their alert
  volume and which just spend it. In this repo that is the detection quality
  scorecard; in a real team it is the analytics-rule catalogue and its precision.
- **Shadow on-call.** Work incidents as second chair; learn the escalation paths,
  the tooling and the unwritten norms before I touch the pager.
- **Review the last quarter of RCAs.** Root causes repeat; the RCA backlog is the
  fastest way to learn where the real risk and the real toil are.
- **Understand the detection estate.** For every high-volume rule, learn its
  false-positive rate and its owner.
- **Deliverable:** a written map of the top noisy detections and the top recurring
  root causes - my first evidence-based point of view.

## Days 31-60: take the pager, cut the noise

- **Identify noisy detections.** Pick the highest false-positive contributors
  from the day-1-30 map.
- **Tune false positives.** Ship one narrow, versioned, tested exclusion through
  the pipeline - the way this repo does the DET-002 VPN-egress exclusion, which
  removed the seeded false-positive class through a narrow tuning rule with zero
  lost true positives. No broad suppression.
- **Build one automation.** Eliminate a piece of manual toil - an enrichment
  step, a repetitive triage lookup - the way my CyberArk lifecycle automation
  removed ~100 engineer-hours a month.
- **Improve one SOAR playbook.** Tighten one response workflow's
  automate-vs-approve boundary or add missing enrichment.
- **Deliverable:** one measurable noise reduction and one automation in
  production, with before/after metrics.

## Days 61-90: own end-to-end improvement

- **Document one incident packet.** Take a real incident from alert to RCA and
  produce a handover packet like the CP-INC-2001 packet in this repo - so the
  next responder starts warm.
- **Propose one prevention control.** Turn a recurring root cause into a
  preventive policy (the prevention-controls folder is the pattern) - moving the
  team from detecting to preventing.
- **Ship a new detection end-to-end.** From proposal through peer review, staging
  validation and the promotion checklist to an approval-gated deployment, with a
  post-deployment monitoring plan.
- **Deliverable:** one prevention control proposed or shipped, and one detection
  in production with my name on the review.

## Metrics I would move

| Metric | Why it matters |
|--------|----------------|
| MTTD (mean time to detect) | Faster detection shrinks attacker dwell time |
| MTTR (mean time to respond) | Faster, safer containment limits blast radius |
| SLA adherence | The promise the team is held to; measured against the paging matrix |
| False-positive rate | Noise reduction is what buys back analyst attention |
| Detection coverage (MITRE) | Visible gaps become the next detections to build |
| Preventive controls enforced | The leading indicator that the team is reducing incidents, not just closing them |

## How this maps to joining Microsoft

The through-line is the hiring manager's brief: builders who automate manual
processes, improve detection, and think in operational excellence. My production
strength is identity and privileged-access automation; this roadmap shows how I
extend that into cloud security engineering - learning the environment fast,
cutting noise, automating toil, and closing the loop from incident to prevention.
