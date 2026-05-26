# docs/INCIDENT-RESPONSE.md

## Purpose

This document provides an incident response guide for **`kanidm_radsec_edge`** operating as a **Kanidm-aware, EAP-TLS-only RadSec edge service**.

It is intended to help responders classify, triage, contain, recover, and review incidents involving:

- service availability,
- TLS / peer trust failures,
- malformed or abusive traffic,
- EAP policy violations,
- upstream Kanidm dependency failures,
- queue/state anomalies,
- and crypto / PQ-readiness governance issues.

This runbook assumes the service is deployed with local config/certificate material under `/etc/radsec`, uses `RADSEC_CONFIG` or the default config path, and relies on a mutually authenticated TLS boundary plus transparent upstream RADIUS exchange to Kanidm. 【1-16afd1】【2-8b0b1e】【1-35fbe7】【3-76da63】【1-5e9a96】

---

## Incident Handling Principles

- **Fail closed**: do not weaken peer policy, EAP-TLS-only policy, or packet validation as an emergency shortcut unless explicitly approved at the correct authority level. The edge is intended to reject malformed, unsupported, or upstream-failed flows by design. 【1-5e9a96】【5-bb3d22】【4-eb5103】
- **Preserve trust boundaries**: the edge owns transport and enforcement; Kanidm owns identity and backend EAP-TLS authority. Do not conflate responsibilities during incident response. 【4-eb5103】【5-bb3d22】
- **Treat queue/state anomalies as meaningful signals**: bounded queues and explicit state transitions are part of the safety model, not incidental implementation details. 【1-5e9a96】
- **Use controlled rollback over ad hoc weakening** whenever possible.
- **Preserve evidence**: logs, config versions, image digests, certificate fingerprints, and timeline notes should be retained for post-incident review.

---

## Incident Severity Template

### Severity 1 — Critical
Examples:
- widespread outage
- all peers failing TLS or auth flow
- sustained inability to reach Kanidm backend
- severe, unexplained reject spike impacting production users broadly

### Severity 2 — High
Examples:
- limited but material peer population affected
- repeated queue/state anomalies
- repeated unexpected Access-Reject behavior
- TLS trust issue affecting specific trusted peers

### Severity 3 — Moderate
Examples:
- isolated peer-policy mismatch
- canary or staging issue
- localized malformed traffic or queue pressure
- recoverable deployment/config issue

### Severity 4 — Low
Examples:
- informational anomaly
- trend review item
- pre-expiry or pre-capacity warning
- documentation/process deviation without current impact

---

## Initial Triage Checklist

At incident declaration, collect:

- [ ] timestamp and timezone
- [ ] affected environment(s)
- [ ] affected peer(s) or source subnet(s)
- [ ] affected upstream Kanidm instance(s)
- [ ] deployment version / image digest
- [ ] current config version
- [ ] certificate/trust-set version identifiers
- [ ] recent change records
- [ ] log excerpts and alert details
- [ ] current severity classification

---

## Incident Categories

---

## 1. Service Fails to Start

### Symptoms
- process exits immediately
- crash loop in container/orchestrator
- no listener bound on expected port
- startup log contains config or key permission error

### Likely causes
- invalid TOML config
- missing config file
- missing certificate/key file
- private-key permissions too loose
- invalid TLS material
- port conflict
- runtime mount/path issue

### Immediate actions
1. Review startup logs from the current deployment. The application explicitly loads config, checks key permissions, builds TLS config, then starts the server. 【1-16afd1】【1-35fbe7】【3-76da63】
2. Confirm config file exists at `RADSEC_CONFIG` or `/etc/radsec/config.toml`. 【1-16afd1】【2-8b0b1e】
3. Confirm `/etc/radsec/server.key` exists and has mode `0400` or `0600`. 【1-35fbe7】
4. Confirm server cert and client CA files exist and are readable. 【2-8b0b1e】【3-76da63】
5. Confirm listener port is not already in use.

### Containment
- stop repeated restart churn if it is causing noise or resource pressure
- avoid opportunistic config edits without version control/change note

### Recovery
- restore last known good config and cert set
- redeploy last known good image if a new artifact introduced the issue
- restart and validate startup path

### Escalation
- platform/runtime owner for container or host issues
- PKI owner for certificate/key problems
- application maintainer for parser / config-model defect suspicion

---

## 2. TLS Handshake Failures Spike

### Symptoms
- sudden increase in TLS handshake failures
- trusted peers stop connecting
- listener remains up but sessions fail before packet processing

### Likely causes
- trusted client CA rotated incorrectly
- peer certificates expired or changed
- peer no longer matches fingerprint/SAN policy
- TLS interoperability regression
- network device/client config drift
- middlebox/network path interference

### Immediate actions
1. Identify affected peer(s), source IPs, and timestamps.
2. Review logged peer fingerprint/SAN data for changed or unknown peers. Current design extracts peer identity metadata from the presented certificate and applies policy checks. 【3-76da63】【1-5e9a96】
3. Confirm current trusted client CA bundle matches policy.
4. Confirm peer certificate validity/expiry with PKI owner.
5. Check for recent config or certificate rotation changes.

### Containment
- rollback recent trust/policy changes if clearly implicated
- do **not** broadly disable peer policy without formal authorization
- if only a subset of peers are affected, isolate the problem peer class rather than weakening system-wide controls

### Recovery
- restore correct trust anchors
- restore correct peer-policy inventory
- redeploy last known good config if change-induced
- validate with a known-good peer and then broaden validation

---

## 3. Unsupported EAP / EAP Policy Reject Spike

### Symptoms
- sudden increase in rejects tied to EAP policy
- peers connect but authentication fails immediately
- controllers or supplicants report auth failure while transport remains healthy

### Likely causes
- peer or supplicant sending PEAP/TTLS/MSCHAP or other unsupported methods
- misconfigured controller profile
- client policy drift
- fallback behavior introduced by a network change

### Immediate actions
1. Review reject reason logs and identify EAP method observed. The edge is designed to allow only **EAP-TLS**, consistent with the intended deployment posture and Kanidm’s documented EAP-TLS role. 【5-bb3d22】【4-eb5103】
2. Identify the responsible peer/controller or client population.
3. Validate controller and supplicant configuration for EAP-TLS.
4. Check whether recent client or controller policy changes were deployed.

### Containment
- contain the misconfigured peer or SSID/policy group
- avoid disabling EAP-TLS-only enforcement as an emergency shortcut unless explicitly authorized

### Recovery
- correct peer/supplicant config
- validate controlled canary auth flow
- confirm reject rate returns to baseline

---

## 4. Upstream Kanidm Timeout / Dependency Failure

### Symptoms
- increased upstream timeout errors
- elevated local reject behavior
- high upstream RTT in metrology
- broad auth failures despite healthy outer TLS

### Likely causes
- Kanidm backend overload or outage
- network segmentation/routing/firewall issue
- upstream address misconfiguration
- resource exhaustion on backend or edge path
- upstream shared secret mismatch

### Immediate actions
1. Review current upstream timeout and RTT trends in logs/metrology.
2. Confirm configured `[upstream]` address is still correct.
3. Validate route/firewall path to Kanidm backend.
4. Confirm shared secret alignment between edge and backend. Transparent proxying depends on that alignment unless packet re-signing exists. 【1-5e9a96】【4-eb5103】
5. Engage Kanidm/backend owners.

### Containment
- if change-induced, rollback recent edge or network change
- if backend is degraded, consider controlled traffic reduction or failover outside the edge if supported by the environment

### Recovery
- restore backend availability
- restore route/firewall correctness
- revalidate known-good end-to-end challenge/accept flow
- monitor for residual reject spikes after backend recovery

---

## 5. Unexpected Access-Reject Spike

### Symptoms
- Access-Reject rate rises sharply
- production users/devices lose network access
- service remains up, but success rate drops materially

### Likely causes
- backend identity/authorization issue in Kanidm
- EAP policy issue at the edge
- peer trust or packet-integrity issue
- shared secret mismatch
- malformed or abusive traffic burst
- change regression

### Immediate actions
1. Classify reject reasons:
   - peer policy
   - `Message-Authenticator` invalid
   - unsupported EAP
   - upstream failure
   - invalid upstream response
2. Compare reject categories before/after latest change.
3. Confirm backend Kanidm health and shared secret alignment.
4. Review queue-drop and state-violation counters for correlated anomalies.

### Containment
- isolate the responsible peer population if identifiable
- pause recent rollout if change-induced
- avoid broad trust-policy weakening without explicit approval

### Recovery
- correct underlying category (trust, EAP, backend, shared secret, route, or rollback)
- validate with canary peers
- confirm baseline success rate restoration

---

## 6. Queue Drop Spike

### Symptoms
- `queue_drop_control`, `queue_drop_shadow`, or `queue_drop_metrics` increases
- reduced observability fidelity
- increased risk of losing internal telemetry under burst load

### Meaning
Bounded queues are intentional and part of the safety model. A queue drop is a **signal of pressure**, not proof of data-plane failure.

### Immediate actions
1. Identify which queue is dropping.
2. Review traffic burst pattern and current host/container resource usage.
3. Review whether a recent deployment changed queue capacity, logging rate, or traffic mix.
4. Confirm the live data plane is still healthy.

### Containment
- if data plane remains healthy, prioritize stability over overreacting to telemetry loss
- do **not** replace bounded queues with unbounded queues as an emergency action

### Recovery
- scale resources or adjust queue sizing through controlled change
- reduce avoidable log/event volume if appropriate
- validate queue baseline after change

---

## 7. State Violation / Illegal Transition Anomaly

### Symptoms
- `state_violations` increase
- unexpected session-state transition logs
- shadow/data-path divergence suspicion
- unusual parser or protocol behavior under load or malformed traffic

### Likely causes
- malformed traffic campaign
- implementation defect or regression
- race/timeout edge case
- unexpected peer behavior
- control-plane pressure or logic mismatch

### Immediate actions
1. Review recent deployment changes and regression test status.
2. Identify affected peer(s) or source IPs.
3. Review correlated malformed traffic or unsupported EAP logs.
4. Preserve relevant logs and packet timeline references for engineering review.

### Containment
- if tied to a malicious or malformed source, block or isolate that source at network boundary
- if tied to a release, consider rollback to last known good version

### Recovery
- reproduce or validate in staging using regression corpus or controlled replay tooling outside production
- patch or rollback as appropriate
- monitor `state_violations` after remediation

---

## 8. Suspected Malformed Traffic / Abuse Campaign

### Symptoms
- malformed packet rejects spike
- handshake rates spike abnormally
- queue pressure rises
- source IP concentration or distributed pattern emerges

### Immediate actions
1. Identify source distribution and affected peers.
2. Confirm rate limiter behavior is functioning. The service includes bounded per-IP rate limiting to reduce connection abuse before deeper processing. 【1-5e9a96】
3. Correlate malformed packet classes and handshake failures.
4. Apply network-level containment if source is unauthorized or malicious.

### Containment
- block/limit hostile sources upstream of the service if possible
- preserve logs and timestamps
- do not weaken parser or EAP policy to “let traffic through”

### Recovery
- maintain block until traffic normalizes
- run corpus regression checks if implementation fragility is suspected
- review capacity and alerting thresholds after event

---

## 9. Certificate or Trust Material Compromise Suspicion

### Symptoms
- unexpected trusted peer identity appears
- unexplained successful connections from unrecognized peer
- key or trust-anchor custody concern
- unauthorized CA/trust set change suspected

### Immediate actions
1. Treat as a security incident immediately.
2. Preserve current logs, config, and file metadata.
3. Verify current trust-anchor and fingerprint policy against approved source.
4. Rotate affected certificates/keys if compromise is plausible.
5. Review recent config and artifact changes.

### Containment
- remove/replace compromised trust material
- suspend affected peer class if needed
- redeploy known-good trust set
- escalate to PKI/security governance immediately

### Recovery
- restore approved trust material
- validate trusted peer inventory
- conduct full post-incident review and impact scoping

---

## 10. PQ-Readiness Governance Incident

### Examples
- unapproved PQ-related TLS/provider change
- incorrect claim that PQ is enabled or validated in production
- interoperability failure caused by premature hybrid PQ rollout

### Immediate actions
1. Determine whether the incident is technical, procedural, or both.
2. Confirm actual deployed cryptographic profile and dependency versions.
3. Suspend unauthorized PQ-related rollout if necessary.
4. Revert to approved profile if interoperability or stability is impacted.

### Recovery
- document actual current cryptographic state
- restore approved TLS/provider configuration
- re-run staged validation in pre-production
- update PQ migration plan and change governance to prevent recurrence

### Key principle
PQ readiness is a **controlled migration posture**, not an excuse for unreviewed cryptographic change. 【7-56d833】【8-2a30d6】【9-20b314】【10-fd7f79】

---

## Evidence Preservation Checklist

For any non-trivial incident, preserve:

- [ ] deployment version / image digest
- [ ] config version/hash
- [ ] relevant certificate fingerprints / trust set identifiers
- [ ] timestamps and timezone
- [ ] affected peers / source IPs
- [ ] key log excerpts
- [ ] metrology snapshot around incident window
- [ ] queue-drop and state-violation counters
- [ ] related change records
- [ ] rollback or recovery actions performed

---

## Communications Checklist

During active incident handling:

- [ ] identify incident commander / lead
- [ ] establish primary technical channel
- [ ] establish stakeholder update interval
- [ ] identify PKI owner, platform owner, and Kanidm owner contacts
- [ ] avoid speculative statements about root cause
- [ ] record timeline continuously

---

## Post-Incident Review Checklist

After stabilization:

- [ ] confirm service healthy and stable
- [ ] validate known-good peer and auth flow
- [ ] capture root cause (or current best known cause)
- [ ] capture contributing factors
- [ ] document containment and recovery timeline
- [ ] identify preventive actions
- [ ] update runbooks/checklists if needed
- [ ] update PQ migration governance docs if relevant
- [ ] archive evidence

---

## Decision Guidance: Rollback vs Continue Troubleshooting

### Prefer rollback when
- recent change correlates strongly with incident start
- outage or auth failure is broad
- last known good version is available and validated
- cause is not yet isolated
- trust or PKI correctness is uncertain after recent change

### Prefer continue troubleshooting when
- issue is clearly isolated to a small peer set
- recent change is not implicated
- rollback would introduce greater risk
- root cause is already narrow and likely resolvable safely in place

---

## Escalation Matrix Template

### Platform / runtime team
Use for:
- host/container failure
- filesystem or mount issues
- port conflicts
- runtime resource exhaustion

### PKI / security engineering
Use for:
- certificate validity issues
- trust-anchor problems
- fingerprint/SAN policy mismatch
- suspected trust material compromise

### Kanidm / identity team
Use for:
- backend RADIUS failure
- backend auth anomalies
- EAP-TLS authority issues
- authorization anomalies

### Application maintainers
Use for:
- parser defect suspicion
- state-machine anomalies
- shadow/data-path divergence
- release regression
- queue-behavior defects

---

## Summary

Incident response for `kanidm_radsec_edge` should preserve four priorities:

1. **Maintain trust boundaries**
2. **Fail closed safely**
3. **Preserve evidence**
4. **Prefer controlled rollback over ad hoc weakening**

Operate the edge as a high-assurance transport and enforcement component:

- keep peer trust strict,
- keep EAP-TLS-only policy intact unless formally changed,
- treat queue and state anomalies as real signals,
- and manage PQ readiness as a governed migration program rather than an implicit feature toggle. 【4-eb5103】【5-bb3d22】【6-ab48bc】【7-56d833】【8-2a30d6】【9-20b314】
