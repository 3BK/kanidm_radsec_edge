# docs/OPERATIONS-CHECKLIST.md

## Purpose

This checklist is intended for day-2 operations of **`kanidm_radsec_edge`** as a **Kanidm-aware, EAP-TLS-only RadSec edge service**. It is designed for operators, platform engineers, on-call responders, and security personnel responsible for production reliability, controlled change, and high-assurance runtime hygiene. The service is expected to run with `RADSEC_CONFIG` or the default `/etc/radsec/config.toml`, and to consume local certificate/key material from `/etc/radsec/`. 【1-16afd1】【2-8b0b1e】【1-35fbe7】

> Use this checklist for:
>
> - daily/shift operations
> - startup verification
> - post-change validation
> - certificate/PKI hygiene review
> - monitoring and metrology review
> - pre-maintenance and rollback readiness
> - PQ-readiness governance tracking

---

## 1. Daily / Shift Checklist

### Service health
- [ ] Confirm service is **running** and not crash-looping. 【1-5e9a96】【1-16afd1】
- [ ] Confirm listener is bound to the configured RadSec address/port (default pattern: `TCP 2083`). 【2-8b0b1e】【1-5e9a96】
- [ ] Confirm no unexpected restart count increase in runtime/orchestrator. 【1-5e9a96】【1-16afd1】
- [ ] Confirm CPU and memory usage remain within expected baseline for current traffic. 【1-5e9a96】

### TLS and peer trust
- [ ] Review successful vs failed TLS handshake trends. The edge is intended to enforce **TLS 1.3**, mutual client certificate validation, and peer policy checks. 【3-76da63】【1-5e9a96】
- [ ] Review peer-policy rejects (fingerprint mismatch, SAN mismatch, or other trust-policy failures). 【3-76da63】【1-5e9a96】
- [ ] Confirm no unexpected new peer fingerprints or SAN patterns appear in logs. 【3-76da63】【1-5e9a96】

### Protocol hygiene
- [ ] Review reject trends for malformed RADIUS packets, invalid attribute lengths, unsupported RADIUS codes, or EAP policy failures. The edge is designed to fail closed on those conditions. 【1-5e9a96】【5-bb3d22】【4-eb5103】
- [ ] Confirm there are no spikes in unsupported EAP methods; the intended policy is **EAP-TLS only**. 【5-bb3d22】【4-eb5103】
- [ ] Confirm `Message-Authenticator` validation failures are not increasing unexpectedly. 【1-5e9a96】

### Upstream health
- [ ] Review Kanidm upstream response timing and timeout rates. The edge transparently proxies valid requests to the Kanidm RADIUS backend. 【1-5e9a96】【4-eb5103】【5-bb3d22】
- [ ] Confirm upstream reachability and no abnormal `Access-Reject` spikes that correlate with backend degradation. 【1-5e9a96】【4-eb5103】

### Control plane / NDT / metrology
- [ ] Review queue-drop counters (`control`, `shadow`, `metrics`) and confirm they remain within baseline. The bounded queue model is intentional and should not be bypassed. 【1-5e9a96】
- [ ] Review `state_violations` or state-machine anomalies. Illegal session transitions are security-relevant and should be investigated. 【1-5e9a96】【5-bb3d22】
- [ ] Confirm periodic metrology flush events continue to appear. 【1-16afd1】【1-5e9a96】

---

## 2. Startup Checklist

### Config and filesystem
- [ ] Confirm `RADSEC_CONFIG` is set correctly if overriding the default path. 【1-16afd1】
- [ ] Confirm `/etc/radsec/config.toml` exists if using the default path. 【1-16afd1】【2-8b0b1e】
- [ ] Confirm `/etc/radsec/server.pem`, `/etc/radsec/server.key`, and `/etc/radsec/client_ca.pem` exist and are readable by the service user. 【2-8b0b1e】【3-76da63】
- [ ] Confirm the private key file mode is `0400` or `0600`; the service enforces a restrictive permission check at startup. 【1-35fbe7】

### TLS bootstrap
- [ ] Confirm TLS material loads without error.
- [ ] Confirm the service starts with **TLS 1.3** policy and mutual client certificate verification. 【3-76da63】
- [ ] Confirm the intended peer-policy constraints (fingerprint / SAN rules) are loaded for the environment. 【3-76da63】【1-5e9a96】

### Runtime posture
- [ ] Confirm service is running as **non-root**.
- [ ] Confirm `/etc/radsec` is mounted **read-only** where containerized.
- [ ] Confirm the root filesystem is **read-only** where supported.
- [ ] Confirm no unnecessary capabilities or privileges are present in the container/host service definition.

### Initial functional validation
- [ ] Confirm listener bind success in logs. 【1-5e9a96】【1-16afd1】
- [ ] Confirm at least one known-good peer can establish a TLS session. 【3-76da63】【1-5e9a96】
- [ ] Confirm a known-good EAP-TLS request path can reach Kanidm and produce the expected Access-Challenge / Access-Accept behavior. 【4-eb5103】【5-bb3d22】【1-5e9a96】

---

## 3. Weekly Checklist

### Configuration and artifact integrity
- [ ] Compare deployed config against approved source of truth.
- [ ] Confirm image/binary digest matches approved deployment artifact.
- [ ] Confirm no unauthorized drift in container runtime posture, service unit, or mounted paths.
- [ ] Confirm log forwarding / SIEM ingestion is healthy and complete.

### PKI hygiene
- [ ] Review certificate expiry horizon for:
  - edge server certificate
  - trusted client CA bundle
  - peer enrollment expectations
- [ ] Confirm no emergency or ad hoc trust-anchor changes were applied outside process.
- [ ] Confirm peer certificate naming/fingerprint inventory remains current.

### Regression and assurance
- [ ] Review results of parser / malformed corpus regression tests.
- [ ] Review results of NDT shadow-path observations if tracked operationally.
- [ ] Confirm no sustained growth in rejects due to malformed packets, unsupported EAP, or invalid authenticators. 【1-5e9a96】【5-bb3d22】【4-eb5103】

### PQ-readiness governance
- [ ] Review current crypto-provider and dependency version posture.
- [ ] Confirm there is an active PQ migration note or roadmap for this service class.
- [ ] Review whether any pre-production hybrid PQ TLS testing is scheduled or pending. PQ readiness should be treated as a staged migration program, not an implicit always-on claim. 【7-56d833】【8-2a30d6】【9-20b314】【10-fd7f79】

---

## 4. Change Checklist

### Before change
- [ ] Approved change record exists.
- [ ] Last known good image/binary digest recorded.
- [ ] Last known good config archived.
- [ ] Current certificate set/fingerprints recorded.
- [ ] Rollback plan reviewed.
- [ ] Maintenance window or canary path approved as required.

### During change
- [ ] Apply change to staging/canary first where possible.
- [ ] Validate startup success.
- [ ] Validate known-good peer TLS handshake.
- [ ] Validate known-good EAP-TLS flow to Kanidm.
- [ ] Review queue-drop and state-violation counters after change.
- [ ] Review reject categories after change.

### After change
- [ ] Confirm no broad spike in TLS handshake failures.
- [ ] Confirm no broad spike in unsupported EAP rejects.
- [ ] Confirm upstream RTT and timeout rates remain within baseline.
- [ ] Confirm no unexpected peer-policy failures.
- [ ] Archive evidence of successful change validation.

---

## 5. Certificate / PKI Checklist

### Edge server certificate
- [ ] Valid and not near expiry.
- [ ] Chain is correct for expected deployment.
- [ ] Key matches certificate.
- [ ] Private key permissions valid. 【1-35fbe7】

### Trusted client CA
- [ ] CA bundle matches approved trust set.
- [ ] No unexpected or emergency-added anchors.
- [ ] Rotation plan documented.

### Peer policy
- [ ] Fingerprint allow-list reviewed if used.
- [ ] SAN URI prefix policy reviewed if used.
- [ ] SAN DNS suffix policy reviewed if used.
- [ ] CN fallback disabled unless explicitly justified. 【3-76da63】【1-5e9a96】

### PQ-readiness and PKI
- [ ] PKI governance includes crypto-agility planning.
- [ ] Any future hybrid/PQ certificate strategy is documented and staged, not ad hoc. 【7-56d833】【8-2a30d6】

---

## 6. Upstream / Kanidm Checklist

- [ ] Upstream Kanidm RADIUS address correct in config.
- [ ] Firewall and routing permit required upstream access only.
- [ ] Shared secret alignment confirmed between edge and Kanidm backend. Transparent proxy behavior depends on this unless packet re-signing is designed separately. 【1-5e9a96】【4-eb5103】
- [ ] Upstream RTT baseline documented.
- [ ] Upstream timeout rate within expected range.
- [ ] Backend ownership and escalation path documented.

---

## 7. Logging / Monitoring Checklist

### Logging
- [ ] Structured JSON logs are emitted and collected.
- [ ] Timestamps are synchronized and trustworthy.
- [ ] Logs are forwarded to centralized collector/SIEM.
- [ ] Retention policy applied per environment requirements.

### Monitoring
- [ ] Alerts exist for:
  - service down
  - restart spikes
  - TLS handshake failure spikes
  - upstream timeout spikes
  - unsupported EAP reject spikes
  - queue-drop spikes
  - state-violation spikes

### Metrology
- [ ] Metrology flush intervals are occurring on schedule.
- [ ] Baselines documented for:
  - sessions opened/closed
  - TLS handshake average
  - upstream RTT average
  - reject totals
  - queue drops
  - state violations

---

## 8. Safe NDT Checklist

- [ ] Shadow mode is internal-only.
- [ ] No external replay endpoint exists.
- [ ] No external fault-injection interface exists in production.
- [ ] Shadow queue is bounded and functioning.
- [ ] Queue pressure is monitored and does not destabilize the data plane.
- [ ] NDT is not being used to bypass peer policy, EAP policy, or upstream validation. 【1-5e9a96】

---

## 9. Security Posture Checklist

- [ ] Non-root execution confirmed.
- [ ] Read-only root filesystem confirmed where possible.
- [ ] Config + cert mount read-only.
- [ ] All capabilities dropped in containerized runtime.
- [ ] No-new-privileges enabled.
- [ ] Host/container image remains on approved baseline.
- [ ] SBOM/dependency scan reviewed for current artifact.
- [ ] Vulnerability management ownership documented.

---

## 10. Rollback Readiness Checklist

- [ ] Last known good image/binary available.
- [ ] Last known good config available.
- [ ] Prior certificate set or trust set available if relevant.
- [ ] Rollback tested in staging or practiced procedurally.
- [ ] Rollback decision thresholds documented.

---

## 11. Operational Anti-Patterns to Avoid

- [ ] Do **not** run as root.
- [ ] Do **not** expose external NDT or fault-injection endpoints.
- [ ] Do **not** “temporarily” disable EAP-TLS-only enforcement without change control.
- [ ] Do **not** loosen private-key permissions.
- [ ] Do **not** convert bounded queues to unbounded as a quick fix.
- [ ] Do **not** change trust anchors or peer-policy material outside process.
- [ ] Do **not** treat PQ readiness as “complete” without staged validation and governance. 【7-56d833】【8-2a30d6】【9-20b314】

---

## Summary

Use this checklist to keep `kanidm_radsec_edge` operating safely as:

- a **RadSec enforcement edge**,
- an **EAP-TLS-only boundary**,
- a **Kanidm-aware transparent proxy**,
- and a **securely testable, measurable, PQ-ready** production component. 【4-eb5103】【5-bb3d22】【6-ab48bc】【7-56d833】【8-2a30d6】
