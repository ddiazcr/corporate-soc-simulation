# Corporate SOC Simulation — Nimbrek S.A. · Plan for remaining work

**Context:** Phases 1–5 are complete and documented. This plan covers the three open
items that take the project from "complete" to "portfolio-standout". Scope is a
controlled home lab (VirtualBox, host-only 192.168.56.0/24); everything is defensive
(Blue Team) and no action is executed against the domain without human approval.

Reviewer (ChatGPT): challenged the **design decisions** marked 🔶 before any code
is written — that is where your review has the most leverage.

---

## Item 1 — Phase 4 live-run evidence (highest priority)

**Goal:** capture real AI-triage verdicts on live Active Directory alerts, with the
human-approval gate and Telegram notification, as reproducible portfolio evidence.

**Why it matters:** the pipeline already passes a labeled benchmark (10/10). What is
missing is *real-time* evidence a recruiter can see: SIEM alert → model verdict →
analyst decision.

**Steps**
1. Power on VMs: DC01 (.10), Wazuh (.102), Kali (.103). Fix clock skew if present.
2. On the analyst host: `AI_MODE=REAL python wazuh_feed.py --ssh wazuhadmin@192.168.56.102`
3. Trigger three already-detected, benign-in-isolation AD activities, one at a time:
   - Service-ticket request for the honeytoken SPN (fires rule 100212).
   - Read of the decoy account `adm_backup_legacy` (fires 100230).
   - Add + immediate remove of a user to a privileged group (fires 100220).
4. For each: read the model's verdict, use the human gate to approve/reject, screenshot
   the console and the Telegram message.

**Acceptance criteria**
- ≥3 verdicts captured with per-alert latency and token cost.
- Screenshots saved to `docs/evidence/phase4-live/`.
- `ai_triage/README.md` and the main README reference the live run.

🔶 **Decision for review:** the triage model is currently `claude-haiku-4-5` (cheap,
fast). For a showcase run, keep Haiku (emphasize cost-efficiency) or switch to a larger
model (emphasize reasoning quality)? Trade-off: cost/latency vs. depth of justification.

---

## Item 2 — Internet-exposed honeypot feeding the same SIEM

**Goal:** a deliberately exposed decoy service that generates real attacker telemetry
into the existing Wazuh manager, proving the SOC can ingest and detect beyond the lab.

**Steps (draft)**
1. Stand up a decoy (candidate: a low-interaction SSH honeypot such as Cowrie) on an
   isolated VM.
2. Ship its logs to the existing Wazuh manager via the agent.
3. Write a decoder + rule so honeypot hits surface as SOC alerts.
4. Document a sample of captured activity.

🔶 **Decisions for review (important — security scoping):**
- **Exposure method.** Options: (a) a cheap cloud VPS as the honeypot, logs forwarded
  back to the lab Wazuh over a restricted channel — isolates risk from the home
  network; (b) a port-forward from the home router to a lab VM — simpler but places a
  deliberately exposed host on the home LAN. Recommendation to debate: (a), for blast-radius
  isolation. What segmentation / firewall rules make this safe?
- **Interaction level.** Low-interaction (Cowrie, safer, less data) vs. higher-interaction
  (richer data, more risk). For a portfolio, is low-interaction enough?
- **Data handling.** Captured source IPs are third-party personal data — how do we
  document findings without publishing raw IPs?

**Acceptance criteria**
- Honeypot events visible in Wazuh with a dedicated rule.
- A short writeup with at least one real captured session (sanitized).
- Clear network diagram showing isolation from the home LAN.

---

## Item 3 — Network-sourced 4769 Kerberoasting detection gap

**Problem:** TGS-REQ (event 4769) with RC4 encryption sourced from the network (Kali)
does not raise rule 100212, although DC-local requests do.

**Investigation plan**
1. Temporarily enable archives logging on the manager, re-run the network request, and
   capture the raw event.
2. Compare the field set of a network-sourced 4769 against a DC-local one — likely the
   rule matches a field that is empty or formatted differently over the network
   (e.g. `ipAddress`, `serviceName`, ticket options).
3. Adjust the rule/decoder to match both paths without widening it into false positives.
4. Re-validate and revert archives logging.

**Acceptance criteria**
- A network-sourced Kerberoast attempt raises an alert.
- Rule 100212 updated with a regression note; false-positive check documented.

---

## Collaboration loop (Claude ⇄ Daniel ⇄ ChatGPT)

1. Claude drafts design (this doc) and, later, code on a branch + Pull Request.
2. Daniel passes the doc/PR to ChatGPT for review.
3. ChatGPT's comments come back; Claude addresses them on the same branch.
4. Daniel approves and merges.

**Order (after review):** Item 1 → Item 3 → Item 2.

---

## Review outcome (ChatGPT, 2026-11-07) — accepted changes

- **Order changed** to live triage → 4769 gap → public honeypot.
- **Item 1:** keep Haiku for the first live run; record exact model ID, latency, cost and
  analyst decision. Add a test of the human *reject* path and verify the privileged-group
  membership is reverted. A model change must be justified by an A/B run on the same
  alerts, prompt and quality rubric.
- **Item 3:** separate the three stages — 4769 generation on the DC, ingestion in Wazuh,
  rule match. Capture one local and one network sample before touching the decoder.
  Regression: both paths alert; a legitimate control request does not. Archives logging
  bounded in time and restored afterwards.
- **Item 2 (design changed):** the VPS agent does **not** report to the home Wazuh.
  The VPS pushes telemetry to an external collector (write-only credential, TLS 443);
  a lab-side importer pulls it with a separate read-only credential, validates the
  schema and writes normalized JSON read by a local agent. Zero Wazuh ports (1514,
  1515, 55000) exposed to the Internet.
  - Cowrie, emulated mode, proxy mode off, unprivileged user.
  - Default-deny on provider firewall and VPS, IPv4 and IPv6; only the decoy TCP port
    inbound; no routes to the home LAN or 192.168.56.0/24; instance metadata blocked;
    no cloud credentials on the VPS.
  - Added risks: log tampering / prompt injection through captured text (schema
    validation, length limits, synthetic injection test before connecting to the AI
    pipeline); decoy compromise (receipt time recorded outside the VPS, quotas,
    teardown runbook); privacy (raw logs restricted with a retention limit; published
    copies use labels like `source-01`, no credentials, relative times).
  - Isolation must be **tested**, not only diagrammed: external scan shows only the
    decoy; egress from the VPS reaches only the collector; malformed/oversized records
    are rejected. Results kept as evidence.
  - Next Claude deliverable for Item 2: flow diagram, firewall matrix and isolation
    tests — before provisioning the VPS.
