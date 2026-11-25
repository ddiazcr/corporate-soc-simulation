# Corporate SOC Simulation — Nimbrek S.A. · Plan for remaining work

**Context:** Phases 1–5 are complete and documented. This plan covers the three open
items that take the project from "complete" to "portfolio-standout". Scope is a
controlled home lab (VirtualBox, host-only 192.168.56.0/24); everything is defensive
(Blue Team) and no action is executed against the domain without human approval.

Reviewer (ChatGPT): challenged the **design decisions** marked 🔶 before any code
is written — that is where your review has the most leverage.

---

## Item 1 — Phase 4 live-run evidence (highest priority)

**Status (2026-11-20): done.** Real verdicts with `claude-haiku-4-5` on all three
scenarios, each through the human gate and Telegram, with latency, tokens and
cost per call: 100212 live (2026-11-08, earlier software: no tripwire floor,
before structured output); 100220 live and 100230 ×2 from pending alerts of
2026-11-19 recovered and processed in REAL mode (2026-11-20, model request as in
the structured-output benchmark at `3c1020f`).
[Evidence](evidence/phase4-live-2026-11-20/) · [100212 run](evidence/live-run-2026-11-08/).
Decision taken: keep Haiku 4.5, the benchmark's model, so the live evidence and
the [benchmark](evidence/benchmark-2026-11-10-structured-output/) share the same
model request; a larger model is a separate, measured comparison (Item 5).

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

## Item 5 — Model comparison on the labeled benchmark (first run done)

**Goal:** run the same 10-alert benchmark with other models and compare
accuracy, false positives/negatives, injection handling, latency and cost
against Haiku 4.5, every raw response kept. Switch the live model only if the
measured result justifies it.

**Candidates ([official list prices](https://platform.claude.com/docs/en/about-claude/pricing), consulted 2026-11-24):**
Haiku 4.5 (baseline, $1 / $5 per million input / output tokens); **Haiku 5.5**
(newer, $0.10 / $0.50 up to 100k-token prompts: a tenth of the baseline);
**Sonnet 5.5** (larger, $2 / $10). Opus 5.5 ($4 / $20) only if Sonnet changes
the outcome.

**Harness (ready):** `AI_MODEL` selects the model; each model has its own price
and writes its own `eval_results.<model>.json` / `eval_raw_responses.<model>.jsonl`;
a model with no known price is refused before any API call. Request settings
are per model: the 5.5 models get no `temperature` and room for thinking
(`max_tokens` 16000); Haiku 4.5 keeps temperature 0 and 1024.

**Design of the comparison**
1. Re-run Haiku 4.5 with the same code and set, so every model is measured by
   the same harness version (the 2026-11-10 result predates it).
2. Declare the limits in the published result: 10 alerts, synthetic, written
   with knowledge of the lab inventory, so a tie at 10/10 says little and the
   differences are expected in the justifications.
3. Score the justifications with a rubric fixed **before** reading any output:
   - grounding: every claim traceable to a field of the alert;
   - invented facts: derived claims not in the alert (e.g. a weekday);
   - clock handling: does it trust a timestamp the alert itself makes suspect;
   - verified object vs intent: does it state what a flag such as
     `decoy_verified` proves (the object) without claiming intent.
4. Add a second, versioned set built from the live cases
   (`docs/evidence/phase4-live-2026-11-20/`, the offline Kerberoast case),
   where the reasoning flaws above were actually observed. Done:
   `ai_triage/eval_live_cases.json` (4 real alerts).
5. Try Opus 5.5 only if Sonnet 5.5 differs from Haiku on the rubric, and decide
   by those differences plus cost per alert.

**First run (2026-11-24):** all three models 10/10 on verdicts; on the rubric
the 5.5 models make fewer grounding and clock errors than Haiku 4.5; cost per
10 alerts $0.050 (Haiku 4.5), $0.008 (Haiku 5.5), $0.088 (Sonnet 5.5). The
5.5 models switch output language within a run. Evidence and scoring:
[`docs/evidence/benchmark-2026-11-24-model-comparison/`](evidence/benchmark-2026-11-24-model-comparison/).
Next: output-language rule and RDS01 wording in the prompt, live-case set,
re-run. The live model stays Haiku 4.5 until then; Opus not justified yet.

**Prompt revision (after the first run):** English-only output; only
top-level alert keys in `campos_sustento`; an evidence-discipline section
(hypotheses stated as such; no intent, shared password, "downgrade" or role
from a name stated as fact; times kept in their own offset; no conclusion from
time of day alone); RDS01's successful logons stated as part of its pattern;
Kerberos rule IDs corrected (the prompt named 100210, which is below the
triage threshold; the triaged rules are 100211 and 100212). This changes the
prompt of the live model too, so the re-run includes Haiku 4.5 on both sets.

**Re-run with the revised prompt (2026-11-24):** 10/10 and 4/4 for all three;
English 14/14 each; on the rubric Haiku 5.5 and Sonnet 5.5 have no finding on
either set, while Haiku 4.5 keeps two miscounts and, on the live-case set,
repeats the `decoy_verified` overclaim. Cost per synthetic alert $0.0056
(Haiku 4.5), $0.00095 (Haiku 5.5), $0.0118 (Sonnet 5.5). Evidence:
[`docs/evidence/benchmark-2026-11-24-prompt-v2/`](evidence/benchmark-2026-11-24-prompt-v2/).
Open decision: switch the live model to Haiku 5.5 (separate change).

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

**Root cause (2026-11-11)** — not a field difference. Observed live: honeytoken
tickets from `::1` alerted, the same request from `::ffff:192.168.56.10` produced
no alert at all. Diagnosis from a static reading of the 4.9.2 ruleset: 100210
chained only from 60106, and the built-in sibling **92651**
(`0840-win_event_channel.xml`, level 0, "ipAddress holds an IPv4 other than
127.0.0.1") loads first, so it would take every 4769 whose source address
contains an IPv4 (a request from Kali, or from the DC itself via
`::ffff:192.168.56.10`). A level-0 match writes no alert, so neither the live
capture nor the engine test records which rule took the event. Fix: 100210
also chains from 92651 (and from 60119, first-time-seen user), plus
`rules/check_shadowing.py` to catch this class of problem. Status: fixed in the
rule; validated with the real engine on 2026-11-15 (injected events: before, the
`::ffff:192.168.56.10` and Kali-address samples produced no alert; after, all three
reach 100212 and a legitimate AES ticket stays at 60106 —
[evidence](evidence/engine-test-2026-11-15/)). **Validated live on 2026-11-15**: a
Kerberoasting request from Kali (`crojas`, Impacket `GetUserSPNs -request`) through
the DC01 agent raised 100212 (level 12, RC4 `0x17`, client `::ffff:192.168.56.103`,
agent 004) — [evidence](evidence/live-kerberoast-2026-11-15/). **Done.**

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

---

## Live validations of open work (status 2026-11-18)

Unit and engine tests are done for each change below; this table tracks the
**live** run that closes each one and links its evidence.

| Change | Live validation | Status | Evidence |
|---|---|---|---|
| [PR #11](https://github.com/ddiazcr/corporate-soc-simulation/pull/11) — Kerberoasting rule shadowed by 92651 | Kerberoasting from Kali through the DC01 agent raises 100212 | ✅ Done 2026-11-15 (agent 004, record 256462, RC4 `0x17`) | [live detection](evidence/live-kerberoast-2026-11-15/) · [engine before/after](evidence/engine-test-2026-11-15/) (published with #11) |
| [PR #12](https://github.com/ddiazcr/corporate-soc-simulation/pull/12) — feed resumes after a stop | Stop the feed, fire the honeytoken during the pause, restart → the same Wazuh alert id is linked to its case and decision in SQLite | ✅ Done 2026-11-18 at `913e768`: alert `1795058621.1289840` written during the pause was read on restart; a stop at the approval prompt resumed on the same case; 1 case, decision `approved`, link `atendida` | [live resume](evidence/live-resume-2026-11-18/) |
| [PR #10](https://github.com/ddiazcr/corporate-soc-simulation/pull/10) — approval gate on Windows | `a → approved`, `r → rejected`, `s → skipped`, each row in `decisiones` linked to its case | ✅ Done 2026-11-18 on the Windows host: five live alerts, each answer → its decision, invalid `x` re-asked, one decision per case, each linked to its Wazuh id | [live gate](evidence/live-gate-windows-2026-11-18/) |

## Item 4 — Offline investigation with Hayabusa

**Goal:** tie the live 100212 alert to the raw DC01 Security log, rebuild the
timeline around it with Hayabusa, and write what the analyst concludes and what
must be verified before escalating.

**Status (2026-11-18): analysed.** DC01 Security log exported and hashed on the
DC; Hayabusa 4.4.0 timeline; the alert matches raw record 256462 on all 14
compared fields. Conclusion: true positive — Kerberoasting of the honeytoken
from 192.168.56.103 with `crojas`, preceded by wrong-password attempts; both
sessions read the discovery decoy's SPN-related attributes (account discovery
kept as hypothesis); `crojas` was used right after a successful password reset
from an `Administrator` session on DC01 (interactive by inference). The reset was
confirmed by the operator as lab setup. Follow-ups closed 2026-11-20: Wazuh
100230 fired on both decoy reads; the `Administrator` session was a console
logon; one SPN requested from .103 in the whole retained log.

**Lab maintenance — DC01 licence.** DC01 runs Windows Server 2022 *Evaluation*
without internet activation. The System log shows WLMS shutting the DC down
for the expired licence already on 2026-11-11 and 2026-11-15 (the 2026-11-15
21:46:54 shutdown ended the `Administrator` session of the offline case);
it was noticed on 2026-11-20. State after `slmgr /rearm` that day
(`slmgr /dlv`, `/xpr`): *Initial grace period*, 10 days, ends 2026-11-30
04:06:57 DC01 local; 5 rearms remaining. **Next check: 2026-11-27** — then
decide, from `slmgr /dlv`, between another rearm (if any remain) and online
activation.
[Investigation](investigations/kerberoast-honeytoken-2026-11-15/) ·
[evidence](evidence/offline-kerberoast-2026-11-15/)
