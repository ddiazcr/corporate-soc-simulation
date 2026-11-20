# Phase 4 live run — real model verdicts on decoy-read and privileged-group alerts (2026-11-20)

Closes roadmap **Item 1**: real AI-triage verdicts on live Active Directory
alerts, through the human-approval gate and Telegram. With the 100212 live run
of [2026-11-08](../live-run-2026-11-08/), the three scenarios of Item 1 now have
at least one real verdict each.

Setup: Windows 11 analysis host, `main` at `b76fa4c`,
`AI_MODE=REAL python wazuh_feed.py --ssh wazuhadmin@192.168.56.102` (dedup on).
Model: `claude-haiku-4-5-20251001`, the model of the 10/10 benchmark, kept so the
live evidence and the benchmark describe the same pipeline.

## Result

| # | Rule | Alerts → case | Model verdict | Latency | Tokens in / out | Cost | Analyst |
|---|---|---|---|---|---|---|---|
| 1 | 100230 decoy read | 2 → `…-f82742e7` | `escalate_tier2`, high, confidence high, T1087.002 | 10.114 s | 3,122 / 479 | $0.005517 | `r` → rejected |
| 2 | 100230 decoy read | 8 → `…-721abfea` | `escalate_tier2`, high, confidence high, T1087.002 | 9.024 s | 3,043 / 522 | $0.005653 | `r` → rejected |
| 3 | 100220 privileged-group add | 1 → `…-57235fc9` | `escalate_tier2`, **critical**, confidence high, T1098 | 7.436 s | 2,885 / 445 | $0.005110 | `r` → rejected |

- Latency, tokens and cost are printed by the pipeline (`[métricas]`), per API
  call. Three calls, $0.016280 in total. n = 3 observations, not a benchmark.
- Every case has one decision and every alert is linked to its case
  (`atendida`): [`sqlite-cases.txt`](sqlite-cases.txt). Nothing is executed on
  any answer.

## The alerts

**100230 (rows 1–2) — the decoy caught the analyst.** The feed picked up
pending 100230 alerts written at 2026-11-19 05:46:54–55Z: the reads of
`adm_backup_legacy` made with `Get-ADObject` and `Get-Acl` on DC01 while
resolving GUIDs for the [offline investigation](../../investigations/kerberoast-honeytoken-2026-11-15/)
(2026-11-18 23:46–23:47, Costa Rica). Real alerts on an authorised activity whose
context the model cannot see: escalating is the expected model output for a
tripwire, and the analyst rejected both as authorised. The ten alerts of the
burst (one per property read) were merged by dedup into **two cases and two
model calls**: same rule and addresses, two distinct content fingerprints.

**100220 (row 3) — planned trigger.** `crojas` added to *Domain Admins* and
removed 5 s later on DC01 (2026-11-20 12:36:40Z on DC01's clock); final
membership `Administrator` only. The rule keeps additions only, so one alert.

## Observations on the model's reasoning

The classifications are correct for what each alert shows. Three points in the
justifications are worth stating, because the analyst has to catch them:

1. **Overclaim on a flag.** Verdict 1 says `decoy_verified` "eliminates the most
   common false-positive scenario". The flag confirms *which object* was read
   (the decoy), not *who or why*; this read was the analyst's own.
2. **A source timestamp taken at face value.** Verdict 3 argues "06:51 UTC …
   outside typical change windows". 06:51 is the Wazuh manager's alert time,
   2026-11-19T06:51:01Z, while DC01 recorded the change at 2026-11-20T12:36:40Z:
   the manager clock was about 29 h 45 min behind (likely a VM resumed without a
   time sync; not checked). The model built an argument on that timestamp.
3. **An invented derived fact.** Verdict 3 calls the day "a Wednesday";
   2026-11-19 was a Thursday (and the change happened on Friday 2026-11-20).

Verdict 2, on an alert almost identical to verdict 1, added that a single
property read "does not prove lateral movement or compromise" and could be "a
benign administrative query": same classification, more careful wording.

None of this changes the outcome — every verdict went to a human — and it is the
reason the gate exists: the model's context is the alert, the analyst's is the
environment.

## Clocks

- Alert timestamps (`>>> Wazuh …`) are the **manager's** clock: correct for the
  100230 alerts of 2026-11-19 05:46Z, ~29 h 45 min behind by the time of the
  100220 alert.
- `primera_deteccion` and decision times in SQLite are the **analysis host's**
  clock: 12:37:37Z for the 100220 case, about a minute after the change on DC01
  (DC01 printed 12:36:40Z after the add, the 5 s wait and the removal). Host and
  DC01 clocks were not cross-checked, so no latency is derived from them.
- The Wazuh alert IDs are manager epoch seconds (`1795071061` =
  2026-11-19T06:51:01Z), so they carry the same offset.

## Files

| File | What it shows |
|---|---|
| `p1-feed-start-and-100230-verdict.png` | Feed in `Modo=REAL` resuming at the saved cursor; verdict 1 and `r` → rejected; start of verdict 2 |
| `p1-100230-telegram.png` | Telegram notification, verdict 1 |
| `p2-100230-telegram.png` | Telegram notification, verdict 2 |
| `p2-p3-dedup-burst-and-100220-verdict.png` | Verdict 2 metrics and decision; the dedup burst (conteo 2…8); verdict 3 metrics and decision |
| `p3-100220-telegram.png` | Telegram notification, verdict 3 |
| `sqlite-cases.txt` | Cases, decisions and linked alerts; the DC01 trigger and final group membership |

Screenshots are unedited captures.
