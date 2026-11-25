# Controlled live trial of Haiku 5.5 (2026-11-24, Costa Rica time)

Step 2 of the Haiku 5.5 trial (roadmap Item 5). The live feed ran with
`AI_MODEL=claude-haiku-5-5` on `main` at `e983c56` (revised prompt of #18,
model recorded per case and per notification since #19), and the three
planned triggers of the [phase 4 run](../phase4-live-2026-11-20/) were repeated
on DC01: a honeytoken ticket (100212), a read of the decoy account (100230) and
an add + immediate removal in Domain Admins (100220). Every verdict went
through the human gate; nothing was executed.

Setup: Windows 11 analysis host, PowerShell,
`$env:AI_MODE = "REAL"; $env:AI_MODEL = "claude-haiku-5-5"`,
`python wazuh_feed.py --ssh wazuhadmin@192.168.56.102`. Banner:
`Modo=REAL | modelo=claude-haiku-5-5 | nivel mínimo 10 | solo reglas Nimbrek (1002xx)`
([`console-1-banner.jpg`](console-1-banner.jpg)).

## Result

| # | Rule | Trigger on DC01 (DC01 UTC) | Case | Verdict | Latency | Tokens in / out | Cost | Analyst |
|---|---|---|---|---|---|---|---|---|
| 1 | 100212 honeytoken ticket | `klist get MSSQLSvc/db01.lab.local:1433`, 00:56:25Z | `23742fbbbf29b189-9c3d54c2` | high / `escalate_tier2`, confidence high | 9.451 s | 568 / 1,633 | $0.001363 | `r` → rejected |
| 2 | 100230 decoy read | `Get-ADUser -Identity adm_backup_legacy`, 00:58:12Z | `c43f86fb474df50a-dc767900` | high / `escalate_tier2`, confidence medium | 6.447 s | 610 / 1,264 | $0.000732 | `r` → rejected |
| 3 | 100230 decoy read (same read, other properties) | same | `c43f86fb474df50a-bc71813a` | high / `escalate_tier2`, confidence medium | 6.957 s | 881 / 1,284 | $0.001220 | `r` → rejected |
| 4 | 100220 Domain Admins add | `Add-ADGroupMember … crojas`, removed after `Start-Sleep 5`; 4728 at 00:59:14Z | `0349b7ae4fc990c2-6e7f8b7b` | **critical** / `escalate_tier2`, confidence high | 6.199 s | 393 / 1,266 | $0.000711 | `r` → rejected |

- Four model calls, $0.004026 in total, mean latency 7.26 s. Latency, tokens
  and cost are the pipeline's `[métricas]` lines
  ([`console-2-…`](console-2-100212-100230-metrics.jpg),
  [`console-3-…`](console-3-100230-100220-metrics.jpg)); input tokens exclude
  the cached system prompt, which the cost includes.
- **Priority and action are the model's own**: no `[PISO]` line, and
  `piso_aplicado` is absent from every stored verdict.
- **The model is recorded.** All four rows of `casos` carry
  `modelo = claude-haiku-5-5` and every Telegram notice has the line
  `Modelo: claude-haiku-5-5` (`t1`–`t4` PNGs). Each case has one decision and
  its alert is linked as `atendida` ([`sqlite-cases.txt`](sqlite-cases.txt),
  which also holds the full stored verdicts).
- The decoy read produced two alerts with different content fingerprints;
  dedup opened two cases with their own analysis, as on 2026-11-20.

## Justification rubric

The same rubric as the [benchmarks](../benchmark-2026-11-24-prompt-v2/),
applied to the four stored verdicts, including the three flaws Haiku 4.5
showed on these triggers on 2026-11-20:

| Point | Result |
|---|---|
| Overclaim on `decoy_verified` (flaw 1) | Not repeated. Both 100230 verdicts say the flag confirms the decoy object was read and keep account discovery as a hypothesis ("a hypothesis to test, not a conclusion" in the first; "consistent with … but a broad directory query … could produce the same single read" in the second). |
| Argument from the manager's skewed timestamp (flaw 2) | Not repeated. No verdict mentions time of day, change windows or off-hours, although the manager stamped these alerts about 5 days 17 hours behind (see Clocks). |
| Invented derived fact, e.g. the weekday (flaw 3) | Not repeated. No weekday or other derived date in any verdict. |
| Claims that contradict the alert | None found. The 100212 verdict reads `::1` as the loopback address, so the request was issued on DC01 itself, which is correct. |
| Field names outside the alert | None: every `campos_sustento` entry is a top-level key of the alert. |
| Inferences stated as fact | None found. Kerberoasting is "consistent with … though one request alone does not confirm it"; the 100220 verdict asks for verification before calling the change legitimate or not. |

**Observation (not a rubric finding).** Two verdicts suggest searching DC01's
logs at the alert's time ("around 07:10:13 UTC", "around 07:12 UTC"). That is
the manager's stamp, about 5 days 17 hours off DC01's clock here, so taken
literally the search would miss the events. The model cannot see the skew and
builds no conclusion on it, as the prompt asks; none of the four verdicts,
however, suggests checking the SIEM clock against DC01's before correlating,
which some benchmark verdicts did. The analyst has to translate the time.

Scored by Claude, the same model family as the model under trial; reviewed
independently before merge.

## What this does and does not compare

- Compared with the 2026-11-20 phase 4 run (Haiku 4.5): same triggers, same
  human gate. Haiku 4.5 then took 7.4–10.1 s and $0.0051–$0.0057 per call;
  Haiku 5.5 took 6.2–9.5 s and $0.0007–$0.0014.
- **Model and prompt both changed** since 2026-11-20 (the prompt revision of
  #18), so this run alone cannot attribute the cleaner justifications to the
  model. The benchmark of #18 separates them partly: on the four
  2026-11-20 alerts replayed with the revised prompt, Haiku 4.5 still repeated
  the `decoy_verified` overclaim, Haiku 5.5 did not.
- The alerts are new events, not the 2026-11-20 ones (other timestamps,
  logon sessions and properties read), so they are comparable in kind, not
  identical.
- n = 4 verdicts in one session. It shows the model works end to end in the
  live pipeline with traceability; it is not a benchmark.

## Clocks

- **Wazuh manager: about 5 days 17 hours 46 minutes behind.** `date -u` on the
  manager returned `Thu Nov 19 07:20:07 AM UTC 2026` at about 01:06Z real time
  (2026-11-25). Consistently, the 4728 logged by DC01 at
  `2026-11-25T00:59:14.108Z` reached `alerts.json` stamped
  `2026-11-19T07:13:38.053+0000`. On 2026-11-20 the offset was about
  29 h 45 min, so it has grown: consistent with the manager VM being paused or
  restored without a time sync (hypothesis, not checked). The
  `>>> Wazuh …` lines in the console show the manager's clock.
- **DC01: UTC correct, local time zone UTC−8.** `Get-Date …ToUniversalTime()`
  printed `2026-11-25T00:56:25Z`, matching the host and Telegram (18:56
  Costa Rica); `klist` printed `16:56:25 (local)`.
- **Kali: UTC correct** (`25 nov 01:03:59 UTC 2026`).
- **One unexplained interval on DC01.** The block slept 5 s between the add and
  the removal, but DC01 logged the 4728 at 00:59:14.108Z and the 4729 at
  00:59:16.969Z (2.86 s; RecordId 393119 → 393122, in order). Whether the
  sleep was shorter or DC01's clock was adjusted during it is not established;
  the order comes from the record numbers.
- SQLite times (`primera_deteccion`, decisions) are the analysis host's clock.

## The human gate serialises the feed

The 100220 alert did not appear for several minutes. It was already in
`alerts.json`; the feed processes one alert at a time and was waiting at the
approval prompt of the previous case. Each case was created in the same
second the previous decision was recorded (00:59:13Z, 01:08:14Z, 01:08:49Z).
Nothing was lost: every alert is linked to its case. A waiting decision delays
the next alert's triage; worth stating for any reader timing the pipeline.

## Files

| File | What it shows |
|---|---|
| `console-1-banner.jpg` | The feed command, banner with `modelo=claude-haiku-5-5`, resume from the saved cursor |
| `console-2-100212-100230-metrics.jpg` | 100212 and the first 100230: metrics and `r` → rejected |
| `console-3-100230-100220-metrics.jpg` | Both 100230 cases (dedup: different content → new case) and 100220: metrics and decisions |
| `t1-100212-telegram.png` … `t4-100220-telegram.png` | The four Telegram notices, each with `Modelo: claude-haiku-5-5` |
| `sqlite-cases.txt` | The four cases with model, decision, linked alert and manager timestamp, and the full stored verdicts |

Console images are screen captures of the feed window, cropped to it;
Telegram images are the analyst's unedited captures.
