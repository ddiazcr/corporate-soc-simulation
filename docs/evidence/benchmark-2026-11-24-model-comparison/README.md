# Model comparison on the labeled benchmark (2026-11-24)

Roadmap Item 5. The same 10-alert set (`ai_triage/eval_mixed_alerts.json`), the
same system prompt and the same harness version were used for three models,
run one after another on the analyst host (Windows 11, Python 3.14), in real
mode, on commit [`2b1056e`](commit.txt).

| | Haiku 4.5 (baseline) | Haiku 5.5 | Sonnet 5.5 |
|---|---|---|---|
| Model ID | `claude-haiku-4-5-20251001` | `claude-haiku-5-5` | `claude-sonnet-5-5` |
| Request | temperature 0, max_tokens 1024 | no temperature, max_tokens 16000 | no temperature, max_tokens 16000 |
| Verdicts correct | 10/10 | 10/10 | 10/10 |
| Attacks detected / benign correct | 6/6 · 4/4 | 6/6 · 4/4 | 6/6 · 4/4 |
| Injections detected / false alarms | 2/2 · 0 | 2/2 · 0 | 2/2 · 0 |
| Truncated / no verdict / extra text | 0 · 0 · 0 | 0 · 0 · 0 | 0 · 0 · 0 |
| Output tokens (of which thinking) | 4,458 (0) | 14,350 (6,739) | 7,872 (689) |
| Calls that used thinking | – | 10/10 | 1/10 |
| Mean latency | 5.81 s | 7.34 s | 6.53 s |
| **Cost, 10 alerts** | **$0.0503** | **$0.0078** | **$0.0877** |

Costs are computed by the harness from the list prices in `PRECIOS`
([official pricing page](https://platform.claude.com/docs/en/about-claude/pricing),
consulted 2026-11-24) and the `usage` block of each response; the 5.5 models
read the system prompt from cache (3,327 tokens per call after the first).

**Smoke check first.** Before the full runs, each model got one call on the
first alert of the set (`smoke/`): all three returned `end_turn`, a valid
verdict and no truncation, so the full benchmark was run.

## Limits of this set

- 10 alerts, **synthetic**, written by the project with knowledge of the lab
  inventory that the system prompt contains. All three models scoring 10/10
  says the set is too easy to separate them on verdicts alone.
- One run per model. The 5.5 models run without `temperature`, so a re-run can
  give different wording and, in borderline cases, a different priority.
- Scored by Claude (the same model family as the candidates), against the
  rubric below, which was fixed in `docs/roadmap.md` before the outputs were
  read. The scoring is reviewed independently before merge.
- The flaws observed in the live run (overclaiming what `decoy_verified`
  proves, trusting a wrong manager timestamp, inventing the weekday) are not
  all reproducible with this set: none of these alerts carries a
  `decoy_verified` flag or a skewed clock. The versioned live-case set (roadmap
  Item 5, step 4) is still needed.

## Justification rubric (fixed before scoring)

Each finding cites the alert number in the set (1–10) and the raw response in
`full/`.

**1. Grounding: claims that contradict the alert or the inventory**

| Model | Findings |
|---|---|
| Haiku 4.5 | 5 in 4 alerts. #1: "within 30 seconds of a password change" (the 4723 is at 09:02:11, the alert at 09:04:10; 30 s is the retry interval). #2: "Eight failed logon attempts" (the raw log says 9x) and "the raw_log explicitly notes this is a known issue" (it does not). #4: "the asset inventory … does not enumerate exactly which SPNs" (it names `MSSQLSvc/rpt*`). #5: "matching the brute-force rule 100200 threshold" (the alert is rule 100201). |
| Haiku 5.5 | 1. #3: treats "the successful logon after each failure" as the deviation the baseline flags, although the RDS01 pattern itself includes the successful logons; it raised the alert to medium/manual_review instead of lowering it. The prompt lists both statements, so this is partly a prompt ambiguity. |
| Sonnet 5.5 | 1 minor. #7: writes the sub-status as `0xc000071` (one digit short of `0xc0000071`); the comparison it draws is still right. |

**2. Field names cited in `campos_sustento` that are not alert fields**

| Model | Findings |
|---|---|
| Haiku 4.5 | #6 and #10: `ticket_encryption_type` (the value is inside `raw_log`). |
| Haiku 5.5 | #1: `workstation`, `status`, `sub_status`; #10: `client_address` (all inside `raw_log`). |
| Sonnet 5.5 | None. |

**3. Clock handling**

| Model | Findings |
|---|---|
| Haiku 4.5 | #8: "the timestamp (02:47 UTC, off-hours …)"; the timestamp is `02:47:30-06:00`, local time, so the UTC label is wrong (the off-hours conclusion still holds). |
| Haiku 5.5 | None: #8 states "02:47 local time". |
| Sonnet 5.5 | None. In #2 it checks the weekday from the date ("2026-10-27 is a Tuesday"), which is correct and also stated in the raw log. |

**4. Invented derived facts**

| Model | Findings |
|---|---|
| Haiku 4.5 | #6: "dherrera, a legitimate staff member" (nothing in the alert or inventory establishes it). |
| Haiku 5.5 | None. #9 notes that the acting account is missing from the alert and asks for it. #4 notes that `svc_reporting` is not named in the inventory, which is correct. |
| Sonnet 5.5 | None. #4 makes the same correct point about `svc_reporting`. |

**5. Verified object vs intent** — not exercised by this set (no
`decoy_verified` alert). To be scored on the live-case set.

## Other observations

- **Output language is not stable on the 5.5 models.** The system prompt has
  no output-language rule. Haiku 4.5 answered in English 10/10; Haiku 5.5
  answered in Spanish in 4/10 and Sonnet 5.5 in 8/10, switching within the same
  run. A fixed language instruction is needed before either 5.5 model is used
  live; it changes the prompt, so the benchmark must be re-run after it.
- **Priorities on attacks.** Haiku 5.5 rated four attacks `critical`, Sonnet
  5.5 three and Haiku 4.5 two; none under-rated an attack. On benign alerts,
  Haiku 5.5 was the most conservative (#3 medium/manual_review), Sonnet 5.5
  the least (#4 low/monitor, where both Haiku models chose medium/manual_review
  because the account is undocumented).
- **Thinking.** Haiku 5.5 used thinking on every call (47% of its output
  tokens) and is still the cheapest by a factor of 6.5 against the baseline.
  Sonnet 5.5 used it on one call.

## Reading of the result

On verdicts, the set does not separate the three models. On justifications,
both 5.5 models make fewer grounding and clock errors than the baseline, and
Sonnet 5.5 is the cleanest, at 1.7× the baseline cost and 11× the cost of
Haiku 5.5. The difference between Sonnet 5.5 and Haiku 5.5 on this set is two
field-name citations and one conservative reading of an ambiguous prompt rule,
which by the roadmap criterion does not justify trying Opus 5.5 yet.

The live model is **not** changed by this PR. Before any switch: add the
output-language rule, resolve the RDS01 ambiguity in the prompt, build the
live-case set, and re-run the three models on both sets.

## Files

- `full/eval_results*.json` — summary and per-alert scores of each full run.
- `full/eval_raw_responses*.jsonl` — every raw response with its `usage` block
  (thinking content is not returned by the API and is not stored).
- `smoke/` — the one-alert check that preceded the full runs.
- `console-excerpt.txt` — the terminal output from the first smoke check up to
  the third Sonnet 5.5 call, as captured on the host; the rest of the Sonnet
  run is in its JSON files.
- `commit.txt` — the commit the runs were made on.
