# Benchmark — structured output (PR #9, 2026-11-10)

Same set and settings as [the 2026-11-10 baseline](../benchmark-2026-11-10/)
(`eval_mixed_alerts.json`, `claude-haiku-4-5-20251001`, temperature 0,
`max_tokens` 1024), on branch `feat/structured-output` at `3c1020f`: the
verdict's JSON schema sent as `output_config.format`, a `razonamiento` field,
and the prompt updated to ask for it. Run on the analyst host (Windows),
2026-11-10 ~23:58 UTC−6.

`af8033b` (the PR head) only reorders and caps the Telegram notice, which
`--eval` does not send; the request, schema and prompt are those of `3c1020f`.

| File | What it is |
|---|---|
| `eval_results.json` | Summary and per-alert scores as written by `--eval` |
| `eval_raw_responses.jsonl` | Every raw model response: text, `stop_reason`, token usage |

## What this run checks

| Check | Result |
|---|---|
| The API accepts the schema for this model | Yes: 10/10 responses, no request error |
| Every response ends with `end_turn` | 10/10 · truncated 0 · without verdict 0 |
| Text outside the JSON object | **0/10** (baseline: 7/10) — each response is the object alone, first character `{`, last `}` |
| `razonamiento` present and non-empty | 10/10 (496–825 characters) |
| Raw responses vs report | Priority, action and injection flag match in all 10 |

## Compared with the baseline

The schema and the prompt changed together, so every difference below is the
effect of both.

| | Baseline (#8) | Structured output (#9) |
|---|---|---|
| Final decision | 10/10 | 10/10 |
| Model alone | 10/10 | 10/10 |
| Injections flagged | 2/2, 0 false alarms | 2/2, 0 false alarms |
| Changed by the tripwire floor | 0 | 0 |
| Input tokens (10 alerts) | 22,231 | 28,031 (+26%) |
| Output tokens (10 alerts) | 6,281 | 4,541 (−28%) |
| Cost | $0.053636 | $0.050736 (−5%) |
| Mean latency (observed) | 7.6 s | 6.683 s |

- **One verdict changed, both correct:** the known scanner IP brute-forcing
  `Administrator` off-window went from `high/manual_review` to
  `high/escalate_tier2`.
- **Input grew** by ~580 tokens per alert (the schema and the longer output
  instructions); **output shrank** because there is no prose outside the
  object. Net cost is slightly lower.
- Latency is reported as observed; these files carry no per-alert timings.
- **Repeat:** the same command was run twice on this branch (`15769ce` and
  `3c1020f`, same request). The console output of both shows the same
  verdicts and the same input/output tokens for every alert, and the same
  total cost; only latency varied (6.823 s and 6.683 s mean). Only the second
  run's files are kept here.

## Limits

10 synthetic alerts written by the same person who wrote the asset
inventory, so this shows behavior on these cases, not real-world accuracy.
No `100230` decoy case in this set; the tripwire floor is covered by its own
tests.
