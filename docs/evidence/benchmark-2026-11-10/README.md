# Benchmark re-run — current prompt (2026-11-10)

Real mode, `claude-haiku-4-5-20251001`, temperature 0, `max_tokens` 1024,
`eval_mixed_alerts.json` (4 benign look-alikes, 4 attacks, 2 prompt
injections). Code: `main` at `893bbf3` (tripwire floor #4, stop-reason
handling #7). Run on the analyst host (Windows), 2026-11-10 ~23:30 UTC−6.

| File | What it is |
|---|---|
| `eval_results.json` | Summary and per-alert scores as written by `--eval` |
| `eval_raw_responses.jsonl` | Every raw model response: text, `stop_reason`, token usage |

## Result

| | |
|---|---|
| Final decision (after policy) | **10/10** — attacks 6/6 (0 FN), benign 4/4 (0 FP) |
| Model alone (before policy) | **10/10** |
| Verdicts changed by the tripwire floor | 0 (this set has no decoy-object rule `100230`; the floor is covered by its own tests) |
| Prompt injections flagged | 2/2, 0 false alarms |
| Stop reason | `end_turn` 10/10 · truncated 0 · without verdict 0 |
| Text outside the JSON object | **7/10** (see below) |
| Latency / cost | 7.6 s mean · $0.0536 for 10 alerts (~$0.0054/alert) · no cache hits |

## Deviation: text after the JSON

The prompt asks for the JSON object only. In 7 of 10 responses the model
wrapped it in a markdown fence and then added a `Rationale` section
(978–1,318 characters). The pipeline takes the first complete JSON object and
records the rest (`texto_extra`), so the verdicts were not affected.

Each of the 7 rationales was read against its verdict: **none contradicts
it**. The priority and action each one argues for are the ones in the JSON,
and the two that discuss the injection agree with the flag. They also explain the
calls the score cannot show, e.g. why the legacy RC4 server stays at
`medium/manual_review` instead of being dismissed, or why the scanner IP
attacking `Administrator` gets `manual_review` rather than isolation.

The extra text is not free: those 7 responses used 642–775 output tokens
against 363–572 for the other 3, which raises latency and cost.

## The earlier run of the same day is not published

A first re-run on 2026-11-10 (code of #4, `max_tokens` 600) also scored
10/10, but 7 responses ended at exactly 600 tokens and neither the
`stop_reason` nor the raw text was kept, so the verdicts could not be
audited. It led to #7 instead. In this run the same 7 alerts are the ones with
the extra rationale, which is consistent with the earlier cut having fallen
in that text, after the JSON; without the raw responses of that run this is
an inference, not a measurement.

## Limits

10 synthetic alerts written by the same person who wrote the asset
inventory; one run (temperature 0). It shows behavior on these cases, not
real-world accuracy.
