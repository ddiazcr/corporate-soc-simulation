"""Recompute tokens and cost of the 2026-11-24 benchmark from the raw `usage`
blocks, independently of the harness code, and compare with the reported cost.

List prices (USD per million tokens), official pricing page consulted
2026-11-24: https://platform.claude.com/docs/en/about-claude/pricing
Cache read = 0.1x input for Haiku 4.5 and Haiku 5.5, 0.05x for Sonnet 5.5;
5-minute cache write = 1.25x input. Prompts here are far below the 100k-token
long-context tier of Haiku 5.5.

Usage: python recompute_usage.py   (run from this folder)
"""
import json
import os

RUNS = [  # (label, raw file, results file, input $/M, output $/M, cache-read multiplier)
    ("Haiku 4.5", "full/eval_raw_responses.jsonl", "full/eval_results.json", 1.00, 5.00, 0.10),
    ("Haiku 5.5", "full/eval_raw_responses.claude-haiku-5-5.jsonl", "full/eval_results.claude-haiku-5-5.json", 0.10, 0.50, 0.10),
    ("Sonnet 5.5", "full/eval_raw_responses.claude-sonnet-5-5.jsonl", "full/eval_results.claude-sonnet-5-5.json", 2.00, 10.00, 0.05),
]
CACHE_WRITE = 1.25
aqui = os.path.dirname(os.path.abspath(__file__))

for label, raw, res, p_in, p_out, m_read in RUNS:
    print(f"== {label}")
    total = 0.0
    tot = {"in": 0, "out": 0, "think": 0, "read": 0, "write": 0}
    with open(os.path.join(aqui, raw), encoding="utf-8") as f:
        for n, linea in enumerate(f, 1):
            u = json.loads(linea)["usage"]
            ti, to = u["input_tokens"], u["output_tokens"]
            cr, cw = u.get("cache_read_input_tokens", 0) or 0, u.get("cache_creation_input_tokens", 0) or 0
            th = (u.get("output_tokens_details") or {}).get("thinking_tokens", 0) or 0
            c = (ti * p_in + to * p_out + cr * p_in * m_read + cw * p_in * CACHE_WRITE) / 1e6
            total += c
            for k, v in (("in", ti), ("out", to), ("think", th), ("read", cr), ("write", cw)):
                tot[k] += v
            print(f"  #{n:<2} in={ti:<5} cache_read={cr:<5} cache_write={cw:<5} out={to:<5} thinking={th:<5} cost=${c:.6f}")
    with open(os.path.join(aqui, res), encoding="utf-8") as f:
        reportado = json.load(f)["resumen"]["costo_total_usd"]
    print(f"  totals: in={tot['in']} cache_read={tot['read']} cache_write={tot['write']} "
          f"out={tot['out']} thinking={tot['think']}")
    print(f"  recomputed cost ${total:.6f} | reported ${reportado:.6f} | "
          f"{'MATCH' if abs(total - reportado) < 1e-5 else 'MISMATCH'}")
print("\nPer-call latency is not stored in these files; mean latency comes from the run summaries.")
