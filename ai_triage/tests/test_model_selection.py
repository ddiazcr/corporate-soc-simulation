"""AI_MODEL selection: per-model prices, separate eval files, and refusal of a
model with no known price before any API call."""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # tests/: aislamiento
import aislamiento  # noqa: E402,F401  (first: clears TELEGRAM_*/ANTHROPIC_API_KEY/AI_MODE/AI_MODEL)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import soc_ai_triage as t  # noqa: E402

AI_TRIAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def costo(modelo, ti, to, lect=0, escr=0):
    p_in, p_out, m_l, m_e = t.precios_de(modelo, ti + lect + escr)
    return ti * p_in + to * p_out + lect * p_in * m_l + escr * p_in * m_e


def importar_con(env_extra):
    """Import soc_ai_triage in a fresh interpreter with extra env; return
    MODEL, EVAL_RAW, EVAL_RESULTS."""
    env = {k: v for k, v in os.environ.items() if k not in aislamiento.AISLADAS}
    env.update(env_extra)
    out = subprocess.run([sys.executable, "-c",
                          "import soc_ai_triage as t; print(t.MODEL); print(t.EVAL_RAW); print(t.EVAL_RESULTS)"],
                         cwd=AI_TRIAGE, env=env, capture_output=True, text=True, timeout=30)
    return out.stdout.split()


class PreciosTests(unittest.TestCase):
    def test_default_model_reproduces_the_published_live_cost(self):
        # Live run 2026-11-20, verdict 1: 3,122 in / 479 out -> $0.005517 (Haiku 4.5)
        self.assertEqual(t.MODEL, t.MODELO_POR_DEFECTO)
        self.assertAlmostEqual(costo("claude-haiku-4-5-20251001", 3122, 479), 0.005517, places=6)

    def test_each_known_model_uses_its_own_rates(self):
        self.assertAlmostEqual(costo("claude-haiku-5-5", 100_000, 1_000_000), 0.01 + 0.50)  # short-prompt rates
        self.assertAlmostEqual(costo("claude-sonnet-5-5", 1_000_000, 1_000_000), 12.00)
        self.assertAlmostEqual(costo("claude-opus-5-5", 1_000_000, 1_000_000), 24.00)

    def test_cache_multipliers_per_model(self):
        self.assertAlmostEqual(costo("claude-haiku-4-5-20251001", 0, 0, lect=1_000_000), 0.10)
        self.assertAlmostEqual(costo("claude-sonnet-5-5", 0, 0, lect=1_000_000), 0.10)
        self.assertAlmostEqual(costo("claude-sonnet-5-5", 0, 0, escr=1_000_000), 2.50)

    def test_haiku_55_long_prompt_tier(self):
        self.assertAlmostEqual(costo("claude-haiku-5-5", 100_000, 0), 0.01)          # at the limit
        self.assertAlmostEqual(costo("claude-haiku-5-5", 100_001, 1_000), 100_001 * 0.5e-6 + 1_000 * 2.5e-6)

    def test_unknown_model_has_no_made_up_price(self):
        with self.assertRaises(ValueError):
            t.precios_de("claude-made-up-9", 10)


class SeleccionTests(unittest.TestCase):
    def test_default_keeps_the_published_file_names(self):
        self.assertEqual(importar_con({}),
                         ["claude-haiku-4-5-20251001", "eval_raw_responses.jsonl", "eval_results.json"])

    def test_other_model_writes_its_own_eval_files(self):
        self.assertEqual(importar_con({"AI_MODEL": "claude-sonnet-5-5"}),
                         ["claude-sonnet-5-5", "eval_raw_responses.claude-sonnet-5-5.jsonl",
                          "eval_results.claude-sonnet-5-5.json"])

    def test_real_or_eval_run_refuses_a_model_without_price_before_any_call(self):
        env = {k: v for k, v in os.environ.items() if k not in aislamiento.AISLADAS}
        env.update(AI_MODE="REAL", AI_MODEL="claude-made-up-9", ANTHROPIC_API_KEY="sk-not-used")
        with tempfile.TemporaryDirectory() as d:
            for args in ([os.path.join(AI_TRIAGE, "soc_ai_triage.py"), "--eval", "x.json"],
                         [os.path.join(AI_TRIAGE, "wazuh_feed.py"), "--file", "x.json"]):
                r = subprocess.run([sys.executable] + args, cwd=d, env=env, capture_output=True,
                                   text=True, timeout=30)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("no tiene precio", r.stdout)
                self.assertFalse(os.path.exists(os.path.join(d, "casos_ad.db")))  # stopped before init_db


if __name__ == "__main__":
    unittest.main()
