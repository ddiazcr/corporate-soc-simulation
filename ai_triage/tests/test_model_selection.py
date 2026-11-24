"""AI_MODEL selection: per-model prices, separate eval files, and refusal of a
model with no known price before any API call."""
import os
import subprocess
import sys
import json
import tempfile
import types
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


VEREDICTO = {
    "resumen": "x", "razonamiento": "y", "prioridad": "critical", "confianza": "high",
    "mitre_id": "T1558.003", "campos_sustento": ["service_name"], "accion_sugerida": "escalate_tier2",
    "verificaciones_sugeridas": ["a"], "possible_prompt_injection": False,
}
ALERTA = {"rule_id": "100212", "level": 12, "src_ip": "192.168.56.103",
          "dest_ip": "192.168.56.10", "raw_log": "4769 svc_sql_backup 0x17"}


class SolicitudTests(unittest.TestCase):
    """The request each model receives, and the parsing of a 5.5-style reply
    (thinking block first, then the text)."""

    def setUp(self):
        self.orig = (t.MODE, t.MODEL, t.PERFIL, t.MAX_TOKENS, sys.modules.get("requests"),
                     os.environ.get("ANTHROPIC_API_KEY"))
        t.MODE = "REAL"
        os.environ["ANTHROPIC_API_KEY"] = "sk-test"
        self.enviado = {}

    def tearDown(self):
        t.MODE, t.MODEL, t.PERFIL, t.MAX_TOKENS, req, clave = self.orig
        if req is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = req
        if clave is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = clave

    def _llamar(self, modelo, contenido):
        t.MODEL, t.PERFIL = modelo, t.PERFILES[modelo]
        t.MAX_TOKENS = t.PERFIL["max_tokens"]

        class Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"content": contenido, "stop_reason": "end_turn",
                        "usage": {"input_tokens": 3000, "output_tokens": 900}}
        sys.modules["requests"] = types.SimpleNamespace(
            post=lambda url, **k: (self.enviado.update(k["json"]), Resp())[1])
        return t.analizar_con_ia(dict(ALERTA))

    def test_haiku_45_keeps_the_benchmark_request(self):
        self._llamar("claude-haiku-4-5-20251001", [{"type": "text", "text": json.dumps(VEREDICTO)}])
        self.assertEqual(self.enviado["temperature"], 0)
        self.assertEqual(self.enviado["max_tokens"], 1024)
        self.assertEqual(self.enviado["model"], "claude-haiku-4-5-20251001")

    def test_55_models_get_no_sampling_parameters_and_room_for_thinking(self):
        for modelo in ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"):
            with self.subTest(modelo=modelo):
                self.enviado.clear()
                self._llamar(modelo, [{"type": "text", "text": json.dumps(VEREDICTO)}])
                for p in ("temperature", "top_p", "top_k"):
                    self.assertNotIn(p, self.enviado)
                self.assertGreaterEqual(self.enviado["max_tokens"], 8000)
                self.assertEqual(self.enviado["messages"][-1]["role"], "user")      # no prefill
                self.assertEqual(self.enviado["output_config"]["format"]["type"], "json_schema")

    def test_a_thinking_block_before_the_text_is_ignored(self):
        analisis, metricas = self._llamar("claude-haiku-5-5", [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": json.dumps(VEREDICTO)}])
        self.assertEqual(analisis["prioridad"], "critical")
        self.assertAlmostEqual(metricas["costo_usd"], 3000 * 0.1e-6 + 900 * 0.5e-6, places=6)

    def test_every_priced_model_has_a_request_profile(self):
        self.assertEqual(set(t.PRECIOS), set(t.PERFILES))

    def test_fresh_import_applies_the_profile(self):
        env = {k: v for k, v in os.environ.items() if k not in aislamiento.AISLADAS}
        env["AI_MODEL"] = "claude-sonnet-5-5"
        out = subprocess.run([sys.executable, "-c", "import soc_ai_triage as t; print(t.MAX_TOKENS, t.PERFIL.get('temperature'))"],
                             cwd=AI_TRIAGE, env=env, capture_output=True, text=True, timeout=30).stdout.split()
        self.assertEqual(out, ["16000", "None"])


if __name__ == "__main__":
    unittest.main()
