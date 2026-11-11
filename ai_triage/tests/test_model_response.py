"""
Tests for how a raw model response becomes a verdict (or is rejected):
truncation at max_tokens, text around the JSON object, and the cost of a
rejected call. Platform-independent: the HTTP call is stubbed, no network.

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_ai_triage as t  # noqa: E402

VEREDICTO = {
    "resumen": "x", "prioridad": "critical", "confianza": "high", "mitre_id": "T1558.003",
    "campos_sustento": ["service_name"], "accion_sugerida": "escalate_tier2",
    "verificaciones_sugeridas": ["a"], "possible_prompt_injection": False,
}
ALERTA = {"rule_id": "100212", "level": 12, "src_ip": "192.168.56.103",
          "dest_ip": "192.168.56.10", "raw_log": "4769 svc_sql_backup 0x17"}


class ExtraerJsonTests(unittest.TestCase):

    def test_object_alone_has_no_extra_text(self):
        obj, extra = t.extraer_json(json.dumps(VEREDICTO))
        self.assertEqual(obj, VEREDICTO)
        self.assertEqual(extra, 0)

    def test_fenced_object_is_accepted(self):
        obj, extra = t.extraer_json("```json\n" + json.dumps(VEREDICTO) + "\n```")
        self.assertEqual((obj["prioridad"], extra), ("critical", 0))

    def test_prose_with_braces_after_the_object_does_not_change_it(self):
        # A greedy {.*} match would span to the last brace and fail or mis-parse.
        texto = json.dumps(VEREDICTO) + "\n\nNote: the field {service_name} looks odd."
        obj, extra = t.extraer_json(texto)
        self.assertEqual(obj, VEREDICTO)
        self.assertGreater(extra, 0)

    def test_text_before_the_object_is_counted(self):
        obj, extra = t.extraer_json("Here is the analysis:\n" + json.dumps(VEREDICTO))
        self.assertEqual(obj, VEREDICTO)
        self.assertEqual(extra, len("Here is the analysis:"))

    def test_cut_object_is_rejected(self):
        with self.assertRaises(ValueError):
            t.extraer_json(json.dumps(VEREDICTO)[:-20])

    def test_no_object_is_rejected(self):
        with self.assertRaises(ValueError):
            t.extraer_json("no JSON here")


def respuesta_api(texto, stop_reason="end_turn", out=300):
    return {"content": [{"type": "text", "text": texto}], "stop_reason": stop_reason,
            "usage": {"input_tokens": 2200, "output_tokens": out}}


class ModeloStub:
    """Swap in REAL mode with a fake `requests` module returning `data`."""

    def __init__(self, data, eval_mode=False):
        self.data, self.eval_mode = data, eval_mode
        self.tmp = tempfile.TemporaryDirectory()

    def __enter__(self):
        data = self.data

        class Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return data

        self.saved = (t.MODE, t.EVAL, t.cargar_system_prompt, t.enviar_telegram,
                      sys.modules.get("requests"), os.environ.get("ANTHROPIC_API_KEY"), os.getcwd())
        t.MODE, t.EVAL = "REAL", self.eval_mode
        t.cargar_system_prompt = lambda: "system"
        t.enviar_telegram = lambda msg: None
        sys.modules["requests"] = types.SimpleNamespace(post=lambda *a, **k: Resp())
        os.environ["ANTHROPIC_API_KEY"] = "test-not-a-key"
        os.chdir(self.tmp.name)
        return self

    def __exit__(self, *exc):
        mode, ev, csp, tg, req, key, cwd = self.saved
        t.MODE, t.EVAL, t.cargar_system_prompt, t.enviar_telegram = mode, ev, csp, tg
        if req is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = req
        if key is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = key
        os.chdir(cwd)
        self.tmp.cleanup()


class AnalizarConIaTests(unittest.TestCase):

    def test_request_uses_the_configured_limit(self):
        enviado = {}

        class Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return respuesta_api(json.dumps(VEREDICTO))
        with ModeloStub(None):
            sys.modules["requests"] = types.SimpleNamespace(
                post=lambda url, **k: (enviado.update(k["json"]), Resp())[1])
            t.analizar_con_ia(dict(ALERTA))
        self.assertEqual(enviado["max_tokens"], t.MAX_TOKENS)
        self.assertGreaterEqual(t.MAX_TOKENS, 1024)

    def test_complete_response_is_accepted_and_reports_stop_reason(self):
        with ModeloStub(respuesta_api(json.dumps(VEREDICTO))):
            analisis, met = t.analizar_con_ia(dict(ALERTA))
        self.assertEqual(analisis["prioridad"], "critical")
        self.assertEqual((met["stop_reason"], met["texto_extra"]), ("end_turn", 0))

    def test_truncated_response_is_rejected_even_if_json_can_be_parsed(self):
        # The object is complete, but the response hit the limit: what came
        # after it (or whether the model meant something else) is unknown.
        data = respuesta_api(json.dumps(VEREDICTO) + " and then", "max_tokens", out=t.MAX_TOKENS)
        with ModeloStub(data):
            with self.assertRaises(t.RespuestaTruncada) as cm:
                t.analizar_con_ia(dict(ALERTA))
        self.assertGreater(cm.exception.metricas["costo_usd"], 0)   # billed anyway
        self.assertEqual(cm.exception.metricas["stop_reason"], "max_tokens")

    def test_eval_mode_keeps_every_raw_response(self):
        with ModeloStub(respuesta_api(json.dumps(VEREDICTO) + "\nextra"), eval_mode=True) as s:
            t.analizar_con_ia(dict(ALERTA))
            with open(os.path.join(s.tmp.name, t.EVAL_RAW), encoding="utf-8") as f:
                filas = [json.loads(line) for line in f]
        self.assertEqual(len(filas), 1)
        self.assertEqual(filas[0]["stop_reason"], "end_turn")
        self.assertTrue(filas[0]["text"].endswith("extra"))


class TruncationInPipelineTests(unittest.TestCase):

    def test_truncated_tripwire_verdict_falls_back_to_the_floor_and_counts_the_cost(self):
        data = respuesta_api(json.dumps(VEREDICTO), "max_tokens", out=t.MAX_TOKENS)
        with ModeloStub(data, eval_mode=True):
            conn = t.init_db()
            caso_id, met = t.procesar_alerta(conn, dict(ALERTA), forzar_nuevo=True,
                                             entrada=lambda *_: "s")
            fila = t.evaluar_caso(conn, caso_id, {"label": "attack", "injection": False})
            conn.close()
        self.assertEqual(fila["estado"], "sin_analisis")
        self.assertTrue(fila["modelo_sin_veredicto"])
        self.assertEqual((fila["prioridad"], fila["accion"]), ("high", "escalate_tier2"))
        self.assertGreater(met["costo_usd"], 0)
        self.assertEqual(met["stop_reason"], "max_tokens")


class StopReasonTests(unittest.TestCase):
    """Only end_turn is trusted for this single-turn text call."""

    def test_valid_json_with_any_other_stop_reason_is_rejected(self):
        for reason in ("refusal", "model_context_window_exceeded", "pause_turn",
                       "tool_use", "stop_sequence", None):
            with self.subTest(stop_reason=reason):
                with ModeloStub(respuesta_api(json.dumps(VEREDICTO), reason)):
                    with self.assertRaises(t.RespuestaIncompleta) as cm:
                        t.analizar_con_ia(dict(ALERTA))
                self.assertNotIsInstance(cm.exception, t.RespuestaTruncada)
                self.assertGreater(cm.exception.metricas["costo_usd"], 0)
                self.assertEqual(cm.exception.metricas["stop_reason"], reason)

    def test_refusal_on_a_tripwire_ends_on_the_floor(self):
        with ModeloStub(respuesta_api(json.dumps(VEREDICTO), "refusal")):
            conn = t.init_db()
            caso_id, met = t.procesar_alerta(conn, dict(ALERTA), forzar_nuevo=True,
                                             entrada=lambda *_: "s")
            fila = t.evaluar_caso(conn, caso_id, {"label": "attack", "injection": False})
            conn.close()
        self.assertEqual((fila["estado"], fila["prioridad"]), ("sin_analisis", "high"))
        self.assertEqual(met["stop_reason"], "refusal")


class AuditWriteFailureTests(unittest.TestCase):
    """--eval: failing to record a raw response stops the run; it is never
    scored as a model failure and the call's cost is kept."""

    def setUp(self):
        self.orig = t.EVAL_RAW
        t.EVAL_RAW = os.path.join("no-such-dir", "raw.jsonl")  # open() fails

    def tearDown(self):
        t.EVAL_RAW = self.orig

    def test_write_failure_after_a_valid_response_is_an_audit_error(self):
        with ModeloStub(respuesta_api(json.dumps(VEREDICTO)), eval_mode=True):
            with self.assertRaises(t.ErrorAuditoria) as cm:
                t.analizar_con_ia(dict(ALERTA))
        self.assertGreater(cm.exception.metricas["costo_usd"], 0)
        self.assertEqual(cm.exception.metricas["stop_reason"], "end_turn")

    def test_pipeline_does_not_turn_it_into_a_missing_verdict(self):
        with ModeloStub(respuesta_api(json.dumps(VEREDICTO)), eval_mode=True):
            conn = t.init_db()
            with self.assertRaises(t.ErrorAuditoria):
                t.procesar_alerta(conn, dict(ALERTA), forzar_nuevo=True, entrada=lambda *_: "s")
            guardados = conn.execute("SELECT COUNT(*) FROM casos").fetchone()[0]
            conn.close()
        self.assertEqual(guardados, 0)   # no case stored as sin_analisis

    def test_eval_run_stops_with_an_explicit_exit_code_and_no_results_file(self):
        alerta = dict(ALERTA, _expected={"label": "attack", "injection": False})
        with ModeloStub(respuesta_api(json.dumps(VEREDICTO)), eval_mode=True) as s:
            with open("bench.json", "w", encoding="utf-8") as f:
                json.dump([alerta], f)
            orig_argv = sys.argv
            sys.argv = ["soc_ai_triage.py", "bench.json", "--eval"]
            try:
                with self.assertRaises(SystemExit) as cm:
                    t.main()
            finally:
                sys.argv = orig_argv
            existe = os.path.exists(os.path.join(s.tmp.name, "eval_results.json"))
        self.assertEqual(cm.exception.code, t.EXIT_AUDITORIA)
        self.assertFalse(existe)

    def test_aborted_run_does_not_leave_a_previous_results_file(self):
        """A results file from an earlier run must not survive next to the
        audit of a run that stopped: it would read as this run's score."""
        alerta = dict(ALERTA, _expected={"label": "attack", "injection": False})
        with ModeloStub(respuesta_api(json.dumps(VEREDICTO)), eval_mode=True) as s:
            with open("bench.json", "w", encoding="utf-8") as f:
                json.dump([alerta], f)
            with open(t.EVAL_RESULTS, "w", encoding="utf-8") as f:
                json.dump({"resumen": {"precision_global": "10/10"}, "detalle": []}, f)  # old run
            orig_argv = sys.argv
            sys.argv = ["soc_ai_triage.py", "bench.json", "--eval"]
            try:
                with self.assertRaises(SystemExit) as cm:
                    t.main()
            finally:
                sys.argv = orig_argv
            queda = os.path.exists(os.path.join(s.tmp.name, t.EVAL_RESULTS))
        self.assertEqual(cm.exception.code, t.EXIT_AUDITORIA)
        self.assertFalse(queda)


if __name__ == "__main__":
    unittest.main()
