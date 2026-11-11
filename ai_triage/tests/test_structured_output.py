"""
Tests for the structured-output request: the JSON schema sent to the API
matches the verdict contract enforced by validar_esquema. Platform-independent:
the HTTP call is stubbed, no network.

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""

import json
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_ai_triage as t  # noqa: E402
from test_model_response import ALERTA, VEREDICTO, ModeloStub, respuesta_api  # noqa: E402

CON_RAZON = dict(VEREDICTO, razonamiento="Honeytoken SPN with RC4: tripwire, no legitimate use.")


class SchemaContractTests(unittest.TestCase):

    def test_schema_requires_every_field_the_validator_requires_plus_the_justification(self):
        requeridos = set(t.SCHEMA_VEREDICTO["required"])
        self.assertEqual(requeridos, set(t.SCHEMA_VEREDICTO["properties"]))
        self.assertIn("razonamiento", requeridos)
        with self.assertRaises(ValueError):          # the validator rejects any missing core field
            t.validar_esquema({k: v for k, v in VEREDICTO.items() if k != "accion_sugerida"})

    def test_enums_are_the_allowlists_used_by_the_validator(self):
        p = t.SCHEMA_VEREDICTO["properties"]
        self.assertEqual(set(p["prioridad"]["enum"]), t.PRIORIDADES)
        self.assertEqual(set(p["confianza"]["enum"]), t.CONFIANZAS)
        self.assertEqual(set(p["accion_sugerida"]["enum"]), t.ACCIONES_PERMITIDAS)

    def test_no_extra_fields_and_serializable(self):
        self.assertIs(t.SCHEMA_VEREDICTO["additionalProperties"], False)
        json.dumps(t.SCHEMA_VEREDICTO)

    def test_justification_must_be_text_when_present(self):
        self.assertEqual(t.validar_esquema(dict(CON_RAZON))["razonamiento"], CON_RAZON["razonamiento"])
        t.validar_esquema(dict(VEREDICTO))          # verdicts stored before the field still load
        with self.assertRaises(ValueError):
            t.validar_esquema(dict(VEREDICTO, razonamiento=["not", "text"]))


class RequestTests(unittest.TestCase):

    def _enviado(self):
        enviado = {}

        class Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return respuesta_api(json.dumps(CON_RAZON))
        with ModeloStub(None):
            sys.modules["requests"] = types.SimpleNamespace(
                post=lambda url, **k: (enviado.update(k["json"]), Resp())[1])
            analisis, _ = t.analizar_con_ia(dict(ALERTA))
        return enviado, analisis

    def test_request_asks_for_the_schema_as_structured_output(self):
        enviado, analisis = self._enviado()
        fmt = enviado["output_config"]["format"]
        self.assertEqual(fmt["type"], "json_schema")
        self.assertEqual(fmt["schema"], t.SCHEMA_VEREDICTO)
        self.assertEqual(analisis["razonamiento"], CON_RAZON["razonamiento"])

    def test_no_assistant_prefill(self):
        # Prefill is incompatible with structured outputs and rejected by newer models.
        enviado, _ = self._enviado()
        self.assertEqual([m["role"] for m in enviado["messages"]], ["user"])


class NotificationTests(unittest.TestCase):

    def test_telegram_message_carries_the_justification(self):
        mensajes = []
        orig = t.enviar_telegram
        t.enviar_telegram = mensajes.append
        try:
            t.notificar("caso-1", dict(ALERTA), dict(CON_RAZON), "analizado")
        finally:
            t.enviar_telegram = orig
        self.assertIn("Por qué: " + CON_RAZON["razonamiento"], mensajes[0])


class PolicyAndLengthNotificationTests(unittest.TestCase):

    def _capturar(self, fn):
        mensajes = []
        orig = t.enviar_telegram
        t.enviar_telegram = mensajes.append
        try:
            fn()
        finally:
            t.enviar_telegram = orig
        return mensajes[0]

    def test_floor_labels_the_model_justification_and_states_the_final_rule(self):
        alerta = dict(ALERTA)                                   # 100212, tripwire
        modelo = dict(CON_RAZON, prioridad="medium", accion_sugerida="monitor",
                      razonamiento="Looks like routine reporting; monitoring is enough.")
        final = t.aplicar_piso_tripwire(alerta["rule_id"], modelo, alerta)
        self.assertEqual((final["prioridad"], final["accion_sugerida"]), ("high", "escalate_tier2"))
        msg = self._capturar(lambda: t.notificar("caso-2", alerta, final, "analizado"))
        self.assertIn("Prioridad: high", msg)
        self.assertIn("requiere aprobación humana): escalate_tier2", msg)
        self.assertIn("Decisión final por política: regla tripwire 100212", msg)
        self.assertIn("El modelo había propuesto medium/monitor", msg)
        self.assertIn("Justificación del modelo (para su veredicto original, no para la decisión final): "
                      "Looks like routine reporting", msg)
        self.assertNotIn("Por qué:", msg)

    def test_long_model_text_is_capped_and_the_full_text_is_stored(self):
        largo = dict(CON_RAZON, resumen="R" * 5000, razonamiento="J" * 10000)
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        cwd = os.getcwd()
        os.chdir(tmp.name)
        mensajes = []
        orig_a, orig_t = t.analizar_con_ia, t.enviar_telegram
        try:
            t.analizar_con_ia = lambda a: (dict(largo), {"latencia_s": 0, "tokens_in": 0,
                                                          "tokens_out": 0, "costo_usd": 0.0})
            t.enviar_telegram = mensajes.append
            conn = t.init_db()
            caso_id, _ = t.procesar_alerta(conn, dict(ALERTA), forzar_nuevo=True, entrada=lambda *_: "s")
            guardado = json.loads(conn.execute("SELECT analisis_ia FROM casos WHERE id=?",
                                               (caso_id,)).fetchone()[0])
            conn.close()
        finally:
            t.analizar_con_ia, t.enviar_telegram = orig_a, orig_t
            os.chdir(cwd)
            tmp.cleanup()
        msg = mensajes[0]
        self.assertLessEqual(len(msg), t.TELEGRAM_MAX)
        self.assertTrue(msg.startswith(f"Caso {caso_id}"))
        self.assertIn("Prioridad: critical", msg)
        self.assertIn("requiere aprobación humana): escalate_tier2", msg)
        self.assertIn(f"recortado; completo en casos_ad.db, caso {caso_id}", msg)
        self.assertEqual(len(guardado["razonamiento"]), 10000)   # nothing lost in the record
        self.assertEqual(len(guardado["resumen"]), 5000)

    def test_final_guard_keeps_the_header_even_if_everything_else_is_huge(self):
        largo = dict(CON_RAZON, resumen="R" * 5000, razonamiento="J" * 10000)
        msg = self._capturar(lambda: t.notificar("caso-3", dict(ALERTA), largo, "analizado",
                                                 caso_relacionado="x" * 9000))
        self.assertLessEqual(len(msg), t.TELEGRAM_MAX)
        self.assertTrue(msg.startswith("Caso caso-3"))
        self.assertIn("Prioridad: critical", msg)


if __name__ == "__main__":
    unittest.main()
