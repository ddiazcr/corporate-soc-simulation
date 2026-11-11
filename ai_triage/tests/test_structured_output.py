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


if __name__ == "__main__":
    unittest.main()
