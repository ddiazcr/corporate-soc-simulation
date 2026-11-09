"""
Tests for the deterministic priority floor on tripwire rules
(soc_ai_triage.aplicar_piso_tripwire). Platform-independent: no network, no
model call, any OS.

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_ai_triage as t  # noqa: E402


def veredicto(prioridad="medium", accion="manual_review"):
    return {
        "resumen": "x", "prioridad": prioridad, "confianza": "medium", "mitre_id": "T1087.002",
        "campos_sustento": [], "accion_sugerida": accion, "verificaciones_sugeridas": [],
        "possible_prompt_injection": False,
    }


DECOY = "dd002ba1-3992-4539-bf9b-9ee77df0952d"     # test value, format as seen in 4662
OTRA = "11111111-2222-3333-4444-555555555555"      # same object class, another account
USER_CLASS = "bf967aba-0de6-11d0-a285-00aa003049e2"


def alerta_4662(object_guid, **extra):
    a = {"rule_id": "100230", "level": 12, "src_ip": None, "dest_ip": "192.168.56.10",
         "object_name": "%{" + object_guid + "}", "object_type": "%{" + USER_CLASS + "}",
         "raw_log": "4662 Read Property"}
    a.update(extra)
    return a


class DecoyGuidMixin:
    def setUp(self):
        self._guid = t.DECOY_OBJECT_GUID
        t.DECOY_OBJECT_GUID = DECOY

    def tearDown(self):
        t.DECOY_OBJECT_GUID = self._guid


class PriorityFloorTests(DecoyGuidMixin, unittest.TestCase):

    def test_decoy_read_rated_medium_is_raised_to_high(self):
        # The exact case seen live on 2026-11-07: rule 100230 rated "medium".
        v = t.aplicar_piso_tripwire("100230", veredicto("medium", "manual_review"), alerta_4662(DECOY))
        self.assertEqual(v["prioridad"], "high")
        self.assertEqual(v["accion_sugerida"], "manual_review")  # not dismissive: kept
        self.assertEqual(v["piso_aplicado"]["prioridad_modelo"], "medium")

    def test_honeytoken_dismissed_by_model_is_escalated(self):
        v = t.aplicar_piso_tripwire("100212", veredicto("low", "mark_false_positive"))
        self.assertEqual((v["prioridad"], v["accion_sugerida"]), ("high", "escalate_tier2"))
        self.assertEqual(v["piso_aplicado"]["accion_modelo"], "mark_false_positive")

    def test_monitor_on_a_tripwire_is_escalated(self):
        v = t.aplicar_piso_tripwire("100230", veredicto("high", "monitor"), alerta_4662(DECOY))
        self.assertEqual(v["accion_sugerida"], "escalate_tier2")

    def test_floor_never_lowers_a_critical_verdict(self):
        original = veredicto("critical", "escalate_tier2")
        v = t.aplicar_piso_tripwire("100212", original)
        self.assertEqual(v["prioridad"], "critical")
        self.assertNotIn("piso_aplicado", v)  # nothing changed, nothing recorded

    def test_non_tripwire_rules_are_untouched(self):
        # Privileged-group change can be an approved change: no floor.
        original = veredicto("medium", "monitor")
        v = t.aplicar_piso_tripwire("100220", original)
        self.assertEqual(v, original)

    def test_input_verdict_is_not_mutated(self):
        original = veredicto("low", "monitor")
        t.aplicar_piso_tripwire("100230", original, alerta_4662(DECOY))
        self.assertEqual((original["prioridad"], original["accion_sugerida"]), ("low", "monitor"))

    def test_floored_verdict_still_passes_schema_validation(self):
        v = t.aplicar_piso_tripwire("100212", veredicto("low", "mark_false_positive"))
        t.validar_esquema(v)  # raises if the floor produced an invalid verdict

    def test_idempotent(self):
        once = t.aplicar_piso_tripwire("100230", veredicto("medium", "monitor"), alerta_4662(DECOY))
        twice = t.aplicar_piso_tripwire("100230", once, alerta_4662(DECOY))
        self.assertEqual((twice["prioridad"], twice["accion_sugerida"]), ("high", "escalate_tier2"))
        self.assertEqual(twice["piso_aplicado"]["prioridad_modelo"], "medium")

    def test_missing_verdict_is_passed_through(self):
        self.assertIsNone(t.aplicar_piso_tripwire("100230", None, alerta_4662(DECOY)))


class DecoyVerificationTests(DecoyGuidMixin, unittest.TestCase):
    """100230: same object class, different objectName. Only the decoy counts."""

    def test_only_the_decoy_guid_activates_the_floor(self):
        senuelo = t.aplicar_piso_tripwire("100230", veredicto("medium", "monitor"), alerta_4662(DECOY))
        otra = t.aplicar_piso_tripwire("100230", veredicto("medium", "monitor"), alerta_4662(OTRA))
        self.assertEqual((senuelo["prioridad"], senuelo["accion_sugerida"]), ("high", "escalate_tier2"))
        self.assertEqual((otra["prioridad"], otra["accion_sugerida"]), ("medium", "monitor"))
        self.assertNotIn("piso_aplicado", otra)

    def test_guid_comparison_ignores_case_and_braces(self):
        self.assertTrue(t.es_senuelo_verificado({"object_name": "%{" + DECOY.upper() + "}"}))
        self.assertTrue(t.es_senuelo_verificado({"object_name": DECOY}))

    def test_missing_object_name_is_not_the_decoy(self):
        self.assertFalse(t.es_senuelo_verificado({"rule_id": "100230"}))

    def test_without_a_verified_guid_100230_never_gets_the_floor(self):
        t.DECOY_OBJECT_GUID = None   # fail-safe default
        v = t.aplicar_piso_tripwire("100230", veredicto("medium", "monitor"), alerta_4662(DECOY))
        self.assertEqual(v["prioridad"], "medium")

    def test_honeytoken_rule_does_not_need_an_object_guid(self):
        v = t.aplicar_piso_tripwire("100212", veredicto("low", "monitor"), {"rule_id": "100212"})
        self.assertEqual(v["prioridad"], "high")

    def test_feed_carries_object_name_from_wazuh(self):
        import wazuh_feed
        wazuh = {"rule": {"id": "100230", "level": 12}, "id": "x",
                 "data": {"win": {"system": {"eventID": "4662"},
                                  "eventdata": {"objectName": "%{" + DECOY + "}"}}}}
        self.assertEqual(wazuh_feed.convertir(wazuh)["object_name"], "%{" + DECOY + "}")


class ModelVerdictTests(DecoyGuidMixin, unittest.TestCase):

    def test_model_verdict_is_recoverable_after_the_floor(self):
        final = t.aplicar_piso_tripwire("100230", veredicto("medium", "monitor"), alerta_4662(DECOY))
        modelo = t.veredicto_modelo(final)
        self.assertEqual((modelo["prioridad"], modelo["accion_sugerida"]), ("medium", "monitor"))
        self.assertEqual((final["prioridad"], final["accion_sugerida"]), ("high", "escalate_tier2"))

    def test_model_and_final_verdicts_are_scored_separately(self):
        final = t.aplicar_piso_tripwire("100230", veredicto("medium", "monitor"), alerta_4662(DECOY))
        ataque = {"label": "attack"}
        self.assertFalse(t.calificar(ataque, t.veredicto_modelo(final))[0])  # model alone: miss
        self.assertTrue(t.calificar(ataque, final)[0])                       # after policy: hit

    def test_unfloored_verdict_is_its_own_model_verdict(self):
        v = veredicto("critical", "escalate_tier2")
        self.assertIs(t.veredicto_modelo(v), v)


SIN_COSTO = {"latencia_s": 0, "tokens_in": 0, "tokens_out": 0, "costo_usd": 0.0}


class FloorInPipelineTests(DecoyGuidMixin, unittest.TestCase):
    """End-to-end through procesar_alerta with a stubbed model."""

    def _run(self, rule_id, analizar, object_guid=DECOY, extra=None):
        """Run one alert through procesar_alerta; return (case row, Telegram text)."""
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        cwd = os.getcwd()
        os.chdir(tmp.name)
        mensajes = []
        orig_analizar, orig_enviar = t.analizar_con_ia, t.enviar_telegram
        try:
            t.analizar_con_ia = analizar
            t.enviar_telegram = mensajes.append  # capture the notification text
            conn = t.init_db()
            alerta = alerta_4662(object_guid, rule_id=rule_id, **(extra or {}))
            self.vista_por_modelo = None
            res = t.procesar_alerta(conn, alerta, forzar_nuevo=True, entrada=lambda *_: "s")
            caso_id = res[0] if isinstance(res, tuple) else res
            fila = conn.execute("SELECT prioridad, confianza, accion_sugerida, estado, analisis_ia "
                                "FROM casos WHERE id=?", (caso_id,)).fetchone()
            conn.close()
        finally:
            t.analizar_con_ia, t.enviar_telegram = orig_analizar, orig_enviar
            os.chdir(cwd)
            tmp.cleanup()
        return fila, mensajes[0]

    def test_floor_is_applied_before_the_case_is_stored_and_notified(self):
        fila, msg = self._run("100230", lambda a: (veredicto("medium", "manual_review"), SIN_COSTO))
        self.assertEqual(fila[0], "high")
        self.assertIn("Prioridad: high", msg)
        self.assertIn("[piso tripwire; modelo: medium]", msg)

    def _falla(self, alerta):
        raise RuntimeError("API no disponible")

    def test_tripwire_keeps_high_priority_when_the_model_fails(self):
        fila, msg = self._run("100230", self._falla)
        prioridad, confianza, accion, estado, analisis_ia = fila
        self.assertEqual(estado, "sin_analisis")
        self.assertIsNone(analisis_ia)
        self.assertEqual(prioridad, "high")            # from the rule, not the model
        self.assertEqual(accion, "escalate_tier2")     # priority human review
        self.assertEqual(confianza, "n/a")             # no invented confidence
        self.assertIn("análisis de IA NO disponible", msg)
        self.assertIn("Prioridad: high (por regla tripwire", msg)
        self.assertIn("PRIORITARIA", msg)

    def test_tripwire_keeps_high_priority_when_the_verdict_is_invalid(self):
        def invalido(alerta):
            return t.validar_esquema({"prioridad": "urgentisimo"}), SIN_COSTO
        fila, msg = self._run("100212", invalido)
        self.assertEqual((fila[0], fila[3]), ("high", "sin_analisis"))
        self.assertIn("Prioridad: high (por regla tripwire", msg)

    def test_non_decoy_account_read_is_not_escalated_by_policy(self):
        fila, msg = self._run("100230", lambda a: (veredicto("medium", "manual_review"), SIN_COSTO),
                              object_guid=OTRA)
        self.assertEqual(fila[0], "medium")
        self.assertNotIn("piso tripwire", msg)

    def test_non_decoy_account_read_gets_no_fallback_priority_when_the_model_fails(self):
        fila, msg = self._run("100230", self._falla, object_guid=OTRA)
        self.assertEqual((fila[0], fila[2]), ("desconocida", None))
        self.assertIn("Revisar manualmente.", msg)

    def test_decoy_verified_flag_is_set_by_the_pipeline_not_the_log(self):
        visto = {}

        def espia(alerta):
            visto.update(alerta)
            return veredicto("medium", "manual_review"), SIN_COSTO
        self._run("100230", espia, object_guid=OTRA, extra={"decoy_verified": True})  # spoofed in the log
        self.assertIs(visto["decoy_verified"], False)

    def test_eval_scores_the_fallback_decision_when_the_model_fails(self):
        """--eval: model fails on a 100212 attack. The report must show model
        without verdict, final decision high/escalate_tier2 (correct), and
        injection detection as not evaluable."""
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        cwd = os.getcwd()
        os.chdir(tmp.name)
        orig_analizar, orig_enviar = t.analizar_con_ia, t.enviar_telegram
        try:
            t.analizar_con_ia = self._falla
            t.enviar_telegram = lambda msg: None
            conn = t.init_db()
            alerta = {"rule_id": "100212", "level": 12, "src_ip": "192.168.56.103",
                      "dest_ip": "192.168.56.10", "raw_log": "4769 svc_sql_backup 0x17"}
            res = t.procesar_alerta(conn, alerta, forzar_nuevo=True, entrada=lambda *_: "s")
            caso_id = res[0] if isinstance(res, tuple) else res
            fila = t.evaluar_caso(conn, caso_id, {"label": "attack", "injection": False})
            conn.close()
        finally:
            t.analizar_con_ia, t.enviar_telegram = orig_analizar, orig_enviar
            os.chdir(cwd)
            tmp.cleanup()
        self.assertTrue(fila["modelo_sin_veredicto"])
        self.assertFalse(fila["correcto_modelo"])
        self.assertEqual((fila["prioridad"], fila["accion"]), ("high", "escalate_tier2"))
        self.assertTrue(fila["correcto"])                 # the SOC's final decision was right
        self.assertTrue(fila["piso_aplicado"])
        self.assertFalse(fila["inyeccion_evaluable"])
        self.assertIsNone(fila["inyeccion_correcta"])     # not scored as a miss
        self.assertEqual(fila["estado"], "sin_analisis")

    def test_non_tripwire_failure_is_unchanged(self):
        fila, msg = self._run("100220", self._falla)
        self.assertEqual((fila[0], fila[1], fila[2]), ("desconocida", "n/a", None))
        self.assertIn("Revisar manualmente.", msg)
        self.assertNotIn("tripwire", msg)


if __name__ == "__main__":
    unittest.main()
