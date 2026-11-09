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


class PriorityFloorTests(unittest.TestCase):

    def test_decoy_read_rated_medium_is_raised_to_high(self):
        # The exact case seen live on 2026-11-07: rule 100230 rated "medium".
        v = t.aplicar_piso_tripwire("100230", veredicto("medium", "manual_review"))
        self.assertEqual(v["prioridad"], "high")
        self.assertEqual(v["accion_sugerida"], "manual_review")  # not dismissive: kept
        self.assertEqual(v["piso_aplicado"]["prioridad_modelo"], "medium")

    def test_honeytoken_dismissed_by_model_is_escalated(self):
        v = t.aplicar_piso_tripwire("100212", veredicto("low", "mark_false_positive"))
        self.assertEqual((v["prioridad"], v["accion_sugerida"]), ("high", "escalate_tier2"))
        self.assertEqual(v["piso_aplicado"]["accion_modelo"], "mark_false_positive")

    def test_monitor_on_a_tripwire_is_escalated(self):
        v = t.aplicar_piso_tripwire("100230", veredicto("high", "monitor"))
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
        t.aplicar_piso_tripwire("100230", original)
        self.assertEqual((original["prioridad"], original["accion_sugerida"]), ("low", "monitor"))

    def test_floored_verdict_still_passes_schema_validation(self):
        v = t.aplicar_piso_tripwire("100212", veredicto("low", "mark_false_positive"))
        t.validar_esquema(v)  # raises if the floor produced an invalid verdict

    def test_idempotent(self):
        once = t.aplicar_piso_tripwire("100230", veredicto("medium", "monitor"))
        twice = t.aplicar_piso_tripwire("100230", once)
        self.assertEqual((twice["prioridad"], twice["accion_sugerida"]), ("high", "escalate_tier2"))
        self.assertEqual(twice["piso_aplicado"]["prioridad_modelo"], "medium")

    def test_missing_verdict_is_passed_through(self):
        self.assertIsNone(t.aplicar_piso_tripwire("100230", None))


class FloorInPipelineTests(unittest.TestCase):
    """End-to-end through procesar_alerta with a stubbed model verdict."""

    def test_floor_is_applied_before_the_case_is_stored_and_notified(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        cwd = os.getcwd()
        os.chdir(tmp.name)
        avisos = []
        orig_analizar, orig_notificar = t.analizar_con_ia, t.notificar
        try:
            t.analizar_con_ia = lambda alerta: (veredicto("medium", "manual_review"),
                                               {"latencia_s": 0, "tokens_in": 0, "tokens_out": 0, "costo_usd": 0.0})
            t.notificar = lambda caso_id, alerta, analisis, estado, rel=None: avisos.append(analisis)
            conn = t.init_db()
            alerta = {"rule_id": "100230", "level": 12, "src_ip": None, "dest_ip": "192.168.56.10",
                      "raw_log": "4662 Read Property {dd002ba1-...}"}
            caso_id, _ = t.procesar_alerta(conn, alerta, forzar_nuevo=True, entrada=lambda *_: "s")
            fila = conn.execute("SELECT prioridad FROM casos WHERE id=?", (caso_id,)).fetchone()
            conn.close()
        finally:
            t.analizar_con_ia, t.notificar = orig_analizar, orig_notificar
            os.chdir(cwd)
            tmp.cleanup()
        self.assertEqual(fila[0], "high")
        self.assertEqual(avisos[0]["prioridad"], "high")
        self.assertEqual(avisos[0]["piso_aplicado"]["prioridad_modelo"], "medium")


if __name__ == "__main__":
    unittest.main()
