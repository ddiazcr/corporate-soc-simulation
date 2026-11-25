"""
Tests for recording which model produced a verdict: the `modelo` column of
`casos` (added to older databases on open) and the "Modelo:" line of the
notification. Platform-independent: no network, no model call, any OS.

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # tests/: aislamiento
import aislamiento  # noqa: E402,F401  (first: clears TELEGRAM_*/ANTHROPIC_API_KEY/AI_MODE)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_ai_triage as t  # noqa: E402

VEREDICTO = {
    "resumen": "x", "razonamiento": "y", "prioridad": "high", "confianza": "high",
    "mitre_id": "T1558.003", "campos_sustento": ["raw_log"], "accion_sugerida": "escalate_tier2",
    "verificaciones_sugeridas": ["a"], "possible_prompt_injection": False,
}
METRICAS = {"latencia_s": 0.1, "tokens_in": 1, "tokens_out": 1, "costo_usd": 0.0}
ALERTA = {"rule_id": "100211", "level": 12, "src_ip": "192.168.56.20",
          "dest_ip": "192.168.56.10", "raw_log": "4769 0x17"}


class ModelTagTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.orig = (t.MODE, t.MODEL, t.analizar_con_ia, t.enviar_telegram)
        self.mensajes = []
        t.enviar_telegram = self.mensajes.append

    def tearDown(self):
        t.MODE, t.MODEL, t.analizar_con_ia, t.enviar_telegram = self.orig
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def _procesar(self, modo, modelo, analizar):
        t.MODE, t.MODEL, t.analizar_con_ia = modo, modelo, analizar
        conn = t.init_db()
        res = t.procesar_alerta(conn, dict(ALERTA), forzar_nuevo=True, entrada=lambda *_: "s")
        caso_id = res[0] if isinstance(res, tuple) else res
        fila = conn.execute("SELECT modelo, estado FROM casos WHERE id=?", (caso_id,)).fetchone()
        conn.close()
        return fila, self.mensajes[0]

    def test_real_verdict_records_the_model(self):
        fila, msg = self._procesar("REAL", "claude-haiku-5-5", lambda a: (dict(VEREDICTO), METRICAS))
        self.assertEqual(fila, ("claude-haiku-5-5", "analizado"))
        self.assertIn("\nModelo: claude-haiku-5-5", msg)
        # The identity, priority and action lines still come first.
        self.assertTrue(msg.startswith("Caso "))
        self.assertLess(msg.index("Prioridad:"), msg.index("Modelo:"))

    def test_default_model_is_recorded_too(self):
        fila, msg = self._procesar("REAL", t.MODELO_POR_DEFECTO, lambda a: (dict(VEREDICTO), METRICAS))
        self.assertEqual(fila[0], "claude-haiku-4-5-20251001")
        self.assertIn("Modelo: claude-haiku-4-5-20251001", msg)

    def test_failed_call_names_the_model_that_was_asked(self):
        def falla(alerta):
            raise RuntimeError("API no disponible")
        fila, msg = self._procesar("REAL", "claude-haiku-5-5", falla)
        self.assertEqual(fila, ("claude-haiku-5-5", "sin_analisis"))
        self.assertIn("análisis de IA NO disponible", msg)
        self.assertIn("Modelo: claude-haiku-5-5", msg)

    def test_simulated_mode_records_no_model(self):
        fila, msg = self._procesar("SIMULADO", "claude-haiku-5-5", lambda a: (dict(VEREDICTO), METRICAS))
        self.assertIsNone(fila[0])
        self.assertIn("Modelo: simulado", msg)

    def test_an_older_database_gets_the_column(self):
        conn = sqlite3.connect(t.DB_PATH)
        conn.execute("CREATE TABLE casos (id TEXT PRIMARY KEY, hash_dedup TEXT, huella_contenido TEXT, "
                     "regla TEXT, mitre_id TEXT, origen TEXT, destino TEXT, primera_deteccion TEXT, "
                     "ultima_deteccion TEXT, conteo INTEGER, evidencia TEXT, analisis_ia TEXT, "
                     "prioridad TEXT, confianza TEXT, accion_sugerida TEXT, estado TEXT)")
        conn.execute("INSERT INTO casos (id, regla, estado) VALUES ('viejo', '100212', 'analizado')")
        conn.commit()
        conn.close()
        fila, _ = self._procesar("REAL", "claude-haiku-5-5", lambda a: (dict(VEREDICTO), METRICAS))
        self.assertEqual(fila[0], "claude-haiku-5-5")
        conn = sqlite3.connect(t.DB_PATH)
        self.assertEqual(conn.execute("SELECT modelo FROM casos WHERE id='viejo'").fetchone(), (None,))
        conn.close()
        t.init_db().close()  # opening it again must not fail (column already there)


if __name__ == "__main__":
    unittest.main()
