"""
Tests for keyboard isolation in the live feed and for the approval gate's
handling of answers. Platform-independent: no network, no real ssh.

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_ai_triage as t  # noqa: E402
import wazuh_feed  # noqa: E402


class _Parar(Exception):
    pass


class SshStdinTests(unittest.TestCase):

    def test_ssh_never_inherits_the_analysts_keyboard(self):
        """2026-11-11: with stdin inherited, ssh competed with the approval
        prompt for keystrokes; 'a' + Enter was logged as skipped on 2 of 3."""
        visto = {}

        def popen_falso(cmd, **kw):
            visto.update(kw)
            raise _Parar()
        orig = wazuh_feed.subprocess.Popen
        wazuh_feed.subprocess.Popen = popen_falso
        try:
            with self.assertRaises(_Parar):
                next(iter(wazuh_feed.lineas_ssh("analyst@192.0.2.1")))
        finally:
            wazuh_feed.subprocess.Popen = orig
        self.assertIs(visto.get("stdin"), subprocess.DEVNULL)


class ApprovalGateTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.conn = t.init_db()

    def tearDown(self):
        self.conn.close()
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def _decidir(self, respuestas):
        it = iter(respuestas)
        preguntas = []

        def entrada(prompt):
            preguntas.append(prompt)
            r = next(it)
            if r is EOFError:
                raise EOFError
            return r
        d = t.solicitar_aprobacion(self.conn, "caso-x", {"accion_sugerida": "escalate_tier2"},
                                   entrada=entrada)
        guardada = self.conn.execute("SELECT decision FROM decisiones WHERE caso_id='caso-x'").fetchone()[0]
        return d, guardada, len(preguntas)

    def test_valid_answers_map_to_decisions(self):
        for r, esperado in (("a", "approved"), (" R ", "rejected"), ("s", "skipped")):
            with self.subTest(r=r):
                self.conn.execute("DELETE FROM decisiones")
                self.assertEqual(self._decidir([r])[:2], (esperado, esperado))

    def test_invalid_or_empty_answer_is_asked_again_not_logged_as_skipped(self):
        d, guardada, preguntas = self._decidir(["", "x", "aprobar", "a"])
        self.assertEqual((d, guardada), ("approved", "approved"))
        self.assertEqual(preguntas, 4)

    def test_no_input_at_all_leaves_the_case_pending(self):
        d, guardada, _ = self._decidir(["", EOFError])
        self.assertEqual((d, guardada), ("pending", "pending"))


if __name__ == "__main__":
    unittest.main()
