"""
Tests for rules/engine_test/run_engine_test.py without a Wazuh manager: the
pass condition needs positive evidence, and the previous rules are restored on
failure, error or Ctrl+C, with the recovery reported truthfully.

Run from the repository root:
    python3 -m unittest discover -s rules/tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "engine_test"))

import run_engine_test as et  # noqa: E402


def r(regla, decoder="windows_eventchannel", ev="4769"):
    return {"regla": regla, "decoder": decoder, "eventID": ev}


BIEN = {"honeytoken-loopback": r("100212"), "honeytoken-dc-fqdn": r("100212"),
        "honeytoken-network": r("100212"), "aes-legit": r("60106")}


class PassConditionTests(unittest.TestCase):

    def test_expected_result_passes(self):
        self.assertTrue(et.cumple(BIEN))

    def test_missing_aes_alert_is_a_failure_not_a_pass(self):
        self.assertFalse(et.cumple(dict(BIEN, **{"aes-legit": {"regla": None, "decoder": None, "eventID": None}})))

    def test_aes_reaching_kerberoasting_rules_fails(self):
        self.assertFalse(et.cumple(dict(BIEN, **{"aes-legit": r("100210")})))

    def test_alert_not_decoded_as_eventchannel_is_no_evidence(self):
        self.assertFalse(et.cumple(dict(BIEN, **{"aes-legit": r("60106", decoder="json")})))
        self.assertFalse(et.cumple(dict(BIEN, **{"honeytoken-network": r("100212", decoder="json")})))

    def test_shadowed_network_sample_fails(self):
        self.assertFalse(et.cumple(dict(BIEN, **{"honeytoken-network": {"regla": None, "decoder": None, "eventID": None}})))


class RestoreTests(unittest.TestCase):
    """main() with the manager simulated: files in a temp dir, engine calls mocked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.rules = os.path.join(d, "local_rules.xml")
        self.nuevas = os.path.join(d, "nuevas.xml")
        with open(self.rules, "w") as f:
            f.write("VIEJAS")
        with open(self.nuevas, "w") as f:
            f.write("NUEVAS")
        self.patches = [
            mock.patch.object(et, "RULES", self.rules),
            mock.patch.object(et, "AQUI", d),
            mock.patch.object(et, "muestras", return_value=({}, {})),
            mock.patch.object(et, "fidelidad", return_value=(True, "ok")),
            mock.patch.object(et, "a_xml", return_value="{}"),
            mock.patch.object(et.os, "geteuid", return_value=0),
            mock.patch.object(et.shutil, "chown"),
            mock.patch.object(et.sys, "argv", ["x", self.nuevas]),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _main(self, despues=None, error=None, reinicio=(True, True), operativo=True):
        llamadas = {"n": 0}

        def correr(etiqueta, *a):
            if etiqueta == "antes":
                return BIEN
            if error:
                raise error
            return despues

        with mock.patch.object(et, "correr", side_effect=correr), \
             mock.patch.object(et, "reiniciar", side_effect=list(reinicio)), \
             mock.patch.object(et, "operativo", return_value=operativo):
            try:
                codigo = et.main()
            except BaseException as e:
                codigo = e
        with open(self.rules) as f:
            instaladas = f.read()
        with open(os.path.join(self.tmp.name, "engine_test_results.json")) as f:
            res = json.load(f)
        return codigo, instaladas, res

    def test_pass_keeps_the_new_rules(self):
        codigo, instaladas, res = self._main(despues=BIEN)
        self.assertEqual((codigo, instaladas, res["instalada"]), (0, "NUEVAS", True))

    def test_failed_expectation_restores_and_verifies_recovery(self):
        codigo, instaladas, res = self._main(despues=dict(BIEN, **{"aes-legit": r("100210")}))
        self.assertEqual((codigo, instaladas, res["manager_recuperado"]), (1, "VIEJAS", True))

    def test_ctrl_c_during_the_after_run_still_restores(self):
        codigo, instaladas, res = self._main(error=KeyboardInterrupt())
        self.assertEqual(instaladas, "VIEJAS")
        self.assertIn("KeyboardInterrupt", res["error"])

    def test_error_during_the_after_run_still_restores(self):
        codigo, instaladas, res = self._main(error=OSError("socket"))
        self.assertEqual(instaladas, "VIEJAS")

    def test_restart_failure_with_new_rules_restores(self):
        codigo, instaladas, res = self._main(reinicio=(False, True))
        self.assertEqual((instaladas, res["manager_recuperado"]), ("VIEJAS", True))

    def test_recovery_is_not_claimed_when_the_manager_does_not_come_back(self):
        codigo, instaladas, res = self._main(despues=dict(BIEN, **{"aes-legit": r("100210")}), operativo=False)
        self.assertEqual((instaladas, res["manager_recuperado"]), ("VIEJAS", False))


if __name__ == "__main__":
    unittest.main()
