"""
Tests for rules/engine_test/run_engine_test.py without a Wazuh manager: the
pass condition needs positive evidence, and the previous rules are restored on
failure, error or Ctrl+C, with the recovery reported truthfully.

Run from the repository root:
    python3 -m unittest discover -s rules/tests -v
"""
import json
import os
import re
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


class EventFormatTests(unittest.TestCase):
    """The injected event must survive the trip the agent's events take: XML
    inside a JSON string, re-printed by cJSON before os_xml parses it."""

    WIN = {"system": {"providerName": "Microsoft-Windows-Security-Auditing", "providerGuid": "{5484}",
                      "eventID": "4769", "keywords": "0x8020000000000000", "systemTime": "2026-11-11T06:52:05Z",
                      "processID": "780", "threadID": "1", "channel": "Security", "computer": "DC01", "message": "m"},
           "eventdata": {"serviceName": "svc_sql_backup", "ipAddress": "::1", "note": "it's \"x\""}}

    def test_attributes_use_single_quotes_like_windows(self):
        """Double-quoted attributes become \\" once printed as JSON and Wazuh's
        os_xml rejects them; the decoder then drops the event without a log
        line (seen on the manager 2026-11-15)."""
        ev = json.loads(et.a_xml(self.WIN, 9000000001))["Event"]
        etiquetas = re.findall(r"<[^>]+>", ev)
        self.assertFalse([t for t in etiquetas if '"' in t], "double quote inside a tag")
        self.assertIn("Name='Microsoft-Windows-Security-Auditing'", ev)

    def test_event_is_well_formed_and_keeps_values(self):
        import xml.dom.minidom as minidom
        ev = json.loads(et.a_xml(self.WIN, 9000000001, ip="::ffff:192.168.56.103"))["Event"]
        d = minidom.parseString(ev)
        datos = {n.getAttribute("Name"): n.firstChild.data for n in d.getElementsByTagName("Data")}
        self.assertEqual(datos["IpAddress"], "::ffff:192.168.56.103")
        self.assertEqual(datos["Note"], "it's \"x\"")
        self.assertEqual(d.getElementsByTagName("EventRecordID")[0].firstChild.data, "9000000001")


class ReadAlertsTests(unittest.TestCase):

    def test_a_half_written_last_line_is_ignored_until_complete(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "alerts.json")
            completa = json.dumps({"rule": {"id": "60106"}, "data": {"win": {"system": {"eventRecordID": "9001"}}}},
                                  separators=(",", ":"))           # compact, as Wazuh writes it
            with open(ruta, "w") as f:
                f.write(completa + "\n" + completa.replace("9001", "9002")[:-3])  # 2nd: marker written, rest not yet
            with mock.patch.object(et, "ALERTS", ruta):
                vistos = et.resultado({"a": 9001, "b": 9002}, 0, espera=1.5)
        self.assertEqual(set(vistos), {"a"})


class TargetTests(unittest.TestCase):
    """destino(): which file is replaced, decided before anything changes."""

    REGLA = '<group name="g,"><rule id="{}" level="3"><if_sid>1</if_sid><description>x</description></rule></group>\n'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.etc = os.path.join(self.tmp.name, "etc")
        self.ruleset = os.path.join(self.tmp.name, "ruleset")
        os.makedirs(self.etc)
        os.makedirs(self.ruleset)
        self.nuevas = self._w(self.tmp.name, "nuevas.xml", "100210", "100212")
        self.p = [mock.patch.object(et, "RULES_DIR", self.etc), mock.patch.object(et, "RULESET_DIR", self.ruleset)]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        self.tmp.cleanup()

    def _w(self, d, nombre, *ids, extra=""):
        ruta = os.path.join(d, nombre)
        with open(ruta, "w") as f:
            f.write(extra + "".join(self.REGLA.format(i) for i in ids))
        return ruta

    def test_the_file_that_defines_the_ids_is_the_target(self):
        """The lab layout: NIMBREK rules in nimbrek_rules.xml, Suricata rule in local_rules.xml."""
        self._w(self.etc, "local_rules.xml", "100001", "100101")
        objetivo = self._w(self.etc, "nimbrek_rules.xml", "100210", "100212")
        self.assertEqual(et.destino(self.nuevas), objetivo)

    def test_ids_in_two_files_stop_before_any_change(self):
        """The state an earlier version of the script left on 2026-11-15."""
        self._w(self.etc, "local_rules.xml", "100101", "100210", "100212")
        self._w(self.etc, "nimbrek_rules.xml", "100210", "100212")
        with self.assertRaises(SystemExit) as cm:
            et.destino(self.nuevas)
        self.assertIn("No se cambió nada", str(cm.exception))

    def test_an_id_also_in_the_built_in_ruleset_stops(self):
        self._w(self.etc, "nimbrek_rules.xml", "100210", "100212")
        self._w(self.ruleset, "0999-x.xml", "100212")
        with self.assertRaises(SystemExit):
            et.destino(self.nuevas)

    def test_no_file_with_the_ids_stops(self):
        self._w(self.etc, "local_rules.xml", "100101")
        with self.assertRaises(SystemExit):
            et.destino(self.nuevas)

    def test_commented_and_overwrite_rules_are_not_definitions(self):
        ruta = self._w(self.tmp.name, "c.xml", "100230",
                       extra='<!-- <rule id="100210" level="3"> -->\n<rule id="60106" level="3" overwrite="yes"></rule>\n')
        self.assertEqual(et.ids_de(ruta), {"100230"})

    def test_backup_files_are_not_rule_files(self):
        objetivo = self._w(self.etc, "nimbrek_rules.xml", "100210", "100212")
        self._w(self.etc, "local_rules.xml.bak-20261111-183016", "100210")
        self.assertEqual(et.destino(self.nuevas), objetivo)


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
            mock.patch.object(et, "destino", return_value=self.rules),
            mock.patch.object(et, "tam_log", return_value=0),
            mock.patch.object(et, "avisos_duplicados", return_value=[]),
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

    def _main(self, despues=None, error=None, reinicio=(True, True, True), operativo=True):
        llamadas = {"n": 0}

        def correr(etiqueta, *a):
            if etiqueta == "antes":
                return BIEN
            if error:
                raise error
            return despues

        with mock.patch.object(et, "correr", side_effect=correr), \
             mock.patch.object(et, "reiniciar", side_effect=list(reinicio)), \
             mock.patch.object(et, "operativo", side_effect=self._operativo(operativo)):
            try:
                codigo = et.main()
            except BaseException as e:
                codigo = e
        with open(self.rules) as f:
            instaladas = f.read()
        with open(os.path.join(self.tmp.name, "engine_test_results.json")) as f:
            res = json.load(f)
        return codigo, instaladas, res

    def _operativo(self, final):
        # 1st call: baseline restart with the rules on disk; 2nd: readiness after
        # installing the new rules (ready, unless the test says the engine never
        # came back); 3rd: check after restoring.
        llamadas = []

        def f(*a, **k):
            llamadas.append(1)
            if len(llamadas) == 1:
                return True
            return getattr(self, "listo_tras_instalar", True) if len(llamadas) == 2 else final
        return f

    def test_engine_not_ready_after_install_restores(self):
        self.listo_tras_instalar = False
        codigo, instaladas, res = self._main(despues=BIEN)
        self.assertEqual(instaladas, "VIEJAS")
        self.assertIn("canario", res["error"])

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
        codigo, instaladas, res = self._main(reinicio=(True, False, True))
        self.assertEqual((instaladas, res["manager_recuperado"]), ("VIEJAS", True))

    def test_ctrl_c_during_the_restore_still_leaves_the_old_rules_and_says_so(self):
        def reinicio_falla_luego_ctrl_c(*a, **k):
            reinicio_falla_luego_ctrl_c.n += 1
            if reinicio_falla_luego_ctrl_c.n == 1:
                return True                       # baseline restart
            if reinicio_falla_luego_ctrl_c.n == 3:
                raise KeyboardInterrupt()
            return False
        reinicio_falla_luego_ctrl_c.n = 0
        with mock.patch.object(et, "correr", return_value=BIEN), \
             mock.patch.object(et, "reiniciar", side_effect=reinicio_falla_luego_ctrl_c), \
             mock.patch.object(et, "operativo", return_value=True):
            et.main()
        with open(self.rules) as f:
            self.assertEqual(f.read(), "VIEJAS")
        with open(os.path.join(self.tmp.name, "engine_test_results.json")) as f:
            res = json.load(f)
        self.assertFalse(res["manager_recuperado"])
        self.assertIn("durante la restauración", res["error"])

    def test_duplicated_ids_after_install_restore_the_previous_rules(self):
        with mock.patch.object(et, "avisos_duplicados", side_effect=[[], ["WARNING: (7612): Rule ID '100210' is duplicated."]]):
            codigo, instaladas, res = self._main(despues=BIEN)
        self.assertEqual((codigo, instaladas, res["instalada"]), (1, "VIEJAS", False))
        self.assertIn("duplicados", res["error"])

    def test_before_is_measured_only_after_a_restart_with_the_rules_on_disk(self):
        orden = []
        with mock.patch.object(et, "correr", side_effect=lambda etiqueta, *a: orden.append(etiqueta) or BIEN), \
             mock.patch.object(et, "reiniciar", side_effect=lambda: orden.append("reinicio") or True), \
             mock.patch.object(et, "operativo", return_value=True):
            et.main()
        self.assertEqual(orden[:2], ["reinicio", "antes"])

    def test_baseline_restart_failure_changes_nothing(self):
        with mock.patch.object(et, "reiniciar", return_value=False), \
             mock.patch.object(et, "correr") as correr:
            with self.assertRaises(SystemExit):
                et.main()
        correr.assert_not_called()
        with open(self.rules) as f:
            self.assertEqual(f.read(), "VIEJAS")

    def test_recovery_is_not_claimed_when_the_manager_does_not_come_back(self):
        codigo, instaladas, res = self._main(despues=dict(BIEN, **{"aes-legit": r("100210")}), operativo=False)
        self.assertEqual((instaladas, res["manager_recuperado"]), ("VIEJAS", False))


if __name__ == "__main__":
    unittest.main()
