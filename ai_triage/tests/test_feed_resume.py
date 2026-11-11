"""
Tests for resuming the live feed after a stop: the checkpoint table, the
resume point, the remote follower's replay from a timestamp, and main() not
triaging an alert twice.

Run from the ai_triage folder:
    python -m unittest discover -s tests -v
"""
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_ai_triage as triage  # noqa: E402
import wazuh_feed  # noqa: E402


def alerta(ts, wid, regla="100212", nivel=12):
    return json.dumps({
        "timestamp": ts, "id": wid,
        "rule": {"id": regla, "level": nivel, "description": "test", "mitre": {"id": ["T1558.003"]}},
        "agent": {"name": "DC01"},
        "data": {"win": {"system": {"eventID": "4769"}, "eventdata": {"serviceName": "svc_sql_backup"}}},
    }, separators=(",", ":"))


T = ["2026-11-11T16:%02d:00.000+0000" % m for m in (10, 20, 30, 40, 50)]


class RemoteCommandTests(unittest.TestCase):

    def test_resume_point_is_passed_to_the_follower(self):
        self.assertTrue(wazuh_feed.comando_remoto("/x/alerts.json", T[1]).endswith(f"/x/alerts.json {T[1]}"))
        self.assertTrue(wazuh_feed.comando_remoto("/x/alerts.json").endswith("/x/alerts.json"))

    def test_anything_but_an_exact_timestamp_is_refused(self):
        for malo in ("2026-11-11", "x; rm -rf /", T[1] + " ; id", "2026-11-11T16:10:00Z"):
            with self.subTest(desde=malo):
                with self.assertRaises(ValueError):
                    wazuh_feed.comando_remoto("/x/alerts.json", malo)


@unittest.skipUnless(os.name == "posix", "the follower runs on the Linux manager")
class FollowerReplayTests(unittest.TestCase):

    def test_replays_from_the_timestamp_then_follows_new_lines(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "alerts.json")
            with open(ruta, "w") as f:
                f.write("\n".join(alerta(t, f"a{i}") for i, t in enumerate(T[:3])) + "\n")
            p = subprocess.Popen([sys.executable, "-u", "-", ruta, T[1]], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p.stdin.write(wazuh_feed.SEGUIDOR_PY.encode())
            p.stdin.close()
            sel = selectors.DefaultSelector()
            sel.register(p.stdout, selectors.EVENT_READ)
            leidas, buf = [], [b""]

            def leer(n, timeout=5):
                # Raw reads: a buffered readline() could swallow several lines
                # while the selector only reports the pipe once.
                fin = time.time() + timeout
                while len(leidas) < n and time.time() < fin:
                    if sel.select(0.2):
                        buf[0] += os.read(p.stdout.fileno(), 65536)
                        *lineas, buf[0] = buf[0].split(b"\n")
                        leidas.extend(json.loads(x)["id"] for x in lineas if x)
            try:
                leer(2)
                self.assertEqual(leidas, ["a1", "a2"])          # a0 is older than the resume point
                with open(ruta, "a") as f:
                    f.write(alerta(T[3], "a3") + "\n")
                    f.write(alerta(T[0], "late") + "\n")       # after catch-up, every new line counts
                leer(4)
                self.assertEqual(leidas, ["a1", "a2", "a3", "late"])
            finally:
                p.kill()
                p.wait()


class ResumePointTests(unittest.TestCase):

    def setUp(self):
        import sqlite3
        self.conn = sqlite3.connect(":memory:")
        wazuh_feed.init_checkpoint(self.conn)

    def tearDown(self):
        self.conn.close()

    def _ahora(self, s):
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")

    def test_no_checkpoint_means_new_alerts_only(self):
        self.assertEqual(wazuh_feed.punto_de_retoma(self.conn), (None, None))

    def test_resumes_from_the_latest_processed_alert(self):
        for i, t in enumerate(T[:3]):
            wazuh_feed.marcar_procesada(self.conn, {"_wazuh_id": f"a{i}", "timestamp": t})
        desde, nota = wazuh_feed.punto_de_retoma(self.conn, self._ahora("2026-11-11T17:00:00+0000"))
        self.assertEqual(desde, T[2])
        self.assertIn(T[2], nota)
        self.assertNotIn("ATENCIÓN", nota)

    def test_stop_across_the_daily_rotation_is_flagged(self):
        wazuh_feed.marcar_procesada(self.conn, {"_wazuh_id": "a", "timestamp": "2026-11-10T23:50:00.000+0000"})
        desde, nota = wazuh_feed.punto_de_retoma(self.conn, self._ahora("2026-11-11T00:20:00+0000"))
        self.assertEqual(desde, "2026-11-10T23:50:00.000+0000")
        self.assertIn("rotación diaria", nota)

    def test_old_checkpoint_is_not_resumed(self):
        wazuh_feed.marcar_procesada(self.conn, {"_wazuh_id": "a", "timestamp": T[0]})
        desde, nota = wazuh_feed.punto_de_retoma(self.conn, self._ahora("2026-11-13T00:00:00+0000"))
        self.assertIsNone(desde)
        self.assertIn("no se retoma", nota)


class MainResumeTests(unittest.TestCase):
    """main() with a stubbed SSH source and a stubbed triage call."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.orig = (wazuh_feed.lineas_ssh, triage.procesar_alerta, sys.argv)
        self.triageadas, self.desde = [], "unset"

        def fuente(destino, desde=None, **kw):
            self.desde = desde
            yield from self.lineas
        wazuh_feed.lineas_ssh = fuente
        triage.procesar_alerta = lambda conn, a, **kw: self.triageadas.append(a["_wazuh_id"])

    def tearDown(self):
        wazuh_feed.lineas_ssh, triage.procesar_alerta, sys.argv = self.orig
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def _main(self, *flags):
        sys.argv = ["wazuh_feed.py", "--ssh", "lab@manager", *flags]
        return wazuh_feed.main()

    def _ts_reciente(self, minutos_atras):
        t = datetime.now(timezone.utc).timestamp() - 60 * minutos_atras
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    def test_second_start_resumes_and_skips_what_was_already_triaged(self):
        a, b = self._ts_reciente(5), self._ts_reciente(1)
        self.lineas = [alerta(a, "A")]
        self._main()
        self.assertEqual((self.desde, self.triageadas), (None, ["A"]))   # first run: nothing to resume
        self.lineas = [alerta(a, "A"), alerta(b, "B")]                    # replay includes A again
        self._main()
        self.assertEqual(self.desde, a)
        self.assertEqual(self.triageadas, ["A", "B"])                     # A not triaged twice

    def test_from_end_ignores_the_checkpoint(self):
        self.lineas = [alerta(self._ts_reciente(5), "A")]
        self._main()
        self.lineas = []
        self._main("--from-end")
        self.assertIsNone(self.desde)

    def test_alert_is_recorded_only_after_triage_returns(self):
        def falla(conn, a, **kw):
            raise RuntimeError("crash mid-triage")
        triage.procesar_alerta = falla
        self.lineas = [alerta(self._ts_reciente(1), "A")]
        with self.assertRaises(RuntimeError):
            self._main()
        conn = triage.init_db()
        wazuh_feed.init_checkpoint(conn)
        self.assertFalse(wazuh_feed.ya_procesada(conn, "A"))             # replayed on the next start
        conn.close()


if __name__ == "__main__":
    unittest.main()
